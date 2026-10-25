"""Attach-only bounded observer for one persisted diagnostics soak campaign."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from . import (
    converged_action_driver,
    converged_observer_state,
    diag_event_runs,
    soak_launch,
    soak_run_layout,
    soak_storage,
)
from .paths import get_workspace_output_root, path_is_relative_to
from .vm_guest_profiles import api_data, http_json

DEFAULT_READY_TIMEOUT_SECONDS = 600.0
DEFAULT_POLL_INTERVAL_SECONDS = 5.0
DEFAULT_CHECKPOINT_INTERVAL_SECONDS = 300.0
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_RECENT_ACTION_LIMIT = 64
DEFAULT_RECENT_ANOMALY_LIMIT = 64
MIN_ACTION_INTERVAL_SECONDS = 300.0
DEFAULT_ACTION_START_DELAY_SECONDS = 60.0
DEFAULT_ACTION_INTERVAL_SECONDS = 1_800.0
DEFAULT_ACTION_SEARCH_TIMEOUT_SECONDS = 180.0
DEFAULT_ACTION_METHOD = "server"
ACTION_METHODS = ("server", "global", "kad")


@dataclass(frozen=True)
class ObserverActionConfig:
    """Immutable synchronized search schedule owned by the observer."""

    enabled: bool = False
    source_profile: str | None = None
    terms: tuple[str, ...] = ()
    method: str = DEFAULT_ACTION_METHOD
    start_delay_seconds: float = DEFAULT_ACTION_START_DELAY_SECONDS
    search_interval_seconds: float = DEFAULT_ACTION_INTERVAL_SECONDS
    search_timeout_seconds: float = DEFAULT_ACTION_SEARCH_TIMEOUT_SECONDS
    max_cycles: int = 0


@dataclass(frozen=True)
class ObserverRuntime:
    """Validated immutable authority for one attach-only observer process."""

    session_manifest: Path
    stop_file: Path
    last_run_manifest: Path
    run_paths: soak_run_layout.SoakRunPaths
    store: soak_storage.BoundedArtifactStore
    launcher_identity: dict[str, Any]
    rust_base_url: str
    mfc_base_url: str
    action_config: ObserverActionConfig = ObserverActionConfig()


def parse_action_config(observer_config: dict[str, Any]) -> ObserverActionConfig:
    """Validates the optional observer-owned synchronized search schedule."""

    payload = observer_config.get("actionDriving")
    if payload is None:
        return ObserverActionConfig()
    if not isinstance(payload, dict):
        raise RuntimeError("Persisted soak observer action config is invalid.")
    required_fields = {
        "enabled",
        "sourceProfile",
        "terms",
        "method",
        "startDelaySeconds",
        "searchIntervalSeconds",
        "searchTimeoutSeconds",
        "maxCycles",
    }
    if set(payload) != required_fields:
        raise RuntimeError("Persisted soak observer action config fields are invalid.")
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        raise RuntimeError("Persisted soak observer action enabled flag is invalid.")
    source_profile = payload.get("sourceProfile")
    if source_profile is not None and (
        not isinstance(source_profile, str) or not source_profile.strip()
    ):
        raise RuntimeError("Persisted soak observer action source profile is invalid.")
    if enabled and source_profile is None:
        raise RuntimeError("Enabled observer action driving requires a source profile.")
    raw_terms = payload.get("terms")
    if not isinstance(raw_terms, list) or any(
        not isinstance(term, str) or not term.strip() for term in raw_terms
    ):
        raise RuntimeError("Persisted soak observer action terms are invalid.")
    terms = tuple(dict.fromkeys(term.strip() for term in raw_terms))
    if enabled and not terms:
        raise RuntimeError("Enabled observer action driving requires search terms.")
    method = payload.get("method")
    if not isinstance(method, str) or method not in ACTION_METHODS:
        raise RuntimeError("Persisted soak observer action method is invalid.")
    start_delay = payload.get("startDelaySeconds")
    interval = payload.get("searchIntervalSeconds")
    search_timeout = payload.get("searchTimeoutSeconds")
    max_cycles = payload.get("maxCycles")
    if (
        isinstance(start_delay, bool)
        or not isinstance(start_delay, (int, float))
        or not math.isfinite(start_delay)
        or start_delay < 0
    ):
        raise RuntimeError("Persisted soak observer action start delay is invalid.")
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(interval)
        or interval < MIN_ACTION_INTERVAL_SECONDS
    ):
        raise RuntimeError(
            f"Persisted soak observer action interval must be at least {MIN_ACTION_INTERVAL_SECONDS:g} seconds."
        )
    if (
        isinstance(search_timeout, bool)
        or not isinstance(search_timeout, (int, float))
        or not math.isfinite(search_timeout)
        or search_timeout <= 0
    ):
        raise RuntimeError("Persisted soak observer action search timeout is invalid.")
    if (
        not isinstance(max_cycles, int)
        or isinstance(max_cycles, bool)
        or max_cycles < 0
    ):
        raise RuntimeError("Persisted soak observer action max cycles is invalid.")
    return ObserverActionConfig(
        enabled=enabled,
        source_profile=source_profile,
        terms=terms,
        method=method,
        start_delay_seconds=float(start_delay),
        search_interval_seconds=float(interval),
        search_timeout_seconds=float(search_timeout),
        max_cycles=max_cycles,
    )


def load_json_object(path: Path) -> dict[str, Any]:
    """Loads one required JSON object."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Unable to load observer JSON object {path}: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"Observer JSON payload must be an object: {path}")
    return payload


def load_runtime(session_manifest: Path, output_root: Path) -> ObserverRuntime:
    """Loads and strictly validates one controller-owned observer attachment."""

    from . import persisted_soak_controller

    resolved_output = output_root.resolve()
    resolved_manifest = session_manifest.resolve()
    if not path_is_relative_to(resolved_manifest, resolved_output):
        raise RuntimeError(
            f"Observer session manifest escaped EMULEBB_WORKSPACE_OUTPUT_ROOT: {resolved_manifest}"
        )
    manifest = load_json_object(resolved_manifest)
    if manifest.get("schema") != persisted_soak_controller.MANIFEST_SCHEMA:
        raise RuntimeError("Persisted soak observer session schema is invalid.")
    if manifest.get("state") != "running":
        raise RuntimeError("Observer requires a running persisted soak session.")
    observer_config = manifest.get("observerConfig")
    if (
        not isinstance(observer_config, dict)
        or observer_config.get("enabled") is not True
    ):
        raise RuntimeError("Persisted soak observer is not enabled for this session.")

    storage = persisted_soak_controller.parse_session_storage_context(
        manifest,
        resolved_output,
    )
    campaign_id = soak_run_layout.validate_campaign_id(
        str(manifest.get("campaignId") or "")
    )
    run_paths = soak_run_layout.build_run_paths(storage.root.parent, campaign_id)
    if run_paths.campaign_dir.resolve() != storage.active_campaign:
        raise RuntimeError(
            "Observer campaign path does not match session storage authority."
        )

    control_files = manifest.get("controlFiles")
    if not isinstance(control_files, dict):
        raise RuntimeError("Persisted soak observer control files are invalid.")
    stop_value = control_files.get("stop")
    last_run_value = control_files.get("lastRunManifest")
    if not isinstance(stop_value, str) or not stop_value.strip():
        raise RuntimeError("Persisted soak observer stop path is invalid.")
    if not isinstance(last_run_value, str) or not last_run_value.strip():
        raise RuntimeError("Persisted soak observer last-run path is invalid.")
    stop_file = Path(stop_value).resolve()
    last_run_manifest = Path(last_run_value).resolve()
    if not path_is_relative_to(stop_file, resolved_output):
        raise RuntimeError("Persisted soak observer stop path escaped the output root.")
    if last_run_manifest != run_paths.last_run_manifest.resolve():
        raise RuntimeError(
            "Persisted soak observer last-run path mismatches the campaign."
        )

    launcher_identity = persisted_soak_controller.exact_identity_payload(
        manifest.get("launcher")
    )
    if launcher_identity is None:
        raise RuntimeError("Persisted soak observer launcher identity is invalid.")
    preflight = manifest.get("preflight")
    control = preflight.get("control") if isinstance(preflight, dict) else None
    if not isinstance(control, dict):
        raise RuntimeError("Persisted soak observer REST authority is invalid.")
    rust_base_url = control.get("rustBaseUrl")
    mfc_base_url = control.get("mfcBaseUrl")
    if not isinstance(rust_base_url, str) or not rust_base_url.strip():
        raise RuntimeError("Persisted soak observer Rust REST authority is invalid.")
    if not isinstance(mfc_base_url, str) or not mfc_base_url.strip():
        raise RuntimeError("Persisted soak observer MFC REST authority is invalid.")

    return ObserverRuntime(
        session_manifest=resolved_manifest,
        stop_file=stop_file,
        last_run_manifest=last_run_manifest,
        run_paths=run_paths,
        store=soak_storage.BoundedArtifactStore(storage.root, storage.policy),
        launcher_identity=launcher_identity,
        rust_base_url=rust_base_url,
        mfc_base_url=mfc_base_url,
        action_config=parse_action_config(observer_config),
    )


def launcher_is_alive(identity: dict[str, Any]) -> bool:
    """Returns whether the exact controller-owned launcher still exists."""

    from . import persisted_soak_controller, windows_processes

    return (
        persisted_soak_controller.exact_process_row(
            identity,
            windows_processes.collect_processes(),
        )
        is not None
    )


def load_ready_manifest(runtime: ObserverRuntime) -> dict[str, Any] | None:
    """Returns the matching running launcher manifest when clients are ready."""

    if not runtime.last_run_manifest.is_file():
        return None
    manifest = load_json_object(runtime.last_run_manifest)
    if manifest.get("campaignId") != runtime.run_paths.campaign_id:
        return None
    if manifest.get("status") != "running":
        return None
    if (
        Path(str(manifest.get("campaignDir") or "")).resolve()
        != runtime.run_paths.campaign_dir.resolve()
    ):
        raise RuntimeError("Running soak manifest campaign path is invalid.")
    return manifest


def diagnostic_writer_health(base_url: str, api_key: str) -> dict[str, Any]:
    """Loads one complete healthy diagnostic writer payload."""

    payload = http_json(
        base_url,
        "/diagnostics",
        api_key=api_key,
        timeout_seconds=5.0,
    )
    data = api_data(payload)
    health = data.get("diagnosticWriter") if isinstance(data, dict) else None
    violations = diag_event_runs.diagnostic_writer_health_violations(health)
    if violations:
        raise RuntimeError(
            "Diagnostic writer is not lossless: " + "; ".join(violations)
        )
    if not isinstance(health, dict):
        raise RuntimeError("Diagnostic writer payload is not an object.")
    return dict(health)


def load_state(runtime: ObserverRuntime) -> dict[str, Any]:
    """Loads the cumulative state or creates the first state for this campaign."""

    summary_path = runtime.run_paths.report_dir / "summary.json"
    if not summary_path.is_file():
        return converged_observer_state.new_state(
            runtime.run_paths.campaign_id,
            recent_action_limit=DEFAULT_RECENT_ACTION_LIMIT,
            recent_anomaly_limit=DEFAULT_RECENT_ANOMALY_LIMIT,
        )
    return converged_observer_state.validate_state(load_json_object(summary_path))


def capture_checkpoint(
    runtime: ObserverRuntime,
    state: dict[str, Any],
    *,
    observed_at: datetime | None = None,
    now_ns: int | None = None,
) -> dict[str, Any]:
    """Captures and persists one bounded observer checkpoint and cumulative state."""

    rust_health = diagnostic_writer_health(
        runtime.rust_base_url,
        soak_launch.RUST_API_KEY,
    )
    mfc_health = diagnostic_writer_health(
        runtime.mfc_base_url,
        soak_launch.MFC_API_KEY,
    )
    timestamp = (observed_at or datetime.now(UTC)).astimezone(UTC).isoformat()
    checkpoint = {
        "schema": "soak_checkpoint_v1",
        "campaignId": runtime.run_paths.campaign_id,
        "ts_utc": timestamp,
        "rustAlive": True,
        "packetRecords": {
            "rust": rust_health["recordsWritten"],
            "mfc": mfc_health["recordsWritten"],
        },
        "diagnosticWriters": {
            "rust": rust_health,
            "mfc": mfc_health,
        },
        "totals": {
            "actions": converged_observer_state.validate_state(state)["totals"][
                "actions"
            ]
        },
    }
    persisted = soak_run_layout.persist_observer_checkpoint(
        paths=runtime.run_paths,
        store=runtime.store,
        checkpoint=checkpoint,
        now_ns=now_ns,
    )
    updated = converged_observer_state.record_checkpoint(state, checkpoint)
    updated = converged_observer_state.record_stream_retention(
        updated,
        stream="checkpoints",
        persisted=persisted,
    )
    soak_run_layout.persist_observer_summary(
        paths=runtime.run_paths,
        store=runtime.store,
        summary=updated,
        now_ns=now_ns,
    )
    return updated


def persist_state(
    runtime: ObserverRuntime,
    state: dict[str, Any],
    *,
    now_ns: int | None = None,
) -> dict[str, Any]:
    """Validates and atomically persists the cumulative observer state."""

    validated = converged_observer_state.validate_state(
        state,
        campaign_id=runtime.run_paths.campaign_id,
    )
    soak_run_layout.persist_observer_summary(
        paths=runtime.run_paths,
        store=runtime.store,
        summary=validated,
        now_ns=now_ns,
    )
    return validated


def utc_now() -> datetime:
    return datetime.now(UTC)


def capture_action_cycle(
    runtime: ObserverRuntime,
    state: dict[str, Any],
    config: ObserverActionConfig,
    *,
    now_utc: Callable[[], datetime] = utc_now,
    now_ns: int | None = None,
) -> dict[str, Any]:
    """Issues and records one synchronized search without owning either client."""

    validated = converged_observer_state.validate_state(
        state,
        campaign_id=runtime.run_paths.campaign_id,
    )
    if not config.enabled or not config.terms:
        raise RuntimeError("Observer action driving is not enabled.")
    cycle_index = int(validated["driver"]["cycles"]) + 1
    query = config.terms[(cycle_index - 1) % len(config.terms)]
    started_at = now_utc().astimezone(UTC).isoformat()
    rust_client = converged_action_driver.ClientEndpoint(
        name="rust",
        base_url=runtime.rust_base_url,
        api_key=soak_launch.RUST_API_KEY,
    )
    mfc_client = converged_action_driver.ClientEndpoint(
        name="mfc",
        base_url=runtime.mfc_base_url,
        api_key=soak_launch.MFC_API_KEY,
    )
    try:
        cycle = converged_action_driver.drive_automatic_cycle(
            cycle_index=cycle_index,
            query=query,
            method=config.method,
            rust=rust_client,
            mfc=mfc_client,
            safety=None,
            download=False,
            search_timeout_seconds=config.search_timeout_seconds,
        )
    except Exception as error:  # noqa: BLE001 - persist live action failures and continue the soak
        cycle = {
            "cycle": cycle_index,
            "queryIndex": cycle_index - 1,
            "method": config.method,
            "query": query,
            "downloadRequested": False,
            "error": f"{type(error).__name__}: {error}",
        }
    cycle["startedAtUtc"] = started_at
    cycle["completedAtUtc"] = now_utc().astimezone(UTC).isoformat()
    updated = converged_observer_state.record_driver_cycle(validated, cycle)
    return persist_state(runtime, updated, now_ns=now_ns)


def run_observer(
    runtime: ObserverRuntime,
    *,
    ready_timeout_seconds: float,
    poll_interval_seconds: float,
    checkpoint_interval_seconds: float,
    failure_threshold: int,
    max_checkpoints: int = 0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    launcher_alive: Callable[[dict[str, Any]], bool] = launcher_is_alive,
    capture: Callable[..., dict[str, Any]] = capture_checkpoint,
    drive_action: Callable[..., dict[str, Any]] = capture_action_cycle,
) -> dict[str, Any]:
    """Runs one attach-only observer until the shared stop contract is requested."""

    if ready_timeout_seconds <= 0:
        raise ValueError("ready_timeout_seconds must be greater than zero.")
    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be greater than zero.")
    if checkpoint_interval_seconds <= 0:
        raise ValueError("checkpoint_interval_seconds must be greater than zero.")
    if failure_threshold <= 0:
        raise ValueError("failure_threshold must be greater than zero.")
    if max_checkpoints < 0:
        raise ValueError("max_checkpoints must be zero or greater.")

    ready_deadline = monotonic() + ready_timeout_seconds
    while load_ready_manifest(runtime) is None:
        if runtime.stop_file.exists():
            return load_state(runtime)
        if not launcher_alive(runtime.launcher_identity):
            raise RuntimeError(
                "Persisted soak launcher exited before observer readiness."
            )
        if monotonic() >= ready_deadline:
            raise RuntimeError(
                "Timed out waiting for the persisted soak campaign to become ready."
            )
        sleep(poll_interval_seconds)

    state = load_state(runtime)
    checkpoint_count = 0
    consecutive_failures = 0
    next_checkpoint = monotonic()
    next_action = (
        monotonic() + runtime.action_config.start_delay_seconds
        if runtime.action_config.enabled
        else float("inf")
    )
    while True:
        if runtime.stop_file.exists():
            return state
        if not launcher_alive(runtime.launcher_identity):
            raise RuntimeError(
                "Persisted soak launcher exited while observer was attached."
            )
        now = monotonic()
        checkpoint_failed = False
        if now >= next_checkpoint:
            try:
                state = capture(runtime, state)
            except Exception:
                consecutive_failures += 1
                if consecutive_failures >= failure_threshold:
                    raise
                next_checkpoint = now + poll_interval_seconds
                checkpoint_failed = True
            else:
                consecutive_failures = 0
                checkpoint_count += 1
                if max_checkpoints and checkpoint_count >= max_checkpoints:
                    return state
                next_checkpoint = now + checkpoint_interval_seconds
        if checkpoint_failed:
            sleep(min(poll_interval_seconds, max(next_checkpoint - monotonic(), 0.0)))
            continue

        action_config = runtime.action_config
        action_cycles = int(state["driver"]["cycles"])
        action_limit_reached = bool(
            action_config.max_cycles and action_cycles >= action_config.max_cycles
        )
        if action_limit_reached:
            next_action = float("inf")
        elif action_config.enabled and now >= next_action:
            state = drive_action(runtime, state, action_config)
            next_action = monotonic() + action_config.search_interval_seconds

        next_due = min(next_checkpoint, next_action)
        sleep(min(poll_interval_seconds, max(next_due - monotonic(), 0.0)))


def build_parser() -> argparse.ArgumentParser:
    """Builds the attach-only observer CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-manifest", type=Path, required=True)
    parser.add_argument(
        "--ready-timeout-seconds",
        type=float,
        default=DEFAULT_READY_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--checkpoint-interval-seconds",
        type=float,
        default=DEFAULT_CHECKPOINT_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--failure-threshold",
        type=int,
        default=DEFAULT_FAILURE_THRESHOLD,
    )
    parser.add_argument("--max-checkpoints", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the bounded attach-only converged observer."""

    args = build_parser().parse_args(argv)
    runtime = load_runtime(args.session_manifest, get_workspace_output_root())
    state = run_observer(
        runtime,
        ready_timeout_seconds=args.ready_timeout_seconds,
        poll_interval_seconds=args.poll_interval_seconds,
        checkpoint_interval_seconds=args.checkpoint_interval_seconds,
        failure_threshold=args.failure_threshold,
        max_checkpoints=args.max_checkpoints,
    )
    print(
        json.dumps(
            {
                "campaignId": state["campaignId"],
                "checkpoints": state["checkpoints"]["count"],
                "actions": state["totals"]["actions"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
