"""Attach-only bounded observer for one persisted diagnostics soak campaign."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from . import (
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
    while True:
        if runtime.stop_file.exists():
            return state
        if not launcher_alive(runtime.launcher_identity):
            raise RuntimeError(
                "Persisted soak launcher exited while observer was attached."
            )
        now = monotonic()
        if now >= next_checkpoint:
            try:
                state = capture(runtime, state)
            except Exception:
                consecutive_failures += 1
                if consecutive_failures >= failure_threshold:
                    raise
                next_checkpoint = now + poll_interval_seconds
            else:
                consecutive_failures = 0
                checkpoint_count += 1
                if max_checkpoints and checkpoint_count >= max_checkpoints:
                    return state
                next_checkpoint = now + checkpoint_interval_seconds
        sleep(min(poll_interval_seconds, max(next_checkpoint - monotonic(), 0.0)))


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
