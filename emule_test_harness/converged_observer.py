"""Attach-only bounded observer for one persisted diagnostics soak campaign."""

from __future__ import annotations

import argparse
import hashlib
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
    observer_action_evidence,
    observer_action_report,
    soak_action_diff,
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
class DiagnosticDirectories:
    """Manifest-authoritative profile directories containing live diagnostics."""

    rust: Path
    mfc: Path


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
    diagnostic_directories: DiagnosticDirectories
    action_config: ObserverActionConfig = ObserverActionConfig()


def action_configuration_digest(config: ObserverActionConfig) -> str:
    """Returns the stable identity of one validated action-driving schedule."""

    payload = {
        "enabled": config.enabled,
        "sourceProfile": config.source_profile,
        "terms": list(config.terms),
        "method": config.method,
        "startDelaySeconds": config.start_delay_seconds,
        "searchIntervalSeconds": config.search_interval_seconds,
        "searchTimeoutSeconds": config.search_timeout_seconds,
        "maxCycles": config.max_cycles,
    }
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
    diagnostic_dirs = diagnostic_profile_directories(preflight)

    return ObserverRuntime(
        session_manifest=resolved_manifest,
        stop_file=stop_file,
        last_run_manifest=last_run_manifest,
        run_paths=run_paths,
        store=soak_storage.BoundedArtifactStore(storage.root, storage.policy),
        launcher_identity=launcher_identity,
        rust_base_url=rust_base_url,
        mfc_base_url=mfc_base_url,
        diagnostic_directories=diagnostic_dirs,
        action_config=parse_action_config(observer_config),
    )


def diagnostic_profile_directories(preflight: object) -> DiagnosticDirectories:
    """Returns live diagnostic directories from the persisted profile authority."""

    if not isinstance(preflight, dict):
        raise RuntimeError("Persisted soak observer preflight authority is invalid.")
    profiles = preflight.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != {"rust", "mfc"}:
        raise RuntimeError("Persisted soak observer diagnostic profiles are invalid.")

    resolved: dict[str, Path] = {}
    for client in ("rust", "mfc"):
        value = profiles[client]
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(
                f"Persisted soak observer {client} diagnostic profile is invalid."
            )
        profile = Path(value).resolve()
        if not profile.is_dir():
            raise RuntimeError(
                f"Persisted soak observer {client} diagnostic profile does not exist: "
                f"{profile}"
            )
        resolved[client] = profile
    return DiagnosticDirectories(
        rust=(resolved["rust"] / "packet-dump").resolve(),
        mfc=(resolved["mfc"] / "logs").resolve(),
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
    configuration_digest = action_configuration_digest(runtime.action_config)
    if not summary_path.is_file():
        return converged_observer_state.new_state(
            runtime.run_paths.campaign_id,
            configuration_digest=configuration_digest,
            recent_action_limit=DEFAULT_RECENT_ACTION_LIMIT,
            recent_anomaly_limit=DEFAULT_RECENT_ANOMALY_LIMIT,
        )
    return converged_observer_state.validate_state(
        load_json_object(summary_path),
        campaign_id=runtime.run_paths.campaign_id,
        configuration_digest=configuration_digest,
    )


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
            "actions": converged_observer_state.validate_state(
                state,
                campaign_id=runtime.run_paths.campaign_id,
                configuration_digest=action_configuration_digest(runtime.action_config),
            )["totals"]["actions"]
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
        configuration_digest=action_configuration_digest(runtime.action_config),
    )
    soak_run_layout.persist_observer_summary(
        paths=runtime.run_paths,
        store=runtime.store,
        summary=validated,
        now_ns=now_ns,
    )
    return validated


def capture_pending_action_evidence(
    runtime: ObserverRuntime,
    pending_action: dict[str, Any],
) -> observer_action_evidence.ActionDiagnosticEvidence:
    """Captures one pending action from only its persisted run and window authority."""

    pending_evidence = pending_action.get("evidence")
    if not isinstance(pending_evidence, dict):
        raise RuntimeError("Observer pending action has no evidence window.")
    diagnostic_runs = pending_action.get("diagnosticRuns")
    if not isinstance(diagnostic_runs, dict):
        raise RuntimeError("Observer pending action has no diagnostic run authority.")
    window = soak_action_diff.ActionWindow.from_utc_strings(
        pending_action.get("reservedAtUtc"),
        pending_evidence.get("windowEndUtc"),
    )

    sources = {}
    for client in ("rust", "mfc"):
        identity = diagnostic_runs.get(client)
        if not isinstance(identity, dict):
            raise RuntimeError(
                f"Observer pending action {client} diagnostic identity is invalid."
            )
        sources[client] = observer_action_evidence.PinnedDiagnosticRun(
            client=client,
            directory=getattr(runtime.diagnostic_directories, client),
            process_id=identity.get("processId"),
            run_id=identity.get("runId"),
        )
    return observer_action_evidence.capture_action_diagnostic_evidence(
        window=window,
        rust=sources["rust"],
        mfc=sources["mfc"],
    )


def finalize_pending_action(
    runtime: ObserverRuntime,
    state: dict[str, Any],
    *,
    now_ns: int | None = None,
) -> dict[str, Any]:
    """Persists one pending report before committing its cumulative state."""

    validated = converged_observer_state.validate_state(
        state,
        campaign_id=runtime.run_paths.campaign_id,
        configuration_digest=action_configuration_digest(runtime.action_config),
    )
    pending_action = validated["pendingAction"]
    if not isinstance(pending_action, dict):
        raise RuntimeError("Observer has no pending action to finalize.")
    if pending_action["driverOutcome"] is None or pending_action["evidence"] is None:
        raise RuntimeError("Observer pending action is not ready for finalization.")

    report_candidate = soak_run_layout.load_observer_action_report_candidate(
        paths=runtime.run_paths,
        pending_action=pending_action,
    )
    if report_candidate is None:
        evidence = capture_pending_action_evidence(runtime, pending_action)
        report = observer_action_report.build_observer_action_report(
            campaign_id=runtime.run_paths.campaign_id,
            pending_action=pending_action,
            evidence=evidence,
        )
    else:
        report = observer_action_report.validate_observer_action_report_for_pending(
            report_candidate,
            pending_action,
        )
    persisted = soak_run_layout.persist_observer_action_report(
        paths=runtime.run_paths,
        store=runtime.store,
        report=report,
        now_ns=now_ns,
    )
    updated = converged_observer_state.commit_action_report(validated, report)
    updated = converged_observer_state.record_stream_retention(
        updated,
        stream="actions",
        persisted=persisted,
    )
    soak_run_layout.persist_observer_summary(
        paths=runtime.run_paths,
        store=runtime.store,
        summary=updated,
        now_ns=now_ns,
    )
    return updated


def utc_now() -> datetime:
    return datetime.now(UTC)


def action_clients(
    runtime: ObserverRuntime,
) -> dict[str, converged_action_driver.ClientEndpoint]:
    """Returns the fixed Rust and MFC REST authorities for action driving."""

    return {
        "rust": converged_action_driver.ClientEndpoint(
            name="rust",
            base_url=runtime.rust_base_url,
            api_key=soak_launch.RUST_API_KEY,
        ),
        "mfc": converged_action_driver.ClientEndpoint(
            name="mfc",
            base_url=runtime.mfc_base_url,
            api_key=soak_launch.MFC_API_KEY,
        ),
    }


def action_diagnostic_runs(
    clients: dict[str, converged_action_driver.ClientEndpoint],
) -> dict[str, dict[str, Any]]:
    """Loads the exact healthy diagnostic run identity for both clients."""

    identities: dict[str, dict[str, Any]] = {}
    for name in ("rust", "mfc"):
        client = clients[name]
        health = diagnostic_writer_health(client.base_url, client.api_key)
        process_id = health.get("processId")
        run_id = health.get("runId")
        if (
            isinstance(process_id, bool)
            or not isinstance(process_id, int)
            or process_id <= 0
            or not isinstance(run_id, str)
            or not run_id.strip()
        ):
            raise RuntimeError(
                f"{name} diagnostic writer run identity is invalid: "
                f"processId={process_id!r}, runId={run_id!r}"
            )
        identities[name] = {"processId": process_id, "runId": run_id}
    return identities


def utc_text(now_utc: Callable[[], datetime]) -> str:
    """Returns one canonical UTC timestamp from the injected clock."""

    return now_utc().astimezone(UTC).isoformat()


def action_phase_error(
    client: str,
    *,
    error_type: str,
    message: str,
) -> dict[str, str]:
    """Returns one exact unredacted action-phase error."""

    return {
        "client": client,
        "phase": "search-create",
        "type": error_type,
        "message": message,
    }


def pending_cycle_payload(
    pending: dict[str, Any],
    *,
    completed_at_utc: str,
) -> dict[str, Any]:
    """Reconstructs one terminal driver cycle from durable phase outcomes."""

    searches: dict[str, dict[str, Any]] = {}
    search_ids: dict[str, str] = {}
    result_counts: dict[str, int] = {}
    errors: list[dict[str, Any]] = []
    for client in ("rust", "mfc"):
        client_state = pending["clients"][client]
        create = client_state["create"]
        if not isinstance(create, dict):
            raise RuntimeError(f"{client} search create is not terminal.")
        status = create["status"]
        if status == "succeeded":
            search_id = str(create["searchId"])
            create_record: dict[str, Any] = {"ok": True, "searchId": search_id}
            search_ids[client] = search_id
        elif status in {"failed", "skipped"}:
            error = create["error"]
            create_record = {"ok": False, "error": error}
            if status == "skipped":
                create_record["skipped"] = "fail-closed"
            errors.append(error)
        else:
            raise RuntimeError(f"{client} search create is not terminal.")

        results = client_state["results"]
        if status != "succeeded":
            results_record: dict[str, Any] = {
                "ok": False,
                "skipped": "search-create-failed",
            }
        elif not isinstance(results, dict):
            raise RuntimeError(f"{client} search results are not terminal.")
        elif results["error"] is not None:
            results_record = {
                "ok": False,
                "completed": results["completed"],
                "error": results["error"],
            }
            if results["resultCount"] is not None:
                results_record["count"] = results["resultCount"]
                result_counts[client] = results["resultCount"]
            errors.append(results["error"])
        else:
            result_count = results["resultCount"]
            results_record = {
                "ok": True,
                "count": result_count,
                "completed": results["completed"],
            }
            result_counts[client] = result_count
        searches[client] = {"create": create_record, "results": results_record}

    return {
        "cycle": pending["cycle"],
        "actionId": pending["actionId"],
        "queryIndex": pending["queryIndex"],
        "method": pending["method"],
        "query": pending["query"],
        "downloadRequested": False,
        "ok": not errors,
        "searches": searches,
        "searchIds": search_ids,
        "resultCounts": result_counts,
        "errors": errors,
        "startedAtUtc": pending["reservedAtUtc"],
        "completedAtUtc": completed_at_utc,
    }


def capture_action_cycle(
    runtime: ObserverRuntime,
    state: dict[str, Any],
    config: ObserverActionConfig,
    *,
    now_utc: Callable[[], datetime] = utc_now,
    now_ns: int | None = None,
    finalize_action: Callable[..., dict[str, Any]] = finalize_pending_action,
) -> dict[str, Any]:
    """Advances one crash-safe synchronized search without owning either client."""

    validated = converged_observer_state.validate_state(
        state,
        campaign_id=runtime.run_paths.campaign_id,
        configuration_digest=action_configuration_digest(runtime.action_config),
    )
    if not config.enabled or not config.terms:
        raise RuntimeError("Observer action driving is not enabled.")
    clients = action_clients(runtime)
    resumed = validated["pendingAction"] is not None
    if not resumed:
        cycle_index = int(validated["scheduler"]["nextCycle"])
        query = config.terms[(cycle_index - 1) % len(config.terms)]
        validated = converged_observer_state.set_next_action_deadline(validated, None)
        validated = converged_observer_state.reserve_driver_cycle(
            validated,
            query=query,
            method=config.method,
            reserved_at_utc=utc_text(now_utc),
            diagnostic_runs=action_diagnostic_runs(clients),
        )
        validated = persist_state(runtime, validated, now_ns=now_ns)

    pending = validated["pendingAction"]
    if not isinstance(pending, dict):
        raise RuntimeError("Observer action reservation was not persisted.")
    if pending["driverOutcome"] is not None:
        if pending["evidence"] is None:
            completed_at_utc = pending["driverOutcome"].get("completedAtUtc")
            if not isinstance(completed_at_utc, str) or not completed_at_utc.strip():
                completed_at_utc = utc_text(now_utc)
            validated = converged_observer_state.mark_evidence_pending(
                validated,
                window_end_utc=completed_at_utc,
            )
            validated = persist_state(runtime, validated, now_ns=now_ns)
        return finalize_action(runtime, validated, now_ns=now_ns)

    entry_creates = {
        client: pending["clients"][client]["create"] for client in ("rust", "mfc")
    }
    if resumed:
        for client, create in entry_creates.items():
            if isinstance(create, dict) and create.get("status") == "prepared":
                prepared_at_utc = create["preparedAtUtc"]
                validated = converged_observer_state.complete_search_create(
                    validated,
                    client=client,
                    completed_at_utc=utc_text(now_utc),
                    search_id=None,
                    error=action_phase_error(
                        client,
                        error_type="AmbiguousSearchCreate",
                        message=(
                            f"{client} search create was prepared at "
                            f"{prepared_at_utc} without a persisted terminal outcome; "
                            "the POST will not be replayed"
                        ),
                    ),
                )
                validated = persist_state(runtime, validated, now_ns=now_ns)

        if any(create is not None for create in entry_creates.values()):
            for client, create in entry_creates.items():
                if create is None:
                    validated = converged_observer_state.skip_search_create(
                        validated,
                        client=client,
                        completed_at_utc=utc_text(now_utc),
                        error=action_phase_error(
                            client,
                            error_type="SearchCreateSkipped",
                            message=(
                                f"{client} search create was not issued after restart "
                                "because the peer create phase had already started"
                            ),
                        ),
                    )
                    validated = persist_state(runtime, validated, now_ns=now_ns)

    pending = validated["pendingAction"]
    if not isinstance(pending, dict):
        raise RuntimeError(
            "Observer pending action disappeared during create recovery."
        )
    creates = [pending["clients"][client]["create"] for client in ("rust", "mfc")]
    prepared_now = all(create is None for create in creates)
    if prepared_now:
        prepared_at_utc = utc_text(now_utc)
        for client in ("rust", "mfc"):
            validated = converged_observer_state.prepare_search_create(
                validated,
                client=client,
                prepared_at_utc=prepared_at_utc,
            )
        validated = persist_state(runtime, validated, now_ns=now_ns)

        pending = validated["pendingAction"]
        if not isinstance(pending, dict):
            raise RuntimeError("Observer create intentions were not persisted.")
        for client in ("rust", "mfc"):
            phase = converged_action_driver.run_search_create_phase(
                clients[client],
                query=pending["query"],
                method=pending["method"],
            )
            validated = converged_observer_state.complete_search_create(
                validated,
                client=client,
                completed_at_utc=utc_text(now_utc),
                search_id=phase.search_id,
                error=phase.error,
            )
            validated = persist_state(runtime, validated, now_ns=now_ns)

    for client in ("rust", "mfc"):
        pending = validated["pendingAction"]
        if not isinstance(pending, dict):
            raise RuntimeError(
                "Observer pending action disappeared during result polling."
            )
        client_state = pending["clients"][client]
        create = client_state["create"]
        if (
            not isinstance(create, dict)
            or create.get("status") != "succeeded"
            or client_state["results"] is not None
        ):
            continue
        phase = converged_action_driver.run_search_results_phase(
            clients[client],
            str(create["searchId"]),
            timeout_seconds=config.search_timeout_seconds,
        )
        validated = converged_observer_state.record_search_results(
            validated,
            client=client,
            completed_at_utc=utc_text(now_utc),
            completed=phase.completed,
            result_count=len(phase.rows),
            error=phase.error,
        )
        validated = persist_state(runtime, validated, now_ns=now_ns)

    pending = validated["pendingAction"]
    if not isinstance(pending, dict):
        raise RuntimeError("Observer pending action disappeared before completion.")
    completed_at_utc = utc_text(now_utc)
    cycle = pending_cycle_payload(pending, completed_at_utc=completed_at_utc)
    validated = converged_observer_state.record_driver_cycle(validated, cycle)
    validated = persist_state(runtime, validated, now_ns=now_ns)
    validated = converged_observer_state.mark_evidence_pending(
        validated,
        window_end_utc=completed_at_utc,
    )
    validated = persist_state(runtime, validated, now_ns=now_ns)
    return finalize_action(runtime, validated, now_ns=now_ns)


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
        next_checkpoint
        if runtime.action_config.enabled and state["pendingAction"] is not None
        else next_checkpoint + runtime.action_config.start_delay_seconds
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
        has_pending_action = state["pendingAction"] is not None
        action_limit_reached = bool(
            action_config.max_cycles
            and action_cycles >= action_config.max_cycles
            and not has_pending_action
        )
        if action_config.enabled and has_pending_action:
            next_action = now
        elif action_limit_reached:
            next_action = float("inf")
        if action_config.enabled and now >= next_action:
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
