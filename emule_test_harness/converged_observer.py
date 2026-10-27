"""Attach-only bounded observer for one persisted diagnostics soak campaign."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
ACTION_RESULT_POLL_INTERVAL_SECONDS = 2.0
ACTION_RESULT_REQUEST_TIMEOUT_SECONDS = 30.0
ACTION_NETWORK_RECONNECT_TIMEOUT_SECONDS = 60.0
ACTION_NETWORK_RECONNECT_POLL_INTERVAL_SECONDS = 2.0
SUPPORTED_ACTION_METHODS = ("server", "global", "kad")
DEFAULT_ACTION_METHODS = ("server", "kad")


@dataclass(frozen=True)
class ObserverActionConfig:
    """Immutable synchronized search schedule owned by the observer."""

    enabled: bool = False
    source_profile: str | None = None
    terms: tuple[str, ...] = ()
    methods: tuple[str, ...] = DEFAULT_ACTION_METHODS
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
    rust_server_endpoint: str
    mfc_server_endpoint: str
    diagnostic_directories: DiagnosticDirectories
    action_config: ObserverActionConfig = ObserverActionConfig()


def action_configuration_digest(config: ObserverActionConfig) -> str:
    """Returns the stable identity of one validated action-driving schedule."""

    payload = {
        "enabled": config.enabled,
        "sourceProfile": config.source_profile,
        "terms": list(config.terms),
        "methods": list(config.methods),
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
        "methods",
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
    raw_methods = payload.get("methods")
    if not isinstance(raw_methods, list) or any(
        not isinstance(method, str) or method not in SUPPORTED_ACTION_METHODS
        for method in raw_methods
    ):
        raise RuntimeError("Persisted soak observer action methods are invalid.")
    methods = tuple(dict.fromkeys(raw_methods))
    if not methods:
        raise RuntimeError("Persisted soak observer action methods are empty.")
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
        methods=methods,
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
    rust_server_endpoint = control.get("rustServerEndpoint")
    mfc_server_endpoint = control.get("mfcServerEndpoint")
    if not isinstance(rust_base_url, str) or not rust_base_url.strip():
        raise RuntimeError("Persisted soak observer Rust REST authority is invalid.")
    if not isinstance(mfc_base_url, str) or not mfc_base_url.strip():
        raise RuntimeError("Persisted soak observer MFC REST authority is invalid.")
    if not isinstance(rust_server_endpoint, str):
        raise RuntimeError("Persisted soak observer Rust server endpoint is invalid.")
    if not isinstance(mfc_server_endpoint, str):
        raise RuntimeError("Persisted soak observer MFC server endpoint is invalid.")
    rust_server_endpoint = soak_launch.require_live_server_endpoint(
        rust_server_endpoint,
        label="Rust server endpoint",
    )
    mfc_server_endpoint = soak_launch.require_live_server_endpoint(
        mfc_server_endpoint,
        label="MFC server endpoint",
    )
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
        rust_server_endpoint=rust_server_endpoint,
        mfc_server_endpoint=mfc_server_endpoint,
        diagnostic_directories=diagnostic_dirs,
        action_config=parse_action_config(observer_config),
    )


def diagnostic_profile_directories(preflight: object) -> DiagnosticDirectories:
    """Returns authoritative diagnostic paths without requiring runtime creation."""

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
        resolved[client] = Path(value).resolve()
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

    if any(
        not directory.is_dir()
        for directory in (
            runtime.diagnostic_directories.rust,
            runtime.diagnostic_directories.mfc,
        )
    ):
        return None
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


def diagnostic_writer_health(
    base_url: str,
    api_key: str,
    *,
    attempts: int = 3,
    timeout_seconds: float = 15.0,
    retry_delay_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Loads one complete healthy diagnostic writer payload."""

    if attempts <= 0:
        raise ValueError("Diagnostic writer health attempts must be positive.")
    if timeout_seconds <= 0:
        raise ValueError("Diagnostic writer health timeout must be positive.")
    if retry_delay_seconds < 0:
        raise ValueError("Diagnostic writer health retry delay must not be negative.")
    payload: object | None = None
    for attempt in range(1, attempts + 1):
        try:
            payload = http_json(
                base_url,
                "/diagnostics",
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
            break
        except (OSError, RuntimeError) as error:
            if attempt == attempts:
                raise RuntimeError(
                    f"Diagnostic writer health failed after {attempts} attempts: {error}"
                ) from error
            sleep(retry_delay_seconds)
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
            server_endpoints={
                "rust": runtime.rust_server_endpoint,
                "mfc": runtime.mfc_server_endpoint,
            },
        )
    else:
        report = observer_action_report.validate_observer_action_report_for_pending(
            report_candidate,
            pending_action,
            server_endpoints={
                "rust": runtime.rust_server_endpoint,
                "mfc": runtime.mfc_server_endpoint,
            },
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
            api_root_url=runtime.rust_base_url,
            api_key=soak_launch.RUST_API_KEY,
        ),
        "mfc": converged_action_driver.ClientEndpoint(
            name="mfc",
            api_root_url=runtime.mfc_base_url,
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
        health = diagnostic_writer_health(client.api_root_url, client.api_key)
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


def classify_action_network_readiness(
    method: str,
    stats_by_client: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Requires both clients to be connected on the action's selected network."""

    required_field = {
        "server": "ed2kConnected",
        "global": "ed2kConnected",
        "kad": "kadConnected",
    }.get(method)
    if required_field is None:
        raise ValueError(f"unsupported observer action method: {method!r}")
    clients: dict[str, dict[str, Any]] = {}
    for name in ("rust", "mfc"):
        stats = stats_by_client.get(name)
        if not isinstance(stats, dict):
            raise RuntimeError(f"{name} action network stats are unavailable")
        clients[name] = {
            "ed2kConnected": stats.get("ed2kConnected"),
            "kadConnected": stats.get("kadConnected"),
            "ready": stats.get(required_field) is True,
        }
    return {
        "ok": all(client["ready"] for client in clients.values()),
        "method": method,
        "requiredField": required_field,
        "clients": clients,
    }


def action_network_readiness(
    clients: dict[str, converged_action_driver.ClientEndpoint],
    method: str,
) -> dict[str, Any]:
    """Loads and classifies exact REST connectivity before reserving an action."""

    stats_by_client: dict[str, dict[str, Any]] = {}
    for name in ("rust", "mfc"):
        client = clients[name]
        payload = http_json(
            client.api_root_url,
            "/stats",
            api_key=client.api_key,
            timeout_seconds=5.0,
        )
        data = api_data(payload)
        if not isinstance(data, dict):
            raise RuntimeError(f"{name} action network stats are not an object")
        stats_by_client[name] = data
    return classify_action_network_readiness(method, stats_by_client)


def rest_origin_url(api_root_url: str) -> str:
    """Returns the REST origin from one canonical `/api/v1` root URL."""

    suffix = "/api/v1"
    normalized = api_root_url.rstrip("/")
    if not normalized.endswith(suffix):
        raise RuntimeError(f"Observer REST root must end with {suffix}: {api_root_url!r}")
    return normalized[: -len(suffix)]


def repair_action_network(
    runtime: ObserverRuntime,
    clients: dict[str, converged_action_driver.ClientEndpoint],
    method: str,
    readiness: dict[str, Any],
    *,
    readiness_probe: Callable[
        [dict[str, converged_action_driver.ClientEndpoint], str], dict[str, Any]
    ] = action_network_readiness,
    timeout_seconds: float = ACTION_NETWORK_RECONNECT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = ACTION_NETWORK_RECONNECT_POLL_INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Reconnects disconnected eD2K clients and returns refreshed readiness."""

    if readiness.get("ok") is True or method not in {"server", "global"}:
        return {
            "attempted": False,
            "method": method,
            "clients": {},
            "readiness": copy.deepcopy(readiness),
        }
    if timeout_seconds <= 0:
        raise ValueError("Action network reconnect timeout must be positive.")
    if poll_interval_seconds <= 0:
        raise ValueError("Action network reconnect poll interval must be positive.")

    endpoints = {
        "rust": runtime.rust_server_endpoint,
        "mfc": runtime.mfc_server_endpoint,
    }
    attempts: dict[str, dict[str, Any]] = {}
    readiness_clients = readiness.get("clients")
    if not isinstance(readiness_clients, dict):
        raise RuntimeError("Action network readiness clients are invalid.")
    for name in ("rust", "mfc"):
        client_readiness = readiness_clients.get(name)
        if not isinstance(client_readiness, dict):
            raise RuntimeError(f"Action network readiness for {name} is invalid.")
        if client_readiness.get("ready") is True:
            continue
        client = clients[name]
        try:
            result = soak_launch.connect_operator_server(
                rest_origin_url(client.api_root_url),
                client.api_key,
                description=f"observer {name} server reconnect",
                endpoint=endpoints[name],
                name=f"persisted-soak-{name}",
            )
        except (OSError, RuntimeError, ValueError) as error:
            attempts[name] = {
                "ok": False,
                "endpoint": endpoints[name],
                "error": {
                    "type": type(error).__name__,
                    "message": str(error),
                },
            }
        else:
            attempts[name] = {
                "ok": True,
                "endpoint": endpoints[name],
                "response": copy.deepcopy(result),
            }

    refreshed = readiness_probe(clients, method)
    deadline = monotonic() + timeout_seconds
    while refreshed.get("ok") is not True and monotonic() < deadline:
        sleep(min(poll_interval_seconds, max(deadline - monotonic(), 0.0)))
        refreshed = readiness_probe(clients, method)
    return {
        "attempted": bool(attempts),
        "method": method,
        "clients": attempts,
        "readiness": copy.deepcopy(refreshed),
    }


def utc_text(now_utc: Callable[[], datetime]) -> str:
    """Returns one canonical UTC timestamp from the injected clock."""

    return utc_datetime(now_utc).isoformat()


def utc_datetime(now_utc: Callable[[], datetime]) -> datetime:
    """Returns one aware UTC datetime from the injected wall clock."""

    current = now_utc()
    if not isinstance(current, datetime) or current.utcoffset() is None:
        raise RuntimeError("Observer wall clock must return an aware datetime.")
    return current.astimezone(UTC)


def action_cycle_limit_reached(
    state: dict[str, Any], config: ObserverActionConfig
) -> bool:
    """Returns whether no additional action cycle may be reserved."""

    return bool(
        config.max_cycles
        and int(state["driver"]["cycles"]) >= config.max_cycles
        and state["pendingAction"] is None
    )


def reconcile_action_deadline(
    runtime: ObserverRuntime,
    state: dict[str, Any],
    *,
    now_utc: Callable[[], datetime] = utc_now,
    after_action: bool = False,
    now_ns: int | None = None,
) -> dict[str, Any]:
    """Persists the one authoritative UTC deadline when scheduling is eligible."""

    validated = converged_observer_state.validate_state(
        state,
        campaign_id=runtime.run_paths.campaign_id,
        configuration_digest=action_configuration_digest(runtime.action_config),
    )
    config = runtime.action_config
    current_deadline = validated["scheduler"]["nextActionAtUtc"]
    scheduling_enabled = bool(
        config.enabled
        and validated["pendingAction"] is None
        and not action_cycle_limit_reached(validated, config)
    )
    if not scheduling_enabled:
        desired_deadline = None
    elif current_deadline is not None and not after_action:
        return validated
    else:
        delay_seconds = (
            config.search_interval_seconds
            if after_action or int(validated["driver"]["cycles"]) > 0
            else config.start_delay_seconds
        )
        desired_deadline = (
            utc_datetime(now_utc) + timedelta(seconds=delay_seconds)
        ).isoformat()
    if current_deadline == desired_deadline:
        return validated
    updated = converged_observer_state.set_next_action_deadline(
        validated,
        desired_deadline,
    )
    return persist_state(runtime, updated, now_ns=now_ns)


def action_due_in_seconds(
    state: dict[str, Any],
    config: ObserverActionConfig,
    *,
    now_utc: Callable[[], datetime] = utc_now,
) -> float:
    """Returns wall-clock seconds until the next persisted action is due."""

    validated = converged_observer_state.validate_state(state)
    if not config.enabled or action_cycle_limit_reached(validated, config):
        return float("inf")
    pending = validated["pendingAction"]
    if isinstance(pending, dict):
        poll_deadlines = []
        for client in ("rust", "mfc"):
            result_poll = pending["clients"][client]["resultPoll"]
            if isinstance(result_poll, dict):
                poll_deadlines.append(
                    soak_action_diff.parse_utc_timestamp(
                        result_poll["nextAttemptAtUtc"],
                        label=f"observer {client} result poll next attempt",
                    )
                )
        if not poll_deadlines:
            return 0.0
        now = utc_datetime(now_utc)
        return max((min(poll_deadlines) - now).total_seconds(), 0.0)
    deadline_text = validated["scheduler"]["nextActionAtUtc"]
    if not isinstance(deadline_text, str):
        raise RuntimeError("Observer action deadline is not reconciled.")
    deadline = soak_action_diff.parse_utc_timestamp(
        deadline_text,
        label="observer next action deadline",
    )
    return max((deadline - utc_datetime(now_utc)).total_seconds(), 0.0)


def scheduled_action(config: ObserverActionConfig, schedule_slot: int) -> tuple[str, str]:
    """Returns the query and method for one positive observer schedule slot."""

    if schedule_slot <= 0:
        raise ValueError("observer action schedule slot must be positive")
    if not config.terms or not config.methods:
        raise ValueError("observer action schedule must contain terms and methods")
    offset = schedule_slot - 1
    method_count = len(config.methods)
    query = config.terms[(offset // method_count) % len(config.terms)]
    method = config.methods[offset % method_count]
    return query, method


def action_phase_error(
    client: str,
    *,
    phase: str = "search-create",
    error_type: str,
    message: str,
) -> dict[str, str]:
    """Returns one exact unredacted action-phase error."""

    return {
        "client": client,
        "phase": phase,
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
    returned_counts: dict[str, int] = {}
    result_totals: dict[str, int] = {}
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
            if results["totalCount"] is not None:
                results_record["returnedCount"] = results["returnedCount"]
                results_record["totalCount"] = results["totalCount"]
                returned_counts[client] = results["returnedCount"]
                result_totals[client] = results["totalCount"]
            errors.append(results["error"])
        else:
            results_record = {
                "ok": True,
                "returnedCount": results["returnedCount"],
                "totalCount": results["totalCount"],
                "completed": results["completed"],
            }
            returned_counts[client] = results["returnedCount"]
            result_totals[client] = results["totalCount"]
        if status == "succeeded":
            results_record["poll"] = copy.deepcopy(results["poll"])
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
        "returnedCounts": returned_counts,
        "resultTotals": result_totals,
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
    readiness_probe: Callable[
        [dict[str, converged_action_driver.ClientEndpoint], str], dict[str, Any]
    ]
    | None = None,
    network_repair: Callable[..., dict[str, Any]] = repair_action_network,
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
        schedule_slot = int(validated["scheduler"]["nextScheduleSlot"])
        query, method = scheduled_action(config, schedule_slot)
        probe = readiness_probe or action_network_readiness
        try:
            readiness = probe(clients, method)
        except (OSError, RuntimeError) as error:
            skipped = converged_observer_state.record_connectivity_skip(
                validated,
                {
                    "attemptedAtUtc": utc_text(now_utc),
                    "phase": "network_readiness",
                    "method": method,
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                },
            )
            return persist_state(runtime, skipped, now_ns=now_ns)
        repair: dict[str, Any] | None = None
        if readiness.get("ok") is not True:
            try:
                repair = network_repair(
                    runtime,
                    clients,
                    method,
                    readiness,
                    readiness_probe=probe,
                )
            except (OSError, RuntimeError, ValueError) as error:
                skipped = converged_observer_state.record_connectivity_skip(
                    validated,
                    {
                        "attemptedAtUtc": utc_text(now_utc),
                        "phase": "network_repair",
                        "method": method,
                        "readiness": copy.deepcopy(readiness),
                        "error": {
                            "type": type(error).__name__,
                            "message": str(error),
                        },
                    },
                )
                return persist_state(runtime, skipped, now_ns=now_ns)
            refreshed = repair.get("readiness")
            if not isinstance(refreshed, dict):
                raise RuntimeError("Action network repair readiness is invalid.")
            readiness = refreshed
        if readiness.get("ok") is not True:
            skip = {
                "attemptedAtUtc": utc_text(now_utc),
                "phase": "network_readiness",
                "method": method,
                "readiness": copy.deepcopy(readiness),
            }
            if repair is not None and repair.get("attempted") is True:
                skip["repair"] = copy.deepcopy(repair)
            skipped = converged_observer_state.record_connectivity_skip(
                validated,
                skip,
            )
            return persist_state(runtime, skipped, now_ns=now_ns)
        try:
            diagnostic_runs = action_diagnostic_runs(clients)
        except (OSError, RuntimeError) as error:
            skipped = converged_observer_state.record_connectivity_skip(
                validated,
                {
                    "attemptedAtUtc": utc_text(now_utc),
                    "phase": "diagnostic_run_identity",
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                },
            )
            return persist_state(runtime, skipped, now_ns=now_ns)
        validated = converged_observer_state.reserve_driver_cycle(
            validated,
            query=query,
            method=method,
            reserved_at_utc=utc_text(now_utc),
            diagnostic_runs=diagnostic_runs,
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

    polls_started = False
    for client in ("rust", "mfc"):
        pending = validated["pendingAction"]
        if not isinstance(pending, dict):
            raise RuntimeError(
                "Observer pending action disappeared before result polling."
            )
        client_state = pending["clients"][client]
        create = client_state["create"]
        if (
            not isinstance(create, dict)
            or create.get("status") != "succeeded"
            or client_state["results"] is not None
            or client_state["resultPoll"] is not None
        ):
            continue
        started_at = soak_action_diff.parse_utc_timestamp(
            create["completedAtUtc"],
            label=f"observer {client} search create completion",
        )
        validated = converged_observer_state.start_search_results_poll(
            validated,
            client=client,
            started_at_utc=started_at.isoformat(),
            deadline_utc=(
                started_at + timedelta(seconds=config.search_timeout_seconds)
            ).isoformat(),
        )
        polls_started = True
    if polls_started:
        validated = persist_state(runtime, validated, now_ns=now_ns)

    for client in ("rust", "mfc"):
        pending = validated["pendingAction"]
        if not isinstance(pending, dict):
            raise RuntimeError(
                "Observer pending action disappeared during result polling."
            )
        result_poll = pending["clients"][client]["resultPoll"]
        if not isinstance(result_poll, dict):
            continue
        observed_at = utc_datetime(now_utc)
        deadline = soak_action_diff.parse_utc_timestamp(
            result_poll["deadlineUtc"],
            label=f"observer {client} result poll deadline",
        )
        if observed_at >= deadline:
            expiration_error = None
            if (
                result_poll["lastObservedTotalCount"] is None
                and result_poll["lastAttemptError"] is None
            ):
                expiration_error = action_phase_error(
                    client,
                    phase="search-results",
                    error_type="SearchResultsDeadlineElapsed",
                    message=(
                        f"{client} search results deadline {deadline.isoformat()} "
                        "elapsed without a persisted result attempt"
                    ),
                )
            validated = converged_observer_state.expire_search_results_poll(
                validated,
                client=client,
                completed_at_utc=observed_at.isoformat(),
                error=expiration_error,
            )
            validated = persist_state(runtime, validated, now_ns=now_ns)
            break
        next_attempt = soak_action_diff.parse_utc_timestamp(
            result_poll["nextAttemptAtUtc"],
            label=f"observer {client} result poll next attempt",
        )
        if observed_at < next_attempt:
            continue
        phase = converged_action_driver.run_search_results_poll_phase(
            clients[client],
            str(pending["clients"][client]["create"]["searchId"]),
            timeout_seconds=min(
                ACTION_RESULT_REQUEST_TIMEOUT_SECONDS,
                (deadline - observed_at).total_seconds(),
            ),
        )
        attempted_at = utc_datetime(now_utc)
        completed_before_deadline = phase.completed and attempted_at < deadline
        terminal = completed_before_deadline or attempted_at >= deadline
        next_attempt_at = None
        if not terminal:
            next_attempt_at = min(
                attempted_at + timedelta(seconds=ACTION_RESULT_POLL_INTERVAL_SECONDS),
                deadline,
            ).isoformat()
        validated = converged_observer_state.record_search_results_poll_attempt(
            validated,
            client=client,
            attempted_at_utc=attempted_at.isoformat(),
            next_attempt_at_utc=next_attempt_at,
            completed=completed_before_deadline,
            returned_count=None if phase.error is not None else len(phase.rows),
            total_count=phase.total,
            error=phase.error,
        )
        validated = persist_state(runtime, validated, now_ns=now_ns)
        break

    pending = validated["pendingAction"]
    if not isinstance(pending, dict):
        raise RuntimeError("Observer pending action disappeared after result polling.")
    if any(
        not converged_observer_state.pending_client_is_terminal(pending, client)
        for client in ("rust", "mfc")
    ):
        return validated

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
    now_utc: Callable[[], datetime] = utc_now,
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

    state = reconcile_action_deadline(
        runtime,
        load_state(runtime),
        now_utc=now_utc,
    )
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
        action_delay = action_due_in_seconds(
            state,
            action_config,
            now_utc=now_utc,
        )
        if action_delay <= 0:
            state = drive_action(runtime, state, action_config)
            state = reconcile_action_deadline(
                runtime,
                state,
                now_utc=now_utc,
                after_action=True,
            )
            action_delay = action_due_in_seconds(
                state,
                action_config,
                now_utc=now_utc,
            )

        checkpoint_delay = max(next_checkpoint - monotonic(), 0.0)
        sleep(min(poll_interval_seconds, checkpoint_delay, action_delay))


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
