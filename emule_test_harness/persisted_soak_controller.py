"""Detached control for persisted full-tunnel Rust and MFC diagnostics soaks."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from . import converged_live_wire as clw
from . import (
    converged_observer,
    diag_event_runs,
    diagnostic_run_scan,
    hideme_vpn,
    soak_launch,
    soak_report_summary,
    soak_run_layout,
    soak_storage,
    windows_processes,
)
from .live_wire_inputs import LiveWireInputs, load_live_wire_inputs
from .paths import get_workspace_output_root, path_is_relative_to
from .vm_guest_profiles import api_data, http_json

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_SCRIPT = REPO_ROOT / "scripts" / "persisted-soak-control.py"
LAUNCH_SCRIPT = REPO_ROOT / "scripts" / "launch-soak.py"
BOUNDED_PROCESS_SCRIPT = REPO_ROOT / "scripts" / "run-bounded-process.py"
OBSERVER_SCRIPT = REPO_ROOT / "scripts" / "converged-soak-observer.py"
MANIFEST_SCHEMA = "emulebb.persisted-soak-session.v3"
STATUS_SCHEMA = "emulebb.persisted-soak-status.v2"
WATCH_SCHEMA = "emulebb.persisted-soak-watch.v1"
DEFAULT_CONTROL_BIND = "127.0.0.1"
DEFAULT_WATCH_INTERVAL_SECONDS = 60.0
DEFAULT_WATCH_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_WATCH_SEGMENTS = 4
WATCH_FAILURE_GRACE_SECONDS = 15.0
STORAGE_FAILURE_FINDING = "campaign-storage-enforcement-failed"
DIAGNOSTIC_WRITER_FAILURE_FINDINGS = frozenset(
    {
        "rust-diagnostic-writer-unhealthy",
        "mfc-diagnostic-writer-unhealthy",
    }
)
POST_READINESS_IMMEDIATE_FAILURE_FINDINGS = frozenset(
    {
        *DIAGNOSTIC_WRITER_FAILURE_FINDINGS,
        "launcher-not-running",
        "observer-not-running",
        "rust-process-count",
        "mfc-process-count",
        "rust-vpn-guard-unhealthy",
        "mfc-vpn-guard-unhealthy",
        "rust-p2p-binding-unhealthy",
        "mfc-p2p-binding-unhealthy",
        "full-tunnel-unhealthy",
    }
)
CONSECUTIVE_FAILURE_THRESHOLDS = {
    "rust-rest-unhealthy": 3,
    "mfc-rest-unhealthy": 3,
    "rust-diagnostic-writer-unavailable": 3,
    "mfc-diagnostic-writer-unavailable": 3,
}
WATCH_HEARTBEAT_MIN_STALE_SECONDS = 30.0
DIAGNOSTIC_INDEX_FILE_NAME = "diagnostic-run-index.json"
_EVIDENCE_PIN_FIELDS = frozenset(
    {
        "segmentId",
        "fileName",
        "source",
        "destination",
        "bytes",
        "sha256",
        "priority",
        "reasons",
        "pinnedUtc",
    }
)


@dataclass(frozen=True)
class ControlPaths:
    """Stable output-root paths for one detached soak session."""

    control_dir: Path
    manifest: Path
    stop_file: Path
    watch_stop_file: Path
    watch_jsonl: Path
    watch_heartbeat: Path
    last_run_manifest: Path


@dataclass(frozen=True)
class CampaignOutputPaths:
    """Campaign-owned bounded controller output paths."""

    root: Path
    launcher_stdout: Path
    launcher_stderr: Path
    observer_stdout: Path
    observer_stderr: Path
    watch_stdout: Path
    watch_stderr: Path


@dataclass(frozen=True)
class SessionConfig:
    """Operator-selected inputs for one persisted diagnostics session."""

    inputs: Path
    vpn_guard_config: Path
    lan_bind_addr: str = DEFAULT_CONTROL_BIND
    rest_timeout_seconds: float = 60.0
    connect_timeout_seconds: float = 240.0
    mfc_variant: str = clw.DEFAULT_MFC_VARIANT
    mfc_arch: str = clw.DEFAULT_MFC_ARCH
    mfc_configuration: str = clw.DEFAULT_MFC_CONFIGURATION


@dataclass(frozen=True)
class SessionStorageContext:
    """Validated immutable storage authority for one persisted session."""

    root: Path
    policy: soak_storage.SoakStoragePolicy
    policy_sha256: str
    active_campaign: Path
    previous_campaign: Path | None


def utc_timestamp() -> str:
    """Returns one filesystem-safe UTC timestamp."""

    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def build_control_paths(output_root: Path, control_dir: Path | None = None) -> ControlPaths:
    """Builds the stable detached-controller output layout."""

    resolved_output_root = output_root.resolve()
    root = (control_dir or resolved_output_root / "soak" / "control").resolve()
    if not path_is_relative_to(root, resolved_output_root):
        raise RuntimeError(f"Persisted soak control files must stay below EMULEBB_WORKSPACE_OUTPUT_ROOT: {root}")
    return ControlPaths(
        control_dir=root,
        manifest=root / "persisted-soak.latest.json",
        stop_file=root / "persisted-soak.stop",
        watch_stop_file=root / "persisted-soak-watch.stop",
        watch_jsonl=root / "persisted-soak-watch.jsonl",
        watch_heartbeat=root / "persisted-soak-watch.latest.json",
        last_run_manifest=resolved_output_root / "soak" / "last-run" / "manifest.json",
    )


def build_campaign_output_paths(campaign_dir: Path) -> CampaignOutputPaths:
    """Builds bounded process-output paths owned by one campaign."""

    root = campaign_dir.resolve() / "controller-output"
    return CampaignOutputPaths(
        root=root,
        launcher_stdout=root / "launcher.stdout.log",
        launcher_stderr=root / "launcher.stderr.log",
        observer_stdout=root / "observer.stdout.log",
        observer_stderr=root / "observer.stderr.log",
        watch_stdout=root / "watcher.stdout.log",
        watch_stderr=root / "watcher.stderr.log",
    )


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Writes JSON through an adjacent temporary file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(path)


def load_json(path: Path) -> dict[str, Any]:
    """Loads one JSON object, returning an empty object for a missing file."""

    if not path.is_file():
        return {}
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Expected a JSON object: {path}")
    return parsed


def campaign_storage_root(output_root: Path) -> Path:
    """Returns the only tree owned by aggregate soak artifact retention."""

    return (output_root.resolve() / "soak" / "campaigns").resolve()


def required_storage_policy(inputs: LiveWireInputs) -> soak_storage.SoakStoragePolicy:
    """Returns the mandatory persisted-soak storage policy."""

    if inputs.soak_storage is None:
        raise RuntimeError("Persisted full-tunnel soaks require soak_storage in the live-wire inputs.")
    return inputs.soak_storage


def storage_plan_summary(root: Path, plan: soak_storage.StoragePrunePlan) -> dict[str, Any]:
    """Returns bounded planning evidence without an unbounded deletion listing."""

    reasons = Counter(deletion.reason for deletion in plan.deletions)
    return {
        "root": str(root),
        "fileCount": len(plan.inventory.files),
        "totalBytes": plan.inventory.total_bytes,
        "freeBytes": plan.disk_space.free_bytes,
        "reservedBytes": plan.reserved_bytes,
        "protectedFileCount": len(plan.protected_files),
        "deletionCount": len(plan.deletions),
        "deletionBytes": sum(item.artifact.size_bytes for item in plan.deletions),
        "deletionReasons": dict(sorted(reasons.items())),
        "projectedTotalBytes": plan.projected_total_bytes,
        "projectedFreeBytes": plan.projected_free_bytes,
        "triggeredConstraints": list(plan.triggered_constraints),
        "unresolvedConstraints": list(plan.unresolved_constraints),
        "feasible": plan.within_limits,
    }


def storage_enforcement_summary(
    root: Path,
    result: soak_storage.StorageEnforcementResult,
) -> dict[str, Any]:
    """Returns bounded applied and verified storage evidence."""

    return {
        "root": str(root),
        "planned": storage_plan_summary(root, result.plan),
        "deletedCount": len(result.deleted_paths),
        "deletedBytes": sum(
            deletion.artifact.size_bytes
            for deletion in result.plan.deletions
            if deletion.artifact.path in result.deleted_paths
        ),
        "failures": list(result.failures[:32]),
        "failureCount": len(result.failures),
        "verification": storage_plan_summary(root, result.verification),
        "withinLimits": result.within_limits,
    }


def required_stream_reservation(
    policy: soak_storage.SoakStoragePolicy,
) -> dict[str, Any]:
    """Returns auditable capacity reserved for standard persisted-session streams."""

    streams: dict[str, dict[str, int]] = {}
    for name in soak_storage.REQUIRED_STREAMS:
        stream = policy.stream(name)
        instances = soak_storage.REQUIRED_STREAM_INSTANCES[name]
        streams[name] = {
            "instances": instances,
            "maxSegmentBytes": stream.max_segment_bytes,
            "retainedSegments": stream.retained_segments,
            "capacityBytes": (
                instances * stream.max_segment_bytes * stream.retained_segments
            ),
        }
    return {
        "totalBytes": soak_storage.required_stream_capacity_bytes(policy),
        "streams": streams,
    }


def latest_campaign_path(paths: ControlPaths, campaigns_root: Path) -> Path | None:
    """Returns the last campaign path when its stable manifest names one."""

    manifest = load_json(paths.last_run_manifest)
    raw_path = manifest.get("campaignDir")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    campaign = Path(raw_path).resolve()
    if not path_is_relative_to(campaign, campaigns_root):
        raise RuntimeError(f"Last-run campaign escaped the owned campaign store: {campaign}")
    return campaign


def session_storage_manifest(
    *,
    root: Path,
    policy: soak_storage.SoakStoragePolicy,
    active_campaign: Path,
    previous_campaign: Path | None,
    preflight_plan: dict[str, Any],
    launch_enforcement: dict[str, Any],
) -> dict[str, Any]:
    """Builds the canonical immutable storage context for one session."""

    return {
        "root": str(root),
        "policy": soak_storage.storage_policy_payload(policy),
        "policySha256": soak_storage.storage_policy_sha256(policy),
        "activeCampaignDir": str(active_campaign),
        "previousCampaignDir": str(previous_campaign) if previous_campaign is not None else None,
        "preflightPlan": preflight_plan,
        "launchEnforcement": launch_enforcement,
    }


def parse_session_storage_context(
    manifest: dict[str, Any],
    output_root: Path,
) -> SessionStorageContext:
    """Validates and returns the manifest-owned storage authority."""

    storage = manifest.get("storage")
    if not isinstance(storage, dict):
        raise RuntimeError("Persisted soak manifest is missing storage context.")
    expected_keys = {
        "root",
        "policy",
        "policySha256",
        "activeCampaignDir",
        "previousCampaignDir",
        "preflightPlan",
        "launchEnforcement",
    }
    actual_keys = set(storage)
    if actual_keys != expected_keys:
        missing = ", ".join(sorted(expected_keys - actual_keys))
        unknown = ", ".join(sorted(actual_keys - expected_keys))
        detail = f"missing={missing or '-'} unknown={unknown or '-'}"
        raise RuntimeError(f"Persisted soak storage context fields are invalid: {detail}.")

    root_value = storage.get("root")
    if not isinstance(root_value, str) or not root_value.strip():
        raise RuntimeError("Persisted soak storage root is invalid.")
    expected_root = campaign_storage_root(output_root)
    root = Path(root_value).resolve()
    if root != expected_root:
        raise RuntimeError(f"Persisted soak storage root mismatch: {root}")

    policy = soak_storage.parse_soak_storage_policy(storage.get("policy"))
    policy_sha256 = storage.get("policySha256")
    if not isinstance(policy_sha256, str) or policy_sha256 != soak_storage.storage_policy_sha256(policy):
        raise RuntimeError("Persisted soak storage policy SHA-256 mismatch.")
    if not isinstance(storage.get("preflightPlan"), dict):
        raise RuntimeError("Persisted soak storage preflight plan is invalid.")
    if not isinstance(storage.get("launchEnforcement"), dict):
        raise RuntimeError("Persisted soak storage launch enforcement is invalid.")

    campaign_id = manifest.get("campaignId")
    if not isinstance(campaign_id, str):
        raise RuntimeError("Persisted soak manifest campaignId is invalid.")
    try:
        soak_run_layout.validate_campaign_id(campaign_id)
    except ValueError as exc:
        raise RuntimeError("Persisted soak manifest campaignId is invalid.") from exc
    active_value = storage.get("activeCampaignDir")
    if not isinstance(active_value, str) or not active_value.strip():
        raise RuntimeError("Persisted soak active campaign path is invalid.")
    active_campaign = Path(active_value).resolve()
    if active_campaign.parent != root or active_campaign.name != campaign_id:
        raise RuntimeError(f"Persisted soak active campaign escaped its storage root: {active_campaign}")

    previous_value = storage.get("previousCampaignDir")
    previous_campaign = None
    if previous_value is not None:
        if not isinstance(previous_value, str) or not previous_value.strip():
            raise RuntimeError("Persisted soak previous campaign path is invalid.")
        previous_campaign = Path(previous_value).resolve()
        if previous_campaign.parent != root or previous_campaign == active_campaign:
            raise RuntimeError(f"Persisted soak previous campaign escaped its storage root: {previous_campaign}")

    return SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=policy_sha256,
        active_campaign=active_campaign,
        previous_campaign=previous_campaign,
    )


def enforce_session_storage_context(context: SessionStorageContext) -> dict[str, Any]:
    """Applies and verifies one manifest-owned storage policy snapshot."""

    pinned_paths = (context.previous_campaign,) if context.previous_campaign is not None else ()
    identity = {
        "policySha256": context.policy_sha256,
        "activeCampaignDir": str(context.active_campaign),
        "previousCampaignDir": (
            str(context.previous_campaign) if context.previous_campaign is not None else None
        ),
    }
    try:
        result = soak_storage.BoundedArtifactStore(
            context.root,
            context.policy,
        ).enforce(
            active_campaign=context.active_campaign,
            pinned_paths=pinned_paths,
        )
    except Exception as error:  # noqa: BLE001 - storage faults must become terminal evidence
        return {
            **identity,
            "ok": False,
            "errorType": type(error).__name__,
            "error": str(error)[:1024],
        }
    summary = storage_enforcement_summary(context.root, result)
    response = {
        **identity,
        "ok": result.within_limits,
        "enforcement": summary,
    }
    if not result.within_limits:
        constraints = ", ".join(result.verification.unresolved_constraints)
        response["errorType"] = "StoragePolicyUnsatisfied"
        response["error"] = (
            constraints
            or (result.failures[0] if result.failures else "pending deletions remain")
        )[:1024]
    return response


def advance_diagnostic_indexes(
    status: dict[str, Any], context: SessionStorageContext
) -> dict[str, Any]:
    """Advances and persists one compact closed-segment index per available writer."""

    diagnostic_writers = status.get("diagnosticWriters")
    if not isinstance(diagnostic_writers, dict):
        raise RuntimeError("Watch status is missing diagnostic writer state.")
    required = diagnostic_writers.get("required") is True
    result: dict[str, Any] = {
        "required": required,
        "rust": None,
        "mfc": None,
    }
    if not required:
        return result

    diagnostic_dirs = status.get("diagnosticDirs")
    if not isinstance(diagnostic_dirs, dict):
        raise RuntimeError("Watch status is missing diagnostic directories.")
    observed_utc = status.get("timestampUtc")
    if not isinstance(observed_utc, str) or not observed_utc:
        raise RuntimeError("Watch status timestampUtc is invalid.")
    store = soak_storage.BoundedArtifactStore(context.root, context.policy)
    for client in ("rust", "mfc"):
        writer = diagnostic_writers.get(client)
        if not isinstance(writer, dict) or not isinstance(writer.get("health"), dict):
            result[client] = {
                "ok": False,
                "status": "writer-health-unavailable",
            }
            continue
        diagnostic_dir_value = diagnostic_dirs.get(client)
        if not isinstance(diagnostic_dir_value, str) or not diagnostic_dir_value.strip():
            raise RuntimeError(
                f"Watch status {client} diagnostic directory is invalid."
            )
        diagnostic_dir = Path(diagnostic_dir_value).resolve()
        directory = (
            context.active_campaign / "report" / "diagnostic-indexes" / client
        ).resolve()
        checkpoint_path = directory / DIAGNOSTIC_INDEX_FILE_NAME
        checkpoint = load_json(checkpoint_path) if checkpoint_path.is_file() else None
        advanced = diagnostic_run_scan.scan_closed_segments(
            profile_dir=diagnostic_dir,
            client=client,
            writer_health=writer["health"],
            observed_utc=observed_utc,
            checkpoint=checkpoint,
        )
        result[client] = _persist_diagnostic_advance(
            client=client,
            advanced=advanced,
            prior_checkpoint=checkpoint,
            context=context,
            observed_utc=observed_utc,
            store=store,
            directory=directory,
            status="indexed",
        )
    return result


def finalize_diagnostic_indexes(
    *,
    diagnostic_dirs: dict[str, Any],
    diagnostic_writers: dict[str, Any],
    context: SessionStorageContext,
    observed_utc: str,
) -> dict[str, Any]:
    """Finalizes both stopped diagnostic runs, including their former active files."""

    required = diagnostic_writers.get("required") is True
    result: dict[str, Any] = {"required": required, "rust": None, "mfc": None}
    if not required:
        return result
    if not observed_utc:
        raise RuntimeError("Diagnostic finalization timestamp is invalid.")

    store = soak_storage.BoundedArtifactStore(context.root, context.policy)
    for client in ("rust", "mfc"):
        diagnostic_dir_value = diagnostic_dirs.get(client)
        if not isinstance(diagnostic_dir_value, str) or not diagnostic_dir_value.strip():
            raise RuntimeError(
                f"Persisted session {client} diagnostic directory is invalid."
            )
        writer = diagnostic_writers.get(client)
        writer_health = (
            writer.get("health")
            if isinstance(writer, dict) and isinstance(writer.get("health"), dict)
            else None
        )
        directory = (
            context.active_campaign / "report" / "diagnostic-indexes" / client
        ).resolve()
        checkpoint_path = directory / DIAGNOSTIC_INDEX_FILE_NAME
        checkpoint = load_json(checkpoint_path) if checkpoint_path.is_file() else None
        advanced = diagnostic_run_scan.finalize_stopped_run(
            profile_dir=Path(diagnostic_dir_value).resolve(),
            client=client,
            observed_utc=observed_utc,
            checkpoint=checkpoint,
            writer_health=writer_health,
        )
        result[client] = _persist_diagnostic_advance(
            client=client,
            advanced=advanced,
            prior_checkpoint=checkpoint,
            context=context,
            observed_utc=observed_utc,
            store=store,
            directory=directory,
            status="finalized",
        )
    return result


def _persist_diagnostic_advance(
    *,
    client: str,
    advanced: diagnostic_run_scan.ClosedSegmentAdvance,
    prior_checkpoint: dict[str, Any] | None,
    context: SessionStorageContext,
    observed_utc: str,
    store: soak_storage.BoundedArtifactStore,
    directory: Path,
    status: str,
) -> dict[str, Any]:
    pin_result = reconcile_diagnostic_evidence_pins(
        client=client,
        checkpoint=advanced.checkpoint,
        prior_checkpoint=prior_checkpoint,
        processed_segments=advanced.processed_segments,
        context=context,
        observed_utc=observed_utc,
    )
    advanced.checkpoint["evidencePins"] = pin_result["pins"]
    persisted = soak_storage.persist_bounded_json_checkpoint(
        store=store,
        active_campaign=context.active_campaign,
        directory=directory,
        stream_name="diagnostic_indexes",
        artifact_name=DIAGNOSTIC_INDEX_FILE_NAME,
        payload=advanced.checkpoint,
    )
    _finalize_diagnostic_evidence_pin_swaps(pin_result["pendingCleanup"])
    source = advanced.checkpoint["source"]
    index = advanced.checkpoint["index"]
    return {
        "ok": True,
        "status": status,
        "checkpoint": str(persisted.path),
        "bytes": persisted.byte_count,
        "sha256": persisted.sha256,
        "coverage": source["coverage"],
        "finalized": source["finalized"],
        "closedSegmentCount": source["closedSegmentCount"],
        "recordCount": index["recordCount"],
        "writerHealthSamples": index["writerHealth"]["samples"],
        "writerHealthViolationsSeen": index["writerHealth"]["violationsSeen"],
        "processedSegments": list(advanced.processed_segments),
        "evidencePins": pin_result["pins"],
        "pinActions": pin_result["actions"],
    }


def reconcile_diagnostic_evidence_pins(
    *,
    client: str,
    checkpoint: dict[str, Any],
    prior_checkpoint: dict[str, Any] | None,
    processed_segments: tuple[dict[str, Any], ...],
    context: SessionStorageContext,
    observed_utc: str,
) -> dict[str, Any]:
    """Keeps the highest-value exact raw segments within one client budget."""

    policy = context.policy.stream("diagnostic_pins")
    directory = (
        context.active_campaign / "archive" / "diagnostic-pins" / client
    ).resolve()
    _recover_diagnostic_evidence_pin_swaps(
        checkpoint.get("evidencePins"),
        directory=directory,
        retained_segments=policy.retained_segments,
    )
    pins = _validated_evidence_pins(
        checkpoint.get("evidencePins"),
        directory=directory,
        retained_segments=policy.retained_segments,
    )
    candidates = _diagnostic_pin_candidates(
        processed_segments,
        pins=pins,
        prior_checkpoint=prior_checkpoint,
    )
    store = soak_storage.BoundedArtifactStore(context.root, context.policy)
    actions: list[dict[str, Any]] = []
    pending_cleanup: list[Path] = []
    for candidate in candidates:
        existing = next(
            (pin for pin in pins if pin["fileName"] == candidate["fileName"]),
            None,
        )
        if existing is not None:
            existing["priority"] = max(existing["priority"], candidate["priority"])
            existing["reasons"] = sorted(
                set(existing["reasons"]) | set(candidate["reasons"])
            )
            actions.append(
                {
                    "action": "updated",
                    "segmentId": existing["segmentId"],
                    "priority": existing["priority"],
                    "reasons": existing["reasons"],
                }
            )
            continue

        source = Path(candidate["source"])
        if not source.is_file() and candidate["priority"] < 200:
            actions.append(
                {
                    "action": "skipped-missing-context",
                    "segmentId": candidate["segmentId"],
                    "reasons": candidate["reasons"],
                }
            )
            continue
        victim = None
        if len(pins) >= policy.retained_segments:
            victim = min(pins, key=_pin_rank)
            if _pin_rank(candidate) <= _pin_rank(victim):
                actions.append(
                    {
                        "action": "skipped-budget",
                        "segmentId": candidate["segmentId"],
                        "priority": candidate["priority"],
                        "reasons": candidate["reasons"],
                    }
                )
                continue

        victim_backup: Path | None = None
        victim_path: Path | None = None
        candidate_path = directory / candidate["fileName"]
        if victim is not None:
            victim_path = Path(victim["destination"])
            victim_backup = victim_path.with_name(f".{victim_path.name}.pin-swap.tmp")
            if victim_backup.exists() or victim_backup.is_symlink():
                raise RuntimeError(
                    f"Diagnostic evidence pin swap path already exists: {victim_backup}"
                )
            os.replace(victim_path, victim_backup)
        try:
            persisted = soak_storage.persist_bounded_file_artifact(
                store=store,
                active_campaign=context.active_campaign,
                directory=directory,
                stream_name="diagnostic_pins",
                source=source,
                artifact_name=candidate["fileName"],
            )
            if persisted.deleted_paths:
                raise RuntimeError(
                    "Diagnostic evidence pin persistence deleted an unselected artifact."
                )
            if (
                persisted.byte_count != candidate["bytes"]
                or persisted.sha256 != candidate["sha256"]
            ):
                raise RuntimeError(
                    "Diagnostic evidence pin does not match its indexed segment snapshot."
                )
        except Exception:
            candidate_path.unlink(missing_ok=True)
            if victim_backup is not None and victim_path is not None:
                os.replace(victim_backup, victim_path)
            raise
        if victim_backup is not None:
            pending_cleanup.append(victim_backup)
        if victim is not None:
            pins.remove(victim)
        pin = {
            "segmentId": candidate["segmentId"],
            "fileName": candidate["fileName"],
            "source": candidate["source"],
            "destination": str(persisted.path),
            "bytes": persisted.byte_count,
            "sha256": persisted.sha256,
            "priority": candidate["priority"],
            "reasons": candidate["reasons"],
            "pinnedUtc": observed_utc,
        }
        pins.append(pin)
        actions.append(
            {
                "action": "replaced" if victim is not None else "pinned",
                "segmentId": pin["segmentId"],
                "priority": pin["priority"],
                "reasons": pin["reasons"],
                "replacedSegmentId": victim["segmentId"]
                if victim is not None
                else None,
            }
        )
    pins.sort(key=lambda pin: (pin["segmentId"], pin["fileName"]))
    return {
        "pins": pins,
        "actions": actions,
        "pendingCleanup": tuple(pending_cleanup),
    }


def _diagnostic_pin_candidates(
    processed_segments: tuple[dict[str, Any], ...],
    *,
    pins: list[dict[str, Any]],
    prior_checkpoint: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    processed_by_id = {
        item["segmentId"]: item
        for item in processed_segments
        if isinstance(item.get("segmentId"), int)
    }
    candidates: dict[str, dict[str, Any]] = {}

    def add(metadata: dict[str, Any], reason: str | None = None) -> None:
        reasons = set(metadata.get("interestingReasons") or ())
        if reason is not None:
            reasons.add(reason)
        if not reasons:
            return
        file_name = metadata.get("fileName")
        if not isinstance(file_name, str):
            raise RuntimeError("Indexed diagnostic segment fileName is invalid.")
        candidate = candidates.setdefault(
            file_name,
            {
                **metadata,
                "reasons": [],
                "priority": 0,
            },
        )
        merged_reasons = sorted(set(candidate["reasons"]) | reasons)
        candidate["reasons"] = merged_reasons
        candidate["priority"] = _pin_priority(merged_reasons)

    signal_segments = [
        item for item in processed_segments if item.get("interestingReasons")
    ]
    for metadata in signal_segments:
        add(metadata)
        previous_id = metadata["segmentId"] - 1
        previous = processed_by_id.get(previous_id)
        if previous is None and prior_checkpoint is not None:
            source = prior_checkpoint.get("source")
            if isinstance(source, dict):
                prior_last = source.get("lastClosedSegment")
                if (
                    isinstance(prior_last, dict)
                    and prior_last.get("segmentId") == previous_id
                ):
                    previous = prior_last
        if previous is not None:
            add(previous, f"context-before:{metadata['segmentId']}")

    signal_pin_ids = {
        pin["segmentId"] for pin in pins if pin.get("priority", 0) >= 200
    } | {item["segmentId"] for item in signal_segments}
    for metadata in processed_segments:
        if metadata["segmentId"] - 1 in signal_pin_ids:
            add(metadata, f"context-after:{metadata['segmentId'] - 1}")

    return sorted(
        candidates.values(),
        key=lambda candidate: (candidate["segmentId"], candidate["fileName"]),
    )


def _pin_priority(reasons: list[str]) -> int:
    severity_values = {
        reason.partition(":")[2] for reason in reasons if reason.startswith("severity:")
    }
    if severity_values & {"critical", "fatal", "error", "high"}:
        return 400
    if severity_values:
        return 300
    if any(reason.startswith(("event:", "outcome:")) for reason in reasons):
        return 250
    return 100


def _pin_rank(pin: dict[str, Any]) -> tuple[int, int, str]:
    return (pin["priority"], pin["segmentId"], pin["fileName"])


def _validated_evidence_pins(
    raw_pins: object,
    *,
    directory: Path,
    retained_segments: int,
) -> list[dict[str, Any]]:
    if not isinstance(raw_pins, list) or len(raw_pins) > retained_segments:
        raise RuntimeError("Diagnostic evidence pin manifest exceeds its file budget.")
    pins: list[dict[str, Any]] = []
    destinations: set[Path] = set()
    for raw_pin in raw_pins:
        if not isinstance(raw_pin, dict) or set(raw_pin) != _EVIDENCE_PIN_FIELDS:
            raise RuntimeError("Diagnostic evidence pin manifest fields are invalid.")
        pin = dict(raw_pin)
        file_name = pin["fileName"]
        source_value = pin["source"]
        destination_value = pin["destination"]
        byte_count = pin["bytes"]
        sha256 = pin["sha256"]
        reasons = pin["reasons"]
        pinned_utc = pin["pinnedUtc"]
        if (
            not isinstance(file_name, str)
            or not file_name
            or Path(file_name).name != file_name
            or not isinstance(source_value, str)
            or not source_value
            or Path(source_value).name != file_name
            or not isinstance(destination_value, str)
            or not destination_value
            or isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count <= 0
            or not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
            or not isinstance(reasons, list)
            or not reasons
            or any(not isinstance(reason, str) or not reason for reason in reasons)
            or reasons != sorted(set(reasons))
            or not isinstance(pinned_utc, str)
            or not pinned_utc
        ):
            raise RuntimeError("Diagnostic evidence pin manifest values are invalid.")
        destination = Path(destination_value).resolve()
        if (
            destination.parent != directory
            or destination.name != file_name
            or destination in destinations
            or destination.is_symlink()
            or not destination.is_file()
            or destination.stat().st_size != byte_count
        ):
            raise RuntimeError(
                f"Diagnostic evidence pin destination is invalid: {destination}"
            )
        if (
            isinstance(pin["segmentId"], bool)
            or not isinstance(pin["segmentId"], int)
            or pin["segmentId"] < 0
            or isinstance(pin["priority"], bool)
            or not isinstance(pin["priority"], int)
            or pin["priority"] <= 0
        ):
            raise RuntimeError("Diagnostic evidence pin manifest values are invalid.")
        destinations.add(destination)
        pins.append(pin)
    if directory.exists():
        actual = {
            path.resolve()
            for path in directory.iterdir()
            if path.is_file() and not path.name.endswith(".tmp")
        }
        if actual != destinations:
            raise RuntimeError(
                "Diagnostic evidence pin directory does not match its checkpoint manifest."
            )
    return pins


def _recover_diagnostic_evidence_pin_swaps(
    raw_pins: object,
    *,
    directory: Path,
    retained_segments: int,
) -> None:
    manifest_destinations = _evidence_pin_manifest_destinations(
        raw_pins,
        directory=directory,
        retained_segments=retained_segments,
    )
    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError(f"Diagnostic evidence pin directory is invalid: {directory}")

    entries = list(directory.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise RuntimeError(
            f"Diagnostic evidence pin directory contains an invalid entry: {directory}"
        )
    swap_suffix = ".pin-swap.tmp"
    for backup in sorted(
        (entry for entry in entries if entry.name.endswith(swap_suffix)),
        key=lambda path: path.name,
    ):
        if not backup.name.startswith("."):
            raise RuntimeError(
                f"Diagnostic evidence pin swap name is invalid: {backup}"
            )
        original_name = backup.name[1 : -len(swap_suffix)]
        if not original_name or Path(original_name).name != original_name:
            raise RuntimeError(
                f"Diagnostic evidence pin swap name is invalid: {backup}"
            )
        original = (directory / original_name).resolve()
        if original in manifest_destinations:
            if original.exists():
                raise RuntimeError(
                    f"Diagnostic evidence pin swap is ambiguous: {backup}"
                )
            os.replace(backup, original)
        else:
            backup.unlink()

    for entry in directory.iterdir():
        if entry.name.endswith(".tmp"):
            entry.unlink()
            continue
        if entry.resolve() not in manifest_destinations:
            entry.unlink()


def _evidence_pin_manifest_destinations(
    raw_pins: object,
    *,
    directory: Path,
    retained_segments: int,
) -> set[Path]:
    if not isinstance(raw_pins, list) or len(raw_pins) > retained_segments:
        raise RuntimeError("Diagnostic evidence pin manifest exceeds its file budget.")
    destinations: set[Path] = set()
    for raw_pin in raw_pins:
        if not isinstance(raw_pin, dict) or set(raw_pin) != _EVIDENCE_PIN_FIELDS:
            raise RuntimeError("Diagnostic evidence pin manifest fields are invalid.")
        file_name = raw_pin.get("fileName")
        destination_value = raw_pin.get("destination")
        if (
            not isinstance(file_name, str)
            or not file_name
            or Path(file_name).name != file_name
            or not isinstance(destination_value, str)
            or not destination_value
        ):
            raise RuntimeError("Diagnostic evidence pin manifest values are invalid.")
        destination = Path(destination_value).resolve()
        if (
            destination.parent != directory
            or destination.name != file_name
            or destination in destinations
        ):
            raise RuntimeError("Diagnostic evidence pin manifest paths are invalid.")
        destinations.add(destination)
    return destinations


def _finalize_diagnostic_evidence_pin_swaps(paths: tuple[Path, ...]) -> None:
    for path in paths:
        if (
            not path.name.startswith(".")
            or not path.name.endswith(".pin-swap.tmp")
            or path.is_symlink()
            or not path.is_file()
        ):
            raise RuntimeError(
                f"Diagnostic evidence pin swap cleanup path is invalid: {path}"
            )
        path.unlink()


def preflight_campaign_storage(
    inputs: LiveWireInputs,
    output_root: Path,
    *,
    protected_campaigns: tuple[Path, ...],
) -> dict[str, Any]:
    """Plans aggregate retention without mutating campaign evidence."""

    policy = required_storage_policy(inputs)
    root = campaign_storage_root(output_root)
    reservation = required_stream_reservation(policy)
    plan = soak_storage.BoundedArtifactStore(root, policy).plan(
        pinned_paths=protected_campaigns,
        reserved_bytes=reservation["totalBytes"],
    )
    if not plan.within_limits:
        constraints = ", ".join(plan.unresolved_constraints) or "unknown"
        raise RuntimeError(f"Persisted soak storage cannot satisfy required limits: {constraints}.")
    return {
        **storage_plan_summary(root, plan),
        "reservation": reservation,
    }


def enforce_campaign_storage(
    inputs: LiveWireInputs,
    output_root: Path,
    *,
    protected_campaigns: tuple[Path, ...],
) -> dict[str, Any]:
    """Applies and verifies aggregate retention before any process launch."""

    policy = required_storage_policy(inputs)
    root = campaign_storage_root(output_root)
    reservation = required_stream_reservation(policy)
    result = soak_storage.BoundedArtifactStore(root, policy).enforce(
        pinned_paths=protected_campaigns,
        reserved_bytes=reservation["totalBytes"],
    )
    summary = storage_enforcement_summary(root, result)
    summary["reservation"] = reservation
    if not result.within_limits:
        constraints = ", ".join(result.verification.unresolved_constraints)
        detail = constraints or (result.failures[0] if result.failures else "pending deletions remain")
        raise RuntimeError(f"Persisted soak storage enforcement failed: {detail}.")
    return summary


def command_fingerprint(command: list[str]) -> str:
    """Returns a stable non-secret command identity fingerprint."""

    encoded = json.dumps(command, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def exact_process_row(
    identity: object,
    processes: list[windows_processes.WindowsProcessInfo],
) -> windows_processes.WindowsProcessInfo | None:
    """Returns a process only when both its PID and creation date match."""

    if not isinstance(identity, dict):
        return None
    pid = identity.get("pid")
    creation_date = str(identity.get("creationDate") or "")
    if not isinstance(pid, int) or pid <= 0 or not creation_date:
        return None
    return next(
        (
            process
            for process in processes
            if process.pid == pid and process.creation_date == creation_date
        ),
        None,
    )


def exact_identity_payload(value: object) -> dict[str, Any] | None:
    """Returns the minimum exact process identity when it is complete."""

    if not isinstance(value, dict):
        return None
    pid = value.get("pid")
    creation_date = value.get("creationDate")
    if not isinstance(pid, int) or pid <= 0:
        return None
    if not isinstance(creation_date, str) or not creation_date:
        return None
    return {"pid": pid, "creationDate": creation_date}


def resolve_watcher_launcher_identity(
    manifest: dict[str, Any],
    launcher_fallback: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolves and cross-checks the watcher's immutable launcher identity."""

    manifest_identity = exact_identity_payload(manifest.get("launcher"))
    fallback_identity = exact_identity_payload(launcher_fallback)
    if (
        manifest_identity is not None
        and fallback_identity is not None
        and manifest_identity != fallback_identity
    ):
        raise RuntimeError("Persisted soak launcher identity mismatches the watcher fallback.")
    return fallback_identity or manifest_identity or {}


def wait_process_identity(
    pid: int,
    *,
    markers: tuple[str, ...],
    timeout_seconds: float = 10.0,
) -> windows_processes.WindowsProcessInfo:
    """Waits for an exact WMI process identity and verifies its command markers."""

    deadline = time.monotonic() + timeout_seconds
    last_row: windows_processes.WindowsProcessInfo | None = None
    while time.monotonic() < deadline:
        last_row = next((row for row in windows_processes.collect_processes() if row.pid == pid), None)
        if last_row is not None and last_row.creation_date:
            if last_row.command_line and not windows_processes.command_line_contains_markers(
                last_row.command_line,
                markers,
            ):
                raise RuntimeError(f"Process {pid} did not match the expected command identity.")
            return last_row
        time.sleep(0.1)
    raise RuntimeError(f"Timed out recording exact process identity for pid {pid}: {last_row}")


def preflight_session(
    config: SessionConfig,
    output_root: Path,
    *,
    inputs: LiveWireInputs | None = None,
    protected_campaigns: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Performs the read-only full-tunnel and persisted-profile preflight."""

    inputs_path = config.inputs.resolve()
    if not inputs_path.is_file():
        raise RuntimeError(f"Live-wire inputs were not found: {inputs_path}")
    inputs = inputs or load_live_wire_inputs(inputs_path)
    if inputs.mfc_profile_dir is None or not inputs.mfc_profile_dir.is_dir():
        raise RuntimeError("Persisted full-tunnel soaks require an existing MFC profile directory.")
    if inputs.rust_profile_dir is None:
        raise RuntimeError("Persisted full-tunnel soaks require rust_profile.profile_dir.")
    rust_profile_dir = inputs.rust_profile_dir.resolve()
    if rust_profile_dir.exists() and not rust_profile_dir.is_dir():
        raise RuntimeError(f"Rust profile path exists and is not a directory: {rust_profile_dir}")
    if not rust_profile_dir.parent.is_dir():
        raise RuntimeError(f"Rust profile parent does not exist: {rust_profile_dir.parent}")
    storage = preflight_campaign_storage(
        inputs,
        output_root,
        protected_campaigns=protected_campaigns,
    )

    rest_addr = soak_launch.resolve_lan_rest_bind_addr(
        config.lan_bind_addr,
        vpn_topology=hideme_vpn.VPN_TOPOLOGY_FULL_TUNNEL,
    )
    rust_exe = clw.resolve_rust_diagnostics_exe(output_root)
    mfc_exe = clw.resolve_mfc_diagnostics_exe(
        output_root,
        variant=config.mfc_variant,
        arch=config.mfc_arch,
        configuration=config.mfc_configuration,
    )
    guard = soak_launch.require_blocking_vpn_guard_config(config.vpn_guard_config)
    routing = soak_launch.prepare_hideme_routing(
        hideme_vpn.VPN_TOPOLOGY_FULL_TUNNEL,
        [
            ("rust", "eMuleBB Rust", rust_exe),
            ("mfc", "eMuleBB MFC", mfc_exe),
        ],
    )
    return {
        "inputs": str(inputs_path),
        "profiles": {
            "mfc": str(inputs.mfc_profile_dir.resolve()),
            "rust": str(rust_profile_dir),
        },
        "diagnosticDirs": {
            "mfc": str((inputs.mfc_profile_dir / "logs").resolve()),
            "rust": str((rust_profile_dir / "packet-dump").resolve()),
        },
        "executables": {
            "mfc": str(mfc_exe.resolve()),
            "rust": str(rust_exe.resolve()),
        },
        "control": {
            "bindAddress": rest_addr,
            "rustBaseUrl": f"http://{rest_addr}:4731/api/v1",
            "mfcBaseUrl": f"http://{rest_addr}:4732/api/v1",
        },
        "vpn": {
            "topology": routing["topology"],
            "adapterUp": True,
            "routesThroughHideMe": True,
            "guardMode": guard["mode"],
            "guardConfig": guard["config_path"],
        },
        "storage": storage,
    }


def build_launch_command(
    config: SessionConfig,
    paths: ControlPaths,
    *,
    campaign_id: str,
) -> list[str]:
    """Builds the canonical until-stopped dual diagnostics command."""

    return [
        sys.executable,
        str(LAUNCH_SCRIPT),
        "--inputs",
        str(config.inputs.resolve()),
        "--campaign-id",
        soak_run_layout.validate_campaign_id(campaign_id),
        "--lan-bind-addr",
        config.lan_bind_addr,
        "--vpn-topology",
        hideme_vpn.VPN_TOPOLOGY_FULL_TUNNEL,
        "--vpn-guard-live-config",
        str(config.vpn_guard_config.resolve()),
        "--vpn-guard-scenario",
        "success",
        "--duration-seconds",
        "0",
        "--stop-file",
        str(paths.stop_file),
        "--rust-shutdown-trigger",
        "rest",
        "--reuse-rust-shared-profile",
        "--reuse-kad-bootstrap",
        "--rest-timeout-seconds",
        str(config.rest_timeout_seconds),
        "--connect-timeout-seconds",
        str(config.connect_timeout_seconds),
        "--mfc-variant",
        config.mfc_variant,
        "--mfc-arch",
        config.mfc_arch,
        "--mfc-configuration",
        config.mfc_configuration,
    ]


def build_observer_command(
    paths: ControlPaths,
    *,
    ready_timeout_seconds: float,
    poll_interval_seconds: float,
    checkpoint_interval_seconds: float,
    failure_threshold: int,
) -> list[str]:
    """Builds the attach-only bounded observer command."""

    return [
        sys.executable,
        str(OBSERVER_SCRIPT),
        "--session-manifest",
        str(paths.manifest),
        "--ready-timeout-seconds",
        str(ready_timeout_seconds),
        "--poll-interval-seconds",
        str(poll_interval_seconds),
        "--checkpoint-interval-seconds",
        str(checkpoint_interval_seconds),
        "--failure-threshold",
        str(failure_threshold),
    ]


def build_observer_action_config(
    inputs: LiveWireInputs,
    *,
    enabled: bool,
    terms: tuple[str, ...],
    method: str,
    start_delay_seconds: float,
    search_interval_seconds: float,
    search_timeout_seconds: float,
    max_cycles: int,
) -> dict[str, Any]:
    """Builds one normalized manifest-only observer action-driving contract."""

    if terms and not enabled:
        raise ValueError("observer action terms require observer action driving.")
    if any(not isinstance(term, str) or not term.strip() for term in terms):
        raise ValueError("observer action terms must be non-empty strings.")
    normalized_terms = tuple(dict.fromkeys(term.strip() for term in terms))
    source_profile: str | None = None
    if enabled:
        if normalized_terms:
            source_profile = "explicit"
        else:
            source_profile = "generic_open"
            normalized_terms = inputs.generic_open_terms
    payload = {
        "enabled": enabled,
        "sourceProfile": source_profile,
        "terms": list(normalized_terms) if enabled else [],
        "method": method,
        "startDelaySeconds": start_delay_seconds,
        "searchIntervalSeconds": search_interval_seconds,
        "searchTimeoutSeconds": search_timeout_seconds,
        "maxCycles": max_cycles,
    }
    try:
        validated = converged_observer.parse_action_config(
            {"actionDriving": payload}
        )
    except RuntimeError as error:
        raise ValueError(str(error)) from error
    return {
        "enabled": validated.enabled,
        "sourceProfile": validated.source_profile,
        "terms": list(validated.terms),
        "method": validated.method,
        "startDelaySeconds": validated.start_delay_seconds,
        "searchIntervalSeconds": validated.search_interval_seconds,
        "searchTimeoutSeconds": validated.search_timeout_seconds,
        "maxCycles": validated.max_cycles,
    }


def build_watch_command(
    paths: ControlPaths,
    *,
    interval_seconds: float,
    max_bytes: int,
    segments: int,
    launcher_identity: dict[str, Any],
) -> list[str]:
    """Builds the detached periodic health command."""

    return [
        sys.executable,
        str(CONTROL_SCRIPT),
        "--control-dir",
        str(paths.control_dir),
        "watch",
        "--interval-seconds",
        str(interval_seconds),
        "--max-bytes",
        str(max_bytes),
        "--segments",
        str(segments),
        "--launcher-pid",
        str(launcher_identity["pid"]),
        "--launcher-creation-date",
        str(launcher_identity["creationDate"]),
    ]


def build_bounded_process_command(
    command: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    policy: soak_storage.ArtifactStreamPolicy,
    stop_files: tuple[Path, ...],
) -> list[str]:
    """Builds one detached supervisor command for exact bounded output."""

    result = [
        sys.executable,
        str(BOUNDED_PROCESS_SCRIPT),
        "--stdout-path",
        str(stdout_path),
        "--stderr-path",
        str(stderr_path),
        "--max-segment-bytes",
        str(policy.max_segment_bytes),
        "--retained-segments",
        str(policy.retained_segments),
    ]
    for stop_file in stop_files:
        result.extend(("--stop-file", str(stop_file)))
    result.append("--")
    result.extend(command)
    return result


def detached_creation_flags() -> int:
    """Returns Windows flags that let the controller processes outlive the caller."""

    if os.name != "nt":
        return 0
    return subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]


def spawn_detached(command: list[str]) -> subprocess.Popen[bytes]:
    """Starts one detached bounded-output supervisor."""

    return subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=False,
        creationflags=detached_creation_flags(),
    )


def process_identity(row: windows_processes.WindowsProcessInfo, command: list[str]) -> dict[str, Any]:
    """Builds the persisted exact identity for one controller-owned process."""

    return {
        "pid": row.pid,
        "creationDate": row.creation_date,
        "commandFingerprint": command_fingerprint(command),
    }


def stop_owned_process(
    identity: object,
    *,
    markers: tuple[str, ...],
    graceful_timeout_seconds: float,
) -> dict[str, Any]:
    """Stops one exact controller-owned process without broad name matching."""

    exact = exact_identity_payload(identity)
    if exact is None:
        return {
            "identityAvailable": False,
            "graceful": True,
            "force": {
                "forced": False,
                "alreadyStopped": True,
                "verifiedStopped": True,
            },
        }
    graceful = wait_exact_exit(exact, graceful_timeout_seconds)
    force = (
        {"forced": False, "alreadyStopped": True, "verifiedStopped": True}
        if graceful
        else stop_exact_process(
            exact,
            markers=markers,
            timeout_seconds=WATCH_FAILURE_GRACE_SECONDS,
        )
    )
    return {
        "identityAvailable": True,
        "graceful": graceful,
        "force": force,
    }


def start_session(
    config: SessionConfig,
    paths: ControlPaths,
    *,
    start_watch: bool = True,
    start_observer: bool = True,
    watch_interval_seconds: float = DEFAULT_WATCH_INTERVAL_SECONDS,
    watch_max_bytes: int = DEFAULT_WATCH_MAX_BYTES,
    watch_segments: int = DEFAULT_WATCH_SEGMENTS,
    observer_ready_timeout_seconds: float = converged_observer.DEFAULT_READY_TIMEOUT_SECONDS,
    observer_poll_interval_seconds: float = converged_observer.DEFAULT_POLL_INTERVAL_SECONDS,
    observer_checkpoint_interval_seconds: float = converged_observer.DEFAULT_CHECKPOINT_INTERVAL_SECONDS,
    observer_failure_threshold: int = converged_observer.DEFAULT_FAILURE_THRESHOLD,
    observer_drive_actions: bool = False,
    observer_action_terms: tuple[str, ...] = (),
    observer_action_method: str = converged_observer.DEFAULT_ACTION_METHOD,
    observer_action_start_delay_seconds: float = converged_observer.DEFAULT_ACTION_START_DELAY_SECONDS,
    observer_action_search_interval_seconds: float = converged_observer.DEFAULT_ACTION_INTERVAL_SECONDS,
    observer_action_search_timeout_seconds: float = converged_observer.DEFAULT_ACTION_SEARCH_TIMEOUT_SECONDS,
    observer_action_max_cycles: int = 0,
) -> dict[str, Any]:
    """Starts one detached dual-client diagnostics session."""

    if config.rest_timeout_seconds <= 0:
        raise ValueError("rest_timeout_seconds must be greater than zero.")
    if config.connect_timeout_seconds <= 0:
        raise ValueError("connect_timeout_seconds must be greater than zero.")
    if start_watch and watch_interval_seconds <= 0:
        raise ValueError("watch_interval_seconds must be greater than zero.")
    if start_watch and watch_max_bytes <= 0:
        raise ValueError("watch_max_bytes must be greater than zero.")
    if start_watch and watch_segments <= 0:
        raise ValueError("watch_segments must be greater than zero.")
    if start_observer and not start_watch:
        raise ValueError("The converged observer requires the persisted health watcher.")
    if observer_drive_actions and not start_observer:
        raise ValueError("Observer action driving requires the converged observer.")
    if start_observer and observer_ready_timeout_seconds <= 0:
        raise ValueError("observer_ready_timeout_seconds must be greater than zero.")
    if start_observer and observer_poll_interval_seconds <= 0:
        raise ValueError("observer_poll_interval_seconds must be greater than zero.")
    if start_observer and observer_checkpoint_interval_seconds <= 0:
        raise ValueError("observer_checkpoint_interval_seconds must be greater than zero.")
    if start_observer and observer_failure_threshold <= 0:
        raise ValueError("observer_failure_threshold must be greater than zero.")
    existing = load_json(paths.manifest)
    processes = windows_processes.collect_processes()
    if exact_process_row(existing.get("launcher", {}), processes) is not None:
        raise RuntimeError(f"A persisted soak launcher is already active: {paths.manifest}")
    if exact_process_row(existing.get("watcher", {}), processes) is not None:
        raise RuntimeError(f"A persisted soak watcher is already active: {paths.manifest}")
    if exact_process_row(existing.get("observer", {}), processes) is not None:
        raise RuntimeError(f"A persisted soak observer is already active: {paths.manifest}")

    output_root = get_workspace_output_root()
    inputs = load_live_wire_inputs(config.inputs.resolve())
    observer_action_config = build_observer_action_config(
        inputs,
        enabled=observer_drive_actions,
        terms=observer_action_terms,
        method=observer_action_method,
        start_delay_seconds=observer_action_start_delay_seconds,
        search_interval_seconds=observer_action_search_interval_seconds,
        search_timeout_seconds=observer_action_search_timeout_seconds,
        max_cycles=observer_action_max_cycles,
    )
    storage_policy = required_storage_policy(inputs)
    controller_output_policy = storage_policy.stream("controller_output")
    campaigns_root = campaign_storage_root(output_root)
    campaign_id = soak_run_layout.utc_campaign_id()
    campaign_dir = (campaigns_root / campaign_id).resolve()
    campaign_output = build_campaign_output_paths(campaign_dir)
    if campaign_dir.exists():
        raise RuntimeError(f"Persisted soak campaign path already exists: {campaign_dir}")
    previous_campaign = latest_campaign_path(paths, campaigns_root)
    protected_campaigns = tuple(
        dict.fromkeys(
            campaign
            for campaign in (previous_campaign, campaign_dir)
            if campaign is not None
        )
    )
    preflight = preflight_session(
        config,
        output_root,
        inputs=inputs,
        protected_campaigns=protected_campaigns,
    )
    storage_enforcement = enforce_campaign_storage(
        inputs,
        output_root,
        protected_campaigns=protected_campaigns,
    )
    paths.control_dir.mkdir(parents=True, exist_ok=True)
    paths.stop_file.unlink(missing_ok=True)
    paths.watch_stop_file.unlink(missing_ok=True)

    launch_target_command = build_launch_command(config, paths, campaign_id=campaign_id)
    launch_command = build_bounded_process_command(
        launch_target_command,
        stdout_path=campaign_output.launcher_stdout,
        stderr_path=campaign_output.launcher_stderr,
        policy=controller_output_policy,
        stop_files=(paths.stop_file, paths.watch_stop_file),
    )
    launcher_process = spawn_detached(launch_command)
    try:
        launcher_row = wait_process_identity(launcher_process.pid, markers=("launch-soak.py",))
    except Exception:
        if launcher_process.poll() is None:
            launcher_process.terminate()
        raise

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "state": "running",
        "startedUtc": datetime.now(UTC).isoformat(),
        "campaignId": campaign_id,
        "campaignDir": str(campaign_dir),
        "launcher": process_identity(launcher_row, launch_command),
        "observer": None,
        "watcher": None,
        "observerConfig": {
            "enabled": start_observer,
            "readyTimeoutSeconds": (
                observer_ready_timeout_seconds if start_observer else None
            ),
            "pollIntervalSeconds": (
                observer_poll_interval_seconds if start_observer else None
            ),
            "checkpointIntervalSeconds": (
                observer_checkpoint_interval_seconds if start_observer else None
            ),
            "failureThreshold": observer_failure_threshold if start_observer else None,
            "actionDriving": observer_action_config,
        },
        "watchConfig": {
            "enabled": start_watch,
            "intervalSeconds": watch_interval_seconds if start_watch else None,
            "heartbeatStaleSeconds": (
                max(
                    watch_interval_seconds * 3,
                    watch_interval_seconds + WATCH_HEARTBEAT_MIN_STALE_SECONDS,
                )
                if start_watch
                else None
            ),
        },
        "command": launch_command,
        "targetCommand": launch_target_command,
        "preflight": preflight,
        "storage": session_storage_manifest(
            root=campaigns_root,
            policy=storage_policy,
            active_campaign=campaign_dir,
            previous_campaign=previous_campaign,
            preflight_plan=preflight["storage"],
            launch_enforcement=storage_enforcement,
        ),
        "controlFiles": {
            "manifest": str(paths.manifest),
            "stop": str(paths.stop_file),
            "watchStop": str(paths.watch_stop_file),
            "watchJsonl": str(paths.watch_jsonl),
            "watchHeartbeat": str(paths.watch_heartbeat),
            "lastRunManifest": str(paths.last_run_manifest),
        },
        "logs": {
            "root": str(campaign_output.root),
            "maxSegmentBytes": controller_output_policy.max_segment_bytes,
            "retainedSegments": controller_output_policy.retained_segments,
            "launcherStdout": str(campaign_output.launcher_stdout),
            "launcherStderr": str(campaign_output.launcher_stderr),
            "observerStdout": str(campaign_output.observer_stdout),
            "observerStderr": str(campaign_output.observer_stderr),
            "watchStdout": str(campaign_output.watch_stdout),
            "watchStderr": str(campaign_output.watch_stderr),
        },
    }
    write_json_atomic(paths.manifest, manifest)

    if start_observer:
        observer_target_command = build_observer_command(
            paths,
            ready_timeout_seconds=observer_ready_timeout_seconds,
            poll_interval_seconds=observer_poll_interval_seconds,
            checkpoint_interval_seconds=observer_checkpoint_interval_seconds,
            failure_threshold=observer_failure_threshold,
        )
        observer_command = build_bounded_process_command(
            observer_target_command,
            stdout_path=campaign_output.observer_stdout,
            stderr_path=campaign_output.observer_stderr,
            policy=controller_output_policy,
            stop_files=(paths.stop_file, paths.watch_stop_file),
        )
        observer_process: subprocess.Popen[bytes] | None = None
        try:
            observer_process = spawn_detached(observer_command)
            observer_row = wait_process_identity(
                observer_process.pid,
                markers=("converged-soak-observer.py",),
            )
        except Exception as error:
            paths.stop_file.write_text(
                datetime.now(UTC).isoformat() + "\n",
                encoding="utf-8",
                newline="\n",
            )
            if observer_process is not None and observer_process.poll() is None:
                observer_process.terminate()
            launcher_stop = stop_owned_process(
                manifest["launcher"],
                markers=("launch-soak.py",),
                graceful_timeout_seconds=15.0,
            )
            manifest["state"] = "start-failed"
            manifest["startFailure"] = {
                "role": "observer",
                "type": type(error).__name__,
                "message": str(error),
                "launcherStop": launcher_stop,
            }
            write_json_atomic(paths.manifest, manifest)
            raise
        manifest["observer"] = process_identity(observer_row, observer_command)
        manifest["observerCommand"] = observer_command
        manifest["observerTargetCommand"] = observer_target_command
        write_json_atomic(paths.manifest, manifest)

    if start_watch:
        watch_target_command = build_watch_command(
            paths,
            interval_seconds=watch_interval_seconds,
            max_bytes=watch_max_bytes,
            segments=watch_segments,
            launcher_identity=manifest["launcher"],
        )
        watch_command = build_bounded_process_command(
            watch_target_command,
            stdout_path=campaign_output.watch_stdout,
            stderr_path=campaign_output.watch_stderr,
            policy=controller_output_policy,
            stop_files=(paths.stop_file, paths.watch_stop_file),
        )
        try:
            watch_process = spawn_detached(watch_command)
            watch_row = wait_process_identity(watch_process.pid, markers=("persisted-soak-control.py", "watch"))
        except Exception as error:
            requested_at = datetime.now(UTC).isoformat() + "\n"
            paths.stop_file.write_text(requested_at, encoding="utf-8", newline="\n")
            paths.watch_stop_file.write_text(
                requested_at,
                encoding="utf-8",
                newline="\n",
            )
            observer_stop = stop_owned_process(
                manifest.get("observer"),
                markers=("converged-soak-observer.py",),
                graceful_timeout_seconds=15.0,
            )
            launcher_stop = stop_owned_process(
                manifest["launcher"],
                markers=("launch-soak.py",),
                graceful_timeout_seconds=15.0,
            )
            manifest["state"] = "start-failed"
            manifest["startFailure"] = {
                "role": "watcher",
                "type": type(error).__name__,
                "message": str(error),
                "observerStop": observer_stop,
                "launcherStop": launcher_stop,
            }
            write_json_atomic(paths.manifest, manifest)
            raise
        manifest["watcher"] = process_identity(watch_row, watch_command)
        manifest["watchCommand"] = watch_command
        manifest["watchTargetCommand"] = watch_target_command
        write_json_atomic(paths.manifest, manifest)

    return manifest


def process_summary(row: windows_processes.WindowsProcessInfo, role: str) -> dict[str, Any]:
    """Returns a sanitized process summary."""

    return {
        "role": role,
        "pid": row.pid,
        "parentPid": row.parent_pid,
        "name": row.name,
        "creationDate": row.creation_date,
    }


def rest_health(base_url: str, api_key: str) -> dict[str, Any]:
    """Returns REST, blocking VPN Guard, and hide.me binding health."""

    try:
        payload = http_json(base_url, "/status", api_key=api_key, timeout_seconds=5.0)
        data = api_data(payload)
        network = data.get("network") if isinstance(data, dict) else None
        vpn_guard = network.get("vpnGuard") if isinstance(network, dict) else None
        binding = network.get("binding") if isinstance(network, dict) else None
        guard_violations: list[str] = []
        if not isinstance(vpn_guard, dict):
            guard_violations.append("missing network.vpnGuard")
        else:
            expected_guard = {
                "enabled": True,
                "mode": "block",
                "startupBlocked": False,
            }
            guard_violations.extend(
                f"{name}={vpn_guard.get(name)!r} expected {expected!r}"
                for name, expected in expected_guard.items()
                if vpn_guard.get(name) != expected
            )
            allowed_cidrs = vpn_guard.get("allowedPublicIpCidrs")
            if not isinstance(allowed_cidrs, str) or not allowed_cidrs.strip():
                guard_violations.append(
                    "allowedPublicIpCidrs expected non-empty string"
                )

        binding_violations: list[str] = []
        if not isinstance(binding, dict):
            binding_violations.append("missing network.binding")
        else:
            active_interface = binding.get("activeInterfaceName")
            if (
                not isinstance(active_interface, str)
                or active_interface.casefold() != "hide.me"
            ):
                binding_violations.append(
                    f"activeInterfaceName={active_interface!r} expected 'hide.me'"
                )
            if binding.get("resolveResult") != "resolved":
                binding_violations.append(
                    f"resolveResult={binding.get('resolveResult')!r} expected 'resolved'"
                )
        return {
            "ok": True,
            "responseType": type(payload).__name__,
            "vpnGuard": {
                "ok": not guard_violations,
                "health": dict(vpn_guard) if isinstance(vpn_guard, dict) else None,
                "violations": guard_violations,
            },
            "p2pBinding": {
                "ok": not binding_violations,
                "health": dict(binding) if isinstance(binding, dict) else None,
                "violations": binding_violations,
            },
        }
    except Exception as error:  # noqa: BLE001 - health status retains only bounded error metadata
        return {"ok": False, "errorType": type(error).__name__, "error": str(error)[:256]}


def diagnostic_writer_health(base_url: str, api_key: str) -> dict[str, Any]:
    """Returns the complete current writer health plus strict integrity findings."""

    try:
        payload = http_json(
            base_url,
            "/diagnostics",
            api_key=api_key,
            timeout_seconds=5.0,
        )
        data = api_data(payload)
        health = data.get("diagnosticWriter") if isinstance(data, dict) else None
        violations = diag_event_runs.diagnostic_writer_health_violations(health)
        return {
            "reachable": True,
            "ok": not violations,
            "health": dict(health) if isinstance(health, dict) else None,
            "violations": list(violations),
        }
    except Exception as error:  # noqa: BLE001 - watcher must persist REST failures
        return {
            "reachable": False,
            "ok": False,
            "health": None,
            "violations": [f"{type(error).__name__}: {error}"[:1024]],
        }


def full_tunnel_health() -> dict[str, Any]:
    """Returns a bounded read-only hide.me health result."""

    try:
        result = hideme_vpn.require_full_tunnel_ready()
        return {
            "ok": True,
            "splitTunnelMode": result["splitTunnelMode"],
            "adapterUp": result["adapterUp"],
            "routeProbeCount": result["routeProbeCount"],
            "routesThroughHideMe": result["routesThroughHideMe"],
        }
    except Exception as error:  # noqa: BLE001 - health status retains only bounded error metadata
        return {"ok": False, "errorType": type(error).__name__, "error": str(error)[:256]}


def parse_aware_timestamp(value: object) -> datetime | None:
    """Parses one timezone-aware ISO timestamp."""

    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def watch_heartbeat_health(
    manifest: dict[str, Any],
    heartbeat: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validates heartbeat freshness and authority for the current campaign."""

    watch_config = manifest.get("watchConfig")
    if not isinstance(watch_config, dict) or watch_config.get("enabled") is not True:
        return {"state": "disabled", "accepted": False}
    stale_seconds = watch_config.get("heartbeatStaleSeconds")
    if isinstance(stale_seconds, bool) or not isinstance(stale_seconds, (int, float)) or stale_seconds <= 0:
        return {"state": "invalid", "accepted": False, "reason": "watch-config"}

    observed_now = (now or datetime.now(UTC)).astimezone(UTC)
    started_at = parse_aware_timestamp(manifest.get("startedUtc"))
    if not heartbeat:
        if started_at is not None and (observed_now - started_at).total_seconds() <= stale_seconds:
            return {"state": "pending", "accepted": False, "staleAfterSeconds": stale_seconds}
        return {"state": "stale", "accepted": False, "reason": "missing"}

    campaign_id = manifest.get("campaignId")
    manifest_storage = manifest.get("storage")
    heartbeat_storage = heartbeat.get("storage")
    if heartbeat.get("schema") != WATCH_SCHEMA:
        return {"state": "invalid", "accepted": False, "reason": "schema"}
    if not isinstance(campaign_id, str) or heartbeat.get("campaignId") != campaign_id:
        if started_at is not None and (observed_now - started_at).total_seconds() <= stale_seconds:
            return {
                "state": "pending",
                "accepted": False,
                "reason": "previous-campaign",
                "staleAfterSeconds": stale_seconds,
            }
        return {"state": "invalid", "accepted": False, "reason": "campaign"}
    if not isinstance(manifest_storage, dict) or not isinstance(heartbeat_storage, dict):
        return {"state": "invalid", "accepted": False, "reason": "storage"}
    if heartbeat_storage.get("policySha256") != manifest_storage.get("policySha256"):
        return {"state": "invalid", "accepted": False, "reason": "policy-sha256"}
    if heartbeat_storage.get("activeCampaignDir") != manifest_storage.get("activeCampaignDir"):
        return {"state": "invalid", "accepted": False, "reason": "active-campaign"}
    if heartbeat_storage.get("previousCampaignDir") != manifest_storage.get("previousCampaignDir"):
        return {"state": "invalid", "accepted": False, "reason": "previous-campaign"}

    heartbeat_at = parse_aware_timestamp(heartbeat.get("timestampUtc"))
    if heartbeat_at is None:
        return {"state": "invalid", "accepted": False, "reason": "timestamp"}
    age_seconds = (observed_now - heartbeat_at).total_seconds()
    if age_seconds < -5:
        return {"state": "invalid", "accepted": False, "reason": "future-timestamp"}
    if isinstance(heartbeat.get("shutdown"), dict):
        return {
            "state": "terminal",
            "accepted": True,
            "ageSeconds": max(0.0, age_seconds),
        }
    if age_seconds > stale_seconds:
        return {
            "state": "stale",
            "accepted": False,
            "ageSeconds": age_seconds,
            "staleAfterSeconds": stale_seconds,
        }
    return {
        "state": "current",
        "accepted": True,
        "ageSeconds": max(0.0, age_seconds),
        "staleAfterSeconds": stale_seconds,
    }


def status_findings(status: dict[str, Any]) -> list[str]:
    """Returns actionable health findings for one session status."""

    findings: list[str] = []
    if not status["launcher"]["alive"]:
        findings.append("launcher-not-running")
    manifest = status.get("manifest") or {}
    watcher = status.get("watcher") or {}
    if manifest.get("state") == "running" and watcher.get("identity") and not watcher.get("alive"):
        findings.append("watcher-not-running")
    observer = status.get("observer") or {}
    if (
        manifest.get("state") == "running"
        and observer.get("enabled") is True
        and not observer.get("alive")
    ):
        findings.append("observer-not-running")
    heartbeat_health = watcher.get("heartbeatHealth") or {}
    if manifest.get("state") == "running" and heartbeat_health.get("state") == "stale":
        findings.append("watcher-heartbeat-stale")
    if manifest.get("state") == "running" and heartbeat_health.get("state") == "invalid":
        findings.append("watcher-heartbeat-invalid")
    if status["clients"]["rustCount"] != 1:
        findings.append("rust-process-count")
    if status["clients"]["mfcCount"] != 1:
        findings.append("mfc-process-count")
    rest = status.get("rest") or {}
    for client in ("rust", "mfc"):
        health = rest.get(client)
        if not isinstance(health, dict):
            continue
        if not health.get("ok"):
            findings.append(f"{client}-rest-unhealthy")
            continue
        if not isinstance(health.get("vpnGuard"), dict) or not health[
            "vpnGuard"
        ].get("ok"):
            findings.append(f"{client}-vpn-guard-unhealthy")
        if not isinstance(health.get("p2pBinding"), dict) or not health[
            "p2pBinding"
        ].get("ok"):
            findings.append(f"{client}-p2p-binding-unhealthy")
    diagnostic_writers = status.get("diagnosticWriters") or {}
    if diagnostic_writers.get("required"):
        for client in ("rust", "mfc"):
            health = diagnostic_writers.get(client)
            if isinstance(health, dict) and health.get("reachable") is False:
                findings.append(f"{client}-diagnostic-writer-unavailable")
            elif not isinstance(health, dict) or not health.get("ok"):
                findings.append(f"{client}-diagnostic-writer-unhealthy")
    vpn = status.get("vpn")
    if isinstance(vpn, dict) and not vpn.get("ok"):
        findings.append("full-tunnel-unhealthy")
    last_run = status.get("lastRun") or {}
    if last_run.get("status") == "failed":
        findings.append("launcher-reported-failure")
    storage = status.get("storage")
    if isinstance(storage, dict) and storage.get("ok") is False:
        findings.append(STORAGE_FAILURE_FINDING)
    return findings


def bounded_error(value: object) -> dict[str, str] | None:
    """Returns bounded failure metadata without retaining tracebacks or payloads."""

    if not isinstance(value, dict):
        return None
    error_type = str(value.get("type") or "")[:128]
    message = str(value.get("message") or "")[:256]
    if not error_type and not message:
        return None
    return {"type": error_type, "message": message}


def current_observer_report(
    manifest: dict[str, Any],
    last_run: dict[str, Any],
) -> dict[str, Any] | None:
    """Returns the exact current cumulative-plus-retained observer report."""

    observer_config = manifest.get("observerConfig")
    if (
        not isinstance(observer_config, dict)
        or observer_config.get("enabled") is not True
    ):
        return None
    campaign_id = manifest.get("campaignId")
    if not isinstance(campaign_id, str) or last_run.get("campaignId") != campaign_id:
        return None
    report_dir_value = last_run.get("reportDir")
    if not isinstance(report_dir_value, str) or not report_dir_value.strip():
        return None
    report_dir = Path(report_dir_value).resolve()
    campaign_dir_value = manifest.get("campaignDir")
    if isinstance(campaign_dir_value, str) and campaign_dir_value.strip():
        expected_report_dir = Path(campaign_dir_value).resolve() / "report"
        if report_dir != expected_report_dir:
            raise soak_report_summary.SoakReportSummaryError(
                "Observer report directory does not match the persisted session campaign."
            )
    elif (report_dir / "summary.json").is_file():
        raise soak_report_summary.SoakReportSummaryError(
            "Persisted session campaign directory is unavailable."
        )
    if not (report_dir / "summary.json").is_file():
        return None
    report = soak_report_summary.summarize_report(report_dir)
    if report.get("campaignId") != campaign_id:
        raise soak_report_summary.SoakReportSummaryError(
            "Observer report campaign does not match the persisted session."
        )
    return report


def session_status(
    paths: ControlPaths,
    *,
    check_rest: bool = True,
    check_vpn: bool = True,
) -> dict[str, Any]:
    """Returns restart-safe status for one persisted session."""

    manifest = load_json(paths.manifest)
    processes = windows_processes.collect_processes()
    launcher_identity = manifest.get("launcher") if isinstance(manifest.get("launcher"), dict) else {}
    observer_identity = manifest.get("observer") if isinstance(manifest.get("observer"), dict) else {}
    watcher_identity = manifest.get("watcher") if isinstance(manifest.get("watcher"), dict) else {}
    launcher = exact_process_row(launcher_identity, processes)
    observer = exact_process_row(observer_identity, processes)
    watcher = exact_process_row(watcher_identity, processes)
    tree = windows_processes.collect_process_tree(launcher.pid, processes) if launcher is not None else []
    preflight = manifest.get("preflight") if isinstance(manifest.get("preflight"), dict) else {}
    executables = preflight.get("executables") if isinstance(preflight.get("executables"), dict) else {}
    rust_name = Path(str(executables.get("rust") or "emulebb-rust-diagnostics.exe")).name.casefold()
    mfc_name = Path(str(executables.get("mfc") or "emule.exe")).name.casefold()
    rust_rows = [row for row in tree if row.name.casefold() == rust_name]
    mfc_rows = [row for row in tree if row.name.casefold() == mfc_name]
    control = preflight.get("control") if isinstance(preflight.get("control"), dict) else {}
    last_run = load_json(paths.last_run_manifest)
    campaign_id = manifest.get("campaignId")
    writer_health_required = bool(
        check_rest
        and control.get("rustBaseUrl")
        and control.get("mfcBaseUrl")
        and campaign_id
        and last_run.get("campaignId") == campaign_id
        and last_run.get("status") == "running"
    )
    rest = None
    diagnostic_writers: dict[str, Any] = {
        "required": writer_health_required,
        "rust": None,
        "mfc": None,
    }
    if check_rest and control.get("rustBaseUrl") and control.get("mfcBaseUrl"):
        rust_base_url = str(control.get("rustBaseUrl") or "")
        mfc_base_url = str(control.get("mfcBaseUrl") or "")
        rest = {
            "rust": rest_health(rust_base_url, soak_launch.RUST_API_KEY),
            "mfc": rest_health(mfc_base_url, soak_launch.MFC_API_KEY),
        }
        if writer_health_required:
            diagnostic_writers.update(
                {
                    "rust": diagnostic_writer_health(
                        rust_base_url, soak_launch.RUST_API_KEY
                    ),
                    "mfc": diagnostic_writer_health(
                        mfc_base_url, soak_launch.MFC_API_KEY
                    ),
                }
            )
    heartbeat = load_json(paths.watch_heartbeat)
    heartbeat_health = watch_heartbeat_health(manifest, heartbeat)
    heartbeat_storage = heartbeat.get("storage") if heartbeat_health.get("accepted") else None
    observer_report = current_observer_report(manifest, last_run)
    result: dict[str, Any] = {
        "schema": STATUS_SCHEMA,
        "timestampUtc": datetime.now(UTC).isoformat(),
        "manifest": {
            "path": str(paths.manifest),
            "exists": bool(manifest),
            "state": manifest.get("state"),
            "campaignId": campaign_id,
        },
        "launcher": {
            "alive": launcher is not None,
            "identity": launcher_identity,
        },
        "observer": {
            "enabled": bool(
                isinstance(manifest.get("observerConfig"), dict)
                and manifest["observerConfig"].get("enabled") is True
            ),
            "alive": observer is not None,
            "identity": observer_identity,
        },
        "observerReport": observer_report,
        "watcher": {
            "alive": watcher is not None,
            "identity": watcher_identity,
            "heartbeat": heartbeat,
            "heartbeatHealth": heartbeat_health,
        },
        "clients": {
            "rustCount": len(rust_rows),
            "mfcCount": len(mfc_rows),
            "processes": [
                *(process_summary(row, "rust") for row in rust_rows),
                *(process_summary(row, "mfc") for row in mfc_rows),
            ],
        },
        "profiles": preflight.get("profiles"),
        "diagnosticDirs": preflight.get("diagnosticDirs"),
        "lastRun": {
            "campaignId": last_run.get("campaignId"),
            "status": last_run.get("status"),
            "error": bounded_error(last_run.get("error")),
        },
        "rest": rest,
        "diagnosticWriters": diagnostic_writers,
        "vpn": full_tunnel_health() if check_vpn else None,
        "storage": heartbeat_storage,
    }
    result["findings"] = status_findings(result)
    result["ok"] = not result["findings"]
    return result


def rotated_path(path: Path, index: int) -> Path:
    """Returns one numbered JSONL segment path."""

    return path.with_name(f"{path.name}.{index}")


def append_bounded_jsonl(path: Path, payload: dict[str, Any], *, max_bytes: int, segments: int) -> None:
    """Appends one JSONL record and rotates a bounded number of segments."""

    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than zero.")
    if segments <= 0:
        raise ValueError("segments must be greater than zero.")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    if path.is_file() and path.stat().st_size + len(encoded) > max_bytes:
        rotated_path(path, segments).unlink(missing_ok=True)
        for index in range(segments - 1, 0, -1):
            source = rotated_path(path, index)
            if source.exists():
                source.replace(rotated_path(path, index + 1))
        path.replace(rotated_path(path, 1))
    with path.open("ab") as handle:
        handle.write(encoded)


def build_watch_sample(
    status: dict[str, Any] | None,
    storage: dict[str, Any],
    *,
    status_error: Exception | None = None,
) -> dict[str, Any]:
    """Builds one bounded health and storage enforcement record."""

    findings = list(status.get("findings", [])) if status is not None else ["watch-status-unavailable"]
    if not storage.get("ok") and STORAGE_FAILURE_FINDING not in findings:
        findings.append(STORAGE_FAILURE_FINDING)
    sample = {
        "schema": WATCH_SCHEMA,
        "campaignId": status.get("manifest", {}).get("campaignId") if status is not None else None,
        "timestampUtc": (
            status.get("timestampUtc") if status is not None else datetime.now(UTC).isoformat()
        ),
        "ok": bool(status is not None and status.get("ok") and storage.get("ok")),
        "findings": findings,
        "launcherAlive": bool(status is not None and status.get("launcher", {}).get("alive")),
        "rustProcessCount": status.get("clients", {}).get("rustCount", 0) if status is not None else 0,
        "mfcProcessCount": status.get("clients", {}).get("mfcCount", 0) if status is not None else 0,
        "rest": status.get("rest") if status is not None else None,
        "diagnosticWriters": (
            status.get("diagnosticWriters") if status is not None else None
        ),
        "diagnosticIndexes": (
            status.get("diagnosticIndexes") if status is not None else None
        ),
        "vpn": status.get("vpn") if status is not None else None,
        "lastRun": status.get("lastRun") if status is not None else None,
        "storage": storage,
    }
    if status_error is not None:
        sample["statusError"] = {
            "type": type(status_error).__name__,
            "message": str(status_error)[:1024],
        }
    return sample


def watch_sample_is_post_readiness(sample: dict[str, Any]) -> bool:
    """Returns whether one watch sample is authoritative for runtime health."""

    campaign_id = sample.get("campaignId")
    last_run = sample.get("lastRun")
    return bool(
        campaign_id
        and isinstance(last_run, dict)
        and last_run.get("campaignId") == campaign_id
        and last_run.get("status") == "running"
    )


def advance_finding_streaks(
    previous: dict[str, int], findings: list[str]
) -> dict[str, int]:
    """Advances only findings that require consecutive unhealthy samples."""

    active = set(findings)
    return {
        finding: previous.get(finding, 0) + 1
        for finding in CONSECUTIVE_FAILURE_THRESHOLDS
        if finding in active
    }


def restored_finding_streaks(
    heartbeat: dict[str, Any], campaign_id: object
) -> dict[str, int]:
    """Restores bounded consecutive-failure state for the same campaign."""

    if (
        not campaign_id
        or heartbeat.get("campaignId") != campaign_id
        or isinstance(heartbeat.get("shutdown"), dict)
    ):
        return {}
    streaks = heartbeat.get("findingStreaks")
    if not isinstance(streaks, dict):
        return {}
    return {
        finding: min(value, CONSECUTIVE_FAILURE_THRESHOLDS[finding])
        for finding, value in streaks.items()
        if finding in CONSECUTIVE_FAILURE_THRESHOLDS
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    }


def terminal_watch_findings(
    sample: dict[str, Any], finding_streaks: dict[str, int]
) -> list[str]:
    """Classifies terminal findings without treating transient REST loss as fatal."""

    findings = set(sample.get("findings") or ())
    terminal: set[str] = set()
    if "launcher-reported-failure" in findings:
        terminal.add("launcher-reported-failure")
    if watch_sample_is_post_readiness(sample):
        terminal.update(findings & POST_READINESS_IMMEDIATE_FAILURE_FINDINGS)
        terminal.update(
            finding
            for finding, threshold in CONSECUTIVE_FAILURE_THRESHOLDS.items()
            if finding_streaks.get(finding, 0) >= threshold
        )
    return sorted(terminal)


def watch_finding_annotation(
    sample: dict[str, Any], previous_streaks: dict[str, int]
) -> dict[str, Any]:
    """Builds persisted restart-safe finding streak and terminal evidence."""

    streaks = (
        advance_finding_streaks(previous_streaks, list(sample["findings"]))
        if watch_sample_is_post_readiness(sample)
        else {}
    )
    return {
        "findingStreaks": streaks,
        "terminalFindings": terminal_watch_findings(sample, streaks),
    }


def persist_watch_sample(
    paths: ControlPaths,
    sample: dict[str, Any],
    *,
    max_bytes: int,
    segments: int,
) -> None:
    """Persists one watch sample to both bounded history and heartbeat."""

    append_bounded_jsonl(paths.watch_jsonl, sample, max_bytes=max_bytes, segments=segments)
    write_json_atomic(paths.watch_heartbeat, sample)


def persist_terminal_watch_sample(
    paths: ControlPaths,
    sample: dict[str, Any],
    *,
    max_bytes: int,
    segments: int,
) -> list[str]:
    """Best-effort persists terminal evidence to each independent watch sink."""

    errors: list[str] = []
    try:
        append_bounded_jsonl(paths.watch_jsonl, sample, max_bytes=max_bytes, segments=segments)
    except Exception as error:  # noqa: BLE001 - continue to the independent heartbeat sink
        errors.append(f"watchJsonl: {type(error).__name__}: {error}"[:1024])
    try:
        write_json_atomic(paths.watch_heartbeat, sample)
    except Exception as error:  # noqa: BLE001 - fail-closed shutdown must still continue
        errors.append(f"watchHeartbeat: {type(error).__name__}: {error}"[:1024])
    return errors


def capture_exact_process_tree(identity: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Captures exact identities for the currently owned launcher tree."""

    processes = windows_processes.collect_processes()
    root = exact_process_row(identity, processes)
    if root is None:
        return ()
    return tuple(
        {
            "pid": row.pid,
            "parentPid": row.parent_pid,
            "creationDate": row.creation_date,
            "name": row.name,
        }
        for row in windows_processes.collect_process_tree(root.pid, processes)
    )


def remaining_exact_tree_rows(
    identities: tuple[dict[str, Any], ...],
) -> list[windows_processes.WindowsProcessInfo]:
    """Returns captured instances and current descendants of their exact lineage."""

    processes = windows_processes.collect_processes()
    captured_by_pid = {int(identity["pid"]): identity for identity in identities}
    current_by_pid = {row.pid: row for row in processes}
    blocked_parent_pids = {
        pid
        for pid, identity in captured_by_pid.items()
        if pid in current_by_pid
        and current_by_pid[pid].creation_date != identity["creationDate"]
    }
    ambiguous_children = [
        row.pid for row in processes if row.parent_pid in blocked_parent_pids
    ]
    if ambiguous_children:
        raise RuntimeError(
            "Captured launcher-tree PID reuse made descendant ownership ambiguous: "
            + ", ".join(str(pid) for pid in sorted(ambiguous_children))
        )
    owned_parent_pids = set(captured_by_pid) - blocked_parent_pids
    selected = {
        row.pid: row
        for identity in identities
        if (row := exact_process_row(identity, processes)) is not None
    }
    changed = True
    while changed:
        changed = False
        for row in processes:
            if row.pid in selected or row.pid in blocked_parent_pids:
                continue
            if row.parent_pid in owned_parent_pids:
                selected[row.pid] = row
                owned_parent_pids.add(row.pid)
                changed = True
    return list(selected.values())


def stop_captured_process_tree(
    identities: tuple[dict[str, Any], ...],
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Force-stops the remaining roots of one pre-stop exact tree snapshot."""

    remaining = remaining_exact_tree_rows(identities)
    if not remaining:
        return {
            "forced": False,
            "alreadyStopped": True,
            "verifiedStopped": True,
            "capturedCount": len(identities),
            "remainingPids": [],
        }
    remaining_pids = {row.pid for row in remaining}
    roots = [row for row in remaining if row.parent_pid not in remaining_pids]
    verification_identities = identities + tuple(
        {
            "pid": row.pid,
            "parentPid": row.parent_pid,
            "creationDate": row.creation_date,
            "name": row.name,
        }
        for row in remaining
        if row.pid not in {int(identity["pid"]) for identity in identities}
    )
    results = [
        windows_processes.terminate_process_tree(
            row.pid,
            timeout_seconds=timeout_seconds,
            expected_root_creation_date=row.creation_date,
        )
        for row in roots
    ]
    survivors = remaining_exact_tree_rows(verification_identities)
    termination_verified = all(
        result.get("return_code") == 0
        and isinstance(result.get("remaining_pids"), list)
        and not result["remaining_pids"]
        for result in results
    )
    return {
        "forced": True,
        "alreadyStopped": False,
        "verifiedStopped": termination_verified and not survivors,
        "capturedCount": len(identities),
        "verificationIdentityCount": len(verification_identities),
        "forcedRootPids": [row.pid for row in roots],
        "results": results,
        "remainingPids": [row.pid for row in survivors],
    }


def request_watch_failure_stop(
    paths: ControlPaths,
    manifest: dict[str, Any],
    *,
    launcher_fallback: dict[str, Any] | None = None,
    graceful_timeout_seconds: float = WATCH_FAILURE_GRACE_SECONDS,
) -> dict[str, Any]:
    """Stops the launcher without waiting on or terminating the current watcher."""

    requested_at = datetime.now(UTC).isoformat()
    stop_errors: list[str] = []
    try:
        launcher_identity = resolve_watcher_launcher_identity(manifest, launcher_fallback)
    except RuntimeError as error:
        stop_errors.append(f"launcherIdentity: {error}"[:1024])
        launcher_identity = (
            exact_identity_payload(launcher_fallback)
            or exact_identity_payload(manifest.get("launcher"))
            or {}
        )
    identity_available = bool(launcher_identity)
    captured_tree: tuple[dict[str, Any], ...] = ()
    if identity_available:
        try:
            captured_tree = capture_exact_process_tree(launcher_identity)
        except Exception as error:  # noqa: BLE001 - stop requests and exact fallback remain available
            stop_errors.append(f"launcherTreeCapture: {type(error).__name__}: {error}"[:1024])

    try:
        paths.control_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        stop_errors.append(f"{paths.control_dir}: {type(error).__name__}: {error}"[:1024])
    for stop_path in (paths.stop_file, paths.watch_stop_file):
        try:
            stop_path.write_text(requested_at + "\n", encoding="utf-8", newline="\n")
        except OSError as error:
            stop_errors.append(f"{stop_path}: {type(error).__name__}: {error}"[:1024])

    try:
        observer_stop = stop_owned_process(
            manifest.get("observer"),
            markers=("converged-soak-observer.py",),
            graceful_timeout_seconds=graceful_timeout_seconds,
        )
    except Exception as error:  # noqa: BLE001 - launcher shutdown must still proceed
        stop_errors.append(f"observerStop: {type(error).__name__}: {error}"[:1024])
        observer_stop = {
            "identityAvailable": bool(exact_identity_payload(manifest.get("observer"))),
            "graceful": False,
            "force": {
                "forced": False,
                "alreadyStopped": False,
                "verifiedStopped": False,
                "errorType": type(error).__name__,
                "error": str(error)[:1024],
            },
        }

    if not identity_available:
        launcher_graceful = False
        launcher_force = {
            "forced": False,
            "alreadyStopped": False,
            "verifiedStopped": False,
            "errorType": "LauncherIdentityUnavailable",
            "error": "Exact launcher PID and creation date were unavailable.",
        }
    else:
        try:
            launcher_root_exited = wait_exact_exit(launcher_identity, graceful_timeout_seconds)
        except Exception as error:  # noqa: BLE001 - exact forced cleanup remains available
            launcher_root_exited = False
            stop_errors.append(f"launcherWait: {type(error).__name__}: {error}"[:1024])
        try:
            captured_tree_stopped = bool(captured_tree) and not remaining_exact_tree_rows(captured_tree)
        except Exception as error:  # noqa: BLE001 - exact forced cleanup remains available
            captured_tree_stopped = False
            stop_errors.append(f"launcherTreeVerify: {type(error).__name__}: {error}"[:1024])
        launcher_graceful = launcher_root_exited and captured_tree_stopped
        if launcher_graceful:
            launcher_force = {
                "forced": False,
                "alreadyStopped": True,
                "verifiedStopped": True,
                "capturedCount": len(captured_tree),
            }
        else:
            try:
                if captured_tree:
                    launcher_force = stop_captured_process_tree(
                        captured_tree,
                        timeout_seconds=WATCH_FAILURE_GRACE_SECONDS,
                    )
                elif not launcher_root_exited:
                    launcher_force = stop_exact_process(
                        launcher_identity,
                        markers=("launch-soak.py",),
                        timeout_seconds=WATCH_FAILURE_GRACE_SECONDS,
                    )
                else:
                    launcher_force = {
                        "forced": False,
                        "alreadyStopped": True,
                        "verifiedStopped": False,
                        "errorType": "LauncherTreeUnavailable",
                        "error": "Launcher exited before its owned process tree could be captured.",
                    }
            except Exception as error:  # noqa: BLE001 - preserve terminal shutdown evidence
                launcher_force = {
                    "forced": False,
                    "alreadyStopped": False,
                    "verifiedStopped": False,
                    "errorType": type(error).__name__,
                    "error": str(error)[:1024],
                }
    launcher_stopped = bool(launcher_graceful or launcher_force.get("verifiedStopped"))
    return {
        "stopRequestedUtc": requested_at,
        "stopWriteErrors": stop_errors,
        "launcherIdentityAvailable": identity_available,
        "observerStop": observer_stop,
        "capturedProcessCount": len(captured_tree),
        "launcherGraceful": launcher_graceful,
        "launcherForce": launcher_force,
        "launcherStopped": launcher_stopped,
    }


def finish_watch_failure(
    paths: ControlPaths,
    manifest: dict[str, Any],
    latest: dict[str, Any],
    *,
    sample_count: int,
    max_bytes: int,
    segments: int,
    launcher_fallback: dict[str, Any] | None,
    emit: Callable[[dict[str, Any]], None] | None,
    initial_persisted: bool,
    persistence_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Persists terminal evidence before and after verified launcher shutdown."""

    errors = list(persistence_errors or ())
    if not initial_persisted:
        errors.extend(
            persist_terminal_watch_sample(
                paths,
                latest,
                max_bytes=max_bytes,
                segments=segments,
            )
        )
    stop = request_watch_failure_stop(
        paths,
        manifest,
        launcher_fallback=launcher_fallback,
    )
    latest = {**latest, "shutdown": stop}
    errors.extend(
        persist_terminal_watch_sample(
            paths,
            latest,
            max_bytes=max_bytes,
            segments=segments,
        )
    )
    if emit is not None:
        try:
            emit(latest)
        except Exception as error:  # noqa: BLE001 - terminal shutdown is already complete
            errors.append(f"watchEmit: {type(error).__name__}: {error}"[:1024])
    return {
        "ok": False,
        "samples": sample_count,
        "latest": latest,
        "watchJsonl": str(paths.watch_jsonl),
        "persistenceErrors": errors,
        "stop": stop,
    }


def watch_session(
    paths: ControlPaths,
    *,
    interval_seconds: float,
    max_bytes: int,
    segments: int,
    max_samples: int = 0,
    emit: Callable[[dict[str, Any]], None] | None = None,
    launcher_fallback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Runs periodic health checks until stopped or the launcher exits."""

    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be greater than zero.")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be greater than zero.")
    if segments <= 0:
        raise ValueError("segments must be greater than zero.")
    if max_samples < 0:
        raise ValueError("max_samples must be zero or greater.")
    manifest: dict[str, Any] = {}
    sample_count = 0
    latest: dict[str, Any] | None = None
    finding_streaks: dict[str, int] = {}
    try:
        manifest = load_json(paths.manifest)
        storage_context = parse_session_storage_context(
            manifest,
            get_workspace_output_root(),
        )
        resolve_watcher_launcher_identity(manifest, launcher_fallback)
        finding_streaks = restored_finding_streaks(
            load_json(paths.watch_heartbeat),
            manifest.get("campaignId"),
        )
    except Exception as error:  # noqa: BLE001 - invalid storage authority is terminal
        storage = {
            "ok": False,
            "phase": "context",
            "errorType": type(error).__name__,
            "error": str(error)[:1024],
        }
        status_error = None
        try:
            status = session_status(paths)
        except Exception as error:  # noqa: BLE001 - retain the primary storage failure
            status = None
            status_error = error
        latest = build_watch_sample(status, storage, status_error=status_error)
        latest.update(watch_finding_annotation(latest, {}))
        return finish_watch_failure(
            paths,
            manifest,
            latest,
            sample_count=1,
            max_bytes=max_bytes,
            segments=segments,
            launcher_fallback=launcher_fallback,
            emit=emit,
            initial_persisted=False,
        )

    while max_samples <= 0 or sample_count < max_samples:
        if paths.watch_stop_file.exists():
            break
        try:
            storage = enforce_session_storage_context(storage_context)
        except Exception as error:  # noqa: BLE001 - enforcement exceptions are terminal
            storage = {
                "ok": False,
                "phase": "enforcement",
                "policySha256": storage_context.policy_sha256,
                "activeCampaignDir": str(storage_context.active_campaign),
                "previousCampaignDir": (
                    str(storage_context.previous_campaign)
                    if storage_context.previous_campaign is not None
                    else None
                ),
                "errorType": type(error).__name__,
                "error": str(error)[:1024],
            }
        try:
            status = session_status(paths)
            status_error = None
        except Exception as error:  # noqa: BLE001 - unattended health loss is terminal
            status = None
            status_error = error
            storage = {
                **storage,
                "ok": False,
                "phase": "watchStatus",
                "errorType": type(error).__name__,
                "error": str(error)[:1024],
            }
        if status is not None and storage.get("ok"):
            try:
                status["diagnosticIndexes"] = advance_diagnostic_indexes(
                    status,
                    storage_context,
                )
            except Exception as error:  # noqa: BLE001 - index evidence loss is terminal
                status["diagnosticIndexes"] = {
                    "required": bool(
                        (status.get("diagnosticWriters") or {}).get("required")
                    ),
                    "errorType": type(error).__name__,
                    "error": str(error)[:1024],
                }
                storage = {
                    **storage,
                    "ok": False,
                    "phase": "diagnosticIndexes",
                    "errorType": type(error).__name__,
                    "error": str(error)[:1024],
                }
        latest = build_watch_sample(status, storage, status_error=status_error)
        finding_annotation = watch_finding_annotation(latest, finding_streaks)
        finding_streaks = finding_annotation["findingStreaks"]
        latest.update(finding_annotation)
        initial_persisted = False
        persistence_errors: list[str] = []
        try:
            persist_watch_sample(
                paths,
                latest,
                max_bytes=max_bytes,
                segments=segments,
            )
            initial_persisted = True
        except Exception as error:  # noqa: BLE001 - watch evidence loss is terminal
            storage = {
                **storage,
                "ok": False,
                "phase": "watchEvidence",
                "errorType": type(error).__name__,
                "error": str(error)[:1024],
            }
            latest = build_watch_sample(status, storage, status_error=status_error)
            latest.update(finding_annotation)
        if storage.get("ok") and emit is not None:
            try:
                emit(latest)
            except Exception as error:  # noqa: BLE001 - watcher output loss is terminal
                storage = {
                    **storage,
                    "ok": False,
                    "phase": "watchEvidence",
                    "errorType": type(error).__name__,
                    "error": str(error)[:1024],
                }
                latest = build_watch_sample(status, storage, status_error=status_error)
                latest.update(finding_annotation)
                initial_persisted = False
        sample_count += 1
        if not storage.get("ok") or latest["terminalFindings"]:
            return finish_watch_failure(
                paths,
                manifest,
                latest,
                sample_count=sample_count,
                max_bytes=max_bytes,
                segments=segments,
                launcher_fallback=launcher_fallback,
                emit=emit,
                initial_persisted=initial_persisted,
                persistence_errors=persistence_errors,
            )
        assert status is not None
        if not status["launcher"]["alive"] or (max_samples > 0 and sample_count >= max_samples):
            break
        time.sleep(interval_seconds)
    return {
        "ok": True,
        "samples": sample_count,
        "latest": latest,
        "watchJsonl": str(paths.watch_jsonl),
    }


def wait_exact_exit(identity: dict[str, Any], timeout_seconds: float) -> bool:
    """Waits for one exact process identity to disappear."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if exact_process_row(identity, windows_processes.collect_processes()) is None:
            return True
        time.sleep(0.25)
    return exact_process_row(identity, windows_processes.collect_processes()) is None


def stop_exact_process(identity: dict[str, Any], *, markers: tuple[str, ...], timeout_seconds: float) -> dict[str, Any]:
    """Force-stops one still-live exact process tree."""

    processes = windows_processes.collect_processes()
    row = exact_process_row(identity, processes)
    if row is None:
        return {"forced": False, "alreadyStopped": True, "verifiedStopped": True}
    result = windows_processes.terminate_process_tree(
        row.pid,
        timeout_seconds=timeout_seconds,
        expected_command_line_markers=markers,
        expected_root_creation_date=row.creation_date,
    )
    verified_root_stopped = exact_process_row(identity, windows_processes.collect_processes()) is None
    remaining_pids = result.get("remaining_pids")
    verified_tree_stopped = bool(
        result.get("return_code") == 0
        and isinstance(remaining_pids, list)
        and not remaining_pids
    )
    return {
        "forced": True,
        "alreadyStopped": False,
        "verifiedRootStopped": verified_root_stopped,
        "verifiedStopped": verified_root_stopped and verified_tree_stopped,
        "result": result,
    }


def finalize_stopped_session_diagnostics(
    paths: ControlPaths,
    manifest: dict[str, Any],
    *,
    stopped_utc: str,
    launcher_stopped: bool,
    watcher_stopped: bool,
) -> dict[str, Any]:
    """Seals both diagnostic indexes after all writers and the watcher stop."""

    preflight = manifest.get("preflight")
    diagnostic_dirs = (
        preflight.get("diagnosticDirs") if isinstance(preflight, dict) else None
    )
    if not isinstance(diagnostic_dirs, dict):
        return {"required": False, "ok": True, "indexes": None}
    if not launcher_stopped:
        raise RuntimeError(
            "Diagnostic finalization requires the launcher and both clients to stop."
        )
    if not watcher_stopped:
        raise RuntimeError("Diagnostic finalization requires the watcher to stop.")

    heartbeat = load_json(paths.watch_heartbeat)
    campaign_id = manifest.get("campaignId")
    if not isinstance(campaign_id, str) or heartbeat.get("campaignId") != campaign_id:
        raise RuntimeError(
            "The final watcher heartbeat does not belong to the stopped campaign."
        )
    diagnostic_writers = heartbeat.get("diagnosticWriters")
    if (
        not isinstance(diagnostic_writers, dict)
        or diagnostic_writers.get("required") is not True
    ):
        raise RuntimeError(
            "The final watcher heartbeat has no authoritative diagnostic writer state."
        )
    context = parse_session_storage_context(manifest, get_workspace_output_root())
    indexes = finalize_diagnostic_indexes(
        diagnostic_dirs=diagnostic_dirs,
        diagnostic_writers=diagnostic_writers,
        context=context,
        observed_utc=stopped_utc,
    )
    ok = all(
        isinstance(indexes.get(client), dict)
        and indexes[client].get("ok") is True
        and indexes[client].get("finalized") is True
        for client in ("rust", "mfc")
    )
    return {"required": True, "ok": ok, "indexes": indexes}


def stop_session(paths: ControlPaths, *, graceful_timeout_seconds: float = 90.0) -> dict[str, Any]:
    """Requests graceful teardown, then force-stops exact owned processes if needed."""

    manifest = load_json(paths.manifest)
    if not manifest:
        return {
            "schema": "emulebb.persisted-soak-stop.v1",
            "noSession": True,
            "manifest": str(paths.manifest),
        }
    launcher_identity = manifest.get("launcher") if isinstance(manifest.get("launcher"), dict) else {}
    observer_identity = manifest.get("observer") if isinstance(manifest.get("observer"), dict) else {}
    watcher_identity = manifest.get("watcher") if isinstance(manifest.get("watcher"), dict) else {}
    paths.control_dir.mkdir(parents=True, exist_ok=True)
    requested_at = datetime.now(UTC).isoformat()
    paths.stop_file.write_text(requested_at + "\n", encoding="utf-8", newline="\n")
    paths.watch_stop_file.write_text(requested_at + "\n", encoding="utf-8", newline="\n")

    observer_stop = stop_owned_process(
        observer_identity,
        markers=("converged-soak-observer.py",),
        graceful_timeout_seconds=min(graceful_timeout_seconds, 15.0),
    )
    launcher_graceful = wait_exact_exit(launcher_identity, graceful_timeout_seconds)
    launcher_force = (
        {"forced": False, "alreadyStopped": True}
        if launcher_graceful
        else stop_exact_process(launcher_identity, markers=("launch-soak.py",), timeout_seconds=15.0)
    )
    watcher_graceful = wait_exact_exit(watcher_identity, min(graceful_timeout_seconds, 15.0))
    watcher_force = (
        {"forced": False, "alreadyStopped": True}
        if watcher_graceful
        else stop_exact_process(
            watcher_identity,
            markers=("persisted-soak-control.py", "watch"),
            timeout_seconds=15.0,
        )
    )
    stopped_utc = datetime.now(UTC).isoformat()
    launcher_stopped = launcher_graceful or launcher_force.get("verifiedStopped") is True
    watcher_stopped = watcher_graceful or watcher_force.get("verifiedStopped") is True
    try:
        diagnostic_finalization = finalize_stopped_session_diagnostics(
            paths,
            manifest,
            stopped_utc=stopped_utc,
            launcher_stopped=launcher_stopped,
            watcher_stopped=watcher_stopped,
        )
    except Exception as error:  # noqa: BLE001 - evidence loss must remain explicit
        diagnostic_finalization = {
            "required": True,
            "ok": False,
            "errorType": type(error).__name__,
            "error": str(error)[:1024],
        }
    observer_stopped = bool(
        observer_stop["graceful"]
        or observer_stop["force"].get("verifiedStopped") is True
    )
    stop_ok = bool(
        launcher_stopped
        and observer_stopped
        and watcher_stopped
        and diagnostic_finalization.get("ok") is True
    )
    report = {
        "stopRequestedUtc": requested_at,
        "launcherGraceful": launcher_graceful,
        "launcherForce": launcher_force,
        "observerGraceful": observer_stop["graceful"],
        "observerForce": observer_stop["force"],
        "watcherGraceful": watcher_graceful,
        "watcherForce": watcher_force,
        "diagnosticFinalization": diagnostic_finalization,
    }
    manifest["state"] = "stopped" if stop_ok else "stop-failed"
    manifest["stoppedUtc"] = stopped_utc
    manifest["stop"] = report
    if manifest:
        write_json_atomic(paths.manifest, manifest)
    return {
        "schema": "emulebb.persisted-soak-stop.v1",
        "ok": stop_ok,
        **report,
        "status": session_status(paths, check_rest=False, check_vpn=False),
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds the operator CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-dir", type=Path, help="Override the output-root soak control directory.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser(
        "preflight",
        help="Validate profiles, diagnostics binaries, localhost control, and full-tunnel VPN state without launching.",
    )
    add_session_config_arguments(preflight)

    start = subparsers.add_parser("start", help="Start detached MFC and Rust diagnostics plus health watch.")
    add_session_config_arguments(start)
    start.add_argument("--no-watch", action="store_true")
    start.add_argument("--no-observer", action="store_true")
    start.add_argument("--watch-interval-seconds", type=float, default=DEFAULT_WATCH_INTERVAL_SECONDS)
    start.add_argument("--watch-max-bytes", type=int, default=DEFAULT_WATCH_MAX_BYTES)
    start.add_argument("--watch-segments", type=int, default=DEFAULT_WATCH_SEGMENTS)
    start.add_argument(
        "--observer-ready-timeout-seconds",
        type=float,
        default=converged_observer.DEFAULT_READY_TIMEOUT_SECONDS,
    )
    start.add_argument(
        "--observer-poll-interval-seconds",
        type=float,
        default=converged_observer.DEFAULT_POLL_INTERVAL_SECONDS,
    )
    start.add_argument(
        "--observer-checkpoint-interval-seconds",
        type=float,
        default=converged_observer.DEFAULT_CHECKPOINT_INTERVAL_SECONDS,
    )
    start.add_argument(
        "--observer-failure-threshold",
        type=int,
        default=converged_observer.DEFAULT_FAILURE_THRESHOLD,
    )
    start.add_argument("--observer-drive-actions", action="store_true")
    start.add_argument("--observer-action-term", action="append", default=[])
    start.add_argument(
        "--observer-action-method",
        choices=converged_observer.ACTION_METHODS,
        default=converged_observer.DEFAULT_ACTION_METHOD,
    )
    start.add_argument(
        "--observer-action-start-delay-seconds",
        type=float,
        default=converged_observer.DEFAULT_ACTION_START_DELAY_SECONDS,
    )
    start.add_argument(
        "--observer-action-search-interval-seconds",
        type=float,
        default=converged_observer.DEFAULT_ACTION_INTERVAL_SECONDS,
    )
    start.add_argument(
        "--observer-action-search-timeout-seconds",
        type=float,
        default=converged_observer.DEFAULT_ACTION_SEARCH_TIMEOUT_SECONDS,
    )
    start.add_argument("--observer-action-max-cycles", type=int, default=0)

    status = subparsers.add_parser("status", help="Print exact process, client, REST, VPN, and watch health.")
    status.add_argument("--no-rest", action="store_true")
    status.add_argument("--no-vpn", action="store_true")

    watch = subparsers.add_parser("watch", help="Run periodic bounded health sampling.")
    watch.add_argument("--interval-seconds", type=float, default=DEFAULT_WATCH_INTERVAL_SECONDS)
    watch.add_argument("--max-bytes", type=int, default=DEFAULT_WATCH_MAX_BYTES)
    watch.add_argument("--segments", type=int, default=DEFAULT_WATCH_SEGMENTS)
    watch.add_argument("--max-samples", type=int, default=0)
    watch.add_argument("--launcher-pid", type=int)
    watch.add_argument("--launcher-creation-date")

    stop = subparsers.add_parser("stop", help="Gracefully stop the detached soak and health watcher.")
    stop.add_argument("--graceful-timeout-seconds", type=float, default=90.0)
    return parser


def add_session_config_arguments(parser: argparse.ArgumentParser) -> None:
    """Adds the shared persisted-session selection arguments."""

    parser.add_argument("--inputs", type=Path, default=REPO_ROOT / "live-wire-inputs.local.json")
    parser.add_argument(
        "--vpn-guard-live-config",
        type=Path,
        default=REPO_ROOT / "vpn-guard-live.local.json",
    )
    parser.add_argument("--lan-bind-addr", default=DEFAULT_CONTROL_BIND)
    parser.add_argument("--rest-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--connect-timeout-seconds", type=float, default=240.0)
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)


def session_config_from_args(args: argparse.Namespace) -> SessionConfig:
    """Builds one persisted-session configuration from shared CLI arguments."""

    return SessionConfig(
        inputs=args.inputs,
        vpn_guard_config=args.vpn_guard_live_config,
        lan_bind_addr=args.lan_bind_addr,
        rest_timeout_seconds=args.rest_timeout_seconds,
        connect_timeout_seconds=args.connect_timeout_seconds,
        mfc_variant=args.mfc_variant,
        mfc_arch=args.mfc_arch,
        mfc_configuration=args.mfc_configuration,
    )


def main(argv: list[str] | None = None) -> int:
    """Runs the persisted dual-client soak controller."""

    args = build_parser().parse_args(argv)
    output_root = get_workspace_output_root()
    paths = build_control_paths(output_root, args.control_dir)
    if args.command == "preflight":
        result = preflight_session(session_config_from_args(args), output_root)
    elif args.command == "start":
        config = session_config_from_args(args)
        result = start_session(
            config,
            paths,
            start_watch=not args.no_watch,
            start_observer=not args.no_observer,
            watch_interval_seconds=args.watch_interval_seconds,
            watch_max_bytes=args.watch_max_bytes,
            watch_segments=args.watch_segments,
            observer_ready_timeout_seconds=args.observer_ready_timeout_seconds,
            observer_poll_interval_seconds=args.observer_poll_interval_seconds,
            observer_checkpoint_interval_seconds=args.observer_checkpoint_interval_seconds,
            observer_failure_threshold=args.observer_failure_threshold,
            observer_drive_actions=args.observer_drive_actions,
            observer_action_terms=tuple(args.observer_action_term),
            observer_action_method=args.observer_action_method,
            observer_action_start_delay_seconds=args.observer_action_start_delay_seconds,
            observer_action_search_interval_seconds=args.observer_action_search_interval_seconds,
            observer_action_search_timeout_seconds=args.observer_action_search_timeout_seconds,
            observer_action_max_cycles=args.observer_action_max_cycles,
        )
    elif args.command == "status":
        result = session_status(paths, check_rest=not args.no_rest, check_vpn=not args.no_vpn)
    elif args.command == "watch":
        launcher_fallback = None
        if args.launcher_pid is not None or args.launcher_creation_date is not None:
            if args.launcher_pid is None or not args.launcher_creation_date:
                raise RuntimeError("Watcher launcher fallback requires both PID and creation date.")
            launcher_fallback = {
                "pid": args.launcher_pid,
                "creationDate": args.launcher_creation_date,
            }
        result = watch_session(
            paths,
            interval_seconds=args.interval_seconds,
            max_bytes=args.max_bytes,
            segments=args.segments,
            max_samples=args.max_samples,
            emit=lambda record: print(json.dumps(record, sort_keys=True), flush=True),
            launcher_fallback=launcher_fallback,
        )
    else:
        result = stop_session(paths, graceful_timeout_seconds=args.graceful_timeout_seconds)
    print(json.dumps(result, indent=2, sort_keys=True))
    if isinstance(result, dict) and result.get("ok") is False:
        return 1
    return 0
