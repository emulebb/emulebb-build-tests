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
from . import hideme_vpn, soak_launch, soak_run_layout, soak_storage, windows_processes
from .live_wire_inputs import LiveWireInputs, load_live_wire_inputs
from .paths import get_workspace_output_root, path_is_relative_to
from .vm_guest_profiles import http_json

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_SCRIPT = REPO_ROOT / "scripts" / "persisted-soak-control.py"
LAUNCH_SCRIPT = REPO_ROOT / "scripts" / "launch-soak.py"
BOUNDED_PROCESS_SCRIPT = REPO_ROOT / "scripts" / "run-bounded-process.py"
MANIFEST_SCHEMA = "emulebb.persisted-soak-session.v1"
STATUS_SCHEMA = "emulebb.persisted-soak-status.v1"
WATCH_SCHEMA = "emulebb.persisted-soak-watch.v1"
DEFAULT_CONTROL_BIND = "127.0.0.1"
DEFAULT_WATCH_INTERVAL_SECONDS = 60.0
DEFAULT_WATCH_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_WATCH_SEGMENTS = 4
WATCH_FAILURE_GRACE_SECONDS = 15.0
STORAGE_FAILURE_FINDING = "campaign-storage-enforcement-failed"


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


def preflight_campaign_storage(
    inputs: LiveWireInputs,
    output_root: Path,
    *,
    protected_campaigns: tuple[Path, ...],
) -> dict[str, Any]:
    """Plans aggregate retention without mutating campaign evidence."""

    policy = required_storage_policy(inputs)
    root = campaign_storage_root(output_root)
    plan = soak_storage.BoundedArtifactStore(root, policy).plan(pinned_paths=protected_campaigns)
    if not plan.within_limits:
        constraints = ", ".join(plan.unresolved_constraints) or "unknown"
        raise RuntimeError(f"Persisted soak storage cannot satisfy required limits: {constraints}.")
    return storage_plan_summary(root, plan)


def enforce_campaign_storage(
    inputs: LiveWireInputs,
    output_root: Path,
    *,
    protected_campaigns: tuple[Path, ...],
) -> dict[str, Any]:
    """Applies and verifies aggregate retention before any process launch."""

    policy = required_storage_policy(inputs)
    root = campaign_storage_root(output_root)
    result = soak_storage.BoundedArtifactStore(root, policy).enforce(pinned_paths=protected_campaigns)
    summary = storage_enforcement_summary(root, result)
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


def build_watch_command(
    paths: ControlPaths,
    *,
    interval_seconds: float,
    max_bytes: int,
    segments: int,
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


def start_session(
    config: SessionConfig,
    paths: ControlPaths,
    *,
    start_watch: bool = True,
    watch_interval_seconds: float = DEFAULT_WATCH_INTERVAL_SECONDS,
    watch_max_bytes: int = DEFAULT_WATCH_MAX_BYTES,
    watch_segments: int = DEFAULT_WATCH_SEGMENTS,
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
    existing = load_json(paths.manifest)
    processes = windows_processes.collect_processes()
    if exact_process_row(existing.get("launcher", {}), processes) is not None:
        raise RuntimeError(f"A persisted soak launcher is already active: {paths.manifest}")
    if exact_process_row(existing.get("watcher", {}), processes) is not None:
        raise RuntimeError(f"A persisted soak watcher is already active: {paths.manifest}")

    output_root = get_workspace_output_root()
    inputs = load_live_wire_inputs(config.inputs.resolve())
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
        "watcher": None,
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
            "watchStdout": str(campaign_output.watch_stdout),
            "watchStderr": str(campaign_output.watch_stderr),
        },
    }
    write_json_atomic(paths.manifest, manifest)

    if start_watch:
        watch_target_command = build_watch_command(
            paths,
            interval_seconds=watch_interval_seconds,
            max_bytes=watch_max_bytes,
            segments=watch_segments,
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
        except Exception:
            paths.stop_file.write_text(datetime.now(UTC).isoformat() + "\n", encoding="utf-8", newline="\n")
            if not wait_exact_exit(manifest["launcher"], 15.0):
                stop_exact_process(manifest["launcher"], markers=("launch-soak.py",), timeout_seconds=15.0)
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
    """Returns a bounded REST health result without retaining response payloads."""

    try:
        payload = http_json(base_url, "/status", api_key=api_key, timeout_seconds=5.0)
        return {"ok": True, "responseType": type(payload).__name__}
    except Exception as error:  # noqa: BLE001 - health status retains only bounded error metadata
        return {"ok": False, "errorType": type(error).__name__, "error": str(error)[:256]}


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


def status_findings(status: dict[str, Any]) -> list[str]:
    """Returns actionable health findings for one session status."""

    findings: list[str] = []
    if not status["launcher"]["alive"]:
        findings.append("launcher-not-running")
    manifest = status.get("manifest") or {}
    watcher = status.get("watcher") or {}
    if manifest.get("state") == "running" and watcher.get("identity") and not watcher.get("alive"):
        findings.append("watcher-not-running")
    if status["clients"]["rustCount"] != 1:
        findings.append("rust-process-count")
    if status["clients"]["mfcCount"] != 1:
        findings.append("mfc-process-count")
    rest = status.get("rest") or {}
    for client in ("rust", "mfc"):
        if client in rest and not rest[client].get("ok"):
            findings.append(f"{client}-rest-unhealthy")
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
    watcher_identity = manifest.get("watcher") if isinstance(manifest.get("watcher"), dict) else {}
    launcher = exact_process_row(launcher_identity, processes)
    watcher = exact_process_row(watcher_identity, processes)
    tree = windows_processes.collect_process_tree(launcher.pid, processes) if launcher is not None else []
    preflight = manifest.get("preflight") if isinstance(manifest.get("preflight"), dict) else {}
    executables = preflight.get("executables") if isinstance(preflight.get("executables"), dict) else {}
    rust_name = Path(str(executables.get("rust") or "emulebb-rust-diagnostics.exe")).name.casefold()
    mfc_name = Path(str(executables.get("mfc") or "emule.exe")).name.casefold()
    rust_rows = [row for row in tree if row.name.casefold() == rust_name]
    mfc_rows = [row for row in tree if row.name.casefold() == mfc_name]
    control = preflight.get("control") if isinstance(preflight.get("control"), dict) else {}
    rest = None
    if check_rest and control.get("rustBaseUrl") and control.get("mfcBaseUrl"):
        rest = {
            "rust": rest_health(str(control.get("rustBaseUrl") or ""), soak_launch.RUST_API_KEY),
            "mfc": rest_health(str(control.get("mfcBaseUrl") or ""), soak_launch.MFC_API_KEY),
        }
    last_run = load_json(paths.last_run_manifest)
    heartbeat = load_json(paths.watch_heartbeat)
    campaign_id = manifest.get("campaignId")
    heartbeat_storage = None
    if (
        isinstance(campaign_id, str)
        and campaign_id
        and heartbeat.get("campaignId") == campaign_id
        and isinstance(heartbeat.get("storage"), dict)
    ):
        heartbeat_storage = heartbeat["storage"]
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
        "watcher": {
            "alive": watcher is not None,
            "identity": watcher_identity,
            "heartbeat": heartbeat,
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
        "lastRun": {
            "campaignId": last_run.get("campaignId"),
            "status": last_run.get("status"),
            "error": bounded_error(last_run.get("error")),
        },
        "rest": rest,
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


def request_watch_failure_stop(
    paths: ControlPaths,
    manifest: dict[str, Any],
    *,
    graceful_timeout_seconds: float = WATCH_FAILURE_GRACE_SECONDS,
) -> dict[str, Any]:
    """Stops the launcher without waiting on or terminating the current watcher."""

    requested_at = datetime.now(UTC).isoformat()
    stop_errors: list[str] = []
    paths.control_dir.mkdir(parents=True, exist_ok=True)
    for stop_path in (paths.stop_file, paths.watch_stop_file):
        try:
            stop_path.write_text(requested_at + "\n", encoding="utf-8", newline="\n")
        except OSError as error:
            stop_errors.append(f"{stop_path}: {type(error).__name__}: {error}"[:1024])

    launcher_identity = manifest.get("launcher") if isinstance(manifest.get("launcher"), dict) else {}
    try:
        launcher_graceful = wait_exact_exit(launcher_identity, graceful_timeout_seconds)
    except Exception as error:  # noqa: BLE001 - exact forced cleanup remains available
        launcher_graceful = False
        stop_errors.append(f"launcherWait: {type(error).__name__}: {error}"[:1024])
    if launcher_graceful:
        launcher_force = {"forced": False, "alreadyStopped": True}
    else:
        try:
            launcher_force = stop_exact_process(
                launcher_identity,
                markers=("launch-soak.py",),
                timeout_seconds=WATCH_FAILURE_GRACE_SECONDS,
            )
        except Exception as error:  # noqa: BLE001 - preserve terminal shutdown evidence
            launcher_force = {
                "forced": False,
                "alreadyStopped": False,
                "errorType": type(error).__name__,
                "error": str(error)[:1024],
            }
    return {
        "stopRequestedUtc": requested_at,
        "stopWriteErrors": stop_errors,
        "launcherGraceful": launcher_graceful,
        "launcherForce": launcher_force,
    }


def watch_session(
    paths: ControlPaths,
    *,
    interval_seconds: float,
    max_bytes: int,
    segments: int,
    max_samples: int = 0,
    emit: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Runs periodic health checks until stopped or the launcher exits."""

    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be greater than zero.")
    manifest: dict[str, Any] = {}
    sample_count = 0
    latest: dict[str, Any] | None = None
    try:
        manifest = load_json(paths.manifest)
        storage_context = parse_session_storage_context(
            manifest,
            get_workspace_output_root(),
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
        persistence_errors = persist_terminal_watch_sample(
            paths,
            latest,
            max_bytes=max_bytes,
            segments=segments,
        )
        if emit is not None:
            emit(latest)
        stop = request_watch_failure_stop(paths, manifest)
        return {
            "ok": False,
            "samples": 1,
            "latest": latest,
            "watchJsonl": str(paths.watch_jsonl),
            "persistenceErrors": persistence_errors,
            "stop": stop,
        }

    while max_samples <= 0 or sample_count < max_samples:
        if paths.watch_stop_file.exists():
            break
        storage = enforce_session_storage_context(storage_context)
        status = session_status(paths)
        latest = build_watch_sample(status, storage)
        try:
            persist_watch_sample(
                paths,
                latest,
                max_bytes=max_bytes,
                segments=segments,
            )
            persistence_errors: list[str] = []
        except Exception as error:  # noqa: BLE001 - watch evidence loss is terminal
            storage = {
                **storage,
                "ok": False,
                "phase": "watchEvidence",
                "errorType": type(error).__name__,
                "error": str(error)[:1024],
            }
            latest = build_watch_sample(status, storage)
            persistence_errors = persist_terminal_watch_sample(
                paths,
                latest,
                max_bytes=max_bytes,
                segments=segments,
            )
        if emit is not None:
            emit(latest)
        sample_count += 1
        if not storage.get("ok"):
            stop = request_watch_failure_stop(paths, manifest)
            return {
                "ok": False,
                "samples": sample_count,
                "latest": latest,
                "watchJsonl": str(paths.watch_jsonl),
                "persistenceErrors": persistence_errors,
                "stop": stop,
            }
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
        return {"forced": False, "alreadyStopped": True}
    result = windows_processes.terminate_process_tree(
        row.pid,
        timeout_seconds=timeout_seconds,
        expected_command_line_markers=markers,
        expected_root_creation_date=row.creation_date,
    )
    return {"forced": True, "alreadyStopped": False, "result": result}


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
    watcher_identity = manifest.get("watcher") if isinstance(manifest.get("watcher"), dict) else {}
    paths.control_dir.mkdir(parents=True, exist_ok=True)
    requested_at = datetime.now(UTC).isoformat()
    paths.stop_file.write_text(requested_at + "\n", encoding="utf-8", newline="\n")
    paths.watch_stop_file.write_text(requested_at + "\n", encoding="utf-8", newline="\n")

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
    report = {
        "stopRequestedUtc": requested_at,
        "launcherGraceful": launcher_graceful,
        "launcherForce": launcher_force,
        "watcherGraceful": watcher_graceful,
        "watcherForce": watcher_force,
    }
    manifest["state"] = "stopped"
    manifest["stoppedUtc"] = datetime.now(UTC).isoformat()
    manifest["stop"] = report
    if manifest:
        write_json_atomic(paths.manifest, manifest)
    return {
        "schema": "emulebb.persisted-soak-stop.v1",
        **report,
        "status": session_status(paths, check_rest=False, check_vpn=False),
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds the operator CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-dir", type=Path, help="Override the output-root soak control directory.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="Start detached MFC and Rust diagnostics plus health watch.")
    start.add_argument("--inputs", type=Path, default=REPO_ROOT / "live-wire-inputs.local.json")
    start.add_argument("--vpn-guard-live-config", type=Path, default=REPO_ROOT / "vpn-guard-live.local.json")
    start.add_argument("--lan-bind-addr", default=DEFAULT_CONTROL_BIND)
    start.add_argument("--rest-timeout-seconds", type=float, default=60.0)
    start.add_argument("--connect-timeout-seconds", type=float, default=240.0)
    start.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    start.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    start.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    start.add_argument("--no-watch", action="store_true")
    start.add_argument("--watch-interval-seconds", type=float, default=DEFAULT_WATCH_INTERVAL_SECONDS)
    start.add_argument("--watch-max-bytes", type=int, default=DEFAULT_WATCH_MAX_BYTES)
    start.add_argument("--watch-segments", type=int, default=DEFAULT_WATCH_SEGMENTS)

    status = subparsers.add_parser("status", help="Print exact process, client, REST, VPN, and watch health.")
    status.add_argument("--no-rest", action="store_true")
    status.add_argument("--no-vpn", action="store_true")

    watch = subparsers.add_parser("watch", help="Run periodic bounded health sampling.")
    watch.add_argument("--interval-seconds", type=float, default=DEFAULT_WATCH_INTERVAL_SECONDS)
    watch.add_argument("--max-bytes", type=int, default=DEFAULT_WATCH_MAX_BYTES)
    watch.add_argument("--segments", type=int, default=DEFAULT_WATCH_SEGMENTS)
    watch.add_argument("--max-samples", type=int, default=0)

    stop = subparsers.add_parser("stop", help="Gracefully stop the detached soak and health watcher.")
    stop.add_argument("--graceful-timeout-seconds", type=float, default=90.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the persisted dual-client soak controller."""

    args = build_parser().parse_args(argv)
    output_root = get_workspace_output_root()
    paths = build_control_paths(output_root, args.control_dir)
    if args.command == "start":
        config = SessionConfig(
            inputs=args.inputs,
            vpn_guard_config=args.vpn_guard_live_config,
            lan_bind_addr=args.lan_bind_addr,
            rest_timeout_seconds=args.rest_timeout_seconds,
            connect_timeout_seconds=args.connect_timeout_seconds,
            mfc_variant=args.mfc_variant,
            mfc_arch=args.mfc_arch,
            mfc_configuration=args.mfc_configuration,
        )
        result = start_session(
            config,
            paths,
            start_watch=not args.no_watch,
            watch_interval_seconds=args.watch_interval_seconds,
            watch_max_bytes=args.watch_max_bytes,
            watch_segments=args.watch_segments,
        )
    elif args.command == "status":
        result = session_status(paths, check_rest=not args.no_rest, check_vpn=not args.no_vpn)
    elif args.command == "watch":
        result = watch_session(
            paths,
            interval_seconds=args.interval_seconds,
            max_bytes=args.max_bytes,
            segments=args.segments,
            max_samples=args.max_samples,
            emit=lambda record: print(json.dumps(record, sort_keys=True), flush=True),
        )
    else:
        result = stop_session(paths, graceful_timeout_seconds=args.graceful_timeout_seconds)
    print(json.dumps(result, indent=2, sort_keys=True))
    if isinstance(result, dict) and result.get("ok") is False:
        return 1
    return 0
