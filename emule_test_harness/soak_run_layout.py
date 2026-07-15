"""Structured filesystem layout and preflight cleanup for converged soak runs."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import windows_processes
from .paths import path_is_relative_to

CAMPAIGN_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")

RUST_PACKET_DUMP_GLOBS = (
    "*.jsonl",
)
RUST_RUNTIME_FILES = (
    "daemon.out",
)
MFC_LOG_GLOBS = (
    "emulebb*.log",
    "emulebb*.trace.json",
    "emulebb-performance*.csv",
    "emulebb-performance*.mrtg",
    "emulebb-performance-data*.mrtg",
    "emulebb-performance-overhead*.mrtg",
)


@dataclass(frozen=True)
class SoakRunPaths:
    """Resolved paths for one converged soak campaign."""

    soak_root: Path
    campaign_id: str
    reports_root: Path
    report_dir: Path
    actions_dir: Path
    checkpoints_dir: Path
    archives_root: Path
    archive_dir: Path
    preflight_archive_dir: Path
    last_run_dir: Path
    last_run_manifest: Path
    latest_report_pointer: Path


def utc_campaign_id(now: datetime | None = None) -> str:
    """Returns the canonical UTC campaign id used by soak reports."""

    now = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ")


def validate_campaign_id(campaign_id: str) -> str:
    """Returns a campaign id or raises if it does not use the canonical format."""

    if not CAMPAIGN_ID_RE.match(campaign_id):
        raise ValueError(f"campaign_id must use UTC YYYYMMDDTHHMMSSZ format, got {campaign_id!r}.")
    return campaign_id


def build_run_paths(soak_root: Path, campaign_id: str) -> SoakRunPaths:
    """Builds the stable converged-soak path set for one campaign."""

    campaign_id = validate_campaign_id(campaign_id)
    reports_root = soak_root / "reports"
    report_dir = reports_root / campaign_id
    archive_dir = soak_root / "archives" / campaign_id
    return SoakRunPaths(
        soak_root=soak_root,
        campaign_id=campaign_id,
        reports_root=reports_root,
        report_dir=report_dir,
        actions_dir=report_dir / "actions",
        checkpoints_dir=report_dir / "checkpoints",
        archives_root=soak_root / "archives",
        archive_dir=archive_dir,
        preflight_archive_dir=archive_dir / "preflight",
        last_run_dir=soak_root / "last-run",
        last_run_manifest=soak_root / "last-run" / "manifest.json",
        latest_report_pointer=reports_root / "latest.json",
    )


def require_output_soak_root(soak_root: Path, output_root: Path) -> Path:
    """Returns the canonical soak root, rejecting repo/workspace-local reports."""

    resolved_output = output_root.resolve()
    resolved_soak = soak_root.resolve()
    expected = (resolved_output / "soak").resolve()
    if resolved_soak != expected:
        raise RuntimeError(f"converged soak output must be under EMULEBB_WORKSPACE_OUTPUT_ROOT\\soak: {resolved_soak}")
    if not path_is_relative_to(resolved_soak, resolved_output):
        raise RuntimeError(f"converged soak output escaped EMULEBB_WORKSPACE_OUTPUT_ROOT: {resolved_soak}")
    return resolved_soak


def mfc_soak_log_dir(*, mfc_artifacts_dir: Path, direct_profile_dir: Path | None) -> Path:
    """Returns the MFC log directory used by the converged soak profile."""

    if direct_profile_dir is not None:
        return direct_profile_dir / "logs"
    return mfc_artifacts_dir / "profiles" / "converged-soak" / "profile-base" / "logs"


def mfc_profile_base_from_log_dir(mfc_log_dir: Path | None) -> Path | None:
    """Returns the MFC profile base implied by a soak log directory."""

    return mfc_log_dir.parent if mfc_log_dir is not None else None


def _normalized_marker(value: Path | str) -> str:
    return str(value).strip().replace("/", "\\").casefold()


def _command_contains_path(command_line: str, path: Path | None) -> bool:
    if path is None:
        return False
    marker = _normalized_marker(path)
    return bool(marker) and marker in command_line.replace("/", "\\").casefold()


def current_process_and_ancestor_pids(processes: list[windows_processes.WindowsProcessInfo]) -> set[int]:
    """Returns the current process and parent-chain pids for self-protection."""

    by_pid = {process.pid: process for process in processes}
    excluded: set[int] = set()
    pid = os.getpid()
    while pid and pid not in excluded:
        excluded.add(pid)
        process = by_pid.get(pid)
        if process is None:
            break
        pid = process.parent_pid
    return excluded


def select_stale_soak_process_roots(
    processes: list[windows_processes.WindowsProcessInfo],
    *,
    rust_runtime_dir: Path,
    mfc_profile_base: Path | None,
    exclude_pids: set[int] | None = None,
) -> list[windows_processes.WindowsProcessInfo]:
    """Returns process roots that belong to an older converged soak run."""

    excluded = set(exclude_pids or set())
    selected: list[windows_processes.WindowsProcessInfo] = []
    for process in processes:
        if process.pid in excluded:
            continue
        name = process.name.casefold()
        command_line = process.command_line
        command_lower = command_line.casefold()
        is_runner = (
            "converged-soak-live.py" in command_lower
            or "scripts\\converged-soak-live.py" in command_lower
            or "launch-soak.py" in command_lower
            or "scripts\\launch-soak.py" in command_lower
        )
        is_rust = name == "emulebb-rust-diagnostics.exe" and _command_contains_path(command_line, rust_runtime_dir)
        is_mfc = name == "emulebb-diagnostics.exe" and _command_contains_path(command_line, mfc_profile_base)
        if is_runner or is_rust or is_mfc:
            selected.append(process)

    selected_pids = {process.pid for process in selected}
    return [process for process in selected if process.parent_pid not in selected_pids]


def stop_stale_soak_processes(
    *,
    rust_runtime_dir: Path,
    mfc_log_dir: Path | None,
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    """Stops stale process trees from previous runs before logs are archived."""

    if os.name != "nt":
        return {"enabled": False, "reason": "non-windows", "targets": [], "results": []}
    processes = windows_processes.collect_processes()
    excluded = current_process_and_ancestor_pids(processes)
    mfc_profile_base = mfc_profile_base_from_log_dir(mfc_log_dir)
    targets = select_stale_soak_process_roots(
        processes,
        rust_runtime_dir=rust_runtime_dir,
        mfc_profile_base=mfc_profile_base,
        exclude_pids=excluded,
    )
    results = [
        windows_processes.terminate_process_tree(
            target.pid,
            timeout_seconds=timeout_seconds,
            expected_root_creation_date=target.creation_date,
        )
        for target in targets
    ]
    return {
        "enabled": True,
        "excludedPids": sorted(excluded),
        "targets": [target.__dict__ for target in targets],
        "results": results,
    }


def _relative_move_target(source: Path, source_root: Path, archive_root: Path) -> Path:
    try:
        relative = source.relative_to(source_root)
    except ValueError:
        relative = Path(source.name)
    return archive_root / relative


def _archive_files(files: Iterable[Path], *, source_root: Path, archive_root: Path) -> list[dict[str, Any]]:
    archived: list[dict[str, Any]] = []
    for source in sorted({path.resolve() for path in files if path.is_file()}):
        target = _relative_move_target(source, source_root.resolve(), archive_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            suffix = 1
            while True:
                candidate = target.with_name(f"{target.stem}-{suffix}{target.suffix}")
                if not candidate.exists():
                    target = candidate
                    break
                suffix += 1
        size = source.stat().st_size
        shutil.move(str(source), str(target))
        archived.append({"from": str(source), "to": str(target), "bytes": size})
    return archived


def _glob_files(root: Path, patterns: Iterable[str]) -> list[Path]:
    if not root.exists():
        return []
    files: list[Path] = []
    for pattern in patterns:
        files.extend(path for path in root.glob(pattern) if path.is_file())
    return files


def archive_rust_volatile_outputs(
    *,
    rust_runtime_dir: Path,
    rust_packet_dump_dir: Path,
    archive_dir: Path,
) -> dict[str, Any]:
    """Archives Rust soak logs/dumps while preserving durable profile state."""

    runtime_files = [rust_runtime_dir / name for name in RUST_RUNTIME_FILES]
    packet_files = _glob_files(rust_packet_dump_dir, RUST_PACKET_DUMP_GLOBS)
    archived_runtime = _archive_files(
        runtime_files,
        source_root=rust_runtime_dir,
        archive_root=archive_dir / "rust-runtime",
    )
    archived_packets = _archive_files(
        packet_files,
        source_root=rust_packet_dump_dir,
        archive_root=archive_dir / "rust-packet-dump",
    )
    rust_packet_dump_dir.mkdir(parents=True, exist_ok=True)
    return {
        "runtimeFiles": archived_runtime,
        "packetDumpFiles": archived_packets,
        "archivedCount": len(archived_runtime) + len(archived_packets),
    }


def archive_mfc_log_outputs(*, mfc_log_dir: Path | None, archive_dir: Path) -> dict[str, Any]:
    """Archives known eMuleBB MFC log files while preserving unrelated files."""

    if mfc_log_dir is None:
        return {"enabled": False, "reason": "no-mfc-log-dir", "archivedFiles": [], "archivedCount": 0}
    files = _glob_files(mfc_log_dir, MFC_LOG_GLOBS)
    archived = _archive_files(files, source_root=mfc_log_dir, archive_root=archive_dir / "mfc-logs")
    mfc_log_dir.mkdir(parents=True, exist_ok=True)
    return {
        "enabled": True,
        "logDir": str(mfc_log_dir),
        "archivedFiles": archived,
        "archivedCount": len(archived),
    }


def prepare_clean_run(
    *,
    paths: SoakRunPaths,
    rust_runtime_dir: Path,
    rust_packet_dump_dir: Path,
    mfc_log_dir: Path | None,
    stop_process_cleanup: bool = True,
) -> dict[str, Any]:
    """Archives stale volatile outputs and creates a clean report directory."""

    paths.report_dir.mkdir(parents=True, exist_ok=True)
    paths.actions_dir.mkdir(parents=True, exist_ok=True)
    paths.checkpoints_dir.mkdir(parents=True, exist_ok=True)
    preflight = paths.preflight_archive_dir
    processes = (
        stop_stale_soak_processes(rust_runtime_dir=rust_runtime_dir, mfc_log_dir=mfc_log_dir)
        if stop_process_cleanup
        else {"enabled": False, "reason": "disabled", "targets": [], "results": []}
    )
    rust = archive_rust_volatile_outputs(
        rust_runtime_dir=rust_runtime_dir,
        rust_packet_dump_dir=rust_packet_dump_dir,
        archive_dir=preflight,
    )
    mfc = archive_mfc_log_outputs(mfc_log_dir=mfc_log_dir, archive_dir=preflight)
    manifest = {
        "schema": "emulebb.converged-soak.last-run.v1",
        "campaignId": paths.campaign_id,
        "status": "starting",
        "soakRoot": str(paths.soak_root),
        "reportDir": str(paths.report_dir),
        "archiveDir": str(paths.archive_dir),
        "rustProfileDir": str(rust_runtime_dir),
        "rustPacketDumpDir": str(rust_packet_dump_dir),
        "mfcLogDir": str(mfc_log_dir) if mfc_log_dir is not None else None,
        "preflightCleanup": {"processes": processes, "rust": rust, "mfc": mfc},
    }
    write_last_run_manifest(paths, manifest)
    write_latest_report_pointer(paths)
    return manifest


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Writes one UTF-8 JSON file with stable formatting."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_last_run_manifest(paths: SoakRunPaths, manifest: dict[str, Any]) -> None:
    """Publishes the stable last-run manifest."""

    write_json(paths.last_run_manifest, manifest)


def write_latest_report_pointer(paths: SoakRunPaths) -> None:
    """Publishes a stable pointer to the latest report directory."""

    write_json(
        paths.latest_report_pointer,
        {
            "schema": "emulebb.converged-soak.latest-report.v1",
            "campaignId": paths.campaign_id,
            "reportDir": str(paths.report_dir),
            "summary": str(paths.report_dir / "summary.json"),
        },
    )


def mark_run_finished(paths: SoakRunPaths, *, status: str, extra: dict[str, Any] | None = None) -> None:
    """Updates the last-run manifest status without dropping preflight evidence."""

    manifest: dict[str, Any] = {}
    if paths.last_run_manifest.is_file():
        manifest = json.loads(paths.last_run_manifest.read_text(encoding="utf-8"))
    manifest.update({"campaignId": paths.campaign_id, "status": status})
    if extra:
        manifest.update(extra)
    write_last_run_manifest(paths, manifest)
