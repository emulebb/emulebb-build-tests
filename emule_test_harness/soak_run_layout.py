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

from . import diag_event_runs, soak_storage, windows_processes
from .paths import path_is_relative_to

CAMPAIGN_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")

RUST_PROFILE_VOLATILE_FILES = ("daemon.out",)
DIAGNOSTIC_SEGMENT_PROMOTION_SCHEMA = (
    "emulebb-build-tests.diagnostic-segment-promotion.v1"
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
    campaigns_root: Path
    campaign_dir: Path
    report_dir: Path
    actions_dir: Path
    checkpoints_dir: Path
    diagnostic_bundles_dir: Path
    diagnostic_segments_dir: Path
    daemon_output_dir: Path
    rust_daemon_output: Path
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
        raise ValueError(
            f"campaign_id must use UTC YYYYMMDDTHHMMSSZ format, got {campaign_id!r}."
        )
    return campaign_id


def build_run_paths(soak_root: Path, campaign_id: str) -> SoakRunPaths:
    """Builds the stable converged-soak path set for one campaign."""

    campaign_id = validate_campaign_id(campaign_id)
    campaigns_root = soak_root / "campaigns"
    campaign_dir = campaigns_root / campaign_id
    report_dir = campaign_dir / "report"
    daemon_output_dir = campaign_dir / "daemon-output"
    archive_dir = campaign_dir / "archive"
    last_run_dir = soak_root / "last-run"
    return SoakRunPaths(
        soak_root=soak_root,
        campaign_id=campaign_id,
        campaigns_root=campaigns_root,
        campaign_dir=campaign_dir,
        report_dir=report_dir,
        actions_dir=report_dir / "actions",
        checkpoints_dir=report_dir / "checkpoints",
        diagnostic_bundles_dir=report_dir / "diagnostic-bundles",
        diagnostic_segments_dir=archive_dir / "preflight" / "diagnostic-segments",
        daemon_output_dir=daemon_output_dir,
        rust_daemon_output=daemon_output_dir / "rust-daemon.out",
        archive_dir=archive_dir,
        preflight_archive_dir=archive_dir / "preflight",
        last_run_dir=last_run_dir,
        last_run_manifest=last_run_dir / "manifest.json",
        latest_report_pointer=last_run_dir / "latest-report.json",
    )


def persist_observer_action_report(
    *,
    paths: SoakRunPaths,
    store: soak_storage.BoundedArtifactStore,
    report: dict[str, Any],
    now_ns: int | None = None,
) -> soak_storage.PersistedArtifact:
    """Persists one immutable observer action report under its stream budget."""

    return soak_storage.persist_bounded_json_artifact(
        store=store,
        active_campaign=paths.campaign_dir,
        directory=paths.actions_dir,
        stream_name="observer_actions",
        stem="action",
        payload=report,
        now_ns=now_ns,
    )


def persist_observer_checkpoint(
    *,
    paths: SoakRunPaths,
    store: soak_storage.BoundedArtifactStore,
    checkpoint: dict[str, Any],
    now_ns: int | None = None,
) -> soak_storage.PersistedArtifact:
    """Persists one immutable observer checkpoint under its stream budget."""

    return soak_storage.persist_bounded_json_artifact(
        store=store,
        active_campaign=paths.campaign_dir,
        directory=paths.checkpoints_dir,
        stream_name="observer_checkpoints",
        stem="checkpoint",
        payload=checkpoint,
        now_ns=now_ns,
    )


def persist_observer_summary(
    *,
    paths: SoakRunPaths,
    store: soak_storage.BoundedArtifactStore,
    summary: dict[str, Any],
    now_ns: int | None = None,
) -> soak_storage.PersistedArtifact:
    """Atomically replaces the singleton observer summary under hard bounds."""

    return soak_storage.persist_bounded_json_checkpoint(
        store=store,
        active_campaign=paths.campaign_dir,
        directory=paths.report_dir,
        stream_name="observer_summary",
        artifact_name="summary.json",
        payload=summary,
        now_ns=now_ns,
    )


def require_output_soak_root(soak_root: Path, output_root: Path) -> Path:
    """Returns the canonical soak root, rejecting repo/workspace-local reports."""

    resolved_output = output_root.resolve()
    resolved_soak = soak_root.resolve()
    expected = (resolved_output / "soak").resolve()
    if resolved_soak != expected:
        raise RuntimeError(
            f"converged soak output must be under EMULEBB_WORKSPACE_OUTPUT_ROOT\\soak: {resolved_soak}"
        )
    if not path_is_relative_to(resolved_soak, resolved_output):
        raise RuntimeError(
            f"converged soak output escaped EMULEBB_WORKSPACE_OUTPUT_ROOT: {resolved_soak}"
        )
    return resolved_soak


def mfc_soak_log_dir(
    *, mfc_artifacts_dir: Path, direct_profile_dir: Path | None
) -> Path:
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


def current_process_and_ancestor_pids(
    processes: list[windows_processes.WindowsProcessInfo],
) -> set[int]:
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
    rust_profile_dir: Path,
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
        is_rust = name == "emulebb-rust-diagnostics.exe" and _command_contains_path(
            command_line, rust_profile_dir
        )
        is_mfc = name == "emulebb-diagnostics.exe" and _command_contains_path(
            command_line, mfc_profile_base
        )
        if is_runner or is_rust or is_mfc:
            selected.append(process)

    selected_pids = {process.pid for process in selected}
    return [process for process in selected if process.parent_pid not in selected_pids]


def stop_stale_soak_processes(
    *,
    rust_profile_dir: Path,
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
        rust_profile_dir=rust_profile_dir,
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


def _archive_files(
    files: Iterable[Path], *, source_root: Path, archive_root: Path
) -> list[dict[str, Any]]:
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
    rust_profile_dir: Path,
    archive_dir: Path,
) -> dict[str, Any]:
    """Archives Rust runtime output while preserving profile diagnostic segments."""

    profile_files = [rust_profile_dir / name for name in RUST_PROFILE_VOLATILE_FILES]
    archived_runtime = _archive_files(
        profile_files,
        source_root=rust_profile_dir,
        archive_root=archive_dir / "rust-profile",
    )
    return {
        "runtimeFiles": archived_runtime,
        "archivedCount": len(archived_runtime),
    }


def _promote_client_diagnostic_segments(
    *,
    client: str,
    source_dir: Path | None,
    destination_dir: Path,
    store: soak_storage.BoundedArtifactStore,
    active_campaign: Path,
) -> dict[str, Any]:
    if source_dir is None:
        return {"client": client, "status": "disabled", "reason": "no-source-dir"}
    if not source_dir.exists():
        return {
            "client": client,
            "status": "empty",
            "sourceDir": str(source_dir),
            "reason": "source-dir-missing",
        }

    candidates = [
        path
        for path in source_dir.glob("*.jsonl")
        if path.is_file()
        and diag_event_runs.diag_segment_identity(path, client=client) is not None
    ]
    selected_run = diag_event_runs.select_latest_diag_run(candidates, client=client)
    if not selected_run:
        return {
            "client": client,
            "status": "empty",
            "sourceDir": str(source_dir),
            "reason": "no-current-segments",
        }

    stream_policy = store.policy.stream("diagnostic_segments")
    promoted_segments = selected_run[-stream_policy.retained_segments :]
    records = diag_event_runs.load_latest_diag_records(
        promoted_segments,
        client=client,
        allow_incomplete_active_tail=False,
    )
    first_identity = diag_event_runs.diag_segment_identity(
        promoted_segments[0], client=client
    )
    last_identity = diag_event_runs.diag_segment_identity(
        promoted_segments[-1], client=client
    )
    retained_first_identity = diag_event_runs.diag_segment_identity(
        selected_run[0], client=client
    )
    assert (
        first_identity is not None
        and last_identity is not None
        and retained_first_identity is not None
    )
    process_id, run_id, first_segment_id = first_identity
    _, _, last_segment_id = last_identity
    _, _, retained_first_segment_id = retained_first_identity

    files: list[dict[str, Any]] = []
    for source in promoted_segments:
        source_stat = source.stat()
        persisted = soak_storage.persist_bounded_file_artifact(
            store=store,
            active_campaign=active_campaign,
            directory=destination_dir,
            stream_name="diagnostic_segments",
            source=source,
            artifact_name=source.name,
        )
        identity = diag_event_runs.diag_segment_identity(source, client=client)
        assert identity is not None
        files.append(
            {
                "segmentId": identity[2],
                "source": str(source.resolve()),
                "destination": str(persisted.path),
                "bytes": persisted.byte_count,
                "modifiedNs": source_stat.st_mtime_ns,
                "sha256": persisted.sha256,
            }
        )

    return {
        "client": client,
        "status": "promoted",
        "classification": "quiesced-immutable-retained-run-suffix",
        "sourceDir": str(source_dir),
        "destinationDir": str(destination_dir.resolve()),
        "processId": process_id,
        "runId": run_id,
        "retainedRunSegmentCount": len(selected_run),
        "promotedSegmentCount": len(files),
        "recordCount": len(records),
        "retainedFirstSegmentId": retained_first_segment_id,
        "promotedFirstSegmentId": first_segment_id,
        "promotedLastSegmentId": last_segment_id,
        "omittedBeforeRetainedSuffix": retained_first_segment_id,
        "omittedByPromotionLimit": first_segment_id - retained_first_segment_id,
        "files": files,
    }


def promote_latest_diagnostic_segments(
    *,
    paths: SoakRunPaths,
    rust_packet_dump_dir: Path,
    mfc_log_dir: Path | None,
    store: soak_storage.BoundedArtifactStore,
) -> dict[str, Any]:
    """Copies validated quiesced run suffixes into bounded campaign storage."""

    clients = [
        _promote_client_diagnostic_segments(
            client="rust",
            source_dir=rust_packet_dump_dir,
            destination_dir=paths.diagnostic_segments_dir / "rust",
            store=store,
            active_campaign=paths.campaign_dir,
        ),
        _promote_client_diagnostic_segments(
            client="mfc",
            source_dir=mfc_log_dir,
            destination_dir=paths.diagnostic_segments_dir / "mfc",
            store=store,
            active_campaign=paths.campaign_dir,
        ),
    ]
    manifest = {
        "schema": DIAGNOSTIC_SEGMENT_PROMOTION_SCHEMA,
        "classification": "quiesced-immutable-retained-run-suffix",
        "clients": clients,
    }
    manifest_path = paths.preflight_archive_dir / "diagnostic-segments-manifest.json"
    write_json(manifest_path, manifest)
    return {
        "enabled": True,
        "manifest": str(manifest_path.resolve()),
        "clients": clients,
        "promotedCount": sum(
            int(client.get("promotedSegmentCount", 0)) for client in clients
        ),
    }


def archive_mfc_log_outputs(
    *, mfc_log_dir: Path | None, archive_dir: Path
) -> dict[str, Any]:
    """Archives known eMuleBB MFC log files while preserving unrelated files."""

    if mfc_log_dir is None:
        return {
            "enabled": False,
            "reason": "no-mfc-log-dir",
            "archivedFiles": [],
            "archivedCount": 0,
        }
    files = _glob_files(mfc_log_dir, MFC_LOG_GLOBS)
    archived = _archive_files(
        files, source_root=mfc_log_dir, archive_root=archive_dir / "mfc-logs"
    )
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
    rust_profile_dir: Path,
    rust_packet_dump_dir: Path,
    mfc_log_dir: Path | None,
    artifact_store: soak_storage.BoundedArtifactStore,
    stop_process_cleanup: bool = True,
) -> dict[str, Any]:
    """Quiesces old clients, promotes diagnostics, and prepares one campaign."""

    paths.report_dir.mkdir(parents=True, exist_ok=True)
    paths.actions_dir.mkdir(parents=True, exist_ok=True)
    paths.checkpoints_dir.mkdir(parents=True, exist_ok=True)
    paths.diagnostic_bundles_dir.mkdir(parents=True, exist_ok=True)
    preflight = paths.preflight_archive_dir
    processes = (
        stop_stale_soak_processes(
            rust_profile_dir=rust_profile_dir, mfc_log_dir=mfc_log_dir
        )
        if stop_process_cleanup
        else {"enabled": False, "reason": "disabled", "targets": [], "results": []}
    )
    if processes.get("enabled") is True:
        current_processes = windows_processes.collect_processes()
        remaining = select_stale_soak_process_roots(
            current_processes,
            rust_profile_dir=rust_profile_dir,
            mfc_profile_base=mfc_profile_base_from_log_dir(mfc_log_dir),
            exclude_pids=current_process_and_ancestor_pids(current_processes),
        )
        if remaining:
            detail = ", ".join(
                f"{process.name}[{process.pid}]" for process in remaining
            )
            raise RuntimeError(
                "Previous soak processes remain after cleanup; diagnostic segments "
                f"are not immutable: {detail}"
            )
        diagnostic_segments = promote_latest_diagnostic_segments(
            paths=paths,
            rust_packet_dump_dir=rust_packet_dump_dir,
            mfc_log_dir=mfc_log_dir,
            store=artifact_store,
        )
    else:
        diagnostic_segments = {
            "enabled": False,
            "reason": str(processes.get("reason", "process-cleanup-disabled")),
            "promotedCount": 0,
            "clients": [],
        }
    rust = archive_rust_volatile_outputs(
        rust_profile_dir=rust_profile_dir,
        archive_dir=preflight,
    )
    mfc = archive_mfc_log_outputs(mfc_log_dir=mfc_log_dir, archive_dir=preflight)
    manifest = {
        "schema": "emulebb.converged-soak.last-run.v1",
        "campaignId": paths.campaign_id,
        "status": "starting",
        "soakRoot": str(paths.soak_root),
        "campaignDir": str(paths.campaign_dir),
        "reportDir": str(paths.report_dir),
        "archiveDir": str(paths.archive_dir),
        "rustProfileDir": str(rust_profile_dir),
        "rustPacketDumpDir": str(rust_packet_dump_dir),
        "mfcLogDir": str(mfc_log_dir) if mfc_log_dir is not None else None,
        "preflightCleanup": {
            "processes": processes,
            "rust": rust,
            "mfc": mfc,
            "diagnosticSegments": diagnostic_segments,
        },
    }
    write_last_run_manifest(paths, manifest)
    write_latest_report_pointer(paths)
    return manifest


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Writes one UTF-8 JSON file with stable formatting."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


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
            "campaignDir": str(paths.campaign_dir),
            "reportDir": str(paths.report_dir),
            "summary": str(paths.report_dir / "summary.json"),
        },
    )


def mark_run_running(
    paths: SoakRunPaths, *, extra: dict[str, Any] | None = None
) -> None:
    """Publishes that both clients and ready diagnostics evidence are available."""

    manifest: dict[str, Any] = {}
    if paths.last_run_manifest.is_file():
        manifest = json.loads(paths.last_run_manifest.read_text(encoding="utf-8"))
    manifest.update(
        {
            "campaignId": paths.campaign_id,
            "status": "running",
            "readyUtc": datetime.now(timezone.utc).isoformat(),
        }
    )
    if extra:
        manifest.update(extra)
    write_last_run_manifest(paths, manifest)


def mark_run_finished(
    paths: SoakRunPaths, *, status: str, extra: dict[str, Any] | None = None
) -> None:
    """Updates the last-run manifest status without dropping preflight evidence."""

    manifest: dict[str, Any] = {}
    if paths.last_run_manifest.is_file():
        manifest = json.loads(paths.last_run_manifest.read_text(encoding="utf-8"))
    manifest.update({"campaignId": paths.campaign_id, "status": status})
    if extra:
        manifest.update(extra)
    write_last_run_manifest(paths, manifest)
