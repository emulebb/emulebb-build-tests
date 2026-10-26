"""Structured filesystem layout and preflight cleanup for converged soak runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
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
PREFLIGHT_ARCHIVE_MANIFEST_SCHEMA = "emulebb-build-tests.preflight-archive-manifest.v1"
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


@dataclass(frozen=True)
class _PreflightArchiveEntry:
    category: str
    stream_name: str
    source: Path
    destination: Path
    relative_path: str
    byte_count: int
    modified_ns: int
    sha256: str

    def manifest_row(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "relativePath": self.relative_path,
            "bytes": self.byte_count,
            "modifiedNs": self.modified_ns,
            "sha256": self.sha256,
        }

    def summary_row(self) -> dict[str, Any]:
        return {
            "from": str(self.source),
            "to": str(self.destination),
            "bytes": self.byte_count,
            "sha256": self.sha256,
        }


def _absolute_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    return Path(os.path.normpath(str(candidate)))


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, FileNotFoundError, OSError):
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _validate_preflight_archive_name(name: str) -> str:
    if (
        not name
        or Path(name).name != name
        or name in {".", ".."}
        or not name.isascii()
        or any(
            not (character.isalnum() or character in {".", "_", "-"})
            for character in name
        )
    ):
        raise RuntimeError(
            "Preflight archive filenames must use safe ASCII letters, digits, dots, "
            f"underscores, and hyphens: {name!r}"
        )
    return name


def _assert_campaign_destination_authority(
    *, paths: SoakRunPaths, target: Path
) -> Path:
    campaign = _absolute_path(paths.campaign_dir)
    absolute_target = _absolute_path(target)
    try:
        relative_target = absolute_target.relative_to(campaign)
    except ValueError:
        raise RuntimeError(
            f"Preflight archive destination escaped its campaign: {absolute_target}"
        ) from None
    current = campaign
    if _is_reparse_point(current):
        raise RuntimeError(
            f"Preflight archive destination contains a reparse point: {current}"
        )
    for part in relative_target.parts:
        current /= part
        if _is_reparse_point(current):
            raise RuntimeError(
                f"Preflight archive destination contains a reparse point: {current}"
            )
    resolved_campaign = campaign.resolve()
    resolved_target = absolute_target.resolve()
    if not path_is_relative_to(resolved_target, resolved_campaign):
        raise RuntimeError(
            f"Preflight archive destination resolved outside its campaign: {target}"
        )
    return absolute_target


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

    path = observer_action_report_path(
        paths=paths,
        campaign_id=report.get("campaignId"),
        sequence=report.get("seq"),
        action_id=report.get("actionId"),
    )
    return soak_storage.persist_bounded_json_identity_artifact(
        store=store,
        active_campaign=paths.campaign_dir,
        directory=paths.actions_dir,
        stream_name="observer_actions",
        stem="action",
        artifact_name=path.name,
        payload=report,
        now_ns=now_ns,
    )


def observer_action_report_path(
    *,
    paths: SoakRunPaths,
    campaign_id: object,
    sequence: object,
    action_id: object,
) -> Path:
    """Returns one validated deterministic observer action-report path."""

    if campaign_id != paths.campaign_id:
        raise RuntimeError("Observer action report campaign identity is invalid.")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise RuntimeError("Observer action report sequence is invalid.")
    if (
        not isinstance(action_id, str)
        or not action_id
        or not action_id.isascii()
        or any(not (character.isalnum() or character == "-") for character in action_id)
    ):
        raise RuntimeError("Observer action report action identity is invalid.")
    return paths.actions_dir / f"action-{sequence:08d}-{action_id}.json"


def load_observer_action_report_candidate(
    *,
    paths: SoakRunPaths,
    pending_action: dict[str, Any],
) -> dict[str, Any] | None:
    """Loads an exact final or prepared report before diagnostic recapture."""

    path = observer_action_report_path(
        paths=paths,
        campaign_id=paths.campaign_id,
        sequence=pending_action.get("reportSeq"),
        action_id=pending_action.get("actionId"),
    )
    temporary = path.with_name(f".{path.name}.tmp")
    if path.exists() and temporary.exists():
        raise RuntimeError(
            f"Observer action report has ambiguous final and temporary state: {path.name}"
        )
    candidate = path if path.exists() else temporary if temporary.exists() else None
    if candidate is None:
        return None
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError(
            f"Observer action report candidate must be one regular file: {candidate}"
        )
    before = candidate.stat()
    try:
        encoded = candidate.read_bytes()
        payload = json.loads(encoded.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Unable to load observer action report candidate {candidate}: {error}"
        ) from error
    after = candidate.stat()
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(encoded) != after.st_size
    ):
        raise RuntimeError(
            f"Observer action report candidate changed while reading: {candidate}"
        )
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"Observer action report candidate must be an object: {candidate}"
        )
    if (
        payload.get("campaignId") != paths.campaign_id
        or payload.get("seq") != pending_action.get("reportSeq")
        or payload.get("actionId") != pending_action.get("actionId")
    ):
        raise RuntimeError(
            f"Observer action report candidate identity is invalid: {candidate}"
        )
    return payload


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


def _hash_stable_file(path: Path) -> tuple[int, int, str]:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns:
        raise RuntimeError(f"Preflight archive source changed during inventory: {path}")
    return before.st_size, before.st_mtime_ns, digest.hexdigest()


def _snapshot_preflight_files(
    *,
    category: str,
    stream_name: str,
    source_root: Path,
    destination_root: Path,
    files: Iterable[Path],
) -> list[_PreflightArchiveEntry]:
    resolved_source_root = source_root.resolve()
    absolute_destination_root = _absolute_path(destination_root)
    if source_root.is_symlink():
        raise RuntimeError(
            f"Preflight archive source root must not be a symlink: {source_root}"
        )
    if destination_root.is_symlink():
        raise RuntimeError(
            "Preflight archive destination root must not be a symlink: "
            f"{destination_root}"
        )

    entries: list[_PreflightArchiveEntry] = []
    seen_sources: set[str] = set()
    seen_destinations: set[str] = set()
    for candidate in sorted(files, key=lambda path: str(path).casefold()):
        if candidate.is_symlink():
            raise RuntimeError(
                f"Preflight archive source must not be a symlink: {candidate}"
            )
        source = candidate.resolve()
        source_key = str(source).casefold()
        if source_key in seen_sources:
            continue
        seen_sources.add(source_key)
        if not source.is_file():
            raise RuntimeError(f"Preflight archive source is not a file: {source}")
        if not path_is_relative_to(source, resolved_source_root):
            raise RuntimeError(
                f"Preflight archive source escaped its configured root: {source}"
            )
        relative = source.relative_to(resolved_source_root)
        if len(relative.parts) != 1:
            raise RuntimeError(
                "Preflight archive inputs must be direct children of their source root: "
                f"{source}"
            )
        _validate_preflight_archive_name(relative.name)
        destination = absolute_destination_root / relative
        destination_key = str(destination).casefold()
        if destination_key in seen_destinations:
            raise RuntimeError(
                f"Preflight archive destination collision: {destination}"
            )
        seen_destinations.add(destination_key)
        byte_count, modified_ns, sha256 = _hash_stable_file(source)
        entries.append(
            _PreflightArchiveEntry(
                category=category,
                stream_name=stream_name,
                source=source,
                destination=destination,
                relative_path=relative.as_posix(),
                byte_count=byte_count,
                modified_ns=modified_ns,
                sha256=sha256,
            )
        )
    return entries


def _glob_files(root: Path, patterns: Iterable[str]) -> list[Path]:
    if not root.exists():
        return []
    files: list[Path] = []
    for pattern in patterns:
        files.extend(
            path for path in root.glob(pattern) if path.is_file() or path.is_symlink()
        )
    return files


def _preflight_source_files(
    *, rust_profile_dir: Path, mfc_log_dir: Path | None
) -> dict[str, list[Path]]:
    rust_files = [
        rust_profile_dir / name
        for name in RUST_PROFILE_VOLATILE_FILES
        if (rust_profile_dir / name).exists() or (rust_profile_dir / name).is_symlink()
    ]
    return {
        "rust": rust_files,
        "mfc": (
            _glob_files(mfc_log_dir, MFC_LOG_GLOBS) if mfc_log_dir is not None else []
        ),
    }


def _preflight_archive_manifest_path(paths: SoakRunPaths) -> Path:
    return paths.preflight_archive_dir / "manifest" / "preflight-archives.json"


def _preflight_archive_payload(
    *,
    paths: SoakRunPaths,
    state: str,
    rust_profile_dir: Path,
    mfc_log_dir: Path | None,
    entries: Iterable[_PreflightArchiveEntry],
) -> dict[str, Any]:
    return {
        "schema": PREFLIGHT_ARCHIVE_MANIFEST_SCHEMA,
        "campaignId": paths.campaign_id,
        "state": state,
        "sourceRoots": {
            "rust": str(rust_profile_dir.resolve()),
            "mfc": str(mfc_log_dir.resolve()) if mfc_log_dir is not None else None,
        },
        "entries": [entry.manifest_row() for entry in entries],
    }


def _encoded_json_size(payload: object) -> int:
    return len(
        (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )


def _persist_preflight_archive_manifest(
    *,
    paths: SoakRunPaths,
    store: soak_storage.BoundedArtifactStore,
    payload: dict[str, Any],
) -> None:
    soak_storage.persist_bounded_json_checkpoint(
        store=store,
        active_campaign=paths.campaign_dir,
        directory=_preflight_archive_manifest_path(paths).parent,
        stream_name="preflight_archive_manifest",
        artifact_name="preflight-archives.json",
        payload=payload,
    )


def _entry_from_manifest_row(
    *,
    row: object,
    rust_profile_dir: Path,
    mfc_log_dir: Path | None,
    preflight_archive_dir: Path,
) -> _PreflightArchiveEntry:
    if not isinstance(row, dict) or set(row) != {
        "category",
        "relativePath",
        "bytes",
        "modifiedNs",
        "sha256",
    }:
        raise RuntimeError("Preflight archive manifest contains an invalid entry.")
    category = row["category"]
    if category == "rust":
        source_root = rust_profile_dir.resolve()
        destination_root = _absolute_path(preflight_archive_dir / "rust-profile")
        stream_name = "preflight_rust_outputs"
    elif category == "mfc" and mfc_log_dir is not None:
        source_root = mfc_log_dir.resolve()
        destination_root = _absolute_path(preflight_archive_dir / "mfc-logs")
        stream_name = "preflight_mfc_outputs"
    else:
        raise RuntimeError(
            f"Preflight archive manifest contains an invalid category: {category!r}"
        )
    relative_path = row["relativePath"]
    byte_count = row["bytes"]
    modified_ns = row["modifiedNs"]
    sha256 = row["sha256"]
    if (
        not isinstance(relative_path, str)
        or isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or byte_count < 0
        or isinstance(modified_ns, bool)
        or not isinstance(modified_ns, int)
        or modified_ns < 0
        or not isinstance(sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
    ):
        raise RuntimeError("Preflight archive manifest contains invalid file metadata.")
    _validate_preflight_archive_name(relative_path)
    return _PreflightArchiveEntry(
        category=category,
        stream_name=stream_name,
        source=source_root / relative_path,
        destination=destination_root / relative_path,
        relative_path=relative_path,
        byte_count=byte_count,
        modified_ns=modified_ns,
        sha256=sha256,
    )


def _load_preflight_archive_manifest(
    *,
    paths: SoakRunPaths,
    rust_profile_dir: Path,
    mfc_log_dir: Path | None,
) -> tuple[str, list[_PreflightArchiveEntry]]:
    manifest_path = _preflight_archive_manifest_path(paths)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Preflight archive manifest could not be read: {manifest_path}"
        ) from exc
    expected_roots = {
        "rust": str(rust_profile_dir.resolve()),
        "mfc": str(mfc_log_dir.resolve()) if mfc_log_dir is not None else None,
    }
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != PREFLIGHT_ARCHIVE_MANIFEST_SCHEMA
        or payload.get("campaignId") != paths.campaign_id
        or payload.get("state") not in {"prepared", "copied", "complete"}
        or payload.get("sourceRoots") != expected_roots
        or not isinstance(payload.get("entries"), list)
    ):
        raise RuntimeError(
            f"Preflight archive manifest is incompatible with this run: {manifest_path}"
        )
    entries = [
        _entry_from_manifest_row(
            row=row,
            rust_profile_dir=rust_profile_dir,
            mfc_log_dir=mfc_log_dir,
            preflight_archive_dir=paths.preflight_archive_dir,
        )
        for row in payload["entries"]
    ]
    identities = [(entry.category, entry.relative_path.casefold()) for entry in entries]
    if len(identities) != len(set(identities)):
        raise RuntimeError(
            "Preflight archive manifest contains duplicate destinations."
        )
    return payload["state"], entries


def _verify_preflight_file(path: Path, entry: _PreflightArchiveEntry) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Preflight archive file is missing or unsafe: {path}")
    byte_count, modified_ns, sha256 = _hash_stable_file(path)
    if path == entry.source and modified_ns != entry.modified_ns:
        raise RuntimeError(f"Preflight archive source timestamp changed: {path}")
    if byte_count != entry.byte_count or sha256 != entry.sha256:
        raise RuntimeError(f"Preflight archive file content changed: {path}")


def _validate_preflight_entry_limits(
    *,
    entries: Iterable[_PreflightArchiveEntry],
    store: soak_storage.BoundedArtifactStore,
) -> None:
    entries = list(entries)
    for stream_name in ("preflight_rust_outputs", "preflight_mfc_outputs"):
        stream_entries = [
            entry for entry in entries if entry.stream_name == stream_name
        ]
        policy = store.policy.stream(stream_name)
        if len(stream_entries) > policy.retained_segments:
            raise RuntimeError(
                f"{stream_name} requires {len(stream_entries)} files, exceeding its "
                f"{policy.retained_segments}-file limit."
            )
        oversized = [
            entry
            for entry in stream_entries
            if entry.byte_count > policy.max_segment_bytes
        ]
        if oversized:
            raise RuntimeError(
                f"{stream_name} contains an artifact larger than its "
                f"{policy.max_segment_bytes}-byte limit: {oversized[0].source}"
            )


def _assert_archive_destinations_known(
    entries: Iterable[_PreflightArchiveEntry],
    *,
    paths: SoakRunPaths,
    destination_roots: Iterable[Path],
) -> None:
    entries = list(entries)
    expected = {
        _assert_campaign_destination_authority(paths=paths, target=entry.destination)
        for entry in entries
    }
    roots = {
        _assert_campaign_destination_authority(paths=paths, target=root)
        for root in destination_roots
    }
    for root in roots:
        if not root.exists():
            continue
        for candidate in root.iterdir():
            candidate = _assert_campaign_destination_authority(
                paths=paths, target=candidate
            )
            if not candidate.is_file():
                raise RuntimeError(
                    f"Preflight archive destination contains an unsafe entry: {candidate}"
                )
            if candidate not in expected:
                raise RuntimeError(
                    "Preflight archive destination contains an unplanned artifact: "
                    f"{candidate}"
                )


def _assert_no_unplanned_preflight_sources(
    *,
    entries: Iterable[_PreflightArchiveEntry],
    rust_profile_dir: Path,
    mfc_log_dir: Path | None,
) -> None:
    expected = {str(entry.source.resolve()).casefold() for entry in entries}
    current = _preflight_source_files(
        rust_profile_dir=rust_profile_dir,
        mfc_log_dir=mfc_log_dir,
    )
    for candidate in (*current["rust"], *current["mfc"]):
        if candidate.is_symlink():
            raise RuntimeError(
                f"Preflight archive source must not be a symlink: {candidate}"
            )
        if str(candidate.resolve()).casefold() not in expected:
            raise RuntimeError(
                f"Preflight archive recovery found an unplanned source: {candidate}"
            )


def _copy_or_verify_preflight_entry(
    *,
    paths: SoakRunPaths,
    store: soak_storage.BoundedArtifactStore,
    entry: _PreflightArchiveEntry,
) -> None:
    _verify_preflight_file(entry.source, entry)
    _assert_campaign_destination_authority(paths=paths, target=entry.destination)
    if entry.destination.exists() or entry.destination.is_symlink():
        _verify_preflight_file(entry.destination, entry)
        return
    result = soak_storage.persist_bounded_file_artifact(
        store=store,
        active_campaign=paths.campaign_dir,
        directory=entry.destination.parent,
        stream_name=entry.stream_name,
        source=entry.source,
        artifact_name=entry.destination.name,
    )
    if result.deleted_paths:
        raise RuntimeError(
            f"Preflight archive unexpectedly rotated existing artifacts: {result.deleted_paths!r}"
        )
    if result.byte_count != entry.byte_count or result.sha256 != entry.sha256:
        raise RuntimeError(
            f"Preflight archive copy verification disagreed with inventory: {entry.source}"
        )


def _remove_preflight_source(path: Path) -> None:
    path.unlink()


def _archive_summary(
    entries: Iterable[_PreflightArchiveEntry], *, category: str
) -> list[dict[str, Any]]:
    return [entry.summary_row() for entry in entries if entry.category == category]


def archive_preflight_outputs(
    *,
    paths: SoakRunPaths,
    rust_profile_dir: Path,
    mfc_log_dir: Path | None,
    store: soak_storage.BoundedArtifactStore,
) -> dict[str, Any]:
    """Copies, verifies, and then removes prior outputs using a recovery manifest."""

    if store.root != paths.campaigns_root.resolve():
        raise RuntimeError(
            "Preflight archives require the bounded store root to be campaigns/."
        )
    manifest_path = _preflight_archive_manifest_path(paths)
    if manifest_path.exists() or manifest_path.is_symlink():
        if manifest_path.is_symlink():
            raise RuntimeError(
                f"Preflight archive manifest must not be a symlink: {manifest_path}"
            )
        state, entries = _load_preflight_archive_manifest(
            paths=paths,
            rust_profile_dir=rust_profile_dir,
            mfc_log_dir=mfc_log_dir,
        )
        _assert_no_unplanned_preflight_sources(
            entries=entries,
            rust_profile_dir=rust_profile_dir,
            mfc_log_dir=mfc_log_dir,
        )
    else:
        source_files = _preflight_source_files(
            rust_profile_dir=rust_profile_dir,
            mfc_log_dir=mfc_log_dir,
        )
        entries = _snapshot_preflight_files(
            category="rust",
            stream_name="preflight_rust_outputs",
            source_root=rust_profile_dir,
            destination_root=paths.preflight_archive_dir / "rust-profile",
            files=source_files["rust"],
        )
        if mfc_log_dir is not None:
            entries.extend(
                _snapshot_preflight_files(
                    category="mfc",
                    stream_name="preflight_mfc_outputs",
                    source_root=mfc_log_dir,
                    destination_root=paths.preflight_archive_dir / "mfc-logs",
                    files=source_files["mfc"],
                )
            )
        entries.sort(key=lambda entry: (entry.category, entry.relative_path.casefold()))
        _validate_preflight_entry_limits(entries=entries, store=store)
        _assert_archive_destinations_known(
            entries,
            paths=paths,
            destination_roots=(
                paths.preflight_archive_dir / "rust-profile",
                paths.preflight_archive_dir / "mfc-logs",
            ),
        )
        payloads = [
            _preflight_archive_payload(
                paths=paths,
                state=state_name,
                rust_profile_dir=rust_profile_dir,
                mfc_log_dir=mfc_log_dir,
                entries=entries,
            )
            for state_name in ("prepared", "copied", "complete")
        ]
        reserved_bytes = sum(entry.byte_count for entry in entries) + max(
            _encoded_json_size(payload) for payload in payloads
        )
        reservation = store.enforce(
            active_campaign=paths.campaign_dir,
            reserved_bytes=reserved_bytes,
        )
        if not reservation.within_limits:
            raise RuntimeError(
                "Preflight archive reservation failed: "
                f"failures={reservation.failures!r}, "
                f"constraints={reservation.verification.unresolved_constraints!r}."
            )
        state = "prepared"
        _persist_preflight_archive_manifest(
            paths=paths,
            store=store,
            payload=payloads[0],
        )

    _validate_preflight_entry_limits(entries=entries, store=store)
    _assert_archive_destinations_known(
        entries,
        paths=paths,
        destination_roots=(
            paths.preflight_archive_dir / "rust-profile",
            paths.preflight_archive_dir / "mfc-logs",
        ),
    )
    if state == "complete":
        if any(entry.source.exists() or entry.source.is_symlink() for entry in entries):
            raise RuntimeError(
                "Completed preflight archive sources were recreated; use a new campaign."
            )
        for entry in entries:
            _assert_campaign_destination_authority(
                paths=paths, target=entry.destination
            )
            _verify_preflight_file(entry.destination, entry)
    else:
        if state == "prepared":
            for entry in entries:
                _copy_or_verify_preflight_entry(paths=paths, store=store, entry=entry)
            state = "copied"
            _persist_preflight_archive_manifest(
                paths=paths,
                store=store,
                payload=_preflight_archive_payload(
                    paths=paths,
                    state=state,
                    rust_profile_dir=rust_profile_dir,
                    mfc_log_dir=mfc_log_dir,
                    entries=entries,
                ),
            )
        for entry in entries:
            _assert_campaign_destination_authority(
                paths=paths, target=entry.destination
            )
            _verify_preflight_file(entry.destination, entry)
            if not entry.source.exists() and not entry.source.is_symlink():
                continue
            _verify_preflight_file(entry.source, entry)
            _remove_preflight_source(entry.source)
        state = "complete"
        _persist_preflight_archive_manifest(
            paths=paths,
            store=store,
            payload=_preflight_archive_payload(
                paths=paths,
                state=state,
                rust_profile_dir=rust_profile_dir,
                mfc_log_dir=mfc_log_dir,
                entries=entries,
            ),
        )

    if mfc_log_dir is not None:
        mfc_log_dir.mkdir(parents=True, exist_ok=True)

    rust_files = _archive_summary(entries, category="rust")
    mfc_files = _archive_summary(entries, category="mfc")
    return {
        "manifest": str(manifest_path.resolve()),
        "state": state,
        "rust": {
            "runtimeFiles": rust_files,
            "archivedCount": len(rust_files),
        },
        "mfc": {
            "enabled": mfc_log_dir is not None,
            "reason": None if mfc_log_dir is not None else "no-mfc-log-dir",
            "logDir": str(mfc_log_dir) if mfc_log_dir is not None else None,
            "archivedFiles": mfc_files,
            "archivedCount": len(mfc_files),
        },
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
    archived = archive_preflight_outputs(
        paths=paths,
        rust_profile_dir=rust_profile_dir,
        mfc_log_dir=mfc_log_dir,
        store=artifact_store,
    )
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
            "archiveManifest": archived["manifest"],
            "archiveState": archived["state"],
            "rust": archived["rust"],
            "mfc": archived["mfc"],
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
