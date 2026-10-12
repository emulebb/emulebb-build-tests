"""Operator-local inputs and path guards for native Windows parity campaigns."""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote

ED2K_HASH_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
AICH_HASH_RE = re.compile(r"^[A-Z2-7]{32}$", re.IGNORECASE)
HANDLE_PROCESS_RE = re.compile(r"^\s*(?P<name>.+?)\s+pid:\s*(?P<pid>\d+)\s+", re.IGNORECASE)
NATIVE_PARITY_SECTION = "native_parity"
CLIENT_PROCESS_STEMS = {
    "emule": "mfc",
    "emulebb": "mfc",
    "emulebb-diagnostics": "mfc",
    "emulebb-rust": "rust",
    "emulebb-rust-diagnostics": "rust",
}


@dataclass(frozen=True)
class Ed2kLinkFixture:
    """One exact eD2K fixture entry supplied by the operator."""

    name: str
    size: int
    ed2k_hash: str
    aich_hash: str | None
    ed2k_link: str


@dataclass(frozen=True)
class NativeParityConfig:
    """Resolved, operator-local configuration for one native parity campaign."""

    ed2k_links_file: Path
    shared_paths_file: Path
    forbidden_roots: tuple[str, ...]
    capture_interface: str


@dataclass(frozen=True)
class CampaignPath:
    """One named, normalized Windows campaign path."""

    label: str
    path: str


@dataclass(frozen=True)
class ProcessSnapshot:
    """Process fields needed to audit campaign path references."""

    pid: int
    name: str
    executable: str | None = None
    command_line: tuple[str, ...] = ()


@dataclass(frozen=True)
class PathAuditFinding:
    """A sensitive path reference described without copying that path."""

    source: str
    forbidden_root_index: int
    pid: int | None = None
    process_name: str | None = None


@dataclass(frozen=True)
class PathAuditResult:
    """Results from an optional process or open-handle audit."""

    available: bool
    inspected_count: int
    findings: tuple[PathAuditFinding, ...]


@dataclass(frozen=True)
class ClientProcessFinding:
    """One running eMuleBB client, retained without its path or command line."""

    pid: int
    client_family: str


@dataclass(frozen=True)
class ClientProcessAuditResult:
    """Results from the pre-existing native client process guard."""

    available: bool
    inspected_count: int
    findings: tuple[ClientProcessFinding, ...]


@dataclass(frozen=True)
class RootMetadataFingerprint:
    """Path-free metadata fingerprint for one indexed forbidden root."""

    root_index: int
    exists: bool
    entry_count: int
    file_count: int
    directory_count: int
    digest: str


@dataclass(frozen=True)
class RootMetadataAuditResult:
    """Before/after comparison of indexed forbidden-root fingerprints."""

    inspected_count: int
    changed_root_indices: tuple[int, ...]


class RunCallable(Protocol):
    """Subset of ``subprocess.run`` used by the handle audit."""

    def __call__(self, command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]: ...


def load_ed2k_link_fixture(path: Path) -> tuple[Ed2kLinkFixture, ...]:
    """Loads non-comment eD2K links without exposing their values in errors."""

    if not path.is_file():
        raise RuntimeError("The operator-local eD2K link fixture is missing.")
    entries: list[Ed2kLinkFixture] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(parse_ed2k_link(line, line_number=line_number))
    if not entries:
        raise RuntimeError("The operator-local eD2K link fixture has no entries.")
    return tuple(entries)


def parse_ed2k_link(value: str, *, line_number: int | None = None) -> Ed2kLinkFixture:
    """Parses one eD2K file link and preserves its identifying fields."""

    location = f" at line {line_number}" if line_number is not None else ""
    fields = value.strip().split("|")
    if len(fields) < 6 or fields[0].lower() != "ed2k://" or fields[1].lower() != "file" or fields[-1] != "/":
        raise RuntimeError(f"Invalid eD2K file link{location}.")
    name = unquote(fields[2])
    if (
        not name
        or name in (".", "..")
        or ntpath.basename(name) != name
        or any(character in name for character in ("\x00", "\r", "\n", "|", ":"))
    ):
        raise RuntimeError(f"Invalid eD2K file name{location}.")
    try:
        size = int(fields[3], 10)
    except ValueError as exc:
        raise RuntimeError(f"Invalid eD2K file size{location}.") from exc
    if size <= 0:
        raise RuntimeError(f"Invalid eD2K file size{location}.")
    ed2k_hash = fields[4]
    if not ED2K_HASH_RE.fullmatch(ed2k_hash):
        raise RuntimeError(f"Invalid eD2K file hash{location}.")

    aich_hash: str | None = None
    for extension in fields[5:-1]:
        if not extension:
            continue
        if extension.lower().startswith("h="):
            if aich_hash is not None:
                raise RuntimeError(f"Duplicate eD2K AICH hash{location}.")
            candidate = extension[2:]
            if not AICH_HASH_RE.fullmatch(candidate):
                raise RuntimeError(f"Invalid eD2K AICH hash{location}.")
            aich_hash = candidate

    return Ed2kLinkFixture(
        name=name,
        size=size,
        ed2k_hash=ed2k_hash,
        aich_hash=aich_hash,
        ed2k_link=value.strip(),
    )


def load_shared_path_fixture(path: Path) -> tuple[str, ...]:
    """Loads absolute Windows share paths from an operator-local fixture."""

    if not path.is_file():
        raise RuntimeError("The operator-local shared-path fixture is missing.")
    paths: list[str] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = normalize_windows_path(line, field=f"shared path line {line_number}")
        key = ntpath.normcase(normalized)
        if key in seen:
            raise RuntimeError(f"Duplicate shared path at line {line_number}.")
        seen.add(key)
        paths.append(normalized)
    if not paths:
        raise RuntimeError("The operator-local shared-path fixture has no entries.")
    return tuple(paths)


def load_forbidden_roots_from_config(
    path: Path,
    *,
    section: str = NATIVE_PARITY_SECTION,
) -> tuple[str, ...]:
    """Loads unique Windows deny roots from an ignored operator-local JSON file."""

    if not path.is_file():
        raise RuntimeError("The operator-local native parity configuration is missing.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("The operator-local native parity configuration is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("The operator-local native parity configuration must contain one JSON object.")
    parity_payload = payload.get(section)
    if not isinstance(parity_payload, dict):
        raise RuntimeError(f"Native parity configuration section {section!r} must be an object.")
    raw_roots = parity_payload.get("forbidden_roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        raise RuntimeError("Native parity forbidden_roots must be a non-empty array.")

    roots: list[str] = []
    seen: set[str] = set()
    for index, raw_root in enumerate(raw_roots):
        if not isinstance(raw_root, str) or not raw_root.strip():
            raise RuntimeError(f"Native parity forbidden_roots[{index}] must be a non-empty string.")
        normalized = normalize_windows_path(raw_root, field=f"forbidden_roots[{index}]")
        key = ntpath.normcase(normalized)
        if key in seen:
            raise RuntimeError(f"Native parity forbidden_roots[{index}] duplicates an earlier root.")
        seen.add(key)
        roots.append(normalized)
    return tuple(roots)


def load_native_parity_config(path: Path) -> NativeParityConfig:
    """Loads native campaign paths while keeping their values out of errors."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("The operator-local native parity configuration could not be loaded.") from exc
    section = payload.get(NATIVE_PARITY_SECTION) if isinstance(payload, dict) else None
    if not isinstance(section, dict):
        raise RuntimeError("The operator-local native parity configuration section is missing.")

    def fixture_path(key: str) -> Path:
        raw_value = section.get(key)
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise RuntimeError(f"Native parity {key} must be a non-empty path string.")
        expanded = Path(os.path.expandvars(raw_value.strip()))
        return (path.parent / expanded).resolve() if not expanded.is_absolute() else expanded.resolve()

    capture_interface = section.get("capture_interface", "auto")
    if not isinstance(capture_interface, str) or not capture_interface.strip():
        raise RuntimeError("Native parity capture_interface must be a non-empty string.")
    return NativeParityConfig(
        ed2k_links_file=fixture_path("ed2k_links_file"),
        shared_paths_file=fixture_path("shared_paths_file"),
        forbidden_roots=load_forbidden_roots_from_config(path),
        capture_interface=capture_interface.strip(),
    )


def normalize_windows_path(value: str | os.PathLike[str], *, field: str = "path") -> str:
    """Normalizes one absolute Windows path without touching the filesystem."""

    raw_value = ntpath.expandvars(ntpath.expanduser(os.fspath(value).strip().strip('"')))
    if raw_value.startswith("\\\\?\\UNC\\"):
        raw_value = "\\\\" + raw_value[8:]
    elif raw_value.startswith("\\\\?\\"):
        raw_value = raw_value[4:]
    normalized = ntpath.normpath(raw_value)
    if not normalized or not ntpath.isabs(normalized):
        raise RuntimeError(f"Native parity {field} must be an absolute Windows path.")
    return normalized


def windows_path_is_within(candidate: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """Returns whether candidate equals or descends from root using Windows semantics."""

    candidate_path = ntpath.normcase(normalize_windows_path(candidate, field="candidate path"))
    root_path = ntpath.normcase(normalize_windows_path(root, field="forbidden root"))
    try:
        return ntpath.commonpath((candidate_path, root_path)) == root_path
    except ValueError:
        return False


def validate_campaign_paths(
    paths: Mapping[str, str | os.PathLike[str]],
    forbidden_roots: Sequence[str | os.PathLike[str]],
) -> tuple[CampaignPath, ...]:
    """Normalizes campaign paths and rejects any path beneath a deny root."""

    normalized_roots = tuple(normalize_windows_path(root, field="forbidden root") for root in forbidden_roots)
    validated: list[CampaignPath] = []
    for label, raw_path in paths.items():
        normalized = normalize_windows_path(raw_path, field=label)
        for root_index, root in enumerate(normalized_roots):
            if windows_path_is_within(normalized, root):
                raise RuntimeError(
                    f"Native parity campaign path {label!r} is below forbidden root index {root_index}."
                )
        validated.append(CampaignPath(label=label, path=normalized))
    return tuple(validated)


def audit_process_references(
    forbidden_roots: Sequence[str | os.PathLike[str]],
    *,
    processes: Iterable[ProcessSnapshot] | None = None,
) -> PathAuditResult:
    """Finds process executable or command-line references to denied roots."""

    normalized_roots = tuple(normalize_windows_path(root, field="forbidden root") for root in forbidden_roots)
    if processes is None:
        try:
            processes = tuple(_iter_process_snapshots())
        except ImportError:
            return PathAuditResult(available=False, inspected_count=0, findings=())

    findings: list[PathAuditFinding] = []
    inspected_count = 0
    for process in processes:
        inspected_count += 1
        for root_index, root in enumerate(normalized_roots):
            if process.executable and _text_references_windows_root(process.executable, root):
                findings.append(
                    PathAuditFinding(
                        source="process_executable",
                        forbidden_root_index=root_index,
                        pid=process.pid,
                        process_name=process.name,
                    )
                )
            if process.command_line and _text_references_windows_root(" ".join(process.command_line), root):
                findings.append(
                    PathAuditFinding(
                        source="process_command_line",
                        forbidden_root_index=root_index,
                        pid=process.pid,
                        process_name=process.name,
                    )
                )
    return PathAuditResult(available=True, inspected_count=inspected_count, findings=tuple(findings))


def audit_client_processes(
    *,
    processes: Iterable[ProcessSnapshot] | None = None,
    allowed_pids: Iterable[int] = (),
) -> ClientProcessAuditResult:
    """Finds pre-existing Rust or MFC clients, excluding campaign-owned PIDs."""

    if processes is None:
        try:
            processes = tuple(_iter_process_snapshots())
        except ImportError:
            return ClientProcessAuditResult(available=False, inspected_count=0, findings=())

    allowed = {int(pid) for pid in allowed_pids}
    findings: list[ClientProcessFinding] = []
    inspected_count = 0
    for process in processes:
        inspected_count += 1
        if process.pid in allowed:
            continue
        family = _client_process_family(process)
        if family is not None:
            findings.append(ClientProcessFinding(pid=process.pid, client_family=family))
    return ClientProcessAuditResult(
        available=True,
        inspected_count=inspected_count,
        findings=tuple(findings),
    )


def fingerprint_forbidden_roots(
    forbidden_roots: Sequence[str | os.PathLike[str]],
) -> tuple[RootMetadataFingerprint, ...]:
    """Fingerprints root and descendant metadata without retaining path names."""

    fingerprints: list[RootMetadataFingerprint] = []
    for root_index, raw_root in enumerate(forbidden_roots):
        normalized = normalize_windows_path(raw_root, field="forbidden root")
        try:
            fingerprints.append(_fingerprint_forbidden_root(Path(normalized), root_index=root_index))
        except OSError:
            # WHY: Native parity must fail closed if a protected root cannot be
            # inventoried, but the exception must not disclose an operator path.
            raise RuntimeError(f"Could not fingerprint forbidden root index {root_index}.") from None
    return tuple(fingerprints)


def compare_forbidden_root_fingerprints(
    before: Sequence[RootMetadataFingerprint],
    after: Sequence[RootMetadataFingerprint],
) -> RootMetadataAuditResult:
    """Reports changed root indices without disclosing roots or entry names."""

    before_by_index = _fingerprints_by_index(before, snapshot="before")
    after_by_index = _fingerprints_by_index(after, snapshot="after")
    indices = sorted(before_by_index.keys() | after_by_index.keys())
    changed = tuple(index for index in indices if before_by_index.get(index) != after_by_index.get(index))
    return RootMetadataAuditResult(inspected_count=len(indices), changed_root_indices=changed)


def find_handle_executable(explicit_path: Path | None = None) -> Path | None:
    """Returns a usable Sysinternals handle executable, when installed."""

    if explicit_path is not None:
        return explicit_path.resolve() if explicit_path.is_file() else None
    discovered = shutil.which("handle.exe") or shutil.which("handle64.exe")
    return Path(discovered).resolve() if discovered else None


def audit_open_handles(
    forbidden_roots: Sequence[str | os.PathLike[str]],
    *,
    handle_executable: Path | None = None,
    timeout_seconds: float = 15.0,
    runner: RunCallable = subprocess.run,
) -> PathAuditResult:
    """Optionally queries Sysinternals handle.exe without retaining path output."""

    executable = find_handle_executable(handle_executable)
    if executable is None:
        return PathAuditResult(available=False, inspected_count=0, findings=())

    normalized_roots = tuple(normalize_windows_path(root, field="forbidden root") for root in forbidden_roots)
    findings: list[PathAuditFinding] = []
    for root_index, root in enumerate(normalized_roots):
        completed = runner(
            [str(executable), "-accepteula", "-nobanner", root],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode not in (0, 1):
            raise RuntimeError(f"handle.exe audit failed for forbidden root index {root_index}.")
        for line in completed.stdout.splitlines():
            match = HANDLE_PROCESS_RE.match(line)
            if not match:
                continue
            findings.append(
                PathAuditFinding(
                    source="open_handle",
                    forbidden_root_index=root_index,
                    pid=int(match.group("pid")),
                    process_name=match.group("name").strip(),
                )
            )
    return PathAuditResult(
        available=True,
        inspected_count=len(normalized_roots),
        findings=tuple(findings),
    )


def summarize_native_parity_inputs(
    links: Sequence[Ed2kLinkFixture],
    shared_paths: Sequence[str | os.PathLike[str]],
    forbidden_roots: Sequence[str | os.PathLike[str]],
) -> dict[str, int]:
    """Summarizes sensitive native inputs using counts only."""

    return {
        "ed2k_link_count": len(links),
        "aich_link_count": sum(link.aich_hash is not None for link in links),
        "shared_path_count": len(shared_paths),
        "forbidden_root_count": len(forbidden_roots),
    }


def summarize_path_audit(result: PathAuditResult) -> dict[str, object]:
    """Summarizes an audit without paths, process names, PIDs, or command lines."""

    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.source] = counts.get(finding.source, 0) + 1
    return {
        "available": result.available,
        "inspected_count": result.inspected_count,
        "finding_count": len(result.findings),
        "finding_sources": dict(sorted(counts.items())),
    }


def summarize_client_process_audit(result: ClientProcessAuditResult) -> dict[str, object]:
    """Summarizes client processes without PIDs, names, paths, or arguments."""

    families: dict[str, int] = {}
    for finding in result.findings:
        families[finding.client_family] = families.get(finding.client_family, 0) + 1
    return {
        "available": result.available,
        "inspected_count": result.inspected_count,
        "finding_count": len(result.findings),
        "client_families": dict(sorted(families.items())),
    }


def summarize_forbidden_root_metadata_audit(result: RootMetadataAuditResult) -> dict[str, object]:
    """Summarizes protected-root changes using stable indices only."""

    return {
        "inspected_count": result.inspected_count,
        "changed_root_count": len(result.changed_root_indices),
        "changed_root_indices": list(result.changed_root_indices),
    }


def _iter_process_snapshots() -> Iterable[ProcessSnapshot]:
    import psutil  # type: ignore[import-not-found]

    for process in psutil.process_iter(("pid", "name", "exe", "cmdline")):
        try:
            info = process.info
            yield ProcessSnapshot(
                pid=int(info.get("pid") or process.pid),
                name=str(info.get("name") or ""),
                executable=str(info["exe"]) if info.get("exe") else None,
                command_line=tuple(str(item) for item in (info.get("cmdline") or ())),
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue


def _client_process_family(process: ProcessSnapshot) -> str | None:
    candidates = (process.executable, process.name)
    for candidate in candidates:
        if not candidate:
            continue
        name = ntpath.basename(candidate).casefold()
        stem = name[:-4] if name.endswith(".exe") else name
        family = CLIENT_PROCESS_STEMS.get(stem)
        if family is not None:
            return family
    return None


def _fingerprint_forbidden_root(root: Path, *, root_index: int) -> RootMetadataFingerprint:
    digest = hashlib.sha256()
    if not root.exists() and not root.is_symlink():
        digest.update(b"missing\0")
        return RootMetadataFingerprint(
            root_index=root_index,
            exists=False,
            entry_count=0,
            file_count=0,
            directory_count=0,
            digest=digest.hexdigest(),
        )

    root_metadata = root.stat(follow_symlinks=False)
    _update_metadata_digest(digest, ".", "root", root_metadata)
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink() or _path_is_junction(root):
        return RootMetadataFingerprint(
            root_index=root_index,
            exists=True,
            entry_count=0,
            file_count=1,
            directory_count=0,
            digest=digest.hexdigest(),
        )

    entry_count = 0
    file_count = 0
    directory_count = 0
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, relative_parent = pending.pop()
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name.casefold())
        for entry in entries:
            relative = ntpath.join(relative_parent, entry.name) if relative_parent else entry.name
            metadata = entry.stat(follow_symlinks=False)
            entry_path = Path(entry.path)
            is_link = entry.is_symlink()
            is_junction = _path_is_junction(entry_path)
            is_directory = stat.S_ISDIR(metadata.st_mode) and not is_link and not is_junction
            kind = "directory" if is_directory else "junction" if is_junction else "link" if is_link else "file"
            _update_metadata_digest(digest, relative, kind, metadata)
            entry_count += 1
            if is_directory:
                directory_count += 1
                pending.append((entry_path, relative))
            else:
                file_count += 1
    return RootMetadataFingerprint(
        root_index=root_index,
        exists=True,
        entry_count=entry_count,
        file_count=file_count,
        directory_count=directory_count,
        digest=digest.hexdigest(),
    )


def _update_metadata_digest(digest: Any, relative: str, kind: str, metadata: os.stat_result) -> None:
    fields = (
        relative.replace("/", "\\").casefold(),
        kind,
        str(metadata.st_mode),
        str(metadata.st_size),
        str(metadata.st_mtime_ns),
        str(metadata.st_ctime_ns),
    )
    for field in fields:
        encoded = field.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, byteorder="big"))
        digest.update(encoded)


def _path_is_junction(path: Path) -> bool:
    check = getattr(path, "is_junction", None)
    return bool(check()) if check is not None else False


def _fingerprints_by_index(
    fingerprints: Sequence[RootMetadataFingerprint],
    *,
    snapshot: str,
) -> dict[int, RootMetadataFingerprint]:
    indexed: dict[int, RootMetadataFingerprint] = {}
    for fingerprint in fingerprints:
        if fingerprint.root_index in indexed:
            raise RuntimeError(f"Duplicate root index in {snapshot} metadata fingerprints.")
        indexed[fingerprint.root_index] = fingerprint
    return indexed


def _text_references_windows_root(value: str, root: str) -> bool:
    text = value.replace("/", "\\").casefold()
    needle = ntpath.normpath(root).casefold().rstrip("\\")
    start = 0
    while True:
        index = text.find(needle, start)
        if index < 0:
            return False
        end = index + len(needle)
        if end == len(text) or text[end] in "\\\"' \t;,":
            return True
        start = index + 1
