"""Protocol-sensitive source drift checks for Kad/eD2K parity."""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ITEM_ID_PATTERN = re.compile(r"^(BUG|FEAT|CI|REF|ARR|AMUT)-\d{3}$")


@dataclass(frozen=True)
class ProtocolSurfaceAllowlistEntry:
    """One intentional protocol-sensitive diff allowance."""

    path_glob: str
    item_id: str
    reason: str
    proof_command: str


@dataclass(frozen=True)
class ProtocolSurfaceManifest:
    """Configured protocol-sensitive paths and intentional drift allowances."""

    protocol_path_globs: tuple[str, ...]
    allowlist: tuple[ProtocolSurfaceAllowlistEntry, ...]


@dataclass(frozen=True)
class ProtocolSurfaceViolation:
    """One unallowlisted protocol-sensitive changed path."""

    path: str
    reason: str


@dataclass(frozen=True)
class ProtocolSurfaceReport:
    """Result of checking current app drift against the protocol surface manifest."""

    changed_protocol_paths: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    violations: tuple[ProtocolSurfaceViolation, ...]

    @property
    def passed(self) -> bool:
        """Reports whether all protocol-sensitive changes were allowlisted."""

        return not self.violations


def load_manifest(path: Path) -> ProtocolSurfaceManifest:
    """Loads and validates a protocol surface manifest JSON file."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    protocol_path_globs = tuple(_read_string_list(payload, "protocol_path_globs"))
    allowlist_entries = tuple(_read_allowlist_entries(payload.get("allowlist", [])))
    if not protocol_path_globs:
        raise ValueError("protocol_path_globs must not be empty")
    return ProtocolSurfaceManifest(protocol_path_globs=protocol_path_globs, allowlist=allowlist_entries)


def check_protocol_surface(
    *,
    manifest: ProtocolSurfaceManifest,
    test_run_app_root: Path,
    baseline_app_root: Path,
) -> ProtocolSurfaceReport:
    """Checks main-vs-baseline app diffs against the configured protocol surface."""

    test_ref = _git_stdout(test_run_app_root, "rev-parse", "HEAD")
    baseline_ref = _git_stdout(baseline_app_root, "rev-parse", "HEAD")
    changed_paths = _changed_paths(test_run_app_root, baseline_ref, test_ref, manifest.protocol_path_globs)
    changed_protocol_paths = tuple(path for path in changed_paths if _matches_any(path, manifest.protocol_path_globs))
    allowed_paths: list[str] = []
    violations: list[ProtocolSurfaceViolation] = []

    for path in changed_protocol_paths:
        if _matching_allowlist_entry(path, manifest.allowlist) is None:
            violations.append(ProtocolSurfaceViolation(path=path, reason="missing protocol drift allowlist entry"))
        else:
            allowed_paths.append(path)

    return ProtocolSurfaceReport(
        changed_protocol_paths=changed_protocol_paths,
        allowed_paths=tuple(allowed_paths),
        violations=tuple(violations),
    )


def write_report(report: ProtocolSurfaceReport, path: Path) -> None:
    """Writes a machine-readable protocol surface report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "passed": report.passed,
        "changed_protocol_paths": list(report.changed_protocol_paths),
        "allowed_paths": list(report.allowed_paths),
        "violations": [{"path": violation.path, "reason": violation.reason} for violation in report.violations],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def render_report_lines(report: ProtocolSurfaceReport) -> list[str]:
    """Renders a concise human-readable protocol surface report."""

    lines = [
        f"Protocol-sensitive changed paths: {len(report.changed_protocol_paths)}",
        f"Allowlisted protocol-sensitive paths: {len(report.allowed_paths)}",
        f"Protocol surface violations: {len(report.violations)}",
    ]
    for violation in report.violations:
        lines.append(f"FAIL {violation.path}: {violation.reason}")
    return lines


def _read_string_list(payload: dict[str, Any], key: str) -> list[str]:
    values = payload.get(key)
    if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"{key} must be a non-empty string list")
    return values


def _read_allowlist_entries(values: Any) -> list[ProtocolSurfaceAllowlistEntry]:
    if not isinstance(values, list):
        raise ValueError("allowlist must be a list")
    entries: list[ProtocolSurfaceAllowlistEntry] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise ValueError(f"allowlist[{index}] must be an object")
        entry = ProtocolSurfaceAllowlistEntry(
            path_glob=_read_required_string(value, "path_glob", index),
            item_id=_read_required_string(value, "item_id", index),
            reason=_read_required_string(value, "reason", index),
            proof_command=_read_required_string(value, "proof_command", index),
        )
        if ITEM_ID_PATTERN.match(entry.item_id) is None:
            raise ValueError(f"allowlist[{index}].item_id must be a tracked item id")
        entries.append(entry)
    return entries


def _read_required_string(value: dict[str, Any], key: str, index: int) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result.strip():
        raise ValueError(f"allowlist[{index}].{key} must be a non-empty string")
    return result


def _changed_paths(app_root: Path, baseline_ref: str, test_ref: str, path_globs: tuple[str, ...]) -> tuple[str, ...]:
    args = ["diff", "--name-only", f"{baseline_ref}..{test_ref}", "--", *path_globs]
    output = _git_stdout(app_root, *args)
    return tuple(sorted(line.replace("\\", "/") for line in output.splitlines() if line.strip()))


def _matching_allowlist_entry(
    path: str,
    entries: tuple[ProtocolSurfaceAllowlistEntry, ...],
) -> ProtocolSurfaceAllowlistEntry | None:
    for entry in entries:
        if fnmatch.fnmatchcase(path, entry.path_glob):
            return entry
    return None


def _matches_any(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _git_stdout(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()
