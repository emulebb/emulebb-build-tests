"""Shared Python-first CLI helpers for the canonical live/UI harness entrypoints."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from emule_test_harness.paths import (
    get_test_artifacts_root,
    get_test_reports_root,
    reject_windows_temp_path,
)
from emule_test_harness.artifact_names import (
    partial_result_file_name,
    result_file_name,
    summary_file_name,
    utc_run_id,
)

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import guard
    winreg = None  # type: ignore[assignment]

WORKSPACE_NAME = "workspace"
DEFAULT_APP_VARIANTS = ("main", "community", "tracing-harness")
MAIN_APP_EXE_NAME = "emulebb.exe"
LEGACY_APP_EXE_NAME = "emule.exe"
APP_VARIANT_WORKTREE_NAMES = {
    "community": "emulebb-community-baseline",
    "tracing-harness": "emulebb-community-tracing-harness",
}
PROTECTED_VOLUME_DIRECTORY_NAMES = frozenset(("system volume information", "$recycle.bin"))
# Admin fixture storage roots are runtime-only; reports keep harness artifacts, not mounted volume trees or VHD images.
REPORT_EXCLUDED_DIRECTORY_NAMES = frozenset(("admin-mounts", "admin-volumes", "shared-hash-root")) | PROTECTED_VOLUME_DIRECTORY_NAMES
LATEST_REPORT_EXCLUDED_DIRECTORY_NAMES = REPORT_EXCLUDED_DIRECTORY_NAMES | frozenset(
    (
        "crash-dumps",
        "dumps",
        "incoming",
        "profiles",
        "procdump",
        "radarr_movies_cat",
        "sonarr_series_cat",
        "temp",
    )
)
LATEST_REPORT_MEDIA_SUFFIXES = frozenset(
    (
        ".avi",
        ".m2ts",
        ".m4v",
        ".mkv",
        ".mov",
        ".mp4",
        ".mpeg",
        ".mpg",
        ".ts",
        ".wmv",
    )
)
LATEST_REPORT_HEAVY_SUFFIXES = LATEST_REPORT_MEDIA_SUFFIXES | frozenset((".dmp", ".etl", ".part", ".zip"))
WER_BASE_SUBKEY = r"Software\Microsoft\Windows\Windows Error Reporting"
LOCAL_DUMPS_BASE_SUBKEY = r"Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
LOCAL_DUMPS_DUMP_TYPE_FULL = 2
LOCAL_DUMPS_DUMP_COUNT = 64
LOCAL_DUMPS_TOOL_IMAGE_NAMES = ("umdh.exe", "procdump.exe", "procdump64.exe")
LOCAL_DUMPS_VALUE_NAMES = ("DumpFolder", "DumpType", "DumpCount")
ACCESS_VIOLATION_EXIT_CODE = 0xC0000005
_LOCAL_DUMPS_RESTORE_STATES: dict[tuple[str, str], dict[str, object] | None] = {}


@dataclass(frozen=True)
class HarnessRunPaths:
    """Resolved filesystem layout for one canonical harness invocation."""

    repo_root: Path
    workspace_root: Path
    app_root: Path
    app_exe: Path
    seed_config_dir: Path
    configuration: str
    suite_name: str
    source_artifacts_dir: Path
    run_report_dir: Path
    latest_report_dir: Path
    keep_source_artifacts: bool
    local_dumps: dict[str, object] = field(default_factory=dict)


def read_json_file(path: Path):
    """Reads one JSON artifact when present."""

    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_file(path: Path, payload) -> None:
    """Writes one JSON artifact with stable formatting."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _read_registry_values(subkey: str) -> dict[str, object] | None:
    """Reads a LocalDumps registry key when it already exists."""

    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as key:
            values: dict[str, object] = {}
            for name in ("DumpFolder", "DumpType", "DumpCount"):
                try:
                    value, value_type = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    continue
                values[name] = {
                    "value": value,
                    "type": int(value_type),
                }
            return values
    except FileNotFoundError:
        return None


def _sanitize_previous_registry_values(values: dict[str, object] | None) -> dict[str, object] | None:
    """Returns prior registry state without persisting stale filesystem roots."""

    if values is None:
        return None
    sanitized = dict(values)
    dump_folder = sanitized.get("DumpFolder")
    if isinstance(dump_folder, dict):
        sanitized["DumpFolder"] = {
            "present": True,
            "type": dump_folder.get("type"),
        }
    return sanitized


def _path_has_parts(path_text: str, expected_parts: tuple[str, ...]) -> bool:
    """Returns true when a path contains one contiguous case-insensitive part sequence."""

    parts = tuple(part.lower() for part in Path(os.path.expandvars(path_text)).parts)
    expected = tuple(part.lower() for part in expected_parts)
    return any(parts[index:index + len(expected)] == expected for index in range(0, len(parts) - len(expected) + 1))


def _is_harness_owned_dump_folder(value: object) -> bool:
    """Returns true for transient harness dump roots that must not be restored later."""

    if not isinstance(value, str) or not value.strip():
        return False
    return (
        _path_has_parts(value, ("state", "test-artifacts"))
        or _path_has_parts(value, ("state", "live-e2e-artifacts"))
        or _path_has_parts(value, ("repos", "emulebb-build-tests", "reports"))
    )


def _registry_restore_values(values: dict[str, object] | None) -> dict[str, object] | None:
    """Returns raw registry values to restore, or none for harness-owned stale roots."""

    if values is None:
        return None
    dump_folder = values.get("DumpFolder")
    if isinstance(dump_folder, dict) and _is_harness_owned_dump_folder(dump_folder.get("value")):
        return None
    return values


def _registry_dump_folder_matches(values: dict[str, object] | None, expected_dump_folder: str) -> bool:
    """Returns true when a LocalDumps key still points at the configured run folder."""

    if not isinstance(values, dict):
        return False
    dump_folder = values.get("DumpFolder")
    if not isinstance(dump_folder, dict):
        return False
    value = dump_folder.get("value")
    if not isinstance(value, str):
        return False
    return str(Path(os.path.expandvars(value)).resolve()).lower() == expected_dump_folder.lower()


def _delete_registry_value_if_present(key, name: str) -> None:
    """Deletes one registry value, ignoring absent values."""

    try:
        winreg.DeleteValue(key, name)
    except FileNotFoundError:
        return
    except OSError:
        return


def _restore_registry_values(subkey: str, restore_values: dict[str, object] | None) -> None:
    """Restores or clears one LocalDumps image key."""

    if restore_values is None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
                for name in LOCAL_DUMPS_VALUE_NAMES:
                    _delete_registry_value_if_present(key, name)
        except FileNotFoundError:
            return
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
        except OSError:
            return
        return

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
        for name in LOCAL_DUMPS_VALUE_NAMES:
            value = restore_values.get(name)
            if isinstance(value, dict) and "value" in value and "type" in value:
                winreg.SetValueEx(key, name, 0, int(value["type"]), value["value"])
            else:
                _delete_registry_value_if_present(key, name)


def _registry_root_name(root) -> str:
    """Returns a stable display name for a Windows registry root handle."""

    if winreg is not None and root == winreg.HKEY_LOCAL_MACHINE:
        return "HKLM"
    return "HKCU"


def _read_wer_root_values(root) -> dict[str, object] | None:
    """Reads Windows Error Reporting root values for one registry hive."""

    if winreg is None:
        return None
    try:
        with winreg.OpenKey(root, WER_BASE_SUBKEY) as key:
            values: dict[str, object] = {}
            for name in ("Disabled", "DontShowUI"):
                try:
                    value, value_type = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    continue
                values[name] = {
                    "value": value,
                    "type": int(value_type),
                }
            return values
    except FileNotFoundError:
        return None


def _set_wer_disabled_value(root, value: int) -> dict[str, object]:
    """Writes the WER Disabled flag for one hive and records before/after state."""

    result: dict[str, object] = {
        "root": _registry_root_name(root),
        "registry_subkey": _registry_root_name(root) + "\\" + WER_BASE_SUBKEY,
        "before": _read_wer_root_values(root),
        "write_attempted": True,
    }
    try:
        with winreg.CreateKeyEx(root, WER_BASE_SUBKEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Disabled", 0, winreg.REG_DWORD, value)
        result["write_ok"] = True
    except OSError as exc:
        result["write_ok"] = False
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    result["after"] = _read_wer_root_values(root)
    return result


def ensure_windows_error_reporting_enabled() -> dict[str, object]:
    """Enables WER where permitted so LocalDumps can be produced by crashes."""

    result: dict[str, object] = {
        "enabled": False,
        "hives": [],
    }
    if winreg is None:
        result["error"] = "winreg is unavailable; Windows Error Reporting can only be configured on Windows"
        return result

    hives: list[dict[str, object]] = []
    hives.append(_set_wer_disabled_value(winreg.HKEY_CURRENT_USER, 0))
    hklm_before = _read_wer_root_values(winreg.HKEY_LOCAL_MACHINE)
    hklm_disabled = (
        isinstance(hklm_before, dict)
        and isinstance(hklm_before.get("Disabled"), dict)
        and int(hklm_before["Disabled"].get("value")) != 0
    )
    if hklm_disabled:
        hives.append(_set_wer_disabled_value(winreg.HKEY_LOCAL_MACHINE, 0))
    else:
        hives.append(
            {
                "root": "HKLM",
                "registry_subkey": "HKLM\\" + WER_BASE_SUBKEY,
                "before": hklm_before,
                "write_attempted": False,
                "write_ok": True,
                "after": hklm_before,
            }
        )

    result["hives"] = hives
    result["enabled"] = not windows_error_reporting_is_disabled({"hives": hives})
    return result


def windows_error_reporting_is_disabled(wer: dict[str, object] | None) -> bool:
    """Returns true when recorded WER state still has Disabled set."""

    hives = wer.get("hives") if isinstance(wer, dict) else None
    if not isinstance(hives, list):
        return False
    for hive in hives:
        if not isinstance(hive, dict):
            continue
        after = hive.get("after")
        if not isinstance(after, dict):
            continue
        disabled = after.get("Disabled")
        if isinstance(disabled, dict):
            try:
                if int(disabled.get("value")) != 0:
                    return True
            except (TypeError, ValueError):
                return True
    return False


def configure_local_dumps(
    *,
    artifact_dir: Path,
    app_exe: Path,
    tool_image_names: tuple[str, ...] = LOCAL_DUMPS_TOOL_IMAGE_NAMES,
    dump_count: int = LOCAL_DUMPS_DUMP_COUNT,
) -> dict[str, object]:
    """Enables full WER LocalDumps for eMule and diagnostic tools for one run."""

    dump_dir = (artifact_dir / "crash-dumps").resolve()
    dump_dir.mkdir(parents=True, exist_ok=True)
    image_names = tuple(dict.fromkeys((app_exe.name, *tool_image_names)))
    result: dict[str, object] = {
        "enabled": False,
        "base_subkey": LOCAL_DUMPS_BASE_SUBKEY,
        "dump_folder": str(dump_dir),
        "dump_type": LOCAL_DUMPS_DUMP_TYPE_FULL,
        "dump_count": dump_count,
        "image_names": list(image_names),
        "wer": None,
        "entries": [],
    }
    if winreg is None:
        result["error"] = "winreg is unavailable; LocalDumps can only be configured on Windows"
        return result

    result["wer"] = ensure_windows_error_reporting_enabled()
    entries: list[dict[str, object]] = []
    for image_name in image_names:
        image_subkey = LOCAL_DUMPS_BASE_SUBKEY + "\\" + image_name
        before = _read_registry_values(image_subkey)
        restore_values = _registry_restore_values(before)
        _LOCAL_DUMPS_RESTORE_STATES[(image_subkey, str(dump_dir).lower())] = restore_values
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, image_subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "DumpFolder", 0, winreg.REG_EXPAND_SZ, str(dump_dir))
            winreg.SetValueEx(key, "DumpType", 0, winreg.REG_DWORD, LOCAL_DUMPS_DUMP_TYPE_FULL)
            winreg.SetValueEx(key, "DumpCount", 0, winreg.REG_DWORD, dump_count)
        before_summary = _sanitize_previous_registry_values(before)
        if before_summary is not None and restore_values is None:
            before_summary["restore_policy"] = "clear_harness_owned_previous"
        entries.append(
            {
                "image_name": image_name,
                "registry_subkey": "HKCU\\" + image_subkey,
                "before": before_summary,
                "after": _read_registry_values(image_subkey),
            }
        )
    result["enabled"] = True
    result["entries"] = entries
    return result


def restore_local_dumps(local_dumps: dict[str, object]) -> dict[str, object]:
    """Restores LocalDumps keys touched by one run before transient artifacts are removed."""

    result: dict[str, object] = {
        "attempted": False,
        "entries": [],
    }
    if winreg is None or not isinstance(local_dumps, dict):
        return result
    dump_folder = local_dumps.get("dump_folder")
    entries = local_dumps.get("entries")
    if not isinstance(dump_folder, str) or not isinstance(entries, list):
        return result

    expected_dump_folder = str(Path(os.path.expandvars(dump_folder)).resolve())
    result["attempted"] = True
    restore_entries: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        image_name = entry.get("image_name")
        if not isinstance(image_name, str) or not image_name:
            continue
        image_subkey = LOCAL_DUMPS_BASE_SUBKEY + "\\" + image_name
        restore_entry: dict[str, object] = {
            "image_name": image_name,
            "registry_subkey": "HKCU\\" + image_subkey,
        }
        current = _read_registry_values(image_subkey)
        if not _registry_dump_folder_matches(current, expected_dump_folder):
            restore_entry["restored"] = False
            restore_entry["reason"] = "current_dump_folder_changed_or_absent"
            restore_entries.append(restore_entry)
            continue
        restore_values = _LOCAL_DUMPS_RESTORE_STATES.pop((image_subkey, expected_dump_folder.lower()), None)
        try:
            _restore_registry_values(image_subkey, restore_values)
            restore_entry["restored"] = True
            restore_entry["cleared"] = restore_values is None
        except OSError as exc:
            restore_entry["restored"] = False
            restore_entry["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        restore_entries.append(restore_entry)
    result["entries"] = restore_entries
    return result


def collect_local_dump_files(local_dumps: dict[str, object]) -> dict[str, object]:
    """Returns the WER dump files currently present in the configured dump folder."""

    dump_folder = local_dumps.get("dump_folder") if isinstance(local_dumps, dict) else None
    image_names = local_dumps.get("image_names") if isinstance(local_dumps, dict) else None
    dump_dir = Path(str(dump_folder)).resolve() if dump_folder else None
    expected_prefixes = {
        str(image_name).lower() + "."
        for image_name in image_names
        if isinstance(image_name, str) and image_name.strip()
    } if isinstance(image_names, list) else set()
    files: list[dict[str, object]] = []
    image_counts: dict[str, int] = {}
    non_empty_image_counts: dict[str, int] = {}
    if dump_dir and dump_dir.is_dir():
        for dump_path in sorted(dump_dir.glob("*.dmp"), key=lambda path: path.stat().st_mtime):
            lowered_name = dump_path.name.lower()
            if expected_prefixes and not any(lowered_name.startswith(prefix) for prefix in expected_prefixes):
                continue
            stat = dump_path.stat()
            matched_image = next(
                (
                    str(image_name)
                    for image_name in image_names
                    if isinstance(image_name, str) and lowered_name.startswith(str(image_name).lower() + ".")
                ),
                "unknown",
            ) if isinstance(image_names, list) else "unknown"
            image_counts[matched_image] = image_counts.get(matched_image, 0) + 1
            if stat.st_size > 0:
                non_empty_image_counts[matched_image] = non_empty_image_counts.get(matched_image, 0) + 1
            files.append(
                {
                    "name": dump_path.name,
                    "path": str(dump_path),
                    "image_name": matched_image,
                    "size_bytes": stat.st_size,
                    "mtime": round(stat.st_mtime, 3),
                }
            )
    return {
        "dump_folder": str(dump_dir) if dump_dir else None,
        "files": files,
        "count": len(files),
        "image_counts": image_counts,
        "non_empty_image_counts": non_empty_image_counts,
    }


def local_dump_files_for_image(local_dump_files: dict[str, object], image_name: str) -> list[dict[str, object]]:
    """Filters a collected LocalDumps file list by executable image name."""

    files = local_dump_files.get("files") if isinstance(local_dump_files, dict) else None
    if not isinstance(files, list):
        return []
    expected_prefix = image_name.lower() + "."
    return [
        row
        for row in files
        if isinstance(row, dict) and str(row.get("name") or "").lower().startswith(expected_prefix)
    ]


def process_exited_with_access_violation(process_state: dict[str, object] | None) -> bool:
    """Returns true when a recorded process exit state is the Windows AV code."""

    if not isinstance(process_state, dict):
        return False
    try:
        exit_code = int(process_state.get("exit_code"))
    except (TypeError, ValueError):
        return False
    return exit_code == ACCESS_VIOLATION_EXIT_CODE or (exit_code & 0xFFFFFFFF) == ACCESS_VIOLATION_EXIT_CODE


def to_windows_extended_path(path: Path) -> str:
    """Returns a Windows extended-length spelling without trimming exact names."""

    text = str(path if path.is_absolute() else Path.cwd() / path)
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def exact_path_exists(path: Path) -> bool:
    """Reports existence through an exact-name-aware Windows path spelling."""

    return os.path.exists(to_windows_extended_path(path))


def exact_makedirs(path: Path) -> None:
    """Creates directories without letting Win32 trim trailing dot/space names."""

    os.makedirs(to_windows_extended_path(path), exist_ok=True)


def exact_copy2(source_path: Path, destination_path: Path) -> None:
    """Copies one file while preserving exact source and destination names."""

    exact_makedirs(destination_path.parent)
    shutil.copy2(to_windows_extended_path(source_path), to_windows_extended_path(destination_path))


def exact_rmtree(path: Path) -> None:
    """Removes a directory tree through an exact-name-aware path spelling."""

    shutil.rmtree(to_windows_extended_path(path))


def get_repo_root(script_file: str | Path) -> Path:
    """Returns the `emulebb-build-tests` repo root from one script path."""

    return Path(script_file).resolve().parent.parent


def get_emule_workspace_root(repo_root: Path) -> Path:
    """Returns the canonical eMule workspace root that owns `repos/` and `workspaces/`."""

    if os.environ.get("EMULEBB_WORKSPACE_ROOT"):
        return Path(os.environ["EMULEBB_WORKSPACE_ROOT"]).resolve()
    return (repo_root / ".." / "..").resolve()


def get_default_workspace_root(repo_root: Path, workspace_name: str = WORKSPACE_NAME) -> Path:
    """Returns the canonical default workspace variant root."""

    return (get_emule_workspace_root(repo_root) / "workspaces" / workspace_name).resolve()


def sanitize_report_token(value: str) -> str:
    """Normalizes one path-ish value into a stable report token."""

    token = "".join(char if char.isalnum() or char in "._-" else "-" for char in value).strip("-")
    while "--" in token:
        token = token.replace("--", "-")
    return token or "run"


def get_app_variant_label(app_exe: Path) -> str:
    """Returns the app-root label used in report directory names."""

    return app_exe.resolve().parent.parent.parent.parent.name


def resolve_app_root(
    repo_root: Path,
    workspace_root: Path | None = None,
    app_root: str | Path | None = None,
    preferred_variant_names: tuple[str, ...] = DEFAULT_APP_VARIANTS,
) -> Path:
    """Resolves the canonical app root without a PowerShell helper."""

    if app_root:
        resolved = Path(app_root).resolve()
        if not resolved.is_dir():
            raise RuntimeError(f"Explicit app root does not exist: {resolved}")
        return resolved

    resolved_workspace_root = (workspace_root or get_default_workspace_root(repo_root)).resolve()
    app_parent = resolved_workspace_root / "app"
    if not app_parent.is_dir():
        raise RuntimeError(f"Workspace app directory does not exist: {app_parent}")

    candidates: list[Path] = [app_parent / "emulebb-main"]
    for variant_name in preferred_variant_names:
        if variant_name == "main":
            continue
        mapped_name = APP_VARIANT_WORKTREE_NAMES.get(variant_name)
        if mapped_name:
            candidates.append(app_parent / mapped_name)
        candidates.append(app_parent / f"eMule-{variant_name}")
    candidates.extend(sorted(path for path in app_parent.glob("eMule-*") if path.is_dir()))

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            return resolved

    raise RuntimeError(f"Unable to resolve a canonical app root under '{app_parent}'.")


def resolve_app_executable(
    repo_root: Path,
    configuration: str,
    workspace_root: Path | None = None,
    app_root: str | Path | None = None,
    app_exe: str | Path | None = None,
) -> tuple[Path, Path, Path]:
    """Resolves the concrete app executable plus its workspace/app roots."""

    resolved_workspace_root = (workspace_root or get_default_workspace_root(repo_root)).resolve()
    resolved_app_root = resolve_app_root(
        repo_root=repo_root,
        workspace_root=resolved_workspace_root,
        app_root=app_root,
    )
    if app_exe:
        resolved_app_exe = Path(app_exe).resolve()
    else:
        exe_name = MAIN_APP_EXE_NAME if resolved_app_root.name == "emulebb-main" else LEGACY_APP_EXE_NAME
        resolved_app_exe = (resolved_app_root / "srchybrid" / "x64" / configuration / exe_name).resolve()
    if not resolved_app_exe.is_file():
        raise RuntimeError(f"App executable was not found at '{resolved_app_exe}'.")
    return resolved_workspace_root, resolved_app_root, resolved_app_exe


def prepare_run_paths(
    *,
    script_file: str | Path,
    suite_name: str,
    configuration: str,
    workspace_root: str | Path | None = None,
    app_root: str | Path | None = None,
    app_exe: str | Path | None = None,
    artifacts_dir: str | Path | None = None,
    keep_artifacts: bool = False,
) -> HarnessRunPaths:
    """Resolves canonical paths for one Python-first harness invocation."""

    repo_root = get_repo_root(script_file)
    resolved_workspace_root, resolved_app_root, resolved_app_exe = resolve_app_executable(
        repo_root=repo_root,
        configuration=configuration,
        workspace_root=Path(workspace_root).resolve() if workspace_root else None,
        app_root=app_root,
        app_exe=app_exe,
    )
    seed_config_dir = (repo_root / "manifests" / "live-profile-seed" / "config").resolve()
    if not seed_config_dir.is_dir():
        raise RuntimeError(f"Seed config directory was not found at '{seed_config_dir}'.")

    report_root = get_test_reports_root(resolved_workspace_root)
    reject_windows_temp_path(report_root, "report root")
    suite_report_root = report_root / suite_name
    report_stamp = utc_run_id()
    report_label = f"{report_stamp}-{sanitize_report_token(get_app_variant_label(resolved_app_exe))}-{configuration.lower()}-{os.getpid()}"
    source_artifacts_dir = (
        Path(artifacts_dir).resolve()
        if artifacts_dir
        else (get_test_artifacts_root(resolved_workspace_root) / suite_name / report_label).resolve()
    )
    reject_windows_temp_path(source_artifacts_dir, "artifacts directory")
    source_artifacts_dir.mkdir(parents=True, exist_ok=True)
    local_dumps = configure_local_dumps(
        artifact_dir=source_artifacts_dir,
        app_exe=resolved_app_exe,
    )
    write_json_file(source_artifacts_dir / "local-dumps.json", local_dumps)

    return HarnessRunPaths(
        repo_root=repo_root,
        workspace_root=resolved_workspace_root,
        app_root=resolved_app_root,
        app_exe=resolved_app_exe,
        seed_config_dir=seed_config_dir,
        configuration=configuration,
        suite_name=suite_name,
        source_artifacts_dir=source_artifacts_dir,
        run_report_dir=(suite_report_root / report_label).resolve(),
        latest_report_dir=(report_root / suite_name / "latest").resolve(),
        keep_source_artifacts=keep_artifacts or bool(artifacts_dir),
        local_dumps=local_dumps,
    )


def resolve_profile_seed_dir(paths: HarnessRunPaths, profile_seed_dir: str | Path | None) -> Path:
    """Resolves an optional profile-seed override against the run path defaults."""

    return Path(profile_seed_dir).resolve() if profile_seed_dir else paths.seed_config_dir


def should_skip_report_snapshot_entry(name: str, *, is_directory: bool, lightweight_latest: bool) -> bool:
    """Returns whether a generated report entry should be left out of a copied snapshot."""

    normalized_name = name.lower()
    if is_directory:
        excluded_directories = LATEST_REPORT_EXCLUDED_DIRECTORY_NAMES if lightweight_latest else REPORT_EXCLUDED_DIRECTORY_NAMES
        return normalized_name in excluded_directories
    return lightweight_latest and Path(normalized_name).suffix in LATEST_REPORT_HEAVY_SUFFIXES


def publish_directory_snapshot(source_directory: Path, destination_directory: Path, *, lightweight_latest: bool = False) -> None:
    """Refreshes one report directory from another directory snapshot."""

    if exact_path_exists(destination_directory):
        exact_rmtree(destination_directory)
    exact_makedirs(destination_directory)
    with os.scandir(to_windows_extended_path(source_directory)) as entries:
        for entry in entries:
            source_path = source_directory / entry.name
            is_directory = entry.is_dir(follow_symlinks=False)
            if should_skip_report_snapshot_entry(entry.name, is_directory=is_directory, lightweight_latest=lightweight_latest):
                continue
            target_path = destination_directory / entry.name
            if is_directory:
                publish_directory_snapshot(source_path, target_path, lightweight_latest=lightweight_latest)
            else:
                exact_copy2(source_path, target_path)


def cleanup_source_artifacts(paths: HarnessRunPaths) -> None:
    """Removes transient source artifacts when the invocation does not retain them."""

    local_dumps_restore = restore_local_dumps(paths.local_dumps)
    failed_restore_entries = [
        entry
        for entry in local_dumps_restore.get("entries", [])
        if isinstance(entry, dict) and entry.get("error")
    ]
    if failed_restore_entries:
        print(f"Warning: LocalDumps registry cleanup had errors: {failed_restore_entries}")
    if paths.keep_source_artifacts:
        return
    if exact_path_exists(paths.source_artifacts_dir):
        deadline = time.monotonic() + 10.0
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            try:
                exact_rmtree(paths.source_artifacts_dir)
                return
            except OSError as exc:
                last_error = exc
                time.sleep(0.5)
        print(f"Warning: leaving source artifacts after cleanup failed: {paths.source_artifacts_dir} ({last_error})")


def publish_run_artifacts(paths: HarnessRunPaths) -> None:
    """Copies the source artifact directory into the stable report directory."""

    exact_makedirs(paths.run_report_dir.parent)
    publish_directory_snapshot(paths.source_artifacts_dir, paths.run_report_dir)
    rewrite_published_json_paths(paths)


def publish_latest_report(paths: HarnessRunPaths) -> None:
    """Refreshes the suite-level latest snapshot from one run report."""

    publish_directory_snapshot(paths.run_report_dir, paths.latest_report_dir, lightweight_latest=True)


def rewrite_published_json_paths(paths: HarnessRunPaths) -> None:
    """Rewrites copied JSON reports to point at their published report tree."""

    replacements = (
        (str(paths.source_artifacts_dir), str(paths.run_report_dir)),
        (paths.source_artifacts_dir.as_posix(), paths.run_report_dir.as_posix()),
    )
    for json_path in paths.run_report_dir.rglob("*.json"):
        try:
            payload = read_json_file(json_path)
        except (OSError, json.JSONDecodeError):
            continue
        rewritten = _rewrite_json_strings(payload, replacements)
        if rewritten != payload:
            write_json_file(json_path, rewritten)


def _rewrite_json_strings(value, replacements: tuple[tuple[str, str], ...]):
    if isinstance(value, str):
        rewritten = value
        for source, target in replacements:
            rewritten = rewritten.replace(source, target)
        return rewritten
    if isinstance(value, list):
        return [_rewrite_json_strings(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_json_strings(item, replacements) for key, item in value.items()}
    return value


def build_live_ui_summary(
    *,
    status: str,
    paths: HarnessRunPaths,
    result_filename: str | None = None,
    error_message: str = "",
) -> dict[str, object]:
    """Builds the UI-harness summary shape consumed by the shared summary publisher."""

    return {
        "generated_utc": utc_generated_timestamp(),
        "status": status,
        "app_exe": str(paths.app_exe),
        "configuration": paths.configuration,
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "local_dumps": paths.local_dumps,
        "result": read_json_file(paths.run_report_dir / (result_filename or result_file_name(paths.suite_name))),
        "error": error_message or None,
    }


def build_startup_diagnostics_summary(
    *,
    status: str,
    paths: HarnessRunPaths,
    shared_root: Path,
    result_filename: str | None = None,
    error_message: str = "",
) -> dict[str, object]:
    """Builds the startup-diagnostics wrapper summary consumed by the shared harness summary."""

    return {
        "generated_utc": utc_generated_timestamp(),
        "status": status,
        "app_exe": str(paths.app_exe),
        "configuration": paths.configuration,
        "shared_root": str(shared_root.resolve()),
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "local_dumps": paths.local_dumps,
        "result": read_json_file(paths.run_report_dir / (result_filename or result_file_name(paths.suite_name))),
        "error": error_message or None,
    }


def find_python_executable() -> str:
    """Returns the preferred Python 3 executable for the harness repo."""

    for candidate in ("python", "py"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("Python 3 was not found on PATH.")


def utc_generated_timestamp() -> str:
    """Returns an ISO-like UTC timestamp for machine-readable reports."""

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def suite_result_file_name(suite_name: str) -> str:
    """Returns the canonical suite result filename."""

    return result_file_name(suite_name)


def suite_partial_result_file_name(suite_name: str) -> str:
    """Returns the canonical suite partial result filename."""

    return partial_result_file_name(suite_name)


def suite_summary_file_name(suite_name: str) -> str:
    """Returns the canonical suite summary filename."""

    return summary_file_name(suite_name)


def update_harness_summary(
    repo_root: Path,
    *,
    live_ui_summary_path: Path | None = None,
    startup_diagnostics_summary_path: Path | None = None,
) -> None:
    """Refreshes the shared harness summary using the canonical Python publisher."""

    python_executable = find_python_executable()
    command = [python_executable]
    if Path(python_executable).stem.lower() == "py":
        command.append("-3")
    command.extend(
        [
            str((repo_root / "scripts" / "publish-harness-summary.py").resolve()),
            "--test-repo-root",
            str(repo_root.resolve()),
        ]
    )
    if live_ui_summary_path is not None:
        command.extend(["--live-ui-summary-path", str(live_ui_summary_path.resolve())])
    if startup_diagnostics_summary_path is not None:
        command.extend(["--startup-diagnostics-summary-path", str(startup_diagnostics_summary_path.resolve())])
    subprocess.run(command, check=True)
