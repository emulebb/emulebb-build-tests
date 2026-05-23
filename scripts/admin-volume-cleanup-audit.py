"""Live audit that admin VHD fixtures and transient harness state are cleaned."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixture,
    AdminVolumeFixtureConfig,
    create_admin_volume_fixture,
)
from emule_test_harness.paths import reject_windows_temp_path  # noqa: E402

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import guard
    winreg = None  # type: ignore[assignment]


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")

LOCAL_DUMPS_BASE_SUBKEY = r"Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
LOCAL_DUMPS_VALUE_NAMES = ("DumpFolder", "DumpType", "DumpCount")
DISKPART_SCRIPT_GLOB = "diskpart-*.txt"


def path_has_parts(path_text: str, expected_parts: tuple[str, ...]) -> bool:
    """Returns true when a path contains one contiguous case-insensitive part sequence."""

    parts = tuple(part.lower() for part in Path(os.path.expandvars(path_text)).parts)
    expected = tuple(part.lower() for part in expected_parts)
    return any(parts[index:index + len(expected)] == expected for index in range(0, len(parts) - len(expected) + 1))


def is_transient_harness_path(path_text: object) -> bool:
    """Returns whether a registry/report path points at transient harness-owned storage."""

    if not isinstance(path_text, str) or not path_text.strip():
        return False
    return (
        path_has_parts(path_text, ("state", "test-artifacts"))
        or path_has_parts(path_text, ("state", "live-e2e-artifacts"))
        or path_has_parts(path_text, ("repos", "emulebb-build-tests", "reports"))
    )


def read_local_dumps_values(subkey: str) -> dict[str, object] | None:
    """Reads selected values from one HKCU LocalDumps subkey."""

    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as key:
            values: dict[str, object] = {}
            for name in LOCAL_DUMPS_VALUE_NAMES:
                try:
                    value, value_type = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    continue
                values[name] = {"value": value, "type": int(value_type)}
            return values
    except FileNotFoundError:
        return None


def enumerate_local_dumps_entries() -> list[dict[str, object]]:
    """Returns HKCU LocalDumps image entries with compact value summaries."""

    if winreg is None:
        return []
    entries: list[dict[str, object]] = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, LOCAL_DUMPS_BASE_SUBKEY) as base_key:
            index = 0
            while True:
                try:
                    image_name = winreg.EnumKey(base_key, index)
                except OSError:
                    break
                image_subkey = LOCAL_DUMPS_BASE_SUBKEY + "\\" + image_name
                entries.append(
                    {
                        "image_name": image_name,
                        "registry_subkey": "HKCU\\" + image_subkey,
                        "values": read_local_dumps_values(image_subkey) or {},
                    }
                )
                index += 1
    except FileNotFoundError:
        return []
    return entries


def audit_local_dumps_transient_roots() -> dict[str, object]:
    """Reports LocalDumps entries that still point at transient harness roots."""

    entries = enumerate_local_dumps_entries()
    offenders: list[dict[str, object]] = []
    for entry in entries:
        values = entry.get("values")
        if not isinstance(values, dict):
            continue
        dump_folder = values.get("DumpFolder")
        if not isinstance(dump_folder, dict):
            continue
        if is_transient_harness_path(dump_folder.get("value")):
            offenders.append(entry)
    return {
        "status": "passed" if not offenders else "failed",
        "checked": winreg is not None,
        "entry_count": len(entries),
        "offenders": offenders,
    }


def volume_mount_point_present(path: Path) -> bool:
    """Returns whether the path is still registered as a Windows volume mount point."""

    if os.name != "nt" or not path.exists():
        return False
    root_text = str(path.resolve())
    if not root_text.endswith("\\"):
        root_text += "\\"
    buffer = ctypes.create_unicode_buffer(256)
    return bool(ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(root_text, buffer, len(buffer)))


def query_disk_image(path: Path) -> dict[str, object]:
    """Queries Windows for one VHD attachment state using the platform storage cmdlet."""

    if os.name != "nt":
        return {"checked": False, "reason": "non_windows"}
    command = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        (
            "& { param([string]$ImagePath) "
            "$image = Get-DiskImage -ImagePath $ImagePath -ErrorAction SilentlyContinue; "
            "if ($null -eq $image) { '{}'} "
            "else { $image | Select-Object ImagePath,Attached | ConvertTo-Json -Compress } }"
        ),
        str(path),
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    result: dict[str, object] = {
        "checked": True,
        "command": command,
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
    if completed.returncode != 0:
        result["query_error"] = completed.stderr.strip() or completed.stdout.strip()
        return result
    try:
        payload = json.loads(completed.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        result["query_error"] = f"invalid JSON from Get-DiskImage: {exc}"
        return result
    result["attached"] = bool(payload.get("Attached")) if isinstance(payload, dict) and payload else False
    return result


def audit_fixture_cleanup(
    *,
    vhd_path: Path,
    drive_root: Path,
    mount_root: Path,
    keep_vhd: bool,
) -> dict[str, object]:
    """Audits one fixture after its context manager has exited."""

    disk_image = query_disk_image(vhd_path)
    checks = {
        "drive_letter_removed": not drive_root.exists(),
        "mount_point_removed": not volume_mount_point_present(mount_root),
        "vhd_file_removed_or_kept_by_policy": keep_vhd or not vhd_path.exists(),
        "vhd_not_attached": disk_image.get("attached") is False,
    }
    errors = [name for name, passed in checks.items() if not passed]
    return {
        "status": "passed" if not errors else "failed",
        "vhd_path": str(vhd_path),
        "drive_root": str(drive_root),
        "mount_root": str(mount_root),
        "keep_vhd": keep_vhd,
        "checks": checks,
        "disk_image": disk_image,
        "errors": errors,
    }


def audit_admin_artifact_tree(root: Path, *, keep_vhd: bool) -> dict[str, object]:
    """Scans the aggregate artifact tree for lingering admin VHD fixture artifacts."""

    vhd_files = sorted(root.rglob("admin-volumes/*.vhdx")) if root.exists() else []
    diskpart_scripts = sorted(root.rglob(f"admin-volumes/diskpart-scripts/{DISKPART_SCRIPT_GLOB}")) if root.exists() else []
    mount_points = [
        path
        for path in sorted(root.rglob("admin-mounts/*")) if path.is_dir() and volume_mount_point_present(path)
    ] if root.exists() else []
    errors: list[str] = []
    if vhd_files and not keep_vhd:
        errors.append("unexpected_vhd_files")
    if diskpart_scripts:
        errors.append("diskpart_scripts_left")
    if mount_points:
        errors.append("mount_points_left")
    return {
        "status": "passed" if not errors else "failed",
        "root": str(root),
        "keep_vhd": keep_vhd,
        "vhd_files": [str(path) for path in vhd_files],
        "diskpart_scripts": [str(path) for path in diskpart_scripts],
        "mount_points": [str(path) for path in mount_points],
        "errors": errors,
    }


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the throwaway VHD fixture used by the cleanup audit."""

    mount_parent = Path(args.mount_root).resolve() if args.mount_root else paths.source_artifacts_dir / "admin-mounts"
    reject_windows_temp_path(mount_parent, "admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / "admin-volume-cleanup-audit.vhdx",
        mount_root=mount_parent / "admin-volume-cleanup-audit",
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


def build_parser() -> argparse.ArgumentParser:
    """Builds the admin-volume cleanup audit parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=128)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    return parser


def run_cleanup_audit(args: argparse.Namespace) -> dict[str, object]:
    """Runs the live cleanup audit and writes a detailed JSON result."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("admin-volume-cleanup-audit requires --admin-volume-fixtures.")
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="admin-volume-cleanup-audit",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    config = build_admin_fixture_config(paths, args)
    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "failed",
        "suite": "admin-volume-cleanup-audit",
        "configuration": paths.configuration,
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "local_dumps": paths.local_dumps,
        "admin_volume_fixture": {
            "enabled": True,
            "vhd_path": str(config.vhd_path),
            "mount_root": str(config.mount_root),
            "local_control_root": str(config.local_control_root),
            "size_mb": config.size_mb,
            "keep": config.keep,
        },
        "checks": {},
    }
    try:
        with create_admin_volume_fixture(config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            drive_root = fixture.drive_root
            mount_root = fixture.mount_root
            vhd_path = fixture.vhd_path
            (drive_root / "sentinel-drive.txt").write_text("drive\n", encoding="utf-8")
            (mount_root / "sentinel-mount.txt").write_text("mount\n", encoding="utf-8")
            fixture.local_control_root.joinpath("sentinel-local.txt").write_text("local\n", encoding="utf-8")
            summary["fixture_runtime"] = {
                "drive_root": str(drive_root),
                "mount_root": str(mount_root),
                "vhd_path": str(vhd_path),
                "drive_exists": drive_root.exists(),
                "mount_point_present": volume_mount_point_present(mount_root),
            }

        summary["checks"]["fixture_cleanup"] = audit_fixture_cleanup(
            vhd_path=vhd_path,
            drive_root=drive_root,
            mount_root=mount_root,
            keep_vhd=args.keep_admin_fixtures,
        )
        summary["local_dumps_restore"] = harness_cli_common.restore_local_dumps(paths.local_dumps)
        summary["checks"]["local_dumps_transient_roots"] = audit_local_dumps_transient_roots()
        summary["checks"]["admin_artifact_tree"] = audit_admin_artifact_tree(
            paths.source_artifacts_dir.parent,
            keep_vhd=args.keep_admin_fixtures,
        )
        failed = [
            name
            for name, check in summary["checks"].items()
            if isinstance(check, dict) and check.get("status") != "passed"
        ]
        summary["failed_checks"] = failed
        summary["status"] = "passed" if not failed else "failed"
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "admin-volume-cleanup-audit-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """CLI entrypoint."""

    summary = run_cleanup_audit(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
