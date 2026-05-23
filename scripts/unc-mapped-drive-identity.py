"""Live proof for UNC and mapped-network shared-cache path identity."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import asdict, dataclass
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
    build_storage_topology,
    create_admin_volume_fixture,
    find_available_drive_letter,
)
from emule_test_harness.paths import reject_windows_temp_path  # noqa: E402


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


live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
startup_profiles = load_local_module("startup_profile_scenarios", "startup-profile-scenarios.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit", "admin-volume-cleanup-audit.py")

SUITE_NAME = "unc-mapped-drive-identity"
FIXTURE_FILES = (
    ("alpha.txt", b"alpha\n"),
    ("beta.txt", b"beta\n"),
    ("gamma space.txt", b"gamma\n"),
)
DRIVE_FIXED = 3
DRIVE_REMOTE = 4


@dataclass(frozen=True)
class CommandResult:
    """Captured result from one SMB or drive-mapping command."""

    command: list[str]
    return_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class NetworkShareFixture:
    """Resolved UNC and mapped-drive roots for one temporary SMB share."""

    share_name: str
    share_root: Path
    unc_root: str
    mapped_drive_root: Path
    create_share_result: CommandResult
    map_drive_result: CommandResult


def run_command(command: list[str]) -> CommandResult:
    """Runs one command and captures text output."""

    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return CommandResult(command=command, return_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)


def current_windows_account() -> str:
    """Returns the current Windows account name for SMB share ACLs."""

    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError(f"Unable to resolve current Windows account: {completed.stderr.strip() or completed.stdout.strip()}")
    return completed.stdout.strip()


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the UNC mapped-drive suite."""

    mount_parent = (
        Path(args.mount_root).resolve()
        if args.mount_root
        else paths.source_artifacts_dir.parent / "admin-mounts" / SUITE_NAME
    )
    reject_windows_temp_path(mount_parent, "admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / f"{SUITE_NAME}.vhdx",
        mount_root=mount_parent / SUITE_NAME,
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


def create_smb_share_command(name: str, path: Path, account: str) -> list[str]:
    """Builds the PowerShell command that creates one temporary SMB share."""

    script = (
        "& { param([string]$Name,[string]$Path,[string]$Account) "
        "New-SmbShare -Name $Name -Path $Path -FullAccess $Account -ErrorAction Stop "
        "| Select-Object Name,Path | ConvertTo-Json -Compress }"
    )
    return ["powershell.exe", "-NoProfile", "-Command", script, name, str(path), account]


def remove_smb_share_command(name: str) -> list[str]:
    """Builds the PowerShell command that removes one temporary SMB share."""

    script = "& { param([string]$Name) Remove-SmbShare -Name $Name -Force -ErrorAction SilentlyContinue }"
    return ["powershell.exe", "-NoProfile", "-Command", script, name]


@contextmanager
def create_network_share_fixture(*, share_root: Path, share_name: str, mapped_drive_letter: str):
    """Creates a temporary SMB share plus non-persistent mapped network drive."""

    share_root.mkdir(parents=True, exist_ok=True)
    account = current_windows_account()
    create_result = run_command(create_smb_share_command(share_name, share_root, account))
    if create_result.return_code != 0:
        raise RuntimeError(f"New-SmbShare failed: {create_result.stderr.strip() or create_result.stdout.strip()}")
    unc_root = f"\\\\localhost\\{share_name}"
    mapped_drive_root = Path(f"{mapped_drive_letter}:\\")
    mapped_drive_device = f"{mapped_drive_letter}:"
    map_result = run_command(["net.exe", "use", mapped_drive_device, unc_root, "/persistent:no"])
    if map_result.return_code != 0:
        run_command(remove_smb_share_command(share_name))
        raise RuntimeError(f"net use failed: {map_result.stderr.strip() or map_result.stdout.strip()}")
    try:
        yield NetworkShareFixture(
            share_name=share_name,
            share_root=share_root,
            unc_root=unc_root,
            mapped_drive_root=mapped_drive_root,
            create_share_result=create_result,
            map_drive_result=map_result,
        )
    finally:
        run_command(["net.exe", "use", mapped_drive_device, "/delete", "/y"])
        run_command(remove_smb_share_command(share_name))


def get_drive_type(root: str) -> int | None:
    """Returns the Windows drive type for one root path."""

    if os.name != "nt":
        return None
    return int(ctypes.windll.kernel32.GetDriveTypeW(str(root)))


def get_volume_guid(root: str) -> str | None:
    """Returns a volume GUID path when the root supports local volume identity."""

    if os.name != "nt":
        return None
    text = str(root)
    if not text.endswith("\\"):
        text += "\\"
    buffer = ctypes.create_unicode_buffer(256)
    if ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(text, buffer, len(buffer)):
        return buffer.value
    return None


def classify_path(root: str) -> dict[str, object]:
    """Classifies a shared root as local drive, UNC, or mapped network drive."""

    drive_type = get_drive_type(root)
    return {
        "root": root,
        "is_unc": root.startswith("\\\\"),
        "drive_type": drive_type,
        "is_fixed_drive": drive_type == DRIVE_FIXED,
        "is_remote_drive": drive_type == DRIVE_REMOTE,
        "volume_guid": get_volume_guid(root),
    }


def write_shared_fixture(root: Path) -> dict[str, object]:
    """Writes one deterministic flat shared tree."""

    shared_root = root / "shared"
    for relative_path, payload in FIXTURE_FILES:
        file_path = shared_root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(payload)
    return live_common.summarize_existing_tree(shared_root)


def cache_file_state(path: Path) -> dict[str, object]:
    """Returns a compact state row for a shared startup cache file."""

    return {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "mtime": path.stat().st_mtime if path.is_file() else None,
    }


def get_counter_value(summary: dict[str, object], counter_id: str) -> int | None:
    """Returns the integer value for one summarized startup counter."""

    value = startup_profiles.get_counter_metric(summary, counter_id)
    return int(value) if isinstance(value, (int, float)) else None


def assert_warm_cache_reuse(summary: dict[str, object], expected_files: int, phase: str) -> list[str]:
    """Returns assertion errors for one warmed relaunch."""

    errors: list[str] = []
    directories_from_cache = get_counter_value(summary, "shared.scan.directories_from_cache")
    files_queued = get_counter_value(summary, "shared.scan.files_queued_for_hash")
    shared_files = get_counter_value(summary, "shared.model.hashing_done_shared_files")
    if directories_from_cache is None or directories_from_cache <= 0:
        errors.append(f"{phase}: expected directories_from_cache>0, got {directories_from_cache!r}")
    if files_queued != 0:
        errors.append(f"{phase}: expected files_queued_for_hash=0, got {files_queued!r}")
    if shared_files != expected_files:
        errors.append(f"{phase}: expected hashing_done_shared_files={expected_files}, got {shared_files!r}")
    return errors


def run_cache_probe(
    *,
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    name: str,
    shared_dir_text: str,
    expected_files: int,
) -> dict[str, object]:
    """Runs first launch plus warm relaunch against one shared path spelling."""

    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=scenario_dir,
        shared_dirs=[shared_dir_text],
        scenario_id=name,
    )
    startup_profile_path = Path(str(fixture["startup_profile_path"]))
    shared_cache_path = Path(str(fixture["config_dir"])) / "sharedcache.dat"
    summary: dict[str, object] = {
        "name": name,
        "status": "failed",
        "shared_directory": shared_dir_text,
        "shared_path_classification": classify_path(shared_dir_text),
        "expected_files": expected_files,
        "profile_base": str(fixture["profile_base"]),
        "shared_cache_path": str(shared_cache_path),
    }
    app = None
    try:
        app = live_common.launch_app(app_exe, Path(str(fixture["profile_base"])), minimized_to_tray=True)
        first_summary: dict[str, object] = {"name": name + ".first-launch"}
        startup_profiles.collect_startup_profile_metrics(
            startup_profile_path,
            first_summary,
            require_startup_profile=True,
            wait_for_shared_hashing_done=True,
        )
        summary["shared_cache_ready"] = startup_profiles.wait_for_shared_cache(
            shared_cache_path,
            expected_known_records=expected_files,
        )
        summary["first_launch"] = first_summary
        summary["shared_cache_first_launch"] = cache_file_state(shared_cache_path)
        live_common.close_app_cleanly(app)
        app = None
        startup_profile_path.unlink(missing_ok=True)

        app = live_common.launch_app(app_exe, Path(str(fixture["profile_base"])), minimized_to_tray=True)
        warm_summary: dict[str, object] = {"name": name + ".warm-relaunch"}
        startup_profiles.collect_startup_profile_metrics(
            startup_profile_path,
            warm_summary,
            require_startup_profile=True,
            wait_for_shared_hashing_done=True,
        )
        errors = assert_warm_cache_reuse(warm_summary, expected_files, "warm-relaunch")
        summary["warm_relaunch"] = warm_summary
        summary["shared_cache_warm_relaunch"] = cache_file_state(shared_cache_path)
        summary["assertion_errors"] = errors
        summary["status"] = "passed" if not errors else "failed"
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception as exc:
                summary["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Builds the UNC mapped-drive identity parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=256)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    return parser


def run_unc_mapped_drive_identity(args: argparse.Namespace) -> dict[str, object]:
    """Runs the UNC and mapped-network live suite and publishes JSON evidence."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("unc-mapped-drive-identity requires --admin-volume-fixtures.")
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    config = build_admin_fixture_config(paths, args)
    fixture_cleanup_inputs: dict[str, Path] | None = None
    mapped_drive_root: Path | None = None
    share_name = f"EMULEBB_{os.getpid()}_{int(time.time())}"
    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "failed",
        "suite": SUITE_NAME,
        "configuration": paths.configuration,
        "app_exe": str(paths.app_exe),
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "strict_success_required": True,
    }
    try:
        with create_admin_volume_fixture(config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            fixture_cleanup_inputs = {
                "vhd_path": fixture.vhd_path,
                "drive_root": fixture.drive_root,
                "mount_root": fixture.mount_root,
            }
            topology = build_storage_topology(fixture, SUITE_NAME)
            share_root = topology.vhd_drive_root / "smb-share-root"
            tree_summary = write_shared_fixture(share_root)
            mapped_letter = find_available_drive_letter("Y")
            mapped_drive_root = Path(f"{mapped_letter}:\\")
            with create_network_share_fixture(
                share_root=share_root,
                share_name=share_name,
                mapped_drive_letter=mapped_letter,
            ) as network:
                actual_shared_dir = share_root / "shared"
                unc_shared_dir = network.unc_root + "\\shared\\"
                mapped_shared_dir = str(network.mapped_drive_root / "shared") + "\\"
                classifications = {
                    "actual_vhd_drive": classify_path(str(actual_shared_dir) + "\\"),
                    "unc_share": classify_path(unc_shared_dir),
                    "mapped_network_drive": classify_path(mapped_shared_dir),
                }
                identity_assertions = {
                    "actual_drive_is_fixed": classifications["actual_vhd_drive"]["is_fixed_drive"],
                    "unc_share_is_unc": classifications["unc_share"]["is_unc"],
                    "mapped_drive_is_remote": classifications["mapped_network_drive"]["is_remote_drive"],
                    "mapped_drive_has_no_local_volume_guid": classifications["mapped_network_drive"]["volume_guid"] is None,
                }
                probes = [
                    run_cache_probe(
                        app_exe=paths.app_exe,
                        seed_config_dir=seed_config_dir,
                        scenario_dir=paths.source_artifacts_dir / "actual-vhd-drive",
                        name="actual-vhd-drive",
                        shared_dir_text=live_common.win_path(actual_shared_dir, trailing_slash=True),
                        expected_files=int(tree_summary["file_count"]),
                    ),
                    run_cache_probe(
                        app_exe=paths.app_exe,
                        seed_config_dir=seed_config_dir,
                        scenario_dir=paths.source_artifacts_dir / "direct-unc-share",
                        name="direct-unc-share",
                        shared_dir_text=unc_shared_dir,
                        expected_files=int(tree_summary["file_count"]),
                    ),
                    run_cache_probe(
                        app_exe=paths.app_exe,
                        seed_config_dir=seed_config_dir,
                        scenario_dir=paths.source_artifacts_dir / "mapped-network-drive",
                        name="mapped-network-drive",
                        shared_dir_text=mapped_shared_dir,
                        expected_files=int(tree_summary["file_count"]),
                    ),
                ]
                summary["network_share"] = {
                    "share_name": network.share_name,
                    "share_root": str(network.share_root),
                    "unc_root": network.unc_root,
                    "mapped_drive_root": str(network.mapped_drive_root),
                    "create_share_result": asdict(network.create_share_result),
                    "map_drive_result": asdict(network.map_drive_result),
                }
                summary["tree_summary"] = tree_summary
                summary["volume_identities"] = {
                    "drive_letter": asdict(fixture.drive_identity),
                    "folder_mount": asdict(fixture.mount_identity),
                    "local_control": asdict(fixture.local_control_identity),
                }
                summary["path_classifications"] = classifications
                summary["identity_assertions"] = identity_assertions
                summary["probes"] = probes
                failed_probes = [probe["name"] for probe in probes if probe.get("status") != "passed"]
                failed_assertions = [name for name, passed in identity_assertions.items() if not passed]
                summary["failed_probes"] = failed_probes
                summary["failed_assertions"] = failed_assertions
                summary["status"] = "passed" if not failed_probes and not failed_assertions else "failed"
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if mapped_drive_root is not None:
            summary["mapped_drive_cleanup_exists"] = mapped_drive_root.exists()
        if fixture_cleanup_inputs is not None:
            summary["fixture_cleanup"] = cleanup_audit.audit_fixture_cleanup(
                vhd_path=fixture_cleanup_inputs["vhd_path"],
                drive_root=fixture_cleanup_inputs["drive_root"],
                mount_root=fixture_cleanup_inputs["mount_root"],
                keep_vhd=config.keep,
            )
            if summary["fixture_cleanup"].get("status") != "passed":  # type: ignore[union-attr]
                summary["status"] = "failed"
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "unc-mapped-drive-identity-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """Runs the UNC mapped-drive identity suite."""

    summary = run_unc_mapped_drive_identity(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
