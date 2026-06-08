"""Live proof that eMule profiles can run fully from VHD-backed roots."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import importlib.util
import json
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
)
from emule_test_harness.paths import path_is_relative_to, reject_windows_temp_path  # noqa: E402


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
startup_diagnostics = load_local_module("startup_diagnostics_scenarios", "startup-diagnostics-scenarios.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit", "admin-volume-cleanup-audit.py")

PROFILE_ROLE_VHD_DRIVE = "vhd-drive-letter"
PROFILE_ROLE_VHD_MOUNT = "vhd-folder-mount"
FIXTURE_FILES = (
    ("shared/alpha.txt", b"alpha\n"),
    ("shared/nested/beta.bin", bytes(range(64))),
)


@dataclass(frozen=True)
class ProfileIsolationCase:
    """One VHD-backed profile-root topology to prove with a real launch."""

    name: str
    profile_role: str


def build_profile_isolation_cases() -> list[ProfileIsolationCase]:
    """Builds the VHD drive-letter and mounted-folder profile matrix."""

    return [
        ProfileIsolationCase(name="profile-on-vhd-drive-letter", profile_role=PROFILE_ROLE_VHD_DRIVE),
        ProfileIsolationCase(name="profile-on-vhd-folder-mount", profile_role=PROFILE_ROLE_VHD_MOUNT),
    ]


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the profile isolation suite."""

    mount_parent = (
        Path(args.mount_root).resolve()
        if args.mount_root
        else paths.source_artifacts_dir.parent / "admin-mounts" / "vhd-profile-isolation"
    )
    reject_windows_temp_path(mount_parent, "admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / "vhd-profile-isolation.vhdx",
        mount_root=mount_parent / "vhd-profile-isolation",
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


def profile_role_root(fixture: AdminVolumeFixture, role: str) -> Path:
    """Returns the suite-scoped VHD root for one profile isolation role."""

    topology = build_storage_topology(fixture, "vhd-profile-isolation")
    roots = {
        PROFILE_ROLE_VHD_DRIVE: topology.vhd_drive_root,
        PROFILE_ROLE_VHD_MOUNT: topology.vhd_mount_root,
    }
    try:
        return roots[role]
    except KeyError as exc:
        raise ValueError(f"Unknown profile isolation role: {role}") from exc


def write_shared_fixture(root: Path) -> dict[str, object]:
    """Writes one deterministic shared tree below the VHD-backed profile root."""

    for relative_path, payload in FIXTURE_FILES:
        file_path = root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(payload)
    return live_common.summarize_existing_tree(root / "shared")


def profile_path_rows(profile: dict[str, object], extra_paths: dict[str, Path]) -> list[dict[str, object]]:
    """Builds normalized path rows for profile isolation assertions."""

    rows: list[dict[str, object]] = []
    for key in ("profile_base", "config_dir", "log_dir", "incoming_dir", "temp_dir", "startup_diagnostics_path"):
        value = profile.get(key)
        if isinstance(value, Path):
            rows.append({"name": key, "path": str(value), "resolved_path": str(value.resolve()), "exists": value.exists()})
    for key, value in extra_paths.items():
        rows.append({"name": key, "path": str(value), "resolved_path": str(value.resolve()), "exists": value.exists()})
    return rows


def assert_profile_paths_isolated(rows: list[dict[str, object]], root: Path) -> list[str]:
    """Returns profile path names that escaped the expected VHD-backed root."""

    escaped: list[str] = []
    for row in rows:
        path = Path(str(row["path"]))
        if not path_is_relative_to(path, root):
            escaped.append(str(row["name"]))
    return escaped


def run_profile_case(
    *,
    case: ProfileIsolationCase,
    fixture: AdminVolumeFixture,
    paths,
    seed_config_dir: Path,
) -> dict[str, object]:
    """Runs one VHD-backed profile launch and returns isolation evidence."""

    profile_root = profile_role_root(fixture, case.profile_role) / case.name
    profile_root.mkdir(parents=True, exist_ok=True)
    tree_summary = write_shared_fixture(profile_root)
    shared_dir = profile_root / "shared"
    profile = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=profile_root,
        shared_dirs=[live_common.win_path(shared_dir, trailing_slash=True)],
        scenario_id=case.name,
    )
    startup_diagnostics_path = Path(str(profile["startup_diagnostics_path"]))
    shared_cache_path = Path(str(profile["config_dir"])) / "sharedcache.dat"
    extra_paths = {
        "preferences_ini": Path(str(profile["config_dir"])) / "preferences.ini",
        "preferences_dat": Path(str(profile["config_dir"])) / "preferences.dat",
        "shareddir_dat": Path(str(profile["config_dir"])) / "shareddir.dat",
        "sharedcache_dat": shared_cache_path,
        "shared_root": shared_dir,
    }
    summary: dict[str, object] = {
        "name": case.name,
        "profile_role": case.profile_role,
        "status": "failed",
        "profile_root": str(profile_root),
        "profile_root_resolved": str(profile_root.resolve()),
        "shared_tree": tree_summary,
        "command_line": subprocess.list2cmdline([str(paths.app_exe), "-ignoreinstances", "-c", str(profile["profile_base"])]),
    }
    app = None
    try:
        app = live_common.launch_app(paths.app_exe, Path(str(profile["profile_base"])), minimized_to_tray=True)
        startup_diagnostics.collect_startup_diagnostics_metrics(
            startup_diagnostics_path,
            summary,
            require_startup_diagnostics=True,
            wait_for_shared_hashing_done=True,
        )
        summary["shared_cache_ready"] = startup_diagnostics.wait_for_shared_cache(
            shared_cache_path,
            expected_known_records=int(tree_summary.get("file_count", 0) or 0),
        )
        live_common.close_app_cleanly(app)
        app = None
        rows = profile_path_rows(profile, extra_paths)
        escaped = assert_profile_paths_isolated(rows, profile_root)
        missing = [str(row["name"]) for row in rows if not bool(row["exists"])]
        summary["profile_paths"] = rows
        summary["escaped_profile_paths"] = escaped
        summary["missing_profile_paths"] = missing
        summary["status"] = "passed" if not escaped and not missing else "failed"
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
    """Builds the VHD profile isolation parser."""

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


def run_vhd_profile_isolation(args: argparse.Namespace) -> dict[str, object]:
    """Runs the profile isolation live suite and publishes JSON evidence."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("vhd-profile-isolation requires --admin-volume-fixtures.")
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="vhd-profile-isolation",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    config = build_admin_fixture_config(paths, args)
    cases: list[dict[str, object]] = []
    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "failed",
        "suite": "vhd-profile-isolation",
        "configuration": paths.configuration,
        "app_exe": str(paths.app_exe),
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
        "cases": cases,
    }
    fixture_cleanup: dict[str, object] | None = None
    try:
        with create_admin_volume_fixture(config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            summary["volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
                "local_control": asdict(fixture.local_control_identity),
            }
            for case in build_profile_isolation_cases():
                cases.append(
                    run_profile_case(
                        case=case,
                        fixture=fixture,
                        paths=paths,
                        seed_config_dir=seed_config_dir,
                    )
                )
            fixture_cleanup = {
                "vhd_path": fixture.vhd_path,
                "drive_root": fixture.drive_root,
                "mount_root": fixture.mount_root,
            }
        if fixture_cleanup is not None:
            summary["fixture_cleanup"] = cleanup_audit.audit_fixture_cleanup(
                vhd_path=Path(str(fixture_cleanup["vhd_path"])),
                drive_root=Path(str(fixture_cleanup["drive_root"])),
                mount_root=Path(str(fixture_cleanup["mount_root"])),
                keep_vhd=args.keep_admin_fixtures,
            )
        failed_cases = [case["name"] for case in cases if case.get("status") != "passed"]
        summary["failed_cases"] = failed_cases
        summary["status"] = (
            "passed"
            if not failed_cases and isinstance(summary.get("fixture_cleanup"), dict) and summary["fixture_cleanup"].get("status") == "passed"
            else "failed"
        )
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "vhd-profile-isolation-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """CLI entrypoint."""

    summary = run_vhd_profile_isolation(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
