"""Live proof for shared Files startup cache identity across Windows mount forms."""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixture,
    AdminVolumeFixtureConfig,
    VolumeIdentity,
    create_admin_volume_fixture,
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

FIXTURE_FILES = (
    ("alpha.txt", b"alpha\n"),
    ("nested/beta.bin", bytes(range(64))),
    ("nested/deeper/gamma space.txt", b"gamma\n"),
)


def identities_match(left: VolumeIdentity, right: VolumeIdentity) -> bool:
    """Returns true when two mount roots report the same stable volume identity."""

    if left.volume_name and right.volume_name:
        return left.volume_name.lower() == right.volume_name.lower()
    if left.serial_hex and right.serial_hex:
        return left.serial_hex.upper() == right.serial_hex.upper()
    return False


def identities_differ(left: VolumeIdentity, right: VolumeIdentity) -> bool | None:
    """Returns whether identities differ, or None when Windows identity data is unavailable."""

    if left.volume_name and right.volume_name:
        return left.volume_name.lower() != right.volume_name.lower()
    if left.serial_hex and right.serial_hex:
        return left.serial_hex.upper() != right.serial_hex.upper()
    return None


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD-backed fixture configuration for this suite."""

    mount_parent = Path(args.mount_root).resolve() if args.mount_root else paths.source_artifacts_dir / "admin-mounts"
    reject_windows_temp_path(mount_parent, "admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / "shared-cache-volume-identity.vhdx",
        mount_root=mount_parent / "shared-cache-volume-identity",
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


def write_shared_fixture(root: Path) -> dict[str, object]:
    """Writes one deterministic shared tree and returns its static summary."""

    shared_root = root / "shared"
    for relative_path, payload in FIXTURE_FILES:
        file_path = shared_root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(payload)
    return live_common.summarize_existing_tree(shared_root)


def cache_file_state(path: Path) -> dict[str, object]:
    """Returns a compact state row for a startup cache file."""

    return {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "mtime": path.stat().st_mtime if path.is_file() else None,
    }


def run_cache_probe(
    *,
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    name: str,
    shared_root: Path,
    identity: VolumeIdentity,
) -> dict[str, object]:
    """Runs first launch plus warm relaunch against one shared root."""

    shared_dir = shared_root / "shared"
    shared_dirs = [live_common.win_path(shared_dir, trailing_slash=True)]
    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=scenario_dir,
        shared_dirs=shared_dirs,
        scenario_id=name,
    )
    startup_profile_path = Path(str(fixture["startup_profile_path"]))
    shared_cache_path = Path(str(fixture["config_dir"])) / "sharedcache.dat"
    summary: dict[str, object] = {
        "name": name,
        "status": "failed",
        "artifact_dir": str(scenario_dir),
        "shared_root": str(shared_root),
        "shared_directories": shared_dirs,
        "shared_directory_metrics": live_common.summarize_shared_directories(shared_dirs),
        "tree_summary": live_common.summarize_existing_tree(shared_dir),
        "volume_identity": asdict(identity),
        "profile_base": str(fixture["profile_base"]),
        "startup_profile_path": str(startup_profile_path),
        "shared_cache_path": str(shared_cache_path),
        "command_line": subprocess.list2cmdline([str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]),
    }

    app = None
    try:
        app = live_common.launch_app(app_exe, Path(str(fixture["profile_base"])), minimized_to_tray=True)
        first_summary: dict[str, object] = {"name": name + ".first-launch", "tree_summary": summary["tree_summary"]}
        startup_profiles.collect_startup_profile_metrics(
            startup_profile_path,
            first_summary,
            require_startup_profile=True,
            wait_for_shared_hashing_done=True,
        )
        summary["shared_cache_ready"] = startup_profiles.wait_for_shared_cache(
            shared_cache_path,
            expected_known_records=int(summary["tree_summary"].get("file_count", 0) or 0),
        )
        summary["first_launch"] = first_summary
        summary["shared_cache_first_launch"] = cache_file_state(shared_cache_path)
        startup_profile_path.unlink(missing_ok=True)
        live_common.close_app_cleanly(app)
        app = None

        app = live_common.launch_app(app_exe, Path(str(fixture["profile_base"])), minimized_to_tray=True)
        relaunch_summary: dict[str, object] = {"name": name + ".warm-relaunch", "tree_summary": summary["tree_summary"]}
        startup_profiles.collect_startup_profile_metrics(
            startup_profile_path,
            relaunch_summary,
            require_startup_profile=True,
            wait_for_shared_hashing_done=True,
        )
        summary["warm_relaunch"] = relaunch_summary
        summary["shared_cache_warm_relaunch"] = cache_file_state(shared_cache_path)
        summary["status"] = "passed"
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
    """Builds the shared-cache volume-identity proof parser."""

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


def run_shared_cache_volume_identity(args: argparse.Namespace) -> dict[str, object]:
    """Runs the admin storage proof and publishes detailed JSON artifacts."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("shared-cache-volume-identity requires --admin-volume-fixtures.")
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="shared-cache-volume-identity",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    config = build_admin_fixture_config(paths, args)
    probes: list[dict[str, object]] = []
    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "failed",
        "suite": "shared-cache-volume-identity",
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
        "strict_success_required": True,
        "probes": probes,
    }
    try:
        with create_admin_volume_fixture(config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            roots = {
                "local-drive-control": (fixture.local_control_root / "shared-cache-volume-identity", fixture.local_control_identity),
                "vhd-drive-letter": (fixture.drive_root / "shared-cache-volume-identity", fixture.drive_identity),
                "vhd-folder-mount": (fixture.mount_root / "shared-cache-volume-identity", fixture.mount_identity),
            }
            for root, _identity in roots.values():
                write_shared_fixture(root)
            identity_assertions = {
                "drive_mount_same_volume": identities_match(fixture.drive_identity, fixture.mount_identity),
                "drive_mount_lexical_paths_distinct": str(fixture.drive_root).lower() != str(fixture.mount_root).lower(),
                "local_control_distinct_from_vhd": identities_differ(fixture.local_control_identity, fixture.drive_identity),
            }
            summary["volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
                "local_control": asdict(fixture.local_control_identity),
            }
            summary["volume_identity_assertions"] = identity_assertions
            for scenario_name, (root, identity) in roots.items():
                probes.append(
                    run_cache_probe(
                        app_exe=paths.app_exe,
                        seed_config_dir=seed_config_dir,
                        scenario_dir=paths.source_artifacts_dir / scenario_name,
                        name=scenario_name,
                        shared_root=root,
                        identity=identity,
                    )
                )
            local_distinct = identity_assertions["local_control_distinct_from_vhd"]
            summary["status"] = (
                "passed"
                if identity_assertions["drive_mount_same_volume"]
                and identity_assertions["drive_mount_lexical_paths_distinct"]
                and local_distinct is not False
                and all(probe.get("status") == "passed" for probe in probes)
                else "failed"
            )
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "shared-cache-volume-identity-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """Runs the shared-cache volume identity suite."""

    summary = run_shared_cache_volume_identity(build_parser().parse_args())
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
