"""Live proof that a VHD-backed eMule profile survives crash, detach, and remount."""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixture,
    AdminVolumeFixtureConfig,
    attach_admin_volume_fixture,
    build_storage_topology,
    create_admin_volume_fixture,
)
from emule_test_harness.ini import read_ini_text  # noqa: E402
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
rest_smoke = load_local_module("rest_api_smoke_for_vhd_profile_durability", "rest-api-smoke.py")
startup_diagnostics = load_local_module("startup_diagnostics_scenarios", "startup-diagnostics-scenarios.py")
crash_smoke = load_local_module("local_dumps_crash_smoke_for_vhd_profile_durability", "local-dumps-crash-smoke.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit_for_vhd_profile_durability", "admin-volume-cleanup-audit.py")

SUITE_NAME = "vhd-profile-durability"
API_KEY = "vhd-profile-durability-key"
FIXTURE_FILES = (
    ("shared/alpha.txt", b"alpha\n"),
    ("shared/nested/beta.bin", bytes(range(64))),
)


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the durability suite."""

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


def write_shared_fixture(root: Path) -> dict[str, object]:
    """Writes one deterministic shared tree under the VHD-backed profile root."""

    for relative_path, payload in FIXTURE_FILES:
        file_path = root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(payload)
    return live_common.summarize_existing_tree(root / "shared")


def file_state(path: Path) -> dict[str, object]:
    """Returns existence, size, and timestamp state for one durability file."""

    return {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "mtime": path.stat().st_mtime if path.is_file() else None,
    }


def collect_durability_file_states(profile: dict[str, object]) -> dict[str, dict[str, object]]:
    """Collects the critical config/cache files that must survive remount."""

    config_dir = Path(str(profile["config_dir"]))
    startup_diagnostics_path = Path(str(profile["startup_diagnostics_path"]))
    paths = {
        "preferences_ini": config_dir / "preferences.ini",
        "preferences_dat": config_dir / "preferences.dat",
        "shareddir_dat": config_dir / "shareddir.dat",
        "sharedcache_dat": config_dir / "sharedcache.dat",
        "startup_diagnostics": startup_diagnostics_path,
    }
    return {name: file_state(path) for name, path in paths.items()}


def missing_required_files(states: dict[str, dict[str, object]]) -> list[str]:
    """Returns required durability file names that are absent or empty."""

    return [
        name
        for name, state in states.items()
        if not bool(state.get("exists")) or int(state.get("size_bytes") or 0) <= 0
    ]


def assert_preferences_still_point_at_profile(profile: dict[str, object]) -> list[str]:
    """Returns preference fields that no longer point at the VHD-backed profile roots."""

    config_dir = Path(str(profile["config_dir"]))
    text = read_ini_text(config_dir / "preferences.ini")
    expected = {
        "IncomingDir": live_common.win_path(Path(str(profile["incoming_dir"])), trailing_slash=True),
        "TempDir": live_common.win_path(Path(str(profile["temp_dir"])), trailing_slash=True),
    }
    missing: list[str] = []
    for key, value in expected.items():
        if value not in text:
            missing.append(key)
    if API_KEY not in text:
        missing.append("WebServer.ApiKey")
    return missing


def run_first_launch_and_crash(
    *,
    fixture: AdminVolumeFixture,
    paths,
    seed_config_dir: Path,
    port: int,
    args: argparse.Namespace,
) -> tuple[dict[str, object], dict[str, object]]:
    """Creates a mounted VHD profile, launches it, crashes it, and returns the profile."""

    profile_root = build_storage_topology(fixture, SUITE_NAME).vhd_mount_root / "mounted-profile"
    profile_root.mkdir(parents=True, exist_ok=True)
    shared_tree = write_shared_fixture(profile_root)
    shared_dir = profile_root / "shared"
    profile = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=profile_root,
        shared_dirs=[live_common.win_path(shared_dir, trailing_slash=True)],
        scenario_id="mounted-profile",
    )
    profile["expected_shared_files"] = int(shared_tree.get("file_count", 0) or 0)
    lan_bind_addr = rest_smoke.require_lan_bind_addr(args.lan_bind_addr)
    rest_smoke.configure_webserver_profile(
        Path(str(profile["config_dir"])),
        paths.app_exe,
        API_KEY,
        port,
        lan_bind_addr,
        enable_crash_test_endpoint=True,
    )
    if args.p2p_bind_interface_name:
        rest_smoke.apply_p2p_bind_interface_override(
            Path(str(profile["config_dir"])),
            args.p2p_bind_interface_name,
            vpn_guard_enabled=args.vpn_guard_enabled,
            vpn_guard_allowed_public_ip_cidrs=args.vpn_guard_allowed_public_ip_cidrs,
        )

    base_url = f"http://{lan_bind_addr}:{port}"
    startup_diagnostics_path = Path(str(profile["startup_diagnostics_path"]))
    shared_cache_path = Path(str(profile["config_dir"])) / "sharedcache.dat"
    summary: dict[str, object] = {
        "phase": "first_launch_crash",
        "status": "failed",
        "base_url": base_url,
        "profile_base": str(profile["profile_base"]),
        "profile_root": str(profile_root),
        "profile_root_resolved": str(profile_root.resolve()),
        "shared_tree": shared_tree,
    }
    app = None
    process_id: int | None = None
    try:
        app = rest_smoke.launch_app(paths.app_exe, Path(str(profile["profile_base"])))
        process_id = rest_smoke.get_app_process_id(app)
        summary["process_id"] = process_id
        summary["ready"] = rest_smoke.compact_http_result(rest_smoke.wait_for_rest_ready(base_url, API_KEY, args.rest_ready_timeout_seconds))
        startup_diagnostics.collect_startup_diagnostics_metrics(
            startup_diagnostics_path,
            summary,
            require_startup_diagnostics=True,
            wait_for_shared_hashing_done=True,
        )
        summary["shared_cache_ready"] = startup_diagnostics.wait_for_shared_cache(
            shared_cache_path,
            expected_known_records=int(shared_tree.get("file_count", 0) or 0),
            base_url=base_url,
            api_key=API_KEY,
            require_rest_status=True,
        )
        summary["pre_crash_files"] = collect_durability_file_states(profile)
        summary["trigger_crash"] = crash_smoke.trigger_crash(base_url, API_KEY, args.request_timeout_seconds)
        summary["process_exit"] = crash_smoke.wait_for_process_access_violation(process_id, args.crash_timeout_seconds)
        summary["process_stopped"] = crash_smoke.wait_for_process_exit(process_id, args.crash_timeout_seconds)
        summary["post_crash_files"] = collect_durability_file_states(profile)
        missing = missing_required_files(summary["post_crash_files"])
        preference_mismatches = assert_preferences_still_point_at_profile(profile)
        summary["missing_post_crash_files"] = missing
        summary["preference_mismatches"] = preference_mismatches
        summary["status"] = "passed" if not missing and not preference_mismatches else "failed"
        app = None
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
        if process_id is not None:
            summary["process_state"] = rest_smoke.get_process_exit_state(process_id)
    finally:
        if app is not None:
            try:
                rest_smoke.close_app_cleanly(app)
            except Exception as exc:
                summary["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
    return profile, summary


def run_remounted_relaunch(
    *,
    profile: dict[str, object],
    paths,
) -> dict[str, object]:
    """Relaunches the same profile after VHD reattach and verifies persisted files."""

    startup_diagnostics_path = Path(str(profile["startup_diagnostics_path"]))
    shared_cache_path = Path(str(profile["config_dir"])) / "sharedcache.dat"
    summary: dict[str, object] = {
        "phase": "remounted_relaunch",
        "status": "failed",
        "profile_base": str(profile["profile_base"]),
        "pre_relaunch_files": collect_durability_file_states(profile),
    }
    app = None
    try:
        missing_before = missing_required_files(summary["pre_relaunch_files"])
        preference_mismatches = assert_preferences_still_point_at_profile(profile)
        if missing_before or preference_mismatches:
            summary["missing_before_relaunch"] = missing_before
            summary["preference_mismatches"] = preference_mismatches
            return summary
        startup_diagnostics_path.unlink(missing_ok=True)
        app = rest_smoke.launch_app(paths.app_exe, Path(str(profile["profile_base"])))
        startup_diagnostics.collect_startup_diagnostics_metrics(
            startup_diagnostics_path,
            summary,
            require_startup_diagnostics=True,
            wait_for_shared_hashing_done=True,
        )
        summary["shared_cache_ready"] = startup_diagnostics.wait_for_shared_cache(
            shared_cache_path,
            expected_known_records=int(profile.get("expected_shared_files", 0) or 0),
        )
        rest_smoke.close_app_cleanly(app)
        app = None
        summary["post_relaunch_files"] = collect_durability_file_states(profile)
        missing_after = missing_required_files(summary["post_relaunch_files"])
        summary["missing_after_relaunch"] = missing_after
        summary["status"] = "passed" if not missing_after else "failed"
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if app is not None:
            try:
                rest_smoke.close_app_cleanly(app)
            except Exception as exc:
                summary["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Builds the VHD profile durability parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=384)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--request-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--crash-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--vpn-guard-enabled", action="store_true")
    parser.add_argument("--vpn-guard-allowed-public-ip-cidrs", default="")
    return parser


def run_vhd_profile_durability(args: argparse.Namespace) -> dict[str, object]:
    """Runs the crash/detach/remount durability proof."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("vhd-profile-durability requires --admin-volume-fixtures.")
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=None,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    config = build_admin_fixture_config(paths, args)
    lan_bind_addr = rest_smoke.require_lan_bind_addr(args.lan_bind_addr)
    port = rest_smoke.choose_listen_port(lan_bind_addr)
    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "failed",
        "suite": SUITE_NAME,
        "configuration": paths.configuration,
        "app_exe": str(paths.app_exe),
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "local_dumps": paths.local_dumps,
        "settings": {
            "rest_ready_timeout_seconds": args.rest_ready_timeout_seconds,
            "request_timeout_seconds": args.request_timeout_seconds,
            "crash_timeout_seconds": args.crash_timeout_seconds,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "lan_bind_addr": lan_bind_addr,
        },
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
    fixture_cleanup: dict[str, object] | None = None
    try:
        create_config = replace(config, keep=True)
        with create_admin_volume_fixture(create_config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            summary["initial_volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
            }
            profile, summary["checks"]["first_launch_crash"] = run_first_launch_and_crash(
                fixture=fixture,
                paths=paths,
                seed_config_dir=seed_config_dir,
                port=port,
                args=args,
            )
            fixture_cleanup = {
                "vhd_path": fixture.vhd_path,
                "drive_root": fixture.drive_root,
                "mount_root": fixture.mount_root,
            }
        summary["checks"]["after_first_detach"] = cleanup_audit.audit_fixture_cleanup(
            vhd_path=Path(str(fixture_cleanup["vhd_path"])),
            drive_root=Path(str(fixture_cleanup["drive_root"])),
            mount_root=Path(str(fixture_cleanup["mount_root"])),
            keep_vhd=True,
        )
        attach_config = replace(config, keep=args.keep_admin_fixtures)
        with attach_admin_volume_fixture(attach_config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            summary["reattached_volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
            }
            summary["checks"]["remounted_relaunch"] = run_remounted_relaunch(profile=profile, paths=paths)
            fixture_cleanup = {
                "vhd_path": fixture.vhd_path,
                "drive_root": fixture.drive_root,
                "mount_root": fixture.mount_root,
            }
        summary["checks"]["final_fixture_cleanup"] = cleanup_audit.audit_fixture_cleanup(
            vhd_path=Path(str(fixture_cleanup["vhd_path"])),
            drive_root=Path(str(fixture_cleanup["drive_root"])),
            mount_root=Path(str(fixture_cleanup["mount_root"])),
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
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "vhd-profile-durability-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """CLI entrypoint."""

    summary = run_vhd_profile_durability(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
