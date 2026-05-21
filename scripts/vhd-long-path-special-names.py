"""Live VHD proof for Shared Files long paths and special file names."""

from __future__ import annotations

import argparse
from dataclasses import asdict
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
generated_fixture = load_local_module("create_long_paths_tree", "create-long-paths-tree.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit", "admin-volume-cleanup-audit.py")

SUITE_NAME = "vhd-long-path-special-names"
FIXTURE_DIR_NAME = "generated-long-path-fixture"
SPECIAL_ASCII_CHARS = (" ", "[", "]", ";", ",", "#", "+", "%", "{", "}", "(", ")")


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the long-path special-name suite."""

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


def cache_file_state(path: Path) -> dict[str, object]:
    """Returns a compact state row for the shared startup cache file."""

    return {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "mtime": path.stat().st_mtime if path.is_file() else None,
    }


def win_path_preserving_mount(path: Path, trailing_slash: bool = False) -> str:
    """Formats a Windows path without resolving folder mounts to drive letters."""

    text = str(path if path.is_absolute() else Path.cwd() / path)
    return text + ("\\" if trailing_slash and not text.endswith("\\") else "")


def extended_path_preserving_mount(path: Path) -> str:
    """Returns an extended-length path spelling without resolving mount points."""

    text = str(path if path.is_absolute() else Path.cwd() / path)
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def strip_extended_prefix(path_text: str) -> str:
    """Strips an extended-length prefix while preserving the original path spelling."""

    if path_text.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path_text[8:]
    if path_text.startswith("\\\\?\\"):
        return path_text[4:]
    return path_text


def enumerate_recursive_shared_dirs(root: Path) -> list[str]:
    """Returns recursive shared directories while preserving drive or mount spelling."""

    directories: list[str] = []
    for current_root, dir_names, _file_names in os.walk(extended_path_preserving_mount(root)):
        dir_names.sort(key=str.lower)
        directories.append(strip_extended_prefix(current_root).rstrip("\\") + "\\")
    return directories


def get_counter_value(summary: dict[str, object], counter_id: str) -> int | None:
    """Returns the integer value for one summarized startup counter."""

    value = startup_profiles.get_counter_metric(summary, counter_id)
    return int(value) if isinstance(value, (int, float)) else None


def build_counter_snapshot(summary: dict[str, object]) -> dict[str, object]:
    """Extracts the startup-cache counters that define this suite's assertions."""

    return {
        "directories_from_cache": get_counter_value(summary, "shared.scan.directories_from_cache"),
        "directories_rescanned": get_counter_value(summary, "shared.scan.directories_rescanned"),
        "files_queued_for_hash": get_counter_value(summary, "shared.scan.files_queued_for_hash"),
        "pending_hashes": get_counter_value(summary, "shared.scan.pending_hashes"),
        "shared_files_after_scan": get_counter_value(summary, "shared.scan.shared_files_after_scan"),
        "completed_hashes": get_counter_value(summary, "shared.hash.completed_files"),
        "hash_waiting_queue_depth": get_counter_value(summary, "shared.hash.waiting_queue_depth"),
        "hash_currently_hashing": get_counter_value(summary, "shared.hash.currently_hashing"),
        "hashing_done_shared_files": get_counter_value(summary, "shared.model.hashing_done_shared_files"),
    }


def expected_visible_file_count(manifest: dict[str, object]) -> int:
    """Returns the total visible Shared Files count represented by the fixture manifest."""

    subtrees = manifest.get("subtrees")
    if not isinstance(subtrees, dict):
        raise RuntimeError("Generated fixture manifest is missing subtrees.")
    total = 0
    for subtree in subtrees.values():
        if isinstance(subtree, dict):
            total += int(subtree.get("expected_visible_file_count", 0))
    return total


def collect_fixture_file_names(manifest: dict[str, object]) -> list[str]:
    """Returns all generated fixture file names from the manifest."""

    names: list[str] = []
    subtrees = manifest.get("subtrees")
    if not isinstance(subtrees, dict):
        return names
    for subtree in subtrees.values():
        if not isinstance(subtree, dict):
            continue
        for key in ("all_file_names", "expected_visible_file_names", "expected_excluded_file_names"):
            values = subtree.get(key)
            if isinstance(values, list):
                names.extend(str(value) for value in values)
    return names


def summarize_manifest(manifest: dict[str, object]) -> dict[str, object]:
    """Builds a compact manifest summary and fixture quality assertions."""

    subtrees = manifest.get("subtrees")
    if not isinstance(subtrees, dict):
        raise RuntimeError("Generated fixture manifest is missing subtrees.")
    file_names = collect_fixture_file_names(manifest)
    quality_checks = {
        "has_file_path_over_260_chars": any(
            int(subtree.get("files_over_260_chars", 0)) > 0
            for subtree in subtrees.values()
            if isinstance(subtree, dict)
        ),
        "has_directory_path_over_260_chars": any(
            int(subtree.get("directories_over_260_chars", 0)) > 0
            for subtree in subtrees.values()
            if isinstance(subtree, dict)
        ),
        "has_ascii_special_names": any(any(char in name for char in SPECIAL_ASCII_CHARS) for name in file_names),
        "has_non_ascii_names": any(not name.isascii() for name in file_names),
    }
    failed_quality_checks = [name for name, passed in quality_checks.items() if not passed]
    return {
        "shared_root": manifest.get("shared_root"),
        "manifest_path": manifest.get("manifest_path"),
        "subtree_names": sorted(str(name) for name in subtrees.keys()),
        "expected_visible_file_count": expected_visible_file_count(manifest),
        "max_file_path_length": max(
            (
                int(subtree.get("max_file_path_length", 0))
                for subtree in subtrees.values()
                if isinstance(subtree, dict)
            ),
            default=0,
        ),
        "max_directory_path_length": max(
            (
                int(subtree.get("max_directory_path_length", 0))
                for subtree in subtrees.values()
                if isinstance(subtree, dict)
            ),
            default=0,
        ),
        "quality_checks": quality_checks,
        "failed_quality_checks": failed_quality_checks,
    }


def shared_dirs_for_fixture(fixture_root: Path) -> list[str]:
    """Returns the fixture roots intentionally shared by the live profile."""

    shared_dirs: list[str] = []
    for subtree_name in ("long_path_output", "shared_files_robustness"):
        shared_dirs.extend(enumerate_recursive_shared_dirs(fixture_root / subtree_name))
    return shared_dirs


def assert_counter_state(snapshot: dict[str, object], *, expected_files: int, phase: str, warm: bool) -> list[str]:
    """Returns startup-counter assertion failures for one launch phase."""

    errors: list[str] = []
    files_queued = snapshot.get("files_queued_for_hash")
    hashing_done_shared_files = snapshot.get("hashing_done_shared_files")
    directories_from_cache = snapshot.get("directories_from_cache")
    if hashing_done_shared_files != expected_files:
        errors.append(f"{phase}: expected hashing_done_shared_files={expected_files}, got {hashing_done_shared_files!r}")
    if warm:
        if directories_from_cache is None or directories_from_cache <= 0:
            errors.append(f"{phase}: expected directories_from_cache>0, got {directories_from_cache!r}")
        if files_queued != 0:
            errors.append(f"{phase}: expected files_queued_for_hash=0, got {files_queued!r}")
    elif files_queued is None or files_queued < expected_files:
        errors.append(f"{phase}: expected files_queued_for_hash>={expected_files}, got {files_queued!r}")
    for queue_counter in ("hash_waiting_queue_depth", "hash_currently_hashing"):
        value = snapshot.get(queue_counter)
        if value not in (0, None):
            errors.append(f"{phase}: expected {queue_counter}=0 after hash drain, got {value!r}")
    return errors


def run_launch_phase(
    *,
    app_exe: Path,
    profile_base: Path,
    startup_profile_path: Path,
    shared_cache_path: Path,
    phase: str,
    expected_files: int,
    warm: bool,
) -> dict[str, object]:
    """Runs one eMule launch and validates Shared Files counters."""

    startup_profile_path.unlink(missing_ok=True)
    summary: dict[str, object] = {
        "phase": phase,
        "status": "failed",
        "expected_files": expected_files,
        "warm": warm,
        "shared_cache_before": cache_file_state(shared_cache_path),
        "command_line": subprocess.list2cmdline([str(app_exe), "-ignoreinstances", "-c", str(profile_base)]),
    }
    app = None
    try:
        app = live_common.launch_app(app_exe, profile_base, minimized_to_tray=True)
        startup_profiles.collect_startup_profile_metrics(
            startup_profile_path,
            summary,
            require_startup_profile=True,
            wait_for_shared_hashing_done=True,
        )
        startup_profiles.wait_for_shared_cache(shared_cache_path)
        summary["counter_snapshot"] = build_counter_snapshot(summary)
        summary["shared_cache_after"] = cache_file_state(shared_cache_path)
        errors = assert_counter_state(
            summary["counter_snapshot"],
            expected_files=expected_files,
            phase=phase,
            warm=warm,
        )
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


def run_cache_probe(
    *,
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    name: str,
    shared_dirs: list[str],
    expected_files: int,
) -> dict[str, object]:
    """Runs cold and warm cache launches for one VHD path spelling."""

    profile = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=scenario_dir,
        shared_dirs=shared_dirs,
        scenario_id=name,
    )
    profile_base = Path(str(profile["profile_base"]))
    startup_profile_path = Path(str(profile["startup_profile_path"]))
    shared_cache_path = Path(str(profile["config_dir"])) / "sharedcache.dat"
    phases = [
        run_launch_phase(
            app_exe=app_exe,
            profile_base=profile_base,
            startup_profile_path=startup_profile_path,
            shared_cache_path=shared_cache_path,
            phase="cold-cache-create",
            expected_files=expected_files,
            warm=False,
        ),
        run_launch_phase(
            app_exe=app_exe,
            profile_base=profile_base,
            startup_profile_path=startup_profile_path,
            shared_cache_path=shared_cache_path,
            phase="warm-cache-reuse",
            expected_files=expected_files,
            warm=True,
        ),
    ]
    failed = [phase for phase in phases if phase.get("status") != "passed"]
    return {
        "name": name,
        "status": "passed" if not failed else "failed",
        "shared_dirs": shared_dirs,
        "shared_directory_metrics": live_common.summarize_shared_directories(shared_dirs),
        "profile_base": str(profile_base),
        "shared_cache_path": str(shared_cache_path),
        "expected_files": expected_files,
        "phases": phases,
        "failed_phases": [str(phase.get("phase")) for phase in failed],
    }


def run_vhd_long_path_probe(*, fixture: AdminVolumeFixture, paths, seed_config_dir: Path) -> dict[str, object]:
    """Materializes the fixture once and probes drive-letter plus folder-mount spellings."""

    topology = build_storage_topology(fixture, SUITE_NAME)
    drive_fixture_root = topology.vhd_drive_root / FIXTURE_DIR_NAME
    mount_fixture_root = topology.vhd_mount_root / FIXTURE_DIR_NAME
    manifest = generated_fixture.ensure_fixture(drive_fixture_root)
    manifest_summary = summarize_manifest(manifest)
    expected_files = int(manifest_summary["expected_visible_file_count"])
    probes = [
        run_cache_probe(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            scenario_dir=paths.source_artifacts_dir / "vhd-drive-letter",
            name="vhd-drive-letter",
            shared_dirs=shared_dirs_for_fixture(drive_fixture_root),
            expected_files=expected_files,
        ),
        run_cache_probe(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            scenario_dir=paths.source_artifacts_dir / "vhd-folder-mount",
            name="vhd-folder-mount",
            shared_dirs=shared_dirs_for_fixture(mount_fixture_root),
            expected_files=expected_files,
        ),
    ]
    failed_probes = [probe["name"] for probe in probes if probe.get("status") != "passed"]
    failed_quality_checks = manifest_summary["failed_quality_checks"]
    return {
        "status": "passed" if not failed_probes and not failed_quality_checks else "failed",
        "drive_fixture_root": str(drive_fixture_root),
        "mount_fixture_root": str(mount_fixture_root),
        "manifest_summary": manifest_summary,
        "probes": probes,
        "failed_probes": failed_probes,
        "failed_quality_checks": failed_quality_checks,
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds the VHD long-path special-name parser."""

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


def run_vhd_long_path_special_names(args: argparse.Namespace) -> dict[str, object]:
    """Runs the VHD long-path special-name suite and publishes JSON evidence."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("vhd-long-path-special-names requires --admin-volume-fixtures.")
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
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    config = build_admin_fixture_config(paths, args)
    fixture_cleanup_inputs: dict[str, Path] | None = None
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
        "admin_volume_fixture": {
            "enabled": True,
            "vhd_path": str(config.vhd_path),
            "mount_root": str(config.mount_root),
            "local_control_root": str(config.local_control_root),
            "size_mb": config.size_mb,
            "keep": config.keep,
        },
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
            summary["volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
                "local_control": asdict(fixture.local_control_identity),
            }
            summary["probe"] = run_vhd_long_path_probe(fixture=fixture, paths=paths, seed_config_dir=seed_config_dir)
            summary["status"] = "passed" if summary["probe"].get("status") == "passed" else "failed"  # type: ignore[union-attr]
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
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
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """Runs the VHD long-path special-name suite."""

    summary = run_vhd_long_path_special_names(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
