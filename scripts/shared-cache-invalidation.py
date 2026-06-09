"""Live proof for shared Files startup cache invalidation on VHD mounts."""

from __future__ import annotations

import argparse
from dataclasses import asdict
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
startup_diagnostics = load_local_module("startup_diagnostics_scenarios", "startup-diagnostics-scenarios.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit", "admin-volume-cleanup-audit.py")

SUITE_NAME = "shared-cache-invalidation"
BASE_FIXTURE_FILES = (
    ("alpha.txt", b"alpha\n"),
    ("beta.txt", b"beta\n"),
    ("gamma space.txt", b"gamma\n"),
)
MUTATED_ALPHA_PAYLOAD = b"alpha changed for cache invalidation\n"
ADDED_DELTA_PAYLOAD = b"new file that must be discovered after the cache is warm\n"


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the shared-cache invalidation suite."""

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


def write_base_shared_fixture(root: Path) -> dict[str, object]:
    """Writes the baseline shared tree used for cold and warm cache probes."""

    shared_root = root / "shared"
    for relative_path, payload in BASE_FIXTURE_FILES:
        file_path = shared_root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(payload)
    return live_common.summarize_existing_tree(shared_root)


def mutate_shared_fixture(root: Path) -> dict[str, object]:
    """Mutates the warmed shared tree so the next launch must invalidate cache entries."""

    shared_root = root / "shared"
    alpha_path = shared_root / "alpha.txt"
    if not alpha_path.is_file():
        raise FileNotFoundError(alpha_path)
    time.sleep(1.1)
    alpha_path.write_bytes(MUTATED_ALPHA_PAYLOAD)
    delta_path = shared_root / "delta-new.txt"
    delta_path.write_bytes(ADDED_DELTA_PAYLOAD)
    return live_common.summarize_existing_tree(shared_root)


def get_counter_value(summary: dict[str, object], counter_id: str) -> int | None:
    """Returns the integer value for one summarized startup counter."""

    value = startup_diagnostics.get_counter_metric(summary, counter_id)
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


def assert_counter_state(
    snapshot: dict[str, object],
    *,
    expected_shared_files: int,
    expect_cache_reuse: bool,
    expected_min_queued: int,
    phase: str,
) -> list[str]:
    """Returns counter assertion failures for one launch phase."""

    errors: list[str] = []
    directories_from_cache = snapshot.get("directories_from_cache")
    files_queued_for_hash = snapshot.get("files_queued_for_hash")
    hashing_done_shared_files = snapshot.get("hashing_done_shared_files")
    if hashing_done_shared_files != expected_shared_files:
        errors.append(f"{phase}: expected hashing_done_shared_files={expected_shared_files}, got {hashing_done_shared_files!r}")
    if expected_min_queued == 0:
        if files_queued_for_hash != 0:
            errors.append(f"{phase}: expected files_queued_for_hash=0, got {files_queued_for_hash!r}")
    elif files_queued_for_hash is None or files_queued_for_hash < expected_min_queued:
        errors.append(f"{phase}: expected files_queued_for_hash>={expected_min_queued}, got {files_queued_for_hash!r}")
    for queue_counter in ("hash_waiting_queue_depth", "hash_currently_hashing"):
        value = snapshot.get(queue_counter)
        if value not in (0, None):
            errors.append(f"{phase}: expected {queue_counter}=0 after hash drain, got {value!r}")
    if expect_cache_reuse and (directories_from_cache is None or directories_from_cache <= 0):
        errors.append(f"{phase}: expected directories_from_cache>0, got {directories_from_cache!r}")
    return errors


def run_launch_phase(
    *,
    app_exe: Path,
    profile_base: Path,
    startup_diagnostics_path: Path,
    shared_cache_path: Path,
    phase: str,
    expected_shared_files: int,
    expect_cache_reuse: bool,
    expected_min_queued: int,
    tree_summary: dict[str, object],
    wait_for_cache_refresh: bool = False,
) -> dict[str, object]:
    """Runs one eMule launch, captures startup counters, and validates cache behavior."""

    startup_diagnostics_path.unlink(missing_ok=True)
    summary: dict[str, object] = {
        "phase": phase,
        "status": "failed",
        "tree_summary": tree_summary,
        "expected_shared_files": expected_shared_files,
        "expected_min_queued": expected_min_queued,
        "expect_cache_reuse": expect_cache_reuse,
        "wait_for_cache_refresh": wait_for_cache_refresh,
        "shared_cache_before": cache_file_state(shared_cache_path),
        "command_line": subprocess.list2cmdline([str(app_exe), "-ignoreinstances", "-c", str(profile_base)]),
    }
    app = None
    try:
        app = live_common.launch_app(app_exe, profile_base, minimized_to_tray=True)
        startup_diagnostics.collect_startup_diagnostics_metrics(
            startup_diagnostics_path,
            summary,
            require_startup_diagnostics=True,
            wait_for_shared_hashing_done=True,
        )
        summary["shared_cache_ready"] = startup_diagnostics.wait_for_shared_cache(
            shared_cache_path,
            expected_known_records=expected_shared_files,
        )
        cache_before = summary["shared_cache_before"]
        if wait_for_cache_refresh and isinstance(cache_before, dict) and cache_before.get("mtime") is not None:
            before_mtime = float(cache_before["mtime"])
            live_common.wait_for(
                lambda: shared_cache_path.is_file() and shared_cache_path.stat().st_mtime > before_mtime,
                timeout=30.0,
                interval=0.5,
                description=f"{phase} startup cache refresh",
            )
        summary["counter_snapshot"] = build_counter_snapshot(summary)
        summary["shared_cache_after"] = cache_file_state(shared_cache_path)
        errors = assert_counter_state(
            summary["counter_snapshot"],
            expected_shared_files=expected_shared_files,
            expect_cache_reuse=expect_cache_reuse,
            expected_min_queued=expected_min_queued,
            phase=phase,
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


def run_invalidation_probe(*, fixture: AdminVolumeFixture, paths, seed_config_dir: Path) -> dict[str, object]:
    """Runs the cold, warm, and mutated cache proof on a VHD mount."""

    topology = build_storage_topology(fixture, SUITE_NAME)
    shared_root = topology.vhd_mount_root
    shared_root.mkdir(parents=True, exist_ok=True)
    base_tree = write_base_shared_fixture(shared_root)
    shared_dir = shared_root / "shared"
    profile = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=paths.source_artifacts_dir / "profile-on-vhd-folder-mount",
        shared_dirs=[live_common.win_path(shared_dir, trailing_slash=True)],
        scenario_id=SUITE_NAME,
    )
    profile_base = Path(str(profile["profile_base"]))
    startup_diagnostics_path = Path(str(profile["startup_diagnostics_path"]))
    shared_cache_path = Path(str(profile["config_dir"])) / "sharedcache.dat"
    phases: list[dict[str, object]] = []
    summary: dict[str, object] = {
        "status": "failed",
        "shared_root": str(shared_root),
        "shared_dir": str(shared_dir),
        "profile_base": str(profile_base),
        "startup_diagnostics_path": str(startup_diagnostics_path),
        "shared_cache_path": str(shared_cache_path),
        "volume_identity": asdict(fixture.mount_identity),
        "shared_directories": [live_common.win_path(shared_dir, trailing_slash=True)],
        "shared_directory_metrics": live_common.summarize_shared_directories(
            [live_common.win_path(shared_dir, trailing_slash=True)]
        ),
        "phases": phases,
    }
    phases.append(
        run_launch_phase(
            app_exe=paths.app_exe,
            profile_base=profile_base,
            startup_diagnostics_path=startup_diagnostics_path,
            shared_cache_path=shared_cache_path,
            phase="cold-cache-create",
            expected_shared_files=int(base_tree["file_count"]),
            expect_cache_reuse=False,
            expected_min_queued=int(base_tree["file_count"]),
            tree_summary=base_tree,
        )
    )
    phases.append(
        run_launch_phase(
            app_exe=paths.app_exe,
            profile_base=profile_base,
            startup_diagnostics_path=startup_diagnostics_path,
            shared_cache_path=shared_cache_path,
            phase="unchanged-warm-cache-reuse",
            expected_shared_files=int(base_tree["file_count"]),
            expect_cache_reuse=True,
            expected_min_queued=0,
            tree_summary=base_tree,
        )
    )
    mutated_tree = mutate_shared_fixture(shared_root)
    summary["mutated_tree_summary"] = mutated_tree
    phases.append(
        run_launch_phase(
            app_exe=paths.app_exe,
            profile_base=profile_base,
            startup_diagnostics_path=startup_diagnostics_path,
            shared_cache_path=shared_cache_path,
            phase="mutated-cache-invalidation",
            expected_shared_files=int(mutated_tree["file_count"]),
            expect_cache_reuse=True,
            expected_min_queued=2,
            tree_summary=mutated_tree,
            wait_for_cache_refresh=True,
        )
    )
    failed = [phase for phase in phases if phase.get("status") != "passed"]
    summary["failed_phases"] = [str(phase.get("phase")) for phase in failed]
    summary["status"] = "passed" if not failed else "failed"
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Builds the shared-cache invalidation parser."""

    parser = argparse.ArgumentParser()
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


def run_shared_cache_invalidation(args: argparse.Namespace) -> dict[str, object]:
    """Runs the VHD shared-cache invalidation suite and publishes JSON evidence."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("shared-cache-invalidation requires --admin-volume-fixtures.")
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
            summary["probe"] = run_invalidation_probe(fixture=fixture, paths=paths, seed_config_dir=seed_config_dir)
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
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "shared-cache-invalidation-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """Runs the shared-cache invalidation suite."""

    summary = run_shared_cache_invalidation(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
