"""Live proof for VHD-backed part-file recovery and non-blocking missing temp-volume startup."""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import sys
import time
from typing import Any

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
rest_smoke = load_local_module("rest_api_smoke", "rest-api-smoke.py")
disk_guard = load_local_module("disk_space_guard_live", "disk-space-guard-live.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit", "admin-volume-cleanup-audit.py")

SUITE_NAME = "vhd-partfile-recovery"
API_KEY = "vhd-partfile-recovery-key"
DEFAULT_TRANSFER_HASH = "ABCDEF1234567890ABCDEF1234567890"
MIN_VHD_SIZE_MB = 6144


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the part-file recovery suite."""

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
        size_mb=max(args.vhd_size_mb, MIN_VHD_SIZE_MB),
        keep=args.keep_admin_fixtures,
    )


def build_recovery_transfer_link(size_bytes: int, file_hash: str = DEFAULT_TRANSFER_HASH) -> str:
    """Builds the synthetic eD2K link used for part-file recovery."""

    if size_bytes <= 0:
        raise ValueError("Transfer size must be greater than zero.")
    cleaned_hash = file_hash.strip().upper()
    if len(cleaned_hash) != 32 or any(char not in "0123456789ABCDEF" for char in cleaned_hash):
        raise ValueError("Transfer hash must be 32 hexadecimal characters.")
    return f"ed2k://|file|vhd-partfile-recovery.bin|{size_bytes}|{cleaned_hash}|/"


def compact_result(result: dict[str, object] | None) -> dict[str, object] | None:
    """Returns bounded HTTP result diagnostics for JSON reports."""

    if result is None:
        return None
    return {
        "status": result.get("status"),
        "content_type": result.get("content_type"),
        "json": result.get("json"),
        "body_text": str(result.get("body_text", ""))[:4000],
    }


def part_metadata_paths(root: Path) -> list[str]:
    """Returns `.part.met` paths under one temp root."""

    if not root.exists():
        return []
    return sorted(str(path) for path in root.rglob("*.part.met"))


def wait_for_part_metadata(root: Path, timeout_seconds: float = 15.0) -> list[str]:
    """Waits until a transfer has materialized part metadata under the VHD temp root."""

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        matches = part_metadata_paths(root)
        if matches:
            return matches
        time.sleep(0.25)
    return part_metadata_paths(root)


def fetch_transfer(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Fetches one transfer by lowercase hash through REST."""

    return rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash.lower()}",
        api_key=api_key,
        request_timeout_seconds=5.0,
    )


def launch_profile_and_wait(paths, profile_base: Path, base_url: str, api_key: str, timeout_seconds: float) -> tuple[Any, dict[str, object]]:
    """Launches eMule and waits for REST readiness."""

    app = live_common.launch_app(paths.app_exe, profile_base, minimized_to_tray=True)
    ready = rest_smoke.wait_for_rest_ready(base_url, api_key, timeout_seconds)
    return app, ready


def is_missing_temp_directory_dialog(title: str, body: str) -> bool:
    """Returns whether one startup dialog reports the expected missing temp path."""

    text = f"{title}\n{body}".lower()
    return "failed to create temporary files directory" in text and "system cannot find the path specified" in text


def startup_error_log_path(profile_base: Path) -> Path:
    """Returns the durable startup error log path for one isolated profile."""

    return profile_base / "logs" / "emulebb-startup-errors.log"


def read_startup_error_log(profile_base: Path) -> str:
    """Reads the durable startup error log when it exists."""

    path = startup_error_log_path(profile_base)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def wait_for_missing_temp_directory_startup_log(profile_base: Path, timeout_seconds: float = 20.0) -> dict[str, object]:
    """Waits until non-modal startup recovery records the missing temp directory."""

    def resolve() -> dict[str, object] | None:
        text = read_startup_error_log(profile_base)
        if not is_missing_temp_directory_dialog("eMule", text):
            return None
        return {
            "path": str(startup_error_log_path(profile_base)),
            "text": text[-4000:],
        }

    return live_common.wait_for(
        resolve,
        timeout=timeout_seconds,
        interval=0.25,
        description="missing temp directory startup log",
    )


def wait_for_missing_temp_directory_dialog(app: Any, timeout_seconds: float = 20.0) -> dict[str, object]:
    """Waits for eMule's missing temp-volume startup dialog and captures it."""

    def resolve() -> dict[str, object] | None:
        try:
            window = app.top_window()
        except Exception:
            return None
        if not getattr(window, "handle", None):
            return None
        title = live_common.win32gui.GetWindowText(window.handle)
        body = live_common.describe_startup_dialog(window.handle)
        if live_common.win32gui.GetClassName(window.handle) == "#32770" and is_missing_temp_directory_dialog(title, body):
            return {"title": title, "body": body, "handle": int(window.handle)}
        return None

    return live_common.wait_for(
        resolve,
        timeout=timeout_seconds,
        interval=0.25,
        description="missing temp directory startup dialog",
    )


def kill_intermediate_recovery_app(app: Any) -> dict[str, object]:
    """Force-stops the missing-volume relaunch before it can persist fallback paths."""

    process_id = rest_smoke.get_app_process_id(app)
    app.kill(soft=False)
    return {"killed": True, "process_id": process_id}


def run_vhd_partfile_recovery(args: argparse.Namespace) -> dict[str, object]:
    """Runs the VHD part-file recovery live proof and publishes JSON artifacts."""

    if not args.admin_volume_fixtures:
        raise RuntimeError(f"{SUITE_NAME} requires --admin-volume-fixtures.")
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
    port = rest_smoke.choose_listen_port()
    base_url = f"http://{args.lan_bind_addr}:{port}"
    transfer_size_bytes = args.transfer_size_mb * 1024 * 1024
    transfer_link = build_recovery_transfer_link(transfer_size_bytes)
    transfer_hash = DEFAULT_TRANSFER_HASH.lower()
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
        "rest": {"base_url": base_url, "port": port, "ready_timeout_seconds": args.rest_ready_timeout_seconds},
        "transfer": {"hash": transfer_hash, "size_bytes": transfer_size_bytes, "link": transfer_link},
        "checks": {},
    }
    app = None
    first_fixture_cleanup: dict[str, object] | None = None
    final_fixture_cleanup: dict[str, object] | None = None
    try:
        with create_admin_volume_fixture(replace(config, keep=True)) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            topology = build_storage_topology(fixture, SUITE_NAME)
            temp_dir = topology.vhd_drive_root / "temp"
            incoming_dir = topology.local_control_root / "incoming"
            temp_dir.mkdir(parents=True, exist_ok=True)
            incoming_dir.mkdir(parents=True, exist_ok=True)
            profile = live_common.prepare_profile_base(
                seed_config_dir=seed_config_dir,
                artifacts_dir=paths.source_artifacts_dir / "profile",
                shared_dirs=[],
                incoming_dir=incoming_dir,
                temp_dir=temp_dir,
                scenario_id=SUITE_NAME,
            )
            rest_smoke.configure_webserver_profile(
                Path(str(profile["config_dir"])),
                paths.app_exe,
                args.api_key,
                port,
                args.lan_bind_addr,
            )
            profile_base = Path(str(profile["profile_base"]))
            summary["profile"] = {
                "profile_base": str(profile_base),
                "config_dir": str(profile["config_dir"]),
                "temp_dir": str(temp_dir),
                "incoming_dir": str(incoming_dir),
            }
            summary["initial_volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
                "local_control": asdict(fixture.local_control_identity),
            }

            app, ready = launch_profile_and_wait(paths, profile_base, base_url, args.api_key, args.rest_ready_timeout_seconds)
            add_result = rest_smoke.http_request(
                base_url,
                "/api/v1/transfers",
                method="POST",
                api_key=args.api_key,
                json_body={"link": transfer_link, "paused": True, "categoryId": 0},
                request_timeout_seconds=10.0,
            )
            first_lookup = fetch_transfer(base_url, args.api_key, transfer_hash)
            first_metadata = wait_for_part_metadata(temp_dir)
            first_ok = int(add_result.get("status", 0) or 0) in {200, 201, 202} and int(first_lookup.get("status", 0) or 0) == 200 and bool(first_metadata)
            summary["checks"]["initial_add"] = {
                "status": "passed" if first_ok else "failed",
                "rest_ready": compact_result(ready),
                "add_transfer": compact_result(add_result),
                "transfer_lookup": compact_result(first_lookup),
                "part_metadata": first_metadata,
            }
            if not first_ok:
                raise RuntimeError("initial VHD temp transfer did not materialize part metadata")
            summary["checks"]["initial_shutdown"] = rest_smoke.close_app_cleanly_with_timing(app)
            app = None
            first_fixture_cleanup = {"vhd_path": fixture.vhd_path, "drive_root": fixture.drive_root, "mount_root": fixture.mount_root}

        if first_fixture_cleanup is not None:
            summary["checks"]["after_detach_keep_vhd"] = cleanup_audit.audit_fixture_cleanup(
                vhd_path=Path(str(first_fixture_cleanup["vhd_path"])),
                drive_root=Path(str(first_fixture_cleanup["drive_root"])),
                mount_root=Path(str(first_fixture_cleanup["mount_root"])),
                keep_vhd=True,
            )

        app = live_common.launch_app(paths.app_exe, profile_base, minimized_to_tray=True)
        missing_ready = rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        missing_lookup = fetch_transfer(base_url, args.api_key, transfer_hash)
        missing_startup_log = wait_for_missing_temp_directory_startup_log(profile_base)
        missing_kill = kill_intermediate_recovery_app(app)
        app = None
        missing_ok = int(missing_ready.get("status", 0) or 0) == 200 and bool(missing_startup_log)
        summary["checks"]["missing_volume_relaunch"] = {
            "status": "passed" if missing_ok else "failed",
            "non_modal_rest_ready": compact_result(missing_ready),
            "transfer_lookup_without_vhd": compact_result(missing_lookup),
            "startup_error_log": missing_startup_log,
            "forced_shutdown": missing_kill,
        }

        with attach_admin_volume_fixture(replace(config, keep=args.keep_admin_fixtures)) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            summary["reattached_volume_identities"] = {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
                "local_control": asdict(fixture.local_control_identity),
            }
            restored_temp_dir = build_storage_topology(fixture, SUITE_NAME).vhd_drive_root / "temp"
            app, restored_ready = launch_profile_and_wait(paths, profile_base, base_url, args.api_key, args.rest_ready_timeout_seconds)
            restored_lookup = fetch_transfer(base_url, args.api_key, transfer_hash)
            restored_metadata = wait_for_part_metadata(restored_temp_dir)
            restored_ok = int(restored_ready.get("status", 0) or 0) == 200 and int(restored_lookup.get("status", 0) or 0) == 200 and bool(restored_metadata)
            summary["checks"]["restored_volume_relaunch"] = {
                "status": "passed" if restored_ok else "failed",
                "rest_ready": compact_result(restored_ready),
                "transfer_lookup": compact_result(restored_lookup),
                "part_metadata": restored_metadata,
            }
            summary["checks"]["restored_shutdown"] = rest_smoke.close_app_cleanly_with_timing(app)
            app = None
            final_fixture_cleanup = {"vhd_path": fixture.vhd_path, "drive_root": fixture.drive_root, "mount_root": fixture.mount_root}

        if final_fixture_cleanup is not None:
            summary["checks"]["final_fixture_cleanup"] = cleanup_audit.audit_fixture_cleanup(
                vhd_path=Path(str(final_fixture_cleanup["vhd_path"])),
                drive_root=Path(str(final_fixture_cleanup["drive_root"])),
                mount_root=Path(str(final_fixture_cleanup["mount_root"])),
                keep_vhd=args.keep_admin_fixtures,
            )
        failed_checks = [
            name for name, check in summary["checks"].items()
            if isinstance(check, dict) and check.get("status") == "failed"
        ]
        summary["failed_checks"] = failed_checks
        summary["status"] = "passed" if not failed_checks else "failed"
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if app is not None:
            try:
                summary["cleanup_shutdown"] = rest_smoke.close_app_cleanly_with_timing(app)
            except Exception as exc:
                summary["cleanup_shutdown_error"] = {"type": type(exc).__name__, "message": str(exc)}
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "vhd-partfile-recovery-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Builds the VHD part-file recovery parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=MIN_VHD_SIZE_MB)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--transfer-size-mb", type=int, default=64)
    return parser


def main() -> int:
    """Runs the VHD part-file recovery live proof."""

    summary = run_vhd_partfile_recovery(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
