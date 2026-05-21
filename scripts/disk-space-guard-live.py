"""Live proof for disk-space guard behavior on a constrained Windows volume."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixtureConfig,
    create_admin_volume_fixture,
    get_volume_identity,
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

DISK_SPACE_TOKENS = ("space", "disk", "volume", "storage", "free")
DEFAULT_GUARD_FILE_HASH = "1234567890ABCDEF1234567890ABCDEF"
DEFAULT_GUARD_FILE_HASH_LOWER = DEFAULT_GUARD_FILE_HASH.lower()


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the constrained VHD fixture configuration for this suite."""

    mount_parent = Path(args.mount_root).resolve() if args.mount_root else paths.source_artifacts_dir / "admin-mounts"
    reject_windows_temp_path(mount_parent, "admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / "disk-space-guard-live.vhdx",
        mount_root=mount_parent / "disk-space-guard-live",
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


def build_guard_transfer_link(size_bytes: int, file_hash: str = DEFAULT_GUARD_FILE_HASH) -> str:
    """Builds an eD2K file link larger than the constrained fixture volume."""

    if size_bytes <= 0:
        raise ValueError("Guard transfer size must be greater than zero.")
    cleaned_hash = file_hash.strip().upper()
    if len(cleaned_hash) != 32 or any(char not in "0123456789ABCDEF" for char in cleaned_hash):
        raise ValueError("Guard transfer hash must be 32 hexadecimal characters.")
    return f"ed2k://|file|disk-space-guard-live.bin|{size_bytes}|{cleaned_hash}|/"


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


def text_contains_disk_space_reason(*values: object) -> bool:
    """Returns true when response or log text names the disk-space condition."""

    text = " ".join(json.dumps(value, default=str) for value in values if value is not None).lower()
    return any(token in text for token in DISK_SPACE_TOKENS)


def summarize_guard_result(
    *,
    add_result: dict[str, object],
    transfer_lookup: dict[str, object] | None,
    logs_result: dict[str, object] | None,
) -> dict[str, object]:
    """Classifies the constrained-volume transfer-add result."""

    add_status = int(add_result.get("status", 0) or 0)
    transfer_status = int(transfer_lookup.get("status", 0) or 0) if transfer_lookup is not None else None
    rejected = add_status not in {200, 201, 202}
    transfer_absent = transfer_status in {None, 404}
    explicit_reason = text_contains_disk_space_reason(add_result.get("json"), add_result.get("body_text"), logs_result)
    errors: list[str] = []
    if not rejected:
        errors.append(f"expected constrained-volume transfer add to be rejected, got HTTP {add_status}")
    if not transfer_absent:
        errors.append(f"expected rejected transfer to be absent, got transfer lookup HTTP {transfer_status}")
    if not explicit_reason:
        errors.append("expected response or logs to include an explicit disk/storage/free-space reason")
    return {
        "status": "passed" if not errors else "failed",
        "rejected": rejected,
        "transfer_absent": transfer_absent,
        "explicit_reason": explicit_reason,
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds the disk-space guard parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=128)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    parser.add_argument("--api-key", default="disk-space-guard-test-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--guard-transfer-size-mb", type=int)
    return parser


def run_disk_space_guard(args: argparse.Namespace) -> dict[str, object]:
    """Runs the constrained-volume disk-space guard proof and publishes JSON artifacts."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("disk-space-guard-live requires --admin-volume-fixtures.")
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="disk-space-guard-live",
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
    base_url = f"http://{args.bind_addr}:{port}"
    guard_size_mb = args.guard_transfer_size_mb or max(args.vhd_size_mb * 2, args.vhd_size_mb + 128)
    guard_size_bytes = guard_size_mb * 1024 * 1024
    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "failed",
        "suite": "disk-space-guard-live",
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
        "guard_transfer": {
            "size_mb": guard_size_mb,
            "size_bytes": guard_size_bytes,
            "link": build_guard_transfer_link(guard_size_bytes),
        },
        "strict_success_required": True,
    }
    app = None
    try:
        with create_admin_volume_fixture(config) as fixture:
            incoming_dir = fixture.drive_root / "incoming"
            temp_dir = fixture.drive_root / "temp"
            incoming_dir.mkdir(parents=True, exist_ok=True)
            temp_dir.mkdir(parents=True, exist_ok=True)
            profile_fixture = live_common.prepare_profile_base(
                seed_config_dir=seed_config_dir,
                artifacts_dir=paths.source_artifacts_dir / "profile",
                shared_dirs=[],
                incoming_dir=incoming_dir,
                temp_dir=temp_dir,
                scenario_id="disk-space-guard-live",
            )
            rest_smoke.configure_webserver_profile(
                Path(str(profile_fixture["config_dir"])),
                paths.app_exe,
                args.api_key,
                port,
                args.bind_addr,
            )
            summary["volume_identity"] = asdict(get_volume_identity(fixture.drive_root))
            summary["directories"] = {
                "incoming": str(incoming_dir),
                "temp": str(temp_dir),
                "profile_base": str(profile_fixture["profile_base"]),
            }
            summary["disk_usage_before"] = dict(shutil.disk_usage(fixture.drive_root)._asdict())
            app = live_common.launch_app(paths.app_exe, Path(str(profile_fixture["profile_base"])), minimized_to_tray=True)
            process_id = rest_smoke.get_app_process_id(app)
            summary["process_id"] = process_id
            summary["resource_snapshots"] = {"after_launch": rest_smoke.get_process_resource_snapshot(process_id)}
            summary["rest_ready"] = compact_result(rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds))
            add_result = rest_smoke.http_request(
                base_url,
                "/api/v1/transfers",
                method="POST",
                api_key=args.api_key,
                json_body={"link": summary["guard_transfer"]["link"], "paused": True, "categoryId": 0},
                request_timeout_seconds=10.0,
            )
            transfer_lookup = rest_smoke.http_request(
                base_url,
                f"/api/v1/transfers/{DEFAULT_GUARD_FILE_HASH_LOWER}",
                api_key=args.api_key,
                request_timeout_seconds=5.0,
            )
            logs_result = rest_smoke.http_request(
                base_url,
                "/api/v1/logs?limit=200",
                api_key=args.api_key,
                request_timeout_seconds=5.0,
            )
            summary["http"] = {
                "add_transfer": compact_result(add_result),
                "transfer_lookup": compact_result(transfer_lookup),
                "logs": compact_result(logs_result),
            }
            summary["guard_assertion"] = summarize_guard_result(
                add_result=add_result,
                transfer_lookup=transfer_lookup,
                logs_result=logs_result,
            )
            summary["resource_snapshots"]["after_guard"] = rest_smoke.get_process_resource_snapshot(process_id)  # type: ignore[index]
            summary["disk_usage_after"] = dict(shutil.disk_usage(fixture.drive_root)._asdict())
            summary["status"] = summary["guard_assertion"]["status"]  # type: ignore[index]
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if app is not None:
            try:
                summary["shutdown"] = rest_smoke.close_app_cleanly_with_timing(app)
            except Exception as exc:
                summary["shutdown_error"] = {"type": type(exc).__name__, "message": str(exc)}
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """Runs the disk-space guard live proof."""

    summary = run_disk_space_guard(build_parser().parse_args())
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
