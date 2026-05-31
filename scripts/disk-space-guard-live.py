"""Live proof for disk-space guard behavior on a constrained Windows volume."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixture,
    AdminVolumeFixtureConfig,
    build_storage_topology,
    create_admin_volume_fixture,
    get_volume_identity,
)
from emule_test_harness.ini import patch_ini_value, read_ini_text, write_utf16_ini_text  # noqa: E402
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
STORAGE_ROLE_LOCAL = "local-control"
STORAGE_ROLE_VHD_DRIVE = "vhd-drive-letter"
STORAGE_ROLE_VHD_MOUNT = "vhd-folder-mount"


@dataclass(frozen=True)
class DiskSpaceGuardCase:
    """One storage topology case in the constrained-volume live matrix."""

    name: str
    temp_role: str
    incoming_role: str
    expected_rejected: bool
    extra_temp_roles: tuple[str, ...] = ()


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


def case_hash(case_index: int) -> str:
    """Returns a deterministic unique eD2K hash for one matrix case."""

    if case_index < 0:
        raise ValueError("Case index must be zero or greater.")
    return f"{case_index + 1:032X}"


def build_disk_space_guard_cases() -> list[DiskSpaceGuardCase]:
    """Builds the required low-space storage topology matrix."""

    return [
        DiskSpaceGuardCase(
            name="drive-letter-temp-and-incoming",
            temp_role=STORAGE_ROLE_VHD_DRIVE,
            incoming_role=STORAGE_ROLE_VHD_DRIVE,
            expected_rejected=True,
        ),
        DiskSpaceGuardCase(
            name="mounted-folder-temp-and-incoming",
            temp_role=STORAGE_ROLE_VHD_MOUNT,
            incoming_role=STORAGE_ROLE_VHD_MOUNT,
            expected_rejected=True,
        ),
        DiskSpaceGuardCase(
            name="local-temp-vhd-incoming",
            temp_role=STORAGE_ROLE_LOCAL,
            incoming_role=STORAGE_ROLE_VHD_DRIVE,
            expected_rejected=True,
        ),
        DiskSpaceGuardCase(
            name="vhd-temp-local-incoming",
            temp_role=STORAGE_ROLE_VHD_DRIVE,
            incoming_role=STORAGE_ROLE_LOCAL,
            expected_rejected=True,
        ),
        DiskSpaceGuardCase(
            name="multi-temp-fallback-to-local",
            temp_role=STORAGE_ROLE_VHD_DRIVE,
            incoming_role=STORAGE_ROLE_LOCAL,
            expected_rejected=False,
            extra_temp_roles=(STORAGE_ROLE_LOCAL,),
        ),
    ]


def storage_role_root(fixture: AdminVolumeFixture, role: str) -> Path:
    """Returns the suite-scoped root for one storage topology role."""

    topology = build_storage_topology(fixture, "disk-space-guard-live")
    roots = {
        STORAGE_ROLE_LOCAL: topology.local_control_root,
        STORAGE_ROLE_VHD_DRIVE: topology.vhd_drive_root,
        STORAGE_ROLE_VHD_MOUNT: topology.vhd_mount_root,
    }
    try:
        return roots[role]
    except KeyError as exc:
        raise ValueError(f"Unknown storage role: {role}") from exc


def configure_temp_dirs(config_dir: Path, primary_temp_dir: Path, extra_temp_dirs: list[Path]) -> None:
    """Writes one primary temp dir and optional fallback temp dirs to preferences.ini."""

    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    primary = live_common.win_path(primary_temp_dir, trailing_slash=True)
    extras = "|".join(live_common.win_path(path, trailing_slash=True) for path in extra_temp_dirs)
    text = patch_ini_value(text, "TempDir", primary)
    text = patch_ini_value(text, "TempDirs", extras)
    write_utf16_ini_text(preferences_path, text)


def find_part_metadata_roots(*roots: Path) -> list[str]:
    """Returns roots that contain created part metadata after an accepted add."""

    matches: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        if any(root.rglob("*.part.met")):
            matches.append(str(root))
    return matches


def wait_for_part_metadata_roots(*roots: Path, timeout_seconds: float = 10.0) -> list[str]:
    """Waits briefly for accepted transfer part metadata to materialize."""

    deadline = time.time() + timeout_seconds
    matches: list[str] = []
    while time.time() < deadline:
        matches = find_part_metadata_roots(*roots)
        if matches:
            return matches
        time.sleep(0.25)
    return matches


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
    expected_rejected: bool = True,
) -> dict[str, object]:
    """Classifies the constrained-volume transfer-add result."""

    add_status = int(add_result.get("status", 0) or 0)
    transfer_status = int(transfer_lookup.get("status", 0) or 0) if transfer_lookup is not None else None
    rejected = add_status not in {200, 201, 202}
    transfer_absent = transfer_status in {None, 404}
    explicit_reason = text_contains_disk_space_reason(add_result.get("json"), add_result.get("body_text"), logs_result)
    errors: list[str] = []
    if expected_rejected:
        if not rejected:
            errors.append(f"expected constrained-volume transfer add to be rejected, got HTTP {add_status}")
        if not transfer_absent:
            errors.append(f"expected rejected transfer to be absent, got transfer lookup HTTP {transfer_status}")
        if not explicit_reason:
            errors.append("expected response or logs to include an explicit disk/storage/free-space reason")
    else:
        if rejected:
            errors.append(f"expected valid fallback temp placement to be accepted, got HTTP {add_status}")
        if transfer_absent:
            errors.append(f"expected accepted transfer to be present, got transfer lookup HTTP {transfer_status}")
    return {
        "status": "passed" if not errors else "failed",
        "expected_rejected": expected_rejected,
        "rejected": rejected,
        "transfer_absent": transfer_absent,
        "explicit_reason": explicit_reason,
        "errors": errors,
    }


def run_disk_space_guard_case(
    *,
    case: DiskSpaceGuardCase,
    case_index: int,
    fixture: AdminVolumeFixture,
    paths,
    seed_config_dir: Path,
    base_url: str,
    port: int,
    args: argparse.Namespace,
    transfer_size_bytes: int,
) -> dict[str, object]:
    """Runs one isolated app/profile against a disk-space topology case."""

    case_artifacts_dir = paths.source_artifacts_dir / "cases" / case.name
    temp_root = storage_role_root(fixture, case.temp_role)
    incoming_root = storage_role_root(fixture, case.incoming_role)
    extra_temp_roots = [storage_role_root(fixture, role) for role in case.extra_temp_roles]
    temp_dir = temp_root / case.name / "temp"
    incoming_dir = incoming_root / case.name / "incoming"
    extra_temp_dirs = [root / case.name / f"temp-extra-{index}" for index, root in enumerate(extra_temp_roots, start=1)]
    for directory in (temp_dir, incoming_dir, *extra_temp_dirs):
        directory.mkdir(parents=True, exist_ok=True)

    transfer_hash = case_hash(case_index)
    transfer_link = build_guard_transfer_link(transfer_size_bytes, transfer_hash)
    summary: dict[str, object] = {
        "name": case.name,
        "status": "failed",
        "storage_roles": {
            "temp": case.temp_role,
            "incoming": case.incoming_role,
            "extra_temps": list(case.extra_temp_roles),
        },
        "directories": {
            "temp": str(temp_dir),
            "incoming": str(incoming_dir),
            "extra_temps": [str(path) for path in extra_temp_dirs],
        },
        "transfer": {
            "hash": transfer_hash.lower(),
            "size_bytes": transfer_size_bytes,
            "link": transfer_link,
        },
        "disk_usage_before": {
            "temp": dict(shutil.disk_usage(temp_dir)._asdict()),
            "incoming": dict(shutil.disk_usage(incoming_dir)._asdict()),
        },
    }
    app = None
    try:
        profile_fixture = live_common.prepare_profile_base(
            seed_config_dir=seed_config_dir,
            artifacts_dir=case_artifacts_dir / "profile",
            shared_dirs=[],
            incoming_dir=incoming_dir,
            temp_dir=temp_dir,
            scenario_id=case.name,
        )
        configure_temp_dirs(Path(str(profile_fixture["config_dir"])), temp_dir, extra_temp_dirs)
        rest_smoke.configure_webserver_profile(
            Path(str(profile_fixture["config_dir"])),
            paths.app_exe,
            args.api_key,
            port,
            args.lan_bind_addr,
        )
        summary["profile_base"] = str(profile_fixture["profile_base"])
        summary["config_dir"] = str(profile_fixture["config_dir"])
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
            json_body={"link": transfer_link, "paused": True, "categoryId": 0},
            request_timeout_seconds=10.0,
        )
        transfer_lookup = rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash.lower()}",
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
        assertion = summarize_guard_result(
            add_result=add_result,
            transfer_lookup=transfer_lookup,
            logs_result=logs_result,
            expected_rejected=case.expected_rejected,
        )
        if not case.expected_rejected:
            selected_roots = wait_for_part_metadata_roots(temp_dir, *extra_temp_dirs)
            summary["selected_temp_roots"] = selected_roots
            if not selected_roots:
                assertion["errors"].append("expected accepted transfer to create part metadata under one configured temp root")
                assertion["status"] = "failed"
        summary["guard_assertion"] = assertion
        summary["resource_snapshots"]["after_guard"] = rest_smoke.get_process_resource_snapshot(process_id)  # type: ignore[index]
        summary["disk_usage_after"] = {
            "temp": dict(shutil.disk_usage(temp_dir)._asdict()),
            "incoming": dict(shutil.disk_usage(incoming_dir)._asdict()),
        }
        summary["status"] = assertion["status"]
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if app is not None:
            try:
                summary["shutdown"] = rest_smoke.close_app_cleanly_with_timing(app)
            except Exception as exc:
                summary["shutdown_error"] = {"type": type(exc).__name__, "message": str(exc)}
        harness_cli_common.write_json_file(case_artifacts_dir / "disk-space-guard-live-result.json", summary)
    return summary


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
    parser.add_argument("--lan-bind-addr", required=True)
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
    base_url = f"http://{args.lan_bind_addr}:{port}"
    guard_size_mb = args.guard_transfer_size_mb or max(args.vhd_size_mb * 2, args.vhd_size_mb + 128)
    guard_size_bytes = guard_size_mb * 1024 * 1024
    cases = build_disk_space_guard_cases()
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
        "case_count": len(cases),
        "cases": [],
        "strict_success_required": True,
    }
    try:
        with create_admin_volume_fixture(config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            topology = build_storage_topology(fixture, "disk-space-guard-live")
            for root in (topology.local_control_root, topology.vhd_drive_root, topology.vhd_mount_root):
                root.mkdir(parents=True, exist_ok=True)
            summary["volume_identities"] = {
                "drive_letter": asdict(get_volume_identity(fixture.drive_root)),
                "folder_mount": asdict(get_volume_identity(fixture.mount_root)),
                "local_control": asdict(get_volume_identity(fixture.local_control_root)),
            }
            case_results = []
            for index, case in enumerate(cases):
                case_result = run_disk_space_guard_case(
                    case=case,
                    case_index=index,
                    fixture=fixture,
                    paths=paths,
                    seed_config_dir=seed_config_dir,
                    base_url=base_url,
                    port=port,
                    args=args,
                    transfer_size_bytes=guard_size_bytes,
                )
                case_results.append(case_result)
            summary["cases"] = case_results
            summary["status"] = "passed" if all(case.get("status") == "passed" for case in case_results) else "failed"
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "disk-space-guard-live-result.json", summary)
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
