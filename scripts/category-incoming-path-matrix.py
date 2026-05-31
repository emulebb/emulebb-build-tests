"""Live proof for category-specific incoming paths on VHD-backed roots."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
from typing import Any

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

SUITE_NAME = "category-incoming-path-matrix"
API_KEY = "category-incoming-path-matrix-key"
CATEGORY_SELECTOR_ID = "categoryId"
CATEGORY_SELECTOR_NAME = "categoryName"
CATEGORY_NAME_PREFIX = "CI035"
STORAGE_ROLE_LOCAL = disk_guard.STORAGE_ROLE_LOCAL
STORAGE_ROLE_VHD_DRIVE = disk_guard.STORAGE_ROLE_VHD_DRIVE
STORAGE_ROLE_VHD_MOUNT = disk_guard.STORAGE_ROLE_VHD_MOUNT


@dataclass(frozen=True)
class CategoryIncomingCase:
    """One category incoming path topology to prove with a real REST add."""

    name: str
    temp_role: str
    category_incoming_role: str
    selector: str
    expected_rejected: bool
    extra_temp_roles: tuple[str, ...] = ()


def build_category_incoming_cases() -> list[CategoryIncomingCase]:
    """Builds the VHD-backed category incoming path matrix."""

    return [
        CategoryIncomingCase(
            name="category-drive-incoming-by-id",
            temp_role=STORAGE_ROLE_LOCAL,
            category_incoming_role=STORAGE_ROLE_VHD_DRIVE,
            selector=CATEGORY_SELECTOR_ID,
            expected_rejected=True,
        ),
        CategoryIncomingCase(
            name="category-mount-incoming-by-id",
            temp_role=STORAGE_ROLE_LOCAL,
            category_incoming_role=STORAGE_ROLE_VHD_MOUNT,
            selector=CATEGORY_SELECTOR_ID,
            expected_rejected=True,
        ),
        CategoryIncomingCase(
            name="category-drive-incoming-by-name",
            temp_role=STORAGE_ROLE_LOCAL,
            category_incoming_role=STORAGE_ROLE_VHD_DRIVE,
            selector=CATEGORY_SELECTOR_NAME,
            expected_rejected=True,
        ),
        CategoryIncomingCase(
            name="same-vhd-drive-temp-mount-category",
            temp_role=STORAGE_ROLE_VHD_DRIVE,
            category_incoming_role=STORAGE_ROLE_VHD_MOUNT,
            selector=CATEGORY_SELECTOR_ID,
            expected_rejected=True,
        ),
        CategoryIncomingCase(
            name="local-category-control-by-name",
            temp_role=STORAGE_ROLE_LOCAL,
            category_incoming_role=STORAGE_ROLE_LOCAL,
            selector=CATEGORY_SELECTOR_NAME,
            expected_rejected=False,
        ),
    ]


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for the category path matrix."""

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


def storage_role_root(fixture: AdminVolumeFixture, role: str) -> Path:
    """Returns the suite-scoped root for one storage topology role."""

    topology = build_storage_topology(fixture, SUITE_NAME)
    roots = {
        STORAGE_ROLE_LOCAL: topology.local_control_root,
        STORAGE_ROLE_VHD_DRIVE: topology.vhd_drive_root,
        STORAGE_ROLE_VHD_MOUNT: topology.vhd_mount_root,
    }
    try:
        return roots[role]
    except KeyError as exc:
        raise ValueError(f"Unknown storage role: {role}") from exc


def category_selector_payload(selector: str, category_id: int, category_name: str) -> dict[str, object]:
    """Builds the transfer-add category selector payload for one matrix case."""

    if selector == CATEGORY_SELECTOR_ID:
        return {"categoryId": category_id}
    if selector == CATEGORY_SELECTOR_NAME:
        return {"categoryName": category_name}
    raise ValueError(f"Unknown category selector: {selector}")


def category_path_matches(row: dict[str, Any], expected_path: Path) -> bool:
    """Returns true when one REST category row points at the expected path."""

    actual = row.get("path")
    if not isinstance(actual, str) or not actual:
        return False
    return Path(actual).resolve() == expected_path.resolve()


def find_category_row(rows: list[Any], category_id: int, category_name: str) -> dict[str, Any] | None:
    """Finds one REST category row by id or name."""

    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("id") == category_id or row.get("name") == category_name:
            return row
    return None


def compact_category_row(row: dict[str, Any]) -> dict[str, Any]:
    """Returns stable category fields for cleanup diagnostics."""

    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "path": row.get("path"),
    }


def is_test_owned_category_row(row: dict[str, Any], case_name: str, category_name: str) -> bool:
    """Returns true for category rows owned by one matrix case."""

    name = row.get("name")
    return isinstance(name, str) and (name == category_name or (name.startswith(CATEGORY_NAME_PREFIX) and case_name in name))


def find_test_owned_category_rows(rows: list[Any], case_name: str, category_name: str) -> list[dict[str, Any]]:
    """Finds category rows that belong to one matrix case."""

    return [row for row in rows if isinstance(row, dict) and is_test_owned_category_row(row, case_name, category_name)]


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


def list_categories(base_url: str, api_key: str) -> tuple[dict[str, object], list[Any]]:
    """Lists REST categories and returns the raw result plus parsed rows."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/categories",
        api_key=api_key,
        request_timeout_seconds=5.0,
    )
    return result, rest_smoke.require_json_array(result, 200)


def transfer_absent(result: dict[str, object]) -> bool:
    """Returns true when a transfer lookup reports the expected NOT_FOUND state."""

    if int(result.get("status", 0) or 0) != 404:
        return False
    payload = result.get("json")
    if isinstance(payload, dict):
        if payload.get("error") == "NOT_FOUND":
            return True
        error = payload.get("error")
        if isinstance(error, dict) and error.get("code") == "NOT_FOUND":
            return True
    return "NOT_FOUND" in str(result.get("body_text", ""))


def lookup_transfer(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Looks up one transfer hash through the public REST API."""

    return rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash.lower()}",
        api_key=api_key,
        request_timeout_seconds=5.0,
    )


def collect_case_record_state(
    base_url: str,
    api_key: str,
    *,
    case_name: str,
    category_name: str,
    transfer_hash: str,
) -> dict[str, object]:
    """Collects category and transfer records owned by one matrix case."""

    categories_result, category_rows = list_categories(base_url, api_key)
    matching_categories = find_test_owned_category_rows(category_rows, case_name, category_name)
    transfer_lookup = lookup_transfer(base_url, api_key, transfer_hash)
    transfer_is_absent = transfer_absent(transfer_lookup)
    errors: list[str] = []
    if matching_categories:
        errors.append(f"found {len(matching_categories)} test-owned category record(s)")
    if not transfer_is_absent:
        errors.append(f"transfer hash {transfer_hash.lower()} is not absent")
    return {
        "clean": not errors,
        "errors": errors,
        "categories": compact_result(categories_result),
        "matching_categories": [compact_category_row(row) for row in matching_categories],
        "transfer_lookup": compact_result(transfer_lookup),
        "transfer_absent": transfer_is_absent,
    }


def require_clean_case_records(state: dict[str, object], phase: str) -> None:
    """Fails when a case has leftover REST records at a lifecycle boundary."""

    if state.get("clean") is True:
        return
    raise RuntimeError(f"{phase} case record cleanup assertion failed: {json.dumps(state, default=str)}")


def delete_category(base_url: str, api_key: str, category_id: int) -> dict[str, object]:
    """Deletes one non-default category by id."""

    if category_id == 0:
        return {"skipped": True, "reason": "default category"}
    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/categories/{category_id}",
        method="DELETE",
        api_key=api_key,
        request_timeout_seconds=10.0,
    )
    return compact_result(result) or {}


def delete_transfer(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Deletes one transfer and its partial files when it exists."""

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash.lower()}/files?confirm=true",
        method="DELETE",
        api_key=api_key,
        request_timeout_seconds=10.0,
    )
    return compact_result(result) or {}


def cleanup_case_records(
    base_url: str,
    api_key: str,
    *,
    case_name: str,
    category_name: str,
    transfer_hash: str,
    created_category_id: int | None,
) -> dict[str, object]:
    """Best-effort cleanup for records created by one matrix case."""

    before = collect_case_record_state(
        base_url,
        api_key,
        case_name=case_name,
        category_name=category_name,
        transfer_hash=transfer_hash,
    )
    deleted_transfers: list[dict[str, object]] = []
    deleted_categories: list[dict[str, object]] = []
    transfer_lookup = before.get("transfer_lookup")
    if isinstance(transfer_lookup, dict) and transfer_lookup.get("status") != 404:
        deleted_transfers.append(delete_transfer(base_url, api_key, transfer_hash))

    category_ids: list[int] = []
    if created_category_id is not None:
        category_ids.append(created_category_id)
    for row in before.get("matching_categories", []):
        if isinstance(row, dict) and isinstance(row.get("id"), int):
            category_ids.append(int(row["id"]))
    for category_id in dict.fromkeys(category_ids):
        if category_id != 0:
            deleted_categories.append(delete_category(base_url, api_key, category_id))

    after = collect_case_record_state(
        base_url,
        api_key,
        case_name=case_name,
        category_name=category_name,
        transfer_hash=transfer_hash,
    )
    return {
        "before": before,
        "deleted_transfers": deleted_transfers,
        "deleted_categories": deleted_categories,
        "after": after,
        "clean": after.get("clean") is True,
    }


def create_category(base_url: str, api_key: str, name: str, path: Path) -> tuple[dict[str, object], dict[str, Any]]:
    """Creates one category through the public REST API."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/categories",
        method="POST",
        api_key=api_key,
        json_body={"name": name, "path": live_common.win_path(path, trailing_slash=True)},
        request_timeout_seconds=10.0,
    )
    if int(result.get("status", 0) or 0) not in {200, 201}:
        raise RuntimeError(f"category create failed: {compact_result(result)}")
    payload = result.get("json")
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), int):
        raise RuntimeError(f"category create did not return an id: {compact_result(result)}")
    return result, payload


def run_category_case(
    *,
    case: CategoryIncomingCase,
    case_index: int,
    fixture: AdminVolumeFixture,
    paths,
    seed_config_dir: Path,
    base_url: str,
    port: int,
    args: argparse.Namespace,
    transfer_size_bytes: int,
) -> dict[str, object]:
    """Runs one live category incoming path topology case."""

    case_artifacts_dir = paths.source_artifacts_dir / "cases" / case.name
    temp_root = storage_role_root(fixture, case.temp_role)
    incoming_root = storage_role_root(fixture, case.category_incoming_role)
    extra_temp_roots = [storage_role_root(fixture, role) for role in case.extra_temp_roles]
    temp_dir = temp_root / case.name / "temp"
    default_incoming_dir = storage_role_root(fixture, STORAGE_ROLE_LOCAL) / case.name / "default-incoming"
    category_incoming_dir = incoming_root / case.name / "category-incoming"
    extra_temp_dirs = [root / case.name / f"temp-extra-{index}" for index, root in enumerate(extra_temp_roots, start=1)]
    for directory in (temp_dir, default_incoming_dir, category_incoming_dir, *extra_temp_dirs):
        directory.mkdir(parents=True, exist_ok=True)

    transfer_hash = disk_guard.case_hash(case_index + 100)
    transfer_link = disk_guard.build_guard_transfer_link(transfer_size_bytes, transfer_hash)
    category_name = f"CI035 {case_index:02d} {case.name}"
    summary: dict[str, object] = {
        "name": case.name,
        "status": "failed",
        "selector": case.selector,
        "expected_rejected": case.expected_rejected,
        "storage_roles": {
            "temp": case.temp_role,
            "default_incoming": STORAGE_ROLE_LOCAL,
            "category_incoming": case.category_incoming_role,
            "extra_temps": list(case.extra_temp_roles),
        },
        "directories": {
            "temp": str(temp_dir),
            "default_incoming": str(default_incoming_dir),
            "category_incoming": str(category_incoming_dir),
            "extra_temps": [str(path) for path in extra_temp_dirs],
        },
        "transfer": {
            "hash": transfer_hash.lower(),
            "size_bytes": transfer_size_bytes,
            "link": transfer_link,
        },
        "disk_usage_before": {
            "temp": dict(shutil.disk_usage(temp_dir)._asdict()),
            "default_incoming": dict(shutil.disk_usage(default_incoming_dir)._asdict()),
            "category_incoming": dict(shutil.disk_usage(category_incoming_dir)._asdict()),
        },
    }
    app = None
    rest_ready = False
    transfer_attempted = False
    created_category_id: int | None = None
    try:
        profile_fixture = live_common.prepare_profile_base(
            seed_config_dir=seed_config_dir,
            artifacts_dir=case_artifacts_dir / "profile",
            shared_dirs=[],
            incoming_dir=default_incoming_dir,
            temp_dir=temp_dir,
            scenario_id=case.name,
        )
        disk_guard.configure_temp_dirs(Path(str(profile_fixture["config_dir"])), temp_dir, extra_temp_dirs)
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
        rest_ready = True
        pre_case_state = collect_case_record_state(
            base_url,
            args.api_key,
            case_name=case.name,
            category_name=category_name,
            transfer_hash=transfer_hash,
        )
        summary["pre_case_cleanup"] = pre_case_state
        require_clean_case_records(pre_case_state, "pre-case")

        category_create_result, category = create_category(base_url, args.api_key, category_name, category_incoming_dir)
        category_id = int(category["id"])
        created_category_id = category_id
        categories_result, category_rows = list_categories(base_url, args.api_key)
        category_row = find_category_row(category_rows, category_id, category_name)
        category_path_ok = category_row is not None and category_path_matches(category_row, category_incoming_dir)
        selector_payload = category_selector_payload(case.selector, category_id, category_name)

        transfer_attempted = True
        add_result = rest_smoke.http_request(
            base_url,
            "/api/v1/transfers",
            method="POST",
            api_key=args.api_key,
            json_body={"link": transfer_link, "paused": True, **selector_payload},
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
        assertion = disk_guard.summarize_guard_result(
            add_result=add_result,
            transfer_lookup=transfer_lookup,
            logs_result=logs_result,
            expected_rejected=case.expected_rejected,
        )
        if not category_path_ok:
            assertion["errors"].append("created category did not retain the requested incoming path")
            assertion["status"] = "failed"
        if not case.expected_rejected:
            selected_roots = disk_guard.wait_for_part_metadata_roots(temp_dir, *extra_temp_dirs)
            summary["selected_temp_roots"] = selected_roots
            expected_roots = {str(path) for path in (extra_temp_dirs or [temp_dir])}
            if not expected_roots.intersection(selected_roots):
                assertion["errors"].append("expected accepted transfer part metadata under a configured temp root")
                assertion["status"] = "failed"

        summary["category"] = {
            "id": category_id,
            "name": category_name,
            "requested_path": str(category_incoming_dir),
            "create": compact_result(category_create_result),
            "listed_row": category_row,
            "path_matches_requested": category_path_ok,
        }
        summary["http"] = {
            "categories": compact_result(categories_result),
            "add_transfer": compact_result(add_result),
            "transfer_lookup": compact_result(transfer_lookup),
            "logs": compact_result(logs_result),
        }
        summary["guard_assertion"] = assertion
        summary["resource_snapshots"]["after_guard"] = rest_smoke.get_process_resource_snapshot(process_id)  # type: ignore[index]
        summary["disk_usage_after"] = {
            "temp": dict(shutil.disk_usage(temp_dir)._asdict()),
            "default_incoming": dict(shutil.disk_usage(default_incoming_dir)._asdict()),
            "category_incoming": dict(shutil.disk_usage(category_incoming_dir)._asdict()),
        }
        summary["status"] = assertion["status"]
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if rest_ready and (created_category_id is not None or transfer_attempted):
            try:
                post_case_cleanup = cleanup_case_records(
                    base_url,
                    args.api_key,
                    case_name=case.name,
                    category_name=category_name,
                    transfer_hash=transfer_hash,
                    created_category_id=created_category_id,
                )
                summary["post_case_cleanup"] = post_case_cleanup
                if post_case_cleanup.get("clean") is not True:
                    summary["record_leak_diagnostics"] = post_case_cleanup
                    summary["status"] = "failed"
                    cleanup_error = "post-case cleanup left category or transfer records behind"
                    assertion = summary.get("guard_assertion")
                    if isinstance(assertion, dict):
                        errors = assertion.setdefault("errors", [])
                        if isinstance(errors, list):
                            errors.append(cleanup_error)
                        assertion["status"] = "failed"
                    if "error" not in summary:
                        summary["error"] = {"type": "RuntimeError", "message": cleanup_error}
            except Exception as exc:
                summary["post_case_cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
                summary["status"] = "failed"
                if "error" not in summary:
                    summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
        if app is not None:
            try:
                summary["shutdown"] = rest_smoke.close_app_cleanly_with_timing(app)
            except Exception as exc:
                summary["shutdown_error"] = {"type": type(exc).__name__, "message": str(exc)}
        harness_cli_common.write_json_file(case_artifacts_dir / "category-incoming-path-matrix-result.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Builds the category incoming matrix parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=384)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--guard-transfer-size-mb", type=int)
    return parser


def run_category_incoming_path_matrix(args: argparse.Namespace) -> dict[str, object]:
    """Runs the category incoming path matrix and publishes JSON artifacts."""

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
    guard_size_mb = args.guard_transfer_size_mb or max(args.vhd_size_mb * 2, args.vhd_size_mb + 128)
    guard_size_bytes = guard_size_mb * 1024 * 1024
    cases = build_category_incoming_cases()
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
        "guard_transfer": {
            "size_mb": guard_size_mb,
            "size_bytes": guard_size_bytes,
            "link": disk_guard.build_guard_transfer_link(guard_size_bytes),
        },
        "case_count": len(cases),
        "cases": [],
    }
    fixture_cleanup: dict[str, object] | None = None
    try:
        with create_admin_volume_fixture(config) as fixture:
            assert isinstance(fixture, AdminVolumeFixture)
            topology = build_storage_topology(fixture, SUITE_NAME)
            for root in (topology.local_control_root, topology.vhd_drive_root, topology.vhd_mount_root):
                root.mkdir(parents=True, exist_ok=True)
            summary["volume_identities"] = {
                "drive_letter": asdict(get_volume_identity(fixture.drive_root)),
                "folder_mount": asdict(get_volume_identity(fixture.mount_root)),
                "local_control": asdict(get_volume_identity(fixture.local_control_root)),
            }
            case_results = []
            for index, case in enumerate(cases):
                case_results.append(
                    run_category_case(
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
                )
            summary["cases"] = case_results
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
        failed_cases = [case["name"] for case in summary["cases"] if case.get("status") != "passed"]  # type: ignore[index]
        summary["failed_cases"] = failed_cases
        summary["status"] = (
            "passed"
            if not failed_cases and isinstance(summary.get("fixture_cleanup"), dict) and summary["fixture_cleanup"].get("status") == "passed"
            else "failed"
        )
    except Exception as exc:
        summary["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "category-incoming-path-matrix-result.json", summary)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    return summary


def main() -> int:
    """Runs the category incoming path live proof."""

    summary = run_category_incoming_path_matrix(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
