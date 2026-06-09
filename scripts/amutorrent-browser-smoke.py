"""Runs a live aMuTorrent browser smoke against eMuleBB REST."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import importlib.util
import ipaddress
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixture,
    AdminVolumeFixtureConfig,
    build_storage_topology,
    create_admin_volume_fixture,
)
from emule_test_harness.ini import read_ini_text, remove_ini_section_value, write_utf16_ini_text  # noqa: E402
from emule_test_harness.paths import reject_windows_temp_path  # noqa: E402
from emule_test_harness.windows_processes import collect_adapter_ipv4_addresses  # noqa: E402

AMUTORRENT_NODE_ENV = "AMUTORRENT_NODE_EXE"
AMUTORRENT_ROOT_ENV = "EMULEBB_TEST_AMUTORRENT_ROOT"
SUPPORTED_NODE_MIN_MAJOR = 20
SUPPORTED_NODE_MAX_MAJOR = 25
DEFAULT_WINDOWS_NODE24 = Path(r"C:\bin\nodejs-v24\node.exe")
DEFAULT_WINDOWS_NODE22 = Path(r"C:\bin\nodejs-v22-old\node.exe")
DEFAULT_SEARCH_ROUNDS = 2
DEFAULT_CONTROLLER_VHD_SIZE_MB = 6144
AMUTORRENT_BROWSER_SMOKE_HASH = "fedcba98765432100123456789abcdef"
AMUTORRENT_BROWSER_SMOKE_SIZE_BYTES = 1024
SUITE_NAME = "amutorrent-browser-smoke"
LAN_IP_RESOLVED_ENV = "EMULEBB_TEST_LAN_IP_RESOLVED"


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    existing = sys.modules.get(module_name)
    if existing is not None and Path(getattr(existing, "__file__", "")).resolve() == module_path:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
rest_api_smoke = load_local_module("rest_api_smoke_helpers", "rest-api-smoke.py")
cleanup_audit = load_local_module("admin_volume_cleanup_audit", "admin-volume-cleanup-audit.py")

choose_listen_port = rest_api_smoke.choose_listen_port
close_app_cleanly = live_common.close_app_cleanly
configure_webserver_profile = rest_api_smoke.configure_webserver_profile
get_app_process_id = rest_api_smoke.get_app_process_id
launch_app = live_common.launch_app
prepare_profile_base = live_common.prepare_profile_base
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
wait_for_requested_networks = rest_api_smoke.wait_for_requested_networks
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready
write_json = live_common.write_json


def clear_p2p_bind_interface_policy(config_dir: Path) -> None:
    """Removes inherited P2P bind-interface policy for LAN address-bound runs."""

    preferences = config_dir / "preferences.ini"
    text = read_ini_text(preferences)
    for key in (
        "BindInterface",
        "BlockNetworkWhenBindUnavailableAtStartup",
        "ExitOnBindInterfaceLoss",
    ):
        text = remove_ini_section_value(text, "eMule", key)
    write_utf16_ini_text(preferences, text)


def find_workspace_repo_root(workspace_root: Path) -> Path:
    """Finds the parent workspace root that contains repos/amutorrent."""

    current = workspace_root.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "repos" / "amutorrent").is_dir():
            return candidate
    raise RuntimeError(f"Could not find repos/amutorrent above {workspace_root}.")


def resolve_amutorrent_root(workspace_root: Path) -> Path:
    """Resolves the aMuTorrent repo from a staged VM root or local workspace."""

    configured = os.environ.get(AMUTORRENT_ROOT_ENV, "").strip()
    if configured:
        root = Path(configured).resolve()
        if not (root / "server").is_dir():
            raise RuntimeError(f"{AMUTORRENT_ROOT_ENV} does not point at an aMuTorrent repo: {root}")
        return root
    return find_workspace_repo_root(workspace_root) / "repos" / "amutorrent"


def wait_for_http_ok(url: str, timeout_seconds: float) -> None:
    """Waits until a local HTTP endpoint responds successfully."""

    import urllib.request

    def probe() -> bool:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as response:
                return 200 <= int(response.status) < 500
        except Exception:
            return False

    wait_for(probe, timeout=timeout_seconds, interval=0.5, description=f"HTTP readiness for {url}")


def parse_node_major(version_text: str) -> int:
    """Parses a Node.js version string such as 'v22.14.0'."""

    version = version_text.strip()
    if version.startswith("v"):
        version = version[1:]
    major = version.split(".", 1)[0]
    if not major.isdigit():
        raise RuntimeError(f"Could not parse Node.js version from '{version_text}'.")
    return int(major)


def describe_install_command(node_exe: Path) -> str:
    """Returns the dependency install command matching the selected Node runtime."""

    npm_cmd = node_exe.with_name("npm.cmd" if os.name == "nt" else "npm")
    npm = str(npm_cmd) if npm_cmd.exists() else "npm"
    if os.name == "nt" and node_exe.is_absolute():
        return f'$env:PATH = "{node_exe.parent};" + $env:PATH; & "{npm}" ci --prefix server --omit=dev'
    return f'"{npm}" ci --prefix server --omit=dev'


def resolve_amutorrent_node() -> dict[str, Any]:
    """Selects the Node.js runtime used for the aMuTorrent browser smoke."""

    configured = os.environ.get(AMUTORRENT_NODE_ENV)
    candidates = [Path(configured)] if configured else []
    if DEFAULT_WINDOWS_NODE24.exists():
        candidates.append(DEFAULT_WINDOWS_NODE24)
    candidates.append(Path("node"))
    if DEFAULT_WINDOWS_NODE22.exists():
        candidates.append(DEFAULT_WINDOWS_NODE22)

    rejected: list[dict[str, str]] = []
    selected: tuple[Path, str, int] | None = None
    for node_exe in candidates:
        try:
            completed = subprocess.run(
                [str(node_exe), "-v"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            rejected.append({"path": str(node_exe), "reason": repr(exc)})
            continue
        version = completed.stdout.strip()
        major = parse_node_major(version)
        if major < SUPPORTED_NODE_MIN_MAJOR or major > SUPPORTED_NODE_MAX_MAJOR:
            rejected.append({"path": str(node_exe), "version": version, "reason": "unsupported_major"})
            continue
        selected = (node_exe, version, major)
        break
    if selected is None:
        raise RuntimeError(
            f"aMuTorrent browser smoke requires Node.js {SUPPORTED_NODE_MIN_MAJOR}-{SUPPORTED_NODE_MAX_MAJOR} "
            "because its locked server dependencies include native addons. "
            f"Set {AMUTORRENT_NODE_ENV} to a compatible Node executable. Rejected candidates: {rejected!r}"
        )
    node_exe, version, major = selected

    return {
        "path": str(node_exe),
        "version": version,
        "major": major,
        "rejected_candidates": rejected,
        "install_command": describe_install_command(node_exe),
    }


def require_amutorrent_server_dependencies(amutorrent_root: Path, node_info: dict[str, Any]) -> None:
    """Fails early if the server dependency tree required by server/server.js is missing."""

    required_paths = [
        amutorrent_root / "server" / "node_modules" / "express",
        amutorrent_root / "server" / "node_modules" / "better-sqlite3",
    ]
    missing = [path for path in required_paths if not path.exists()]
    if missing:
        missing_display = ", ".join(str(path.relative_to(amutorrent_root)) for path in missing)
        raise RuntimeError(
            "aMuTorrent server dependencies are not installed. "
            f"Missing: {missing_display}. "
            f"Run from {amutorrent_root}: {node_info['install_command']}"
        )


def normalize_lan_bind_address(value: str | None) -> str:
    """Returns the explicit controller bind address for local HTTP surfaces."""

    return rest_api_smoke.require_lan_bind_addr(value, allow_env_fallback=False)


def _browser_host_sort_key(value: str) -> tuple[int, str]:
    """Ranks local adapter addresses for browser access to an all-interface server."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return (99, value)
    if address.version != 4 or address.is_loopback or address.is_link_local:
        return (99, value)
    if value.startswith("192.168."):
        return (0, value)
    if value.startswith("172."):
        second_octet_text = value.split(".", 2)[1]
        if second_octet_text.isdigit() and 16 <= int(second_octet_text) <= 31:
            return (1, value)
    if value.startswith("10."):
        return (2, value)
    return (3, value)


def resolve_browser_lan_host(lan_bind_address: str) -> str:
    """Returns a browser-reachable host for the aMuTorrent controller."""

    return normalize_lan_bind_address(lan_bind_address)


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the VHD fixture configuration for aMuTorrent controller storage."""

    mount_parent = (
        Path(args.mount_root).resolve()
        if args.mount_root
        else paths.output_root / "artifacts" / "admin-mounts"
    )
    reject_windows_temp_path(mount_parent, "admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / f"{SUITE_NAME}.vhdx",
        mount_root=mount_parent / SUITE_NAME,
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


def build_search_mode_specs(search_rounds: int) -> list[dict[str, str]]:
    """Builds repeated search-mode probes for the browser smoke."""

    if search_rounds <= 0:
        raise ValueError("search_rounds must be greater than zero.")

    base_terms = [
        ("automatic", "cafe unicode test"),
        ("server", "linux"),
        ("kad", "ubuntu"),
    ]
    alternate_terms = [
        ("automatic", "café 測試"),
        ("server", "debian"),
        ("kad", "libreoffice"),
    ]
    specs: list[dict[str, str]] = []
    for round_index in range(search_rounds):
        terms = base_terms if round_index % 2 == 0 else alternate_terms
        for search_type, query in terms:
            specs.append(
                {
                    "round": str(round_index + 1),
                    "type": search_type,
                    "query": query,
                }
            )
    return specs


def iter_browser_http_results(value: Any, prefix: str = ""):
    """Yields nested browser fetch results with stable diagnostic names."""

    if isinstance(value, dict):
        if "status" in value and "payload" in value:
            yield prefix or "<root>", value
            return
        for key, nested in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from iter_browser_http_results(nested, name)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from iter_browser_http_results(nested, name)


def is_expected_browser_console_error(entry: dict[str, Any]) -> bool:
    """Returns true for console noise from intentional search-lock retry probes."""

    text = str(entry.get("text", ""))
    location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
    url = str(location.get("url", ""))
    return "409 (Conflict)" in text and "/api/v1/search?wait=false" in url


def unexpected_browser_diagnostics(diagnostics: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Filters expected browser diagnostics that are already covered by HTTP checks."""

    return {
        "console_errors": [
            entry for entry in diagnostics.get("console_errors", [])
            if not is_expected_browser_console_error(entry)
        ],
        "page_errors": list(diagnostics.get("page_errors", [])),
        "request_failures": list(diagnostics.get("request_failures", [])),
    }


def snapshot_items(checks: dict[str, Any], check_name: str) -> list[dict[str, Any]]:
    """Returns unified snapshot items from one browser workflow check."""

    result = checks.get(check_name)
    if not isinstance(result, dict) or int(result.get("status", 0)) >= 300:
        return []
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    items = data.get("items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def iter_snapshot_items(checks: dict[str, Any]):
    """Yields aMuTorrent unified snapshot items from browser workflow checks."""

    for check_name in ("snapshot", "snapshot_after_add", "snapshot_after_delete"):
        for index, item in enumerate(snapshot_items(checks, check_name)):
            yield check_name, index, item


def find_snapshot_item(checks: dict[str, Any], check_name: str, item_hash: str) -> dict[str, Any] | None:
    """Finds one unified snapshot item by lowercase hash."""

    expected = item_hash.lower()
    for item in snapshot_items(checks, check_name):
        if str(item.get("hash") or "").lower() == expected:
            return item
    return None


def category_items(checks: dict[str, Any], check_name: str) -> list[dict[str, Any]]:
    """Returns category rows from one browser workflow category API result."""

    result = checks.get(check_name)
    if not isinstance(result, dict) or int(result.get("status", 0)) >= 300:
        return []
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return []
    rows = payload.get("data")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def find_category_item(checks: dict[str, Any], check_name: str, category_name: str) -> dict[str, Any] | None:
    """Finds one browser-visible category row by name or title."""

    for row in category_items(checks, check_name):
        if row.get("name") == category_name or row.get("title") == category_name:
            return row
    return None


def segment_snapshot_item(checks: dict[str, Any], check_name: str, item_hash: str) -> dict[str, Any] | None:
    """Finds one WebSocket segment-subscribed snapshot item by lowercase hash."""

    expected = item_hash.lower()
    result = checks.get(check_name)
    if not isinstance(result, dict) or int(result.get("status", 0)) >= 300:
        return None
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return None
    item = payload.get("item")
    if not isinstance(item, dict):
        return None
    if str(item.get("hash") or "").lower() == expected:
        return item
    return None


def has_emulebb_detail_basics(item: dict[str, Any] | None) -> bool:
    """Returns true once the non-segment snapshot carries detail hydration fields."""

    if not isinstance(item, dict):
        return False
    if item.get("client") != "emulebb":
        return False
    return isinstance(item.get("partStatus"), list) and isinstance(item.get("peers"), list)


def assert_snapshot_items_are_display_safe(checks: dict[str, Any]) -> None:
    """Rejects snapshot shapes that would render noisy or ambiguous transfer UI."""

    for check_name, index, item in iter_snapshot_items(checks):
        item_name = f"{check_name}.payload.data.items[{index}]"
        progress = item.get("progress")
        if not isinstance(progress, (int, float)) or isinstance(progress, bool):
            raise RuntimeError(f"aMuTorrent browser workflow '{item_name}' has non-numeric progress: {progress!r}")
        if progress < 0 or progress > 100:
            raise RuntimeError(f"aMuTorrent browser workflow '{item_name}' has out-of-range progress: {progress!r}")
        if round(float(progress), 2) != float(progress):
            raise RuntimeError(f"aMuTorrent browser workflow '{item_name}' has noisy progress precision: {progress!r}")
        status = item.get("status")
        if not isinstance(status, str) or not status.strip():
            raise RuntimeError(f"aMuTorrent browser workflow '{item_name}' has missing status: {status!r}")
        if item.get("shared") is True and item.get("downloading") is not True and progress != 100:
            raise RuntimeError(f"aMuTorrent browser workflow '{item_name}' has incomplete shared-file progress: {progress!r}")


def assert_snapshot_stats_are_host_usable(checks: dict[str, Any]) -> None:
    """Rejects host stats payloads that silently degrade on Windows/package hosts."""

    for check_name in ("snapshot_after_add", "snapshot_after_delete"):
        result = checks.get(check_name)
        if not isinstance(result, dict) or int(result.get("status", 0)) >= 300:
            continue
        payload = result.get("payload")
        data = payload.get("data") if isinstance(payload, dict) else None
        stats = data.get("stats") if isinstance(data, dict) else None
        if not isinstance(stats, dict):
            continue
        disk_space = stats.get("diskSpace")
        if isinstance(disk_space, dict):
            if disk_space.get("error"):
                raise RuntimeError(f"aMuTorrent browser workflow '{check_name}' reported disk stats error: {disk_space!r}")
            if not isinstance(disk_space.get("total"), int) or disk_space.get("total", 0) <= 0:
                raise RuntimeError(f"aMuTorrent browser workflow '{check_name}' reported unusable disk stats: {disk_space!r}")
        cpu_usage = stats.get("cpuUsage")
        if isinstance(cpu_usage, dict):
            if cpu_usage.get("error"):
                raise RuntimeError(f"aMuTorrent browser workflow '{check_name}' reported CPU stats error: {cpu_usage!r}")
            percent = cpu_usage.get("percent")
            if not isinstance(percent, (int, float)) or isinstance(percent, bool) or percent < 0 or percent > 100:
                raise RuntimeError(f"aMuTorrent browser workflow '{check_name}' reported unusable CPU stats: {cpu_usage!r}")


def assert_browser_delete_removed_added_download(checks: dict[str, Any]) -> None:
    """Verifies the browser delete workflow removed the synthetic eD2K transfer."""

    if "delete_added_download" not in checks:
        return
    added = find_snapshot_item(checks, "snapshot_after_add", AMUTORRENT_BROWSER_SMOKE_HASH)
    if added is None:
        raise RuntimeError("aMuTorrent browser workflow did not observe the added eD2K transfer before delete.")
    delete_result = checks.get("delete_added_download")
    if not isinstance(delete_result, dict) or int(delete_result.get("status", 0)) >= 300:
        raise RuntimeError(f"aMuTorrent browser delete workflow failed: {delete_result}")
    deleted = find_snapshot_item(checks, "snapshot_after_delete", AMUTORRENT_BROWSER_SMOKE_HASH)
    if deleted is not None:
        raise RuntimeError(f"aMuTorrent browser delete workflow left the added transfer in the snapshot: {deleted}")
    payload = delete_result.get("payload")
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or not any(
        isinstance(result, dict)
        and str(result.get("fileHash") or "").lower() == AMUTORRENT_BROWSER_SMOKE_HASH
        and result.get("success") is True
        for result in results
    ):
        checks["delete_added_download_inferred_success"] = {
            "reason": "snapshot-removed",
            "delete_result": delete_result,
        }


def assert_browser_category_lifecycle(checks: dict[str, Any]) -> None:
    """Verifies the browser category create/delete workflow changed visible state."""

    if "category_create" not in checks:
        return
    expected = checks.get("category_expected")
    category_name = str(expected.get("name") or "") if isinstance(expected, dict) else ""
    if not category_name:
        raise RuntimeError("aMuTorrent browser category workflow did not record the expected category name.")

    create_result = checks.get("category_create")
    create_payload = create_result.get("payload") if isinstance(create_result, dict) else None
    if not isinstance(create_payload, dict) or create_payload.get("success") is not True:
        raise RuntimeError(f"aMuTorrent browser category create did not report success: {create_result}")
    created = find_category_item(checks, "categories_after_create", category_name)
    if created is None:
        raise RuntimeError(f"aMuTorrent browser category create was not visible in the category list: {category_name!r}")

    delete_result = checks.get("category_delete")
    delete_payload = delete_result.get("payload") if isinstance(delete_result, dict) else None
    if not isinstance(delete_payload, dict) or delete_payload.get("success") is not True:
        raise RuntimeError(f"aMuTorrent browser category delete did not report success: {delete_result}")
    deleted = find_category_item(checks, "categories_after_delete", category_name)
    if deleted is not None:
        raise RuntimeError(f"aMuTorrent browser category delete left the category visible: {deleted}")


def assert_search_result_payload(name: str, result: dict[str, Any]) -> None:
    """Verifies one aMuTorrent search-results payload has the expected shape."""

    payload = result.get("payload")
    if not isinstance(payload, dict) or payload.get("type") != "previous-search-results":
        raise RuntimeError(f"aMuTorrent browser workflow '{name}' returned an invalid search results payload: {result}")
    if not isinstance(payload.get("data"), list):
        raise RuntimeError(f"aMuTorrent browser workflow '{name}' search results data is not a list: {result}")


def assert_browser_search_workflows(checks: dict[str, Any]) -> None:
    """Verifies every browser search mode started and returned a valid result shape."""

    if "search_modes" not in checks:
        return
    search_modes = checks.get("search_modes")
    if not isinstance(search_modes, list) or not search_modes:
        raise RuntimeError(f"aMuTorrent browser search workflow did not record search modes: {search_modes!r}")

    allowed_types = {"automatic", "server", "kad"}
    for index, row in enumerate(search_modes):
        name = f"search_modes[{index}]"
        if not isinstance(row, dict):
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' is not an object: {row!r}")
        if row.get("type") not in allowed_types:
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' has invalid search type: {row.get('type')!r}")
        if not str(row.get("round") or "").strip() or not str(row.get("query") or "").strip():
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' has missing search metadata: {row!r}")
        attempt_count = row.get("attempt_count")
        if not isinstance(attempt_count, int) or isinstance(attempt_count, bool) or attempt_count < 1 or attempt_count > 30:
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' has invalid retry count: {attempt_count!r}")

        start = row.get("start")
        if not isinstance(start, dict):
            raise RuntimeError(f"aMuTorrent browser workflow '{name}.start' is missing: {row!r}")
        start_payload = start.get("payload")
        if not isinstance(start_payload, dict) or start_payload.get("type") != "search-started":
            raise RuntimeError(f"aMuTorrent browser workflow '{name}.start' did not start a search: {start}")

        results = row.get("results")
        if not isinstance(results, dict):
            raise RuntimeError(f"aMuTorrent browser workflow '{name}.results' is missing: {row!r}")
        assert_search_result_payload(f"{name}.results", results)

    final_results = checks.get("search_results")
    if isinstance(final_results, dict):
        assert_search_result_payload("search_results", final_results)


def assert_emulebb_detail_hydration(checks: dict[str, Any]) -> None:
    """Verifies the browser-visible snapshot carries eMuleBB detail hydration fields."""

    if "snapshot_after_add" not in checks:
        return
    added = find_snapshot_item(checks, "snapshot_after_add", AMUTORRENT_BROWSER_SMOKE_HASH)
    if added is None:
        raise RuntimeError("aMuTorrent browser workflow did not observe the added eD2K transfer for detail hydration.")
    if added.get("client") != "emulebb":
        raise RuntimeError(f"aMuTorrent browser workflow added transfer through the wrong client type: {added.get('client')!r}")
    for field_name in ("partStatus", "peers"):
        value = added.get(field_name)
        if not isinstance(value, list):
            raise RuntimeError(
                f"aMuTorrent browser workflow did not expose hydrated eMuleBB field "
                f"{field_name!r} as a list: {value!r}"
            )
    segment_added = segment_snapshot_item(checks, "segment_snapshot_after_add", AMUTORRENT_BROWSER_SMOKE_HASH)
    if segment_added is None:
        raise RuntimeError("aMuTorrent browser workflow did not observe the added transfer with segmentData subscribed.")
    for field_name in ("gapStatus", "reqStatus"):
        value = segment_added.get(field_name)
        if not isinstance(value, list):
            raise RuntimeError(
                f"aMuTorrent browser workflow did not expose segment-subscribed eMuleBB field "
                f"{field_name!r} as a list: {value!r}"
            )


def assert_browser_workflow_results(checks: dict[str, Any], diagnostics: dict[str, list[dict[str, Any]]]) -> None:
    """Raises when browser workflow HTTP calls or page diagnostics report failures."""

    unexpected_diagnostics = unexpected_browser_diagnostics(diagnostics)
    if any(unexpected_diagnostics.values()):
        raise RuntimeError(f"aMuTorrent browser diagnostics reported errors: {unexpected_diagnostics}")
    for name, result in iter_browser_http_results(checks):
        if int(result["status"]) >= 400:
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' failed: {result}")
        payload = result.get("payload")
        if isinstance(payload, dict) and payload.get("type") == "error":
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' returned an error payload: {result}")
    assert_snapshot_items_are_display_safe(checks)
    assert_snapshot_stats_are_host_usable(checks)
    assert_browser_category_lifecycle(checks)
    assert_browser_search_workflows(checks)
    assert_emulebb_detail_hydration(checks)
    assert_browser_delete_removed_added_download(checks)


def assert_add_ed2k_result(result: dict[str, Any]) -> None:
    """Raises when aMuTorrent did not accept the synthetic eD2K transfer."""

    if int(result.get("status", 0)) >= 300:
        raise RuntimeError(f"aMuTorrent browser eD2K add request failed: {result}")
    payload = result.get("payload")
    if isinstance(payload, dict) and payload.get("type") == "error":
        raise RuntimeError(f"aMuTorrent browser eD2K add request returned an error payload: {result}")
    rows = payload.get("results") if isinstance(payload, dict) else None
    if isinstance(rows, list) and not any(isinstance(row, dict) and row.get("success") is True for row in rows):
        raise RuntimeError(f"aMuTorrent browser eD2K add request did not report success: {result}")


def run_browser_workflows(
    base_url: str,
    instance_id: str,
    category_path: str,
    *,
    search_rounds: int = DEFAULT_SEARCH_ROUNDS,
    require_search_connected: bool = True,
) -> dict[str, Any]:
    """Drives the critical aMuTorrent workflows through a browser page."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent browser smoke. Install the Python package and browser runtime.") from exc

    checks: dict[str, Any] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        diagnostics: dict[str, list[dict[str, Any]]] = {
            "console_errors": [],
            "page_errors": [],
            "request_failures": [],
        }

        def on_console_message(message: Any) -> None:
            if message.type != "error":
                return
            diagnostics["console_errors"].append(
                {
                    "text": message.text,
                    "type": message.type,
                    "location": message.location,
                }
            )

        def on_page_error(error: Any) -> None:
            diagnostics["page_errors"].append({"text": str(error)})

        def on_request_failed(request: Any) -> None:
            diagnostics["request_failures"].append(
                {
                    "failure": str(request.failure),
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "url": request.url,
                }
            )

        page.on("console", on_console_message)
        page.on("pageerror", on_page_error)
        page.on("requestfailed", on_request_failed)

        try:
            page.goto(base_url, wait_until="domcontentloaded", timeout=30000)
            checks["page_title"] = page.title()

            def fetch_json(path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
                return page.evaluate(
                    """async ({path, method, body}) => {
                        const response = await fetch(path, {
                            method,
                            headers: {'Content-Type': 'application/json'},
                            body: body == null ? undefined : JSON.stringify(body)
                        });
                        const text = await response.text();
                        let payload = null;
                        try { payload = text ? JSON.parse(text) : null; } catch (e) { payload = {parseError: String(e), text}; }
                        return {status: response.status, payload};
                    }""",
                    {"path": path, "method": method, "body": body},
                )

            def wait_for_hydrated_added_snapshot(timeout_seconds: float = 15.0) -> dict[str, Any]:
                deadline = time.monotonic() + timeout_seconds
                last_snapshot: dict[str, Any] | None = None
                while time.monotonic() < deadline:
                    last_snapshot = fetch_json("/api/v1/data/snapshot")
                    added = find_snapshot_item({"snapshot_after_add": last_snapshot}, "snapshot_after_add", AMUTORRENT_BROWSER_SMOKE_HASH)
                    if has_emulebb_detail_basics(added):
                        return last_snapshot
                    page.wait_for_timeout(1000)
                return last_snapshot if last_snapshot is not None else fetch_json("/api/v1/data/snapshot")

            def wait_for_segment_snapshot(timeout_ms: int = 15000) -> dict[str, Any]:
                return page.evaluate(
                    """async ({hash, timeoutMs}) => {
                        const expected = String(hash).toLowerCase();
                        const wsUrl = new URL('/', window.location.href);
                        wsUrl.protocol = wsUrl.protocol === 'https:' ? 'wss:' : 'ws:';
                        return await new Promise(resolve => {
                            let settled = false;
                            let latest = null;
                            const itemsByHash = new Map();
                            let requestTimer = null;
                            const finish = result => {
                                if (settled) return;
                                settled = true;
                                clearTimeout(timeoutTimer);
                                if (requestTimer != null) clearInterval(requestTimer);
                                try { ws.close(); } catch (_) {}
                                resolve(result);
                            };
                            const findItem = items => Array.isArray(items)
                                ? items.find(item => String(item?.hash || '').toLowerCase() === expected)
                                : null;
                            const mergeItem = item => {
                                const hash = String(item?.hash || '').toLowerCase();
                                if (!hash) return null;
                                const merged = {...(itemsByHash.get(hash) || {}), ...item};
                                itemsByHash.set(hash, merged);
                                return merged;
                            };
                            const mergeItems = items => {
                                if (!Array.isArray(items)) return;
                                for (const item of items) mergeItem(item);
                            };
                            const maybeFinish = item => {
                                if (
                                    item
                                    && Array.isArray(item.gapStatus)
                                    && Array.isArray(item.reqStatus)
                                ) {
                                    finish({status: 200, payload: {item}});
                                }
                            };
                            const requestSnapshot = () => {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.send(JSON.stringify({action: 'requestFullSnapshot'}));
                                }
                            };
                            const timeoutTimer = setTimeout(() => {
                                finish({status: 408, payload: latest, error: 'Timed out waiting for segmentData snapshot'});
                            }, timeoutMs);
                            const ws = new WebSocket(wsUrl.href);
                            ws.onopen = () => {
                                ws.send(JSON.stringify({action: 'subscribe', channel: 'segmentData'}));
                                requestSnapshot();
                                requestTimer = setInterval(requestSnapshot, 1000);
                            };
                            ws.onerror = () => {
                                finish({status: 500, payload: latest, error: 'WebSocket error while waiting for segmentData snapshot'});
                            };
                            ws.onmessage = event => {
                                let message = null;
                                try { message = JSON.parse(event.data); } catch (error) { return; }
                                if (message?.type !== 'batch-update') return;
                                latest = message;
                                mergeItems(message?.data?.items);
                                const delta = message?.data?.delta || {};
                                mergeItems(delta?.added);
                                mergeItems(delta?.changed);
                                maybeFinish(findItem(message?.data?.items));
                                maybeFinish(findItem(delta?.changed));
                                maybeFinish(itemsByHash.get(expected));
                            };
                        });
                    }""",
                    {"hash": AMUTORRENT_BROWSER_SMOKE_HASH, "timeoutMs": timeout_ms},
                )

            def start_search_with_retry(search_type: str, query: str, round_number: str) -> dict[str, Any]:
                last_result: dict[str, Any] | None = None
                attempt_count = 0
                for attempt in range(1, 31):
                    attempt_count = attempt
                    result = fetch_json(
                        "/api/v1/search?wait=false",
                        "POST",
                        {"query": query, "type": search_type, "instanceId": instance_id},
                    )
                    last_result = result
                    payload = result.get("payload")
                    message = str(payload.get("message", "")) if isinstance(payload, dict) else ""
                    if not (isinstance(payload, dict) and payload.get("type") == "error" and "Another search is running" in message):
                        break
                    page.wait_for_timeout(1000)

                return {
                    "round": round_number,
                    "type": search_type,
                    "query": query,
                    "start": last_result,
                    "attempt_count": attempt_count,
                    "results": fetch_json(f"/api/v1/search/results?type={search_type}&instanceId={instance_id}"),
                }

            snapshot = fetch_json("/api/v1/data/snapshot")
            if not (200 <= int(snapshot["status"]) < 300):
                raise RuntimeError(f"aMuTorrent snapshot failed: {snapshot}")
            checks["snapshot"] = snapshot

            checks["categories"] = fetch_json("/api/v1/categories")
            smoke_category = f"amutorrent-smoke-{int(time.time())}"
            checks["category_expected"] = {"name": smoke_category, "path": category_path}
            checks["category_create"] = fetch_json(
                "/api/v1/categories",
                "POST",
                {
                    "title": smoke_category,
                    "path": category_path,
                    "comment": "aMuTorrent browser smoke",
                    "color": 255,
                    "priority": 0,
                },
            )
            checks["categories_after_create"] = fetch_json("/api/v1/categories")
            checks["category_delete"] = fetch_json(
                "/api/v1/categories",
                "DELETE",
                {"name": smoke_category},
            )
            checks["categories_after_delete"] = fetch_json("/api/v1/categories")
            checks["add_ed2k"] = fetch_json(
                "/api/v1/downloads/ed2k",
                "POST",
                {
                    "links": [
                        f"ed2k://|file|amutorrent-browser-smoke.bin|{AMUTORRENT_BROWSER_SMOKE_SIZE_BYTES}|"
                        f"{AMUTORRENT_BROWSER_SMOKE_HASH}|/"
                    ],
                    "instanceId": instance_id,
                },
            )
            assert_add_ed2k_result(checks["add_ed2k"])
            checks["snapshot_after_add"] = wait_for_hydrated_added_snapshot()
            added_item = find_snapshot_item(checks, "snapshot_after_add", AMUTORRENT_BROWSER_SMOKE_HASH)
            if added_item is None:
                raise RuntimeError(
                    "aMuTorrent browser smoke did not observe the added eD2K transfer: "
                    + json.dumps(
                        {
                            "add_ed2k": checks.get("add_ed2k"),
                            "snapshot_after_add": checks.get("snapshot_after_add"),
                        },
                        sort_keys=True,
                    )
                )
            checks["segment_snapshot_after_add"] = wait_for_segment_snapshot()
            checks["delete_added_download"] = fetch_json(
                "/api/v1/downloads/delete",
                "POST",
                {
                    "items": [
                        {
                            "fileHash": AMUTORRENT_BROWSER_SMOKE_HASH,
                            "clientType": added_item.get("client") or "emulebb",
                            "instanceId": added_item.get("instanceId") or instance_id,
                            "fileName": added_item.get("name") or "amutorrent-browser-smoke.bin",
                        }
                    ],
                    "deleteFiles": True,
                    "source": "downloads",
                },
            )
            page.wait_for_timeout(1000)
            checks["snapshot_after_delete"] = fetch_json("/api/v1/data/snapshot")
            if require_search_connected:
                checks["search_modes"] = [
                    start_search_with_retry(spec["type"], spec["query"], spec["round"])
                    for spec in build_search_mode_specs(search_rounds)
                ]
                checks["search_results"] = fetch_json(f"/api/v1/search/results?instanceId={instance_id}")
            else:
                checks["search_modes_skipped"] = {
                    "reason": "offline-lan",
                    "message": "P2P search requires eD2K or Kad connectivity.",
                }
            checks["server_list"] = fetch_json("/api/v1/ed2k/servers")
            checks["server_disconnect"] = fetch_json(
                "/api/v1/ed2k/servers/action",
                "POST",
                {"ip": "127.0.0.1", "port": 4661, "serverAction": "disconnect", "instanceId": instance_id},
            )
            checks["shared_dirs_reload"] = fetch_json(
                "/api/v1/ed2k/refresh-shared",
                "POST",
                {"instanceId": instance_id},
            )
            checks["browser_diagnostics"] = diagnostics

            assert_browser_workflow_results(checks, diagnostics)
        finally:
            browser.close()
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-browser-smoke-key")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--vpn-guard-enabled", action="store_true")
    parser.add_argument("--vpn-guard-allowed-public-ip-cidrs", default="")
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--search-rounds", type=int, default=DEFAULT_SEARCH_ROUNDS)
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=DEFAULT_CONTROLLER_VHD_SIZE_MB)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    args = parser.parse_args()
    if args.search_rounds <= 0:
        raise ValueError("--search-rounds must be greater than zero.")

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="amutorrent-browser-smoke",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    fixture_context = None
    fixture_cleanup_inputs: dict[str, Path] | None = None
    admin_storage: dict[str, object] = {"enabled": False}
    incoming_dir: Path | None = None
    temp_dir: Path | None = None
    amutorrent_data_dir: Path | None = None
    if args.admin_volume_fixtures:
        config = build_admin_fixture_config(paths, args)
        fixture_context = create_admin_volume_fixture(config)
        fixture = fixture_context.__enter__()
        assert isinstance(fixture, AdminVolumeFixture)
        fixture_cleanup_inputs = {
            "vhd_path": fixture.vhd_path,
            "drive_root": fixture.drive_root,
            "mount_root": fixture.mount_root,
        }
        topology = build_storage_topology(fixture, SUITE_NAME)
        controller_root = topology.vhd_mount_root / "controller-storage"
        incoming_dir = controller_root / "incoming"
        temp_dir = controller_root / "temp"
        amutorrent_data_dir = controller_root / "amutorrent-data"
        admin_storage = {
            "enabled": True,
            "vhd_path": str(config.vhd_path),
            "mount_root": str(config.mount_root),
            "local_control_root": str(config.local_control_root),
            "size_mb": config.size_mb,
            "keep": config.keep,
            "controller_root": str(controller_root),
            "incoming_dir": str(incoming_dir),
            "temp_dir": str(temp_dir),
            "amutorrent_data_dir": str(amutorrent_data_dir),
            "volume_identities": {
                "drive_letter": asdict(fixture.drive_identity),
                "folder_mount": asdict(fixture.mount_identity),
                "local_control": asdict(fixture.local_control_identity),
            },
        }
    amutorrent_root = resolve_amutorrent_root(paths.workspace_root)
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    node_info = resolve_amutorrent_node()
    if amutorrent_data_dir is None:
        amutorrent_data_dir = artifacts_dir / "amutorrent-data"

    emule_port = choose_listen_port(args.lan_bind_addr)
    amutorrent_port = choose_listen_port(args.lan_bind_addr)
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port(args.lan_bind_addr)
    lan_bind_addr = normalize_lan_bind_address(args.lan_bind_addr)
    lan_host = resolve_browser_lan_host(lan_bind_addr)
    amutorrent_lan_bind_addr = lan_bind_addr
    amutorrent_bind_addr = amutorrent_lan_bind_addr
    amutorrent_browser_host = resolve_browser_lan_host(amutorrent_bind_addr)
    emule_base_url = f"http://{lan_host}:{emule_port}"
    amutorrent_base_url = f"http://{lan_host}:{amutorrent_port}"
    amutorrent_browser_base_url = f"http://{amutorrent_browser_host}:{amutorrent_port}"
    instance_id = f"emulebb-{lan_host}-{emule_port}"

    profile = prepare_profile_base(
        seed_config_dir,
        artifacts_dir,
        shared_dirs=[],
        scenario_id="amutorrent-browser-smoke",
        incoming_dir=incoming_dir,
        temp_dir=temp_dir,
    )
    configure_webserver_profile(Path(profile["config_dir"]), paths.app_exe, args.api_key, emule_port, lan_bind_addr)
    if args.p2p_bind_interface_name.strip():
        rest_api_smoke.apply_p2p_bind_interface_override(
            Path(profile["config_dir"]),
            args.p2p_bind_interface_name,
            vpn_guard_enabled=args.vpn_guard_enabled,
            vpn_guard_allowed_public_ip_cidrs=args.vpn_guard_allowed_public_ip_cidrs,
        )
    else:
        clear_p2p_bind_interface_policy(Path(profile["config_dir"]))

    report: dict[str, Any] = {
        "suite": SUITE_NAME,
        "status": "failed",
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "amutorrent_browser_base_url": amutorrent_browser_base_url,
        "amutorrent_bind_addr": amutorrent_bind_addr,
        "profile_base": str(profile["profile_base"]),
        "config_dir": str(profile["config_dir"]),
        "amutorrent_root": str(amutorrent_root),
        "amutorrent_data_dir": str(amutorrent_data_dir),
        "node": node_info,
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "enable_upnp": True,
        "launch_inputs": {
            "app_exe": str(paths.app_exe),
            "lan_bind_addr": lan_bind_addr,
            "lan_host": lan_host,
            "config_dir": str(profile["config_dir"]),
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "enable_upnp": True,
            "profile_base": str(profile["profile_base"]),
            "seed_config_dir": str(seed_config_dir),
        },
        "network_ready_timeout_seconds": args.network_ready_timeout_seconds,
        "search_rounds": args.search_rounds,
        "admin_volume_fixture": admin_storage,
        "checks": {},
        "cleanup": {},
    }

    app = None
    amutorrent: subprocess.Popen[str] | None = None
    amutorrent_output = None
    amutorrent_log_path = artifacts_dir / "amutorrent-server.log"
    pending_error: Exception | None = None
    try:
        require_amutorrent_server_dependencies(amutorrent_root, node_info)
        app = launch_app(paths.app_exe, Path(profile["profile_base"]))
        report["emule_process_id"] = get_app_process_id(app)
        main_window = wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        report["checks"]["emule_rest_ready"] = wait_for_rest_ready(emule_base_url, args.api_key, args.ready_timeout_seconds)
        require_public_network_ready = bool(args.p2p_bind_interface_name.strip())
        if require_public_network_ready:
            report["checks"]["emule_network_ready"] = wait_for_requested_networks(
                emule_base_url,
                args.api_key,
                args.network_ready_timeout_seconds,
                require_server_connected=True,
                require_kad_connected=True,
            )
        else:
            report["checks"]["emule_network_ready"] = {
                "ready": True,
                "mode": "offline-lan",
                "server_ready": False,
                "kad_ready": False,
                "reason": "P2P bind interface is empty for LAN VM controller smoke.",
            }

        env = os.environ.copy()
        env.update(
            {
                "PORT": str(amutorrent_port),
                "lan_bind_address": amutorrent_bind_addr,
                "AMUTORRENT_DATA_DIR": str(amutorrent_data_dir),
                "WEB_AUTH_ENABLED": "false",
                "SKIP_SETUP_WIZARD": "true",
                "EMULEBB_ENABLED": "true",
                "EMULEBB_HOST": lan_host,
                "EMULEBB_PORT": str(emule_port),
                "EMULEBB_API_KEY": args.api_key,
                "EMULEBB_USE_SSL": "false",
                "EMULEBB_ID": instance_id,
                "EMULEBB_NAME": "eMuleBB Browser Smoke",
            }
        )
        node_path = Path(str(node_info["path"]))
        if node_path.is_absolute():
            env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
        amutorrent_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
        amutorrent = subprocess.Popen(
            [str(node_path), "server/server.js"],
            cwd=str(amutorrent_root),
            env=env,
            stdout=amutorrent_output,
            stderr=subprocess.STDOUT,
        )
        wait_for_http_ok(f"{amutorrent_base_url}/api/config/status", args.ready_timeout_seconds)
        report["amutorrent_process_id"] = amutorrent.pid
        category_path = live_common.win_path(Path(profile["incoming_dir"]), trailing_slash=True)
        report["checks"]["browser_workflows"] = run_browser_workflows(
            amutorrent_browser_base_url,
            instance_id,
            category_path,
            search_rounds=args.search_rounds,
            require_search_connected=require_public_network_ready,
        )
        report["status"] = "passed"
    except Exception as exc:
        pending_error = exc
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if amutorrent is not None:
            amutorrent.terminate()
            try:
                amutorrent.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                amutorrent.kill()
                amutorrent.communicate(timeout=10)
        if amutorrent_output is not None:
            amutorrent_output.close()
            report["cleanup"]["amutorrent_log"] = str(amutorrent_log_path)
            if amutorrent_log_path.exists():
                report["cleanup"]["amutorrent_output_tail"] = amutorrent_log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        if app is not None:
            try:
                close_app_cleanly(app)
                report["cleanup"]["emule_closed"] = True
            except Exception as exc:
                app.kill()
                report["cleanup"]["emule_closed"] = False
                report["cleanup"]["emule_killed"] = True
                report["cleanup"]["emule_close_error"] = repr(exc)
        if fixture_context is not None:
            try:
                fixture_context.__exit__(None, None, None)
                report["cleanup"]["admin_fixture_context_closed"] = True
            except Exception as exc:
                report["cleanup"]["admin_fixture_context_closed"] = False
                report["cleanup"]["admin_fixture_close_error"] = repr(exc)
                if report.get("status") == "passed":
                    report["status"] = "failed"
            if fixture_cleanup_inputs is not None:
                report["fixture_cleanup"] = cleanup_audit.audit_fixture_cleanup(
                    vhd_path=fixture_cleanup_inputs["vhd_path"],
                    drive_root=fixture_cleanup_inputs["drive_root"],
                    mount_root=fixture_cleanup_inputs["mount_root"],
                    keep_vhd=args.keep_admin_fixtures,
                )
                if report["fixture_cleanup"].get("status") != "passed":
                    report["status"] = "failed"
        write_json(artifacts_dir / "amutorrent-browser-smoke-result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    if pending_error is not None:
        raise pending_error
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
