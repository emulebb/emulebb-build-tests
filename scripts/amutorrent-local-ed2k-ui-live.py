"""Runs deterministic local ED2K aMuTorrent UI downloads against eMuleBB and aMule."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES  # noqa: E402
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


dtt = load_local_module("deterministic_two_client_transfer_amutorrent_ui", "deterministic-two-client-transfer.py")
amule_transfer = load_local_module("deterministic_amule_transfer_amutorrent_ui", "deterministic-amule-transfer.py")
amutorrent_smoke = load_local_module("amutorrent_browser_smoke_local_ed2k", "amutorrent-browser-smoke.py")
amutorrent_ui = load_local_module("amutorrent_emulebb_ui_live_local_ed2k", "amutorrent-emulebb-ui-live.py")

harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "amutorrent-local-ed2k-ui-live"
API_KEY = "amutorrent-local-ed2k-ui-live-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]
CLIENT04 = CLIENT_IDENTITIES["amule"]
AMUTORRENT_EMULEBB_ID = CLIENT01.profile_id
AMUTORRENT_AMULE_ID = CLIENT04.profile_id


def build_parser() -> argparse.ArgumentParser:
    """Builds the standalone local ED2K aMuTorrent UI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone local ED2K aMuTorrent UI arguments."""

    return build_parser().parse_args(argv)


def choose_ports() -> dict[str, int]:
    """Allocates local ED2K, eMuleBB, aMule, and aMuTorrent ports."""

    ports = amule_transfer.choose_amule_ports(dtt.choose_distinct_ports())
    used = set(ports.values())
    for name in ("amutorrent",):
        for _ in range(100):
            candidate = rest_smoke.choose_listen_port()
            if candidate not in used and dtt.is_port_available(candidate):
                ports[name] = candidate
                used.add(candidate)
                break
        else:
            raise RuntimeError(f"Could not allocate port for {name}.")
    return ports


def build_local_amutorrent_environment(
    *,
    base_env: dict[str, str],
    amutorrent_port: int,
    node_path: Path,
    data_dir: Path,
    emulebb_rest_port: int,
    emulebb_api_key: str,
    amule_ec_port: int,
    amule_password: str,
) -> dict[str, str]:
    """Builds a workspace-local aMuTorrent environment with both ED2K clients enabled."""

    reject_windows_temp_path(data_dir, "aMuTorrent local ED2K data directory")
    data_dir.mkdir(parents=True, exist_ok=True)
    env = dict(base_env)
    env.update(
        {
            "PORT": str(amutorrent_port),
            "BIND_ADDRESS": "127.0.0.1",
            "AMUTORRENT_DATA_DIR": str(data_dir.resolve()),
            "WEB_AUTH_ENABLED": "false",
            "SKIP_SETUP_WIZARD": "true",
            "EMULEBB_ENABLED": "true",
            "EMULEBB_HOST": "127.0.0.1",
            "EMULEBB_PORT": str(emulebb_rest_port),
            "EMULEBB_API_KEY": emulebb_api_key,
            "EMULEBB_USE_SSL": "false",
            "EMULEBB_ID": AMUTORRENT_EMULEBB_ID,
            "EMULEBB_NAME": CLIENT01.profile_id,
            "AMULE_ENABLED": "true",
            "AMULE_HOST": "127.0.0.1",
            "AMULE_PORT": str(amule_ec_port),
            "AMULE_PASSWORD": amule_password,
            "AMULE_ID": AMUTORRENT_AMULE_ID,
            "AMULE_NAME": CLIENT04.profile_id,
        }
    )
    if node_path.is_absolute():
        env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
    return env


def wait_for_amutorrent_clients(
    *,
    base_url: str,
    expected: dict[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits until aMuTorrent health reports all expected client instances connected."""

    observations: list[dict[str, Any]] = []

    def probe() -> dict[str, Any] | None:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=2.0) as response:
                import json

                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            observations.append({"error": repr(exc), "observed_at": round(time.time(), 3)})
            return None
        clients = payload.get("clients") if isinstance(payload, dict) else {}
        row = {
            "observed_at": round(time.time(), 3),
            "clients": clients,
        }
        observations.append(row)
        if not isinstance(clients, dict):
            return None
        for instance_id, client_type in expected.items():
            client = clients.get(instance_id)
            if not isinstance(client, dict):
                return None
            if client.get("type") != client_type or client.get("connected") is not True:
                return None
        return payload

    result = live_common.wait_for(
        probe,
        timeout=timeout_seconds,
        interval=1.0,
        description="aMuTorrent local ED2K clients",
    )
    return {"payload": result, "observations": observations[-10:]}


def fetch_page_json(page: Any, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one same-origin browser fetch and returns status plus parsed payload."""

    return amutorrent_ui.fetch_page_json(page, path, method, body)


def require_browser_http_ok(name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Returns a browser fetch payload or raises with diagnostic context."""

    return amutorrent_ui.require_browser_http_ok(name, result)


def wait_for_snapshot_item(
    page: Any,
    *,
    transfer_hash: str,
    instance_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits until the unified aMuTorrent snapshot contains one instance-scoped item."""

    expected_hash = transfer_hash.lower()

    def resolve() -> dict[str, Any] | None:
        snapshot = fetch_page_json(page, "/api/v1/data/snapshot")
        payload = require_browser_http_ok("snapshot-item", snapshot)
        data = payload.get("data")
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise RuntimeError(f"aMuTorrent snapshot did not contain an item list: {snapshot!r}")
        for item in items:
            if not isinstance(item, dict):
                continue
            item_hash = str(item.get("hash") or item.get("fileHash") or "").lower()
            if item_hash == expected_hash and item.get("instanceId") == instance_id:
                return item
        return None

    return live_common.wait_for(
        resolve,
        timeout=timeout_seconds,
        interval=1.0,
        description=f"aMuTorrent snapshot item {expected_hash} on {instance_id}",
    )


def click_ed2k_instance_button(page: Any, instance_id: str) -> None:
    """Clicks the visible Add Download ED2K instance button by stable instance hook."""

    selector = f'[data-testid="emulebb-add-download-modal"] [data-testid="ed2k-instance-{instance_id}"]'
    button = page.locator(selector).first
    button.wait_for(timeout=15000)
    button.click()
    page.locator(f'{selector}[data-selected="true"]:visible').first.wait_for(timeout=15000)
    page.locator(
        f'[data-testid="emulebb-add-download-modal"][data-selected-ed2k-instance="{instance_id}"]'
    ).wait_for(timeout=15000)


def add_download_through_visible_modal(
    page: Any,
    *,
    link: str,
    transfer_hash: str,
    instance_id: str,
    instance_name: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Adds one ED2K link through visible aMuTorrent controls for a target instance."""

    amutorrent_ui.click_visible_test_id(page, "nav-downloads")
    page.locator('[data-testid="view-downloads"]').wait_for(timeout=15000)
    amutorrent_ui.click_visible_test_id(page, "emulebb-downloads-add")
    page.locator('[data-testid="emulebb-add-download-modal"]').wait_for(timeout=15000)
    page.locator('[data-testid="emulebb-add-download-links"]').fill(link)
    click_ed2k_instance_button(page, instance_id)
    page.locator('[data-testid="emulebb-add-download-submit"]').click()
    try:
        page.locator('[data-testid="emulebb-add-download-modal"]').wait_for(state="detached", timeout=15000)
    except Exception:
        page.locator('[data-testid="emulebb-add-download-modal"]').wait_for(state="hidden", timeout=15000)
    item = wait_for_snapshot_item(
        page,
        transfer_hash=transfer_hash,
        instance_id=instance_id,
        timeout_seconds=timeout_seconds,
    )
    return {
        "instance_id": instance_id,
        "instance_name": instance_name,
        "snapshot_item": {
            "hash": item.get("hash") or item.get("fileHash"),
            "name": item.get("name") or item.get("fileName"),
            "client": item.get("client"),
            "status": item.get("status"),
            "progress": item.get("progress"),
            "instanceId": item.get("instanceId"),
        },
    }


def run_browser_download_matrix(
    *,
    base_url: str,
    link: str,
    transfer_hash: str,
    artifacts_dir: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Drives the visible aMuTorrent UI for both local ED2K client targets."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent local ED2K UI live proof.") from exc

    diagnostics: dict[str, list[dict[str, Any]]] = {
        "console_errors": [],
        "page_errors": [],
        "request_failures": [],
    }
    browser_profile = artifacts_dir / "browser-profile"
    reject_windows_temp_path(browser_profile, "aMuTorrent local ED2K browser profile")
    browser_profile.mkdir(parents=True, exist_ok=True)
    checks: dict[str, Any] = {"browser_profile": str(browser_profile), "browser_diagnostics": diagnostics}

    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            user_data_dir=str(browser_profile),
            headless=True,
            viewport={"width": 1366, "height": 900},
        )
        page = context.pages[0] if context.pages else context.new_page()
        amutorrent_ui.install_browser_diagnostics(page, diagnostics)
        try:
            page.goto(base_url, wait_until="domcontentloaded", timeout=30000)
            checks["dismissed_version_modal"] = amutorrent_ui.dismiss_first_run_version_modal(page)
            page.locator('[data-testid="view-home"]').wait_for(timeout=30000)
            checks["health"] = require_browser_http_ok("health", fetch_page_json(page, "/health"))
            checks["view_navigation"] = amutorrent_ui.navigate_and_verify_views(page)
            checks["add_downloads"] = [
                add_download_through_visible_modal(
                    page,
                    link=link,
                    transfer_hash=transfer_hash,
                    instance_id=AMUTORRENT_EMULEBB_ID,
                    instance_name=CLIENT01.profile_id,
                    timeout_seconds=timeout_seconds,
                ),
                add_download_through_visible_modal(
                    page,
                    link=link,
                    transfer_hash=transfer_hash,
                    instance_id=AMUTORRENT_AMULE_ID,
                    instance_name=CLIENT04.profile_id,
                    timeout_seconds=timeout_seconds,
                ),
            ]
            screenshot = artifacts_dir / "amutorrent-local-ed2k-ui-final.png"
            page.screenshot(path=str(screenshot), full_page=True)
            checks["screenshots"] = {"final": str(screenshot)}
            amutorrent_ui.assert_no_unexpected_browser_diagnostics(diagnostics)
            return checks
        except Exception:
            failure = artifacts_dir / "amutorrent-local-ed2k-ui-failure.png"
            try:
                page.screenshot(path=str(failure), full_page=True)
                checks["screenshots"] = {"failure": str(failure)}
            except Exception:
                pass
            raise
        finally:
            context.close()


def stop_amutorrent(process: subprocess.Popen[str] | None) -> None:
    """Stops the aMuTorrent Node process."""

    if process is None:
        return
    process.terminate()
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)


def write_reports(paths, report: dict[str, object]) -> None:
    """Writes suite-specific and generic JSON reports."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "amutorrent-local-ed2k-ui-live-result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the deterministic local ED2K aMuTorrent UI suite."""

    args = parse_args(argv)
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
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    amule_process: subprocess.Popen | None = None
    amutorrent_process: subprocess.Popen[str] | None = None
    amutorrent_output = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    current_phase = "initializing"

    try:
        amule_client = amule_transfer.resolve_required_amule(paths, args)
        amule_daemon_exe = amule_client.executable
        amule_control_exe = amule_client.control_executable
        report["amule_inventory"] = amule_client.as_report()

        workspace_repo_root = amutorrent_smoke.find_workspace_repo_root(paths.workspace_root)
        amutorrent_root = workspace_repo_root / "repos" / "amutorrent"
        node_info = amutorrent_smoke.resolve_amutorrent_node()
        node_path = Path(str(node_info["path"]))
        report["node"] = node_info
        amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
        report["checks"]["amutorrent_frontend_bundle"] = amutorrent_ui.build_and_verify_frontend_bundle(amutorrent_root, node_path)

        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = choose_ports()
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "ports": ports,
        }

        ed2k_repo = dtt.resolve_ed2k_server_repo(paths.workspace_root, args.ed2k_server_repo)
        ed2k_exe = dtt.resolve_ed2k_server_exe(paths.workspace_root, args.ed2k_server_exe)
        report["checks"]["server_build"] = dtt.build_ed2k_server_binary(ed2k_repo, ed2k_exe)

        server_dir = paths.source_artifacts_dir / "ed2k-server"
        catalog_path = server_dir / "catalog.json"
        config_path = server_dir / "config.json"
        dtt.write_empty_catalog(catalog_path)
        report["ed2k_server"] = dtt.build_server_config(
            config_path,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            catalog_path=catalog_path,
            token=args.api_key,
        )
        current_phase = "start_ed2k_server"
        server_process = dtt.start_ed2k_server(ed2k_exe, config_path, server_dir / "server.log")
        admin_base_url = f"http://127.0.0.1:{ports['ed2k_admin']}"
        report["checks"]["ed2k_server_health"] = dtt.wait_for_admin_health(admin_base_url, 30.0)

        fixture_dir = paths.source_artifacts_dir / "seed-shared"
        fixture_file = fixture_dir / "amutorrent-local-ed2k-ui.bin"
        fixture_sha256 = dtt.write_fixture_file(fixture_file, args.fixture_size_bytes)
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
        }

        current_phase = "prepare_profiles"
        client1 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [],
            CLIENT01.profile_id,
        )
        client2 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [],
            CLIENT02.profile_id,
        )
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=paths.source_artifacts_dir / "clients" / CLIENT04.profile_id,
            profile_id=CLIENT04.profile_id,
            nick=CLIENT04.nick,
            tcp_port=ports["amule_tcp"],
            udp_port=ports["amule_udp"],
            ec_port=ports["amule_ec"],
            advertised_address=p2p_address,
        )
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
        dtt.configure_client_profile(
            config_dir=Path(client1["config_dir"]),
            app_exe=paths.app_exe,
            nick=CLIENT01.nick,
            tcp_port=ports["client1_tcp"],
            udp_port=ports["client1_udp"],
            ed2k_enabled=True,
            autoconnect=False,
            rest_api_key=args.api_key,
            rest_port=ports["client1_rest"],
            rest_bind_addr=args.bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        dtt.configure_client_profile(
            config_dir=Path(client2["config_dir"]),
            app_exe=client2_app_exe,
            nick=CLIENT02.nick,
            tcp_port=ports["client2_tcp"],
            udp_port=ports["client2_udp"],
            ed2k_enabled=True,
            autoconnect=True,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        for config_dir in (Path(client1["config_dir"]), Path(client2["config_dir"]), amule_profile.config_dir):
            dtt.write_server_met(
                config_dir / "server.met",
                address=p2p_address,
                port=ports["ed2k_tcp"],
                name="emulebb-local-e2e",
            )
        report["profiles"] = {
            CLIENT01.profile_id: {
                "client_key": CLIENT01.key,
                "nick": CLIENT01.nick,
                "profile_base": str(client1["profile_base"]),
                "config_dir": str(client1["config_dir"]),
                "incoming_dir": str(client1["incoming_dir"]),
                "temp_dir": str(client1["temp_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client1["config_dir"])),
            },
            CLIENT02.profile_id: {
                "client_key": CLIENT02.key,
                "nick": CLIENT02.nick,
                "profile_base": str(client2["profile_base"]),
                "config_dir": str(client2["config_dir"]),
                "incoming_dir": str(client2["incoming_dir"]),
                "temp_dir": str(client2["temp_dir"]),
                "app_exe": str(client2_app_exe),
                "preferences": dtt.read_preferences_snapshot(Path(client2["config_dir"])),
            },
            CLIENT04.profile_id: amule_profile.as_report(),
        }

        export_link_path = paths.source_artifacts_dir / "seed-export" / "fixture.ed2k.txt"
        ready_path = paths.source_artifacts_dir / "seed-export" / "ready.txt"
        export_link_path.parent.mkdir(parents=True, exist_ok=True)

        current_phase = "launch_seed_harness"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=True,
            extra_args=dtt.build_client2_harness_args(
                ready_path=ready_path,
                fixture_file=fixture_file,
                export_link_path=export_link_path,
                source_ip=p2p_address,
            ),
        )
        report["checks"]["seed_ready"] = dtt.wait_for_file(ready_path, 90.0, "local ED2K seed harness ready file")
        exported_link = dtt.wait_for_exported_link(export_link_path, args.link_export_timeout_seconds)
        link_info = dtt.parse_ed2k_file_link(exported_link)
        transfer_hash = str(link_info["hash"])
        report["checks"]["seed_exported_link"] = {"path": str(export_link_path), "link": exported_link, "parsed": link_info}
        report["checks"]["seed_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT02.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["seed_server_file"] = dtt.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "launch_download_clients"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=True)
        client1_base_url = f"http://{args.bind_addr}:{ports['client1_rest']}"
        report["checks"]["client1_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(client1_base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["client1_server_connect"] = dtt.add_and_connect_server(
            client1_base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["client1_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT01.nick,
            args.server_connect_timeout_seconds,
        )

        amule_process = amule_harness.start_amuled(amule_daemon_exe, amule_profile)
        report["checks"]["amule_ec_ready"] = amule_harness.wait_for_ec_ready(
            amule_control_exe,
            amule_profile,
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["amule_add_server"] = amule_transfer.amule_command_summary(
            amule_harness.run_amulecmd(
                amule_control_exe,
                amule_profile,
                f"Add {amule_harness.build_server_link(p2p_address, ports['ed2k_tcp'])}",
                timeout_seconds=30.0,
            )
        )
        report["checks"]["amule_connect_server"] = amule_transfer.amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Connect ed2k", timeout_seconds=30.0)
        )
        report["checks"]["amule_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT04.nick,
            args.server_connect_timeout_seconds,
        )

        current_phase = "launch_amutorrent"
        amutorrent_data_dir = paths.source_artifacts_dir / "amutorrent-data"
        amutorrent_log_path = paths.source_artifacts_dir / "amutorrent-server.log"
        env = build_local_amutorrent_environment(
            base_env=os.environ,
            amutorrent_port=ports["amutorrent"],
            node_path=node_path,
            data_dir=amutorrent_data_dir,
            emulebb_rest_port=ports["client1_rest"],
            emulebb_api_key=args.api_key,
            amule_ec_port=ports["amule_ec"],
            amule_password=amule_profile.ec_password,
        )
        amutorrent_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
        amutorrent_process = subprocess.Popen(
            [str(node_path), "server/server.js"],
            cwd=str(amutorrent_root),
            env=env,
            stdout=amutorrent_output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        amutorrent_base_url = f"http://127.0.0.1:{ports['amutorrent']}"
        amutorrent_smoke.wait_for_http_ok(f"{amutorrent_base_url}/api/config/status", args.rest_ready_timeout_seconds)
        report["amutorrent"] = {
            "base_url": amutorrent_base_url,
            "data_dir": str(amutorrent_data_dir),
            "process_id": amutorrent_process.pid,
        }
        report["checks"]["amutorrent_clients_connected"] = wait_for_amutorrent_clients(
            base_url=amutorrent_base_url,
            expected={AMUTORRENT_EMULEBB_ID: "emulebb", AMUTORRENT_AMULE_ID: "amule"},
            timeout_seconds=args.rest_ready_timeout_seconds,
        )

        current_phase = "browser_ui_downloads"
        report["checks"]["browser_ui"] = run_browser_download_matrix(
            base_url=amutorrent_base_url,
            link=exported_link,
            transfer_hash=transfer_hash,
            artifacts_dir=paths.source_artifacts_dir,
            timeout_seconds=args.rest_ready_timeout_seconds,
        )

        current_phase = "verify_completed_files"
        emulebb_completed_path = Path(client1["incoming_dir"]) / str(link_info["name"])
        amule_completed_path = amule_profile.incoming_dir / str(link_info["name"])
        report["checks"]["emulebb_completed_file"] = dtt.wait_for_completed_file(
            emulebb_completed_path,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
            snapshot_callback=lambda: dtt.collect_client1_transfer_snapshot(
                base_url=client1_base_url,
                api_key=args.api_key,
                transfer_hash=transfer_hash,
                incoming_path=emulebb_completed_path,
                temp_dir=Path(client1["temp_dir"]),
                hash_limit_bytes=max(int(link_info["size"]), args.fixture_size_bytes),
            ),
        )
        report["checks"]["amule_completed_file"] = dtt.wait_for_completed_file(
            amule_completed_path,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        report["checks"]["ed2k_server_stats_final"] = dtt.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, dtt.TransferCompletionTimeout):
            report["checks"]["transfer_completion_timeout"] = {"observations": exc.observations}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        stop_amutorrent(amutorrent_process)
        if amutorrent_output is not None:
            amutorrent_output.close()
            amutorrent_log_path = paths.source_artifacts_dir / "amutorrent-server.log"
            cleanup["amutorrent_log"] = str(amutorrent_log_path)
            if amutorrent_log_path.exists():
                cleanup["amutorrent_output_tail"] = amutorrent_log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        if client1_app is not None:
            try:
                live_common.close_app_cleanly(client1_app)
                cleanup[CLIENT01.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[CLIENT01.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        if client2_app is not None:
            try:
                live_common.close_app_cleanly(client2_app)
                cleanup[CLIENT02.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[CLIENT02.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        try:
            cleanup[CLIENT04.profile_id] = amule_transfer.shutdown_amule(amule_control_exe, amule_profile)
        except Exception as exc:
            cleanup[CLIENT04.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        dtt.stop_process(amule_process)
        dtt.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        write_reports(paths, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
