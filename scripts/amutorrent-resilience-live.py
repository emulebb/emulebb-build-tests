"""Runs aMuTorrent resilience live E2E checks against eMuleBB REST."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_wire_inputs


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
amutorrent_smoke = load_local_module("amutorrent_browser_smoke_helpers", "amutorrent-browser-smoke.py")
amutorrent_session = load_local_module("amutorrent_interactive_session_helpers", "amutorrent-interactive-session.py")
amutorrent_clean = load_local_module("amutorrent_clean_startup_helpers", "amutorrent-clean-startup.py")

choose_listen_port = rest_api_smoke.choose_listen_port
close_app_cleanly = live_common.close_app_cleanly
get_app_process_id = rest_api_smoke.get_app_process_id
launch_app = live_common.launch_app
prepare_profile_base = live_common.prepare_profile_base
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
wait_for_requested_networks = rest_api_smoke.wait_for_requested_networks
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready
write_json = live_common.write_json


def observe_optional_main_window(app: Any, *, timeout: float = 5.0) -> dict[str, Any]:
    """Returns best-effort eMule main-window evidence without failing tray-only runs."""

    try:
        window = wait_for_main_window(app, timeout=timeout)
    except Exception as exc:
        return {"observed": False, "reason": str(exc)}

    return {
        "observed": True,
        "title": window.window_text(),
        "handle": int(window.handle),
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds the aMuTorrent resilience live argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-resilience-key")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--rest-webserver-scheme", choices=["http", "https"], default="https")
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--reconnect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--live-wire-inputs-file", default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)))
    return parser


def resolve_live_wire_inputs_path(repo_root: Path, raw_path: str | None) -> Path:
    """Resolves live-wire inputs from repo-relative or workspace-relative paths."""

    return amutorrent_clean.resolve_clean_live_wire_inputs_path(repo_root, raw_path)


def fetch_page_json(page: Any, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one same-origin browser fetch and returns status plus parsed payload."""

    return amutorrent_clean.fetch_page_json(page, path, method, body)


def require_browser_http_ok(name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Returns a browser fetch payload or raises with diagnostic context."""

    return amutorrent_clean.require_browser_http_ok(name, result)


def is_config_test_failure(result: dict[str, Any]) -> bool:
    """Reports whether a configuration-test response cleanly rejected a connection."""

    if not isinstance(result, dict) or int(result.get("status", 0)) >= 400:
        return False
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return False
    emulebb = payload.get("results", {}).get("emulebb") if isinstance(payload.get("results"), dict) else None
    if not isinstance(emulebb, dict):
        return False
    return payload.get("success") is False and emulebb.get("success") is False


def build_emulebb_config_payload(*, host: str, port: int, api_key: str, use_ssl: bool = False, enabled: bool = True) -> dict[str, Any]:
    """Builds the eMuleBB section accepted by aMuTorrent config test/save endpoints."""

    return {
        "enabled": enabled,
        "host": host,
        "port": port,
        "apiKey": api_key,
        "useSsl": use_ssl,
        "path": "",
    }


def find_client_config(config_payload: dict[str, Any], *, instance_id: str) -> dict[str, Any]:
    """Finds one persisted client config from aMuTorrent's current configuration."""

    clients = config_payload.get("clients")
    if not isinstance(clients, list):
        raise RuntimeError(f"aMuTorrent current config did not contain a client list: {config_payload!r}")
    for client in clients:
        if isinstance(client, dict) and client.get("id") == instance_id:
            return dict(client)
    raise RuntimeError(f"aMuTorrent current config did not contain expected eMuleBB instance {instance_id!r}.")


def build_saved_config_with_key(
    current_config: dict[str, Any],
    *,
    instance_id: str,
    host: str,
    port: int,
    api_key: str,
    use_ssl: bool = False,
) -> dict[str, Any]:
    """Returns a complete config object with one eMuleBB client key replaced."""

    updated = dict(current_config)
    updated_clients: list[dict[str, Any]] = []
    replaced = False
    clients = current_config.get("clients")
    if not isinstance(clients, list):
        raise RuntimeError(f"aMuTorrent current config did not contain clients: {current_config!r}")
    for client in clients:
        if not isinstance(client, dict):
            continue
        next_client = dict(client)
        if next_client.get("id") == instance_id:
            next_client.update(build_emulebb_config_payload(host=host, port=port, api_key=api_key, use_ssl=use_ssl))
            next_client["id"] = instance_id
            next_client["type"] = "emulebb"
            replaced = True
        updated_clients.append(next_client)
    if not replaced:
        raise RuntimeError(f"Could not update missing eMuleBB instance {instance_id!r}.")
    updated["clients"] = updated_clients
    return updated


def wait_for_transfer_absent(page: Any, transfer_hash: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until a transfer hash disappears from aMuTorrent's unified snapshot."""

    expected = transfer_hash.lower()

    def resolve() -> dict[str, Any] | None:
        snapshot = fetch_page_json(page, "/api/v1/data/snapshot")
        payload = require_browser_http_ok("snapshot-after-cleanup", snapshot)
        data = payload.get("data")
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise RuntimeError(f"aMuTorrent snapshot did not contain an item list: {snapshot!r}")
        if any(str(item.get("hash") or item.get("fileHash") or "").lower() == expected for item in items if isinstance(item, dict)):
            return None
        return snapshot

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description="aMuTorrent transfer cleanup")


def run_bad_credential_recovery(
    page: Any,
    *,
    emule_host: str,
    emule_port: int,
    api_key: str,
    use_ssl: bool,
    instance_id: str,
) -> dict[str, Any]:
    """Verifies a bad eMuleBB key fails cleanly and a valid key recovers."""

    current = fetch_page_json(page, "/api/config/current")
    current_payload = require_browser_http_ok("current-config-before-bad-key", current)
    find_client_config(current_payload, instance_id=instance_id)

    bad_key = api_key + "-invalid"
    bad_test = fetch_page_json(
        page,
        "/api/config/test",
        "POST",
        {"emulebb": build_emulebb_config_payload(host=emule_host, port=emule_port, api_key=bad_key, use_ssl=use_ssl)},
    )
    if not is_config_test_failure(bad_test):
        raise RuntimeError(f"aMuTorrent bad-key connection test did not fail cleanly: {bad_test!r}")

    invalid_config = build_saved_config_with_key(
        current_payload,
        instance_id=instance_id,
        host=emule_host,
        port=emule_port,
        api_key=bad_key,
        use_ssl=use_ssl,
    )
    bad_save = fetch_page_json(page, "/api/config/save", "POST", invalid_config)
    require_browser_http_ok("save-bad-key-config", bad_save)
    disconnected_snapshot = fetch_page_json(page, "/api/v1/data/snapshot")

    restored_config = build_saved_config_with_key(
        current_payload,
        instance_id=instance_id,
        host=emule_host,
        port=emule_port,
        api_key=api_key,
        use_ssl=use_ssl,
    )
    restore_save = fetch_page_json(page, "/api/config/save", "POST", restored_config)
    require_browser_http_ok("restore-valid-key-config", restore_save)
    valid_test = fetch_page_json(
        page,
        "/api/config/test",
        "POST",
        {"emulebb": build_emulebb_config_payload(host=emule_host, port=emule_port, api_key=api_key, use_ssl=use_ssl)},
    )
    valid_payload = require_browser_http_ok("valid-key-connection-test", valid_test)
    if valid_payload.get("success") is not True:
        raise RuntimeError(f"aMuTorrent valid-key recovery test did not pass: {valid_test!r}")

    return {
        "bad_test": bad_test,
        "bad_save": bad_save,
        "disconnected_snapshot_status": disconnected_snapshot.get("status"),
        "restore_save": restore_save,
        "valid_test": valid_test,
    }


def run_concurrent_search_conflict(
    page: Any,
    *,
    instance_id: str,
    inputs: live_wire_inputs.LiveWireInputs,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Verifies overlapping aMuTorrent searches report conflict without breaking recovery."""

    term_index, query = live_wire_inputs.select_daily(inputs.generic_open_terms)
    alternate_query = f"{query} conflict"
    start = fetch_page_json(
        page,
        "/api/v1/search?wait=false",
        "POST",
        {"query": query, "type": "automatic", "instanceId": instance_id},
    )
    require_browser_http_ok("conflict-search-start", start)
    conflict = fetch_page_json(
        page,
        "/api/v1/search?wait=false",
        "POST",
        {"query": alternate_query, "type": "automatic", "instanceId": instance_id},
    )
    conflict_payload = conflict.get("payload")
    conflict_message = str(conflict_payload.get("message", "")) if isinstance(conflict_payload, dict) else ""
    if int(conflict.get("status", 0)) != 409 and "Another search is running" not in conflict_message:
        raise RuntimeError(f"aMuTorrent concurrent search did not report the expected conflict: {conflict!r}")

    candidate, observations = amutorrent_clean.wait_for_amutorrent_search_candidate(
        page,
        instance_id=instance_id,
        search_type="automatic",
        timeout_seconds=timeout_seconds,
    )
    return {
        "term_selection": live_wire_inputs.redact_term_selection(term_index, inputs.generic_open_terms, source="generic_open"),
        "start": {"status": start.get("status"), "payload": start.get("payload")},
        "conflict": {"status": conflict.get("status"), "payload": conflict.get("payload")},
        "candidate": amutorrent_clean.summarize_amutorrent_candidate(candidate),
        "observations": observations,
    }


def run_live_transfer_cleanup(
    page: Any,
    *,
    emule_base_url: str,
    api_key: str,
    instance_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Downloads one safe live search result and deletes only that harness-created transfer."""

    candidate, observations = amutorrent_clean.wait_for_amutorrent_search_candidate(
        page,
        instance_id=instance_id,
        search_type="automatic",
        timeout_seconds=timeout_seconds,
    )
    transfer_hash = str(candidate.get("fileHash") or candidate.get("hash") or "").strip().lower()
    file_name = str(candidate.get("fileName") or candidate.get("name") or "amutorrent-live-transfer").strip()
    download = fetch_page_json(
        page,
        "/api/v1/downloads/search-results",
        "POST",
        {"fileHashes": [transfer_hash], "categoryId": 0, "instanceId": instance_id},
    )
    require_browser_http_ok("resilience-download-trigger", download)
    materialized = amutorrent_clean.wait_for_emule_transfer_materialized(
        emule_base_url=emule_base_url,
        api_key=api_key,
        transfer_hash=transfer_hash,
        timeout_seconds=timeout_seconds,
    )
    delete_result = fetch_page_json(
        page,
        "/api/v1/downloads/delete",
        "POST",
        {
            "items": [
                {
                    "fileHash": transfer_hash,
                    "clientType": "emulebb",
                    "instanceId": instance_id,
                    "fileName": file_name,
                }
            ],
            "deleteFiles": True,
            "source": "downloads",
        },
    )
    require_browser_http_ok("resilience-transfer-delete", delete_result)
    cleanup_snapshot = wait_for_transfer_absent(page, transfer_hash, timeout_seconds)
    return {
        "candidate": amutorrent_clean.summarize_amutorrent_candidate(candidate),
        "search_observations": observations,
        "download_trigger": download,
        "transfer_materialization": materialized,
        "delete": delete_result,
        "cleanup_snapshot_status": cleanup_snapshot.get("status"),
    }


def run_browser_resilience_workflows(
    *,
    base_url: str,
    emule_base_url: str,
    emule_host: str,
    api_key: str,
    instance_id: str,
    use_ssl: bool,
    inputs: live_wire_inputs.LiveWireInputs,
    artifacts_dir: Path,
    search_timeout_seconds: float,
) -> dict[str, Any]:
    """Runs the browser-origin aMuTorrent resilience workflow checks."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent resilience live proof.") from exc

    checks: dict[str, Any] = {
        "screenshots": {},
        "browser_diagnostics": {"console_errors": [], "page_errors": [], "request_failures": []},
    }
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1366, "height": 900})
        diagnostics = checks["browser_diagnostics"]
        page.on("console", lambda message: diagnostics["console_errors"].append({"type": message.type, "text": message.text, "location": message.location}) if message.type == "error" else None)
        page.on("pageerror", lambda error: diagnostics["page_errors"].append({"text": str(error)}))
        page.on("requestfailed", lambda request: diagnostics["request_failures"].append({"failure": str(request.failure), "method": request.method, "resource_type": request.resource_type, "url": request.url}))
        try:
            page.goto(base_url, wait_until="domcontentloaded", timeout=30000)
            checks["initial_snapshot"] = fetch_page_json(page, "/api/v1/data/snapshot")
            require_browser_http_ok("initial-snapshot", checks["initial_snapshot"])
            checks["bad_credential_recovery"] = run_bad_credential_recovery(
                page,
                emule_host=emule_host,
                emule_port=int(emule_base_url.rsplit(":", 1)[1]),
                api_key=api_key,
                use_ssl=use_ssl,
                instance_id=instance_id,
            )
            checks["concurrent_search_conflict"] = run_concurrent_search_conflict(
                page,
                instance_id=instance_id,
                inputs=inputs,
                timeout_seconds=search_timeout_seconds,
            )
            checks["live_transfer_cleanup"] = run_live_transfer_cleanup(
                page,
                emule_base_url=emule_base_url,
                api_key=api_key,
                instance_id=instance_id,
                timeout_seconds=search_timeout_seconds,
            )
            final = artifacts_dir / "amutorrent-resilience-final.png"
            page.screenshot(path=str(final), full_page=True)
            checks["screenshots"]["final"] = str(final)
            return checks
        except Exception:
            failure = artifacts_dir / "amutorrent-resilience-failure.png"
            try:
                page.screenshot(path=str(failure), full_page=True)
                checks["screenshots"]["failure"] = str(failure)
            except Exception:
                pass
            raise
        finally:
            browser.close()


def restart_emule_for_reconnect(
    *,
    app: Any,
    app_exe: Path,
    profile_base: Path,
    emule_base_url: str,
    api_key: str,
    ready_timeout_seconds: float,
    network_ready_timeout_seconds: float,
) -> tuple[Any, dict[str, Any]]:
    """Restarts eMuleBB with the same profile and waits for REST/network recovery."""

    started_at = time.monotonic()
    close_app_cleanly(app)
    outage_started_at = time.monotonic()
    restarted = launch_app(app_exe, profile_base)
    rest_ready = wait_for_rest_ready(emule_base_url, api_key, ready_timeout_seconds)
    network_ready = wait_for_requested_networks(
        emule_base_url,
        api_key,
        network_ready_timeout_seconds,
        require_server_connected=True,
        require_kad_connected=False,
    )
    return restarted, {
        "closed_previous": True,
        "outage_seconds": round(time.monotonic() - outage_started_at, 3),
        "total_seconds": round(time.monotonic() - started_at, 3),
        "main_window": observe_optional_main_window(restarted),
        "rest_ready": rest_ready,
        "network_ready": network_ready,
    }


def wait_for_amutorrent_snapshot(base_url: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until aMuTorrent's snapshot endpoint responds after an eMule restart."""

    import json
    import urllib.request

    def resolve() -> dict[str, Any] | None:
        try:
            with urllib.request.urlopen(f"{base_url}/api/v1/data/snapshot", timeout=3.0) as response:
                text = response.read().decode("utf-8", errors="replace")
                payload = json.loads(text) if text else {}
                if 200 <= int(response.status) < 300:
                    return {"status": int(response.status), "payload": payload}
        except Exception:
            return None
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="aMuTorrent snapshot after eMule restart")


def main() -> int:
    """Runs the aMuTorrent resilience live E2E proof."""

    args = build_parser().parse_args()
    inputs = live_wire_inputs.load_live_wire_inputs(
        resolve_live_wire_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="amutorrent-resilience-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    workspace_repo_root = amutorrent_smoke.find_workspace_repo_root(paths.workspace_root)
    amutorrent_root = workspace_repo_root / "repos" / "amutorrent"
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    node_info = amutorrent_smoke.resolve_amutorrent_node()

    lan_host = rest_api_smoke.rest_base_host_for_lan_bind_addr(args.lan_bind_addr)
    emule_port = choose_listen_port(args.lan_bind_addr)
    amutorrent_port = choose_listen_port(args.lan_bind_addr)
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port(args.lan_bind_addr)
    rest_scheme = amutorrent_clean.normalize_rest_scheme(args.rest_webserver_scheme)
    emule_base_url = f"{rest_scheme}://{lan_host}:{emule_port}"
    amutorrent_base_url = f"http://{lan_host}:{amutorrent_port}"
    instance_id = f"emulebb-{lan_host}-{emule_port}"
    artifacts_dir = paths.source_artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    amutorrent_data_dir = artifacts_dir / "amutorrent-resilience-data"
    rest_transport = amutorrent_clean.prepare_rest_transport(
        scheme=rest_scheme,
        app_exe=paths.app_exe,
        artifacts_dir=artifacts_dir,
        hosts=(lan_host,),
    )
    rest_api_smoke.configure_https_trust(str(rest_transport["node_extra_ca_cert"]) or None)

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="amutorrent-resilience-live")
    amutorrent_session.configure_session_profile(
        Path(profile["config_dir"]),
        paths.app_exe,
        args.api_key,
        emule_port,
        args.lan_bind_addr,
        args.p2p_bind_interface_name,
        live_network=True,
        use_https=bool(rest_transport["use_https"]),
        https_certificate=str(rest_transport["https_material"]["certificate"]) if rest_transport["https_material"] else "",
        https_key=str(rest_transport["https_material"]["key"]) if rest_transport["https_material"] else "",
    )

    report: dict[str, Any] = {
        "suite": "amutorrent-resilience-live",
        "status": "failed",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "configuration": args.configuration,
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "lan_bind_address": args.lan_bind_addr,
        "lan_host": lan_host,
        "enable_upnp": True,
        "rest_webserver_scheme": rest_transport["scheme"],
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "profile_base": str(profile["profile_base"]),
        "config_dir": str(profile["config_dir"]),
        "amutorrent_root": str(amutorrent_root),
        "amutorrent_data_dir": str(amutorrent_data_dir),
        "https_material": rest_transport["https_material"],
        "live_wire_inputs_file": str(inputs.path),
        "live_wire_inputs": {
            "generic_open": live_wire_inputs.summarize_terms(inputs.generic_open_terms),
            "direct_bootstrap_transfers": live_wire_inputs.summarize_direct_transfers(inputs.direct_bootstrap_transfers),
        },
        "node": node_info,
        "checks": {},
        "cleanup": {},
    }
    app = None
    amutorrent: subprocess.Popen[str] | None = None
    amutorrent_output = None
    amutorrent_log_path = artifacts_dir / "amutorrent-server.log"
    pending_error: Exception | None = None
    try:
        amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
        app = launch_app(paths.app_exe, Path(profile["profile_base"]))
        report["emule_process_id"] = get_app_process_id(app)
        report["main_window"] = observe_optional_main_window(app)
        if report["main_window"].get("title"):
            report["main_window_title"] = report["main_window"]["title"]
        report["checks"]["emule_rest_ready"] = wait_for_rest_ready(emule_base_url, args.api_key, args.ready_timeout_seconds)
        report["checks"]["emule_network_ready"] = wait_for_requested_networks(
            emule_base_url,
            args.api_key,
            args.network_ready_timeout_seconds,
            require_server_connected=True,
            require_kad_connected=False,
        )

        node_path = Path(str(node_info["path"]))
        env = amutorrent_clean.build_clean_amutorrent_environment(
            base_env=os.environ,
            amutorrent_port=amutorrent_port,
            node_path=node_path,
            data_dir=amutorrent_data_dir,
            lan_bind_addr=args.lan_bind_addr,
            extra_ca_cert=str(rest_transport["node_extra_ca_cert"]),
        )
        amutorrent_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
        amutorrent = subprocess.Popen(
            [str(node_path), "server/server.js"],
            cwd=str(amutorrent_root),
            env=env,
            stdout=amutorrent_output,
            stderr=subprocess.STDOUT,
        )
        amutorrent_smoke.wait_for_http_ok(f"{amutorrent_base_url}/api/config/status", args.ready_timeout_seconds)
        report["amutorrent_process_id"] = amutorrent.pid
        report["checks"]["wizard"] = amutorrent_clean.drive_first_run_wizard(
            base_url=amutorrent_base_url,
            emule_host=lan_host,
            emule_port=emule_port,
            api_key=args.api_key,
            use_ssl=bool(rest_transport["use_https"]),
            artifacts_dir=artifacts_dir,
            timeout_seconds=args.ready_timeout_seconds,
        )
        app, restart_report = restart_emule_for_reconnect(
            app=app,
            app_exe=paths.app_exe,
            profile_base=Path(profile["profile_base"]),
            emule_base_url=emule_base_url,
            api_key=args.api_key,
            ready_timeout_seconds=args.ready_timeout_seconds,
            network_ready_timeout_seconds=args.network_ready_timeout_seconds,
        )
        report["emule_process_id_after_restart"] = get_app_process_id(app)
        report["checks"]["emule_restart_recovery"] = restart_report
        report["checks"]["amutorrent_snapshot_after_restart"] = wait_for_amutorrent_snapshot(
            amutorrent_base_url,
            args.reconnect_timeout_seconds,
        )
        report["checks"]["browser_resilience_workflows"] = run_browser_resilience_workflows(
            base_url=amutorrent_base_url,
            emule_base_url=emule_base_url,
            emule_host=lan_host,
            api_key=args.api_key,
            instance_id=instance_id,
            use_ssl=bool(rest_transport["use_https"]),
            inputs=inputs,
            artifacts_dir=artifacts_dir,
            search_timeout_seconds=args.search_observation_timeout_seconds,
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
        write_json(artifacts_dir / "amutorrent-resilience-live-result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        if not args.keep_artifacts:
            harness_cli_common.cleanup_source_artifacts(paths)
    if pending_error is not None:
        raise pending_error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
