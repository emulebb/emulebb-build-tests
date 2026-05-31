"""Runs a clean-startup aMuTorrent first-run wizard proof against eMuleBB REST."""

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

BROWSER_FETCH_TRANSIENT_MARKERS = (
    "ECONNRESET",
    "ERR_CONNECTION_RESET",
    "socket hang up",
    "UNEXPECTED_EOF_WHILE_READING",
    "Remote end closed connection without response",
    "WinError 10053",
    "WinError 10054",
    "WinError 10061",
)


def build_clean_amutorrent_environment(
    *,
    base_env: dict[str, str],
    amutorrent_port: int,
    node_path: Path,
    data_dir: Path,
    lan_bind_addr: str,
    extra_ca_cert: str = "",
) -> dict[str, str]:
    """Builds the environment for first-run aMuTorrent without pre-seeding eMuleBB."""

    env = dict(base_env)
    env.update(
        {
            "PORT": str(amutorrent_port),
            "lan_bind_address": rest_api_smoke.require_lan_bind_addr(lan_bind_addr),
            "AMUTORRENT_DATA_DIR": str(data_dir),
            "WEB_AUTH_ENABLED": "false",
        }
    )
    env.pop("SKIP_SETUP_WIZARD", None)
    for key in tuple(env):
        if key.startswith("EMULEBB_"):
            env.pop(key, None)
    if extra_ca_cert:
        env["NODE_EXTRA_CA_CERTS"] = extra_ca_cert
    if node_path.is_absolute():
        env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
    return env


def normalize_rest_scheme(raw_scheme: str) -> str:
    """Returns a supported REST WebServer scheme token."""

    scheme = str(raw_scheme or "https").strip().lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported REST WebServer scheme: {raw_scheme!r}")
    return scheme


def prepare_rest_transport(*, scheme: str, app_exe: Path, artifacts_dir: Path, hosts: tuple[str, ...] = ()) -> dict[str, Any]:
    """Prepares disposable REST transport material for one live run."""

    rest_scheme = normalize_rest_scheme(scheme)
    if rest_scheme != "https":
        rest_api_smoke.configure_https_trust(None)
        return {
            "scheme": "http",
            "use_https": False,
            "https_material": None,
            "node_extra_ca_cert": "",
        }

    https_material = rest_api_smoke.create_https_certificate_pair(app_exe, artifacts_dir, hosts=hosts)
    certificate = str(https_material["certificate"])
    rest_api_smoke.configure_https_trust(certificate)
    return {
        "scheme": "https",
        "use_https": True,
        "https_material": https_material,
        "node_extra_ca_cert": certificate,
    }


def resolve_clean_live_wire_inputs_path(repo_root: Path, raw_path: str | None) -> Path:
    """Resolves live-wire inputs from repo-relative or workspace-cwd-relative paths."""

    resolved = live_wire_inputs.resolve_inputs_path(repo_root, raw_path)
    if raw_path and not resolved.is_file():
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            cwd_candidate = (Path.cwd() / candidate).resolve()
            if cwd_candidate.is_file():
                return cwd_candidate
    return resolved


def fetch_page_json_once(page: Any, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one same-origin browser fetch and returns status plus parsed payload."""

    try:
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
    except Exception as exc:
        return {"status": 0, "payload": {"type": "error", "message": str(exc)}}


def payload_text_fragments(value: Any) -> list[str]:
    """Returns string fragments from nested browser-fetch payload values."""

    if isinstance(value, dict):
        fragments: list[str] = []
        for item in value.values():
            fragments.extend(payload_text_fragments(item))
        return fragments
    if isinstance(value, list):
        fragments = []
        for item in value:
            fragments.extend(payload_text_fragments(item))
        return fragments
    if value is None:
        return []
    return [str(value)]


def is_retryable_browser_fetch(method: str, path: str, result: dict[str, Any]) -> bool:
    """Returns whether a browser-origin aMuTorrent request can be retried safely."""

    method_upper = method.upper()
    if method_upper != "GET" and not (method_upper == "POST" and path.split("?", 1)[0] == "/api/config/test"):
        return False
    payload = result.get("payload")
    message = " ".join(payload_text_fragments(payload))
    return any(marker in message for marker in BROWSER_FETCH_TRANSIENT_MARKERS)


def fetch_page_json(page: Any, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one same-origin browser fetch, retrying safe transient bridge resets."""

    attempts = 3 if method.upper() == "GET" or path.split("?", 1)[0] == "/api/config/test" else 1
    last_result: dict[str, Any] = {}
    for attempt in range(1, attempts + 1):
        last_result = fetch_page_json_once(page, path, method, body)
        if not is_retryable_browser_fetch(method, path, last_result):
            if attempt > 1:
                last_result["attempts"] = attempt
            return last_result
        if attempt < attempts:
            time.sleep(0.5 * attempt)
    last_result["attempts"] = attempts
    return last_result


def require_browser_http_ok(name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Returns a browser fetch payload or raises with diagnostic context."""

    status = int(result.get("status", 0))
    payload = result.get("payload")
    if status >= 400:
        raise RuntimeError(f"aMuTorrent browser HTTP check {name!r} failed: {result!r}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"aMuTorrent browser HTTP check {name!r} did not return an object: {result!r}")
    if payload.get("type") == "error" or payload.get("success") is False:
        raise RuntimeError(f"aMuTorrent browser HTTP check {name!r} returned an error payload: {result!r}")
    return payload


def is_safe_amutorrent_search_result(row: Any) -> bool:
    """Returns true for one aMuTorrent search row safe enough to trigger."""

    if not isinstance(row, dict):
        return False
    transfer_hash = str(row.get("fileHash") or row.get("hash") or "").strip().lower()
    name = str(row.get("fileName") or row.get("name") or "").strip().lower()
    file_type = str(row.get("fileType") or row.get("type") or "").strip().lower()
    size = row.get("fileSize", row.get("sizeBytes", row.get("size")))
    sources = row.get("sourceCount", row.get("sources"))
    if not name or name.endswith(rest_api_smoke.UNSAFE_LIVE_DOWNLOAD_SUFFIXES):
        return False
    if file_type in {"arc", "archive", "program", "pro", "video"}:
        return False
    if rest_api_smoke.has_unsafe_live_download_name_token(name):
        return False
    return (
        rest_api_smoke.is_lowercase_md4_hash(transfer_hash)
        and isinstance(size, int)
        and not isinstance(size, bool)
        and 0 < size <= rest_api_smoke.MAX_SAFE_LIVE_DOWNLOAD_BYTES
        and isinstance(sources, int)
        and not isinstance(sources, bool)
        and sources >= rest_api_smoke.MIN_SAFE_LIVE_DOWNLOAD_SOURCES
    )


def summarize_amutorrent_candidate(row: dict[str, Any]) -> dict[str, object]:
    """Builds a report-safe candidate summary without the runtime query or file name."""

    return {
        "hash_present": bool(row.get("fileHash") or row.get("hash")),
        "name_present": bool(row.get("fileName") or row.get("name")),
        "size": row.get("fileSize", row.get("sizeBytes", row.get("size"))),
        "sources": row.get("sourceCount", row.get("sources")),
        "completeSources": row.get("completeSourceCount", row.get("completeSources")),
    }


def wait_for_amutorrent_search_candidate(
    page: Any,
    *,
    instance_id: str,
    search_type: str,
    timeout_seconds: float,
) -> tuple[dict[str, Any], list[dict[str, object]]]:
    """Polls aMuTorrent search results until one safe candidate is available."""

    observations: list[dict[str, object]] = []

    def resolve() -> dict[str, Any] | None:
        result = fetch_page_json(page, f"/api/v1/search/results?type={search_type}&instanceId={instance_id}")
        payload = require_browser_http_ok("search-results", result)
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise RuntimeError(f"aMuTorrent search results data is not a list: {result!r}")
        candidate = next((row for row in rows if is_safe_amutorrent_search_result(row)), None)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "result_count": len(rows),
                "has_candidate": candidate is not None,
            }
        )
        return candidate

    return wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="aMuTorrent safe live search candidate"), observations


def wait_for_emule_transfer_materialized(
    *,
    emule_base_url: str,
    api_key: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until eMuleBB REST can see the transfer triggered by aMuTorrent."""

    return rest_api_smoke.wait_for_triggered_transfer(
        emule_base_url,
        api_key,
        transfer_hash,
        timeout_seconds,
    )


def drive_first_run_wizard(
    *,
    base_url: str,
    emule_host: str,
    emule_port: int,
    api_key: str,
    use_ssl: bool,
    artifacts_dir: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Completes the first-run wizard through the browser UI."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent clean-startup proof.") from exc

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
        page.on(
            "requestfailed",
            lambda request: diagnostics["request_failures"].append(
                {
                    "failure": str(request.failure),
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "url": request.url,
                }
            ),
        )

        try:
            page.goto(base_url, wait_until="domcontentloaded", timeout=int(timeout_seconds * 1000))
            page.get_by_text("Welcome to aMuTorrent").wait_for(timeout=int(timeout_seconds * 1000))
            first_run = fetch_page_json(page, "/api/config/status")
            checks["status_before_setup"] = first_run
            if require_browser_http_ok("status-before-setup", first_run).get("firstRun") is not True:
                raise RuntimeError(f"aMuTorrent did not start in first-run mode: {first_run!r}")

            wizard_start = artifacts_dir / "wizard-start.png"
            page.screenshot(path=str(wizard_start), full_page=True)
            checks["screenshots"]["wizard_start"] = str(wizard_start)

            page.get_by_role("button", name="Next").click()
            page.get_by_text("Enable Authentication", exact=True).click()
            page.get_by_role("button", name="Next").click()

            page.get_by_role("heading", name="ED2K Integration").wait_for(timeout=int(timeout_seconds * 1000))
            emulebb_card = page.locator("xpath=//h3[normalize-space()='eMuleBB (REST API)']/ancestor::div[contains(@class,'border')][1]")
            emulebb_card.get_by_text("Enable eMuleBB", exact=True).click()
            emulebb_card.get_by_placeholder("127.0.0.1").fill(emule_host)
            emulebb_card.get_by_placeholder("4711").fill(str(emule_port))
            emulebb_card.get_by_placeholder("Enter eMuleBB API key").fill(api_key)
            if use_ssl:
                emulebb_card.get_by_text("Use SSL (HTTPS)", exact=True).click()

            connection = fetch_page_json(
                page,
                "/api/config/test",
                "POST",
                {"emulebb": {"enabled": True, "host": emule_host, "port": emule_port, "apiKey": api_key, "useSsl": use_ssl, "path": ""}},
            )
            checks["emulebb_connection_test"] = connection
            connection_payload = require_browser_http_ok("emulebb-connection-test", connection)
            if connection_payload.get("success") is not True:
                raise RuntimeError(f"aMuTorrent eMuleBB connection test did not pass: {connection!r}")

            configured = artifacts_dir / "wizard-emulebb-configured.png"
            page.screenshot(path=str(configured), full_page=True)
            checks["screenshots"]["wizard_emulebb_configured"] = str(configured)

            for _ in range(4):
                page.get_by_role("button", name="Next").click()
            page.get_by_role("button", name="Complete Setup").click()

            def setup_finished() -> dict[str, Any] | None:
                status = fetch_page_json(page, "/api/config/status")
                payload = require_browser_http_ok("status-after-setup", status)
                return status if payload.get("firstRun") is False else None

            checks["status_after_setup"] = wait_for(setup_finished, timeout=timeout_seconds, interval=1.0, description="aMuTorrent first-run completion")
            current = fetch_page_json(page, "/api/config/current")
            checks["current_config_after_setup"] = current
            current_payload = require_browser_http_ok("current-config-after-setup", current)
            clients = current_payload.get("clients")
            if not isinstance(clients, list) or not any(item.get("type") == "emulebb" and item.get("enabled") is not False for item in clients if isinstance(item, dict)):
                raise RuntimeError(f"aMuTorrent config did not persist an enabled eMuleBB client: {current!r}")

            after_setup = artifacts_dir / "wizard-complete.png"
            page.screenshot(path=str(after_setup), full_page=True)
            checks["screenshots"]["wizard_complete"] = str(after_setup)
            checks["page"] = page
            return checks
        except Exception:
            failure = artifacts_dir / "wizard-failure.png"
            try:
                page.screenshot(path=str(failure), full_page=True)
                checks["screenshots"]["wizard_failure"] = str(failure)
            except Exception:
                pass
            raise
        finally:
            checks.pop("page", None)
            browser.close()


def run_browser_live_search_and_download(
    *,
    base_url: str,
    emule_base_url: str,
    api_key: str,
    instance_id: str,
    inputs: live_wire_inputs.LiveWireInputs,
    artifacts_dir: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Runs live search and download trigger through aMuTorrent browser APIs."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent clean-startup proof.") from exc

    term_index, query = live_wire_inputs.select_daily(inputs.generic_open_terms)
    search_type = "automatic"
    checks: dict[str, Any] = {
        "term_selection": live_wire_inputs.redact_term_selection(term_index, inputs.generic_open_terms, source="generic_open"),
        "input_summary": {
            "generic_open": live_wire_inputs.summarize_terms(inputs.generic_open_terms),
            "direct_bootstrap_transfers": live_wire_inputs.summarize_direct_transfers(inputs.direct_bootstrap_transfers),
        },
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
            start = fetch_page_json(
                page,
                "/api/v1/search?wait=false",
                "POST",
                {"query": query, "type": search_type, "instanceId": instance_id},
            )
            checks["search_start"] = {"status": start.get("status"), "payload_type": start.get("payload", {}).get("type") if isinstance(start.get("payload"), dict) else None}
            require_browser_http_ok("search-start", start)

            candidate, observations = wait_for_amutorrent_search_candidate(
                page,
                instance_id=instance_id,
                search_type=search_type,
                timeout_seconds=timeout_seconds,
            )
            transfer_hash = str(candidate.get("fileHash") or candidate.get("hash") or "").strip().lower()
            checks["candidate"] = summarize_amutorrent_candidate(candidate)
            checks["search_observations"] = observations

            download = fetch_page_json(
                page,
                "/api/v1/downloads/search-results",
                "POST",
                {"fileHashes": [transfer_hash], "categoryId": 0, "instanceId": instance_id},
            )
            checks["download_trigger"] = download
            require_browser_http_ok("download-trigger", download)
            checks["transfer_materialization"] = wait_for_emule_transfer_materialized(
                emule_base_url=emule_base_url,
                api_key=api_key,
                transfer_hash=transfer_hash,
                timeout_seconds=timeout_seconds,
            )
            screenshot = artifacts_dir / "live-search-transfer-materialized.png"
            page.screenshot(path=str(screenshot), full_page=True)
            checks["screenshots"] = {"transfer_materialized": str(screenshot)}
            return checks
        finally:
            browser.close()


def build_parser() -> argparse.ArgumentParser:
    """Builds the clean-startup argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-clean-startup-key")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--rest-webserver-scheme", choices=["http", "https"], default="https")
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--vpn-guard-enabled", action="store_true")
    parser.add_argument("--vpn-guard-allowed-public-ip-cidrs", default="")
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--live-wire-inputs-file", default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)))
    return parser


def main() -> int:
    """Runs the automated first-run setup, live search, and transfer proof."""

    args = build_parser().parse_args()
    inputs = live_wire_inputs.load_live_wire_inputs(
        resolve_clean_live_wire_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="amutorrent-clean-startup",
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
    rest_scheme = normalize_rest_scheme(args.rest_webserver_scheme)
    emule_base_url = f"{rest_scheme}://{lan_host}:{emule_port}"
    amutorrent_base_url = f"http://{lan_host}:{amutorrent_port}"
    instance_id = f"emulebb-{lan_host}-{emule_port}"
    artifacts_dir = paths.source_artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    amutorrent_data_dir = artifacts_dir / "amutorrent-clean-data"
    rest_transport = prepare_rest_transport(
        scheme=rest_scheme,
        app_exe=paths.app_exe,
        artifacts_dir=artifacts_dir,
        hosts=(lan_host,),
    )

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="amutorrent-clean-startup")
    amutorrent_session.configure_session_profile(
        Path(profile["config_dir"]),
        paths.app_exe,
        args.api_key,
        emule_port,
        args.lan_bind_addr,
        args.p2p_bind_interface_name,
        live_network=True,
        vpn_guard_enabled=args.vpn_guard_enabled,
        vpn_guard_allowed_public_ip_cidrs=args.vpn_guard_allowed_public_ip_cidrs,
        use_https=bool(rest_transport["use_https"]),
        https_certificate=str(rest_transport["https_material"]["certificate"]) if rest_transport["https_material"] else "",
        https_key=str(rest_transport["https_material"]["key"]) if rest_transport["https_material"] else "",
    )

    report: dict[str, Any] = {
        "suite": "amutorrent-clean-startup",
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
        main_window = wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        report["checks"]["emule_rest_ready"] = wait_for_rest_ready(emule_base_url, args.api_key, args.ready_timeout_seconds)
        report["checks"]["emule_network_ready"] = wait_for_requested_networks(
            emule_base_url,
            args.api_key,
            args.network_ready_timeout_seconds,
            require_server_connected=True,
            require_kad_connected=False,
        )

        node_path = Path(str(node_info["path"]))
        env = build_clean_amutorrent_environment(
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
        report["checks"]["wizard"] = drive_first_run_wizard(
            base_url=amutorrent_base_url,
            emule_host=lan_host,
            emule_port=emule_port,
            api_key=args.api_key,
            use_ssl=bool(rest_transport["use_https"]),
            artifacts_dir=artifacts_dir,
            timeout_seconds=args.ready_timeout_seconds,
        )
        report["checks"]["live_search_download"] = run_browser_live_search_and_download(
            base_url=amutorrent_base_url,
            emule_base_url=emule_base_url,
            api_key=args.api_key,
            instance_id=instance_id,
            inputs=inputs,
            artifacts_dir=artifacts_dir,
            timeout_seconds=args.search_observation_timeout_seconds,
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
        write_json(artifacts_dir / "amutorrent-clean-startup-result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        if not args.keep_artifacts:
            harness_cli_common.cleanup_source_artifacts(paths)
    if pending_error is not None:
        raise pending_error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
