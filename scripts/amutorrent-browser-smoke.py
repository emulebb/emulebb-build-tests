"""Runs a live aMuTorrent browser smoke against eMule BB REST."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

AMUTORRENT_NODE_ENV = "AMUTORRENT_NODE_EXE"
DEFAULT_WINDOWS_NODE22 = Path(r"C:\bin\nodejs-v22-old\node.exe")


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


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
rest_api_smoke = load_local_module("rest_api_smoke_helpers", "rest-api-smoke.py")

choose_listen_port = rest_api_smoke.choose_listen_port
close_app_cleanly = live_common.close_app_cleanly
configure_webserver_profile = rest_api_smoke.configure_webserver_profile
get_app_process_id = rest_api_smoke.get_app_process_id
launch_app = live_common.launch_app
prepare_profile_base = live_common.prepare_profile_base
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready
write_json = live_common.write_json


def find_workspace_repo_root(workspace_root: Path) -> Path:
    """Finds the parent workspace root that contains repos/amutorrent."""

    current = workspace_root.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "repos" / "amutorrent").is_dir():
            return candidate
    raise RuntimeError(f"Could not find repos/amutorrent above {workspace_root}.")


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
    if configured:
        node_exe = Path(configured)
    elif DEFAULT_WINDOWS_NODE22.exists():
        node_exe = DEFAULT_WINDOWS_NODE22
    else:
        node_exe = Path("node")

    try:
        completed = subprocess.run(
            [str(node_exe), "-v"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"Unable to run Node.js executable '{node_exe}'. Set {AMUTORRENT_NODE_ENV} to a Node 20-22 runtime.") from exc

    version = completed.stdout.strip()
    major = parse_node_major(version)
    if major < 20 or major > 22:
        raise RuntimeError(
            f"aMuTorrent browser smoke requires Node.js 20-22 because its locked server dependencies include native addons; "
            f"'{node_exe}' reports {version}. Set {AMUTORRENT_NODE_ENV} to a Node 22 executable."
        )

    return {
        "path": str(node_exe),
        "version": version,
        "major": major,
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


def assert_browser_workflow_results(checks: dict[str, Any], diagnostics: dict[str, list[dict[str, Any]]]) -> None:
    """Raises when browser workflow HTTP calls or page diagnostics report failures."""

    for name, result in iter_browser_http_results(checks):
        if int(result["status"]) >= 500:
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' failed: {result}")
        payload = result.get("payload")
        if isinstance(payload, dict) and payload.get("type") == "error":
            raise RuntimeError(f"aMuTorrent browser workflow '{name}' returned an error payload: {result}")
    if any(diagnostics.values()):
        raise RuntimeError(f"aMuTorrent browser diagnostics reported errors: {diagnostics}")


def run_browser_workflows(base_url: str, instance_id: str, category_path: str) -> dict[str, Any]:
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

            def start_search_with_retry(search_type: str, query: str) -> dict[str, Any]:
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
            checks["category_delete"] = fetch_json(
                "/api/v1/categories",
                "DELETE",
                {"name": smoke_category},
            )
            checks["add_ed2k"] = fetch_json(
                "/api/v1/downloads/ed2k",
                "POST",
                {
                    "links": ["ed2k://|file|amutorrent-browser-smoke.bin|1|0123456789abcdef0123456789abcdef|/"],
                    "instanceId": instance_id,
                },
            )
            checks["qbit_delete_probe"] = fetch_json(
                "/api/v2/torrents/delete",
                "POST",
                {"hashes": "0123456789abcdef0123456789abcdef", "deleteFiles": "true"},
            )
            checks["search_modes"] = [
                start_search_with_retry("automatic", "caf\u00e9 \u6e2c\u8a66"),
                start_search_with_retry("server", "linux"),
                start_search_with_retry("kad", "ubuntu"),
            ]
            checks["search_results"] = fetch_json(f"/api/v1/search/results?instanceId={instance_id}")
            checks["server_list"] = fetch_json("/api/v1/amule/servers")
            checks["server_disconnect"] = fetch_json(
                "/api/v1/amule/servers/action",
                "POST",
                {"ip": "127.0.0.1", "port": 4661, "serverAction": "disconnect", "instanceId": instance_id},
            )
            checks["shared_dirs_reload"] = fetch_json(
                f"/api/amule/shared-dirs/reload?instanceId={instance_id}",
                "POST",
                {},
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
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()

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
    workspace_repo_root = find_workspace_repo_root(paths.workspace_root)
    amutorrent_root = workspace_repo_root / "repos" / "amutorrent"
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    node_info = resolve_amutorrent_node()
    amutorrent_data_dir = artifacts_dir / "amutorrent-data"

    emule_port = choose_listen_port()
    amutorrent_port = choose_listen_port()
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port()
    emule_base_url = f"http://127.0.0.1:{emule_port}"
    amutorrent_base_url = f"http://127.0.0.1:{amutorrent_port}"
    instance_id = f"emulebb-127.0.0.1-{emule_port}"

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    configure_webserver_profile(Path(profile["config_dir"]), paths.app_exe, args.api_key, emule_port, args.bind_addr)
    rest_api_smoke.apply_p2p_bind_interface_override(Path(profile["config_dir"]), args.p2p_bind_interface_name)

    report: dict[str, Any] = {
        "suite": "amutorrent-browser-smoke",
        "status": "failed",
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "profile_base": str(profile["profile_base"]),
        "config_dir": str(profile["config_dir"]),
        "amutorrent_root": str(amutorrent_root),
        "amutorrent_data_dir": str(amutorrent_data_dir),
        "node": node_info,
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "enable_upnp": True,
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

        env = os.environ.copy()
        env.update(
            {
                "PORT": str(amutorrent_port),
                "BIND_ADDRESS": "127.0.0.1",
                "AMUTORRENT_DATA_DIR": str(amutorrent_data_dir),
                "WEB_AUTH_ENABLED": "false",
                "SKIP_SETUP_WIZARD": "true",
                "EMULEBB_ENABLED": "true",
                "EMULEBB_HOST": "127.0.0.1",
                "EMULEBB_PORT": str(emule_port),
                "EMULEBB_API_KEY": args.api_key,
                "EMULEBB_USE_SSL": "false",
                "EMULEBB_ID": instance_id,
                "EMULEBB_NAME": "eMule BB Browser Smoke",
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
        report["checks"]["browser_workflows"] = run_browser_workflows(amutorrent_base_url, instance_id, category_path)
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
        write_json(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    if pending_error is not None:
        raise pending_error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
