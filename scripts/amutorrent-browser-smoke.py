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


def run_browser_workflows(base_url: str, instance_id: str) -> dict[str, Any]:
    """Drives the critical aMuTorrent workflows through a browser page."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent browser smoke. Install the Python package and browser runtime.") from exc

    checks: dict[str, Any] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
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

        snapshot = fetch_json("/api/v1/data/snapshot")
        if not (200 <= int(snapshot["status"]) < 300):
            raise RuntimeError(f"aMuTorrent snapshot failed: {snapshot}")
        checks["snapshot"] = snapshot

        checks["categories"] = fetch_json("/api/v1/categories")
        checks["add_ed2k"] = fetch_json(
            "/api/v1/downloads/ed2k",
            "POST",
            {
                "links": ["ed2k://|file|amutorrent-browser-smoke.bin|1|0123456789abcdef0123456789abcdef|/"],
                "instanceId": instance_id,
            },
        )
        checks["search_start"] = fetch_json(
            "/api/v1/search?wait=false",
            "POST",
            {"query": "linux", "type": "automatic", "instanceId": instance_id},
        )
        checks["search_results"] = fetch_json("/api/v1/search/results")
        checks["server_list"] = fetch_json("/api/v1/amule/servers")
        checks["server_disconnect"] = fetch_json(
            "/api/v1/amule/servers/action",
            "POST",
            {"ip": "127.0.0.1", "port": 4661, "serverAction": "disconnect", "instanceId": instance_id},
        )
        checks["shared_dirs_reload"] = fetch_json("/api/amule/shared-dirs/reload", "POST", {})

        for name, result in checks.items():
            if isinstance(result, dict) and "status" in result and int(result["status"]) >= 500:
                raise RuntimeError(f"aMuTorrent browser workflow '{name}' failed: {result}")
        browser.close()
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--seed-config-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-browser-smoke-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
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
    seed_config_dir = Path(args.seed_config_dir).resolve() if args.seed_config_dir else paths.seed_config_dir

    emule_port = choose_listen_port()
    amutorrent_port = choose_listen_port()
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port()
    emule_base_url = f"http://127.0.0.1:{emule_port}"
    amutorrent_base_url = f"http://127.0.0.1:{amutorrent_port}"
    instance_id = "emulebb-browser-smoke"

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    configure_webserver_profile(Path(profile["config_dir"]), paths.app_exe, args.api_key, emule_port, args.bind_addr, False)

    report: dict[str, Any] = {
        "suite": "amutorrent-browser-smoke",
        "status": "failed",
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "profile_base": str(profile["profile_base"]),
        "config_dir": str(profile["config_dir"]),
        "amutorrent_root": str(amutorrent_root),
        "checks": {},
        "cleanup": {},
    }

    app = None
    amutorrent: subprocess.Popen[str] | None = None
    pending_error: Exception | None = None
    try:
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
        amutorrent = subprocess.Popen(
            ["node", "server/server.js"],
            cwd=str(amutorrent_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_http_ok(f"{amutorrent_base_url}/api/config/status", args.ready_timeout_seconds)
        report["amutorrent_process_id"] = amutorrent.pid
        report["checks"]["browser_workflows"] = run_browser_workflows(amutorrent_base_url, instance_id)
        report["status"] = "passed"
    except Exception as exc:
        pending_error = exc
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if amutorrent is not None:
            amutorrent.terminate()
            try:
                stdout, _ = amutorrent.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                amutorrent.kill()
                stdout, _ = amutorrent.communicate(timeout=10)
            report["cleanup"]["amutorrent_output_tail"] = (stdout or "")[-4000:]
        if app is not None:
            try:
                close_app_cleanly(app)
                report["cleanup"]["emule_closed"] = True
            except Exception as exc:
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
