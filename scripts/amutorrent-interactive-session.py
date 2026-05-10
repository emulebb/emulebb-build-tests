"""Starts a persistent interactive aMuTorrent session against eMule BB REST."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
import webbrowser
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
amutorrent_smoke = load_local_module("amutorrent_browser_smoke_helpers", "amutorrent-browser-smoke.py")

choose_listen_port = rest_api_smoke.choose_listen_port
close_app_cleanly = live_common.close_app_cleanly
get_app_process_id = rest_api_smoke.get_app_process_id
launch_app = live_common.launch_app
prepare_profile_base = live_common.prepare_profile_base
wait_for_main_window = live_common.wait_for_main_window
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready
write_json = live_common.write_json


def configure_session_profile(
    config_dir: Path,
    app_exe: Path,
    api_key: str,
    port: int,
    bind_addr: str,
    p2p_bind_interface_name: str,
    *,
    live_network: bool,
) -> None:
    """Enables REST and applies the requested live-network startup policy."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("ConfirmExit", "0"),
            ("Autoconnect", "1" if live_network else "0"),
            ("Reconnect", "1" if live_network else "0"),
            ("NetworkED2K", "1" if live_network else "0"),
            ("NetworkKademlia", "1" if live_network else "0"),
        ),
    )
    live_common.apply_webserver_profile(
        config_dir,
        live_common.WebServerProfileSpec(
            app_exe=app_exe,
            api_key=api_key,
            port=port,
            bind_addr=bind_addr,
            use_gzip=True,
            allow_admin_high_level_func=True,
        ),
    )
    rest_api_smoke.apply_p2p_bind_interface_override(config_dir, p2p_bind_interface_name)


def build_amutorrent_environment(
    *,
    base_env: dict[str, str],
    amutorrent_port: int,
    emule_port: int,
    api_key: str,
    instance_id: str,
    node_path: Path,
    data_dir: Path,
) -> dict[str, str]:
    """Builds the environment used by the interactive aMuTorrent server."""

    env = dict(base_env)
    env.update(
        {
            "PORT": str(amutorrent_port),
            "BIND_ADDRESS": "127.0.0.1",
            "AMUTORRENT_DATA_DIR": str(data_dir),
            "WEB_AUTH_ENABLED": "false",
            "SKIP_SETUP_WIZARD": "true",
            "EMULEBB_ENABLED": "true",
            "EMULEBB_HOST": "127.0.0.1",
            "EMULEBB_PORT": str(emule_port),
            "EMULEBB_API_KEY": api_key,
            "EMULEBB_USE_SSL": "false",
            "EMULEBB_ID": instance_id,
            "EMULEBB_NAME": "eMule BB Interactive",
        }
    )
    if node_path.is_absolute():
        env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
    return env


def write_stop_script(path: Path, *, emule_pid: int | None, amutorrent_pid: int | None) -> None:
    """Writes a command helper that stops the launched interactive processes."""

    process_rows = [
        ("eMule BB", emule_pid),
        ("aMuTorrent", amutorrent_pid),
    ]
    stop_calls = "\n".join(
        f'call :stop_process "{name}" "{pid}"'
        for name, pid in process_rows
        if pid is not None
    )
    path.write_text(
        f"""@echo off
setlocal
{stop_calls}
exit /b 0

:stop_process
set "name=%~1"
set "pid=%~2"
if "%pid%"=="" exit /b 0

tasklist /FI "PID eq %pid%" 2>NUL | findstr /C:"%pid%" >NUL
if errorlevel 1 (
    echo %name% is not running (PID %pid%).
    exit /b 0
)

echo Closing %name% (PID %pid%)...
taskkill /PID %pid% >NUL 2>NUL
for /L %%I in (1,1,30) do (
    tasklist /FI "PID eq %pid%" 2>NUL | findstr /C:"%pid%" >NUL
    if errorlevel 1 exit /b 0
    timeout /T 1 /NOBREAK >NUL
)

echo Forcing %name% (PID %pid%)...
taskkill /PID %pid% /F >NUL 2>NUL
exit /b 0
""",
        encoding="utf-8",
        newline="\r\n",
    )


def build_parser() -> argparse.ArgumentParser:
    """Builds the interactive-session argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-interactive-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--live-network", action="store_true")
    parser.add_argument("--no-open-browser", action="store_true")
    return parser


def main() -> int:
    """Starts eMule BB and aMuTorrent, then leaves both running for the operator."""

    args = build_parser().parse_args()
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="amutorrent-interactive-session",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=True,
    )
    workspace_repo_root = amutorrent_smoke.find_workspace_repo_root(paths.workspace_root)
    amutorrent_root = workspace_repo_root / "repos" / "amutorrent"
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    node_info = amutorrent_smoke.resolve_amutorrent_node()

    emule_port = choose_listen_port()
    amutorrent_port = choose_listen_port()
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port()

    emule_base_url = f"http://127.0.0.1:{emule_port}"
    amutorrent_base_url = f"http://127.0.0.1:{amutorrent_port}"
    instance_id = f"emulebb-127.0.0.1-{emule_port}"
    artifacts_dir = paths.source_artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    amutorrent_data_dir = artifacts_dir / "amutorrent-data"

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    configure_session_profile(
        Path(profile["config_dir"]),
        paths.app_exe,
        args.api_key,
        emule_port,
        args.bind_addr,
        args.p2p_bind_interface_name,
        live_network=bool(args.live_network),
    )

    report: dict[str, Any] = {
        "suite": "amutorrent-interactive-session",
        "status": "failed",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "configuration": args.configuration,
        "live_network": bool(args.live_network),
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "enable_upnp": True,
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "profile_base": str(profile["profile_base"]),
        "config_dir": str(profile["config_dir"]),
        "amutorrent_root": str(amutorrent_root),
        "amutorrent_data_dir": str(amutorrent_data_dir),
        "node": node_info,
        "artifacts_dir": str(artifacts_dir),
        "checks": {},
        "cleanup": {},
    }

    app = None
    amutorrent: subprocess.Popen[str] | None = None
    try:
        amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
        app = launch_app(paths.app_exe, Path(profile["profile_base"]))
        report["emule_process_id"] = get_app_process_id(app)
        main_window = wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        report["checks"]["emule_rest_ready"] = wait_for_rest_ready(
            emule_base_url,
            args.api_key,
            args.ready_timeout_seconds,
        )

        node_path = Path(str(node_info["path"]))
        env = build_amutorrent_environment(
            base_env=os.environ,
            amutorrent_port=amutorrent_port,
            emule_port=emule_port,
            api_key=args.api_key,
            instance_id=instance_id,
            node_path=node_path,
            data_dir=amutorrent_data_dir,
        )
        amutorrent_log_path = artifacts_dir / "amutorrent-server.log"
        amutorrent_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
        try:
            amutorrent = subprocess.Popen(
                [str(node_path), "server/server.js"],
                cwd=str(amutorrent_root),
                env=env,
                stdout=amutorrent_output,
                stderr=subprocess.STDOUT,
            )
        finally:
            amutorrent_output.close()

        amutorrent_smoke.wait_for_http_ok(
            f"{amutorrent_base_url}/api/config/status",
            args.ready_timeout_seconds,
        )
        report["amutorrent_process_id"] = amutorrent.pid
        report["amutorrent_log"] = str(amutorrent_log_path)
        report["stop_script"] = str(artifacts_dir / "stop-session.cmd")
        report["status"] = "running"

        write_stop_script(
            artifacts_dir / "stop-session.cmd",
            emule_pid=int(report["emule_process_id"]),
            amutorrent_pid=amutorrent.pid,
        )
        write_json(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)

        if not args.no_open_browser:
            webbrowser.open(amutorrent_base_url)

        print(f"eMule BB REST: {emule_base_url}")
        print(f"aMuTorrent UI: {amutorrent_base_url}")
        print(f"Artifacts: {paths.run_report_dir}")
        print(f"Stop script: {paths.run_report_dir / 'stop-session.cmd'}")
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        write_json(artifacts_dir / "result.json", report)
        if amutorrent is not None:
            amutorrent.terminate()
            try:
                amutorrent.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                amutorrent.kill()
                amutorrent.communicate(timeout=10)
        if app is not None:
            try:
                close_app_cleanly(app)
            except Exception:
                app.kill()
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
