"""Starts a persistent interactive aMuTorrent session against eMuleBB REST."""

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

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_client  # noqa: E402


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
    lan_bind_addr: str,
    p2p_bind_interface_name: str,
    *,
    live_network: bool,
    vpn_guard_enabled: bool = False,
    vpn_guard_allowed_public_ip_cidrs: str = "",
    use_https: bool = False,
    https_certificate: str = "",
    https_key: str = "",
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
            lan_bind_addr=lan_bind_addr,
            use_gzip=True,
            allow_admin_high_level_func=True,
            use_https=use_https,
            https_certificate=https_certificate,
            https_key=https_key,
        ),
    )
    rest_api_smoke.apply_p2p_bind_interface_override(
        config_dir,
        p2p_bind_interface_name,
        vpn_guard_enabled=vpn_guard_enabled,
        vpn_guard_allowed_public_ip_cidrs=vpn_guard_allowed_public_ip_cidrs,
    )


def build_amutorrent_environment(
    *,
    base_env: dict[str, str],
    amutorrent_port: int,
    emule_port: int,
    api_key: str,
    instance_id: str,
    lan_bind_addr: str,
    node_path: Path,
    data_dir: Path,
    use_ssl: bool = False,
    extra_ca_cert: str = "",
) -> dict[str, str]:
    """Builds the environment used by the interactive aMuTorrent server."""

    env = dict(base_env)
    lan_bind_host = rest_api_smoke.require_lan_bind_addr(lan_bind_addr)
    env.update(
        {
            "PORT": str(amutorrent_port),
            "lan_bind_address": lan_bind_host,
            "AMUTORRENT_DATA_DIR": str(data_dir),
            "WEB_AUTH_ENABLED": "false",
            "SKIP_SETUP_WIZARD": "true",
            "EMULEBB_ENABLED": "true",
            "EMULEBB_HOST": lan_bind_host,
            "EMULEBB_PORT": str(emule_port),
            "EMULEBB_API_KEY": api_key,
            "EMULEBB_USE_SSL": "true" if use_ssl else "false",
            "EMULEBB_ID": instance_id,
            "EMULEBB_NAME": "eMuleBB Interactive",
        }
    )
    if extra_ca_cert:
        env["NODE_EXTRA_CA_CERTS"] = extra_ca_cert
    if node_path.is_absolute():
        env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
    return env


def write_stop_script(
    path: Path,
    *,
    emule_pid: int | None,
    amutorrent_pid: int | None,
    emule_label: str = "eMuleBB",
) -> None:
    """Writes a command helper that stops the launched interactive processes."""

    process_rows = [
        (emule_label, emule_pid),
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
    parser.add_argument("--backend", choices=["native", "rust"], default="native")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--rust-exe")
    parser.add_argument("--rust-repo")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-interactive-key")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--vpn-guard-enabled", action="store_true")
    parser.add_argument("--vpn-guard-allowed-public-ip-cidrs", default="")
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--live-network", action="store_true")
    parser.add_argument("--no-open-browser", action="store_true")
    return parser


def prepare_rust_run_paths(args: argparse.Namespace) -> harness_cli_common.HarnessRunPaths:
    """Prepares report/artifact paths for a Rust-backed session without requiring a native app build."""

    repo_root = harness_cli_common.get_repo_root(__file__)
    workspace_root = harness_cli_common.get_default_workspace_root(repo_root)
    report_root = harness_cli_common.get_test_reports_root(workspace_root)
    harness_cli_common.reject_windows_temp_path(report_root, "report root")
    suite_report_root = report_root / "amutorrent-interactive-session"
    report_stamp = harness_cli_common.utc_run_id()
    report_label = f"{report_stamp}-emulebb-rust-{args.configuration.lower()}-{os.getpid()}"
    source_artifacts_dir = (
        Path(args.artifacts_dir).resolve()
        if args.artifacts_dir
        else (
            harness_cli_common.get_test_artifacts_root(workspace_root)
            / "amutorrent-interactive-session"
            / report_label
        ).resolve()
    )
    harness_cli_common.reject_windows_temp_path(source_artifacts_dir, "artifacts directory")
    source_artifacts_dir.mkdir(parents=True, exist_ok=True)
    rust_app_path = Path(args.rust_exe or args.rust_repo or repo_root).resolve()
    return harness_cli_common.HarnessRunPaths(
        repo_root=repo_root,
        workspace_root=workspace_root,
        output_root=harness_cli_common.get_workspace_output_root(),
        app_root=rust_app_path.parent,
        app_exe=rust_app_path,
        seed_config_dir=(repo_root / "manifests" / "live-profile-seed" / "config").resolve(),
        configuration=args.configuration,
        suite_name="amutorrent-interactive-session",
        source_artifacts_dir=source_artifacts_dir,
        run_report_dir=(suite_report_root / report_label).resolve(),
        latest_report_dir=(report_root / "amutorrent-interactive-session" / "latest").resolve(),
        keep_source_artifacts=True,
    )


def resolve_rust_executable(paths: harness_cli_common.HarnessRunPaths, args: argparse.Namespace) -> Path:
    """Returns the staged Rust executable path preferred by package-backed sessions."""

    if args.rust_exe:
        return Path(args.rust_exe).resolve()
    exe_name = "emulebb-rust.exe" if os.name == "nt" else "emulebb-rust"
    return paths.output_root / "tools" / "emulebb-rust" / "bin" / exe_name


def resolve_rust_repo(paths: harness_cli_common.HarnessRunPaths, args: argparse.Namespace) -> Path:
    """Returns the Rust repo path used when no staged executable is available."""

    if args.rust_repo:
        return Path(args.rust_repo).resolve()
    return paths.workspace_root.parent.parent / "repos" / "emulebb-rust"


def start_rust_backend(
    paths: harness_cli_common.HarnessRunPaths,
    args: argparse.Namespace,
    *,
    rest_addr: str,
    rest_port: int,
) -> tuple[subprocess.Popen[str], dict[str, str]]:
    """Starts the Rust client for an interactive aMuTorrent session."""

    runtime_dir = paths.source_artifacts_dir / "rust-runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    config_path = paths.source_artifacts_dir / "emulebb-rust.toml"
    rust_client.write_rust_config(
        config_path,
        runtime_dir=runtime_dir,
        rest_addr=rest_addr,
        rest_port=rest_port,
        api_key=args.api_key,
    )
    log_path = paths.source_artifacts_dir / "emulebb-rust.log"
    executable = resolve_rust_executable(paths, args)
    if executable.is_file():
        process = rust_client.start_rust_client_executable(executable, config_path, log_path)
        launch_mode = "executable"
        launched_from = executable
    else:
        rust_repo = resolve_rust_repo(paths, args)
        process = rust_client.start_rust_client(rust_repo, config_path, log_path)
        launch_mode = "cargo"
        launched_from = rust_repo
    return process, {
        "rust_launch_mode": launch_mode,
        "rust_launch_path": str(launched_from),
        "rust_config": str(config_path),
        "rust_runtime_dir": str(runtime_dir),
        "rust_log": str(log_path),
    }


def main() -> int:
    """Starts eMuleBB and aMuTorrent, then leaves both running for the operator."""

    args = build_parser().parse_args()
    if args.backend == "rust":
        paths = prepare_rust_run_paths(args)
    else:
        paths = harness_cli_common.prepare_run_paths(
            script_file=__file__,
            suite_name="amutorrent-interactive-session",
            configuration=args.configuration,
            workspace_root=None,
            app_root=args.app_root,
            app_exe=args.app_exe,
            artifacts_dir=args.artifacts_dir,
            keep_artifacts=True,
        )
    amutorrent_root = amutorrent_smoke.resolve_amutorrent_root(paths.workspace_root)
    node_info = amutorrent_smoke.resolve_amutorrent_node()

    emule_port = choose_listen_port(args.lan_bind_addr)
    amutorrent_port = choose_listen_port(args.lan_bind_addr)
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port(args.lan_bind_addr)

    lan_bind_addr = rest_api_smoke.require_lan_bind_addr(args.lan_bind_addr)
    emule_base_url = f"http://{lan_bind_addr}:{emule_port}"
    amutorrent_base_url = f"http://{lan_bind_addr}:{amutorrent_port}"
    instance_id = f"emulebb-{lan_bind_addr}-{emule_port}"
    artifacts_dir = paths.source_artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    amutorrent_data_dir = artifacts_dir / "amutorrent-data"

    profile: dict[str, Any] | None = None
    if args.backend == "native":
        seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
        profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="amutorrent-interactive-session")
        configure_session_profile(
            Path(profile["config_dir"]),
            paths.app_exe,
            args.api_key,
            emule_port,
            args.lan_bind_addr,
            args.p2p_bind_interface_name,
            live_network=bool(args.live_network),
            vpn_guard_enabled=args.vpn_guard_enabled,
            vpn_guard_allowed_public_ip_cidrs=args.vpn_guard_allowed_public_ip_cidrs,
        )

    report: dict[str, Any] = {
        "suite": "amutorrent-interactive-session",
        "status": "failed",
        "backend": args.backend,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "configuration": args.configuration,
        "live_network": bool(args.live_network),
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "enable_upnp": True,
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "amutorrent_root": str(amutorrent_root),
        "amutorrent_data_dir": str(amutorrent_data_dir),
        "node": node_info,
        "artifacts_dir": str(artifacts_dir),
        "checks": {},
        "cleanup": {},
    }
    if profile is not None:
        report["profile_base"] = str(profile["profile_base"])
        report["config_dir"] = str(profile["config_dir"])

    app = None
    rust_process: subprocess.Popen[str] | None = None
    amutorrent: subprocess.Popen[str] | None = None
    try:
        amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
        if args.backend == "rust":
            rust_process, rust_report = start_rust_backend(
                paths,
                args,
                rest_addr=lan_bind_addr,
                rest_port=emule_port,
            )
            report.update(rust_report)
            report["emule_process_id"] = rust_process.pid
        else:
            assert profile is not None
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
            lan_bind_addr=lan_bind_addr,
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
            emule_label="eMuleBB Rust" if args.backend == "rust" else "eMuleBB",
        )
        write_json(artifacts_dir / "amutorrent-interactive-session-result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)

        if not args.no_open_browser:
            webbrowser.open(amutorrent_base_url)

        print(f"eMuleBB REST: {emule_base_url}")
        print(f"aMuTorrent UI: {amutorrent_base_url}")
        print(f"Artifacts: {paths.run_report_dir}")
        print(f"Stop script: {paths.run_report_dir / 'stop-session.cmd'}")
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        write_json(artifacts_dir / "amutorrent-interactive-session-result.json", report)
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
        if rust_process is not None:
            rust_client.stop_process_tree(rust_process)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
