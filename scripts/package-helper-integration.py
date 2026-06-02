"""Runs package PowerShell helper registration checks against throwaway services."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_dependencies, workspace_layout  # noqa: E402

SUITE_NAME = "package-helper-integration"
INCONCLUSIVE_EXIT_CODE = 2


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
rest_smoke = load_local_module("package_helper_rest_smoke", "rest-api-smoke.py")
amutorrent_smoke = load_local_module("package_helper_amutorrent_smoke", "amutorrent-browser-smoke.py")


class InconclusiveSuite(RuntimeError):
    """Raised when external runtime dependencies are unavailable."""


def read_json_url(base_url: str, path: str, *, api_key: str | None = None, timeout_seconds: float = 15.0) -> Any:
    headers = {}
    if api_key:
        headers["X-Api-Key"] = api_key
    request = urllib.request.Request(base_url.rstrip("/") + path, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        text = response.read().decode("utf-8", errors="replace")
        return json.loads(text) if text else None


def wait_for_http(base_url: str, path: str, *, api_key: str | None = None, timeout_seconds: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            read_json_url(base_url, path, api_key=api_key, timeout_seconds=5.0)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {base_url}{path}: {last_error!r}")


def invoke_json_api(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    api_key: str | None = None,
    body: object | None = None,
    timeout_seconds: float = 30.0,
) -> Any:
    data = None
    headers = {}
    if api_key:
        headers["X-Api-Key"] = api_key
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        text = response.read().decode("utf-8", errors="replace")
        return json.loads(text) if text else None


def write_arr_config(data_dir: Path, *, port: int, api_key: str, instance_name: str, lan_bind_addr: str) -> Path:
    """Writes the minimal Servarr config needed for isolated LAN-bound tests."""

    data_dir.mkdir(parents=True, exist_ok=True)
    config_path = data_dir / "config.xml"
    config_path.write_text(
        "\n".join(
            [
                "<Config>",
                f"  <LogLevel>info</LogLevel>",
                f"  <Port>{port}</Port>",
                "  <UrlBase></UrlBase>",
                f"  <BindAddress>{lan_bind_addr}</BindAddress>",
                "  <EnableSsl>False</EnableSsl>",
                f"  <ApiKey>{api_key}</ApiKey>",
                "  <AuthenticationMethod>None</AuthenticationMethod>",
                "  <AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>",
                "  <LaunchBrowser>False</LaunchBrowser>",
                f"  <InstanceName>{instance_name}</InstanceName>",
                "</Config>",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config_path


def start_arr(name: str, exe_path: Path, data_dir: Path, port: int, api_key: str, log_path: Path, lan_bind_addr: str) -> subprocess.Popen[str]:
    write_arr_config(data_dir, port=port, api_key=api_key, instance_name=f"eMuleBB {name} helper test", lan_bind_addr=lan_bind_addr)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    output = log_path.open("w", encoding="utf-8", errors="replace")
    process = subprocess.Popen(
        [str(exe_path), f"/data={data_dir}", "/nobrowser"],
        cwd=str(exe_path.parent),
        stdout=output,
        stderr=subprocess.STDOUT,
        text=True,
    )
    process._emulebb_log_handle = output  # type: ignore[attr-defined]
    return process


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)
    handle = getattr(process, "_emulebb_log_handle", None)
    if handle is not None:
        handle.close()


def powershell_command() -> str:
    for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        if shutil_which(name):
            return name
    raise InconclusiveSuite("PowerShell was not found on PATH")


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


def run_helper(script_path: Path, args: list[str], report: dict[str, Any], key: str, *, expect_success: bool = True) -> None:
    command = [
        powershell_command(),
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        *args,
        "-NoRetry",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    report.setdefault("helper_runs", {})[key] = {
        "script": script_path.name,
        "return_code": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
        "expected_success": expect_success,
    }
    if expect_success and completed.returncode != 0:
        raise RuntimeError(f"{script_path.name} failed for {key}: {completed.stderr or completed.stdout}")
    if not expect_success and completed.returncode == 0:
        raise RuntimeError(f"{script_path.name} unexpectedly succeeded for {key}")


def helper_scripts_root(build_repo_root: Path) -> Path:
    root = build_repo_root / "emule_workspace" / "release_assets" / "emulebb" / "scripts"
    if not root.is_dir():
        raise RuntimeError(f"Package helper scripts root not found: {root}")
    return root


def resolve_arr_dependencies(args: argparse.Namespace, paths) -> dict[str, live_dependencies.PortableDependency]:
    cache_root = Path(args.dependency_cache_root).resolve() if args.dependency_cache_root else None
    overrides = {
        "prowlarr": args.prowlarr_exe,
        "radarr": args.radarr_exe,
        "sonarr": args.sonarr_exe,
    }
    resolved: dict[str, live_dependencies.PortableDependency] = {}
    unavailable: list[str] = []
    for name in ("prowlarr", "radarr", "sonarr"):
        try:
            resolved[name] = live_dependencies.resolve_portable_dependency(
                name,
                workspace_root=paths.workspace_root,
                cache_root=cache_root,
                mode=args.dependency_mode,
                channel=args.dependency_channel,
                override_exe=overrides[name],
                refresh=args.refresh_dependencies,
            )
        except live_dependencies.DependencyUnavailableError as exc:
            unavailable.append(f"{name}: {exc}")
    if unavailable:
        raise InconclusiveSuite("; ".join(unavailable))
    return resolved


def list_named_provider(base_url: str, api_key: str, path: str, name: str) -> dict[str, Any] | None:
    rows = invoke_json_api(base_url, path, api_key=api_key)
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and row.get("name") == name:
            return row
    return None


def run_suite(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
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
    artifacts_dir = paths.source_artifacts_dir
    result_path = artifacts_dir / f"{SUITE_NAME}-result.json"
    build_repo_root = workspace_layout.resolve_workspace_repo(paths.workspace_root, "build")
    amutorrent_root = amutorrent_smoke.resolve_amutorrent_root(paths.workspace_root)
    report: dict[str, Any] = {
        "suite": SUITE_NAME,
        "status": "failed",
        "dependency_mode": args.dependency_mode,
        "dependency_channel": args.dependency_channel,
        "dependencies": {},
        "checks": {},
        "helper_runs": {},
    }

    app = None
    amutorrent_process: subprocess.Popen[str] | None = None
    arr_processes: list[subprocess.Popen[str]] = []
    amutorrent_log_output = None
    try:
        try:
            arr = resolve_arr_dependencies(args, paths)
        except InconclusiveSuite as exc:
            # Missing external Arr tools mean the package helper wiring cannot
            # be evaluated, but that is an environment problem rather than a
            # product regression. Report it distinctly so release gates can
            # separate "not provisioned" from "helper failed".
            report["status"] = "inconclusive"
            report["reason"] = str(exc)
            live_common.write_json(result_path, report)
            return INCONCLUSIVE_EXIT_CODE, report
        report["dependencies"] = {name: dependency.to_report() for name, dependency in arr.items()}

        node_info = amutorrent_smoke.resolve_amutorrent_node()
        amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
        report["dependencies"]["amutorrent_node"] = node_info

        seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
        lan_bind_addr = rest_smoke.require_lan_bind_addr(args.lan_bind_addr)
        emule_port = rest_smoke.choose_listen_port(lan_bind_addr)
        amutorrent_port = rest_smoke.choose_listen_port(lan_bind_addr)
        prowlarr_port = rest_smoke.choose_listen_port(lan_bind_addr)
        radarr_port = rest_smoke.choose_listen_port(lan_bind_addr)
        sonarr_port = rest_smoke.choose_listen_port(lan_bind_addr)
        emule_api_key = args.api_key
        prowlarr_api_key = secrets.token_hex(16)
        radarr_api_key = secrets.token_hex(16)
        sonarr_api_key = secrets.token_hex(16)
        emule_base_url = f"http://{lan_bind_addr}:{emule_port}"
        amutorrent_base_url = f"http://{lan_bind_addr}:{amutorrent_port}"
        prowlarr_base_url = f"http://{lan_bind_addr}:{prowlarr_port}"
        radarr_base_url = f"http://{lan_bind_addr}:{radarr_port}"
        sonarr_base_url = f"http://{lan_bind_addr}:{sonarr_port}"

        profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id=SUITE_NAME)
        rest_smoke.configure_webserver_profile(Path(profile["config_dir"]), paths.app_exe, emule_api_key, emule_port, lan_bind_addr)
        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]))
        live_common.wait_for_main_window(app)
        report["checks"]["emule_rest_ready"] = rest_smoke.wait_for_rest_ready(emule_base_url, emule_api_key, args.ready_timeout_seconds)

        arr_roots = artifacts_dir / "arr-profiles"
        arr_specs = [
            ("prowlarr", arr["prowlarr"].exe_path, arr_roots / "prowlarr", prowlarr_port, prowlarr_api_key, prowlarr_base_url, "/api/v1/system/status"),
            ("radarr", arr["radarr"].exe_path, arr_roots / "radarr", radarr_port, radarr_api_key, radarr_base_url, "/api/v3/system/status"),
            ("sonarr", arr["sonarr"].exe_path, arr_roots / "sonarr", sonarr_port, sonarr_api_key, sonarr_base_url, "/api/v3/system/status"),
        ]
        for name, exe_path, data_dir, port, api_key, base_url, status_path in arr_specs:
            assert exe_path is not None
            process = start_arr(name, exe_path, data_dir, port, api_key, artifacts_dir / f"{name}.log", lan_bind_addr)
            arr_processes.append(process)
            wait_for_http(base_url, status_path, api_key=api_key, timeout_seconds=args.ready_timeout_seconds)
            report["checks"][f"{name}_ready"] = {"port": port, "pid": process.pid}

        amutorrent_data_dir = artifacts_dir / "amutorrent-data"
        amutorrent_log_path = artifacts_dir / "amutorrent.log"
        amutorrent_log_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
        env = os.environ.copy()
        env.update(
            {
                "PORT": str(amutorrent_port),
                "lan_bind_address": lan_bind_addr,
                "AMUTORRENT_DATA_DIR": str(amutorrent_data_dir),
                "WEB_AUTH_ENABLED": "false",
                "SKIP_SETUP_WIZARD": "true",
            }
        )
        node_path = Path(str(node_info["path"]))
        if node_path.is_absolute():
            env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
        amutorrent_process = subprocess.Popen(
            [str(node_path), "server/server.js"],
            cwd=str(amutorrent_root),
            env=env,
            stdout=amutorrent_log_output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_http(amutorrent_base_url, "/api/config/status", timeout_seconds=args.ready_timeout_seconds)
        report["checks"]["amutorrent_ready"] = {"port": amutorrent_port, "pid": amutorrent_process.pid}

        scripts_root = helper_scripts_root(build_repo_root)
        run_helper(
            scripts_root / "register-amutorrent.ps1",
            [
                "-AmutorrentUrl",
                amutorrent_base_url,
                "-AmutorrentApiKey",
                "",
                "-EmulebbBaseUrl",
                emule_base_url,
                "-EmulebbApiKey",
                emule_api_key,
                "-InstanceName",
                "eMuleBB Helper Test",
                "-InstanceId",
                f"emulebb-helper-{emule_port}",
            ],
            report,
            "amutorrent_register",
        )
        current_config = invoke_json_api(amutorrent_base_url, "/api/config/current")
        clients = current_config.get("clients") if isinstance(current_config, dict) else []
        report["checks"]["amutorrent_client_registered"] = {
            "client_count": len(clients) if isinstance(clients, list) else 0,
            "matched": any(isinstance(client, dict) and client.get("name") == "eMuleBB Helper Test" for client in clients or []),
        }
        if not report["checks"]["amutorrent_client_registered"]["matched"]:
            raise RuntimeError("aMuTorrent helper did not create the eMuleBB client")
        # Keep the unregister path covered without leaving aMuTorrent in an
        # unusable no-client state. The helper is expected to refuse removal of
        # the last enabled client; the suite verifies that guard still fires.
        run_helper(
            scripts_root / "register-amutorrent.ps1",
            [
                "-Action",
                "Unregister",
                "-AmutorrentUrl",
                amutorrent_base_url,
                "-AmutorrentApiKey",
                "",
                "-InstanceName",
                "eMuleBB Helper Test",
                "-InstanceId",
                f"emulebb-helper-{emule_port}",
            ],
            report,
            "amutorrent_last_client_refusal",
            expect_success=False,
        )

        run_helper(
            scripts_root / "register-prowlarr.ps1",
            [
                "-ProwlarrUrl",
                prowlarr_base_url,
                "-ProwlarrApiKey",
                prowlarr_api_key,
                "-EmulebbBaseUrl",
                emule_base_url,
                "-EmulebbApiKey",
                emule_api_key,
                "-IndexerName",
                "eMuleBB Helper Test",
            ],
            report,
            "prowlarr_register",
        )
        report["checks"]["prowlarr_indexer_registered"] = list_named_provider(
            prowlarr_base_url,
            prowlarr_api_key,
            "/api/v1/indexer",
            "eMuleBB Helper Test",
        ) is not None
        if not report["checks"]["prowlarr_indexer_registered"]:
            raise RuntimeError("Prowlarr helper did not create the indexer")

        for target, base_url, api_key, check_path in (
            ("Radarr", radarr_base_url, radarr_api_key, "/api/v3/downloadclient"),
            ("Sonarr", sonarr_base_url, sonarr_api_key, "/api/v3/downloadclient"),
        ):
            run_helper(
                scripts_root / "register-arr-stack.ps1",
                [
                    "-Target",
                    target,
                    "-EmulebbBaseUrl",
                    emule_base_url,
                    "-EmulebbApiKey",
                    emule_api_key,
                    f"-{target}Url",
                    base_url,
                    f"-{target}ApiKey",
                    api_key,
                    "-ProwlarrUrl",
                    prowlarr_base_url,
                    "-ProwlarrApiKey",
                    prowlarr_api_key,
                    "-DownloadClientName",
                    "eMuleBB Helper Test",
                ],
                report,
                f"{target.lower()}_register",
            )
            report["checks"][f"{target.lower()}_download_client_registered"] = list_named_provider(
                base_url,
                api_key,
                check_path,
                "eMuleBB Helper Test",
            ) is not None
            if not report["checks"][f"{target.lower()}_download_client_registered"]:
                raise RuntimeError(f"{target} helper did not create the download client")

        report["status"] = "passed"
        live_common.write_json(result_path, report)
        return 0, report
    except InconclusiveSuite as exc:
        report["status"] = "inconclusive"
        report["reason"] = str(exc)
        live_common.write_json(result_path, report)
        return INCONCLUSIVE_EXIT_CODE, report
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        live_common.write_json(result_path, report)
        return 1, report
    finally:
        stop_process(amutorrent_process)
        if amutorrent_log_output is not None:
            amutorrent_log_output.close()
        for process in reversed(arr_processes):
            stop_process(process)
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:
                app.kill()
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
            harness_cli_common.cleanup_source_artifacts(paths)
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default="package-helper-test-key")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--ready-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--dependency-mode", choices=live_dependencies.DEPENDENCY_MODES, default="cache-only")
    parser.add_argument("--dependency-channel", choices=live_dependencies.DEPENDENCY_CHANNELS, default="pinned")
    parser.add_argument("--dependency-cache-root")
    parser.add_argument("--refresh-dependencies", action="store_true")
    parser.add_argument("--prowlarr-exe")
    parser.add_argument("--radarr-exe")
    parser.add_argument("--sonarr-exe")
    return parser


def main() -> int:
    return run_suite(build_parser().parse_args())[0]


if __name__ == "__main__":
    raise SystemExit(main())
