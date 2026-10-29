"""Rust ed2k-server configuration and normalized admin control."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ed2k_server import ManagedProcess, UnsupportedEd2kServerCapability
from .multi_client import resolve_manifest_repo
from .paths import get_workspace_output_root, reject_windows_temp_path
from .script_modules import load_script_module


live_common = load_script_module("emule_live_profile_common_rust_ed2k", "emule-live-profile-common.py")
RUST_ED2K_SERVER_EXE_ENV = "EMULEBB_TEST_RUST_ED2K_SERVER_EXE"
RUST_ED2K_WSL_DISTRIBUTION_ENV = "EMULEBB_TEST_WSL_DISTRIBUTION"


@dataclass(frozen=True)
class RustEd2kServerBinary:
    """Resolved staged Rust server executable and its build result."""

    server_exe: Path
    build: dict[str, object]


@dataclass(frozen=True)
class RustEd2kServerLaunch:
    """Result of launching one local Rust ed2k-server instance."""

    process: ManagedProcess
    admin_base_url: str
    ed2k_host: str
    ed2k_port: int
    server_exe: Path
    server_dir: Path
    config_path: Path
    log_path: Path
    build: dict[str, object]
    config: dict[str, object]
    health: dict[str, Any]


def resolve_server_repo(workspace_root: Path, override: str | None) -> Path:
    """Resolves the managed Rust server repository from the workspace manifest."""

    candidate = Path(override).resolve() if override else resolve_manifest_repo(workspace_root, "ed2k_server")
    if not (candidate / "Cargo.toml").is_file():
        raise RuntimeError(f"Rust ED2K server repo was not found at '{candidate}'.")
    return candidate


def resolve_server_exe(override: str | None) -> Path:
    """Resolves the staged Linux Rust server binary under the output root."""

    if override:
        return Path(override).resolve()
    return (get_workspace_output_root() / "tools" / "ed2k-server" / "bin" / "ed2k-server").resolve()


def env_server_exe_override(env: dict[str, str] | None = None) -> str | None:
    """Returns the Rust server executable override passed to harness children."""

    value = (env or os.environ).get(RUST_ED2K_SERVER_EXE_ENV, "").strip()
    return value or None


def build_or_skip_server_binary(
    workspace_root: Path,
    server_exe: Path,
    *,
    repo_override: str | None = None,
    exe_override: str | None = None,
) -> dict[str, object]:
    """Builds through emule_workspace unless an explicit staged binary is supplied."""

    reject_windows_temp_path(server_exe.parent, "Rust ED2K server binary directory")
    if exe_override:
        if not server_exe.is_file():
            raise RuntimeError(f"Explicit Rust ED2K server binary was not found: {server_exe}")
        return {
            "command": [],
            "cwd": "",
            "return_code": 0,
            "server_exe": str(server_exe),
            "skipped": True,
            "reason": "using explicit Rust ED2K server executable",
        }
    if repo_override:
        raise RuntimeError(
            "Rust --ed2k-server-repo overrides require --ed2k-server-exe; canonical Rust builds are owned by emule_workspace."
        )
    resolve_server_repo(workspace_root, None)
    build_repo = resolve_manifest_repo(workspace_root, "build")
    command = [
        sys.executable,
        "-m",
        "emule_workspace",
        "build",
        "ed2k-server",
        "--config",
        "Release",
        "--platform",
        "x64",
    ]
    completed = subprocess.run(
        command,
        cwd=build_repo,
        text=True,
        capture_output=True,
        timeout=900,
        check=False,
    )
    result = {
        "command": command,
        "cwd": str(build_repo),
        "return_code": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "server_exe": str(server_exe),
    }
    if completed.returncode != 0:
        raise RuntimeError(f"Rust ED2K server build failed: {result!r}")
    if not server_exe.is_file():
        raise RuntimeError(f"Rust ED2K server build did not stage the expected binary: {server_exe}")
    return result


def prepare_server_binary(
    workspace_root: Path,
    *,
    repo_override: str | None = None,
    exe_override: str | None = None,
) -> RustEd2kServerBinary:
    """Resolves and stages the Linux Rust server binary."""

    effective_override = exe_override or env_server_exe_override()
    server_exe = resolve_server_exe(effective_override)
    build = build_or_skip_server_binary(
        workspace_root,
        server_exe,
        repo_override=repo_override,
        exe_override=effective_override,
    )
    return RustEd2kServerBinary(server_exe=server_exe, build=build)


def _wsl_command(distribution: str | None, *arguments: str) -> list[str]:
    command = ["wsl.exe"]
    if distribution:
        command.extend(("--distribution", distribution))
    command.extend(("--", *arguments))
    return command


def wsl_path(path: Path, distribution: str | None = None) -> str:
    """Translates an existing Windows path into the selected WSL distribution."""

    completed = subprocess.run(
        _wsl_command(distribution, "wslpath", "-a", "-u", path.resolve().as_posix()),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    translated = completed.stdout.strip()
    if completed.returncode != 0 or not translated.startswith("/"):
        raise RuntimeError(f"WSL path translation failed for {path}: {completed.stderr.strip()}")
    return translated


def wsl_ipv4_address(distribution: str | None = None) -> str:
    """Returns the WSL address selected by its default IPv4 route."""

    completed = subprocess.run(
        _wsl_command(distribution, "ip", "-j", "-4", "route", "get", "1.1.1.1"),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    try:
        routes = json.loads(completed.stdout)
        address = str(routes[0].get("prefsrc") or "") if isinstance(routes, list) and routes else ""
    except (json.JSONDecodeError, AttributeError):
        address = ""
    if completed.returncode != 0 or not address:
        raise RuntimeError(f"Could not resolve the WSL IPv4 address: {completed.stderr.strip()}")
    return address


@dataclass
class RustWslProcess:
    """WSL process proxy with PID-backed Linux process-group signaling."""

    proxy: subprocess.Popen
    pid_path: Path
    distribution: str | None = None

    @property
    def returncode(self) -> int | None:
        return self.proxy.returncode

    def poll(self) -> int | None:
        return self.proxy.poll()

    def _signal(self, signal_name: str) -> None:
        try:
            linux_pid = int(self.pid_path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            if self.proxy.poll() is None:
                self.proxy.terminate()
            return
        completed = subprocess.run(
            _wsl_command(self.distribution, "kill", f"-{signal_name}", "--", f"-{linux_pid}"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            subprocess.run(
                _wsl_command(self.distribution, "kill", f"-{signal_name}", str(linux_pid)),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )

    def terminate(self) -> None:
        self._signal("TERM")

    def kill(self) -> None:
        self._signal("KILL")
        if self.proxy.poll() is None:
            self.proxy.kill()

    def wait(self, timeout: float | None = None) -> int:
        return self.proxy.wait(timeout=timeout)


def _is_windows_host() -> bool:
    return os.name == "nt"


def start_server(
    server_exe: Path,
    config_path: Path,
    log_path: Path,
    pid_path: Path,
    *,
    distribution: str | None = None,
) -> ManagedProcess:
    """Starts the Linux Rust server directly or through a managed WSL process."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("wb", buffering=0)
    try:
        if _is_windows_host():
            linux_exe = wsl_path(server_exe, distribution)
            linux_config = wsl_path(config_path, distribution)
            linux_pid = wsl_path(pid_path, distribution)
            proxy = subprocess.Popen(
                _wsl_command(
                    distribution,
                    "setsid",
                    "--wait",
                    "/bin/sh",
                    "-c",
                    "printf '%s\\n' \"$$\" > \"$1\"; shift; exec \"$@\"",
                    "emulebb-ed2k-server",
                    linux_pid,
                    linux_exe,
                    "--config",
                    linux_config,
                ),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
            return RustWslProcess(proxy=proxy, pid_path=pid_path, distribution=distribution)
        return subprocess.Popen(
            [str(server_exe), "--config", str(config_path)],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            cwd=server_exe.parent,
            start_new_session=True,
        )
    finally:
        log_handle.close()


def stop_process(process: ManagedProcess | None, *, timeout_seconds: float = 10.0) -> None:
    """Stops one direct or WSL Rust server process without leaving descendants."""

    if process is None:
        return
    if not isinstance(process, RustWslProcess) and process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout_seconds)


def wait_for_admin_health(
    admin_base_url: str,
    process: ManagedProcess,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits for Rust readiness and fails immediately on an early process exit."""

    def resolve():
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(f"Rust ed2k-server exited before readiness with code {return_code}.")
        try:
            payload = admin_request(admin_base_url, "/api/ready", timeout_seconds=2.0)
        except (OSError, RuntimeError, json.JSONDecodeError):
            return None
        if isinstance(payload, dict) and payload.get("ready") is True:
            return {"ok": True, "data": payload}
        return None

    return live_common.wait_for(resolve, timeout_seconds, 0.5, "Rust ED2K server admin readiness")


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def build_server_config(
    path: Path,
    *,
    ed2k_port: int,
    admin_port: int,
    listen_address: str,
    advertised_address: str,
    protocol_obfuscation: bool = True,
    offerfiles_v1: bool = False,
    soft_limit_files: int = 5000,
    hard_limit_files: int = 200000,
    server_name: str = "emulebb-local-e2e",
) -> dict[str, object]:
    """Writes a minimal private Rust server configuration for local harness runs."""

    if not listen_address.strip():
        raise ValueError("listen_address must be explicit.")
    if not advertised_address.strip():
        raise ValueError("advertised_address must be explicit.")
    if soft_limit_files < 0:
        raise ValueError("soft_limit_files must be non-negative.")
    if hard_limit_files < 0:
        raise ValueError("hard_limit_files must be non-negative.")
    config: dict[str, object] = {
        "server": {
            "name": server_name,
            "desc": "Workspace deterministic eMuleBB live E2E server",
            "this_ip": advertised_address,
            "public": False,
        },
        "network": {
            "tcp_port": ed2k_port,
            "listen_ip": listen_address,
            "support_crypt": protocol_obfuscation,
            "private_highid_probe": True,
        },
        "limits": {
            "max_clients": 1000,
            "soft_limit_files": soft_limit_files,
            "hard_limit_files": hard_limit_files,
            "ping_delay_seconds": 600,
            "offerfiles_v1": offerfiles_v1,
        },
        "content_filter": {
            "hash_banlist": [],
            "hash_filter": [],
            "publisher_count_window_seconds": 86400,
        },
        "welcome": {
            "messages": ["Workspace deterministic eMuleBB live E2E server"],
        },
        "log": {
            "level": "info",
            "connection_trace": False,
        },
        "storage": {
            "ipfilter_path": "",
            "country_db_path": "",
            "geoip_mmdb_path": "off",
            "bot_log_path": "off",
        },
        "admin": {
            "enabled": True,
            "port": admin_port,
            "bind": "127.0.0.1",
            "tls": "off",
        },
        "updates": {
            "enabled": False,
        },
    }
    lines = [
        "[server]",
        f"name = {_toml_string(server_name)}",
        f"desc = {_toml_string(str(config['server']['desc']))}",
        f"this_ip = {_toml_string(advertised_address)}",
        "public = false",
        "",
        "[network]",
        f"tcp_port = {ed2k_port}",
        f"listen_ip = {_toml_string(listen_address)}",
        f"support_crypt = {str(protocol_obfuscation).lower()}",
        "private_highid_probe = true",
        "",
        "[limits]",
        "max_clients = 1000",
        f"soft_limit_files = {soft_limit_files}",
        f"hard_limit_files = {hard_limit_files}",
        "ping_delay_seconds = 600",
        f"offerfiles_v1 = {str(offerfiles_v1).lower()}",
        "",
        "[content_filter]",
        "hash_banlist = []",
        "hash_filter = []",
        "publisher_count_window_seconds = 86400",
        "",
        "[welcome]",
        f"messages = [{_toml_string('Workspace deterministic eMuleBB live E2E server')}]",
        "",
        "[log]",
        'level = "info"',
        "connection_trace = false",
        "",
        "[storage]",
        'ipfilter_path = ""',
        'country_db_path = ""',
        'geoip_mmdb_path = "off"',
        'bot_log_path = "off"',
        "",
        "[admin]",
        "enabled = true",
        f"port = {admin_port}",
        'bind = "127.0.0.1"',
        'tls = "off"',
        "",
        "[updates]",
        "enabled = false",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return config


def admin_request(admin_base_url: str, path: str, *, timeout_seconds: float = 10.0) -> Any:
    """Reads one JSON response from the loopback-only Rust admin service."""

    request = urllib.request.Request(admin_base_url + path)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        data = exc.read()
        raise RustEd2kAdminError(path, exc.code, data) from exc
    return json.loads(data.decode("utf-8"))


class RustEd2kAdminError(RuntimeError):
    """One non-success response from the Rust server admin API."""

    def __init__(self, path: str, status_code: int, body: bytes) -> None:
        self.path = path
        self.status_code = status_code
        self.body = body
        super().__init__(f"Rust ED2K admin request failed: {path} status={status_code} body={body!r}")


def normalize_file_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalizes the Rust exact-file response to the provider-neutral shape."""

    native_sources = payload.get("sources")
    endpoints: list[dict[str, Any]] = []
    if isinstance(native_sources, list):
        for source in native_sources:
            if not isinstance(source, dict):
                continue
            endpoints.append(
                {
                    "host": str(source.get("ip") or ""),
                    "port": int(source.get("port") or 0),
                    "complete": bool(source.get("complete")),
                    "user_hash": str(source.get("user_hash") or "").upper(),
                }
            )
    source_count = payload.get("source_count")
    complete_source_count = payload.get("complete_source_count")
    return {
        "hash": str(payload.get("hash") or "").upper(),
        "name": str(payload.get("name") or ""),
        "size": int(payload.get("size") or 0),
        "sources": int(source_count) if source_count is not None else len(endpoints),
        "complete_sources": (
            int(complete_source_count)
            if complete_source_count is not None
            else sum(1 for endpoint in endpoints if endpoint["complete"])
        ),
        "endpoints": endpoints,
        "sources_truncated": bool(payload.get("sources_truncated")),
    }


@dataclass(frozen=True)
class RustEd2kServerControl:
    """Semantic control adapter over the Rust server's native admin API."""

    admin_base_url: str

    def stats(self) -> dict[str, Any]:
        return {"ok": True, "data": admin_request(self.admin_base_url, "/api/stats")}

    def list_clients(self) -> list[dict[str, Any]]:
        payload = admin_request(self.admin_base_url, "/api/clients")
        if not isinstance(payload, list):
            raise RuntimeError(f"Rust ED2K clients response was not a list: {payload!r}")
        clients: list[dict[str, Any]] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            normalized = dict(row)
            normalized["client_name"] = str(row.get("nick") or "")
            clients.append(normalized)
        return clients

    def get_file(self, file_hash: str) -> dict[str, Any] | None:
        try:
            payload = admin_request(self.admin_base_url, f"/api/files/{file_hash.upper()}")
        except RustEd2kAdminError as exc:
            if exc.status_code == 404:
                return None
            raise
        if not isinstance(payload, dict):
            raise RuntimeError(f"Rust ED2K file response was not an object: {payload!r}")
        return normalize_file_response(payload)

    def wait_for_client(self, name_fragment: str, timeout_seconds: float) -> dict[str, Any]:
        observations: list[dict[str, object]] = []

        def resolve():
            rows = self.list_clients()
            observations.append({"count": len(rows), "observed_at": round(time.time(), 3)})
            for row in rows:
                if name_fragment.lower() in str(row.get("client_name") or "").lower():
                    result = dict(row)
                    result["observations"] = observations
                    return result
            return None

        return live_common.wait_for(resolve, timeout_seconds, 1.0, f"ED2K client {name_fragment!r}")

    def wait_for_client_absent(
        self,
        name_fragment: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Waits until no connected client name contains the requested fragment."""

        observations: list[dict[str, object]] = []

        def resolve():
            rows = self.list_clients()
            matches = [
                row
                for row in rows
                if name_fragment.lower() in str(row.get("client_name") or "").lower()
            ]
            observations.append(
                {
                    "count": len(rows),
                    "matching_count": len(matches),
                    "observed_at": round(time.time(), 3),
                }
            )
            if matches:
                return None
            return {"absent": True, "observations": observations}

        return live_common.wait_for(
            resolve,
            timeout_seconds,
            1.0,
            f"ED2K client {name_fragment!r} withdrawal",
        )

    def wait_for_client_shared_files(
        self,
        name_fragment: str,
        minimum_shared_files: int,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Waits until a named client publishes at least the requested file count."""

        observations: list[dict[str, object]] = []

        def resolve():
            rows = self.list_clients()
            for row in rows:
                if name_fragment.lower() not in str(row.get("client_name") or "").lower():
                    continue
                shared_files = int(row.get("shared_files") or 0)
                observations.append(
                    {
                        "shared_files": shared_files,
                        "observed_at": round(time.time(), 3),
                    }
                )
                if shared_files >= minimum_shared_files:
                    result = dict(row)
                    result["observations"] = observations
                    return result
                return None
            observations.append(
                {
                    "shared_files": None,
                    "observed_at": round(time.time(), 3),
                }
            )
            return None

        return live_common.wait_for(
            resolve,
            timeout_seconds,
            1.0,
            f"ED2K client {name_fragment!r} shared-file publication",
        )

    def wait_for_file(self, file_hash: str, timeout_seconds: float) -> dict[str, Any]:
        observations: list[dict[str, object]] = []

        def resolve():
            row = self.get_file(file_hash)
            if row is not None:
                result = dict(row)
                result["observations"] = observations
                return result
            observations.append({"observed_at": round(time.time(), 3), "indexed": False})
            return None

        return live_common.wait_for(resolve, timeout_seconds, 1.0, "ED2K server file publication")

    def wait_for_file_endpoint(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
    ) -> dict[str, Any]:
        def resolve():
            row = self.get_file(file_hash)
            if row is None:
                return None
            endpoints = row.get("endpoints")
            if not isinstance(endpoints, list):
                return None
            if any(
                isinstance(endpoint, dict)
                and endpoint.get("host") == host
                and int(endpoint.get("port") or 0) == port
                for endpoint in endpoints
            ):
                return row
            return None

        return live_common.wait_for(resolve, timeout_seconds, 1.0, description)

    def wait_for_file_endpoint_absent(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint withdrawal",
    ) -> dict[str, Any]:
        """Waits until one exact published endpoint is absent from a file."""

        observations: list[dict[str, object]] = []

        def resolve():
            row = self.get_file(file_hash)
            if row is None:
                observations.append(
                    {
                        "indexed": False,
                        "endpoint_present": False,
                        "observed_at": round(time.time(), 3),
                    }
                )
                return {"absent": True, "file": None, "observations": observations}
            endpoints = row.get("endpoints")
            endpoint_rows = endpoints if isinstance(endpoints, list) else []
            endpoint_present = any(
                isinstance(endpoint, dict)
                and endpoint.get("host") == host
                and int(endpoint.get("port") or 0) == port
                for endpoint in endpoint_rows
            )
            observations.append(
                {
                    "indexed": True,
                    "endpoint_count": len(endpoint_rows),
                    "endpoint_present": endpoint_present,
                    "observed_at": round(time.time(), 3),
                }
            )
            if endpoint_present:
                return None
            return {"absent": True, "file": row, "observations": observations}

        return live_common.wait_for(resolve, timeout_seconds, 1.0, description)


def launch_server(
    *,
    workspace_root: Path,
    server_dir: Path,
    ed2k_port: int,
    admin_port: int,
    admin_secret: str,
    admin_address: str,
    ed2k_address: str | None = None,
    fixture_files: list[dict[str, object]] | None = None,
    repo_override: str | None = None,
    exe_override: str | None = None,
    protocol_obfuscation: bool = True,
    offerfiles_v1: bool = False,
    soft_limit_files: int = 5000,
    hard_limit_files: int = 200000,
    server_udp: bool = True,
    packet_trace: bool = False,
    health_timeout_seconds: float = 30.0,
) -> RustEd2kServerLaunch:
    """Launches the upstream-aligned Linux Rust server."""

    del admin_secret, admin_address
    if fixture_files:
        raise UnsupportedEd2kServerCapability(
            "Rust ed2k-server fixtures must be published through ED2K; static catalog seeding is unavailable."
        )
    if packet_trace:
        raise UnsupportedEd2kServerCapability(
            "Rust ed2k-server structured packet tracing is not implemented yet."
        )
    if not server_udp:
        raise UnsupportedEd2kServerCapability("Rust ed2k-server always enables its protocol UDP sockets.")
    if not ed2k_address:
        raise ValueError("ed2k_address must identify the client-side harness interface.")

    binary = prepare_server_binary(
        workspace_root,
        repo_override=repo_override,
        exe_override=exe_override,
    )
    distribution = os.environ.get(RUST_ED2K_WSL_DISTRIBUTION_ENV, "").strip() or None
    if _is_windows_host():
        advertised_address = wsl_ipv4_address(distribution)
        listen_address = "0.0.0.0"
        client_address = "127.0.0.1"
    else:
        advertised_address = ed2k_address
        listen_address = ed2k_address
        client_address = ed2k_address
    server_dir.mkdir(parents=True, exist_ok=True)
    config_path = server_dir / "config.toml"
    log_path = server_dir / "server.log"
    pid_path = server_dir / "server.pid"
    config = build_server_config(
        config_path,
        ed2k_port=ed2k_port,
        admin_port=admin_port,
        listen_address=listen_address,
        advertised_address=advertised_address,
        protocol_obfuscation=protocol_obfuscation,
        offerfiles_v1=offerfiles_v1,
        soft_limit_files=soft_limit_files,
        hard_limit_files=hard_limit_files,
    )
    process = start_server(
        binary.server_exe,
        config_path,
        log_path,
        pid_path,
        distribution=distribution,
    )
    admin_base_url = f"http://127.0.0.1:{admin_port}"
    try:
        health = wait_for_admin_health(admin_base_url, process, health_timeout_seconds)
    except Exception as exc:
        stop_process(process)
        log_tail = ""
        if log_path.is_file():
            log_tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        raise RuntimeError(f"Rust ed2k-server failed readiness: {exc}; log_tail={log_tail!r}") from exc
    return RustEd2kServerLaunch(
        process=process,
        admin_base_url=admin_base_url,
        ed2k_host=client_address,
        ed2k_port=ed2k_port,
        server_exe=binary.server_exe,
        server_dir=server_dir,
        config_path=config_path,
        log_path=log_path,
        build=binary.build,
        config=config,
        health=health,
    )


def create_server_control(admin_base_url: str, admin_secret: str) -> RustEd2kServerControl:
    """Returns the Rust server's semantic control surface."""

    del admin_secret
    return RustEd2kServerControl(admin_base_url)


def stop_server_processes() -> None:
    """Stops stray Rust server processes on the current host."""

    distribution = os.environ.get(RUST_ED2K_WSL_DISTRIBUTION_ENV, "").strip() or None
    if _is_windows_host():
        subprocess.run(
            _wsl_command(distribution, "pkill", "-x", "ed2k-server"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        return
    subprocess.run(
        ["pkill", "-x", "ed2k-server"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
