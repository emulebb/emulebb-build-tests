"""Shared goed2k-server helpers for deterministic local ED2K suites."""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .multi_client import resolve_manifest_repo
from .paths import get_workspace_output_root, reject_windows_temp_path
from .script_modules import load_script_module


live_common = load_script_module("emule_live_profile_common_goed2k", "emule-live-profile-common.py")
ED2K_SERVER_EXE_ENV = "EMULEBB_TEST_ED2K_SERVER_EXE"
SERVER_TCP_FLAG_TCPOBFUSCATION = 0x0000_0400


@dataclass(frozen=True)
class Goed2kServerLaunch:
    """Result of launching one local goed2k-server instance for a harness suite."""

    process: subprocess.Popen
    admin_base_url: str
    server_exe: Path
    server_dir: Path
    catalog_path: Path
    config_path: Path
    log_path: Path
    build: dict[str, object]
    config: dict[str, object]
    health: dict[str, Any]


@dataclass(frozen=True)
class Goed2kServerBinary:
    """Resolved goed2k-server executable plus the build or explicit-override result."""

    server_exe: Path
    build: dict[str, object]


def resolve_ed2k_server_repo(workspace_root: Path, override: str | None) -> Path:
    """Resolves the workspace ED2K server repo path from args or manifest."""

    candidate = Path(override).resolve() if override else resolve_manifest_repo(workspace_root, "ed2k_server")
    if not (candidate / "go.mod").is_file():
        raise RuntimeError(f"ED2K server repo was not found at '{candidate}'.")
    return candidate


def resolve_ed2k_server_exe(_workspace_root: Path, override: str | None) -> Path:
    """Resolves the output-root ED2K server tool output path."""

    if override:
        return Path(override).resolve()
    return (get_workspace_output_root() / "tools" / "goed2k-server" / "goed2k-server.exe").resolve()


def env_ed2k_server_exe_override(env: dict[str, str] | None = None) -> str | None:
    """Returns the shared goed2k-server executable override passed to pytest children."""

    value = (env or os.environ).get(ED2K_SERVER_EXE_ENV, "").strip()
    return value or None


def with_ed2k_server_exe_env(env: dict[str, str], server_exe: str | Path | None) -> dict[str, str]:
    """Returns a child-process environment with the shared goed2k-server override applied."""

    child_env = dict(env)
    if server_exe:
        child_env[ED2K_SERVER_EXE_ENV] = str(Path(server_exe).resolve())
    return child_env


def build_ed2k_server_binary(server_repo: Path, server_exe: Path) -> dict[str, object]:
    """Builds the local ED2K server binary into the output root."""

    reject_windows_temp_path(server_exe.parent, "ED2K server binary directory")
    server_exe.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "go",
        "build",
        "-o",
        str(server_exe),
        "./cmd/goed2k-server",
    ]
    completed = subprocess.run(
        command,
        cwd=server_repo,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    result = {
        "command": command,
        "cwd": str(server_repo),
        "return_code": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "server_exe": str(server_exe),
    }
    if completed.returncode != 0:
        raise RuntimeError(f"ED2K server build failed: {result!r}")
    return result


def build_or_skip_ed2k_server_binary(
    workspace_root: Path,
    server_exe: Path,
    *,
    repo_override: str | None = None,
    exe_override: str | None = None,
) -> dict[str, object]:
    """Builds the ED2K server unless an explicit executable override is already staged."""

    if exe_override:
        return {
            "command": [],
            "cwd": "",
            "return_code": 0,
            "server_exe": str(server_exe),
            "skipped": True,
            "reason": "using explicit --ed2k-server-exe",
        }
    server_repo = resolve_ed2k_server_repo(workspace_root, repo_override)
    return build_ed2k_server_binary(server_repo, server_exe)


def prepare_ed2k_server_binary(
    workspace_root: Path,
    *,
    repo_override: str | None = None,
    exe_override: str | None = None,
) -> Goed2kServerBinary:
    """Resolves and stages the goed2k-server executable for one or more launches."""

    server_exe = resolve_ed2k_server_exe(workspace_root, exe_override)
    build = build_or_skip_ed2k_server_binary(
        workspace_root,
        server_exe,
        repo_override=repo_override,
        exe_override=exe_override,
    )
    return Goed2kServerBinary(server_exe=server_exe, build=build)


def write_empty_catalog(path: Path) -> None:
    """Creates an empty JSON catalog accepted by the ED2K server."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": []}, indent=2), encoding="utf-8")


def catalog_file(
    *,
    file_hash: str,
    name: str,
    size: int,
    endpoints: list[dict[str, object]] | None = None,
    file_type: str = "Archive",
    extension: str = "bin",
    sources: int = 1,
    complete_sources: int = 1,
) -> dict[str, object]:
    """Builds one JSON catalog file row accepted by goed2k-server."""

    return {
        "hash": file_hash.upper(),
        "name": name,
        "size": size,
        "file_type": file_type,
        "extension": extension,
        "sources": sources,
        "complete_sources": complete_sources,
        "endpoints": list(endpoints or []),
    }


def build_server_met(ip: str, port: int, name: str) -> bytes:
    """Builds a minimal single-server ``server.met`` pointing an eMule-compatible
    client at a goed2k-server endpoint, so live suites can drive a real ED2K
    client connection without scraping a public server list.

    Layout: MET header (0x0E), uint32 server count, then per server the 4 IPv4
    octets, a little-endian uint16 port, a uint32 tag count, and a single special
    ST_SERVERNAME string tag.
    """

    import struct

    octets = [int(part) for part in ip.split(".")]
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        raise ValueError(f"server.met requires an IPv4 address, got {ip!r}")
    name_bytes = name.encode("utf-8")
    out = bytearray()
    out.append(0x0E)
    out += struct.pack("<I", 1)
    out += bytes(octets)
    out += struct.pack("<H", port)
    out += struct.pack("<I", 1)  # one tag
    out.append(0x02 | 0x80)  # string tag with special 1-byte name id
    out.append(0x01)  # ST_SERVERNAME
    out += struct.pack("<H", len(name_bytes))
    out += name_bytes
    return bytes(out)


def write_catalog(path: Path, files: list[dict[str, object]]) -> None:
    """Writes a goed2k-server JSON catalog with the provided file rows."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": files}, indent=2) + "\n", encoding="utf-8")


def build_server_config(
    path: Path,
    *,
    ed2k_port: int,
    admin_port: int,
    catalog_path: Path,
    token: str,
    admin_address: str,
    ed2k_address: str | None = None,
    protocol_obfuscation: bool = True,
    server_udp: bool = True,
    packet_trace: bool = False,
    packet_trace_path: str | Path | None = None,
) -> dict[str, object]:
    """Writes and returns the local ED2K server JSON configuration.

    When ``packet_trace`` is set the server emits a structured per-frame trace
    (TCP and UDP, both directions); ``packet_trace_path`` additionally appends a
    JSON-line trace file useful for parity comparisons against LegacyED2KServer.
    """

    ed2k_bind_address = ed2k_address or "0.0.0.0"
    config = {
        "listen_address": f"{ed2k_bind_address}:{ed2k_port}",
        "admin_listen_address": f"{admin_address}:{admin_port}",
        "admin_token": token,
        "server_name": "emulebb-local-e2e",
        "server_description": "Workspace deterministic eMuleBB live E2E server",
        "message": "Workspace deterministic eMuleBB live E2E server",
        "storage_backend": "json",
        "catalog_path": str(catalog_path),
        "search_batch_size": 200,
        "tcp_flags": SERVER_TCP_FLAG_TCPOBFUSCATION if protocol_obfuscation else 0,
        "aux_port": 0,
        "protocol_obfuscation": protocol_obfuscation,
        "server_udp": server_udp,
        "udp_port_offset": 4,
        "soft_files_limit": 5000,
        "hard_files_limit": 200000,
        "max_users_advertised": 500000,
        "packet_trace": packet_trace,
    }
    if packet_trace_path is not None:
        config["packet_trace_path"] = str(packet_trace_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config


def launch_ed2k_server(
    *,
    workspace_root: Path,
    server_dir: Path,
    ed2k_port: int,
    admin_port: int,
    token: str,
    admin_address: str,
    ed2k_address: str | None = None,
    catalog_files: list[dict[str, object]] | None = None,
    repo_override: str | None = None,
    exe_override: str | None = None,
    protocol_obfuscation: bool = True,
    server_udp: bool = True,
    packet_trace: bool = False,
    health_timeout_seconds: float = 30.0,
) -> Goed2kServerLaunch:
    """Builds, configures, starts, and health-checks a local goed2k-server instance."""

    binary = prepare_ed2k_server_binary(
        workspace_root,
        repo_override=repo_override,
        exe_override=exe_override,
    )
    catalog_path = server_dir / "catalog.json"
    config_path = server_dir / "config.json"
    log_path = server_dir / "server.log"
    trace_path = server_dir / "packets.trace.jsonl" if packet_trace else None
    if catalog_files is None:
        write_empty_catalog(catalog_path)
    else:
        write_catalog(catalog_path, catalog_files)
    config = build_server_config(
        config_path,
        ed2k_port=ed2k_port,
        admin_port=admin_port,
        catalog_path=catalog_path,
        token=token,
        admin_address=admin_address,
        ed2k_address=ed2k_address,
        protocol_obfuscation=protocol_obfuscation,
        server_udp=server_udp,
        packet_trace=packet_trace,
        packet_trace_path=trace_path,
    )
    process = start_ed2k_server(binary.server_exe, config_path, log_path)
    admin_base_url = f"http://{admin_address}:{admin_port}"
    health = wait_for_admin_health(admin_base_url, health_timeout_seconds)
    return Goed2kServerLaunch(
        process=process,
        admin_base_url=admin_base_url,
        server_exe=binary.server_exe,
        server_dir=server_dir,
        catalog_path=catalog_path,
        config_path=config_path,
        log_path=log_path,
        build=binary.build,
        config=config,
        health=health,
    )


def admin_request(admin_base_url: str, token: str, path: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
    """Issues one ED2K server admin request and returns its JSON payload."""

    request = urllib.request.Request(admin_base_url + path, headers={"X-Admin-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        data = exc.read()
        raise RuntimeError(f"ED2K admin request failed: {path} status={exc.code} body={data!r}") from exc
    payload = json.loads(data.decode("utf-8"))
    if not payload.get("ok"):
        raise RuntimeError(f"ED2K admin request failed: {path} payload={payload!r}")
    return payload


def wait_for_admin_health(admin_base_url: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until the ED2K admin health endpoint is reachable."""

    def resolve():
        try:
            request = urllib.request.Request(admin_base_url + "/healthz")
            with urllib.request.urlopen(request, timeout=2.0) as response:
                return json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return None

    return live_common.wait_for(resolve, timeout_seconds, 0.5, "ED2K server admin health")


def wait_for_server_client(admin_base_url: str, token: str, name_fragment: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits for one connected client to appear in the ED2K server admin API."""

    observations: list[dict[str, object]] = []

    def resolve():
        payload = admin_request(admin_base_url, token, "/api/clients", timeout_seconds=5.0)
        rows = payload.get("data")
        if not isinstance(rows, list):
            return None
        observations.append({"count": len(rows), "observed_at": round(time.time(), 3)})
        for row in rows:
            if isinstance(row, dict) and name_fragment.lower() in str(row.get("client_name") or "").lower():
                row = dict(row)
                row["observations"] = observations
                return row
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"ED2K client {name_fragment!r}")


def wait_for_server_file(admin_base_url: str, token: str, file_hash: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until a client publishes the fixture file to the ED2K server."""

    normalized_hash = file_hash.upper()
    observations: list[dict[str, object]] = []

    def resolve():
        payload = admin_request(admin_base_url, token, f"/api/files/{normalized_hash}", timeout_seconds=5.0)
        row = payload.get("data")
        if isinstance(row, dict):
            row = dict(row)
            row["observations"] = observations
            return row
        observations.append({"observed_at": round(time.time(), 3), "payload": payload})
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, "ED2K server file publication")


def wait_for_server_file_endpoint(
    admin_base_url: str,
    token: str,
    file_hash: str,
    host: str,
    port: int,
    timeout_seconds: float,
    description: str = "ED2K server file endpoint publication",
) -> dict[str, Any]:
    """Waits until a published server file advertises one expected source endpoint."""

    normalized_hash = file_hash.lower()

    def resolve():
        payload = admin_request(admin_base_url, token, f"/api/files?search={file_hash}", timeout_seconds=5.0)
        rows = payload.get("data")
        if not isinstance(rows, list):
            return None
        for row in rows:
            if not isinstance(row, dict) or str(row.get("hash") or "").lower() != normalized_hash:
                continue
            endpoints = row.get("endpoints")
            if not isinstance(endpoints, list):
                continue
            if any(
                isinstance(endpoint, dict)
                and endpoint.get("host") == host
                and int(endpoint.get("port", 0)) == port
                for endpoint in endpoints
            ):
                return row
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, description)


def start_ed2k_server(server_exe: Path, config_path: Path, log_path: Path) -> subprocess.Popen:
    """Starts the local ED2K server with stdout/stderr captured under artifacts."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        [str(server_exe), "-config", str(config_path)],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        cwd=server_exe.parent,
        text=True,
    )


def stop_process(process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None:
    """Terminates one child process without leaving it running after the suite."""

    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout_seconds)


def stop_server_processes() -> None:
    """Stops any stray `goed2k-server.exe` processes left behind after harness runs."""

    if os.name != "nt":
        return
    subprocess.run(
        ["taskkill", "/IM", "goed2k-server.exe", "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
