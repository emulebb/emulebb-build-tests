"""Provider-neutral local ED2K server contract for deterministic suites."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from typing import Any, Protocol


ED2K_SERVER_EXE_ENV = "EMULEBB_TEST_RUST_ED2K_SERVER_EXE"


class Ed2kServerBinary(Protocol):
    """Common binary preparation result exposed by every server provider."""

    server_exe: Path
    build: dict[str, object]


class ManagedProcess(Protocol):
    """Process operations required for reliable provider cleanup."""

    @property
    def returncode(self) -> int | None: ...

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


class Ed2kServerLaunch(Ed2kServerBinary, Protocol):
    """Common launch result exposed by every server provider."""

    process: ManagedProcess
    admin_base_url: str
    ed2k_host: str
    ed2k_port: int
    server_dir: Path
    config_path: Path
    log_path: Path
    config: dict[str, object]
    health: dict[str, Any]


class UnsupportedEd2kServerCapability(RuntimeError):
    """Raised when a selected server cannot provide an optional harness capability."""


class Ed2kServerControl(Protocol):
    """Semantic observation operations normalized across server providers."""

    def stats(self) -> dict[str, Any]: ...

    def list_clients(self) -> list[dict[str, Any]]: ...

    def get_file(self, file_hash: str) -> dict[str, Any] | None: ...

    def wait_for_client(self, name_fragment: str, timeout_seconds: float) -> dict[str, Any]: ...

    def wait_for_client_absent(
        self,
        name_fragment: str,
        timeout_seconds: float,
    ) -> dict[str, Any]: ...

    def wait_for_client_shared_files(
        self,
        name_fragment: str,
        minimum_shared_files: int,
        timeout_seconds: float,
    ) -> dict[str, Any]: ...

    def wait_for_file(self, file_hash: str, timeout_seconds: float) -> dict[str, Any]: ...

    def wait_for_file_endpoint(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
    ) -> dict[str, Any]: ...

    def wait_for_file_endpoint_absent(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint withdrawal",
    ) -> dict[str, Any]: ...


def env_ed2k_server_exe_override(env: dict[str, str] | None = None) -> str | None:
    """Returns the explicit staged Rust server executable override."""

    value = (env or os.environ).get(ED2K_SERVER_EXE_ENV, "").strip()
    return value or None


def with_ed2k_server_exe_env(
    env: dict[str, str],
    server_exe: str | Path | None,
) -> dict[str, str]:
    """Returns a child environment carrying the staged Rust server executable."""

    child_env = dict(env)
    if server_exe:
        child_env[ED2K_SERVER_EXE_ENV] = str(Path(server_exe).resolve())
    return child_env


def prepare_ed2k_server_binary(
    workspace_root: Path,
    *,
    repo_override: str | None = None,
    exe_override: str | None = None,
) -> Ed2kServerBinary:
    """Prepares the managed Rust ED2K server binary."""

    from .rust_ed2k import prepare_server_binary

    return prepare_server_binary(
        workspace_root,
        repo_override=repo_override,
        exe_override=exe_override,
    )


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
    offerfiles_v1: bool = False,
    soft_limit_files: int = 5000,
    hard_limit_files: int = 200000,
    server_udp: bool = True,
    packet_trace: bool = False,
    health_timeout_seconds: float = 30.0,
) -> Ed2kServerLaunch:
    """Launches the managed Rust ED2K server for a local suite."""

    from .rust_ed2k import launch_server

    return launch_server(
        workspace_root=workspace_root,
        server_dir=server_dir,
        ed2k_port=ed2k_port,
        admin_port=admin_port,
        admin_secret=token,
        admin_address=admin_address,
        ed2k_address=ed2k_address,
        fixture_files=catalog_files,
        repo_override=repo_override,
        exe_override=exe_override,
        protocol_obfuscation=protocol_obfuscation,
        offerfiles_v1=offerfiles_v1,
        soft_limit_files=soft_limit_files,
        hard_limit_files=hard_limit_files,
        server_udp=server_udp,
        packet_trace=packet_trace,
        health_timeout_seconds=health_timeout_seconds,
    )


def ed2k_server_control(admin_base_url: str, admin_secret: str) -> Ed2kServerControl:
    """Returns the semantic control surface for the managed ED2K server."""

    from .rust_ed2k import create_server_control

    return create_server_control(admin_base_url, admin_secret)


def admin_request(
    admin_base_url: str,
    _admin_secret: str,
    path: str,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Reads a Rust admin endpoint and returns the normalized harness envelope."""

    from .rust_ed2k import admin_request as rust_admin_request

    payload = rust_admin_request(admin_base_url, path, timeout_seconds=timeout_seconds)
    if isinstance(payload, dict) and "ok" in payload and "data" in payload:
        return payload
    return {"ok": True, "data": payload}


def wait_for_server_client(
    admin_base_url: str,
    admin_secret: str,
    name_fragment: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits until the Rust server observes a matching client."""

    return ed2k_server_control(admin_base_url, admin_secret).wait_for_client(
        name_fragment,
        timeout_seconds,
    )


def wait_for_server_file(
    admin_base_url: str,
    admin_secret: str,
    file_hash: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits until the Rust server indexes a file hash."""

    return ed2k_server_control(admin_base_url, admin_secret).wait_for_file(
        file_hash,
        timeout_seconds,
    )


def require_published_endpoint(file_row: dict[str, object], *, port: int) -> dict[str, object]:
    """Returns the unique server-observed source endpoint using one client port."""

    endpoints = file_row.get("endpoints")
    rows = endpoints if isinstance(endpoints, list) else []
    matches = [
        endpoint
        for endpoint in rows
        if isinstance(endpoint, dict) and int(endpoint.get("port") or 0) == port
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one published source endpoint on port {port}, found {len(matches)}: {rows!r}"
        )
    endpoint = dict(matches[0])
    host = str(endpoint.get("host") or "")
    if not host:
        raise RuntimeError(f"Published source endpoint on port {port} has no host: {endpoint!r}")
    return endpoint


def resolve_route_bind_ip(server_host: str, server_port: int) -> str:
    """Returns the non-loopback IPv4 source selected for the managed server route."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((server_host, server_port))
        address = str(probe.getsockname()[0])
    if not address or address == "0.0.0.0" or address.startswith("127."):
        raise RuntimeError(f"Managed ED2K server route resolved to an invalid client bind address: {address!r}")
    return address


def wait_for_server_file_endpoint(
    admin_base_url: str,
    admin_secret: str,
    file_hash: str,
    host: str,
    port: int,
    timeout_seconds: float,
    description: str = "ED2K server file endpoint publication",
) -> dict[str, Any]:
    """Waits until the Rust server advertises one exact source endpoint."""

    return ed2k_server_control(admin_base_url, admin_secret).wait_for_file_endpoint(
        file_hash,
        host,
        port,
        timeout_seconds,
        description,
    )


def stop_process(process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None:
    """Stops one Rust server process."""

    from .rust_ed2k import stop_process as stop_rust_server_process

    stop_rust_server_process(process, timeout_seconds=timeout_seconds)


def stop_server_processes() -> None:
    """Stops stray managed Rust server processes."""

    from .rust_ed2k import stop_server_processes as stop_rust_server_processes

    stop_rust_server_processes()
