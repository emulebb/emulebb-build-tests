"""Provider-neutral local ED2K server contract for deterministic suites."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Protocol


ED2K_SERVER_PROVIDER_ENV = "EMULEBB_TEST_ED2K_SERVER_PROVIDER"
ED2K_SERVER_EXE_ENV = "EMULEBB_TEST_RUST_ED2K_SERVER_EXE"
DEFAULT_ED2K_SERVER_PROVIDER = "rust"


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

    def list_files(self, search: str | None = None) -> dict[str, Any]: ...

    def audit(self) -> dict[str, Any]: ...

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


class Ed2kServerProvider(Protocol):
    """Operations required by provider-neutral local ED2K suites."""

    name: str

    def prepare_binary(
        self,
        workspace_root: Path,
        *,
        repo_override: str | None = None,
        exe_override: str | None = None,
    ) -> Ed2kServerBinary: ...

    def launch(
        self,
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
        server_udp: bool = True,
        packet_trace: bool = False,
        health_timeout_seconds: float = 30.0,
    ) -> Ed2kServerLaunch: ...

    def control(self, admin_base_url: str, admin_secret: str) -> Ed2kServerControl: ...

    def stop_process(self, process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None: ...

    def stop_server_processes(self) -> None: ...


def requested_provider_name(
    provider_name: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Returns the normalized provider requested by an argument or environment."""

    value = provider_name
    if value is None:
        value = (env or os.environ).get(ED2K_SERVER_PROVIDER_ENV, DEFAULT_ED2K_SERVER_PROVIDER)
    return value.strip().lower()


def resolve_provider(
    provider_name: str | None = None,
    env: dict[str, str] | None = None,
) -> Ed2kServerProvider:
    """Resolves the sole supported local ED2K server provider."""

    requested = requested_provider_name(provider_name, env)
    if requested == "rust":
        from .rust_ed2k import RUST_ED2K_PROVIDER

        return RUST_ED2K_PROVIDER
    raise RuntimeError(f"ED2K server provider {requested!r} is unavailable; available provider: rust.")


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

    return resolve_provider().prepare_binary(
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
    server_udp: bool = True,
    packet_trace: bool = False,
    health_timeout_seconds: float = 30.0,
) -> Ed2kServerLaunch:
    """Launches the managed Rust ED2K server for a local suite."""

    return resolve_provider().launch(
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
        server_udp=server_udp,
        packet_trace=packet_trace,
        health_timeout_seconds=health_timeout_seconds,
    )


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

    return resolve_provider().control(admin_base_url, admin_secret).wait_for_client(
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

    return resolve_provider().control(admin_base_url, admin_secret).wait_for_file(
        file_hash,
        timeout_seconds,
    )


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

    return resolve_provider().control(admin_base_url, admin_secret).wait_for_file_endpoint(
        file_hash,
        host,
        port,
        timeout_seconds,
        description,
    )


def stop_process(process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None:
    """Stops one Rust server process."""

    resolve_provider().stop_process(process, timeout_seconds=timeout_seconds)


def stop_server_processes() -> None:
    """Stops stray managed Rust server processes."""

    resolve_provider().stop_server_processes()
