"""Provider-neutral local ED2K server contract for deterministic suites."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Protocol

from . import goed2k


ED2K_SERVER_PROVIDER_ENV = "EMULEBB_TEST_ED2K_SERVER_PROVIDER"
DEFAULT_ED2K_SERVER_PROVIDER = "goed2k"


class Ed2kServerBinary(Protocol):
    """Common binary preparation result exposed by every server provider."""

    server_exe: Path
    build: dict[str, object]


class Ed2kServerLaunch(Ed2kServerBinary, Protocol):
    """Common launch result exposed by every server provider."""

    process: subprocess.Popen
    admin_base_url: str
    server_dir: Path
    config_path: Path
    log_path: Path
    config: dict[str, object]
    health: dict[str, Any]


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

    def admin_request(
        self,
        admin_base_url: str,
        admin_secret: str,
        path: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]: ...

    def wait_for_client(
        self,
        admin_base_url: str,
        admin_secret: str,
        name_fragment: str,
        timeout_seconds: float,
    ) -> dict[str, Any]: ...

    def wait_for_file(
        self,
        admin_base_url: str,
        admin_secret: str,
        file_hash: str,
        timeout_seconds: float,
    ) -> dict[str, Any]: ...

    def wait_for_file_endpoint(
        self,
        admin_base_url: str,
        admin_secret: str,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
    ) -> dict[str, Any]: ...

    def stop_process(self, process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None: ...

    def stop_server_processes(self) -> None: ...


class Goed2kServerProvider:
    """Provider adapter that preserves the existing Go harness behavior."""

    name = "goed2k"

    def prepare_binary(
        self,
        workspace_root: Path,
        *,
        repo_override: str | None = None,
        exe_override: str | None = None,
    ) -> Ed2kServerBinary:
        return goed2k.prepare_ed2k_server_binary(
            workspace_root,
            repo_override=repo_override,
            exe_override=exe_override,
        )

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
    ) -> Ed2kServerLaunch:
        return goed2k.launch_ed2k_server(
            workspace_root=workspace_root,
            server_dir=server_dir,
            ed2k_port=ed2k_port,
            admin_port=admin_port,
            token=admin_secret,
            admin_address=admin_address,
            ed2k_address=ed2k_address,
            catalog_files=fixture_files,
            repo_override=repo_override,
            exe_override=exe_override,
            protocol_obfuscation=protocol_obfuscation,
            server_udp=server_udp,
            packet_trace=packet_trace,
            health_timeout_seconds=health_timeout_seconds,
        )

    def admin_request(
        self,
        admin_base_url: str,
        admin_secret: str,
        path: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> dict[str, Any]:
        return goed2k.admin_request(
            admin_base_url,
            admin_secret,
            path,
            timeout_seconds=timeout_seconds,
        )

    def wait_for_client(
        self,
        admin_base_url: str,
        admin_secret: str,
        name_fragment: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        return goed2k.wait_for_server_client(
            admin_base_url,
            admin_secret,
            name_fragment,
            timeout_seconds,
        )

    def wait_for_file(
        self,
        admin_base_url: str,
        admin_secret: str,
        file_hash: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        return goed2k.wait_for_server_file(
            admin_base_url,
            admin_secret,
            file_hash,
            timeout_seconds,
        )

    def wait_for_file_endpoint(
        self,
        admin_base_url: str,
        admin_secret: str,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
    ) -> dict[str, Any]:
        return goed2k.wait_for_server_file_endpoint(
            admin_base_url,
            admin_secret,
            file_hash,
            host,
            port,
            timeout_seconds,
            description,
        )

    def stop_process(self, process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None:
        goed2k.stop_process(process, timeout_seconds=timeout_seconds)

    def stop_server_processes(self) -> None:
        goed2k.stop_server_processes()


GOED2K_PROVIDER = Goed2kServerProvider()


def requested_provider_name(
    provider_name: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Returns the normalized provider requested by an argument or environment."""

    value = provider_name
    if value is None:
        value = (env or os.environ).get(ED2K_SERVER_PROVIDER_ENV, DEFAULT_ED2K_SERVER_PROVIDER)
    normalized = value.strip().lower()
    aliases = {
        "go": "goed2k",
        "goed2k-server": "goed2k",
    }
    return aliases.get(normalized, normalized)


def resolve_provider(
    provider_name: str | None = None,
    env: dict[str, str] | None = None,
) -> Ed2kServerProvider:
    """Resolves the requested provider, rejecting unavailable migrations explicitly."""

    requested = requested_provider_name(provider_name, env)
    if requested == GOED2K_PROVIDER.name:
        return GOED2K_PROVIDER
    raise RuntimeError(
        f"ED2K server provider {requested!r} is unavailable; available providers: {GOED2K_PROVIDER.name}."
    )
