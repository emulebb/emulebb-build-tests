"""Provider-neutral local ED2K server contract for deterministic suites."""

from __future__ import annotations

import os
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from . import goed2k


ED2K_SERVER_PROVIDER_ENV = "EMULEBB_TEST_ED2K_SERVER_PROVIDER"
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

    def wait_for_file(self, file_hash: str, timeout_seconds: float) -> dict[str, Any]: ...

    def wait_for_file_endpoint(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
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


@dataclass(frozen=True)
class Goed2kServerControl:
    """Semantic control adapter over the Go server's admin API."""

    admin_base_url: str
    admin_secret: str

    def _request(self, path: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        return goed2k.admin_request(
            self.admin_base_url,
            self.admin_secret,
            path,
            timeout_seconds=timeout_seconds,
        )

    def stats(self) -> dict[str, Any]:
        return self._request("/api/stats")

    def list_clients(self) -> list[dict[str, Any]]:
        payload = self._request("/api/clients")
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise RuntimeError(f"ED2K clients response did not contain a list: {payload!r}")
        return [dict(row) for row in rows if isinstance(row, dict)]

    def get_file(self, file_hash: str) -> dict[str, Any] | None:
        payload = self._request(f"/api/files/{file_hash.upper()}")
        row = payload.get("data")
        return dict(row) if isinstance(row, dict) else None

    def list_files(self, search: str | None = None) -> dict[str, Any]:
        path = "/api/files"
        if search:
            path += "?search=" + urllib.parse.quote(search)
        return self._request(path)

    def audit(self) -> dict[str, Any]:
        return self._request("/api/audit")

    def wait_for_client(
        self,
        name_fragment: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        return goed2k.wait_for_server_client(
            self.admin_base_url,
            self.admin_secret,
            name_fragment,
            timeout_seconds,
        )

    def wait_for_file(
        self,
        file_hash: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        return goed2k.wait_for_server_file(
            self.admin_base_url,
            self.admin_secret,
            file_hash,
            timeout_seconds,
        )

    def wait_for_file_endpoint(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
    ) -> dict[str, Any]:
        return goed2k.wait_for_server_file_endpoint(
            self.admin_base_url,
            self.admin_secret,
            file_hash,
            host,
            port,
            timeout_seconds,
            description,
        )


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

    def control(self, admin_base_url: str, admin_secret: str) -> Ed2kServerControl:
        return Goed2kServerControl(admin_base_url, admin_secret)

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
    if requested == "rust":
        from .rust_ed2k import RUST_ED2K_PROVIDER

        return RUST_ED2K_PROVIDER
    raise RuntimeError(
        f"ED2K server provider {requested!r} is unavailable; available providers: {GOED2K_PROVIDER.name}, rust."
    )
