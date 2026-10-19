"""Provider-neutral local ED2K server contract for deterministic suites."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Protocol


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
