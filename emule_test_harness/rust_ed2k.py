"""Rust ed2k-server configuration and normalized admin control."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ed2k_server import UnsupportedEd2kServerCapability
from .script_modules import load_script_module


live_common = load_script_module("emule_live_profile_common_rust_ed2k", "emule-live-profile-common.py")


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
    server_name: str = "emulebb-local-e2e",
) -> dict[str, object]:
    """Writes a minimal private Rust server configuration for local harness runs."""

    if not listen_address.strip():
        raise ValueError("listen_address must be explicit.")
    if not advertised_address.strip():
        raise ValueError("advertised_address must be explicit.")
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
        },
        "limits": {
            "max_clients": 1000,
            "soft_limit_files": 5000,
            "hard_limit_files": 200000,
            "ping_delay_seconds": 600,
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
        "",
        "[limits]",
        "max_clients = 1000",
        "soft_limit_files = 5000",
        "hard_limit_files = 200000",
        "ping_delay_seconds = 600",
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
        raise RuntimeError(f"Rust ED2K admin request failed: {path} status={exc.code} body={data!r}") from exc
    return json.loads(data.decode("utf-8"))


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
        raise UnsupportedEd2kServerCapability(
            f"Rust ed2k-server does not yet expose file lookup required for {file_hash.upper()}."
        )

    def list_files(self, search: str | None = None) -> dict[str, Any]:
        detail = f" for {search!r}" if search else ""
        raise UnsupportedEd2kServerCapability(f"Rust ed2k-server does not yet expose file listing{detail}.")

    def audit(self) -> dict[str, Any]:
        raise UnsupportedEd2kServerCapability("Rust ed2k-server does not expose the Go server audit API.")

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

    def wait_for_file(self, file_hash: str, timeout_seconds: float) -> dict[str, Any]:
        del timeout_seconds
        return self.get_file(file_hash) or {}

    def wait_for_file_endpoint(
        self,
        file_hash: str,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K server file endpoint publication",
    ) -> dict[str, Any]:
        del host, port, timeout_seconds, description
        return self.get_file(file_hash) or {}
