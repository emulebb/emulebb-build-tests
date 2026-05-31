"""Helpers for local VPN Guard live-test control and configuration."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

SCHEMA = "emulebb.vpnGuardLiveConfig.v1"
HOOK_NAMES = frozenset({
    "connect",
    "disconnect",
    "allowlistEmulebb",
    "removeAllowlistEmulebb",
    "checkConnected",
    "checkDisconnected",
    "checkAllowlisted",
    "checkNotAllowlisted",
})


def public_ipv4_cidr32(ip_address: str) -> str:
    """Returns a /32 CIDR for one globally routable IPv4 address."""

    address = ipaddress.ip_address(ip_address.strip())
    if address.version != 4 or not address.is_global:
        raise ValueError(f"VPN Guard public IP must be a globally routable IPv4 address: {ip_address!r}")
    return f"{address}/32"


def build_config(*, p2p_bind_interface_name: str, public_ip: str, commands: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """Builds one local VPN Guard live-test config payload."""

    return {
        "schema": SCHEMA,
        "p2pBindInterfaceName": p2p_bind_interface_name.strip(),
        "allowedPublicIpCidrs": public_ipv4_cidr32(public_ip),
        "commands": commands or {},
    }


def write_config(path: Path, payload: dict[str, Any]) -> None:
    """Writes a local VPN Guard live-test config file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_config(path: Path) -> dict[str, Any]:
    """Loads and validates a local VPN Guard live-test config file."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("VPN Guard live config must be a JSON object.")
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"VPN Guard live config schema must be {SCHEMA!r}.")
    if not str(payload.get("p2pBindInterfaceName") or "").strip():
        raise ValueError("VPN Guard live config requires p2pBindInterfaceName.")
    commands = payload.get("commands", {})
    if not isinstance(commands, dict):
        raise ValueError("VPN Guard live config commands must be an object.")
    for name, command in commands.items():
        if name not in HOOK_NAMES:
            raise ValueError(f"Unsupported VPN Guard hook name: {name!r}.")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
            raise ValueError(f"VPN Guard hook {name!r} must be a non-empty string array.")
    return payload


def render_command(command: list[str], context: dict[str, str]) -> list[str]:
    """Expands simple named placeholders in one command array."""

    return [part.format(**context) for part in command]


def run_hook(config: dict[str, Any], name: str, context: dict[str, str], *, timeout_seconds: float = 60.0) -> dict[str, object]:
    """Runs one configured VPN Guard hook command if it exists."""

    commands = config.get("commands", {})
    command_template = commands.get(name) if isinstance(commands, dict) else None
    if command_template is None:
        return {"hook": name, "configured": False, "skipped": True}
    command = render_command(list(command_template), context)
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout_seconds, check=False)
    return {
        "hook": name,
        "configured": True,
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "ok": completed.returncode == 0,
    }


def require_hook_ok(result: dict[str, object]) -> None:
    """Raises when a configured VPN Guard hook command failed."""

    if result.get("configured") and result.get("returncode") != 0:
        raise RuntimeError(f"VPN Guard hook failed: {result}")
