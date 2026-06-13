"""hide.me split-tunnel + VPN lifecycle helpers for host live-wire runs.

The hide.me client routes only whitelisted executables through the tunnel
(``SplitTunneling.Mode == 2``). For a host-level live-wire run the Rust daemon
exe must be on that whitelist; this module ensures it is, restarts the client
when the list changes, and waits for the tunnel adapter to come up.

No operator-specific paths are baked in: the settings file is resolved from
``%APPDATA%`` and the exe path is supplied by the caller.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

HIDE_ME_APP_EXE = r"C:\Program Files (x86)\hide.me VPN\Hide.me.exe"
HIDE_ME_SERVICE = "hmevpnsvc"
_SPLIT_TUNNEL_WHITELIST_MODE = 2


def vpn_settings_path() -> Path:
    """Returns ``%APPDATA%/Hide.me/vpn.settings`` for the current user."""

    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set; cannot locate hide.me settings.")
    return Path(appdata) / "Hide.me" / "vpn.settings"


def _load_settings(path: Path) -> dict[str, Any]:
    # hide.me writes the file with a UTF-8 BOM.
    return json.loads(path.read_text(encoding="utf-8-sig"))


def is_whitelisted(exe_path: Path, settings_path: Path | None = None) -> bool:
    """Returns True when ``exe_path`` is already in the split-tunnel whitelist."""

    settings_path = settings_path or vpn_settings_path()
    settings = _load_settings(settings_path)
    whitelist = settings.get("SplitTunneling", {}).get("Whitelisted") or []
    target = str(exe_path).casefold()
    return any(str(entry.get("Path", "")).casefold() == target for entry in whitelist)


def ensure_whitelisted(exe_path: Path, *, name: str | None = None, settings_path: Path | None = None) -> bool:
    """Ensures ``exe_path`` is split-tunnel whitelisted.

    Returns True when an entry was added (caller should restart hide.me), False
    when it was already present (idempotent no-op).
    """

    settings_path = settings_path or vpn_settings_path()
    settings = _load_settings(settings_path)
    split = settings.setdefault("SplitTunneling", {})
    whitelist = split.setdefault("Whitelisted", [])
    target = str(exe_path)
    if any(str(entry.get("Path", "")).casefold() == target.casefold() for entry in whitelist):
        return False
    whitelist.append(
        {
            "Name": name or exe_path.stem,
            "Path": target,
            "Paths": None,
            "Icon": None,
        }
    )
    # Whitelist mode must be active for the entry to take effect.
    if split.get("Mode") != _SPLIT_TUNNEL_WHITELIST_MODE:
        split["Mode"] = _SPLIT_TUNNEL_WHITELIST_MODE
    settings_path.write_text(json.dumps(settings, indent=0), encoding="utf-8")
    return True


def _powershell(script: str, *, timeout_seconds: float = 60.0) -> str:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout


def hideme_adapter_up() -> bool:
    """Returns True when a hide.me network adapter is present and ``Up``."""

    out = _powershell(
        "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status | ConvertTo-Json -Compress"
    )
    payload = json.loads(out or "[]")
    if isinstance(payload, dict):
        payload = [payload]
    for row in payload:
        label = f"{row.get('Name', '')} {row.get('InterfaceDescription', '')}".casefold()
        if "hide.me" in label and str(row.get("Status", "")).casefold() == "up":
            return True
    return False


def restart_hideme(app_exe: str = HIDE_ME_APP_EXE, *, connect_timeout_seconds: float = 90.0) -> None:
    """Restarts the hide.me client so it reloads split-tunnel settings, then waits for the tunnel."""

    _powershell(
        "Get-Process -Name 'Hide.me' -ErrorAction SilentlyContinue | "
        "Stop-Process -Force -ErrorAction SilentlyContinue; "
        f"Restart-Service -Name {HIDE_ME_SERVICE} -ErrorAction SilentlyContinue; "
        f"Start-Process -FilePath '{app_exe}'"
    )
    wait_for_tunnel(connect_timeout_seconds)


def wait_for_tunnel(timeout_seconds: float = 90.0) -> None:
    """Blocks until a hide.me adapter reports ``Up`` or the timeout expires."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            if hideme_adapter_up():
                return
        except RuntimeError:
            pass
        time.sleep(2.0)
    raise RuntimeError("Timed out waiting for the hide.me tunnel adapter to come up.")


def hideme_adapter_ipv4() -> str:
    """Returns the IPv4 address bound to the hide.me tunnel adapter."""

    out = _powershell(
        "Get-NetIPConfiguration | "
        "Where-Object { ($_.NetAdapter.Name + ' ' + $_.InterfaceDescription) -match 'hide\\.me' } | "
        "ForEach-Object { $_.IPv4Address.IPAddress } | ConvertTo-Json -Compress"
    )
    payload = json.loads(out or "[]")
    addresses = payload if isinstance(payload, list) else [payload]
    for address in addresses:
        text = str(address)
        if text and not text.startswith("127.") and text != "0.0.0.0":
            return text
    raise RuntimeError("No IPv4 address is bound to the hide.me tunnel adapter.")


def ensure_vpn_ready(exe_path: Path, *, name: str | None = None) -> dict[str, Any]:
    """Whitelists the exe (restarting hide.me only if needed) and returns the tunnel bind IP."""

    added = ensure_whitelisted(exe_path, name=name)
    if added:
        restart_hideme()
    else:
        wait_for_tunnel()
    return {"whitelistAdded": added, "bindIp": hideme_adapter_ipv4()}
