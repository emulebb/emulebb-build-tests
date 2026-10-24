"""Read-only hide.me settings, adapter, and routing checks for host live runs."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

HIDE_ME_APP_EXE = r"C:\Program Files (x86)\hide.me VPN\Hide.me.exe"
HIDE_ME_SERVICE = "hmevpnsvc"
FULL_TUNNEL_SPLIT_MODE = 0


def vpn_settings_path() -> Path:
    """Return the current user's hide.me settings path."""

    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set; cannot locate hide.me settings.")
    return Path(appdata) / "Hide.me" / "vpn.settings"


def load_settings(path: Path) -> dict[str, Any]:
    """Load hide.me settings without changing provider state."""

    return json.loads(path.read_text(encoding="utf-8-sig"))


def run_powershell(script: str, *, timeout_seconds: float = 60.0) -> str:
    """Run one read-only or lifecycle PowerShell probe and return stdout."""

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


def split_tunnel_mode(settings_path: Path | None = None) -> int:
    """Return hide.me's numeric split-tunnel mode from its settings file."""

    settings = load_settings(settings_path or vpn_settings_path())
    split = settings.get("SplitTunneling")
    if not isinstance(split, dict):
        raise RuntimeError("hide.me settings are missing SplitTunneling state.")
    raw_mode = split.get("Mode")
    if isinstance(raw_mode, bool):
        raise RuntimeError(f"hide.me SplitTunneling.Mode must be numeric, got {raw_mode!r}.")
    try:
        return int(raw_mode)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"hide.me SplitTunneling.Mode must be numeric, got {raw_mode!r}.") from exc


def hideme_adapter_up() -> bool:
    """Return whether a hide.me network adapter is present and up."""

    out = run_powershell(
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


def wait_for_tunnel(timeout_seconds: float = 90.0) -> None:
    """Wait until a hide.me adapter reports up or the timeout expires."""

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
    """Return the IPv4 address bound to the hide.me tunnel adapter."""

    out = run_powershell(
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


def hideme_public_route_status() -> dict[str, object]:
    """Return whether representative public routes resolve through hide.me."""

    out = run_powershell(
        "$adapterIndexes = @(Get-NetAdapter | "
        "Where-Object { (($_.Name + ' ' + $_.InterfaceDescription) -match 'hide\\.me') -and $_.Status -eq 'Up' } | "
        "ForEach-Object { [int]$_.InterfaceIndex }); "
        "$routeIndexes = @('192.0.2.1','198.51.100.1','203.0.113.1' | ForEach-Object { "
        "$route = Find-NetRoute -RemoteIPAddress $_ -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($null -ne $route) { [int]$route.InterfaceIndex } }); "
        "[pscustomobject]@{ adapterInterfaceIndexes=$adapterIndexes; routeInterfaceIndexes=$routeIndexes } | "
        "ConvertTo-Json -Compress"
    )
    payload = json.loads(out or "{}")
    if not isinstance(payload, dict):
        raise RuntimeError("Unable to read hide.me route state.")

    adapter_indexes = payload.get("adapterInterfaceIndexes") or []
    route_indexes = payload.get("routeInterfaceIndexes") or []
    if isinstance(adapter_indexes, int):
        adapter_indexes = [adapter_indexes]
    if isinstance(route_indexes, int):
        route_indexes = [route_indexes]
    normalized_adapters = {int(value) for value in adapter_indexes}
    normalized_routes = [int(value) for value in route_indexes]
    routes_through_hideme = (
        bool(normalized_adapters)
        and len(normalized_routes) == 3
        and all(value in normalized_adapters for value in normalized_routes)
    )
    return {
        "adapterCount": len(normalized_adapters),
        "routeProbeCount": len(normalized_routes),
        "routesThroughHideMe": routes_through_hideme,
    }


def require_full_tunnel_ready(*, settings_path: Path | None = None) -> dict[str, object]:
    """Require an active full-tunnel hide.me route without mutating provider state."""

    mode = split_tunnel_mode(settings_path)
    if mode != FULL_TUNNEL_SPLIT_MODE:
        raise RuntimeError(
            "hide.me split tunneling must be disabled for the full-tunnel live lane; "
            f"observed mode {mode}."
        )
    if not hideme_adapter_up():
        raise RuntimeError("hide.me must already be connected before the full-tunnel live lane starts.")
    route_status = hideme_public_route_status()
    if not route_status["routesThroughHideMe"]:
        raise RuntimeError("Representative public routes do not resolve through the active hide.me adapter.")
    return {
        "schema": "emulebb.hide-me-full-tunnel-status.v1",
        "splitTunnelMode": mode,
        "adapterUp": True,
        **route_status,
        "bindIp": hideme_adapter_ipv4(),
    }
