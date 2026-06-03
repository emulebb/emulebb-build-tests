"""Shared Windows VM guest profile helpers."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_HIDEME_VPN_GUARD_PUBLIC_IP_CIDRS = (
    "176.10.104.0/22",
    "149.88.27.0/24",
    "98.98.148.0/23",
)
DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS = ",".join(DEFAULT_HIDEME_VPN_GUARD_PUBLIC_IP_CIDRS)


def emit(payload: dict[str, Any]) -> int:
    """Writes one JSON object for the host PowerShell shim."""

    print(json.dumps(payload, sort_keys=True))
    return 0


def run(command: list[str], *, timeout_seconds: float = 60.0) -> None:
    """Runs one guest command and raises with useful output on failure."""

    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"{command[0]} failed with exit code {completed.returncode}: {detail}")


def api_data(payload: Any) -> Any:
    """Unwraps eMuleBB REST envelopes while keeping older raw test shapes valid."""

    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def api_rows(payload: Any, *candidate_keys: str) -> list[dict[str, Any]]:
    """Returns REST rows from either a raw list or a wrapped API object."""

    data = api_data(payload)
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = []
        for key in (*candidate_keys, "items"):
            value = data.get(key)
            if isinstance(value, list):
                rows = value
                break
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def http_json(
    base_url: str,
    path: str,
    *,
    api_key: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout_seconds: float = 30.0,
) -> Any:
    """Calls one eMuleBB REST endpoint and decodes the JSON response."""

    data = None
    headers = {"X-API-Key": api_key}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8-sig")) if raw else {}


def retry_http_json(
    description: str,
    attempts: int,
    base_url: str,
    path: str,
    request_func=None,
    **kwargs: Any,
) -> Any:
    """Calls REST with backoff for eMule's single-client web worker."""

    last_error: str | None = None
    request = request_func or http_json
    for attempt in range(attempts):
        try:
            return request(base_url, path, **kwargs)
        except (OSError, TimeoutError, urllib.error.URLError, RuntimeError) as exc:
            last_error = str(exc)
            time.sleep(min(1.0 + attempt, 5.0))
    suffix = f": {last_error}" if last_error else ""
    raise RuntimeError(f"{description} failed after {attempts} attempts{suffix}")


def wait_until(description: str, timeout_seconds: float, callback):
    """Retries a callback until it returns a truthy result or the timeout expires."""

    deadline = time.monotonic() + timeout_seconds
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            result = callback()
            if result:
                return result
        except (OSError, TimeoutError, urllib.error.URLError, RuntimeError) as exc:
            last_error = str(exc)
        time.sleep(1.0)
    suffix = f": {last_error}" if last_error else ""
    raise RuntimeError(f"Timed out waiting for {description}{suffix}")


def repair_firewall(script_path: Path, program_path: Path, result_path: Path) -> dict[str, Any]:
    """Runs the packaged firewall repair script and returns its result JSON."""

    run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-ProgramPath",
            str(program_path),
            "-ResultPath",
            str(result_path),
        ],
        timeout_seconds=60.0,
    )
    return json.loads(result_path.read_text(encoding="utf-8-sig"))


def start_visible_app(exe_path: Path, profile_dir: Path, *, task_name: str, username: str, password: str) -> None:
    """Starts eMuleBB in the interactive user session through Task Scheduler."""

    subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    command = f'"{exe_path}" -ignoreinstances -c "{profile_dir}"'
    start_time = time.strftime("%H:%M", time.localtime(time.time() + 60))
    run(
        [
            "schtasks.exe",
            "/Create",
            "/TN",
            task_name,
            "/SC",
            "ONCE",
            "/ST",
            start_time,
            "/TR",
            command,
            "/RU",
            username,
            "/RP",
            password,
            "/RL",
            "HIGHEST",
            "/IT",
            "/F",
        ],
        timeout_seconds=30.0,
    )
    run(["schtasks.exe", "/Run", "/TN", task_name], timeout_seconds=30.0)


def write_preferences_ini(config_dir: Path, text: str) -> None:
    """Writes the VM guest eMule preferences file with Windows-compatible UTF-16 encoding."""

    (config_dir / "preferences.ini").write_text(text, encoding="utf-16")


def local_ed2k_preferences_text(
    *,
    target: str,
    incoming_dir: Path,
    temp_dir: Path,
    tcp_port: int,
    udp_port: int,
    bind_addr: str,
    rest_port: int,
    api_key: str,
) -> str:
    """Builds the eMuleBB profile used by the local VM transfer test."""

    return "\n".join(
        [
            "[eMule]",
            f"Nick={target}-vm",
            "ConfirmExit=0",
            f"IncomingDir={incoming_dir}",
            f"TempDir={temp_dir}",
            f"Port={tcp_port}",
            f"UDPPort={udp_port}",
            "ServerUDPPort=65535",
            f"BindAddr={bind_addr}",
            "BindInterface=",
            "BlockNetworkWhenBindUnavailableAtStartup=1",
            "NetworkED2K=1",
            "NetworkKademlia=0",
            "Autoconnect=0",
            "Reconnect=0",
            "SafeServerConnect=0",
            "FilterBadIPs=0",
            "AllowLocalHostIP=1",
            "GeoLocationLookupEnabled=0",
            "IPFilterEnabled=0",
            "SaveLogToDisk=1",
            "SaveDebugToDisk=1",
            "Verbose=1",
            "FullVerbose=1",
            "[WebServer]",
            "Enabled=1",
            f"ApiKey={api_key}",
            f"Port={rest_port}",
            f"BindAddr={bind_addr}",
            "UseHTTPS=0",
            "[UPnP]",
            "EnableUPnP=0",
            "",
        ]
    )


def hideme_live_preferences_text(
    *,
    target: str,
    incoming_dir: Path,
    temp_dir: Path,
    tcp_port: int,
    udp_port: int,
    rest_port: int,
    lan_bind_addr: str,
    api_key: str,
) -> str:
    """Builds the eMuleBB profile used by the public hide.me VM live-wire test."""

    return "\n".join(
        [
            "[eMule]",
            f"Nick={target}-vm-hideme",
            "ConfirmExit=0",
            f"IncomingDir={incoming_dir}",
            f"TempDir={temp_dir}",
            f"Port={tcp_port}",
            f"UDPPort={udp_port}",
            "BindAddr=",
            "BindInterface=hide.me",
            "NetworkED2K=1",
            "NetworkKademlia=0",
            "Autoconnect=0",
            "Reconnect=0",
            "SafeServerConnect=0",
            "FilterBadIPs=1",
            "IPFilterEnabled=0",
            "GeoLocationLookupEnabled=0",
            "VpnGuardMode=Block",
            f"VpnGuardAllowedPublicIpCidrs={DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS}",
            "SaveLogToDisk=1",
            "SaveDebugToDisk=1",
            "Verbose=1",
            "FullVerbose=1",
            "[WebServer]",
            "Enabled=1",
            f"ApiKey={api_key}",
            f"Port={rest_port}",
            f"BindAddr={lan_bind_addr}",
            "UseHTTPS=0",
            "[UPnP]",
            "EnableUPnP=1",
            "",
        ]
    )
