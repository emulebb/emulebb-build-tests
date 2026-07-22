"""Launch a persisted emulebb-rust profile with the regular staged daemon."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None

REQUIRED_ENV_PATHS = (
    "CARGO_TARGET_DIR",
    "EMULEBB_WORKSPACE_OUTPUT_ROOT",
    "EMULEBB_WORKSPACE_ROOT",
)
AUTO_ED2K_SERVER = "176.123.5.89:4725"
AUTO_ED2K_SERVER_NAME = AUTO_ED2K_SERVER
DEFAULT_CONNECT_TIMEOUT_SECONDS = 120.0


def require_existing_env_path(name: str) -> Path:
    """Returns a required inherited environment path without repairing it."""

    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be set in the environment")
    path = Path(value)
    if not path.exists():
        raise RuntimeError(f"{name} points to a missing path: {path}")
    return path


def load_toml(path: Path) -> dict[str, Any]:
    """Loads one TOML file with the standard-library parser."""

    if tomllib is None:
        raise RuntimeError("Python 3.11+ is required to parse emulebb-rust-settings.toml")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def rest_base_url(config: dict[str, Any]) -> str:
    """Returns the profile REST API base URL from emulebb-rust settings."""

    bind_addr = str(config.get("rest", {}).get("bindAddr", "")).strip()
    if not bind_addr:
        raise RuntimeError("rest.bindAddr is missing from emulebb-rust-settings.toml")
    host, sep, port = bind_addr.rpartition(":")
    if not sep or not host or not port:
        raise RuntimeError(f"rest.bindAddr is not host:port: {bind_addr}")
    if host in {"0.0.0.0", "::"}:
        host = os.environ.get("X_LOCAL_IP", "").strip()
        if not host:
            raise RuntimeError("rest.bindAddr is wildcard and X_LOCAL_IP is not set")
    return f"http://{host}:{port}/api/v1"


def api_key(config: dict[str, Any]) -> str:
    """Returns the configured REST API key, if present."""

    return str(config.get("rest", {}).get("apiKey", "")).strip()


def api_request(
    config: dict[str, Any],
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Runs one JSON REST request against the configured profile daemon."""

    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    key = api_key(config)
    if key:
        headers["X-API-Key"] = key
    request = urllib.request.Request(
        f"{rest_base_url(config)}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
    if not payload:
        return {}
    decoded = json.loads(payload.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {"data": decoded}


def api_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Returns a REST data object while accepting unwrapped legacy payloads."""

    data = payload.get("data")
    return data if isinstance(data, dict) else payload


def daemon_is_running(config: dict[str, Any]) -> bool:
    """Returns whether the profile REST endpoint is already answering."""

    try:
        api_request(config, "/snapshot?limit=1", timeout=2.0)
        return True
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return False


def wait_rest_ready(config: dict[str, Any], timeout_seconds: float = 60.0) -> None:
    """Waits until the daemon REST API answers."""

    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            api_request(config, "/stats", timeout=5.0)
            return
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(1.0)
    raise RuntimeError(f"REST did not become ready: {last_error}")


def endpoint_parts(endpoint: str) -> tuple[str, int]:
    """Splits one host:port endpoint."""

    host, sep, raw_port = endpoint.rpartition(":")
    if not sep or not host:
        raise ValueError(f"server endpoint is not host:port: {endpoint}")
    port = int(raw_port)
    if not (1 <= port <= 65535):
        raise ValueError(f"server endpoint port is out of range: {endpoint}")
    return host, port


def ensure_auto_server(config: dict[str, Any]) -> None:
    """Ensures the operator ED2K server exists and is enabled."""

    address, port = endpoint_parts(AUTO_ED2K_SERVER)
    servers = api_request(config, "/servers", timeout=15.0)
    rows = servers.get("data", {}).get("items", [])
    matching = [
        row
        for row in rows
        if isinstance(row, dict)
        and str(row.get("address") or "").casefold() == address.casefold()
        and int(row.get("port") or 0) == port
    ]
    if matching:
        api_request(
            config,
            f"/servers/{AUTO_ED2K_SERVER}",
            method="PATCH",
            body={
                "name": AUTO_ED2K_SERVER_NAME,
                "priority": "high",
                "static": True,
                "enabled": True,
            },
            timeout=15.0,
        )
        return
    api_request(
        config,
        "/servers",
        method="POST",
        body={
            "address": address,
            "port": port,
            "name": AUTO_ED2K_SERVER_NAME,
            "priority": "high",
            "static": True,
            "connect": False,
        },
        timeout=15.0,
    )


def auto_connect_network(config: dict[str, Any], timeout_seconds: float) -> None:
    """Requests ED2K and Kad startup early, retrying transient REST/startup races."""

    wait_rest_ready(config)
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ensure_auto_server(config)
            api_request(config, "/servers/operations/connect", method="POST", body={}, timeout=15.0)
            api_request(config, "/kad/operations/start", method="POST", body={}, timeout=15.0)
            return
        except urllib.error.HTTPError as error:
            text = error.read().decode("utf-8", errors="replace")[:512]
            last_error = RuntimeError(f"HTTP {error.code} {error.reason}: {text}")
            print(f"Connect request failed; retrying: {last_error}")
            time.sleep(5.0)
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            print(f"Connect request failed; retrying: {error}")
            time.sleep(5.0)
    raise RuntimeError(f"Timed out requesting ED2K/Kad connect: {last_error}")


def wait_network_connected(config: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    """Waits until ED2K and Kad are connected, failing early enough for operators."""

    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = api_data(api_request(config, "/status", timeout=15.0))
        servers = latest.get("servers") if isinstance(latest.get("servers"), dict) else {}
        kad = latest.get("kad") if isinstance(latest.get("kad"), dict) else {}
        if servers.get("connected") is True and kad.get("connected") is True:
            return latest
        time.sleep(2.0)
    raise RuntimeError(f"Timed out waiting for ED2K+Kad connected: {latest}")


def wait_shared_files_ready(config: dict[str, Any], timeout_seconds: float = 60.0) -> tuple[int, int, bool]:
    """Waits until the profile has upload-capable shared files.

    A large persisted library may continue hashing for hours after a profile
    repair or share-root refresh. Uploads can still happen while the settled
    hash backlog drains, so readiness is nonzero shared files plus explicit
    reporting of the remaining hash state.
    """

    deadline = time.monotonic() + timeout_seconds
    latest_count = 0
    latest_hashing_count = 0
    latest_hashing_active = False
    while time.monotonic() < deadline:
        status = api_data(api_request(config, "/status", timeout=15.0))
        stats = status.get("stats") if isinstance(status.get("stats"), dict) else {}
        runtime = status.get("runtimeDiagnostics") if isinstance(status.get("runtimeDiagnostics"), dict) else {}
        latest_count = int(runtime.get("sharedFileCount") or 0)
        latest_hashing_count = int(stats.get("sharedHashingCount") or 0)
        latest_hashing_active = bool(stats.get("sharedHashingActive"))
        if latest_count > 0:
            return latest_count, latest_hashing_count, latest_hashing_active
        time.sleep(2.0)
    raise RuntimeError(f"Timed out waiting for upload-capable shared files; latest count={latest_count}")


def build_parser() -> argparse.ArgumentParser:
    """Builds the persisted profile client launcher parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-dir", type=Path, default=Path.cwd())
    parser.add_argument("--dry-run", action="store_true", help="Print the command without launching the daemon.")
    parser.add_argument(
        "--allow-second-instance",
        action="store_true",
        help="Launch even when the profile REST endpoint is already answering.",
    )
    parser.add_argument(
        "--connect-timeout-seconds",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT_SECONDS,
        help="Seconds to wait for early ED2K+Kad connection before returning.",
    )
    parser.add_argument(
        "--no-wait-connected",
        action="store_false",
        dest="wait_connected",
        help="Return after requesting network connect instead of waiting for ED2K+Kad.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    """Runs the persisted regular Rust daemon launcher."""

    args = build_parser().parse_args(argv)
    for name in REQUIRED_ENV_PATHS:
        require_existing_env_path(name)
    output_root = require_existing_env_path("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    profile_dir = args.profile_dir.resolve()
    config_path = profile_dir / "emulebb-rust-settings.toml"
    if not config_path.is_file():
        raise RuntimeError(f"Missing profile settings: {config_path}")
    config = load_toml(config_path)
    client_exe = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    if not client_exe.is_file():
        raise RuntimeError(f"Missing client executable: {client_exe}")

    command = [str(client_exe), "--profile", str(profile_dir)]
    print(" ".join(f'"{part}"' if " " in part else part for part in command))
    if args.dry_run:
        return 0
    if not args.allow_second_instance and daemon_is_running(config):
        print("Profile REST endpoint is already answering; not launching a second daemon.")
        auto_connect_network(config, args.connect_timeout_seconds)
        if args.wait_connected:
            wait_network_connected(config, args.connect_timeout_seconds)
        shared_count, hashing_count, hashing_active = wait_shared_files_ready(config)
        print(
            "Upload-capable persisted profile ready with "
            f"{shared_count} shared files; hashingActive={hashing_active} hashingCount={hashing_count}."
        )
        print("Requested ED2K auto-connect and Kad start on the running daemon.")
        return 0

    log_path = profile_dir / "daemon.out"
    log_handle = log_path.open("ab", buffering=0)
    env = os.environ.copy()
    env.setdefault("RUST_LOG", "info")
    process = subprocess.Popen(
        command,
        cwd=profile_dir,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        env=env,
    )
    print(f"Started emulebb-rust.exe pid={process.pid}; logging to {log_path}")
    try:
        auto_connect_network(config, args.connect_timeout_seconds)
        if args.wait_connected:
            wait_network_connected(config, args.connect_timeout_seconds)
        shared_count, hashing_count, hashing_active = wait_shared_files_ready(config)
        print(
            "Upload-capable persisted profile ready with "
            f"{shared_count} shared files; hashingActive={hashing_active} hashingCount={hashing_count}."
        )
        print("Requested ED2K auto-connect and Kad start.")
    except Exception as error:
        print(f"Started daemon, but auto-connect failed: {error}")
        return 1
    return 0
