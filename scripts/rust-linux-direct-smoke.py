"""Bounded WSL/Linux beta smoke against public ED2K and Kad.

The runner creates a fresh external profile, binds REST to loopback, configures
no shared roots, leaves VPN Guard and UPnP off, and stops the daemon after the
observation window. A transfer is allowed only when its exact hash, size, and
SHA-256 are present in the operator's checked live-wire input allowlist.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.rust_client import (
    start_rust_client_executable_with_output,
    stop_process_tree,
    write_rust_profile,
)
from emule_test_harness.vm_guest_profiles import api_data, retry_http_json, wait_until

API_KEY = "rust-linux-direct-smoke"
OPERATOR_SERVER = "176.123.5.89:4725"
REST_ADDR = "127.0.0.1"
REST_PORT = 4731
ED2K_PORT = 41662
KAD_PORT = 41672


def require_environment() -> tuple[Path, Path]:
    workspace_value = os.environ.get("EMULEBB_WORKSPACE_ROOT", "").strip()
    if not workspace_value:
        raise RuntimeError("EMULEBB_WORKSPACE_ROOT must already be set.")
    workspace_root = Path(workspace_value).resolve()
    if not workspace_root.is_dir():
        raise RuntimeError(f"EMULEBB_WORKSPACE_ROOT is missing: {workspace_root}")
    output_root = get_workspace_output_root()
    cargo_value = os.environ.get("CARGO_TARGET_DIR", "").strip()
    expected_cargo = (output_root / "builds" / "rust" / "target").resolve()
    if not cargo_value or Path(cargo_value).resolve() != expected_cargo:
        raise RuntimeError(f"CARGO_TARGET_DIR must already be {expected_cargo}.")
    return workspace_root, output_root


def resolve_direct_bind_ip() -> str:
    """Return the IPv4 address selected by the host route to the ED2K server."""

    host, _, raw_port = OPERATOR_SERVER.rpartition(":")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, int(raw_port)))
        address = str(probe.getsockname()[0])
    if not address or address == "0.0.0.0" or address.startswith("127."):
        raise RuntimeError("direct route did not resolve to a non-loopback IPv4 address.")
    return address


def load_safe_transfer(inputs_path: Path) -> dict[str, Any]:
    payload = json.loads(inputs_path.read_text(encoding="utf-8-sig"))
    rows = payload.get("auto_browse", {}).get("direct_bootstrap_transfers", [])
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("direct smoke requires exactly one allowlisted direct bootstrap transfer.")
    row = dict(rows[0])
    transfer_hash = str(row.get("hash") or "").lower()
    sha256 = str(row.get("sha256") or "").lower()
    name = str(row.get("name") or "")
    size = row.get("size")
    if (
        len(transfer_hash) != 32
        or any(ch not in "0123456789abcdef" for ch in transfer_hash)
        or len(sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in sha256)
        or not name.lower().endswith(".iso")
        or not isinstance(size, int)
        or size <= 0
    ):
        raise RuntimeError("direct bootstrap transfer is not a complete verified ISO allowlist entry.")
    return {"name": name, "hash": transfer_hash, "size": size, "sha256": sha256}


def status(base_url: str) -> dict[str, Any]:
    data = api_data(retry_http_json("status", 2, base_url, "/api/v1/status", api_key=API_KEY))
    stats = data.get("stats") if isinstance(data, dict) else None
    return stats if isinstance(stats, dict) else {}


def kad_status(base_url: str) -> dict[str, Any]:
    data = api_data(retry_http_json("kad", 2, base_url, "/api/v1/kad", api_key=API_KEY))
    return data if isinstance(data, dict) else {}


def webui_ready(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url}/", timeout=5.0) as response:
            return response.status == 200 and b'<div id="app"></div>' in response.read()
    except OSError:
        return False


def post_json(base_url: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
    )
    try:
        with urllib.request.urlopen(request, timeout=20.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"POST {path} returned HTTP {error.code}: {detail}") from error
    return payload if isinstance(payload, dict) else {}


def add_allowlisted_transfer(base_url: str, row: dict[str, Any]) -> None:
    link = f"ed2k://|file|{row['name']}|{row['size']}|{str(row['hash']).upper()}|/"
    retry_http_json(
        "safe transfer add",
        2,
        base_url,
        "/api/v1/transfers",
        api_key=API_KEY,
        method="POST",
        body={"link": link, "paused": False},
        timeout_seconds=20.0,
    )


def transfer_snapshot(base_url: str, transfer_hash: str) -> dict[str, Any]:
    data = api_data(
        retry_http_json(
            "safe transfer",
            2,
            base_url,
            f"/api/v1/transfers/{transfer_hash}",
            api_key=API_KEY,
        )
    )
    if not isinstance(data, dict):
        return {}
    return {
        key: data.get(key)
        for key in ("hash", "state", "completedBytes", "sizeBytes", "sources", "speedDownBytesPerSec")
        if key in data
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", default=str(REPO_ROOT / "live-wire-inputs.local.json"))
    parser.add_argument("--connect-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--observe-seconds", type=float, default=60.0)
    parser.add_argument("--transfer-seconds", type=float, default=0.0, help="Queue the exact allowlisted ISO and observe it for this many seconds.")
    parser.add_argument("--bootstrap-limit", type=int, default=40)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.connect_timeout_seconds <= 0 or args.observe_seconds < 0 or args.transfer_seconds < 0:
        raise RuntimeError("timeouts must be non-negative and connect timeout must be positive.")
    workspace_root, output_root = require_environment()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    executable = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust"
    if not executable.is_file():
        raise RuntimeError(f"staged Linux daemon is missing: {executable}")
    safe_transfer = load_safe_transfer(Path(args.inputs).resolve())
    bootstrap_nodes = fetch_bootstrap_endpoints(DEFAULT_NODES_DAT_URL, limit=args.bootstrap_limit)
    direct_bind_ip = resolve_direct_bind_ip()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = output_root / "reports" / "rust-linux-direct-smoke" / run_id
    profile_dir = output_root / "profiles" / "rust-linux-direct-smoke" / run_id
    incoming_dir = profile_dir / "incoming"
    run_root.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)
    write_rust_profile(
        profile_dir,
        rust_repo=rust_repo,
        incoming_dir=incoming_dir,
        rest_addr=REST_ADDR,
        rest_port=REST_PORT,
        api_key=API_KEY,
        p2p_bind_ip=direct_bind_ip,
        ed2k_port=ED2K_PORT,
        kad_port=KAD_PORT,
        server_endpoint=OPERATOR_SERVER,
        replace_servers=True,
        kad_bootstrap_nodes=bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=2,
        nat_enabled=False,
        initial_shared_directory_reload=False,
        vpn_guard_mode="off",
    )

    base_url = f"http://{REST_ADDR}:{REST_PORT}"
    daemon_log = run_root / "daemon.log"
    report: dict[str, Any] = {
        "schema": "emulebb.rust-linux-direct-smoke.v1",
        "runId": run_id,
        "networkMode": "direct",
        "vpnGuard": "off",
        "upnp": False,
        "restLoopback": True,
        "sharedRootCount": 0,
        "bootstrapContactCount": len(bootstrap_nodes),
        "safeTransfer": {"hash": safe_transfer["hash"], "size": safe_transfer["size"], "sha256": safe_transfer["sha256"]},
    }
    handle = daemon_log.open("w", encoding="utf-8", newline="\n")
    process = start_rust_client_executable_with_output(executable, profile_dir, handle)
    try:
        wait_until("Rust REST ready", 60.0, lambda: status(base_url) or None)
        report["webuiReady"] = webui_ready(base_url)
        retry_http_json(
            "enable networks",
            2,
            base_url,
            "/api/v1/app/settings",
            api_key=API_KEY,
            method="PATCH",
            body={"core": {"networkEd2k": True, "networkKademlia": True, "autoConnect": False, "reconnect": False}},
        )
        retry_http_json("kad start", 2, base_url, "/api/v1/kad/operations/start", api_key=API_KEY, method="POST", body={})
        post_json(base_url, "/api/v1/servers/operations/connect", {})
        def connected_stats() -> dict[str, Any] | None:
            current = status(base_url)
            return current if current.get("ed2kConnected") else None

        stats = wait_until("ED2K connected", args.connect_timeout_seconds, connected_stats)

        def kad_with_contact() -> dict[str, Any] | None:
            current = kad_status(base_url)
            return current if int(current.get("contactCount") or 0) > 0 else None

        try:
            kad = wait_until("Kad contact", args.connect_timeout_seconds, kad_with_contact)
        except RuntimeError:
            kad = kad_status(base_url)
        report["ed2k"] = {"connected": bool(stats.get("ed2kConnected")), "highId": bool(stats.get("ed2kHighId"))}
        report["kad"] = {
            "running": bool(kad.get("running")),
            "connected": bool(kad.get("connected")),
            "contactCount": int(kad.get("contactCount") or 0),
        }
        if args.transfer_seconds > 0:
            add_allowlisted_transfer(base_url, safe_transfer)
            deadline = time.monotonic() + args.transfer_seconds
            snapshot: dict[str, Any] = {}
            while time.monotonic() < deadline:
                snapshot = transfer_snapshot(base_url, str(safe_transfer["hash"]))
                time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
            report["transfer"] = snapshot
        if args.observe_seconds > 0:
            time.sleep(args.observe_seconds)
        final_stats = status(base_url)
        final_kad = kad_status(base_url)
        report["ed2k"] = {
            "connected": bool(final_stats.get("ed2kConnected")),
            "highId": bool(final_stats.get("ed2kHighId")),
        }
        report["kad"] = {
            "running": bool(final_kad.get("running")),
            "connected": bool(final_kad.get("connected")),
            "contactCount": int(final_kad.get("contactCount") or 0),
        }
        report["status"] = "passed" if (
            report["webuiReady"] and report["ed2k"]["connected"] and report["kad"]["running"] and report["kad"]["contactCount"] > 0
        ) else "failed"
    except Exception as exc:  # noqa: BLE001 - evidence must survive a live failure
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        stop_process_tree(process)
        handle.close()

    report_path = run_root / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"report": str(report_path), **report}, sort_keys=True))
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
