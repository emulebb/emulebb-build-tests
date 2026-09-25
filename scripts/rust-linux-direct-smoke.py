"""Bounded WSL/Linux beta smoke against public ED2K and Kad.

The runner creates a fresh external profile, binds REST to loopback, configures
no shared roots, leaves VPN Guard off, and stops the daemon after the observation
window. When invoked on Windows it relaunches itself in WSL with translated
operator paths. A transfer is allowed only when its exact hash, size, and SHA-256
are present in the operator's checked live-wire input allowlist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
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
CONNECT_COOLDOWN_SECONDS = 300.0
ALLOWED_TRANSFER_SUFFIXES = {".iso", ".pdf"}


def require_environment() -> tuple[Path, Path]:
    workspace_value = os.environ.get("EMULEBB_WORKSPACE_ROOT", "").strip()
    if not workspace_value:
        raise RuntimeError("EMULEBB_WORKSPACE_ROOT must already be set.")
    workspace_root = Path(workspace_value).resolve()
    if not workspace_root.is_dir():
        raise RuntimeError(f"EMULEBB_WORKSPACE_ROOT is missing: {workspace_root}")
    output_root = get_workspace_output_root()
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


def enforce_connect_cooldown(marker: Path) -> None:
    """Keep public ED2K login attempts at least five minutes apart."""

    marker.parent.mkdir(parents=True, exist_ok=True)
    try:
        last_attempt = float(marker.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        last_attempt = 0.0
    wait_seconds = CONNECT_COOLDOWN_SECONDS - (time.time() - last_attempt)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    marker.write_text(str(time.time()), encoding="ascii", newline="\n")


def load_safe_transfers(inputs_path: Path, required_suffixes: set[str] | None = None) -> list[dict[str, Any]]:
    payload = json.loads(inputs_path.read_text(encoding="utf-8-sig"))
    rows = payload.get("auto_browse", {}).get("direct_bootstrap_transfers", [])
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("direct smoke requires at least one allowlisted direct bootstrap transfer.")
    transfers: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            raise RuntimeError("direct bootstrap transfer rows must be objects.")
        row = dict(raw_row)
        transfer_hash = str(row.get("hash") or "").lower()
        sha256 = str(row.get("sha256") or "").lower()
        name = str(row.get("name") or "")
        size = row.get("size")
        suffix = Path(name).suffix.lower()
        if (
            len(transfer_hash) != 32
            or any(ch not in "0123456789abcdef" for ch in transfer_hash)
            or transfer_hash in seen_hashes
            or len(sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in sha256)
            or Path(name).name != name
            or suffix not in ALLOWED_TRANSFER_SUFFIXES
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise RuntimeError("direct bootstrap transfer is not a complete, unique, verified ISO/PDF allowlist entry.")
        seen_hashes.add(transfer_hash)
        transfers.append({"name": name, "hash": transfer_hash, "size": size, "sha256": sha256, "suffix": suffix})
    required = {suffix.lower() if suffix.startswith(".") else f".{suffix.lower()}" for suffix in (required_suffixes or set())}
    available = {str(row["suffix"]) for row in transfers}
    missing = sorted(required - available)
    if missing:
        raise RuntimeError(f"direct smoke allowlist is missing required transfer type(s): {', '.join(missing)}")
    return sorted(transfers, key=lambda row: (row["suffix"] != ".pdf", str(row["name"]).lower()))


def sha256_file(path: Path) -> str:
    """Returns the SHA-256 digest of one completed allowlisted download."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wsl_path(path: Path, distribution: str | None) -> str:
    """Translates an existing Windows path through the selected WSL distribution."""

    command = ["wsl.exe"]
    if distribution:
        command.extend(["--distribution", distribution])
    # wsl.exe forwards the command through Linux argument parsing; forward
    # slashes keep a Windows drive path from losing its backslash separators.
    command.extend(["--", "wslpath", "-a", "-u", path.as_posix()])
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    translated = result.stdout.strip()
    if not translated.startswith("/"):
        raise RuntimeError(f"WSL path translation returned an invalid path for {path}.")
    return translated


def run_in_wsl(args: argparse.Namespace) -> int:
    """Relaunches this persisted runner across the Windows-to-WSL boundary."""

    workspace_value = os.environ.get("EMULEBB_WORKSPACE_ROOT", "").strip()
    output_value = os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT", "").strip()
    if not workspace_value or not output_value:
        raise RuntimeError("Windows workspace and output roots must already be present before WSL launch.")
    workspace_root = Path(workspace_value).resolve()
    output_root = Path(output_value).resolve()
    if not workspace_root.is_dir():
        raise RuntimeError(f"Windows workspace root is missing: {workspace_root}")
    if output_root == workspace_root or output_root.is_relative_to(workspace_root):
        raise RuntimeError("Windows output root must remain outside the workspace root.")
    inputs_path = Path(args.inputs).resolve()
    if not inputs_path.is_file():
        raise RuntimeError(f"live input allowlist is missing: {inputs_path}")

    wsl_workspace = wsl_path(workspace_root, args.wsl_distribution)
    wsl_output = wsl_path(output_root, args.wsl_distribution)
    wsl_script = wsl_path(SCRIPT_PATH, args.wsl_distribution)
    wsl_inputs = wsl_path(inputs_path, args.wsl_distribution)
    command = ["wsl.exe"]
    if args.wsl_distribution:
        command.extend(["--distribution", args.wsl_distribution])
    command.extend(
        [
            "--",
            "env",
            f"EMULEBB_WORKSPACE_ROOT={wsl_workspace}",
            f"EMULEBB_WORKSPACE_OUTPUT_ROOT={wsl_output}",
            "python3",
            wsl_script,
            "--wsl-child",
            "--inputs",
            wsl_inputs,
            "--connect-timeout-seconds",
            str(args.connect_timeout_seconds),
            "--observe-seconds",
            str(args.observe_seconds),
            "--transfer-timeout-seconds",
            str(args.transfer_timeout_seconds),
            "--bootstrap-limit",
            str(args.bootstrap_limit),
            "--host-workspace-root",
            workspace_root.as_posix(),
            "--host-output-root",
            output_root.as_posix(),
        ]
    )
    if args.enable_upnp:
        command.append("--enable-upnp")
    if args.complete_transfers:
        command.append("--complete-transfers")
    for suffix in args.require_transfer_type:
        command.extend(["--require-transfer-type", suffix])
    return subprocess.run(command, check=False).returncode


def status(base_url: str) -> dict[str, Any]:
    data = api_data(retry_http_json("status", 2, base_url, "/api/v1/status", api_key=API_KEY))
    stats = data.get("stats") if isinstance(data, dict) else None
    return stats if isinstance(stats, dict) else {}


def kad_status(base_url: str) -> dict[str, Any]:
    data = api_data(retry_http_json("kad", 2, base_url, "/api/v1/kad", api_key=API_KEY))
    return data if isinstance(data, dict) else {}


def nat_status(base_url: str) -> dict[str, Any]:
    data = api_data(retry_http_json("nat", 2, base_url, "/api/v1/nat", api_key=API_KEY))
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


def completed_transfer_evidence(
    base_url: str,
    row: dict[str, Any],
    incoming_dir: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits for and verifies one exact allowlisted transfer."""

    add_allowlisted_transfer(base_url, row)
    deadline = time.monotonic() + timeout_seconds
    snapshot: dict[str, Any] = {}
    while time.monotonic() < deadline:
        snapshot = transfer_snapshot(base_url, str(row["hash"]))
        if int(snapshot.get("completedBytes") or 0) == int(row["size"]):
            break
        time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
    else:
        raise RuntimeError(f"Timed out waiting for allowlisted {row['suffix']} transfer completion: {snapshot}")

    completed_path = incoming_dir / str(row["name"])
    wait_until("completed transfer delivery", 30.0, lambda: completed_path if completed_path.is_file() else None)
    actual_size = completed_path.stat().st_size
    actual_sha256 = sha256_file(completed_path)
    if actual_size != int(row["size"]) or actual_sha256 != str(row["sha256"]):
        raise RuntimeError(f"Completed allowlisted {row['suffix']} transfer failed size/SHA-256 verification.")
    return {
        "hash": row["hash"],
        "suffix": row["suffix"],
        "expectedSize": row["size"],
        "completedBytes": snapshot.get("completedBytes"),
        "sources": snapshot.get("sources"),
        "sizeVerified": True,
        "sha256Verified": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", default=str(REPO_ROOT / "live-wire-inputs.local.json"))
    parser.add_argument("--connect-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--observe-seconds", type=float, default=60.0)
    parser.add_argument("--complete-transfers", action="store_true", help="Download and verify every exact allowlisted transfer.")
    parser.add_argument("--transfer-timeout-seconds", type=float, default=3600.0, help="Completion timeout for each allowlisted transfer.")
    parser.add_argument("--require-transfer-type", action="append", default=[], choices=("iso", "pdf"))
    parser.add_argument("--enable-upnp", action="store_true", help="Require live UPnP discovery and TCP/UDP mappings.")
    parser.add_argument("--bootstrap-limit", type=int, default=40)
    parser.add_argument("--wsl-distribution")
    parser.add_argument("--wsl-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-workspace-root", help=argparse.SUPPRESS)
    parser.add_argument("--host-output-root", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.name == "nt" and not args.wsl_child:
        return run_in_wsl(args)
    if args.connect_timeout_seconds <= 0 or args.observe_seconds < 0 or args.transfer_timeout_seconds <= 0:
        raise RuntimeError("timeouts must be non-negative and connection/transfer timeouts must be positive.")
    workspace_root, output_root = require_environment()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    executable = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust"
    if not executable.is_file():
        raise RuntimeError(f"staged Linux daemon is missing: {executable}")
    safe_transfers = load_safe_transfers(Path(args.inputs).resolve(), set(args.require_transfer_type))
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
        nat_enabled=args.enable_upnp,
        nat_require_initial_mapping=args.enable_upnp,
        initial_shared_directory_reload=False,
        vpn_guard_mode="off",
    )

    base_url = f"http://{REST_ADDR}:{REST_PORT}"
    daemon_log = run_root / "daemon.log"
    report: dict[str, Any] = {
        "schema": "emulebb.rust-linux-direct-smoke.v2",
        "runId": run_id,
        "networkMode": "direct",
        "vpnGuard": "off",
        "upnp": {"requested": args.enable_upnp},
        "restLoopback": True,
        "sharedRootCount": 0,
        "bootstrapContactCount": len(bootstrap_nodes),
        "safeTransfers": [
            {"hash": row["hash"], "size": row["size"], "sha256": row["sha256"], "suffix": row["suffix"]}
            for row in safe_transfers
        ],
    }
    if args.host_workspace_root and args.host_output_root:
        report["wslBoundary"] = {
            "sourceWorkspaceRoot": args.host_workspace_root,
            "sourceOutputRoot": args.host_output_root,
            "translatedWorkspaceRoot": str(workspace_root),
            "translatedOutputRoot": str(output_root),
        }
    handle = daemon_log.open("w", encoding="utf-8", newline="\n")
    process = start_rust_client_executable_with_output(executable, profile_dir, handle)
    try:
        wait_until("Rust REST ready", 60.0, lambda: status(base_url) or None)
        report["webuiReady"] = webui_ready(base_url)
        if args.enable_upnp:
            nat = nat_status(base_url)
            report["upnp"] = {
                "requested": True,
                "enabled": bool(nat.get("enabled")),
                "gatewayDiscovered": bool(nat.get("gatewayDiscovered")),
                "mappingCount": len(nat.get("mappings") or []),
                "backend": nat.get("backend"),
                "lastError": nat.get("lastError"),
            }
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
        enforce_connect_cooldown(output_root / "live-wire" / ".last-server-connect")
        post_json(base_url, "/api/v1/servers/operations/connect", {})
        def connected_stats() -> dict[str, Any] | None:
            current = status(base_url)
            return current if current.get("ed2kConnected") else None

        stats = wait_until("ED2K connected", args.connect_timeout_seconds, connected_stats)

        def kad_connected() -> dict[str, Any] | None:
            current = kad_status(base_url)
            return current if current.get("connected") and int(current.get("contactCount") or 0) > 0 else None

        try:
            kad = wait_until("Kad connected", args.connect_timeout_seconds, kad_connected)
        except RuntimeError:
            kad = kad_status(base_url)
        report["ed2k"] = {"connected": bool(stats.get("ed2kConnected")), "highId": bool(stats.get("ed2kHighId"))}
        report["kad"] = {
            "running": bool(kad.get("running")),
            "connected": bool(kad.get("connected")),
            "contactCount": int(kad.get("contactCount") or 0),
        }
        if args.complete_transfers:
            report["transfers"] = []
            for row in safe_transfers:
                report["transfers"].append(
                    completed_transfer_evidence(base_url, row, incoming_dir, args.transfer_timeout_seconds)
                )
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
            report["webuiReady"]
            and report["ed2k"]["connected"]
            and (not args.enable_upnp or (report["ed2k"]["highId"] and report["upnp"]["gatewayDiscovered"] and report["upnp"]["mappingCount"] >= 2))
            and report["kad"]["running"]
            and report["kad"]["connected"]
            and report["kad"]["contactCount"] > 0
            and (not args.complete_transfers or len(report.get("transfers", [])) == len(safe_transfers))
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
