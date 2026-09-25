"""Bounded direct beta smoke against public ED2K and Kad on WSL or Windows.

The runner creates a fresh external profile, configures no shared roots, leaves
VPN Guard off, and stops the daemon after the observation window. Windows native
mode binds REST to inherited X_LOCAL_IP and requires UPnP; the WSL mode binds to
loopback. A transfer is allowed only when its exact hash, size, and SHA-256 are
present in the operator's checked live-wire input allowlist.
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
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from collections import Counter
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.direct_safe_corpus import LINUX_PDF_TERMS, MAX_PDF_BYTES
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness import rust_client
from emule_test_harness.rust_client import (
    stop_process_tree,
    write_rust_profile,
)
from emule_test_harness.vm_guest_profiles import api_data, api_rows, retry_http_json, wait_until

API_KEY = "rust-linux-direct-smoke"
ROUTE_PROBE_IP = "192.0.2.1"
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

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        # UDP connect selects the outbound interface without sending a packet.
        probe.connect((ROUTE_PROBE_IP, 9))
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
            or (suffix == ".pdf" and (size > MAX_PDF_BYTES or not any(term in name.casefold() for term in LINUX_PDF_TERMS)))
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
            "--probe-count",
            str(args.probe_count),
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
    # Stock MFC EncodeUrlUtf8 percent-encodes spaces and UTF-8 file-name bytes.
    encoded_name = urllib.parse.quote(str(row["name"]), safe="")
    link = f"ed2k://|file|{encoded_name}|{row['size']}|{str(row['hash']).upper()}|/"
    post_json(base_url, "/api/v1/transfers", {"link": link, "paused": False})


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
    monitor=None,
) -> dict[str, Any]:
    """Waits for and verifies one exact allowlisted transfer."""

    add_allowlisted_transfer(base_url, row)
    deadline = time.monotonic() + timeout_seconds
    snapshot: dict[str, Any] = {}
    while time.monotonic() < deadline:
        if monitor is not None:
            monitor()
        snapshot = transfer_snapshot(base_url, str(row["hash"]))
        if int(snapshot.get("completedBytes") or 0) == int(row["size"]):
            break
        time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
    else:
        if not snapshot.get("sources") and not int(snapshot.get("completedBytes") or 0):
            return {"hash": row["hash"], "suffix": row["suffix"], "status": "inconclusive", "reason": "no_source"}
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
        "status": "passed",
    }


class PacketDumpMonitor:
    """Checks fresh diagnostic JSONL while retaining only schema counts in reports."""

    def __init__(self, dump_dir: Path, process: subprocess.Popen, max_bytes: int = 512 * 1024 * 1024) -> None:
        self.dump_dir = dump_dir
        self.process = process
        self.max_bytes = max_bytes
        self.positions: dict[Path, int] = {}
        self.pending: dict[Path, bytes] = {}
        self.schemas: Counter[str] = Counter()
        self.error_events: Counter[str] = Counter()
        self.source_software: dict[tuple[str, str], str] = {}
        self.accepted_source_bytes: Counter[tuple[str, str]] = Counter()
        self.peak_source_count = 0
        self.records = 0

    def sample(self) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError(f"Rust daemon exited during live diagnostics (code {self.process.returncode}).")
        total_bytes = 0
        for path in sorted(self.dump_dir.glob("emulebb-rust-*.jsonl")):
            size = path.stat().st_size
            total_bytes += size
            if total_bytes > self.max_bytes:
                raise RuntimeError("Live diagnostic dumps exceeded the bounded retention limit.")
            previous = self.positions.get(path, 0)
            if size < previous:
                raise RuntimeError("Live diagnostic dump was truncated during capture.")
            if size == previous:
                continue
            with path.open("rb") as handle:
                handle.seek(previous)
                fresh = handle.read(size - previous)
            self.positions[path] = size
            parts = (self.pending.pop(path, b"") + fresh).split(b"\n")
            self.pending[path] = parts.pop()
            for line in parts:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise RuntimeError("Malformed live diagnostic JSONL record.") from error
                if not isinstance(record, dict) or not isinstance(record.get("schema"), str):
                    raise RuntimeError("Live diagnostic record is missing a schema.")
                self.schemas[record["schema"]] += 1
                if record.get("severity") == "error":
                    self.error_events[str(record.get("event") or "unknown")] += 1
                if record.get("schema") == "diag_event_v1":
                    keys = record.get("keys") or {}
                    body = record.get("body") or {}
                    if isinstance(keys, dict) and isinstance(body, dict):
                        if record.get("event") == "source_count":
                            count = body.get("sourceCount")
                            if isinstance(count, int) and count > self.peak_source_count:
                                self.peak_source_count = count
                        source_key = (str(keys.get("fileHash") or ""), str(keys.get("peer") or ""))
                        if all(source_key):
                            software = body.get("clientSoftware")
                            if isinstance(software, str) and software:
                                self.source_software[source_key] = software
                            if record.get("event") == "download_payload_accepted":
                                accepted = body.get("bytes")
                                if isinstance(accepted, int) and accepted > 0:
                                    self.accepted_source_bytes[source_key] += accepted
                self.records += 1
        stock_bytes = sum(
            count for key, count in self.accepted_source_bytes.items()
            if self.source_software.get(key, "").lower().startswith("emule ")
        )
        return {
            "records": self.records,
            "schemas": dict(sorted(self.schemas.items())),
            "errorEvents": dict(sorted(self.error_events.items())),
            "acceptedPayloadBytes": sum(self.accepted_source_bytes.values()),
            "stockIdentifiedAcceptedBytes": stock_bytes,
            "acceptedSourceCount": len(self.accepted_source_bytes),
            "peakSourceCount": self.peak_source_count,
            "bytes": total_bytes,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", default=str(REPO_ROOT / "live-wire-inputs.local.json"))
    parser.add_argument("--connect-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--observe-seconds", type=float, default=60.0)
    parser.add_argument("--complete-transfers", action="store_true", help="Download and verify every exact allowlisted transfer.")
    parser.add_argument("--probe-count", type=int, default=0, help="Queue up to 50 allowlisted transfers for bounded source/byte observation.")
    parser.add_argument("--transfer-timeout-seconds", type=float, default=3600.0, help="Completion timeout for each allowlisted transfer.")
    parser.add_argument("--require-transfer-type", action="append", default=[], choices=("iso", "pdf"))
    parser.add_argument("--enable-upnp", action="store_true", help="Require live UPnP discovery and TCP/UDP mappings.")
    parser.add_argument("--wsl-distribution")
    parser.add_argument("--native-windows", action="store_true", help="Use the staged Windows diagnostics daemon and direct host route instead of WSL.")
    parser.add_argument("--wsl-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-workspace-root", help=argparse.SUPPRESS)
    parser.add_argument("--host-output-root", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.name == "nt" and not args.wsl_child and not args.native_windows:
        return run_in_wsl(args)
    if args.native_windows and (os.name != "nt" or args.wsl_child or not args.enable_upnp):
        raise RuntimeError("Native Windows direct mode requires Windows, --enable-upnp, and no WSL child mode.")
    if args.connect_timeout_seconds <= 0 or args.observe_seconds < 0 or args.transfer_timeout_seconds <= 0:
        raise RuntimeError("timeouts must be non-negative and connection/transfer timeouts must be positive.")
    if not 0 <= args.probe_count <= 50 or (args.probe_count and args.complete_transfers):
        raise RuntimeError("--probe-count must be 0..50 and cannot be combined with --complete-transfers.")
    workspace_root, output_root = require_environment()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    executable_name = "emulebb-rust-diagnostics.exe" if args.native_windows else "emulebb-rust"
    executable = output_root / "tools" / "emulebb-rust" / "bin" / executable_name
    if not executable.is_file():
        raise RuntimeError(f"staged daemon is missing: {executable}")
    safe_transfers = load_safe_transfers(Path(args.inputs).resolve(), set(args.require_transfer_type))
    direct_bind_ip = resolve_direct_bind_ip()
    rest_addr = REST_ADDR
    if args.native_windows:
        rest_addr = os.environ.get("X_LOCAL_IP", "").strip()
        if not rest_addr or rest_addr.startswith("127.") or rest_addr == "0.0.0.0":
            raise RuntimeError("Native Windows direct smoke requires inherited non-loopback X_LOCAL_IP.")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lane = "rust-windows-direct-smoke" if args.native_windows else "rust-linux-direct-smoke"
    run_root = output_root / "reports" / lane / run_id
    profile_dir = output_root / "profiles" / lane / run_id
    incoming_dir = profile_dir / "incoming"
    run_root.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)
    write_rust_profile(
        profile_dir,
        rust_repo=rust_repo,
        incoming_dir=incoming_dir,
        rest_addr=rest_addr,
        rest_port=REST_PORT,
        api_key=API_KEY,
        p2p_bind_ip=direct_bind_ip,
        ed2k_port=ED2K_PORT,
        kad_port=KAD_PORT,
        server_endpoint=None,
        replace_servers=False,
        kad_bootstrap_min_routing_contacts=2,
        nat_enabled=args.enable_upnp,
        nat_require_initial_mapping=args.enable_upnp,
        initial_shared_directory_reload=False,
        vpn_guard_mode="off",
    )

    base_url = f"http://{rest_addr}:{REST_PORT}"
    daemon_log = run_root / "daemon.log"
    diagnostic_dir = run_root / "diagnostics"
    if args.native_windows:
        diagnostic_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "emulebb.rust-direct-smoke.v3",
        "runId": run_id,
        "networkMode": "direct",
        "vpnGuard": "off",
        "upnp": {"requested": args.enable_upnp},
        "restLoopback": not args.native_windows,
        "diagnosticsRequired": args.native_windows,
        "sharedRootCount": 0,
        "bootstrap": {"mode": "product-first-run"},
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
    launch_env = os.environ.copy()
    if args.native_windows:
        launch_env["EMULEBB_RUST_LOG_DIR"] = str(diagnostic_dir)
    process = rust_client.spawn_rust_daemon(executable, profile_dir, output_handle=handle, env=launch_env)
    monitor = PacketDumpMonitor(diagnostic_dir, process) if args.native_windows else None
    try:
        wait_until("Rust REST ready", 60.0, lambda: status(base_url) or None)
        report["webuiReady"] = webui_ready(base_url)
        server_rows = api_rows(
            retry_http_json("imported servers", 2, base_url, "/api/v1/servers", api_key=API_KEY),
            "servers",
        )
        if not server_rows:
            raise RuntimeError("fresh Rust profile did not import any trusted server.met entries")
        nodes_dat = profile_dir / "nodes.dat"
        report["bootstrap"] = {
            "mode": "product-first-run",
            "serverCount": len(server_rows),
            "nodesDatBytes": nodes_dat.stat().st_size if nodes_dat.is_file() else 0,
        }
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
        if args.probe_count:
            for row in safe_transfers[:args.probe_count]:
                add_allowlisted_transfer(base_url, row)
        if args.complete_transfers:
            report["transfers"] = []
            for row in safe_transfers:
                report["transfers"].append(
                    completed_transfer_evidence(base_url, row, incoming_dir, args.transfer_timeout_seconds, monitor.sample if monitor else None)
                )
        if args.observe_seconds > 0:
            deadline = time.monotonic() + args.observe_seconds
            while time.monotonic() < deadline:
                if monitor:
                    report["diagnostics"] = monitor.sample()
                time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
        if monitor:
            report["diagnostics"] = monitor.sample()
        if args.probe_count:
            report["probes"] = [
                {"hash": row["hash"], "suffix": row["suffix"],
                 **transfer_snapshot(base_url, str(row["hash"]))}
                for row in safe_transfers[:args.probe_count]
            ]
        final_stats = status(base_url)
        final_kad = kad_status(base_url)
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
        report["ed2k"] = {
            "connected": bool(final_stats.get("ed2kConnected")),
            "highId": bool(final_stats.get("ed2kHighId")),
        }
        report["kad"] = {
            "running": bool(final_kad.get("running")),
            "connected": bool(final_kad.get("connected")),
            "contactCount": int(final_kad.get("contactCount") or 0),
        }
        connectivity_passed = (
            report["webuiReady"]
            and report["ed2k"]["connected"]
            and (not args.enable_upnp or (report["ed2k"]["highId"] and report["upnp"]["gatewayDiscovered"] and report["upnp"]["mappingCount"] >= 2))
            and report["kad"]["running"]
            and report["kad"]["connected"]
            and report["kad"]["contactCount"] > 0
            and (not monitor or all(monitor.schemas.get(schema, 0) > 0 for schema in ("ed2k_packet_v1", "udp_packet_v1", "diag_event_v1")))
        )
        transfer_results = report.get("transfers", [])
        if not connectivity_passed:
            report["status"] = "failed"
        elif any(row.get("status") == "inconclusive" for row in transfer_results):
            report["status"] = "inconclusive"
        elif args.probe_count and not (
            any(int(row.get("completedBytes") or 0) > 0 for row in report["probes"])
            or int(report.get("diagnostics", {}).get("acceptedPayloadBytes") or 0) > 0
        ):
            report["status"] = "inconclusive"
        else:
            report["status"] = "passed"
    except Exception as exc:  # noqa: BLE001 - evidence must survive a live failure
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"
        if args.enable_upnp and process.poll() is None:
            try:
                nat = nat_status(base_url)
                report["upnp"] = {
                    "requested": True,
                    "enabled": bool(nat.get("enabled")),
                    "gatewayDiscovered": bool(nat.get("gatewayDiscovered")),
                    "mappingCount": len(nat.get("mappings") or []),
                    "backend": nat.get("backend"),
                    "lastError": nat.get("lastError"),
                }
            except Exception:  # noqa: BLE001 - preserve primary error
                pass
        if monitor and process.poll() is None:
            try:
                report["diagnostics"] = monitor.sample()
            except Exception as dump_error:  # noqa: BLE001 - preserve primary error
                report["diagnosticsError"] = f"{type(dump_error).__name__}: {dump_error}"
    finally:
        # WHY: force-killing the daemon skips NAT shutdown and can leave the
        # router's test port mappings behind. Ask Rust to exit cleanly first.
        if process.poll() is None:
            try:
                post_json(base_url, "/api/v1/app/shutdown", {"confirmShutdown": True})
                process.wait(timeout=20.0)
                report["teardown"] = "graceful"
            except Exception as exc:  # noqa: BLE001 - retain failure evidence
                try:
                    process.wait(timeout=2.0)
                    report["teardown"] = "graceful-after-response-error"
                except subprocess.TimeoutExpired:
                    report["teardown"] = f"forced: {type(exc).__name__}: {exc}"
                    stop_process_tree(process)
        else:
            report["teardown"] = f"already-exited: {process.returncode}"
        handle.close()

    report_path = run_root / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "report": str(report_path), "status": report.get("status"),
        "error": report.get("error"), "bootstrap": report.get("bootstrap"),
        "ed2k": report.get("ed2k"), "kad": report.get("kad"),
        "upnp": report.get("upnp"), "diagnostics": report.get("diagnostics"),
        "probeCount": len(report.get("probes", [])), "teardown": report.get("teardown"),
    }, sort_keys=True))
    return {"passed": 0, "failed": 1, "inconclusive": 2}.get(str(report.get("status")), 1)


if __name__ == "__main__":
    raise SystemExit(main())
