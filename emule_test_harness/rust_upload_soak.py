"""Deterministic local Rust upload soak with daemon diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import socket
import subprocess
import time
import traceback
from urllib.parse import urlsplit
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import ed2k_server as ed2k_harness, kad_nodes, live_process_monitor, rust_client, rust_ed2k, rust_metadata
from .kad_firewall_helper import DockerKadFirewallWitness, start_docker_witness
from .paths import get_required_emule_workspace_root, get_workspace_output_root
from .rust_local_ed2k import (
    ed2k_link_with_source,
    file_sha256,
    publish_shared_tree,
    request_json,
    wait_for,
    wait_for_ed2k_connected,
    wait_for_rest_ready,
)

API_KEY = "rust-local-upload-soak-key-2026-beta"
DEFAULT_DURATION_SECONDS = 300.0
DEFAULT_SAMPLE_INTERVAL_SECONDS = 5.0
DEFAULT_PAYLOAD_MIB = 64
DEFAULT_UPLOAD_LIMIT_KIBPS = 64
KAD_FIREWALL_LOG_FILTER = (
    "info,emulebb_core::kad_udp_firewall_check=debug,"
    "emulebb_core::kad_hello=debug,"
    "emulebb_ed2k::ed2k_tcp::listener::session=debug"
)


def utc_run_id(now: datetime | None = None) -> str:
    """Returns the canonical UTC run id used for local upload soaks."""

    now = datetime.now(UTC) if now is None else now.astimezone(UTC)
    return now.strftime("%Y%m%dT%H%M%SZ")


def default_artifacts_dir() -> Path:
    """Returns the default generated artifact directory for one local upload soak."""

    return get_workspace_output_root() / "soak" / "rust-local-upload" / utc_run_id()


def staged_rust_bin(name: str) -> Path:
    """Returns one staged Rust executable path under the workspace output root."""

    return get_workspace_output_root() / "tools" / "emulebb-rust" / "bin" / name


def resolve_ed2k_server_repo_override(override: Path | None) -> str | None:
    """Passes only an operator-selected ED2K server repo override."""

    return str(override) if override is not None else None


def free_lan_port(host: str, used: set[int] | None = None) -> int:
    """Allocates one free TCP port bound to the selected LAN/control address."""

    used = used if used is not None else set()
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            port = int(sock.getsockname()[1])
        if port not in used:
            used.add(port)
            return port
    raise RuntimeError("Could not allocate a free LAN TCP port.")


def free_lan_port_with_udp_offset(host: str, used: set[int]) -> int:
    """Allocates a TCP port whose stock obfuscation UDP offset is also free."""

    last_error: OSError | None = None
    for _ in range(100):
        # Windows often reserves UDP ports adjacent to ephemeral TCP ports.
        port = random.SystemRandom().randrange(20_000, 40_000)
        udp_port = port + 4
        if port in used or udp_port in used:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM
            ) as udp:
                tcp.bind((host, port))
                udp.bind((host, udp_port))
        except OSError as error:
            last_error = error
            continue
        used.add(port)
        used.add(udp_port)
        return port
    raise RuntimeError(f"Could not allocate a free LAN TCP port with UDP offset on {host}: {last_error}")


def free_lan_udp_port(host: str, used: set[int]) -> int:
    """Allocates a standalone Kad UDP port outside the Windows ephemeral range."""

    for _ in range(100):
        port = random.SystemRandom().randrange(20_000, 40_000)
        if port in used:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind((host, port))
        except OSError:
            continue
        used.add(port)
        return port
    raise RuntimeError(f"Could not allocate a free Kad UDP port on {host}.")


def wsl_metadata_path(mountpoint: str, path: Path) -> str:
    """Maps a Windows output path into a metadata-enabled WSL drive mount."""

    absolute = path.resolve()
    if not absolute.drive or not absolute.is_relative_to(get_workspace_output_root().resolve()):
        raise ValueError(f"WSL profile path must be below the workspace output root: {absolute}")
    return mountpoint + "/" + "/".join(absolute.parts[1:])


def mount_wsl_output_with_metadata(run_id: str, output_path: Path) -> str:
    """Mounts the output drive with DrvFs metadata for Linux secret permissions."""

    mountpoint = f"/mnt/emulebb-rust-output-{run_id}-{os.getpid()}"
    uid = subprocess.run(["wsl.exe", "--", "id", "-u"], capture_output=True, text=True, check=True).stdout.strip()
    gid = subprocess.run(["wsl.exe", "--", "id", "-g"], capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(["wsl.exe", "--user", "root", "--", "mkdir", mountpoint], check=True)
    try:
        subprocess.run(
            ["wsl.exe", "--user", "root", "--", "mount", "-t", "drvfs", output_path.drive,
             mountpoint, "-o", f"metadata,uid={uid},gid={gid}"],
            check=True,
        )
    except Exception:
        subprocess.run(["wsl.exe", "--user", "root", "--", "rmdir", mountpoint], check=False)
        raise
    return mountpoint


def unmount_wsl_output(mountpoint: str | None) -> None:
    """Releases the alternate DrvFs view and its empty mountpoint."""

    if mountpoint is None:
        return
    mounted = subprocess.run(["wsl.exe", "--", "mountpoint", "-q", mountpoint], check=False)
    if mounted.returncode == 0:
        subprocess.run(["wsl.exe", "--user", "root", "--", "umount", "-l", mountpoint], check=True)
    subprocess.run(["wsl.exe", "--user", "root", "--", "rmdir", mountpoint], check=True)


def build_parser() -> argparse.ArgumentParser:
    """Builds the local Rust upload soak argument parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lan-bind-addr", default=os.environ.get("X_LOCAL_IP", ""))
    parser.add_argument("--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS)
    parser.add_argument("--sample-interval-seconds", type=float, default=DEFAULT_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument("--payload-mib", type=int, default=DEFAULT_PAYLOAD_MIB)
    parser.add_argument("--upload-limit-kibps", type=int, default=DEFAULT_UPLOAD_LIMIT_KIBPS)
    parser.add_argument("--artifacts-dir", type=Path, default=None)
    parser.add_argument("--rust-exe", type=Path, default=staged_rust_bin("emulebb-rust.exe"))
    parser.add_argument("--discovery-mode", choices=("direct", "kad-wsl"), default="direct")
    parser.add_argument("--linux-rust-exe", type=Path, default=staged_rust_bin("emulebb-rust"))
    parser.add_argument("--start-paused-resume", action="store_true")
    parser.add_argument("--require-completion", action="store_true")
    parser.add_argument("--require-delivered-path", action="store_true")
    parser.add_argument("--ed2k-server-repo", type=Path)
    parser.add_argument("--ed2k-server-exe", type=Path)
    parser.add_argument("--api-key", default=API_KEY)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Rejects invalid local upload soak arguments."""

    if not str(args.lan_bind_addr).strip():
        raise ValueError("--lan-bind-addr or X_LOCAL_IP is required.")
    if len(args.api_key.encode("utf-8")) < 32:
        raise ValueError("--api-key must contain at least 32 bytes of secret material.")
    if args.duration_seconds <= 0:
        raise ValueError("--duration-seconds must be greater than zero.")
    if args.sample_interval_seconds <= 0:
        raise ValueError("--sample-interval-seconds must be greater than zero.")
    if args.payload_mib <= 0:
        raise ValueError("--payload-mib must be greater than zero.")
    if args.upload_limit_kibps <= 0:
        raise ValueError("--upload-limit-kibps must be greater than zero.")
    if not args.rust_exe.is_file():
        raise ValueError(f"Rust diagnostics executable was not found: {args.rust_exe}")
    if args.discovery_mode == "kad-wsl" and not args.linux_rust_exe.is_file():
        raise ValueError(f"Linux Rust executable was not found: {args.linux_rust_exe}")


def recheck_kad_after_bootstrap(
    seeder_base: str, leecher_base: str, api_key: str, seeder_ip: str,
    *, witness_nodes_url: str | None = None,
) -> dict[str, object]:
    """Queue a real UDP reachability check after both local Kad peers connect."""

    connected: dict[str, int] = {}
    for role, base in (("seeder", seeder_base), ("leecher", leecher_base)):
        status = wait_for(
            lambda base=base: (
                data
                if (data := request_json(base, "GET", "/api/v1/kad", api_key)).get("connected")
                else None
            ),
            timeout_seconds=60.0,
            interval_seconds=1.0,
            description=f"{role} Kad connected",
        )
        connected[role] = safe_int(status.get("contactCount"))
    if witness_nodes_url is not None:
        imported = request_json(
            seeder_base, "POST", "/api/v1/kad/operations/import-nodes-url", api_key,
            {"url": witness_nodes_url},
        )
        if imported.get("imported") is not True:
            raise RuntimeError("Kad firewall witness contact was not imported")
    nodes = request_json(seeder_base, "GET", "/api/v1/kad/nodes?limit=100", api_key)
    rows = nodes.get("items") if isinstance(nodes.get("items"), list) else []
    if witness_nodes_url is not None and not any(
        isinstance(row, dict) and row.get("ip") == urlsplit(witness_nodes_url).hostname
        for row in rows
    ):
        raise RuntimeError("Kad firewall witness was not admitted to the routing table")
    contact_evidence = [
        {
            "sameBindIp": row.get("ip") == seeder_ip,
            "kadVersion": safe_int(row.get("kadVersion")),
            "udpPortPresent": safe_int(row.get("udpPort")) > 0,
            "tcpPortPresent": safe_int(row.get("tcpPort")) > 0,
            "udpFirewalled": row.get("udpFirewalled") is True,
        }
        for row in rows
        if isinstance(row, dict)
    ]
    eligible_helpers = sum(
        not row["sameBindIp"]
        and row["kadVersion"] >= 6
        and row["udpPortPresent"]
        and row["tcpPortPresent"]
        and not row["udpFirewalled"]
        for row in contact_evidence
    )
    # WHY: the driver's warmup can fire before bootstrap, then defer its next
    # round for the normal long interval. The explicit operation preserves the
    # stock reachability gate while testing it during this bounded local run.
    recheck = request_json(
        seeder_base,
        "POST",
        "/api/v1/kad/operations/recheck-firewall",
        api_key,
        {},
    )
    return {
        "seederConnectedContacts": connected["seeder"],
        "leecherConnectedContacts": connected["leecher"],
        "seederFirewallContacts": contact_evidence,
        "seederEligibleFirewallHelpers": eligible_helpers,
        "witnessImported": witness_nodes_url is not None,
        "recheckQueued": recheck.get("operationQueued") is True,
    }


def write_payload(path: Path, size_bytes: int) -> dict[str, object]:
    """Writes deterministic incompressible soak bytes and returns metadata."""

    remaining = size_bytes
    digest = hashlib.sha256()
    rng = random.Random(0xE2D2_036)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        while remaining > 0:
            chunk_len = min(8 * 1024 * 1024, remaining)
            chunk = rng.randbytes(chunk_len)
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return {
        "path": str(path),
        "sizeBytes": size_bytes,
        "sha256": digest.hexdigest(),
        "contentKind": "deterministic-randbytes",
    }


def open_process_metrics(process: subprocess.Popen, label: str, report_dir: Path, interval_seconds: float) -> dict[str, object]:
    """Creates one mutable process metrics sampler state."""

    return {
        "process": process,
        "label": label,
        "handle": live_process_monitor.open_process(process.pid),
        "started": time.monotonic(),
        "lastSampleMonotonic": None,
        "lastCpuSeconds": None,
        "nextSample": 0.0,
        "rows": [],
        "csvPath": report_dir / f"{label}-process-metrics.csv",
    }


def sample_process_metrics(state: dict[str, object] | None, interval_seconds: float) -> dict[str, object] | None:
    """Samples one process metrics state when its interval has elapsed."""

    if state is None:
        return None
    now = time.monotonic()
    if now < float(state["nextSample"]):
        return None
    row = live_process_monitor.sample_process_metrics(
        handle=int(state["handle"]),
        started_monotonic=float(state["started"]),
        last_sample_monotonic=state["lastSampleMonotonic"],
        last_cpu_seconds=state["lastCpuSeconds"],
    )
    row["pid"] = state["process"].pid  # type: ignore[union-attr]
    rows = state["rows"]
    assert isinstance(rows, list)
    rows.append(row)
    state["lastSampleMonotonic"] = time.monotonic()
    state["lastCpuSeconds"] = float(row["cpu_seconds"])
    state["nextSample"] = now + interval_seconds
    live_process_monitor.write_metric_csv(Path(state["csvPath"]), rows)
    return row


def close_process_metrics(state: dict[str, object] | None) -> dict[str, object] | None:
    """Closes one process metrics state and returns a summary payload."""

    if state is None:
        return None
    rows = state["rows"]
    assert isinstance(rows, list)
    try:
        live_process_monitor.close_handle(int(state["handle"]))
    finally:
        summary = live_process_monitor.summarize_metric_rows(rows)
    return {
        "label": state["label"],
        "pid": state["process"].pid,  # type: ignore[union-attr]
        "csvPath": str(state["csvPath"]),
        "summary": summary,
    }


def start_rust(
    *,
    exe: Path,
    profile_dir: Path,
    log_path: Path,
    diag_dir: Path,
    rust_log: str | None = None,
) -> tuple[subprocess.Popen, object]:
    """Starts one staged Rust diagnostics daemon with packet dumps enabled."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    diag_dir.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("w", encoding="utf-8")
    env = os.environ.copy()
    env["EMULEBB_RUST_LOG_DIR"] = str(diag_dir)
    if rust_log is not None:
        env["RUST_LOG"] = rust_log
    process = rust_client.spawn_rust_daemon(exe, profile_dir, output_handle=handle, env=env)
    return process, handle


def patch_upload_limit(base_url: str, api_key: str, upload_limit_kibps: int) -> dict[str, object]:
    """Applies the Rust core upload cap for a deterministic slow upload soak."""

    return request_json(
        base_url,
        "PATCH",
        "/api/v1/app/settings",
        api_key,
        {"core": {"uploadLimitKiBps": upload_limit_kibps}},
    )


def safe_int(value: object) -> int:
    """Returns an integer counter from REST payload values that may be missing."""

    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def safe_float(value: object) -> float:
    """Returns a float counter from REST payload values that may be missing."""

    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def wait_for_transfer_state(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    *,
    states: set[str],
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until one transfer is visible in any expected state."""

    def probe() -> dict[str, object] | None:
        transfer = request_json(base_url, "GET", f"/api/v1/transfers/{transfer_hash}", api_key)
        return transfer if str(transfer.get("state") or "") in states else None

    return wait_for(
        probe,
        timeout_seconds=timeout_seconds,
        interval_seconds=0.5,
        description=f"transfer {transfer_hash} state in {sorted(states)}",
    )


def find_hash_item(base_url: str, api_key: str, path: str, file_hash: str) -> dict[str, object] | None:
    """Finds one file in this isolated fixture's transfer or share list."""

    response = request_json(base_url, "GET", path, api_key)
    items = response.get("items")
    if not isinstance(items, list):
        raise RuntimeError(f"Rust REST {path} did not return an items list.")
    return next((item for item in items if isinstance(item, dict) and item.get("hash") == file_hash), None)


def verify_download_delivery(
    final_transfer: dict[str, object] | None,
    final_share: dict[str, object] | None,
    payload: dict[str, object],
    *,
    require_completion: bool,
    require_delivered_path: bool,
) -> dict[str, object]:
    """Builds and enforces the strict download/delivery checks requested by beta proof."""

    expected_size = safe_int(payload.get("sizeBytes"))
    expected_sha256 = str(payload.get("sha256") or "")
    completed = final_transfer is None and final_share is not None and safe_int(final_share.get("sizeBytes")) == expected_size
    completed_bytes = expected_size if completed else safe_int((final_transfer or {}).get("completedBytes"))
    delivered_path_value = (final_share or {}).get("path")
    delivered_path = Path(str(delivered_path_value)) if delivered_path_value else None
    result: dict[str, object] = {
        "requireCompletion": require_completion,
        "requireDeliveredPath": require_delivered_path,
        "state": "shared" if completed else (final_transfer or {}).get("state"),
        "completedBytes": completed_bytes,
        "expectedSizeBytes": expected_size,
        "deliveredPathPresent": delivered_path is not None,
        "deliveredFileExists": delivered_path.is_file() if delivered_path is not None else False,
        "ok": True,
    }
    if require_completion:
        result["completed"] = completed
        if not completed:
            result["ok"] = False
            raise RuntimeError(
                f"Rust local download did not enter the verified library: state={(final_transfer or {}).get('state')!r} "
                f"completedBytes={completed_bytes} expected={expected_size}"
            )
    if require_delivered_path:
        if not completed:
            result["ok"] = False
            raise RuntimeError("Rust local download still has a transfer row or no verified library share.")
        if delivered_path is None:
            result["ok"] = False
            raise RuntimeError("Rust local download completed without deliveredPath.")
        if not delivered_path.is_file():
            result["ok"] = False
            raise RuntimeError(f"Rust local download deliveredPath does not exist: {delivered_path}")
        result["deliveredFileSizeBytes"] = delivered_path.stat().st_size
        result["deliveredSha256"] = file_sha256(delivered_path)
        if delivered_path.stat().st_size != expected_size or result["deliveredSha256"] != expected_sha256:
            result["ok"] = False
            raise RuntimeError("Rust local download delivered file did not match the source payload.")
    return result


def run(argv: list[str] | None = None) -> int:
    """Runs one deterministic local Rust upload soak."""

    args = build_parser().parse_args(argv)
    validate_args(args)
    workspace_root = get_required_emule_workspace_root()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    artifacts_dir = (args.artifacts_dir or default_artifacts_dir()).resolve()
    if not artifacts_dir.is_relative_to(get_workspace_output_root().resolve()):
        raise ValueError(f"Rust upload soak artifacts must be below the workspace output root: {artifacts_dir}")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifacts_dir / "rust-local-upload-soak-result.json"
    samples_path = artifacts_dir / "samples.jsonl"
    used_ports: set[int] = set()
    lan = str(args.lan_bind_addr).strip()
    server_port = free_lan_port_with_udp_offset(lan, used_ports)
    server_admin_port = free_lan_port(lan, used_ports)
    seeder_rest_port = free_lan_port("127.0.0.1", used_ports)
    seeder_ed2k_port = free_lan_port_with_udp_offset(lan, used_ports)
    seeder_kad_port = free_lan_udp_port(lan, used_ports)
    leecher_rest_port = free_lan_port("127.0.0.1", used_ports)
    leecher_ed2k_port = free_lan_port_with_udp_offset(lan, used_ports)
    leecher_kad_port = free_lan_udp_port(lan, used_ports)
    report: dict[str, Any] = {
        "schema": "emulebb-rust.local-upload-soak.v1",
        "status": "running",
        "artifactsDir": str(artifacts_dir),
        "durationSeconds": args.duration_seconds,
        "payloadMiB": args.payload_mib,
        "uploadLimitKiBps": args.upload_limit_kibps,
        "startPausedResume": args.start_paused_resume,
        "requireCompletion": args.require_completion,
        "requireDeliveredPath": args.require_delivered_path,
        "rustExe": str(args.rust_exe),
        "buildProvenance": {
            "windowsBinarySha256": file_sha256(args.rust_exe),
            "linuxBinarySha256": file_sha256(args.linux_rust_exe) if args.discovery_mode == "kad-wsl" else None,
            "rustRevision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=rust_repo, text=True,
            ).strip(),
            "harnessRevision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True,
            ).strip(),
        },
        "discoveryMode": args.discovery_mode,
        "network": {
            "lanBindAddr": lan,
            "serverPort": server_port,
            "serverAdminPort": server_admin_port,
            "seederRestPort": seeder_rest_port,
            "seederEd2kPort": seeder_ed2k_port,
            "seederKadPort": seeder_kad_port,
            "leecherRestPort": leecher_rest_port,
            "leecherEd2kPort": leecher_ed2k_port,
            "leecherKadPort": leecher_kad_port,
        },
        "samplesPath": str(samples_path),
        "checks": {},
    }
    server_process = None
    seeder_process = None
    leecher_process = None
    seeder_log = None
    leecher_log = None
    seeder_metrics = None
    leecher_metrics = None
    seeder_base = ""
    leecher_base = ""
    file_hash = ""
    wsl_mountpoint: str | None = None
    kad_helper: DockerKadFirewallWitness | None = None
    try:
        payload = write_payload(
            artifacts_dir / "shared" / "Rust.Local.Upload.Soak.Payload.zip",
            args.payload_mib * 1024 * 1024,
        )
        report["payload"] = payload
        ed2k_server = ed2k_harness.launch_ed2k_server(
            workspace_root=workspace_root,
            server_dir=artifacts_dir / "ed2k-server",
            ed2k_port=server_port,
            admin_port=server_admin_port,
            token=args.api_key,
            admin_address=lan,
            ed2k_address=lan,
            repo_override=resolve_ed2k_server_repo_override(args.ed2k_server_repo),
            exe_override=str(args.ed2k_server_exe) if args.ed2k_server_exe else None,
        )
        server_process = ed2k_server.process
        report["ed2kServer"] = ed2k_server.config
        kad_wsl = args.discovery_mode == "kad-wsl"
        seeder_addr = ed2k_server.ed2k_host if kad_wsl else lan
        report["network"]["seederAddress"] = seeder_addr
        seeder_profile = artifacts_dir / "seeder-profile"
        leecher_profile = artifacts_dir / "leecher-profile"
        rust_client.write_rust_profile(
            seeder_profile,
            rust_repo=rust_repo,
            incoming_dir=seeder_profile / "incoming",
            rest_addr="127.0.0.1",
            rest_port=seeder_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=seeder_addr,
            ed2k_port=seeder_ed2k_port,
            kad_port=seeder_kad_port,
            server_endpoint=f"{ed2k_server.ed2k_host}:{server_port}",
            local_only_discovery=True,
            network_kademlia=True if kad_wsl else None,
            local_kad_seed=kad_nodes.BootstrapContact(lan, leecher_kad_port, leecher_ed2k_port) if kad_wsl else None,
            kad_bootstrap_min_routing_contacts=1 if kad_wsl else 10,
            obfuscation_enabled=not kad_wsl,
        )
        if kad_wsl:
            # WHY: plain DrvFs reports 0777 for the API key file, which Linux
            # correctly rejects. An alternate metadata mount keeps all profile
            # bytes in the configured output root while honoring mode 0600.
            wsl_mountpoint = mount_wsl_output_with_metadata(artifacts_dir.name, artifacts_dir)
            seeder_settings = wsl_metadata_path(wsl_mountpoint, seeder_profile / rust_client.RUST_PROFILE_SETTINGS_FILE)
            subprocess.run(["wsl.exe", "--", "chmod", "600", seeder_settings], check=True)
            rust_metadata.replace_settings_section(
                seeder_profile / rust_metadata.RUST_PROFILE_METADATA_FILE,
                "daemon",
                {"incomingDir": wsl_metadata_path(wsl_mountpoint, seeder_profile / "incoming"), "p2pBindIp": seeder_addr},
            )
        rust_client.write_rust_profile(
            leecher_profile,
            rust_repo=rust_repo,
            incoming_dir=leecher_profile / "incoming",
            rest_addr="127.0.0.1",
            rest_port=leecher_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=lan,
            ed2k_port=leecher_ed2k_port,
            kad_port=leecher_kad_port,
            server_endpoint=f"{ed2k_server.ed2k_host}:{server_port}",
            local_only_discovery=True,
            network_kademlia=True if kad_wsl else None,
            local_kad_seed=kad_nodes.BootstrapContact(seeder_addr, seeder_kad_port, seeder_ed2k_port) if kad_wsl else None,
            kad_bootstrap_min_routing_contacts=1 if kad_wsl else 10,
            obfuscation_enabled=not kad_wsl,
        )
        seeder_diag = artifacts_dir / "diagnostics" / "seeder"
        leecher_diag = artifacts_dir / "diagnostics" / "leecher"
        if kad_wsl:
            seeder_process = rust_ed2k.start_wsl_managed_executable(
                args.linux_rust_exe,
                ["--profile", wsl_metadata_path(wsl_mountpoint, seeder_profile)],
                artifacts_dir / "logs" / "seeder.out",
                artifacts_dir / "logs" / "seeder.pid",
                rust_log=KAD_FIREWALL_LOG_FILTER,
            )
        else:
            seeder_process, seeder_log = start_rust(
                exe=args.rust_exe,
                profile_dir=seeder_profile,
                log_path=artifacts_dir / "logs" / "seeder.out",
                diag_dir=seeder_diag,
            )
        leecher_process, leecher_log = start_rust(
            exe=args.rust_exe,
            profile_dir=leecher_profile,
            log_path=artifacts_dir / "logs" / "leecher.out",
            diag_dir=leecher_diag,
            rust_log=KAD_FIREWALL_LOG_FILTER if kad_wsl else None,
        )
        seeder_base = f"http://127.0.0.1:{seeder_rest_port}"
        leecher_base = f"http://127.0.0.1:{leecher_rest_port}"
        wait_for_rest_ready(seeder_base, seeder_process, artifacts_dir / "logs" / "seeder.out", args.api_key, 60.0)
        wait_for_rest_ready(leecher_base, leecher_process, artifacts_dir / "logs" / "leecher.out", args.api_key, 60.0)
        patch_upload_limit(seeder_base, args.api_key, args.upload_limit_kibps)
        if kad_wsl:
            for base in (seeder_base, leecher_base):
                request_json(base, "POST", "/api/v1/kad/operations/start", args.api_key, {})
            # Each clean profile already owns its local bootstrap contact.
            # Starting the network below performs the normal configured join.
        request_json(seeder_base, "POST", "/api/v1/servers/operations/connect", args.api_key)
        request_json(leecher_base, "POST", "/api/v1/servers/operations/connect", args.api_key)
        wait_for_ed2k_connected(seeder_base, args.api_key, 45.0)
        wait_for_ed2k_connected(leecher_base, args.api_key, 45.0)
        if kad_wsl:
            kad_helper = start_docker_witness(
                artifacts_dir / "kad-witness", {seeder_addr},
                distribution=os.environ.get(rust_ed2k.RUST_ED2K_WSL_DISTRIBUTION_ENV, "").strip() or None,
            )
            report["checks"]["kadReachabilityRecheck"] = recheck_kad_after_bootstrap(
                seeder_base, leecher_base, args.api_key, seeder_addr,
                witness_nodes_url=kad_helper.nodes_url,
            )
        share = publish_shared_tree(
            seeder_base,
            args.api_key,
            root=wsl_metadata_path(wsl_mountpoint, Path(payload["path"]).parent) if kad_wsl else Path(payload["path"]).parent,
            file_name=Path(payload["path"]).name,
            timeout_seconds=60.0,
        )
        report["checks"]["seederSharedTreePublish"] = share
        shared_files = share.get("sharedFiles") if isinstance(share.get("sharedFiles"), dict) else {}
        file_row = shared_files.get("matched") if isinstance(shared_files.get("matched"), dict) else share
        file_hash = str(file_row["hash"]).lower()
        server_control = ed2k_harness.ed2k_server_control(ed2k_server.admin_base_url, args.api_key)
        report["checks"]["serverOffer"] = wait_for(
            lambda: next(
                (client for client in server_control.list_clients() if int(client.get("shared_files") or 0) >= 1),
                None,
            ),
            timeout_seconds=30.0,
            interval_seconds=1.0,
            description="local Rust seeder offer indexed by server",
        )
        if kad_wsl:
            def published_kad_source() -> dict[str, object] | None:
                diagnostics = request_json(seeder_base, "GET", "/api/v1/diagnostics", args.api_key)
                publish = diagnostics.get("kadPublish") or {}
                return publish if safe_int(publish.get("sourcePublishedTotal")) > 0 else None

            report["checks"]["kadSourcePublication"] = wait_for(
                published_kad_source, timeout_seconds=90, interval_seconds=1,
                description="stock-gated Kad source publication acknowledged",
            )
            # A clean leecher has no source hints. Retire its server session so
            # the plain link can discover the first peer only through Kad.
            request_json(leecher_base, "POST", "/api/v1/servers/operations/disconnect", args.api_key)
            isolated = request_json(leecher_base, "GET", "/api/v1/status", args.api_key)
            if isolated.get("stats", {}).get("ed2kConnected") is not False:
                raise RuntimeError("Kad-only leecher still has a server session")
            report["checks"]["kadDiscoveryIsolation"] = {"serverDisconnectedBeforeTransfer": True}
        transfer = request_json(
            leecher_base,
            "POST",
            "/api/v1/transfers",
            args.api_key,
            {
                "link": str(file_row["ed2kLink"]) if kad_wsl else ed2k_link_with_source(
                    str(file_row["ed2kLink"]), lan, seeder_ed2k_port
                ),
                "paused": bool(args.start_paused_resume),
            },
        )
        report["transferCreate"] = transfer
        if args.start_paused_resume:
            paused_transfer = wait_for_transfer_state(
                leecher_base,
                args.api_key,
                file_hash,
                states={"paused"},
                timeout_seconds=20.0,
            )
            resume = request_json(
                leecher_base,
                "POST",
                f"/api/v1/transfers/{file_hash}/operations/resume",
                args.api_key,
                {},
            )
            resumed_transfer = wait_for_transfer_state(
                leecher_base,
                args.api_key,
                file_hash,
                states={"downloading", "queued", "completed"},
                timeout_seconds=20.0,
            )
            report["checks"]["pausedStartResume"] = {
                "pausedState": paused_transfer.get("state"),
                "resume": resume,
                "resumedState": resumed_transfer.get("state"),
                "ok": True,
            }
        if not kad_wsl:
            seeder_metrics = open_process_metrics(seeder_process, "seeder", artifacts_dir / "analysis", args.sample_interval_seconds)
        leecher_metrics = open_process_metrics(leecher_process, "leecher", artifacts_dir / "analysis", args.sample_interval_seconds)
        deadline = time.monotonic() + args.duration_seconds
        sample_count = 0
        max_active_uploads = 0
        max_upload_speed_kibps = 0.0
        max_completed_bytes = 0
        upload_rows_observed = 0
        with samples_path.open("w", encoding="utf-8") as samples:
            while time.monotonic() < deadline:
                if seeder_process.poll() is not None:
                    raise RuntimeError(f"seeder exited early with code {seeder_process.returncode}")
                if leecher_process.poll() is not None:
                    raise RuntimeError(f"leecher exited early with code {leecher_process.returncode}")
                seeder_status = request_json(seeder_base, "GET", "/api/v1/status", args.api_key)
                leecher_transfer = find_hash_item(leecher_base, args.api_key, "/api/v1/transfers", file_hash)
                leecher_share = find_hash_item(leecher_base, args.api_key, "/api/v1/shared-files", file_hash)
                seeder_uploads = request_json(seeder_base, "GET", "/api/v1/uploads", args.api_key)
                seeder_stats = seeder_status.get("stats", {}) if isinstance(seeder_status.get("stats"), dict) else {}
                upload_items = seeder_uploads.get("items") if isinstance(seeder_uploads.get("items"), list) else []
                max_active_uploads = max(max_active_uploads, safe_int(seeder_stats.get("activeUploads")))
                max_upload_speed_kibps = max(max_upload_speed_kibps, safe_float(seeder_stats.get("uploadSpeedKiBps")))
                max_completed_bytes = max(
                    max_completed_bytes,
                    safe_int((leecher_transfer or {}).get("completedBytes")),
                    safe_int((leecher_share or {}).get("sizeBytes")) if leecher_transfer is None else 0,
                )
                upload_rows_observed += len(upload_items)
                row = {
                    "elapsedSeconds": round(args.duration_seconds - max(0.0, deadline - time.monotonic()), 3),
                    "seederStats": seeder_stats,
                    "leecherTransfer": {
                        "state": (leecher_transfer or {}).get("state"),
                        "completedBytes": (leecher_transfer or {}).get("completedBytes"),
                        "sizeBytes": (leecher_transfer or {}).get("sizeBytes"),
                        "progress": (leecher_transfer or {}).get("progress"),
                    },
                    "leecherSharedFile": leecher_share,
                    "seederUploads": seeder_uploads,
                    "seederKad": request_json(seeder_base, "GET", "/api/v1/kad", args.api_key) if kad_wsl else None,
                    "seederKadPublish": request_json(
                        seeder_base, "GET", "/api/v1/diagnostics", args.api_key
                    ).get("kadPublish") if kad_wsl else None,
                    "processMetrics": {
                        "seeder": sample_process_metrics(seeder_metrics, args.sample_interval_seconds),
                        "leecher": sample_process_metrics(leecher_metrics, args.sample_interval_seconds),
                    },
                }
                samples.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
                samples.flush()
                sample_count += 1
                if leecher_share is not None and leecher_transfer is None:
                    report["completedBeforeDuration"] = True
                    break
                time.sleep(args.sample_interval_seconds)
        report["uploadEvidence"] = {
            "maxActiveUploads": max_active_uploads,
            "maxUploadSpeedKiBps": round(max_upload_speed_kibps, 3),
            "maxLeecherCompletedBytes": max_completed_bytes,
            "uploadRowsObserved": upload_rows_observed,
        }
        if max_completed_bytes <= 0 and max_active_uploads <= 0 and max_upload_speed_kibps <= 0:
            raise RuntimeError("Rust local upload soak did not observe upload progress.")
        report["sampleCount"] = sample_count
        report["finalSeederStatus"] = request_json(seeder_base, "GET", "/api/v1/status", args.api_key)
        report["finalLeecherTransfer"] = find_hash_item(leecher_base, args.api_key, "/api/v1/transfers", file_hash)
        report["finalLeecherSharedFile"] = find_hash_item(leecher_base, args.api_key, "/api/v1/shared-files", file_hash)
        report["checks"]["downloadDelivery"] = verify_download_delivery(
            report["finalLeecherTransfer"],
            report["finalLeecherSharedFile"],
            payload,
            require_completion=bool(args.require_completion),
            require_delivered_path=bool(args.require_delivered_path),
        )
        if kad_helper is not None and safe_int(kad_helper.evidence().get("unbiasedRequests")) == 0:
            raise RuntimeError("Kad run has no unbiased UDP firewall witness")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        report["traceback"] = traceback.format_exc()
        if seeder_base and seeder_process is not None and seeder_process.poll() is None:
            try:
                report["failureSeederDiagnostics"] = request_json(seeder_base, "GET", "/api/v1/diagnostics", args.api_key)
            except Exception as diagnostics_error:
                report["failureSeederDiagnosticsError"] = str(diagnostics_error)
        if server_process is not None and server_process.poll() is None and file_hash:
            try:
                control = ed2k_harness.ed2k_server_control(ed2k_server.admin_base_url, args.api_key)
                report["failureServerClients"] = control.list_clients()
            except Exception as server_error:
                report["failureServerEvidenceError"] = str(server_error)
        return 1
    finally:
        if kad_helper is not None:
            try:
                kad_helper.close()
            except Exception as helper_error:
                report["helperCleanupError"] = str(helper_error)
            report["checks"]["kadFirewallWitness"] = kad_helper.evidence()
        report["processMetrics"] = {
            "seeder": close_process_metrics(seeder_metrics),
            "leecher": close_process_metrics(leecher_metrics),
        }
        rust_client.stop_process_tree(leecher_process)
        if isinstance(seeder_process, rust_ed2k.RustWslProcess):
            rust_ed2k.stop_process(seeder_process)
        else:
            rust_client.stop_process_tree(seeder_process)
        for handle in (leecher_log, seeder_log):
            if handle is not None:
                handle.close()
        if server_process is not None:
            ed2k_harness.stop_process(server_process)
            ed2k_harness.stop_server_processes()
        try:
            unmount_wsl_output(wsl_mountpoint)
        except Exception as unmount_error:
            report["cleanupError"] = str(unmount_error)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
