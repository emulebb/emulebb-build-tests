"""Deterministic local Rust upload soak with diagnostics and native UI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import goed2k, live_process_monitor, rust_client
from .paths import get_required_emule_workspace_root, get_workspace_output_root
from .rust_local_ed2k import request_json, wait_for_ed2k_connected, wait_for_rest_ready

API_KEY = "rust-local-upload-soak-key"
DEFAULT_DURATION_SECONDS = 300.0
DEFAULT_SAMPLE_INTERVAL_SECONDS = 5.0
DEFAULT_PAYLOAD_MIB = 64
DEFAULT_UPLOAD_LIMIT_KIBPS = 64


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


def resolve_goed2k_repo_override(workspace_root: Path, override: Path | None) -> str | None:
    """Returns the goed2k repo override for the canonical workspace layout."""

    if override is not None:
        return str(override)
    repo = workspace_root / "repos" / "goed2k-server"
    return str(repo) if (repo / "go.mod").is_file() else None


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

    for _ in range(100):
        port = free_lan_port(host, used)
        udp_port = port + 4
        if udp_port > 65535 or udp_port in used:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((host, udp_port))
        except OSError:
            continue
        used.add(udp_port)
        return port
    raise RuntimeError("Could not allocate a free LAN TCP port with UDP offset.")


def build_parser() -> argparse.ArgumentParser:
    """Builds the local Rust upload soak argument parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lan-bind-addr", default=os.environ.get("X_LOCAL_IP", ""))
    parser.add_argument("--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS)
    parser.add_argument("--sample-interval-seconds", type=float, default=DEFAULT_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument("--payload-mib", type=int, default=DEFAULT_PAYLOAD_MIB)
    parser.add_argument("--upload-limit-kibps", type=int, default=DEFAULT_UPLOAD_LIMIT_KIBPS)
    parser.add_argument("--artifacts-dir", type=Path, default=None)
    parser.add_argument("--rust-exe", type=Path, default=staged_rust_bin("emulebb-rust-diagnostics.exe"))
    parser.add_argument("--rust-ui-exe", type=Path, default=staged_rust_bin("emulebb-rust-ui.exe"))
    parser.add_argument("--ed2k-server-repo", type=Path)
    parser.add_argument("--ed2k-server-exe", type=Path)
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--ui-poll-interval-ms", type=int, default=1000)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Rejects invalid local upload soak arguments."""

    if not str(args.lan_bind_addr).strip():
        raise ValueError("--lan-bind-addr or X_LOCAL_IP is required.")
    if args.duration_seconds <= 0:
        raise ValueError("--duration-seconds must be greater than zero.")
    if args.sample_interval_seconds <= 0:
        raise ValueError("--sample-interval-seconds must be greater than zero.")
    if args.payload_mib <= 0:
        raise ValueError("--payload-mib must be greater than zero.")
    if args.upload_limit_kibps <= 0:
        raise ValueError("--upload-limit-kibps must be greater than zero.")
    if args.ui_poll_interval_ms < 1000:
        raise ValueError("--ui-poll-interval-ms must be at least 1000.")
    if not args.rust_exe.is_file():
        raise ValueError(f"Rust diagnostics executable was not found: {args.rust_exe}")
    if not args.rust_ui_exe.is_file():
        raise ValueError(f"Rust UI executable was not found: {args.rust_ui_exe}")


def write_payload(path: Path, size_bytes: int) -> dict[str, object]:
    """Writes deterministic incompressible soak bytes and returns metadata."""

    remaining = size_bytes
    digest = hashlib.sha256()
    state = 0x9E3779B97F4A7C15
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        while remaining > 0:
            chunk = bytearray()
            chunk_len = min(1024 * 1024, remaining)
            while len(chunk) < chunk_len:
                state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
                state ^= state >> 7
                state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
                chunk.extend(state.to_bytes(8, "little"))
            chunk = chunk[:chunk_len]
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return {
        "path": str(path),
        "sizeBytes": size_bytes,
        "sha256": digest.hexdigest(),
        "contentKind": "deterministic-xorshift64",
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


def sample_process_metrics(state: dict[str, object], interval_seconds: float) -> dict[str, object] | None:
    """Samples one process metrics state when its interval has elapsed."""

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
) -> tuple[subprocess.Popen, object]:
    """Starts one staged Rust diagnostics daemon with packet dumps enabled."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    diag_dir.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("w", encoding="utf-8")
    env = os.environ.copy()
    env["EMULEBB_RUST_LOG_DIR"] = str(diag_dir)
    process = rust_client.spawn_rust_daemon(exe, profile_dir, output_handle=handle, env=env)
    return process, handle


def launch_rust_ui(*, ui_exe: Path, base_url: str, api_key: str, poll_interval_ms: int, output_path: Path) -> tuple[subprocess.Popen, object]:
    """Launches the native Rust UI against one local soak daemon."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle = output_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            str(ui_exe),
            "--base-url",
            base_url.rstrip("/") + "/api/v1",
            "--api-key",
            api_key,
            "--poll-interval-ms",
            str(poll_interval_ms),
        ],
        cwd=ui_exe.parent,
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
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


def run(argv: list[str] | None = None) -> int:
    """Runs one deterministic local Rust upload soak."""

    args = build_parser().parse_args(argv)
    validate_args(args)
    workspace_root = get_required_emule_workspace_root()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    artifacts_dir = (args.artifacts_dir or default_artifacts_dir()).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifacts_dir / "rust-local-upload-soak-result.json"
    samples_path = artifacts_dir / "samples.jsonl"
    used_ports: set[int] = set()
    lan = str(args.lan_bind_addr).strip()
    server_port = free_lan_port_with_udp_offset(lan, used_ports)
    server_admin_port = free_lan_port(lan, used_ports)
    seeder_rest_port = free_lan_port(lan, used_ports)
    seeder_ed2k_port = free_lan_port(lan, used_ports)
    seeder_kad_port = free_lan_port(lan, used_ports)
    leecher_rest_port = free_lan_port(lan, used_ports)
    leecher_ed2k_port = free_lan_port(lan, used_ports)
    leecher_kad_port = free_lan_port(lan, used_ports)
    report: dict[str, Any] = {
        "schema": "emulebb-rust.local-upload-soak.v1",
        "status": "running",
        "artifactsDir": str(artifacts_dir),
        "durationSeconds": args.duration_seconds,
        "payloadMiB": args.payload_mib,
        "uploadLimitKiBps": args.upload_limit_kibps,
        "rustExe": str(args.rust_exe),
        "rustUiExe": str(args.rust_ui_exe),
        "network": {
            "lanBindAddr": lan,
            "serverPort": server_port,
            "serverAdminPort": server_admin_port,
            "seederRestPort": seeder_rest_port,
            "seederEd2kPort": seeder_ed2k_port,
            "leecherRestPort": leecher_rest_port,
            "leecherEd2kPort": leecher_ed2k_port,
        },
        "samplesPath": str(samples_path),
    }
    server_process = None
    seeder_process = None
    leecher_process = None
    ui_process = None
    seeder_log = None
    leecher_log = None
    ui_log = None
    seeder_metrics = None
    leecher_metrics = None
    ui_metrics = None
    try:
        payload = write_payload(
            artifacts_dir / "shared" / "Rust.Local.Upload.Soak.Payload.zip",
            args.payload_mib * 1024 * 1024,
        )
        report["payload"] = payload
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=workspace_root,
            server_dir=artifacts_dir / "goed2k-server",
            ed2k_port=server_port,
            admin_port=server_admin_port,
            token=args.api_key,
            admin_address=lan,
            ed2k_address=lan,
            repo_override=resolve_goed2k_repo_override(workspace_root, args.ed2k_server_repo),
            exe_override=str(args.ed2k_server_exe) if args.ed2k_server_exe else None,
            packet_trace=True,
        )
        server_process = ed2k_server.process
        report["ed2kServer"] = ed2k_server.config
        report["ed2kServerTracePath"] = str(ed2k_server.server_dir / "packets.trace.jsonl")
        seeder_profile = artifacts_dir / "seeder-profile"
        leecher_profile = artifacts_dir / "leecher-profile"
        rust_client.write_rust_profile(
            seeder_profile,
            rust_repo=rust_repo,
            incoming_dir=seeder_profile / "incoming",
            rest_addr=lan,
            rest_port=seeder_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=lan,
            ed2k_port=seeder_ed2k_port,
            kad_port=seeder_kad_port,
            server_endpoint=f"{lan}:{server_port}",
            kad_bootstrap_nodes=[f"{lan}:{leecher_kad_port}"],
            kad_bootstrap_min_routing_contacts=1,
        )
        rust_client.write_rust_profile(
            leecher_profile,
            rust_repo=rust_repo,
            incoming_dir=leecher_profile / "incoming",
            rest_addr=lan,
            rest_port=leecher_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=lan,
            ed2k_port=leecher_ed2k_port,
            kad_port=leecher_kad_port,
            server_endpoint=f"{lan}:{server_port}",
            kad_bootstrap_nodes=[f"{lan}:{seeder_kad_port}"],
            kad_bootstrap_min_routing_contacts=1,
        )
        seeder_diag = artifacts_dir / "diagnostics" / "seeder"
        leecher_diag = artifacts_dir / "diagnostics" / "leecher"
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
        )
        seeder_base = f"http://{lan}:{seeder_rest_port}"
        leecher_base = f"http://{lan}:{leecher_rest_port}"
        wait_for_rest_ready(seeder_base, seeder_process, artifacts_dir / "logs" / "seeder.out", args.api_key, 60.0)
        wait_for_rest_ready(leecher_base, leecher_process, artifacts_dir / "logs" / "leecher.out", args.api_key, 60.0)
        patch_upload_limit(seeder_base, args.api_key, args.upload_limit_kibps)
        request_json(seeder_base, "POST", "/api/v1/servers/operations/connect", args.api_key)
        request_json(leecher_base, "POST", "/api/v1/servers/operations/connect", args.api_key)
        wait_for_ed2k_connected(seeder_base, args.api_key, 45.0)
        wait_for_ed2k_connected(leecher_base, args.api_key, 45.0)
        share = request_json(
            seeder_base,
            "POST",
            "/api/v1/shared-files",
            args.api_key,
            {"path": str(Path(payload["path"]))},
        )
        file_row = share["file"] if isinstance(share.get("file"), dict) else share
        file_hash = str(file_row["hash"]).lower()
        goed2k.wait_for_server_file_endpoint(
            ed2k_server.admin_base_url,
            args.api_key,
            file_hash,
            lan,
            seeder_ed2k_port,
            60.0,
            "local Rust upload soak file published",
        )
        transfer = request_json(
            leecher_base,
            "POST",
            "/api/v1/transfers",
            args.api_key,
            {"link": str(file_row["ed2kLink"]), "paused": False},
        )
        report["transferCreate"] = transfer
        ui_process, ui_log = launch_rust_ui(
            ui_exe=args.rust_ui_exe,
            base_url=seeder_base,
            api_key=args.api_key,
            poll_interval_ms=args.ui_poll_interval_ms,
            output_path=artifacts_dir / "logs" / "rust-ui.out",
        )
        seeder_metrics = open_process_metrics(seeder_process, "seeder", artifacts_dir / "analysis", args.sample_interval_seconds)
        leecher_metrics = open_process_metrics(leecher_process, "leecher", artifacts_dir / "analysis", args.sample_interval_seconds)
        ui_metrics = open_process_metrics(ui_process, "rust-ui", artifacts_dir / "analysis", args.sample_interval_seconds)
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
                if ui_process.poll() is not None:
                    raise RuntimeError(f"rust UI exited early with code {ui_process.returncode}")
                seeder_status = request_json(seeder_base, "GET", "/api/v1/status", args.api_key)
                leecher_transfer = request_json(leecher_base, "GET", f"/api/v1/transfers/{file_hash}", args.api_key)
                seeder_uploads = request_json(seeder_base, "GET", "/api/v1/uploads", args.api_key)
                seeder_stats = seeder_status.get("stats", {}) if isinstance(seeder_status.get("stats"), dict) else {}
                upload_items = seeder_uploads.get("items") if isinstance(seeder_uploads.get("items"), list) else []
                max_active_uploads = max(max_active_uploads, safe_int(seeder_stats.get("activeUploads")))
                max_upload_speed_kibps = max(max_upload_speed_kibps, safe_float(seeder_stats.get("uploadSpeedKiBps")))
                max_completed_bytes = max(max_completed_bytes, safe_int(leecher_transfer.get("completedBytes")))
                upload_rows_observed += len(upload_items)
                row = {
                    "elapsedSeconds": round(args.duration_seconds - max(0.0, deadline - time.monotonic()), 3),
                    "seederStats": seeder_stats,
                    "leecherTransfer": {
                        "state": leecher_transfer.get("state"),
                        "completedBytes": leecher_transfer.get("completedBytes"),
                        "sizeBytes": leecher_transfer.get("sizeBytes"),
                        "progress": leecher_transfer.get("progress"),
                    },
                    "seederUploads": seeder_uploads,
                    "processMetrics": {
                        "seeder": sample_process_metrics(seeder_metrics, args.sample_interval_seconds),
                        "leecher": sample_process_metrics(leecher_metrics, args.sample_interval_seconds),
                        "rustUi": sample_process_metrics(ui_metrics, args.sample_interval_seconds),
                    },
                }
                samples.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
                samples.flush()
                sample_count += 1
                if leecher_transfer.get("state") == "completed":
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
        report["finalLeecherTransfer"] = request_json(leecher_base, "GET", f"/api/v1/transfers/{file_hash}", args.api_key)
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        report["processMetrics"] = {
            "seeder": close_process_metrics(seeder_metrics),
            "leecher": close_process_metrics(leecher_metrics),
            "rustUi": close_process_metrics(ui_metrics),
        }
        for proc in (ui_process, leecher_process, seeder_process):
            rust_client.stop_process_tree(proc)
        for handle in (ui_log, leecher_log, seeder_log):
            if handle is not None:
                handle.close()
        if server_process is not None:
            goed2k.stop_process(server_process)
            goed2k.stop_server_processes()
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
