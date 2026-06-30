"""Control and sample a persisted emulebb-rust soak profile.

This is intentionally operational glue, not a scenario runner. It keeps the
common long-soak chores reusable:

* sample sanitized Rust REST counters;
* gracefully restart the diagnostics daemon against an existing runtime dir;
* restart the upload parity monitor with the current PID-specific Rust diag log;
* run reusable long-soak cadence checks without shell loops.

Private operator paths, such as the MFC upload diagnostics log, must be passed at
runtime and are never embedded here.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.soak_launch import RUST_API_KEY
from emule_test_harness.windows_processes import (
    collect_processes,
    process_command_line,
    process_creation_date,
    terminate_process_tree,
)

ED2K_OFFER_BATCH_SIZE = 200
ED2K_OFFER_INTERVAL_SECONDS = 60


def output_root() -> Path:
    """Returns the configured workspace output root."""

    return get_workspace_output_root()


def default_runtime_dir() -> Path:
    """Returns the persistent Rust soak runtime directory."""

    return output_root() / "soak" / "rust-runtime"


def default_executable() -> Path:
    """Returns the diagnostics executable built by the workspace orchestrator."""

    target = output_root() / "builds" / "rust" / "target"
    target_triple = target / "x86_64-pc-windows-msvc" / "release" / "emulebb-rust-diagnostics.exe"
    if target_triple.exists():
        return target_triple
    return target / "release" / "emulebb-rust-diagnostics.exe"


def default_base_url() -> str:
    """Builds the default Rust REST base URL from X_LOCAL_IP when available."""

    host = os.environ.get("X_LOCAL_IP", "127.0.0.1").strip() or "127.0.0.1"
    return f"http://{host}:4731/api/v1"


def api_url(base_url: str, path: str) -> str:
    """Combines a base URL and API path without double slashes."""

    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def request_json(
    base_url: str,
    path: str,
    *,
    api_key: str,
    method: str = "GET",
    body: dict[str, object] | None = None,
    timeout_seconds: float = 8.0,
) -> dict[str, object]:
    """Runs one authenticated Rust REST request and unwraps the v1 data envelope."""

    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        api_url(base_url, path),
        data=payload,
        method=method,
        headers={"X-API-Key": api_key, "Accept": "application/json"},
    )
    if payload is not None:
        request.add_header("Content-Type", "application/json; charset=utf-8")
    with urlopen(request, timeout=timeout_seconds) as response:
        text = response.read().decode("utf-8")
    parsed = json.loads(text) if text else {}
    if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
        return parsed["data"]  # type: ignore[return-value]
    if isinstance(parsed, dict):
        return parsed
    raise RuntimeError(f"Rust REST returned a non-object payload for {method} {path}: {parsed!r}")


def safe_int(value: object) -> int | None:
    """Converts JSON-ish values to int when possible."""

    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ed2k_visibility_projection(published: object, pending: object) -> dict[str, object]:
    """Estimates remaining ED2K server visibility at the MFC-compatible cadence."""

    published_count = safe_int(published)
    pending_count = safe_int(pending)
    if published_count is None or pending_count is None:
        return {}
    total = published_count + pending_count
    percent = round((published_count / total) * 100.0, 2) if total > 0 else 100.0
    batches_remaining = (pending_count + ED2K_OFFER_BATCH_SIZE - 1) // ED2K_OFFER_BATCH_SIZE
    return {
        "ed2kOfferBatchSize": ED2K_OFFER_BATCH_SIZE,
        "ed2kOfferIntervalSeconds": ED2K_OFFER_INTERVAL_SECONDS,
        "ed2kVisibilityPercent": percent,
        "ed2kVisibilityEtaSeconds": batches_remaining * ED2K_OFFER_INTERVAL_SECONDS,
    }


def sanitize_status(status: dict[str, object]) -> dict[str, object]:
    """Extracts parity-relevant counters without file names, paths, or peer IDs."""

    stats = status.get("stats") if isinstance(status.get("stats"), dict) else {}
    kad = status.get("kad") if isinstance(status.get("kad"), dict) else {}
    servers = status.get("servers") if isinstance(status.get("servers"), dict) else {}
    runtime = status.get("runtimeDiagnostics") if isinstance(status.get("runtimeDiagnostics"), dict) else {}
    ed2k_publish = runtime.get("ed2kPublish") if isinstance(runtime.get("ed2kPublish"), dict) else {}
    kad_publish = runtime.get("kadPublish") if isinstance(runtime.get("kadPublish"), dict) else {}
    ed2k_published = ed2k_publish.get("publishedEntries")
    ed2k_pending = ed2k_publish.get("pendingEntries")
    sanitized = {
        "ed2kConnected": servers.get("connected"),
        "ed2kHighId": not bool(servers.get("lowId")),
        "kadConnected": kad.get("connected"),
        "kadFirewalled": kad.get("firewalled"),
        "kadContactCount": kad.get("contactCount"),
        "kadUsers": kad.get("users"),
        "kadFiles": kad.get("files"),
        "activeUploads": stats.get("activeUploads"),
        "waitingUploads": stats.get("waitingUploads"),
        "uploadSpeedKiBps": round(float(stats.get("uploadSpeedKiBps") or 0.0), 2),
        "sharedHashingActive": stats.get("sharedHashingActive"),
        "sharedHashingCount": stats.get("sharedHashingCount"),
        "knownFileCount": runtime.get("knownFileCount"),
        "sharedFileCount": runtime.get("sharedFileCount"),
        "ed2kPublishedEntries": ed2k_published,
        "ed2kPendingEntries": ed2k_pending,
        "ed2kPublishPhase": ed2k_publish.get("phase"),
        "kadPublishPhase": kad_publish.get("phase"),
        "kadGateAllowed": kad_publish.get("gateAllowed"),
        "kadGateBlockReason": kad_publish.get("gateBlockReason"),
        "kadInFlightCount": kad_publish.get("inFlightCount"),
        "kadInFlightBudget": kad_publish.get("inFlightBudget"),
        "kadAvailableSearchPermits": kad_publish.get("availableSearchPermits"),
        "kadActiveKeywordPublishes": kad_publish.get("activeKeywordPublishes"),
        "kadActiveSourcePublishes": kad_publish.get("activeSourcePublishes"),
        "kadActiveNotesPublishes": kad_publish.get("activeNotesPublishes"),
        "kadKeywordDueCount": kad_publish.get("keywordDueCount"),
        "kadSourceDueCount": kad_publish.get("sourceDueCount"),
        "kadNotesDueCount": kad_publish.get("notesDueCount"),
        "kadKeywordAttempted": kad_publish.get("keywordAttempted"),
        "kadSourceAttempted": kad_publish.get("sourceAttempted"),
        "kadNotesAttempted": kad_publish.get("notesAttempted"),
        "kadBusyCount": kad_publish.get("busyCount"),
        "kadTimedOutCount": kad_publish.get("timedOutCount"),
        "kadSourcePublishedTotal": kad_publish.get("sourcePublishedTotal"),
        "kadSourceAttemptedContactsTotal": kad_publish.get("sourceAttemptedContactsTotal"),
        "kadSourceAckedContactsTotal": kad_publish.get("sourceAckedContactsTotal"),
        "kadSourceContactTimeoutsTotal": kad_publish.get("sourceContactTimeoutsTotal"),
        "kadSourceFailed": kad_publish.get("sourceFailed"),
        "kadKeywordPublishedTotal": kad_publish.get("keywordPublishedTotal"),
        "kadKeywordAttemptedContactsTotal": kad_publish.get("keywordAttemptedContactsTotal"),
        "kadKeywordAckedContactsTotal": kad_publish.get("keywordAckedContactsTotal"),
        "kadKeywordContactTimeoutsTotal": kad_publish.get("keywordContactTimeoutsTotal"),
        "kadKeywordFailed": kad_publish.get("keywordFailed"),
    }
    sanitized.update(ed2k_visibility_projection(ed2k_published, ed2k_pending))
    return sanitized


def sample(base_url: str, api_key: str) -> dict[str, object]:
    """Returns a sanitized live Rust status sample."""

    return sanitize_status(request_json(base_url, "/status", api_key=api_key))


def pid_exists(pid: int) -> bool:
    """Returns whether a process id is currently live."""

    if pid <= 0:
        return False
    if os.name == "nt":
        return any(process.pid == pid for process in collect_processes())
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_pid_exit(pid: int, timeout_seconds: float) -> bool:
    """Waits for one process id to exit."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not pid_exists(pid):
            return True
        time.sleep(0.5)
    return not pid_exists(pid)


def terminate_pid_tree(pid: int, *, markers: tuple[str, ...] = (), timeout_seconds: float = 15.0) -> None:
    """Terminates one process tree after optional command-line marker checks."""

    if pid <= 0 or not pid_exists(pid):
        return
    if os.name == "nt":
        terminate_process_tree(
            pid,
            timeout_seconds=timeout_seconds,
            expected_command_line_markers=markers,
            expected_root_creation_date=process_creation_date(pid),
        )
        return
    os.kill(pid, signal.SIGTERM)
    if not wait_pid_exit(pid, timeout_seconds):
        os.kill(pid, signal.SIGKILL)


def request_rust_shutdown(base_url: str, api_key: str) -> None:
    """Requests Rust's graceful network/profile shutdown."""

    try:
        request_json(
            base_url,
            "/app/shutdown",
            api_key=api_key,
            method="POST",
            body={"confirmShutdown": True},
            timeout_seconds=10.0,
        )
    except (HTTPError, URLError, TimeoutError, OSError, RuntimeError):
        pass


def wait_rest_ready(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until Rust REST responds to /stats."""

    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return request_json(base_url, "/stats", api_key=api_key, timeout_seconds=5.0)
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as exc:
            last_error = exc
            time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for Rust REST readiness: {last_error}")


def wait_connected(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until Rust reports both ED2K and Kad connected."""

    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, object] = {}
    while time.monotonic() < deadline:
        latest = sample(base_url, api_key)
        if latest.get("ed2kConnected") is True and latest.get("kadConnected") is True:
            return latest
        time.sleep(2.0)
    raise RuntimeError(f"Timed out waiting for ED2K+Kad connected: {latest}")


def latest_diag_log(log_dir: Path, rust_pid: int | None = None) -> Path | None:
    """Returns the PID-specific Rust diagnostics JSONL when available."""

    if rust_pid is not None:
        candidate = log_dir / f"emulebb-rust-diag-{rust_pid}.jsonl"
        if candidate.exists():
            return candidate
    matches = sorted(log_dir.glob("emulebb-rust-diag-*.jsonl"), key=lambda path: path.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def start_rust(args: argparse.Namespace) -> dict[str, object]:
    """Starts the diagnostics daemon against the persisted runtime."""

    runtime_dir = args.runtime_dir
    log_dir = args.log_dir or runtime_dir / "packet-dump"
    config_path = args.config or runtime_dir / "emulebb-rust.toml"
    exe = args.exe
    if not exe.is_file():
        raise RuntimeError(f"Rust diagnostics executable was not found: {exe}")
    if not config_path.is_file():
        raise RuntimeError(f"Rust config was not found: {config_path}")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["EMULEBB_RUST_LOG_DIR"] = str(log_dir)
    stdout = (runtime_dir / "daemon.out").open("ab", buffering=0)
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    process = subprocess.Popen(
        [str(exe), "--config", str(config_path)],
        cwd=str(runtime_dir),
        env=env,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    wait_rest_ready(args.base_url, args.api_key, args.rest_timeout_seconds)
    if args.start_kad:
        request_json(args.base_url, "/kad/operations/start", api_key=args.api_key, method="POST", body={})
    connected = wait_connected(args.base_url, args.api_key, args.connect_timeout_seconds) if args.wait_connected else {}
    diag = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        diag = latest_diag_log(log_dir, process.pid)
        if diag is not None:
            break
        time.sleep(1.0)
    return {
        "rustPid": process.pid,
        "runtimeDir": str(runtime_dir),
        "logDir": str(log_dir),
        "diagLog": str(diag) if diag is not None else None,
        "connected": connected,
    }


def stop_rust(args: argparse.Namespace) -> dict[str, object]:
    """Stops Rust gracefully and falls back to exact process-tree termination."""

    request_rust_shutdown(args.base_url, args.api_key)
    exited = wait_pid_exit(args.pid, args.shutdown_timeout_seconds) if args.pid else True
    if args.pid and not exited:
        terminate_pid_tree(args.pid, markers=("emulebb-rust-diagnostics",), timeout_seconds=15.0)
    return {"rustPid": args.pid, "stopped": not args.pid or not pid_exists(args.pid)}


def rust_processes(_: argparse.Namespace) -> dict[str, object]:
    """Returns current eMuleBB Rust process rows through the Python WMI helper."""

    matches = [
        process
        for process in collect_processes()
        if process.name.lower().startswith("emulebb-rust")
    ]
    matches.sort(key=lambda process: (process.name.lower(), process.pid))
    return {
        "processes": [
            {
                "pid": process.pid,
                "parentPid": process.parent_pid,
                "name": process.name,
                "creationDate": process.creation_date,
                "commandLine": process.command_line,
            }
            for process in matches
        ]
    }


def stop_upload_monitor(output_dir: Path, timeout_seconds: float = 20.0) -> dict[str, object]:
    """Requests the upload parity monitor to stop through its stop file."""

    pid_path = output_dir / "upload-parity-monitor.pid"
    stop_path = output_dir / "upload-parity-monitor.stop"
    pid = int(pid_path.read_text(encoding="ascii").strip()) if pid_path.exists() else 0
    stop_path.parent.mkdir(parents=True, exist_ok=True)
    stop_path.write_text("stop\n", encoding="ascii")
    stopped = wait_pid_exit(pid, timeout_seconds) if pid else True
    if pid and not stopped:
        terminate_pid_tree(pid, markers=("upload-parity-monitor.py",), timeout_seconds=15.0)
    return {"monitorPid": pid or None, "stopped": not pid or not pid_exists(pid)}


def extract_command_line_option(command_line: str, option: str) -> str:
    """Extracts a quoted or unquoted option value from a process command line."""

    pattern = rf"(?:^|\s){re.escape(option)}\s+(?:\"([^\"]+)\"|(\S+))"
    match = re.search(pattern, command_line)
    if match is None:
        return ""
    return match.group(1) or match.group(2) or ""


def existing_monitor_mfc_upload_log(output_dir: Path) -> Path | None:
    """Returns the current monitor's MFC upload log argument without exposing it."""

    pid_path = output_dir / "upload-parity-monitor.pid"
    pid = int(pid_path.read_text(encoding="ascii").strip()) if pid_path.exists() else 0
    if not pid:
        return None
    command_line = process_command_line(pid)
    if not command_line:
        return None
    value = extract_command_line_option(command_line, "--mfc-upload-log")
    return Path(value) if value else None


def start_upload_monitor(args: argparse.Namespace) -> dict[str, object]:
    """Starts the existing upload parity monitor as a detached helper."""

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    stop_path = output_dir / "upload-parity-monitor.stop"
    if stop_path.exists():
        stop_path.unlink()
    diag_log = args.rust_diag_log or latest_diag_log(args.log_dir, args.rust_pid)
    script = SCRIPT_PATH.parent / "upload-parity-monitor.py"
    mfc_upload_log = args.mfc_upload_log or existing_monitor_mfc_upload_log(output_dir)
    if diag_log is None:
        raise RuntimeError(f"No Rust diagnostics log found under {args.log_dir}.")
    if mfc_upload_log is None:
        raise RuntimeError("No MFC upload diagnostics log was provided and no reusable monitor command line was found.")
    stdout = (output_dir / "upload-parity-monitor.stdout.log").open("ab", buffering=0)
    stderr = (output_dir / "upload-parity-monitor.stderr.log").open("ab", buffering=0)
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    command = [
        sys.executable,
        str(script),
        "--rust-base-url",
        args.base_url,
        "--rust-api-key",
        args.api_key,
        "--rust-diag-log",
        str(diag_log),
        "--mfc-upload-log",
        str(mfc_upload_log),
        "--output-dir",
        str(output_dir),
        "--interval-seconds",
        str(args.interval_seconds),
    ]
    process = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdout=stdout,
        stderr=stderr,
        creationflags=creationflags,
    )
    return {"monitorPid": process.pid, "rustDiagLog": str(diag_log), "outputDir": str(output_dir)}


def restart_upload_monitor(args: argparse.Namespace) -> dict[str, object]:
    """Stops then starts the upload parity monitor."""

    if args.mfc_upload_log is None:
        args.mfc_upload_log = existing_monitor_mfc_upload_log(args.output_dir)
    stopped = stop_upload_monitor(args.output_dir)
    started = start_upload_monitor(args)
    return {"stopped": stopped, "started": started}


def latest_monitor_record(output_dir: Path) -> dict[str, object]:
    """Returns the most recent upload parity monitor JSONL record."""

    jsonl_path = output_dir / "upload-parity-monitor.jsonl"
    if not jsonl_path.exists():
        return {}
    latest = ""
    with jsonl_path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - 1024 * 1024), os.SEEK_SET)
        if size > 1024 * 1024:
            handle.readline()
        for line in handle.read().decode("utf-8", errors="replace").splitlines():
            if line.strip():
                latest = line
    return json.loads(latest) if latest else {}


def timestamp_age_seconds(timestamp: object) -> float | None:
    """Returns the age in seconds for an ISO-8601 timestamp."""

    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - parsed.astimezone(UTC)).total_seconds())


def upload_monitor_sample(args: argparse.Namespace) -> dict[str, object]:
    """Returns a sanitized summary of the live upload parity monitor state."""

    output_dir = args.output_dir
    heartbeat_path = output_dir / "upload-parity-monitor.heartbeat.txt"
    pid_path = output_dir / "upload-parity-monitor.pid"
    heartbeat = heartbeat_path.read_text(encoding="utf-8", errors="replace").strip() if heartbeat_path.exists() else ""
    pid = int(pid_path.read_text(encoding="ascii").strip()) if pid_path.exists() else 0
    record = latest_monitor_record(output_dir)
    latest_age_seconds = timestamp_age_seconds(record.get("timestamp")) if record else None
    monitor_stale = latest_age_seconds is None or latest_age_seconds > args.stale_seconds
    if not record:
        return {
            "heartbeat": heartbeat,
            "latestAgeSeconds": latest_age_seconds,
            "monitorStale": monitor_stale,
            "monitorPid": pid or None,
            "monitorAlive": pid_exists(pid) if pid else False,
            "latestRecord": None,
        }
    if "error" in record:
        latest: dict[str, object] = {
            "timestamp": record.get("timestamp"),
            "error": record.get("error"),
        }
    else:
        rust = record.get("rust") if isinstance(record.get("rust"), dict) else {}
        sched = record.get("rustSched") if isinstance(record.get("rustSched"), dict) else {}
        action = record.get("action") if isinstance(record.get("action"), dict) else {}
        latest = {
            "timestamp": record.get("timestamp"),
            "rustKiBps": rust.get("uploadSpeedKiBps"),
            "rustUploads": rust.get("activeUploads"),
            "rustWaiting": rust.get("waitingUploads"),
            "mfcKiBps": action.get("mfcEffectiveKiBps"),
            "mfcWaiting": action.get("mfcWaitingDemand"),
            "parityGap": action.get("parityGap"),
            "postVisibilityDemandGap": action.get("postVisibilityDemandGap"),
            "rustEd2kPending": rust.get("ed2kPendingEntries"),
            "rustKadFirewalled": rust.get("kadFirewalled"),
            "rustKadSource": {
                "published": rust.get("kadSourcePublishedTotal"),
                "attemptedContacts": rust.get("kadSourceAttemptedContactsTotal"),
                "ackedContacts": rust.get("kadSourceAckedContactsTotal"),
                "timeouts": rust.get("kadSourceContactTimeoutsTotal"),
                "failed": rust.get("kadSourceFailed"),
            },
            "diagKadPublish": {
                "events": sched.get("kadPublishEvents"),
                "attemptedContacts": sched.get("kadPublishAttemptedContacts"),
                "ackedContacts": sched.get("kadPublishAckedContacts"),
                "timeouts": sched.get("kadPublishTimedOutContacts"),
                "failedContacts": sched.get("kadPublishFailedContacts"),
            },
            "lastCapacity": sched.get("lastCapacity"),
        }
    return {
        "heartbeat": heartbeat,
        "latestAgeSeconds": latest_age_seconds,
        "monitorStale": monitor_stale,
        "monitorPid": pid or None,
        "monitorAlive": pid_exists(pid) if pid else False,
        "latestRecord": latest,
    }


def watch_findings(rust: dict[str, object], monitor: dict[str, object]) -> list[str]:
    """Returns compact operator-facing findings for one soak cadence check."""

    findings: list[str] = []
    latest = monitor.get("latestRecord") if isinstance(monitor.get("latestRecord"), dict) else {}
    if monitor.get("monitorAlive") is False:
        findings.append("monitor-not-running")
    if monitor.get("monitorStale") is True:
        findings.append("monitor-stale")
    if rust.get("sharedHashingActive") is True or int(rust.get("sharedHashingCount") or 0) > 0:
        findings.append("rust-hashing-active")
    if rust.get("ed2kConnected") is not True:
        findings.append("rust-ed2k-disconnected")
    if rust.get("ed2kHighId") is not True:
        findings.append("rust-ed2k-not-high-id")
    if rust.get("kadConnected") is not True:
        findings.append("rust-kad-disconnected")
    if rust.get("kadFirewalled") is True:
        findings.append("rust-kad-firewalled")
    gate_reason = str(rust.get("kadGateBlockReason") or "")
    if gate_reason == "dhtSearchBusy":
        findings.append("rust-kad-search-capacity-busy")
    elif rust.get("kadGateAllowed") is False:
        findings.append("rust-kad-publish-gated")
    if latest.get("postVisibilityDemandGap") is True:
        findings.append("post-visibility-demand-gap")
    if latest.get("parityGap") is True and int(rust.get("ed2kPendingEntries") or 0) > 0:
        findings.append("visibility-still-maturing")
    elif latest.get("parityGap") is True:
        findings.append("upload-parity-gap")
    return findings


def watch_once(args: argparse.Namespace) -> dict[str, object]:
    """Runs one reusable long-soak cadence check and optional monitor repair."""

    rust = sample(args.base_url, args.api_key)
    monitor_args = argparse.Namespace(output_dir=args.output_dir, stale_seconds=args.stale_seconds)
    monitor = upload_monitor_sample(monitor_args)
    action: dict[str, object] = {"monitorRestarted": False}
    if args.restart_stale_monitor and (
        monitor.get("monitorAlive") is False or monitor.get("monitorStale") is True
    ):
        restart_args = argparse.Namespace(
            base_url=args.base_url,
            api_key=args.api_key,
            output_dir=args.output_dir,
            log_dir=args.log_dir,
            rust_pid=args.rust_pid,
            rust_diag_log=args.rust_diag_log,
            mfc_upload_log=args.mfc_upload_log,
            interval_seconds=args.interval_seconds,
        )
        action = {"monitorRestarted": True, "restart": restart_upload_monitor(restart_args)}
        monitor = upload_monitor_sample(monitor_args)
    return {
        "timestampUtc": datetime.now(UTC).isoformat(),
        "rust": rust,
        "monitor": monitor,
        "findings": watch_findings(rust, monitor),
        "action": action,
    }


def append_jsonl(path: Path, payload: dict[str, object]) -> None:
    """Appends one JSON record to a retained soak evidence file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def write_watch_heartbeat(path: Path, payload: dict[str, object]) -> None:
    """Writes a compact heartbeat for a long-running watch loop."""

    rust = payload.get("rust") if isinstance(payload.get("rust"), dict) else {}
    monitor = payload.get("monitor") if isinstance(payload.get("monitor"), dict) else {}
    latest = monitor.get("latestRecord") if isinstance(monitor.get("latestRecord"), dict) else {}
    lines = [
        f"timestampUtc={payload.get('timestampUtc')}",
        f"findings={','.join(str(item) for item in payload.get('findings', []))}",
        f"rustKiBps={rust.get('uploadSpeedKiBps')}",
        f"rustUploads={rust.get('activeUploads')}",
        f"rustWaiting={rust.get('waitingUploads')}",
        f"ed2kPublished={rust.get('ed2kPublishedEntries')}",
        f"ed2kPending={rust.get('ed2kPendingEntries')}",
        f"ed2kVisibilityPercent={rust.get('ed2kVisibilityPercent')}",
        f"kadFirewalled={rust.get('kadFirewalled')}",
        f"monitorSample={latest.get('timestamp')}",
        f"monitorParityGap={latest.get('parityGap')}",
        f"monitorPostVisibilityDemandGap={latest.get('postVisibilityDemandGap')}",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def watch_loop(args: argparse.Namespace) -> dict[str, object]:
    """Runs repeated long-soak cadence checks and retains JSONL evidence."""

    sample_count = 0
    last_result: dict[str, object] | None = None
    while args.max_samples <= 0 or sample_count < args.max_samples:
        if args.watch_stop_file.exists():
            break
        last_result = watch_once(args)
        append_jsonl(args.watch_jsonl, last_result)
        write_watch_heartbeat(args.watch_heartbeat, last_result)
        sample_count += 1
        print(json.dumps(last_result, sort_keys=True), flush=True)
        if args.max_samples > 0 and sample_count >= args.max_samples:
            break
        time.sleep(args.watch_interval_seconds)

    return {
        "samples": sample_count,
        "watchJsonl": str(args.watch_jsonl),
        "watchHeartbeat": str(args.watch_heartbeat),
        "lastResult": last_result,
    }


def start_watch_loop(args: argparse.Namespace) -> dict[str, object]:
    """Starts the retained soak watch loop as a detached Python process."""

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.watch_stop_file.unlink(missing_ok=True)
    stdout = (args.output_dir / "rust-soak-watch.stdout.log").open("ab", buffering=0)
    stderr = (args.output_dir / "rust-soak-watch.stderr.log").open("ab", buffering=0)
    command = [
        sys.executable,
        str(SCRIPT_PATH),
        "--base-url",
        args.base_url,
        "--api-key",
        args.api_key,
        "watch-loop",
        "--output-dir",
        str(args.output_dir),
        "--stale-seconds",
        str(args.stale_seconds),
        "--log-dir",
        str(args.log_dir),
        "--interval-seconds",
        str(args.interval_seconds),
        "--watch-interval-seconds",
        str(args.watch_interval_seconds),
        "--max-samples",
        str(args.max_samples),
        "--watch-jsonl",
        str(args.watch_jsonl),
        "--watch-heartbeat",
        str(args.watch_heartbeat),
        "--watch-stop-file",
        str(args.watch_stop_file),
    ]
    if args.rust_pid is not None:
        command.extend(["--rust-pid", str(args.rust_pid)])
    if args.rust_diag_log is not None:
        command.extend(["--rust-diag-log", str(args.rust_diag_log)])
    if args.mfc_upload_log is not None:
        command.extend(["--mfc-upload-log", str(args.mfc_upload_log)])
    if not args.restart_stale_monitor:
        command.append("--no-restart-stale-monitor")

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdout=stdout,
        stderr=stderr,
        stdin=subprocess.DEVNULL,
        close_fds=False,
        creationflags=creationflags,
    )
    pid_path = args.output_dir / "rust-soak-watch.pid"
    pid_path.write_text(f"{process.pid}\n", encoding="utf-8", newline="\n")
    return {
        "watchPid": process.pid,
        "watchPidFile": str(pid_path),
        "watchJsonl": str(args.watch_jsonl),
        "watchHeartbeat": str(args.watch_heartbeat),
        "watchStopFile": str(args.watch_stop_file),
    }


def stop_watch_loop(args: argparse.Namespace) -> dict[str, object]:
    """Requests a detached soak watch loop to stop."""

    args.watch_stop_file.parent.mkdir(parents=True, exist_ok=True)
    args.watch_stop_file.write_text(datetime.now(UTC).isoformat() + "\n", encoding="utf-8", newline="\n")
    pid = None
    if args.watch_pid_file.exists():
        text = args.watch_pid_file.read_text(encoding="utf-8", errors="replace").strip()
        if text.isdigit():
            pid = int(text)
    if args.terminate and pid is not None:
        terminate_pid_tree(pid, markers=("rust-soak-control.py", "watch-loop"), timeout_seconds=15.0)
    return {
        "watchPid": pid,
        "watchAlive": pid_exists(pid) if pid is not None else False,
        "watchStopFile": str(args.watch_stop_file),
        "stopRequested": True,
    }


def latest_jsonl_record(path: Path) -> dict[str, object] | None:
    """Returns the last JSONL record from a retained evidence file."""

    if not path.exists():
        return None
    with path.open("rb") as handle:
        size = path.stat().st_size
        if size > 1_000_000:
            handle.seek(-1_000_000, os.SEEK_END)
            handle.readline()
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def watch_status(args: argparse.Namespace) -> dict[str, object]:
    """Returns detached soak watch loop health without shell process listings."""

    pid = None
    if args.watch_pid_file.exists():
        text = args.watch_pid_file.read_text(encoding="utf-8", errors="replace").strip()
        if text.isdigit():
            pid = int(text)
    heartbeat = args.watch_heartbeat.read_text(encoding="utf-8", errors="replace") if args.watch_heartbeat.exists() else ""
    latest = latest_jsonl_record(args.watch_jsonl)
    return {
        "watchPid": pid,
        "watchAlive": pid_exists(pid) if pid is not None else False,
        "watchPidFile": str(args.watch_pid_file),
        "watchJsonl": str(args.watch_jsonl),
        "watchHeartbeat": heartbeat,
        "watchStopFilePresent": args.watch_stop_file.exists(),
        "latestRecord": latest,
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=default_base_url())
    parser.add_argument("--api-key", default=RUST_API_KEY)
    sub = parser.add_subparsers(dest="command", required=True)

    sample_parser = sub.add_parser("sample", help="Print sanitized Rust status counters.")
    sample_parser.set_defaults(func=lambda args: sample(args.base_url, args.api_key))

    stop_parser = sub.add_parser("stop-rust", help="Gracefully stop a running Rust diagnostics daemon.")
    stop_parser.add_argument("--pid", type=int, required=True)
    stop_parser.add_argument("--shutdown-timeout-seconds", type=float, default=45.0)
    stop_parser.set_defaults(func=stop_rust)

    rust_processes_parser = sub.add_parser("rust-processes", help="List Rust process rows through Python WMI.")
    rust_processes_parser.set_defaults(func=rust_processes)

    start_parser = sub.add_parser("start-rust", help="Start Rust diagnostics against a persisted runtime.")
    start_parser.add_argument("--runtime-dir", type=Path, default=default_runtime_dir())
    start_parser.add_argument("--log-dir", type=Path)
    start_parser.add_argument("--config", type=Path)
    start_parser.add_argument("--exe", type=Path, default=default_executable())
    start_parser.add_argument("--rest-timeout-seconds", type=float, default=90.0)
    start_parser.add_argument("--connect-timeout-seconds", type=float, default=180.0)
    start_parser.add_argument("--start-kad", action="store_true", default=True)
    start_parser.add_argument("--no-start-kad", action="store_false", dest="start_kad")
    start_parser.add_argument("--wait-connected", action="store_true", default=True)
    start_parser.add_argument("--no-wait-connected", action="store_false", dest="wait_connected")
    start_parser.set_defaults(func=start_rust)

    stop_monitor_parser = sub.add_parser("stop-monitor", help="Stop the upload parity monitor via its stop file.")
    stop_monitor_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    stop_monitor_parser.set_defaults(func=lambda args: stop_upload_monitor(args.output_dir))

    sample_monitor_parser = sub.add_parser("monitor-sample", help="Print the latest upload parity monitor summary.")
    sample_monitor_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    sample_monitor_parser.add_argument(
        "--stale-seconds",
        type=float,
        default=600.0,
        help="Age threshold for reporting the latest monitor sample as stale.",
    )
    sample_monitor_parser.set_defaults(func=upload_monitor_sample)

    monitor_parser = sub.add_parser("restart-monitor", help="Restart the upload parity monitor.")
    monitor_parser.add_argument("--mfc-upload-log", type=Path)
    monitor_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    monitor_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    monitor_parser.add_argument("--rust-pid", type=int)
    monitor_parser.add_argument("--rust-diag-log", type=Path)
    monitor_parser.add_argument("--interval-seconds", type=float, default=300.0)
    monitor_parser.set_defaults(func=restart_upload_monitor)

    watch_parser = sub.add_parser("watch-once", help="Run one long-soak cadence check and optional monitor repair.")
    watch_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    watch_parser.add_argument("--stale-seconds", type=float, default=900.0)
    watch_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    watch_parser.add_argument("--rust-pid", type=int)
    watch_parser.add_argument("--rust-diag-log", type=Path)
    watch_parser.add_argument("--mfc-upload-log", type=Path)
    watch_parser.add_argument("--interval-seconds", type=float, default=300.0)
    watch_parser.add_argument("--restart-stale-monitor", action="store_true", default=True)
    watch_parser.add_argument("--no-restart-stale-monitor", action="store_false", dest="restart_stale_monitor")
    watch_parser.set_defaults(func=watch_once)

    watch_loop_parser = sub.add_parser("watch-loop", help="Run repeated long-soak cadence checks.")
    watch_loop_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    watch_loop_parser.add_argument("--stale-seconds", type=float, default=900.0)
    watch_loop_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    watch_loop_parser.add_argument("--rust-pid", type=int)
    watch_loop_parser.add_argument("--rust-diag-log", type=Path)
    watch_loop_parser.add_argument("--mfc-upload-log", type=Path)
    watch_loop_parser.add_argument("--interval-seconds", type=float, default=300.0)
    watch_loop_parser.add_argument("--restart-stale-monitor", action="store_true", default=True)
    watch_loop_parser.add_argument("--no-restart-stale-monitor", action="store_false", dest="restart_stale_monitor")
    watch_loop_parser.add_argument(
        "--watch-interval-seconds",
        type=float,
        default=300.0,
        help="Seconds to sleep between watch samples.",
    )
    watch_loop_parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Maximum samples to take; 0 means run until interrupted.",
    )
    watch_loop_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_loop_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    watch_loop_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    watch_loop_parser.set_defaults(func=watch_loop)

    start_watch_loop_parser = sub.add_parser("start-watch-loop", help="Start detached repeated soak checks.")
    start_watch_loop_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    start_watch_loop_parser.add_argument("--stale-seconds", type=float, default=900.0)
    start_watch_loop_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    start_watch_loop_parser.add_argument("--rust-pid", type=int)
    start_watch_loop_parser.add_argument("--rust-diag-log", type=Path)
    start_watch_loop_parser.add_argument("--mfc-upload-log", type=Path)
    start_watch_loop_parser.add_argument("--interval-seconds", type=float, default=300.0)
    start_watch_loop_parser.add_argument("--restart-stale-monitor", action="store_true", default=True)
    start_watch_loop_parser.add_argument(
        "--no-restart-stale-monitor",
        action="store_false",
        dest="restart_stale_monitor",
    )
    start_watch_loop_parser.add_argument("--watch-interval-seconds", type=float, default=300.0)
    start_watch_loop_parser.add_argument("--max-samples", type=int, default=0)
    start_watch_loop_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    start_watch_loop_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    start_watch_loop_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    start_watch_loop_parser.set_defaults(func=start_watch_loop)

    stop_watch_loop_parser = sub.add_parser("stop-watch-loop", help="Request the detached soak watch loop to stop.")
    stop_watch_loop_parser.add_argument(
        "--watch-pid-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.pid",
    )
    stop_watch_loop_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    stop_watch_loop_parser.add_argument("--terminate", action="store_true")
    stop_watch_loop_parser.set_defaults(func=stop_watch_loop)

    watch_status_parser = sub.add_parser("watch-status", help="Print detached soak watch loop health.")
    watch_status_parser.add_argument(
        "--watch-pid-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.pid",
    )
    watch_status_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_status_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    watch_status_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    watch_status_parser.set_defaults(func=watch_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the helper CLI."""

    args = build_parser().parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
