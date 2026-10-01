"""Run the hosted Windows Rust ZIP through the real first-run WebUI workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from .live_dependencies import safe_extract_zip
from .paths import get_workspace_output_root
from .rust_webui_live_proof import (
    ConsumerNetworkWorkflow,
    api_data,
    profile_settings_api_key,
    run_webui_live_proof,
    sanitize_report_text,
)

DEFAULT_MAX_TRANSFER_BYTES = 5 * 1024 * 1024 - 1
DEFAULT_MAX_COMPLETION_BYTES = DEFAULT_MAX_TRANSFER_BYTES
DEFAULT_NETWORK_TIMEOUT_SECONDS = 240.0
DEFAULT_TRANSFER_TIMEOUT_SECONDS = 120.0
REST_PORT = 4711
ED2K_PORT = 4662
KAD_PORT = 4672
PACKAGE_ROOT = "emulebb-rust"


@dataclass(frozen=True)
class SuspendedDaemon:
    executable: Path
    settings_path: Path
    api_key: str
    graceful_shutdown: bool


def persist_consumer_report(path: Path, report: dict[str, Any]) -> None:
    """Persist the current report state, including post-run recovery fields."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    """Return the streaming SHA-256 digest for one artifact or delivered file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release_zip(asset: Path) -> dict[str, Any]:
    """Verify the exact package ZIP and its extracted payload against its manifest."""

    manifest_path = asset.with_name(asset.name.removesuffix(".zip") + ".manifest.json")
    if not asset.is_file() or not manifest_path.is_file():
        raise RuntimeError("consumer live proof requires the hosted ZIP and sibling manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = str(manifest.get("sha256") or "").lower()
    actual = sha256_file(asset)
    if manifest.get("asset") != asset.name or len(expected) != 64 or actual != expected:
        raise RuntimeError("hosted Windows ZIP does not match its release manifest")
    if manifest.get("platform") != "x64" or manifest.get("signed") is not False:
        raise RuntimeError("consumer live proof requires the unsigned Windows x64 beta package")
    return manifest


def verify_extracted_payload(root: Path, manifest: dict[str, Any]) -> int:
    """Verify all extracted package files and reject unmanifested extras."""

    expected = manifest.get("perFileSha256")
    if not isinstance(expected, dict) or not expected:
        raise RuntimeError("release manifest has no per-file SHA-256 map")
    expected_paths = {str(path).replace("\\", "/") for path in expected}
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual_paths != expected_paths:
        raise RuntimeError("extracted Windows package file set differs from its manifest")
    for relative, digest in expected.items():
        path = root / Path(str(relative))
        if sha256_file(path) != str(digest).lower():
            raise RuntimeError("extracted Windows package file hash differs from its manifest")
    return len(expected_paths)


def _candidate_rows(
    payload: dict[str, Any],
    max_download_bytes: int,
    *,
    require_sha256: bool = False,
) -> list[dict[str, Any]]:
    rows = payload.get("auto_browse", {}).get("direct_bootstrap_transfers", [])
    candidates: list[dict[str, Any]] = []
    for raw in rows if isinstance(rows, list) else []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        transfer_hash = str(raw.get("hash") or "").lower()
        sha256 = str(raw.get("sha256") or "").lower()
        size = raw.get("size")
        suffix = Path(name).suffix.lower()
        if (
            Path(name).name != name
            or suffix != ".pdf"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= max_download_bytes
            or len(transfer_hash) != 32
            or any(ch not in "0123456789abcdef" for ch in transfer_hash)
            or (
                require_sha256
                and (len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256))
            )
        ):
            continue
        candidates.append(
            {
                "name": name,
                "hash": transfer_hash,
                "sha256": sha256,
                "size": size,
                "suffix": suffix,
            }
        )
    return sorted(candidates, key=lambda row: (int(row["size"]), str(row["hash"])))


def load_consumer_transfer(
    inputs_path: Path,
    max_transfer_bytes: int,
    *,
    require_sha256: bool = False,
) -> dict[str, Any]:
    """Load one exact operator-approved public transfer without retaining its identity."""

    payload = json.loads(inputs_path.read_text(encoding="utf-8-sig"))
    candidates = _candidate_rows(payload, max_transfer_bytes, require_sha256=require_sha256)
    if not candidates:
        raise RuntimeError(
            "consumer live proof requires an approved PDF smaller than 5 MiB and no larger than "
            f"{max_transfer_bytes} bytes with exact eD2K hash and size"
            + (", plus SHA-256 for completion mode" if require_sha256 else "")
        )
    return candidates[0]


def _assert_port_available(port: int, *, udp: bool = False) -> None:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as probe:
        if os.name == "nt":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("0.0.0.0", port))
        except OSError as exc:
            protocol = "UDP" if udp else "TCP"
            raise RuntimeError(f"consumer live proof requires free {protocol} port {port}") from exc


def _port_is_claimed(port: int, *, udp: bool = False) -> bool:
    import psutil

    kind = "udp" if udp else "tcp"
    return any(
        connection.pid is not None
        and connection.pid > 0
        and connection.laddr
        and int(connection.laddr.port) == port
        and (udp or connection.status == psutil.CONN_LISTEN)
        for connection in psutil.net_connections(kind=kind)
    )


def _wait_for_profile(settings_path: Path, process: subprocess.Popen[str], log_path: Path) -> str:
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(
                f"hosted package exited {process.returncode} during first run: "
                f"{sanitize_report_text(tail)}"
            )
        if settings_path.is_file():
            try:
                return profile_settings_api_key(settings_path)
            except (OSError, RuntimeError):
                pass
        time.sleep(0.25)
    raise RuntimeError("hosted package did not create its default profile")


def _wait_for_rest(base_url: str, api_key: str, process: subprocess.Popen[str], log_path: Path) -> None:
    deadline = time.monotonic() + 90.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(
                f"hosted package exited {process.returncode} before REST was ready: "
                f"{sanitize_report_text(tail)}"
            )
        try:
            api_data(base_url, "app", api_key)
            return
        except Exception as exc:  # noqa: BLE001 - keep retrying bounded startup
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"hosted package REST did not become ready: {last_error}")


def _start_daemon(executable: Path, *, local_app_data: Path, log_path: Path) -> tuple[subprocess.Popen[str], Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("a", encoding="utf-8", newline="\n")
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(local_app_data)
    env["RUST_LOG"] = "info"
    process = subprocess.Popen(
        [str(executable)],
        cwd=executable.parent,
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return process, handle


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_for_clean_exit(process: subprocess.Popen[str]) -> None:
    try:
        process.wait(timeout=45)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("hosted package did not exit after WebUI shutdown") from exc
    if process.returncode != 0:
        raise RuntimeError(f"hosted package exited {process.returncode} after WebUI shutdown")


def _suspend_existing_daemon(settings_path: Path) -> SuspendedDaemon:
    """Gracefully stop an idle operator daemon that owns all consumer ports."""

    import psutil

    api_key = profile_settings_api_key(settings_path)
    transfers = api_data(f"http://127.0.0.1:{REST_PORT}", "transfers?limit=500", api_key)
    rows = transfers.get("items", []) if isinstance(transfers, dict) else []
    active = [
        row
        for row in rows
        if isinstance(row, dict)
        and str(row.get("state") or "").lower() not in {"completed", "paused", "stopped"}
    ]
    if active:
        raise RuntimeError("refusing to suspend an operator daemon with active transfers")

    owners: dict[int, set[int]] = {REST_PORT: set(), ED2K_PORT: set(), KAD_PORT: set()}
    for connection in psutil.net_connections(kind="inet"):
        if connection.pid is None or connection.pid <= 0 or not connection.laddr:
            continue
        port = int(connection.laddr.port)
        if port in owners:
            owners[port].add(int(connection.pid))
    rest_owners = owners[REST_PORT]
    if len(rest_owners) != 1:
        raise RuntimeError("consumer ports are not owned by one unambiguous operator daemon")
    owner_pid = next(iter(rest_owners))
    if any(value and value != {owner_pid} for port, value in owners.items() if port != REST_PORT):
        raise RuntimeError("consumer P2P ports conflict with the operator daemon owner")
    process = psutil.Process(owner_pid)
    executable = Path(process.exe()).resolve()
    if executable.name.lower() != "emulebb-rust.exe":
        raise RuntimeError("consumer ports are not owned by emulebb-rust.exe")

    request = Request(
        f"http://127.0.0.1:{REST_PORT}/api/v1/app/shutdown",
        data=b'{"confirmShutdown":true}',
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )
    with urlopen(request, timeout=10.0) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError("operator daemon rejected graceful shutdown")
    graceful_shutdown = True
    try:
        process.wait(timeout=45.0)
    except psutil.TimeoutExpired:
        graceful_shutdown = False
        process.terminate()
        try:
            process.wait(timeout=15.0)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
    for port, udp in ((REST_PORT, False), (ED2K_PORT, False), (KAD_PORT, True)):
        _assert_port_available(port, udp=udp)
    return SuspendedDaemon(
        executable=executable,
        settings_path=settings_path,
        api_key=api_key,
        graceful_shutdown=graceful_shutdown,
    )


def _restore_existing_daemon(suspended: SuspendedDaemon) -> int:
    """Restart the previously suspended operator daemon with its original profile."""

    profile_dir = suspended.settings_path.parent
    if profile_dir.name.lower() != "emulebb-rust":
        raise RuntimeError("operator settings must belong to an emulebb-rust profile directory")
    env = os.environ.copy()
    env["LOCALAPPDATA"] = str(profile_dir.parent)
    creationflags = int(getattr(subprocess, "DETACHED_PROCESS", 0)) | int(
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    )
    process = subprocess.Popen(
        [str(suspended.executable)],
        cwd=suspended.executable.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
    )
    deadline = time.monotonic() + 90.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"restored operator daemon exited {process.returncode} during startup")
        try:
            api_data(f"http://127.0.0.1:{REST_PORT}", "app", suspended.api_key)
            return int(process.pid)
        except Exception as exc:  # noqa: BLE001 - bounded restore readiness poll
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"restored operator daemon REST did not become ready: {last_error}")


def _persistence_snapshot(base_url: str, api_key: str, transfer_hash: str) -> dict[str, Any]:
    searches = api_data(base_url, "searches", api_key)
    search_rows = searches.get("items", []) if isinstance(searches, dict) else []
    transfer = api_data(base_url, f"transfers/{transfer_hash}", api_key)
    if not isinstance(transfer, dict):
        raise RuntimeError("persisted transfer did not return an object")
    return {
        "searchCount": len(search_rows),
        "transferPresent": bool(transfer.get("hash")),
        "transferCompleted": int(transfer.get("completedBytes") or 0)
        == int(transfer.get("sizeBytes") or -1),
        "transferState": str(transfer.get("state") or "unknown"),
    }


def run_consumer_live(
    *,
    release_zip: Path,
    inputs_path: Path,
    search_term: str,
    max_transfer_bytes: int,
    max_completion_bytes: int,
    complete_transfer: bool,
    network_timeout_seconds: float,
    transfer_timeout_seconds: float,
) -> dict[str, Any]:
    """Execute the exact-package first-run, live network, persistence, and shutdown proof."""

    if os.name != "nt":
        raise RuntimeError("consumer live proof is a Windows-only release gate")
    if not search_term.strip():
        raise RuntimeError("consumer live proof requires an explicit search term")
    if (
        max_transfer_bytes <= 0
        or max_completion_bytes <= 0
        or network_timeout_seconds <= 0
        or transfer_timeout_seconds <= 0
    ):
        raise RuntimeError("consumer live proof bounds must be positive")
    if max_transfer_bytes > DEFAULT_MAX_TRANSFER_BYTES:
        raise RuntimeError("consumer live proof requires a PDF strictly smaller than 5 MiB")
    manifest = verify_release_zip(release_zip)
    transfer = load_consumer_transfer(
        inputs_path,
        max_transfer_bytes,
        require_sha256=complete_transfer,
    )
    if complete_transfer and int(transfer["size"]) > max_completion_bytes:
        raise RuntimeError(
            "full consumer download completion requires an approved transfer no larger than "
            f"{max_completion_bytes} bytes"
        )
    for port, udp in ((REST_PORT, False), (ED2K_PORT, False), (KAD_PORT, True)):
        _assert_port_available(port, udp=udp)

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = get_workspace_output_root()
    report_dir = output_root / "reports" / "rust-consumer-live" / run_id
    package_dir = report_dir / "package"
    profile_parent = output_root / "profiles" / "rust-consumer-live" / run_id
    local_app_data = profile_parent / "localappdata"
    profile_dir = local_app_data / "emulebb-rust"
    if profile_dir.exists():
        raise RuntimeError("consumer live proof profile must be fresh")
    report_dir.mkdir(parents=True, exist_ok=False)
    local_app_data.mkdir(parents=True, exist_ok=False)
    safe_extract_zip(release_zip, package_dir)
    verified_file_count = verify_extracted_payload(package_dir, manifest)
    executable = package_dir / PACKAGE_ROOT / "emulebb-rust.exe"
    if not executable.is_file():
        raise RuntimeError("hosted Windows ZIP is missing emulebb-rust.exe")

    base_url = f"http://127.0.0.1:{REST_PORT}"
    settings_path = profile_dir / "emulebb-rust-settings.toml"
    metadata_path = profile_dir / "emulebb-rust-metadata.db"
    incoming_dir = profile_dir / "incoming"
    log_path = report_dir / "daemon.log"
    report_path = report_dir / "rust-consumer-live-result.json"
    report: dict[str, Any] = {
        "schema": "emulebb.rust-consumer-live.v1",
        "status": "running",
        "runId": run_id,
        "artifact": {
            "name": release_zip.name,
            "sha256": str(manifest["sha256"]),
            "sourceCommit": str(manifest.get("source", {}).get("emulebbRust", {}).get("commit") or ""),
            "verifiedFileCount": verified_file_count,
        },
        "networkMode": "direct-default-route",
        "bindOverride": False,
        "sharedRootCount": 0,
        "search": {
            "operatorProvided": True,
            "methods": ["automatic", "server", "kad"],
        },
        "download": {
            "approved": True,
            "mode": "complete" if complete_transfer else "trigger-observe-stop",
            "pdfOnly": True,
            "strictLessThan5MiB": True,
            "maxTransferBytes": max_transfer_bytes,
            "maxCompletionBytes": max_completion_bytes,
        },
        "checks": {},
    }
    process: subprocess.Popen[str] | None = None
    log_handle = None
    api_key = ""
    try:
        process, log_handle = _start_daemon(
            executable,
            local_app_data=local_app_data,
            log_path=log_path,
        )
        api_key = _wait_for_profile(settings_path, process, log_path)
        _wait_for_rest(base_url, api_key, process, log_path)
        settings = api_data(base_url, "app/settings", api_key)
        daemon_settings = settings.get("daemon", {}) if isinstance(settings, dict) else {}
        if daemon_settings.get("p2pBindIp") or daemon_settings.get("p2pBindInterface"):
            raise RuntimeError("fresh consumer profile unexpectedly configured a P2P bind override")
        report["checks"]["firstRun"] = {
            "freshProfile": metadata_path.is_file(),
            "apiKeyCreated": bool(api_key),
            "p2pBindIpEmpty": not bool(daemon_settings.get("p2pBindIp")),
            "p2pBindInterfaceEmpty": not bool(daemon_settings.get("p2pBindInterface")),
            "tcpPortClaimed": _port_is_claimed(ED2K_PORT),
            "udpPortClaimed": _port_is_claimed(KAD_PORT, udp=True),
        }
        upnp_setup = run_webui_live_proof(
            base_url=base_url,
            api_key=api_key,
            report_path=report_dir / "first-run-upnp-webui.json",
            steady_seconds=3.0,
            tab_wait_seconds=0.4,
            timeout_seconds=max(60.0, network_timeout_seconds),
            max_main_thread_busy_ratio=0.25,
            navigation_only=True,
            verify_stale_key_recovery=True,
            configure_best_effort_upnp=True,
            shutdown_after_proof=True,
        )
        report["checks"]["upnpSetupWebui"] = upnp_setup
        if upnp_setup.get("status") != "passed":
            raise RuntimeError("first-run rendered UPnP setup failed")
        if not upnp_setup.get("checks", {}).get("shutdown", {}).get("ok"):
            raise RuntimeError("UPnP setup proof did not request package shutdown")
        _wait_for_clean_exit(process)
        process = None
        if log_handle is not None:
            log_handle.close()
            log_handle = None

        process, log_handle = _start_daemon(
            executable,
            local_app_data=local_app_data,
            log_path=log_path,
        )
        restarted_api_key = _wait_for_profile(settings_path, process, log_path)
        if restarted_api_key != api_key:
            raise RuntimeError("default-profile API key changed after UPnP setup restart")
        _wait_for_rest(base_url, api_key, process, log_path)
        restarted_settings = api_data(base_url, "app/settings", api_key)
        nat_settings = restarted_settings.get("nat", {}) if isinstance(restarted_settings, dict) else {}
        if nat_settings.get("enabled") is not True or nat_settings.get("requireInitialMapping") is not False:
            raise RuntimeError("best-effort UPnP settings did not persist across restart")
        report["checks"]["upnpRestart"] = {
            "apiKeyStable": True,
            "enabled": True,
            "requireInitialMapping": False,
        }

        workflow = ConsumerNetworkWorkflow(
            search_term=search_term,
            transfer_name=str(transfer["name"]),
            transfer_hash=str(transfer["hash"]),
            transfer_size=int(transfer["size"]),
            network_timeout_seconds=network_timeout_seconds,
            transfer_timeout_seconds=transfer_timeout_seconds,
            complete_transfer=complete_transfer,
        )
        network_proof = run_webui_live_proof(
            base_url=base_url,
            api_key=api_key,
            report_path=report_dir / "network-workflow-webui.json",
            steady_seconds=3.0,
            tab_wait_seconds=0.4,
            timeout_seconds=max(60.0, network_timeout_seconds),
            max_main_thread_busy_ratio=0.25,
            navigation_only=False,
            verify_stale_key_recovery=False,
            consumer_workflow=workflow,
            shutdown_after_proof=True,
        )
        report["checks"]["networkWorkflowWebui"] = network_proof
        shutdown_requested = bool(
            network_proof.get("checks", {}).get("shutdown", {}).get("ok")
        )
        if shutdown_requested:
            try:
                _wait_for_clean_exit(process)
                report["checks"]["networkCleanShutdown"] = True
            except RuntimeError:
                report["checks"]["networkCleanShutdown"] = False
                _stop_process(process)
            process = None
            if log_handle is not None:
                log_handle.close()
                log_handle = None
        if network_proof.get("status") != "passed":
            raise RuntimeError("rendered consumer network workflow failed")
        if not shutdown_requested:
            raise RuntimeError("first-run WebUI proof did not request package shutdown")
        if not report["checks"]["networkCleanShutdown"]:
            raise RuntimeError("hosted package did not exit after network WebUI shutdown")

        workflow_check = network_proof.get("checks", {}).get("consumerNetworkWorkflow", {})
        transfer_check = workflow_check.get("transfer", {}) if isinstance(workflow_check, dict) else {}
        if complete_transfer:
            delivered = incoming_dir / str(transfer["name"])
            if (
                not delivered.is_file()
                or delivered.stat().st_size != int(transfer["size"])
                or sha256_file(delivered) != str(transfer["sha256"])
            ):
                raise RuntimeError("completed consumer download failed exact size/SHA-256 verification")
            report["checks"]["download"] = {
                "triggered": bool(transfer_check.get("triggeredFromRenderedSearchResult")),
                "identityVerified": bool(transfer_check.get("identityVerified")),
                "delivered": True,
                "sizeVerified": True,
                "sha256Verified": True,
            }
        else:
            report["checks"]["download"] = {
                "triggered": bool(transfer_check.get("triggeredFromRenderedSearchResult")),
                "identityVerified": bool(transfer_check.get("identityVerified")),
                "networkActivityRequired": bool(transfer_check.get("networkActivityRequired")),
                "networkActivityObserved": bool(transfer_check.get("networkActivityObserved")),
                "stoppedAfterObservation": bool(transfer_check.get("stoppedFlag")),
            }

        process, log_handle = _start_daemon(
            executable,
            local_app_data=local_app_data,
            log_path=log_path,
        )
        restarted_api_key = _wait_for_profile(settings_path, process, log_path)
        if restarted_api_key != api_key:
            raise RuntimeError("default-profile API key changed across restart")
        _wait_for_rest(base_url, api_key, process, log_path)
        persistence = _persistence_snapshot(base_url, api_key, str(transfer["hash"]))
        if persistence["searchCount"] < 3 or not persistence["transferPresent"]:
            raise RuntimeError("search or transfer state did not persist across restart")
        if complete_transfer and not persistence["transferCompleted"]:
            raise RuntimeError("completed-transfer state did not persist across restart")
        second_proof = run_webui_live_proof(
            base_url=base_url,
            api_key=api_key,
            report_path=report_dir / "restart-webui.json",
            steady_seconds=3.0,
            tab_wait_seconds=0.4,
            timeout_seconds=60.0,
            max_main_thread_busy_ratio=0.25,
            navigation_only=True,
            verify_stale_key_recovery=False,
            shutdown_after_proof=True,
        )
        report["checks"]["persistence"] = {
            **persistence,
            "apiKeyStable": True,
            "renderedWebui": second_proof,
        }
        if second_proof.get("status") != "passed":
            raise RuntimeError("restart rendered consumer workflow failed")
        _wait_for_clean_exit(process)
        process = None
        report["checks"]["cleanShutdown"] = {
            "upnpSetup": True,
            "networkWorkflow": bool(report["checks"]["networkCleanShutdown"]),
            "persistence": True,
        }
        report["status"] = "passed"
    except Exception as exc:  # noqa: BLE001 - retain bounded failure evidence
        report["status"] = "failed"
        report["error"] = {
            "type": type(exc).__name__,
            "message": sanitize_report_text(
                str(exc) or repr(exc),
                (search_term, str(transfer.get("name") or ""), str(transfer.get("hash") or "")),
            ),
        }
    finally:
        if process is not None:
            _stop_process(process)
        if log_handle is not None:
            log_handle.close()
        report["finishedUtc"] = datetime.now(UTC).isoformat()
        persist_consumer_report(report_path, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-zip", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--search-term", required=True)
    parser.add_argument("--max-transfer-bytes", type=int, default=DEFAULT_MAX_TRANSFER_BYTES)
    parser.add_argument("--max-completion-bytes", type=int, default=DEFAULT_MAX_COMPLETION_BYTES)
    parser.add_argument("--complete-transfer", action="store_true")
    parser.add_argument(
        "--replace-running-profile-settings",
        type=Path,
        help="Gracefully suspend an idle port-owning daemon and restore it after the isolated proof.",
    )
    parser.add_argument(
        "--restore-operator-executable",
        type=Path,
        help="Restore this executable when the operator daemon was already stopped before the proof.",
    )
    parser.add_argument("--network-timeout-seconds", type=float, default=DEFAULT_NETWORK_TIMEOUT_SECONDS)
    parser.add_argument("--transfer-timeout-seconds", type=float, default=DEFAULT_TRANSFER_TIMEOUT_SECONDS)
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.restore_operator_executable is not None and args.replace_running_profile_settings is None:
        raise RuntimeError("--restore-operator-executable requires --replace-running-profile-settings")
    suspended: SuspendedDaemon | None = None
    if args.replace_running_profile_settings is not None:
        settings_path = args.replace_running_profile_settings.resolve()
        claimed = any(
            _port_is_claimed(port, udp=udp)
            for port, udp in ((REST_PORT, False), (ED2K_PORT, False), (KAD_PORT, True))
        )
        if claimed:
            suspended = _suspend_existing_daemon(settings_path)
        elif args.restore_operator_executable is not None:
            suspended = SuspendedDaemon(
                executable=args.restore_operator_executable.resolve(),
                settings_path=settings_path,
                api_key=profile_settings_api_key(settings_path),
                graceful_shutdown=False,
            )
        else:
            raise RuntimeError("no running operator daemon was available to suspend")
    report: dict[str, Any]
    try:
        report = run_consumer_live(
            release_zip=args.release_zip.resolve(),
            inputs_path=args.inputs.resolve(),
            search_term=str(args.search_term).strip(),
            max_transfer_bytes=int(args.max_transfer_bytes),
            max_completion_bytes=int(args.max_completion_bytes),
            complete_transfer=bool(args.complete_transfer),
            network_timeout_seconds=float(args.network_timeout_seconds),
            transfer_timeout_seconds=float(args.transfer_timeout_seconds),
        )
    finally:
        if suspended is not None:
            restored_pid = _restore_existing_daemon(suspended)
    if suspended is not None:
        report["operatorDaemonRestored"] = True
        report["operatorDaemonPid"] = restored_pid
        report["operatorDaemonGracefulShutdown"] = suspended.graceful_shutdown
        persist_consumer_report(
            get_workspace_output_root()
            / "reports"
            / "rust-consumer-live"
            / str(report["runId"])
            / "rust-consumer-live-result.json",
            report,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "passed" else 1
