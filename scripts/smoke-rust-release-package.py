#!/usr/bin/env python3
"""Smoke two daemons, local transfer, and embedded WebUI from each native artifact.

This uses fresh, local-only, non-autoconnecting profiles on the native runner.
It never installs a package into the runner's system directories or launches
the managed ED2K server.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import TextIO

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness.build_provenance import require_clean_git_source  # noqa: E402
from emule_test_harness.rust_local_ed2k import (  # noqa: E402
    ed2k_link_with_source,
    file_sha256,
    publish_shared_tree,
    wait_for,
)
from emule_test_harness.rust_webui_live_proof import run_webui_live_proof  # noqa: E402

API_KEY = "native-package-smoke-secret-0001"
WEBUI_TITLE = "eMuleBB WebUI"
TRANSFER_FILE_NAME = "eMuleBB.Native.Package.Transfer.bin"
TRANSFER_SIZE_BYTES = 12 * 1024 * 1024
PARTIAL_DOWNLOAD_LIMIT_KIBPS = 512
PANEL_ROUTES = {
    "overview": "/api/v1/status",
    "transfers": "/api/v1/transfers",
    "search": "/api/v1/searches",
    "sharing": "/api/v1/shared-directories",
    "shared-files": "/api/v1/shared-files",
    "uploads": "/api/v1/uploads",
    "network": "/api/v1/network",
    "servers": "/api/v1/servers",
    "kad": "/api/v1/kad",
    "categories": "/api/v1/categories",
    "friends": "/api/v1/friends",
    "settings": "/api/v1/app/settings",
    "diagnostics": "/api/v1/diagnostics",
    "logs": "/api/v1/logs?limit=20",
}


@contextmanager
def _temporary_root(*, directory: Path | None = None):
    path = Path(tempfile.mkdtemp(prefix="emulebb-rust-package-smoke-", dir=directory))
    try:
        yield path
    finally:
        last_error = None
        for _ in range(10):
            try:
                gc.collect()
                shutil.rmtree(path)
                break
            except FileNotFoundError:
                break
            except PermissionError as exc:
                last_error = exc
                time.sleep(1)
        else:
            if last_error is not None:
                raise last_error


def _webui_asset_paths(html: str) -> list[str]:
    """Return root-relative asset paths from Vite's relative or rooted output."""

    assets = re.findall(r'(?:src|href)="((?:\./|/)?assets/[^"]+)"', html)
    return ["/" + asset.removeprefix("./").removeprefix("/") for asset in assets]


def _local_p2p_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))
        address = str(probe.getsockname()[0])
    parsed = ipaddress.IPv4Address(address)
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        raise RuntimeError(f"native package smoke requires a usable local IPv4 interface, got {address}")
    return address


def _probe_linux_interface_pinning() -> None:
    """Check the daemon's required socket capability before starting peers.

    QEMU user-mode does not translate every socket option. A successful ELF
    launch therefore cannot establish that the network runtime is executable.
    """
    if sys.platform != "linux":
        return
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        try:
            # Linux UAPI SO_BINDTOIFINDEX = 62 on the supported x64/ARM64 ABIs.
            probe.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTOIFINDEX", 62),
                             socket.if_nametoindex("lo"))
        except OSError as error:
            raise RuntimeError(
                "Linux runtime cannot apply required SO_BINDTOIFINDEX interface pinning: "
                f"{error}. User-mode emulation may lack this socket option; "
                "run the packaged lifecycle on a native runner or a full-system VM. "
                "This is a failed runtime check, not passing platform coverage."
            ) from error


def _available_port(host: str = "127.0.0.1", socket_type: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, socket_type) as listener:
        listener.bind((host, 0))
        return int(listener.getsockname()[1])


def _available_unique_port(
    reserved: set[int],
    *,
    host: str = "127.0.0.1",
    socket_type: int = socket.SOCK_STREAM,
) -> int:
    while True:
        port = _available_port(host, socket_type)
        if port not in reserved:
            reserved.add(port)
            return port


def _write_profile(
    profile: Path,
    *,
    rust_repo: Path,
    incoming: Path,
    rest_port: int,
    ed2k_port: int,
    kad_port: int,
    runtime_server_port: int,
    p2p_ip: str,
) -> None:
    rust_client.write_rust_profile(
        profile,
        rust_repo=rust_repo,
        incoming_dir=incoming,
        rest_addr="127.0.0.1",
        rest_port=rest_port,
        api_key=API_KEY,
        auto_connect=False,
        network_kademlia=False,
        p2p_bind_ip=p2p_ip,
        ed2k_port=ed2k_port,
        kad_port=kad_port,
        server_endpoint=f"127.0.0.1:{runtime_server_port}",
        nat_enabled=False,
        replace_servers=True,
        initial_shared_directory_reload=False,
        local_only_discovery=True,
    )


def _start_daemon(binary: Path, profile: Path, log_path: Path) -> tuple[subprocess.Popen[str], TextIO]:
    log = log_path.open("a", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [str(binary), "--profile", str(profile)],
            stdout=log,
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": "warn"},
            text=True,
        )
    except Exception:
        log.close()
        raise
    return process, log


def _wait_for_rest(base_url: str, process: subprocess.Popen[str], log_path: Path) -> dict[str, object]:
    def probe() -> dict[str, object] | None:
        if process.poll() is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RuntimeError(f"packaged daemon exited {process.returncode}: {tail}")
        try:
            return request_json(base_url, "GET", "/api/v1/app", API_KEY)
        except (OSError, urllib.error.URLError, RuntimeError):
            return None

    return wait_for(
        probe,
        timeout_seconds=90.0,
        interval_seconds=0.5,
        description="packaged daemon REST readiness",
    )


def _graceful_shutdown(base_url: str, process: subprocess.Popen[str]) -> None:
    request_json(
        base_url,
        "POST",
        "/api/v1/app/shutdown",
        API_KEY,
        {"confirmShutdown": True},
    )
    process.wait(timeout=30)
    if process.returncode != 0:
        raise RuntimeError(f"packaged daemon exited {process.returncode} after REST shutdown")


def _stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    rust_client.stop_process_tree(process)


def _shutdown_or_stop(base_url: str, process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        _graceful_shutdown(base_url, process)
    except Exception:
        _stop_process(process)


def _write_transfer_payload(path: Path, size_bytes: int = TRANSFER_SIZE_BYTES) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    # WHY: a repeating payload compresses into one burst and cannot establish a
    # reliable partial checkpoint. SHAKE supplies deterministic incompressible bytes.
    path.write_bytes(hashlib.shake_256(b"emulebb-rust native package transfer smoke").digest(size_bytes))
    return {
        "name": path.name,
        "path": str(path),
        "sizeBytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def _partial_snapshot(details: dict, *, transfer_hash: str, expected_size: int) -> dict | None:
    """Describe verified parts only while the original transfer remains incomplete."""
    transfer, parts = details.get("transfer"), details.get("parts")
    if (not isinstance(transfer, dict) or not isinstance(parts, list)
            or str(transfer.get("hash", "")).lower() != transfer_hash.lower()
            or transfer.get("sizeBytes") != expected_size or transfer.get("partsTotal") != len(parts)):
        raise RuntimeError("Packaged transfer details do not match the expected file")
    completed = transfer.get("completedBytes")
    if type(completed) is not int or not 0 <= completed <= expected_size:
        raise RuntimeError("Packaged transfer has an invalid completed byte count")
    markers = transfer.get("partsProgressText")
    if (not isinstance(markers, str) or len(markers) != len(parts)
            or set(markers) - {"#", "0"}):
        raise RuntimeError("Packaged transfer has invalid verified part markers")
    verified, seen = {}, set()
    for part in parts:
        if (not isinstance(part, dict) or type(part.get("index")) is not int
                or not 0 <= part["index"] < len(parts) or part["index"] in seen
                or type(part.get("size")) is not int or part["size"] <= 0):
            raise RuntimeError("Packaged transfer has invalid part geometry")
        seen.add(part["index"])
        # WHY: fully received bytes can precede hash verification. Bind the
        # persisted checkpoint to the exact verified indices in this snapshot.
        if (markers[part["index"]] == "#" and part.get("complete") is True and part.get("corrupted") is False
                and part.get("completedBytes") == part["size"] and part.get("gapBytes") == 0):
            verified[part["index"]] = part["size"]
    verified_bytes = sum(verified.values())
    if (not verified or type(transfer.get("partsObtained")) is not int
            or transfer["partsObtained"] != markers.count("#") or markers.count("#") != len(verified)
            or not 0 < verified_bytes <= completed < expected_size):
        return None
    return {"partsTotal": len(parts), "verifiedPartIndices": sorted(verified), "verifiedBytes": verified_bytes,
            "completedBytes": completed, "state": transfer.get("state")}


def _wait_for_verified_partial(base_url: str, transfer_hash: str, expected_size: int, *, paused: bool = False) -> dict:
    def probe():
        details = request_json(base_url, "GET", f"/api/v1/transfers/{transfer_hash}/details", API_KEY)
        snapshot = _partial_snapshot(details, transfer_hash=transfer_hash, expected_size=expected_size)
        return snapshot if snapshot and (not paused or snapshot["state"] == "paused") else None
    return wait_for(probe, timeout_seconds=90.0, interval_seconds=0.1,
                    description="packaged verified partial transfer" + (" pause" if paused else ""))


def _app_metadata(app: dict) -> dict:
    if (app.get("name") != "eMuleBB" or app.get("apiVersion") != "v1" or app.get("build") != "release"
            or not isinstance(app.get("version"), str) or not app["version"]
            or app.get("platform") not in {"x64", "arm64"}
            or not isinstance(app.get("lifecycle"), dict) or app["lifecycle"].get("state") != "running"):
        raise RuntimeError("Packaged REST must identify the running release app and CPU")
    return {"appVersion": app["version"], "appBuild": app["build"], "appPlatform": app["platform"]}


def _wait_for_transfer_delivery(
    base_url: str,
    transfer_hash: str,
    *,
    incoming: Path,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, object]:
    observations: list[dict[str, object]] = []

    def probe() -> dict[str, object] | None:
        # WHY: successful promotion removes the active transfer. The completed
        # shared-file registration and its exact delivered bytes are durable evidence.
        shared = request_json(base_url, "GET", f"/api/v1/shared-files/{transfer_hash}", API_KEY)
        observations.append(
            {
                "complete": shared.get("complete"),
                "sizeBytes": shared.get("sizeBytes"),
                "deliveredPathPresent": bool(shared.get("path")),
            }
        )
        delivered_value = shared.get("path")
        if (
            str(shared.get("hash") or "").lower() != transfer_hash.lower()
            or shared.get("complete") is not True
            or shared.get("partFile") is not False
            or int(shared.get("sizeBytes") or 0) != expected_size
        ):
            return None
        if not delivered_value:
            return None
        delivered = Path(str(delivered_value))
        if not delivered.is_file():
            return None
        if delivered.resolve().parent != incoming.resolve():
            raise RuntimeError(f"packaged transfer was delivered outside the configured incoming directory: {delivered}")
        delivered_sha256 = file_sha256(delivered)
        if delivered.stat().st_size != expected_size or delivered_sha256 != expected_sha256:
            raise RuntimeError("packaged transfer delivered bytes do not match the shared payload")
        return {
            "hash": transfer_hash,
            "state": "completed",
            "completedBytes": expected_size,
            "sharedFileRegistered": True,
            "deliveredPathWithinIncoming": True,
            "deliveredSha256": delivered_sha256,
            "observations": observations[-20:],
        }

    try:
        return wait_for(
            probe,
            timeout_seconds=120.0,
            interval_seconds=0.5,
            description=f"packaged local transfer {transfer_hash} delivery",
        )
    except RuntimeError as error:
        try:
            transfers = request_json(base_url, "GET", "/api/v1/transfers", API_KEY)
            detail = json.dumps(transfers, sort_keys=True)[-16000:]
        except Exception as snapshot_error:
            detail = str(snapshot_error)
        raise RuntimeError(f"{error}; final transfer state: {detail}") from error


def _request(
    url: str,
    *,
    api_key: str | None = None,
    method: str = "GET",
    json_body: dict[str, object] | None = None,
) -> bytes:
    headers = {"X-API-Key": api_key} if api_key else {}
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=3) as response:
        if response.status not in ((200,) if method == "GET" else (200, 201, 202)):
            raise RuntimeError(f"unexpected HTTP {response.status} from {url}")
        return response.read()


def request_json(base_url: str, method: str, path: str, api_key: str, body: dict | None = None) -> dict:
    """Use this smoke's HTTP transport and require the current REST envelope."""
    document = json.loads(_request(base_url + path, method=method, api_key=api_key, json_body=body))
    if (not isinstance(document, dict) or not isinstance(document.get("data"), dict)
            or not isinstance(document.get("meta"), dict) or document["meta"].get("apiVersion") != "v1"):
        raise RuntimeError("Packaged REST must return the current v1 data/meta envelope")
    return document["data"]


def _reject_offline_profile_writers(binary: Path, profile: Path, base_url: str,
                                    temp_root: Path) -> list[dict[str, object]]:
    """Probe the live owner's CLI boundary with valid, disposable offline inputs."""
    from emule_test_harness.emule_profile_export import ExportJob
    from emule_test_harness.profile_exchange import write_exchange
    from emule_test_harness.profile_import_audit import create_import_fixture

    fixture = temp_root / "ownership-import"
    create_import_fixture(fixture)
    # Export only hashes from the stock fixture. Its share paths are a separate
    # native directory-list input and need no stock Windows path mapping.
    hashes = fixture / "hashes"
    hashes.mkdir()
    for name in ("known.met", "known2_64.met"):
        shutil.copyfile(fixture / "stock" / "config" / name, hashes / name)
    target_platform = {"Windows": "windows", "Linux": "unix", "Darwin": "macos"}[platform.system()]
    archive = fixture / "hashes.sqlite"
    write_exchange(ExportJob(fixture / "windows.toml", hashes, "stock", target_platform, archive, ()),
                   hashes_only=True)
    directory_list = fixture / "shared.txt"
    directory_list.write_text(f"{fixture / 'shared'}\n", encoding="utf-8")

    bootstrap = profile / "emulebb-rust-settings.toml"
    before_bootstrap = file_sha256(bootstrap)
    before_settings = request_json(base_url, "GET", "/api/v1/app/settings", API_KEY)
    before_roots = request_json(base_url, "GET", "/api/v1/shared-directories", API_KEY)["roots"]
    contenders = []
    for command, arguments in (
        ("import-emule-profile", ["--hashes-only", str(archive)]),
        ("import-shared-directories", [str(directory_list)]),
        ("reconcile-shared-files", []),
    ):
        result = subprocess.run(
            [str(binary), "--profile", str(profile), command, *arguments],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
        )
        if (result.returncode == 0 or result.stdout.strip()
                or "profile is already in use:" not in result.stderr
                or "stop its daemon or offline command before retrying" not in result.stderr):
            raise RuntimeError(f"{command} did not reject the busy profile before offline work "
                               f"(exit {result.returncode}): {result.stderr[-2000:]}")
        contenders.append({"command": command, "exitCode": result.returncode, "profileBusy": True})
    if (file_sha256(bootstrap) != before_bootstrap
            or request_json(base_url, "GET", "/api/v1/app/settings", API_KEY) != before_settings
            or request_json(base_url, "GET", "/api/v1/shared-directories", API_KEY)["roots"] != before_roots):
        raise RuntimeError("denied offline commands changed the owned profile's bootstrap, settings or roots")
    return contenders


def _smoke_binary(
    binary: Path,
    webui: Path,
    temp_root: Path,
    *,
    rust_repo: Path,
    render_webui: bool,
    verify_profile_ownership: bool = False,
) -> dict[str, object]:
    if not binary.is_file() or not (webui / "index.html").is_file():
        raise RuntimeError("package is missing its daemon or embedded WebUI")
    _probe_linux_interface_pinning()
    help_result = subprocess.run(
        [str(binary), "--help"], capture_output=True, text=True, timeout=20, check=True
    )
    required_options = ("--profile", "--p2p-bind-interface")
    if any(option not in help_result.stdout for option in required_options):
        raise RuntimeError("packaged daemon CLI is missing beta options")

    reserved_ports: set[int] = set()
    p2p_ip = _local_p2p_ip()
    seeder_profile = temp_root / "seeder-profile"
    leecher_profile = temp_root / "leecher-profile"
    seeder_incoming = temp_root / "seeder-incoming"
    leecher_incoming = temp_root / "leecher-incoming"
    seeder_rest_port = _available_unique_port(reserved_ports)
    seeder_ed2k_port = _available_unique_port(reserved_ports, host=p2p_ip)
    seeder_kad_port = _available_unique_port(reserved_ports, host=p2p_ip, socket_type=socket.SOCK_DGRAM)
    leecher_rest_port = _available_unique_port(reserved_ports)
    leecher_ed2k_port = _available_unique_port(reserved_ports, host=p2p_ip)
    leecher_kad_port = _available_unique_port(reserved_ports, host=p2p_ip, socket_type=socket.SOCK_DGRAM)
    runtime_server_port = _available_unique_port(reserved_ports)
    seeder_base_url = f"http://127.0.0.1:{seeder_rest_port}"
    leecher_base_url = f"http://127.0.0.1:{leecher_rest_port}"
    seeder_log_path = temp_root / "seeder.log"
    leecher_log_path = temp_root / "leecher.log"
    _write_profile(
        seeder_profile,
        rust_repo=rust_repo,
        incoming=seeder_incoming,
        rest_port=seeder_rest_port,
        ed2k_port=seeder_ed2k_port,
        kad_port=seeder_kad_port,
        runtime_server_port=runtime_server_port,
        p2p_ip=p2p_ip,
    )
    _write_profile(
        leecher_profile,
        rust_repo=rust_repo,
        incoming=leecher_incoming,
        rest_port=leecher_rest_port,
        ed2k_port=leecher_ed2k_port,
        kad_port=leecher_kad_port,
        runtime_server_port=runtime_server_port,
        p2p_ip=p2p_ip,
    )

    seeder_process: subprocess.Popen[str] | None = None
    leecher_process: subprocess.Popen[str] | None = None
    log_handles: list[TextIO] = []
    try:
        seeder_process, seeder_log = _start_daemon(binary, seeder_profile, seeder_log_path)
        leecher_process, leecher_log = _start_daemon(binary, leecher_profile, leecher_log_path)
        log_handles.extend((seeder_log, leecher_log))
        app = _app_metadata(_wait_for_rest(seeder_base_url, seeder_process, seeder_log_path))
        if _app_metadata(_wait_for_rest(leecher_base_url, leecher_process, leecher_log_path)) != app:
            raise RuntimeError("Packaged peers disagree about their release identity")
        contenders = None
        if verify_profile_ownership:
            contenders = _reject_offline_profile_writers(binary, leecher_profile, leecher_base_url, temp_root)
        request_json(seeder_base_url, "POST", "/api/v1/servers/operations/connect", API_KEY)
        request_json(leecher_base_url, "POST", "/api/v1/servers/operations/connect", API_KEY)
        html = _request(seeder_base_url + "/").decode("utf-8")
        status = json.loads(_request(seeder_base_url + "/api/v1/status", api_key=API_KEY))
        if WEBUI_TITLE not in html or '<div id="app"></div>' not in html:
            raise RuntimeError("packaged WebUI index is incomplete")
        assets = _webui_asset_paths(html)
        if not assets or not all(_request(seeder_base_url + asset) for asset in assets):
            raise RuntimeError("packaged WebUI assets are missing")
        data = status.get("data") if isinstance(status, dict) else None
        stats = data.get("stats") if isinstance(data, dict) else None
        if not isinstance(stats, dict) or "ed2kConnected" not in stats:
            raise RuntimeError("packaged REST status is invalid")
        panel_routes = {}
        for panel, path in PANEL_ROUTES.items():
            response = json.loads(_request(seeder_base_url + path, api_key=API_KEY))
            if not isinstance(response, dict):
                raise RuntimeError(f"{panel} panel REST backend returned non-object JSON")
            panel_routes[panel] = path
        rendered_webui = None
        if render_webui:
            rendered_webui = run_webui_live_proof(
                base_url=seeder_base_url,
                api_key=API_KEY,
                report_path=temp_root / "rendered-webui-proof.json",
                steady_seconds=3.0,
                tab_wait_seconds=0.25,
                timeout_seconds=30.0,
                max_main_thread_busy_ratio=0.25,
                navigation_only=True,
                verify_stale_key_recovery=True,
            )
            if rendered_webui.get("status") != "passed":
                raise RuntimeError(f"packaged rendered WebUI proof failed: {rendered_webui!r}")
        if not (seeder_profile / "emulebb-rust-metadata.db").exists():
            raise RuntimeError("packaged daemon did not create its profile database")
        if not (leecher_profile / "emulebb-rust-metadata.db").exists():
            raise RuntimeError("packaged leecher did not create its profile database")

        payload = _write_transfer_payload(temp_root / "shared" / TRANSFER_FILE_NAME)
        shared_tree = publish_shared_tree(
            seeder_base_url,
            API_KEY,
            root=Path(str(payload["path"])).parent,
            file_name=TRANSFER_FILE_NAME,
            timeout_seconds=60.0,
        )
        shared_files = shared_tree.get("sharedFiles")
        matched = shared_files.get("matched") if isinstance(shared_files, dict) else None
        if not isinstance(matched, dict):
            raise RuntimeError("packaged seeder did not expose the transfer payload")
        transfer_hash = str(matched.get("hash") or "").lower()
        direct_link = ed2k_link_with_source(
            str(matched.get("ed2kLink") or ""),
            p2p_ip,
            seeder_ed2k_port,
        )
        previous_limit = request_json(leecher_base_url, "GET", "/api/v1/app/settings", API_KEY)["core"]["downloadLimitKiBps"]
        if type(previous_limit) is not int or not 1 <= previous_limit <= 4294967294:
            raise RuntimeError("Packaged REST returned an invalid download limit")
        request_json(leecher_base_url, "PATCH", "/api/v1/app/settings", API_KEY,
                     {"core": {"downloadLimitKiBps": PARTIAL_DOWNLOAD_LIMIT_KIBPS}})
        transfer_create = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/transfers",
            API_KEY,
            {"link": direct_link, "paused": False},
        )
        _wait_for_verified_partial(leecher_base_url, transfer_hash, int(payload["sizeBytes"]))
        request_json(leecher_base_url, "POST", f"/api/v1/transfers/{transfer_hash}/operations/pause", API_KEY)
        before = _wait_for_verified_partial(leecher_base_url, transfer_hash, int(payload["sizeBytes"]), paused=True)
        _graceful_shutdown(leecher_base_url, leecher_process)
        leecher_process = None
        leecher_log.close()
        leecher_process, leecher_log = _start_daemon(binary, leecher_profile, leecher_log_path)
        log_handles.append(leecher_log)
        if _app_metadata(_wait_for_rest(leecher_base_url, leecher_process, leecher_log_path)) != app:
            raise RuntimeError("Restarted packaged daemon has a different release identity")
        # Read durable progress before reconnecting or resuming; a new transfer
        # or newly downloaded parts must not conceal missing persisted state.
        after = _partial_snapshot(request_json(leecher_base_url, "GET", f"/api/v1/transfers/{transfer_hash}/details", API_KEY),
                                  transfer_hash=transfer_hash, expected_size=int(payload["sizeBytes"]))
        if (after is None or after["state"] != "paused"
                or after["partsTotal"] != before["partsTotal"]
                or not set(before["verifiedPartIndices"]).issubset(after["verifiedPartIndices"])
                or after["verifiedBytes"] < before["verifiedBytes"]):
            raise RuntimeError("Verified partial data did not survive the same-profile packaged restart")
        settings = request_json(leecher_base_url, "GET", "/api/v1/app/settings", API_KEY)
        if settings["core"]["downloadLimitKiBps"] != PARTIAL_DOWNLOAD_LIMIT_KIBPS:
            raise RuntimeError("Packaged restart did not preserve the download setting")
        request_json(leecher_base_url, "POST", "/api/v1/servers/operations/connect", API_KEY)
        request_json(leecher_base_url, "PATCH", "/api/v1/app/settings", API_KEY, {"core": {"downloadLimitKiBps": previous_limit}})
        request_json(leecher_base_url, "POST", f"/api/v1/transfers/{transfer_hash}/operations/resume", API_KEY)
        transfer_delivery = _wait_for_transfer_delivery(
            leecher_base_url,
            transfer_hash,
            incoming=leecher_incoming,
            expected_size=int(payload["sizeBytes"]),
            expected_sha256=str(payload["sha256"]),
        )

        _graceful_shutdown(leecher_base_url, leecher_process)
        _graceful_shutdown(seeder_base_url, seeder_process)
        ownership = {}
        if contenders is not None:
            from emule_test_harness.profile_import_audit import run_json

            run_json([str(binary), "--profile", str(leecher_profile), "reconcile-shared-files"], 20)
            ownership["profileOwnership"] = {
                "contenders": contenders,
                "bootstrapSettingsAndRootsUnchanged": True,
                "reconcileAfterShutdown": True,
            }
        return {
            "status": "passed",
            **app,
            **ownership,
            "webuiAssets": len(assets),
            "restStatus": True,
            "webuiPanelBackends": panel_routes,
            "gracefulShutdown": True,
            "sharedRoots": 1,
            "profile": "fresh-local-only",
            "renderedWebui": bool(rendered_webui),
            "localTransfer": {
                "payload": {
                    "name": payload["name"],
                    "sizeBytes": payload["sizeBytes"],
                    "sha256": payload["sha256"],
                },
                "sharedFile": {
                    "hash": transfer_hash,
                    "name": matched.get("name"),
                    "sizeBytes": matched.get("sizeBytes"),
                },
                "transferAccepted": bool(transfer_create),
                "delivery": transfer_delivery,
                "sourceDiscovery": "ed2k-link-direct-source",
                "publicDiscoveryDisabled": True,
                "partialRestart": {"before": before, "after": after, "sameProfile": True, "sameBinary": True,
                                   "resumeRequested": True, "downloadLimitRestored": True},
                "gracefulShutdowns": 3,
            },
        }
    except Exception as error:
        # Preserve bounded diagnostics before temporary profiles are removed.
        # REST operation errors can contain less context than the daemon logs.
        for name, base_url, log_path in (
            ("seeder", seeder_base_url, seeder_log_path),
            ("leecher", leecher_base_url, leecher_log_path),
        ):
            _attach_failure_diagnostics(error, name, base_url, log_path)
        raise
    finally:
        _shutdown_or_stop(leecher_base_url, leecher_process)
        _shutdown_or_stop(seeder_base_url, seeder_process)
        for handle in log_handles:
            if not handle.closed:
                handle.close()
        if os.name == "nt":
            # The Windows loader can briefly retain the just-stopped EXE.
            time.sleep(1)


def _attach_failure_diagnostics(error: Exception, name: str, base_url: str, log_path: Path) -> None:
    """Retain bounded daemon diagnostics without masking the original failure."""
    try:
        logs = request_json(base_url, "GET", "/api/v1/logs?limit=20", API_KEY)
        error.add_note(f"{name} REST logs: {json.dumps(logs, ensure_ascii=True)[-12000:]}")
    except Exception as diagnostic_error:
        error.add_note(f"{name} REST diagnostics unavailable: {diagnostic_error}")
    try:
        error.add_note(f"{name} process log: {log_path.read_text(encoding='utf-8', errors='replace')[-12000:]}")
    except OSError as diagnostic_error:
        error.add_note(f"{name} process diagnostics unavailable: {diagnostic_error}")


def _smoke_windows(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool,
    verify_profile_ownership: bool = False,
) -> dict[str, object]:
    with zipfile.ZipFile(asset) as archive:
        archive.extractall(temp_root / "unpacked")
    root = temp_root / "unpacked" / "emulebb-rust"
    return _smoke_binary(
        root / "emulebb-rust.exe",
        root / "webui",
        temp_root,
        rust_repo=rust_repo,
        render_webui=render_webui,
        verify_profile_ownership=verify_profile_ownership,
    )


def _extract_portable_stream(stream, destination: Path) -> None:
    """Extract only regular files/directories within the portable package root."""
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or not name.parts
                    or name.parts[0] != "emulebb-rust" or not (member.isfile() or member.isdir())):
                raise RuntimeError(f"unsafe portable archive member: {member.name}")
            archive.extract(member, destination, filter="data")


def _verify_package_manifest(asset: Path, expected_source_sha: str, expected_version: str,
                              expected_target: str | None = None) -> dict:
    """Verify canonical package provenance and SBOM bytes before any launch."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None:
        raise RuntimeError("Package smoke requires a full lowercase source SHA")
    manifest = json.loads(asset.with_name(asset.name + ".manifest.json").read_text(encoding="utf-8"))
    if (manifest.get("schema") != "emulebb.rust.package/2" or manifest.get("version") != expected_version
            or manifest.get("asset") != asset.name or manifest.get("sha256") != file_sha256(asset)
            or manifest.get("sourceDirty") is not False
            or (expected_target is not None and manifest.get("target") != expected_target)
            or manifest.get("source", {}).get("emulebbRust", {}).get("commit") != expected_source_sha):
        raise RuntimeError("Package checksum or source provenance mismatch")
    sbom_name = manifest.get("sbom")
    if (not isinstance(sbom_name, str) or not sbom_name or Path(sbom_name).name != sbom_name
            or "/" in sbom_name or "\\" in sbom_name
            or not (asset.parent / sbom_name).is_file()
            or file_sha256(asset.parent / sbom_name) != manifest.get("sbomSha256")):
        raise RuntimeError("Package SBOM checksum or path does not match provenance")
    return manifest


def _smoke_linux_archive(asset: Path, temp_root: Path, *, rust_repo: Path,
                         render_webui: bool, verify_profile_ownership: bool = False) -> dict[str, object]:
    with subprocess.Popen(["zstd", "--decompress", "--stdout", "--", str(asset)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            _extract_portable_stream(process.stdout, temp_root)
        except BaseException:
            process.kill()
            process.communicate()
            raise
        _, errors = process.communicate()
        if process.returncode:
            raise RuntimeError(f"portable archive decompression failed: {errors.decode(errors='replace')[-2000:]}")
    root = temp_root / "emulebb-rust"
    result = _smoke_binary(root / "emulebb-rust", root / "webui", temp_root,
                           rust_repo=rust_repo, render_webui=render_webui,
                           verify_profile_ownership=verify_profile_ownership)
    return result


def _smoke_linux_deb(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool,
    verify_profile_ownership: bool = False,
) -> dict[str, object]:
    extracted = temp_root / "deb"
    subprocess.run(["dpkg-deb", "-x", str(asset), str(extracted)], check=True, timeout=30)
    root = extracted / "usr" / "lib" / "emulebb-rust"
    if not (extracted / "usr" / "bin" / "emulebb-rust-launch").is_file():
        raise RuntimeError("DEB is missing its browser launcher")
    return _smoke_binary(
        root / "emulebb-rust",
        root / "webui",
        temp_root,
        rust_repo=rust_repo,
        render_webui=render_webui,
        verify_profile_ownership=verify_profile_ownership,
    )


def _smoke_linux_appimage(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool,
    verify_profile_ownership: bool = False,
) -> dict[str, object]:
    extracted = temp_root / "appimage"
    extracted.mkdir()
    os.chmod(asset, asset.stat().st_mode | stat.S_IXUSR)
    subprocess.run(
        [str(asset), "--appimage-extract"],
        cwd=extracted,
        check=True,
        timeout=60,
        stdout=subprocess.DEVNULL,
    )
    root = extracted / "squashfs-root"
    if not (root / "AppRun").is_file():
        raise RuntimeError("AppImage is missing AppRun")
    package = root / "usr" / "lib" / "emulebb-rust"
    return _smoke_binary(
        package / "emulebb-rust",
        package / "webui",
        temp_root,
        rust_repo=rust_repo,
        render_webui=render_webui,
        verify_profile_ownership=verify_profile_ownership,
    )


def _smoke_macos(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool,
    verify_profile_ownership: bool = False,
) -> dict[str, object]:
    mount = temp_root / "mounted"
    mount.mkdir()
    subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount),
                    str(asset)], check=True, timeout=60, stdout=subprocess.DEVNULL)
    try:
        root = mount / "eMuleBB Rust.app" / "Contents" / "MacOS"
        if not (root / "launch").is_file():
            raise RuntimeError("DMG app is missing its browser launcher")
        return _smoke_binary(
            root / "emulebb-rust",
            root / "webui",
            temp_root,
            rust_repo=rust_repo,
            render_webui=render_webui,
            verify_profile_ownership=verify_profile_ownership,
        )
    finally:
        subprocess.run(["hdiutil", "detach", str(mount)], check=True, timeout=60,
                       stdout=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--rust-repo", type=Path, required=True)
    parser.add_argument("--report-path", type=Path)
    parser.add_argument("--target-os", required=True, choices=("windows", "linux", "macos"))
    parser.add_argument("--platform", required=True, choices=("x64", "ARM64"))
    parser.add_argument("--linux-libc", choices=("gnu", "musl"), help="Test the selected portable Linux archive.")
    parser.add_argument("--expected-source-sha", required=True, help="Full clean source revision required for every tested package.")
    parser.add_argument(
        "--render-webui",
        action="store_true",
        help="Render the packaged WebUI in Chromium and prove stale-key recovery plus all primary views.",
    )
    parser.add_argument(
        "--verify-profile-ownership",
        action="store_true",
        help="Check that the running packaged daemon rejects offline writers to its disposable profile.",
    )
    args = parser.parse_args()
    if args.linux_libc and args.target_os != "linux":
        parser.error("--linux-libc requires --target-os linux")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha) is None:
        parser.error("--expected-source-sha must be a full lowercase commit SHA")
    harness_before = require_clean_git_source(REPO_ROOT, label="Package smoke harness")
    stem = f"emulebb-rust-v{args.release_version}"
    arch = args.platform.lower()
    expected_target = None
    if args.verify_profile_ownership:
        from emule_test_harness.paths import get_workspace_output_root

        output = get_workspace_output_root()
        if not output.is_dir():
            parser.error("--verify-profile-ownership requires an existing workspace output directory")
        if args.report_path and not args.report_path.resolve().is_relative_to(output):
            parser.error("--verify-profile-ownership report must stay under the workspace output root")
        temporary = _temporary_root(directory=output)
    else:
        temporary = _temporary_root()
    with temporary as temp_root:
        if args.target_os == "windows":
            assets = [(f"{stem}-windows-{arch}.zip", _smoke_windows)]
        elif args.target_os == "linux" and args.linux_libc:
            package_arch = "amd64" if arch == "x64" else "arm64"
            expected_target = f"{'x86_64' if arch == 'x64' else 'aarch64'}-unknown-linux-{args.linux_libc}"
            assets = [(f"{stem}-linux-{package_arch}-{args.linux_libc}.tar.zst", _smoke_linux_archive)]
        elif args.target_os == "linux":
            deb_arch, image_arch = ("amd64", "x86_64") if arch == "x64" else ("arm64", "aarch64")
            assets = [(f"{stem}-linux-{deb_arch}.deb", _smoke_linux_deb),
                      (f"{stem}-linux-{image_arch}.AppImage", _smoke_linux_appimage)]
        else:
            assets = [(f"{stem}-macos-{arch}.dmg", _smoke_macos)]
        reports = []
        for name, smoke in assets:
            asset = args.release_dir / name
            if not asset.is_file():
                raise RuntimeError(f"native package is missing: {asset}")
            manifest = _verify_package_manifest(asset, args.expected_source_sha, args.release_version, expected_target)
            child = temp_root / str(len(reports))
            child.mkdir()
            result = smoke(
                asset, child, rust_repo=args.rust_repo.resolve(), render_webui=args.render_webui,
                verify_profile_ownership=args.verify_profile_ownership,
            )
            if (result.get("status") != "passed" or result.get("appVersion") != args.release_version or result.get("appBuild") != "release"
                    or result.get("appPlatform") != ("x64" if arch == "x64" else "arm64")):
                raise RuntimeError("Running package version/build/CPU does not match the selected release asset")
            if _verify_package_manifest(asset, args.expected_source_sha, args.release_version, expected_target) != manifest:
                raise RuntimeError("Package bytes or provenance changed during smoke validation")
            reports.append({"asset": name, "assetSha256": manifest["sha256"], "sourceSha": args.expected_source_sha,
                            "packageManifestSha256": file_sha256(asset.with_name(asset.name + ".manifest.json")),
                            "sbomSha256": manifest["sbomSha256"], **result})
    # WHY: a public pass must identify the exact clean validator, including
    # changes made while the packaged daemons and their restart proof ran.
    harness_after = require_clean_git_source(REPO_ROOT, label="Package smoke harness")
    if harness_after.revision != harness_before.revision:
        raise RuntimeError("Package smoke harness revision changed during validation")
    machine = platform.machine().lower()
    native_arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    native_os = {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}.get(platform.system())
    hosted = os.environ.get("GITHUB_ACTIONS") == "true"
    report = {
        "schema": "emulebb.rust.package-smoke/3", "status": "passed", "sourceSha": args.expected_source_sha,
        "harnessSha": harness_before.revision,
        "origin": "github-actions" if hosted else "local-development",
        "workflow": {key: os.environ.get(name) for key, name in
                     {"repository": "GITHUB_REPOSITORY", "runId": "GITHUB_RUN_ID",
                      "runAttempt": "GITHUB_RUN_ATTEMPT", "workflowSha": "GITHUB_WORKFLOW_SHA"}.items()} if hosted else None,
        "runtimeExecution": "native" if (native_arch, native_os) == (arch, args.target_os) else "emulated",
        "platform": f"{args.target_os}-{arch}" + (f"-{args.linux_libc}" if args.linux_libc else ""),
        "results": reports,
    }
    report_json = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report_path:
        args.report_path.parent.mkdir(parents=True, exist_ok=True)
        args.report_path.write_text(report_json, encoding="utf-8")
    print(report_json, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
