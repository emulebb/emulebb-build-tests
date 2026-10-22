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
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness.rust_local_ed2k import (  # noqa: E402
    ed2k_link_with_source,
    file_sha256,
    publish_shared_tree,
    request_json,
    wait_for,
)
from emule_test_harness.rust_webui_live_proof import run_webui_live_proof  # noqa: E402

API_KEY = "native-package-smoke-secret-0001"
WEBUI_TITLE = "eMuleBB WebUI"
TRANSFER_FILE_NAME = "eMuleBB.Native.Package.Transfer.bin"
TRANSFER_SIZE_BYTES = 256 * 1024
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
def _temporary_root():
    path = Path(tempfile.mkdtemp(prefix="emulebb-rust-package-smoke-"))
    try:
        yield path
    finally:
        last_error = None
        for _ in range(10):
            try:
                gc.collect()
                shutil.rmtree(path)
                return
            except FileNotFoundError:
                return
            except PermissionError as exc:
                last_error = exc
                time.sleep(1)
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
    seed = hashlib.sha256(b"emulebb-rust native package transfer smoke").digest()
    with path.open("wb") as handle:
        remaining = size_bytes
        while remaining:
            chunk = seed[: min(remaining, len(seed))]
            handle.write(chunk)
            remaining -= len(chunk)
    return {
        "name": path.name,
        "path": str(path),
        "sizeBytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


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
        transfer = request_json(base_url, "GET", f"/api/v1/transfers/{transfer_hash}", API_KEY)
        observations.append(
            {
                "state": transfer.get("state"),
                "completedBytes": transfer.get("completedBytes"),
                "deliveredPathPresent": bool(transfer.get("deliveredPath")),
            }
        )
        delivered_value = transfer.get("deliveredPath")
        if transfer.get("state") != "completed" or int(transfer.get("completedBytes") or 0) != expected_size:
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
            "state": transfer.get("state"),
            "completedBytes": transfer.get("completedBytes"),
            "deliveredPathWithinIncoming": True,
            "deliveredSha256": delivered_sha256,
            "observations": observations[-20:],
        }

    return wait_for(
        probe,
        timeout_seconds=120.0,
        interval_seconds=0.5,
        description=f"packaged local transfer {transfer_hash} delivery",
    )


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
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP {response.status} from {url}")
        return response.read()


def _smoke_binary(
    binary: Path,
    webui: Path,
    temp_root: Path,
    *,
    rust_repo: Path,
    render_webui: bool,
) -> dict[str, object]:
    if not binary.is_file() or not (webui / "index.html").is_file():
        raise RuntimeError("package is missing its daemon or embedded WebUI")
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
        _wait_for_rest(seeder_base_url, seeder_process, seeder_log_path)
        _wait_for_rest(leecher_base_url, leecher_process, leecher_log_path)
        request_json(seeder_base_url, "POST", "/api/v1/servers/operations/connect", API_KEY)
        request_json(leecher_base_url, "POST", "/api/v1/servers/operations/connect", API_KEY)
        html = _request(seeder_base_url + "/").decode("utf-8")
        status = json.loads(_request(seeder_base_url + "/api/v1/status", api_key=API_KEY))
        if WEBUI_TITLE not in html or '<div id="app"></div>' not in html:
            raise RuntimeError("packaged WebUI index is incomplete")
        assets = _webui_asset_paths(html)
        if not assets or not all(_request(seeder_base_url + asset) for asset in assets):
            raise RuntimeError("packaged WebUI assets are missing")
        data = status.get("data", status) if isinstance(status, dict) else None
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
        transfer_create = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/transfers",
            API_KEY,
            {"link": direct_link, "paused": False},
        )
        transfer_delivery = _wait_for_transfer_delivery(
            leecher_base_url,
            transfer_hash,
            incoming=leecher_incoming,
            expected_size=int(payload["sizeBytes"]),
            expected_sha256=str(payload["sha256"]),
        )

        _graceful_shutdown(leecher_base_url, leecher_process)
        _graceful_shutdown(seeder_base_url, seeder_process)
        return {
            "status": "passed",
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
                "gracefulShutdowns": 2,
            },
        }
    finally:
        _shutdown_or_stop(leecher_base_url, leecher_process)
        _shutdown_or_stop(seeder_base_url, seeder_process)
        for handle in log_handles:
            if not handle.closed:
                handle.close()
        if os.name == "nt":
            # The Windows loader can briefly retain the just-stopped EXE.
            time.sleep(1)


def _smoke_windows(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool
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
    )


def _smoke_linux_deb(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool
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
    )


def _smoke_linux_appimage(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool
) -> dict[str, object]:
    extracted = temp_root / "appimage"
    extracted.mkdir()
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
    )


def _smoke_macos(
    asset: Path, temp_root: Path, *, rust_repo: Path, render_webui: bool
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
    parser.add_argument(
        "--render-webui",
        action="store_true",
        help="Render the packaged WebUI in Chromium and prove stale-key recovery plus all primary views.",
    )
    args = parser.parse_args()
    stem = f"emulebb-rust-v{args.release_version}"
    arch = args.platform.lower()
    with _temporary_root() as temp_root:
        if args.target_os == "windows":
            assets = [(f"{stem}-windows-{arch}.zip", _smoke_windows)]
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
            child = temp_root / str(len(reports))
            child.mkdir()
            reports.append(
                {
                    "asset": name,
                    **smoke(
                        asset,
                        child,
                        rust_repo=args.rust_repo.resolve(),
                        render_webui=args.render_webui,
                    ),
                }
            )
    report = {
        "schema": "emulebb.rust.package-smoke/2",
        "platform": f"{args.target_os}-{arch}",
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
