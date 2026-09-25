#!/usr/bin/env python3
"""Smoke the daemon and embedded WebUI from each native release artifact.

This uses a fresh, unshared, non-autoconnecting profile on the native runner.
It never installs a package into the runner's system directories.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

API_KEY = "native-package-smoke"
WEBUI_TITLE = "eMuleBB WebUI"


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(url: str, *, api_key: str | None = None) -> bytes:
    headers = {"X-API-Key": api_key} if api_key else {}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=3) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP {response.status} from {url}")
        return response.read()


def _smoke_binary(binary: Path, webui: Path, temp_root: Path) -> dict[str, object]:
    if not binary.is_file() or not (webui / "index.html").is_file():
        raise RuntimeError("package is missing its daemon or embedded WebUI")
    help_result = subprocess.run(
        [str(binary), "--help"], capture_output=True, text=True, timeout=20, check=True
    )
    if "--profile" not in help_result.stdout or "--rest-bind-addr" not in help_result.stdout:
        raise RuntimeError("packaged daemon CLI is missing beta options")

    profile = temp_root / "profile"
    incoming = temp_root / "incoming"
    profile.mkdir()
    incoming.mkdir()
    port = _available_port()
    (profile / "emulebb-rust-settings.toml").write_text(
        f'[rest]\nbindAddr = "127.0.0.1:{port}"\napiKey = "{API_KEY}"\n',
        encoding="utf-8",
    )
    base_url = f"http://127.0.0.1:{port}"
    log_path = temp_root / "daemon.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(binary), "--profile", str(profile), "--rest-bind-addr", f"127.0.0.1:{port}",
             "--incoming-dir", str(incoming)],
            stdout=log,
            stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": "warn"},
        )
        try:
            deadline = time.monotonic() + 90
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"packaged daemon exited {process.returncode}: {log_path.read_text(encoding='utf-8')[-3000:]}")
                try:
                    html = _request(base_url + "/").decode("utf-8")
                    status = json.loads(_request(base_url + "/api/v1/status", api_key=API_KEY))
                    break
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"packaged daemon did not serve REST/WebUI: {log_path.read_text(encoding='utf-8')[-3000:]}")
                    time.sleep(0.5)
            if WEBUI_TITLE not in html or '<div id="app"></div>' not in html:
                raise RuntimeError("packaged WebUI index is incomplete")
            assets = re.findall(r'(?:src|href)="(\.\/assets\/[^\"]+)"', html)
            if not assets or not all(_request(base_url + "/" + asset.removeprefix("./")) for asset in assets):
                raise RuntimeError("packaged WebUI assets are missing")
            data = status.get("data", status) if isinstance(status, dict) else None
            stats = data.get("stats") if isinstance(data, dict) else None
            if not isinstance(stats, dict) or "ed2kConnected" not in stats:
                raise RuntimeError("packaged REST status is invalid")
            if not (profile / "emulebb-rust-metadata.db").exists():
                raise RuntimeError("packaged daemon did not create its profile database")
            return {"status": "passed", "webuiAssets": len(assets), "restStatus": True,
                    "sharedRoots": 0, "profile": "fresh"}
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def _smoke_windows(asset: Path, temp_root: Path) -> dict[str, object]:
    with zipfile.ZipFile(asset) as archive:
        archive.extractall(temp_root / "unpacked")
    root = temp_root / "unpacked" / "emulebb-rust"
    return _smoke_binary(root / "emulebb-rust.exe", root / "webui", temp_root)


def _smoke_linux_deb(asset: Path, temp_root: Path) -> dict[str, object]:
    extracted = temp_root / "deb"
    subprocess.run(["dpkg-deb", "-x", str(asset), str(extracted)], check=True, timeout=30)
    root = extracted / "usr" / "lib" / "emulebb-rust"
    if not (extracted / "usr" / "bin" / "emulebb-rust-launch").is_file():
        raise RuntimeError("DEB is missing its browser launcher")
    return _smoke_binary(root / "emulebb-rust", root / "webui", temp_root)


def _smoke_linux_appimage(asset: Path, temp_root: Path) -> dict[str, object]:
    extracted = temp_root / "appimage"
    extracted.mkdir()
    subprocess.run([str(asset), "--appimage-extract"], cwd=extracted, check=True, timeout=60,
                   stdout=subprocess.DEVNULL)
    root = extracted / "squashfs-root"
    if not (root / "AppRun").is_file():
        raise RuntimeError("AppImage is missing AppRun")
    package = root / "usr" / "lib" / "emulebb-rust"
    return _smoke_binary(package / "emulebb-rust", package / "webui", temp_root)


def _smoke_macos(asset: Path, temp_root: Path) -> dict[str, object]:
    mount = temp_root / "mounted"
    mount.mkdir()
    subprocess.run(["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount),
                    str(asset)], check=True, timeout=60, stdout=subprocess.DEVNULL)
    try:
        root = mount / "eMuleBB Rust.app" / "Contents" / "MacOS"
        if not (root / "launch").is_file():
            raise RuntimeError("DMG app is missing its browser launcher")
        return _smoke_binary(root / "emulebb-rust", root / "webui", temp_root)
    finally:
        subprocess.run(["hdiutil", "detach", str(mount)], check=True, timeout=60,
                       stdout=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--target-os", required=True, choices=("windows", "linux", "macos"))
    parser.add_argument("--platform", required=True, choices=("x64", "ARM64"))
    args = parser.parse_args()
    stem = f"emulebb-rust-v{args.release_version}"
    arch = args.platform.lower()
    with tempfile.TemporaryDirectory(prefix="emulebb-rust-package-smoke-") as temp:
        temp_root = Path(temp)
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
            reports.append({"asset": name, **smoke(asset, child)})
    print(json.dumps({"schema": "emulebb.rust.package-smoke/1", "platform": f"{args.target_os}-{arch}",
                      "results": reports}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
