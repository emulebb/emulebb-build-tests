"""aMuTorrent eMuleBB controller adapter driven against a live emulebb-rust client.

Proves aMuTorrent's real `EmulebbManager` adapter manages the Rust client through
the canonical `/api/v1` contract (connect, categories, snapshot, shared files,
search) with no private adapters, aliases, or shims.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from emule_test_harness import rust_client
from emule_test_harness import rust_metadata

API_KEY = "amutorrent-rust-controller-key"
SEED_HASH = "00112233445566778899aabbccddeeff"


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def free_lan_port(host: str) -> int:
    for port in range(31000, 45000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                tcp.bind((host, port))
            return port
        except OSError:
            continue
    raise RuntimeError("no free LAN port")


def wait_for_rest(base_url: str, process: subprocess.Popen[str], output_path: Path) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"emulebb-rust exited early ({process.returncode})\n"
                f"{output_path.read_text(encoding='utf-8', errors='replace')}"
            )
        try:
            request = urllib.request.Request(f"{base_url}/api/v1/app", headers={"X-API-Key": API_KEY})
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5):
                return
        except urllib.error.URLError:
            time.sleep(0.2)
    raise AssertionError("emulebb-rust REST API did not become ready")


def test_amutorrent_adapter_drives_rust_controller(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    if shutil.which("node") is None:
        pytest.skip("node is not available")
    repo = workspace_root() / "repos" / "emulebb-rust"
    amutorrent = workspace_root() / "repos" / "amutorrent"
    driver = amutorrent / "scripts" / "emulebb-rust-controller-check.cjs"
    if not repo.is_dir() or not driver.is_file():
        pytest.skip("emulebb-rust or amutorrent repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    profile_dir = tmp_path / "profile"
    output_path = tmp_path / "emulebb-rust.out"
    port = free_lan_port(lan_host)
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=repo,
        rest_addr=lan_host,
        rest_port=port,
        api_key=API_KEY,
    )
    metadata_path = profile_dir / rust_client.RUST_PROFILE_METADATA_FILE
    rust_metadata.seed_indexed_file(
        metadata_path,
        ed2k_hash=SEED_HASH,
        name="Scenario.File.bin",
        size_bytes=4096,
        content_type="archive",
        availability_score=3,
    )

    process = rust_client.start_rust_client(repo, profile_dir, output_path)
    try:
        base_url = f"http://{lan_host}:{port}"
        wait_for_rest(base_url, process, output_path)

        completed = subprocess.run(
            [
                "node",
                str(driver),
                f"--host={lan_host}",
                f"--port={port}",
                f"--api-key={API_KEY}",
                "--query=scenario file",
            ],
            cwd=str(amutorrent),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        last_line = (completed.stdout or "").strip().splitlines()[-1] if completed.stdout else ""
        assert completed.returncode == 0, f"driver failed:\n{completed.stdout}"
        report = json.loads(last_line)
        assert report["ok"] is True, completed.stdout
        assert report["connected"] is True
        assert report["categories"] >= 1
        # snapshot + paginated shared-files round-tripped through the adapter.
        assert {"downloads", "sharedFiles", "uploads"} <= report.keys()
        # the seeded indexed file is discoverable via the controller's search.
        assert report["searchResults"] >= 1, completed.stdout
        assert report["searchStatus"] == "complete"
    finally:
        rust_client.stop_process_tree(process, timeout_seconds=5)
