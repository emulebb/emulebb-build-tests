"""Live ED2K campaign for the goed2k UDP search + source-lookup feature.

Drives the server's UDP global path directly (OP_GLOBSEARCHREQ2 -> 0x99,
OP_GLOBGETSOURCES -> 0x9b) from a real UDP socket on X_LOCAL_IP, asserting both
the decoded replies and the server packet trace. This is the feature-specific
campaign for UDP search/sources; MFC and emulebb-rust cover the TCP paths.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import time
from pathlib import Path

import pytest

from emule_test_harness import goed2k

pytestmark = pytest.mark.live

ED2K_HDR = 0xE3
OP_SEARCH_REQ2 = 0x92
OP_SEARCH_RES = 0x99
OP_GETSOURCES = 0x9A
OP_FOUNDSOURCES = 0x9B
SEED_HASH = "00112233445566778899AABBCCDDEEFF"
SOURCE_HOST = "203.0.113.10"
SOURCE_PORT = 4662


def _free_lan_port(host: str, taken: set[int]) -> int:
    for _ in range(200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((host, 0))
            port = probe.getsockname()[1]
        if port + 4 > 65535 or port in taken or (port + 4) in taken:
            continue
        # The goed2k server derives its UDP port as ed2k_port+4; ensure that port
        # is bindable too (Windows reserves some high ports), else the server's UDP
        # listener fails and the datagram test gets WinError 10054.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_probe:
                udp_probe.bind((host, port + 4))
        except OSError:
            continue
        taken.add(port)
        return port
    raise RuntimeError("no free LAN port found")


def _udp_roundtrip(sock: socket.socket, target: tuple[str, int], payload: bytes) -> bytes | None:
    deadline = time.time() + 6.0
    while time.time() < deadline:
        sock.sendto(payload, target)
        sock.settimeout(0.3)
        try:
            data, _ = sock.recvfrom(8192)
            return data
        except socket.timeout:
            continue
    return None


def test_goed2k_udp_search_and_sources_live() -> None:
    host = os.environ.get("X_LOCAL_IP")
    if not host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound live ED2K traffic")
    output_root = os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    if not output_root:
        pytest.skip("EMULEBB_WORKSPACE_OUTPUT_ROOT is required")
    out = Path(output_root)
    server_exe_override = goed2k.env_ed2k_server_exe_override()
    if server_exe_override is None and shutil.which("go") is None:
        pytest.skip("goed2k-server exe override missing and go is unavailable to build it")

    run_dir = out / "artifacts" / "live-udp-search"
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True, exist_ok=True)

    goed2k.stop_server_processes()
    time.sleep(0.5)

    taken: set[int] = set()
    ed2k_port = _free_lan_port(host, taken)
    admin_port = _free_lan_port(host, taken)
    token = "udp-live-token"

    launch = goed2k.launch_ed2k_server(
        workspace_root=Path(__file__).resolve().parents[4] / "workspaces" / "workspace",
        server_dir=run_dir / "server",
        ed2k_port=ed2k_port,
        admin_port=admin_port,
        token=token,
        admin_address=host,
        ed2k_address=host,
        exe_override=server_exe_override,
        catalog_files=[
            goed2k.catalog_file(
                file_hash=SEED_HASH,
                name="ubuntu-24.04-desktop-amd64.iso",
                size=6144000000,
                file_type="Iso",
                extension="iso",
                endpoints=[{"host": SOURCE_HOST, "port": SOURCE_PORT}],
            )
        ],
        packet_trace=True,
    )
    trace_path = launch.server_dir / "packets.trace.jsonl"

    search_hashes: list[str] = []
    sources: list[tuple[str, int]] = []
    desc_name: list[str] = []
    try:
        udp_target = (host, ed2k_port + 4)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, 0))

        # OP_GLOBSEARCHREQ2 for the keyword "ubuntu" (single string term).
        term = b"ubuntu"
        search_body = bytes([0x01]) + struct.pack("<H", len(term)) + term
        search = _udp_roundtrip(sock, udp_target, bytes([ED2K_HDR, OP_SEARCH_REQ2]) + search_body)
        if search:
            i = 0
            while i + 2 <= len(search) and search[i] == ED2K_HDR and search[i + 1] == OP_SEARCH_RES:
                i += 2
                search_hashes.append(search[i : i + 16].hex().upper())
                i += 16 + 4 + 2  # hash + clientID + port
                i += 4  # tag-count prefix
                while i < len(search) and search[i] != ED2K_HDR:
                    i += 1

        # OP_GLOBGETSOURCES for the same hash.
        getsrc = _udp_roundtrip(sock, udp_target, bytes([ED2K_HDR, OP_GETSOURCES]) + bytes.fromhex(SEED_HASH))
        if getsrc and len(getsrc) >= 19 and getsrc[1] == OP_FOUNDSOURCES:
            count = getsrc[18]
            off = 19
            for _ in range(count):
                ip = ".".join(str(b) for b in getsrc[off : off + 4])
                port = struct.unpack_from("<H", getsrc, off + 4)[0]
                sources.append((ip, port))
                off += 6

        # OP_SERVER_DESC_REQ (0xA2) -> OP_SERVER_DESC_RES (0xA3): server identity.
        desc = _udp_roundtrip(sock, udp_target, bytes([ED2K_HDR, 0xA2]))
        if desc and len(desc) >= 4 and desc[1] == 0xA3:
            nlen = struct.unpack_from("<H", desc, 2)[0]
            desc_name.append(desc[4 : 4 + nlen].decode("utf-8", "replace"))
        sock.close()
        time.sleep(0.3)
    finally:
        goed2k.stop_process(launch.process)
        goed2k.stop_server_processes()

    assert SEED_HASH in search_hashes, f"UDP search did not return the seeded file: {search_hashes}"
    assert (SOURCE_HOST, SOURCE_PORT) in sources, f"UDP sources did not return the endpoint: {sources}"
    # Feature #3: OP_SERVER_DESC reply carries the configured server name.
    assert "emulebb-local-e2e" in desc_name, f"OP_SERVER_DESC reply missing server name: {desc_name}"

    search_res_traced = False
    found_sources_traced = False
    desc_res_traced = False
    assert trace_path.is_file(), "packet trace was not written"
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("transport") != "udp":
            continue
        search_res_traced = search_res_traced or rec.get("op_name") == "OP_GLOBSEARCHRES"
        found_sources_traced = found_sources_traced or rec.get("op_name") == "OP_GLOBFOUNDSOURCES"
        desc_res_traced = desc_res_traced or rec.get("op_name") == "OP_SERVER_DESC_RES"

    assert search_res_traced, "OP_GLOBSEARCHRES not present in trace"
    assert found_sources_traced, "OP_GLOBFOUNDSOURCES not present in trace"
    assert desc_res_traced, "OP_SERVER_DESC_RES not present in trace"
