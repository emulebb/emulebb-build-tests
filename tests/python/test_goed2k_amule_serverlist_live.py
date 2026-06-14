"""Live ED2K campaign: a real aMule daemon drives goed2k-server on X_LOCAL_IP.

This promotes the standalone live driver into a marked pytest case. It proves the
TCP handshake and the OP_GETSERVERLIST -> OP_SERVERLIST (0x32) reply against a
real ED2K client, verified two ways: the goed2k admin API (client appears) and
the server packet trace (both opcodes observed). LAN-bound, no loopback.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from emule_test_harness import amule, goed2k

pytestmark = pytest.mark.live

SEED_HASH = "00112233445566778899AABBCCDDEEFF"


def _free_lan_port(host: str, taken: set[int]) -> int:
    for _ in range(200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((host, 0))
            port = probe.getsockname()[1]
        if port + 4 > 65535 or port in taken or (port + 4) in taken:
            continue
        try:  # ensure the derived ED2K UDP port (TCP+4) is bindable too
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_probe:
                udp_probe.bind((host, port + 4))
        except OSError:
            continue
        taken.add(port)
        return port
    raise RuntimeError("no free LAN port found")


def _resolve_exe(env_value: str | None, default: Path) -> Path | None:
    if env_value:
        candidate = Path(env_value)
        return candidate if candidate.is_file() else None
    return default if default.is_file() else None


def test_amule_drives_goed2k_serverlist_live() -> None:
    host = os.environ.get("X_LOCAL_IP")
    if not host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound live ED2K traffic")
    output_root = os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    if not output_root:
        pytest.skip("EMULEBB_WORKSPACE_OUTPUT_ROOT is required")
    out = Path(output_root)
    # The harness forbids profile roots under Windows temp; stage under output root.
    run_dir = out / "artifacts" / "live-amule-serverlist"
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True, exist_ok=True)

    server_exe = _resolve_exe(
        goed2k.env_ed2k_server_exe_override(),
        out / "tools" / "goed2k-server" / "goed2k-server.exe",
    )
    if server_exe is None and shutil.which("go") is None:
        pytest.skip("goed2k-server exe override missing and go is unavailable to build it")
    amuled = out / "tools" / "amule" / "bin" / "amuled.exe"
    amulecmd = out / "tools" / "amule" / "bin" / "amulecmd.exe"
    if not amuled.is_file() or not amulecmd.is_file():
        pytest.skip("prebuilt aMule daemon/control binaries are not staged")

    # Avoid colliding with a stale instance from an earlier run.
    goed2k.stop_server_processes()
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/IM", "amuled.exe", "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    time.sleep(1.0)

    taken: set[int] = set()
    ed2k_port = _free_lan_port(host, taken)
    admin_port = _free_lan_port(host, taken)
    amule_tcp = _free_lan_port(host, taken)
    amule_udp = _free_lan_port(host, taken)
    amule_ec = _free_lan_port(host, taken)
    token = "amule-live-token"
    nick = "emulebb-amule-live"

    launch = goed2k.launch_ed2k_server(
        workspace_root=Path(__file__).resolve().parents[4] / "workspaces" / "workspace",
        server_dir=run_dir / "server",
        ed2k_port=ed2k_port,
        admin_port=admin_port,
        token=token,
        admin_address=host,
        ed2k_address=host,
        exe_override=str(server_exe) if server_exe else None,
        catalog_files=[
            goed2k.catalog_file(
                file_hash=SEED_HASH,
                name="ubuntu-24.04-desktop-amd64.iso",
                size=6144000000,
                file_type="Iso",
                extension="iso",
                endpoints=[{"host": "203.0.113.10", "port": 4662}],
            )
        ],
        packet_trace=True,
    )
    trace_path = launch.server_dir / "packets.trace.jsonl"

    profile = amule.prepare_amule_profile(
        root_dir=run_dir / "amule",
        profile_id="live",
        nick=nick,
        tcp_port=amule_tcp,
        udp_port=amule_udp,
        ec_port=amule_ec,
        advertised_address=host,
        ec_address=host,
        connect_to_ed2k=True,
    )
    (profile.config_dir / "server.met").write_bytes(goed2k.build_server_met(host, ed2k_port, "goed2k-live"))
    conf_path = profile.config_dir / "amule.conf"
    conf = conf_path.read_text(encoding="utf-8")
    conf = conf.replace("Serverlist=0", "Serverlist=1").replace(
        "AddServerListFromServer=0", "AddServerListFromServer=1"
    )
    conf_path.write_text(conf, encoding="utf-8")

    daemon = None
    client = None
    try:
        daemon = amule.start_amuled(amuled, profile)
        amule.wait_for_ec_ready(amulecmd, profile, timeout_seconds=45.0)
        amule.run_amulecmd(amulecmd, profile, "connect ed2k", timeout_seconds=20.0, check=False)
        client = goed2k.wait_for_server_client(launch.admin_base_url, token, nick, timeout_seconds=45.0)
        # Allow the post-login server-list exchange to round-trip.
        time.sleep(8.0)
    finally:
        amule.run_amulecmd(amulecmd, profile, "disconnect", timeout_seconds=10.0, check=False)
        goed2k.stop_process(daemon)
        goed2k.stop_process(launch.process)
        goed2k.stop_server_processes()

    assert client is not None, "aMule client did not register on the server"

    getserverlist_seen = False
    serverlist_reply_seen = False
    login_seen = False
    assert trace_path.is_file(), "packet trace was not written"
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("transport") != "tcp":
            continue
        name = rec.get("op_name")
        login_seen = login_seen or name == "OP_LOGINREQUEST"
        getserverlist_seen = getserverlist_seen or name == "OP_GETSERVERLIST"
        serverlist_reply_seen = serverlist_reply_seen or name == "OP_SERVERLIST"

    assert login_seen, "OP_LOGINREQUEST not observed in trace"
    assert getserverlist_seen, "aMule did not request the server list"
    assert serverlist_reply_seen, "server did not reply with OP_SERVERLIST"
