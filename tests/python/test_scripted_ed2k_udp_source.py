from __future__ import annotations

import json
import socket
import time
from pathlib import Path

from emule_test_harness.scripted_ed2k_udp_source import (
    OP_EDONKEYPROT,
    OP_GLOBFOUNDSOURCES,
    OP_GLOBGETSOURCES,
    OP_GLOBGETSOURCES2,
    OP_GLOBSERVSTATREQ,
    OP_GLOBSERVSTATRES,
    SERVER_UDP_FLAG_EXT_GETSOURCES,
    ScriptedEd2kUdpSourceServer,
)


def _free_server_base_port() -> int:
    for base_port in range(31_000, 32_000):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp_socket.bind(("127.0.0.1", base_port))
            udp_socket.bind(("127.0.0.1", base_port + 4))
            return base_port
        except OSError:
            continue
        finally:
            tcp_socket.close()
            udp_socket.close()
    raise RuntimeError("No free deterministic test port.")


def _recv(socket_: socket.socket) -> bytes:
    socket_.settimeout(2)
    return socket_.recvfrom(65_535)[0]


def test_scripted_udp_server_advertises_v1_only_and_returns_exact_source(tmp_path: Path) -> None:
    file_hash = bytes.fromhex("22334455667788990011AABBCCDDEEFF")
    transcript_path = tmp_path / "transcript.json"
    server = ScriptedEd2kUdpSourceServer(
        bind_host="127.0.0.1",
        server_tcp_port=_free_server_base_port(),
        file_hash=file_hash,
        source_host="198.18.240.2",
        source_tcp_port=4662,
        transcript_path=transcript_path,
    )
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    try:
        server.start()
        target = ("127.0.0.1", server.server_udp_port)
        challenge = 0x55AA_1234
        client.sendto(
            bytes((OP_EDONKEYPROT, OP_GLOBSERVSTATREQ))
            + challenge.to_bytes(4, "little"),
            target,
        )
        status = _recv(client)
        assert status[:2] == bytes((OP_EDONKEYPROT, OP_GLOBSERVSTATRES))
        assert int.from_bytes(status[2:6], "little") == challenge
        assert int.from_bytes(status[26:30], "little") == SERVER_UDP_FLAG_EXT_GETSOURCES

        client.sendto(bytes((OP_EDONKEYPROT, OP_GLOBGETSOURCES)) + file_hash, target)
        reply = _recv(client)
        assert reply[:2] == bytes((OP_EDONKEYPROT, OP_GLOBFOUNDSOURCES))
        assert reply[2:18] == file_hash
        assert reply[18] == 1
        assert reply[19:23] == bytes((198, 18, 240, 2))
        assert int.from_bytes(reply[23:25], "little") == 4662
    finally:
        client.close()
        server.stop()

    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    assert transcript["udpFlags"] == SERVER_UDP_FLAG_EXT_GETSOURCES
    assert [event["opcode"] for event in transcript["events"]] == [
        OP_GLOBSERVSTATREQ,
        OP_GLOBSERVSTATRES,
        OP_GLOBGETSOURCES,
        OP_GLOBFOUNDSOURCES,
    ]
    assert all(event["accepted"] for event in transcript["events"])


def test_scripted_udp_server_records_and_refuses_v2_and_wrong_hash(tmp_path: Path) -> None:
    file_hash = bytes.fromhex("22334455667788990011AABBCCDDEEFF")
    server = ScriptedEd2kUdpSourceServer(
        bind_host="127.0.0.1",
        server_tcp_port=_free_server_base_port(),
        file_hash=file_hash,
        source_host="198.18.240.2",
        source_tcp_port=4662,
        transcript_path=tmp_path / "transcript.json",
    )
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(0.15)
    try:
        server.start()
        target = ("127.0.0.1", server.server_udp_port)
        client.sendto(bytes((OP_EDONKEYPROT, OP_GLOBGETSOURCES2)) + file_hash, target)
        client.sendto(bytes((OP_EDONKEYPROT, OP_GLOBGETSOURCES)) + bytes(16), target)
        time.sleep(0.2)
        try:
            client.recvfrom(65_535)
        except TimeoutError:
            pass
        else:
            raise AssertionError("The v1-only fixture answered a forbidden request.")
    finally:
        client.close()
        server.stop()

    received = [
        event
        for event in server.snapshot()["events"]
        if event["direction"] == "recv"
    ]
    assert [event["note"] for event in received] == [
        "forbidden-v2-source-request",
        "wrong-v1-source-payload",
    ]
    assert not any(event["accepted"] for event in received)
