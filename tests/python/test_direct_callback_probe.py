from __future__ import annotations

import socket
import threading

import pytest

from emule_test_harness import direct_callback_probe
from emule_test_harness import ed2k_wire


REQUESTER_HASH = bytes.fromhex("426486A8CAEC0E20426486A8CAEC6E00")


@pytest.mark.unit
def test_direct_callback_request_matches_stock_layout() -> None:
    datagram = direct_callback_probe.encode_direct_callback_request(
        tcp_port=4662,
        user_hash=bytes(range(16)),
        connect_options=0x03,
    )

    assert datagram == bytes.fromhex(
        "C5953612" "000102030405060708090A0B0C0D0E0F" "03"
    )
    assert len(datagram) == direct_callback_probe.DIRECT_CALLBACK_REQUEST_BYTES


@pytest.mark.unit
def test_direct_callback_probe_correlates_udp_stimulus_to_peer_hello() -> None:
    udp_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_receiver.bind(("127.0.0.1", 0))
    target_udp_port = udp_receiver.getsockname()[1]
    callback_port_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    callback_port_socket.bind(("127.0.0.1", 0))
    callback_port = callback_port_socket.getsockname()[1]
    callback_port_socket.close()
    peer_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

    def peer() -> None:
        raw, source = udp_receiver.recvfrom(64)
        assert raw[0:2] == bytes((0xC5, 0x95))
        requester_port = int.from_bytes(raw[2:4], "little")
        assert requester_port == callback_port
        assert raw[4:20] == REQUESTER_HASH
        with socket.create_connection((source[0], requester_port), timeout=2.0) as stream:
            hello_payload = (
                b"\x10"
                + peer_hash
                + (7).to_bytes(4, "little")
                + (4661).to_bytes(2, "little")
                + (0).to_bytes(4, "little")
            )
            stream.sendall(ed2k_wire.encode_frame(0x01, hello_payload))
            stream.recv(128)

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    try:
        with direct_callback_probe.DirectCallbackProbe(
            bind_host="127.0.0.1",
            tcp_port=callback_port,
            user_hash=REQUESTER_HASH,
        ) as probe:
            result = probe.request(
                target_host="127.0.0.1",
                target_udp_port=target_udp_port,
                target_label="fixture",
                timeout_seconds=2.0,
            )
    finally:
        udp_receiver.close()
        thread.join(timeout=2.0)

    assert result["status"] == "completed"
    assert result["request"]["rawHex"].startswith("C595")
    assert result["callbackConnection"]["userHash"] == peer_hash.hex().upper()
    assert result["callbackConnection"]["clientId"] == 7
    assert result["callbackConnection"]["tcpPort"] == 4661
