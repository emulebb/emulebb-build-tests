from __future__ import annotations

import ipaddress
import socket
import struct
import threading

import pytest

from emule_test_harness import buddy_callback_probe
from emule_test_harness import ed2k_wire
from emule_test_harness.docker_ed2k_source_publisher import encode_hello_answer


BUDDY_ID = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
BUDDY_HASH = bytes.fromhex("1032547698BADCFE1032547698BADCFE")
TARGET_HASH = bytes.fromhex("21436587A9CBED0F21436587A9CBED0F")
REQUESTER_HASH = bytes.fromhex("32547698BADCFE1032547698BADCFE10")
FILE_HASH = bytes.fromhex("436587A9CBED0F21436587A9CBED0F21")


def _free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _recv_frame(stream: socket.socket) -> bytes:
    header = stream.recv(6)
    while len(header) < 6:
        header += stream.recv(6 - len(header))
    declared = int.from_bytes(header[1:5], "little")
    body = b""
    while len(body) < declared - 1:
        body += stream.recv(declared - 1 - len(body))
    return header + body


@pytest.mark.unit
def test_buddy_callback_codecs_match_stock_layouts() -> None:
    find_request = buddy_callback_probe.encode_find_buddy_request(
        buddy_id=bytes(range(16)),
        client_hash=bytes(range(16, 32)),
        tcp_port=0x1234,
    )
    callback_request = buddy_callback_probe.encode_callback_request(
        buddy_id=bytes(range(16)),
        file_hash=bytes(range(32, 48)),
        requester_tcp_port=0x5678,
    )

    assert find_request == bytes.fromhex(
        "E451000102030405060708090A0B0C0D0E0F13121110171615141B1A19181F1E1D1C3412"
    )
    assert callback_request == bytes.fromhex(
        "E452000102030405060708090A0B0C0D0E0F23222120272625242B2A29282F2E2D2C7856"
    )


@pytest.mark.unit
def test_find_buddy_response_and_callback_relay_decode_exact_fields() -> None:
    response = (
        bytes((0xE4, 0x5A))
        + BUDDY_ID
        + buddy_callback_probe._kad_uint128_wire_bytes(TARGET_HASH, "target_hash")
        + struct.pack("<H", 4662)
    )
    decoded_response = buddy_callback_probe.decode_find_buddy_response(response)
    requester_host = "192.0.2.17"
    relay_payload = (
        BUDDY_ID
        + buddy_callback_probe._kad_uint128_wire_bytes(FILE_HASH, "file_hash")
        + int(ipaddress.IPv4Address(requester_host)).to_bytes(4, "little")
        + struct.pack("<H", 4670)
    )
    relay_raw = (
        bytes((0xC5,))
        + struct.pack("<I", len(relay_payload) + 1)
        + bytes((0x99,))
        + relay_payload
    )
    relay = buddy_callback_probe.decode_callback_relay(relay_raw)

    assert decoded_response["buddyId"] == BUDDY_ID.hex().upper()
    assert decoded_response["clientHash"] == TARGET_HASH.hex().upper()
    assert decoded_response["tcpPort"] == 4662
    assert decoded_response["connectOptions"] is None
    assert relay["buddyId"] == BUDDY_ID.hex().upper()
    assert relay["fileHash"] == FILE_HASH.hex().upper()
    assert relay["requesterHost"] == requester_host
    assert relay["requesterTcpPort"] == 4670


@pytest.mark.unit
@pytest.mark.parametrize(
    "raw",
    [
        b"",
        bytes((0xE4, 0x5A)) + bytes(33),
        bytes((0xE4, 0x5A)) + bytes(36),
        bytes((0xE4, 0x51)) + bytes(34),
    ],
)
def test_find_buddy_response_rejects_noncanonical_shape(raw: bytes) -> None:
    with pytest.raises(ValueError):
        buddy_callback_probe.decode_find_buddy_response(raw)


@pytest.mark.unit
def test_buddy_callback_probe_records_complete_socket_chain() -> None:
    target_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target_udp.bind(("127.0.0.1", 0))
    target_udp_port = int(target_udp.getsockname()[1])
    target_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target_tcp.bind(("127.0.0.1", 0))
    target_tcp.listen(1)
    target_tcp_port = int(target_tcp.getsockname()[1])
    buddy_udp_port = _free_port(socket.SOCK_DGRAM)
    buddy_tcp_port = _free_port(socket.SOCK_STREAM)
    requester_tcp_port = _free_port(socket.SOCK_STREAM)
    target_client_id = 0x01020304
    failure: list[BaseException] = []

    def target() -> None:
        try:
            find_raw, buddy_source = target_udp.recvfrom(1024)
            assert find_raw == buddy_callback_probe.encode_find_buddy_request(
                buddy_id=BUDDY_ID,
                client_hash=BUDDY_HASH,
                tcp_port=buddy_tcp_port,
            )
            find_response = (
                bytes((0xE4, 0x5A))
                + BUDDY_ID
                + buddy_callback_probe._kad_uint128_wire_bytes(
                    TARGET_HASH, "target_hash"
                )
                + struct.pack("<H", target_tcp_port)
            )
            target_udp.sendto(find_response, buddy_source)
            held, _peer = target_tcp.accept()
            with held:
                held.settimeout(2.0)
                hello = ed2k_wire.decode_frame_bytes(_recv_frame(held))
                assert hello.opcode == 0x01
                assert hello.payload[1:17] == BUDDY_HASH
                held.sendall(
                    encode_hello_answer(
                        user_hash=TARGET_HASH,
                        client_id=target_client_id,
                        tcp_port=target_tcp_port,
                    )
                )
                callback_raw, requester_source = target_udp.recvfrom(1024)
                assert callback_raw == buddy_callback_probe.encode_callback_request(
                    buddy_id=BUDDY_ID,
                    file_hash=FILE_HASH,
                    requester_tcp_port=requester_tcp_port,
                )
                relay_payload = (
                    BUDDY_ID
                    + buddy_callback_probe._kad_uint128_wire_bytes(
                        FILE_HASH, "file_hash"
                    )
                    + int(ipaddress.IPv4Address(requester_source[0])).to_bytes(
                        4, "little"
                    )
                    + struct.pack("<H", requester_tcp_port)
                )
                relay = (
                    bytes((0xC5,))
                    + struct.pack("<I", len(relay_payload) + 1)
                    + bytes((0x99,))
                    + relay_payload
                )
                held.sendall(relay)
        except BaseException as exc:  # pragma: no cover - asserted by caller
            failure.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    try:
        with buddy_callback_probe.BuddyCallbackProbe(
            bind_host="127.0.0.1",
            buddy_tcp_port=buddy_tcp_port,
            buddy_udp_port=buddy_udp_port,
            buddy_user_hash=BUDDY_HASH,
            buddy_id=BUDDY_ID,
            file_hash=FILE_HASH,
            requester_tcp_port=requester_tcp_port,
            requester_user_hash=REQUESTER_HASH,
        ) as probe:
            result = probe.request(
                target_label="fixture",
                target_host="127.0.0.1",
                target_tcp_port=target_tcp_port,
                target_udp_port=target_udp_port,
                target_user_hash=TARGET_HASH,
                target_server_client_id=target_client_id,
                target_peer_hello_client_id=target_client_id,
                timeout_seconds=2.0,
            )
    finally:
        target_udp.close()
        target_tcp.close()
        thread.join(timeout=2.0)

    assert not failure
    assert result["status"] == "completed"
    assert result["findBuddyRequest"]["rawHex"].startswith("E451")
    assert result["findBuddyResponse"]["rawHex"].startswith("E45A")
    assert result["callbackRequest"]["rawHex"].startswith("E452")
    assert result["callbackRelay"]["rawHex"].startswith("C5")
    assert result["callbackRelay"]["buddyId"] == BUDDY_ID.hex().upper()
    assert result["callbackRelay"]["fileHash"] == FILE_HASH.hex().upper()
    assert (
        result["resultingPeerSession"]["listenerObservation"]["userHash"]
        == BUDDY_HASH.hex().upper()
    )
    assert result["resultingPeerSession"]["listenerObservation"]["clientId"] == 7
