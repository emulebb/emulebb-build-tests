from __future__ import annotations

import socket
import threading

import pytest

from emule_test_harness import relayed_reask_probe


def _free_udp_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _callback(*, tail: bytes = b"") -> bytes:
    return (
        bytes(
            (
                relayed_reask_probe.OP_EMULEPROT,
                relayed_reask_probe.OP_REASKCALLBACKUDP,
            )
        )
        + bytes.fromhex("11" * 16)
        + bytes.fromhex("AB" * 16)
        + tail
    )


@pytest.mark.parametrize(
    ("udp_version", "tail", "part_count", "part_status_hex", "complete_count"),
    [
        (2, b"", None, None, None),
        (3, b"\x07\x00", None, None, 7),
        (4, b"\x09\x00\x01\x01\x07\x00", 9, "0101", 7),
    ],
)
def test_decode_reask_callback_udp_versions(
    udp_version: int,
    tail: bytes,
    part_count: int | None,
    part_status_hex: str | None,
    complete_count: int | None,
) -> None:
    raw = _callback(tail=tail)

    decoded = relayed_reask_probe.decode_reask_callback_udp(
        raw,
        source_udp_version=udp_version,
    )

    assert decoded["rawHex"] == raw.hex().upper()
    assert decoded["buddyId"] == "11" * 16
    assert decoded["fileHash"] == "AB" * 16
    assert decoded["partCount"] == part_count
    assert decoded["partStatusHex"] == part_status_hex
    assert decoded["completeSourceCount"] == complete_count


def test_decode_reask_callback_udp_rejects_trailing_data() -> None:
    with pytest.raises(ValueError, match="trailing bytes"):
        relayed_reask_probe.decode_reask_callback_udp(
            _callback(tail=b"\x00"),
            source_udp_version=2,
        )


def test_encode_reask_ack_uses_stock_v4_part_status_shape() -> None:
    assert relayed_reask_probe.encode_reask_ack(
        queue_rank=37,
        requester_udp_version=4,
    ) == bytes.fromhex("C59100002500")
    assert relayed_reask_probe.encode_reask_ack(
        queue_rank=37,
        requester_udp_version=4,
        part_status=(True, False, True),
    ) == bytes.fromhex("C5910300052500")


def test_probe_receives_callback_and_acks_from_source_endpoint() -> None:
    host = "127.0.0.1"
    buddy_port = _free_udp_port(host)
    source_port = _free_udp_port(host)
    requester_port = _free_udp_port(host)
    while len({buddy_port, source_port, requester_port}) != 3:
        source_port = _free_udp_port(host)
        requester_port = _free_udp_port(host)
    callback = _callback(tail=bytes.fromhex("00000700"))
    observed: dict[str, object] = {}

    def requester() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((host, requester_port))
            sock.settimeout(2.0)
            sock.sendto(callback, (host, buddy_port))
            response, endpoint = sock.recvfrom(64)
            observed["response"] = response
            observed["endpoint"] = endpoint

    with relayed_reask_probe.RelayedReaskProbe(
        buddy_host=host,
        buddy_udp_port=buddy_port,
        source_host=host,
        source_udp_port=source_port,
        buddy_id=bytes.fromhex("11" * 16),
        file_hash=bytes.fromhex("AB" * 16),
    ) as probe:
        thread = threading.Thread(target=requester)
        thread.start()
        transcript = probe.receive_and_ack(
            target_label="rust",
            expected_requester_host=host,
            expected_requester_udp_port=requester_port,
            timeout_seconds=2.0,
        )
        thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert observed == {
        "response": bytes.fromhex("C59100002500"),
        "endpoint": (host, source_port),
    }
    assert transcript["status"] == "completed"
    assert transcript["request"]["rawHex"] == callback.hex().upper()
    assert transcript["response"]["queueRank"] == 37
