import socket
import struct
from contextlib import ExitStack

import pytest

from emule_test_harness import ed2k_wire as wire
from emule_test_harness.native_partial_publisher import PART_SIZE, TAIL_SIZE, PartialPublisher
from emule_test_harness.scripted_actions import _md4_digest


def _open_source(stack, host, part):
    source = PartialPublisher(host, 0, part)
    source.start()
    stack.callback(source.stop)
    peer = stack.enter_context(wire.Ed2kWireClient(host, source.tcp_port, peer_protocol=True))
    peer.send(0x01, wire.peer_hello_payload(bytes(range(16)), 0x0100007F, 4711))
    hello = peer.receive()
    assert hello.opcode == 0x4C
    assert struct.unpack_from("<H", hello.payload, 20) == (source.tcp_port,)
    peer.send(0x58, source.file_hash)
    name = source.file_name.encode("ascii")
    assert peer.receive().payload == source.file_hash + struct.pack("<H", len(name)) + name
    peer.send(0x4F, source.file_hash)
    assert peer.receive().payload == source.file_hash + struct.pack("<HB", 2, 1 << part)
    peer.send(0x51, source.file_hash)
    hashes = peer.receive()
    assert hashes.opcode == 0x52
    assert hashes.payload[:18] == source.file_hash + b"\x02\x00"
    assert len(hashes.payload) == 50
    assert _md4_digest(hashes.payload[18:]) == source.file_hash
    peer.send(0x54, source.file_hash)
    assert peer.receive() == wire.Ed2kFrame(0xE3, 0x55, b"")
    return source, peer, hello.payload[:16]


def _request(peer, file_hash, start, end):
    peer.send(0x47, file_hash + struct.pack("<6I", start, 0, 0, end, 0, 0))


def _expect_data(peer, file_hash, start, end, unit):
    reply = peer.receive()
    assert reply.opcode == 0x46
    assert reply.payload[:24] == file_hash + struct.pack("<2I", start, end)
    assert reply.payload[24:] == unit * (end - start)


def test_two_sources_hold_one_adjacent_byte_until_released():
    with ExitStack() as stack:
        head, first, head_identity = _open_source(stack, "127.0.0.1", 0)
        tail, second, tail_identity = _open_source(stack, "127.0.0.2", 1)
        assert head_identity != tail_identity
        assert head.file_hash == tail.file_hash
        assert head.file_size == tail.file_size == PART_SIZE + TAIL_SIZE
        # Request blocks out of order and repeat the first one.
        blocks = list(range(0, PART_SIZE, TAIL_SIZE))[::-1]
        for start in [blocks[0], *blocks]:
            end = min(start + TAIL_SIZE, PART_SIZE)
            _request(first, head.file_hash, start, end)
            _expect_data(first, head.file_hash, start, min(end, PART_SIZE - 2), b"A")
        head.wait_for_sent(PART_SIZE - 2, 2)
        _request(second, tail.file_hash, PART_SIZE, PART_SIZE + TAIL_SIZE)
        _expect_data(second, tail.file_hash, PART_SIZE, PART_SIZE + 1, b"B")
        tail.wait_for_sent(1, 2)
        assert head.sent_bytes + tail.sent_bytes == PART_SIZE - 1
        with pytest.raises(TimeoutError):
            second.receive(timeout_seconds=0.15)
        tail.release_threshold_byte(2)
        _expect_data(second, tail.file_hash, PART_SIZE + 1, PART_SIZE + 2, b"B")
        assert head.sent_bytes + tail.sent_bytes == PART_SIZE


def test_stop_with_incomplete_hello():
    source = PartialPublisher("127.0.0.1", 0, 0)
    source.start()
    try:
        with socket.create_connection(("127.0.0.1", source.tcp_port), timeout=2) as peer:
            peer.sendall(b"\xe3\x40")
            source.stop()
    finally:
        source.stop()
