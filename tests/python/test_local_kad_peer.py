from __future__ import annotations

import socket
import struct
import time
import urllib.request

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness.local_kad_peer import LocalKadPeer, receive_frame
from emule_test_harness.kad_nodes import BootstrapContact, encode_nodes_dat

pytestmark = pytest.mark.unit


@pytest.fixture
def witness():
    helper = LocalKadPeer("127.0.0.1", {"127.0.0.1"})
    helper.start()
    try:
        yield helper
    finally:
        helper.close()


def test_contact_import_uses_stock_nodes_dat_without_udp(
    witness: LocalKadPeer,
) -> None:
    with urllib.request.urlopen(witness.nodes_url, timeout=2) as response:
        body = response.read()
    assert body == encode_nodes_dat(
        [
            BootstrapContact("127.0.0.1", witness.udp_port, witness.tcp_port),
        ]
    )
    assert body[12:28] == witness.node_id
    assert witness.evidence().get("priorUdpPackets", 0) == 0


@pytest.mark.parametrize("prior_udp", [False, True])
def test_firewall_verdict_disqualifies_prior_udp_contact(
    witness: LocalKadPeer,
    prior_udp: bool,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(2)
        port = udp.getsockname()[1]
        if prior_udp:
            udp.sendto(b"\xe4\x00", ("127.0.0.1", witness.udp_port))
            deadline = time.monotonic() + 2
            while witness.evidence().get("priorUdpPackets", 0) == 0:
                assert time.monotonic() < deadline
                time.sleep(0.01)
        with socket.create_connection(
            ("127.0.0.1", witness.tcp_port), timeout=2
        ) as stream:
            hello = (
                bytes([16])
                + bytes([0x11]) * 16
                + struct.pack("<IHIIH", 0, 4662, 0, 0, 0)
            )
            stream.sendall(ed2k_wire.encode_frame(0x01, hello))
            marker, opcode, _payload = receive_frame(stream)
            assert (marker, opcode) == (0xE3, 0x4C)
            request = struct.pack("<HHI", port, port, 0xAABBCCDD)
            stream.sendall(
                bytes([0xC5]) + struct.pack("<I", len(request) + 1) + b"\xa7" + request
            )
            packet, source = udp.recvfrom(64)
        assert source[1] == witness.udp_port
        assert packet == b"\xe4\x62" + bytes([int(prior_udp)]) + struct.pack("<H", port)
        evidence = witness.evidence()
        assert evidence["biasedRequests" if prior_udp else "unbiasedRequests"] == 1
        assert "127.0.0.1" not in str(evidence)


def test_source_publish_and_search_preserve_identity_and_stamp_observed_ip(
    witness: LocalKadPeer,
) -> None:
    target, publisher = b"t" * 16, b"p" * 16
    tags = b"".join(
        b"\x83" + bytes([name]) + struct.pack("<I", value)
        for name, value in [
            (0x02, 12),
            (0xFF, 6),
            (0xFD, 4662),
            (0xFC, 4672),
            (0xFE, 1),
        ]
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(2)
        destination = ("127.0.0.1", witness.udp_port)
        udp.sendto(b"\xe4\x21\x04" + target + witness.node_id, destination)
        assert udp.recvfrom(65536)[0] == b"\xe4\x29" + target + b"\x00"
        udp.sendto(b"\xe4\x44" + target + publisher + b"\x05" + tags, destination)
        assert udp.recvfrom(65536)[0] == b"\xe4\x4b" + target + b"\x01"
        udp.sendto(b"\xe4\x34" + target + struct.pack("<HQ", 0, 12), destination)
        result = udp.recvfrom(65536)[0]
    assert result[:36] == b"\xe4\x3b" + witness.node_id + target + b"\x01\x00"
    assert result[36:52] == publisher
    values = {
        name: value
        for name, value, _raw in ed2k_wire.decode_tag_sequence(result[53:], result[52])
    }
    assert values[0xFE] == 0x7F000001
    assert values[0xFD] == 4662
    assert values[0xFF] == 6
    assert witness.evidence()["sourcePublishes"] == 1
    assert witness.evidence()["sourceResults"] == 1


def test_source_index_rejects_malformed_or_oversized_tag_vectors(
    witness: LocalKadPeer,
) -> None:
    with pytest.raises(ed2k_wire.Ed2kWireError):
        witness._store_source(b"t" * 16 + b"p" * 16 + b"\x01\x83", "127.0.0.1")
    with pytest.raises(ValueError):
        witness._store_source(b"t" * 16 + b"p" * 16 + b"\x40", "127.0.0.1")
    assert witness._sources == {}
