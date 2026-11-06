from __future__ import annotations

import socket
import struct
import time
import urllib.request

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness.kad_firewall_helper import KadFirewallHelper, receive_frame
from emule_test_harness.kad_nodes import BootstrapContact, encode_nodes_dat

pytestmark = pytest.mark.unit


@pytest.fixture
def witness():
    helper = KadFirewallHelper("127.0.0.1", {"127.0.0.1"})
    helper.start()
    try:
        yield helper
    finally:
        helper.close()


def test_contact_import_uses_stock_nodes_dat_without_udp(
    witness: KadFirewallHelper,
) -> None:
    with urllib.request.urlopen(witness.nodes_url, timeout=2) as response:
        body = response.read()
    assert body == encode_nodes_dat(
        [
            BootstrapContact("127.0.0.1", witness.udp_port, witness.tcp_port),
        ]
    )
    assert witness.evidence().get("priorUdpPackets", 0) == 0


@pytest.mark.parametrize("prior_udp", [False, True])
def test_firewall_verdict_disqualifies_prior_udp_contact(
    witness: KadFirewallHelper,
    prior_udp: bool,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(2)
        port = udp.getsockname()[1]
        if prior_udp:
            udp.sendto(b"\xe4\x01", ("127.0.0.1", witness.udp_port))
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
