"""Unit tests for the SecIdent liveness audit (emule_test_harness.secident_audit)."""

from __future__ import annotations

import struct

import pytest

from emule_test_harness import secident_audit as sia

pytestmark = pytest.mark.unit


def _hello_payload(miscoptions1: int | None, *, answer: bool = False, long_name: bool = False) -> str:
    """Builds a synthetic OP_HELLO / OP_HELLOANSWER payload with client-hello tags."""

    body = b"" if answer else bytes([16])  # OP_HELLO leads with the hash-size byte
    body += b"\x11" * 16  # user hash
    body += b"\x22" * 4  # client id
    body += struct.pack("<H", 4662)  # tcp port
    tags: list[bytes] = []
    # A short-string nick tag (CT_NAME=0x01, TAGTYPE_STR4) the parser must skip.
    tags.append(bytes([0x80 | 0x14, 0x01]) + b"nick")
    # A uint16 tag (CT_EMULE_VERSION-ish) the parser must skip.
    tags.append(bytes([0x80 | 0x08, 0xFB]) + struct.pack("<H", 0x1234))
    if miscoptions1 is not None:
        if long_name:
            # Long-form name: type u8, u16 name length, name bytes, u32 value.
            tags.append(bytes([0x03]) + struct.pack("<H", 1) + bytes([0xFA]) + struct.pack("<I", miscoptions1))
        else:
            tags.append(bytes([0x80 | 0x03, 0xFA]) + struct.pack("<I", miscoptions1))
    body += struct.pack("<I", len(tags)) + b"".join(tags)
    body += b"\x00" * 4 + struct.pack("<H", 4661)  # server ip + port trailer
    return body.hex()


def _pkt(direction: str, marker: int, opcode: int, payload_hex: str = "") -> dict:
    return {
        "schema": "ed2k_packet_v1",
        "flow": "client",
        "direction": direction,
        "protocol_marker": marker,
        "opcode": opcode,
        "payload_hex": payload_hex,
        "payload_len": len(payload_hex) // 2,
    }


MISC1_CRYPTO_ON = (3 << 16) | (4 << 24) | (1 << 20)  # secident=3 + udpVer/dataComp noise
MISC1_CRYPTO_OFF = (4 << 24) | (1 << 20)  # same options with secident bits 0


def test_parse_hello_miscoptions1_compact_and_long_tag_names() -> None:
    assert sia.parse_hello_miscoptions1(_hello_payload(MISC1_CRYPTO_ON), sia.OP_HELLO) == MISC1_CRYPTO_ON
    assert (
        sia.parse_hello_miscoptions1(_hello_payload(MISC1_CRYPTO_ON, long_name=True), sia.OP_HELLO)
        == MISC1_CRYPTO_ON
    )
    assert (
        sia.parse_hello_miscoptions1(_hello_payload(MISC1_CRYPTO_ON, answer=True), sia.OP_HELLOANSWER)
        == MISC1_CRYPTO_ON
    )


def test_parse_hello_miscoptions1_is_none_for_garbage_or_missing_tag() -> None:
    assert sia.parse_hello_miscoptions1("zz", sia.OP_HELLO) is None
    assert sia.parse_hello_miscoptions1("", sia.OP_HELLO) is None
    assert sia.parse_hello_miscoptions1(_hello_payload(None), sia.OP_HELLO) is None


def test_secident_bits_extracts_the_three_bit_field() -> None:
    assert sia.secident_bits(MISC1_CRYPTO_ON) == 3
    assert sia.secident_bits(MISC1_CRYPTO_OFF) == 0


def test_audit_flags_secident_dead_on_zero_hello_bits() -> None:
    packets = [_pkt("send", 0xE3, sia.OP_HELLO, _hello_payload(MISC1_CRYPTO_OFF))]
    audit = sia.audit_client_secident(packets, declared_enabled=True, min_peer_packets=100)
    assert audit["verdict"] == "secident-dead"
    assert "hello-secident-bits-zero" in audit["findings"]
    assert audit["helloSecIdentBits"] == [0]


def test_audit_flags_dead_hello_bits_even_when_declared_state_unknown() -> None:
    # Pre-knob recordings carry no declared state; bits=0 on the wire is still
    # direct evidence of dead crypto and must be loud.
    packets = [_pkt("send", 0xE3, sia.OP_HELLOANSWER, _hello_payload(MISC1_CRYPTO_OFF, answer=True))]
    audit = sia.audit_client_secident(packets, declared_enabled=None, min_peer_packets=100)
    assert audit["verdict"] == "secident-dead"


def test_audit_flags_dead_on_zero_secident_packets_with_peer_traffic() -> None:
    packets = [_pkt("send", 0xE3, 0x58) for _ in range(30)]  # peer traffic, no 0x85/86/87
    audit = sia.audit_client_secident(packets, declared_enabled=True, min_peer_packets=25)
    assert audit["verdict"] == "secident-dead"
    assert "no-secident-packets-with-peer-traffic" in audit["findings"]


def test_audit_ok_with_live_crypto_evidence() -> None:
    packets = [
        _pkt("send", 0xE3, sia.OP_HELLO, _hello_payload(MISC1_CRYPTO_ON)),
        _pkt("send", 0xC5, 0x85),  # OP_PUBLICKEY
        _pkt("recv", 0xC5, 0x86),  # OP_SIGNATURE
        _pkt("recv", 0xC5, 0x87),  # OP_SECIDENTSTATE
    ]
    audit = sia.audit_client_secident(packets, declared_enabled=True, min_peer_packets=1)
    assert audit["verdict"] == "ok"
    assert audit["helloSecIdentBits"] == [3]
    assert audit["secIdentPackets"] == {"send": 1, "recv": 2, "total": 3}


def test_audit_respects_deliberate_off_campaign() -> None:
    packets = [_pkt("send", 0xE3, sia.OP_HELLO, _hello_payload(MISC1_CRYPTO_OFF))] * 30
    audit = sia.audit_client_secident(packets, declared_enabled=False, min_peer_packets=25)
    assert audit["verdict"] == "disabled-by-config"
    assert audit["findings"] == []


def test_audit_not_assessable_without_traffic_or_hellos() -> None:
    audit = sia.audit_client_secident([], declared_enabled=True, min_peer_packets=25)
    assert audit["verdict"] == "not-assessable"


def test_audit_ignores_server_channel_and_foreign_schemas() -> None:
    packets = [
        {**_pkt("send", 0xC5, 0x85), "flow": "server"},  # server channel, ignored
        {**_pkt("send", 0xC5, 0x85), "schema": "udp_packet_v1"},  # foreign schema
    ]
    audit = sia.audit_client_secident(packets, declared_enabled=True, min_peer_packets=1)
    assert audit["clientChannelPackets"] == 0
    assert audit["verdict"] == "not-assessable"
