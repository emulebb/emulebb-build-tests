"""SecIdent liveness audit over ``ed2k_packet_v1`` recordings.

WHY this exists: the 2026-07-04 MFC soak capture ran with SecIdent effectively
dead — zero OP_PUBLICKEY/OP_SIGNATURE/OP_SECIDENTSTATE (0xC5 0x85/86/87) packets
and HELLO ``CT_EMULE_MISCOPTIONS1`` secident bits = 0 — because the launched
profile silently carried ``SecureIdent=0``, and nothing in the diff pipeline
noticed that an entire parity surface had gone quiet. This module detects that
condition from a capture alone so a silenced surface can never pass unremarked
again:

* :func:`parse_hello_miscoptions1` decodes the ``CT_EMULE_MISCOPTIONS1`` (0xFA)
  tag out of a sent OP_HELLO / OP_HELLOANSWER payload;
* :func:`secident_bits` extracts the 3-bit SecIdent support field
  (``BaseClient.cpp``: ``uSupportSecIdent << 16``, value 3 when
  ``CryptoAvailable()``, 0 when crypto is dead);
* :func:`audit_client_secident` combines the client's own sent-HELLO bits with
  the 0x85/86/87 packet counts over the client channel and yields a verdict —
  ``secident-dead`` when the profile claims SecIdent on (or claims nothing) but
  the wire shows it off while real peer traffic was present.
"""

from __future__ import annotations

import struct
from typing import Any

from .packet_trace_diff import canonical_channel

OP_EDONKEYPROT = 0xE3
OP_EMULEPROT = 0xC5
OP_HELLO = 0x01
OP_HELLOANSWER = 0x4C
CT_EMULE_MISCOPTIONS1 = 0xFA

# The SecIdent exchange opcodes (eMule protocol 0xC5).
SECIDENT_OPCODES: dict[int, str] = {
    0x85: "OP_PUBLICKEY",
    0x86: "OP_SIGNATURE",
    0x87: "OP_SECIDENTSTATE",
}

# Minimum client-channel packets before "zero secident packets" counts as
# evidence: with no meaningful peer traffic there was nothing to identify.
DEFAULT_MIN_PEER_PACKETS = 25

_PACKET_DIRECTIONS = ("send", "recv")


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_tag(data: bytes, offset: int) -> tuple[int | None, int | None, int]:
    """Reads one eMule client-hello tag; returns (name_id, int_value, next_offset).

    Handles both the compact form (type | 0x80, one-byte name) and the long form
    (u16 name length + name bytes; ``name_id`` is the byte when the name is one
    byte long). Non-integer tag values are skipped (value ``None``). Raises
    ``ValueError`` on a tag type this parser does not know, so the caller treats
    the whole HELLO as not-assessable instead of misreading it.
    """

    tag_type = data[offset]
    offset += 1
    if tag_type & 0x80:
        tag_type &= 0x7F
        name_id: int | None = data[offset]
        offset += 1
    else:
        name_len = _u16(data, offset)
        offset += 2
        name_id = data[offset] if name_len == 1 else None
        offset += name_len

    value: int | None = None
    if tag_type == 0x09:  # TAGTYPE_UINT8
        value = data[offset]
        offset += 1
    elif tag_type == 0x08:  # TAGTYPE_UINT16
        value = _u16(data, offset)
        offset += 2
    elif tag_type == 0x03:  # TAGTYPE_UINT32
        value = _u32(data, offset)
        offset += 4
    elif tag_type == 0x0B:  # TAGTYPE_UINT64
        value = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
    elif tag_type == 0x02:  # TAGTYPE_STRING
        offset += 2 + _u16(data, offset)
    elif tag_type == 0x01:  # TAGTYPE_HASH16
        offset += 16
    elif tag_type == 0x04:  # TAGTYPE_FLOAT32
        offset += 4
    elif tag_type == 0x05:  # TAGTYPE_BOOL
        offset += 1
    elif tag_type == 0x07:  # TAGTYPE_BLOB (u32 length + data)
        offset += 4 + _u32(data, offset)
    elif 0x11 <= tag_type <= 0x20:  # TAGTYPE_STR1..STR16 (length in the type)
        offset += tag_type - 0x11 + 1
    else:
        raise ValueError(f"unknown hello tag type 0x{tag_type:02X}")
    return name_id, value, offset


def parse_hello_miscoptions1(payload_hex: str, opcode: int) -> int | None:
    """Extracts the ``CT_EMULE_MISCOPTIONS1`` value from a HELLO/HELLOANSWER payload.

    Returns ``None`` when the payload cannot be parsed or carries no
    MISCOPTIONS1 tag — callers must treat that as not-assessable, never as
    bits = 0.
    """

    try:
        data = bytes.fromhex((payload_hex or "").strip())
    except ValueError:
        return None
    try:
        # OP_HELLO leads with the one-byte user-hash size (16); OP_HELLOANSWER
        # starts directly at the user hash.
        offset = 1 if opcode == OP_HELLO else 0
        offset += 16 + 4 + 2  # userhash + clientid + tcp port
        tag_count = _u32(data, offset)
        offset += 4
        if tag_count > 0xFF:
            return None  # implausible; refuse to walk a corrupt payload
        for _ in range(tag_count):
            name_id, value, offset = _read_tag(data, offset)
            if name_id == CT_EMULE_MISCOPTIONS1 and value is not None:
                return int(value)
    except (IndexError, struct.error, ValueError):
        return None
    return None


def secident_bits(miscoptions1: int) -> int:
    """The 3-bit SecIdent support field of MISCOPTIONS1 (``uSupportSecIdent << 16``)."""

    return (int(miscoptions1) >> 16) & 0x7


def audit_client_secident(
    packets: list[dict[str, Any]],
    *,
    declared_enabled: bool | None = None,
    min_peer_packets: int = DEFAULT_MIN_PEER_PACKETS,
) -> dict[str, Any]:
    """Audits one client's recording for SecIdent liveness.

    ``declared_enabled`` is the profile/config claim (``True``/``False``/``None``
    when unrecorded). Verdicts:

    * ``secident-dead`` — the claim is on (or unknown) but the wire shows crypto
      off: the client's own sent HELLOs advertise secident bits = 0, and/or the
      claim is on with zero 0x85/86/87 packets despite ``min_peer_packets`` of
      client-channel traffic;
    * ``disabled-by-config`` — the profile deliberately says off (expected state
      for an off-campaign);
    * ``ok`` — secident evidence present (non-zero hello bits or exchange packets);
    * ``not-assessable`` — no sent HELLO decoded and not enough peer traffic to
      judge absence.
    """

    hello_bits: list[int] = []
    hello_seen = 0
    secident_counts = {"send": 0, "recv": 0}
    client_packets = 0
    for record in packets or []:
        if record.get("schema") != "ed2k_packet_v1":
            continue
        direction = record.get("direction")
        if direction not in _PACKET_DIRECTIONS:
            continue
        if canonical_channel(record.get("flow")) != "client":
            continue
        try:
            marker = int(record.get("protocol_marker") or 0)
            opcode = int(record.get("opcode") or 0)
        except (TypeError, ValueError):
            continue
        client_packets += 1
        if marker == OP_EMULEPROT and opcode in SECIDENT_OPCODES:
            secident_counts[str(direction)] += 1
        if direction == "send" and marker == OP_EDONKEYPROT and opcode in (OP_HELLO, OP_HELLOANSWER):
            hello_seen += 1
            miscoptions1 = parse_hello_miscoptions1(record.get("payload_hex") or "", opcode)
            if miscoptions1 is not None:
                hello_bits.append(secident_bits(miscoptions1))

    secident_total = secident_counts["send"] + secident_counts["recv"]
    findings: list[str] = []
    if declared_enabled is not False and hello_bits and all(bits == 0 for bits in hello_bits):
        findings.append("hello-secident-bits-zero")
    if declared_enabled is True and client_packets >= min_peer_packets and secident_total == 0:
        findings.append("no-secident-packets-with-peer-traffic")

    if declared_enabled is False:
        verdict = "disabled-by-config"
    elif findings:
        verdict = "secident-dead"
    elif any(bits > 0 for bits in hello_bits) or secident_total > 0:
        verdict = "ok"
    else:
        verdict = "not-assessable"
    return {
        "verdict": verdict,
        "findings": findings,
        "declaredEnabled": declared_enabled,
        "helloSecIdentBits": sorted(set(hello_bits)),
        "helloSendCount": hello_seen,
        "helloDecodedCount": len(hello_bits),
        "secIdentPackets": {**secident_counts, "total": secident_total},
        "clientChannelPackets": client_packets,
        "minPeerPackets": min_peer_packets,
    }
