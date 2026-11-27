"""Encode a short stock Kad receiver-key envelope for local peer fixtures."""

from __future__ import annotations

import hashlib
import struct


def encode_receiver_key_packet(payload: bytes, receiver_key: int, nonce: int, *, sender_key: int = 0) -> bytes:
    """Wrap a synthetic datagram using the verify key advertised by its recipient."""
    # Stock EncryptedDatagramSocket::EncryptSendClient: the key hashes the
    # little-endian receiver key and the two-byte nonce. Kad begins RC4 at byte 0.
    key = hashlib.md5(struct.pack("<IH", receiver_key, nonce), usedforsecurity=False).digest()
    data = struct.pack("<IBII", 0x395F2EC1, 0, receiver_key, sender_key) + payload
    return b"\x02" + struct.pack("<H", nonce) + _rc4(key, data)


def decode_fixture_packet(wire: bytes, node_id: bytes, receiver_key: int) -> tuple[bytes, int]:
    """Decode a fixture's stock plaintext, node-ID, or receiver-key datagram."""
    if wire[:1] == b"\xe4":
        return wire, 0
    if len(wire) < 18:
        raise ValueError("Truncated keyed Kad fixture datagram")
    nonce = wire[1:3]
    for material in (node_id, struct.pack("<I", receiver_key)):
        key = hashlib.md5(material + nonce, usedforsecurity=False).digest()
        data = _rc4(key, wire[3:])
        if data[:4] != b"\xc1\x2e\x5f\x39":
            continue
        keys_offset = 5 + (data[4] & 0x0F)
        if len(data) >= keys_offset + 10 and data[keys_offset + 8] == 0xE4:
            _, sender_key = struct.unpack_from("<II", data, keys_offset)
            return data[keys_offset + 8:], sender_key
    raise ValueError("Kad fixture datagram did not match a stock envelope")


def _rc4(key: bytes, content: bytes) -> bytes:
    data = bytearray(content)
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    for index in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        data[index] ^= state[(state[i] + state[j]) & 0xFF]
    return bytes(data)
