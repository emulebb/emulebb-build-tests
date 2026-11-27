"""Encode a short stock Kad receiver-key envelope for local peer fixtures."""

from __future__ import annotations

import hashlib
import struct


def encode_receiver_key_packet(payload: bytes, receiver_key: int, nonce: int, *, sender_key: int = 0) -> bytes:
    """Wrap a synthetic datagram using the verify key advertised by its recipient."""
    # Stock EncryptedDatagramSocket::EncryptSendClient: the key hashes the
    # little-endian receiver key and the two-byte nonce. Kad begins RC4 at byte 0.
    key = hashlib.md5(struct.pack("<IH", receiver_key, nonce), usedforsecurity=False).digest()
    data = bytearray(struct.pack("<IBII", 0x395F2EC1, 0, receiver_key, sender_key) + payload)
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
    return b"\x02" + struct.pack("<H", nonce) + data
