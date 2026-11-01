from __future__ import annotations

import struct
import zlib

import pytest

from emule_test_harness import ed2k_wire


@pytest.mark.unit
def test_clear_and_packed_frames_decode_to_the_same_payload() -> None:
    payload = b"protocol evidence"
    clear = ed2k_wire.encode_frame(0x42, payload)
    packed_body = zlib.compress(payload)
    packed = (
        bytes([ed2k_wire.PROTO_PACKED])
        + struct.pack("<I", len(packed_body) + 1)
        + b"\x42"
        + packed_body
    )

    assert ed2k_wire.decode_frame_bytes(clear).payload == payload
    assert ed2k_wire.decode_frame_bytes(packed).payload == payload


@pytest.mark.unit
def test_login_request_uses_stock_tags_without_private_highid_controls() -> None:
    payload = ed2k_wire.encode_login_request(
        user_hash=bytes(range(16)),
        tcp_port=4662,
        nickname="wire-probe",
    )

    assert payload[:16] == bytes(range(16))
    assert payload[16:22] == struct.pack("<IH", 0, 4662)
    assert int.from_bytes(payload[22:26], "little") == 2
    assert b"wire-probe" in payload
    assert ed2k_wire.DEFAULT_SERVER_FLAGS & ed2k_wire.SRVCAP_LUGDUNUM_NAT_CALLBACK


@pytest.mark.unit
def test_search_result_decoder_preserves_hash_size_and_source_counts() -> None:
    file_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    tags = b"".join(
        [
            bytes([0x82, ed2k_wire.FT_FILENAME])
            + struct.pack("<H", 11)
            + b"fixture.bin",
            bytes([0x89, ed2k_wire.FT_FILESIZE]) + b"\x7b",
            bytes([0x89, ed2k_wire.FT_SOURCES]) + b"\x02",
            bytes([0x89, ed2k_wire.FT_COMPLETE_SOURCES]) + b"\x01",
        ]
    )
    payload = (
        struct.pack("<I", 1)
        + file_hash
        + struct.pack("<IH", 0x01020304, 4662)
        + struct.pack("<I", 4)
        + tags
        + b"\x00"
    )

    assert ed2k_wire.decode_search_results(payload) == [
        {
            "hash": file_hash.hex().upper(),
            "name": "fixture.bin",
            "size": 123,
            "sources": 2,
            "complete_sources": 1,
            "result_source_id": 0x01020304,
            "result_source_port": 4662,
        }
    ]


@pytest.mark.unit
def test_obfuscated_source_decoder_distinguishes_lowid_and_highid() -> None:
    file_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    user_hash = bytes.fromhex("FFEEDDCCBBAA99887766554433221100")
    payload = (
        file_hash
        + b"\x02"
        + struct.pack("<IHB", 7, 4662, 0)
        + struct.pack("<IHB", int.from_bytes(b"\xc0\x00\x02\x0a", "little"), 4663, 0x81)
        + user_hash
    )

    decoded = ed2k_wire.decode_found_sources(payload, obfuscated=True)

    assert decoded["source_count"] == 2
    assert decoded["sources"][0] == {
        "kind": "low-id",
        "client_id": 7,
        "host": None,
        "port": 4662,
        "crypt_options": 0,
        "user_hash": None,
    }
    assert decoded["sources"][1] == {
        "kind": "high-id",
        "client_id": int.from_bytes(b"\xc0\x00\x02\x0a", "little"),
        "host": "192.0.2.10",
        "port": 4663,
        "crypt_options": 0x81,
        "user_hash": user_hash.hex().upper(),
    }
