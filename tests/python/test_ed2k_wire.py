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

    assert ed2k_wire.decode_login_request(payload) == {
        "user_hash": bytes(range(16)).hex().upper(),
        "client_id": 0,
        "tcp_port": 4662,
        "tag_count": 2,
        "tags": [
            {"name": ed2k_wire.CT_NAME, "value": "wire-probe"},
            {
                "name": ed2k_wire.CT_SERVER_FLAGS,
                "value": ed2k_wire.DEFAULT_SERVER_FLAGS,
            },
        ],
    }


@pytest.mark.unit
def test_login_request_decoder_rejects_trailing_bytes() -> None:
    payload = ed2k_wire.encode_login_request(
        user_hash=bytes(range(16)),
        tcp_port=4662,
        nickname="wire-probe",
    )

    with pytest.raises(ed2k_wire.Ed2kWireError, match="trailing bytes"):
        ed2k_wire.decode_login_request(payload + b"\x00")


@pytest.mark.unit
def test_server_session_reply_decoders_are_exact() -> None:
    assert ed2k_wire.decode_id_change(struct.pack("<I", 7) + b"extension") == {
        "assigned_id": 7,
        "id_kind": "low-id",
        "extension_hex": b"extension".hex().upper(),
    }
    assert ed2k_wire.decode_server_status(struct.pack("<II", 2, 1)) == {
        "users": 2,
        "files": 1,
    }

    with pytest.raises(ed2k_wire.Ed2kWireError, match="trailing bytes"):
        ed2k_wire.decode_server_status(struct.pack("<II", 2, 1) + b"\x00")


@pytest.mark.unit
def test_server_udp_status_transaction_decoder_preserves_extended_fields() -> None:
    challenge = 0x55AA_1234
    request = struct.pack("<I", challenge)
    response = struct.pack(
        "<IIIIIIIIHHI",
        challenge,
        1,
        1,
        1000,
        5000,
        200000,
        ed2k_wire.SERVER_UDP_FLAG_UDPOBFUSCATION
        | ed2k_wire.SERVER_UDP_FLAG_TCPOBFUSCATION,
        0,
        0,
        0,
        0x11223344,
    )

    assert ed2k_wire.decode_server_udp_status_request(request) == {
        "challenge": challenge
    }
    assert ed2k_wire.decode_server_udp_status_response(
        response,
        expected_challenge=challenge,
        server_port=4661,
    ) == {
        "challenge": challenge,
        "users": 1,
        "files": 1,
        "max_users": 1000,
        "soft_files": 5000,
        "hard_files": 200000,
        "udp_flags": 0x600,
        "low_id_users": 0,
        "wire_obfuscation_port_udp": 0,
        "wire_obfuscation_port_tcp": 0,
        "obfuscation_port_udp": 4673,
        "obfuscation_port_tcp": 4661,
        "udp_key": 0x11223344,
        "trailing_hex": "",
    }

    with pytest.raises(ed2k_wire.Ed2kWireError, match="does not match"):
        ed2k_wire.decode_server_udp_status_response(
            response,
            expected_challenge=challenge + 1,
        )


@pytest.mark.unit
def test_server_udp_description_decoder_requires_modern_challenge_and_exact_tags() -> None:
    challenge = 0x1234_F0FF
    tags = b"".join(
        [
            bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_SERVERNAME])
            + struct.pack("<H", 12)
            + b"local-server",
            bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_DESCRIPTION])
            + struct.pack("<H", 13)
            + b"deterministic",
            bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_UINT32, ed2k_wire.ST_VERSION])
            + struct.pack("<I", (17 << 16) | 6),
            bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_AUXPORTSLIST])
            + struct.pack("<H", 13)
            + b"4661, 4662, 0",
        ]
    )
    response = struct.pack("<II", challenge, 4) + tags

    assert ed2k_wire.decode_server_udp_description_request(
        struct.pack("<I", challenge)
    ) == {"challenge": challenge}
    decoded = ed2k_wire.decode_server_udp_description_response(
        response,
        expected_challenge=challenge,
    )
    assert decoded["name"] == "local-server"
    assert decoded["description"] == "deterministic"
    assert decoded["version"] == "17.06"
    assert decoded["auxiliary_ports"] == [4661, 4662]
    assert decoded["response_format"] == "tagged"

    with pytest.raises(ed2k_wire.Ed2kWireError, match="modern challenged format"):
        ed2k_wire.decode_server_udp_description_response(b"\x06\x00Server\x00\x00")


@pytest.mark.unit
def test_server_ident_decoder_preserves_identity_and_tags() -> None:
    payload = (
        bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        + bytes([192, 0, 2, 10])
        + struct.pack("<H", 4661)
        + struct.pack("<I", 3)
        + bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_SERVERNAME])
        + struct.pack("<H", 12)
        + b"local-server"
        + bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_DESCRIPTION])
        + struct.pack("<H", 13)
        + b"deterministic"
        + bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_UINT32, 0x87])
        + struct.pack("<I", 1000)
    )

    assert ed2k_wire.decode_server_ident(payload) == {
        "server_hash": "00112233445566778899AABBCCDDEEFF",
        "advertised_ip": "192.0.2.10",
        "advertised_port": 4661,
        "name": "local-server",
        "description": "deterministic",
        "tags": [
            {"name": ed2k_wire.ST_SERVERNAME, "value": "local-server"},
            {"name": ed2k_wire.ST_DESCRIPTION, "value": "deterministic"},
            {"name": 0x87, "value": 1000},
        ],
    }


@pytest.mark.unit
def test_server_ident_decoder_rejects_trailing_bytes() -> None:
    with pytest.raises(ed2k_wire.Ed2kWireError, match="trailing bytes"):
        ed2k_wire.decode_server_ident(bytes(16 + 4 + 2) + struct.pack("<I", 0) + b"\x00")


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
