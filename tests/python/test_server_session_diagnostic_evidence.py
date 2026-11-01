from __future__ import annotations

import struct

from emule_test_harness import ed2k_wire
from emule_test_harness import server_session_diagnostic_evidence as evidence

ENDPOINT = "127.0.0.1:4661"
NICKNAME = "cl-emulebb-rust-005"
TCP_PORT = 4662
TRACE_ID = 7


def record(
    seq: int,
    event: str,
    *,
    keys: dict[str, object],
    body: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "seq": seq,
        "streamSeq": seq,
        "family": "ed2k_tcp",
        "event": event,
        "keys": keys,
        "body": body,
    }


def connection_state(
    seq: int,
    outcome: str,
    state: str,
    *,
    obfuscated: bool = True,
) -> dict[str, object]:
    mode = "obfuscated" if obfuscated else "plaintext"
    return record(
        seq,
        "connection_state",
        keys={"flow": "server", "peer": ENDPOINT, "traceId": TRACE_ID},
        body={
            "flow": "server",
            "obfuscated": obfuscated,
            "outcome": outcome,
            "phase": "connection",
            "state": state,
            "traceId": TRACE_ID,
            "transportMode": mode,
        },
    )


def packet(
    seq: int,
    direction: str,
    opcode: int,
    payload: bytes,
    *,
    send_attempt_id: int | None = None,
    obfuscated: bool = True,
) -> dict[str, object]:
    mode = "obfuscated" if obfuscated else "plaintext"
    clear_frame = ed2k_wire.encode_frame(opcode, payload)
    raw_frame = bytes(value ^ 0xA5 for value in clear_frame) if obfuscated else clear_frame
    keys: dict[str, object] = {
        "opcode": opcode,
        "peer": ENDPOINT,
        "protocolMarker": ed2k_wire.PROTO_EDONKEY,
    }
    if send_attempt_id is not None:
        keys["sendAttemptId"] = send_attempt_id
    return record(
        seq,
        "packet",
        keys=keys,
        body={
            "clearFrameHex": clear_frame.hex(),
            "clearFrameLen": len(clear_frame),
            "direction": direction,
            "flow": "server",
            "obfuscated": obfuscated,
            "opcode": opcode,
            "outcome": "attempted" if direction == "send" else "accepted",
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(payload),
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "rawHex": raw_frame.hex(),
            "rawLen": len(raw_frame),
            "sendAttemptId": send_attempt_id,
            "traceId": TRACE_ID,
            "transportMode": mode,
        },
    )


def rust_login_payload(user_hash: bytes) -> bytes:
    nickname = NICKNAME.encode("utf-8")
    extension_name = b"offerfiles_v"
    tags = [
        bytes([0x80 | ed2k_wire.TAGTYPE_STRING, ed2k_wire.CT_NAME])
        + struct.pack("<H", len(nickname))
        + nickname,
        bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, evidence.CT_VERSION])
        + struct.pack("<I", 60),
        bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, ed2k_wire.CT_SERVER_FLAGS])
        + struct.pack("<I", evidence.REQUIRED_SERVER_FLAGS),
        bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, 0xFB]) + struct.pack("<I", 73_728),
        bytes([ed2k_wire.TAGTYPE_UINT32])
        + struct.pack("<H", len(extension_name))
        + extension_name
        + struct.pack("<I", 1),
    ]
    return (
        user_hash
        + struct.pack("<IH", 0, TCP_PORT)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def canonical_records(*, obfuscated: bool = True) -> list[dict[str, object]]:
    login_payload = rust_login_payload(
        bytes.fromhex("00112233440E66778899AABBCCDD6FEF")
    )
    return [
        connection_state(1, "attempt_started", "connecting", obfuscated=obfuscated),
        packet(
            2,
            "send",
            ed2k_wire.OP_LOGINREQUEST,
            login_payload,
            send_attempt_id=11,
            obfuscated=obfuscated,
        ),
        record(
            3,
            "send_outcome",
            keys={
                "opcode": ed2k_wire.OP_LOGINREQUEST,
                "peer": ENDPOINT,
                "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                "sendAttemptId": 11,
            },
            body={
                "deliveryKnown": True,
                "direction": "send",
                "flow": "server",
                "obfuscated": obfuscated,
                "opcode": ed2k_wire.OP_LOGINREQUEST,
                "outcome": "send_succeeded",
                "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                "transportMode": "obfuscated" if obfuscated else "plaintext",
            },
        ),
        connection_state(
            4,
            "transport_connected",
            "awaiting_idchange",
            obfuscated=obfuscated,
        ),
        packet(
            5,
            "recv",
            ed2k_wire.OP_IDCHANGE,
            struct.pack("<I", 7),
            obfuscated=obfuscated,
        ),
        connection_state(6, "login_accepted", "connected", obfuscated=obfuscated),
        packet(
            7,
            "recv",
            ed2k_wire.OP_SERVERSTATUS,
            struct.pack("<II", 2, 1),
            obfuscated=obfuscated,
        ),
    ]


def build(
    records: list[dict[str, object]] | None = None,
    *,
    transport_mode: str = "obfuscated",
) -> dict[str, object]:
    return evidence.build_server_session_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        expected_nickname=NICKNAME,
        expected_tcp_port=TCP_PORT,
        expected_transport_mode=transport_mode,
        expected_users=2,
        expected_files=1,
        rust_records=canonical_records() if records is None else records,
    )


def test_exact_obfuscated_session_is_claimable() -> None:
    report = build()

    assert report["ok"] is True
    assert report["checks"]["connection"]["traceId"] == TRACE_ID
    assert report["checks"]["login"]["decoded"]["tcp_port"] == TCP_PORT
    assert report["checks"]["idChange"]["decoded"]["id_kind"] == "low-id"
    assert report["checks"]["status"]["decoded"] == {"users": 2, "files": 1}
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": [
            "server.connect.obfuscated",
            "server.login.request",
            "server.reply.status",
        ],
        "evidenceLayers": list(evidence.EVIDENCE_LAYERS),
    }
    evidence.require_server_session_diagnostic_evidence(report)


def test_exact_plaintext_session_is_claimable_without_obfuscation() -> None:
    report = build(canonical_records(obfuscated=False), transport_mode="plaintext")

    assert report["ok"] is True
    assert report["coverageClaims"]["eligibleCoverageIds"][0] == "server.connect.plaintext"


def test_transport_intent_cannot_substitute_for_observed_transport() -> None:
    report = build(canonical_records(obfuscated=False), transport_mode="obfuscated")

    assert report["ok"] is False
    assert report["checks"]["connection"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_duplicate_connection_attempt_is_not_one_session() -> None:
    records = canonical_records()
    records.insert(1, connection_state(0, "attempt_started", "connecting"))

    report = build(records)

    assert report["ok"] is False
    assert report["checks"]["connection"]["connectionRecordCount"] == 4


def test_login_requires_stock_identity_markers_and_successful_send() -> None:
    records = canonical_records()
    login_payload = rust_login_payload(
        bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    )
    records[1] = packet(
        2,
        "send",
        ed2k_wire.OP_LOGINREQUEST,
        login_payload,
        send_attempt_id=11,
    )
    records.pop(2)

    report = build(records)

    assert report["ok"] is False
    assert report["checks"]["login"]["stockIdentityMarkers"] is False
    assert report["checks"]["login"]["sendSucceeded"] is False


def test_status_must_match_the_deterministic_server_state() -> None:
    records = canonical_records()
    records[-1] = packet(
        7,
        "recv",
        ed2k_wire.OP_SERVERSTATUS,
        struct.pack("<II", 3, 1),
    )

    report = build(records)

    assert report["ok"] is False
    assert report["checks"]["status"]["decoded"] == {"users": 3, "files": 1}


def test_status_before_login_acceptance_is_not_causal() -> None:
    records = canonical_records()
    records[-1]["seq"] = 5
    records[-1]["streamSeq"] = 5

    report = build(records)

    assert report["ok"] is False
    assert report["checks"]["status"]["ok"] is False
