from __future__ import annotations

import struct

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness import server_udp_metadata_diagnostic_evidence as evidence


ANCHOR = "127.0.0.1:4661"
TARGET = "127.0.0.1:4761"
TARGET_UDP = "127.0.0.1:4765"
SEED_NAME = "seed-before-udp"
SEED_DESCRIPTION = "seed description before UDP metadata"
SERVER_NAME = "emulebb-local-e2e"
SERVER_DESCRIPTION = "Workspace deterministic eMuleBB live E2E server"


def _tag(tag_id: int, value: str) -> bytes:
    encoded = value.encode()
    return bytes([0x80 | ed2k_wire.TAGTYPE_STRING, tag_id]) + struct.pack("<H", len(encoded)) + encoded


def _packet(seq: int, opcode: int, direction: str, payload: bytes, trace_id: int) -> dict[str, object]:
    return {
        "family": "ed2k_server_udp",
        "event": "packet",
        "seq": seq,
        "keys": {
            "peer": TARGET_UDP,
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
        },
        "body": {
            "flow": "server",
            "phase": "udp",
            "direction": direction,
            "outcome": "attempted" if direction == "send" else "accepted",
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "transportMode": "plaintext",
            "obfuscated": False,
            "payloadLen": len(payload),
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
        },
    }


def _applied(
    seq: int,
    event: str,
    opcode: int,
    challenge: int,
    trace_id: int,
    fields: dict[str, object],
) -> dict[str, object]:
    return {
        "family": "ed2k_server_udp",
        "event": event,
        "seq": seq,
        "keys": {
            "peer": TARGET_UDP,
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "challenge": challenge,
        },
        "body": {
            "flow": "server",
            "phase": "udp",
            "direction": "meta",
            "outcome": "applied",
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "challenge": challenge,
            "serverEndpoint": TARGET,
            "transportMode": "plaintext",
            "obfuscated": False,
            **fields,
        },
    }


def _records() -> list[dict[str, object]]:
    status_challenge = 0x55AA_1234
    description_challenge = 0x4321_F0FF
    status = struct.pack(
        "<IIIIIIIIHHI",
        status_challenge,
        1,
        1,
        1000,
        5000,
        200000,
        0x123,
        0,
        0,
        0,
        0,
    )
    description = (
        struct.pack("<II", description_challenge, 2)
        + _tag(ed2k_wire.ST_SERVERNAME, SERVER_NAME)
        + _tag(ed2k_wire.ST_DESCRIPTION, SERVER_DESCRIPTION)
    )
    return [
        _packet(1, ed2k_wire.OP_GLOBSERVSTATREQ, "send", struct.pack("<I", status_challenge), 10),
        _packet(2, ed2k_wire.OP_GLOBSERVSTATRES, "recv", status, 20),
        _applied(
            3,
            "server_status_applied",
            ed2k_wire.OP_GLOBSERVSTATRES,
            status_challenge,
            20,
            {
                "users": 1,
                "files": 1,
                "maxUsers": 1000,
                "softFiles": 5000,
                "hardFiles": 200000,
                "udpFlags": 0x123,
                "lowIdUsers": 0,
                "obfuscationPortUdp": 0,
                "obfuscationPortTcp": 0,
                "udpKey": 0,
            },
        ),
        _packet(4, ed2k_wire.OP_SERVER_DESC_REQ, "send", struct.pack("<I", description_challenge), 30),
        _packet(5, ed2k_wire.OP_SERVER_DESC_RES, "recv", description, 40),
        _applied(
            6,
            "server_description_applied",
            ed2k_wire.OP_SERVER_DESC_RES,
            description_challenge,
            40,
            {
                "responseFormat": "tagged",
                "name": SERVER_NAME,
                "description": SERVER_DESCRIPTION,
                "dynamicHost": "",
                "version": "",
            },
        ),
    ]


def _snapshots() -> dict[str, dict[str, object]]:
    return {
        client: {
            "connectionStatus": {
                "connected": True,
                "currentServer": {"address": "127.0.0.1", "port": 4661},
            },
            "serverEntity": {
                "address": "127.0.0.1",
                "port": 4761,
                "name": SERVER_NAME,
                "description": SERVER_DESCRIPTION,
                "users": 1,
                "files": 1,
                "softFiles": 5000,
                "hardFiles": 200000,
            },
        }
        for client in ("rust", "mfc")
    }


def _build(
    *,
    rust_records: list[dict[str, object]] | None = None,
    mfc_records: list[dict[str, object]] | None = None,
    snapshots: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    return evidence.build_server_udp_metadata_diagnostic_evidence(
        anchor_server_endpoint=ANCHOR,
        target_server_endpoint=TARGET,
        target_udp_endpoint=TARGET_UDP,
        seed_name=SEED_NAME,
        seed_description=SEED_DESCRIPTION,
        expected_name=SERVER_NAME,
        expected_description=SERVER_DESCRIPTION,
        expected_users=1,
        expected_files=1,
        rust_records=rust_records or _records(),
        mfc_records=mfc_records or _records(),
        rest_snapshots=snapshots or _snapshots(),
    )


def test_builds_complete_bilateral_udp_metadata_proof() -> None:
    result = _build()

    assert result["passed"] is True
    assert result["eligibleCoverageIds"] == list(evidence.ELIGIBLE_COVERAGE_IDS)
    assert result["bilateral"]["ok"] is True
    assert all(result["clients"][client]["ok"] for client in ("rust", "mfc"))
    evidence.require_server_udp_metadata_diagnostic_evidence(result)


def test_rejects_mismatched_reply_challenge() -> None:
    records = _records()
    reply = records[1]
    payload = bytearray.fromhex(reply["body"]["payloadHex"])
    payload[:4] = struct.pack("<I", 0x55AA_9999)
    reply["body"]["payloadHex"] = payload.hex()

    result = _build(rust_records=records)

    assert result["passed"] is False
    assert result["clients"]["rust"]["wire"]["ok"] is False
    with pytest.raises(RuntimeError, match="did not pass"):
        evidence.require_server_udp_metadata_diagnostic_evidence(result)


def test_rejects_missing_applied_record() -> None:
    records = [record for record in _records() if record.get("event") != "server_description_applied"]

    result = _build(mfc_records=records)

    assert result["passed"] is False
    assert result["clients"]["mfc"]["applied"]["description"]["count"] == 0


def test_rejects_unchanged_seed_state() -> None:
    snapshots = _snapshots()
    snapshots["rust"]["serverEntity"]["name"] = SEED_NAME

    result = _build(snapshots=snapshots)

    assert result["passed"] is False
    assert result["clients"]["rust"]["rest"]["ok"] is False


def test_rejects_duplicate_matching_packet() -> None:
    records = _records()
    records.append(dict(records[0]))

    result = _build(rust_records=records)

    assert result["passed"] is False
    assert result["clients"]["rust"]["wire"]["packetCounts"]["statusRequest"] == 2
