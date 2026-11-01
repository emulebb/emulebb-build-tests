from __future__ import annotations

import struct

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness import server_tcp_metadata_diagnostic_evidence as evidence


ENDPOINT = "127.0.0.1:4661"
SEED_NAME = "seed-before-ident"
SERVER_NAME = "emulebb-local-e2e"
SERVER_DESCRIPTION = "Workspace deterministic eMuleBB live E2E server"


def _ident_payload() -> bytes:
    name = SERVER_NAME.encode()
    description = SERVER_DESCRIPTION.encode()
    tags = (
        bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_SERVERNAME])
        + struct.pack("<H", len(name))
        + name
        + bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_STRING, ed2k_wire.ST_DESCRIPTION])
        + struct.pack("<H", len(description))
        + description
    )
    return (
        bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        + bytes([192, 0, 2, 10])
        + struct.pack("<H", 4661)
        + struct.pack("<I", 2)
        + tags
    )


def _packet(seq: int, opcode: int, direction: str, payload: bytes, trace_id: int) -> dict[str, object]:
    return {
        "family": "ed2k_tcp",
        "event": "packet",
        "seq": seq,
        "keys": {
            "peer": ENDPOINT,
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
        },
        "body": {
            "flow": "server",
            "direction": direction,
            "outcome": "accepted",
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "payloadLen": len(payload),
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
            "transportMode": "obfuscated",
        },
    }


def _applied(
    seq: int,
    event: str,
    opcode: int,
    trace_id: int,
    **fields: object,
) -> dict[str, object]:
    return {
        "family": "ed2k_tcp",
        "event": event,
        "seq": seq,
        "keys": {
            "peer": ENDPOINT,
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
        },
        "body": {
            "direction": "meta",
            "outcome": "applied",
            "flow": "server",
            "traceId": trace_id,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "transportMode": "obfuscated",
            **fields,
        },
    }


def _records(*, trace_id: int, users: int, files: int) -> list[dict[str, object]]:
    return [
        _packet(1, ed2k_wire.OP_IDCHANGE, "recv", struct.pack("<I", 7), trace_id),
        _packet(2, evidence.GET_SERVER_LIST_OPCODE, "send", b"", trace_id),
        _packet(3, ed2k_wire.OP_SERVERSTATUS, "recv", struct.pack("<II", users, files), trace_id),
        _packet(4, ed2k_wire.OP_SERVERIDENT, "recv", _ident_payload(), trace_id),
        _applied(
            5,
            "server_status_applied",
            ed2k_wire.OP_SERVERSTATUS,
            trace_id,
            users=users,
            files=files,
        ),
        _applied(
            6,
            "server_ident_applied",
            ed2k_wire.OP_SERVERIDENT,
            trace_id,
            name=SERVER_NAME,
            description=SERVER_DESCRIPTION,
        ),
    ]


def _rest(users: int, files: int) -> dict[str, object]:
    return {
        "connectionStatus": {
            "connected": True,
            "currentServer": {
                "current": True,
                "address": "127.0.0.1",
                "port": 4661,
                "name": SEED_NAME,
            },
        },
        "serverEntity": {
            "address": "127.0.0.1",
            "port": 4661,
            "name": SERVER_NAME,
            "description": SERVER_DESCRIPTION,
            "users": users,
            "files": files,
        },
    }


def _build() -> dict[str, object]:
    return evidence.build_server_tcp_metadata_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        seed_name=SEED_NAME,
        expected_name=SERVER_NAME,
        expected_description=SERVER_DESCRIPTION,
        rust_records=_records(trace_id=11, users=2, files=1),
        mfc_records=_records(trace_id=22, users=3, files=2),
        rest_snapshots={"rust": _rest(2, 1), "mfc": _rest(3, 2)},
    )


def test_bilateral_tcp_metadata_proof_accepts_per_client_dynamic_counts() -> None:
    report = _build()

    evidence.require_server_tcp_metadata_diagnostic_evidence(report)
    assert report["ok"] is True
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "server.reply.tcp-ident",
        "server.reply.tcp-status",
    ]
    assert report["clients"]["rust"]["wire"]["status"] == {"users": 2, "files": 1}
    assert report["clients"]["mfc"]["wire"]["status"] == {"users": 3, "files": 2}


def test_tcp_metadata_proof_rejects_missing_post_apply_event() -> None:
    mfc_records = _records(trace_id=22, users=3, files=2)
    mfc_records.pop()

    report = evidence.build_server_tcp_metadata_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        seed_name=SEED_NAME,
        expected_name=SERVER_NAME,
        expected_description=SERVER_DESCRIPTION,
        rust_records=_records(trace_id=11, users=2, files=1),
        mfc_records=mfc_records,
        rest_snapshots={"rust": _rest(2, 1), "mfc": _rest(3, 2)},
    )

    assert report["ok"] is False
    assert report["observedCoverageIds"] == []
    with pytest.raises(RuntimeError, match="incomplete"):
        evidence.require_server_tcp_metadata_diagnostic_evidence(report)


def test_tcp_metadata_proof_rejects_rest_state_not_equal_to_wire() -> None:
    report = evidence.build_server_tcp_metadata_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        seed_name=SEED_NAME,
        expected_name=SERVER_NAME,
        expected_description=SERVER_DESCRIPTION,
        rust_records=_records(trace_id=11, users=2, files=1),
        mfc_records=_records(trace_id=22, users=3, files=2),
        rest_snapshots={"rust": _rest(999, 1), "mfc": _rest(3, 2)},
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["rest"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_tcp_metadata_proof_rejects_duplicate_or_malformed_wire_reply() -> None:
    rust_records = _records(trace_id=11, users=2, files=1)
    duplicate = dict(rust_records[2])
    duplicate["seq"] = 7
    rust_records.append(duplicate)

    report = evidence.build_server_tcp_metadata_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        seed_name=SEED_NAME,
        expected_name=SERVER_NAME,
        expected_description=SERVER_DESCRIPTION,
        rust_records=rust_records,
        mfc_records=_records(trace_id=22, users=3, files=2),
        rest_snapshots={"rust": _rest(2, 1), "mfc": _rest(3, 2)},
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["wire"]["packetCounts"]["status"] == 2


def test_tcp_metadata_proof_requires_one_schema_only() -> None:
    report = _build()
    report["schema"] = "emulebb-build-tests.deterministic-server-tcp-metadata-diagnostics.v0"

    with pytest.raises(RuntimeError, match="unexpected schema"):
        evidence.require_server_tcp_metadata_diagnostic_evidence(report)
