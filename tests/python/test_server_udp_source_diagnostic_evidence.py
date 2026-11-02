from __future__ import annotations

from copy import deepcopy

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness.scripted_ed2k_udp_source import (
    SERVER_UDP_FLAG_EXT_GETSOURCES,
    SERVER_UDP_FLAG_EXT_GETSOURCES2,
    V1_TRANSCRIPT_SCHEMA,
    V2_TRANSCRIPT_SCHEMA,
)
from emule_test_harness.server_udp_source_diagnostic_evidence import (
    build_server_udp_source_diagnostic_evidence,
    require_server_udp_source_diagnostic_evidence,
)


FILE_HASH = "22334455667788990011aabbccddeeff"
SERVER_ENDPOINT = "192.0.2.10:4661"
UDP_ENDPOINT = "192.0.2.10:4665"
SOURCE_HOST = "198.18.240.2"
SOURCE_PORT = 4662
SOURCE_ID = int.from_bytes(bytes((198, 18, 240, 2)), "little")
FILE_NAME = "deterministic-server-udp-source.bin"
FILE_SIZE = 67_890


def _record(
    *,
    sequence: int,
    event: str,
    opcode: int,
    direction: str,
    trace_id: int,
    send_attempt_id: int | None = None,
    payload: bytes | None = None,
    body_extra: dict[str, object] | None = None,
    keys_extra: dict[str, object] | None = None,
) -> dict[str, object]:
    keys = {
        "peer": UDP_ENDPOINT,
        "protocolMarker": ed2k_wire.PROTO_EDONKEY,
        "opcode": opcode,
        "traceId": trace_id,
    }
    keys.update(keys_extra or {})
    body: dict[str, object] = {
        "flow": "server",
        "phase": "udp" if event != "source_result_applied" else "source_search",
        "direction": direction,
        "outcome": "attempted" if direction == "send" else "accepted",
        "protocolMarker": ed2k_wire.PROTO_EDONKEY,
        "opcode": opcode,
        "traceId": trace_id,
        "transportMode": "plaintext",
        "obfuscated": False,
    }
    if send_attempt_id is not None:
        keys["sendAttemptId"] = send_attempt_id
        body["sendAttemptId"] = send_attempt_id
    if payload is not None:
        body.update(
            {
                "payloadLen": len(payload),
                "payloadHex": payload.hex(),
                "payloadHexTruncated": False,
            }
        )
    body.update(body_extra or {})
    return {
        "schema": "diag_event_v2",
        "seq": sequence,
        "family": "ed2k_server_udp",
        "event": event,
        "keys": keys,
        "body": body,
    }


def _records(
    *, rust: bool, source_request_version: int = 1
) -> list[dict[str, object]]:
    file_hash = bytes.fromhex(FILE_HASH)
    request_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES2
    )
    request_opcode_name = (
        "OP_GLOBGETSOURCES"
        if source_request_version == 1
        else "OP_GLOBGETSOURCES2"
    )
    request_datagram = (
        ed2k_wire.encode_server_udp_source_v1_request([file_hash])
        if source_request_version == 1
        else ed2k_wire.encode_server_udp_source_v2_request(
            [(file_hash, FILE_SIZE)]
        )
    )
    request_payload = request_datagram[2:]
    reply_payload = ed2k_wire.encode_server_udp_source_reply(
        file_hash=file_hash,
        sources=[(SOURCE_ID, SOURCE_PORT)],
    )[2:]
    records = [
        _record(
            sequence=10,
            event="packet",
            opcode=request_opcode,
            direction="send",
            trace_id=0 if rust else 31,
            send_attempt_id=5 if rust else None,
            payload=request_payload,
        )
    ]
    if rust:
        records.append(
            _record(
                sequence=11,
                event="send_outcome",
                opcode=request_opcode,
                direction="send",
                trace_id=0,
                send_attempt_id=5,
                body_extra={"outcome": "send_succeeded", "deliveryKnown": True},
            )
        )
    records.extend(
        [
            _record(
                sequence=12,
                event="packet",
                opcode=ed2k_wire.OP_GLOBFOUNDSOURCES,
                direction="recv",
                trace_id=32,
                payload=reply_payload,
            ),
            _record(
                sequence=13,
                event="source_result_applied",
                opcode=ed2k_wire.OP_GLOBFOUNDSOURCES,
                direction="recv",
                trace_id=32,
                keys_extra={
                    "fileHash": FILE_HASH,
                    "requestOpcode": request_opcode,
                },
                body_extra={
                    "outcome": "applied",
                    "requestOpcode": request_opcode,
                    "requestOpcodeName": request_opcode_name,
                    "serverEndpoint": SERVER_ENDPOINT,
                    "stateId": "server.source.result_applied",
                    "milestone": "result_applied",
                    "wireSourceCount": 1,
                    "sourceCountBefore": 0,
                    "sourceCountAfter": 1,
                },
            ),
        ]
    )
    return records


def _transcript(source_request_version: int = 1) -> dict[str, object]:
    request_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES2
    )
    request = (
        ed2k_wire.encode_server_udp_source_v1_request([bytes.fromhex(FILE_HASH)])
        if source_request_version == 1
        else ed2k_wire.encode_server_udp_source_v2_request(
            [(bytes.fromhex(FILE_HASH), FILE_SIZE)]
        )
    )
    reply = ed2k_wire.encode_server_udp_source_reply(
        file_hash=bytes.fromhex(FILE_HASH),
        sources=[(SOURCE_ID, SOURCE_PORT)],
    )
    events = []
    for index, peer in enumerate(("192.0.2.20:41000", "192.0.2.21:41001")):
        status_request_sequence = index * 4 + 1
        status_reply_sequence = status_request_sequence + 1
        source_request_sequence = status_request_sequence + 2
        source_reply_sequence = status_request_sequence + 3
        events.extend(
            [
                {
                    "sequence": status_request_sequence,
                    "direction": "recv",
                    "peer": peer,
                    "opcode": ed2k_wire.OP_GLOBSERVSTATREQ,
                    "accepted": True,
                },
                {
                    "sequence": status_reply_sequence,
                    "direction": "send",
                    "peer": peer,
                    "opcode": ed2k_wire.OP_GLOBSERVSTATRES,
                    "accepted": True,
                },
                {
                    "sequence": source_request_sequence,
                    "direction": "recv",
                    "peer": peer,
                    "opcode": request_opcode,
                    "frameHex": request.hex().upper(),
                    "accepted": True,
                },
                {
                    "sequence": source_reply_sequence,
                    "direction": "send",
                    "peer": peer,
                    "opcode": ed2k_wire.OP_GLOBFOUNDSOURCES,
                    "frameHex": reply.hex().upper(),
                    "accepted": True,
                },
            ]
        )
    transcript = {
        "schema": (
            V1_TRANSCRIPT_SCHEMA
            if source_request_version == 1
            else V2_TRANSCRIPT_SCHEMA
        ),
        "serverEndpoint": SERVER_ENDPOINT,
        "udpEndpoint": UDP_ENDPOINT,
        "udpFlags": (
            SERVER_UDP_FLAG_EXT_GETSOURCES
            if source_request_version == 1
            else SERVER_UDP_FLAG_EXT_GETSOURCES
            | SERVER_UDP_FLAG_EXT_GETSOURCES2
        ),
        "fileHash": FILE_HASH,
        "source": {
            "host": SOURCE_HOST,
            "clientId": SOURCE_ID,
            "tcpPort": SOURCE_PORT,
        },
        "events": events,
    }
    if source_request_version == 2:
        transcript["fileSize"] = FILE_SIZE
    return transcript


def _build(*, source_request_version: int = 1, **overrides):
    arguments = {
        "source_request_version": source_request_version,
        "expected_file_hash": FILE_HASH,
        "expected_file_name": FILE_NAME,
        "expected_file_size": FILE_SIZE,
        "target_server_endpoint": SERVER_ENDPOINT,
        "target_udp_endpoint": UDP_ENDPOINT,
        "source_host": SOURCE_HOST,
        "source_tcp_port": SOURCE_PORT,
        "rust_records": _records(
            rust=True, source_request_version=source_request_version
        ),
        "mfc_records": _records(
            rust=False, source_request_version=source_request_version
        ),
        "transfer_rows": {
            "rust": {
                "hash": FILE_HASH,
                "displayName": FILE_NAME,
                "sizeBytes": FILE_SIZE,
                "sources": 1,
            },
            "mfc": {
                "hash": FILE_HASH,
                "name": FILE_NAME,
                "sizeBytes": FILE_SIZE,
                "sources": 1,
            },
        },
        "fixture_transcript": _transcript(source_request_version),
    }
    arguments.update(overrides)
    return build_server_udp_source_diagnostic_evidence(**arguments)


def test_udp_source_v1_evidence_accepts_complete_bilateral_trace() -> None:
    evidence = _build()

    require_server_udp_source_diagnostic_evidence(
        evidence, source_request_version=1
    )
    assert evidence["ok"] is True
    assert evidence["eligibleCoverageIds"] == [
        "server.source.udp-v1",
        "server.reply.sources",
    ]
    assert evidence["clients"]["rust"]["wire"]["request"]["traceId"] is None
    assert evidence["clients"]["rust"]["wire"]["request"]["sendAttemptId"] == 5
    assert evidence["clients"]["rust"]["wire"]["sendOutcome"]["sendAttemptId"] == 5


def test_udp_source_v2_evidence_accepts_exact_size_bilateral_trace() -> None:
    evidence = _build(source_request_version=2)

    require_server_udp_source_diagnostic_evidence(
        evidence, source_request_version=2
    )
    assert evidence["eligibleCoverageIds"] == [
        "server.source.udp-v2",
        "server.reply.sources",
    ]
    assert evidence["fixture"]["sourceRequestVersion"] == 2
    assert evidence["fixture"]["requestDatagramHex"] == (
        ed2k_wire.encode_server_udp_source_v2_request(
            [(bytes.fromhex(FILE_HASH), FILE_SIZE)]
        ).hex()
    )
    assert evidence["fixtureTranscript"]["forbiddenV1RequestCount"] == 0


def test_udp_source_v2_evidence_rejects_wrong_wire_size() -> None:
    rust_records = _records(rust=True, source_request_version=2)
    request = rust_records[0]["body"]
    assert isinstance(request, dict)
    wrong_payload = ed2k_wire.encode_server_udp_source_v2_request(
        [(bytes.fromhex(FILE_HASH), FILE_SIZE + 1)]
    )[2:]
    request["payloadHex"] = wrong_payload.hex()
    request["payloadLen"] = len(wrong_payload)

    evidence = _build(
        source_request_version=2,
        rust_records=rust_records,
    )

    assert evidence["ok"] is False
    assert "rust.request" in evidence["failures"]


def test_udp_source_v1_evidence_rejects_mismatched_rust_send_attempt() -> None:
    rust_records = _records(rust=True)
    send_outcome = next(
        record for record in rust_records if record["event"] == "send_outcome"
    )
    send_outcome["keys"]["sendAttemptId"] = 6
    send_outcome["body"]["sendAttemptId"] = 6

    evidence = _build(rust_records=rust_records)

    assert evidence["ok"] is False
    assert "rust.sendOutcome" in evidence["failures"]


def test_udp_source_v1_evidence_ignores_later_request_for_another_hash() -> None:
    rust_records = _records(rust=True)
    rust_records.append(
        _record(
            sequence=14,
            event="packet",
            opcode=ed2k_wire.OP_GLOBGETSOURCES,
            direction="send",
            trace_id=0,
            send_attempt_id=6,
            payload=b"\xff" * 16,
        )
    )

    evidence = _build(rust_records=rust_records)

    require_server_udp_source_diagnostic_evidence(
        evidence, source_request_version=1
    )
    assert evidence["clients"]["rust"]["wire"]["request"]["packetCount"] == 1


def test_udp_source_v1_evidence_rejects_duplicate_request_for_target_hash() -> None:
    rust_records = _records(rust=True)
    rust_records.append(
        _record(
            sequence=14,
            event="packet",
            opcode=ed2k_wire.OP_GLOBGETSOURCES,
            direction="send",
            trace_id=0,
            send_attempt_id=6,
            payload=bytes.fromhex(FILE_HASH),
        )
    )

    evidence = _build(rust_records=rust_records)

    assert evidence["ok"] is False
    assert "rust.request" in evidence["failures"]


def test_udp_source_v1_evidence_rejects_v2_request_even_with_valid_v1_trace() -> None:
    rust_records = _records(rust=True)
    rust_records.append(
        _record(
            sequence=9,
            event="packet",
            opcode=0x94,
            direction="send",
            trace_id=30,
            payload=bytes.fromhex(FILE_HASH) + (67_890).to_bytes(4, "little"),
        )
    )

    evidence = _build(rust_records=rust_records)

    assert evidence["ok"] is False
    assert "rust.request" in evidence["failures"]
    with pytest.raises(RuntimeError, match="incomplete"):
        require_server_udp_source_diagnostic_evidence(
            evidence, source_request_version=1
        )


def test_udp_source_v1_evidence_rejects_fixture_transcript_mutation() -> None:
    transcript = deepcopy(_transcript())
    source_request = next(
        event
        for event in transcript["events"]
        if event.get("opcode") == ed2k_wire.OP_GLOBGETSOURCES
    )
    source_request["frameHex"] += "00"

    evidence = _build(fixture_transcript=transcript)

    assert evidence["ok"] is False
    assert "fixture.transcript" in evidence["failures"]
