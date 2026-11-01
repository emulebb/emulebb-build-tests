from __future__ import annotations

import copy
import struct

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness import server_source_diagnostic_evidence as evidence


FILE_HASH = "22334455667788990011aabbccddeeff"
FILE_NAME = "deterministic-server-source.bin"
FILE_SIZE = 67_890
ENDPOINT = "127.0.0.1:4661"
PUBLISHER_CLIENT_ID = 7
PUBLISHER_TCP_PORT = 48_017


def record(
    client: str,
    seq: int,
    event: str,
    *,
    keys: dict[str, object],
    body: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "seq": seq,
        "streamSeq": seq,
        "family": "ed2k_tcp",
        "event": event,
        "keys": keys,
        "body": body,
    }


def request_record(client: str, seq: int, trace_id: int) -> dict[str, object]:
    payload = ed2k_wire.encode_source_request(bytes.fromhex(FILE_HASH), FILE_SIZE)
    return record(
        client,
        seq,
        "packet",
        keys={
            "opcode": evidence.SOURCE_REQUEST_OPCODE,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "send",
            "flow": "server",
            "obfuscated": False,
            "opcode": evidence.SOURCE_REQUEST_OPCODE,
            "opcodeName": "OP_GETSOURCES",
            "outcome": "attempted",
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(payload),
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": "plaintext",
        },
    )


def send_outcome_record(client: str, seq: int, trace_id: int) -> dict[str, object]:
    return record(
        client,
        seq,
        "send_outcome",
        keys={
            "opcode": evidence.SOURCE_REQUEST_OPCODE,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
        },
        body={
            "deliveryKnown": True,
            "direction": "send",
            "flow": "server",
            "obfuscated": False,
            "opcode": evidence.SOURCE_REQUEST_OPCODE,
            "outcome": "send_succeeded",
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": "plaintext",
        },
    )


def found_sources_payload(
    *,
    file_hash: str = FILE_HASH,
    client_id: int = PUBLISHER_CLIENT_ID,
    tcp_port: int = PUBLISHER_TCP_PORT,
) -> bytes:
    return bytes.fromhex(file_hash) + b"\x01" + struct.pack("<IH", client_id, tcp_port)


def reply_record(
    client: str,
    seq: int,
    trace_id: int,
    *,
    payload: bytes | None = None,
) -> dict[str, object]:
    wire_payload = found_sources_payload() if payload is None else payload
    return record(
        client,
        seq,
        "packet",
        keys={
            "opcode": evidence.SOURCE_REPLY_OPCODE,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "recv",
            "flow": "server",
            "obfuscated": False,
            "opcode": evidence.SOURCE_REPLY_OPCODE,
            "opcodeName": "OP_FOUNDSOURCES",
            "outcome": "accepted",
            "payloadHex": wire_payload.hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(wire_payload),
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": "plaintext",
        },
    )


def application_record(client: str, seq: int, trace_id: int) -> dict[str, object]:
    return record(
        client,
        seq,
        "source_result_applied",
        keys={
            "fileHash": FILE_HASH,
            "opcode": evidence.SOURCE_REPLY_OPCODE,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "recv",
            "flow": "server",
            "milestone": "result_applied",
            "obfuscated": False,
            "opcode": evidence.SOURCE_REPLY_OPCODE,
            "opcodeName": "OP_FOUNDSOURCES",
            "outcome": "applied",
            "phase": "source_search",
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "sourceCountAfter": 1,
            "sourceCountBefore": 0,
            "stateId": "server.source.result_applied",
            "traceId": trace_id,
            "transportMode": "plaintext",
            "wireSourceCount": 1,
        },
    )


def client_records(client: str, trace_id: int) -> list[dict[str, object]]:
    return [
        request_record(client, 10, trace_id),
        send_outcome_record(client, 11, trace_id),
        reply_record(client, 12, trace_id),
        application_record(client, 13, trace_id),
    ]


def transfer_row(client: str) -> dict[str, object]:
    row: dict[str, object] = {
        "hash": FILE_HASH.upper(),
        "sizeBytes": FILE_SIZE,
        "sources": 1,
    }
    row["displayName" if client == "rust" else "name"] = FILE_NAME
    return row


def build(
    *,
    rust: list[dict[str, object]] | None = None,
    mfc: list[dict[str, object]] | None = None,
    rows: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    return evidence.build_server_source_diagnostic_evidence(
        expected_file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        server_endpoint=ENDPOINT,
        publisher_client_id=PUBLISHER_CLIENT_ID,
        publisher_tcp_port=PUBLISHER_TCP_PORT,
        rust_records=client_records("rust", 101) if rust is None else rust,
        mfc_records=client_records("mfc", 202) if mfc is None else mfc,
        transfer_rows=(
            {"rust": transfer_row("rust"), "mfc": transfer_row("mfc")}
            if rows is None
            else rows
        ),
    )


def test_exact_bilateral_plaintext_source_lookup_is_claimable() -> None:
    report = build()

    assert report["schema"] == evidence.SCHEMA
    assert report["ok"] is True
    assert report["failures"] == []
    assert report["clients"]["rust"]["wire"]["request"]["sequence"] == 10
    assert report["clients"]["rust"]["wire"]["sendOutcome"]["sequence"] == 11
    assert report["clients"]["rust"]["wire"]["reply"]["decoded"] == {
        "hash": FILE_HASH.upper(),
        "source_count": 1,
        "sources": [
            {
                "kind": "low-id",
                "client_id": PUBLISHER_CLIENT_ID,
                "host": None,
                "port": PUBLISHER_TCP_PORT,
                "crypt_options": 0,
                "user_hash": None,
            }
        ],
    }
    assert report["clients"]["mfc"]["wire"]["application"]["sequence"] == 13
    assert report["comparison"] == {
        "ok": True,
        "applicationCountsEqual": True,
        "replyHashEqual": True,
        "replyIdentityEqual": True,
        "requestPayloadEqual": True,
        "transportModeEqual": True,
    }
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": list(evidence.ELIGIBLE_COVERAGE_IDS),
        "evidenceLayers": list(evidence.EVIDENCE_LAYERS),
    }
    evidence.require_server_source_diagnostic_evidence(report)


def test_duplicate_request_fails_closed() -> None:
    records = client_records("rust", 101)
    records.insert(0, copy.deepcopy(records[0]))

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["request"]["packetCount"] == 2
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_legacy_diagnostic_record_is_not_accepted() -> None:
    records = client_records("rust", 101)
    records[0]["schema"] = "diag_event_v1"

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["request"]["packetCount"] == 0
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_wrong_request_payload_fails_closed() -> None:
    records = client_records("rust", 101)
    wrong = ed2k_wire.encode_source_request(bytes.fromhex("ff" * 16), FILE_SIZE)
    records[0]["body"]["payloadHex"] = wrong.hex()
    records[0]["body"]["payloadLen"] = len(wrong)

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["request"]["exactPacketCount"] == 0
    assert report["comparison"]["requestPayloadEqual"] is False
    assert report["ok"] is False


def test_wrong_request_size_encoding_fails_closed() -> None:
    records = client_records("mfc", 202)
    wrong = bytes.fromhex(FILE_HASH) + (FILE_SIZE + 1).to_bytes(4, "little")
    records[0]["body"]["payloadHex"] = wrong.hex()

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["request"]["exactPacketCount"] == 0
    assert "mfc.request" in report["failures"]


def test_wrong_send_outcome_trace_fails_closed() -> None:
    records = client_records("rust", 101)
    records[1]["body"]["traceId"] = 999

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["sendOutcome"]["outcomeCount"] == 0
    assert "rust.sendOutcome" in report["failures"]


def test_send_outcome_must_follow_request() -> None:
    records = client_records("rust", 101)
    records[1]["seq"] = 9

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["sendOutcome"]["successfulOutcomeCount"] == 1
    assert report["clients"]["rust"]["wire"]["sendOutcome"]["ok"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [("outcome", "send_failed"), ("deliveryKnown", False), ("transportMode", "obfuscated"), ("obfuscated", True)],
)
def test_send_outcome_must_be_delivered_plaintext(field: str, value: object) -> None:
    records = client_records("mfc", 202)
    records[1]["body"][field] = value

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["sendOutcome"]["successfulOutcomeCount"] == 0
    assert report["ok"] is False


def test_wrong_reply_trace_fails_closed() -> None:
    records = client_records("mfc", 202)
    records[2]["keys"]["traceId"] = 303
    records[2]["body"]["traceId"] = 303

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["reply"]["tracePacketCount"] == 0
    assert "mfc.reply" in report["failures"]


def test_reply_must_follow_successful_send() -> None:
    records = client_records("rust", 101)
    records[2]["seq"] = 10

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["reply"]["exactPacketCount"] == 1
    assert report["clients"]["rust"]["wire"]["reply"]["ok"] is False


@pytest.mark.parametrize(
    "payload",
    [
        found_sources_payload(file_hash="ff" * 16),
        found_sources_payload(client_id=PUBLISHER_CLIENT_ID + 1),
        found_sources_payload(tcp_port=PUBLISHER_TCP_PORT + 1),
        bytes.fromhex(FILE_HASH) + b"\x01" + struct.pack("<IH", 0xC000020A, PUBLISHER_TCP_PORT),
        found_sources_payload() + b"\x00",
    ],
    ids=["hash", "client-id", "tcp-port", "high-id", "trailing-byte"],
)
def test_wrong_reply_hash_or_source_fails_closed(payload: bytes) -> None:
    records = client_records("rust", 101)
    records[2] = reply_record("rust", 12, 101, payload=payload)

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["reply"]["ok"] is False
    assert "rust.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_duplicate_reply_fails_closed() -> None:
    records = client_records("mfc", 202)
    duplicate = copy.deepcopy(records[2])
    duplicate["seq"] = 14
    records.append(duplicate)

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["reply"]["packetCount"] == 2
    assert report["ok"] is False


def test_missing_application_event_fails_closed() -> None:
    records = client_records("rust", 101)[:3]

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["application"]["endpointHashEventCount"] == 0
    assert "rust.application" in report["failures"]


def test_wrong_application_trace_fails_closed() -> None:
    records = client_records("mfc", 202)
    records[3]["keys"]["traceId"] = 999
    records[3]["body"]["traceId"] = 999

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["application"]["traceEventCount"] == 0
    assert report["ok"] is False


def test_application_must_follow_reply() -> None:
    records = client_records("rust", 101)
    records[3]["seq"] = 11

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["application"]["exactEventCount"] == 1
    assert report["clients"]["rust"]["wire"]["application"]["ok"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stateId", "server.source.result_decoded"),
        ("milestone", "result_decoded"),
        ("wireSourceCount", 2),
        ("sourceCountBefore", 1),
        ("sourceCountAfter", 2),
        ("outcome", "ignored"),
        ("transportMode", "obfuscated"),
        ("obfuscated", True),
        ("wireSourceCount", True),
        ("sourceCountBefore", False),
    ],
)
def test_application_contract_is_exact(field: str, value: object) -> None:
    records = client_records("mfc", 202)
    records[3]["body"][field] = value

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["application"]["exactEventCount"] == 0
    assert "mfc.application" in report["failures"]


@pytest.mark.parametrize(
    ("client", "field", "value"),
    [
        ("rust", "hash", "ff" * 16),
        ("rust", "displayName", "wrong.bin"),
        ("rust", "sizeBytes", FILE_SIZE + 1),
        ("rust", "sizeBytes", True),
        ("rust", "sources", 0),
        ("mfc", "hash", "ff" * 16),
        ("mfc", "name", "wrong.bin"),
        ("mfc", "sizeBytes", FILE_SIZE + 1),
        ("mfc", "sources", False),
    ],
)
def test_rest_corroboration_fails_closed(client: str, field: str, value: object) -> None:
    rows = {"rust": transfer_row("rust"), "mfc": transfer_row("mfc")}
    rows[client][field] = value

    report = build(rows=rows)

    assert report["clients"][client]["rest"]["ok"] is False
    assert f"{client}.rest" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_aggregate_rest_sources_may_exceed_wire_reply_count() -> None:
    rows = {"rust": transfer_row("rust"), "mfc": transfer_row("mfc")}
    rows["rust"]["sources"] = 3
    rows["mfc"]["sources"] = 2

    report = build(rows=rows)

    assert report["ok"] is True
    assert report["clients"]["rust"]["rest"]["sources"] == 3
    assert report["clients"]["mfc"]["rest"]["sources"] == 2


def test_no_sources_identity_or_source_engaged_event_is_required() -> None:
    report = build()

    assert report["ok"] is True
    assert set(report["clients"]["rust"]) == {"ok", "failures", "wire", "rest"}


def test_unexpected_schema_is_rejected() -> None:
    report = build()
    report["schema"] = "emulebb-build-tests.deterministic-server-source-diagnostics.v0"

    with pytest.raises(RuntimeError, match="unexpected schema"):
        evidence.require_server_source_diagnostic_evidence(report)


def test_invalid_plain_source_fixture_is_rejected() -> None:
    with pytest.raises(ValueError, match="positive u32"):
        evidence.build_server_source_diagnostic_evidence(
            expected_file_hash=FILE_HASH,
            expected_file_name=FILE_NAME,
            expected_file_size=0x1_0000_0000,
            server_endpoint=ENDPOINT,
            publisher_client_id=PUBLISHER_CLIENT_ID,
            publisher_tcp_port=PUBLISHER_TCP_PORT,
            rust_records=[],
            mfc_records=[],
            transfer_rows={"rust": {}, "mfc": {}},
        )
