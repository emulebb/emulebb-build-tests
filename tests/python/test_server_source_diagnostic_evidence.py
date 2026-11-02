from __future__ import annotations

import copy
import ipaddress
import struct

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness import server_source_diagnostic_evidence as evidence


FILE_HASH = "22334455667788990011aabbccddeeff"
FILE_NAME = "deterministic-server-source.bin"
FILE_SIZE = 67_890
ENDPOINT = "127.0.0.1:4661"
PUBLISHER_HOST = "198.18.240.2"
PUBLISHER_CLIENT_ID = int.from_bytes(ipaddress.IPv4Address(PUBLISHER_HOST).packed, "little")
PUBLISHER_TCP_PORT = 48_017
PUBLISHER_USER_HASH = "32547698badcfe1021436587a9cbed0f"


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


def request_record(
    client: str,
    seq: int,
    trace_id: int,
    transport_mode: str = "plaintext",
) -> dict[str, object]:
    payload = ed2k_wire.encode_source_request(bytes.fromhex(FILE_HASH), FILE_SIZE)
    opcode = evidence.SOURCE_REQUEST_OPCODE_BY_TRANSPORT[transport_mode]
    return record(
        client,
        seq,
        "packet",
        keys={
            "opcode": opcode,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "send",
            "flow": "server",
            "obfuscated": transport_mode == "obfuscated",
            "opcode": opcode,
            "opcodeName": (
                "OP_GETSOURCES_OBFU" if transport_mode == "obfuscated" else "OP_GETSOURCES"
            ),
            "outcome": "attempted",
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(payload),
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": transport_mode,
        },
    )


def send_outcome_record(
    client: str,
    seq: int,
    trace_id: int,
    transport_mode: str = "plaintext",
) -> dict[str, object]:
    opcode = evidence.SOURCE_REQUEST_OPCODE_BY_TRANSPORT[transport_mode]
    return record(
        client,
        seq,
        "send_outcome",
        keys={
            "opcode": opcode,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
        },
        body={
            "deliveryKnown": True,
            "direction": "send",
            "flow": "server",
            "obfuscated": transport_mode == "obfuscated",
            "opcode": opcode,
            "outcome": "send_succeeded",
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": transport_mode,
        },
    )


def found_sources_payload(
    *,
    file_hash: str = FILE_HASH,
    client_id: int = PUBLISHER_CLIENT_ID,
    tcp_port: int = PUBLISHER_TCP_PORT,
    transport_mode: str = "plaintext",
) -> bytes:
    source = struct.pack("<IH", client_id, tcp_port)
    if transport_mode == "obfuscated":
        source += b"\x81" + bytes.fromhex(PUBLISHER_USER_HASH)
    return bytes.fromhex(file_hash) + b"\x01" + source


def reply_record(
    client: str,
    seq: int,
    trace_id: int,
    *,
    payload: bytes | None = None,
    transport_mode: str = "plaintext",
) -> dict[str, object]:
    wire_payload = (
        found_sources_payload(transport_mode=transport_mode)
        if payload is None
        else payload
    )
    opcode = evidence.SOURCE_REPLY_OPCODE_BY_TRANSPORT[transport_mode]
    return record(
        client,
        seq,
        "packet",
        keys={
            "opcode": opcode,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "recv",
            "flow": "server",
            "obfuscated": transport_mode == "obfuscated",
            "opcode": opcode,
            "opcodeName": (
                "OP_FOUNDSOURCES_OBFU" if transport_mode == "obfuscated" else "OP_FOUNDSOURCES"
            ),
            "outcome": "accepted",
            "payloadHex": wire_payload.hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(wire_payload),
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": transport_mode,
        },
    )


def application_record(
    client: str,
    seq: int,
    trace_id: int,
    transport_mode: str = "plaintext",
) -> dict[str, object]:
    opcode = evidence.SOURCE_REPLY_OPCODE_BY_TRANSPORT[transport_mode]
    return record(
        client,
        seq,
        "source_result_applied",
        keys={
            "fileHash": FILE_HASH,
            "opcode": opcode,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "recv",
            "flow": "server",
            "milestone": "result_applied",
            "obfuscated": transport_mode == "obfuscated",
            "opcode": opcode,
            "opcodeName": (
                "OP_FOUNDSOURCES_OBFU" if transport_mode == "obfuscated" else "OP_FOUNDSOURCES"
            ),
            "outcome": "applied",
            "phase": "source_search",
            "protocolMarker": evidence.SOURCE_PROTOCOL_MARKER,
            "sourceCountAfter": 1,
            "sourceCountBefore": 0,
            "stateId": "server.source.result_applied",
            "traceId": trace_id,
            "transportMode": transport_mode,
            "wireSourceCount": 1,
        },
    )


def client_records(
    client: str,
    trace_id: int,
    transport_mode: str = "plaintext",
) -> list[dict[str, object]]:
    records = [request_record(client, 10, trace_id, transport_mode)]
    if client == "rust":
        records.append(send_outcome_record(client, 11, trace_id, transport_mode))
    records.extend(
        [
            reply_record(client, 12, trace_id, transport_mode=transport_mode),
            application_record(client, 13, trace_id, transport_mode),
        ]
    )
    return records


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
    transport_mode: str = "plaintext",
) -> dict[str, object]:
    record_transport_mode = (
        transport_mode
        if transport_mode in evidence.SOURCE_COVERAGE_BY_TRANSPORT
        else "plaintext"
    )
    return evidence.build_server_source_diagnostic_evidence(
        expected_file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        server_endpoint=ENDPOINT,
        publisher_client_id=PUBLISHER_CLIENT_ID,
        publisher_host=PUBLISHER_HOST,
        publisher_tcp_port=PUBLISHER_TCP_PORT,
        publisher_user_hash=PUBLISHER_USER_HASH,
        expected_transport_mode=transport_mode,
        rust_records=(
            client_records("rust", 101, record_transport_mode) if rust is None else rust
        ),
        mfc_records=(
            client_records("mfc", 202, record_transport_mode) if mfc is None else mfc
        ),
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
    assert report["clients"]["rust"]["wire"]["reply"]["causalPredecessor"] == "send_outcome"
    assert report["clients"]["mfc"]["wire"]["sendOutcome"] == {
        "conflictingOutcomeCount": 0,
        "deliveryKnown": None,
        "evidenceModel": "correlated-reply-after-attempt",
        "obfuscated": None,
        "ok": True,
        "outcome": None,
        "outcomeCount": 0,
        "required": False,
        "sequence": None,
        "successfulOutcomeCount": 0,
        "traceId": None,
        "transportMode": None,
    }
    assert report["clients"]["mfc"]["wire"]["reply"]["causalPredecessor"] == "request"
    assert report["clients"]["rust"]["wire"]["reply"]["decoded"] == {
        "hash": FILE_HASH.upper(),
        "source_count": 1,
        "sources": [
            {
                "kind": "high-id",
                "client_id": PUBLISHER_CLIENT_ID,
                "host": PUBLISHER_HOST,
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
        "eligibleCoverageIds": [
            evidence.SOURCE_COVERAGE_BY_TRANSPORT["plaintext"],
            evidence.REPLY_COVERAGE_ID,
        ],
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


def test_exact_bilateral_obfuscated_source_lookup_is_claimable() -> None:
    report = build(transport_mode="obfuscated")

    assert report["ok"] is True
    assert report["transportMode"] == "obfuscated"
    assert report["clients"]["rust"]["wire"]["request"]["obfuscated"] is True
    assert report["clients"]["mfc"]["wire"]["reply"]["transportMode"] == "obfuscated"
    assert report["clients"]["mfc"]["wire"]["reply"]["decoded"]["sources"][0] == {
        "kind": "high-id",
        "client_id": PUBLISHER_CLIENT_ID,
        "host": PUBLISHER_HOST,
        "port": PUBLISHER_TCP_PORT,
        "crypt_options": 0x81,
        "user_hash": PUBLISHER_USER_HASH.upper(),
    }
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "server.source.tcp-obfuscated",
        "server.reply.sources",
    ]


def test_selected_transport_must_match_every_causal_record() -> None:
    report = build(
        rust=client_records("rust", 101, "plaintext"),
        transport_mode="obfuscated",
    )

    assert report["ok"] is False
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_plaintext_request_opcode() -> None:
    records = client_records("rust", 101, "obfuscated")
    records[0]["keys"]["opcode"] = ed2k_wire.OP_GETSOURCES
    records[0]["body"]["opcode"] = ed2k_wire.OP_GETSOURCES

    report = build(rust=records, transport_mode="obfuscated")

    assert report["clients"]["rust"]["wire"]["request"]["packetCount"] == 0
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_plaintext_reply_opcode() -> None:
    records = client_records("mfc", 202, "obfuscated")
    records[1]["keys"]["opcode"] = ed2k_wire.OP_FOUNDSOURCES
    records[1]["body"]["opcode"] = ed2k_wire.OP_FOUNDSOURCES

    report = build(mfc=records, transport_mode="obfuscated")

    assert report["clients"]["mfc"]["wire"]["reply"]["packetCount"] == 0
    assert "mfc.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_coexisting_plaintext_request() -> None:
    records = client_records("rust", 101, "obfuscated")
    records.insert(0, request_record("rust", 9, 303, "plaintext"))

    report = build(rust=records, transport_mode="obfuscated")

    assert report["clients"]["rust"]["wire"]["request"][
        "conflictingPacketCount"
    ] == 1
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_same_hash_plaintext_request_with_wrong_size() -> None:
    records = client_records("rust", 101, "obfuscated")
    conflicting = request_record("rust", 9, 303, "plaintext")
    payload = bytes.fromhex(FILE_HASH) + (FILE_SIZE + 1).to_bytes(4, "little")
    conflicting["body"]["payloadHex"] = payload.hex()
    conflicting["body"]["payloadLen"] = len(payload)
    records.insert(0, conflicting)

    report = build(rust=records, transport_mode="obfuscated")

    assert report["clients"]["rust"]["wire"]["request"][
        "conflictingPacketCount"
    ] == 1
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_truncated_plaintext_request() -> None:
    records = client_records("rust", 101, "obfuscated")
    conflicting = request_record("rust", 9, 303, "plaintext")
    conflicting["body"]["payloadHexTruncated"] = True
    records.insert(0, conflicting)

    report = build(rust=records, transport_mode="obfuscated")

    assert report["clients"]["rust"]["wire"]["request"][
        "conflictingPacketCount"
    ] == 1
    assert "rust.request" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_coexisting_plaintext_send_outcome() -> None:
    records = client_records("rust", 101, "obfuscated")
    records.insert(2, send_outcome_record("rust", 11, 101, "plaintext"))

    report = build(rust=records, transport_mode="obfuscated")

    assert report["clients"]["rust"]["wire"]["sendOutcome"][
        "conflictingOutcomeCount"
    ] == 1
    assert "rust.sendOutcome" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_coexisting_plaintext_reply() -> None:
    records = client_records("mfc", 202, "obfuscated")
    records.insert(2, reply_record("mfc", 12, 202, transport_mode="plaintext"))

    report = build(mfc=records, transport_mode="obfuscated")

    assert report["clients"]["mfc"]["wire"]["reply"][
        "conflictingPacketCount"
    ] == 1
    assert "mfc.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_same_hash_plaintext_reply_on_other_trace() -> None:
    records = client_records("mfc", 202, "obfuscated")
    records.insert(2, reply_record("mfc", 12, 303, transport_mode="plaintext"))

    report = build(mfc=records, transport_mode="obfuscated")

    assert report["clients"]["mfc"]["wire"]["reply"][
        "conflictingPacketCount"
    ] == 1
    assert "mfc.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_obfuscated_transport_rejects_length_inconsistent_plaintext_reply() -> None:
    records = client_records("mfc", 202, "obfuscated")
    conflicting = reply_record("mfc", 12, 303, transport_mode="plaintext")
    conflicting["body"]["payloadLen"] += 1
    records.insert(2, conflicting)

    report = build(mfc=records, transport_mode="obfuscated")

    assert report["clients"]["mfc"]["wire"]["reply"][
        "conflictingPacketCount"
    ] == 1
    assert "mfc.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_unknown_source_transport_is_rejected() -> None:
    with pytest.raises(ValueError, match="plaintext or obfuscated"):
        build(transport_mode="auto")


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


def test_outbound_request_is_an_attempt_not_a_fabricated_success() -> None:
    records = client_records("mfc", 202)
    records[0]["body"]["outcome"] = "send_succeeded"

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["request"]["exactPacketCount"] == 0
    assert "mfc.request" in report["failures"]


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
    records = client_records("rust", 101)
    records[1]["body"][field] = value

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["sendOutcome"]["successfulOutcomeCount"] == 0
    assert report["ok"] is False


def test_mfc_causal_reply_does_not_require_a_fabricated_send_outcome() -> None:
    report = build()

    assert report["clients"]["mfc"]["wire"]["sendOutcome"]["required"] is False
    assert report["clients"]["mfc"]["wire"]["sendOutcome"]["ok"] is True
    assert report["clients"]["mfc"]["wire"]["reply"]["ok"] is True


def test_mfc_unexpected_terminal_send_outcome_fails_closed() -> None:
    records = client_records("mfc", 202)
    records.insert(1, send_outcome_record("mfc", 11, 202))

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["sendOutcome"]["outcomeCount"] == 1
    assert "mfc.sendOutcome" in report["failures"]


def test_wrong_reply_trace_fails_closed() -> None:
    records = client_records("mfc", 202)
    records[1]["keys"]["traceId"] = 303
    records[1]["body"]["traceId"] = 303

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
        bytes.fromhex(FILE_HASH) + b"\x01" + struct.pack("<IH", 7, PUBLISHER_TCP_PORT),
        found_sources_payload() + b"\x00",
    ],
    ids=["hash", "client-id", "tcp-port", "low-id", "trailing-byte"],
)
def test_wrong_reply_hash_or_source_fails_closed(payload: bytes) -> None:
    records = client_records("rust", 101)
    records[2] = reply_record("rust", 12, 101, payload=payload)

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["reply"]["ok"] is False
    assert "rust.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.parametrize("mutation", ["crypt-options", "user-hash"])
def test_obfuscated_reply_requires_exact_crypt_identity(mutation: str) -> None:
    payload = bytearray(found_sources_payload(transport_mode="obfuscated"))
    if mutation == "crypt-options":
        payload[23] = 0x80
    else:
        payload[24:40] = bytes.fromhex("ff" * 16)
    records = client_records("rust", 101, "obfuscated")
    records[2] = reply_record(
        "rust",
        12,
        101,
        payload=bytes(payload),
        transport_mode="obfuscated",
    )

    report = build(rust=records, transport_mode="obfuscated")

    assert report["clients"]["rust"]["wire"]["reply"]["ok"] is False
    assert "rust.reply" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_duplicate_reply_fails_closed() -> None:
    records = client_records("mfc", 202)
    duplicate = copy.deepcopy(records[1])
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
    records[2]["keys"]["traceId"] = 999
    records[2]["body"]["traceId"] = 999

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
    records[2]["body"][field] = value

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
            publisher_host=PUBLISHER_HOST,
            publisher_tcp_port=PUBLISHER_TCP_PORT,
            publisher_user_hash=PUBLISHER_USER_HASH,
            expected_transport_mode="plaintext",
            rust_records=[],
            mfc_records=[],
            transfer_rows={"rust": {}, "mfc": {}},
        )


@pytest.mark.parametrize(
    ("publisher_host", "publisher_client_id", "message"),
    [
        ("not-an-ip", PUBLISHER_CLIENT_ID, "canonical IPv4"),
        (PUBLISHER_HOST, PUBLISHER_CLIENT_ID + 1, "HighID encoded"),
        (PUBLISHER_HOST, 7, "HighID encoded"),
    ],
)
def test_publisher_identity_must_be_one_exact_high_id(
    publisher_host: str,
    publisher_client_id: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        evidence.build_server_source_diagnostic_evidence(
            expected_file_hash=FILE_HASH,
            expected_file_name=FILE_NAME,
            expected_file_size=FILE_SIZE,
            server_endpoint=ENDPOINT,
            publisher_client_id=publisher_client_id,
            publisher_host=publisher_host,
            publisher_tcp_port=PUBLISHER_TCP_PORT,
            publisher_user_hash=PUBLISHER_USER_HASH,
            expected_transport_mode="plaintext",
            rust_records=[],
            mfc_records=[],
            transfer_rows={"rust": {}, "mfc": {}},
        )
