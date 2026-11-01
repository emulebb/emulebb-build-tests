from __future__ import annotations

from emule_test_harness import ed2k_wire
from emule_test_harness import server_search_diagnostic_evidence as evidence

FILE_HASH = "00112233445566778899aabbccddeeff"
FILE_NAME = "deterministicparitysearch-fixture.bin"
FILE_SIZE = 132 * 1024 * 1024
QUERY = "deterministicparitysearch"
ENDPOINT = "127.0.0.1:4661"


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


def canonical_records() -> list[dict[str, object]]:
    request_payload = ed2k_wire.encode_term_search(QUERY)
    reply_payload = ed2k_wire.encode_offer_file(
        file_hash=bytes.fromhex(FILE_HASH),
        name=FILE_NAME,
        size=FILE_SIZE,
    )
    return [
        record(
            10,
            "packet",
            keys={
                "opcode": evidence.SEARCH_REQUEST_OPCODE,
                "peer": ENDPOINT,
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
                "sendAttemptId": 7,
            },
            body={
                "direction": "send",
                "flow": "server",
                "opcode": evidence.SEARCH_REQUEST_OPCODE,
                "opcodeName": "OP_SEARCHREQUEST",
                "outcome": "attempted",
                "payloadHex": request_payload.hex(),
                "payloadHexTruncated": False,
                "payloadLen": len(request_payload),
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
            },
        ),
        record(
            11,
            "send_outcome",
            keys={
                "opcode": evidence.SEARCH_REQUEST_OPCODE,
                "peer": ENDPOINT,
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
                "sendAttemptId": 7,
            },
            body={
                "deliveryKnown": True,
                "direction": "send",
                "flow": "server",
                "opcode": evidence.SEARCH_REQUEST_OPCODE,
                "opcodeName": "OP_SEARCHREQUEST",
                "outcome": "send_succeeded",
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
            },
        ),
        record(
            12,
            "packet",
            keys={
                "opcode": evidence.SEARCH_RESULT_OPCODE,
                "peer": ENDPOINT,
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
            },
            body={
                "direction": "recv",
                "flow": "server",
                "opcode": evidence.SEARCH_RESULT_OPCODE,
                "opcodeName": "OP_SEARCHRESULT",
                "outcome": "accepted",
                "payloadHex": reply_payload.hex(),
                "payloadHexTruncated": False,
                "payloadLen": len(reply_payload),
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
            },
        ),
    ]


def build(records: list[dict[str, object]] | None = None) -> dict[str, object]:
    return evidence.build_server_search_diagnostic_evidence(
        query=QUERY,
        expected_file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        server_endpoint=ENDPOINT,
        rust_records=canonical_records() if records is None else records,
        rest_result={
            "hash": FILE_HASH.upper(),
            "displayName": FILE_NAME,
            "sizeBytes": FILE_SIZE,
        },
    )


def test_exact_keyword_request_and_reply_are_claimable() -> None:
    report = build()

    assert report["ok"] is True
    assert report["checks"]["request"]["sequence"] == 10
    assert report["checks"]["reply"]["firstResponseSequence"] == 12
    assert report["checks"]["reply"]["exactRow"]["hash"] == FILE_HASH.upper()
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": ["server.reply.search", "server.search.keyword"],
        "evidenceLayers": list(evidence.EVIDENCE_LAYERS),
    }
    evidence.require_server_search_diagnostic_evidence(report)


def test_duplicate_request_is_not_causally_attributable() -> None:
    records = canonical_records()
    duplicate = {**records[0], "seq": 9, "streamSeq": 9}
    records.insert(0, duplicate)

    report = build(records)

    assert report["ok"] is False
    assert report["checks"]["request"]["endpointRequestCount"] == 2
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_mismatched_query_payload_is_rejected() -> None:
    records = canonical_records()
    payload = ed2k_wire.encode_term_search("some-other-query")
    records[0]["body"]["payloadHex"] = payload.hex()
    records[0]["body"]["payloadLen"] = len(payload)

    report = build(records)

    assert report["checks"]["request"]["exactRequestCount"] == 0
    assert report["ok"] is False


def test_mismatched_wire_result_is_rejected_even_when_rest_matches() -> None:
    records = canonical_records()
    payload = ed2k_wire.encode_offer_file(
        file_hash=bytes.fromhex("ff" * 16),
        name=FILE_NAME,
        size=FILE_SIZE,
    )
    records[2]["body"]["payloadHex"] = payload.hex()
    records[2]["body"]["payloadLen"] = len(payload)

    report = build(records)

    assert report["checks"]["reply"]["exactRowCount"] == 0
    assert report["ok"] is False


def test_truncated_result_payload_is_rejected() -> None:
    records = canonical_records()
    records[2]["body"]["payloadHexTruncated"] = True

    report = build(records)

    assert report["checks"]["reply"]["malformedResponseCount"] == 1
    assert report["ok"] is False
