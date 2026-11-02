from __future__ import annotations

import copy

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness import server_search_diagnostic_evidence as evidence


FILE_HASH = "00112233445566778899aabbccddeeff"
FILE_NAME = "deterministicparitysearch-result.bin"
FILE_SIZE = 12_345
QUERY = "deterministicparitysearch"
ENDPOINT = "127.0.0.1:4661"


def record(
    client: str,
    seq: int,
    event: str,
    *,
    keys: dict[str, object],
    body: dict[str, object],
    family: str = "ed2k_tcp",
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "seq": seq,
        "streamSeq": seq,
        "family": family,
        "event": event,
        "keys": keys,
        "body": body,
    }


def request_record(client: str, seq: int, trace_id: int, send_attempt_id: int | None) -> dict[str, object]:
    payload = ed2k_wire.encode_search_request(QUERY)
    keys: dict[str, object] = {
        "opcode": evidence.SEARCH_REQUEST_OPCODE,
        "peer": ENDPOINT,
        "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
        "traceId": trace_id,
    }
    if send_attempt_id is not None:
        keys["sendAttemptId"] = send_attempt_id
    body: dict[str, object] = {
        "direction": "send",
        "flow": "server",
        "opcode": evidence.SEARCH_REQUEST_OPCODE,
        "opcodeName": "OP_SEARCHREQUEST",
        "outcome": "attempted" if client == "rust" else "send_succeeded",
        "payloadHex": payload.hex(),
        "payloadHexTruncated": False,
        "payloadLen": len(payload),
        "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
        "traceId": trace_id,
        "transportMode": "obfuscated",
    }
    if send_attempt_id is not None:
        body["sendAttemptId"] = send_attempt_id
    return record(client, seq, "packet", keys=keys, body=body)


def reply_record(
    client: str,
    seq: int,
    trace_id: int,
    *,
    file_hash: str = FILE_HASH,
    source_id: int | None = None,
) -> dict[str, object]:
    payload = bytearray(ed2k_wire.encode_offer_file(
        file_hash=bytes.fromhex(file_hash),
        name=FILE_NAME,
        size=FILE_SIZE,
    ))
    payload[26:30] = (4).to_bytes(4, "little")
    payload.extend(
        bytes([ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_UINT32, ed2k_wire.FT_SOURCES])
        + (1).to_bytes(4, "little")
        + bytes(
            [
                ed2k_wire.TAG_SHORT_NAME | ed2k_wire.TAGTYPE_UINT32,
                ed2k_wire.FT_COMPLETE_SOURCES,
            ]
        )
        + (1).to_bytes(4, "little")
    )
    if source_id is not None:
        payload[20:24] = source_id.to_bytes(4, "little")
    return record(
        client,
        seq,
        "packet",
        keys={
            "opcode": evidence.SEARCH_RESULT_OPCODE,
            "peer": ENDPOINT,
            "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
            "traceId": trace_id,
        },
        body={
            "direction": "recv",
            "flow": "server",
            "opcode": evidence.SEARCH_RESULT_OPCODE,
            "opcodeName": "OP_SEARCHRESULT",
            "outcome": "accepted",
            "payloadHex": bytes(payload).hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(payload),
            "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
            "traceId": trace_id,
            "transportMode": "obfuscated",
        },
    )


def rust_records() -> list[dict[str, object]]:
    return [
        record(
            "rust",
            10,
            "state",
            keys={"peer": ENDPOINT},
            body={
                "flow": "server",
                "stateId": "server.background.search_active",
                "note": f'dispatching background keyword search query="{QUERY}"',
                "traceId": 1,
            },
        ),
        request_record("rust", 11, 1, 7),
        record(
            "rust",
            12,
            "send_outcome",
            keys={
                "opcode": evidence.SEARCH_REQUEST_OPCODE,
                "peer": ENDPOINT,
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
                "sendAttemptId": 7,
            },
            body={
                "deliveryKnown": True,
                "flow": "server",
                "opcode": evidence.SEARCH_REQUEST_OPCODE,
                "outcome": "send_succeeded",
                "sendAttemptId": 7,
                "traceId": 1,
            },
        ),
        reply_record("rust", 13, 1),
        record(
            "rust",
            14,
            "state",
            keys={"peer": ENDPOINT},
            body={
                "flow": "server",
                "stateId": "server.background.completed",
                "note": f'completed background keyword search query="{QUERY}" pages=1 results=1',
                "traceId": 1,
            },
        ),
        record(
            "rust",
            15,
            "keyword_search",
            family="sched",
            keys={"searchId": "1"},
            body={
                "method": "server",
                "query": QUERY,
                "resultCount": 1,
                "status": "completed",
            },
        ),
    ]


def mfc_records() -> list[dict[str, object]]:
    return [
        request_record("mfc", 20, 2, None),
        reply_record("mfc", 21, 2),
        record(
            "mfc",
            22,
            "search_result_applied",
            keys={
                "opcode": evidence.SEARCH_RESULT_OPCODE,
                "peer": ENDPOINT,
                "protocolMarker": evidence.SEARCH_PROTOCOL_MARKER,
                "searchId": 2,
                "traceId": 2,
            },
            body={
                "cumulativeSourceCountAfter": 1,
                "cumulativeSourceCountBefore": 0,
                "distinctFileCountAfter": 1,
                "distinctFileCountBefore": 0,
                "expectedReply": True,
                "flow": "server",
                "milestone": "result_applied",
                "moreResultsAvailable": False,
                "opcode": evidence.SEARCH_RESULT_OPCODE,
                "outcome": "accepted",
                "stateId": "server.search.result_applied",
                "traceId": 2,
                "wireResultCount": 1,
            },
        ),
    ]


def driven_search(client: str, search_id: str) -> dict[str, object]:
    result = {
        "completeSources": 1,
        "hash": FILE_HASH.upper(),
        "searchId": search_id,
        "sizeBytes": FILE_SIZE,
        "sources": 1,
    }
    if client == "rust":
        result["displayName"] = FILE_NAME
        created_method = {"requestedMethod": "server"}
        final_method = {
            "requestedMethod": "server",
            "resolvedMethod": "server",
        }
    elif client == "mfc":
        result["name"] = FILE_NAME
        created_method = {"method": "server"}
        final_method = {"method": "server"}
    else:
        raise AssertionError(f"unsupported test client: {client}")
    return {
        "searchId": search_id,
        "created": {
            "id": search_id,
            "query": QUERY,
            **created_method,
        },
        "search": {
            "id": search_id,
            "items": [result],
            "query": QUERY,
            **final_method,
            "status": "complete",
            "total": 1,
        },
        "result": result,
    }


def build(
    *,
    rust: list[dict[str, object]] | None = None,
    mfc: list[dict[str, object]] | None = None,
    searches: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    return evidence.build_server_search_diagnostic_evidence(
        query=QUERY,
        expected_file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        server_endpoint=ENDPOINT,
        rust_records=rust_records() if rust is None else rust,
        mfc_records=mfc_records() if mfc is None else mfc,
        driven_searches=({"rust": driven_search("rust", "1"), "mfc": driven_search("mfc", "2")} if searches is None else searches),
    )


def test_exact_bilateral_keyword_request_and_applied_reply_are_claimable() -> None:
    report = build()

    assert report["ok"] is True
    assert report["clients"]["rust"]["wire"]["request"]["sequence"] == 11
    assert report["clients"]["rust"]["lifecycle"]["schedulerSequence"] == 15
    assert report["clients"]["mfc"]["lifecycle"]["appliedSequence"] == 22
    assert report["comparison"] == {
        "ok": True,
        "mfcWireRestEqual": True,
        "requestPayloadEqual": True,
        "replyRowEqual": True,
        "restResultEqual": True,
        "rustWireRestEqual": True,
        "transportModeEqual": True,
    }
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": list(evidence.ELIGIBLE_COVERAGE_IDS),
        "evidenceLayers": list(evidence.EVIDENCE_LAYERS),
    }
    evidence.require_server_search_diagnostic_evidence(report)


def test_duplicate_mfc_request_is_not_causally_attributable() -> None:
    records = mfc_records()
    duplicate = copy.deepcopy(records[0])
    duplicate["seq"] = 19
    records.insert(0, duplicate)

    report = build(mfc=records)

    assert report["ok"] is False
    assert report["clients"]["mfc"]["wire"]["request"]["endpointRequestCount"] == 2
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_mismatched_query_payload_is_rejected() -> None:
    records = rust_records()
    payload = ed2k_wire.encode_search_request("some-other-query")
    records[1]["body"]["payloadHex"] = payload.hex()
    records[1]["body"]["payloadLen"] = len(payload)

    report = build(rust=records)

    assert report["clients"]["rust"]["wire"]["request"]["exactRequestCount"] == 0
    assert report["ok"] is False


def test_packet_key_and_body_opcode_must_agree() -> None:
    records = mfc_records()
    records[0]["keys"]["opcode"] = evidence.SEARCH_RESULT_OPCODE

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["request"]["endpointRequestCount"] == 0
    assert report["ok"] is False


def test_truncated_mfc_result_payload_is_rejected() -> None:
    records = mfc_records()
    records[1]["body"]["payloadHexTruncated"] = True

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["reply"]["malformedResponseCount"] == 1
    assert report["ok"] is False


def test_rust_requires_successful_send_and_terminal_scheduler_join() -> None:
    records = rust_records()
    records.pop(2)

    report = build(rust=records)

    assert report["clients"]["rust"]["lifecycle"]["sendOutcomeCount"] == 0
    assert report["clients"]["rust"]["ok"] is False


def test_mfc_requires_post_parse_application_event() -> None:
    records = mfc_records()[:2]

    report = build(mfc=records)

    assert report["clients"]["mfc"]["lifecycle"]["appliedCount"] == 0
    assert report["ok"] is False


def test_mfc_late_reply_cannot_claim_parity() -> None:
    records = mfc_records()
    records[2]["body"]["expectedReply"] = False
    records[2]["body"]["outcome"] = "late"

    report = build(mfc=records)

    assert report["clients"]["mfc"]["lifecycle"]["expectedReply"] is False
    assert report["ok"] is False


def test_mfc_applied_event_must_join_rest_search_id() -> None:
    records = mfc_records()
    records[2]["keys"]["searchId"] = 99

    report = build(mfc=records)

    assert report["clients"]["mfc"]["lifecycle"]["appliedCount"] == 0
    assert report["ok"] is False


def test_cross_client_reply_difference_is_rejected() -> None:
    records = mfc_records()
    records[1] = reply_record("mfc", 21, 2, file_hash="ff" * 16)

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["reply"]["exactRowCount"] == 0
    assert report["comparison"]["replyRowEqual"] is False
    assert report["ok"] is False


def test_cross_client_result_source_difference_is_rejected() -> None:
    records = mfc_records()
    records[1] = reply_record("mfc", 21, 2, source_id=99)

    report = build(mfc=records)

    assert report["clients"]["mfc"]["wire"]["reply"]["exactRowCount"] == 1
    assert report["comparison"]["replyRowEqual"] is False
    assert report["ok"] is False


def test_bilateral_rest_agreement_cannot_hide_wire_rest_source_difference() -> None:
    searches = {
        "rust": driven_search("rust", "1"),
        "mfc": driven_search("mfc", "2"),
    }
    for driven in searches.values():
        driven["result"]["sources"] = 0
        driven["result"]["completeSources"] = 0

    report = build(searches=searches)

    assert report["comparison"]["restResultEqual"] is True
    assert report["comparison"]["rustWireRestEqual"] is False
    assert report["comparison"]["mfcWireRestEqual"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_matching_invalid_availability_values_cannot_claim_parity() -> None:
    searches = {
        "rust": driven_search("rust", "1"),
        "mfc": driven_search("mfc", "2"),
    }
    for driven in searches.values():
        driven["result"]["sources"] = True
        driven["result"]["completeSources"] = None

    report = build(searches=searches)

    assert report["comparison"]["restResultEqual"] is False
    assert report["clients"]["rust"]["wireRestEqual"] is False
    assert report["clients"]["mfc"]["wireRestEqual"] is False
    assert report["ok"] is False


def test_rust_rest_result_requires_resolved_server_method() -> None:
    searches = {
        "rust": driven_search("rust", "1"),
        "mfc": driven_search("mfc", "2"),
    }
    searches["rust"]["search"]["resolvedMethod"] = "kad"

    report = build(searches=searches)

    assert report["clients"]["rust"]["rest"]["ok"] is False
    assert report["ok"] is False


def test_mfc_rest_result_requires_native_server_method() -> None:
    searches = {
        "rust": driven_search("rust", "1"),
        "mfc": driven_search("mfc", "2"),
    }
    searches["mfc"]["search"]["method"] = "kad"

    report = build(searches=searches)

    assert report["clients"]["mfc"]["rest"]["ok"] is False
    assert report["ok"] is False


def test_legacy_unilateral_schema_is_rejected() -> None:
    report = build()
    report["schema"] = "emulebb-build-tests.deterministic-server-search-diagnostics.v1"

    with pytest.raises(RuntimeError, match="unexpected schema"):
        evidence.require_server_search_diagnostic_evidence(report)
