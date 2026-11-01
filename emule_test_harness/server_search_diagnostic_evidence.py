"""Causal diagnostics gate for one deterministic eD2K server keyword search."""

from __future__ import annotations

import unicodedata
from typing import Any, Iterable

from emule_test_harness import ed2k_wire

SCHEMA = "emulebb-build-tests.deterministic-server-search-diagnostics.v1"
EVIDENCE_LAYERS = ("codec-transcript", "deterministic-state-machine", "local-cross-client")
SEARCH_PROTOCOL_MARKER = 0xE3
SEARCH_REQUEST_OPCODE = 0x16
SEARCH_RESULT_OPCODE = 0x33


def _body(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("body")
    return value if isinstance(value, dict) else {}


def _keys(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("keys")
    return value if isinstance(value, dict) else {}


def _sequence(record: dict[str, Any]) -> int:
    value = record.get("streamSeq", record.get("seq", 0))
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _payload(record: dict[str, Any]) -> bytes | None:
    body = _body(record)
    payload_hex = body.get("payloadHex")
    if body.get("payloadHexTruncated") is not False or not isinstance(payload_hex, str):
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if body.get("payloadLen") != len(payload):
        return None
    return payload


def _peer(record: dict[str, Any]) -> str:
    return str(_keys(record).get("peer") or "").casefold()


def _packet(
    record: dict[str, Any],
    *,
    endpoint: str,
    direction: str,
    opcode: int,
) -> bool:
    body = _body(record)
    return bool(
        record.get("family") == "ed2k_tcp"
        and record.get("event") == "packet"
        and _peer(record) == endpoint.casefold()
        and body.get("flow") == "server"
        and body.get("direction") == direction
        and body.get("protocolMarker") == SEARCH_PROTOCOL_MARKER
        and body.get("opcode") == opcode
    )


def _request_send_succeeded(
    records: list[dict[str, Any]],
    request: dict[str, Any],
    endpoint: str,
) -> bool:
    attempt_id = _keys(request).get("sendAttemptId")
    if not isinstance(attempt_id, int) or isinstance(attempt_id, bool):
        return False
    return any(
        record.get("family") == "ed2k_tcp"
        and record.get("event") == "send_outcome"
        and _peer(record) == endpoint.casefold()
        and _keys(record).get("sendAttemptId") == attempt_id
        and _body(record).get("opcode") == SEARCH_REQUEST_OPCODE
        and _body(record).get("outcome") == "send_succeeded"
        and _body(record).get("deliveryKnown") is True
        and _sequence(record) >= _sequence(request)
        for record in records
    )


def _rest_result_matches(
    result: dict[str, Any] | None,
    *,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
) -> bool:
    if not isinstance(result, dict):
        return False
    name = result.get("displayName", result.get("name"))
    size = result.get("sizeBytes", result.get("size"))
    return bool(
        str(result.get("hash") or "").casefold() == expected_hash
        and name == expected_name
        and size == expected_size
    )


def build_server_search_diagnostic_evidence(
    *,
    query: str,
    expected_file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
    server_endpoint: str,
    rust_records: Iterable[dict[str, Any]],
    rest_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """Proves one exact keyword request and its exact decoded server result."""

    normalized_query = unicodedata.normalize("NFC", query)
    normalized_hash = expected_file_hash.casefold()
    if not normalized_query:
        raise ValueError("Server search query must not be empty.")
    if len(normalized_hash) != 32 or any(value not in "0123456789abcdef" for value in normalized_hash):
        raise ValueError("Expected server search file hash must be 32 hexadecimal characters.")
    if not expected_file_name:
        raise ValueError("Expected server search filename must not be empty.")
    if not isinstance(expected_file_size, int) or isinstance(expected_file_size, bool) or expected_file_size <= 0:
        raise ValueError("Expected server search file size must be a positive integer.")
    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("Server search endpoint must be host:port.")

    records = list(rust_records)
    expected_request_payload = ed2k_wire.encode_term_search(normalized_query)
    endpoint_requests = [
        record
        for record in records
        if _packet(
            record,
            endpoint=server_endpoint,
            direction="send",
            opcode=SEARCH_REQUEST_OPCODE,
        )
    ]
    exact_requests = [
        record for record in endpoint_requests if _payload(record) == expected_request_payload
    ]
    request = exact_requests[0] if len(exact_requests) == 1 else None
    send_succeeded = bool(
        request is not None
        and _request_send_succeeded(records, request, server_endpoint)
    )

    responses = [
        record
        for record in records
        if _packet(
            record,
            endpoint=server_endpoint,
            direction="recv",
            opcode=SEARCH_RESULT_OPCODE,
        )
        and _body(record).get("outcome") == "accepted"
        and (request is None or _sequence(record) > _sequence(request))
    ]
    decoded_rows: list[dict[str, object]] = []
    malformed_responses = 0
    for response in responses:
        payload = _payload(response)
        if payload is None:
            malformed_responses += 1
            continue
        try:
            decoded_rows.extend(ed2k_wire.decode_search_results(payload))
        except ed2k_wire.Ed2kWireError:
            malformed_responses += 1
    exact_rows = [
        row
        for row in decoded_rows
        if str(row.get("hash") or "").casefold() == normalized_hash
        and row.get("name") == expected_file_name
        and row.get("size") == expected_file_size
    ]
    checks = {
        "request": {
            "ok": len(endpoint_requests) == 1 and len(exact_requests) == 1 and send_succeeded,
            "endpointRequestCount": len(endpoint_requests),
            "exactRequestCount": len(exact_requests),
            "sendSucceeded": send_succeeded,
            "sequence": _sequence(request) if request is not None else None,
            "payloadHex": expected_request_payload.hex(),
        },
        "reply": {
            "ok": bool(responses) and malformed_responses == 0 and len(exact_rows) == 1,
            "responseCount": len(responses),
            "malformedResponseCount": malformed_responses,
            "decodedRowCount": len(decoded_rows),
            "exactRowCount": len(exact_rows),
            "exactRow": exact_rows[0] if len(exact_rows) == 1 else None,
            "firstResponseSequence": min((_sequence(row) for row in responses), default=None),
        },
        "restResult": {
            "ok": _rest_result_matches(
                rest_result,
                expected_hash=normalized_hash,
                expected_name=expected_file_name,
                expected_size=expected_file_size,
            ),
        },
    }
    failures = [name for name, check in checks.items() if check["ok"] is not True]
    coverage_ids = (
        ["server.reply.search", "server.search.keyword"] if not failures else []
    )
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "query": normalized_query,
        "serverEndpoint": server_endpoint.casefold(),
        "expectedFile": {
            "hash": normalized_hash,
            "name": expected_file_name,
            "size": expected_file_size,
        },
        "failures": failures,
        "checks": checks,
        "coverageClaims": {
            "eligibleCoverageIds": coverage_ids,
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_search_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises when an exact deterministic server search is not causally proven."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic server search diagnostics have an unexpected schema.")
    if report.get("ok") is not True:
        raise RuntimeError(
            f"Deterministic server search diagnostics are incomplete: {report.get('failures')!r}"
        )
