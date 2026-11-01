"""Causal bilateral diagnostics gate for one deterministic eD2K server search."""

from __future__ import annotations

import unicodedata
from typing import Any, Iterable

from emule_test_harness import ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-server-search-diagnostics.v2"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
ELIGIBLE_COVERAGE_IDS = ("server.reply.search", "server.search.keyword")
SEARCH_PROTOCOL_MARKER = 0xE3
SEARCH_REQUEST_OPCODE = 0x16
SEARCH_RESULT_OPCODE = 0x33
CLIENTS = ("rust", "mfc")


def _body(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("body")
    return value if isinstance(value, dict) else {}


def _keys(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("keys")
    return value if isinstance(value, dict) else {}


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _nonnegative_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _sequence(record: dict[str, Any]) -> int:
    return _positive_int(record.get("seq")) or 0


def _trace_id(record: dict[str, Any]) -> int | None:
    values = [value for value in (_keys(record).get("traceId"), _body(record).get("traceId")) if value is not None]
    normalized = [_positive_int(value) for value in values]
    if not normalized or any(value is None for value in normalized):
        return None
    unique = set(normalized)
    return next(iter(unique)) if len(unique) == 1 else None


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
    keys = _keys(record)
    return bool(
        record.get("family") == "ed2k_tcp"
        and record.get("event") == "packet"
        and _peer(record) == endpoint.casefold()
        and keys.get("protocolMarker") == SEARCH_PROTOCOL_MARKER
        and keys.get("opcode") == opcode
        and body.get("flow") == "server"
        and body.get("direction") == direction
        and body.get("protocolMarker") == SEARCH_PROTOCOL_MARKER
        and body.get("opcode") == opcode
    )


def _file_row_matches(
    row: object,
    *,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
) -> bool:
    if not isinstance(row, dict):
        return False
    name = row.get("displayName", row.get("name"))
    size = row.get("sizeBytes", row.get("size"))
    return bool(str(row.get("hash") or "").casefold() == expected_hash and name == expected_name and size == expected_size)


def _rest_search_evidence(
    driven: object,
    *,
    client: str,
    query: str,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
) -> dict[str, Any]:
    value = driven if isinstance(driven, dict) else {}
    created = value.get("created") if isinstance(value.get("created"), dict) else {}
    search = value.get("search") if isinstance(value.get("search"), dict) else {}
    result = value.get("result") if isinstance(value.get("result"), dict) else {}
    search_id = str(value.get("searchId") or "")
    items_value = search.get("items")
    items = items_value if isinstance(items_value, list) else []
    exact_items = [
        row
        for row in items
        if _file_row_matches(
            row,
            expected_hash=expected_hash,
            expected_name=expected_name,
            expected_size=expected_size,
        )
    ]
    total = search.get("total")
    if client == "rust":
        method_ok = bool(
            created.get("requestedMethod") == "server"
            and search.get("requestedMethod") == "server"
            and search.get("resolvedMethod") == "server"
        )
        method = {
            "createdRequested": created.get("requestedMethod"),
            "finalRequested": search.get("requestedMethod"),
            "finalResolved": search.get("resolvedMethod"),
        }
    elif client == "mfc":
        method_ok = bool(created.get("method") == "server" and search.get("method") == "server")
        method = {
            "created": created.get("method"),
            "final": search.get("method"),
        }
    else:
        raise ValueError(f"Unsupported deterministic server-search client: {client!r}")
    ok = bool(
        search_id
        and str(created.get("id") or "") == search_id
        and created.get("query") == query
        and method_ok
        and str(search.get("id") or "") == search_id
        and search.get("query") == query
        and str(search.get("status") or "").casefold() in {"complete", "completed"}
        and isinstance(total, int)
        and not isinstance(total, bool)
        and total >= 1
        and len(exact_items) == 1
        and _file_row_matches(
            result,
            expected_hash=expected_hash,
            expected_name=expected_name,
            expected_size=expected_size,
        )
        and str(result.get("searchId") or "") == search_id
    )
    return {
        "ok": ok,
        "searchId": search_id or None,
        "status": str(search.get("status") or "") or None,
        "method": method,
        "total": total if isinstance(total, int) and not isinstance(total, bool) else None,
        "exactResultCount": len(exact_items),
        "result": exact_items[0] if len(exact_items) == 1 else None,
    }


def _wire_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    expected_request_payload: bytes,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
) -> dict[str, Any]:
    endpoint_requests = [
        record
        for record in records
        if _packet(
            record,
            endpoint=endpoint,
            direction="send",
            opcode=SEARCH_REQUEST_OPCODE,
        )
    ]
    exact_requests = [record for record in endpoint_requests if _payload(record) == expected_request_payload]
    request = exact_requests[0] if len(endpoint_requests) == 1 and len(exact_requests) == 1 else None
    request_sequence = _sequence(request) if request is not None else 0
    trace_id = _trace_id(request) if request is not None else None
    send_attempt_id = _positive_int(_keys(request).get("sendAttemptId")) if request is not None else None

    endpoint_responses = [
        record
        for record in records
        if _packet(
            record,
            endpoint=endpoint,
            direction="recv",
            opcode=SEARCH_RESULT_OPCODE,
        )
        and _body(record).get("outcome") == "accepted"
        and _sequence(record) > request_sequence
    ]
    responses = [record for record in endpoint_responses if _trace_id(record) == trace_id]
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
        if _file_row_matches(
            row,
            expected_hash=expected_hash,
            expected_name=expected_name,
            expected_size=expected_size,
        )
    ]
    response_sequence = min((_sequence(row) for row in responses), default=0)
    request_ok = bool(
        request is not None and request_sequence > 0 and trace_id is not None and _body(request).get("transportMode") == "obfuscated"
    )
    reply_ok = bool(
        request_ok
        and len(endpoint_responses) == 1
        and len(responses) == 1
        and malformed_responses == 0
        and len(decoded_rows) == 1
        and len(exact_rows) == 1
        and response_sequence > request_sequence
        and _body(responses[0]).get("transportMode") == "obfuscated"
    )
    return {
        "ok": request_ok and reply_ok,
        "request": {
            "ok": request_ok,
            "endpointRequestCount": len(endpoint_requests),
            "exactRequestCount": len(exact_requests),
            "sequence": request_sequence or None,
            "traceId": trace_id,
            "sendAttemptId": send_attempt_id,
            "payloadHex": expected_request_payload.hex(),
            "transportMode": _body(request).get("transportMode") if request is not None else None,
        },
        "reply": {
            "ok": reply_ok,
            "endpointResponseCount": len(endpoint_responses),
            "traceResponseCount": len(responses),
            "malformedResponseCount": malformed_responses,
            "decodedRowCount": len(decoded_rows),
            "exactRowCount": len(exact_rows),
            "exactRow": exact_rows[0] if len(exact_rows) == 1 else None,
            "sequence": response_sequence or None,
            "transportMode": _body(responses[0]).get("transportMode") if len(responses) == 1 else None,
        },
    }


def _rust_lifecycle_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    query: str,
    search_id: str,
    wire: dict[str, Any],
) -> dict[str, Any]:
    request = wire["request"]
    reply = wire["reply"]
    trace_id = request.get("traceId")
    request_sequence = request.get("sequence")
    reply_sequence = reply.get("sequence")
    send_attempt_id = request.get("sendAttemptId")
    send_outcomes = [
        record
        for record in records
        if record.get("family") == "ed2k_tcp"
        and record.get("event") == "send_outcome"
        and _peer(record) == endpoint.casefold()
        and _keys(record).get("sendAttemptId") == send_attempt_id
        and _trace_id(record) == trace_id
        and _body(record).get("opcode") == SEARCH_REQUEST_OPCODE
        and _body(record).get("outcome") == "send_succeeded"
        and _body(record).get("deliveryKnown") is True
    ]
    states = [
        record
        for record in records
        if record.get("family") == "ed2k_tcp"
        and record.get("event") == "state"
        and _peer(record) == endpoint.casefold()
        and _trace_id(record) == trace_id
        and _body(record).get("flow") == "server"
    ]
    active = [
        record
        for record in states
        if _body(record).get("stateId") == "server.background.search_active"
        and isinstance(_body(record).get("note"), str)
        and f'query="{query}"' in _body(record)["note"]
        and isinstance(request_sequence, int)
        and _sequence(record) < request_sequence
    ]
    completed = [
        record
        for record in states
        if _body(record).get("stateId") == "server.background.completed"
        and isinstance(_body(record).get("note"), str)
        and _body(record)["note"].startswith("completed background keyword search ")
        and f'query="{query}"' in _body(record)["note"]
        and "pages=1 results=1" in _body(record)["note"]
        and isinstance(reply_sequence, int)
        and _sequence(record) > reply_sequence
    ]
    scheduler = [
        record
        for record in records
        if record.get("family") == "sched"
        and record.get("event") == "keyword_search"
        and str(_keys(record).get("searchId") or "") == search_id
        and _body(record).get("query") == query
        and _body(record).get("method") == "server"
        and _body(record).get("status") == "completed"
        and _body(record).get("resultCount") == 1
    ]
    active_sequence = _sequence(active[0]) if len(active) == 1 else 0
    send_sequence = _sequence(send_outcomes[0]) if len(send_outcomes) == 1 else 0
    completed_sequence = _sequence(completed[0]) if len(completed) == 1 else 0
    scheduler_sequence = _sequence(scheduler[0]) if len(scheduler) == 1 else 0
    ok = bool(
        len(send_outcomes) == 1
        and len(active) == 1
        and len(completed) == 1
        and len(scheduler) == 1
        and active_sequence < request_sequence < send_sequence < reply_sequence
        and reply_sequence < completed_sequence < scheduler_sequence
    )
    return {
        "ok": ok,
        "sendOutcomeCount": len(send_outcomes),
        "searchActiveCount": len(active),
        "completedCount": len(completed),
        "schedulerCompletionCount": len(scheduler),
        "searchActiveSequence": active_sequence or None,
        "sendOutcomeSequence": send_sequence or None,
        "completedSequence": completed_sequence or None,
        "schedulerSequence": scheduler_sequence or None,
    }


def _mfc_lifecycle_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    search_id: str,
    wire: dict[str, Any],
) -> dict[str, Any]:
    trace_id = wire["request"].get("traceId")
    reply_sequence = wire["reply"].get("sequence")
    applied = [
        record
        for record in records
        if record.get("family") == "ed2k_tcp"
        and record.get("event") == "search_result_applied"
        and _peer(record) == endpoint.casefold()
        and _trace_id(record) == trace_id
        and str(_keys(record).get("searchId") or "") == search_id
    ]
    applied_sequence = _sequence(applied[0]) if len(applied) == 1 else 0
    body = _body(applied[0]) if len(applied) == 1 else {}
    ok = bool(
        len(applied) == 1
        and isinstance(reply_sequence, int)
        and applied_sequence > reply_sequence
        and body.get("stateId") == "server.search.result_applied"
        and body.get("milestone") == "result_applied"
        and body.get("opcode") == SEARCH_RESULT_OPCODE
        and body.get("expectedReply") is True
        and body.get("outcome") == "accepted"
        and body.get("wireResultCount") == 1
        and body.get("cumulativeSourceCountBefore") == 0
        and isinstance(body.get("cumulativeSourceCountAfter"), int)
        and not isinstance(body.get("cumulativeSourceCountAfter"), bool)
        and body["cumulativeSourceCountAfter"] >= 1
        and body.get("distinctFileCountBefore") == 0
        and body.get("distinctFileCountAfter") == 1
        and body.get("moreResultsAvailable") is False
    )
    return {
        "ok": ok,
        "appliedCount": len(applied),
        "appliedSequence": applied_sequence or None,
        "expectedReply": body.get("expectedReply"),
        "wireResultCount": body.get("wireResultCount"),
        "cumulativeSourceCountBefore": body.get("cumulativeSourceCountBefore"),
        "cumulativeSourceCountAfter": body.get("cumulativeSourceCountAfter"),
        "distinctFileCountBefore": body.get("distinctFileCountBefore"),
        "distinctFileCountAfter": body.get("distinctFileCountAfter"),
        "moreResultsAvailable": body.get("moreResultsAvailable"),
        "outcome": body.get("outcome"),
    }


def _comparable_row(row: object) -> dict[str, object] | None:
    if not isinstance(row, dict):
        return None
    sources = _nonnegative_int(row.get("sources"))
    complete_sources = _nonnegative_int(row.get("complete_sources", row.get("completeSources")))
    if sources is None or complete_sources is None:
        return None
    return {
        "hash": str(row.get("hash") or "").casefold(),
        "name": row.get("name", row.get("displayName")),
        "size": row.get("size", row.get("sizeBytes")),
        "sources": sources,
        "completeSources": complete_sources,
    }


def _comparable_wire_row(row: object) -> dict[str, object] | None:
    comparable = _comparable_row(row)
    if comparable is None or not isinstance(row, dict):
        return None
    return {
        **comparable,
        "resultSourceId": row.get("result_source_id"),
        "resultSourcePort": row.get("result_source_port"),
    }


def build_server_search_diagnostic_evidence(
    *,
    query: str,
    expected_file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
    server_endpoint: str,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
    driven_searches: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Proves one exact keyword request and applied result on Rust and MFC."""

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
    if not isinstance(driven_searches, dict) or set(driven_searches) != set(CLIENTS):
        raise ValueError("Driven server searches must contain exactly rust and mfc.")

    expected_request_payload = ed2k_wire.encode_term_search(normalized_query)
    records_by_client = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for client in CLIENTS:
        rest = _rest_search_evidence(
            driven_searches[client],
            client=client,
            query=normalized_query,
            expected_hash=normalized_hash,
            expected_name=expected_file_name,
            expected_size=expected_file_size,
        )
        wire = _wire_evidence(
            records_by_client[client],
            endpoint=server_endpoint,
            expected_request_payload=expected_request_payload,
            expected_hash=normalized_hash,
            expected_name=expected_file_name,
            expected_size=expected_file_size,
        )
        search_id = str(rest.get("searchId") or "")
        lifecycle = (
            _rust_lifecycle_evidence(
                records_by_client[client],
                endpoint=server_endpoint,
                query=normalized_query,
                search_id=search_id,
                wire=wire,
            )
            if client == "rust"
            else _mfc_lifecycle_evidence(
                records_by_client[client],
                endpoint=server_endpoint,
                search_id=search_id,
                wire=wire,
            )
        )
        comparable_wire = _comparable_row(wire["reply"]["exactRow"])
        comparable_rest = _comparable_row(rest["result"])
        wire_rest_equal = comparable_wire is not None and comparable_rest is not None and comparable_wire == comparable_rest
        client_ok = bool(rest["ok"] is True and wire["ok"] is True and lifecycle["ok"] is True and wire_rest_equal)
        clients[client] = {
            "ok": client_ok,
            "rest": rest,
            "wire": wire,
            "lifecycle": lifecycle,
            "wireRestEqual": wire_rest_equal,
        }
        if not client_ok:
            failures.append(client)

    rust_wire_row = _comparable_wire_row(clients["rust"]["wire"]["reply"]["exactRow"])
    mfc_wire_row = _comparable_wire_row(clients["mfc"]["wire"]["reply"]["exactRow"])
    rust_rest_row = _comparable_row(clients["rust"]["rest"]["result"])
    mfc_rest_row = _comparable_row(clients["mfc"]["rest"]["result"])
    comparison = {
        "requestPayloadEqual": (clients["rust"]["wire"]["request"]["payloadHex"] == clients["mfc"]["wire"]["request"]["payloadHex"]),
        "replyRowEqual": (
            rust_wire_row is not None
            and mfc_wire_row is not None
            and rust_wire_row == mfc_wire_row
        ),
        "restResultEqual": (
            rust_rest_row is not None
            and mfc_rest_row is not None
            and rust_rest_row == mfc_rest_row
        ),
        "transportModeEqual": (
            clients["rust"]["wire"]["request"]["transportMode"] == clients["mfc"]["wire"]["request"]["transportMode"] == "obfuscated"
        ),
        "rustWireRestEqual": clients["rust"]["wireRestEqual"],
        "mfcWireRestEqual": clients["mfc"]["wireRestEqual"],
    }
    comparison_ok = all(value is True for value in comparison.values())
    if not comparison_ok:
        failures.append("comparison")
    observed_ids = list(ELIGIBLE_COVERAGE_IDS) if not failures else []
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
        "clients": clients,
        "comparison": {"ok": comparison_ok, **comparison},
        "observedCoverageIds": observed_ids,
        "coverageClaims": {
            "eligibleCoverageIds": observed_ids,
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_search_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises when an exact bilateral deterministic server search is not proven."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic server search diagnostics have an unexpected schema.")
    if report.get("ok") is not True:
        raise RuntimeError(f"Deterministic server search diagnostics are incomplete: {report.get('failures')!r}")
