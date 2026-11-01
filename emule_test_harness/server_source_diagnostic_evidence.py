"""Strict bilateral evidence gate for one plaintext eD2K server source lookup."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from emule_test_harness import ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-server-source-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
ELIGIBLE_COVERAGE_IDS = ("server.source.tcp-plain", "server.reply.sources")
SOURCE_PROTOCOL_MARKER = ed2k_wire.PROTO_EDONKEY
SOURCE_REQUEST_OPCODE = ed2k_wire.OP_GETSOURCES
SOURCE_REPLY_OPCODE = ed2k_wire.OP_FOUNDSOURCES
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


def _sequence(record: dict[str, Any] | None) -> int:
    return (_positive_int(record.get("seq")) or 0) if record is not None else 0


def _trace_id(record: dict[str, Any] | None) -> int | None:
    if record is None:
        return None
    values = [value for value in (_keys(record).get("traceId"), _body(record).get("traceId")) if value is not None]
    normalized = [_positive_int(value) for value in values]
    if not normalized or any(value is None for value in normalized):
        return None
    unique = set(normalized)
    return next(iter(unique)) if len(unique) == 1 else None


def _peer(record: dict[str, Any]) -> str:
    return str(_keys(record).get("peer") or "").casefold()


def _payload(record: dict[str, Any] | None) -> bytes | None:
    if record is None:
        return None
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


def _packet_shape(
    record: dict[str, Any],
    *,
    endpoint: str,
    direction: str,
    opcode: int,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_tcp"
        and record.get("event") == "packet"
        and _peer(record) == endpoint.casefold()
        and keys.get("protocolMarker") == SOURCE_PROTOCOL_MARKER
        and keys.get("opcode") == opcode
        and body.get("flow") == "server"
        and body.get("direction") == direction
        and body.get("protocolMarker") == SOURCE_PROTOCOL_MARKER
        and body.get("opcode") == opcode
    )


def _is_plaintext(record: dict[str, Any] | None) -> bool:
    body = _body(record) if record is not None else {}
    return body.get("transportMode") == "plaintext" and body.get("obfuscated") is False


def _request_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    expected_payload: bytes,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    candidates = [
        record
        for record in records
        if _packet_shape(
            record,
            endpoint=endpoint,
            direction="send",
            opcode=SOURCE_REQUEST_OPCODE,
        )
    ]
    exact = [
        record
        for record in candidates
        if _payload(record) == expected_payload
        and _is_plaintext(record)
        and _body(record).get("outcome") == "attempted"
    ]
    request = exact[0] if len(candidates) == 1 and len(exact) == 1 else None
    observed_payload = _payload(candidates[0]) if len(candidates) == 1 else None
    sequence = _sequence(request)
    trace_id = _trace_id(request)
    ok = bool(request is not None and sequence > 0 and trace_id is not None)
    return (
        {
            "ok": ok,
            "packetCount": len(candidates),
            "exactPacketCount": len(exact),
            "sequence": sequence or None,
            "traceId": trace_id,
            "payloadHex": observed_payload.hex() if observed_payload is not None else None,
            "expectedPayloadHex": expected_payload.hex(),
            "transportMode": _body(request).get("transportMode") if request is not None else None,
            "obfuscated": _body(request).get("obfuscated") if request is not None else None,
        },
        request,
    )


def _send_outcome_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    trace_id: int | None,
    request_sequence: int | None,
    required: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    candidates = [
        record
        for record in records
        if record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_tcp"
        and record.get("event") == "send_outcome"
        and _peer(record) == endpoint.casefold()
        and _trace_id(record) == trace_id
        and _keys(record).get("protocolMarker") == SOURCE_PROTOCOL_MARKER
        and _keys(record).get("opcode") == SOURCE_REQUEST_OPCODE
        and _body(record).get("flow") == "server"
        and _body(record).get("direction") == "send"
        and _body(record).get("protocolMarker") == SOURCE_PROTOCOL_MARKER
        and _body(record).get("opcode") == SOURCE_REQUEST_OPCODE
    ]
    exact = [
        record
        for record in candidates
        if _body(record).get("outcome") == "send_succeeded"
        and _body(record).get("deliveryKnown") is True
        and _is_plaintext(record)
    ]
    outcome = exact[0] if len(candidates) == 1 and len(exact) == 1 else None
    sequence = _sequence(outcome)
    ok = (
        bool(
            outcome is not None
            and isinstance(request_sequence, int)
            and sequence > request_sequence
        )
        if required
        else not candidates
    )
    return (
        {
            "ok": ok,
            "required": required,
            "evidenceModel": "terminal-socket-outcome" if required else "correlated-reply-after-attempt",
            "outcomeCount": len(candidates),
            "successfulOutcomeCount": len(exact),
            "sequence": sequence or None,
            "traceId": _trace_id(outcome),
            "outcome": _body(outcome).get("outcome") if outcome is not None else None,
            "deliveryKnown": _body(outcome).get("deliveryKnown") if outcome is not None else None,
            "transportMode": _body(outcome).get("transportMode") if outcome is not None else None,
            "obfuscated": _body(outcome).get("obfuscated") if outcome is not None else None,
        },
        outcome,
    )


def _reply_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    trace_id: int | None,
    predecessor_sequence: int | None,
    predecessor_kind: str,
    expected_hash: str,
    expected_client_id: int,
    expected_host: str,
    expected_tcp_port: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    candidates = [
        record
        for record in records
        if _packet_shape(
            record,
            endpoint=endpoint,
            direction="recv",
            opcode=SOURCE_REPLY_OPCODE,
        )
    ]
    same_trace = [record for record in candidates if _trace_id(record) == trace_id]
    decoded_rows: list[tuple[dict[str, Any], dict[str, object]]] = []
    malformed_count = 0
    for record in same_trace:
        payload = _payload(record)
        if payload is None:
            malformed_count += 1
            continue
        try:
            decoded = ed2k_wire.decode_found_sources(payload, obfuscated=False)
        except ed2k_wire.Ed2kWireError:
            malformed_count += 1
            continue
        decoded_rows.append((record, decoded))

    expected_source = {
        "kind": "high-id",
        "client_id": expected_client_id,
        "host": expected_host,
        "port": expected_tcp_port,
        "crypt_options": 0,
        "user_hash": None,
    }
    exact = [
        (record, decoded)
        for record, decoded in decoded_rows
        if _body(record).get("outcome") == "accepted"
        and _is_plaintext(record)
        and str(decoded.get("hash") or "").casefold() == expected_hash
        and decoded.get("source_count") == 1
        and decoded.get("sources") == [expected_source]
    ]
    reply = exact[0][0] if len(candidates) == 1 and len(same_trace) == 1 and len(exact) == 1 else None
    decoded = exact[0][1] if reply is not None else None
    sequence = _sequence(reply)
    ok = bool(
        reply is not None
        and malformed_count == 0
        and isinstance(predecessor_sequence, int)
        and sequence > predecessor_sequence
    )
    return (
        {
            "ok": ok,
            "packetCount": len(candidates),
            "tracePacketCount": len(same_trace),
            "malformedPacketCount": malformed_count,
            "exactPacketCount": len(exact),
            "sequence": sequence or None,
            "traceId": _trace_id(reply),
            "causalPredecessor": predecessor_kind,
            "payloadHex": _payload(reply).hex() if _payload(reply) is not None else None,
            "transportMode": _body(reply).get("transportMode") if reply is not None else None,
            "obfuscated": _body(reply).get("obfuscated") if reply is not None else None,
            "decoded": decoded,
        },
        reply,
    )


def _application_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    trace_id: int | None,
    reply_sequence: int | None,
    expected_hash: str,
) -> dict[str, Any]:
    endpoint_hash_events = [
        record
        for record in records
        if record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_tcp"
        and record.get("event") == "source_result_applied"
        and _peer(record) == endpoint.casefold()
        and str(_keys(record).get("fileHash") or "").casefold() == expected_hash
    ]
    same_trace = [record for record in endpoint_hash_events if _trace_id(record) == trace_id]
    exact = []
    for record in same_trace:
        keys = _keys(record)
        body = _body(record)
        if (
            keys.get("protocolMarker") == SOURCE_PROTOCOL_MARKER
            and keys.get("opcode") == SOURCE_REPLY_OPCODE
            and body.get("flow") == "server"
            and body.get("phase") == "source_search"
            and body.get("direction") == "recv"
            and body.get("protocolMarker") == SOURCE_PROTOCOL_MARKER
            and body.get("opcode") == SOURCE_REPLY_OPCODE
            and _is_plaintext(record)
            and body.get("stateId") == "server.source.result_applied"
            and body.get("milestone") == "result_applied"
            and _positive_int(body.get("wireSourceCount")) == 1
            and _nonnegative_int(body.get("sourceCountBefore")) == 0
            and _positive_int(body.get("sourceCountAfter")) == 1
            and body.get("outcome") == "applied"
        ):
            exact.append(record)
    applied = exact[0] if len(endpoint_hash_events) == 1 and len(same_trace) == 1 and len(exact) == 1 else None
    sequence = _sequence(applied)
    body = _body(applied) if applied is not None else {}
    ok = bool(
        applied is not None
        and isinstance(reply_sequence, int)
        and sequence > reply_sequence
    )
    return {
        "ok": ok,
        "endpointHashEventCount": len(endpoint_hash_events),
        "traceEventCount": len(same_trace),
        "exactEventCount": len(exact),
        "sequence": sequence or None,
        "traceId": _trace_id(applied),
        "transportMode": body.get("transportMode"),
        "obfuscated": body.get("obfuscated"),
        "wireSourceCount": body.get("wireSourceCount"),
        "sourceCountBefore": body.get("sourceCountBefore"),
        "sourceCountAfter": body.get("sourceCountAfter"),
        "outcome": body.get("outcome"),
    }


def _rest_evidence(
    row: object,
    *,
    client: str,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
) -> dict[str, Any]:
    value = row if isinstance(row, dict) else {}
    name_field = "displayName" if client == "rust" else "name"
    size_bytes = _positive_int(value.get("sizeBytes"))
    source_count = _positive_int(value.get("sources"))
    ok = bool(
        str(value.get("hash") or "").casefold() == expected_hash
        and value.get(name_field) == expected_name
        and size_bytes == expected_size
        and source_count is not None
    )
    return {
        "ok": ok,
        "hash": str(value.get("hash") or "").casefold() or None,
        "name": value.get(name_field),
        "sizeBytes": size_bytes,
        "sources": source_count,
    }


def _component_failures(parts: dict[str, dict[str, Any]]) -> list[str]:
    return [name for name, part in parts.items() if part.get("ok") is not True]


def build_server_source_diagnostic_evidence(
    *,
    expected_file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
    server_endpoint: str,
    publisher_client_id: int,
    publisher_host: str,
    publisher_tcp_port: int,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
    transfer_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Proves one exact plaintext source lookup and source-state upsert per client."""

    normalized_hash = expected_file_hash.casefold()
    if len(normalized_hash) != 32 or any(value not in "0123456789abcdef" for value in normalized_hash):
        raise ValueError("Expected source file hash must be 32 hexadecimal characters.")
    if not expected_file_name:
        raise ValueError("Expected source filename must not be empty.")
    if (
        not isinstance(expected_file_size, int)
        or isinstance(expected_file_size, bool)
        or expected_file_size <= 0
        or expected_file_size > 0xFFFF_FFFF
    ):
        raise ValueError("Plain GETSOURCES file size must be a positive u32 integer.")
    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("Source server endpoint must be host:port.")
    try:
        publisher_address = ipaddress.IPv4Address(publisher_host)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Publisher host must be one canonical IPv4 address.") from exc
    expected_client_id = int.from_bytes(publisher_address.packed, "little")
    if (
        not isinstance(publisher_client_id, int)
        or isinstance(publisher_client_id, bool)
        or publisher_client_id < ed2k_wire.LOW_ID_CEILING
        or publisher_client_id != expected_client_id
    ):
        raise ValueError("Publisher client ID must be the HighID encoded by publisher_host.")
    if (
        not isinstance(publisher_tcp_port, int)
        or isinstance(publisher_tcp_port, bool)
        or not 1 <= publisher_tcp_port <= 0xFFFF
    ):
        raise ValueError("Publisher TCP port must be in 1..65535.")
    if not isinstance(transfer_rows, dict) or set(transfer_rows) != set(CLIENTS):
        raise ValueError("Transfer REST rows must contain exactly rust and mfc.")

    expected_payload = ed2k_wire.encode_source_request(bytes.fromhex(normalized_hash), expected_file_size)
    if len(expected_payload) != 20:
        raise AssertionError("Plain small-file GETSOURCES payload must be exactly 20 bytes.")

    records_by_client = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for client in CLIENTS:
        request, _ = _request_evidence(
            records_by_client[client],
            endpoint=server_endpoint,
            expected_payload=expected_payload,
        )
        send_outcome, _ = _send_outcome_evidence(
            records_by_client[client],
            endpoint=server_endpoint,
            trace_id=request.get("traceId"),
            request_sequence=request.get("sequence"),
            required=client == "rust",
        )
        reply_predecessor = send_outcome if client == "rust" else request
        reply, _ = _reply_evidence(
            records_by_client[client],
            endpoint=server_endpoint,
            trace_id=request.get("traceId"),
            predecessor_sequence=reply_predecessor.get("sequence"),
            predecessor_kind="send_outcome" if client == "rust" else "request",
            expected_hash=normalized_hash,
            expected_client_id=publisher_client_id,
            expected_host=str(publisher_address),
            expected_tcp_port=publisher_tcp_port,
        )
        application = _application_evidence(
            records_by_client[client],
            endpoint=server_endpoint,
            trace_id=request.get("traceId"),
            reply_sequence=reply.get("sequence"),
            expected_hash=normalized_hash,
        )
        rest = _rest_evidence(
            transfer_rows[client],
            client=client,
            expected_hash=normalized_hash,
            expected_name=expected_file_name,
            expected_size=expected_file_size,
        )
        parts = {
            "request": request,
            "sendOutcome": send_outcome,
            "reply": reply,
            "application": application,
            "rest": rest,
        }
        client_failures = _component_failures(parts)
        clients[client] = {
            "ok": not client_failures,
            "failures": client_failures,
            "wire": {
                "request": request,
                "sendOutcome": send_outcome,
                "reply": reply,
                "application": application,
            },
            "rest": rest,
        }
        failures.extend(f"{client}.{failure}" for failure in client_failures)

    rust_wire = clients["rust"]["wire"]
    mfc_wire = clients["mfc"]["wire"]
    rust_reply = rust_wire["reply"].get("decoded")
    mfc_reply = mfc_wire["reply"].get("decoded")
    rust_source = rust_reply.get("sources") if isinstance(rust_reply, dict) else None
    mfc_source = mfc_reply.get("sources") if isinstance(mfc_reply, dict) else None
    rust_application = rust_wire["application"]
    mfc_application = mfc_wire["application"]
    comparison = {
        "requestPayloadEqual": (
            rust_wire["request"].get("payloadHex") == mfc_wire["request"].get("payloadHex") == expected_payload.hex()
        ),
        "replyHashEqual": (
            isinstance(rust_reply, dict)
            and isinstance(mfc_reply, dict)
            and str(rust_reply.get("hash") or "").casefold()
            == str(mfc_reply.get("hash") or "").casefold()
            == normalized_hash
        ),
        "replyIdentityEqual": (
            rust_source
            == mfc_source
            == [
                {
                    "kind": "high-id",
                    "client_id": publisher_client_id,
                    "host": str(publisher_address),
                    "port": publisher_tcp_port,
                    "crypt_options": 0,
                    "user_hash": None,
                }
            ]
        ),
        "transportModeEqual": all(
            part.get("transportMode") == "plaintext" and part.get("obfuscated") is False
            for part in (
                rust_wire["request"],
                rust_wire["sendOutcome"],
                rust_wire["reply"],
                rust_wire["application"],
                mfc_wire["request"],
                mfc_wire["reply"],
                mfc_wire["application"],
            )
        ),
        "applicationCountsEqual": (
            rust_application.get("wireSourceCount")
            == mfc_application.get("wireSourceCount")
            == 1
            and rust_application.get("sourceCountBefore")
            == mfc_application.get("sourceCountBefore")
            == 0
            and rust_application.get("sourceCountAfter")
            == mfc_application.get("sourceCountAfter")
            == 1
        ),
    }
    comparison_ok = all(value is True for value in comparison.values())
    if not comparison_ok:
        failures.extend(f"comparison.{name}" for name, value in comparison.items() if value is not True)

    eligible_ids = list(ELIGIBLE_COVERAGE_IDS) if not failures else []
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "serverEndpoint": server_endpoint.casefold(),
        "expectedFile": {
            "hash": normalized_hash,
            "name": expected_file_name,
            "sizeBytes": expected_file_size,
        },
        "expectedPublisher": {
            "kind": "high-id",
            "clientId": publisher_client_id,
            "host": str(publisher_address),
            "tcpPort": publisher_tcp_port,
        },
        "failures": failures,
        "clients": clients,
        "comparison": {"ok": comparison_ok, **comparison},
        "observedCoverageIds": eligible_ids,
        "coverageClaims": {
            "eligibleCoverageIds": eligible_ids,
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_source_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless the exact bilateral plaintext source lookup is proven."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic server source diagnostics have an unexpected schema.")
    if report.get("ok") is not True:
        raise RuntimeError(f"Deterministic server source diagnostics are incomplete: {report.get('failures')!r}")
