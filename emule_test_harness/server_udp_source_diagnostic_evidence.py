"""Strict bilateral evidence gate for deterministic server UDP source lookups."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from emule_test_harness import ed2k_wire
from emule_test_harness.scripted_ed2k_udp_source import (
    SERVER_UDP_FLAG_EXT_GETSOURCES,
    SERVER_UDP_FLAG_EXT_GETSOURCES2,
    V1_TRANSCRIPT_SCHEMA,
    V2_TRANSCRIPT_SCHEMA,
)


SCHEMAS = {
    1: "emulebb-build-tests.deterministic-server-udp-source-v1-diagnostics.v1",
    2: "emulebb-build-tests.deterministic-server-udp-source-v2-diagnostics.v1",
}
DIAGNOSTIC_SCHEMA = "diag_event_v2"
CLIENTS = ("rust", "mfc")
ELIGIBLE_COVERAGE_IDS = {
    1: ("server.source.udp-v1", "server.reply.sources"),
    2: ("server.source.udp-v2", "server.reply.sources"),
}
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)


def _body(record: dict[str, Any] | None) -> dict[str, Any]:
    value = record.get("body") if record is not None else None
    return value if isinstance(value, dict) else {}


def _keys(record: dict[str, Any] | None) -> dict[str, Any]:
    value = record.get("keys") if record is not None else None
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
    values = [
        value
        for value in (_keys(record).get("traceId"), _body(record).get("traceId"))
        if value is not None
    ]
    normalized = [_positive_int(value) for value in values]
    if not normalized or any(value is None for value in normalized):
        return None
    unique = set(normalized)
    return next(iter(unique)) if len(unique) == 1 else None


def _send_attempt_id(record: dict[str, Any] | None) -> int | None:
    if record is None:
        return None
    values = [
        value
        for value in (
            _keys(record).get("sendAttemptId"),
            _body(record).get("sendAttemptId"),
        )
        if value is not None
    ]
    normalized = [_positive_int(value) for value in values]
    if not normalized or any(value is None for value in normalized):
        return None
    unique = set(normalized)
    return next(iter(unique)) if len(unique) == 1 else None


def _payload(record: dict[str, Any] | None) -> bytes | None:
    body = _body(record)
    value = body.get("payloadHex")
    if not isinstance(value, str) or body.get("payloadHexTruncated") is not False:
        return None
    try:
        payload = bytes.fromhex(value)
    except ValueError:
        return None
    return payload if body.get("payloadLen") == len(payload) else None


def _packet_candidates(
    records: list[dict[str, Any]],
    *,
    udp_endpoint: str,
    direction: str,
    opcode: int,
) -> list[dict[str, Any]]:
    return [
        record
        for record in records
        if record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_server_udp"
        and record.get("event") == "packet"
        and str(_keys(record).get("peer") or "").casefold() == udp_endpoint.casefold()
        and _keys(record).get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and _keys(record).get("opcode") == opcode
        and _body(record).get("flow") == "server"
        and _body(record).get("phase") == "udp"
        and _body(record).get("direction") == direction
        and _body(record).get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and _body(record).get("opcode") == opcode
        and _body(record).get("transportMode") == "plaintext"
        and _body(record).get("obfuscated") is False
    ]


def _request_evidence(
    records: list[dict[str, Any]],
    *,
    udp_endpoint: str,
    request_opcode: int,
    opposite_opcode: int,
    opposite_version: int,
    expected_payload: bytes,
    require_send_attempt_id: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    candidates = _packet_candidates(
        records,
        udp_endpoint=udp_endpoint,
        direction="send",
        opcode=request_opcode,
    )
    matching_payload = [
        record for record in candidates if _payload(record) == expected_payload
    ]
    forbidden = [
        record
        for record in _packet_candidates(
            records,
            udp_endpoint=udp_endpoint,
            direction="send",
            opcode=opposite_opcode,
        )
        if (_payload(record) or b"").startswith(expected_payload[:16])
    ]
    exact = [
        record
        for record in matching_payload
        if _body(record).get("outcome") == "attempted"
        and (
            _send_attempt_id(record) is not None
            if require_send_attempt_id
            else _trace_id(record) is not None
        )
    ]
    request = (
        exact[0]
        if len(matching_payload) == len(exact) == 1 and not forbidden
        else None
    )
    summary = {
        "ok": request is not None,
        "packetCount": len(matching_payload),
        "exactPacketCount": len(exact),
        "sequence": _sequence(request) or None,
        "traceId": _trace_id(request),
        "sendAttemptId": _send_attempt_id(request),
        "payloadHex": _payload(request).hex() if _payload(request) is not None else None,
        "expectedPayloadHex": expected_payload.hex(),
    }
    summary[f"forbiddenV{opposite_version}PacketCount"] = len(forbidden)
    return summary, request


def _send_outcome_evidence(
    records: list[dict[str, Any]],
    *,
    udp_endpoint: str,
    request_opcode: int,
    request: dict[str, Any] | None,
    required: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    send_attempt_id = _send_attempt_id(request)
    candidates = [
        record
        for record in records
        if record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_server_udp"
        and record.get("event") == "send_outcome"
        and str(_keys(record).get("peer") or "").casefold() == udp_endpoint.casefold()
        and _send_attempt_id(record) == send_attempt_id
        and _keys(record).get("opcode") == request_opcode
        and _body(record).get("opcode") == request_opcode
    ]
    exact = [
        record
        for record in candidates
        if _body(record).get("outcome") == "send_succeeded"
        and _body(record).get("deliveryKnown") is True
        and _body(record).get("transportMode") == "plaintext"
        and _body(record).get("obfuscated") is False
        and _sequence(record) > _sequence(request)
    ]
    outcome = exact[0] if len(candidates) == len(exact) == 1 else None
    ok = outcome is not None if required else not candidates
    return (
        {
            "ok": ok,
            "required": required,
            "evidenceModel": "terminal-socket-outcome" if required else "correlated-reply-after-attempt",
            "outcomeCount": len(candidates),
            "successfulOutcomeCount": len(exact),
            "sequence": _sequence(outcome) or None,
            "traceId": _trace_id(outcome),
            "sendAttemptId": _send_attempt_id(outcome),
            "outcome": _body(outcome).get("outcome") if outcome is not None else None,
            "deliveryKnown": _body(outcome).get("deliveryKnown") if outcome is not None else None,
        },
        outcome,
    )


def _reply_evidence(
    records: list[dict[str, Any]],
    *,
    udp_endpoint: str,
    expected_datagram: bytes,
    predecessor: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    expected_payload = expected_datagram[2:]
    candidates = _packet_candidates(
        records,
        udp_endpoint=udp_endpoint,
        direction="recv",
        opcode=ed2k_wire.OP_GLOBFOUNDSOURCES,
    )
    decoded: list[tuple[dict[str, Any], dict[str, object]]] = []
    malformed = 0
    for record in candidates:
        payload = _payload(record)
        if payload is None:
            malformed += 1
            continue
        try:
            value = ed2k_wire.decode_server_udp_source_reply(
                bytes((ed2k_wire.PROTO_EDONKEY, ed2k_wire.OP_GLOBFOUNDSOURCES)) + payload
            )
        except ed2k_wire.Ed2kWireError:
            malformed += 1
            continue
        decoded.append((record, value))
    exact = [
        (record, value)
        for record, value in decoded
        if _payload(record) == expected_payload
        and _body(record).get("outcome") == "accepted"
        and _trace_id(record) is not None
        and _sequence(record) > _sequence(predecessor)
    ]
    reply = exact[0][0] if len(candidates) == len(exact) == 1 and malformed == 0 else None
    return (
        {
            "ok": reply is not None,
            "packetCount": len(candidates),
            "exactPacketCount": len(exact),
            "malformedPacketCount": malformed,
            "sequence": _sequence(reply) or None,
            "traceId": _trace_id(reply),
            "payloadHex": _payload(reply).hex() if _payload(reply) is not None else None,
            "decoded": exact[0][1] if reply is not None else None,
        },
        reply,
    )


def _application_evidence(
    records: list[dict[str, Any]],
    *,
    target_server_endpoint: str,
    target_udp_endpoint: str,
    expected_hash: str,
    request_opcode: int,
    request_opcode_name: str,
    reply: dict[str, Any] | None,
) -> dict[str, Any]:
    trace_id = _trace_id(reply)
    candidates = [
        record
        for record in records
        if record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_server_udp"
        and record.get("event") == "source_result_applied"
        and str(_keys(record).get("peer") or "").casefold() == target_udp_endpoint.casefold()
        and str(_keys(record).get("fileHash") or "").casefold() == expected_hash
    ]
    same_trace = [record for record in candidates if _trace_id(record) == trace_id]
    exact = []
    for record in same_trace:
        keys = _keys(record)
        body = _body(record)
        if (
            keys.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
            and keys.get("opcode") == ed2k_wire.OP_GLOBFOUNDSOURCES
            and keys.get("requestOpcode") == request_opcode
            and body.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
            and body.get("opcode") == ed2k_wire.OP_GLOBFOUNDSOURCES
            and body.get("requestOpcode") == request_opcode
            and body.get("requestOpcodeName") == request_opcode_name
            and body.get("flow") == "server"
            and body.get("phase") == "source_search"
            and body.get("direction") == "recv"
            and body.get("transportMode") == "plaintext"
            and body.get("obfuscated") is False
            and str(body.get("serverEndpoint") or "").casefold()
            == target_server_endpoint.casefold()
            and body.get("stateId") == "server.source.result_applied"
            and body.get("milestone") == "result_applied"
            and _positive_int(body.get("wireSourceCount")) == 1
            and _nonnegative_int(body.get("sourceCountBefore")) == 0
            and _positive_int(body.get("sourceCountAfter")) == 1
            and body.get("outcome") == "applied"
            and _sequence(record) > _sequence(reply)
        ):
            exact.append(record)
    applied = exact[0] if len(candidates) == len(same_trace) == len(exact) == 1 else None
    body = _body(applied)
    return {
        "ok": applied is not None,
        "endpointHashEventCount": len(candidates),
        "traceEventCount": len(same_trace),
        "exactEventCount": len(exact),
        "sequence": _sequence(applied) or None,
        "traceId": _trace_id(applied),
        "requestOpcode": body.get("requestOpcode"),
        "opcode": body.get("opcode"),
        "wireSourceCount": body.get("wireSourceCount"),
        "sourceCountBefore": body.get("sourceCountBefore"),
        "sourceCountAfter": body.get("sourceCountAfter"),
        "serverEndpoint": body.get("serverEndpoint"),
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
    sources = _positive_int(value.get("sources"))
    ok = bool(
        str(value.get("hash") or "").casefold() == expected_hash
        and value.get(name_field) == expected_name
        and _positive_int(value.get("sizeBytes")) == expected_size
        and sources is not None
    )
    return {
        "ok": ok,
        "hash": str(value.get("hash") or "").casefold() or None,
        "name": value.get(name_field),
        "sizeBytes": _positive_int(value.get("sizeBytes")),
        "sources": sources,
    }


def _transcript_evidence(
    transcript: object,
    *,
    target_server_endpoint: str,
    target_udp_endpoint: str,
    expected_hash: str,
    expected_size: int,
    source_request_version: int,
    expected_request_datagram: bytes,
    expected_reply_datagram: bytes,
) -> dict[str, Any]:
    value = transcript if isinstance(transcript, dict) else {}
    events = value.get("events") if isinstance(value.get("events"), list) else []
    request_hex = expected_request_datagram.hex().upper()
    reply_hex = expected_reply_datagram.hex().upper()
    request_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES2
    )
    opposite_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES2
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES
    )
    opposite_version = 2 if source_request_version == 1 else 1
    expected_schema = (
        V1_TRANSCRIPT_SCHEMA
        if source_request_version == 1
        else V2_TRANSCRIPT_SCHEMA
    )
    expected_flags = SERVER_UDP_FLAG_EXT_GETSOURCES
    if source_request_version == 2:
        expected_flags |= SERVER_UDP_FLAG_EXT_GETSOURCES2
    requests = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("direction") == "recv"
        and event.get("opcode") == request_opcode
    ]
    replies = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("direction") == "send"
        and event.get("opcode") == ed2k_wire.OP_GLOBFOUNDSOURCES
    ]
    forbidden = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("direction") == "recv"
        and event.get("opcode") == opposite_opcode
    ]
    status_requests = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("direction") == "recv"
        and event.get("opcode") == ed2k_wire.OP_GLOBSERVSTATREQ
        and event.get("accepted") is True
    ]
    status_replies = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("direction") == "send"
        and event.get("opcode") == ed2k_wire.OP_GLOBSERVSTATRES
        and event.get("accepted") is True
    ]
    peers = {str(event.get("peer") or "") for event in requests}
    status_peers = {str(event.get("peer") or "") for event in status_requests}
    paired = all(
        any(
            str(reply.get("peer") or "") == str(request.get("peer") or "")
            and _positive_int(reply.get("sequence")) is not None
            and _positive_int(request.get("sequence")) is not None
            and int(reply["sequence"]) > int(request["sequence"])
            for reply in replies
        )
        for request in requests
    )
    exact_requests = [
        event
        for event in requests
        if event.get("accepted") is True and event.get("frameHex") == request_hex
    ]
    exact_replies = [
        event
        for event in replies
        if event.get("accepted") is True and event.get("frameHex") == reply_hex
    ]
    status_paired = all(
        any(
            str(reply.get("peer") or "") == str(request.get("peer") or "")
            and _positive_int(reply.get("sequence")) is not None
            and _positive_int(request.get("sequence")) is not None
            and int(reply["sequence"]) > int(request["sequence"])
            for reply in status_replies
        )
        for request in status_requests
    )
    expected_keys = {
        "schema",
        "serverEndpoint",
        "udpEndpoint",
        "udpFlags",
        "fileHash",
        "source",
        "events",
    }
    if source_request_version == 2:
        expected_keys.add("fileSize")
    ok = bool(
        set(value) == expected_keys
        and value.get("schema") == expected_schema
        and str(value.get("serverEndpoint") or "").casefold()
        == target_server_endpoint.casefold()
        and str(value.get("udpEndpoint") or "").casefold() == target_udp_endpoint.casefold()
        and value.get("udpFlags") == expected_flags
        and str(value.get("fileHash") or "").casefold() == expected_hash
        and (
            value.get("fileSize") == expected_size
            if source_request_version == 2
            else "fileSize" not in value
        )
        and len(status_requests) == len(status_replies) == 2
        and len(status_peers) == 2
        and status_paired
        and len(requests) == len(exact_requests) == 2
        and len(replies) == len(exact_replies) == 2
        and len(peers) == 2
        and not forbidden
        and paired
    )
    summary = {
        "ok": ok,
        "schema": value.get("schema"),
        "requestCount": len(requests),
        "exactRequestCount": len(exact_requests),
        "replyCount": len(replies),
        "exactReplyCount": len(exact_replies),
        "statusRequestCount": len(status_requests),
        "statusReplyCount": len(status_replies),
        "distinctStatusPeerCount": len(status_peers),
        "statusPaired": status_paired,
        "distinctRequestPeerCount": len(peers),
        "paired": paired,
    }
    summary[f"forbiddenV{opposite_version}RequestCount"] = len(forbidden)
    return summary


def build_server_udp_source_diagnostic_evidence(
    *,
    source_request_version: int,
    expected_file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
    target_server_endpoint: str,
    target_udp_endpoint: str,
    source_host: str,
    source_tcp_port: int,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
    transfer_rows: dict[str, dict[str, Any]],
    fixture_transcript: dict[str, Any],
) -> dict[str, Any]:
    """Builds fail-closed Rust/MFC/fixture proof for one UDP source version."""

    if source_request_version not in SCHEMAS:
        raise ValueError("Server UDP source request version must be 1 or 2.")
    normalized_hash = expected_file_hash.casefold()
    if len(normalized_hash) != 32 or any(value not in "0123456789abcdef" for value in normalized_hash):
        raise ValueError("Expected file hash must be 32 hexadecimal characters.")
    if not expected_file_name or expected_file_size <= 0:
        raise ValueError("Expected file metadata must be complete.")
    if ":" not in target_server_endpoint or ":" not in target_udp_endpoint:
        raise ValueError("Target server endpoints must be host:port.")
    source_address = ipaddress.IPv4Address(source_host)
    if not 1 <= source_tcp_port <= 0xFFFF:
        raise ValueError("Source TCP port must be in 1..65535.")
    if not isinstance(transfer_rows, dict) or set(transfer_rows) != set(CLIENTS):
        raise ValueError("Transfer REST rows must contain exactly rust and mfc.")

    source_id = int.from_bytes(source_address.packed, "little")
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
    opposite_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES2
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES
    )
    opposite_version = 2 if source_request_version == 1 else 1
    if source_request_version == 1:
        request_datagram = ed2k_wire.encode_server_udp_source_v1_request(
            [bytes.fromhex(normalized_hash)]
        )
    else:
        request_datagram = ed2k_wire.encode_server_udp_source_v2_request(
            [(bytes.fromhex(normalized_hash), expected_file_size)]
        )
    reply_datagram = ed2k_wire.encode_server_udp_source_reply(
        file_hash=bytes.fromhex(normalized_hash),
        sources=[(source_id, source_tcp_port)],
    )
    expected_request_payload = request_datagram[2:]

    records_by_client = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for client in CLIENTS:
        request_summary, request = _request_evidence(
            records_by_client[client],
            udp_endpoint=target_udp_endpoint,
            request_opcode=request_opcode,
            opposite_opcode=opposite_opcode,
            opposite_version=opposite_version,
            expected_payload=expected_request_payload,
            require_send_attempt_id=client == "rust",
        )
        outcome_summary, outcome = _send_outcome_evidence(
            records_by_client[client],
            udp_endpoint=target_udp_endpoint,
            request_opcode=request_opcode,
            request=request,
            required=client == "rust",
        )
        predecessor = outcome if client == "rust" else request
        reply_summary, reply = _reply_evidence(
            records_by_client[client],
            udp_endpoint=target_udp_endpoint,
            expected_datagram=reply_datagram,
            predecessor=predecessor,
        )
        application = _application_evidence(
            records_by_client[client],
            target_server_endpoint=target_server_endpoint,
            target_udp_endpoint=target_udp_endpoint,
            expected_hash=normalized_hash,
            request_opcode=request_opcode,
            request_opcode_name=request_opcode_name,
            reply=reply,
        )
        rest = _rest_evidence(
            transfer_rows[client],
            client=client,
            expected_hash=normalized_hash,
            expected_name=expected_file_name,
            expected_size=expected_file_size,
        )
        components = {
            "request": request_summary,
            "sendOutcome": outcome_summary,
            "reply": reply_summary,
            "application": application,
            "rest": rest,
        }
        client_failures = [name for name, part in components.items() if part.get("ok") is not True]
        failures.extend(f"{client}.{name}" for name in client_failures)
        clients[client] = {
            "ok": not client_failures,
            "failures": client_failures,
            "wire": {name: components[name] for name in ("request", "sendOutcome", "reply", "application")},
            "rest": rest,
        }

    transcript = _transcript_evidence(
        fixture_transcript,
        target_server_endpoint=target_server_endpoint,
        target_udp_endpoint=target_udp_endpoint,
        expected_hash=normalized_hash,
        expected_size=expected_file_size,
        source_request_version=source_request_version,
        expected_request_datagram=request_datagram,
        expected_reply_datagram=reply_datagram,
    )
    if transcript.get("ok") is not True:
        failures.append("fixture.transcript")

    rust_wire = clients["rust"]["wire"]
    mfc_wire = clients["mfc"]["wire"]
    comparison = {
        "requestPayloadEqual": (
            rust_wire["request"].get("payloadHex")
            == mfc_wire["request"].get("payloadHex")
            == expected_request_payload.hex()
        ),
        "replyPayloadEqual": (
            rust_wire["reply"].get("payloadHex")
            == mfc_wire["reply"].get("payloadHex")
            == reply_datagram[2:].hex()
        ),
        "replyIdentityEqual": (
            rust_wire["reply"].get("decoded") == mfc_wire["reply"].get("decoded")
        ),
        "applicationTransitionEqual": (
            rust_wire["application"].get("sourceCountBefore")
            == mfc_wire["application"].get("sourceCountBefore")
            == 0
            and rust_wire["application"].get("sourceCountAfter")
            == mfc_wire["application"].get("sourceCountAfter")
            == 1
        ),
        "restSourceCountEqual": (
            clients["rust"]["rest"].get("sources")
            == clients["mfc"]["rest"].get("sources")
            == 1
        ),
    }
    comparison_failures = [name for name, value in comparison.items() if value is not True]
    failures.extend(f"comparison.{name}" for name in comparison_failures)
    ok = not failures
    fixture = {
        "fileHash": normalized_hash,
        "fileName": expected_file_name,
        "fileSize": expected_file_size,
        "targetServerEndpoint": target_server_endpoint,
        "targetUdpEndpoint": target_udp_endpoint,
        "sourceHost": str(source_address),
        "sourceClientId": source_id,
        "sourceTcpPort": source_tcp_port,
        "requestDatagramHex": request_datagram.hex(),
        "replyDatagramHex": reply_datagram.hex(),
    }
    if source_request_version == 2:
        fixture["sourceRequestVersion"] = source_request_version
    return {
        "schema": SCHEMAS[source_request_version],
        "ok": ok,
        "failures": failures,
        "evidenceLayers": list(EVIDENCE_LAYERS),
        "eligibleCoverageIds": (
            list(ELIGIBLE_COVERAGE_IDS[source_request_version]) if ok else []
        ),
        "fixture": fixture,
        "clients": clients,
        "fixtureTranscript": transcript,
        "comparison": {"ok": not comparison_failures, "failures": comparison_failures, **comparison},
    }


def require_server_udp_source_diagnostic_evidence(
    evidence: dict[str, Any],
    *,
    source_request_version: int,
) -> None:
    """Raises unless all bilateral UDP source proof layers are complete."""

    if source_request_version not in SCHEMAS:
        raise ValueError("Server UDP source request version must be 1 or 2.")
    if (
        evidence.get("schema") != SCHEMAS[source_request_version]
        or evidence.get("ok") is not True
    ):
        raise RuntimeError(
            f"Deterministic server UDP source v{source_request_version} evidence is incomplete: "
            f"{evidence.get('failures')!r}"
        )
    if evidence.get("eligibleCoverageIds") != list(
        ELIGIBLE_COVERAGE_IDS[source_request_version]
    ):
        raise RuntimeError(
            f"Server UDP source v{source_request_version} evidence has an invalid coverage claim."
        )
