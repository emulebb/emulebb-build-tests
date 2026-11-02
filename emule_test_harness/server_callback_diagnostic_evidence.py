"""Causal bilateral evidence gate for one deterministic server callback reply."""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any, Iterable

from emule_test_harness import ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-server-callback-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
COVERAGE_ID = "server.reply.callback"
CLIENTS = ("rust", "mfc")


def _body(record: dict[str, Any] | None) -> dict[str, Any]:
    value = record.get("body") if record is not None else None
    return value if isinstance(value, dict) else {}


def _keys(record: dict[str, Any] | None) -> dict[str, Any]:
    value = record.get("keys") if record is not None else None
    return value if isinstance(value, dict) else {}


def _positive_int(value: object) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else None
    )


def _sequence(record: dict[str, Any] | None) -> int:
    return _positive_int(record.get("seq")) or 0 if record is not None else 0


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


def _peer(record: dict[str, Any]) -> str:
    return str(_keys(record).get("peer") or "").casefold()


def _payload(record: dict[str, Any] | None) -> bytes | None:
    body = _body(record)
    payload_hex = body.get("payloadHex")
    if body.get("payloadHexTruncated") is not False or not isinstance(
        payload_hex, str
    ):
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    return payload if body.get("payloadLen") == len(payload) else None


def _callback_packet(record: dict[str, Any], endpoint: str) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_tcp"
        and record.get("event") == "packet"
        and _peer(record) == endpoint.casefold()
        and keys.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and keys.get("opcode") == ed2k_wire.OP_CALLBACKREQUESTED
        and body.get("flow") == "server"
        and body.get("direction") == "recv"
        and body.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and body.get("opcode") == ed2k_wire.OP_CALLBACKREQUESTED
        and body.get("outcome") == "accepted"
    )


def _callback_application(
    record: dict[str, Any],
    *,
    endpoint: str,
    trace_id: int | None,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_tcp"
        and record.get("event") == "callback_request_applied"
        and _peer(record) == endpoint.casefold()
        and _trace_id(record) == trace_id
        and keys.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and keys.get("opcode") == ed2k_wire.OP_CALLBACKREQUESTED
        and body.get("flow") == "server"
        and body.get("direction") == "recv"
        and body.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and body.get("opcode") == ed2k_wire.OP_CALLBACKREQUESTED
    )


def _target(value: object) -> dict[str, Any]:
    row = value if isinstance(value, dict) else {}
    client_id = row.get("clientId")
    tcp_port = row.get("tcpPort")
    user_hash = str(row.get("userHash") or "").upper()
    ok = bool(
        isinstance(client_id, int)
        and not isinstance(client_id, bool)
        and 0 < client_id < ed2k_wire.LOW_ID_CEILING
        and isinstance(tcp_port, int)
        and not isinstance(tcp_port, bool)
        and 0 < tcp_port <= 0xFFFF
        and len(user_hash) == 32
        and all(character in "0123456789ABCDEF" for character in user_hash)
        and row.get("idKind") == "low-id"
    )
    return {
        "ok": ok,
        "clientId": client_id,
        "tcpPort": tcp_port,
        "userHash": user_hash or None,
        "idKind": row.get("idKind"),
    }


def _requester_result(
    value: object,
    *,
    client: str,
    target: dict[str, Any],
) -> dict[str, Any]:
    result = value if isinstance(value, dict) else {}
    request_payload = (
        ed2k_wire.encode_callback_request(target["clientId"])
        if target["ok"]
        else b""
    )
    transcript = (
        result.get("requestTranscript")
        if isinstance(result.get("requestTranscript"), dict)
        else {}
    )
    connection = (
        result.get("callbackConnection")
        if isinstance(result.get("callbackConnection"), dict)
        else {}
    )
    request_hash = hashlib.sha256(request_payload).hexdigest()
    ok = bool(
        target["ok"]
        and result.get("schema")
        == "emulebb.docker-ed2k-source-publisher.callback-result/1"
        and result.get("status") == "completed"
        and result.get("targetLabel") == client
        and result.get("targetClientId") == target["clientId"]
        and result.get("requestOpcode") == ed2k_wire.OP_CALLBACKREQUEST
        and result.get("requestPayloadHex") == request_payload.hex().upper()
        and transcript.get("direction") == "send"
        and transcript.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and transcript.get("opcode") == ed2k_wire.OP_CALLBACKREQUEST
        and transcript.get("payloadLength") == len(request_payload)
        and transcript.get("payloadSha256") == request_hash
        and str(transcript.get("payloadHex") or "").casefold()
        == request_payload.hex()
        and str(connection.get("userHash") or "").upper() == target["userHash"]
        and connection.get("tcpPort") == target["tcpPort"]
    )
    return {
        "ok": ok,
        "targetClientId": target["clientId"],
        "requestPayloadHex": request_payload.hex().upper() or None,
        "requestTranscript": transcript or None,
        "callbackConnection": connection or None,
    }


def _client_evidence(
    *,
    client: str,
    records: list[dict[str, Any]],
    endpoint: str,
    expected_reply_payload: bytes,
    target_value: object,
    requester_result: object,
) -> dict[str, Any]:
    target = _target(target_value)
    request = _requester_result(requester_result, client=client, target=target)
    packets = [record for record in records if _callback_packet(record, endpoint)]
    exact_packets = [
        record for record in packets if _payload(record) == expected_reply_payload
    ]
    packet = exact_packets[0] if len(packets) == 1 and len(exact_packets) == 1 else None
    packet_sequence = _sequence(packet)
    trace_id = _trace_id(packet)
    decoded: dict[str, object] | None = None
    decode_error: str | None = None
    if packet is not None:
        try:
            decoded = ed2k_wire.decode_callback_requested(expected_reply_payload)
        except ed2k_wire.Ed2kWireError as exc:
            decode_error = str(exc)

    applications = [
        record
        for record in records
        if _callback_application(record, endpoint=endpoint, trace_id=trace_id)
    ]
    exact_applications = [
        record
        for record in applications
        if decoded is not None
        and _sequence(record) > packet_sequence
        and _body(record).get("callbackEndpoint")
        == f"{decoded['peer_host']}:{decoded['peer_port']}"
        and _body(record).get("connectOptions") == decoded["connect_options"]
        and (
            str(_body(record).get("userHash") or "").upper() or None
        )
        == decoded["user_hash"]
        and _body(record).get("payloadLen") == decoded["payload_length"]
        and _body(record).get("stateId") == "server.callback.request_applied"
        and _body(record).get("milestone") == "callback_dispatch"
        and _body(record).get("dispatchAccepted") is True
        and _body(record).get("outcome") == "applied"
    ]
    application = (
        exact_applications[0]
        if len(applications) == 1 and len(exact_applications) == 1
        else None
    )
    transport_mode = _body(packet).get("transportMode") if packet is not None else None
    application_transport = (
        _body(application).get("transportMode") if application is not None else None
    )
    ok = bool(
        target["ok"]
        and request["ok"]
        and packet is not None
        and packet_sequence > 0
        and trace_id is not None
        and decoded is not None
        and application is not None
        and transport_mode in {"plaintext", "obfuscated"}
        and application_transport == transport_mode
    )
    return {
        "ok": ok,
        "target": target,
        "requester": request,
        "wire": {
            "ok": packet is not None and decoded is not None,
            "packetCount": len(packets),
            "exactPacketCount": len(exact_packets),
            "sequence": packet_sequence or None,
            "traceId": trace_id,
            "payloadHex": (
                _payload(packet).hex().upper() if _payload(packet) is not None else None
            ),
            "decoded": decoded,
            "decodeError": decode_error,
            "transportMode": transport_mode,
        },
        "application": {
            "ok": application is not None,
            "recordCount": len(applications),
            "exactRecordCount": len(exact_applications),
            "sequence": _sequence(application) or None,
            "traceId": _trace_id(application),
            "transportMode": application_transport,
        },
    }


def build_server_callback_diagnostic_evidence(
    *,
    server_endpoint: str,
    requester_host: str,
    requester_port: int,
    targets: dict[str, object],
    requester_results: dict[str, object],
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Proves the exact server reply, application, and callback connect for both clients."""

    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("Server callback endpoint must be host:port")
    if not 0 < requester_port <= 0xFFFF:
        raise ValueError("Requester callback port must be in 1..65535")
    requester_ip = ipaddress.IPv4Address(requester_host)
    expected_reply_payload = requester_ip.packed + struct.pack("<H", requester_port)
    records = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients = {
        client: _client_evidence(
            client=client,
            records=records[client],
            endpoint=server_endpoint,
            expected_reply_payload=expected_reply_payload,
            target_value=targets.get(client),
            requester_result=requester_results.get(client),
        )
        for client in CLIENTS
    }
    comparison = {
        "replyPayloadEqual": all(
            row["wire"]["payloadHex"] == expected_reply_payload.hex().upper()
            for row in clients.values()
        ),
        "callbackEndpointEqual": all(
            (row["wire"]["decoded"] or {}).get("peer_host") == requester_host
            and (row["wire"]["decoded"] or {}).get("peer_port") == requester_port
            for row in clients.values()
        ),
        "shortReplyEqual": all(
            (row["wire"]["decoded"] or {}).get("has_crypt_profile") is False
            for row in clients.values()
        ),
        "bothApplied": all(row["application"]["ok"] is True for row in clients.values()),
        "bothConnected": all(row["requester"]["ok"] is True for row in clients.values()),
    }
    comparison["ok"] = all(comparison.values())
    failures = [
        *[
            f"client.{client}"
            for client, row in clients.items()
            if row["ok"] is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "serverEndpoint": server_endpoint.casefold(),
        "requesterEndpoint": f"{requester_host}:{requester_port}",
        "expectedReplyPayloadHex": expected_reply_payload.hex().upper(),
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [COVERAGE_ID] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_callback_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless both selected clients causally applied the callback reply."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic server-callback diagnostics have an unexpected schema")
    if report.get("ok") is not True:
        raise RuntimeError(
            "Deterministic server-callback diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [COVERAGE_ID]:
        raise RuntimeError("Deterministic server-callback coverage claims are invalid")
