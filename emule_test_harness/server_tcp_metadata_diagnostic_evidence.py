"""Causal bilateral gate for deterministic eD2K TCP server metadata replies."""

from __future__ import annotations

from typing import Any, Iterable

from emule_test_harness import ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-server-tcp-metadata-diagnostics.v1"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
ELIGIBLE_COVERAGE_IDS = ("server.reply.tcp-ident", "server.reply.tcp-status")
PROTOCOL_MARKER = ed2k_wire.PROTO_EDONKEY
GET_SERVER_LIST_OPCODE = 0x14
ID_CHANGE_OPCODE = ed2k_wire.OP_IDCHANGE
STATUS_OPCODE = ed2k_wire.OP_SERVERSTATUS
IDENT_OPCODE = ed2k_wire.OP_SERVERIDENT
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
    if record is None:
        return 0
    return _positive_int(record.get("seq")) or 0


def _trace_id(record: dict[str, Any] | None) -> int | None:
    if record is None:
        return None
    values = [value for value in (_keys(record).get("traceId"), _body(record).get("traceId")) if value is not None]
    normalized = [_positive_int(value) for value in values]
    if not normalized or any(value is None for value in normalized):
        return None
    unique = set(normalized)
    return next(iter(unique)) if len(unique) == 1 else None


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
    return payload if body.get("payloadLen") == len(payload) else None


def _packet(
    record: dict[str, Any],
    *,
    endpoint: str,
    direction: str,
    opcode: int,
    outcome: str,
) -> bool:
    body = _body(record)
    keys = _keys(record)
    return bool(
        record.get("family") == "ed2k_tcp"
        and record.get("event") == "packet"
        and str(keys.get("peer") or "").casefold() == endpoint.casefold()
        and keys.get("protocolMarker") == PROTOCOL_MARKER
        and keys.get("opcode") == opcode
        and body.get("flow") == "server"
        and body.get("direction") == direction
        and body.get("outcome") == outcome
        and body.get("protocolMarker") == PROTOCOL_MARKER
        and body.get("opcode") == opcode
    )


def _one_packet(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    direction: str,
    opcode: int,
    outcome: str,
) -> tuple[dict[str, Any] | None, int]:
    matches = [
        record
        for record in records
        if _packet(
            record,
            endpoint=endpoint,
            direction=direction,
            opcode=opcode,
            outcome=outcome,
        )
    ]
    return (matches[0] if len(matches) == 1 else None, len(matches))


def _wire_evidence(
    records: list[dict[str, Any]], *, client: str, endpoint: str
) -> dict[str, Any]:
    id_change, id_change_count = _one_packet(
        records,
        endpoint=endpoint,
        direction="recv",
        opcode=ID_CHANGE_OPCODE,
        outcome="accepted",
    )
    request, request_count = _one_packet(
        records,
        endpoint=endpoint,
        direction="send",
        opcode=GET_SERVER_LIST_OPCODE,
        outcome="attempted" if client == "rust" else "send_succeeded",
    )
    status, status_count = _one_packet(
        records,
        endpoint=endpoint,
        direction="recv",
        opcode=STATUS_OPCODE,
        outcome="accepted",
    )
    ident, ident_count = _one_packet(
        records,
        endpoint=endpoint,
        direction="recv",
        opcode=IDENT_OPCODE,
        outcome="accepted",
    )
    decode_errors: list[str] = []
    decoded_status = None
    decoded_ident = None
    try:
        status_payload = _payload(status)
        if status_payload is None:
            raise ed2k_wire.Ed2kWireError("missing exact status payload")
        decoded_status = ed2k_wire.decode_server_status(status_payload)
    except ed2k_wire.Ed2kWireError as exc:
        decode_errors.append(f"status: {exc}")
    try:
        ident_payload = _payload(ident)
        if ident_payload is None:
            raise ed2k_wire.Ed2kWireError("missing exact ident payload")
        decoded_ident = ed2k_wire.decode_server_ident(ident_payload)
    except ed2k_wire.Ed2kWireError as exc:
        decode_errors.append(f"ident: {exc}")

    trace_ids = {_trace_id(record) for record in (id_change, request, status, ident)}
    trace_id = next(iter(trace_ids)) if len(trace_ids) == 1 and None not in trace_ids else None
    sequences = {
        "idChange": _sequence(id_change),
        "request": _sequence(request),
        "status": _sequence(status),
        "ident": _sequence(ident),
    }
    request_payload = _payload(request)
    transports = [_body(record).get("transportMode") for record in (id_change, request, status, ident) if record]
    ok = bool(
        id_change_count == request_count == status_count == ident_count == 1
        and trace_id is not None
        and request_payload == b""
        and decoded_status is not None
        and decoded_ident is not None
        and sequences["idChange"] < sequences["request"] < sequences["ident"]
        and sequences["idChange"] < sequences["status"]
        and all(value == "obfuscated" for value in transports)
        and not decode_errors
    )
    return {
        "ok": ok,
        "traceId": trace_id,
        "packetCounts": {
            "idChange": id_change_count,
            "getServerList": request_count,
            "status": status_count,
            "ident": ident_count,
        },
        "sequences": sequences,
        "requestPayloadHex": request_payload.hex() if request_payload is not None else None,
        "requestOutcome": _body(request).get("outcome") if request is not None else None,
        "transportModes": transports,
        "status": decoded_status,
        "ident": decoded_ident,
        "decodeErrors": decode_errors,
    }


def _applied_evidence(
    records: list[dict[str, Any]],
    *,
    endpoint: str,
    wire: dict[str, Any],
) -> dict[str, Any]:
    trace_id = wire.get("traceId")
    applied: dict[str, list[dict[str, Any]]] = {}
    for name, event, opcode in (
        ("status", "server_status_applied", STATUS_OPCODE),
        ("ident", "server_ident_applied", IDENT_OPCODE),
    ):
        applied[name] = [
            record
            for record in records
            if record.get("family") == "ed2k_tcp"
            and record.get("event") == event
            and str(_keys(record).get("peer") or "").casefold() == endpoint.casefold()
            and _trace_id(record) == trace_id
            and _keys(record).get("protocolMarker") == PROTOCOL_MARKER
            and _keys(record).get("opcode") == opcode
            and _body(record).get("protocolMarker") == PROTOCOL_MARKER
            and _body(record).get("opcode") == opcode
        ]
    status_record = applied["status"][0] if len(applied["status"]) == 1 else None
    ident_record = applied["ident"][0] if len(applied["ident"]) == 1 else None
    status_body = _body(status_record) if status_record is not None else {}
    ident_body = _body(ident_record) if ident_record is not None else {}
    decoded_status = wire.get("status") if isinstance(wire.get("status"), dict) else {}
    decoded_ident = wire.get("ident") if isinstance(wire.get("ident"), dict) else {}
    status_sequence = _sequence(status_record)
    ident_sequence = _sequence(ident_record)
    wire_sequences = wire.get("sequences") if isinstance(wire.get("sequences"), dict) else {}
    common_ok = all(
        body.get("direction") == "meta"
        and body.get("outcome") == "applied"
        and body.get("transportMode") == "obfuscated"
        and body.get("flow") == "server"
        for body in (status_body, ident_body)
    )
    status_ok = bool(
        len(applied["status"]) == 1
        and status_sequence > int(wire_sequences.get("status") or 0)
        and status_body.get("users") == decoded_status.get("users")
        and status_body.get("files") == decoded_status.get("files")
    )
    ident_ok = bool(
        len(applied["ident"]) == 1
        and ident_sequence > int(wire_sequences.get("ident") or 0)
        and ident_body.get("name") == decoded_ident.get("name")
        and ident_body.get("description") == decoded_ident.get("description")
    )
    return {
        "ok": common_ok and status_ok and ident_ok,
        "status": {
            "ok": status_ok,
            "count": len(applied["status"]),
            "sequence": status_sequence or None,
            "users": status_body.get("users"),
            "files": status_body.get("files"),
        },
        "ident": {
            "ok": ident_ok,
            "count": len(applied["ident"]),
            "sequence": ident_sequence or None,
            "name": ident_body.get("name"),
            "description": ident_body.get("description"),
        },
    }


def _rest_evidence(
    snapshot: object,
    *,
    endpoint: str,
    seed_name: str,
    wire: dict[str, Any],
) -> dict[str, Any]:
    value = snapshot if isinstance(snapshot, dict) else {}
    status = value.get("connectionStatus") if isinstance(value.get("connectionStatus"), dict) else {}
    current = status.get("currentServer") if isinstance(status.get("currentServer"), dict) else {}
    server = value.get("serverEntity") if isinstance(value.get("serverEntity"), dict) else {}
    host, port_text = endpoint.rsplit(":", 1)
    decoded_status = wire.get("status") if isinstance(wire.get("status"), dict) else {}
    decoded_ident = wire.get("ident") if isinstance(wire.get("ident"), dict) else {}
    comparable = {
        "address": server.get("address"),
        "port": server.get("port"),
        "name": server.get("name"),
        "description": server.get("description"),
        "users": server.get("users"),
        "files": server.get("files"),
    }
    ok = bool(
        status.get("connected") is True
        and current.get("current") is True
        and str(current.get("address") or "").casefold() == host.casefold()
        and current.get("port") == int(port_text)
        and str(server.get("address") or "").casefold() == host.casefold()
        and server.get("port") == int(port_text)
        and server.get("name") == decoded_ident.get("name")
        and server.get("description") == decoded_ident.get("description")
        and server.get("name") != seed_name
        and _nonnegative_int(server.get("users")) == decoded_status.get("users")
        and _nonnegative_int(server.get("files")) == decoded_status.get("files")
    )
    return {
        "ok": ok,
        "seedNameChanged": server.get("name") != seed_name,
        "connection": {
            "connected": status.get("connected"),
            "address": current.get("address"),
            "port": current.get("port"),
        },
        "server": comparable,
    }


def build_server_tcp_metadata_diagnostic_evidence(
    *,
    server_endpoint: str,
    seed_name: str,
    expected_name: str,
    expected_description: str,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
    rest_snapshots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Proves exact TCP status and ident application on Rust and MFC."""

    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("TCP server metadata endpoint must be host:port.")
    if not seed_name or seed_name == expected_name:
        raise ValueError("TCP server metadata proof requires a distinct non-empty seed name.")
    if not expected_name or not expected_description:
        raise ValueError("TCP server metadata proof requires expected name and description.")
    if not isinstance(rest_snapshots, dict) or set(rest_snapshots) != set(CLIENTS):
        raise ValueError("TCP server metadata REST snapshots must contain exactly rust and mfc.")

    records_by_client = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for client in CLIENTS:
        wire = _wire_evidence(
            records_by_client[client],
            client=client,
            endpoint=server_endpoint,
        )
        applied = _applied_evidence(
            records_by_client[client],
            endpoint=server_endpoint,
            wire=wire,
        )
        rest = _rest_evidence(
            rest_snapshots[client],
            endpoint=server_endpoint,
            seed_name=seed_name,
            wire=wire,
        )
        client_ok = bool(wire["ok"] is True and applied["ok"] is True and rest["ok"] is True)
        clients[client] = {"ok": client_ok, "wire": wire, "applied": applied, "rest": rest}
        if not client_ok:
            failures.append(client)

    rust_ident = clients["rust"]["wire"].get("ident")
    mfc_ident = clients["mfc"]["wire"].get("ident")
    comparison = {
        "identEqual": rust_ident == mfc_ident,
        "identMatchesExpected": bool(
            isinstance(rust_ident, dict)
            and rust_ident.get("name") == expected_name
            and rust_ident.get("description") == expected_description
        ),
        "transportModeEqual": all(
            set(clients[client]["wire"].get("transportModes", [])) == {"obfuscated"}
            for client in CLIENTS
        ),
    }
    comparison_ok = all(value is True for value in comparison.values())
    if not comparison_ok:
        failures.append("comparison")
    observed_ids = list(ELIGIBLE_COVERAGE_IDS) if not failures else []
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "serverEndpoint": server_endpoint.casefold(),
        "seedName": seed_name,
        "expectedIdent": {"name": expected_name, "description": expected_description},
        "failures": failures,
        "clients": clients,
        "comparison": {"ok": comparison_ok, **comparison},
        "observedCoverageIds": observed_ids,
        "coverageClaims": {
            "eligibleCoverageIds": observed_ids,
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_tcp_metadata_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless both clients causally applied exact TCP metadata replies."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic TCP server metadata diagnostics have an unexpected schema.")
    if report.get("ok") is not True:
        raise RuntimeError(
            f"Deterministic TCP server metadata diagnostics are incomplete: {report.get('failures')!r}"
        )
