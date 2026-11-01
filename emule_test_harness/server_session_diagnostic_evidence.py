"""Causal diagnostics gate for one deterministic eD2K server session."""

from __future__ import annotations

from typing import Any, Iterable

from emule_test_harness import ed2k_wire

SCHEMA = "emulebb-build-tests.deterministic-server-session-diagnostics.v1"
EVIDENCE_LAYERS = ("codec-transcript", "deterministic-state-machine", "local-cross-client")
SERVER_PROTOCOL_MARKER = ed2k_wire.PROTO_EDONKEY
LOGIN_OPCODE = ed2k_wire.OP_LOGINREQUEST
ID_CHANGE_OPCODE = ed2k_wire.OP_IDCHANGE
STATUS_OPCODE = ed2k_wire.OP_SERVERSTATUS
SUPPORTED_TRANSPORT_MODES = frozenset({"plaintext", "obfuscated"})
REQUIRED_SERVER_FLAGS = (
    ed2k_wire.SRVCAP_ZLIB
    | ed2k_wire.SRVCAP_NEWTAGS
    | ed2k_wire.SRVCAP_UNICODE
    | ed2k_wire.SRVCAP_LARGEFILES
    | ed2k_wire.SRVCAP_SUPPORTCRYPT
)
CT_VERSION = 0x11


def _body(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("body")
    return value if isinstance(value, dict) else {}


def _keys(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("keys")
    return value if isinstance(value, dict) else {}


def _sequence(record: dict[str, Any] | None) -> int:
    if record is None:
        return 0
    value = record.get("streamSeq", record.get("seq", 0))
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _peer(record: dict[str, Any]) -> str:
    return str(_keys(record).get("peer") or "").casefold()


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


def _is_server_record(record: dict[str, Any], endpoint: str) -> bool:
    return bool(
        record.get("family") == "ed2k_tcp"
        and _peer(record) == endpoint.casefold()
        and _body(record).get("flow") == "server"
    )


def _packet(
    record: dict[str, Any],
    *,
    endpoint: str,
    direction: str,
    opcode: int,
) -> bool:
    body = _body(record)
    return bool(
        _is_server_record(record, endpoint)
        and record.get("event") == "packet"
        and body.get("direction") == direction
        and body.get("protocolMarker") == SERVER_PROTOCOL_MARKER
        and body.get("opcode") == opcode
    )


def _send_succeeded(
    records: list[dict[str, Any]],
    request: dict[str, Any] | None,
    endpoint: str,
) -> bool:
    if request is None:
        return False
    attempt_id = _keys(request).get("sendAttemptId")
    if not isinstance(attempt_id, int) or isinstance(attempt_id, bool):
        return False
    return any(
        _is_server_record(record, endpoint)
        and record.get("event") == "send_outcome"
        and _keys(record).get("sendAttemptId") == attempt_id
        and _body(record).get("opcode") == LOGIN_OPCODE
        and _body(record).get("outcome") == "send_succeeded"
        and _body(record).get("deliveryKnown") is True
        and _sequence(record) >= _sequence(request)
        for record in records
    )


def _tag_values(decoded: dict[str, object]) -> tuple[dict[int | str, object], bool]:
    tags = decoded.get("tags")
    if not isinstance(tags, list):
        return {}, False
    values: dict[int | str, object] = {}
    for row in tags:
        if not isinstance(row, dict):
            return {}, False
        name = row.get("name")
        if not isinstance(name, (int, str)) or isinstance(name, bool) or name in values:
            return {}, False
        values[name] = row.get("value")
    return values, len(values) == decoded.get("tag_count")


def _transport_matches(record: dict[str, Any], expected_mode: str) -> bool:
    body = _body(record)
    expected_obfuscated = expected_mode == "obfuscated"
    if (
        body.get("transportMode") != expected_mode
        or body.get("obfuscated") is not expected_obfuscated
    ):
        return False
    if record.get("event") != "packet":
        return True
    raw_hex = body.get("rawHex")
    clear_hex = body.get("clearFrameHex")
    if not isinstance(raw_hex, str) or not isinstance(clear_hex, str):
        return False
    if body.get("rawLen") != body.get("clearFrameLen"):
        return False
    return raw_hex != clear_hex if expected_obfuscated else raw_hex == clear_hex


def build_server_session_diagnostic_evidence(
    *,
    server_endpoint: str,
    expected_nickname: str,
    expected_tcp_port: int,
    expected_transport_mode: str,
    expected_users: int,
    expected_files: int,
    rust_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Proves one exact login, accepted transport, and status reply."""

    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("Server endpoint must be host:port.")
    if not expected_nickname:
        raise ValueError("Expected server-session nickname must not be empty.")
    if not isinstance(expected_tcp_port, int) or isinstance(expected_tcp_port, bool):
        raise ValueError("Expected server-session TCP port must be an integer.")
    if not 1 <= expected_tcp_port <= 65535:
        raise ValueError("Expected server-session TCP port must be in 1..65535.")
    if expected_transport_mode not in SUPPORTED_TRANSPORT_MODES:
        raise ValueError("Expected server-session transport must be plaintext or obfuscated.")
    for value, name in ((expected_users, "users"), (expected_files, "files")):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"Expected server-session {name} must be a non-negative integer.")

    records = list(rust_records)
    login_packets = [
        record
        for record in records
        if _packet(
            record,
            endpoint=server_endpoint,
            direction="send",
            opcode=LOGIN_OPCODE,
        )
    ]
    login = login_packets[0] if len(login_packets) == 1 else None
    decoded_login: dict[str, object] | None = None
    login_decode_error: str | None = None
    if login is not None:
        payload = _payload(login)
        if payload is None:
            login_decode_error = "missing-complete-payload"
        else:
            try:
                decoded_login = ed2k_wire.decode_login_request(payload)
            except ed2k_wire.Ed2kWireError as exc:
                login_decode_error = str(exc)
    tags, unique_tags = _tag_values(decoded_login or {})
    user_hash = str((decoded_login or {}).get("user_hash") or "")
    user_hash_bytes = bytes.fromhex(user_hash) if len(user_hash) == 32 else b""
    stock_identity = bool(
        len(user_hash_bytes) == 16
        and user_hash_bytes[5] == 0x0E
        and user_hash_bytes[14] == 0x6F
    )
    flags = tags.get(ed2k_wire.CT_SERVER_FLAGS)
    stock_tags = bool(
        unique_tags
        and tags.get(ed2k_wire.CT_NAME) == expected_nickname
        and isinstance(tags.get(CT_VERSION), int)
        and not isinstance(tags.get(CT_VERSION), bool)
        and tags.get(CT_VERSION, 0) > 0
        and isinstance(flags, int)
        and not isinstance(flags, bool)
        and flags & REQUIRED_SERVER_FLAGS == REQUIRED_SERVER_FLAGS
    )
    login_ok = bool(
        login is not None
        and decoded_login is not None
        and decoded_login.get("client_id") == 0
        and decoded_login.get("tcp_port") == expected_tcp_port
        and stock_identity
        and stock_tags
        and _transport_matches(login, expected_transport_mode)
        and _send_succeeded(records, login, server_endpoint)
    )

    trace_id = _body(login).get("traceId") if login is not None else None
    connection_records = [
        record
        for record in records
        if _is_server_record(record, server_endpoint)
        and record.get("event") == "connection_state"
        and _body(record).get("traceId") == trace_id
    ]

    def one_state(outcome: str, state: str) -> dict[str, Any] | None:
        matches = [
            record
            for record in connection_records
            if _body(record).get("outcome") == outcome
            and _body(record).get("state") == state
        ]
        return matches[0] if len(matches) == 1 else None

    attempt = one_state("attempt_started", "connecting")
    connected = one_state("transport_connected", "awaiting_idchange")
    accepted = one_state("login_accepted", "connected")

    id_change_packets = [
        record
        for record in records
        if _packet(
            record,
            endpoint=server_endpoint,
            direction="recv",
            opcode=ID_CHANGE_OPCODE,
        )
        and _body(record).get("outcome") == "accepted"
    ]
    id_change = id_change_packets[0] if len(id_change_packets) == 1 else None
    decoded_id_change: dict[str, object] | None = None
    if id_change is not None:
        payload = _payload(id_change)
        if payload is not None:
            try:
                decoded_id_change = ed2k_wire.decode_id_change(payload)
            except ed2k_wire.Ed2kWireError:
                pass

    connection_ok = bool(
        login_ok
        and isinstance(trace_id, int)
        and not isinstance(trace_id, bool)
        and len(connection_records) == 3
        and attempt is not None
        and connected is not None
        and accepted is not None
        and id_change is not None
        and decoded_id_change is not None
        and _transport_matches(attempt, expected_transport_mode)
        and _transport_matches(connected, expected_transport_mode)
        and _transport_matches(id_change, expected_transport_mode)
        and _transport_matches(accepted, expected_transport_mode)
        and _sequence(attempt) < _sequence(login)
        and _sequence(login) < _sequence(connected)
        and _sequence(connected) < _sequence(id_change)
        and _sequence(id_change) < _sequence(accepted)
    )

    status_packets = [
        record
        for record in records
        if _packet(
            record,
            endpoint=server_endpoint,
            direction="recv",
            opcode=STATUS_OPCODE,
        )
        and _body(record).get("outcome") == "accepted"
    ]
    status = status_packets[0] if len(status_packets) == 1 else None
    decoded_status: dict[str, int] | None = None
    status_decode_error: str | None = None
    if status is not None:
        payload = _payload(status)
        if payload is None:
            status_decode_error = "missing-complete-payload"
        else:
            try:
                decoded_status = ed2k_wire.decode_server_status(payload)
            except ed2k_wire.Ed2kWireError as exc:
                status_decode_error = str(exc)
    status_ok = bool(
        connection_ok
        and status is not None
        and decoded_status == {"users": expected_users, "files": expected_files}
        and _transport_matches(status, expected_transport_mode)
        and _sequence(status) > _sequence(accepted)
    )

    checks = {
        "connection": {
            "ok": connection_ok,
            "transportMode": expected_transport_mode,
            "traceId": trace_id,
            "connectionRecordCount": len(connection_records),
            "attemptSequence": _sequence(attempt) or None,
            "transportConnectedSequence": _sequence(connected) or None,
            "loginAcceptedSequence": _sequence(accepted) or None,
        },
        "login": {
            "ok": login_ok,
            "packetCount": len(login_packets),
            "sendSucceeded": _send_succeeded(records, login, server_endpoint),
            "sequence": _sequence(login) or None,
            "decodeError": login_decode_error,
            "decoded": decoded_login,
            "stockIdentityMarkers": stock_identity,
            "stockTags": stock_tags,
        },
        "idChange": {
            "ok": id_change is not None and decoded_id_change is not None,
            "packetCount": len(id_change_packets),
            "sequence": _sequence(id_change) or None,
            "decoded": decoded_id_change,
        },
        "status": {
            "ok": status_ok,
            "packetCount": len(status_packets),
            "sequence": _sequence(status) or None,
            "decodeError": status_decode_error,
            "decoded": decoded_status,
        },
    }
    failures = [name for name, check in checks.items() if check["ok"] is not True]
    coverage_ids: list[str] = []
    if not failures:
        coverage_ids = [
            f"server.connect.{expected_transport_mode}",
            "server.login.request",
            "server.reply.status",
        ]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "serverEndpoint": server_endpoint.casefold(),
        "expected": {
            "nickname": expected_nickname,
            "tcpPort": expected_tcp_port,
            "transportMode": expected_transport_mode,
            "users": expected_users,
            "files": expected_files,
        },
        "failures": failures,
        "checks": checks,
        "coverageClaims": {
            "eligibleCoverageIds": coverage_ids,
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_session_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises when an exact deterministic server session is not proven."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic server-session diagnostics have an unexpected schema.")
    if report.get("ok") is not True:
        raise RuntimeError(
            f"Deterministic server-session diagnostics are incomplete: {report.get('failures')!r}"
        )
