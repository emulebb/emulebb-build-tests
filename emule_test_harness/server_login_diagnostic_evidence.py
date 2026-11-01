"""Bilateral causal diagnostics gate for one deterministic server login."""

from __future__ import annotations

from typing import Any, Iterable

from emule_test_harness import ed2k_wire

SCHEMA = "emulebb-build-tests.deterministic-server-login-diagnostics"
EVIDENCE_LAYERS = ("codec-transcript", "deterministic-state-machine", "local-cross-client")
CONNECTION_COVERAGE_ID_BY_TRANSPORT = {
    "obfuscated": "server.connect.obfuscated",
    "plaintext": "server.connect.plaintext",
}
SERVER_PROTOCOL_MARKER = ed2k_wire.PROTO_EDONKEY
LOGIN_OPCODE = ed2k_wire.OP_LOGINREQUEST
ID_CHANGE_OPCODE = ed2k_wire.OP_IDCHANGE
CT_VERSION = 0x11
CT_UDP_PORTS = 0xFB
STOCK_CORE_TAGS = frozenset({ed2k_wire.CT_NAME, CT_VERSION, ed2k_wire.CT_SERVER_FLAGS, CT_UDP_PORTS})
EXPECTED_EXTENSION_TAGS: dict[str, dict[int | str, object]] = {
    "rust": {"offerfiles_v": 1},
    "mfc": {},
}
REQUIRED_STOCK_SERVER_FLAGS = (
    ed2k_wire.SRVCAP_ZLIB
    | ed2k_wire.SRVCAP_NEWTAGS
    | ed2k_wire.SRVCAP_UNICODE
    | ed2k_wire.SRVCAP_LARGEFILES
)


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


def _user_hash_has_stock_markers(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 32:
        return False
    try:
        user_hash = bytes.fromhex(value)
    except ValueError:
        return False
    return user_hash[5] == 0x0E and user_hash[14] == 0x6F


def _send_succeeded(
    *,
    client: str,
    records: list[dict[str, Any]],
    login: dict[str, Any] | None,
    endpoint: str,
) -> bool:
    if login is None:
        return False
    if _body(login).get("outcome") == "send_succeeded":
        return True
    if client != "rust" or _body(login).get("outcome") != "attempted":
        return False
    attempt_id = _keys(login).get("sendAttemptId")
    if not isinstance(attempt_id, int) or isinstance(attempt_id, bool):
        return False
    return any(
        _is_server_record(record, endpoint)
        and record.get("event") == "send_outcome"
        and _keys(record).get("sendAttemptId") == attempt_id
        and _body(record).get("opcode") == LOGIN_OPCODE
        and _body(record).get("outcome") == "send_succeeded"
        and _body(record).get("deliveryKnown") is True
        and _sequence(record) >= _sequence(login)
        for record in records
    )


def _client_evidence(
    *,
    client: str,
    records: list[dict[str, Any]],
    endpoint: str,
    expected_nickname: str,
    expected_tcp_port: int,
    expected_transport_mode: str,
) -> dict[str, Any]:
    login_packets = [
        record
        for record in records
        if _packet(record, endpoint=endpoint, direction="send", opcode=LOGIN_OPCODE)
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
    stock_tags = {name: tags.get(name) for name in STOCK_CORE_TAGS if name in tags}
    extension_tags = {name: value for name, value in tags.items() if name not in STOCK_CORE_TAGS}
    flags = stock_tags.get(ed2k_wire.CT_SERVER_FLAGS)
    semantic_shape = bool(
        decoded_login is not None
        and unique_tags
        and decoded_login.get("client_id") == 0
        and decoded_login.get("tcp_port") == expected_tcp_port
        and stock_tags.get(ed2k_wire.CT_NAME) == expected_nickname
        and isinstance(stock_tags.get(CT_VERSION), int)
        and not isinstance(stock_tags.get(CT_VERSION), bool)
        and stock_tags.get(CT_VERSION, 0) > 0
        and isinstance(flags, int)
        and not isinstance(flags, bool)
        and flags & REQUIRED_STOCK_SERVER_FLAGS == REQUIRED_STOCK_SERVER_FLAGS
        and isinstance(stock_tags.get(CT_UDP_PORTS), int)
        and extension_tags == EXPECTED_EXTENSION_TAGS[client]
        and _user_hash_has_stock_markers(decoded_login.get("user_hash"))
    )
    send_succeeded = _send_succeeded(
        client=client,
        records=records,
        login=login,
        endpoint=endpoint,
    )

    id_change_packets = [
        record
        for record in records
        if _packet(record, endpoint=endpoint, direction="recv", opcode=ID_CHANGE_OPCODE)
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

    accepted_records = [
        record
        for record in records
        if _is_server_record(record, endpoint)
        and record.get("event") == "connection_state"
        and _body(record).get("outcome") == "login_accepted"
        and _body(record).get("state") == "connected"
    ]
    accepted = accepted_records[0] if len(accepted_records) == 1 else None
    lifecycle_ok = bool(
        login is not None
        and id_change is not None
        and decoded_id_change is not None
        and accepted is not None
        and _sequence(login) < _sequence(id_change) < _sequence(accepted)
    )
    transport_observation = {
        "login": _body(login).get("transportMode") if login is not None else None,
        "idChange": _body(id_change).get("transportMode") if id_change is not None else None,
        "accepted": _body(accepted).get("transportMode") if accepted is not None else None,
    }
    transport_exact = set(transport_observation.values()) == {expected_transport_mode}
    ok = bool(
        len(login_packets) == 1
        and semantic_shape
        and send_succeeded
        and len(id_change_packets) == 1
        and len(accepted_records) == 1
        and lifecycle_ok
        and transport_exact
    )
    return {
        "ok": ok,
        "packetCount": len(login_packets),
        "sendSucceeded": send_succeeded,
        "loginSequence": _sequence(login) or None,
        "idChangeSequence": _sequence(id_change) or None,
        "loginAcceptedSequence": _sequence(accepted) or None,
        "loginDecodeError": login_decode_error,
        "decodedLogin": decoded_login,
        "decodedIdChange": decoded_id_change,
        "stockTags": stock_tags,
        "extensionTags": extension_tags,
        "semanticShape": semantic_shape,
        "transportObservation": transport_observation,
        "transportExact": transport_exact,
    }


def build_server_login_diagnostic_evidence(
    *,
    server_endpoint: str,
    rust_nickname: str,
    rust_tcp_port: int,
    mfc_nickname: str,
    mfc_tcp_port: int,
    expected_transport_mode: str,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Proves and compares one accepted stock-core login from Rust and MFC."""

    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("Server login endpoint must be host:port.")
    if expected_transport_mode not in CONNECTION_COVERAGE_ID_BY_TRANSPORT:
        raise ValueError("Expected server transport mode must be plaintext or obfuscated.")
    for nickname, name in ((rust_nickname, "Rust"), (mfc_nickname, "MFC")):
        if not nickname:
            raise ValueError(f"Expected {name} server-login nickname must not be empty.")
    for port, name in ((rust_tcp_port, "Rust"), (mfc_tcp_port, "MFC")):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"Expected {name} server-login TCP port must be in 1..65535.")

    clients = {
        "rust": _client_evidence(
            client="rust",
            records=list(rust_records),
            endpoint=server_endpoint,
            expected_nickname=rust_nickname,
            expected_tcp_port=rust_tcp_port,
            expected_transport_mode=expected_transport_mode,
        ),
        "mfc": _client_evidence(
            client="mfc",
            records=list(mfc_records),
            endpoint=server_endpoint,
            expected_nickname=mfc_nickname,
            expected_tcp_port=mfc_tcp_port,
            expected_transport_mode=expected_transport_mode,
        ),
    }
    rust_tags = clients["rust"]["stockTags"]
    mfc_tags = clients["mfc"]["stockTags"]
    comparison = {
        "bothAccepted": all(row["ok"] is True for row in clients.values()),
        "versionEqual": rust_tags.get(CT_VERSION) == mfc_tags.get(CT_VERSION),
        "serverFlagsEqual": rust_tags.get(ed2k_wire.CT_SERVER_FLAGS)
        == mfc_tags.get(ed2k_wire.CT_SERVER_FLAGS),
        "udpPortsTagEqual": rust_tags.get(CT_UDP_PORTS) == mfc_tags.get(CT_UDP_PORTS),
        "idKindEqual": (
            (clients["rust"].get("decodedIdChange") or {}).get("id_kind")
            == (clients["mfc"].get("decodedIdChange") or {}).get("id_kind")
        ),
        "transportModeExact": all(row["transportExact"] is True for row in clients.values()),
    }
    comparison["ok"] = all(comparison.values())
    failures = [
        *[f"client.{client}" for client, row in clients.items() if row["ok"] is not True],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "serverEndpoint": server_endpoint.casefold(),
        "expectedTransportMode": expected_transport_mode,
        "expectedClients": {
            "rust": {"nickname": rust_nickname, "tcpPort": rust_tcp_port},
            "mfc": {"nickname": mfc_nickname, "tcpPort": mfc_tcp_port},
        },
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": sorted(
                [
                    "server.login.request",
                    CONNECTION_COVERAGE_ID_BY_TRANSPORT[expected_transport_mode],
                ]
            )
            if not failures
            else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_server_login_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless both selected clients produced comparable accepted logins."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic server-login diagnostics have an unexpected schema.")
    if report.get("ok") is not True:
        raise RuntimeError(
            f"Deterministic server-login diagnostics are incomplete: {report.get('failures')!r}"
        )
