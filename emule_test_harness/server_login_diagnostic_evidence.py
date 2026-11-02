"""Bilateral causal diagnostics gate for one deterministic server login."""

from __future__ import annotations

from typing import Any, Iterable

from emule_test_harness import ed2k_wire

SCHEMA = "emulebb-build-tests.deterministic-server-login-diagnostics"
EVIDENCE_LAYERS = ("codec-transcript", "deterministic-state-machine", "local-cross-client")
CONNECTION_COVERAGE_ID_BY_TRANSPORT_PLAN = {
    ("plaintext",): "server.connect.plaintext",
    ("obfuscated",): "server.connect.obfuscated",
    ("obfuscated", "plaintext"): "server.connect.fallback",
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


def _trace_id(record: dict[str, Any] | None) -> int | None:
    if record is None:
        return None
    values = {
        value
        for value in (_keys(record).get("traceId"), _body(record).get("traceId"))
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    }
    return next(iter(values)) if len(values) == 1 else None


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


def _linked_send_outcome(
    *,
    client: str,
    records: list[dict[str, Any]],
    login: dict[str, Any] | None,
    endpoint: str,
) -> dict[str, Any] | None:
    if login is None:
        return None
    if client != "rust" or _body(login).get("outcome") != "attempted":
        return None
    attempt_id = _keys(login).get("sendAttemptId")
    if not isinstance(attempt_id, int) or isinstance(attempt_id, bool):
        return None
    outcomes = [
        record
        for record in records
        if (
            _is_server_record(record, endpoint)
            and record.get("event") == "send_outcome"
            and _keys(record).get("sendAttemptId") == attempt_id
            and _body(record).get("opcode") == LOGIN_OPCODE
        )
    ]
    if len(outcomes) != 1:
        return None
    outcome = outcomes[0]
    return (
        outcome
        if _body(outcome).get("outcome") == "send_succeeded"
        and _body(outcome).get("deliveryKnown") is True
        and _trace_id(outcome) == _trace_id(login)
        and _body(outcome).get("transportMode") == _body(login).get("transportMode")
        and _sequence(outcome) > _sequence(login)
        else None
    )


def _client_evidence(
    *,
    client: str,
    records: list[dict[str, Any]],
    endpoint: str,
    expected_nickname: str,
    expected_tcp_port: int,
    expected_transport_plan: tuple[str, ...],
) -> dict[str, Any]:
    final_transport_mode = expected_transport_plan[-1]
    attempt_starts = [
        record
        for record in records
        if _is_server_record(record, endpoint)
        and record.get("event") == "connection_state"
        and _body(record).get("outcome") == "attempt_started"
    ]
    attempt_modes = tuple(_body(record).get("transportMode") for record in attempt_starts)
    attempt_phases = tuple(_body(record).get("phase") for record in attempt_starts)
    attempt_states = tuple(_body(record).get("state") for record in attempt_starts)
    attempt_sequences = tuple(_sequence(record) for record in attempt_starts)
    attempt_trace_ids = tuple(_trace_id(record) for record in attempt_starts)
    attempt_plan_exact = bool(
        attempt_modes == expected_transport_plan
        and attempt_phases == ("connection",) * len(expected_transport_plan)
        and attempt_states == ("connecting",) * len(expected_transport_plan)
        and len(attempt_sequences) == len(expected_transport_plan)
        and all(sequence > 0 for sequence in attempt_sequences)
        and list(attempt_sequences) == sorted(set(attempt_sequences))
        and all(trace_id is not None for trace_id in attempt_trace_ids)
        and len(set(attempt_trace_ids)) == len(attempt_trace_ids)
    )
    final_attempt = attempt_starts[-1] if attempt_starts else None
    final_attempt_sequence = _sequence(final_attempt)
    final_attempt_trace_id = _trace_id(final_attempt)
    login_packets = [
        record
        for record in records
        if _packet(record, endpoint=endpoint, direction="send", opcode=LOGIN_OPCODE)
    ]
    final_login_packets = [
        record
        for record in login_packets
        if final_attempt_trace_id is not None
        and _trace_id(record) == final_attempt_trace_id
        and _body(record).get("transportMode") == final_transport_mode
    ]
    login = final_login_packets[0] if len(final_login_packets) == 1 else None
    failed_attempt_login_packets = [record for record in login_packets if record is not login]
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
    send_outcome = _linked_send_outcome(
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
    ]
    accepted = accepted_records[0] if len(accepted_records) == 1 else None
    accepted_shape = bool(
        accepted is not None
        and _body(accepted).get("phase") == "connection"
        and _body(accepted).get("state") == "connected"
    )
    login_sequence = _sequence(login)
    id_change_sequence = _sequence(id_change)
    accepted_sequence = _sequence(accepted)
    send_attempt_recorded = bool(
        login is not None and _body(login).get("outcome") == "attempted"
    )
    send_outcome_required = client == "rust"
    send_outcome_observed = send_outcome is not None
    lifecycle_ok = bool(
        final_attempt is not None
        and login is not None
        and id_change is not None
        and decoded_id_change is not None
        and accepted is not None
        and final_attempt_sequence > 0
        and login_sequence > 0
        and id_change_sequence > 0
        and accepted_sequence > 0
        and final_attempt_sequence < login_sequence < id_change_sequence < accepted_sequence
    )
    final_trace_ids = tuple(_trace_id(record) for record in (final_attempt, login, id_change, accepted))
    final_trace_id = (
        final_trace_ids[0]
        if all(value is not None for value in final_trace_ids)
        and len(set(final_trace_ids)) == 1
        else None
    )
    trace_correlation = final_trace_id is not None
    delivery_proven = bool(
        lifecycle_ok
        and trace_correlation
        and (
            not send_outcome_required
            or send_outcome_observed
            and _sequence(send_outcome) < id_change_sequence
        )
    )

    connection_failures = [
        record
        for record in records
        if _is_server_record(record, endpoint)
        and record.get("event") == "connection_state"
        and _body(record).get("outcome") == "connection_failed"
    ]
    connection_failure = connection_failures[0] if len(connection_failures) == 1 else None
    fallback_records = [
        record
        for record in records
        if _is_server_record(record, endpoint) and record.get("event") == "transport_fallback"
    ]
    fallback = fallback_records[0] if len(fallback_records) == 1 else None
    connection_failure_sequence = _sequence(connection_failure)
    fallback_sequence = _sequence(fallback)
    failure_trace_id = _trace_id(connection_failure)
    fallback_trace_id = _trace_id(fallback)
    fallback_body = _body(fallback) if fallback is not None else {}
    fallback_error = fallback_body.get("error")
    fallback_shape = bool(
        fallback is not None
        and fallback_body.get("phase") == "connection"
        and fallback_body.get("outcome") == "retrying"
        and fallback_body.get("fromTransportMode") == "obfuscated"
        and fallback_body.get("toTransportMode") == "plaintext"
        and isinstance(fallback_error, str)
        and fallback_error
    )
    observed_transport_plan = attempt_modes
    fallback_required = len(expected_transport_plan) == 2
    failed_attempt = attempt_starts[0] if fallback_required and attempt_starts else None
    failed_attempt_sequence = _sequence(failed_attempt)
    failed_attempt_trace_id = _trace_id(failed_attempt)
    failed_attempt_login = (
        failed_attempt_login_packets[0] if len(failed_attempt_login_packets) == 1 else None
    )
    failed_attempt_login_sequence = _sequence(failed_attempt_login)
    failed_attempt_login_trace_id = _trace_id(failed_attempt_login)
    failed_attempt_login_body = _body(failed_attempt_login) if failed_attempt_login is not None else {}
    expected_failed_attempt_login_count = 1 if fallback_required and client == "mfc" else 0
    failed_attempt_logins_exact = bool(
        len(failed_attempt_login_packets) == expected_failed_attempt_login_count
        and (
            failed_attempt_login is None
            or failed_attempt_login_trace_id == failed_attempt_trace_id
            and failed_attempt_login_body.get("transportMode") == "obfuscated"
            and failed_attempt_login_body.get("outcome") == "attempted"
            and failed_attempt_sequence
            < failed_attempt_login_sequence
            < connection_failure_sequence
        )
    )
    if fallback_required:
        fallback_causal = bool(
            attempt_plan_exact
            and len(connection_failures) == 1
            and len(fallback_records) == 1
            and failed_attempt is not None
            and connection_failure is not None
            and fallback is not None
            and _body(connection_failure).get("phase") == "connection"
            and _body(connection_failure).get("transportMode") == "obfuscated"
            and fallback_shape
            and login is not None
            and failed_attempt_sequence > 0
            and connection_failure_sequence > 0
            and fallback_sequence > 0
            and final_attempt_sequence > 0
            and login_sequence > 0
            and failed_attempt_sequence
            < connection_failure_sequence
            < fallback_sequence
            < final_attempt_sequence
            < login_sequence
            and failed_attempt_logins_exact
            and failed_attempt_trace_id is not None
            and failure_trace_id is not None
            and final_trace_id is not None
            and failure_trace_id == failed_attempt_trace_id
            and failure_trace_id != final_trace_id
            and fallback_trace_id == failure_trace_id
        )
        trace_correlation = trace_correlation and fallback_causal
    else:
        fallback_causal = bool(
            attempt_plan_exact
            and not connection_failures
            and not fallback_records
            and not failed_attempt_login_packets
        )

    transport_observation = {
        "attempts": list(observed_transport_plan),
        "login": _body(login).get("transportMode") if login is not None else None,
        "idChange": _body(id_change).get("transportMode") if id_change is not None else None,
        "accepted": _body(accepted).get("transportMode") if accepted is not None else None,
    }
    transport_plan_exact = bool(
        attempt_plan_exact
        and transport_observation["login"] == final_transport_mode
        and transport_observation["idChange"] == final_transport_mode
        and transport_observation["accepted"] == final_transport_mode
        and fallback_causal
    )
    ok = bool(
        len(final_login_packets) == 1
        and failed_attempt_logins_exact
        and semantic_shape
        and send_attempt_recorded
        and delivery_proven
        and len(id_change_packets) == 1
        and len(accepted_records) == 1
        and accepted_shape
        and lifecycle_ok
        and trace_correlation
        and transport_plan_exact
    )
    return {
        "ok": ok,
        "attemptStartCount": len(attempt_starts),
        "attemptPhases": list(attempt_phases),
        "attemptStates": list(attempt_states),
        "attemptStartSequences": list(attempt_sequences),
        "attemptTraceIds": list(attempt_trace_ids),
        "attemptPlanExact": attempt_plan_exact,
        "loginPacketCount": len(login_packets),
        "finalLoginPacketCount": len(final_login_packets),
        "failedAttemptLoginPacketCount": len(failed_attempt_login_packets),
        "loginPacketOutcome": _body(login).get("outcome") if login is not None else None,
        "sendAttemptRecorded": send_attempt_recorded,
        "sendOutcomeRequired": send_outcome_required,
        "sendOutcomeObserved": send_outcome_observed,
        "deliveryProven": delivery_proven,
        "sendOutcomeSequence": _sequence(send_outcome) or None,
        "sendOutcomeTraceId": _trace_id(send_outcome),
        "sendOutcomeTransportMode": (
            _body(send_outcome).get("transportMode") if send_outcome is not None else None
        ),
        "failedAttemptStartSequence": failed_attempt_sequence or None,
        "failedAttemptLoginSequence": failed_attempt_login_sequence or None,
        "finalAttemptStartSequence": final_attempt_sequence or None,
        "loginSequence": login_sequence or None,
        "idChangeSequence": id_change_sequence or None,
        "loginAcceptedSequence": accepted_sequence or None,
        "loginAcceptedCount": len(accepted_records),
        "connectionFailureSequence": connection_failure_sequence or None,
        "transportFallbackSequence": fallback_sequence or None,
        "connectionFailureCount": len(connection_failures),
        "transportFallbackCount": len(fallback_records),
        "failedTraceId": failure_trace_id,
        "fallbackTraceId": fallback_trace_id,
        "failedAttemptTraceId": failed_attempt_trace_id,
        "failedAttemptLoginTraceId": failed_attempt_login_trace_id,
        "finalTraceId": final_trace_id,
        "finalAttemptTraceId": final_trace_ids[0],
        "loginTraceId": final_trace_ids[1],
        "idChangeTraceId": final_trace_ids[2],
        "loginAcceptedTraceId": final_trace_ids[3],
        "loginAcceptedPhase": _body(accepted).get("phase") if accepted is not None else None,
        "loginAcceptedState": _body(accepted).get("state") if accepted is not None else None,
        "fallbackError": fallback_error if isinstance(fallback_error, str) else None,
        "connectionFailureTransportMode": (
            _body(connection_failure).get("transportMode")
            if connection_failure is not None
            else None
        ),
        "connectionFailurePhase": (
            _body(connection_failure).get("phase") if connection_failure is not None else None
        ),
        "connectionFailureOutcome": (
            _body(connection_failure).get("outcome") if connection_failure is not None else None
        ),
        "failedAttemptLoginTransportMode": failed_attempt_login_body.get("transportMode"),
        "failedAttemptLoginOutcome": failed_attempt_login_body.get("outcome"),
        "transportFallbackPhase": fallback_body.get("phase"),
        "transportFallbackOutcome": fallback_body.get("outcome"),
        "transportFallbackFromMode": fallback_body.get("fromTransportMode"),
        "transportFallbackToMode": fallback_body.get("toTransportMode"),
        "loginDecodeError": login_decode_error,
        "decodedLogin": decoded_login,
        "decodedIdChange": decoded_id_change,
        "stockTags": stock_tags,
        "extensionTags": extension_tags,
        "semanticShape": semantic_shape,
        "transportObservation": transport_observation,
        "transportPlanExact": transport_plan_exact,
        "traceCorrelation": trace_correlation,
        "fallbackCausal": fallback_causal,
    }


def build_server_login_diagnostic_evidence(
    *,
    server_endpoint: str,
    rust_nickname: str,
    rust_tcp_port: int,
    mfc_nickname: str,
    mfc_tcp_port: int,
    expected_transport_plan: tuple[str, ...],
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Proves and compares one accepted stock-core login from Rust and MFC."""

    if not server_endpoint or ":" not in server_endpoint:
        raise ValueError("Server login endpoint must be host:port.")
    if expected_transport_plan not in CONNECTION_COVERAGE_ID_BY_TRANSPORT_PLAN:
        raise ValueError("Expected server transport plan is not a supported deterministic plan.")
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
            expected_transport_plan=expected_transport_plan,
        ),
        "mfc": _client_evidence(
            client="mfc",
            records=list(mfc_records),
            endpoint=server_endpoint,
            expected_nickname=mfc_nickname,
            expected_tcp_port=mfc_tcp_port,
            expected_transport_plan=expected_transport_plan,
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
        "transportPlanExact": all(
            row["transportPlanExact"] is True for row in clients.values()
        ),
        "traceCorrelationExact": all(
            row["traceCorrelation"] is True for row in clients.values()
        ),
        "fallbackSequenceExact": all(
            row["fallbackCausal"] is True for row in clients.values()
        ),
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
        "expectedTransportPlan": list(expected_transport_plan),
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
                    CONNECTION_COVERAGE_ID_BY_TRANSPORT_PLAN[expected_transport_plan],
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
    expected_plan = report.get("expectedTransportPlan")
    if (
        "expectedTransportMode" in report
        or not isinstance(expected_plan, list)
        or not all(isinstance(mode, str) for mode in expected_plan)
        or tuple(expected_plan) not in CONNECTION_COVERAGE_ID_BY_TRANSPORT_PLAN
    ):
        raise RuntimeError("Deterministic server-login diagnostics have an invalid transport plan.")
    if report.get("ok") is not True:
        raise RuntimeError(
            f"Deterministic server-login diagnostics are incomplete: {report.get('failures')!r}"
        )
