"""Causal bilateral gate for deterministic eD2K UDP server metadata replies."""

from __future__ import annotations

from typing import Any, Iterable

from emule_test_harness import ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-server-udp-metadata-diagnostics.v1"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
ELIGIBLE_COVERAGE_IDS = (
    "server.reply.udp-description",
    "server.reply.udp-status",
)
CLIENTS = ("rust", "mfc")


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
    if record is None:
        return 0
    return _positive_int(record.get("seq")) or 0


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


def _payload(record: dict[str, Any] | None) -> bytes | None:
    body = _body(record)
    payload_hex = body.get("payloadHex")
    if body.get("payloadHexTruncated") is not False or not isinstance(payload_hex, str):
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    return payload if body.get("payloadLen") == len(payload) else None


def _packet_matches(
    record: dict[str, Any],
    *,
    udp_endpoint: str,
    direction: str,
    opcode: int,
    outcome: str,
    transport_mode: str,
    obfuscated: bool,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        record.get("family") == "ed2k_server_udp"
        and record.get("event") == "packet"
        and str(keys.get("peer") or "").casefold() == udp_endpoint.casefold()
        and keys.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and keys.get("opcode") == opcode
        and body.get("flow") == "server"
        and body.get("phase") == "udp"
        and body.get("direction") == direction
        and body.get("outcome") == outcome
        and body.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
        and body.get("opcode") == opcode
        and body.get("transportMode") == transport_mode
        and body.get("obfuscated") is obfuscated
        and (direction == "send" or _trace_id(record) is not None)
    )


def _one_packet(
    records: list[dict[str, Any]],
    *,
    udp_endpoint: str,
    direction: str,
    opcode: int,
    outcome: str,
    transport_mode: str,
    obfuscated: bool,
) -> tuple[dict[str, Any] | None, int]:
    matches = [
        record
        for record in records
        if _packet_matches(
            record,
            udp_endpoint=udp_endpoint,
            direction=direction,
            opcode=opcode,
            outcome=outcome,
            transport_mode=transport_mode,
            obfuscated=obfuscated,
        )
    ]
    return (matches[0] if len(matches) == 1 else None, len(matches))


def _description_transports(
    *,
    udp_endpoint: str,
    status_reply: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    transports: list[dict[str, Any]] = [
        {
            "udpEndpoint": udp_endpoint,
            "transportMode": "plaintext",
            "obfuscated": False,
        }
    ]
    obfuscation_port = (
        _positive_int(status_reply.get("obfuscation_port_udp"))
        if status_reply is not None
        else None
    )
    if obfuscation_port is not None and obfuscation_port <= 65535:
        host, _ = udp_endpoint.rsplit(":", 1)
        transports.append(
            {
                "udpEndpoint": f"{host}:{obfuscation_port}",
                "transportMode": "obfuscated",
                "obfuscated": True,
            }
        )
    return transports


def _one_packet_across_transports(
    records: list[dict[str, Any]],
    *,
    transports: list[dict[str, Any]],
    direction: str,
    opcode: int,
    outcome: str,
) -> tuple[dict[str, Any] | None, int, dict[str, Any] | None]:
    matches = [
        (record, transport)
        for record in records
        for transport in transports
        if _packet_matches(
            record,
            udp_endpoint=str(transport["udpEndpoint"]),
            direction=direction,
            opcode=opcode,
            outcome=outcome,
            transport_mode=str(transport["transportMode"]),
            obfuscated=bool(transport["obfuscated"]),
        )
    ]
    if len(matches) != 1:
        return None, len(matches), None
    record, transport = matches[0]
    return record, 1, transport


def _wire_evidence(records: list[dict[str, Any]], *, udp_endpoint: str) -> dict[str, Any]:
    packets: dict[str, dict[str, Any] | None] = {}
    counts: dict[str, int] = {}
    for name, direction, opcode, outcome in (
        ("statusRequest", "send", ed2k_wire.OP_GLOBSERVSTATREQ, "attempted"),
        ("statusReply", "recv", ed2k_wire.OP_GLOBSERVSTATRES, "accepted"),
    ):
        packets[name], counts[name] = _one_packet(
            records,
            udp_endpoint=udp_endpoint,
            direction=direction,
            opcode=opcode,
            outcome=outcome,
            transport_mode="plaintext",
            obfuscated=False,
        )
    decode_errors: list[str] = []
    status_request = status_reply = description_request = description_reply = None
    try:
        payload = _payload(packets["statusRequest"])
        if payload is None:
            raise ed2k_wire.Ed2kWireError("missing exact status request payload")
        status_request = ed2k_wire.decode_server_udp_status_request(payload)
        payload = _payload(packets["statusReply"])
        if payload is None:
            raise ed2k_wire.Ed2kWireError("missing exact status reply payload")
        status_reply = ed2k_wire.decode_server_udp_status_response(
            payload,
            expected_challenge=status_request["challenge"],
        )
    except ed2k_wire.Ed2kWireError as exc:
        decode_errors.append(f"status: {exc}")

    description_transports = _description_transports(
        udp_endpoint=udp_endpoint,
        status_reply=status_reply,
    )
    packets["descriptionRequest"], counts["descriptionRequest"], request_transport = (
        _one_packet_across_transports(
            records,
            transports=description_transports,
            direction="send",
            opcode=ed2k_wire.OP_SERVER_DESC_REQ,
            outcome="attempted",
        )
    )
    packets["descriptionReply"], counts["descriptionReply"], reply_transport = (
        _one_packet_across_transports(
            records,
            transports=description_transports,
            direction="recv",
            opcode=ed2k_wire.OP_SERVER_DESC_RES,
            outcome="accepted",
        )
    )
    description_transport = (
        request_transport
        if request_transport is not None and request_transport == reply_transport
        else None
    )
    if request_transport is not None and reply_transport is not None and description_transport is None:
        decode_errors.append("description: request and reply used different transports")
    try:
        payload = _payload(packets["descriptionRequest"])
        if payload is None:
            raise ed2k_wire.Ed2kWireError("missing exact description request payload")
        description_request = ed2k_wire.decode_server_udp_description_request(payload)
        payload = _payload(packets["descriptionReply"])
        if payload is None:
            raise ed2k_wire.Ed2kWireError("missing exact description reply payload")
        description_reply = ed2k_wire.decode_server_udp_description_response(
            payload,
            expected_challenge=description_request["challenge"],
        )
    except ed2k_wire.Ed2kWireError as exc:
        decode_errors.append(f"description: {exc}")
    sequences = {name: _sequence(packet) for name, packet in packets.items()}
    strict_sequence = (
        sequences["statusRequest"]
        < sequences["statusReply"]
        < sequences["descriptionRequest"]
        < sequences["descriptionReply"]
    )
    ok = bool(
        all(count == 1 for count in counts.values())
        and all(packet is not None for packet in packets.values())
        and status_request is not None
        and status_reply is not None
        and description_request is not None
        and description_reply is not None
        and description_transport is not None
        and strict_sequence
        and not decode_errors
    )
    return {
        "ok": ok,
        "packetCounts": counts,
        "sequences": sequences,
        "traceIds": {name: _trace_id(packet) for name, packet in packets.items()},
        "payloadHex": {
            name: payload.hex() if (payload := _payload(packet)) is not None else None
            for name, packet in packets.items()
        },
        "statusRequest": status_request,
        "statusReply": status_reply,
        "descriptionRequest": description_request,
        "descriptionReply": description_reply,
        "transports": {
            "status": {
                "udpEndpoint": udp_endpoint,
                "transportMode": "plaintext",
                "obfuscated": False,
            },
            "description": description_transport,
        },
        "decodeErrors": decode_errors,
    }


def _applied_record(
    records: list[dict[str, Any]],
    *,
    event: str,
    opcode: int,
    udp_endpoint: str,
    server_endpoint: str,
    trace_id: int | None,
    challenge: int | None,
    transport_mode: str,
    obfuscated: bool,
) -> tuple[dict[str, Any] | None, int]:
    matches = []
    for record in records:
        keys = _keys(record)
        body = _body(record)
        if (
            record.get("family") == "ed2k_server_udp"
            and record.get("event") == event
            and str(keys.get("peer") or "").casefold() == udp_endpoint.casefold()
            and _trace_id(record) == trace_id
            and keys.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
            and keys.get("opcode") == opcode
            and keys.get("challenge") == challenge
            and body.get("direction") == "meta"
            and body.get("outcome") == "applied"
            and body.get("flow") == "server"
            and body.get("phase") == "udp"
            and body.get("transportMode") == transport_mode
            and body.get("obfuscated") is obfuscated
            and str(body.get("serverEndpoint") or "").casefold()
            == server_endpoint.casefold()
            and body.get("protocolMarker") == ed2k_wire.PROTO_EDONKEY
            and body.get("opcode") == opcode
            and body.get("challenge") == challenge
        ):
            matches.append(record)
    return (matches[0] if len(matches) == 1 else None, len(matches))


def _applied_evidence(
    records: list[dict[str, Any]],
    *,
    udp_endpoint: str,
    server_endpoint: str,
    wire: dict[str, Any],
) -> dict[str, Any]:
    traces = wire.get("traceIds") if isinstance(wire.get("traceIds"), dict) else {}
    status = wire.get("statusReply") if isinstance(wire.get("statusReply"), dict) else {}
    description = (
        wire.get("descriptionReply")
        if isinstance(wire.get("descriptionReply"), dict)
        else {}
    )
    transports = wire.get("transports") if isinstance(wire.get("transports"), dict) else {}
    description_transport = (
        transports.get("description")
        if isinstance(transports.get("description"), dict)
        else {}
    )
    status_record, status_count = _applied_record(
        records,
        event="server_status_applied",
        opcode=ed2k_wire.OP_GLOBSERVSTATRES,
        udp_endpoint=udp_endpoint,
        server_endpoint=server_endpoint,
        trace_id=_positive_int(traces.get("statusReply")),
        challenge=_positive_int(status.get("challenge")),
        transport_mode="plaintext",
        obfuscated=False,
    )
    description_record, description_count = _applied_record(
        records,
        event="server_description_applied",
        opcode=ed2k_wire.OP_SERVER_DESC_RES,
        udp_endpoint=str(description_transport.get("udpEndpoint") or ""),
        server_endpoint=server_endpoint,
        trace_id=_positive_int(traces.get("descriptionReply")),
        challenge=_positive_int(description.get("challenge")),
        transport_mode=str(description_transport.get("transportMode") or ""),
        obfuscated=description_transport.get("obfuscated") is True,
    )
    status_body = _body(status_record)
    description_body = _body(description_record)
    status_fields = {
        "users": "users",
        "files": "files",
        "max_users": "maxUsers",
        "soft_files": "softFiles",
        "hard_files": "hardFiles",
        "udp_flags": "udpFlags",
        "low_id_users": "lowIdUsers",
        "obfuscation_port_udp": "obfuscationPortUdp",
        "obfuscation_port_tcp": "obfuscationPortTcp",
        "udp_key": "udpKey",
    }
    status_values = {body_name: status_body.get(body_name) for body_name in status_fields.values()}
    status_ok = bool(
        status_count == 1
        and _sequence(status_record) > int(wire.get("sequences", {}).get("statusReply") or 0)
        and all(status_body.get(body_name) == status.get(wire_name) for wire_name, body_name in status_fields.items())
    )
    description_values = {
        name: description_body.get(name)
        for name in ("responseFormat", "name", "description", "dynamicHost", "version")
    }
    description_ok = bool(
        description_count == 1
        and _sequence(description_record)
        > int(wire.get("sequences", {}).get("descriptionReply") or 0)
        and description_body.get("responseFormat") == description.get("response_format")
        and description_body.get("name") == description.get("name")
        and description_body.get("description") == description.get("description")
        and (description_body.get("dynamicHost") or None) == description.get("dynamic_host")
        and (description_body.get("version") or None) == description.get("version")
    )
    return {
        "ok": status_ok and description_ok,
        "status": {
            "ok": status_ok,
            "count": status_count,
            "sequence": _sequence(status_record) or None,
            **status_values,
        },
        "description": {
            "ok": description_ok,
            "count": description_count,
            "sequence": _sequence(description_record) or None,
            **description_values,
        },
    }


def _rest_evidence(
    snapshot: object,
    *,
    anchor_endpoint: str,
    server_endpoint: str,
    seed_name: str,
    seed_description: str,
    wire: dict[str, Any],
) -> dict[str, Any]:
    value = snapshot if isinstance(snapshot, dict) else {}
    connection = value.get("connectionStatus") if isinstance(value.get("connectionStatus"), dict) else {}
    current = connection.get("currentServer") if isinstance(connection.get("currentServer"), dict) else {}
    server = value.get("serverEntity") if isinstance(value.get("serverEntity"), dict) else {}
    anchor_host, anchor_port_text = anchor_endpoint.rsplit(":", 1)
    server_host, server_port_text = server_endpoint.rsplit(":", 1)
    status = wire.get("statusReply") if isinstance(wire.get("statusReply"), dict) else {}
    description = wire.get("descriptionReply") if isinstance(wire.get("descriptionReply"), dict) else {}
    comparable = {
        name: server.get(name)
        for name in (
            "address",
            "port",
            "name",
            "description",
            "users",
            "files",
            "softFiles",
            "hardFiles",
        )
    }
    ok = bool(
        connection.get("connected") is True
        and str(current.get("address") or "").casefold() == anchor_host.casefold()
        and current.get("port") == int(anchor_port_text)
        and str(server.get("address") or "").casefold() == server_host.casefold()
        and server.get("port") == int(server_port_text)
        and server.get("name") == description.get("name")
        and server.get("description") == description.get("description")
        and server.get("name") != seed_name
        and server.get("description") != seed_description
        and _nonnegative_int(server.get("users")) == status.get("users")
        and _nonnegative_int(server.get("files")) == status.get("files")
        and _nonnegative_int(server.get("softFiles")) == status.get("soft_files")
        and _nonnegative_int(server.get("hardFiles")) == status.get("hard_files")
    )
    return {
        "ok": ok,
        "seedChanged": server.get("name") != seed_name
        and server.get("description") != seed_description,
        "anchor": {
            "address": current.get("address"),
            "port": current.get("port"),
        },
        "server": comparable,
    }


def build_server_udp_metadata_diagnostic_evidence(
    *,
    anchor_server_endpoint: str,
    target_server_endpoint: str,
    target_udp_endpoint: str,
    seed_name: str,
    seed_description: str,
    expected_name: str,
    expected_description: str,
    expected_users: int,
    expected_files: int,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
    rest_snapshots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Proves both challenged UDP metadata transactions on Rust and MFC."""

    for name, endpoint in (
        ("anchor", anchor_server_endpoint),
        ("target", target_server_endpoint),
        ("target UDP", target_udp_endpoint),
    ):
        if not endpoint or ":" not in endpoint:
            raise ValueError(f"UDP metadata {name} endpoint must be host:port.")
    if not seed_name or not seed_description:
        raise ValueError("UDP metadata proof requires explicit stale seed metadata.")
    if seed_name == expected_name or seed_description == expected_description:
        raise ValueError("UDP metadata seed values must differ from expected metadata.")
    if expected_users <= 0 or expected_files <= 0:
        raise ValueError("UDP metadata proof requires non-zero deterministic target counters.")
    if set(rest_snapshots) != set(CLIENTS):
        raise ValueError("UDP metadata REST snapshots must contain exactly rust and mfc.")

    records_by_client = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for client in CLIENTS:
        wire = _wire_evidence(records_by_client[client], udp_endpoint=target_udp_endpoint)
        applied = _applied_evidence(
            records_by_client[client],
            udp_endpoint=target_udp_endpoint,
            server_endpoint=target_server_endpoint,
            wire=wire,
        )
        rest = _rest_evidence(
            rest_snapshots[client],
            anchor_endpoint=anchor_server_endpoint,
            server_endpoint=target_server_endpoint,
            seed_name=seed_name,
            seed_description=seed_description,
            wire=wire,
        )
        status = wire.get("statusReply") if isinstance(wire.get("statusReply"), dict) else {}
        description = wire.get("descriptionReply") if isinstance(wire.get("descriptionReply"), dict) else {}
        expectations_ok = bool(
            status.get("users") == expected_users
            and status.get("files") == expected_files
            and description.get("name") == expected_name
            and description.get("description") == expected_description
        )
        ok = wire["ok"] and applied["ok"] and rest["ok"] and expectations_ok
        if not ok:
            failures.append(f"{client} did not prove wire-to-applied-to-REST UDP metadata")
        clients[client] = {
            "ok": ok,
            "wire": wire,
            "applied": applied,
            "rest": rest,
            "expectationsOk": expectations_ok,
        }

    bilateral_status = [
        {
            key: clients[client]["wire"]["statusReply"].get(key)
            for key in (
                "users",
                "files",
                "max_users",
                "soft_files",
                "hard_files",
                "udp_flags",
                "low_id_users",
                "obfuscation_port_udp",
                "obfuscation_port_tcp",
                "udp_key",
                "trailing_hex",
            )
        }
        for client in CLIENTS
        if isinstance(clients[client]["wire"].get("statusReply"), dict)
    ]
    bilateral_description = [
        {
            key: clients[client]["wire"]["descriptionReply"].get(key)
            for key in (
                "response_format",
                "name",
                "description",
                "dynamic_host",
                "version",
                "auxiliary_ports",
            )
        }
        for client in CLIENTS
        if isinstance(clients[client]["wire"].get("descriptionReply"), dict)
    ]
    bilateral_ok = bool(
        len(bilateral_status) == len(bilateral_description) == 2
        and bilateral_status[0] == bilateral_status[1]
        and bilateral_description[0] == bilateral_description[1]
    )
    if not bilateral_ok:
        failures.append("Rust and MFC decoded different UDP metadata values")
    passed = all(clients[client]["ok"] for client in CLIENTS) and bilateral_ok
    return {
        "schema": SCHEMA,
        "passed": passed,
        "evidenceLayers": list(EVIDENCE_LAYERS),
        "eligibleCoverageIds": list(ELIGIBLE_COVERAGE_IDS) if passed else [],
        "anchorServerEndpoint": anchor_server_endpoint,
        "targetServerEndpoint": target_server_endpoint,
        "targetUdpEndpoint": target_udp_endpoint,
        "expected": {
            "seedName": seed_name,
            "seedDescription": seed_description,
            "name": expected_name,
            "description": expected_description,
            "users": expected_users,
            "files": expected_files,
        },
        "clients": clients,
        "bilateral": {
            "ok": bilateral_ok,
            "status": bilateral_status,
            "description": bilateral_description,
        },
        "failures": failures,
    }


def require_server_udp_metadata_diagnostic_evidence(evidence: object) -> dict[str, Any]:
    """Returns one valid current-schema proof or raises with its failures."""

    if not isinstance(evidence, dict) or evidence.get("schema") != SCHEMA:
        raise RuntimeError("UDP server metadata diagnostics use an unsupported schema.")
    if evidence.get("passed") is not True:
        failures = evidence.get("failures")
        detail = "; ".join(str(value) for value in failures) if isinstance(failures, list) else "unknown failure"
        raise RuntimeError(f"UDP server metadata diagnostics did not pass: {detail}")
    if evidence.get("eligibleCoverageIds") != list(ELIGIBLE_COVERAGE_IDS):
        raise RuntimeError("UDP server metadata diagnostics have inconsistent eligible coverage IDs.")
    return evidence
