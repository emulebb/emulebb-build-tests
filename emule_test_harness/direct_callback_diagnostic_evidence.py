"""Causal bilateral evidence gate for deterministic direct UDP callbacks."""

from __future__ import annotations

from typing import Any, Iterable

from emule_test_harness import direct_callback_probe, ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-direct-callback-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
COVERAGE_ID = "lowid.direct-callback"
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


def _target(value: object) -> dict[str, Any]:
    row = value if isinstance(value, dict) else {}
    client_id = row.get("clientId")
    tcp_port = row.get("tcpPort")
    udp_port = row.get("udpPort")
    user_hash = str(row.get("userHash") or "").upper()
    ok = bool(
        isinstance(client_id, int)
        and not isinstance(client_id, bool)
        and 0 < client_id < ed2k_wire.LOW_ID_CEILING
        and isinstance(tcp_port, int)
        and not isinstance(tcp_port, bool)
        and 0 < tcp_port <= 0xFFFF
        and isinstance(udp_port, int)
        and not isinstance(udp_port, bool)
        and 0 < udp_port <= 0xFFFF
        and len(user_hash) == 32
        and all(character in "0123456789ABCDEF" for character in user_hash)
        and row.get("idKind") == "low-id"
    )
    return {
        "ok": ok,
        "clientId": client_id,
        "tcpPort": tcp_port,
        "udpPort": udp_port,
        "userHash": user_hash or None,
        "idKind": row.get("idKind"),
    }


def _hello_identity(value: object) -> dict[str, object] | None:
    connection = value if isinstance(value, dict) else {}
    payload_hex = connection.get("payloadHex")
    if not isinstance(payload_hex, str):
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if (
        payload_hex != payload.hex().upper()
        or connection.get("payloadLength") != len(payload)
        or len(payload) < 23
        or payload[0] != 16
    ):
        return None
    return {
        "userHash": payload[1:17].hex().upper(),
        "clientId": int.from_bytes(payload[17:21], "little"),
        "tcpPort": int.from_bytes(payload[21:23], "little"),
    }


def _request(
    value: object,
    *,
    client: str,
    requester_host: str,
    requester_tcp_port: int,
    requester_user_hash: bytes,
    target_host: str,
    target: dict[str, Any],
) -> dict[str, Any]:
    result = value if isinstance(value, dict) else {}
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    destination = (
        result.get("target") if isinstance(result.get("target"), dict) else {}
    )
    requester = (
        result.get("requester")
        if isinstance(result.get("requester"), dict)
        else {}
    )
    request = (
        result.get("request") if isinstance(result.get("request"), dict) else {}
    )
    connection = (
        result.get("callbackConnection")
        if isinstance(result.get("callbackConnection"), dict)
        else {}
    )
    raw = direct_callback_probe.encode_direct_callback_request(
        tcp_port=requester_tcp_port,
        user_hash=requester_user_hash,
        connect_options=0x01,
    )
    source_udp_port = _positive_int(source.get("udpPort"))
    sent_at = request.get("sentAt")
    observed_at = connection.get("observedAt")
    expected_identity = {
        "userHash": target["userHash"],
        "clientId": target["clientId"],
        "tcpPort": target["tcpPort"],
    }
    hello_identity = _hello_identity(connection)
    ok = bool(
        target["ok"]
        and result.get("schema") == "emulebb.direct-callback-probe/1"
        and result.get("status") == "completed"
        and result.get("targetLabel") == client
        and source.get("host") == requester_host
        and source_udp_port is not None
        and destination
        == {"host": target_host, "udpPort": target["udpPort"]}
        and requester.get("tcpPort") == requester_tcp_port
        and requester.get("userHash") == requester_user_hash.hex().upper()
        and requester.get("clientId")
        == direct_callback_probe.high_id_for_ipv4(requester_host)
        and requester.get("connectOptions") == 0x01
        and request.get("protocol") == direct_callback_probe.OP_EMULEPROT
        and request.get("opcode") == direct_callback_probe.OP_DIRECTCALLBACKREQ
        and request.get("rawHex") == raw.hex().upper()
        and request.get("payloadHex") == raw[2:].hex().upper()
        and request.get("sentBytes") == len(raw)
        and isinstance(sent_at, (int, float))
        and not isinstance(sent_at, bool)
        and isinstance(observed_at, (int, float))
        and not isinstance(observed_at, bool)
        and observed_at >= sent_at
        and str(connection.get("userHash") or "").upper() == target["userHash"]
        and connection.get("clientId") == target["clientId"]
        and connection.get("tcpPort") == target["tcpPort"]
        and hello_identity == expected_identity
    )
    return {
        "ok": ok,
        "sourceEndpoint": (
            f"{requester_host}:{source_udp_port}" if source_udp_port is not None else None
        ),
        "targetEndpoint": f"{target_host}:{target['udpPort']}",
        "rawHex": raw.hex().upper(),
        "payloadHex": raw[2:].hex().upper(),
        "sentAt": sent_at,
        "callbackConnection": connection or None,
        "helloIdentity": hello_identity,
    }


def _receive_packet(
    record: dict[str, Any],
    *,
    source_endpoint: str,
    raw: bytes,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == "ed2k_client_udp"
        and record.get("event") == "packet"
        and str(keys.get("peer") or "").casefold() == source_endpoint.casefold()
        and keys.get("protocolMarker") == direct_callback_probe.OP_EMULEPROT
        and keys.get("opcode") == direct_callback_probe.OP_DIRECTCALLBACKREQ
        and body.get("direction") == "recv"
        and body.get("outcome") == "accepted"
        and body.get("stateId") == "client_udp.direct_callback"
        and body.get("stateLabel") == "direct_callback"
        and body.get("flow") == "client_udp"
        and body.get("phase") == "direct_callback_request"
        and body.get("transportMode") == "plaintext"
        and body.get("obfuscated") is False
        and body.get("protocolMarker") == direct_callback_probe.OP_EMULEPROT
        and body.get("protocolName") == "emule"
        and body.get("opcode") == direct_callback_probe.OP_DIRECTCALLBACKREQ
        and body.get("opcodeName") == "OP_DIRECTCALLBACKREQ"
        and body.get("rawLen") == len(raw)
        and str(body.get("rawHex") or "").casefold() == raw.hex()
        and body.get("payloadLen") == len(raw) - 2
        and str(body.get("payloadHex") or "").casefold() == raw[2:].hex()
        and body.get("payloadHexTruncated") is False
        and body.get("note") == "direct_callback_raised"
    )


def _client_evidence(
    *,
    client: str,
    records: list[dict[str, Any]],
    requester_host: str,
    requester_tcp_port: int,
    requester_user_hash: bytes,
    target_host: str,
    target_value: object,
    requester_result: object,
) -> dict[str, Any]:
    target = _target(target_value)
    request = _request(
        requester_result,
        client=client,
        requester_host=requester_host,
        requester_tcp_port=requester_tcp_port,
        requester_user_hash=requester_user_hash,
        target_host=target_host,
        target=target,
    )
    raw = bytes.fromhex(request["rawHex"])
    source_endpoint = request.get("sourceEndpoint")
    packets = [
        record
        for record in records
        if isinstance(source_endpoint, str)
        and _receive_packet(record, source_endpoint=source_endpoint, raw=raw)
    ]
    packet = packets[0] if len(packets) == 1 else None
    ok = bool(
        target["ok"]
        and request["ok"]
        and packet is not None
        and _sequence(packet) > 0
    )
    return {
        "ok": ok,
        "target": target,
        "requester": request,
        "wireApplication": {
            "ok": packet is not None,
            "packetCount": len(packets),
            "sequence": _sequence(packet) or None,
            "peer": _keys(packet).get("peer") if packet is not None else None,
            "outcome": _body(packet).get("outcome") if packet is not None else None,
            "note": _body(packet).get("note") if packet is not None else None,
            "rawHex": _body(packet).get("rawHex") if packet is not None else None,
        },
    }


def build_direct_callback_diagnostic_evidence(
    *,
    requester_host: str,
    requester_tcp_port: int,
    requester_user_hash: bytes,
    target_host: str,
    targets: dict[str, object],
    requester_results: dict[str, object],
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Proves exact direct UDP receipt and identity-correlated connect-back."""

    expected_raw = direct_callback_probe.encode_direct_callback_request(
        tcp_port=requester_tcp_port,
        user_hash=requester_user_hash,
        connect_options=0x01,
    )
    records = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients = {
        client: _client_evidence(
            client=client,
            records=records[client],
            requester_host=requester_host,
            requester_tcp_port=requester_tcp_port,
            requester_user_hash=requester_user_hash,
            target_host=target_host,
            target_value=targets.get(client),
            requester_result=requester_results.get(client),
        )
        for client in CLIENTS
    }
    comparison = {
        "requestBytesEqual": all(
            row["requester"]["rawHex"] == expected_raw.hex().upper()
            for row in clients.values()
        ),
        "bothAccepted": all(
            row["wireApplication"]["ok"] is True for row in clients.values()
        ),
        "bothConnected": all(
            row["requester"]["ok"] is True for row in clients.values()
        ),
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
        "requesterEndpoint": f"{requester_host}:{requester_tcp_port}",
        "targetHost": target_host,
        "expectedRequestHex": expected_raw.hex().upper(),
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [COVERAGE_ID] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_direct_callback_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless both clients causally applied the exact direct callback."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError(
            "Deterministic direct-callback diagnostics have an unexpected schema"
        )
    if report.get("ok") is not True:
        raise RuntimeError(
            "Deterministic direct-callback diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        COVERAGE_ID
    ]:
        raise RuntimeError("Deterministic direct-callback coverage claims are invalid")
