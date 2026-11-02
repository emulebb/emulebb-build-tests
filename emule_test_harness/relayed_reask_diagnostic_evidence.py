"""Causal bilateral evidence gate for deterministic LowID relayed reasks."""

from __future__ import annotations

from typing import Any, Callable, Iterable

from emule_test_harness import relayed_reask_probe


SCHEMA = "emulebb-build-tests.deterministic-relayed-reask-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
COVERAGE_ID = "lowid.relayed-reask"
CLIENTS = ("rust", "mfc")
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


def _sequence(record: dict[str, Any] | None) -> int:
    value = record.get("seq") if record is not None else None
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else 0
    )


def _event(record: dict[str, Any], family: str, event: str) -> bool:
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == family
        and record.get("event") == event
        and _sequence(record) > 0
    )


def _single(
    records: list[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
) -> tuple[dict[str, Any] | None, int]:
    matches = [record for record in records if predicate(record)]
    return (matches[0] if len(matches) == 1 else None, len(matches))


def _control_receipt(
    value: object,
    *,
    file_hash: str,
    source_host: str,
    source_tcp_port: int,
    source_udp_port: int,
    source_user_hash: str,
    source_udp_version: int,
    buddy_host: str,
    buddy_udp_port: int,
    buddy_id: str,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    request = receipt.get("request") if isinstance(receipt.get("request"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    expected_request = {
        "fileHash": file_hash,
        "sourceIp": source_host,
        "sourceTcpPort": source_tcp_port,
        "sourceUdpPort": source_udp_port,
        "sourceUserHash": source_user_hash,
        "sourceUdpVersion": source_udp_version,
        "buddyIp": buddy_host,
        "buddyUdpPort": buddy_udp_port,
        "buddyId": buddy_id,
    }
    expected_response = {
        "accepted": True,
        "fileHash": file_hash,
        "sourceEndpoint": f"{source_host}:{source_udp_port}",
        "sourceTcpPort": source_tcp_port,
        "sourceUserHash": source_user_hash,
        "sourceUdpVersion": source_udp_version,
        "buddyEndpoint": f"{buddy_host}:{buddy_udp_port}",
        "buddyId": buddy_id,
        "state": "queued-lowid-source",
    }
    ok = bool(
        request == expected_request
        and response.get("status") == 200
        and response.get("json") == expected_response
    )
    return {
        "ok": ok,
        "request": request or None,
        "response": response or None,
    }


def _probe_receipt(
    value: object,
    *,
    client: str,
    file_hash: str,
    buddy_id: str,
    buddy_endpoint: str,
    source_endpoint: str,
    requester_endpoint: str,
    source_udp_version: int,
    queue_rank: int,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    request = receipt.get("request") if isinstance(receipt.get("request"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    raw_hex = str(request.get("rawHex") or "")
    try:
        raw = bytes.fromhex(raw_hex)
        decoded = relayed_reask_probe.decode_reask_callback_udp(
            raw,
            source_udp_version=source_udp_version,
        )
    except (TypeError, ValueError):
        raw = b""
        decoded = {}
    expected_ack = relayed_reask_probe.encode_reask_ack(
        queue_rank=queue_rank,
        requester_udp_version=source_udp_version,
    )
    received_at = request.get("receivedAt")
    sent_at = response.get("sentAt")
    ok = bool(
        receipt.get("schema") == "emulebb.relayed-reask-probe/1"
        and receipt.get("status") == "completed"
        and receipt.get("targetLabel") == client
        and receipt.get("buddyEndpoint") == buddy_endpoint
        and receipt.get("sourceEndpoint") == source_endpoint
        and receipt.get("requesterEndpoint") == requester_endpoint
        and decoded.get("fileHash") == file_hash.upper()
        and decoded.get("buddyId") == buddy_id.upper()
        and decoded.get("sourceUdpVersion") == source_udp_version
        and response.get("protocol") == relayed_reask_probe.OP_EMULEPROT
        and response.get("opcode") == relayed_reask_probe.OP_REASKACK
        and response.get("rawHex") == expected_ack.hex().upper()
        and response.get("payloadHex") == expected_ack[2:].hex().upper()
        and response.get("queueRank") == queue_rank
        and response.get("sentBytes") == len(expected_ack)
        and isinstance(received_at, (int, float))
        and not isinstance(received_at, bool)
        and isinstance(sent_at, (int, float))
        and not isinstance(sent_at, bool)
        and sent_at >= received_at
    )
    return {
        "ok": ok,
        "requestRawHex": raw.hex().upper() if raw else None,
        "requestPayloadHex": raw[2:].hex().upper() if len(raw) >= 2 else None,
        "request": decoded or None,
        "responseRawHex": expected_ack.hex().upper(),
        "queueRank": queue_rank,
        "receivedAt": received_at,
        "sentAt": sent_at,
    }


def _sched_identity(
    record: dict[str, Any],
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
) -> bool:
    keys = _keys(record)
    return bool(
        str(keys.get("fileHash") or "").casefold() == file_hash
        and str(keys.get("peer") or "").casefold() == source_tcp_endpoint.casefold()
        and str(keys.get("peerHash") or "").casefold() == source_user_hash
    )


def _client_evidence(
    *,
    client: str,
    records: list[dict[str, Any]],
    control_value: object,
    probe_value: object,
    file_hash: str,
    source_host: str,
    source_tcp_port: int,
    source_udp_port: int,
    source_user_hash: str,
    source_udp_version: int,
    buddy_host: str,
    buddy_udp_port: int,
    buddy_id: str,
    requester_udp_port: int,
    queue_rank: int,
) -> dict[str, Any]:
    source_tcp_endpoint = f"{source_host}:{source_tcp_port}"
    source_udp_endpoint = f"{source_host}:{source_udp_port}"
    buddy_endpoint = f"{buddy_host}:{buddy_udp_port}"
    requester_endpoint = f"{buddy_host}:{requester_udp_port}"
    control = _control_receipt(
        control_value,
        file_hash=file_hash,
        source_host=source_host,
        source_tcp_port=source_tcp_port,
        source_udp_port=source_udp_port,
        source_user_hash=source_user_hash,
        source_udp_version=source_udp_version,
        buddy_host=buddy_host,
        buddy_udp_port=buddy_udp_port,
        buddy_id=buddy_id,
    )
    probe = _probe_receipt(
        probe_value,
        client=client,
        file_hash=file_hash,
        buddy_id=buddy_id,
        buddy_endpoint=buddy_endpoint,
        source_endpoint=source_udp_endpoint,
        requester_endpoint=requester_endpoint,
        source_udp_version=source_udp_version,
        queue_rank=queue_rank,
    )
    request_raw_hex = probe.get("requestRawHex")
    response_raw_hex = probe.get("responseRawHex")

    def identity(record: dict[str, Any]) -> bool:
        return _sched_identity(
            record,
            file_hash=file_hash,
            source_tcp_endpoint=source_tcp_endpoint,
            source_user_hash=source_user_hash,
        )

    registration, registration_count = _single(
        records,
        lambda record: (
            _event(record, "sched", "udp_reask_source_registered")
            and identity(record)
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("sourceUdpEndpoint") == source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == source_udp_version
            and _body(record).get("lowId") is True
            and _body(record).get("buddyEndpoint") == buddy_endpoint
            and str(_body(record).get("buddyId") or "").casefold() == buddy_id
        ),
    )
    schedule, schedule_count = _single(
        records,
        lambda record: (
            _event(record, "sched", "udp_reask_schedule_decision")
            and identity(record)
            and _body(record).get("outcome") == "eligible"
            and _body(record).get("reason") == "eligible"
        ),
    )
    decision, decision_count = _single(
        records,
        lambda record: (
            _event(record, "sched", "udp_reask_decision")
            and identity(record)
            and _body(record).get("outcome") == "sent"
            and _body(record).get("transportEligible") is True
            and _body(record).get("reason") == "callback_reask_sent"
            and _body(record).get("path") == "callback"
        ),
    )
    outbound, outbound_count = _single(
        records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == buddy_endpoint.casefold()
            and str(_keys(record).get("fileHash") or "").casefold() == file_hash
            and _keys(record).get("protocolMarker") == relayed_reask_probe.OP_EMULEPROT
            and _keys(record).get("opcode") == relayed_reask_probe.OP_REASKCALLBACKUDP
            and _body(record).get("direction") == "send"
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "buddy_relay_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and str(_body(record).get("rawHex") or "").casefold()
            == str(request_raw_hex or "").casefold()
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    send_attempt_id = _keys(outbound).get("sendAttemptId") if outbound else None
    send_outcome, send_outcome_count = _single(
        records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == buddy_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == send_attempt_id
            and _body(record).get("sendAttemptId") == send_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "buddy_relay_request"
        ),
    )
    inbound, inbound_count = _single(
        records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == source_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == relayed_reask_probe.OP_EMULEPROT
            and _keys(record).get("opcode") == relayed_reask_probe.OP_REASKACK
            and _body(record).get("direction") == "recv"
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and str(_body(record).get("rawHex") or "").casefold()
            == str(response_raw_hex or "").casefold()
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    applied, applied_count = _single(
        records,
        lambda record: (
            _event(record, "sched", "udp_reask_reply_applied")
            and identity(record)
            and _body(record).get("outcome") == "applied"
            and _body(record).get("replyOpcode") == relayed_reask_probe.OP_REASKACK
            and _body(record).get("queueRank") == queue_rank
            and _body(record).get("requestPendingAfter") is False
            and _body(record).get("remoteQueueFullAfter") is False
        ),
    )
    sequences = {
        "registration": _sequence(registration),
        "schedule": _sequence(schedule),
        "decision": _sequence(decision),
        "outbound": _sequence(outbound),
        "sendOutcome": _sequence(send_outcome),
        "inbound": _sequence(inbound),
        "applied": _sequence(applied),
    }
    ordered = bool(
        all(sequences.values())
        and sequences["registration"] < sequences["schedule"]
        and sequences["schedule"] < sequences["decision"]
        and sequences["decision"] < sequences["outbound"]
        and sequences["outbound"] < sequences["sendOutcome"]
        and sequences["sendOutcome"] < sequences["inbound"]
        and sequences["sendOutcome"] < sequences["applied"]
    )
    counts = {
        "registration": registration_count,
        "schedule": schedule_count,
        "decision": decision_count,
        "outbound": outbound_count,
        "sendOutcome": send_outcome_count,
        "inbound": inbound_count,
        "applied": applied_count,
    }
    ok = bool(
        control["ok"]
        and probe["ok"]
        and all(count == 1 for count in counts.values())
        and isinstance(send_attempt_id, int)
        and not isinstance(send_attempt_id, bool)
        and send_attempt_id > 0
        and ordered
    )
    return {
        "ok": ok,
        "control": control,
        "probe": probe,
        "diagnostics": {
            "ok": all(count == 1 for count in counts.values()) and ordered,
            "counts": counts,
            "sequences": sequences,
            "ordered": ordered,
            "sendAttemptId": send_attempt_id,
            "requestRawHex": (
                _body(outbound).get("rawHex") if outbound is not None else None
            ),
            "responseRawHex": (
                _body(inbound).get("rawHex") if inbound is not None else None
            ),
            "queueRank": (
                _body(applied).get("queueRank") if applied is not None else None
            ),
        },
    }


def build_relayed_reask_diagnostic_evidence(
    *,
    file_hash: bytes,
    source_host: str,
    source_tcp_port: int,
    source_udp_port: int,
    source_user_hash: bytes,
    source_udp_version: int,
    buddy_host: str,
    buddy_udp_port: int,
    buddy_id: bytes,
    requester_udp_ports: dict[str, int],
    queue_rank: int,
    controls: dict[str, object],
    probe_results: dict[str, object],
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Proves exact bilateral buddy requests and source-routed ACK application."""

    file_hash_hex = file_hash.hex()
    source_user_hash_hex = source_user_hash.hex()
    buddy_id_hex = buddy_id.hex()
    records = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients = {
        client: _client_evidence(
            client=client,
            records=records[client],
            control_value=controls.get(client),
            probe_value=probe_results.get(client),
            file_hash=file_hash_hex,
            source_host=source_host,
            source_tcp_port=source_tcp_port,
            source_udp_port=source_udp_port,
            source_user_hash=source_user_hash_hex,
            source_udp_version=source_udp_version,
            buddy_host=buddy_host,
            buddy_udp_port=buddy_udp_port,
            buddy_id=buddy_id_hex,
            requester_udp_port=requester_udp_ports.get(client, 0),
            queue_rank=queue_rank,
        )
        for client in CLIENTS
    }
    comparison = {
        "requestBytesEqual": (
            clients["rust"]["probe"]["requestRawHex"]
            == clients["mfc"]["probe"]["requestRawHex"]
        ),
        "ackBytesEqual": (
            clients["rust"]["probe"]["responseRawHex"]
            == clients["mfc"]["probe"]["responseRawHex"]
        ),
        "queueRankEqual": all(
            client["diagnostics"]["queueRank"] == queue_rank
            for client in clients.values()
        ),
        "bothApplied": all(client["ok"] is True for client in clients.values()),
    }
    comparison["ok"] = all(comparison.values())
    failures = [
        *[
            f"client.{client}"
            for client, evidence in clients.items()
            if evidence["ok"] is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "fileHash": file_hash_hex,
        "sourceTcpEndpoint": f"{source_host}:{source_tcp_port}",
        "sourceUdpEndpoint": f"{source_host}:{source_udp_port}",
        "sourceUserHash": source_user_hash_hex,
        "sourceUdpVersion": source_udp_version,
        "buddyEndpoint": f"{buddy_host}:{buddy_udp_port}",
        "buddyId": buddy_id_hex,
        "queueRank": queue_rank,
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [COVERAGE_ID] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_relayed_reask_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless both clients causally applied the exact relayed reask ACK."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError(
            "Deterministic relayed-reask diagnostics have an unexpected schema"
        )
    if report.get("ok") is not True:
        raise RuntimeError(
            "Deterministic relayed-reask diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        COVERAGE_ID
    ]:
        raise RuntimeError("Deterministic relayed-reask coverage claims are invalid")
