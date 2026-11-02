"""Causal bilateral evidence gate for direct client-UDP version 4 reasks."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Iterable


SCHEMA = "emulebb-build-tests.client-udp-v4-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
COVERAGE_ID = "client-udp.v4"
CLIENTS = ("rust", "mfc")
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
STOCK_RECORD_ID = "stock.client-udp.corpus"
STOCK_CORPUS_SHA256 = "89468db8e028268f21598216f5949ae11c2b1c3e1370b151d3d7136e8fda812b"
OP_EMULEPROT = 0xC5
OP_REASKFILEPING = 0x90
OP_REASKACK = 0x91
OP_FILENOTFOUND = 0x92
OP_QUEUEFULL = 0x93
OP_REASKCALLBACKUDP = 0x94


@dataclass(frozen=True)
class ClientUdpV4Transition:
    requester: str
    responder: str
    source_tcp_endpoint: str
    source_udp_endpoint: str
    source_user_hash: bytes
    requester_udp_endpoint: str
    control_receipt: object
    requester_records: Iterable[dict[str, Any]]
    responder_records: Iterable[dict[str, Any]]


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


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    host, separator, raw_port = endpoint.rpartition(":")
    if not separator or not host:
        return None
    try:
        port = int(raw_port)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def _decode_part_status(
    data: bytes,
    offset: int,
) -> tuple[dict[str, Any], int]:
    if len(data) < offset + 2:
        raise ValueError("short part-status header")
    count = int.from_bytes(data[offset : offset + 2], "little")
    offset += 2
    byte_count = (count + 7) // 8
    if len(data) < offset + byte_count:
        raise ValueError("short part-status bitmap")
    bitmap = data[offset : offset + byte_count]
    offset += byte_count
    if count and count % 8 and bitmap[-1] >> (count % 8):
        raise ValueError("non-zero part-status padding bits")
    bits = "".join(
        "1" if bitmap[index // 8] & (1 << (index % 8)) else "0"
        for index in range(count)
    )
    return {
        "wirePartCount": count,
        "partStatusBits": bits if count else None,
        "completeSource": count == 0,
        "rawHex": data[offset - byte_count - 2 : offset].hex(),
    }, offset


def _encode_part_status(bits: str | None) -> bytes:
    if bits is None:
        return bytes(2)
    if any(bit not in "01" for bit in bits) or len(bits) > 0xFFFF:
        raise ValueError("invalid part-status bits")
    encoded = bytearray(len(bits).to_bytes(2, "little"))
    encoded.extend(bytes((len(bits) + 7) // 8))
    for index, bit in enumerate(bits):
        if bit == "1":
            encoded[2 + index // 8] |= 1 << (index % 8)
    return bytes(encoded)


def _decode_request(raw_hex: object) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex))
        if len(raw) < 22 or raw[:2] != bytes((OP_EMULEPROT, OP_REASKFILEPING)):
            raise ValueError("not a version-4 OP_REASKFILEPING frame")
        part_status, offset = _decode_part_status(raw, 18)
        if len(raw) != offset + 2:
            raise ValueError("unexpected OP_REASKFILEPING tail")
        return {
            "ok": True,
            "rawHex": raw.hex(),
            "fileHash": raw[2:18].hex(),
            "partStatus": part_status,
            "completeSourceCount": int.from_bytes(raw[offset : offset + 2], "little"),
        }
    except (TypeError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def _decode_ack(raw_hex: object) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex))
        if len(raw) < 6 or raw[:2] != bytes((OP_EMULEPROT, OP_REASKACK)):
            raise ValueError("not a version-4 OP_REASKACK frame")
        part_status, offset = _decode_part_status(raw, 2)
        if len(raw) != offset + 2:
            raise ValueError("unexpected OP_REASKACK tail")
        rank = int.from_bytes(raw[offset : offset + 2], "little")
        if rank == 0:
            raise ValueError("OP_REASKACK queue rank must be non-zero")
        return {
            "ok": True,
            "rawHex": raw.hex(),
            "partStatus": part_status,
            "queueRank": rank,
        }
    except (TypeError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def _stock_authority(value: object) -> dict[str, Any]:
    record = value if isinstance(value, dict) else {}
    try:
        fixture = base64.b64decode(str(record.get("fixtureBase64") or ""), validate=True)
        digest = hashlib.sha256(fixture).hexdigest()
        v1_request = fixture[:18]
        v1_ack = fixture[18:22]
        file_not_found = fixture[22:24]
        queue_full = fixture[24:26]
        callback = fixture[26:]
        semantics_ok = bool(
            len(fixture) == 64
            and v1_request == bytes((OP_EMULEPROT, OP_REASKFILEPING)) + bytes(range(16))
            and v1_ack == bytes((OP_EMULEPROT, OP_REASKACK, 1, 0))
            and file_not_found == bytes((OP_EMULEPROT, OP_FILENOTFOUND))
            and queue_full == bytes((OP_EMULEPROT, OP_QUEUEFULL))
            and callback[:2] == bytes((OP_EMULEPROT, OP_REASKCALLBACKUDP))
            and callback[2:18] == bytes(range(16))
            and callback[18:34] == bytes(range(16, 32))
            and callback[34:] == bytes.fromhex("02000100")
        )
    except (TypeError, ValueError):
        fixture = b""
        digest = ""
        semantics_ok = False
    ok = bool(
        record.get("recordId") == STOCK_RECORD_ID
        and record.get("protocol") == "client_udp"
        and record.get("recordType") == "udp-packet"
        and record.get("direction") == "both"
        and record.get("transport") == "udp"
        and isinstance(record.get("coverageIds"), list)
        and COVERAGE_ID in record["coverageIds"]
        and record.get("fixtureEncoding") == "concatenated-client-udp-corpus"
        and record.get("fixtureLength") == len(fixture) == 64
        and record.get("payloadDigest") == f"sha256:{STOCK_CORPUS_SHA256}"
        and digest == STOCK_CORPUS_SHA256
        and semantics_ok
    )
    return {
        "ok": ok,
        "recordId": record.get("recordId"),
        "sha256": digest or None,
        "length": len(fixture),
        "semanticsOk": semantics_ok,
    }


def _control_evidence(
    value: object,
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_udp_endpoint: str,
    source_user_hash: str,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    request = receipt.get("request") if isinstance(receipt.get("request"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    tcp = _split_endpoint(source_tcp_endpoint)
    udp = _split_endpoint(source_udp_endpoint)
    expected_request = (
        {
            "fileHash": file_hash,
            "sourceIp": tcp[0],
            "sourceTcpPort": tcp[1],
            "sourceUdpPort": udp[1],
            "sourceUserHash": source_user_hash,
            "sourceUdpVersion": 4,
        }
        if tcp is not None and udp is not None and tcp[0] == udp[0]
        else None
    )
    expected_response = (
        {
            "accepted": True,
            "fileHash": file_hash,
            "sourceEndpoint": source_udp_endpoint,
            "sourceTcpPort": tcp[1],
            "sourceUserHash": source_user_hash,
            "sourceUdpVersion": 4,
            "state": "queued-source-reask-pending",
        }
        if tcp is not None
        else None
    )
    return {
        "ok": bool(
            expected_request is not None
            and request == expected_request
            and response.get("status") == 200
            and response.get("json") == expected_response
        ),
        "request": request or None,
        "response": response or None,
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
        and str(keys.get("peer") or "").casefold()
        == source_tcp_endpoint.casefold()
        and str(keys.get("peerHash") or "").casefold() == source_user_hash
    )


def _transition_evidence(
    transition: ClientUdpV4Transition,
    *,
    file_hash: str,
    part_count: int,
) -> dict[str, Any]:
    requester_records = list(transition.requester_records)
    responder_records = list(transition.responder_records)
    source_hash = transition.source_user_hash.hex()
    control = _control_evidence(
        transition.control_receipt,
        file_hash=file_hash,
        source_tcp_endpoint=transition.source_tcp_endpoint,
        source_udp_endpoint=transition.source_udp_endpoint,
        source_user_hash=source_hash,
    )

    def identity(record: dict[str, Any]) -> bool:
        return _sched_identity(
            record,
            file_hash=file_hash,
            source_tcp_endpoint=transition.source_tcp_endpoint,
            source_user_hash=source_hash,
        )

    registration, registration_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_source_registered")
            and identity(record)
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("sourceUdpEndpoint")
            == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == 4
            and _body(record).get("lowId") is False
            and _body(record).get("buddyEndpoint") is None
            and _body(record).get("buddyId") is None
        ),
    )
    schedule, schedule_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_schedule_decision")
            and identity(record)
            and _body(record).get("outcome") == "eligible"
            and _body(record).get("reason") == "eligible"
        ),
    )
    decision, decision_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_decision")
            and identity(record)
            and _body(record).get("outcome") == "sent"
            and _body(record).get("transportEligible") is True
            and _body(record).get("reason") == "udp_reask_sent"
            and _body(record).get("path") == "direct"
        ),
    )
    request_out, request_out_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and str(_keys(record).get("fileHash") or "").casefold() == file_hash
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKFILEPING
            and _body(record).get("direction") == "send"
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "reask_request"
            and _body(record).get("phase") == "reask_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    request_attempt_id = _keys(request_out).get("sendAttemptId") if request_out else None
    request_terminal, request_terminal_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "reask_request"
        ),
    )
    request_in, request_in_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKFILEPING
            and _body(record).get("direction") == "recv"
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    ack_out, ack_out_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKACK
            and _body(record).get("direction") == "send"
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "reciprocity_reply"
            and _body(record).get("phase") == "reciprocity_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    ack_attempt_id = _keys(ack_out).get("sendAttemptId") if ack_out else None
    ack_terminal, ack_terminal_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == ack_attempt_id
            and _body(record).get("sendAttemptId") == ack_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "reciprocity_reply"
        ),
    )
    ack_in, ack_in_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKACK
            and _body(record).get("direction") == "recv"
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )

    request = _decode_request(_body(request_out).get("rawHex") if request_out else None)
    responder_request = _decode_request(
        _body(request_in).get("rawHex") if request_in else None
    )
    ack = _decode_ack(_body(ack_out).get("rawHex") if ack_out else None)
    requester_ack = _decode_ack(_body(ack_in).get("rawHex") if ack_in else None)
    queue_rank = ack.get("queueRank") if ack.get("ok") is True else None
    applied, applied_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_reply_applied")
            and identity(record)
            and _body(record).get("outcome") == "applied"
            and _body(record).get("replyOpcode") == OP_REASKACK
            and _body(record).get("queueRank") == queue_rank
            and _body(record).get("requestPendingAfter") is False
            and _body(record).get("remoteQueueFullAfter") is False
            and _body(record).get("sourceUdpEndpoint")
            == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == 4
            and _body(record).get("queueRankApplied") is True
            and _body(record).get("partStatusIncluded") is True
            and _body(record).get("wirePartCount") == 0
            and _body(record).get("partStatusApplied") is True
            and _body(record).get("partCountAfter") == part_count
            and _body(record).get("availablePartsAfter") == part_count
            and _body(record).get("partStatusBitsAfter") == "1" * part_count
            and _body(record).get("noNeededPartsAfter") is False
        ),
    )

    requester_sequences = {
        "registration": _sequence(registration),
        "schedule": _sequence(schedule),
        "decision": _sequence(decision),
        "requestOut": _sequence(request_out),
        "requestTerminal": _sequence(request_terminal),
        "ackIn": _sequence(ack_in),
        "applied": _sequence(applied),
    }
    responder_sequences = {
        "requestIn": _sequence(request_in),
        "ackOut": _sequence(ack_out),
        "ackTerminal": _sequence(ack_terminal),
    }
    requester_ordered = bool(
        all(requester_sequences.values())
        and requester_sequences["registration"] < requester_sequences["schedule"]
        < requester_sequences["decision"] < requester_sequences["requestOut"]
        < requester_sequences["requestTerminal"] < requester_sequences["ackIn"]
        < requester_sequences["applied"]
    )
    responder_ordered = bool(
        all(responder_sequences.values())
        and responder_sequences["requestIn"] < responder_sequences["ackOut"]
        < responder_sequences["ackTerminal"]
    )
    counts = {
        "registration": registration_count,
        "schedule": schedule_count,
        "decision": decision_count,
        "requestOut": request_out_count,
        "requestTerminal": request_terminal_count,
        "requestIn": request_in_count,
        "ackOut": ack_out_count,
        "ackTerminal": ack_terminal_count,
        "ackIn": ack_in_count,
        "applied": applied_count,
    }
    expected_request = (
        bytes((OP_EMULEPROT, OP_REASKFILEPING))
        + bytes.fromhex(file_hash)
        + _encode_part_status("0" * part_count)
        + int(request.get("completeSourceCount") or 0).to_bytes(2, "little")
        if request.get("ok") is True
        else b""
    )
    expected_ack = (
        bytes((OP_EMULEPROT, OP_REASKACK))
        + _encode_part_status(None)
        + int(queue_rank or 0).to_bytes(2, "little")
        if queue_rank
        else b""
    )
    wire_ok = bool(
        request.get("ok") is True
        and request.get("fileHash") == file_hash
        and request.get("partStatus", {}).get("wirePartCount") == part_count
        and request.get("partStatus", {}).get("partStatusBits") == "0" * part_count
        and request.get("rawHex") == expected_request.hex()
        and responder_request == request
        and ack.get("ok") is True
        and ack.get("partStatus", {}).get("completeSource") is True
        and ack.get("rawHex") == expected_ack.hex()
        and requester_ack == ack
    )
    ok = bool(
        transition.requester in CLIENTS
        and transition.responder in CLIENTS
        and transition.requester != transition.responder
        and control["ok"]
        and all(count == 1 for count in counts.values())
        and isinstance(request_attempt_id, int)
        and not isinstance(request_attempt_id, bool)
        and request_attempt_id > 0
        and isinstance(ack_attempt_id, int)
        and not isinstance(ack_attempt_id, bool)
        and ack_attempt_id > 0
        and requester_ordered
        and responder_ordered
        and wire_ok
    )
    return {
        "ok": ok,
        "requester": transition.requester,
        "responder": transition.responder,
        "sourceTcpEndpoint": transition.source_tcp_endpoint,
        "sourceUdpEndpoint": transition.source_udp_endpoint,
        "sourceUserHash": source_hash,
        "requesterUdpEndpoint": transition.requester_udp_endpoint,
        "control": control,
        "wire": {
            "ok": wire_ok,
            "request": request,
            "ack": ack,
            "expectedRequestRawHex": expected_request.hex() or None,
            "expectedAckRawHex": expected_ack.hex() or None,
        },
        "diagnostics": {
            "ok": all(count == 1 for count in counts.values())
            and requester_ordered
            and responder_ordered,
            "counts": counts,
            "requesterSequences": requester_sequences,
            "responderSequences": responder_sequences,
            "requesterOrdered": requester_ordered,
            "responderOrdered": responder_ordered,
            "requestSendAttemptId": request_attempt_id,
            "ackSendAttemptId": ack_attempt_id,
        },
        "application": _body(applied) if applied is not None else None,
    }


def build_client_udp_v4_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpV4Transition],
) -> dict[str, Any]:
    """Prove both clients originate, answer, and apply one exact direct V4 reask."""

    file_hash_hex = file_hash.hex()
    stock = _stock_authority(stock_record)
    transition_list = list(transitions)
    clients: dict[str, dict[str, Any]] = {}
    duplicate_requesters: list[str] = []
    for transition in transition_list:
        if transition.requester in clients:
            duplicate_requesters.append(transition.requester)
            continue
        clients[transition.requester] = _transition_evidence(
            transition,
            file_hash=file_hash_hex,
            part_count=part_count,
        )
    exact_clients = set(clients) == set(CLIENTS) and not duplicate_requesters
    requests = [
        client.get("wire", {}).get("request", {}).get("rawHex")
        for client in clients.values()
    ]
    acks = [
        client.get("wire", {}).get("ack", {}).get("rawHex")
        for client in clients.values()
    ]
    ranks = [
        client.get("wire", {}).get("ack", {}).get("queueRank")
        for client in clients.values()
    ]
    application_fields = (
        "replyOpcode",
        "queueRank",
        "requestPendingAfter",
        "remoteQueueFullAfter",
        "sourceUdpVersion",
        "queueRankApplied",
        "partStatusIncluded",
        "wirePartCount",
        "partStatusApplied",
        "partCountAfter",
        "availablePartsAfter",
        "partStatusBitsAfter",
        "noNeededPartsAfter",
        "outcome",
    )
    applications = [
        {
            field: application.get(field)
            for field in application_fields
        }
        for client in clients.values()
        if isinstance((application := client.get("application")), dict)
    ]
    comparison = {
        "requestBytesEqual": len(requests) == 2 and requests[0] == requests[1],
        "ackBytesEqual": len(acks) == 2 and acks[0] == acks[1],
        "queueRankEqual": len(ranks) == 2 and ranks[0] == ranks[1],
        "applicationEqual": len(applications) == 2
        and applications[0] == applications[1],
        "bothApplied": exact_clients
        and all(client.get("ok") is True for client in clients.values()),
    }
    comparison["ok"] = all(comparison.values())
    failures = [
        *([] if stock["ok"] else ["stockAuthority"]),
        *([] if exact_clients else ["transitionSet"]),
        *[
            f"client.{client}"
            for client, evidence in clients.items()
            if evidence.get("ok") is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "fileHash": file_hash_hex,
        "partCount": part_count,
        "stockAuthority": stock,
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [COVERAGE_ID] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_client_udp_v4_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raise unless both clients causally completed the exact direct V4 transition."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Client-UDP V4 diagnostics have an unexpected schema")
    if report.get("ok") is not True:
        raise RuntimeError(
            "Client-UDP V4 diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        COVERAGE_ID
    ]:
        raise RuntimeError("Client-UDP V4 coverage claims are invalid")
