from __future__ import annotations

import hashlib
from typing import Any

import pytest

from emule_test_harness import ed2k_wire, server_callback_diagnostic_evidence as evidence


SERVER_ENDPOINT = "172.17.0.2:4661"
REQUESTER_HOST = "198.18.240.2"
REQUESTER_PORT = 4662
REPLY_PAYLOAD = bytes.fromhex("C612F0023612")


def packet(seq: int, trace_id: int, payload: bytes = REPLY_PAYLOAD) -> dict[str, Any]:
    return {
        "schema": "diag_event_v2",
        "family": "ed2k_tcp",
        "event": "packet",
        "seq": seq,
        "keys": {
            "peer": SERVER_ENDPOINT,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": ed2k_wire.OP_CALLBACKREQUESTED,
            "traceId": trace_id,
        },
        "body": {
            "flow": "server",
            "direction": "recv",
            "outcome": "accepted",
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": ed2k_wire.OP_CALLBACKREQUESTED,
            "traceId": trace_id,
            "transportMode": "plaintext",
            "obfuscated": False,
            "payloadLen": len(payload),
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
        },
    }


def applied(seq: int, trace_id: int) -> dict[str, Any]:
    return {
        "schema": "diag_event_v2",
        "family": "ed2k_tcp",
        "event": "callback_request_applied",
        "seq": seq,
        "keys": {
            "peer": SERVER_ENDPOINT,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": ed2k_wire.OP_CALLBACKREQUESTED,
            "traceId": trace_id,
        },
        "body": {
            "flow": "server",
            "direction": "recv",
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": ed2k_wire.OP_CALLBACKREQUESTED,
            "traceId": trace_id,
            "transportMode": "plaintext",
            "obfuscated": False,
            "callbackEndpoint": f"{REQUESTER_HOST}:{REQUESTER_PORT}",
            "connectOptions": None,
            "userHash": None,
            "payloadLen": 6,
            "stateId": "server.callback.request_applied",
            "milestone": "callback_dispatch",
            "dispatchAccepted": True,
            "outcome": "applied",
        },
    }


def target(client_id: int, tcp_port: int, user_hash_byte: int) -> dict[str, object]:
    return {
        "clientId": client_id,
        "tcpPort": tcp_port,
        "userHash": (bytes([user_hash_byte]) * 16).hex().upper(),
        "idKind": "low-id",
    }


def requester_result(
    client: str, client_id: int, tcp_port: int, user_hash_byte: int
) -> dict[str, object]:
    payload = ed2k_wire.encode_callback_request(client_id)
    return {
        "schema": "emulebb.docker-ed2k-source-publisher.callback-result/1",
        "status": "completed",
        "commandId": f"callback-{client}",
        "runId": "fixture-run",
        "targetClientId": client_id,
        "targetLabel": client,
        "requestOpcode": ed2k_wire.OP_CALLBACKREQUEST,
        "requestPayloadHex": payload.hex().upper(),
        "requestTranscript": {
            "direction": "send",
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": ed2k_wire.OP_CALLBACKREQUEST,
            "payloadLength": len(payload),
            "payloadSha256": hashlib.sha256(payload).hexdigest(),
            "payloadHex": payload.hex(),
        },
        "callbackConnection": {
            "userHash": (bytes([user_hash_byte]) * 16).hex().upper(),
            "clientId": 0,
            "tcpPort": tcp_port,
            "peerHost": "198.18.240.1",
            "peerPort": 50000 + client_id,
        },
    }


def passing_report(
    *,
    rust_records: list[dict[str, Any]] | None = None,
    mfc_records: list[dict[str, Any]] | None = None,
    rust_result: dict[str, object] | None = None,
) -> dict[str, Any]:
    targets = {
        "rust": target(7, 4662, 0x11),
        "mfc": target(9, 4663, 0x22),
    }
    return evidence.build_server_callback_diagnostic_evidence(
        server_endpoint=SERVER_ENDPOINT,
        requester_host=REQUESTER_HOST,
        requester_port=REQUESTER_PORT,
        targets=targets,
        requester_results={
            "rust": rust_result or requester_result("rust", 7, 4662, 0x11),
            "mfc": requester_result("mfc", 9, 4663, 0x22),
        },
        rust_records=rust_records or [packet(10, 1), applied(11, 1)],
        mfc_records=mfc_records or [packet(20, 2), applied(21, 2)],
    )


@pytest.mark.unit
def test_bilateral_callback_reply_and_connect_are_claimable() -> None:
    report = passing_report()

    evidence.require_server_callback_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "server.reply.callback"
    ]
    assert report["expectedReplyPayloadHex"] == REPLY_PAYLOAD.hex().upper()
    assert report["clients"]["rust"]["target"]["clientId"] == 7
    assert report["clients"]["mfc"]["target"]["clientId"] == 9


@pytest.mark.unit
def test_callback_application_must_follow_reply_on_same_trace() -> None:
    report = passing_report(rust_records=[packet(10, 1), applied(11, 2)])

    assert report["ok"] is False
    assert "client.rust" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_duplicate_callback_reply_is_ambiguous() -> None:
    report = passing_report(
        mfc_records=[packet(20, 2), packet(21, 2), applied(22, 2)]
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["wire"]["packetCount"] == 2


@pytest.mark.unit
def test_callback_connection_must_match_target_login_identity() -> None:
    wrong = requester_result("rust", 7, 4662, 0x11)
    wrong["callbackConnection"] = {
        **wrong["callbackConnection"],  # type: ignore[dict-item]
        "userHash": "FF" * 16,
    }
    report = passing_report(rust_result=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["requester"]["ok"] is False


@pytest.mark.unit
def test_malformed_callback_payload_cannot_claim_coverage() -> None:
    report = passing_report(rust_records=[packet(10, 1, b"\x01" * 5), applied(11, 1)])

    assert report["ok"] is False
    assert report["clients"]["rust"]["wire"]["ok"] is False
