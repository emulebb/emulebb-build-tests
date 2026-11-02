from __future__ import annotations

from typing import Any

import pytest

from emule_test_harness import relayed_reask_diagnostic_evidence as evidence
from emule_test_harness import relayed_reask_probe


FILE_HASH = bytes.fromhex("44556677889900112233AABBCCDDEEFF")
SOURCE_HASH = bytes.fromhex("527496B8DAFC1E30527496B8DAFC7E10")
BUDDY_ID = bytes.fromhex("6385A7C9EB0D2F416385A7C9EB0D8F21")
HOST = "127.0.0.1"
SOURCE_TCP_PORT = 31001
SOURCE_UDP_PORT = 31002
BUDDY_UDP_PORT = 31003
REQUESTER_PORTS = {"rust": 31004, "mfc": 31005}
QUEUE_RANK = 37
REQUEST_RAW = (
    bytes((relayed_reask_probe.OP_EMULEPROT, relayed_reask_probe.OP_REASKCALLBACKUDP))
    + BUDDY_ID
    + FILE_HASH
    + bytes.fromhex("0100000000")
)
ACK_RAW = relayed_reask_probe.encode_reask_ack(
    queue_rank=QUEUE_RANK,
    requester_udp_version=4,
)


def control() -> dict[str, object]:
    request = {
        "fileHash": FILE_HASH.hex(),
        "sourceIp": HOST,
        "sourceTcpPort": SOURCE_TCP_PORT,
        "sourceUdpPort": SOURCE_UDP_PORT,
        "sourceUserHash": SOURCE_HASH.hex(),
        "sourceUdpVersion": 4,
        "buddyIp": HOST,
        "buddyUdpPort": BUDDY_UDP_PORT,
        "buddyId": BUDDY_ID.hex(),
    }
    return {
        "request": request,
        "response": {
            "status": 200,
            "json": {
                "accepted": True,
                "fileHash": FILE_HASH.hex(),
                "sourceEndpoint": f"{HOST}:{SOURCE_UDP_PORT}",
                "sourceTcpPort": SOURCE_TCP_PORT,
                "sourceUserHash": SOURCE_HASH.hex(),
                "sourceUdpVersion": 4,
                "buddyEndpoint": f"{HOST}:{BUDDY_UDP_PORT}",
                "buddyId": BUDDY_ID.hex(),
                "state": "queued-lowid-source",
            },
        },
    }


def probe(client: str) -> dict[str, object]:
    decoded = relayed_reask_probe.decode_reask_callback_udp(
        REQUEST_RAW,
        source_udp_version=4,
    )
    return {
        "schema": "emulebb.relayed-reask-probe/1",
        "status": "completed",
        "targetLabel": client,
        "buddyEndpoint": f"{HOST}:{BUDDY_UDP_PORT}",
        "sourceEndpoint": f"{HOST}:{SOURCE_UDP_PORT}",
        "requesterEndpoint": f"{HOST}:{REQUESTER_PORTS[client]}",
        "request": {**decoded, "receivedAt": 1000.0},
        "response": {
            "protocol": relayed_reask_probe.OP_EMULEPROT,
            "opcode": relayed_reask_probe.OP_REASKACK,
            "rawHex": ACK_RAW.hex().upper(),
            "payloadHex": ACK_RAW[2:].hex().upper(),
            "queueRank": QUEUE_RANK,
            "sentBytes": len(ACK_RAW),
            "sentAt": 1000.1,
        },
    }


def sched_record(seq: int, event: str, body: dict[str, object]) -> dict[str, Any]:
    return {
        "schema": "diag_event_v2",
        "seq": seq,
        "family": "sched",
        "event": event,
        "keys": {
            "peer": f"{HOST}:{SOURCE_TCP_PORT}",
            "peerHash": SOURCE_HASH.hex(),
            "fileHash": FILE_HASH.hex(),
        },
        "body": body,
    }


def records() -> list[dict[str, Any]]:
    return [
        sched_record(
            1,
            "udp_reask_source_registered",
            {
                "outcome": "accepted",
                "sourceUdpEndpoint": f"{HOST}:{SOURCE_UDP_PORT}",
                "sourceUdpVersion": 4,
                "lowId": True,
                "buddyEndpoint": f"{HOST}:{BUDDY_UDP_PORT}",
                "buddyId": BUDDY_ID.hex(),
            },
        ),
        sched_record(
            2,
            "udp_reask_schedule_decision",
            {"outcome": "eligible", "reason": "eligible"},
        ),
        sched_record(
            3,
            "udp_reask_decision",
            {
                "outcome": "sent",
                "transportEligible": True,
                "reason": "callback_reask_sent",
                "path": "callback",
            },
        ),
        {
            "schema": "diag_event_v2",
            "seq": 4,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": f"{HOST}:{BUDDY_UDP_PORT}",
                "fileHash": FILE_HASH.hex(),
                "protocolMarker": relayed_reask_probe.OP_EMULEPROT,
                "opcode": relayed_reask_probe.OP_REASKCALLBACKUDP,
                "sendAttemptId": 9,
            },
            "body": {
                "direction": "send",
                "outcome": "attempted",
                "sendAttemptId": 9,
                "role": "buddy_relay_request",
                "transportMode": "plaintext",
                "obfuscated": False,
                "rawHex": REQUEST_RAW.hex(),
                "payloadHexTruncated": False,
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 5,
            "family": "ed2k_client_udp",
            "event": "send_outcome",
            "keys": {
                "peer": f"{HOST}:{BUDDY_UDP_PORT}",
                "sendAttemptId": 9,
            },
            "body": {
                "sendAttemptId": 9,
                "outcome": "send_succeeded",
                "deliveryKnown": True,
                "role": "buddy_relay_request",
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 6,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": f"{HOST}:{SOURCE_UDP_PORT}",
                "protocolMarker": relayed_reask_probe.OP_EMULEPROT,
                "opcode": relayed_reask_probe.OP_REASKACK,
            },
            "body": {
                "direction": "recv",
                "outcome": "accepted",
                "phase": "reask_reply",
                "transportMode": "plaintext",
                "obfuscated": False,
                "rawHex": ACK_RAW.hex(),
                "payloadHexTruncated": False,
            },
        },
        sched_record(
            7,
            "udp_reask_reply_applied",
            {
                "outcome": "applied",
                "replyOpcode": relayed_reask_probe.OP_REASKACK,
                "queueRank": QUEUE_RANK,
                "requestPendingAfter": False,
                "remoteQueueFullAfter": False,
            },
        ),
    ]


def passing_report(
    *,
    rust_records: list[dict[str, Any]] | None = None,
    rust_probe: dict[str, object] | None = None,
) -> dict[str, Any]:
    return evidence.build_relayed_reask_diagnostic_evidence(
        file_hash=FILE_HASH,
        source_host=HOST,
        source_tcp_port=SOURCE_TCP_PORT,
        source_udp_port=SOURCE_UDP_PORT,
        source_user_hash=SOURCE_HASH,
        source_udp_version=4,
        buddy_host=HOST,
        buddy_udp_port=BUDDY_UDP_PORT,
        buddy_id=BUDDY_ID,
        requester_udp_ports=REQUESTER_PORTS,
        queue_rank=QUEUE_RANK,
        controls={"rust": control(), "mfc": control()},
        probe_results={"rust": rust_probe or probe("rust"), "mfc": probe("mfc")},
        rust_records=rust_records or records(),
        mfc_records=records(),
    )


@pytest.mark.unit
def test_bilateral_relayed_reask_is_claimable() -> None:
    report = passing_report()

    evidence.require_relayed_reask_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["lowid.relayed-reask"]
    assert report["comparison"]["requestBytesEqual"] is True
    assert report["clients"]["rust"]["diagnostics"]["sendAttemptId"] == 9


@pytest.mark.unit
def test_terminal_send_must_join_exact_attempt() -> None:
    wrong = records()
    wrong[4]["keys"]["sendAttemptId"] = 10
    wrong[4]["body"]["sendAttemptId"] = 10

    report = passing_report(rust_records=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["sendOutcome"] == 0


@pytest.mark.unit
def test_reply_application_must_carry_exact_queue_rank() -> None:
    wrong = records()
    wrong[-1]["body"]["queueRank"] = QUEUE_RANK + 1

    report = passing_report(rust_records=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["applied"] == 0


@pytest.mark.unit
def test_probe_request_bytes_must_match_bilateral_wire() -> None:
    wrong = probe("rust")
    wrong["request"] = {**wrong["request"], "rawHex": REQUEST_RAW[:-1].hex().upper()}

    report = passing_report(rust_probe=wrong)

    assert report["ok"] is False
    assert "client.rust" in report["failures"]
