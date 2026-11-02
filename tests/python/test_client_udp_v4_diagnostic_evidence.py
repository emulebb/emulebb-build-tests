from __future__ import annotations

import copy
from typing import Any

import pytest

from emule_test_harness import client_udp_v4_diagnostic_evidence as evidence


FILE_HASH = bytes.fromhex("44556677889900112233AABBCCDDEEFF")
PART_COUNT = 1
QUEUE_RANK = 1
REQUEST_RAW = (
    bytes((evidence.OP_EMULEPROT, evidence.OP_REASKFILEPING))
    + FILE_HASH
    + bytes.fromhex("010000")
    + bytes.fromhex("0100")
)
ACK_RAW = bytes(
    (evidence.OP_EMULEPROT, evidence.OP_REASKACK, 0, 0, QUEUE_RANK, 0)
)
STOCK_RECORD = {
    "coverageIds": [
        "client-udp.v1",
        "client-udp.v2",
        "client-udp.v3",
        "client-udp.v4",
        "client-udp.clear",
        "client-udp.encrypted",
        "client-udp.queue-full",
        "client-udp.file-not-found",
        "client-udp.unsolicited",
    ],
    "direction": "both",
    "fixtureBase64": (
        "xZAAAQIDBAUGBwgJCgsMDQ4PxZEBAMWSxZPFlAABAgMEBQYHCAkKCwwNDg8Q"
        "ERITFBUWFxgZGhscHR4fAgABAA=="
    ),
    "fixtureEncoding": "concatenated-client-udp-corpus",
    "fixtureLength": 64,
    "opcode": "MULTI",
    "opcodeName": "CLIENT_UDP_V1_V4_CORPUS",
    "payloadDigest": (
        "sha256:89468db8e028268f21598216f5949ae11c2b1c3e1370b151d3d7136e8fda812b"
    ),
    "protocol": "client_udp",
    "recordId": "stock.client-udp.corpus",
    "recordType": "udp-packet",
    "scenarioId": "stock.13.client-udp.v1",
    "transport": "udp",
}
ENDPOINTS = {
    "rust": {
        "sourceTcp": "127.0.0.10:4662",
        "sourceUdp": "127.0.0.10:4672",
        "sourceHash": bytes.fromhex("11223344556677889900AABBCCDDEEFF"),
        "requesterUdp": "127.0.0.20:4772",
    },
    "mfc": {
        "sourceTcp": "127.0.0.30:4862",
        "sourceUdp": "127.0.0.30:4872",
        "sourceHash": bytes.fromhex("FFEEDDCCBBAA00998877665544332211"),
        "requesterUdp": "127.0.0.40:4972",
    },
}


def sched_record(
    seq: int,
    event: str,
    body: dict[str, object],
    *,
    requester: str,
) -> dict[str, Any]:
    endpoints = ENDPOINTS[requester]
    return {
        "schema": "diag_event_v2",
        "seq": seq,
        "family": "sched",
        "event": event,
        "keys": {
            "peer": endpoints["sourceTcp"],
            "peerHash": endpoints["sourceHash"].hex(),
            "fileHash": FILE_HASH.hex(),
        },
        "body": body,
    }


def requester_records(requester: str) -> list[dict[str, Any]]:
    endpoints = ENDPOINTS[requester]
    return [
        sched_record(
            1,
            "udp_reask_source_registered",
            {
                "outcome": "accepted",
                "sourceUdpEndpoint": endpoints["sourceUdp"],
                "sourceUdpVersion": 4,
                "lowId": False,
                "buddyEndpoint": None,
                "buddyId": None,
            },
            requester=requester,
        ),
        sched_record(
            2,
            "udp_reask_schedule_decision",
            {"outcome": "eligible", "reason": "eligible"},
            requester=requester,
        ),
        sched_record(
            3,
            "udp_reask_decision",
            {
                "outcome": "sent",
                "transportEligible": True,
                "reason": "udp_reask_sent",
                "path": "direct",
            },
            requester=requester,
        ),
        {
            "schema": "diag_event_v2",
            "seq": 4,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": endpoints["sourceUdp"],
                "fileHash": FILE_HASH.hex(),
                "protocolMarker": evidence.OP_EMULEPROT,
                "opcode": evidence.OP_REASKFILEPING,
                "sendAttemptId": 9,
            },
            "body": {
                "direction": "send",
                "outcome": "attempted",
                "sendAttemptId": 9,
                "role": "reask_request",
                "phase": "reask_request",
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
                "peer": endpoints["sourceUdp"],
                "sendAttemptId": 9,
            },
            "body": {
                "sendAttemptId": 9,
                "outcome": "send_succeeded",
                "deliveryKnown": True,
                "role": "reask_request",
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 6,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": endpoints["sourceUdp"],
                "protocolMarker": evidence.OP_EMULEPROT,
                "opcode": evidence.OP_REASKACK,
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
                "replyOpcode": evidence.OP_REASKACK,
                "queueRank": QUEUE_RANK,
                "requestPendingAfter": False,
                "remoteQueueFullAfter": False,
                "sourceUdpEndpoint": endpoints["sourceUdp"],
                "sourceUdpVersion": 4,
                "queueRankApplied": True,
                "partStatusIncluded": True,
                "wirePartCount": 0,
                "partStatusApplied": True,
                "partCountAfter": PART_COUNT,
                "availablePartsAfter": PART_COUNT,
                "partStatusBitsAfter": "1",
                "noNeededPartsAfter": False,
                "outcome": "applied",
            },
            requester=requester,
        ),
    ]


def responder_records(requester: str) -> list[dict[str, Any]]:
    requester_endpoint = ENDPOINTS[requester]["requesterUdp"]
    return [
        {
            "schema": "diag_event_v2",
            "seq": 20,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": requester_endpoint,
                "protocolMarker": evidence.OP_EMULEPROT,
                "opcode": evidence.OP_REASKFILEPING,
            },
            "body": {
                "direction": "recv",
                "outcome": "accepted",
                "phase": "reask_request",
                "transportMode": "plaintext",
                "obfuscated": False,
                "rawHex": REQUEST_RAW.hex(),
                "payloadHexTruncated": False,
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 21,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": requester_endpoint,
                "protocolMarker": evidence.OP_EMULEPROT,
                "opcode": evidence.OP_REASKACK,
                "sendAttemptId": 11,
            },
            "body": {
                "direction": "send",
                "outcome": "attempted",
                "sendAttemptId": 11,
                "role": "reciprocity_reply",
                "phase": "reciprocity_reply",
                "transportMode": "plaintext",
                "obfuscated": False,
                "rawHex": ACK_RAW.hex(),
                "payloadHexTruncated": False,
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 22,
            "family": "ed2k_client_udp",
            "event": "send_outcome",
            "keys": {
                "peer": requester_endpoint,
                "sendAttemptId": 11,
            },
            "body": {
                "sendAttemptId": 11,
                "outcome": "send_succeeded",
                "deliveryKnown": True,
                "role": "reciprocity_reply",
            },
        },
    ]


def control(requester: str) -> dict[str, object]:
    endpoints = ENDPOINTS[requester]
    host, tcp_port = str(endpoints["sourceTcp"]).split(":")
    _, udp_port = str(endpoints["sourceUdp"]).split(":")
    request = {
        "fileHash": FILE_HASH.hex(),
        "sourceIp": host,
        "sourceTcpPort": int(tcp_port),
        "sourceUdpPort": int(udp_port),
        "sourceUserHash": endpoints["sourceHash"].hex(),
        "sourceUdpVersion": 4,
    }
    return {
        "request": request,
        "response": {
            "status": 200,
            "json": {
                "accepted": True,
                "fileHash": FILE_HASH.hex(),
                "sourceEndpoint": endpoints["sourceUdp"],
                "sourceTcpPort": int(tcp_port),
                "sourceUserHash": endpoints["sourceHash"].hex(),
                "sourceUdpVersion": 4,
                "state": "queued-source-reask-pending",
            },
        },
    }


def transition(requester: str) -> evidence.ClientUdpV4Transition:
    endpoints = ENDPOINTS[requester]
    responder = "mfc" if requester == "rust" else "rust"
    return evidence.ClientUdpV4Transition(
        requester=requester,
        responder=responder,
        source_tcp_endpoint=str(endpoints["sourceTcp"]),
        source_udp_endpoint=str(endpoints["sourceUdp"]),
        source_user_hash=endpoints["sourceHash"],
        requester_udp_endpoint=str(endpoints["requesterUdp"]),
        control_receipt=control(requester),
        requester_records=requester_records(requester),
        responder_records=responder_records(requester),
    )


def passing_report(
    *,
    rust_transition: evidence.ClientUdpV4Transition | None = None,
    stock_record: object = STOCK_RECORD,
) -> dict[str, Any]:
    return evidence.build_client_udp_v4_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=stock_record,
        transitions=[rust_transition or transition("rust"), transition("mfc")],
    )


@pytest.mark.unit
def test_bilateral_client_udp_v4_is_claimable() -> None:
    report = passing_report()

    evidence.require_client_udp_v4_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["client-udp.v4"]
    assert report["stockAuthority"]["ok"] is True
    assert report["comparison"]["requestBytesEqual"] is True
    assert report["comparison"]["ackBytesEqual"] is True
    assert report["clients"]["rust"]["wire"]["request"]["partStatus"][
        "partStatusBits"
    ] == "0"


@pytest.mark.unit
def test_request_terminal_must_join_the_exact_attempt() -> None:
    records = requester_records("rust")
    records[4]["keys"]["sendAttemptId"] = 10
    records[4]["body"]["sendAttemptId"] = 10
    original = transition("rust")
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"][
        "requestTerminal"
    ] == 0


@pytest.mark.unit
def test_responder_receive_must_match_the_exact_request_bytes() -> None:
    records = responder_records("rust")
    records[0]["body"]["rawHex"] = (REQUEST_RAW[:-1] + b"\x02").hex()
    original = transition("rust")
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "responder_records": records}
    )

    report = passing_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["wire"]["ok"] is False


@pytest.mark.unit
def test_reply_application_must_include_exact_v4_state() -> None:
    records = requester_records("rust")
    records[-1]["body"]["partStatusBitsAfter"] = "0"
    original = transition("rust")
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["applied"] == 0


@pytest.mark.unit
def test_duplicate_transition_is_evidence_incomplete() -> None:
    report = evidence.build_client_udp_v4_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=STOCK_RECORD,
        transitions=[transition("rust"), transition("rust"), transition("mfc")],
    )

    assert report["ok"] is False
    assert "transitionSet" in report["failures"]


@pytest.mark.unit
def test_stock_corpus_digest_must_match_the_accepted_record() -> None:
    wrong_stock = copy.deepcopy(STOCK_RECORD)
    wrong_stock["fixtureBase64"] = wrong_stock["fixtureBase64"][:-4] + "AAAA"

    report = passing_report(stock_record=wrong_stock)

    assert report["ok"] is False
    assert report["stockAuthority"]["ok"] is False
    assert "stockAuthority" in report["failures"]
