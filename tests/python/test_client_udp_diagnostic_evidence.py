from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from emule_test_harness import client_udp_diagnostic_evidence as evidence
from emule_test_harness import protocol_evidence_registration as registration


FILE_HASH = bytes.fromhex("44556677889900112233AABBCCDDEEFF")
PART_COUNT = 1
QUEUE_RANK = 1
REQUEST_RAW = (
    bytes((evidence.OP_EMULEPROT, evidence.OP_REASKFILEPING))
    + FILE_HASH
    + bytes.fromhex("010000")
    + bytes.fromhex("0100")
)
ACK_RAW = bytes((evidence.OP_EMULEPROT, evidence.OP_REASKACK, 0, 0, QUEUE_RANK, 0))
QUEUE_FULL_RAW = bytes((evidence.OP_EMULEPROT, evidence.OP_QUEUEFULL))
FILE_NOT_FOUND_RAW = bytes((evidence.OP_EMULEPROT, evidence.OP_FILENOTFOUND))
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


def authoritative_builds() -> dict[str, Any]:
    """Return the strict build provenance required by client-UDP registration."""

    def receipt(command: list[str], source_revision: str) -> dict[str, Any]:
        return {
            "schema": registration.build_provenance.BUILD_RECEIPT_SCHEMA,
            "command": command,
            "returnCode": 0,
            "sourceRevision": source_revision,
            "sourceCleanBefore": True,
            "sourceCleanAfter": True,
            "orchestratorRevision": "8" * 40,
            "orchestratorCleanBefore": True,
            "orchestratorCleanAfter": True,
        }

    return {
        "runner": {"sourceRevision": "1" * 40, "sourceClean": True},
        "mfcDiagnostics": {
            "sha256": "2" * 64,
            "build": receipt(
                registration.soak_build_refresh.diagnostics_build_command(
                    "mfc", clean=True
                ),
                "3" * 40,
            ),
        },
        "rustDiagnostics": {
            "sha256": "4" * 64,
            "build": receipt(
                registration.soak_build_refresh.diagnostics_build_command(
                    "rust", clean=True
                ),
                "5" * 40,
            ),
        },
        "ed2kServer": {
            "sha256": "6" * 64,
            "build": receipt(
                registration.rust_ed2k.server_build_command(clean=True),
                "7" * 40,
            ),
        },
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
                "shouldCrypt": False,
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
                "rawLen": len(REQUEST_RAW),
                "payloadHex": REQUEST_RAW[2:].hex(),
                "payloadLen": len(REQUEST_RAW) - 2,
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
                "rawLen": len(ACK_RAW),
                "payloadHex": ACK_RAW[2:].hex(),
                "payloadLen": len(ACK_RAW) - 2,
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
                "rawLen": len(REQUEST_RAW),
                "payloadHex": REQUEST_RAW[2:].hex(),
                "payloadLen": len(REQUEST_RAW) - 2,
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
                "rawLen": len(ACK_RAW),
                "payloadHex": ACK_RAW[2:].hex(),
                "payloadLen": len(ACK_RAW) - 2,
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


def encrypted_transition(requester: str) -> evidence.ClientUdpV4Transition:
    original = transition(requester)
    requester_rows = copy.deepcopy(list(original.requester_records))
    responder_rows = copy.deepcopy(list(original.responder_records))
    requester_rows[0]["body"]["shouldCrypt"] = True
    seed = 0x11 if requester == "rust" else 0x22
    request_wire = bytes((0x01,)) + bytes((seed,)) * 7 + REQUEST_RAW
    ack_wire = bytes((0x03,)) + bytes((seed ^ 0xFF,)) * 7 + ACK_RAW

    def mark_obfuscated(record: dict[str, Any], wire: bytes) -> None:
        body = record["body"]
        body["transportMode"] = "obfuscated"
        body["obfuscated"] = True
        body["rawHex"] = wire.hex()
        body["rawLen"] = len(wire)

    mark_obfuscated(requester_rows[3], request_wire)
    mark_obfuscated(requester_rows[5], ack_wire)
    mark_obfuscated(responder_rows[0], request_wire)
    mark_obfuscated(responder_rows[1], ack_wire)
    return evidence.ClientUdpV4Transition(
        **{
            **original.__dict__,
            "requester_records": requester_rows,
            "responder_records": responder_rows,
        }
    )


def queue_full_requester_records(requester: str) -> list[dict[str, Any]]:
    records = requester_records(requester)
    endpoints = ENDPOINTS[requester]
    records[-2] = {
        "schema": "diag_event_v2",
        "seq": 6,
        "family": "ed2k_client_udp",
        "event": "packet",
        "keys": {
            "peer": endpoints["sourceUdp"],
            "protocolMarker": evidence.OP_EMULEPROT,
            "opcode": evidence.OP_QUEUEFULL,
        },
        "body": {
            "direction": "recv",
            "outcome": "accepted",
            "phase": "reask_reply",
            "transportMode": "plaintext",
            "obfuscated": False,
            "rawHex": QUEUE_FULL_RAW.hex(),
            "payloadHexTruncated": False,
        },
    }
    records[-1] = sched_record(
        7,
        "udp_reask_reply_applied",
        {
            "replyOpcode": evidence.OP_QUEUEFULL,
            "queueRank": 0,
            "requestPendingAfter": False,
            "remoteQueueFullAfter": True,
            "sourceUdpEndpoint": endpoints["sourceUdp"],
            "sourceUdpVersion": 4,
            "queueRankApplied": True,
            "partStatusIncluded": False,
            "wirePartCount": None,
            "partStatusApplied": False,
            "partCountAfter": None,
            "availablePartsAfter": None,
            "partStatusBitsAfter": None,
            "noNeededPartsAfter": None,
            "udpTotalAfter": 1 if requester == "rust" else 2,
            "udpFailedAfter": 0,
            "nextReaskScheduled": True,
            "sourceRetainedAfter": True,
            "outcome": "applied",
        },
        requester=requester,
    )
    return records


def queue_pressure(requester: str) -> dict[str, object]:
    requester_udp = str(ENDPOINTS[requester]["requesterUdp"])
    host, raw_port = requester_udp.split(":")
    fixture_id = 31 if requester == "rust" else 32
    return {
        "request": {
            "fileHash": FILE_HASH.hex(),
            "sourceIp": host,
            "sourceUdpPort": int(raw_port),
        },
        "response": {
            "status": 200,
            "json": {
                "accepted": True,
                "fixtureId": fixture_id,
                "fileHash": FILE_HASH.hex(),
                "sourceEndpoint": requester_udp,
                "actualWaitingUserCount": 0,
                "effectiveWaitingUserCount": 1951,
                "queueSize": 2000,
                "expiresAfterMillis": 30000,
                "state": "client-udp-queue-pressure-armed",
            },
        },
    }


def waiter_removal(requester: str) -> dict[str, object]:
    host, _raw_port = str(ENDPOINTS[requester]["requesterUdp"]).split(":")
    return {
        "waiter": {
            "clientId": f"{requester}-waiting-client",
            "address": host,
            "requestedFileHash": FILE_HASH.hex(),
            "waitingQueue": True,
        },
        "response": {
            "status": 200,
            "json": {"ok": True, "removed": "queue"},
        },
        "verifiedAbsent": True,
    }


def queue_full_responder_records(requester: str) -> list[dict[str, Any]]:
    requester_endpoint = str(ENDPOINTS[requester]["requesterUdp"])
    fixture_id = 31 if requester == "rust" else 32
    responder = "mfc" if requester == "rust" else "rust"
    request_sequence = 20
    fixture_sequence = 19 if responder == "mfc" else 21
    return [
        {
            "schema": "diag_event_v2",
            "seq": request_sequence,
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
            "seq": fixture_sequence,
            "family": "sched",
            "event": "client_udp_queue_pressure_fixture_consumed",
            "keys": {
                "fileHash": FILE_HASH.hex(),
                "peer": requester_endpoint,
            },
            "body": {
                "outcome": "consumed",
                "fixtureId": fixture_id,
                "actualWaitingUserCount": 0,
                "effectiveWaitingUserCount": 1951,
                "queueSize": 2000,
                "queueFullMargin": 50,
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 22,
            "family": "ed2k_client_udp",
            "event": "packet",
            "keys": {
                "peer": requester_endpoint,
                "protocolMarker": evidence.OP_EMULEPROT,
                "opcode": evidence.OP_QUEUEFULL,
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
                "rawHex": QUEUE_FULL_RAW.hex(),
                "payloadHexTruncated": False,
            },
        },
        {
            "schema": "diag_event_v2",
            "seq": 23,
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


def queue_full_transition(requester: str) -> evidence.ClientUdpQueueFullTransition:
    endpoints = ENDPOINTS[requester]
    responder = "mfc" if requester == "rust" else "rust"
    return evidence.ClientUdpQueueFullTransition(
        requester=requester,
        responder=responder,
        source_tcp_endpoint=str(endpoints["sourceTcp"]),
        source_udp_endpoint=str(endpoints["sourceUdp"]),
        source_user_hash=endpoints["sourceHash"],
        requester_udp_endpoint=str(endpoints["requesterUdp"]),
        control_receipt=control(requester),
        waiter_removal_receipt=waiter_removal(requester),
        queue_pressure_receipt=queue_pressure(requester),
        requester_records=queue_full_requester_records(requester),
        responder_records=queue_full_responder_records(requester),
    )


def passing_queue_full_report(
    *,
    rust_transition: evidence.ClientUdpQueueFullTransition | None = None,
    stock_record: object = STOCK_RECORD,
) -> dict[str, Any]:
    return evidence.build_client_udp_queue_full_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=stock_record,
        transitions=[
            rust_transition or queue_full_transition("rust"),
            queue_full_transition("mfc"),
        ],
    )


def file_not_found_requester_records(requester: str) -> list[dict[str, Any]]:
    records = requester_records(requester)
    endpoints = ENDPOINTS[requester]
    records[-2] = {
        "schema": "diag_event_v2",
        "seq": 6,
        "family": "ed2k_client_udp",
        "event": "packet",
        "keys": {
            "peer": endpoints["sourceUdp"],
            "protocolMarker": evidence.OP_EMULEPROT,
            "opcode": evidence.OP_FILENOTFOUND,
        },
        "body": {
            "direction": "recv",
            "outcome": "accepted",
            "phase": "reask_reply",
            "transportMode": "plaintext",
            "obfuscated": False,
            "rawHex": FILE_NOT_FOUND_RAW.hex(),
            "payloadHexTruncated": False,
        },
    }
    records[-1] = sched_record(
        7,
        "udp_reask_reply_applied",
        {
            "replyOpcode": evidence.OP_FILENOTFOUND,
            "requestPendingAfter": False,
            "remoteQueueFullAfter": False,
            "sourceUdpEndpoint": endpoints["sourceUdp"],
            "sourceUdpVersion": 4,
            "queueRankApplied": False,
            "partStatusIncluded": False,
            "wirePartCount": None,
            "partStatusApplied": False,
            "partCountAfter": None,
            "availablePartsAfter": None,
            "partStatusBitsAfter": None,
            "noNeededPartsAfter": None,
            "outcome": "applied",
        },
        requester=requester,
    )
    records.extend(
        [
            sched_record(
                8,
                "source_dead_listed",
                {
                    "outcome": "dead_listed",
                    "reason": "udp_fnf",
                    "blockSecs": 2700,
                },
                requester=requester,
            ),
            sched_record(
                9,
                "source_dropped",
                {"outcome": "dropped"},
                requester=requester,
            ),
        ]
    )
    return records


def file_not_found_responder_records(requester: str) -> list[dict[str, Any]]:
    requester_endpoint = str(ENDPOINTS[requester]["requesterUdp"])
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
                "opcode": evidence.OP_FILENOTFOUND,
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
                "rawHex": FILE_NOT_FOUND_RAW.hex(),
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


def shared_withdrawal(*, method: str) -> dict[str, object]:
    receipt: dict[str, object] = {
        "fileHash": FILE_HASH.hex(),
        "method": method,
        "fixturePath": "C:/campaign/fixture/client-udp-v4.bin",
        "presentBefore": True,
        "reloadResponse": {"status": 200, "json": {"ok": True}},
        "absentAfter": True,
    }
    if method == "file-move":
        receipt["movedToPath"] = "C:/campaign/withdrawn/client-udp-v4.bin"
    elif method == "shared-roots-cleared":
        receipt["sharedDirectories"] = {
            "request": {"roots": [], "confirmReplaceRoots": True},
            "response": {"status": 200, "json": {"roots": []}},
        }
    else:
        raise ValueError(f"unsupported test withdrawal method: {method}")
    return receipt


def source_absence(requester: str) -> dict[str, object]:
    endpoints = ENDPOINTS[requester]
    return {
        "fileHash": FILE_HASH.hex(),
        "sourceTcpEndpoint": endpoints["sourceTcp"],
        "sourceUserHash": endpoints["sourceHash"].hex(),
        "verifiedAbsent": True,
    }


def file_not_found_transition(
    requester: str,
) -> evidence.ClientUdpFileNotFoundTransition:
    endpoints = ENDPOINTS[requester]
    responder = "mfc" if requester == "rust" else "rust"
    return evidence.ClientUdpFileNotFoundTransition(
        requester=requester,
        responder=responder,
        source_tcp_endpoint=str(endpoints["sourceTcp"]),
        source_udp_endpoint=str(endpoints["sourceUdp"]),
        source_user_hash=endpoints["sourceHash"],
        requester_udp_endpoint=str(endpoints["requesterUdp"]),
        control_receipt=control(requester),
        shared_withdrawal_receipt=shared_withdrawal(
            method=("file-move" if requester == "rust" else "shared-roots-cleared")
        ),
        source_absence_receipt=source_absence(requester),
        requester_records=file_not_found_requester_records(requester),
        responder_records=file_not_found_responder_records(requester),
    )


def passing_file_not_found_report(
    *,
    rust_transition: evidence.ClientUdpFileNotFoundTransition | None = None,
    stock_record: object = STOCK_RECORD,
) -> dict[str, Any]:
    return evidence.build_client_udp_file_not_found_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=stock_record,
        transitions=[
            rust_transition or file_not_found_transition("rust"),
            file_not_found_transition("mfc"),
        ],
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


def passing_clear_report(
    *,
    rust_transition: evidence.ClientUdpV4Transition | None = None,
    stock_record: object = STOCK_RECORD,
) -> dict[str, Any]:
    return evidence.build_client_udp_clear_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=stock_record,
        transitions=[rust_transition or transition("rust"), transition("mfc")],
    )


def passing_encrypted_report(
    *,
    rust_transition: evidence.ClientUdpV4Transition | None = None,
    stock_record: object = STOCK_RECORD,
) -> dict[str, Any]:
    return evidence.build_client_udp_encrypted_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=stock_record,
        transitions=[
            rust_transition or encrypted_transition("rust"),
            encrypted_transition("mfc"),
        ],
    )


def immutable_campaign_report(
    tmp_path: Path,
    *,
    scenario: str = "v4",
) -> tuple[Path, Path, dict[str, Any]]:
    assert scenario in {"v4", "clear", "encrypted"}
    output_root = tmp_path / "output"
    run_dir = (
        output_root
        / "artifacts"
        / "emulebb-rust-reask-cross-client"
        / "20261102T123752Z-emulebb-main-release-100"
    )
    fixture_path = run_dir / "fixture" / f"client-udp-{scenario}.bin"
    fixture_path.parent.mkdir(parents=True)
    fixture_path.write_bytes(b"fixture")
    transitions = (
        [encrypted_transition("rust"), encrypted_transition("mfc")]
        if scenario == "encrypted"
        else [transition("rust"), transition("mfc")]
    )
    diagnostics = (
        evidence.build_client_udp_encrypted_diagnostic_evidence(
            file_hash=FILE_HASH,
            part_count=PART_COUNT,
            stock_record=STOCK_RECORD,
            transitions=transitions,
        )
        if scenario == "encrypted"
        else evidence.build_client_udp_clear_diagnostic_evidence(
            file_hash=FILE_HASH,
            part_count=PART_COUNT,
            stock_record=STOCK_RECORD,
            transitions=transitions,
        )
        if scenario == "clear"
        else evidence.build_client_udp_v4_diagnostic_evidence(
            file_hash=FILE_HASH,
            part_count=PART_COUNT,
            stock_record=STOCK_RECORD,
            transitions=transitions,
        )
    )
    rust = diagnostics["clients"]["rust"]
    mfc = diagnostics["clients"]["mfc"]
    report = {
        "schema": f"emulebb-build-tests.client-udp-{scenario}-campaign.v1",
        "suite": "emulebb-rust-reask-cross-client",
        "scenario": scenario,
        "coverageId": f"client-udp.{scenario}",
        "status": "passed",
        "currentPhase": "complete",
        "network": {
            "publicTraffic": False,
            "transportMode": "obfuscated" if scenario == "encrypted" else "plaintext",
        },
        "fixture": {
            "path": str(fixture_path),
            "sizeBytes": fixture_path.stat().st_size,
            "partCount": 1,
        },
        "builds": authoritative_builds(),
        "checks": {
            "rustRequesterMfcResponder": {
                "fileHash": FILE_HASH.hex(),
                "control": {
                    "request": rust["control"]["request"],
                    "response": rust["control"]["response"],
                },
                "applicationSequence": rust["diagnostics"]["requesterSequences"][
                    "applied"
                ],
                "capacity": {
                    "baseSlots": 2,
                    "elasticSlots": 0,
                    "effectiveSlotCap": 2,
                    "activeSlots": 2,
                },
                "publication": {
                    "clientName": "mfc-responder",
                    "address": (
                        "127.0.0.10" if scenario == "encrypted" else "192.0.2.1"
                    ),
                    "highId": True,
                    "sharedFiles": 1,
                },
                "rustHighIdClients": [
                    {
                        "clientName": f"rust-{index}",
                        "address": (
                            "127.0.0.20"
                            if scenario == "encrypted" and index == 2
                            else f"192.0.2.{index + 2}"
                        ),
                        "highId": True,
                        "sharedFiles": 0,
                    }
                    for index in range(3)
                ],
                "registration": {
                    "fileHash": FILE_HASH.hex(),
                    "sourceTcpEndpoint": rust["sourceTcpEndpoint"],
                    "sourceUdpEndpoint": rust["sourceUdpEndpoint"],
                    "sourceUserHash": rust["sourceUserHash"],
                    "sourceUdpVersion": 4,
                },
            },
            "mfcRequesterRustResponder": {
                "fileHash": FILE_HASH.hex(),
                "control": {
                    "request": mfc["control"]["request"],
                    "response": mfc["control"]["response"],
                },
                "applicationSequence": mfc["diagnostics"]["requesterSequences"][
                    "applied"
                ],
                "publication": {
                    "clientName": "rust-responder",
                    "address": (
                        "127.0.0.30" if scenario == "encrypted" else "192.0.2.10"
                    ),
                    "highId": True,
                    "sharedFiles": 1,
                },
                "occupierHighIdClient": {
                    "clientName": "rust-occupier",
                    "address": "192.0.2.11",
                    "highId": True,
                    "sharedFiles": 0,
                },
                "mfcHighIdClient": {
                    "clientName": "mfc-requester",
                    "address": (
                        "127.0.0.40" if scenario == "encrypted" else "192.0.2.12"
                    ),
                    "highId": True,
                    "sharedFiles": 0,
                },
                "occupiedSlot": {
                    "fileHash": FILE_HASH.hex(),
                    "slotOpenedSequence": 10,
                    "policy": {
                        "baseSlots": 1,
                        "elasticSlots": 0,
                        "effectiveSlotCap": 1,
                    },
                },
                "queueSource": {
                    "queueRank": QUEUE_RANK,
                    "sourceIp": "127.0.0.30",
                    "sourceTcpPort": 4862,
                    "sourceUserHash": mfc["sourceUserHash"],
                },
            },
        },
        "evidence": diagnostics,
    }
    if scenario in {"clear", "encrypted"}:
        raw_path = run_dir / f"client-udp-{scenario}-raw-evidence.json"
        raw_payload = {
            "schema": (
                evidence.ENCRYPTED_RAW_EVIDENCE_SCHEMA
                if scenario == "encrypted"
                else evidence.CLEAR_RAW_EVIDENCE_SCHEMA
            ),
            "scenario": scenario,
            "fileHash": FILE_HASH.hex(),
            "partCount": PART_COUNT,
            "transitions": [
                {
                    "requester": item.requester,
                    "responder": item.responder,
                    "sourceTcpEndpoint": item.source_tcp_endpoint,
                    "sourceUdpEndpoint": item.source_udp_endpoint,
                    "sourceUserHash": item.source_user_hash.hex(),
                    "requesterUdpEndpoint": item.requester_udp_endpoint,
                    "controlReceipt": item.control_receipt,
                    "requesterRecords": list(item.requester_records),
                    "responderRecords": list(item.responder_records),
                }
                for item in transitions
            ],
        }
        raw_path.write_text(json.dumps(raw_payload, indent=2), encoding="utf-8")
        report["rawEvidence"] = {
            "path": str(raw_path),
            "sizeBytes": raw_path.stat().st_size,
            "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        }
    report_path = run_dir / "emulebb-rust-reask-cross-client-result.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_root, report_path, report


def immutable_queue_full_campaign_report(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    output_root = tmp_path / "output"
    run_dir = (
        output_root
        / "artifacts"
        / "emulebb-rust-reask-cross-client"
        / "20261102T150409Z-emulebb-main-release-16096"
    )
    fixture_path = run_dir / "fixture" / "client-udp-queue-full.bin"
    fixture_path.parent.mkdir(parents=True)
    fixture_path.write_bytes(b"fixture")
    diagnostics = passing_queue_full_report()
    rust = diagnostics["clients"]["rust"]
    mfc = diagnostics["clients"]["mfc"]

    def raw_receipt(client: dict[str, Any], field: str) -> dict[str, Any]:
        return {key: value for key, value in client[field].items() if key != "ok"}

    report = {
        "schema": "emulebb-build-tests.client-udp-queue-full-campaign.v1",
        "suite": "emulebb-rust-reask-cross-client",
        "scenario": "queue-full",
        "coverageId": "client-udp.queue-full",
        "status": "passed",
        "currentPhase": "complete",
        "network": {"publicTraffic": False, "transportMode": "plaintext"},
        "fixture": {
            "path": str(fixture_path),
            "sizeBytes": fixture_path.stat().st_size,
            "partCount": 1,
        },
        "builds": authoritative_builds(),
        "checks": {
            "rustRequesterMfcResponder": {
                "fileHash": FILE_HASH.hex(),
                "control": raw_receipt(rust, "control"),
                "waiterRemoval": raw_receipt(rust, "waiterRemoval"),
                "queuePressure": {
                    "request": rust["queuePressure"]["request"],
                    "response": rust["queuePressure"]["response"],
                },
                "applicationSequence": rust["diagnostics"]["requesterSequences"][
                    "applied"
                ],
                "capacity": {
                    "baseSlots": 2,
                    "elasticSlots": 0,
                    "effectiveSlotCap": 2,
                    "activeSlots": 2,
                },
                "publication": {
                    "clientName": "mfc-responder",
                    "address": "192.0.2.1",
                    "highId": True,
                    "sharedFiles": 1,
                },
                "rustHighIdClients": [
                    {
                        "clientName": f"rust-{index}",
                        "address": f"192.0.2.{index + 2}",
                        "highId": True,
                        "sharedFiles": 0,
                    }
                    for index in range(3)
                ],
                "registration": {
                    "fileHash": FILE_HASH.hex(),
                    "sourceTcpEndpoint": rust["sourceTcpEndpoint"],
                    "sourceUdpEndpoint": rust["sourceUdpEndpoint"],
                    "sourceUserHash": rust["sourceUserHash"],
                    "sourceUdpVersion": 4,
                },
            },
            "mfcRequesterRustResponder": {
                "fileHash": FILE_HASH.hex(),
                "control": raw_receipt(mfc, "control"),
                "waiterRemoval": raw_receipt(mfc, "waiterRemoval"),
                "queuePressure": {
                    "request": mfc["queuePressure"]["request"],
                    "response": mfc["queuePressure"]["response"],
                },
                "applicationSequence": mfc["diagnostics"]["requesterSequences"][
                    "applied"
                ],
                "publication": {
                    "clientName": "rust-responder",
                    "address": "192.0.2.10",
                    "highId": True,
                    "sharedFiles": 1,
                },
                "occupierHighIdClient": {
                    "clientName": "rust-occupier",
                    "address": "192.0.2.11",
                    "highId": True,
                    "sharedFiles": 0,
                },
                "mfcHighIdClient": {
                    "clientName": "mfc-requester",
                    "address": "192.0.2.12",
                    "highId": True,
                    "sharedFiles": 0,
                },
                "occupiedSlot": {
                    "fileHash": FILE_HASH.hex(),
                    "slotOpenedSequence": 10,
                    "policy": {
                        "baseSlots": 1,
                        "elasticSlots": 0,
                        "effectiveSlotCap": 1,
                    },
                },
                "queueSource": {
                    "queueRank": 1,
                    "sourceIp": "127.0.0.30",
                    "sourceTcpPort": 4862,
                    "sourceUserHash": mfc["sourceUserHash"],
                },
            },
        },
        "evidence": diagnostics,
    }
    report_path = run_dir / "emulebb-rust-reask-cross-client-result.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_root, report_path, report


def immutable_file_not_found_campaign_report(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    output_root = tmp_path / "output"
    run_dir = (
        output_root
        / "artifacts"
        / "emulebb-rust-reask-cross-client"
        / "20261102T171500Z-emulebb-main-release-20000"
    )
    fixture_path = run_dir / "fixture" / "client-udp-file-not-found.bin"
    fixture_path.parent.mkdir(parents=True)
    fixture_path.write_bytes(b"fixture")
    withdrawn_path = run_dir / "withdrawn" / fixture_path.name

    transitions = []
    for requester in ("rust", "mfc"):
        original = file_not_found_transition(requester)
        withdrawal = copy.deepcopy(original.shared_withdrawal_receipt)
        withdrawal["fixturePath"] = str(fixture_path.resolve())
        if withdrawal["method"] == "file-move":
            withdrawal["movedToPath"] = str(withdrawn_path.resolve())
        transitions.append(
            evidence.ClientUdpFileNotFoundTransition(
                **{
                    **original.__dict__,
                    "shared_withdrawal_receipt": withdrawal,
                }
            )
        )
    diagnostics = evidence.build_client_udp_file_not_found_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=STOCK_RECORD,
        transitions=transitions,
    )
    rust = diagnostics["clients"]["rust"]
    mfc = diagnostics["clients"]["mfc"]

    def raw_receipt(client: dict[str, Any], field: str) -> dict[str, Any]:
        return {key: value for key, value in client[field].items() if key != "ok"}

    report = {
        "schema": "emulebb-build-tests.client-udp-file-not-found-campaign.v1",
        "suite": "emulebb-rust-reask-cross-client",
        "scenario": "file-not-found",
        "coverageId": "client-udp.file-not-found",
        "status": "passed",
        "currentPhase": "complete",
        "network": {"publicTraffic": False, "transportMode": "plaintext"},
        "fixture": {
            "path": str(fixture_path),
            "sizeBytes": fixture_path.stat().st_size,
            "partCount": 1,
        },
        "builds": authoritative_builds(),
        "checks": {
            "rustRequesterMfcResponder": {
                "fileHash": FILE_HASH.hex(),
                "control": raw_receipt(rust, "control"),
                "sharedWithdrawal": raw_receipt(rust, "sharedWithdrawal"),
                "sourceAbsence": raw_receipt(rust, "sourceAbsence"),
                "applicationSequence": rust["diagnostics"]["requesterSequences"][
                    "applied"
                ],
                "deadListedSequence": rust["diagnostics"]["requesterSequences"][
                    "deadListed"
                ],
                "droppedSequence": rust["diagnostics"]["requesterSequences"]["dropped"],
                "capacity": {
                    "baseSlots": 2,
                    "elasticSlots": 0,
                    "effectiveSlotCap": 2,
                    "activeSlots": 2,
                },
                "publication": {
                    "clientName": "mfc-responder",
                    "address": "192.0.2.1",
                    "highId": True,
                    "sharedFiles": 1,
                },
                "rustHighIdClients": [
                    {
                        "clientName": f"rust-{index}",
                        "address": f"192.0.2.{index + 2}",
                        "highId": True,
                        "sharedFiles": 0,
                    }
                    for index in range(3)
                ],
                "registration": {
                    "fileHash": FILE_HASH.hex(),
                    "sourceTcpEndpoint": rust["sourceTcpEndpoint"],
                    "sourceUdpEndpoint": rust["sourceUdpEndpoint"],
                    "sourceUserHash": rust["sourceUserHash"],
                    "sourceUdpVersion": 4,
                },
            },
            "mfcRequesterRustResponder": {
                "fileHash": FILE_HASH.hex(),
                "control": raw_receipt(mfc, "control"),
                "sharedWithdrawal": raw_receipt(mfc, "sharedWithdrawal"),
                "sourceAbsence": raw_receipt(mfc, "sourceAbsence"),
                "applicationSequence": mfc["diagnostics"]["requesterSequences"][
                    "applied"
                ],
                "deadListedSequence": mfc["diagnostics"]["requesterSequences"][
                    "deadListed"
                ],
                "droppedSequence": mfc["diagnostics"]["requesterSequences"]["dropped"],
                "publication": {
                    "clientName": "rust-responder",
                    "address": "192.0.2.10",
                    "highId": True,
                    "sharedFiles": 1,
                },
                "occupierHighIdClient": {
                    "clientName": "rust-occupier",
                    "address": "192.0.2.11",
                    "highId": True,
                    "sharedFiles": 0,
                },
                "mfcHighIdClient": {
                    "clientName": "mfc-requester",
                    "address": "192.0.2.12",
                    "highId": True,
                    "sharedFiles": 0,
                },
                "occupiedSlot": {
                    "fileHash": FILE_HASH.hex(),
                    "slotOpenedSequence": 10,
                    "policy": {
                        "baseSlots": 1,
                        "elasticSlots": 0,
                        "effectiveSlotCap": 1,
                    },
                },
                "queueSource": {
                    "queueRank": 1,
                    "sourceIp": "127.0.0.30",
                    "sourceTcpPort": 4862,
                    "sourceUserHash": mfc["sourceUserHash"],
                },
            },
        },
        "evidence": diagnostics,
    }
    report_path = run_dir / "emulebb-rust-reask-cross-client-result.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_root, report_path, report


@pytest.mark.unit
def test_bilateral_client_udp_v4_is_claimable() -> None:
    report = passing_report()

    evidence.require_client_udp_v4_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["client-udp.v4"]
    assert report["stockAuthority"]["ok"] is True
    assert report["comparison"]["requestBytesEqual"] is True
    assert report["comparison"]["ackBytesEqual"] is True
    assert (
        report["clients"]["rust"]["wire"]["request"]["partStatus"]["partStatusBits"]
        == "0"
    )


@pytest.mark.unit
def test_bilateral_client_udp_clear_is_claimable() -> None:
    report = passing_clear_report()

    evidence.require_client_udp_clear_diagnostic_evidence(report)
    assert report["schema"] == evidence.CLEAR_SCHEMA
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["client-udp.clear"]
    assert report["clients"]["rust"]["clearTransport"] == {
        "registrationShouldCrypt": False,
        "requestOut": {"transportMode": "plaintext", "obfuscated": False},
        "requestIn": {"transportMode": "plaintext", "obfuscated": False},
        "ackOut": {"transportMode": "plaintext", "obfuscated": False},
        "ackIn": {"transportMode": "plaintext", "obfuscated": False},
        "ok": True,
    }


@pytest.mark.unit
def test_bilateral_client_udp_encrypted_is_claimable() -> None:
    report = passing_encrypted_report()

    evidence.require_client_udp_encrypted_diagnostic_evidence(report)
    assert report["schema"] == evidence.ENCRYPTED_SCHEMA
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["client-udp.encrypted"]
    transport = report["clients"]["rust"]["encryptedTransport"]
    assert transport["registrationShouldCrypt"] is True
    assert transport["requestWireBytesEqual"] is True
    assert transport["ackWireBytesEqual"] is True
    assert transport["requestOut"]["overheadBytes"] == 8
    assert transport["requestOut"]["clearFrameHex"] == REQUEST_RAW.hex()
    assert transport["ackOut"]["clearFrameHex"] == ACK_RAW.hex()


@pytest.mark.unit
def test_encrypted_requires_true_registered_crypt_decision() -> None:
    original = encrypted_transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    records[0]["body"]["shouldCrypt"] = False
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_encrypted_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["encryptedTransport"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("plaintext", False),
        ("bad-overhead", False),
        ("reserved-marker", False),
        ("changed-in-flight", False),
    ],
)
def test_encrypted_rejects_invalid_wire_evidence(
    mutation: str,
    expected: bool,
) -> None:
    original = encrypted_transition("rust")
    requester_rows = copy.deepcopy(list(original.requester_records))
    responder_rows = copy.deepcopy(list(original.responder_records))
    if mutation == "plaintext":
        requester_rows[3]["body"].update(
            {
                "transportMode": "plaintext",
                "obfuscated": False,
                "rawHex": REQUEST_RAW.hex(),
                "rawLen": len(REQUEST_RAW),
            }
        )
    elif mutation == "bad-overhead":
        raw = bytes.fromhex(requester_rows[3]["body"]["rawHex"])[1:]
        requester_rows[3]["body"]["rawHex"] = raw.hex()
        requester_rows[3]["body"]["rawLen"] = len(raw)
    elif mutation == "reserved-marker":
        raw = bytearray.fromhex(requester_rows[3]["body"]["rawHex"])
        raw[0] = evidence.OP_EMULEPROT
        requester_rows[3]["body"]["rawHex"] = raw.hex()
    elif mutation == "changed-in-flight":
        raw = bytearray.fromhex(responder_rows[0]["body"]["rawHex"])
        raw[1] ^= 0xFF
        responder_rows[0]["body"]["rawHex"] = raw.hex()
    wrong = evidence.ClientUdpV4Transition(
        **{
            **original.__dict__,
            "requester_records": requester_rows,
            "responder_records": responder_rows,
        }
    )

    report = passing_encrypted_report(rust_transition=wrong)

    assert report["ok"] is expected
    assert report["clients"]["rust"]["encryptedTransport"]["ok"] is expected
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_clear_allows_prior_noneligible_scheduler_observation() -> None:
    original = transition("mfc")
    records = copy.deepcopy(list(original.requester_records))
    for record in records[1:]:
        record["seq"] += 1
    records.insert(
        1,
        sched_record(
            2,
            "udp_reask_schedule_decision",
            {
                "outcome": "skipped",
                "reason": "reask_window_not_open",
                "timeUntilReaskMs": 1_738_922,
            },
            requester="mfc",
        ),
    )
    mfc_transition = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )
    report = evidence.build_client_udp_clear_diagnostic_evidence(
        file_hash=FILE_HASH,
        part_count=PART_COUNT,
        stock_record=STOCK_RECORD,
        transitions=[transition("rust"), mfc_transition],
    )

    evidence.require_client_udp_clear_diagnostic_evidence(report)
    assert report["clients"]["mfc"]["diagnostics"]["counts"]["schedule"] == 1
    assert (
        report["clients"]["mfc"]["diagnostics"]["requesterSequences"]["schedule"] == 3
    )


@pytest.mark.unit
@pytest.mark.parametrize("should_crypt", [None, True])
def test_clear_requires_false_registered_crypt_decision(
    should_crypt: bool | None,
) -> None:
    original = transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    if should_crypt is None:
        records[0]["body"].pop("shouldCrypt")
    else:
        records[0]["body"]["shouldCrypt"] = should_crypt
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_clear_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["registration"] == 1
    assert report["clients"]["rust"]["clearTransport"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_clear_rejects_obfuscated_packet_evidence() -> None:
    original = transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    records[3]["body"]["transportMode"] = "obfuscated"
    records[3]["body"]["obfuscated"] = True
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_clear_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["requestOut"] == 1
    assert report["clients"]["rust"]["clearTransport"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_clear_rejects_contradictory_registered_crypt_decision() -> None:
    original = transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    contradictory = copy.deepcopy(records[0])
    contradictory["seq"] = 8
    contradictory["body"]["shouldCrypt"] = True
    records.append(contradictory)
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_clear_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["registration"] == 2
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_clear_rejects_contradictory_obfuscated_packet() -> None:
    original = transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    contradictory = copy.deepcopy(records[3])
    contradictory["seq"] = 8
    contradictory["body"]["transportMode"] = "obfuscated"
    contradictory["body"]["obfuscated"] = True
    records.append(contradictory)
    wrong = evidence.ClientUdpV4Transition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_clear_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["requestOut"] == 2
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_bilateral_client_udp_queue_full_is_claimable() -> None:
    report = passing_queue_full_report()

    evidence.require_client_udp_queue_full_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["client-udp.queue-full"]
    assert report["stockAuthority"]["ok"] is True
    assert report["comparison"] == {
        "requestBytesEqual": True,
        "queueFullBytesEqual": True,
        "applicationEqual": True,
        "bothApplied": True,
        "ok": True,
    }
    assert report["clients"]["rust"]["wire"]["queueFull"] == {
        "ok": True,
        "rawHex": "c593",
        "payloadLength": 0,
    }
    assert (
        report["clients"]["rust"]["diagnostics"]["responderSequences"][
            "fixtureConsumed"
        ]
        < report["clients"]["rust"]["diagnostics"]["responderSequences"]["requestIn"]
    )


@pytest.mark.unit
def test_queue_full_requires_real_waiter_removal() -> None:
    original = queue_full_transition("rust")
    receipt = copy.deepcopy(original.waiter_removal_receipt)
    receipt["response"]["json"]["removed"] = "none"
    wrong = evidence.ClientUdpQueueFullTransition(
        **{**original.__dict__, "waiter_removal_receipt": receipt}
    )

    report = passing_queue_full_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["waiterRemoval"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_queue_full_requires_waiter_absence_after_removal() -> None:
    original = queue_full_transition("rust")
    receipt = copy.deepcopy(original.waiter_removal_receipt)
    receipt["verifiedAbsent"] = False
    wrong = evidence.ClientUdpQueueFullTransition(
        **{**original.__dict__, "waiter_removal_receipt": receipt}
    )

    report = passing_queue_full_report(rust_transition=wrong)

    assert report["ok"] is False
    waiter = report["clients"]["rust"]["waiterRemoval"]
    assert waiter["ok"] is False
    assert waiter["verifiedAbsent"] is False


@pytest.mark.unit
def test_queue_full_requires_exact_pressure_consumption() -> None:
    original = queue_full_transition("rust")
    records = copy.deepcopy(list(original.responder_records))
    records[1]["body"]["fixtureId"] = 999
    wrong = evidence.ClientUdpQueueFullTransition(
        **{**original.__dict__, "responder_records": records}
    )

    report = passing_queue_full_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["fixtureConsumed"] == 0


@pytest.mark.unit
def test_queue_full_rejects_alternate_reply_opcode() -> None:
    original = queue_full_transition("rust")
    records = copy.deepcopy(list(original.responder_records))
    records[2]["keys"]["opcode"] = evidence.OP_REASKACK
    wrong = evidence.ClientUdpQueueFullTransition(
        **{**original.__dict__, "responder_records": records}
    )

    report = passing_queue_full_report(rust_transition=wrong)

    assert report["ok"] is False
    counts = report["clients"]["rust"]["diagnostics"]["counts"]
    assert counts["queueFullOut"] == 0
    assert counts["forbiddenResponderReply"] == 1


@pytest.mark.unit
def test_queue_full_application_must_retain_healthy_source() -> None:
    original = queue_full_transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    records[-1]["body"]["sourceRetainedAfter"] = False
    wrong = evidence.ClientUdpQueueFullTransition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_queue_full_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["applied"] == 0


@pytest.mark.unit
def test_bilateral_client_udp_file_not_found_is_claimable() -> None:
    report = passing_file_not_found_report()

    evidence.require_client_udp_file_not_found_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "client-udp.file-not-found"
    ]
    assert report["stockAuthority"]["ok"] is True
    assert report["comparison"] == {
        "requestBytesEqual": True,
        "fileNotFoundBytesEqual": True,
        "applicationEqual": True,
        "deadListEqual": True,
        "bothDropped": True,
        "ok": True,
    }
    assert report["clients"]["rust"]["wire"]["fileNotFound"] == {
        "ok": True,
        "rawHex": "c592",
        "payloadLength": 0,
    }


@pytest.mark.unit
def test_file_not_found_requires_exact_shared_withdrawal() -> None:
    original = file_not_found_transition("rust")
    receipt = copy.deepcopy(original.shared_withdrawal_receipt)
    receipt["absentAfter"] = False
    wrong = evidence.ClientUdpFileNotFoundTransition(
        **{**original.__dict__, "shared_withdrawal_receipt": receipt}
    )

    report = passing_file_not_found_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sharedWithdrawal"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.unit
def test_file_not_found_rejects_alternate_reply_opcode() -> None:
    original = file_not_found_transition("rust")
    records = copy.deepcopy(list(original.responder_records))
    records[1]["keys"]["opcode"] = evidence.OP_REASKACK
    records[1]["body"]["rawHex"] = ACK_RAW.hex()
    wrong = evidence.ClientUdpFileNotFoundTransition(
        **{**original.__dict__, "responder_records": records}
    )

    report = passing_file_not_found_report(rust_transition=wrong)

    assert report["ok"] is False
    counts = report["clients"]["rust"]["diagnostics"]["counts"]
    assert counts["fileNotFoundOut"] == 0
    assert counts["forbiddenResponderReply"] == 1


@pytest.mark.unit
def test_file_not_found_requires_exact_dead_list_semantics() -> None:
    original = file_not_found_transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    records[-2]["body"]["blockSecs"] = 2699
    wrong = evidence.ClientUdpFileNotFoundTransition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_file_not_found_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["deadListed"] == 0


@pytest.mark.unit
def test_file_not_found_application_omits_queue_rank() -> None:
    original = file_not_found_transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    records[-3]["body"]["queueRank"] = None
    wrong = evidence.ClientUdpFileNotFoundTransition(
        **{**original.__dict__, "requester_records": records}
    )

    report = passing_file_not_found_report(rust_transition=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["diagnostics"]["counts"]["applied"] == 0


@pytest.mark.unit
def test_file_not_found_requires_source_removal_without_swap() -> None:
    original = file_not_found_transition("rust")
    records = copy.deepcopy(list(original.requester_records))
    records[-1]["event"] = "source_swapped"
    records[-1]["body"] = {"outcome": "swapped"}
    absence = copy.deepcopy(original.source_absence_receipt)
    absence["verifiedAbsent"] = False
    wrong = evidence.ClientUdpFileNotFoundTransition(
        **{
            **original.__dict__,
            "requester_records": records,
            "source_absence_receipt": absence,
        }
    )

    report = passing_file_not_found_report(rust_transition=wrong)

    assert report["ok"] is False
    client = report["clients"]["rust"]
    assert client["sourceAbsence"]["ok"] is False
    assert client["diagnostics"]["counts"]["dropped"] == 0
    assert client["diagnostics"]["counts"]["forbiddenSwap"] == 1


@pytest.mark.unit
def test_immutable_client_udp_v4_campaign_builds_catalog_registration(
    tmp_path: Path,
) -> None:
    output_root, report_path, _report = immutable_campaign_report(tmp_path)

    result = registration.build_client_udp_registration(
        report_path,
        scenario="v4",
        output_root=output_root,
    )

    receipt = result["evidenceReceipt"]
    assert receipt["coverageIds"] == ["client-udp.v4"]
    assert receipt["runnerPath"] == "scripts/emulebb-rust-reask-cross-client.py"
    assert [subject["authorityId"] for subject in receipt["subjects"]] == [
        "mfc-oracle",
        "rust-product",
        "ed2k-server-dependency",
    ]
    assert result["coverageEvidence"][0]["verdict"] == "parity"


@pytest.mark.unit
def test_immutable_clear_campaign_builds_exact_catalog_registration(
    tmp_path: Path,
) -> None:
    output_root, report_path, _report = immutable_campaign_report(
        tmp_path,
        scenario="clear",
    )

    result = registration.build_client_udp_registration(
        report_path,
        scenario="clear",
        output_root=output_root,
    )

    receipt = result["evidenceReceipt"]
    assert receipt["receiptId"] == "rust-mfc-client-udp-clear-20261102t123752z"
    assert receipt["coverageIds"] == ["client-udp.clear"]
    assert result["coverageEvidence"] == [
        {
            "coverageId": "client-udp.clear",
            "evidenceLayers": [
                "codec-transcript",
                "deterministic-state-machine",
                "local-cross-client",
            ],
            "reason": (
                "Rust and MFC each selected the non-crypt client-UDP path, emitted "
                "the same clear OP_EMULEPROT reask and ACK bytes, and causally "
                "applied the same queue-rank and complete-source state."
            ),
            "receiptIds": ["rust-mfc-client-udp-clear-20261102t123752z"],
            "verdict": "parity",
        }
    ]


@pytest.mark.unit
def test_immutable_encrypted_campaign_builds_exact_catalog_registration(
    tmp_path: Path,
) -> None:
    output_root, report_path, _report = immutable_campaign_report(
        tmp_path,
        scenario="encrypted",
    )

    result = registration.build_client_udp_registration(
        report_path,
        scenario="encrypted",
        output_root=output_root,
    )

    receipt = result["evidenceReceipt"]
    assert receipt["receiptId"] == "rust-mfc-client-udp-encrypted-20261102t123752z"
    assert receipt["coverageIds"] == ["client-udp.encrypted"]
    assert result["coverageEvidence"] == [
        {
            "coverageId": "client-udp.encrypted",
            "evidenceLayers": [
                "codec-transcript",
                "deterministic-state-machine",
                "local-cross-client",
            ],
            "reason": (
                "Rust and MFC each selected the crypt client-UDP path, exchanged "
                "stock eight-byte obfuscated envelopes around identical clear V4 "
                "reask and ACK frames, and causally applied the same queue state."
            ),
            "receiptIds": ["rust-mfc-client-udp-encrypted-20261102t123752z"],
            "verdict": "parity",
        }
    ]


@pytest.mark.unit
def test_encrypted_registration_rereduces_hashed_raw_diagnostics(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(
        tmp_path,
        scenario="encrypted",
    )
    raw_path = Path(report["rawEvidence"]["path"])
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["transitions"][0]["requesterRecords"][0]["body"]["shouldCrypt"] = False
    raw_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    report["rawEvidence"]["sizeBytes"] = raw_path.stat().st_size
    report["rawEvidence"]["sha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="raw client-UDP encrypted diagnostics"):
        registration.build_client_udp_registration(
            report_path,
            scenario="encrypted",
            output_root=output_root,
        )


@pytest.mark.unit
def test_encrypted_registration_rejects_high_id_wire_address_mismatch(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(
        tmp_path,
        scenario="encrypted",
    )
    report["checks"]["mfcRequesterRustResponder"]["mfcHighIdClient"]["address"] = (
        "192.0.2.99"
    )
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="MFC requester HighID"):
        registration.build_client_udp_registration(
            report_path,
            scenario="encrypted",
            output_root=output_root,
        )


@pytest.mark.unit
def test_clear_registration_rejects_tampered_transport_decision(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(
        tmp_path,
        scenario="clear",
    )
    report["evidence"]["clients"]["rust"]["clearTransport"][
        "registrationShouldCrypt"
    ] = True
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"evidence differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="clear",
            output_root=output_root,
        )


@pytest.mark.unit
def test_clear_registration_rereduces_hashed_raw_diagnostics(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(
        tmp_path,
        scenario="clear",
    )
    raw_path = Path(report["rawEvidence"]["path"])
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["transitions"][0]["requesterRecords"][0]["body"]["shouldCrypt"] = True
    raw_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    report["rawEvidence"]["sizeBytes"] = raw_path.stat().st_size
    report["rawEvidence"]["sha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="raw client-UDP clear diagnostics"):
        registration.build_client_udp_registration(
            report_path,
            scenario="clear",
            output_root=output_root,
        )


@pytest.mark.unit
def test_immutable_queue_full_campaign_builds_exact_catalog_registration(
    tmp_path: Path,
) -> None:
    output_root, report_path, _report = immutable_queue_full_campaign_report(tmp_path)

    result = registration.build_client_udp_registration(
        report_path,
        scenario="queue-full",
        output_root=output_root,
    )

    receipt = result["evidenceReceipt"]
    assert receipt["receiptId"] == ("rust-mfc-client-udp-queue-full-20261102t150409z")
    assert receipt["coverageIds"] == ["client-udp.queue-full"]
    assert receipt["runnerPath"] == "scripts/emulebb-rust-reask-cross-client.py"
    assert result["coverageEvidence"] == [
        {
            "coverageId": "client-udp.queue-full",
            "evidenceLayers": [
                "codec-transcript",
                "deterministic-state-machine",
                "local-cross-client",
            ],
            "reason": (
                "Rust and MFC each produced and applied the same clear zero-payload "
                "queue-full reply after exact real-waiter removal and one causally "
                "consumed stock queue-pressure prerequisite."
            ),
            "receiptIds": ["rust-mfc-client-udp-queue-full-20261102t150409z"],
            "verdict": "parity",
        }
    ]


@pytest.mark.unit
def test_queue_full_registration_rejects_tampered_fixture_order(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_queue_full_campaign_report(tmp_path)
    sequences = report["evidence"]["clients"]["rust"]["diagnostics"][
        "responderSequences"
    ]
    sequences["fixtureConsumed"] = sequences["queueFullOut"]
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="responder sequence is not causal"):
        registration.build_client_udp_registration(
            report_path,
            scenario="queue-full",
            output_root=output_root,
        )


@pytest.mark.unit
def test_queue_full_registration_rejects_unconfirmed_waiter_removal(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_queue_full_campaign_report(tmp_path)
    report["evidence"]["clients"]["mfc"]["waiterRemoval"]["verifiedAbsent"] = False
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"waiterRemoval differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="queue-full",
            output_root=output_root,
        )


@pytest.mark.unit
def test_queue_full_registration_rejects_failed_udp_application(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_queue_full_campaign_report(tmp_path)
    report["evidence"]["clients"]["rust"]["application"]["udpFailedAfter"] = 1
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"application differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="queue-full",
            output_root=output_root,
        )


@pytest.mark.unit
def test_immutable_file_not_found_campaign_builds_exact_catalog_registration(
    tmp_path: Path,
) -> None:
    output_root, report_path, _report = immutable_file_not_found_campaign_report(
        tmp_path
    )

    result = registration.build_client_udp_registration(
        report_path,
        scenario="file-not-found",
        output_root=output_root,
    )

    receipt = result["evidenceReceipt"]
    assert receipt["receiptId"] == (
        "rust-mfc-client-udp-file-not-found-20261102t171500z"
    )
    assert receipt["coverageIds"] == ["client-udp.file-not-found"]
    assert receipt["runnerPath"] == "scripts/emulebb-rust-reask-cross-client.py"
    assert result["coverageEvidence"] == [
        {
            "coverageId": "client-udp.file-not-found",
            "evidenceLayers": [
                "codec-transcript",
                "deterministic-state-machine",
                "local-cross-client",
            ],
            "reason": (
                "Rust and MFC each produced the same clear zero-payload file-not-found "
                "reply after exact shared-hash withdrawal, then causally applied it, "
                "dead-listed the source for 2700 seconds, and removed the source."
            ),
            "receiptIds": ["rust-mfc-client-udp-file-not-found-20261102t171500z"],
            "verdict": "parity",
        }
    ]


@pytest.mark.unit
def test_file_not_found_registration_rejects_unrestored_fixture_path(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_file_not_found_campaign_report(
        tmp_path
    )
    withdrawn_path = Path(
        report["checks"]["rustRequesterMfcResponder"]["sharedWithdrawal"]["movedToPath"]
    )
    withdrawn_path.parent.mkdir(parents=True)
    withdrawn_path.write_bytes(b"not-restored")

    with pytest.raises(ValueError, match="does not prove restoration"):
        registration.build_client_udp_registration(
            report_path,
            scenario="file-not-found",
            output_root=output_root,
        )


@pytest.mark.unit
def test_file_not_found_registration_rejects_tampered_dead_list(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_file_not_found_campaign_report(
        tmp_path
    )
    report["evidence"]["clients"]["mfc"]["deadList"]["blockSecs"] = 2699
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"deadList differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="file-not-found",
            output_root=output_root,
        )


@pytest.mark.unit
def test_file_not_found_registration_rejects_unconfirmed_source_absence(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_file_not_found_campaign_report(
        tmp_path
    )
    report["evidence"]["clients"]["rust"]["sourceAbsence"]["verifiedAbsent"] = False
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"sourceAbsence differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="file-not-found",
            output_root=output_root,
        )


@pytest.mark.unit
def test_client_udp_v4_registration_rejects_tampered_causal_order(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(tmp_path)
    sequences = report["evidence"]["clients"]["rust"]["diagnostics"][
        "requesterSequences"
    ]
    sequences["ackIn"] = sequences["requestTerminal"]
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="requester sequence is not causal"):
        registration.build_client_udp_registration(
            report_path,
            scenario="v4",
            output_root=output_root,
        )


@pytest.mark.unit
def test_client_udp_v4_registration_rejects_tampered_wire_bytes(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(tmp_path)
    report["evidence"]["clients"]["mfc"]["wire"]["request"]["rawHex"] = "c590"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"evidence\.clients\.mfc\.wire differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="v4",
            output_root=output_root,
        )


@pytest.mark.unit
def test_client_udp_v4_registration_requires_source_provenance(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(tmp_path)
    report["builds"]["mfcDiagnostics"]["build"].pop("sourceRevision")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"builds\.mfcDiagnostics\.build\.sourceRevision is malformed",
    ):
        registration.build_client_udp_registration(
            report_path,
            scenario="v4",
            output_root=output_root,
        )


@pytest.mark.unit
def test_client_udp_registration_rejects_noncanonical_build_command(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(tmp_path)
    report["builds"]["rustDiagnostics"]["build"]["command"].remove("--clean")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match=r"rustDiagnostics\.build\.command differs"):
        registration.build_client_udp_registration(
            report_path,
            scenario="v4",
            output_root=output_root,
        )


@pytest.mark.unit
def test_client_udp_registration_rejects_dirty_build_source(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(tmp_path)
    report["builds"]["mfcDiagnostics"]["build"]["sourceCleanAfter"] = False
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="sourceCleanAfter must be true"):
        registration.build_client_udp_registration(
            report_path,
            scenario="v4",
            output_root=output_root,
        )


@pytest.mark.unit
def test_client_udp_registration_requires_server_build_provenance(
    tmp_path: Path,
) -> None:
    output_root, report_path, report = immutable_campaign_report(tmp_path)
    report["builds"].pop("ed2kServer")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="builds.ed2kServer must be an object"):
        registration.build_client_udp_registration(
            report_path,
            scenario="v4",
            output_root=output_root,
        )


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
    assert report["clients"]["rust"]["diagnostics"]["counts"]["requestTerminal"] == 0


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
    assert report["clients"]["rust"]["diagnostics"]["ok"] is False


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
