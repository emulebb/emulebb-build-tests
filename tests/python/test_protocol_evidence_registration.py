from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import struct

import pytest

from emule_test_harness import direct_callback_diagnostic_evidence
from emule_test_harness import direct_callback_probe
from emule_test_harness import ed2k_wire
from emule_test_harness import docker_ed2k_source_publisher
from emule_test_harness import ed2k_protocol_cases
from emule_test_harness import kad_nodes
from emule_test_harness import relayed_reask_diagnostic_evidence
from emule_test_harness import relayed_reask_probe
from emule_test_harness import server_callback_diagnostic_evidence
from emule_test_harness import server_search_diagnostic_evidence
from emule_test_harness import server_source_diagnostic_evidence
from emule_test_harness import server_tcp_metadata_diagnostic_evidence
from emule_test_harness import server_udp_metadata_diagnostic_evidence
from emule_test_harness import server_udp_source_diagnostic_evidence
from emule_test_harness import scripted_ed2k_udp_source
from emule_test_harness.diag_event_schema import DIAG_EVENT_SCHEMA
from emule_test_harness.protocol_evidence_registration import (
    build_transfer_registration,
)
from emule_test_harness.transfer_diagnostic_evidence import EVIDENCE_LAYERS, SCHEMA

FILE_HASH = "00112233445566778899aabbccddeeff"
SEARCH_FILE_HASH = "ffeeddccbbaa99887766554433221100"
SEARCH_FILE_NAME = "deterministicparitysearch-result.bin"
SEARCH_FILE_SIZE = 12_345
SEARCH_QUERY = "deterministicparitysearch"
SERVER_METADATA_SEED_NAME = "seed-before-server-ident"
SERVER_IDENT_NAME = "emulebb-local-e2e"
SERVER_IDENT_DESCRIPTION = "Workspace deterministic eMuleBB live E2E server"
SERVER_UDP_METADATA_FILE_HASH = "11223344556677889900AABBCCDDEEFF"
SERVER_UDP_METADATA_FILE_NAME = "deterministic-udp-metadata-file.bin"
SERVER_UDP_METADATA_FILE_SIZE = 54_321
SERVER_UDP_METADATA_PUBLISHER_NICK = "emulebb-harness-udp-metadata-publisher"
SERVER_SOURCE_FILE_HASH = "22334455667788990011aabbccddeeff"
SERVER_SOURCE_FILE_NAME = "deterministic-server-source.bin"
SERVER_SOURCE_FILE_SIZE = 67_890
SERVER_SOURCE_PUBLISHER_NICK = "emulebb-harness-source-publisher"
SERVER_SOURCE_PUBLISHER_HASH = bytes.fromhex("32547698BADCFE1021436587A9CBED0F")
SERVER_SOURCE_PUBLISHER_HOST = "198.18.240.2"
SERVER_SOURCE_PUBLISHER_ID = int.from_bytes(
    ipaddress.IPv4Address(SERVER_SOURCE_PUBLISHER_HOST).packed,
    "little",
)
SERVER_SOURCE_PUBLISHER_PORT = 48_017
SERVER_UDP_SOURCE_TARGET_HOST = "127.0.0.1"
RELAYED_REASK_FILE_HASH = bytes.fromhex("44556677889900112233AABBCCDDEEFF")
RELAYED_REASK_FILE_NAME = "deterministic-relayed-reask.bin"
RELAYED_REASK_FILE_SIZE = 34_567
RELAYED_REASK_SOURCE_HASH = bytes.fromhex("527496B8DAFC1E30527496B8DAFC7E10")
RELAYED_REASK_BUDDY_ID = bytes.fromhex("6385A7C9EB0D2F416385A7C9EB0D8F21")
RELAYED_REASK_QUEUE_RANK = 37
SERVER_UDP_SOURCE_TARGET_PORT = 4_761
SERVER_UDP_SOURCE_TARGET_UDP_PORT = SERVER_UDP_SOURCE_TARGET_PORT + 4
SERVER_CALLBACK_REQUESTER_HASH = bytes.fromhex("426486A8CAEC0E20426486A8CAEC6E00")
SERVER_CALLBACK_REQUESTER_NICK = "emulebb-harness-callback-requester"
SERVER_CALLBACK_FILE_HASH = bytes.fromhex("33445566778899001122AABBCCDDEEFF")
SERVER_CALLBACK_FILE_NAME = "deterministic-server-callback.bin"
SERVER_CALLBACK_FILE_SIZE = 23_456
SERVER_CALLBACK_REQUESTER_PORT = 48_018
SERVER_CALLBACK_RUN_ID = "c" * 32


def bilateral_login_evidence(
    transport_plan: tuple[str, ...] = ("plaintext",),
) -> dict[str, object]:
    fallback = len(transport_plan) == 2
    final_transport_mode = transport_plan[-1]

    def client_row(client: str) -> dict[str, object]:
        failed_attempt_login_count = 1 if fallback and client == "mfc" else 0
        failed_attempt_sequence = 1 if fallback else None
        final_attempt_sequence = 5 if fallback else 1
        login_sequence = 6 if fallback else 2
        return {
            "ok": True,
            "attemptStartCount": len(transport_plan),
            "attemptPhases": ["connection"] * len(transport_plan),
            "attemptStates": ["connecting"] * len(transport_plan),
            "attemptStartSequences": (
                [failed_attempt_sequence, final_attempt_sequence]
                if fallback
                else [final_attempt_sequence]
            ),
            "attemptTraceIds": [1, 2] if fallback else [2],
            "attemptPlanExact": True,
            "loginPacketCount": 1 + failed_attempt_login_count,
            "finalLoginPacketCount": 1,
            "failedAttemptLoginPacketCount": failed_attempt_login_count,
            "loginPacketOutcome": "attempted",
            "sendAttemptRecorded": True,
            "sendOutcomeRequired": client == "rust",
            "sendOutcomeObserved": client == "rust",
            "deliveryProven": True,
            "sendOutcomeSequence": (7 if fallback else 3) if client == "rust" else None,
            "sendOutcomeTraceId": 2 if client == "rust" else None,
            "sendOutcomeTransportMode": final_transport_mode
            if client == "rust"
            else None,
            "failedAttemptStartSequence": failed_attempt_sequence,
            "failedAttemptLoginSequence": 2 if fallback and client == "mfc" else None,
            "finalAttemptStartSequence": final_attempt_sequence,
            "loginSequence": login_sequence,
            "idChangeSequence": (8 if client == "rust" else 7)
            if fallback
            else (4 if client == "rust" else 3),
            "loginAcceptedSequence": (9 if client == "rust" else 8)
            if fallback
            else (5 if client == "rust" else 4),
            "loginAcceptedCount": 1,
            "connectionFailureSequence": 3 if fallback else None,
            "transportFallbackSequence": 4 if fallback else None,
            "connectionFailureCount": 1 if fallback else 0,
            "transportFallbackCount": 1 if fallback else 0,
            "failedAttemptTraceId": 1 if fallback else None,
            "failedAttemptLoginTraceId": 1 if fallback and client == "mfc" else None,
            "failedTraceId": 1 if fallback else None,
            "fallbackTraceId": 1 if fallback else None,
            "finalTraceId": 2,
            "finalAttemptTraceId": 2,
            "loginTraceId": 2,
            "idChangeTraceId": 2,
            "loginAcceptedTraceId": 2,
            "loginAcceptedPhase": "connection",
            "loginAcceptedState": "connected",
            "fallbackError": "crypt negotiation rejected" if fallback else None,
            "connectionFailurePhase": "connection" if fallback else None,
            "connectionFailureOutcome": "connection_failed" if fallback else None,
            "connectionFailureTransportMode": "obfuscated" if fallback else None,
            "failedAttemptLoginTransportMode": (
                "obfuscated" if fallback and client == "mfc" else None
            ),
            "failedAttemptLoginOutcome": (
                "attempted" if fallback and client == "mfc" else None
            ),
            "transportFallbackPhase": "connection" if fallback else None,
            "transportFallbackOutcome": "retrying" if fallback else None,
            "transportFallbackFromMode": "obfuscated" if fallback else None,
            "transportFallbackToMode": "plaintext" if fallback else None,
            "decodedLogin": {"client_id": 0},
            "decodedIdChange": {"id_kind": "low-id"},
            "extensionTags": {"offerfiles_v": 1} if client == "rust" else {},
            "semanticShape": True,
            "transportPlanExact": True,
            "traceCorrelation": True,
            "fallbackCausal": True,
            "transportObservation": {
                "attempts": list(transport_plan),
                "login": final_transport_mode,
                "idChange": final_transport_mode,
                "accepted": final_transport_mode,
            },
        }

    clients = {
        "rust": client_row("rust"),
        "mfc": client_row("mfc"),
    }
    connection_id = (
        "server.connect.fallback"
        if fallback
        else f"server.connect.{final_transport_mode}"
    )
    return {
        "schema": "emulebb-build-tests.deterministic-server-login-diagnostics",
        "ok": True,
        "serverEndpoint": "127.0.0.1:4661",
        "expectedTransportPlan": list(transport_plan),
        "expectedClients": {
            "rust": {"nickname": "rust-test", "tcpPort": 4662},
            "mfc": {"nickname": "mfc-test", "tcpPort": 4663},
        },
        "failures": [],
        "clients": clients,
        "comparison": {
            "bothAccepted": True,
            "versionEqual": True,
            "serverFlagsEqual": True,
            "udpPortsTagEqual": True,
            "idKindEqual": True,
            "transportPlanExact": True,
            "traceCorrelationExact": True,
            "fallbackSequenceExact": True,
            "ok": True,
        },
        "captures": {
            "rust": {"processId": 101, "selectedSegments": ["rust.jsonl"]},
            "mfc": {"processId": 202, "selectedSegments": ["mfc.jsonl"]},
        },
        "coverageClaims": {
            "eligibleCoverageIds": [
                connection_id,
                "server.login.request",
            ],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def server_protocol_case(transport_plan: tuple[str, ...]) -> dict[str, object]:
    fallback = len(transport_plan) == 2
    obfuscated = transport_plan == ("obfuscated",)
    return {
        "name": (
            "obfuscated-preferred-fallback"
            if fallback
            else "obfuscated-required"
            if obfuscated
            else "plain-server-plain-clients"
        ),
        "server_protocol_obfuscation": obfuscated,
        "client_crypt_supported": obfuscated or fallback,
        "client_crypt_requested": obfuscated or fallback,
        "client_crypt_required": obfuscated,
        "rust_server_metadata_mode": "endpoint-only" if fallback else "known",
    }


def attach_server_login(
    report: dict[str, object],
    login: dict[str, object],
    transport_plan: tuple[str, ...],
) -> None:
    report["transfer_scenario"] = "server-login-request"
    report["protocol_case"] = server_protocol_case(transport_plan)
    report["network"] = {
        "ed2k_server_address": "127.0.0.1",
        "ports": {"ed2k_tcp": 4661, "client1_tcp": 4662, "client2_tcp": 4663},
    }
    report["profiles"]["rust"]["nick"] = "rust-test"
    report["profiles"]["mfc"]["nick"] = "mfc-test"
    report["checks"]["client_server_login_diagnostics"] = login
    report["checks"]["rust_server_entry"] = (
        {
            "host": "127.0.0.1",
            "port": 4661,
            "name": "emulebb-local-e2e",
            "description": "test",
        }
        if len(transport_plan) == 2
        else {
            "host": "127.0.0.1",
            "port": 4661,
            "name": "emulebb-local-e2e",
            "description": "test",
            "udpFlags": 0,
            "udpKey": 0,
            "udpKeyIp": 0,
            "obfuscationPortTcp": 0,
            "obfuscationPortUdp": 0,
        }
    )
    report["diagnostics"]["serverLogin"] = login
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        login["coverageClaims"]["eligibleCoverageIds"]
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()


def server_search_contract(
    scenario: str,
) -> tuple[str, ed2k_wire.ServerSearchCriteria]:
    if scenario == "server-keyword-search":
        return (
            server_search_diagnostic_evidence.KEYWORD_VARIANT,
            ed2k_wire.ServerSearchCriteria(),
        )
    if scenario == "server-advanced-search":
        return (
            server_search_diagnostic_evidence.ADVANCED_VARIANT,
            ed2k_wire.ServerSearchCriteria(
                min_size_bytes=SEARCH_FILE_SIZE,
                max_size_bytes=SEARCH_FILE_SIZE,
            ),
        )
    raise AssertionError(f"unsupported test server-search scenario: {scenario}")


def driven_server_search(
    client: str,
    search_id: str,
    criteria: ed2k_wire.ServerSearchCriteria,
) -> dict[str, object]:
    result = {
        "hash": SEARCH_FILE_HASH.upper(),
        "sizeBytes": SEARCH_FILE_SIZE,
        "sources": 1,
        "completeSources": 1,
        "searchId": search_id,
    }
    result["displayName" if client == "rust" else "name"] = SEARCH_FILE_NAME
    created_method = (
        {"requestedMethod": "server"} if client == "rust" else {"method": "server"}
    )
    result_method = (
        {"requestedMethod": "server", "resolvedMethod": "server"}
        if client == "rust"
        else {"method": "server"}
    )
    return {
        "request": {
            "query": SEARCH_QUERY,
            "method": "server",
            "type": "",
            **(
                {"minSizeBytes": criteria.min_size_bytes}
                if criteria.min_size_bytes is not None
                else {}
            ),
            **(
                {"maxSizeBytes": criteria.max_size_bytes}
                if criteria.max_size_bytes is not None
                else {}
            ),
        },
        "searchId": search_id,
        "created": {
            "id": search_id,
            "query": SEARCH_QUERY,
            **created_method,
        },
        "search": {
            "id": search_id,
            "query": SEARCH_QUERY,
            **result_method,
            "status": "completed",
            "total": 1,
            "items": [result],
        },
        "result": result,
        "observations": [{"status": "completed", "resultCount": 1}],
    }


def bilateral_search_evidence(
    driven_searches: dict[str, dict[str, object]],
    *,
    variant: str,
    criteria: ed2k_wire.ServerSearchCriteria,
) -> dict[str, object]:
    coverage_ids = server_search_diagnostic_evidence.COVERAGE_IDS_BY_VARIANT[variant]
    payload_hex = ed2k_wire.encode_search_request(SEARCH_QUERY, criteria).hex()
    wire_result = {
        "hash": SEARCH_FILE_HASH.upper(),
        "name": SEARCH_FILE_NAME,
        "size": SEARCH_FILE_SIZE,
        "sources": 1,
        "complete_sources": 1,
        "result_source_id": 1,
        "result_source_port": 4664,
    }

    def client_row(client: str) -> dict[str, object]:
        rust = client == "rust"
        request_sequence = 20 if rust else 30
        reply_sequence = 23 if rust else 31
        search_id = str(driven_searches[client]["searchId"])
        driven_result = driven_searches[client]["result"]
        return {
            "ok": True,
            "rest": {
                "ok": True,
                "searchId": search_id,
                "status": "completed",
                "method": (
                    {
                        "createdRequested": "server",
                        "finalRequested": "server",
                        "finalResolved": "server",
                    }
                    if rust
                    else {"created": "server", "final": "server"}
                ),
                "total": 1,
                "exactResultCount": 1,
                "result": driven_result,
            },
            "wire": {
                "ok": True,
                "request": {
                    "ok": True,
                    "endpointRequestCount": 1,
                    "exactRequestCount": 1,
                    "sequence": request_sequence,
                    "traceId": 41 if rust else 42,
                    "sendAttemptId": 51 if rust else None,
                    "payloadHex": payload_hex,
                    "transportMode": "obfuscated",
                },
                "reply": {
                    "ok": True,
                    "endpointResponseCount": 1,
                    "traceResponseCount": 1,
                    "malformedResponseCount": 0,
                    "decodedRowCount": 1,
                    "exactRowCount": 1,
                    "exactRow": dict(wire_result),
                    "sequence": reply_sequence,
                    "transportMode": "obfuscated",
                },
            },
            "lifecycle": (
                {
                    "ok": True,
                    "sendOutcomeCount": 1,
                    "searchActiveCount": 1,
                    "completedCount": 1,
                    "schedulerCompletionCount": 1,
                    "searchActiveSequence": 19,
                    "sendOutcomeSequence": 21,
                    "completedSequence": 24,
                    "schedulerSequence": 25,
                }
                if rust
                else {
                    "ok": True,
                    "appliedCount": 1,
                    "appliedSequence": 32,
                    "expectedReply": True,
                    "wireResultCount": 1,
                    "cumulativeSourceCountBefore": 0,
                    "cumulativeSourceCountAfter": 1,
                    "distinctFileCountBefore": 0,
                    "distinctFileCountAfter": 1,
                    "moreResultsAvailable": False,
                    "outcome": "accepted",
                }
            ),
            "wireRestEqual": True,
        }

    return {
        "schema": server_search_diagnostic_evidence.SCHEMA,
        "ok": True,
        "variant": variant,
        "query": SEARCH_QUERY,
        "criteria": {
            **(
                {"minSizeBytes": criteria.min_size_bytes}
                if criteria.min_size_bytes is not None
                else {}
            ),
            **(
                {"maxSizeBytes": criteria.max_size_bytes}
                if criteria.max_size_bytes is not None
                else {}
            ),
        },
        "serverEndpoint": "127.0.0.1:4661",
        "expectedFile": {
            "hash": SEARCH_FILE_HASH,
            "name": SEARCH_FILE_NAME,
            "size": SEARCH_FILE_SIZE,
        },
        "failures": [],
        "clients": {
            "rust": client_row("rust"),
            "mfc": client_row("mfc"),
        },
        "comparison": {
            "ok": True,
            "requestPayloadEqual": True,
            "replyRowEqual": True,
            "restResultEqual": True,
            "transportModeEqual": True,
            "rustWireRestEqual": True,
            "mfcWireRestEqual": True,
        },
        "observedCoverageIds": list(coverage_ids),
        "coverageClaims": {
            "eligibleCoverageIds": list(coverage_ids),
            "evidenceLayers": list(server_search_diagnostic_evidence.EVIDENCE_LAYERS),
        },
        "captures": {
            "rust": {"processId": 101, "selectedSegments": ["rust.jsonl"]},
            "mfc": {"processId": 202, "selectedSegments": ["mfc.jsonl"]},
        },
    }


def attach_server_search(
    report: dict[str, object],
    scenario: str = "server-keyword-search",
) -> dict[str, object]:
    variant, criteria = server_search_contract(scenario)
    coverage_ids = server_search_diagnostic_evidence.COVERAGE_IDS_BY_VARIANT[variant]
    driven_searches = {
        "rust": driven_server_search("rust", "rust-search-1", criteria),
        "mfc": driven_server_search("mfc", "mfc-search-1", criteria),
    }
    evidence = bilateral_search_evidence(
        driven_searches,
        variant=variant,
        criteria=criteria,
    )
    report["transfer_scenario"] = scenario
    report["network"] = {
        "ed2k_server_address": "127.0.0.1",
        "ports": {"ed2k_tcp": 4661, "search_publisher_tcp": 4664},
    }
    report["server_search_fixture"] = {
        "hash": SEARCH_FILE_HASH,
        "name": SEARCH_FILE_NAME,
        "size": SEARCH_FILE_SIZE,
        "publisher": {
            "nickname": "search-fixture-publisher",
            "tcpPort": 4664,
            "login": {"assigned_id": 1, "id_kind": "low-id"},
        },
        "publication": {
            "hash": SEARCH_FILE_HASH.upper(),
            "indexed": True,
            "name": SEARCH_FILE_NAME,
            "requested_size": SEARCH_FILE_SIZE,
            "search_result": {
                "hash": SEARCH_FILE_HASH.upper(),
                "name": SEARCH_FILE_NAME,
                "result_source_id": 1,
                "result_source_port": 4664,
                "size": SEARCH_FILE_SIZE,
            },
            "search_source": {
                "id": 1,
                "kind": "low-id-search-reference",
                "port": 4664,
            },
            "size": SEARCH_FILE_SIZE,
        },
    }
    report["checks"]["client_server_searches"] = driven_searches
    report["checks"]["client_server_search_diagnostics"] = evidence
    report["diagnostics"]["serverSearch"] = evidence
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(coverage_ids)
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def bilateral_server_tcp_metadata_evidence() -> dict[str, object]:
    server_ident = {
        "server_hash": "00112233445566778899AABBCCDDEEFF",
        "advertised_ip": "192.0.2.10",
        "advertised_port": 4661,
        "name": SERVER_IDENT_NAME,
        "description": SERVER_IDENT_DESCRIPTION,
        "tags": [
            {"name": ed2k_wire.ST_SERVERNAME, "value": SERVER_IDENT_NAME},
            {"name": ed2k_wire.ST_DESCRIPTION, "value": SERVER_IDENT_DESCRIPTION},
        ],
    }

    def client_row(client: str, *, users: int, files: int) -> dict[str, object]:
        base = 10 if client == "rust" else 20
        return {
            "ok": True,
            "wire": {
                "ok": True,
                "traceId": 41 if client == "rust" else 42,
                "packetCounts": {
                    "idChange": 1,
                    "getServerList": 1,
                    "status": 1,
                    "ident": 1,
                },
                "sequences": {
                    "idChange": base,
                    "request": base + 1,
                    "status": base + 2,
                    "ident": base + 3,
                },
                "requestPayloadHex": "",
                "requestOutcome": "attempted" if client == "rust" else "send_succeeded",
                "transportModes": ["obfuscated"] * 4,
                "status": {"users": users, "files": files},
                "ident": dict(server_ident),
                "decodeErrors": [],
            },
            "applied": {
                "ok": True,
                "status": {
                    "ok": True,
                    "count": 1,
                    "sequence": base + 4,
                    "users": users,
                    "files": files,
                },
                "ident": {
                    "ok": True,
                    "count": 1,
                    "sequence": base + 5,
                    "name": SERVER_IDENT_NAME,
                    "description": SERVER_IDENT_DESCRIPTION,
                },
            },
            "rest": {
                "ok": True,
                "seedNameChanged": True,
                "connection": {
                    "connected": True,
                    "address": "127.0.0.1",
                    "port": 4661,
                },
                "server": {
                    "address": "127.0.0.1",
                    "port": 4661,
                    "name": SERVER_IDENT_NAME,
                    "description": SERVER_IDENT_DESCRIPTION,
                    "users": users,
                    "files": files,
                },
            },
        }

    return {
        "schema": server_tcp_metadata_diagnostic_evidence.SCHEMA,
        "ok": True,
        "serverEndpoint": "127.0.0.1:4661",
        "seedName": SERVER_METADATA_SEED_NAME,
        "expectedIdent": {
            "name": SERVER_IDENT_NAME,
            "description": SERVER_IDENT_DESCRIPTION,
        },
        "failures": [],
        "clients": {
            "rust": client_row("rust", users=2, files=1),
            "mfc": client_row("mfc", users=3, files=2),
        },
        "comparison": {
            "ok": True,
            "identEqual": True,
            "identMatchesExpected": True,
            "transportModeEqual": True,
        },
        "observedCoverageIds": list(
            server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
        ),
        "coverageClaims": {
            "eligibleCoverageIds": list(
                server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
            ),
            "evidenceLayers": list(
                server_tcp_metadata_diagnostic_evidence.EVIDENCE_LAYERS
            ),
        },
        "captures": {
            "rust": {"processId": 101, "selectedSegments": ["rust.jsonl"]},
            "mfc": {"processId": 202, "selectedSegments": ["mfc.jsonl"]},
        },
    }


def attach_server_tcp_metadata(report: dict[str, object]) -> dict[str, object]:
    evidence = bilateral_server_tcp_metadata_evidence()
    report["transfer_scenario"] = "server-tcp-metadata"
    report["checks"]["client_server_tcp_metadata_rest"] = {
        client: {
            "connectionStatus": {
                "connected": True,
                "currentServer": {
                    "current": True,
                    "address": "127.0.0.1",
                    "port": 4661,
                    "name": SERVER_METADATA_SEED_NAME,
                },
            },
            "serverEntity": dict(evidence["clients"][client]["rest"]["server"]),
        }
        for client in ("rust", "mfc")
    }
    report["checks"]["client_server_tcp_metadata_diagnostics"] = evidence
    report["diagnostics"]["serverTcpMetadata"] = evidence
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def _server_source_records(
    *,
    client: str,
    process_id: int,
    run_id: str,
    trace_id: int,
    transport_mode: str = "plaintext",
) -> list[dict[str, object]]:
    endpoint = "127.0.0.1:4661"
    request_payload = ed2k_wire.encode_source_request(
        bytes.fromhex(SERVER_SOURCE_FILE_HASH),
        SERVER_SOURCE_FILE_SIZE,
    )
    source_payload = struct.pack(
        "<IH", SERVER_SOURCE_PUBLISHER_ID, SERVER_SOURCE_PUBLISHER_PORT
    )
    if transport_mode == "obfuscated":
        source_payload += b"\x81" + SERVER_SOURCE_PUBLISHER_HASH
    reply_payload = bytes.fromhex(SERVER_SOURCE_FILE_HASH) + b"\x01" + source_payload
    request_opcode = (
        server_source_diagnostic_evidence.SOURCE_REQUEST_OPCODE_BY_TRANSPORT[
            transport_mode
        ]
    )
    reply_opcode = server_source_diagnostic_evidence.SOURCE_REPLY_OPCODE_BY_TRANSPORT[
        transport_mode
    ]

    def row(
        sequence: int,
        event: str,
        *,
        keys: dict[str, object],
        body: dict[str, object],
    ) -> dict[str, object]:
        return {
            "schema": DIAG_EVENT_SCHEMA,
            "client": client,
            "runId": run_id,
            "processId": process_id,
            "segmentId": 0,
            "seq": sequence,
            "streamSeq": sequence,
            "family": "ed2k_tcp",
            "event": event,
            "keys": keys,
            "body": body,
        }

    packet_keys = {
        "peer": endpoint,
        "protocolMarker": server_source_diagnostic_evidence.SOURCE_PROTOCOL_MARKER,
    }
    request = row(
        1,
        "packet",
        keys={
            **packet_keys,
            "opcode": request_opcode,
            "traceId": trace_id,
        },
        body={
            "flow": "server",
            "direction": "send",
            "outcome": "attempted",
            "protocolMarker": server_source_diagnostic_evidence.SOURCE_PROTOCOL_MARKER,
            "opcode": request_opcode,
            "transportMode": transport_mode,
            "obfuscated": transport_mode == "obfuscated",
            "traceId": trace_id,
            "payloadLen": len(request_payload),
            "payloadHex": request_payload.hex(),
            "payloadHexTruncated": False,
        },
    )
    send_outcome = row(
        2,
        "send_outcome",
        keys={
            **packet_keys,
            "opcode": request_opcode,
        },
        body={
            "flow": "server",
            "direction": "send",
            "outcome": "send_succeeded",
            "deliveryKnown": True,
            "protocolMarker": server_source_diagnostic_evidence.SOURCE_PROTOCOL_MARKER,
            "opcode": request_opcode,
            "transportMode": transport_mode,
            "obfuscated": transport_mode == "obfuscated",
            "traceId": trace_id,
        },
    )
    reply = row(
        3,
        "packet",
        keys={
            **packet_keys,
            "opcode": reply_opcode,
            "traceId": trace_id,
        },
        body={
            "flow": "server",
            "direction": "recv",
            "outcome": "accepted",
            "protocolMarker": server_source_diagnostic_evidence.SOURCE_PROTOCOL_MARKER,
            "opcode": reply_opcode,
            "transportMode": transport_mode,
            "obfuscated": transport_mode == "obfuscated",
            "traceId": trace_id,
            "payloadLen": len(reply_payload),
            "payloadHex": reply_payload.hex(),
            "payloadHexTruncated": False,
        },
    )
    applied = row(
        4,
        "source_result_applied",
        keys={
            **packet_keys,
            "fileHash": SERVER_SOURCE_FILE_HASH,
            "opcode": reply_opcode,
            "traceId": trace_id,
        },
        body={
            "flow": "server",
            "phase": "source_search",
            "direction": "recv",
            "outcome": "applied",
            "protocolMarker": server_source_diagnostic_evidence.SOURCE_PROTOCOL_MARKER,
            "opcode": reply_opcode,
            "transportMode": transport_mode,
            "obfuscated": transport_mode == "obfuscated",
            "traceId": trace_id,
            "stateId": "server.source.result_applied",
            "milestone": "result_applied",
            "wireSourceCount": 1,
            "sourceCountBefore": 0,
            "sourceCountAfter": 1,
        },
    )
    if client == "rust":
        return [request, send_outcome, reply, applied]
    reply["seq"] = reply["streamSeq"] = 2
    applied["seq"] = applied["streamSeq"] = 3
    return [request, reply, applied]


def _write_server_source_segment(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )


def attach_server_source(
    report: dict[str, object],
    *,
    run_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    transport_mode: str = "plaintext",
) -> dict[str, object]:
    del monkeypatch
    endpoint = "127.0.0.1:4661"
    records = {
        "rust": _server_source_records(
            client="rust",
            process_id=101,
            run_id="rust-source-run",
            trace_id=101,
            transport_mode=transport_mode,
        ),
        "mfc": _server_source_records(
            client="mfc",
            process_id=202,
            run_id="mfc-source-run",
            trace_id=202,
            transport_mode=transport_mode,
        ),
    }
    captures: dict[str, dict[str, object]] = {}
    for client, process_id, run_id in (
        ("rust", 101, "rust-source-run"),
        ("mfc", 202, "mfc-source-run"),
    ):
        diagnostics_dir = run_directory / "diagnostics" / client
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        prefix = "emulebb-rust-diag" if client == "rust" else "emulebb-mfc-diag"
        segment = diagnostics_dir / f"{prefix}-{process_id}-{run_id}-000000.jsonl"
        _write_server_source_segment(segment, records[client])
        captures[client] = {
            "diagnosticsDir": str(diagnostics_dir),
            "processId": process_id,
            "selectedSegments": [str(segment)],
        }

    transfer_rows = {
        "rust": {
            "hash": SERVER_SOURCE_FILE_HASH.upper(),
            "displayName": SERVER_SOURCE_FILE_NAME,
            "sizeBytes": SERVER_SOURCE_FILE_SIZE,
            "sources": 1,
        },
        "mfc": {
            "hash": SERVER_SOURCE_FILE_HASH.upper(),
            "name": SERVER_SOURCE_FILE_NAME,
            "sizeBytes": SERVER_SOURCE_FILE_SIZE,
            "sources": 1,
        },
    }
    evidence = (
        server_source_diagnostic_evidence.build_server_source_diagnostic_evidence(
            expected_file_hash=SERVER_SOURCE_FILE_HASH,
            expected_file_name=SERVER_SOURCE_FILE_NAME,
            expected_file_size=SERVER_SOURCE_FILE_SIZE,
            server_endpoint=endpoint,
            publisher_client_id=SERVER_SOURCE_PUBLISHER_ID,
            publisher_host=SERVER_SOURCE_PUBLISHER_HOST,
            publisher_tcp_port=SERVER_SOURCE_PUBLISHER_PORT,
            publisher_user_hash=SERVER_SOURCE_PUBLISHER_HASH.hex(),
            expected_transport_mode=transport_mode,
            rust_records=records["rust"],
            mfc_records=records["mfc"],
            transfer_rows=transfer_rows,
        )
    )
    evidence["captures"] = captures

    expected_source = {
        "kind": "high-id",
        "client_id": SERVER_SOURCE_PUBLISHER_ID,
        "host": SERVER_SOURCE_PUBLISHER_HOST,
        "port": SERVER_SOURCE_PUBLISHER_PORT,
        "crypt_options": 0x81 if transport_mode == "obfuscated" else 0,
        "user_hash": (
            SERVER_SOURCE_PUBLISHER_HASH.hex().upper()
            if transport_mode == "obfuscated"
            else None
        ),
    }
    expected_server_flags = (
        docker_ed2k_source_publisher.OBFUSCATED_SOURCE_SERVER_FLAGS
        if transport_mode == "obfuscated"
        else docker_ed2k_source_publisher.PLAIN_SERVER_FLAGS
    )
    report["transfer_scenario"] = "server-tcp-source"
    protocol_case_name = (
        "plain-server-plain-clients"
        if transport_mode == "plaintext"
        else "obfuscated-required"
    )
    report["protocol_case"] = ed2k_protocol_cases.protocol_surface(
        ed2k_protocol_cases.PROTOCOL_CASE_MAP[protocol_case_name]
    )
    report["network"] = {
        "ed2k_server_address": "127.0.0.1",
        "ports": {
            "ed2k_tcp": 4661,
            "source_publisher_tcp": SERVER_SOURCE_PUBLISHER_PORT,
        },
    }
    report["server_source_fixture"] = {
        "hash": SERVER_SOURCE_FILE_HASH,
        "name": SERVER_SOURCE_FILE_NAME,
        "size": SERVER_SOURCE_FILE_SIZE,
        "publisher": {
            "nickname": SERVER_SOURCE_PUBLISHER_NICK,
            "tcpPort": SERVER_SOURCE_PUBLISHER_PORT,
            "login": {
                "assigned_id": SERVER_SOURCE_PUBLISHER_ID,
                "id_kind": "high-id",
            },
            "client": {
                "client_name": SERVER_SOURCE_PUBLISHER_NICK,
                "nick": SERVER_SOURCE_PUBLISHER_NICK,
                "high_id": True,
                "ip": SERVER_SOURCE_PUBLISHER_HOST,
                "shared_files": 1,
            },
            "runtime": {
                "schema": docker_ed2k_source_publisher.RECEIPT_SCHEMA,
                "status": "ready",
                "runId": "source-publisher-run",
                "publisherIp": SERVER_SOURCE_PUBLISHER_HOST,
                "expectedHighId": SERVER_SOURCE_PUBLISHER_ID,
                "server": {"host": "127.0.0.1", "port": 4661},
                "publisher": {
                    "nickname": SERVER_SOURCE_PUBLISHER_NICK,
                    "tcpPort": SERVER_SOURCE_PUBLISHER_PORT,
                    "userHash": SERVER_SOURCE_PUBLISHER_HASH.hex().upper(),
                    "serverFlags": expected_server_flags,
                },
                "file": {
                    "hash": SERVER_SOURCE_FILE_HASH.upper(),
                    "name": SERVER_SOURCE_FILE_NAME,
                    "size": SERVER_SOURCE_FILE_SIZE,
                },
                "login": {
                    "assigned_id": SERVER_SOURCE_PUBLISHER_ID,
                    "id_kind": "high-id",
                },
                "identityProbeAnswers": 0,
                "transcript": [
                    ed2k_wire.Ed2kFrame(
                        ed2k_wire.PROTO_EDONKEY,
                        ed2k_wire.OP_LOGINREQUEST,
                        ed2k_wire.encode_login_request(
                            user_hash=SERVER_SOURCE_PUBLISHER_HASH,
                            tcp_port=SERVER_SOURCE_PUBLISHER_PORT,
                            nickname=SERVER_SOURCE_PUBLISHER_NICK,
                            server_flags=expected_server_flags,
                        ),
                    ).evidence("send"),
                    ed2k_wire.Ed2kFrame(
                        ed2k_wire.PROTO_EDONKEY,
                        ed2k_wire.OP_OFFERFILES,
                        ed2k_wire.encode_offer_file(
                            file_hash=bytes.fromhex(SERVER_SOURCE_FILE_HASH),
                            name=SERVER_SOURCE_FILE_NAME,
                            size=SERVER_SOURCE_FILE_SIZE,
                        ),
                    ).evidence("send"),
                ],
            },
        },
        "publication": {
            "hash": SERVER_SOURCE_FILE_HASH.upper(),
            "requested_size": SERVER_SOURCE_FILE_SIZE,
            "indexed": True,
            "name": SERVER_SOURCE_FILE_NAME,
            "size": SERVER_SOURCE_FILE_SIZE,
            "sources": 1,
            "search_sources": 1,
            "complete_sources": 1,
            "endpoints": [expected_source],
            "search_source": {
                "kind": "high-id-search-reference",
                "id": SERVER_SOURCE_PUBLISHER_ID,
                "port": SERVER_SOURCE_PUBLISHER_PORT,
            },
            "search_result": {
                "hash": SERVER_SOURCE_FILE_HASH.upper(),
                "name": SERVER_SOURCE_FILE_NAME,
                "size": SERVER_SOURCE_FILE_SIZE,
                "sources": 1,
                "complete_sources": 1,
                "result_source_id": SERVER_SOURCE_PUBLISHER_ID,
                "result_source_port": SERVER_SOURCE_PUBLISHER_PORT,
            },
            "source_reply": {
                "hash": SERVER_SOURCE_FILE_HASH.upper(),
                "source_count": 1,
                "sources": [expected_source],
            },
        },
    }
    report["checks"]["client_server_source_stimulus"] = {
        "mode": "source-free-ed2k-link",
        "link": (
            f"ed2k://|file|{SERVER_SOURCE_FILE_NAME}|{SERVER_SOURCE_FILE_SIZE}|"
            f"{SERVER_SOURCE_FILE_HASH}|/"
        ),
        "hash": SERVER_SOURCE_FILE_HASH,
        "name": SERVER_SOURCE_FILE_NAME,
        "sizeBytes": SERVER_SOURCE_FILE_SIZE,
    }
    report["checks"]["client_server_source_transfers"] = transfer_rows
    report["checks"]["client_server_source_diagnostics"] = evidence
    report["checks"]["mfc_diagnostics_shutdown"] = {
        "ok": True,
        "processId": 202,
    }
    report["diagnostics"]["serverSource"] = evidence
    report["diagnostics"]["captures"] = {
        client: {
            "diagnosticsDir": capture["diagnosticsDir"],
            "processId": capture["processId"],
            "selectedSegments": list(capture["selectedSegments"]),
        }
        for client, capture in captures.items()
    }
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        evidence["coverageClaims"]["eligibleCoverageIds"]
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()

    return evidence


def _server_udp_source_records(
    *,
    source_request_version: int,
    client: str,
    process_id: int,
    run_id: str,
) -> list[dict[str, object]]:
    target_endpoint = (
        f"{SERVER_UDP_SOURCE_TARGET_HOST}:{SERVER_UDP_SOURCE_TARGET_UDP_PORT}"
    )
    file_hash = bytes.fromhex(SERVER_SOURCE_FILE_HASH)
    request_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES2
    )
    request_opcode_name = (
        "OP_GLOBGETSOURCES" if source_request_version == 1 else "OP_GLOBGETSOURCES2"
    )
    request_datagram = (
        ed2k_wire.encode_server_udp_source_v1_request([file_hash])
        if source_request_version == 1
        else ed2k_wire.encode_server_udp_source_v2_request(
            [(file_hash, SERVER_SOURCE_FILE_SIZE)]
        )
    )
    request_payload = request_datagram[2:]
    reply_payload = ed2k_wire.encode_server_udp_source_reply(
        file_hash=file_hash,
        sources=[(SERVER_SOURCE_PUBLISHER_ID, SERVER_SOURCE_PUBLISHER_PORT)],
    )[2:]

    def row(
        sequence: int,
        event: str,
        *,
        opcode: int,
        trace_id: int,
        send_attempt_id: int | None = None,
        direction: str,
        outcome: str,
        payload: bytes | None = None,
        keys_extra: dict[str, object] | None = None,
        body_extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        keys = {
            "peer": target_endpoint,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "traceId": trace_id,
        }
        keys.update(keys_extra or {})
        body: dict[str, object] = {
            "flow": "server",
            "phase": "udp" if event != "source_result_applied" else "source_search",
            "direction": direction,
            "outcome": outcome,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "transportMode": "plaintext",
            "obfuscated": False,
            "traceId": trace_id,
        }
        if send_attempt_id is not None:
            keys["sendAttemptId"] = send_attempt_id
            body["sendAttemptId"] = send_attempt_id
        if payload is not None:
            body.update(
                {
                    "payloadLen": len(payload),
                    "payloadHex": payload.hex(),
                    "payloadHexTruncated": False,
                }
            )
        body.update(body_extra or {})
        return {
            "schema": DIAG_EVENT_SCHEMA,
            "client": client,
            "runId": run_id,
            "processId": process_id,
            "segmentId": 0,
            "seq": sequence,
            "streamSeq": sequence,
            "family": "ed2k_server_udp",
            "event": event,
            "keys": keys,
            "body": body,
        }

    records = [
        row(
            1,
            "packet",
            opcode=request_opcode,
            trace_id=0 if client == "rust" else 31,
            send_attempt_id=5 if client == "rust" else None,
            direction="send",
            outcome="attempted",
            payload=request_payload,
        )
    ]
    next_sequence = 2
    if client == "rust":
        records.append(
            row(
                next_sequence,
                "send_outcome",
                opcode=request_opcode,
                trace_id=0,
                send_attempt_id=5,
                direction="send",
                outcome="send_succeeded",
                body_extra={"deliveryKnown": True},
            )
        )
        next_sequence += 1
    records.extend(
        [
            row(
                next_sequence,
                "packet",
                opcode=ed2k_wire.OP_GLOBFOUNDSOURCES,
                trace_id=32,
                direction="recv",
                outcome="accepted",
                payload=reply_payload,
            ),
            row(
                next_sequence + 1,
                "source_result_applied",
                opcode=ed2k_wire.OP_GLOBFOUNDSOURCES,
                trace_id=32,
                direction="recv",
                outcome="applied",
                keys_extra={
                    "fileHash": SERVER_SOURCE_FILE_HASH,
                    "requestOpcode": request_opcode,
                },
                body_extra={
                    "requestOpcode": request_opcode,
                    "requestOpcodeName": request_opcode_name,
                    "serverEndpoint": (
                        f"{SERVER_UDP_SOURCE_TARGET_HOST}:"
                        f"{SERVER_UDP_SOURCE_TARGET_PORT}"
                    ),
                    "stateId": "server.source.result_applied",
                    "milestone": "result_applied",
                    "wireSourceCount": 1,
                    "sourceCountBefore": 0,
                    "sourceCountAfter": 1,
                },
            ),
        ]
    )
    return records


def _server_udp_source_transcript(
    source_request_version: int,
) -> dict[str, object]:
    file_hash = bytes.fromhex(SERVER_SOURCE_FILE_HASH)
    request_opcode = (
        ed2k_wire.OP_GLOBGETSOURCES
        if source_request_version == 1
        else ed2k_wire.OP_GLOBGETSOURCES2
    )
    request = (
        ed2k_wire.encode_server_udp_source_v1_request([file_hash])
        if source_request_version == 1
        else ed2k_wire.encode_server_udp_source_v2_request(
            [(file_hash, SERVER_SOURCE_FILE_SIZE)]
        )
    )
    reply = ed2k_wire.encode_server_udp_source_reply(
        file_hash=bytes.fromhex(SERVER_SOURCE_FILE_HASH),
        sources=[(SERVER_SOURCE_PUBLISHER_ID, SERVER_SOURCE_PUBLISHER_PORT)],
    )
    events: list[dict[str, object]] = []
    for index, peer in enumerate(("127.0.0.1:41000", "127.0.0.1:41001")):
        start = index * 4 + 1
        events.extend(
            [
                {
                    "sequence": start,
                    "direction": "recv",
                    "peer": peer,
                    "opcode": ed2k_wire.OP_GLOBSERVSTATREQ,
                    "accepted": True,
                },
                {
                    "sequence": start + 1,
                    "direction": "send",
                    "peer": peer,
                    "opcode": ed2k_wire.OP_GLOBSERVSTATRES,
                    "accepted": True,
                },
                {
                    "sequence": start + 2,
                    "direction": "recv",
                    "peer": peer,
                    "opcode": request_opcode,
                    "frameHex": request.hex().upper(),
                    "accepted": True,
                },
                {
                    "sequence": start + 3,
                    "direction": "send",
                    "peer": peer,
                    "opcode": ed2k_wire.OP_GLOBFOUNDSOURCES,
                    "frameHex": reply.hex().upper(),
                    "accepted": True,
                },
            ]
        )
    transcript = {
        "schema": (
            scripted_ed2k_udp_source.V1_TRANSCRIPT_SCHEMA
            if source_request_version == 1
            else scripted_ed2k_udp_source.V2_TRANSCRIPT_SCHEMA
        ),
        "serverEndpoint": (
            f"{SERVER_UDP_SOURCE_TARGET_HOST}:{SERVER_UDP_SOURCE_TARGET_PORT}"
        ),
        "udpEndpoint": (
            f"{SERVER_UDP_SOURCE_TARGET_HOST}:{SERVER_UDP_SOURCE_TARGET_UDP_PORT}"
        ),
        "udpFlags": (
            scripted_ed2k_udp_source.SERVER_UDP_FLAG_EXT_GETSOURCES
            if source_request_version == 1
            else scripted_ed2k_udp_source.SERVER_UDP_FLAG_EXT_GETSOURCES
            | scripted_ed2k_udp_source.SERVER_UDP_FLAG_EXT_GETSOURCES2
        ),
        "fileHash": SERVER_SOURCE_FILE_HASH,
        "source": {
            "host": SERVER_SOURCE_PUBLISHER_HOST,
            "clientId": SERVER_SOURCE_PUBLISHER_ID,
            "tcpPort": SERVER_SOURCE_PUBLISHER_PORT,
        },
        "events": events,
    }
    if source_request_version == 2:
        transcript["fileSize"] = SERVER_SOURCE_FILE_SIZE
    return transcript


def attach_server_udp_source(
    report: dict[str, object],
    *,
    run_directory: Path,
    source_request_version: int,
) -> dict[str, object]:
    version_token = f"v{source_request_version}"
    records = {
        "rust": _server_udp_source_records(
            source_request_version=source_request_version,
            client="rust",
            process_id=101,
            run_id=f"rust-udp-source-{version_token}-run",
        ),
        "mfc": _server_udp_source_records(
            source_request_version=source_request_version,
            client="mfc",
            process_id=202,
            run_id=f"mfc-udp-source-{version_token}-run",
        ),
    }
    captures: dict[str, dict[str, object]] = {}
    for client, process_id, run_id in (
        ("rust", 101, f"rust-udp-source-{version_token}-run"),
        ("mfc", 202, f"mfc-udp-source-{version_token}-run"),
    ):
        diagnostics_dir = run_directory / "diagnostics" / client
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        prefix = "emulebb-rust-diag" if client == "rust" else "emulebb-mfc-diag"
        segment = diagnostics_dir / f"{prefix}-{process_id}-{run_id}-000000.jsonl"
        _write_server_source_segment(segment, records[client])
        captures[client] = {
            "diagnosticsDir": str(diagnostics_dir),
            "processId": process_id,
            "selectedSegments": [str(segment)],
        }

    transcript = _server_udp_source_transcript(source_request_version)
    transcript_path = (
        run_directory / f"server-udp-source-v{source_request_version}-transcript.json"
    )
    transcript_path.write_text(json.dumps(transcript), encoding="utf-8")
    transfer_rows = {
        "rust": {
            "hash": SERVER_SOURCE_FILE_HASH.upper(),
            "displayName": SERVER_SOURCE_FILE_NAME,
            "sizeBytes": SERVER_SOURCE_FILE_SIZE,
            "sources": 1,
        },
        "mfc": {
            "hash": SERVER_SOURCE_FILE_HASH.upper(),
            "name": SERVER_SOURCE_FILE_NAME,
            "sizeBytes": SERVER_SOURCE_FILE_SIZE,
            "sources": 1,
        },
    }
    evidence = server_udp_source_diagnostic_evidence.build_server_udp_source_diagnostic_evidence(
        source_request_version=source_request_version,
        expected_file_hash=SERVER_SOURCE_FILE_HASH,
        expected_file_name=SERVER_SOURCE_FILE_NAME,
        expected_file_size=SERVER_SOURCE_FILE_SIZE,
        target_server_endpoint=(
            f"{SERVER_UDP_SOURCE_TARGET_HOST}:{SERVER_UDP_SOURCE_TARGET_PORT}"
        ),
        target_udp_endpoint=(
            f"{SERVER_UDP_SOURCE_TARGET_HOST}:{SERVER_UDP_SOURCE_TARGET_UDP_PORT}"
        ),
        source_host=SERVER_SOURCE_PUBLISHER_HOST,
        source_tcp_port=SERVER_SOURCE_PUBLISHER_PORT,
        rust_records=records["rust"],
        mfc_records=records["mfc"],
        transfer_rows=transfer_rows,
        fixture_transcript=transcript,
    )
    evidence["captures"] = captures

    report["transfer_scenario"] = f"server-udp-source-v{source_request_version}"
    report["protocol_case"] = ed2k_protocol_cases.protocol_surface(
        ed2k_protocol_cases.PROTOCOL_CASE_MAP["plain-server-plain-clients"]
    )
    report["network"] = {
        "p2p_bind_interface_address": SERVER_UDP_SOURCE_TARGET_HOST,
        "ed2k_server_address": SERVER_UDP_SOURCE_TARGET_HOST,
        "ports": {
            "ed2k_tcp": 4661,
            "udp_source_target_tcp": SERVER_UDP_SOURCE_TARGET_PORT,
            "udp_source_target_udp": SERVER_UDP_SOURCE_TARGET_UDP_PORT,
            "udp_source_peer_tcp": SERVER_SOURCE_PUBLISHER_PORT,
        },
    }
    report[f"server_udp_source_v{source_request_version}_target"] = transcript
    peers = sorted(
        {
            str(event["peer"])
            for event in transcript["events"]
            if event["direction"] == "recv"
            and event["opcode"] == ed2k_wire.OP_GLOBSERVSTATREQ
        }
    )
    report["checks"][f"server_udp_source_v{source_request_version}_capabilities"] = {
        "ok": True,
        "expectedClients": 2,
        "distinctClientCount": 2,
        "peers": peers,
        "udpFlags": transcript["udpFlags"],
    }
    field_prefix = f"client_server_udp_source_v{source_request_version}"
    report["checks"][f"{field_prefix}_stimulus"] = {
        "mode": "source-free-ed2k-link",
        "link": (
            f"ed2k://|file|{SERVER_SOURCE_FILE_NAME}|{SERVER_SOURCE_FILE_SIZE}|"
            f"{SERVER_SOURCE_FILE_HASH}|/"
        ),
        "hash": SERVER_SOURCE_FILE_HASH,
        "name": SERVER_SOURCE_FILE_NAME,
        "sizeBytes": SERVER_SOURCE_FILE_SIZE,
    }
    report["checks"][f"{field_prefix}_transfers"] = transfer_rows
    report["checks"][f"{field_prefix}_diagnostics"] = evidence
    report["checks"]["mfc_diagnostics_shutdown"] = {
        "ok": True,
        "processId": 202,
    }
    report["diagnostics"][f"serverUdpSourceV{source_request_version}"] = evidence
    report["diagnostics"]["captures"] = {
        client: {
            "diagnosticsDir": capture["diagnosticsDir"],
            "processId": capture["processId"],
            "selectedSegments": list(capture["selectedSegments"]),
        }
        for client, capture in captures.items()
    }
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        server_udp_source_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS[
            source_request_version
        ]
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def _udp_tag(tag_id: int, value: str) -> bytes:
    encoded = value.encode()
    return (
        bytes([0x80 | ed2k_wire.TAGTYPE_STRING, tag_id])
        + struct.pack("<H", len(encoded))
        + encoded
    )


def _udp_record(
    *,
    client: str,
    process_id: int,
    run_id: str,
    sequence: int,
    event: str,
    keys: dict[str, object],
    body: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": DIAG_EVENT_SCHEMA,
        "client": client,
        "runId": run_id,
        "processId": process_id,
        "segmentId": 0,
        "seq": sequence,
        "streamSeq": sequence,
        "family": "ed2k_server_udp",
        "event": event,
        "keys": keys,
        "body": body,
    }


def _udp_metadata_records(
    *,
    client: str,
    process_id: int,
    run_id: str,
    obfuscated_description: bool,
) -> list[dict[str, object]]:
    target = "127.0.0.1:4761"
    target_udp = "127.0.0.1:4765"
    description_peer = "127.0.0.1:4775" if obfuscated_description else target_udp
    description_mode = "obfuscated" if obfuscated_description else "plaintext"
    status_challenge = 0x55AA_1234
    description_challenge = 0x4321_F0FF
    status_payload = struct.pack(
        "<IIIIIIIIHHI",
        status_challenge,
        1,
        1,
        1000,
        5000,
        200000,
        0x123,
        0,
        4775,
        4761,
        0,
    )
    description_payload = (
        struct.pack("<II", description_challenge, 2)
        + _udp_tag(ed2k_wire.ST_SERVERNAME, SERVER_IDENT_NAME)
        + _udp_tag(ed2k_wire.ST_DESCRIPTION, SERVER_IDENT_DESCRIPTION)
    )

    def packet(
        sequence: int,
        *,
        opcode: int,
        direction: str,
        payload: bytes,
        peer: str,
        trace_id: int | None,
        transport_mode: str,
        obfuscated: bool,
    ) -> dict[str, object]:
        keys: dict[str, object] = {
            "peer": peer,
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
        }
        body: dict[str, object] = {
            "flow": "server",
            "phase": "udp",
            "direction": direction,
            "outcome": "attempted" if direction == "send" else "accepted",
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": opcode,
            "transportMode": transport_mode,
            "obfuscated": obfuscated,
            "payloadLen": len(payload),
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
        }
        if trace_id is not None:
            keys["traceId"] = trace_id
            body["traceId"] = trace_id
        return _udp_record(
            client=client,
            process_id=process_id,
            run_id=run_id,
            sequence=sequence,
            event="packet",
            keys=keys,
            body=body,
        )

    def applied(
        sequence: int,
        *,
        event: str,
        opcode: int,
        challenge: int,
        trace_id: int,
        peer: str,
        transport_mode: str,
        obfuscated: bool,
        fields: dict[str, object],
    ) -> dict[str, object]:
        return _udp_record(
            client=client,
            process_id=process_id,
            run_id=run_id,
            sequence=sequence,
            event=event,
            keys={
                "peer": peer,
                "traceId": trace_id,
                "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                "opcode": opcode,
                "challenge": challenge,
            },
            body={
                "flow": "server",
                "phase": "udp",
                "direction": "meta",
                "outcome": "applied",
                "traceId": trace_id,
                "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                "opcode": opcode,
                "challenge": challenge,
                "serverEndpoint": target,
                "transportMode": transport_mode,
                "obfuscated": obfuscated,
                **fields,
            },
        )

    return [
        packet(
            1,
            opcode=ed2k_wire.OP_GLOBSERVSTATREQ,
            direction="send",
            payload=struct.pack("<I", status_challenge),
            peer=target_udp,
            trace_id=None,
            transport_mode="plaintext",
            obfuscated=False,
        ),
        packet(
            2,
            opcode=ed2k_wire.OP_GLOBSERVSTATRES,
            direction="recv",
            payload=status_payload,
            peer=target_udp,
            trace_id=20,
            transport_mode="plaintext",
            obfuscated=False,
        ),
        applied(
            3,
            event="server_status_applied",
            opcode=ed2k_wire.OP_GLOBSERVSTATRES,
            challenge=status_challenge,
            trace_id=20,
            peer=target_udp,
            transport_mode="plaintext",
            obfuscated=False,
            fields={
                "users": 1,
                "files": 1,
                "maxUsers": 1000,
                "softFiles": 5000,
                "hardFiles": 200000,
                "udpFlags": 0x123,
                "lowIdUsers": 0,
                "obfuscationPortUdp": 4775,
                "obfuscationPortTcp": 4761,
                "udpKey": 0,
            },
        ),
        packet(
            4,
            opcode=ed2k_wire.OP_SERVER_DESC_REQ,
            direction="send",
            payload=struct.pack("<I", description_challenge),
            peer=description_peer,
            trace_id=None,
            transport_mode=description_mode,
            obfuscated=obfuscated_description,
        ),
        packet(
            5,
            opcode=ed2k_wire.OP_SERVER_DESC_RES,
            direction="recv",
            payload=description_payload,
            peer=description_peer,
            trace_id=40,
            transport_mode=description_mode,
            obfuscated=obfuscated_description,
        ),
        applied(
            6,
            event="server_description_applied",
            opcode=ed2k_wire.OP_SERVER_DESC_RES,
            challenge=description_challenge,
            trace_id=40,
            peer=description_peer,
            transport_mode=description_mode,
            obfuscated=obfuscated_description,
            fields={
                "responseFormat": "tagged",
                "name": SERVER_IDENT_NAME,
                "description": SERVER_IDENT_DESCRIPTION,
                "dynamicHost": "",
                "version": "",
            },
        ),
    ]


def attach_server_udp_metadata(
    report: dict[str, object], *, run_directory: Path
) -> dict[str, object]:
    snapshots = {
        client: {
            "connectionStatus": {
                "connected": True,
                "currentServer": {"address": "127.0.0.1", "port": 4661},
            },
            "serverEntity": {
                "address": "127.0.0.1",
                "port": 4761,
                "name": SERVER_IDENT_NAME,
                "description": SERVER_IDENT_DESCRIPTION,
                "users": 1,
                "files": 1,
                "softFiles": 5000,
                "hardFiles": 200000,
            },
        }
        for client in ("rust", "mfc")
    }
    records = {
        "rust": _udp_metadata_records(
            client="rust",
            process_id=101,
            run_id="rust-run",
            obfuscated_description=True,
        ),
        "mfc": _udp_metadata_records(
            client="mfc",
            process_id=202,
            run_id="mfc-run",
            obfuscated_description=False,
        ),
    }
    captures: dict[str, object] = {}
    for client, process_id in (("rust", 101), ("mfc", 202)):
        diagnostics_dir = run_directory / "diagnostics" / client
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        prefix = "emulebb-rust-diag" if client == "rust" else "emulebb-mfc-diag"
        segment = diagnostics_dir / f"{prefix}-{process_id}-{client}-run-000000.jsonl"
        segment.write_text(
            "".join(f"{json.dumps(record)}\n" for record in records[client]),
            encoding="utf-8",
        )
        captures[client] = {
            "diagnosticsDir": str(diagnostics_dir),
            "processId": process_id,
            "selectedSegments": [str(segment)],
        }

    evidence = server_udp_metadata_diagnostic_evidence.build_server_udp_metadata_diagnostic_evidence(
        anchor_server_endpoint="127.0.0.1:4661",
        target_server_endpoint="127.0.0.1:4761",
        target_udp_endpoint="127.0.0.1:4765",
        seed_name=SERVER_METADATA_SEED_NAME,
        seed_description="seed metadata before server reply",
        expected_name=SERVER_IDENT_NAME,
        expected_description=SERVER_IDENT_DESCRIPTION,
        expected_users=1,
        expected_files=1,
        rust_records=records["rust"],
        mfc_records=records["mfc"],
        rest_snapshots=snapshots,
    )
    evidence["captures"] = captures
    report["transfer_scenario"] = "server-udp-metadata"
    report["protocol_case"] = {"name": "plain-server-plain-clients"}
    report["network"] = {
        "ed2k_server_address": "127.0.0.1",
        "ports": {
            "ed2k_tcp": 4661,
            "metadata_ed2k_tcp": 4761,
            "metadata_ed2k_udp": 4765,
        },
    }
    report["udp_metadata_target"] = {
        "address": "127.0.0.1",
        "tcpPort": 4761,
        "udpPort": 4765,
        "publisher": {
            "nickname": SERVER_UDP_METADATA_PUBLISHER_NICK,
            "client": {
                "nick": SERVER_UDP_METADATA_PUBLISHER_NICK,
                "shared_files": 1,
            },
        },
        "file": {
            "hash": SERVER_UDP_METADATA_FILE_HASH,
            "name": SERVER_UDP_METADATA_FILE_NAME,
            "size": SERVER_UDP_METADATA_FILE_SIZE,
            "requested_size": SERVER_UDP_METADATA_FILE_SIZE,
            "indexed": True,
            "complete_sources": 1,
            "endpoints": [{"client_id": 1}],
        },
    }
    report["checks"]["client_server_udp_metadata_rest"] = snapshots
    report["checks"]["client_server_udp_metadata_diagnostics"] = evidence
    report["diagnostics"]["serverUdpMetadata"] = evidence
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        server_udp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def _direct_callback_record(
    *,
    client: str,
    process_id: int,
    run_id: str,
    sequence: int,
    source_port: int,
) -> dict[str, object]:
    raw = direct_callback_probe.encode_direct_callback_request(
        tcp_port=SERVER_CALLBACK_REQUESTER_PORT,
        user_hash=SERVER_CALLBACK_REQUESTER_HASH,
        connect_options=0x01,
    )
    return {
        "schema": DIAG_EVENT_SCHEMA,
        "client": client,
        "runId": run_id,
        "processId": process_id,
        "segmentId": 0,
        "seq": sequence,
        "streamSeq": sequence,
        "family": "ed2k_client_udp",
        "event": "packet",
        "keys": {
            "peer": f"127.0.0.1:{source_port}",
            "protocolMarker": direct_callback_probe.OP_EMULEPROT,
            "opcode": direct_callback_probe.OP_DIRECTCALLBACKREQ,
        },
        "body": {
            "direction": "recv",
            "outcome": "accepted",
            "stateId": "client_udp.direct_callback",
            "stateLabel": "direct_callback",
            "traceKey": f"client_udp:127.0.0.1:{source_port}",
            "flow": "client_udp",
            "phase": "direct_callback_request",
            "transportMode": "plaintext",
            "obfuscated": False,
            "protocolMarker": direct_callback_probe.OP_EMULEPROT,
            "protocolName": "emule",
            "opcode": direct_callback_probe.OP_DIRECTCALLBACKREQ,
            "opcodeName": "OP_DIRECTCALLBACKREQ",
            "rawLen": len(raw),
            "rawHex": raw.hex(),
            "payloadLen": len(raw) - 2,
            "payloadHex": raw[2:].hex(),
            "payloadHexTruncated": False,
            "note": "direct_callback_raised",
        },
    }


def _direct_callback_result(
    *,
    client: str,
    target: dict[str, object],
    source_port: int,
) -> dict[str, object]:
    raw = direct_callback_probe.encode_direct_callback_request(
        tcp_port=SERVER_CALLBACK_REQUESTER_PORT,
        user_hash=SERVER_CALLBACK_REQUESTER_HASH,
        connect_options=0x01,
    )
    hello = (
        b"\x10"
        + bytes.fromhex(str(target["userHash"]))
        + int(target["clientId"]).to_bytes(4, "little")
        + int(target["tcpPort"]).to_bytes(2, "little")
    )
    return {
        "schema": "emulebb.direct-callback-probe/1",
        "status": "completed",
        "targetLabel": client,
        "source": {"host": "127.0.0.1", "udpPort": source_port},
        "target": {"host": "127.0.0.1", "udpPort": target["udpPort"]},
        "requester": {
            "tcpPort": SERVER_CALLBACK_REQUESTER_PORT,
            "userHash": SERVER_CALLBACK_REQUESTER_HASH.hex().upper(),
            "clientId": direct_callback_probe.high_id_for_ipv4("127.0.0.1"),
            "connectOptions": 0x01,
        },
        "request": {
            "protocol": direct_callback_probe.OP_EMULEPROT,
            "opcode": direct_callback_probe.OP_DIRECTCALLBACKREQ,
            "rawHex": raw.hex().upper(),
            "payloadHex": raw[2:].hex().upper(),
            "sentBytes": len(raw),
            "sentAt": 1000.0,
        },
        "callbackConnection": {
            "userHash": target["userHash"],
            "clientId": target["clientId"],
            "tcpPort": target["tcpPort"],
            "payloadLength": len(hello),
            "payloadHex": hello.hex().upper(),
            "peerHost": "127.0.0.1",
            "peerPort": 50_000 + int(target["clientId"]),
            "observedAt": 1000.1,
        },
    }


def attach_direct_callback(
    report: dict[str, object],
    *,
    run_directory: Path,
) -> dict[str, object]:
    login = bilateral_login_evidence()
    identities = {
        "rust": {
            "clientId": 4,
            "tcpPort": 4662,
            "udpPort": 4672,
            "userHash": "11" * 16,
        },
        "mfc": {
            "clientId": 2,
            "tcpPort": 4663,
            "udpPort": 4673,
            "userHash": "22" * 16,
        },
    }
    for client, identity in identities.items():
        login["clients"][client]["decodedLogin"] = {
            "client_id": 0,
            "tcp_port": identity["tcpPort"],
            "user_hash": identity["userHash"],
        }
        login["clients"][client]["decodedIdChange"] = {
            "assigned_id": identity["clientId"],
            "id_kind": "low-id",
        }
    attach_server_login(report, login, ("plaintext",))
    report["transfer_scenario"] = "direct-callback"
    report["protocol_case"] = ed2k_protocol_cases.protocol_surface(
        ed2k_protocol_cases.PROTOCOL_CASE_MAP["plain-server-plain-clients"]
    )
    report["network"].update(
        {
            "p2p_bind_interface_address": "127.0.0.1",
            "directCallbackKadIsolation": {
                "publicDiscovery": False,
                "rustBootstrapSeed": {
                    "endpoint": f"127.0.0.1:{SERVER_CALLBACK_REQUESTER_PORT}",
                    "tcpPort": SERVER_CALLBACK_REQUESTER_PORT,
                },
                "mfcBootstrapSeeds": [],
            },
        }
    )
    report["network"]["ports"].update(
        {
            "client1_udp": identities["rust"]["udpPort"],
            "client2_udp": identities["mfc"]["udpPort"],
            "callback_requester_tcp": SERVER_CALLBACK_REQUESTER_PORT,
        }
    )
    rust_profile_dir = run_directory / "profiles" / "rust"
    mfc_config_dir = run_directory / "profiles" / "mfc" / "config"
    report["profiles"]["rust"]["profile_dir"] = str(rust_profile_dir)
    report["profiles"]["mfc"]["config_dir"] = str(mfc_config_dir)
    rust_nodes = kad_nodes.encode_nodes_dat(
        [
            kad_nodes.BootstrapContact(
                "127.0.0.1",
                SERVER_CALLBACK_REQUESTER_PORT,
                SERVER_CALLBACK_REQUESTER_PORT,
            )
        ]
    )
    mfc_nodes = kad_nodes.encode_nodes_dat([])
    (rust_profile_dir / "nodes.dat").parent.mkdir(parents=True, exist_ok=True)
    (rust_profile_dir / "nodes.dat").write_bytes(rust_nodes)
    (mfc_config_dir / "nodes.dat").parent.mkdir(parents=True, exist_ok=True)
    (mfc_config_dir / "nodes.dat").write_bytes(mfc_nodes)
    launch_inputs = run_directory / "launch-inputs" / "direct-callback-kad"
    launch_inputs.mkdir(parents=True, exist_ok=True)
    launch_receipts: dict[str, dict[str, object]] = {}
    for label, name, payload in (
        ("rustNodesDat", "rust-nodes.dat", rust_nodes),
        ("mfcNodesDat", "mfc-nodes.dat", mfc_nodes),
    ):
        path = launch_inputs / name
        path.write_bytes(payload)
        launch_receipts[label] = {
            "path": str(path),
            "sizeBytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    report["network"]["directCallbackKadIsolation"]["launchInputs"] = launch_receipts
    targets = {
        client: {
            "clientId": identity["clientId"],
            "idKind": "low-id",
            "tcpPort": identity["tcpPort"],
            "udpPort": identity["udpPort"],
            "userHash": identity["userHash"],
        }
        for client, identity in identities.items()
    }
    source_ports = {"rust": 31_001, "mfc": 31_002}
    records = {
        "rust": [
            _direct_callback_record(
                client="rust",
                process_id=101,
                run_id="rust-direct-run",
                sequence=10,
                source_port=source_ports["rust"],
            )
        ],
        "mfc": [
            _direct_callback_record(
                client="mfc",
                process_id=202,
                run_id="mfc-direct-run",
                sequence=20,
                source_port=source_ports["mfc"],
            )
        ],
    }
    captures: dict[str, dict[str, object]] = {}
    for client, process_id, run_id in (
        ("rust", 101, "rust-direct-run"),
        ("mfc", 202, "mfc-direct-run"),
    ):
        diagnostics_dir = run_directory / "diagnostics" / client
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        prefix = "emulebb-rust-diag" if client == "rust" else "emulebb-mfc-diag"
        segment = diagnostics_dir / f"{prefix}-{process_id}-{run_id}-000000.jsonl"
        _write_server_source_segment(segment, records[client])
        captures[client] = {
            "diagnosticsDir": str(diagnostics_dir),
            "processId": process_id,
            "selectedSegments": [str(segment)],
        }
    results = {
        client: _direct_callback_result(
            client=client,
            target=targets[client],
            source_port=source_ports[client],
        )
        for client in ("rust", "mfc")
    }
    evidence = (
        direct_callback_diagnostic_evidence.build_direct_callback_diagnostic_evidence(
            requester_host="127.0.0.1",
            requester_tcp_port=SERVER_CALLBACK_REQUESTER_PORT,
            requester_user_hash=SERVER_CALLBACK_REQUESTER_HASH,
            target_host="127.0.0.1",
            targets=targets,
            requester_results=results,
            rust_records=records["rust"],
            mfc_records=records["mfc"],
        )
    )
    evidence["captures"] = captures
    report["checks"].update(
        {
            "client_direct_callback_kad_running": {
                client: {
                    "status": {"status": 200, "json": {"running": True}},
                    "observations": [{"running": True, "observed_at": 999.0}],
                }
                for client in ("rust", "mfc")
            },
            "client_direct_callback_targets": targets,
            "client_direct_callback_requests": results,
            "client_direct_callback_diagnostics": evidence,
            "mfc_diagnostics_shutdown": {"ok": True, "processId": 202},
        }
    )
    report["diagnostics"]["directCallback"] = evidence
    report["diagnostics"]["captures"] = {
        client: dict(capture) for client, capture in captures.items()
    }
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].append(
        direct_callback_diagnostic_evidence.COVERAGE_ID
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def _server_callback_records(
    *,
    client: str,
    process_id: int,
    run_id: str,
    trace_id: int,
) -> list[dict[str, object]]:
    server_endpoint = "127.0.0.1:4661"
    requester_endpoint = (
        f"{docker_ed2k_source_publisher.PUBLISHER_IP}:{SERVER_CALLBACK_REQUESTER_PORT}"
    )
    reply_payload = ipaddress.IPv4Address(
        docker_ed2k_source_publisher.PUBLISHER_IP
    ).packed + struct.pack("<H", SERVER_CALLBACK_REQUESTER_PORT)

    def row(
        sequence: int,
        event: str,
        *,
        body: dict[str, object],
    ) -> dict[str, object]:
        return {
            "schema": DIAG_EVENT_SCHEMA,
            "client": client,
            "runId": run_id,
            "processId": process_id,
            "segmentId": 0,
            "seq": sequence,
            "streamSeq": sequence,
            "family": "ed2k_tcp",
            "event": event,
            "keys": {
                "peer": server_endpoint,
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
                **body,
            },
        }

    return [
        row(
            10,
            "packet",
            body={
                "outcome": "accepted",
                "payloadLen": len(reply_payload),
                "payloadHex": reply_payload.hex(),
                "payloadHexTruncated": False,
            },
        ),
        row(
            11,
            "callback_request_applied",
            body={
                "outcome": "applied",
                "callbackEndpoint": requester_endpoint,
                "connectOptions": None,
                "userHash": None,
                "payloadLen": len(reply_payload),
                "stateId": "server.callback.request_applied",
                "milestone": "callback_dispatch",
                "dispatchAccepted": True,
            },
        ),
    ]


def _server_callback_request_result(
    *,
    client: str,
    command_id: str,
    target: dict[str, object],
) -> dict[str, object]:
    client_id = int(target["clientId"])
    tcp_port = int(target["tcpPort"])
    user_hash = bytes.fromhex(str(target["userHash"]))
    request_payload = ed2k_wire.encode_callback_request(client_id)
    hello_payload = (
        bytes([16])
        + user_hash
        + client_id.to_bytes(4, "little")
        + tcp_port.to_bytes(2, "little")
    )
    return {
        "schema": docker_ed2k_source_publisher.CALLBACK_RESULT_SCHEMA,
        "status": "completed",
        "commandId": command_id,
        "runId": SERVER_CALLBACK_RUN_ID,
        "targetClientId": client_id,
        "targetLabel": client,
        "requestOpcode": ed2k_wire.OP_CALLBACKREQUEST,
        "requestPayloadHex": request_payload.hex().upper(),
        "requestTranscript": {
            "direction": "send",
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "opcode": ed2k_wire.OP_CALLBACKREQUEST,
            "payloadLength": len(request_payload),
            "payloadSha256": hashlib.sha256(request_payload).hexdigest(),
            "payloadHex": request_payload.hex(),
        },
        "callbackConnection": {
            "userHash": user_hash.hex().upper(),
            "clientId": client_id,
            "tcpPort": tcp_port,
            "payloadLength": len(hello_payload),
            "payloadHex": hello_payload.hex().upper(),
            "peerHost": "127.0.0.1",
            "peerPort": 50_000 + client_id,
            "helloAnswerSent": True,
            "helloAnswerError": None,
        },
    }


def attach_server_callback(
    report: dict[str, object],
    *,
    run_directory: Path,
) -> dict[str, object]:
    login = bilateral_login_evidence()
    identities = {
        "rust": {
            "clientId": 4,
            "tcpPort": 4662,
            "userHash": "11" * 16,
        },
        "mfc": {
            "clientId": 2,
            "tcpPort": 4663,
            "userHash": "22" * 16,
        },
    }
    for client, identity in identities.items():
        login["clients"][client]["decodedLogin"] = {
            "client_id": 0,
            "tcp_port": identity["tcpPort"],
            "user_hash": identity["userHash"],
        }
        login["clients"][client]["decodedIdChange"] = {
            "assigned_id": identity["clientId"],
            "id_kind": "low-id",
        }
    attach_server_login(report, login, ("plaintext",))
    report["transfer_scenario"] = "server-callback-reply"
    report["protocol_case"] = ed2k_protocol_cases.protocol_surface(
        ed2k_protocol_cases.PROTOCOL_CASE_MAP["plain-server-plain-clients"]
    )
    report["network"]["ports"]["callback_requester_tcp"] = (
        SERVER_CALLBACK_REQUESTER_PORT
    )

    targets = {
        client: {
            "clientId": identity["clientId"],
            "idKind": "low-id",
            "tcpPort": identity["tcpPort"],
            "userHash": identity["userHash"],
        }
        for client, identity in identities.items()
    }
    records = {
        "rust": _server_callback_records(
            client="rust",
            process_id=101,
            run_id="rust-callback-run",
            trace_id=31,
        ),
        "mfc": _server_callback_records(
            client="mfc",
            process_id=202,
            run_id="mfc-callback-run",
            trace_id=41,
        ),
    }
    captures: dict[str, dict[str, object]] = {}
    for client, process_id, run_id in (
        ("rust", 101, "rust-callback-run"),
        ("mfc", 202, "mfc-callback-run"),
    ):
        diagnostics_dir = run_directory / "diagnostics" / client
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        prefix = "emulebb-rust-diag" if client == "rust" else "emulebb-mfc-diag"
        segment = diagnostics_dir / f"{prefix}-{process_id}-{run_id}-000000.jsonl"
        _write_server_source_segment(segment, records[client])
        captures[client] = {
            "diagnosticsDir": str(diagnostics_dir),
            "processId": process_id,
            "selectedSegments": [str(segment)],
        }

    callback_results = {
        "rust": _server_callback_request_result(
            client="rust",
            command_id="a" * 32,
            target=targets["rust"],
        ),
        "mfc": _server_callback_request_result(
            client="mfc",
            command_id="b" * 32,
            target=targets["mfc"],
        ),
    }
    requester_directory = run_directory / "ed2k-server" / "callback-requester"
    control_directory = requester_directory / "callback-control"
    control_directory.mkdir(parents=True)
    for client, result in callback_results.items():
        command_id = str(result["commandId"])
        request_payload = ed2k_wire.encode_callback_request(
            int(targets[client]["clientId"])
        )
        command = {
            "schema": docker_ed2k_source_publisher.CALLBACK_COMMAND_SCHEMA,
            "commandId": command_id,
            "runId": SERVER_CALLBACK_RUN_ID,
            "targetClientId": targets[client]["clientId"],
            "targetLabel": client,
            "timeoutSeconds": 20.0,
            "requestPayloadHex": request_payload.hex().upper(),
        }
        (control_directory / f"{command_id}.request.json").write_text(
            json.dumps(command),
            encoding="utf-8",
        )
        (control_directory / f"{command_id}.result.json").write_text(
            json.dumps(result),
            encoding="utf-8",
        )

    requester_login = {
        "assigned_id": docker_ed2k_source_publisher.PUBLISHER_HIGH_ID,
        "id_kind": "high-id",
        "welcome_opcodes": [ed2k_wire.OP_IDCHANGE, ed2k_wire.OP_SERVERSTATUS],
    }
    login_payload = ed2k_wire.encode_login_request(
        user_hash=SERVER_CALLBACK_REQUESTER_HASH,
        tcp_port=SERVER_CALLBACK_REQUESTER_PORT,
        nickname=SERVER_CALLBACK_REQUESTER_NICK,
        server_flags=docker_ed2k_source_publisher.PLAIN_SERVER_FLAGS,
    )
    offer_payload = ed2k_wire.encode_offer_file(
        file_hash=SERVER_CALLBACK_FILE_HASH,
        name=SERVER_CALLBACK_FILE_NAME,
        size=SERVER_CALLBACK_FILE_SIZE,
    )
    runtime = {
        "schema": docker_ed2k_source_publisher.RECEIPT_SCHEMA,
        "status": "ready",
        "runId": SERVER_CALLBACK_RUN_ID,
        "publisherIp": docker_ed2k_source_publisher.PUBLISHER_IP,
        "expectedHighId": docker_ed2k_source_publisher.PUBLISHER_HIGH_ID,
        "server": {"host": "127.0.0.1", "port": 4661},
        "publisher": {
            "nickname": SERVER_CALLBACK_REQUESTER_NICK,
            "tcpPort": SERVER_CALLBACK_REQUESTER_PORT,
            "userHash": SERVER_CALLBACK_REQUESTER_HASH.hex().upper(),
            "serverFlags": docker_ed2k_source_publisher.PLAIN_SERVER_FLAGS,
        },
        "file": {
            "hash": SERVER_CALLBACK_FILE_HASH.hex().upper(),
            "name": SERVER_CALLBACK_FILE_NAME,
            "size": SERVER_CALLBACK_FILE_SIZE,
        },
        "login": requester_login,
        "identityProbeAnswers": 0,
        "transcript": [
            {
                "direction": "send",
                "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                "opcode": ed2k_wire.OP_LOGINREQUEST,
                "payloadHex": login_payload.hex(),
            },
            {
                "direction": "send",
                "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                "opcode": ed2k_wire.OP_OFFERFILES,
                "payloadHex": offer_payload.hex(),
            },
        ],
    }
    (requester_directory / f"{SERVER_CALLBACK_RUN_ID}.publisher-ready.json").write_text(
        json.dumps(runtime),
        encoding="utf-8",
    )
    expected_source = {
        "client_id": docker_ed2k_source_publisher.PUBLISHER_HIGH_ID,
        "crypt_options": 0,
        "host": docker_ed2k_source_publisher.PUBLISHER_IP,
        "kind": "high-id",
        "port": SERVER_CALLBACK_REQUESTER_PORT,
        "user_hash": None,
    }
    report["server_callback_requester"] = {
        "nickname": SERVER_CALLBACK_REQUESTER_NICK,
        "ip": docker_ed2k_source_publisher.PUBLISHER_IP,
        "tcpPort": SERVER_CALLBACK_REQUESTER_PORT,
        "userHash": SERVER_CALLBACK_REQUESTER_HASH.hex().upper(),
        "serverFlags": docker_ed2k_source_publisher.PLAIN_SERVER_FLAGS,
        "login": requester_login,
        "client": {
            "client_name": SERVER_CALLBACK_REQUESTER_NICK,
            "nick": SERVER_CALLBACK_REQUESTER_NICK,
            "ip": docker_ed2k_source_publisher.PUBLISHER_IP,
            "high_id": True,
            "shared_files": 1,
        },
        "publication": {
            "hash": SERVER_CALLBACK_FILE_HASH.hex().upper(),
            "requested_size": SERVER_CALLBACK_FILE_SIZE,
            "indexed": True,
            "name": SERVER_CALLBACK_FILE_NAME,
            "size": SERVER_CALLBACK_FILE_SIZE,
            "sources": 1,
            "search_sources": 1,
            "complete_sources": 1,
            "endpoints": [expected_source],
            "search_result": {
                "hash": SERVER_CALLBACK_FILE_HASH.hex().upper(),
                "name": SERVER_CALLBACK_FILE_NAME,
                "size": SERVER_CALLBACK_FILE_SIZE,
                "sources": 1,
                "complete_sources": 1,
                "result_source_id": docker_ed2k_source_publisher.PUBLISHER_HIGH_ID,
                "result_source_port": SERVER_CALLBACK_REQUESTER_PORT,
            },
        },
        "runtime": runtime,
        "windowsRoute": {
            "destination": f"{docker_ed2k_source_publisher.PUBLISHER_IP}/32",
            "gateway": "127.0.0.1",
            "publishedTcpPort": SERVER_CALLBACK_REQUESTER_PORT,
        },
    }
    evidence = (
        server_callback_diagnostic_evidence.build_server_callback_diagnostic_evidence(
            server_endpoint="127.0.0.1:4661",
            requester_host=docker_ed2k_source_publisher.PUBLISHER_IP,
            requester_port=SERVER_CALLBACK_REQUESTER_PORT,
            targets=targets,
            requester_results=callback_results,
            rust_records=records["rust"],
            mfc_records=records["mfc"],
        )
    )
    evidence["captures"] = captures
    report["checks"]["client_server_callback_targets"] = targets
    report["checks"]["client_server_callback_requests"] = callback_results
    report["checks"]["client_server_callback_diagnostics"] = evidence
    report["checks"]["mfc_diagnostics_shutdown"] = {
        "ok": True,
        "processId": 202,
    }
    report["diagnostics"]["serverCallback"] = evidence
    report["diagnostics"]["captures"] = {
        client: {
            "diagnosticsDir": capture["diagnosticsDir"],
            "processId": capture["processId"],
            "selectedSegments": list(capture["selectedSegments"]),
        }
        for client, capture in captures.items()
    }
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].append(
        server_callback_diagnostic_evidence.COVERAGE_ID
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def attach_relayed_reask(
    report: dict[str, object],
    *,
    run_directory: Path,
) -> dict[str, object]:
    host = "127.0.0.1"
    ports = {
        "client1_udp": 31_004,
        "client2_udp": 31_005,
        "relayed_reask_source_tcp": 31_001,
        "relayed_reask_source_udp": 31_002,
        "relayed_reask_buddy_udp": 31_003,
    }
    request_raw = (
        bytes(
            (
                relayed_reask_probe.OP_EMULEPROT,
                relayed_reask_probe.OP_REASKCALLBACKUDP,
            )
        )
        + RELAYED_REASK_BUDDY_ID
        + RELAYED_REASK_FILE_HASH
        + bytes.fromhex("0100000000")
    )
    ack_raw = relayed_reask_probe.encode_reask_ack(
        queue_rank=RELAYED_REASK_QUEUE_RANK,
        requester_udp_version=4,
    )

    def row(
        client: str,
        process_id: int,
        run_id: str,
        sequence: int,
        family: str,
        event: str,
        keys: dict[str, object],
        body: dict[str, object],
    ) -> dict[str, object]:
        return {
            "schema": DIAG_EVENT_SCHEMA,
            "client": client,
            "runId": run_id,
            "processId": process_id,
            "segmentId": 0,
            "seq": sequence,
            "streamSeq": sequence,
            "family": family,
            "event": event,
            "keys": keys,
            "body": body,
        }

    sched_keys = {
        "peer": f"{host}:{ports['relayed_reask_source_tcp']}",
        "peerHash": RELAYED_REASK_SOURCE_HASH.hex(),
        "fileHash": RELAYED_REASK_FILE_HASH.hex(),
    }

    def records(client: str, process_id: int, run_id: str) -> list[dict[str, object]]:
        return [
            row(
                client,
                process_id,
                run_id,
                1,
                "sched",
                "udp_reask_source_registered",
                dict(sched_keys),
                {
                    "outcome": "accepted",
                    "sourceUdpEndpoint": f"{host}:{ports['relayed_reask_source_udp']}",
                    "sourceUdpVersion": 4,
                    "lowId": True,
                    "buddyEndpoint": f"{host}:{ports['relayed_reask_buddy_udp']}",
                    "buddyId": RELAYED_REASK_BUDDY_ID.hex(),
                },
            ),
            row(
                client,
                process_id,
                run_id,
                2,
                "sched",
                "udp_reask_schedule_decision",
                dict(sched_keys),
                {"outcome": "eligible", "reason": "eligible"},
            ),
            row(
                client,
                process_id,
                run_id,
                3,
                "sched",
                "udp_reask_decision",
                dict(sched_keys),
                {
                    "outcome": "sent",
                    "transportEligible": True,
                    "reason": "callback_reask_sent",
                    "path": "callback",
                },
            ),
            row(
                client,
                process_id,
                run_id,
                4,
                "ed2k_client_udp",
                "packet",
                {
                    "peer": f"{host}:{ports['relayed_reask_buddy_udp']}",
                    "fileHash": RELAYED_REASK_FILE_HASH.hex(),
                    "protocolMarker": relayed_reask_probe.OP_EMULEPROT,
                    "opcode": relayed_reask_probe.OP_REASKCALLBACKUDP,
                    "sendAttemptId": 9,
                },
                {
                    "direction": "send",
                    "outcome": "attempted",
                    "sendAttemptId": 9,
                    "role": "buddy_relay_request",
                    "transportMode": "plaintext",
                    "obfuscated": False,
                    "rawHex": request_raw.hex(),
                    "payloadHexTruncated": False,
                },
            ),
            row(
                client,
                process_id,
                run_id,
                5,
                "ed2k_client_udp",
                "send_outcome",
                {
                    "peer": f"{host}:{ports['relayed_reask_buddy_udp']}",
                    "sendAttemptId": 9,
                },
                {
                    "sendAttemptId": 9,
                    "outcome": "send_succeeded",
                    "deliveryKnown": True,
                    "role": "buddy_relay_request",
                },
            ),
            row(
                client,
                process_id,
                run_id,
                6,
                "ed2k_client_udp",
                "packet",
                {
                    "peer": f"{host}:{ports['relayed_reask_source_udp']}",
                    "protocolMarker": relayed_reask_probe.OP_EMULEPROT,
                    "opcode": relayed_reask_probe.OP_REASKACK,
                },
                {
                    "direction": "recv",
                    "outcome": "accepted",
                    "phase": "reask_reply",
                    "transportMode": "plaintext",
                    "obfuscated": False,
                    "rawHex": ack_raw.hex(),
                    "payloadHexTruncated": False,
                },
            ),
            row(
                client,
                process_id,
                run_id,
                7,
                "sched",
                "udp_reask_reply_applied",
                dict(sched_keys),
                {
                    "outcome": "applied",
                    "replyOpcode": relayed_reask_probe.OP_REASKACK,
                    "queueRank": RELAYED_REASK_QUEUE_RANK,
                    "requestPendingAfter": False,
                    "remoteQueueFullAfter": False,
                },
            ),
        ]

    controls: dict[str, object] = {}
    probes: dict[str, object] = {}
    captures: dict[str, dict[str, object]] = {}
    records_by_client: dict[str, list[dict[str, object]]] = {}
    for client, process_id, run_id, requester_port in (
        ("rust", 101, "rust-relayed-run", ports["client1_udp"]),
        ("mfc", 202, "mfc-relayed-run", ports["client2_udp"]),
    ):
        request = {
            "fileHash": RELAYED_REASK_FILE_HASH.hex(),
            "sourceIp": host,
            "sourceTcpPort": ports["relayed_reask_source_tcp"],
            "sourceUdpPort": ports["relayed_reask_source_udp"],
            "sourceUserHash": RELAYED_REASK_SOURCE_HASH.hex(),
            "sourceUdpVersion": 4,
            "buddyIp": host,
            "buddyUdpPort": ports["relayed_reask_buddy_udp"],
            "buddyId": RELAYED_REASK_BUDDY_ID.hex(),
        }
        controls[client] = {
            "request": request,
            "response": {
                "status": 200,
                "json": {
                    "accepted": True,
                    "fileHash": RELAYED_REASK_FILE_HASH.hex(),
                    "sourceEndpoint": f"{host}:{ports['relayed_reask_source_udp']}",
                    "sourceTcpPort": ports["relayed_reask_source_tcp"],
                    "sourceUserHash": RELAYED_REASK_SOURCE_HASH.hex(),
                    "sourceUdpVersion": 4,
                    "buddyEndpoint": f"{host}:{ports['relayed_reask_buddy_udp']}",
                    "buddyId": RELAYED_REASK_BUDDY_ID.hex(),
                    "state": "queued-lowid-source",
                },
            },
        }
        decoded = relayed_reask_probe.decode_reask_callback_udp(
            request_raw,
            source_udp_version=4,
        )
        probes[client] = {
            "schema": "emulebb.relayed-reask-probe/1",
            "status": "completed",
            "targetLabel": client,
            "buddyEndpoint": f"{host}:{ports['relayed_reask_buddy_udp']}",
            "sourceEndpoint": f"{host}:{ports['relayed_reask_source_udp']}",
            "requesterEndpoint": f"{host}:{requester_port}",
            "request": {**decoded, "receivedAt": 1000.0},
            "response": {
                "protocol": relayed_reask_probe.OP_EMULEPROT,
                "opcode": relayed_reask_probe.OP_REASKACK,
                "rawHex": ack_raw.hex().upper(),
                "payloadHex": ack_raw[2:].hex().upper(),
                "queueRank": RELAYED_REASK_QUEUE_RANK,
                "sentBytes": len(ack_raw),
                "sentAt": 1000.1,
            },
        }
        client_records = records(client, process_id, run_id)
        records_by_client[client] = client_records
        diagnostics_dir = run_directory / "diagnostics" / client
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        prefix = "emulebb-rust-diag" if client == "rust" else "emulebb-mfc-diag"
        segment = diagnostics_dir / f"{prefix}-{process_id}-{run_id}-000000.jsonl"
        _write_server_source_segment(segment, client_records)
        captures[client] = {
            "diagnosticsDir": str(diagnostics_dir),
            "processId": process_id,
            "selectedSegments": [str(segment)],
        }

    evidence = (
        relayed_reask_diagnostic_evidence.build_relayed_reask_diagnostic_evidence(
            file_hash=RELAYED_REASK_FILE_HASH,
            source_host=host,
            source_tcp_port=ports["relayed_reask_source_tcp"],
            source_udp_port=ports["relayed_reask_source_udp"],
            source_user_hash=RELAYED_REASK_SOURCE_HASH,
            source_udp_version=4,
            buddy_host=host,
            buddy_udp_port=ports["relayed_reask_buddy_udp"],
            buddy_id=RELAYED_REASK_BUDDY_ID,
            requester_udp_ports={
                "rust": ports["client1_udp"],
                "mfc": ports["client2_udp"],
            },
            queue_rank=RELAYED_REASK_QUEUE_RANK,
            controls=controls,
            probe_results=probes,
            rust_records=records_by_client["rust"],
            mfc_records=records_by_client["mfc"],
        )
    )
    evidence["captures"] = captures

    rust_nodes = kad_nodes.encode_nodes_dat(
        [
            kad_nodes.BootstrapContact(
                host,
                ports["relayed_reask_source_tcp"],
                ports["relayed_reask_source_tcp"],
            )
        ]
    )
    mfc_nodes = kad_nodes.encode_nodes_dat([])
    launch_dir = run_directory / "launch-inputs" / "relayed-reask-kad"
    launch_dir.mkdir(parents=True)
    launch_receipts: dict[str, object] = {}
    for label, name, payload in (
        ("rustNodesDat", "rust-nodes.dat", rust_nodes),
        ("mfcNodesDat", "mfc-nodes.dat", mfc_nodes),
    ):
        path = launch_dir / name
        path.write_bytes(payload)
        launch_receipts[label] = {
            "path": str(path),
            "sizeBytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    link = (
        f"ed2k://|file|{RELAYED_REASK_FILE_NAME}|{RELAYED_REASK_FILE_SIZE}|"
        f"{RELAYED_REASK_FILE_HASH.hex()}|/"
    )
    report["transfer_scenario"] = "relayed-reask"
    report["protocol_case"] = ed2k_protocol_cases.protocol_surface(
        ed2k_protocol_cases.PROTOCOL_CASE_MAP["plain-server-plain-clients"]
    )
    report["network"] = {
        "p2p_bind_interface_address": host,
        "ports": ports,
        "relayedReaskKadIsolation": {
            "publicDiscovery": False,
            "rustBootstrapSeed": {
                "endpoint": f"{host}:{ports['relayed_reask_source_tcp']}",
                "tcpPort": ports["relayed_reask_source_tcp"],
            },
            "mfcBootstrapSeeds": [],
            "launchInputs": launch_receipts,
        },
    }
    transfer_row = {
        "hash": RELAYED_REASK_FILE_HASH.hex(),
        "displayName": RELAYED_REASK_FILE_NAME,
        "sizeBytes": RELAYED_REASK_FILE_SIZE,
    }
    report["checks"].update(
        {
            "client_relayed_reask_kad_running": {
                client: {
                    "status": {"status": 200, "json": {"running": True}},
                    "observations": [{"running": True, "observed_at": 999.0}],
                }
                for client in ("rust", "mfc")
            },
            "client_relayed_reask_stimulus": {
                "mode": "source-free-ed2k-link-plus-diagnostic-lowid-source",
                "link": link,
                "hash": RELAYED_REASK_FILE_HASH.hex(),
                "name": RELAYED_REASK_FILE_NAME,
                "sizeBytes": RELAYED_REASK_FILE_SIZE,
                "source": {
                    "host": host,
                    "tcpPort": ports["relayed_reask_source_tcp"],
                    "udpPort": ports["relayed_reask_source_udp"],
                    "userHash": RELAYED_REASK_SOURCE_HASH.hex(),
                    "udpVersion": 4,
                },
                "buddy": {
                    "host": host,
                    "udpPort": ports["relayed_reask_buddy_udp"],
                    "id": RELAYED_REASK_BUDDY_ID.hex(),
                },
                "queueRank": RELAYED_REASK_QUEUE_RANK,
            },
            "client_relayed_reask_transfers": {
                client: {
                    "add": {
                        "item": {
                            "ok": True,
                            "hash": RELAYED_REASK_FILE_HASH.hex(),
                        }
                    },
                    "transfer": dict(transfer_row),
                }
                for client in ("rust", "mfc")
            },
            "client_relayed_reask_controls": controls,
            "client_relayed_reask_probe": probes,
            "client_relayed_reask_diagnostics": evidence,
            "mfc_diagnostics_shutdown": {"ok": True, "processId": 202},
        }
    )
    report["diagnostics"]["relayedReask"] = evidence
    report["diagnostics"]["captures"] = {
        client: dict(capture) for client, capture in captures.items()
    }
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].append(
        relayed_reask_diagnostic_evidence.COVERAGE_ID
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def write_transfer_report(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    output_root = tmp_path / "output"
    run = (
        output_root
        / "reports"
        / "deterministic-two-client-transfer"
        / "20261101T183823Z-test"
    )
    fixture_path = run / "client2-shared" / "fixture.bin"
    delivered_path = run / "profiles" / "rust" / "incoming" / "fixture.bin"
    fixture_path.parent.mkdir(parents=True)
    delivered_path.parent.mkdir(parents=True)
    content = b"canonical transfer fixture"
    fixture_path.write_bytes(content)
    delivered_path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    report: dict[str, object] = {
        "suite": "deterministic-two-client-transfer",
        "status": "passed",
        "runner_revision": "1" * 40,
        "fixture": {
            "name": "fixture.bin",
            "path": str(fixture_path),
            "size": len(content),
            "sha256": digest,
        },
        "checks": {
            "client1_transfer_completed_file": {
                "completedBytes": len(content),
                "deliveredPath": str(delivered_path),
                "hash": FILE_HASH,
                "state": "completed",
            }
        },
        "diagnostics": {
            "schema": SCHEMA,
            "ok": True,
            "failures": [],
            "fileHash": FILE_HASH,
            "metadataRecoveryRequired": False,
            "coverageClaims": {
                "eligibleCoverageIds": [
                    "peer.startup.aich",
                    "peer.startup.multipacket-ext2",
                    "queue.admission",
                    "transfer.block.uncompressed",
                ],
                "evidenceLayers": list(EVIDENCE_LAYERS),
            },
            "startupChecks": {
                "multipacketRequestFrames": {
                    "ok": True,
                    "matchedFrameCount": 1,
                    "leftFrameCount": 1,
                    "rightFrameCount": 1,
                    "unmatchedLeftFrameCount": 0,
                    "unmatchedRightFrameCount": 0,
                },
                "multipacketAnswerFrames": {
                    "ok": True,
                    "matchedFrameCount": 1,
                    "leftFrameCount": 1,
                    "rightFrameCount": 1,
                    "unmatchedLeftFrameCount": 0,
                    "unmatchedRightFrameCount": 0,
                },
                "multipacketRequestSemantics": {"ok": True},
                "multipacketAnswerSemantics": {"ok": True},
                "hashsetRequestFrames": {
                    "ok": True,
                    "matchedFrameCount": 1,
                    "leftFrameCount": 1,
                    "rightFrameCount": 1,
                    "unmatchedLeftFrameCount": 0,
                    "unmatchedRightFrameCount": 0,
                },
                "hashsetAnswerFrames": {
                    "ok": True,
                    "matchedFrameCount": 1,
                    "leftFrameCount": 1,
                    "rightFrameCount": 1,
                    "unmatchedLeftFrameCount": 0,
                    "unmatchedRightFrameCount": 0,
                },
                "hashsetRequestSemantics": {"ok": True},
                "hashsetAnswerSemantics": {"ok": True},
                "persistedManifest": {
                    "ok": True,
                    "checks": {
                        "fileHash": True,
                        "fileName": True,
                        "fileSize": True,
                        "completed": True,
                        "md4Acquired": True,
                        "md4Hashset": True,
                        "aichAcquired": True,
                        "aichRoot": True,
                        "aichHashset": True,
                    },
                    "md4HashsetCount": 2,
                    "aichHashsetCount": 2,
                },
            },
            "wireChecks": {
                "requestFrames": {
                    "ok": True,
                    "matchedFrameCount": 2,
                    "leftFrameCount": 2,
                    "rightFrameCount": 2,
                    "unmatchedLeftFrameCount": 0,
                    "unmatchedRightFrameCount": 0,
                    "opcodes": ["OP_REQUESTPARTS"],
                },
                "payloadFrames": {
                    "ok": True,
                    "matchedFrameCount": 3,
                    "leftFrameCount": 3,
                    "rightFrameCount": 3,
                    "unmatchedLeftFrameCount": 0,
                    "unmatchedRightFrameCount": 0,
                    "opcodes": ["OP_SENDINGPART"],
                },
            },
            "clients": {
                "mfc": {
                    "checks": {
                        "uploadRequestServed": {
                            "matchingRecordCount": 2,
                        }
                    }
                }
            },
        },
        "profiles": {
            "rust": {
                "client_key": "emulebb_rust",
                "app_sha256": "2" * 64,
                "source_revision": "3" * 40,
            },
            "mfc": {
                "client_key": "mfc_oracle",
                "app_sha256": "4" * 64,
                "availability": {"source_revision": "5" * 40},
            },
        },
    }
    report_path = run / "deterministic-two-client-transfer-result.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path, output_root, report


def test_build_transfer_registration_accepts_only_causally_claimed_ids(
    tmp_path: Path,
) -> None:
    report_path, output_root, _ = write_transfer_report(tmp_path)

    registration = build_transfer_registration(report_path, output_root=output_root)

    receipt = registration["evidenceReceipt"]
    assert receipt["artifactLocator"] == (
        "output-root:reports/deterministic-two-client-transfer/"
        "20261101T183823Z-test/deterministic-two-client-transfer-result.json"
    )
    assert receipt["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "transfer.block.uncompressed",
    ]
    assert receipt["receiptId"] == "rust-mfc-transfer-20261101t183823z"
    assert [row["coverageId"] for row in registration["coverageEvidence"]] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "transfer.block.uncompressed",
    ]


def test_build_transfer_registration_rejects_coverage_overclaim(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].append(
        "queue.rank-transition"
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="claims exceed"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_hash_only_metadata_recovery(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "hash-only-metadata-recovery"
    report["diagnostics"]["metadataRecoveryRequired"] = True
    report["diagnostics"]["metadataRecovery"] = {"ok": True, "sourceMatch": True}
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].insert(
        1,
        "peer.startup.metadata-recovery",
    )
    report["checks"]["client1_transfer_stimulus"] = {
        "mode": "hash-only-direct-source-link-with-profile-identity",
        "inputMetadata": {"name": FILE_HASH, "size": 0, "hash": FILE_HASH},
        "authorityMetadata": {
            "name": "fixture.bin",
            "size": report["fixture"]["size"],
            "hash": FILE_HASH,
        },
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert (
        "peer.startup.metadata-recovery"
        in registration["evidenceReceipt"]["coverageIds"]
    )


@pytest.mark.parametrize(
    ("transport_plan", "connection_id"),
    [
        (("plaintext",), "server.connect.plaintext"),
        (("obfuscated",), "server.connect.obfuscated"),
        (("obfuscated", "plaintext"), "server.connect.fallback"),
    ],
)
def test_build_transfer_registration_accepts_bilateral_server_login(
    tmp_path: Path, transport_plan: tuple[str, ...], connection_id: str
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(transport_plan)
    attach_server_login(report, login, transport_plan)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        connection_id,
        "server.login.request",
        "transfer.block.uncompressed",
    ]


def test_build_transfer_registration_rejects_one_sided_server_login(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence()
    login["clients"]["mfc"]["ok"] = False
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="mfc server login evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_final_trace_components(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    login["clients"]["mfc"]["idChangeTraceId"] = 99
    attach_server_login(report, login, plan)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="final server-login trace IDs"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_attempt_sequence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    login["clients"]["rust"]["attemptStartSequences"] = [5, 1]
    attach_server_login(report, login, plan)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="transport attempts are not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_joins_singular_attempt_to_final_trace(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["attemptTraceIds"] = [77]
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="singular server attempt"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_boolean_login_count(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["finalLoginPacketCount"] = True
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="positive integer"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_duplicate_acceptance_count(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["loginAcceptedCount"] = 2
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="not singular and causal"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_wrong_failed_attempt_login_count(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    login["clients"]["mfc"]["failedAttemptLoginPacketCount"] = 0
    login["clients"]["mfc"]["loginPacketCount"] = 1
    attach_server_login(report, login, plan)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="fallback evidence is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_failed_login_trace(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    login["clients"]["mfc"]["failedAttemptLoginTraceId"] = 99
    attach_server_login(report, login, plan)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="fallback evidence is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_rust_send_outcome(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["sendOutcomeTraceId"] = 99
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="send outcome is not joined"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_late_rust_send_outcome(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["sendOutcomeSequence"] = 6
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="send outcome is not joined"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_malformed_attempt_shape(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["attemptPhases"] = ["malformed"]
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="transport attempts are not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_case_flags_that_only_match_report_claims(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    attach_server_login(report, login, plan)
    report["protocol_case"]["server_protocol_obfuscation"] = True
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="flags do not match"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_fallback_with_known_rust_metadata(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    attach_server_login(report, login, plan)
    report["checks"]["rust_server_entry"]["udpFlags"] = 0x123
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="not endpoint-only"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_retired_server_login_mode_field(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence()
    login["expectedTransportMode"] = "plaintext"
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid transport plan"):
        build_transfer_registration(report_path, output_root=output_root)


def write_server_callback_report(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_callback(report, run_directory=report_path.parent)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path, output_root, report, evidence


def write_direct_callback_report(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_direct_callback(report, run_directory=report_path.parent)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path, output_root, report, evidence


def test_build_transfer_registration_accepts_exact_direct_callback(
    tmp_path: Path,
) -> None:
    report_path, output_root, _, _ = write_direct_callback_report(tmp_path)

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "lowid.direct-callback",
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.connect.plaintext",
        "server.login.request",
        "transfer.block.uncompressed",
    ]
    reason = next(
        row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"] == "lowid.direct-callback"
    )
    assert "same exact direct UDP callback request" in reason
    assert "HELLO matching the assigned identity" in reason


def test_build_transfer_registration_rejects_direct_callback_without_evidence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_direct_callback_report(tmp_path)
    del report["diagnostics"]["directCallback"]
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_changed_direct_callback_target(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_direct_callback_report(tmp_path)
    report["checks"]["client_direct_callback_targets"]["rust"]["clientId"] = 7
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="do not derive exactly"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_public_direct_callback_seed(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_direct_callback_report(tmp_path)
    report["network"]["directCallbackKadIsolation"]["publicDiscovery"] = True
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="Kad isolation is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_uses_retained_launch_input_after_mfc_shutdown_mutation(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_direct_callback_report(tmp_path)
    mfc_nodes = Path(report["profiles"]["mfc"]["config_dir"]) / "nodes.dat"
    kad_nodes.write_nodes_dat(
        mfc_nodes,
        [kad_nodes.BootstrapContact("127.0.0.1", 4672, 4662)],
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert "lowid.direct-callback" in registration["evidenceReceipt"]["coverageIds"]


def test_build_transfer_registration_rejects_mutated_mfc_kad_launch_input(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_direct_callback_report(tmp_path)
    retained = Path(
        report["network"]["directCallbackKadIsolation"]["launchInputs"]["mfcNodesDat"][
            "path"
        ]
    )
    retained.write_bytes(
        kad_nodes.encode_nodes_dat(
            [kad_nodes.BootstrapContact("127.0.0.1", 4672, 4662)]
        )
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="mfcNodesDat launch input does not match"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_direct_callback_capture(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, evidence = write_direct_callback_report(tmp_path)
    segment = Path(evidence["captures"]["mfc"]["selectedSegments"][0])
    records = [
        json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    records[0]["body"]["note"] = "direct_callback_disabled"
    _write_server_source_segment(segment, records)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def write_relayed_reask_report(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_relayed_reask(report, run_directory=report_path.parent)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path, output_root, report, evidence


def test_build_transfer_registration_accepts_exact_relayed_reask(
    tmp_path: Path,
) -> None:
    report_path, output_root, _, _ = write_relayed_reask_report(tmp_path)

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert "lowid.relayed-reask" in registration["evidenceReceipt"]["coverageIds"]
    reason = next(
        row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"] == "lowid.relayed-reask"
    )
    assert "identical OP_REASKCALLBACKUDP bytes" in reason
    assert "OP_REASKACK queue rank" in reason


def test_build_transfer_registration_rejects_relayed_reask_without_evidence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_relayed_reask_report(tmp_path)
    del report["diagnostics"]["relayedReask"]
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_public_relayed_reask_seed(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_relayed_reask_report(tmp_path)
    report["network"]["relayedReaskKadIsolation"]["publicDiscovery"] = True
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="Kad isolation is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_relayed_reask_capture(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, evidence = write_relayed_reask_report(tmp_path)
    segment = Path(evidence["captures"]["mfc"]["selectedSegments"][0])
    records = [
        json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    records[-1]["body"]["queueRank"] = RELAYED_REASK_QUEUE_RANK + 1
    _write_server_source_segment(segment, records)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_exact_server_callback(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_server_callback_report(tmp_path)

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert (
        "lowid.server-callback"
        not in report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"]
    )
    assert registration["evidenceReceipt"]["coverageIds"] == [
        "lowid.server-callback",
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.connect.plaintext",
        "server.login.request",
        "server.reply.callback",
        "transfer.block.uncompressed",
    ]
    reason = next(
        row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"] == "server.reply.callback"
    )
    assert "callback HELLO matching its accepted LowID login identity" in reason
    lowid_reason = next(
        row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"] == "lowid.server-callback"
    )
    assert "started from an accepted LowID assignment" in lowid_reason
    assert "connected to the HighID requester" in lowid_reason


def test_build_transfer_registration_rejects_callback_wrong_trace(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, evidence = write_server_callback_report(tmp_path)
    segment = Path(evidence["captures"]["rust"]["selectedSegments"][0])
    records = [
        json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    records[1]["keys"]["traceId"] = 99
    _write_server_source_segment(segment, records)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_changed_callback_target(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_server_callback_report(tmp_path)
    report["checks"]["client_server_callback_targets"]["rust"]["clientId"] = 7
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="do not derive exactly"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_changed_callback_control_file(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_server_callback_report(tmp_path)
    result = report["checks"]["client_server_callback_requests"]["rust"]
    command_id = result["commandId"]
    command_path = (
        report_path.parent
        / "ed2k-server"
        / "callback-requester"
        / "callback-control"
        / f"{command_id}.request.json"
    )
    command = json.loads(command_path.read_text(encoding="utf-8"))
    command["requestPayloadHex"] = "FFFFFFFF"
    command_path.write_text(json.dumps(command), encoding="utf-8")

    with pytest.raises(ValueError, match="request receipt is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_changed_callback_hello_bytes(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_server_callback_report(tmp_path)
    result = report["checks"]["client_server_callback_requests"]["rust"]
    connection = result["callbackConnection"]
    connection["payloadHex"] = "10FF" + connection["payloadHex"][4:]
    result_path = (
        report_path.parent
        / "ed2k-server"
        / "callback-requester"
        / "callback-control"
        / f"{result['commandId']}.result.json"
    )
    result_path.write_text(json.dumps(result), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_inexact_callback_route(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_server_callback_report(tmp_path)
    report["server_callback_requester"]["windowsRoute"]["gateway"] = "127.0.0.2"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="route is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_callback_capture_bytes(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, evidence = write_server_callback_report(tmp_path)
    segment = Path(evidence["captures"]["mfc"]["selectedSegments"][0])
    records = [
        json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    payload = records[0]["body"]["payloadHex"]
    records[0]["body"]["payloadHex"] = payload[:-2] + "00"
    _write_server_source_segment(segment, records)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_callback_evidence_in_wrong_scenario(
    tmp_path: Path,
) -> None:
    report_path, output_root, report, _ = write_server_callback_report(tmp_path)
    report["transfer_scenario"] = "server-login-request"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="requires its dedicated scenario"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_exact_server_keyword_search(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.search",
        "server.search.keyword",
        "transfer.block.uncompressed",
    ]
    search_rows = [
        row
        for row in registration["coverageEvidence"]
        if row["coverageId"]
        in server_search_diagnostic_evidence.COVERAGE_IDS_BY_VARIANT[
            server_search_diagnostic_evidence.KEYWORD_VARIANT
        ]
    ]
    assert [row["coverageId"] for row in search_rows] == [
        "server.reply.search",
        "server.search.keyword",
    ]


def test_build_transfer_registration_accepts_exact_server_advanced_search(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report, "server-advanced-search")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.search",
        "server.search.advanced",
        "transfer.block.uncompressed",
    ]
    rows = {
        row["coverageId"]: row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"] in {"server.reply.search", "server.search.advanced"}
    }
    assert set(rows) == {"server.reply.search", "server.search.advanced"}
    assert "encoded advanced request" in rows["server.search.advanced"]


def test_build_transfer_registration_rejects_advanced_search_without_exact_bounds(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report, "server-advanced-search")
    evidence["criteria"]["maxSizeBytes"] += 1
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected criteria"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_server_search_schema(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["schema"] = (
        "emulebb-build-tests.deterministic-server-search-diagnostics.v2"
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_one_client_search_mismatch(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["clients"]["mfc"]["wire"]["reply"]["exactRow"]["hash"] = FILE_HASH
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match server_search_fixture"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_joins_search_result_to_neutral_publisher(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report)
    report["server_search_fixture"]["publication"]["search_result"][
        "result_source_id"
    ] = 99
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="not joined to the neutral publisher"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_nonisolated_server_search_fixture(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report)
    report["fixture"]["name"] = SEARCH_FILE_NAME
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="not isolated from the MFC transfer fixture"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_unjoined_server_search_id(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["clients"]["mfc"]["rest"]["searchId"] = "different-search"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="REST search evidence is not joined"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_out_of_order_server_search_lifecycle(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["clients"]["rust"]["lifecycle"]["sendOutcomeSequence"] = 19
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="lifecycle is not causally ordered"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize("claim_field", ["observedCoverageIds", "eligibleCoverageIds"])
def test_build_transfer_registration_rejects_inexact_server_search_claims(
    tmp_path: Path,
    claim_field: str,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    if claim_field == "observedCoverageIds":
        evidence[claim_field] = ["server.search.keyword"]
        error = "observations are not exact"
    else:
        evidence["coverageClaims"][claim_field] = ["server.search.keyword"]
        error = "claims are not exact"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_false_server_search_comparison(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["comparison"]["requestPayloadEqual"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="comparison is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_wire_rest_source_mismatch_even_when_bilateral(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report)
    for driven in report["checks"]["client_server_searches"].values():
        driven["result"]["sources"] = 0
        driven["result"]["completeSources"] = 0
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(
        ValueError, match="wire result is not joined to its applied REST result"
    ):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_invalid_search_availability_values(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    for client in ("rust", "mfc"):
        report["checks"]["client_server_searches"][client]["result"]["sources"] = True
        evidence["clients"][client]["wire"]["reply"]["exactRow"]["sources"] = True
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="must be a non-negative integer"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    ("client", "field"),
    [("rust", "method"), ("mfc", "requestedMethod")],
)
def test_build_transfer_registration_rejects_wrong_authority_search_method_schema(
    tmp_path: Path,
    client: str,
    field: str,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report)
    report["checks"]["client_server_searches"][client]["created"][field] = "server"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match=f"{client} driven server search is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_wrong_evidence_search_method_schema(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["clients"]["mfc"]["rest"]["method"] = {
        "createdRequested": "server",
        "finalRequested": "server",
        "finalResolved": "server",
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="REST search evidence is not joined"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_noncanonical_server_search_payload(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["clients"]["mfc"]["wire"]["request"]["payloadHex"] = "00"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="request is not singular and exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_unindexed_server_search_fixture(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_search(report)
    report["server_search_fixture"]["publication"]["indexed"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="not an exact indexed observation"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_server_search_without_exact_publication(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "server-keyword-search"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_exact_server_tcp_metadata(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_tcp_metadata(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.tcp-ident",
        "server.reply.tcp-status",
        "transfer.block.uncompressed",
    ]
    rows = {
        row["coverageId"]: row
        for row in registration["coverageEvidence"]
        if row["coverageId"]
        in server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    }
    assert set(rows) == set(
        server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    )
    assert "per-client dynamic counts" in rows["server.reply.tcp-status"]["reason"]


def test_build_transfer_registration_rejects_tcp_metadata_without_evidence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "server-tcp-metadata"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_tcp_metadata_schema(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_tcp_metadata(report)
    evidence["schema"] = (
        "emulebb-build-tests.deterministic-server-tcp-metadata-diagnostics.v0"
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_duplicate_tcp_metadata_packet(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_tcp_metadata(report)
    evidence["clients"]["mfc"]["wire"]["packetCounts"]["status"] = 2
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="packets are not singular"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_unjoined_tcp_metadata_application(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_tcp_metadata(report)
    evidence["clients"]["rust"]["applied"]["status"]["users"] = 999
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="not joined to its post-apply event"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_tcp_metadata_raw_rest_drift(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_tcp_metadata(report)
    report["checks"]["client_server_tcp_metadata_rest"]["mfc"]["serverEntity"][
        "files"
    ] = 999
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="raw REST server entity does not match"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_fabricated_tcp_metadata_comparison(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_tcp_metadata(report)
    evidence["clients"]["mfc"]["wire"]["ident"]["server_hash"] = "F" * 32
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not compare exactly"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_plaintext_tcp_metadata_claim(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_tcp_metadata(report)
    evidence["clients"]["rust"]["wire"]["transportModes"][2] = "plaintext"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="transport is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_wrong_tcp_metadata_send_outcome(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_tcp_metadata(report)
    evidence["clients"]["rust"]["wire"]["requestOutcome"] = "send_succeeded"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="request or decode result is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_exact_server_tcp_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.sources",
        "server.source.tcp-plain",
        "transfer.block.uncompressed",
    ]
    reasons = {
        row["coverageId"]: row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"] in server_source_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    }
    assert "singular HighID source" in reasons["server.reply.sources"]
    assert "plaintext GETSOURCES" in reasons["server.source.tcp-plain"]


def test_build_transfer_registration_accepts_obfuscated_server_tcp_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
        transport_mode="obfuscated",
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert (
        "server.source.tcp-obfuscated" in registration["evidenceReceipt"]["coverageIds"]
    )
    reasons = {
        row["coverageId"]: row["reason"] for row in registration["coverageEvidence"]
    }
    assert "obfuscated GETSOURCES" in reasons["server.source.tcp-obfuscated"]


def test_build_transfer_registration_rejects_source_transport_case_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
        transport_mode="obfuscated",
    )
    report["protocol_case"] = ed2k_protocol_cases.protocol_surface(
        ed2k_protocol_cases.PROTOCOL_CASE_MAP["plain-server-plain-clients"]
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="selected server transport"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_source_protocol_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
        transport_mode="obfuscated",
    )
    report["protocol_case"]["client_crypt_required"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="exact canonical surface"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_source_scenario_without_evidence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "server-tcp-source"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_source_evidence_in_wrong_scenario(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    report["transfer_scenario"] = "full-metadata-link"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="requires its dedicated scenario"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_server_source_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    evidence["schema"] = (
        "emulebb-build-tests.deterministic-server-source-diagnostics.v0"
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_server_source_segment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    segment = Path(evidence["captures"]["rust"]["selectedSegments"][0])
    rows = [
        json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["schema"] = "diag_event_v1"
    _write_server_source_segment(segment, rows)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected diagnostic schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_source_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    evidence["clients"]["rust"]["wire"]["application"]["sourceCountAfter"] = 2
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hash", "ff" * 16),
        ("name", "wrong-source.bin"),
        ("size", SERVER_SOURCE_FILE_SIZE + 1),
    ],
)
def test_build_transfer_registration_rejects_noncanonical_source_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    report["server_source_fixture"][field] = value
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical source fixture"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    ("source_request_version", "request_opcode_name"),
    [(1, "OP_GLOBGETSOURCES"), (2, "OP_GLOBGETSOURCES2")],
)
def test_build_transfer_registration_accepts_exact_server_udp_source_version(
    tmp_path: Path,
    source_request_version: int,
    request_opcode_name: str,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=source_request_version,
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.sources",
        f"server.source.udp-v{source_request_version}",
        "transfer.block.uncompressed",
    ]
    reasons = {
        row["coverageId"]: row["reason"] for row in registration["coverageEvidence"]
    }
    assert (
        request_opcode_name in reasons[f"server.source.udp-v{source_request_version}"]
    )
    assert "UDP HighID source" in reasons["server.reply.sources"]


def test_build_transfer_registration_rejects_udp_source_v1_without_evidence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "server-udp-source-v1"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_udp_source_v1_wrong_scenario(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    report["transfer_scenario"] = "full-metadata-link"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="requires its dedicated scenario"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_udp_source_v1_schema(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    evidence["schema"] = (
        "emulebb-build-tests.deterministic-server-udp-source-v1-diagnostics.v0"
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_udp_source_v1_receipt(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    evidence["clients"]["rust"]["wire"]["application"]["sourceCountAfter"] = 2
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_udp_source_v1_transcript_drift(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    transcript_path = report_path.parent / "server-udp-source-v1-transcript.json"
    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    transcript["events"][-1]["frameHex"] = "E39B00"
    transcript_path.write_text(json.dumps(transcript), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable transcript"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_udp_source_v1_transcript(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    transcript = report["server_udp_source_v1_target"]
    transcript["events"][-1]["frameHex"] = "E39B00"
    transcript_path = report_path.parent / "server-udp-source-v1-transcript.json"
    transcript_path.write_text(json.dumps(transcript), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_udp_source_v1_segment(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    segment = Path(evidence["captures"]["rust"]["selectedSegments"][0])
    rows = [
        json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["schema"] = "diag_event_v1"
    _write_server_source_segment(segment, rows)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected diagnostic schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_udp_source_v1_stale_capture(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_source(
        report,
        run_directory=report_path.parent,
        source_request_version=1,
    )
    evidence["captures"]["rust"]["processId"] = 999
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="final process selection"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rebuilds_source_evidence_from_raw_rest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    report["checks"]["client_server_source_transfers"]["rust"]["sources"] = 0
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assigned_id", SERVER_SOURCE_PUBLISHER_ID + 1),
        ("tcpPort", SERVER_SOURCE_PUBLISHER_PORT + 1),
    ],
)
def test_build_transfer_registration_rejects_wrong_source_publisher_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    publisher = report["server_source_fixture"]["publisher"]
    if field == "assigned_id":
        publisher["login"][field] = value
    else:
        publisher[field] = value
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="(HighID|runtime receipt)"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    "mutation",
    ["identity", "server-flags", "login-frame", "offer-frame"],
)
def test_build_transfer_registration_rejects_mutated_source_publisher_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    runtime = report["server_source_fixture"]["publisher"]["runtime"]
    if mutation == "identity":
        runtime["publisherIp"] = "198.18.240.3"
    elif mutation == "server-flags":
        runtime["publisher"]["serverFlags"] ^= ed2k_wire.SRVCAP_SUPPORTCRYPT
    elif mutation == "login-frame":
        runtime["transcript"][0]["payloadHex"] = "00"
    else:
        runtime["transcript"][1]["payloadHex"] = "00"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="runtime receipt is not canonical"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_conflicting_publisher_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
        transport_mode="obfuscated",
    )
    runtime = report["server_source_fixture"]["publisher"]["runtime"]
    runtime["transcript"].append(
        ed2k_wire.Ed2kFrame(
            ed2k_wire.PROTO_EDONKEY,
            ed2k_wire.OP_LOGINREQUEST,
            ed2k_wire.encode_login_request(
                user_hash=SERVER_SOURCE_PUBLISHER_HASH,
                tcp_port=SERVER_SOURCE_PUBLISHER_PORT,
                nickname=SERVER_SOURCE_PUBLISHER_NICK,
                server_flags=docker_ed2k_source_publisher.PLAIN_SERVER_FLAGS,
            ),
        ).evidence("send")
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="runtime receipt is not canonical"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    "conflict",
    ["request-size", "request-truncated", "reply-trace", "reply-length"],
)
def test_build_transfer_registration_rejects_opposite_source_family_in_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conflict: str,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
        transport_mode="obfuscated",
    )
    if conflict.startswith("request"):
        client = "rust"
        rows = _server_source_records(
            client=client,
            process_id=101,
            run_id="rust-source-run",
            trace_id=909,
            transport_mode="plaintext",
        )
        conflicting = rows[0]
        if conflict == "request-size":
            payload = bytes.fromhex(SERVER_SOURCE_FILE_HASH) + (
                SERVER_SOURCE_FILE_SIZE + 1
            ).to_bytes(4, "little")
            conflicting["body"]["payloadHex"] = payload.hex()
            conflicting["body"]["payloadLen"] = len(payload)
        else:
            conflicting["body"]["payloadHexTruncated"] = True
    else:
        client = "mfc"
        rows = _server_source_records(
            client=client,
            process_id=202,
            run_id="mfc-source-run",
            trace_id=909,
            transport_mode="plaintext",
        )
        conflicting = rows[1]
        if conflict == "reply-length":
            conflicting["body"]["payloadLen"] += 1
    segment = Path(evidence["captures"][client]["selectedSegments"][0])
    retained = [
        json.loads(line)
        for line in segment.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    next_sequence = len(retained) + 1
    conflicting["seq"] = next_sequence
    conflicting["streamSeq"] = next_sequence
    _write_server_source_segment(segment, [*retained, conflicting])
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_stale_source_capture_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    diagnostics_dir = Path(evidence["captures"]["rust"]["diagnosticsDir"])
    stale_segment = diagnostics_dir / "emulebb-rust-diag-101-stale-run-000000.jsonl"
    _write_server_source_segment(
        stale_segment,
        _server_source_records(
            client="rust",
            process_id=101,
            run_id="stale-run",
            trace_id=101,
        ),
    )
    evidence["captures"]["rust"]["selectedSegments"] = [str(stale_segment)]
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="final process selection"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_source_capture_outside_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    outside = tmp_path / "emulebb-rust-diag-101-rust-source-run-000000.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    evidence["captures"]["rust"]["selectedSegments"] = [str(outside)]
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="under the immutable run directory"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_wrong_source_capture_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    evidence["captures"]["mfc"]["processId"] = 203
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="final process selection"):
        build_transfer_registration(report_path, output_root=output_root)


@pytest.mark.parametrize(
    "subject",
    ["rust", "mfc", "runner"],
)
def test_build_transfer_registration_rejects_malformed_source_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    subject: str,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_source(
        report,
        run_directory=report_path.parent,
        monkeypatch=monkeypatch,
    )
    if subject == "rust":
        report["profiles"]["rust"]["source_revision"] = "invalid"
        error = "Rust source revision"
    elif subject == "mfc":
        report["profiles"]["mfc"]["availability"]["source_revision"] = "invalid"
        error = "MFC source revision"
    else:
        report["runner_revision"] = "invalid"
        error = "runner_revision"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_exact_server_udp_metadata(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_udp_metadata(report, run_directory=report_path.parent)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    registration = build_transfer_registration(report_path, output_root=output_root)

    assert registration["evidenceReceipt"]["coverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "server.reply.udp-description",
        "server.reply.udp-status",
        "transfer.block.uncompressed",
    ]
    reasons = {
        row["coverageId"]: row["reason"]
        for row in registration["coverageEvidence"]
        if row["coverageId"]
        in server_udp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    }
    assert "obfuscated/plaintext transport" in reasons["server.reply.udp-description"]
    assert "challenged UDP status reply" in reasons["server.reply.udp-status"]


def test_build_transfer_registration_rejects_udp_metadata_without_evidence(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "server-udp-metadata"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="has no diagnostic evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_legacy_udp_metadata_schema(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_metadata(report, run_directory=report_path.parent)
    evidence["schema"] = (
        "emulebb-build-tests.deterministic-server-udp-metadata-diagnostics.v0"
    )
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected schema"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_udp_receipt_not_backed_by_capture(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_metadata(report, run_directory=report_path.parent)
    evidence["clients"]["rust"]["applied"]["status"]["files"] = 2
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match its immutable captures"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_udp_capture_outside_run(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_udp_metadata(report, run_directory=report_path.parent)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    evidence["captures"]["mfc"]["selectedSegments"] = [str(outside)]
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="under the immutable run directory"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_udp_topology_drift(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    attach_server_udp_metadata(report, run_directory=report_path.parent)
    report["udp_metadata_target"]["file"]["complete_sources"] = 2
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="singular canonical fixture"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_mutated_delivered_file(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    delivered = Path(
        report["checks"]["client1_transfer_completed_file"]["deliveredPath"]
    )
    delivered.write_bytes(b"mutated transfer fixture")

    with pytest.raises(ValueError, match="delivered file bytes"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_latest_alias(tmp_path: Path) -> None:
    report_path, output_root, _ = write_transfer_report(tmp_path)
    latest = report_path.parents[1] / "latest" / report_path.name
    latest.parent.mkdir()
    latest.write_bytes(report_path.read_bytes())

    with pytest.raises(ValueError, match="not latest"):
        build_transfer_registration(latest, output_root=output_root)
