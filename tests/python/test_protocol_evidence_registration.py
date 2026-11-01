from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from emule_test_harness import ed2k_wire
from emule_test_harness import server_search_diagnostic_evidence
from emule_test_harness.protocol_evidence_registration import build_transfer_registration
from emule_test_harness.transfer_diagnostic_evidence import EVIDENCE_LAYERS, SCHEMA

FILE_HASH = "00112233445566778899aabbccddeeff"
SEARCH_FILE_HASH = "ffeeddccbbaa99887766554433221100"
SEARCH_FILE_NAME = "deterministicparitysearch-result.bin"
SEARCH_FILE_SIZE = 12_345
SEARCH_QUERY = "deterministicparitysearch"


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
                [failed_attempt_sequence, final_attempt_sequence] if fallback else [final_attempt_sequence]
            ),
            "attemptTraceIds": [1, 2] if fallback else [2],
            "attemptPlanExact": True,
            "loginPacketCount": 1 + failed_attempt_login_count,
            "finalLoginPacketCount": 1,
            "failedAttemptLoginPacketCount": failed_attempt_login_count,
            "sendSucceeded": True,
            "sendOutcomeSequence": (7 if fallback else 3) if client == "rust" else None,
            "sendOutcomeTraceId": 2 if client == "rust" else None,
            "sendOutcomeTransportMode": final_transport_mode if client == "rust" else None,
            "failedAttemptStartSequence": failed_attempt_sequence,
            "failedAttemptLoginSequence": 2 if fallback and client == "mfc" else None,
            "finalAttemptStartSequence": final_attempt_sequence,
            "loginSequence": login_sequence,
            "idChangeSequence": (8 if client == "rust" else 7) if fallback else (4 if client == "rust" else 3),
            "loginAcceptedSequence": (9 if client == "rust" else 8) if fallback else (5 if client == "rust" else 4),
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
                "send_succeeded" if fallback and client == "mfc" else None
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


def driven_server_search(client: str, search_id: str) -> dict[str, object]:
    result = {
        "hash": SEARCH_FILE_HASH.upper(),
        "sizeBytes": SEARCH_FILE_SIZE,
        "sources": 1,
        "completeSources": 1,
        "searchId": search_id,
    }
    result["displayName" if client == "rust" else "name"] = SEARCH_FILE_NAME
    created_method = {"requestedMethod": "server"} if client == "rust" else {"method": "server"}
    result_method = (
        {"requestedMethod": "server", "resolvedMethod": "server"} if client == "rust" else {"method": "server"}
    )
    return {
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
) -> dict[str, object]:
    payload_hex = ed2k_wire.encode_term_search(SEARCH_QUERY).hex()
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
        "query": SEARCH_QUERY,
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
        "observedCoverageIds": list(server_search_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS),
        "coverageClaims": {
            "eligibleCoverageIds": list(server_search_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS),
            "evidenceLayers": list(server_search_diagnostic_evidence.EVIDENCE_LAYERS),
        },
        "captures": {
            "rust": {"processId": 101, "selectedSegments": ["rust.jsonl"]},
            "mfc": {"processId": 202, "selectedSegments": ["mfc.jsonl"]},
        },
    }


def attach_server_search(report: dict[str, object]) -> dict[str, object]:
    driven_searches = {
        "rust": driven_server_search("rust", "rust-search-1"),
        "mfc": driven_server_search("mfc", "mfc-search-1"),
    }
    evidence = bilateral_search_evidence(driven_searches)
    report["transfer_scenario"] = "server-keyword-search"
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
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        server_search_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
    return evidence


def write_transfer_report(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    output_root = tmp_path / "output"
    run = output_root / "reports" / "deterministic-two-client-transfer" / "20261101T183823Z-test"
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


def test_build_transfer_registration_accepts_only_causally_claimed_ids(tmp_path: Path) -> None:
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
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].append("queue.rank-transition")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="claims do not match"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_accepts_hash_only_metadata_recovery(tmp_path: Path) -> None:
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

    assert "peer.startup.metadata-recovery" in registration["evidenceReceipt"]["coverageIds"]


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


def test_build_transfer_registration_rejects_one_sided_server_login(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence()
    login["clients"]["mfc"]["ok"] = False
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="mfc server login evidence"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_final_trace_components(tmp_path: Path) -> None:
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


def test_build_transfer_registration_rejects_boolean_login_count(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["finalLoginPacketCount"] = True
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="positive integer"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_duplicate_acceptance_count(tmp_path: Path) -> None:
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


def test_build_transfer_registration_revalidates_failed_login_trace(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    plan = ("obfuscated", "plaintext")
    login = bilateral_login_evidence(plan)
    login["clients"]["mfc"]["failedAttemptLoginTraceId"] = 99
    attach_server_login(report, login, plan)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="fallback evidence is not exact"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_revalidates_rust_send_outcome(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["sendOutcomeTraceId"] = 99
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="send outcome is not joined"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_late_rust_send_outcome(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    login = bilateral_login_evidence(("plaintext",))
    login["clients"]["rust"]["sendOutcomeSequence"] = 6
    attach_server_login(report, login, ("plaintext",))
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="send outcome is not joined"):
        build_transfer_registration(report_path, output_root=output_root)


def test_build_transfer_registration_rejects_malformed_attempt_shape(tmp_path: Path) -> None:
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


def test_build_transfer_registration_accepts_exact_server_keyword_search(tmp_path: Path) -> None:
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
        if row["coverageId"] in server_search_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS
    ]
    assert [row["coverageId"] for row in search_rows] == [
        "server.reply.search",
        "server.search.keyword",
    ]


def test_build_transfer_registration_rejects_legacy_server_search_schema(
    tmp_path: Path,
) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    evidence = attach_server_search(report)
    evidence["schema"] = "emulebb-build-tests.deterministic-server-search-diagnostics.v1"
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
    report["server_search_fixture"]["publication"]["search_result"]["result_source_id"] = 99
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

    with pytest.raises(ValueError, match="wire result is not joined to its applied REST result"):
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


def test_build_transfer_registration_rejects_mutated_delivered_file(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    delivered = Path(report["checks"]["client1_transfer_completed_file"]["deliveredPath"])
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
