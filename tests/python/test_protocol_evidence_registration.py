from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from emule_test_harness.protocol_evidence_registration import build_transfer_registration
from emule_test_harness.transfer_diagnostic_evidence import EVIDENCE_LAYERS, SCHEMA

FILE_HASH = "00112233445566778899aabbccddeeff"


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


def test_build_transfer_registration_accepts_exact_server_keyword_search(tmp_path: Path) -> None:
    report_path, output_root, report = write_transfer_report(tmp_path)
    report["transfer_scenario"] = "server-keyword-search"
    report["network"] = {
        "ed2k_server_address": "127.0.0.1",
        "ports": {"ed2k_tcp": 4661},
    }
    report["checks"]["client2_server_file"] = {
        "indexed": True,
        "hash": FILE_HASH.upper(),
        "name": "fixture.bin",
        "size": report["fixture"]["size"],
    }
    report["checks"]["client1_server_search"] = {
        "result": {
            "hash": FILE_HASH.upper(),
            "displayName": "fixture.bin",
            "sizeBytes": report["fixture"]["size"],
        }
    }
    report["diagnostics"]["serverSearch"] = {
        "schema": "emulebb-build-tests.deterministic-server-search-diagnostics.v1",
        "ok": True,
        "query": "deterministicparitysearch",
        "serverEndpoint": "127.0.0.1:4661",
        "expectedFile": {
            "hash": FILE_HASH,
            "name": "fixture.bin",
            "size": report["fixture"]["size"],
        },
        "failures": [],
        "checks": {
            "request": {
                "ok": True,
                "endpointRequestCount": 1,
                "exactRequestCount": 1,
                "sendSucceeded": True,
                "sequence": 20,
            },
            "reply": {
                "ok": True,
                "responseCount": 1,
                "malformedResponseCount": 0,
                "decodedRowCount": 1,
                "exactRowCount": 1,
                "exactRow": {
                    "hash": FILE_HASH.upper(),
                    "name": "fixture.bin",
                    "size": report["fixture"]["size"],
                },
                "firstResponseSequence": 22,
            },
            "restResult": {"ok": True},
        },
        "coverageClaims": {
            "eligibleCoverageIds": ["server.reply.search", "server.search.keyword"],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].extend(
        ["server.reply.search", "server.search.keyword"]
    )
    report["diagnostics"]["coverageClaims"]["eligibleCoverageIds"].sort()
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
