from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated Rust ED2K total parity audit script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "rust-ed2k-total-parity-audit.py"
    spec = importlib.util.spec_from_file_location("rust_ed2k_total_parity_audit_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: dict[str, object]) -> None:
    """Writes compact synthetic evidence for audit tests."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def seed_complete_evidence(output_root: Path) -> None:
    """Seeds the complete output-root evidence set required by the audit."""

    write_json(
        output_root
        / "reports"
        / "local-ed2k-rust-protocol-combinations"
        / "latest"
        / "local-ed2k-rust-protocol-combinations-result.json",
        {
            "status": "passed",
            "checks": {
                "protocol_matrix_coverage": {
                    "caseCount": 4,
                    "plainServerPlainClients": True,
                    "obfuscatedPreferred": True,
                    "obfuscatedRequired": True,
                    "serverUdpDisabled": True,
                    "compressibleFixture": True,
                    "lowCompressibilityFixture": True,
                    "unicodeFixtureNames": True,
                },
                "rust_protocol_case_requirements": {
                    "allCasesPassed": True,
                    "threeTransfersPerCase": True,
                    "hashOnlyMetadataRecoveryPerCase": True,
                    "unicodeHashOnlyMetadataPerCase": True,
                    "namedTransferHashsetsPerCase": True,
                    "obfuscatedSourceUserHashPerCase": True,
                },
            },
        },
    )
    write_json(
        output_root
        / "reports"
        / "rust-ed2k-private-parity-modules"
        / "latest"
        / "rust-ed2k-private-parity-modules-result.json",
        {
            "status": "passed",
            "checks": {
                "rust_private_ed2k_module_requirements": {
                    "caseCount": 55,
                    "allCasesPassed": True,
                    "protocolCodecCovered": True,
                    "serverProtocolCovered": True,
                    "transferRuntimeCovered": True,
                    "hashset2AichCovered": True,
                    "obfuscatedProtocolCovered": True,
                    "secureIdentProtocolCovered": True,
                    "indexSnoopQueueCovered": True,
                }
            },
        },
    )
    write_json(
        output_root / "reports" / "rust-overnight-pytest-proof" / "latest" / "rust-overnight-pytest-proof-result.json",
        {
            "status": "passed",
            "checks": {
                "rust_overnight_pytest_requirements": {
                    "caseCount": 2,
                    "allCasesPassed": True,
                    "localClientPytestPassed": True,
                    "restContractPytestPassed": True,
                }
            },
        },
    )
    write_json(
        output_root / "reports" / "multi-client-p2p-matrix" / "20260612T010000Z" / "multi-client-p2p-matrix-result.json",
        {
            "status": "passed",
            "scenarios": [
                {
                    "id": "cl-emulebb-001-cl-emulebb-rust-005-bidirectional-exchange",
                    "status": "passed",
                    "report": {
                        "status": "passed",
                        "checks": {
                            "rust_emulebb_cross_client_requirements": {
                                "bidirectionalTransfers": True,
                                "unicodeFixtureNames": True,
                                "recursiveSharedTreeUpload": True,
                                "rustPersistedSourceUserHash": True,
                                "rustPersistedMd4Hashset": True,
                                "rustPersistedAichHashset": True,
                            }
                        },
                    },
                }
            ],
        },
    )
    write_json(
        output_root / "reports" / "multi-client-p2p-matrix" / "20260612T020000Z" / "multi-client-p2p-matrix-result.json",
        {
            "status": "passed",
            "scenarios": [
                {
                    "id": "cl-emulebb-rust-005-cl-emulebb-rust-006-bidirectional-exchange",
                    "status": "passed",
                    "report": {
                        "status": "passed",
                        "checks": {
                            "multiTransferCount": 3,
                            "unicodeFilenameTransfer": True,
                            "hashOnlyMetadataRecovery": True,
                            "bidirectionalRustTransfers": True,
                            "sourcePersistenceAfterRestart": True,
                            "sourceControlOperations": True,
                        },
                    },
                }
            ],
        },
    )

def configure_output_root(monkeypatch, tmp_path: Path) -> Path:
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "output"
    workspace_root.mkdir()
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", os.fspath(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", os.fspath(output_root))
    return output_root


def test_total_parity_audit_accepts_complete_output_root_evidence(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    output_root = configure_output_root(monkeypatch, tmp_path)
    seed_complete_evidence(output_root)

    requirements = [module.evaluate_path_requirement(output_root, requirement) for requirement in module.REQUIREMENTS]
    requirements.extend(module.evaluate_glob_requirement(output_root, requirement) for requirement in module.SCENARIO_REQUIREMENTS)
    checks = module.build_checks(requirements)

    assert [row["status"] for row in requirements] == ["passed"] * 6
    assert checks == {
        "requirementCount": 6,
        "allRequirementsPassed": True,
        "failedRequirementCount": 0,
        "failedRequirementIds": [],
        "protocolVariantsPassed": True,
        "multiUnicodeMetadataPassed": True,
        "privateP2pOverlordModulesPassed": True,
        "preflightAndRestPassed": True,
        "crossClientMatrixPassed": True,
    }


def test_total_parity_audit_rejects_stale_protocol_evidence(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    output_root = configure_output_root(monkeypatch, tmp_path)
    seed_complete_evidence(output_root)
    protocol_report = (
        output_root
        / "reports"
        / "local-ed2k-rust-protocol-combinations"
        / "latest"
        / "local-ed2k-rust-protocol-combinations-result.json"
    )
    payload = json.loads(protocol_report.read_text(encoding="utf-8"))
    payload["checks"]["protocol_matrix_coverage"]["obfuscatedRequired"] = False
    write_json(protocol_report, payload)

    result = module.evaluate_path_requirement(output_root, module.REQUIREMENTS[0])

    assert result["status"] == "failed"
    assert result["mismatches"] == [
        {
            "pointer": "/checks/protocol_matrix_coverage/obfuscatedRequired",
            "expected": True,
            "actual": False,
        }
    ]


def test_main_writes_total_audit_latest_under_workspace_output_root(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    output_root = configure_output_root(monkeypatch, tmp_path)
    seed_complete_evidence(output_root)
    monkeypatch.setattr(module, "utc_run_id", lambda: "20260612T010203Z")

    assert module.main([]) == 0

    report_path = (
        output_root
        / "reports"
        / "rust-ed2k-total-parity-audit"
        / "latest"
        / "rust-ed2k-total-parity-audit-result.json"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert report["checks"]["rust_ed2k_total_parity_audit"]["requirementCount"] == 6
