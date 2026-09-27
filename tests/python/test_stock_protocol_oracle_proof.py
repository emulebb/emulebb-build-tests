from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated stock oracle proof script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "stock-protocol-oracle-proof.py"
    spec = importlib.util.spec_from_file_location("stock_protocol_oracle_proof_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_checks_reports_complete_binary_state_and_anchor_evidence() -> None:
    module = load_suite_module()
    manifest_path = module.default_golden_path(Path(__file__).resolve().parents[2])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    checks = module.build_checks(manifest, ())

    assert checks == {
        "allRequirementsPassed": True,
        "validationErrorCount": 0,
        "validationErrors": [],
        "requiredCoverageCount": 97,
        "coverageGroupCount": 15,
        "stockRecordCount": 17,
        "binaryVectorCount": 15,
        "stateVectorCount": 2,
        "sourceAnchorCount": 22,
        "rustProofSelectorCount": 44,
        "baselineRevisionPinned": True,
        "sourceAnchorsPassed": True,
        "rustProofSelectorsPassed": True,
        "binaryDigestsPassed": True,
    }


def test_build_checks_surfaces_anchor_and_digest_failures() -> None:
    module = load_suite_module()
    manifest_path = module.default_golden_path(Path(__file__).resolve().parents[2])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    checks = module.build_checks(
        manifest,
        (
            "stock source anchor drift for tags",
            "records[1].payloadDigest does not match fixtureBase64",
        ),
    )

    assert checks["allRequirementsPassed"] is False
    assert checks["sourceAnchorsPassed"] is False
    assert checks["binaryDigestsPassed"] is False
