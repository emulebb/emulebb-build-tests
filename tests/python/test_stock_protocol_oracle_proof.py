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
        "rustProofExecutionRequired": False,
        "rustProofExpectedPackageCount": 5,
        "rustProofPackageCount": 0,
        "rustProofPackages": [],
        "rustProofExecutionsPassed": False,
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


def test_rust_proof_packages_run_through_workspace_wrapper(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    workspace_root = tmp_path / "workspace"
    build_repo = workspace_root / "repos" / "emulebb-build"
    build_repo.mkdir(parents=True)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return module.subprocess.CompletedProcess(command, 0, stdout="passed\n", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    rows = module.run_rust_proof_packages(workspace_root)

    assert [row["package"] for row in rows] == list(module.RUST_PROOF_PACKAGES)
    assert [row["status"] for row in rows] == ["passed"] * 5
    assert all(call[1]["cwd"] == build_repo for call in calls)
    assert all(call[0][1:6] == ["-m", "emule_workspace", "test", "rust-unit", "--package"] for call in calls)


def test_build_checks_requires_every_rust_proof_package_when_execution_is_blocking() -> None:
    module = load_suite_module()
    manifest_path = module.default_golden_path(Path(__file__).resolve().parents[2])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [{"package": package, "status": "passed"} for package in module.RUST_PROOF_PACKAGES]

    checks = module.build_checks(manifest, (), rows, execution_required=True)

    assert checks["allRequirementsPassed"] is True
    assert checks["rustProofExecutionRequired"] is True
    assert checks["rustProofPackageCount"] == 5
    assert checks["rustProofExecutionsPassed"] is True

    rows[-1]["status"] = "failed"
    failed = module.build_checks(manifest, (), rows, execution_required=True)
    assert failed["allRequirementsPassed"] is False
    assert failed["rustProofExecutionsPassed"] is False
