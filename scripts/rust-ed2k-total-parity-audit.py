"""Audits the complete Rust ED2K overnight parity evidence set."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.artifact_names import utc_run_id  # noqa: E402
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402

SUITE_NAME = "rust-ed2k-total-parity-audit"


@dataclass(frozen=True)
class Requirement:
    """One concrete Rust ED2K parity evidence requirement."""

    requirement_id: str
    title: str
    source_path: str
    matches: tuple[tuple[str, object], ...]


REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "protocol-matrix",
        "All local ED2K protocol variants pass",
        "reports/local-ed2k-rust-protocol-combinations/latest/local-ed2k-rust-protocol-combinations-result.json",
        (
            ("/status", "passed"),
            ("/checks/protocol_matrix_coverage/caseCount", 4),
            ("/checks/protocol_matrix_coverage/plainServerPlainClients", True),
            ("/checks/protocol_matrix_coverage/obfuscatedPreferred", True),
            ("/checks/protocol_matrix_coverage/obfuscatedRequired", True),
            ("/checks/protocol_matrix_coverage/serverUdpDisabled", True),
            ("/checks/protocol_matrix_coverage/compressibleFixture", True),
            ("/checks/protocol_matrix_coverage/lowCompressibilityFixture", True),
            ("/checks/protocol_matrix_coverage/unicodeFixtureNames", True),
        ),
    ),
    Requirement(
        "protocol-metadata",
        "Protocol matrix proves multi-transfer, Unicode, hash-only, hashset, and source metadata",
        "reports/local-ed2k-rust-protocol-combinations/latest/local-ed2k-rust-protocol-combinations-result.json",
        (
            ("/checks/rust_protocol_case_requirements/allCasesPassed", True),
            ("/checks/rust_protocol_case_requirements/threeTransfersPerCase", True),
            ("/checks/rust_protocol_case_requirements/hashOnlyMetadataRecoveryPerCase", True),
            ("/checks/rust_protocol_case_requirements/unicodeHashOnlyMetadataPerCase", True),
            ("/checks/rust_protocol_case_requirements/namedTransferHashsetsPerCase", True),
            ("/checks/rust_protocol_case_requirements/obfuscatedSourceUserHashPerCase", True),
        ),
    ),
    Requirement(
        "private-modules",
        "p2p-overlord-derived private Rust ED2K protocol and runtime modules pass",
        "reports/rust-ed2k-private-parity-modules/latest/rust-ed2k-private-parity-modules-result.json",
        (
            ("/status", "passed"),
            ("/checks/rust_private_ed2k_module_requirements/caseCount", 55),
            ("/checks/rust_private_ed2k_module_requirements/allCasesPassed", True),
            ("/checks/rust_private_ed2k_module_requirements/protocolCodecCovered", True),
            ("/checks/rust_private_ed2k_module_requirements/serverProtocolCovered", True),
            ("/checks/rust_private_ed2k_module_requirements/transferRuntimeCovered", True),
            ("/checks/rust_private_ed2k_module_requirements/hashset2AichCovered", True),
            ("/checks/rust_private_ed2k_module_requirements/obfuscatedProtocolCovered", True),
            ("/checks/rust_private_ed2k_module_requirements/secureIdentProtocolCovered", True),
            ("/checks/rust_private_ed2k_module_requirements/indexSnoopQueueCovered", True),
        ),
    ),
    Requirement(
        "pytest-preflight",
        "Rust local-client and REST contract preflight pass through workspace orchestration",
        "reports/rust-overnight-pytest-proof/latest/rust-overnight-pytest-proof-result.json",
        (
            ("/status", "passed"),
            ("/checks/rust_overnight_pytest_requirements/caseCount", 2),
            ("/checks/rust_overnight_pytest_requirements/allCasesPassed", True),
            ("/checks/rust_overnight_pytest_requirements/localClientPytestPassed", True),
            ("/checks/rust_overnight_pytest_requirements/restContractPytestPassed", True),
        ),
    ),
)

SCENARIO_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "cross-emulebb",
        "Rust and eMuleBB bidirectional exchange passes with Unicode, source userHash, MD4, and AICH metadata",
        "reports/multi-client-p2p-matrix/*/multi-client-p2p-matrix-result.json",
        (
            ("/status", "passed"),
            ("/scenarios/*/id", "cl-emulebb-001-cl-emulebb-rust-005-bidirectional-exchange"),
            ("/scenarios/*/status", "passed"),
            ("/scenarios/*/report/status", "passed"),
            ("/scenarios/*/report/checks/rust_emulebb_cross_client_requirements/bidirectionalTransfers", True),
            ("/scenarios/*/report/checks/rust_emulebb_cross_client_requirements/unicodeFixtureNames", True),
            ("/scenarios/*/report/checks/rust_emulebb_cross_client_requirements/rustPersistedSourceUserHash", True),
            ("/scenarios/*/report/checks/rust_emulebb_cross_client_requirements/rustPersistedMd4Hashset", True),
            ("/scenarios/*/report/checks/rust_emulebb_cross_client_requirements/rustPersistedAichHashset", True),
        ),
    ),
    Requirement(
        "cross-rust",
        "Rust-to-Rust bidirectional exchange passes with multi-transfer, Unicode, hash-only, restart, and source controls",
        "reports/multi-client-p2p-matrix/*/multi-client-p2p-matrix-result.json",
        (
            ("/status", "passed"),
            ("/scenarios/*/id", "cl-emulebb-rust-005-cl-emulebb-rust-006-bidirectional-exchange"),
            ("/scenarios/*/status", "passed"),
            ("/scenarios/*/report/status", "passed"),
            ("/scenarios/*/report/checks/multiTransferCount", 3),
            ("/scenarios/*/report/checks/unicodeFilenameTransfer", True),
            ("/scenarios/*/report/checks/hashOnlyMetadataRecovery", True),
            ("/scenarios/*/report/checks/bidirectionalRustTransfers", True),
            ("/scenarios/*/report/checks/sourcePersistenceAfterRestart", True),
            ("/scenarios/*/report/checks/sourceControlOperations", True),
        ),
    ),
    Requirement(
        "cross-amule",
        "Rust and aMule bidirectional exchange passes with Rust-side persisted source and MD4 metadata",
        "reports/multi-client-p2p-matrix/*/multi-client-p2p-matrix-result.json",
        (
            ("/status", "passed"),
            ("/scenarios/*/id", "cl-emulebb-rust-005-cl-amule-004-bidirectional-exchange"),
            ("/scenarios/*/status", "passed"),
            ("/scenarios/*/report/status", "passed"),
            ("/scenarios/*/report/checks/rust_amule_manifest_metadata/md4HashsetAcquired", True),
            ("/scenarios/*/report/checks/rust_amule_manifest_metadata/sourceUserHashCount", 1),
        ),
    ),
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path)
    return parser.parse_args(argv)


def read_json(path: Path) -> Any:
    """Reads one JSON evidence file."""

    return json.loads(path.read_text(encoding="utf-8"))


def json_pointer(payload: Any, pointer: str) -> Any:
    """Returns one JSON pointer value."""

    if pointer in ("", "/"):
        return payload
    current = payload
    for raw_part in pointer.strip("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


def scenario_from_requirement(payload: Any, requirement: Requirement) -> dict[str, Any] | None:
    """Returns the scenario row referenced by a scenario requirement."""

    scenario_id = next((expected for pointer, expected in requirement.matches if pointer == "/scenarios/*/id"), None)
    if not isinstance(payload, dict) or not isinstance(scenario_id, str):
        return None
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        return None
    return next((row for row in scenarios if isinstance(row, dict) and row.get("id") == scenario_id), None)


def match_requirement(payload: Any, requirement: Requirement) -> tuple[bool, list[dict[str, Any]]]:
    """Checks one requirement against one JSON payload."""

    scenario = scenario_from_requirement(payload, requirement)
    mismatches: list[dict[str, Any]] = []
    for pointer, expected in requirement.matches:
        effective_pointer = pointer
        effective_payload = payload
        if pointer.startswith("/scenarios/*/"):
            effective_payload = scenario
            effective_pointer = "/" + pointer.removeprefix("/scenarios/*/")
        actual = json_pointer(effective_payload, effective_pointer)
        if actual != expected:
            mismatches.append({"pointer": pointer, "expected": expected, "actual": actual})
    return not mismatches, mismatches


def evaluate_path_requirement(output_root: Path, requirement: Requirement) -> dict[str, Any]:
    """Evaluates a requirement backed by a fixed output-root path."""

    path = output_root / requirement.source_path
    if not path.is_file():
        return requirement_result(requirement, "failed", None, [{"error": "missing evidence"}])
    payload = read_json(path)
    ok, mismatches = match_requirement(payload, requirement)
    return requirement_result(requirement, "passed" if ok else "failed", path, mismatches)


def evaluate_glob_requirement(output_root: Path, requirement: Requirement) -> dict[str, Any]:
    """Evaluates a scenario requirement against the newest matching report."""

    candidates = sorted(
        (path for path in output_root.glob(requirement.source_path) if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in candidates:
        payload = read_json(path)
        ok, mismatches = match_requirement(payload, requirement)
        if ok:
            return requirement_result(requirement, "passed", path, [])
    return requirement_result(
        requirement,
        "failed",
        candidates[0] if candidates else None,
        [{"error": "no matching scenario evidence", "candidateCount": len(candidates)}],
    )


def requirement_result(
    requirement: Requirement,
    status: str,
    path: Path | None,
    mismatches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Builds one requirement audit row."""

    return {
        "id": requirement.requirement_id,
        "title": requirement.title,
        "status": status,
        "source": requirement.source_path,
        "path": str(path) if path is not None else "",
        "mismatches": mismatches,
    }


def build_checks(requirements: list[dict[str, Any]]) -> dict[str, Any]:
    """Builds the total parity audit checks object."""

    failed = [row["id"] for row in requirements if row.get("status") != "passed"]
    return {
        "requirementCount": len(requirements),
        "allRequirementsPassed": not failed,
        "failedRequirementCount": len(failed),
        "failedRequirementIds": failed,
        "protocolVariantsPassed": "protocol-matrix" not in failed,
        "multiUnicodeMetadataPassed": "protocol-metadata" not in failed,
        "privateP2pOverlordModulesPassed": "private-modules" not in failed,
        "preflightAndRestPassed": "pytest-preflight" not in failed,
        "crossClientMatrixPassed": not any(row in failed for row in ("cross-emulebb", "cross-rust", "cross-amule")),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Writes one stable JSON artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def publish_latest(run_dir: Path, latest_dir: Path) -> None:
    """Refreshes the lightweight latest evidence directory for this suite."""

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)


def main(argv: list[str] | None = None) -> int:
    """Audits all current Rust ED2K parity evidence and publishes the result."""

    args = parse_args(argv)
    output_root = get_workspace_output_root()
    run_id = utc_run_id()
    run_dir = args.artifacts_dir.resolve() if args.artifacts_dir else output_root / "reports" / SUITE_NAME / run_id
    latest_dir = output_root / "reports" / SUITE_NAME / "latest"
    requirements = [evaluate_path_requirement(output_root, requirement) for requirement in REQUIREMENTS]
    requirements.extend(evaluate_glob_requirement(output_root, requirement) for requirement in SCENARIO_REQUIREMENTS)
    checks = build_checks(requirements)
    report = {
        "suite": SUITE_NAME,
        "status": "passed" if checks["allRequirementsPassed"] else "failed",
        "runId": run_id,
        "startedAtUtc": datetime.now(UTC).isoformat(),
        "finishedAtUtc": datetime.now(UTC).isoformat(),
        "requirements": requirements,
        "checks": {"rust_ed2k_total_parity_audit": checks},
    }
    write_json(run_dir / f"{SUITE_NAME}-result.json", report)
    publish_latest(run_dir, latest_dir)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
