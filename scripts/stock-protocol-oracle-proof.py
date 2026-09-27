"""Validates and publishes the source-anchored stock protocol oracle proof."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.artifact_names import utc_run_id  # noqa: E402
from emule_test_harness.paths import get_required_emule_workspace_root, get_workspace_output_root  # noqa: E402
from emule_test_harness.protocol_goldens import (  # noqa: E402
    REQUIRED_STOCK_COVERAGE_IDS,
    default_golden_path,
    load_json,
    validate_golden_manifest,
)

SUITE_NAME = "stock-protocol-oracle-proof"
RUST_PROOF_PACKAGES = (
    "emulebb-ed2k",
    "emulebb-kad-dht",
    "emulebb-kad-net",
    "emulebb-kad-proto",
    "emulebb-core",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--manifest-path", type=Path)
    parser.add_argument(
        "--execute-rust-proofs",
        action="store_true",
        help="Run every Rust package containing a cited oracle proof through workspace orchestration.",
    )
    return parser.parse_args(argv)


def write_json(path: Path, payload: dict[str, object]) -> None:
    """Writes one stable JSON evidence artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def publish_latest(run_dir: Path, latest_dir: Path) -> None:
    """Refreshes the lightweight latest evidence directory."""

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)


def run_rust_proof_packages(workspace_root: Path) -> list[dict[str, object]]:
    """Executes all packages containing manifest proof selectors via the workspace wrapper."""

    build_repo = workspace_root / "repos" / "emulebb-build"
    rows: list[dict[str, object]] = []
    for package in RUST_PROOF_PACKAGES:
        command = [
            sys.executable,
            "-m",
            "emule_workspace",
            "test",
            "rust-unit",
            "--package",
            package,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=build_repo,
                text=True,
                capture_output=True,
                check=False,
            )
            rows.append(
                {
                    "package": package,
                    "status": "passed" if completed.returncode == 0 else "failed",
                    "returnCode": completed.returncode,
                    "command": command,
                    "stdoutTail": completed.stdout[-4000:],
                    "stderrTail": completed.stderr[-4000:],
                }
            )
        except OSError as exc:
            rows.append(
                {
                    "package": package,
                    "status": "failed",
                    "returnCode": None,
                    "command": command,
                    "stdoutTail": "",
                    "stderrTail": str(exc),
                }
            )
    return rows


def build_checks(
    manifest: dict[str, object],
    errors: tuple[str, ...],
    rust_proof_runs: list[dict[str, object]] | None = None,
    *,
    execution_required: bool = False,
) -> dict[str, object]:
    """Builds explicit proof metrics from the validated manifest."""

    records = manifest.get("records")
    groups = manifest.get("coverageGroups")
    record_rows = records if isinstance(records, list) else []
    group_rows = groups if isinstance(groups, list) else []
    stock_records = [row for row in record_rows if isinstance(row, dict) and row.get("recordId")]
    binary_records = [row for row in stock_records if row.get("recordType") != "state-sequence"]
    state_records = [row for row in stock_records if row.get("recordType") == "state-sequence"]
    source_anchor_count = sum(
        len(row.get("sourceAnchors", []))
        for row in group_rows
        if isinstance(row, dict) and isinstance(row.get("sourceAnchors"), list)
    )
    rust_proof_count = sum(
        len(row.get("rustProofs", []))
        for row in group_rows
        if isinstance(row, dict) and isinstance(row.get("rustProofs"), list)
    )
    execution_rows = rust_proof_runs or []
    execution_packages = [str(row.get("package", "")) for row in execution_rows]
    executions_passed = (
        tuple(execution_packages) == RUST_PROOF_PACKAGES
        and all(row.get("status") == "passed" for row in execution_rows)
    )
    return {
        "allRequirementsPassed": not errors and (not execution_required or executions_passed),
        "validationErrorCount": len(errors),
        "validationErrors": list(errors),
        "requiredCoverageCount": len(REQUIRED_STOCK_COVERAGE_IDS),
        "coverageGroupCount": len(group_rows),
        "stockRecordCount": len(stock_records),
        "binaryVectorCount": len(binary_records),
        "stateVectorCount": len(state_records),
        "sourceAnchorCount": source_anchor_count,
        "rustProofSelectorCount": rust_proof_count,
        "rustProofExecutionRequired": execution_required,
        "rustProofExpectedPackageCount": len(RUST_PROOF_PACKAGES),
        "rustProofPackageCount": len(execution_rows),
        "rustProofPackages": execution_packages,
        "rustProofExecutionsPassed": executions_passed,
        "baselineRevisionPinned": not any("baseline revision drift" in error for error in errors),
        "sourceAnchorsPassed": not any("source anchor" in error for error in errors),
        "rustProofSelectorsPassed": not any("Rust proof" in error for error in errors),
        "binaryDigestsPassed": not any("fixtureBase64" in error or "payloadDigest" in error for error in errors),
    }


def main(argv: list[str] | None = None) -> int:
    """Validates the tracked oracle and publishes campaign-readable evidence."""

    args = parse_args(argv)
    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    manifest_path = (args.manifest_path or default_golden_path(REPO_ROOT)).resolve()
    run_id = utc_run_id()
    run_dir = args.artifacts_dir.resolve() if args.artifacts_dir else output_root / "reports" / SUITE_NAME / run_id
    latest_dir = output_root / "reports" / SUITE_NAME / "latest"
    started = datetime.now(UTC).isoformat()

    validation = validate_golden_manifest(manifest_path, workspace_root=workspace_root)
    manifest = load_json(manifest_path)
    rust_proof_runs = run_rust_proof_packages(workspace_root) if args.execute_rust_proofs else []
    checks = build_checks(
        manifest,
        validation.errors,
        rust_proof_runs,
        execution_required=args.execute_rust_proofs,
    )
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "passed" if checks["allRequirementsPassed"] else "failed",
        "runId": run_id,
        "startedAtUtc": started,
        "finishedAtUtc": datetime.now(UTC).isoformat(),
        "manifestPath": str(manifest_path),
        "rustProofExecutions": rust_proof_runs,
        "checks": {"stock_protocol_oracle_requirements": checks},
    }
    write_json(run_dir / f"{SUITE_NAME}-result.json", report)
    publish_latest(run_dir, latest_dir)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
