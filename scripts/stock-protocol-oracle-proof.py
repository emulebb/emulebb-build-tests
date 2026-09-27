"""Validates and publishes the source-anchored stock protocol oracle proof."""

from __future__ import annotations

import argparse
import json
import shutil
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--manifest-path", type=Path)
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


def build_checks(manifest: dict[str, object], errors: tuple[str, ...]) -> dict[str, object]:
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
    return {
        "allRequirementsPassed": not errors,
        "validationErrorCount": len(errors),
        "validationErrors": list(errors),
        "requiredCoverageCount": len(REQUIRED_STOCK_COVERAGE_IDS),
        "coverageGroupCount": len(group_rows),
        "stockRecordCount": len(stock_records),
        "binaryVectorCount": len(binary_records),
        "stateVectorCount": len(state_records),
        "sourceAnchorCount": source_anchor_count,
        "rustProofSelectorCount": rust_proof_count,
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
    checks = build_checks(manifest, validation.errors)
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "passed" if checks["allRequirementsPassed"] else "failed",
        "runId": run_id,
        "startedAtUtc": started,
        "finishedAtUtc": datetime.now(UTC).isoformat(),
        "manifestPath": str(manifest_path),
        "checks": {"stock_protocol_oracle_requirements": checks},
    }
    write_json(run_dir / f"{SUITE_NAME}-result.json", report)
    publish_latest(run_dir, latest_dir)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
