"""Builds catalog registrations from immutable deterministic evidence receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from emule_test_harness import transfer_diagnostic_evidence

TRANSFER_SUITE = "deterministic-two-client-transfer"
TRANSFER_RUNNER_PATH = "scripts/deterministic-two-client-transfer.py"
PROFILE_AUTHORITY = "harness-generated-ephemeral-local-profiles"
RUN_DIRECTORY_PATTERN = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)-")
GIT_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _lower_hex(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{field} is malformed")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_within(value: Any, root: Path, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty path")
    path = Path(value).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"{field} must resolve to a file under the immutable run directory")
    return path


def _profile_by_client_key(profiles: dict[str, Any], client_key: str) -> dict[str, Any]:
    matches = [row for row in profiles.values() if isinstance(row, dict) and row.get("client_key") == client_key]
    if len(matches) != 1:
        raise ValueError(f"profiles must contain exactly one {client_key} subject")
    return matches[0]


def _exact_wire_check(diagnostics: dict[str, Any], name: str) -> dict[str, Any]:
    wire_checks = _object(diagnostics.get("wireChecks"), "diagnostics.wireChecks")
    check = _object(wire_checks.get(name), f"diagnostics.wireChecks.{name}")
    matched = _positive_int(check.get("matchedFrameCount"), f"diagnostics.wireChecks.{name}.matchedFrameCount")
    if check.get("ok") is not True:
        raise ValueError(f"diagnostics.wireChecks.{name} is not green")
    if check.get("leftFrameCount") != matched or check.get("rightFrameCount") != matched:
        raise ValueError(f"diagnostics.wireChecks.{name} is not an exact frame match")
    if check.get("unmatchedLeftFrameCount") != 0 or check.get("unmatchedRightFrameCount") != 0:
        raise ValueError(f"diagnostics.wireChecks.{name} contains unmatched frames")
    return check


def _exact_startup_check(diagnostics: dict[str, Any], name: str) -> dict[str, Any]:
    startup_checks = _object(diagnostics.get("startupChecks"), "diagnostics.startupChecks")
    check = _object(startup_checks.get(name), f"diagnostics.startupChecks.{name}")
    matched = _positive_int(
        check.get("matchedFrameCount"),
        f"diagnostics.startupChecks.{name}.matchedFrameCount",
    )
    if check.get("ok") is not True:
        raise ValueError(f"diagnostics.startupChecks.{name} is not green")
    if check.get("leftFrameCount") != matched or check.get("rightFrameCount") != matched:
        raise ValueError(f"diagnostics.startupChecks.{name} is not an exact frame match")
    if check.get("unmatchedLeftFrameCount") != 0 or check.get("unmatchedRightFrameCount") != 0:
        raise ValueError(f"diagnostics.startupChecks.{name} contains unmatched frames")
    return check


def _green_startup_check(diagnostics: dict[str, Any], name: str) -> dict[str, Any]:
    startup_checks = _object(diagnostics.get("startupChecks"), "diagnostics.startupChecks")
    check = _object(startup_checks.get(name), f"diagnostics.startupChecks.{name}")
    if check.get("ok") is not True:
        raise ValueError(f"diagnostics.startupChecks.{name} is not green")
    return check


def _derived_transfer_coverage_ids(diagnostics: dict[str, Any]) -> list[str]:
    _exact_startup_check(diagnostics, "multipacketRequestFrames")
    _exact_startup_check(diagnostics, "multipacketAnswerFrames")
    _green_startup_check(diagnostics, "multipacketRequestSemantics")
    _green_startup_check(diagnostics, "multipacketAnswerSemantics")
    _exact_startup_check(diagnostics, "hashsetRequestFrames")
    _exact_startup_check(diagnostics, "hashsetAnswerFrames")
    _green_startup_check(diagnostics, "hashsetRequestSemantics")
    _green_startup_check(diagnostics, "hashsetAnswerSemantics")
    manifest = _green_startup_check(diagnostics, "persistedManifest")
    manifest_checks = _object(
        manifest.get("checks"),
        "diagnostics.startupChecks.persistedManifest.checks",
    )
    if not manifest_checks or any(value is not True for value in manifest_checks.values()):
        raise ValueError("diagnostics startup manifest checks are not all green")
    _positive_int(manifest.get("md4HashsetCount"), "persisted MD4 hashset count")
    _positive_int(manifest.get("aichHashsetCount"), "persisted AICH hashset count")
    _exact_wire_check(diagnostics, "requestFrames")
    payload = _exact_wire_check(diagnostics, "payloadFrames")
    opcodes = payload.get("opcodes")
    if not isinstance(opcodes, list) or not opcodes or not all(isinstance(value, str) for value in opcodes):
        raise ValueError("diagnostics.wireChecks.payloadFrames.opcodes must be a non-empty string list")
    observed = set(opcodes)
    coverage_ids = [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
    ]
    if observed.intersection(transfer_diagnostic_evidence.UNCOMPRESSED_PAYLOAD_OPCODES):
        coverage_ids.append("transfer.block.uncompressed")
    if observed.intersection(transfer_diagnostic_evidence.COMPRESSED_PAYLOAD_OPCODES):
        coverage_ids.append("transfer.block.compressed")
    return sorted(coverage_ids)


def _coverage_reason(coverage_id: str, diagnostics: dict[str, Any]) -> str:
    if coverage_id == "peer.startup.multipacket-ext2":
        request = _exact_startup_check(diagnostics, "multipacketRequestFrames")
        answer = _exact_startup_check(diagnostics, "multipacketAnswerFrames")
        return (
            f"Matched {request['matchedFrameCount']} exact EXT2 startup request and "
            f"{answer['matchedFrameCount']} exact EXT2 answer with decoded filename and status."
        )
    if coverage_id == "peer.startup.aich":
        answer = _exact_startup_check(diagnostics, "hashsetAnswerFrames")
        manifest = _green_startup_check(diagnostics, "persistedManifest")
        return (
            f"Matched {answer['matchedFrameCount']} exact MD4+AICH hashset answer and persisted "
            f"{manifest['aichHashsetCount']} exact AICH part hashes in Rust."
        )
    if coverage_id == "queue.admission":
        mfc = _object(_object(diagnostics.get("clients"), "diagnostics.clients").get("mfc"), "diagnostics.clients.mfc")
        checks = _object(mfc.get("checks"), "diagnostics.clients.mfc.checks")
        admissions = _object(checks.get("uploadRequestServed"), "diagnostics.clients.mfc.checks.uploadRequestServed")
        count = _positive_int(admissions.get("matchingRecordCount"), "upload request admission count")
        return f"MFC recorded {count} exact-hash upload admissions in the causally ordered completed transfer."
    payload = _exact_wire_check(diagnostics, "payloadFrames")
    count = _positive_int(payload.get("matchedFrameCount"), "matched payload frame count")
    variant = "uncompressed" if coverage_id.endswith("uncompressed") else "compressed"
    return f"All {count} {variant} payload frames matched exactly before manifest-backed completion."


def build_transfer_registration(report_path: Path, *, output_root: Path) -> dict[str, Any]:
    """Validates one immutable Rust-from-MFC report and builds catalog rows."""

    resolved_output = output_root.resolve()
    resolved_report = report_path.resolve()
    if not resolved_report.is_relative_to(resolved_output) or not resolved_report.is_file():
        raise ValueError("report must be an existing file under EMULEBB_WORKSPACE_OUTPUT_ROOT")
    relative_report = resolved_report.relative_to(resolved_output)
    if "latest" in relative_report.parts:
        raise ValueError("report must use an immutable timestamped run path, not latest")
    run_directory = resolved_report.parent
    stamp_match = RUN_DIRECTORY_PATTERN.match(run_directory.name)
    if stamp_match is None:
        raise ValueError("report parent must be a timestamped deterministic transfer run directory")

    report = json.loads(resolved_report.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    if report.get("suite") != TRANSFER_SUITE or report.get("status") != "passed":
        raise ValueError("report must be a passed deterministic-two-client-transfer receipt")
    runner_revision = _lower_hex(report.get("runner_revision"), GIT_REVISION_PATTERN, "runner_revision")

    diagnostics = _object(report.get("diagnostics"), "diagnostics")
    transfer_diagnostic_evidence.require_transfer_diagnostic_evidence(diagnostics)
    claims = _object(diagnostics.get("coverageClaims"), "diagnostics.coverageClaims")
    claim_ids = claims.get("eligibleCoverageIds")
    expected_ids = _derived_transfer_coverage_ids(diagnostics)
    if claim_ids != expected_ids:
        raise ValueError("diagnostic coverage claims do not match the decisive wire evidence")
    expected_layers = list(transfer_diagnostic_evidence.EVIDENCE_LAYERS)
    if claims.get("evidenceLayers") != expected_layers:
        raise ValueError("diagnostic coverage claims do not declare the canonical evidence layers")

    fixture = _object(report.get("fixture"), "fixture")
    fixture_size = _positive_int(fixture.get("size"), "fixture.size")
    fixture_sha256 = _lower_hex(fixture.get("sha256"), SHA256_PATTERN, "fixture.sha256")
    fixture_path = _path_within(fixture.get("path"), run_directory, "fixture.path")
    if fixture_path.stat().st_size != fixture_size or _file_sha256(fixture_path) != fixture_sha256:
        raise ValueError("fixture bytes do not match the receipt")

    checks = _object(report.get("checks"), "checks")
    completed = _object(checks.get("client1_transfer_completed_file"), "checks.client1_transfer_completed_file")
    if completed.get("state") != "completed" or completed.get("completedBytes") != fixture_size:
        raise ValueError("completed transfer does not contain the full fixture")
    if str(completed.get("hash") or "").lower() != diagnostics.get("fileHash"):
        raise ValueError("completed transfer hash does not match diagnostics")
    delivered_path = _path_within(completed.get("deliveredPath"), run_directory, "completed deliveredPath")
    if delivered_path.stat().st_size != fixture_size or _file_sha256(delivered_path) != fixture_sha256:
        raise ValueError("delivered file bytes do not match the fixture")

    profiles = _object(report.get("profiles"), "profiles")
    rust = _profile_by_client_key(profiles, "emulebb_rust")
    mfc = _profile_by_client_key(profiles, "mfc_oracle")
    mfc_availability = _object(mfc.get("availability"), "MFC profile availability")
    subjects = [
        {
            "authorityId": "mfc-oracle",
            "executableSha256": _lower_hex(mfc.get("app_sha256"), SHA256_PATTERN, "MFC executable SHA-256"),
            "sourceRevision": _lower_hex(
                mfc_availability.get("source_revision"),
                GIT_REVISION_PATTERN,
                "MFC source revision",
            ),
        },
        {
            "authorityId": "rust-product",
            "executableSha256": _lower_hex(rust.get("app_sha256"), SHA256_PATTERN, "Rust executable SHA-256"),
            "sourceRevision": _lower_hex(rust.get("source_revision"), GIT_REVISION_PATTERN, "Rust source revision"),
        },
    ]
    stamp = stamp_match.group("stamp").lower()
    receipt_id = f"rust-mfc-transfer-{stamp}"
    receipt = {
        "artifactLocator": f"output-root:{relative_report.as_posix()}",
        "artifactSha256": _file_sha256(resolved_report),
        "coverageIds": expected_ids,
        "evidenceLayers": expected_layers,
        "profileAuthority": PROFILE_AUTHORITY,
        "receiptId": receipt_id,
        "runnerPath": TRANSFER_RUNNER_PATH,
        "runnerRevision": runner_revision,
        "subjects": subjects,
    }
    coverage_evidence = [
        {
            "coverageId": coverage_id,
            "evidenceLayers": expected_layers,
            "reason": _coverage_reason(coverage_id, diagnostics),
            "receiptIds": [receipt_id],
            "verdict": "parity",
        }
        for coverage_id in expected_ids
    ]
    return {"coverageEvidence": coverage_evidence, "evidenceReceipt": receipt}


def run_transfer_registration_cli(argv: list[str] | None = None) -> int:
    """Validates a local receipt and prints deterministic catalog registration JSON."""

    parser = argparse.ArgumentParser(description="Build protocol catalog rows from one Rust-from-MFC transfer receipt.")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-root", type=Path)
    args = parser.parse_args(argv)
    output_root = args.output_root
    if output_root is None:
        inherited = os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        if not inherited:
            parser.error("EMULEBB_WORKSPACE_OUTPUT_ROOT is required")
        output_root = Path(inherited)
    registration = build_transfer_registration(args.report, output_root=output_root)
    print(json.dumps(registration, indent=2, sort_keys=True))
    return 0
