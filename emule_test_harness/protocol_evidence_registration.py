"""Builds catalog registrations from immutable deterministic evidence receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from emule_test_harness import server_login_diagnostic_evidence
from emule_test_harness import server_search_diagnostic_evidence
from emule_test_harness import transfer_diagnostic_evidence

TRANSFER_SUITE = "deterministic-two-client-transfer"
TRANSFER_RUNNER_PATH = "scripts/deterministic-two-client-transfer.py"
PROFILE_AUTHORITY = "harness-generated-ephemeral-local-profiles"
RUN_DIRECTORY_PATTERN = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)-")
GIT_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SERVER_LOGIN_SCENARIO = "server-login-request"
SERVER_KEYWORD_SEARCH_SCENARIO = "server-keyword-search"


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
    if diagnostics.get("metadataRecoveryRequired") is True:
        metadata_recovery = _object(
            diagnostics.get("metadataRecovery"),
            "diagnostics.metadataRecovery",
        )
        if metadata_recovery.get("ok") is not True or metadata_recovery.get("sourceMatch") is not True:
            raise ValueError("diagnostics metadata recovery is not green")
        coverage_ids.append("peer.startup.metadata-recovery")
    if observed.intersection(transfer_diagnostic_evidence.UNCOMPRESSED_PAYLOAD_OPCODES):
        coverage_ids.append("transfer.block.uncompressed")
    if observed.intersection(transfer_diagnostic_evidence.COMPRESSED_PAYLOAD_OPCODES):
        coverage_ids.append("transfer.block.compressed")
    return sorted(coverage_ids)


def _derived_server_search_coverage_ids(
    report: dict[str, Any], diagnostics: dict[str, Any]
) -> list[str]:
    search_value = diagnostics.get("serverSearch")
    if search_value is None:
        if report.get("transfer_scenario") == SERVER_KEYWORD_SEARCH_SCENARIO:
            raise ValueError("server keyword search scenario has no diagnostic evidence")
        return []
    if report.get("transfer_scenario") != SERVER_KEYWORD_SEARCH_SCENARIO:
        raise ValueError("server search evidence requires the server keyword search scenario")
    search = _object(search_value, "diagnostics.serverSearch")
    server_search_diagnostic_evidence.require_server_search_diagnostic_evidence(search)
    claims = _object(search.get("coverageClaims"), "diagnostics.serverSearch.coverageClaims")
    observed_ids = ["server.reply.search", "server.search.keyword"]
    if search.get("observedCoverageIds") != observed_ids:
        raise ValueError("server search diagnostic observations are not exact")
    if claims.get("eligibleCoverageIds") != []:
        raise ValueError("unilateral server search diagnostics cannot claim parity coverage")
    if claims.get("evidenceLayers") != list(server_search_diagnostic_evidence.EVIDENCE_LAYERS):
        raise ValueError("server search diagnostic evidence layers are not canonical")

    search_checks = _object(search.get("checks"), "diagnostics.serverSearch.checks")
    request = _object(search_checks.get("request"), "diagnostics.serverSearch.checks.request")
    reply = _object(search_checks.get("reply"), "diagnostics.serverSearch.checks.reply")
    rest_result = _object(
        search_checks.get("restResult"),
        "diagnostics.serverSearch.checks.restResult",
    )
    request_sequence = _positive_int(request.get("sequence"), "server search request sequence")
    response_sequence = _positive_int(
        reply.get("firstResponseSequence"),
        "server search response sequence",
    )
    if (
        request.get("ok") is not True
        or request.get("endpointRequestCount") != 1
        or request.get("exactRequestCount") != 1
        or request.get("sendSucceeded") is not True
    ):
        raise ValueError("server search request is not singular and exact")
    if (
        reply.get("ok") is not True
        or not isinstance(reply.get("responseCount"), int)
        or reply.get("responseCount") < 1
        or reply.get("malformedResponseCount") != 0
        or reply.get("exactRowCount") != 1
        or response_sequence <= request_sequence
    ):
        raise ValueError("server search reply is not exact and causally ordered")
    if rest_result.get("ok") is not True:
        raise ValueError("server search REST result does not match the wire result")

    expected_file = _object(
        search.get("expectedFile"),
        "diagnostics.serverSearch.expectedFile",
    )
    fixture = _object(report.get("fixture"), "fixture")
    if (
        expected_file.get("hash") != diagnostics.get("fileHash")
        or expected_file.get("name") != fixture.get("name")
        or expected_file.get("size") != fixture.get("size")
    ):
        raise ValueError("server search expected file does not match the transfer fixture")
    exact_row = _object(reply.get("exactRow"), "diagnostics.serverSearch.checks.reply.exactRow")
    if (
        str(exact_row.get("hash") or "").casefold() != expected_file.get("hash")
        or exact_row.get("name") != expected_file.get("name")
        or exact_row.get("size") != expected_file.get("size")
    ):
        raise ValueError("server search decoded row does not match the expected file")

    checks = _object(report.get("checks"), "checks")
    driven = _object(checks.get("client1_server_search"), "checks.client1_server_search")
    driven_result = _object(driven.get("result"), "checks.client1_server_search.result")
    if (
        str(driven_result.get("hash") or "").casefold() != expected_file.get("hash")
        or driven_result.get("displayName", driven_result.get("name"))
        != expected_file.get("name")
        or driven_result.get("sizeBytes", driven_result.get("size"))
        != expected_file.get("size")
    ):
        raise ValueError("driven server search result does not match the expected file")
    publication = _object(checks.get("client2_server_file"), "checks.client2_server_file")
    if (
        publication.get("indexed") is not True
        or str(publication.get("hash") or "").casefold() != expected_file.get("hash")
        or publication.get("name") != expected_file.get("name")
        or publication.get("size") != expected_file.get("size")
    ):
        raise ValueError("MFC publication authority does not match the searched file")

    network = _object(report.get("network"), "network")
    ports = _object(network.get("ports"), "network.ports")
    expected_endpoint = (
        f"{network.get('ed2k_server_address')}:{ports.get('ed2k_tcp')}".casefold()
    )
    if search.get("serverEndpoint") != expected_endpoint:
        raise ValueError("server search diagnostics use an unexpected server endpoint")
    return []


def _derived_server_login_coverage_ids(
    report: dict[str, Any], diagnostics: dict[str, Any]
) -> list[str]:
    login_value = diagnostics.get("serverLogin")
    if login_value is None:
        if report.get("transfer_scenario") == SERVER_LOGIN_SCENARIO:
            raise ValueError("server login scenario has no bilateral diagnostic evidence")
        return []
    if report.get("transfer_scenario") != SERVER_LOGIN_SCENARIO:
        raise ValueError("server login evidence requires the server-login-request scenario")
    login = _object(login_value, "diagnostics.serverLogin")
    server_login_diagnostic_evidence.require_server_login_diagnostic_evidence(login)
    claims = _object(login.get("coverageClaims"), "diagnostics.serverLogin.coverageClaims")
    expected_ids = ["server.login.request"]
    if claims.get("eligibleCoverageIds") != expected_ids:
        raise ValueError("server login diagnostic claims are not exact")
    if claims.get("evidenceLayers") != list(server_login_diagnostic_evidence.EVIDENCE_LAYERS):
        raise ValueError("server login diagnostic evidence layers are not canonical")

    checks = _object(report.get("checks"), "checks")
    if checks.get("client_server_login_diagnostics") != login:
        raise ValueError("server login diagnostics do not match the pre-transfer snapshot")
    clients = _object(login.get("clients"), "diagnostics.serverLogin.clients")
    for client in ("rust", "mfc"):
        row = _object(clients.get(client), f"diagnostics.serverLogin.clients.{client}")
        login_sequence = _positive_int(
            row.get("loginSequence"),
            f"diagnostics.serverLogin.clients.{client}.loginSequence",
        )
        id_change_sequence = _positive_int(
            row.get("idChangeSequence"),
            f"diagnostics.serverLogin.clients.{client}.idChangeSequence",
        )
        accepted_sequence = _positive_int(
            row.get("loginAcceptedSequence"),
            f"diagnostics.serverLogin.clients.{client}.loginAcceptedSequence",
        )
        decoded_login = _object(
            row.get("decodedLogin"),
            f"diagnostics.serverLogin.clients.{client}.decodedLogin",
        )
        decoded_id = _object(
            row.get("decodedIdChange"),
            f"diagnostics.serverLogin.clients.{client}.decodedIdChange",
        )
        if (
            row.get("ok") is not True
            or row.get("packetCount") != 1
            or row.get("sendSucceeded") is not True
            or row.get("semanticShape") is not True
            or decoded_login.get("client_id") != 0
            or decoded_id.get("id_kind") != "low-id"
            or not login_sequence < id_change_sequence < accepted_sequence
        ):
            raise ValueError(f"{client} server login evidence is not singular and causal")
    if clients["rust"].get("extensionTags") != {"offerfiles_v": 1}:
        raise ValueError("Rust server login has unexpected extension tags")
    if clients["mfc"].get("extensionTags") != {}:
        raise ValueError("MFC server login has unexpected extension tags")

    comparison = _object(login.get("comparison"), "diagnostics.serverLogin.comparison")
    required_comparisons = {
        "bothAccepted",
        "versionEqual",
        "serverFlagsEqual",
        "udpPortsTagEqual",
        "idKindEqual",
        "ok",
    }
    if set(comparison) != required_comparisons or any(
        comparison.get(name) is not True for name in required_comparisons
    ):
        raise ValueError("bilateral server login comparison is not exact")

    profiles = _object(report.get("profiles"), "profiles")
    rust_profile = _profile_by_client_key(profiles, "emulebb_rust")
    mfc_profile = _profile_by_client_key(profiles, "mfc_oracle")
    network = _object(report.get("network"), "network")
    ports = _object(network.get("ports"), "network.ports")
    expected_clients = {
        "rust": {
            "nickname": rust_profile.get("nick"),
            "tcpPort": ports.get("client1_tcp"),
        },
        "mfc": {
            "nickname": mfc_profile.get("nick"),
            "tcpPort": ports.get("client2_tcp"),
        },
    }
    if login.get("expectedClients") != expected_clients:
        raise ValueError("server login expected clients do not match profile provenance")
    expected_endpoint = (
        f"{network.get('ed2k_server_address')}:{ports.get('ed2k_tcp')}".casefold()
    )
    if login.get("serverEndpoint") != expected_endpoint:
        raise ValueError("server login diagnostics use an unexpected server endpoint")

    captures = _object(login.get("captures"), "diagnostics.serverLogin.captures")
    for client in ("rust", "mfc"):
        capture = _object(captures.get(client), f"diagnostics.serverLogin.captures.{client}")
        _positive_int(capture.get("processId"), f"server login {client} process ID")
        segments = capture.get("selectedSegments")
        if not isinstance(segments, list) or not segments or not all(
            isinstance(value, str) and value for value in segments
        ):
            raise ValueError(f"server login {client} capture has no selected segments")
    return expected_ids


def _coverage_reason(coverage_id: str, diagnostics: dict[str, Any]) -> str:
    if coverage_id == "server.login.request":
        login = _object(diagnostics.get("serverLogin"), "diagnostics.serverLogin")
        clients = _object(login.get("clients"), "diagnostics.serverLogin.clients")
        return (
            "Rust and MFC emitted one decoded stock-core login each, followed by exact "
            f"ID-change and accepted-session transitions at sequences "
            f"{clients['rust']['loginSequence']}/{clients['mfc']['loginSequence']}."
        )
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
    if coverage_id == "peer.startup.metadata-recovery":
        return (
            "Rust recovered the exact Unicode name, size, MD4/AICH metadata, and source identity "
            "from a causally ordered hash-only startup."
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
    expected_ids = sorted(
        [
            *_derived_transfer_coverage_ids(diagnostics),
            *_derived_server_login_coverage_ids(report, diagnostics),
            *_derived_server_search_coverage_ids(report, diagnostics),
        ]
    )
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

    if "peer.startup.metadata-recovery" in expected_ids:
        if report.get("transfer_scenario") != "hash-only-metadata-recovery":
            raise ValueError("metadata recovery evidence requires the hash-only transfer scenario")
        stimulus = _object(
            _object(report.get("checks"), "checks").get("client1_transfer_stimulus"),
            "checks.client1_transfer_stimulus",
        )
        if stimulus.get("mode") != "hash-only-direct-source-link-with-profile-identity":
            raise ValueError("metadata recovery evidence requires an identity-bearing hash-only stimulus")
        input_metadata = _object(stimulus.get("inputMetadata"), "stimulus.inputMetadata")
        authority_metadata = _object(stimulus.get("authorityMetadata"), "stimulus.authorityMetadata")
        if (
            input_metadata.get("name") != diagnostics.get("fileHash")
            or input_metadata.get("size") != 0
            or str(input_metadata.get("hash") or "").lower() != diagnostics.get("fileHash")
        ):
            raise ValueError("metadata recovery stimulus contains source filename or size metadata")
        if (
            authority_metadata.get("name") != fixture.get("name")
            or authority_metadata.get("size") != fixture_size
            or str(authority_metadata.get("hash") or "").lower() != diagnostics.get("fileHash")
        ):
            raise ValueError("metadata recovery authority metadata does not match the fixture")

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
