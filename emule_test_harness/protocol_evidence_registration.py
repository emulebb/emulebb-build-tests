"""Builds catalog registrations from immutable deterministic evidence receipts."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

from emule_test_harness import ed2k_wire
from emule_test_harness import server_login_diagnostic_evidence
from emule_test_harness import server_tcp_metadata_diagnostic_evidence
from emule_test_harness import transfer_diagnostic_evidence

TRANSFER_SUITE = "deterministic-two-client-transfer"
TRANSFER_RUNNER_PATH = "scripts/deterministic-two-client-transfer.py"
PROFILE_AUTHORITY = "harness-generated-ephemeral-local-profiles"
RUN_DIRECTORY_PATTERN = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)-")
GIT_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ED2K_HASH_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SERVER_LOGIN_SCENARIO = "server-login-request"
SERVER_KEYWORD_SEARCH_SCENARIO = "server-keyword-search"
SERVER_TCP_METADATA_SCENARIO = "server-tcp-metadata"
SERVER_SEARCH_SCHEMA = "emulebb-build-tests.deterministic-server-search-diagnostics.v2"
SERVER_SEARCH_COVERAGE_IDS = ("server.reply.search", "server.search.keyword")
SERVER_SEARCH_EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
SERVER_METADATA_SEED_NAME = "seed-before-server-ident"
SERVER_IDENT_NAME = "emulebb-local-e2e"
SERVER_IDENT_DESCRIPTION = "Workspace deterministic eMuleBB live E2E server"
SERVER_LOGIN_CASE_AUTHORITY = {
    "plain-server-plain-clients": {
        "transportPlan": ("plaintext",),
        "flags": (False, False, False, False),
        "rustServerMetadataMode": "known",
        "coverageId": "server.connect.plaintext",
    },
    "obfuscated-preferred-fallback": {
        "transportPlan": ("obfuscated", "plaintext"),
        "flags": (False, True, True, False),
        "rustServerMetadataMode": "endpoint-only",
        "coverageId": "server.connect.fallback",
    },
    "obfuscated-required": {
        "transportPlan": ("obfuscated",),
        "flags": (True, True, True, True),
        "rustServerMetadataMode": "known",
        "coverageId": "server.connect.obfuscated",
    },
}


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
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
    if search.get("schema") != SERVER_SEARCH_SCHEMA:
        raise ValueError("server search diagnostics use an unexpected schema")
    if search.get("ok") is not True or search.get("failures") != []:
        raise ValueError("server search diagnostics are not complete")

    expected_ids = list(SERVER_SEARCH_COVERAGE_IDS)
    claims = _object(search.get("coverageClaims"), "diagnostics.serverSearch.coverageClaims")
    if search.get("observedCoverageIds") != expected_ids:
        raise ValueError("server search diagnostic observations are not exact")
    if claims.get("eligibleCoverageIds") != expected_ids:
        raise ValueError("server search diagnostic claims are not exact")
    if claims.get("evidenceLayers") != list(SERVER_SEARCH_EVIDENCE_LAYERS):
        raise ValueError("server search diagnostic evidence layers are not canonical")

    checks = _object(report.get("checks"), "checks")
    if checks.get("client_server_search_diagnostics") != search:
        raise ValueError("server search diagnostics do not match the pre-transfer snapshot")

    fixture = _object(report.get("server_search_fixture"), "server_search_fixture")
    fixture_hash = _lower_hex(
        fixture.get("hash"),
        ED2K_HASH_PATTERN,
        "server_search_fixture.hash",
    )
    fixture_name = fixture.get("name")
    if not isinstance(fixture_name, str) or not fixture_name:
        raise ValueError("server_search_fixture.name must be a non-empty string")
    fixture_size = _positive_int(fixture.get("size"), "server_search_fixture.size")
    expected_file = {
        "hash": fixture_hash,
        "name": fixture_name,
        "size": fixture_size,
    }
    if search.get("expectedFile") != expected_file:
        raise ValueError("server search expected file does not match server_search_fixture")
    transfer_fixture = _object(report.get("fixture"), "fixture")
    if (
        fixture_hash == str(diagnostics.get("fileHash") or "").casefold()
        or fixture_name == transfer_fixture.get("name")
    ):
        raise ValueError("server search fixture is not isolated from the MFC transfer fixture")

    def require_fixture_row(value: Any, field: str) -> dict[str, Any]:
        row = _object(value, field)
        names = [row[key] for key in ("name", "displayName") if key in row]
        sizes = [row[key] for key in ("size", "sizeBytes") if key in row]
        if (
            str(row.get("hash") or "").casefold() != fixture_hash
            or not names
            or any(value != fixture_name for value in names)
            or not sizes
            or any(value != fixture_size for value in sizes)
        ):
            raise ValueError(f"{field} does not match server_search_fixture")
        return row

    publication = require_fixture_row(
        fixture.get("publication"),
        "server_search_fixture.publication",
    )
    if publication.get("indexed") is not True or publication.get("requested_size") != fixture_size:
        raise ValueError("server_search_fixture publication is not an exact indexed observation")
    publication_result = require_fixture_row(
        publication.get("search_result"),
        "server_search_fixture.publication.search_result",
    )
    publisher = _object(fixture.get("publisher"), "server_search_fixture.publisher")
    if not isinstance(publisher.get("nickname"), str) or not publisher["nickname"]:
        raise ValueError("server_search_fixture.publisher.nickname must be a non-empty string")
    publisher_port = _positive_int(
        publisher.get("tcpPort"),
        "server_search_fixture.publisher.tcpPort",
    )
    publisher_login = _object(publisher.get("login"), "server_search_fixture.publisher.login")
    publisher_id = _positive_int(
        publisher_login.get("assigned_id"),
        "server_search_fixture.publisher.login.assigned_id",
    )
    expected_id_kind = "low-id" if publisher_id < ed2k_wire.LOW_ID_CEILING else "high-id"
    if publisher_login.get("id_kind") != expected_id_kind:
        raise ValueError("server search publisher login ID class is inconsistent")
    if (
        publication_result.get("result_source_id") != publisher_id
        or publication_result.get("result_source_port") != publisher_port
    ):
        raise ValueError("server search publication is not joined to the neutral publisher")
    publication_source = _object(
        publication.get("search_source"),
        "server_search_fixture.publication.search_source",
    )
    if publication_source.get("id") != publisher_id or publication_source.get("port") != publisher_port:
        raise ValueError("server search publication source reference is not the neutral publisher")
    if publication.get("hash") is None:
        raise ValueError("server_search_fixture publication has no hash")

    network = _object(report.get("network"), "network")
    ports = _object(network.get("ports"), "network.ports")
    server_port = _positive_int(ports.get("ed2k_tcp"), "network.ports.ed2k_tcp")
    if ports.get("search_publisher_tcp") != publisher_port:
        raise ValueError("server search publisher port does not match network provenance")
    server_address = network.get("ed2k_server_address")
    if not isinstance(server_address, str) or not server_address:
        raise ValueError("network.ed2k_server_address must be a non-empty string")
    expected_endpoint = f"{server_address}:{server_port}".casefold()
    if search.get("serverEndpoint") != expected_endpoint:
        raise ValueError("server search diagnostics use an unexpected server endpoint")

    query = search.get("query")
    if not isinstance(query, str) or not query:
        raise ValueError("server search query must be a non-empty string")
    expected_payload_hex = ed2k_wire.encode_term_search(query).hex()
    driven_searches = _object(
        checks.get("client_server_searches"),
        "checks.client_server_searches",
    )
    if set(driven_searches) != {"rust", "mfc"}:
        raise ValueError("driven server searches must contain exactly rust and mfc")
    clients = _object(search.get("clients"), "diagnostics.serverSearch.clients")
    if set(clients) != {"rust", "mfc"}:
        raise ValueError("server search diagnostics must contain exactly rust and mfc")

    comparable_wire_rows: dict[str, dict[str, Any]] = {}
    comparable_rest_rows: dict[str, dict[str, Any]] = {}
    request_payloads: dict[str, str] = {}
    transport_modes: dict[str, tuple[Any, Any]] = {}
    for client in ("rust", "mfc"):
        driven = _object(
            driven_searches.get(client),
            f"checks.client_server_searches.{client}",
        )
        search_id = driven.get("searchId")
        if not isinstance(search_id, str) or not search_id:
            raise ValueError(f"{client} driven server search has no search ID")
        created = _object(
            driven.get("created"),
            f"checks.client_server_searches.{client}.created",
        )
        final_search = _object(
            driven.get("search"),
            f"checks.client_server_searches.{client}.search",
        )
        result = require_fixture_row(
            driven.get("result"),
            f"checks.client_server_searches.{client}.result",
        )
        items = final_search.get("items")
        if not isinstance(items, list) or len(items) != 1 or items[0] != result:
            raise ValueError(f"{client} driven server search does not contain one exact result")
        require_fixture_row(
            items[0],
            f"checks.client_server_searches.{client}.search.items[0]",
        )
        status = final_search.get("status")
        common_rest_exact = bool(
            str(created.get("id") or "") == search_id
            and created.get("query") == query
            and str(final_search.get("id") or "") == search_id
            and final_search.get("query") == query
            and str(status or "").casefold() in {"complete", "completed"}
            and final_search.get("total") == 1
            and str(result.get("searchId") or "") == search_id
        )
        rust_method_exact = bool(
            created.get("requestedMethod") == "server"
            and final_search.get("requestedMethod") == "server"
            and final_search.get("resolvedMethod") == "server"
            and "method" not in created
            and "method" not in final_search
        )
        mfc_method_exact = bool(
            created.get("method") == "server"
            and final_search.get("method") == "server"
            and "requestedMethod" not in created
            and "requestedMethod" not in final_search
            and "resolvedMethod" not in created
            and "resolvedMethod" not in final_search
        )
        if not common_rest_exact or not (rust_method_exact if client == "rust" else mfc_method_exact):
            raise ValueError(f"{client} driven server search is not exact")

        client_evidence = _object(
            clients.get(client),
            f"diagnostics.serverSearch.clients.{client}",
        )
        if client_evidence.get("ok") is not True:
            raise ValueError(f"{client} server search evidence is not green")
        rest = _object(
            client_evidence.get("rest"),
            f"diagnostics.serverSearch.clients.{client}.rest",
        )
        rest_result = require_fixture_row(
            rest.get("result"),
            f"diagnostics.serverSearch.clients.{client}.rest.result",
        )
        expected_rest_method = (
            {
                "createdRequested": "server",
                "finalRequested": "server",
                "finalResolved": "server",
            }
            if client == "rust"
            else {"created": "server", "final": "server"}
        )
        if (
            rest.get("ok") is not True
            or rest.get("searchId") != search_id
            or rest.get("status") != status
            or rest.get("method") != expected_rest_method
            or rest.get("total") != 1
            or rest.get("exactResultCount") != 1
            or rest_result != result
        ):
            raise ValueError(f"{client} REST search evidence is not joined to the driven search")

        wire = _object(
            client_evidence.get("wire"),
            f"diagnostics.serverSearch.clients.{client}.wire",
        )
        request = _object(
            wire.get("request"),
            f"diagnostics.serverSearch.clients.{client}.wire.request",
        )
        reply = _object(
            wire.get("reply"),
            f"diagnostics.serverSearch.clients.{client}.wire.reply",
        )
        request_sequence = _positive_int(
            request.get("sequence"),
            f"{client} server search request sequence",
        )
        reply_sequence = _positive_int(
            reply.get("sequence"),
            f"{client} server search reply sequence",
        )
        _positive_int(request.get("traceId"), f"{client} server search trace ID")
        if client == "rust":
            _positive_int(
                request.get("sendAttemptId"),
                "rust server search send attempt ID",
            )
        if (
            wire.get("ok") is not True
            or request.get("ok") is not True
            or request.get("endpointRequestCount") != 1
            or request.get("exactRequestCount") != 1
            or request.get("payloadHex") != expected_payload_hex
            or request.get("transportMode") != "obfuscated"
        ):
            raise ValueError(f"{client} server search request is not singular and exact")
        exact_row = require_fixture_row(
            reply.get("exactRow"),
            f"diagnostics.serverSearch.clients.{client}.wire.reply.exactRow",
        )
        if (
            exact_row.get("result_source_id") != publisher_id
            or exact_row.get("result_source_port") != publisher_port
        ):
            raise ValueError(f"{client} server search reply is not sourced by the neutral publisher")
        if (
            reply.get("ok") is not True
            or reply.get("endpointResponseCount") != 1
            or reply.get("traceResponseCount") != 1
            or reply.get("malformedResponseCount") != 0
            or reply.get("decodedRowCount") != 1
            or reply.get("exactRowCount") != 1
            or reply_sequence <= request_sequence
            or reply.get("transportMode") != "obfuscated"
        ):
            raise ValueError(f"{client} server search reply is not singular and causal")

        lifecycle = _object(
            client_evidence.get("lifecycle"),
            f"diagnostics.serverSearch.clients.{client}.lifecycle",
        )
        if lifecycle.get("ok") is not True:
            raise ValueError(f"{client} server search lifecycle is not green")
        if client == "rust":
            active_sequence = _positive_int(
                lifecycle.get("searchActiveSequence"),
                "rust server search active sequence",
            )
            send_sequence = _positive_int(
                lifecycle.get("sendOutcomeSequence"),
                "rust server search send outcome sequence",
            )
            completed_sequence = _positive_int(
                lifecycle.get("completedSequence"),
                "rust server search completed sequence",
            )
            scheduler_sequence = _positive_int(
                lifecycle.get("schedulerSequence"),
                "rust server search scheduler sequence",
            )
            if (
                lifecycle.get("sendOutcomeCount") != 1
                or lifecycle.get("searchActiveCount") != 1
                or lifecycle.get("completedCount") != 1
                or lifecycle.get("schedulerCompletionCount") != 1
                or not (
                    active_sequence
                    < request_sequence
                    < send_sequence
                    < reply_sequence
                    < completed_sequence
                    < scheduler_sequence
                )
            ):
                raise ValueError("rust server search lifecycle is not causally ordered")
        else:
            applied_sequence = _positive_int(
                lifecycle.get("appliedSequence"),
                "mfc server search applied sequence",
            )
            cumulative_after = _positive_int(
                lifecycle.get("cumulativeSourceCountAfter"),
                "mfc server search cumulative source count after",
            )
            if (
                lifecycle.get("appliedCount") != 1
                or applied_sequence <= reply_sequence
                or lifecycle.get("expectedReply") is not True
                or lifecycle.get("wireResultCount") != 1
                or lifecycle.get("cumulativeSourceCountBefore") != 0
                or cumulative_after < 1
                or lifecycle.get("distinctFileCountBefore") != 0
                or lifecycle.get("distinctFileCountAfter") != 1
                or lifecycle.get("moreResultsAvailable") is not False
                or lifecycle.get("outcome") != "accepted"
            ):
                raise ValueError("mfc server search lifecycle is not causally ordered")

        comparable_wire_rows[client] = {
            "hash": str(exact_row.get("hash") or "").casefold(),
            "name": exact_row.get("name", exact_row.get("displayName")),
            "size": exact_row.get("size", exact_row.get("sizeBytes")),
            "sources": _nonnegative_int(
                exact_row.get("sources"),
                f"{client} server search wire source count",
            ),
            "completeSources": _nonnegative_int(
                exact_row.get("complete_sources", exact_row.get("completeSources")),
                f"{client} server search wire complete-source count",
            ),
            "resultSourceId": exact_row.get("result_source_id"),
            "resultSourcePort": exact_row.get("result_source_port"),
        }
        comparable_rest_rows[client] = {
            "hash": str(rest_result.get("hash") or "").casefold(),
            "name": rest_result.get("name", rest_result.get("displayName")),
            "size": rest_result.get("size", rest_result.get("sizeBytes")),
            "sources": _nonnegative_int(
                rest_result.get("sources"),
                f"{client} server search REST source count",
            ),
            "completeSources": _nonnegative_int(
                rest_result.get("complete_sources", rest_result.get("completeSources")),
                f"{client} server search REST complete-source count",
            ),
        }
        comparable_wire_rest_row = {
            key: value
            for key, value in comparable_wire_rows[client].items()
            if key not in {"resultSourceId", "resultSourcePort"}
        }
        if (
            client_evidence.get("wireRestEqual") is not True
            or comparable_wire_rest_row != comparable_rest_rows[client]
        ):
            raise ValueError(f"{client} wire result is not joined to its applied REST result")
        request_payloads[client] = request["payloadHex"]
        transport_modes[client] = (
            request.get("transportMode"),
            reply.get("transportMode"),
        )

    comparison = _object(search.get("comparison"), "diagnostics.serverSearch.comparison")
    comparison_fields = {
        "ok",
        "requestPayloadEqual",
        "replyRowEqual",
        "restResultEqual",
        "transportModeEqual",
        "rustWireRestEqual",
        "mfcWireRestEqual",
    }
    if set(comparison) != comparison_fields or any(comparison.get(field) is not True for field in comparison_fields):
        raise ValueError("bilateral server search comparison is not exact")
    if (
        request_payloads["rust"] != request_payloads["mfc"]
        or comparable_wire_rows["rust"] != comparable_wire_rows["mfc"]
        or comparable_rest_rows["rust"] != comparable_rest_rows["mfc"]
        or transport_modes["rust"] != transport_modes["mfc"]
        or transport_modes["rust"] != ("obfuscated", "obfuscated")
    ):
        raise ValueError("bilateral server search evidence does not compare exactly")

    captures = _object(search.get("captures"), "diagnostics.serverSearch.captures")
    if set(captures) != {"rust", "mfc"}:
        raise ValueError("server search captures must contain exactly rust and mfc")
    for client in ("rust", "mfc"):
        capture = _object(
            captures.get(client),
            f"diagnostics.serverSearch.captures.{client}",
        )
        _positive_int(capture.get("processId"), f"server search {client} process ID")
        segments = capture.get("selectedSegments")
        if (
            not isinstance(segments, list)
            or not segments
            or not all(isinstance(value, str) and value for value in segments)
        ):
            raise ValueError(f"server search {client} capture has no selected segments")
    return expected_ids


def _derived_server_tcp_metadata_coverage_ids(
    report: dict[str, Any], diagnostics: dict[str, Any]
) -> list[str]:
    metadata_value = diagnostics.get("serverTcpMetadata")
    if metadata_value is None:
        if report.get("transfer_scenario") == SERVER_TCP_METADATA_SCENARIO:
            raise ValueError("server TCP metadata scenario has no diagnostic evidence")
        return []
    if report.get("transfer_scenario") != SERVER_TCP_METADATA_SCENARIO:
        raise ValueError("server TCP metadata evidence requires its dedicated scenario")

    metadata = _object(metadata_value, "diagnostics.serverTcpMetadata")
    if metadata.get("schema") != server_tcp_metadata_diagnostic_evidence.SCHEMA:
        raise ValueError("server TCP metadata diagnostics use an unexpected schema")
    if metadata.get("ok") is not True or metadata.get("failures") != []:
        raise ValueError("server TCP metadata diagnostics are not complete")

    expected_ids = list(server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS)
    claims = _object(
        metadata.get("coverageClaims"),
        "diagnostics.serverTcpMetadata.coverageClaims",
    )
    if metadata.get("observedCoverageIds") != expected_ids:
        raise ValueError("server TCP metadata observations are not exact")
    if claims.get("eligibleCoverageIds") != expected_ids:
        raise ValueError("server TCP metadata claims are not exact")
    if claims.get("evidenceLayers") != list(
        server_tcp_metadata_diagnostic_evidence.EVIDENCE_LAYERS
    ):
        raise ValueError("server TCP metadata evidence layers are not canonical")

    checks = _object(report.get("checks"), "checks")
    if checks.get("client_server_tcp_metadata_diagnostics") != metadata:
        raise ValueError("server TCP metadata diagnostics do not match the pre-transfer snapshot")

    endpoint = metadata.get("serverEndpoint")
    if not isinstance(endpoint, str) or endpoint.count(":") != 1:
        raise ValueError("server TCP metadata endpoint must be canonical IPv4 host:port")
    host, port_text = endpoint.rsplit(":", 1)
    try:
        canonical_host = str(ipaddress.IPv4Address(host))
        endpoint_port = int(port_text)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError("server TCP metadata endpoint must be canonical IPv4 host:port") from exc
    if canonical_host != host or not 1 <= endpoint_port <= 65535 or str(endpoint_port) != port_text:
        raise ValueError("server TCP metadata endpoint must be canonical IPv4 host:port")
    if metadata.get("seedName") != SERVER_METADATA_SEED_NAME:
        raise ValueError("server TCP metadata seed name is not canonical")
    expected_ident = {
        "name": SERVER_IDENT_NAME,
        "description": SERVER_IDENT_DESCRIPTION,
    }
    if metadata.get("expectedIdent") != expected_ident:
        raise ValueError("server TCP metadata expected ident is not canonical")

    clients = _object(metadata.get("clients"), "diagnostics.serverTcpMetadata.clients")
    if set(clients) != {"rust", "mfc"}:
        raise ValueError("server TCP metadata clients must contain exactly rust and mfc")
    raw_rest = _object(
        checks.get("client_server_tcp_metadata_rest"),
        "checks.client_server_tcp_metadata_rest",
    )
    if set(raw_rest) != {"rust", "mfc"}:
        raise ValueError("server TCP metadata REST snapshots must contain exactly rust and mfc")

    ident_rows: dict[str, dict[str, Any]] = {}
    transport_rows: dict[str, list[str]] = {}
    for client in ("rust", "mfc"):
        prefix = f"diagnostics.serverTcpMetadata.clients.{client}"
        row = _object(clients.get(client), prefix)
        if set(row) != {"ok", "wire", "applied", "rest"} or row.get("ok") is not True:
            raise ValueError(f"{client} server TCP metadata row is not exact")

        wire = _object(row.get("wire"), f"{prefix}.wire")
        wire_fields = {
            "ok",
            "traceId",
            "packetCounts",
            "sequences",
            "requestPayloadHex",
            "requestOutcome",
            "transportModes",
            "status",
            "ident",
            "decodeErrors",
        }
        if set(wire) != wire_fields or wire.get("ok") is not True:
            raise ValueError(f"{client} server TCP metadata wire row is not exact")
        _positive_int(wire.get("traceId"), f"{prefix}.wire.traceId")
        packet_counts = _object(wire.get("packetCounts"), f"{prefix}.wire.packetCounts")
        if packet_counts != {"idChange": 1, "getServerList": 1, "status": 1, "ident": 1}:
            raise ValueError(f"{client} server TCP metadata packets are not singular")
        sequences = _object(wire.get("sequences"), f"{prefix}.wire.sequences")
        if set(sequences) != {"idChange", "request", "status", "ident"}:
            raise ValueError(f"{client} server TCP metadata sequences are malformed")
        id_change_sequence = _positive_int(
            sequences.get("idChange"), f"{prefix}.wire.sequences.idChange"
        )
        request_sequence = _positive_int(
            sequences.get("request"), f"{prefix}.wire.sequences.request"
        )
        status_sequence = _positive_int(
            sequences.get("status"), f"{prefix}.wire.sequences.status"
        )
        ident_sequence = _positive_int(
            sequences.get("ident"), f"{prefix}.wire.sequences.ident"
        )
        if not (
            id_change_sequence < request_sequence < ident_sequence
            and id_change_sequence < status_sequence
        ):
            raise ValueError(f"{client} server TCP metadata packets are not causally ordered")
        expected_request_outcome = "attempted" if client == "rust" else "send_succeeded"
        if (
            wire.get("requestPayloadHex") != ""
            or wire.get("requestOutcome") != expected_request_outcome
            or wire.get("decodeErrors") != []
        ):
            raise ValueError(f"{client} server TCP metadata request or decode result is not exact")
        transport_modes = wire.get("transportModes")
        if transport_modes != ["obfuscated", "obfuscated", "obfuscated", "obfuscated"]:
            raise ValueError(f"{client} server TCP metadata transport is not exact")
        transport_rows[client] = transport_modes

        status = _object(wire.get("status"), f"{prefix}.wire.status")
        if set(status) != {"users", "files"}:
            raise ValueError(f"{client} server status decode is malformed")
        status_users = _nonnegative_int(status.get("users"), f"{prefix}.wire.status.users")
        status_files = _nonnegative_int(status.get("files"), f"{prefix}.wire.status.files")

        ident = _object(wire.get("ident"), f"{prefix}.wire.ident")
        if set(ident) != {
            "server_hash",
            "advertised_ip",
            "advertised_port",
            "name",
            "description",
            "tags",
        }:
            raise ValueError(f"{client} server ident decode is malformed")
        server_hash = ident.get("server_hash")
        if not isinstance(server_hash, str) or re.fullmatch(r"[0-9A-F]{32}", server_hash) is None:
            raise ValueError(f"{client} server ident hash is malformed")
        advertised_ip = ident.get("advertised_ip")
        try:
            canonical_advertised_ip = str(ipaddress.IPv4Address(advertised_ip))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"{client} server ident address is malformed") from exc
        if canonical_advertised_ip != advertised_ip or ident.get("advertised_port") != endpoint_port:
            raise ValueError(f"{client} server ident endpoint is malformed")
        if ident.get("name") != SERVER_IDENT_NAME or ident.get("description") != SERVER_IDENT_DESCRIPTION:
            raise ValueError(f"{client} server ident text does not match the canonical server")
        tags = ident.get("tags")
        if not isinstance(tags, list) or not all(
            isinstance(tag, dict) and set(tag) == {"name", "value"} for tag in tags
        ):
            raise ValueError(f"{client} server ident tags are malformed")
        if [tag for tag in tags if tag == {"name": ed2k_wire.ST_SERVERNAME, "value": SERVER_IDENT_NAME}] != [
            {"name": ed2k_wire.ST_SERVERNAME, "value": SERVER_IDENT_NAME}
        ] or [
            tag
            for tag in tags
            if tag == {"name": ed2k_wire.ST_DESCRIPTION, "value": SERVER_IDENT_DESCRIPTION}
        ] != [{"name": ed2k_wire.ST_DESCRIPTION, "value": SERVER_IDENT_DESCRIPTION}]:
            raise ValueError(f"{client} server ident tags do not contain the canonical text exactly once")
        ident_rows[client] = ident

        applied = _object(row.get("applied"), f"{prefix}.applied")
        if set(applied) != {"ok", "status", "ident"} or applied.get("ok") is not True:
            raise ValueError(f"{client} server metadata application row is not exact")
        applied_status = _object(applied.get("status"), f"{prefix}.applied.status")
        if set(applied_status) != {"ok", "count", "sequence", "users", "files"}:
            raise ValueError(f"{client} applied server status row is malformed")
        applied_status_sequence = _positive_int(
            applied_status.get("sequence"), f"{prefix}.applied.status.sequence"
        )
        if (
            applied_status.get("ok") is not True
            or applied_status.get("count") != 1
            or applied_status_sequence <= status_sequence
            or applied_status.get("users") != status_users
            or applied_status.get("files") != status_files
        ):
            raise ValueError(f"{client} server status is not joined to its post-apply event")
        applied_ident = _object(applied.get("ident"), f"{prefix}.applied.ident")
        if set(applied_ident) != {"ok", "count", "sequence", "name", "description"}:
            raise ValueError(f"{client} applied server ident row is malformed")
        applied_ident_sequence = _positive_int(
            applied_ident.get("sequence"), f"{prefix}.applied.ident.sequence"
        )
        if (
            applied_ident.get("ok") is not True
            or applied_ident.get("count") != 1
            or applied_ident_sequence <= ident_sequence
            or applied_ident.get("name") != ident.get("name")
            or applied_ident.get("description") != ident.get("description")
        ):
            raise ValueError(f"{client} server ident is not joined to its post-apply event")

        rest = _object(row.get("rest"), f"{prefix}.rest")
        if set(rest) != {"ok", "seedNameChanged", "connection", "server"}:
            raise ValueError(f"{client} server metadata REST row is malformed")
        connection = _object(rest.get("connection"), f"{prefix}.rest.connection")
        expected_connection = {
            "connected": True,
            "address": host,
            "port": endpoint_port,
        }
        expected_server = {
            "address": host,
            "port": endpoint_port,
            "name": ident["name"],
            "description": ident["description"],
            "users": status_users,
            "files": status_files,
        }
        if (
            rest.get("ok") is not True
            or rest.get("seedNameChanged") is not True
            or connection != expected_connection
            or rest.get("server") != expected_server
        ):
            raise ValueError(f"{client} REST state is not joined to its decoded server metadata")
        raw_snapshot = _object(raw_rest.get(client), f"checks.client_server_tcp_metadata_rest.{client}")
        if set(raw_snapshot) != {"connectionStatus", "serverEntity"}:
            raise ValueError(f"{client} raw REST snapshot has an unexpected shape")
        raw_status = _object(
            raw_snapshot.get("connectionStatus"),
            f"checks.client_server_tcp_metadata_rest.{client}.connectionStatus",
        )
        raw_current = _object(
            raw_status.get("currentServer"),
            f"checks.client_server_tcp_metadata_rest.{client}.connectionStatus.currentServer",
        )
        if raw_status.get("connected") is not True or raw_current.get("current") is not True:
            raise ValueError(f"{client} raw REST snapshot is not connected to the current server")
        if any(
            raw_current.get(field) != value
            for field, value in expected_connection.items()
            if field != "connected"
        ):
            raise ValueError(f"{client} raw REST connection does not match the diagnostic endpoint")
        raw_entity = _object(
            raw_snapshot.get("serverEntity"),
            f"checks.client_server_tcp_metadata_rest.{client}.serverEntity",
        )
        if any(raw_entity.get(field) != value for field, value in expected_server.items()):
            raise ValueError(f"{client} raw REST server entity does not match the diagnostic state")

    comparison = _object(metadata.get("comparison"), "diagnostics.serverTcpMetadata.comparison")
    comparison_fields = {"ok", "identEqual", "identMatchesExpected", "transportModeEqual"}
    if set(comparison) != comparison_fields or any(
        comparison.get(field) is not True for field in comparison_fields
    ):
        raise ValueError("bilateral server TCP metadata comparison is not exact")
    if (
        ident_rows["rust"] != ident_rows["mfc"]
        or ident_rows["rust"].get("name") != SERVER_IDENT_NAME
        or ident_rows["rust"].get("description") != SERVER_IDENT_DESCRIPTION
        or transport_rows["rust"] != transport_rows["mfc"]
    ):
        raise ValueError("bilateral server TCP metadata evidence does not compare exactly")

    captures = _object(metadata.get("captures"), "diagnostics.serverTcpMetadata.captures")
    if set(captures) != {"rust", "mfc"}:
        raise ValueError("server TCP metadata captures must contain exactly rust and mfc")
    for client in ("rust", "mfc"):
        capture = _object(
            captures.get(client),
            f"diagnostics.serverTcpMetadata.captures.{client}",
        )
        _positive_int(capture.get("processId"), f"server TCP metadata {client} process ID")
        segments = capture.get("selectedSegments")
        if not isinstance(segments, list) or not segments or not all(
            isinstance(value, str) and value for value in segments
        ):
            raise ValueError(f"server TCP metadata {client} capture has no selected segments")
    return expected_ids


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
    protocol_case = _object(report.get("protocol_case"), "protocol_case")
    case_name = protocol_case.get("name")
    case_authority = (
        SERVER_LOGIN_CASE_AUTHORITY.get(case_name) if isinstance(case_name, str) else None
    )
    if case_authority is None:
        raise ValueError("server login evidence requires one canonical transport protocol case")
    expected_transport_plan = list(case_authority["transportPlan"])
    expected_case_flags = dict(
        zip(
            (
                "server_protocol_obfuscation",
                "client_crypt_supported",
                "client_crypt_requested",
                "client_crypt_required",
            ),
            case_authority["flags"],
            strict=True,
        )
    )
    if any(protocol_case.get(name) is not value for name, value in expected_case_flags.items()):
        raise ValueError("server login protocol case flags do not match its named transport case")
    metadata_mode = case_authority["rustServerMetadataMode"]
    if protocol_case.get("rust_server_metadata_mode") != metadata_mode:
        raise ValueError("server login Rust metadata mode does not match its named transport case")
    if login.get("expectedTransportPlan") != expected_transport_plan:
        raise ValueError("server login expected transport plan does not match the protocol case")

    claims = _object(login.get("coverageClaims"), "diagnostics.serverLogin.coverageClaims")
    expected_ids = sorted(
        [
            "server.login.request",
            case_authority["coverageId"],
        ]
    )
    if claims.get("eligibleCoverageIds") != expected_ids:
        raise ValueError("server login diagnostic claims are not exact")
    if claims.get("evidenceLayers") != list(server_login_diagnostic_evidence.EVIDENCE_LAYERS):
        raise ValueError("server login diagnostic evidence layers are not canonical")

    checks = _object(report.get("checks"), "checks")
    rust_server_entry = _object(checks.get("rust_server_entry"), "checks.rust_server_entry")
    capability_fields = {
        "udpFlags",
        "udpKey",
        "udpKeyIp",
        "obfuscationPortTcp",
        "obfuscationPortUdp",
    }
    if metadata_mode == "endpoint-only" and capability_fields.intersection(rust_server_entry):
        raise ValueError("server fallback Rust entry is not endpoint-only")
    if metadata_mode == "known" and not capability_fields.issubset(rust_server_entry):
        raise ValueError("server login Rust entry lacks required capability metadata")
    if checks.get("client_server_login_diagnostics") != login:
        raise ValueError("server login diagnostics do not match the pre-transfer snapshot")
    clients = _object(login.get("clients"), "diagnostics.serverLogin.clients")
    for client in ("rust", "mfc"):
        row = _object(clients.get(client), f"diagnostics.serverLogin.clients.{client}")
        attempt_start_sequences = row.get("attemptStartSequences")
        attempt_trace_ids = row.get("attemptTraceIds")
        attempt_phases = row.get("attemptPhases")
        attempt_states = row.get("attemptStates")
        attempt_start_count = _positive_int(
            row.get("attemptStartCount"),
            f"diagnostics.serverLogin.clients.{client}.attemptStartCount",
        )
        login_packet_count = _positive_int(
            row.get("loginPacketCount"),
            f"diagnostics.serverLogin.clients.{client}.loginPacketCount",
        )
        final_login_packet_count = _positive_int(
            row.get("finalLoginPacketCount"),
            f"diagnostics.serverLogin.clients.{client}.finalLoginPacketCount",
        )
        failed_attempt_login_count = _nonnegative_int(
            row.get("failedAttemptLoginPacketCount"),
            f"diagnostics.serverLogin.clients.{client}.failedAttemptLoginPacketCount",
        )
        connection_failure_count = _nonnegative_int(
            row.get("connectionFailureCount"),
            f"diagnostics.serverLogin.clients.{client}.connectionFailureCount",
        )
        fallback_count = _nonnegative_int(
            row.get("transportFallbackCount"),
            f"diagnostics.serverLogin.clients.{client}.transportFallbackCount",
        )
        accepted_count = _positive_int(
            row.get("loginAcceptedCount"),
            f"diagnostics.serverLogin.clients.{client}.loginAcceptedCount",
        )
        if (
            attempt_start_count != len(expected_transport_plan)
            or attempt_phases != ["connection"] * len(expected_transport_plan)
            or attempt_states != ["connecting"] * len(expected_transport_plan)
            or not isinstance(attempt_start_sequences, list)
            or len(attempt_start_sequences) != len(expected_transport_plan)
            or not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0
                for value in attempt_start_sequences
            )
            or attempt_start_sequences != sorted(set(attempt_start_sequences))
            or not isinstance(attempt_trace_ids, list)
            or len(attempt_trace_ids) != len(expected_transport_plan)
            or not all(
                isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in attempt_trace_ids
            )
            or len(set(attempt_trace_ids)) != len(attempt_trace_ids)
            or row.get("attemptPlanExact") is not True
        ):
            raise ValueError(f"{client} server transport attempts are not exact")
        final_attempt_sequence = _positive_int(
            row.get("finalAttemptStartSequence"),
            f"diagnostics.serverLogin.clients.{client}.finalAttemptStartSequence",
        )
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
        final_trace_id = _positive_int(
            row.get("finalTraceId"),
            f"diagnostics.serverLogin.clients.{client}.finalTraceId",
        )
        final_trace_components = {
            _positive_int(
                row.get(field),
                f"diagnostics.serverLogin.clients.{client}.{field}",
            )
            for field in (
                "finalAttemptTraceId",
                "loginTraceId",
                "idChangeTraceId",
                "loginAcceptedTraceId",
            )
        }
        if final_trace_components != {final_trace_id}:
            raise ValueError(f"{client} final server-login trace IDs are not exact")
        if len(expected_transport_plan) == 1 and (
            attempt_start_sequences != [final_attempt_sequence]
            or attempt_trace_ids != [final_trace_id]
        ):
            raise ValueError(f"{client} singular server attempt is not joined to the final trace")
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
            or accepted_count != 1
            or row.get("loginAcceptedPhase") != "connection"
            or row.get("loginAcceptedState") != "connected"
            or final_login_packet_count != 1
            or login_packet_count != 1 + failed_attempt_login_count
            or row.get("sendSucceeded") is not True
            or row.get("semanticShape") is not True
            or row.get("transportPlanExact") is not True
            or row.get("traceCorrelation") is not True
            or row.get("fallbackCausal") is not True
            or decoded_login.get("client_id") != 0
            or decoded_id.get("id_kind") != "low-id"
            or not final_attempt_sequence < login_sequence < id_change_sequence < accepted_sequence
        ):
            raise ValueError(f"{client} server login evidence is not singular and causal")
        final_transport_mode = expected_transport_plan[-1]
        if client == "rust":
            send_outcome_sequence = _positive_int(
                row.get("sendOutcomeSequence"),
                "diagnostics.serverLogin.clients.rust.sendOutcomeSequence",
            )
            send_outcome_trace_id = _positive_int(
                row.get("sendOutcomeTraceId"),
                "diagnostics.serverLogin.clients.rust.sendOutcomeTraceId",
            )
            if (
                not login_sequence < send_outcome_sequence < id_change_sequence
                or send_outcome_trace_id != final_trace_id
                or row.get("sendOutcomeTransportMode") != final_transport_mode
            ):
                raise ValueError("Rust server-login send outcome is not joined to the final attempt")
        elif any(
            row.get(field) is not None
            for field in (
                "sendOutcomeSequence",
                "sendOutcomeTraceId",
                "sendOutcomeTransportMode",
            )
        ):
            raise ValueError("MFC server login contains an unexpected separate send outcome")
        if row.get("transportObservation") != {
            "attempts": expected_transport_plan,
            "login": final_transport_mode,
            "idChange": final_transport_mode,
            "accepted": final_transport_mode,
        }:
            raise ValueError(f"{client} server login transport observations are not exact")
        if len(expected_transport_plan) == 2:
            failed_attempt_sequence = _positive_int(
                row.get("failedAttemptStartSequence"),
                f"diagnostics.serverLogin.clients.{client}.failedAttemptStartSequence",
            )
            failure_sequence = _positive_int(
                row.get("connectionFailureSequence"),
                f"diagnostics.serverLogin.clients.{client}.connectionFailureSequence",
            )
            fallback_sequence = _positive_int(
                row.get("transportFallbackSequence"),
                f"diagnostics.serverLogin.clients.{client}.transportFallbackSequence",
            )
            failed_trace_id = _positive_int(
                row.get("failedTraceId"),
                f"diagnostics.serverLogin.clients.{client}.failedTraceId",
            )
            fallback_trace_id = _positive_int(
                row.get("fallbackTraceId"),
                f"diagnostics.serverLogin.clients.{client}.fallbackTraceId",
            )
            failed_attempt_trace_id = _positive_int(
                row.get("failedAttemptTraceId"),
                f"diagnostics.serverLogin.clients.{client}.failedAttemptTraceId",
            )
            expected_failed_login_count = 0 if client == "rust" else 1
            failed_login_fields = {
                "failedAttemptLoginSequence": None,
                "failedAttemptLoginTraceId": None,
                "failedAttemptLoginTransportMode": None,
                "failedAttemptLoginOutcome": None,
            }
            if client == "mfc":
                failed_login_sequence = _positive_int(
                    row.get("failedAttemptLoginSequence"),
                    "diagnostics.serverLogin.clients.mfc.failedAttemptLoginSequence",
                )
                failed_login_trace_id = _positive_int(
                    row.get("failedAttemptLoginTraceId"),
                    "diagnostics.serverLogin.clients.mfc.failedAttemptLoginTraceId",
                )
                failed_login_exact = bool(
                    failed_attempt_sequence < failed_login_sequence < failure_sequence
                    and failed_login_trace_id == failed_attempt_trace_id
                    and row.get("failedAttemptLoginTransportMode") == "obfuscated"
                    and row.get("failedAttemptLoginOutcome") == "send_succeeded"
                )
            else:
                failed_login_exact = all(
                    row.get(field) is expected for field, expected in failed_login_fields.items()
                )
            if (
                connection_failure_count != 1
                or fallback_count != 1
                or failed_attempt_login_count != expected_failed_login_count
                or not failed_login_exact
                or attempt_start_sequences != [failed_attempt_sequence, final_attempt_sequence]
                or attempt_trace_ids != [failed_attempt_trace_id, final_trace_id]
                or not failed_attempt_sequence
                < failure_sequence
                < fallback_sequence
                < final_attempt_sequence
                < login_sequence
                or failed_attempt_trace_id != failed_trace_id
                or failed_trace_id != fallback_trace_id
                or failed_trace_id == final_trace_id
                or row.get("connectionFailurePhase") != "connection"
                or row.get("connectionFailureOutcome") != "connection_failed"
                or row.get("connectionFailureTransportMode") != "obfuscated"
                or row.get("transportFallbackPhase") != "connection"
                or row.get("transportFallbackOutcome") != "retrying"
                or row.get("transportFallbackFromMode") != "obfuscated"
                or row.get("transportFallbackToMode") != "plaintext"
                or not isinstance(row.get("fallbackError"), str)
                or not row["fallbackError"]
            ):
                raise ValueError(f"{client} server fallback evidence is not exact and causal")
        elif (
            connection_failure_count != 0
            or fallback_count != 0
            or failed_attempt_login_count != 0
            or any(
                row.get(name) is not expected
                for name, expected in {
                    "failedAttemptStartSequence": None,
                    "connectionFailureSequence": None,
                    "transportFallbackSequence": None,
                    "failedAttemptTraceId": None,
                    "failedTraceId": None,
                    "fallbackTraceId": None,
                    "fallbackError": None,
                    "connectionFailurePhase": None,
                    "connectionFailureOutcome": None,
                    "connectionFailureTransportMode": None,
                    "failedAttemptLoginSequence": None,
                    "failedAttemptLoginTraceId": None,
                    "failedAttemptLoginTransportMode": None,
                    "failedAttemptLoginOutcome": None,
                    "transportFallbackPhase": None,
                    "transportFallbackOutcome": None,
                    "transportFallbackFromMode": None,
                    "transportFallbackToMode": None,
                }.items()
            )
        ):
            raise ValueError(f"{client} singular server transport contains fallback evidence")
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
        "transportPlanExact",
        "traceCorrelationExact",
        "fallbackSequenceExact",
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
    if coverage_id in {
        "server.connect.plaintext",
        "server.connect.obfuscated",
        "server.connect.fallback",
    }:
        login = _object(diagnostics.get("serverLogin"), "diagnostics.serverLogin")
        clients = _object(login.get("clients"), "diagnostics.serverLogin.clients")
        plan = login.get("expectedTransportPlan")
        if coverage_id == "server.connect.fallback":
            return (
                "Rust and MFC each recorded an obfuscated connection failure, a causally "
                "joined plaintext fallback, and an accepted plaintext session at fallback "
                f"sequences {clients['rust']['transportFallbackSequence']}/"
                f"{clients['mfc']['transportFallbackSequence']}."
            )
        return (
            f"Rust and MFC each recorded {plan[0]} transport on login, ID-change, and "
            f"accepted-session transitions at sequences "
            f"{clients['rust']['loginSequence']}/{clients['mfc']['loginSequence']}."
        )
    if coverage_id == "server.login.request":
        login = _object(diagnostics.get("serverLogin"), "diagnostics.serverLogin")
        clients = _object(login.get("clients"), "diagnostics.serverLogin.clients")
        return (
            "Rust and MFC emitted one decoded stock-core login each, followed by exact "
            f"ID-change and accepted-session transitions at sequences "
            f"{clients['rust']['loginSequence']}/{clients['mfc']['loginSequence']}."
        )
    if coverage_id in server_tcp_metadata_diagnostic_evidence.ELIGIBLE_COVERAGE_IDS:
        metadata = _object(
            diagnostics.get("serverTcpMetadata"),
            "diagnostics.serverTcpMetadata",
        )
        clients = _object(
            metadata.get("clients"),
            "diagnostics.serverTcpMetadata.clients",
        )
        rust = _object(clients.get("rust"), "diagnostics.serverTcpMetadata.clients.rust")
        mfc = _object(clients.get("mfc"), "diagnostics.serverTcpMetadata.clients.mfc")
        rust_wire = _object(rust.get("wire"), "Rust server TCP metadata wire evidence")
        mfc_wire = _object(mfc.get("wire"), "MFC server TCP metadata wire evidence")
        rust_sequences = _object(rust_wire.get("sequences"), "Rust server TCP metadata sequences")
        mfc_sequences = _object(mfc_wire.get("sequences"), "MFC server TCP metadata sequences")
        if coverage_id == "server.reply.tcp-ident":
            return (
                "Rust and MFC each decoded and post-applied the same exact server ident, then "
                "exposed it through REST, at wire sequences "
                f"{rust_sequences['ident']}/{mfc_sequences['ident']}."
            )
        return (
            "Rust and MFC each decoded and post-applied one exact server status, then exposed "
            "its per-client dynamic counts through REST, at wire sequences "
            f"{rust_sequences['status']}/{mfc_sequences['status']}."
        )
    if coverage_id in SERVER_SEARCH_COVERAGE_IDS:
        search = _object(diagnostics.get("serverSearch"), "diagnostics.serverSearch")
        clients = _object(search.get("clients"), "diagnostics.serverSearch.clients")
        rust = _object(clients.get("rust"), "diagnostics.serverSearch.clients.rust")
        mfc = _object(clients.get("mfc"), "diagnostics.serverSearch.clients.mfc")
        rust_wire = _object(rust.get("wire"), "diagnostics.serverSearch.clients.rust.wire")
        mfc_wire = _object(mfc.get("wire"), "diagnostics.serverSearch.clients.mfc.wire")
        rust_request = _object(
            rust_wire.get("request"),
            "diagnostics.serverSearch.clients.rust.wire.request",
        )
        mfc_request = _object(
            mfc_wire.get("request"),
            "diagnostics.serverSearch.clients.mfc.wire.request",
        )
        if coverage_id == "server.search.keyword":
            return (
                "Rust and MFC each emitted one identical encoded keyword request over "
                f"obfuscated server transport at sequences "
                f"{rust_request['sequence']}/{mfc_request['sequence']}."
            )
        rust_reply = _object(
            rust_wire.get("reply"),
            "diagnostics.serverSearch.clients.rust.wire.reply",
        )
        mfc_reply = _object(
            mfc_wire.get("reply"),
            "diagnostics.serverSearch.clients.mfc.wire.reply",
        )
        return (
            "Rust and MFC each decoded and applied the same exact server-search result "
            f"at reply sequences {rust_reply['sequence']}/{mfc_reply['sequence']}."
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
            *_derived_server_tcp_metadata_coverage_ids(report, diagnostics),
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
