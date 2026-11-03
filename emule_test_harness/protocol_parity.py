"""Protocol-parity catalog, evidence normalization, and validation helpers."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

CATALOG_SCHEMA = "emulebb-build-tests.protocol-parity-catalog"
NORMALIZED_EVIDENCE_SCHEMA = "emulebb-build-tests.protocol-normalized-evidence"
CATALOG_EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
    "public-discovery",
)
CATALOG_PROVENANCE_FIELDS = (
    "artifactLocator",
    "artifactSha256",
    "runnerPath",
    "runnerRevision",
    "profileAuthority",
    "subjects.authorityId",
    "subjects.sourceRevision",
    "subjects.executableSha256",
)
CATALOG_VERDICTS = (
    "parity",
    "divergence",
    "evidence-incomplete",
    "not-observed",
    "intentional-difference",
)
CATALOG_AUTHORITY_ROLES = frozenset(
    {
        "analysis-only",
        "frozen-executable-reference",
        "frozen-independent-parity-reference",
        "preferred-observable-runtime-oracle",
        "product-under-test",
        "upstream-clean-deterministic-dependency",
        "wire-and-state-intent",
    }
)
CATALOG_ASSET_CLASSIFICATIONS = frozenset(
    {
        "canonical",
        "support",
        "duplicate",
        "product-only",
        "historical",
    }
)
SENSITIVE_FIELD_NAMES = {
    "decoded_hex",
    "payload_hex",
    "peer",
    "raw_hex",
    "remote_addr",
    "ts",
    "ts_utc",
    "wire_hex",
}
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DIGEST_RE = re.compile(r"^(fnv1a64:0x[0-9A-F]{16}|sha256:[0-9a-f]{64})$")
HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")

STOCK_ED2K_VECTOR_CONTRACTS = {
    "server.login.request": {
        "direction": "send",
        "encoding": "ed2k-frame",
        "opcode": 0x01,
        "opcodeName": "OP_LOGINREQUEST",
        "transport": "tcp",
    },
    "server.reply.tcp-ident": {
        "direction": "recv",
        "encoding": "ed2k-frame",
        "opcode": 0x41,
        "opcodeName": "OP_SERVERIDENT",
        "transport": "tcp",
    },
    "server.reply.tcp-status": {
        "direction": "recv",
        "encoding": "ed2k-frame",
        "opcode": 0x34,
        "opcodeName": "OP_SERVERSTATUS",
        "transport": "tcp",
    },
    "server.reply.udp-description": {
        "direction": "recv",
        "encoding": "ed2k-server-udp-datagram",
        "opcode": 0xA3,
        "opcodeName": "OP_SERVER_DESC_RES",
        "transport": "udp",
    },
    "server.reply.udp-status": {
        "direction": "recv",
        "encoding": "ed2k-server-udp-datagram",
        "opcode": 0x97,
        "opcodeName": "OP_GLOBSERVSTATRES",
        "transport": "udp",
    },
}

# Phase-4 stock oracle coverage is intentionally explicit. A manifest cannot
# pass merely by accumulating a large number of records: every behavior below
# must be tied to a canonical binary/state vector, a stock-source anchor, and a
# Rust proof selector.
REQUIRED_STOCK_COVERAGE_IDS = frozenset(
    {
        "client-udp.clear",
        "client-udp.encrypted",
        "client-udp.file-not-found",
        "client-udp.queue-full",
        "client-udp.unsolicited",
        "client-udp.v1",
        "client-udp.v2",
        "client-udp.v3",
        "client-udp.v4",
        "ident.invalid-key",
        "ident.ip-kind.local",
        "ident.ip-kind.remote",
        "ident.replay",
        "ident.v1",
        "ident.v2",
        "kad.contact.v10",
        "kad.contact.v2",
        "kad.contact.v3",
        "kad.contact.v4",
        "kad.contact.v5",
        "kad.contact.v6",
        "kad.contact.v7",
        "kad.contact.v8",
        "kad.contact.v9",
        "kad.crypto.node-id",
        "kad.crypto.receiver-key",
        "kad.flow.buddy",
        "kad.flow.callback",
        "kad.flow.firewall",
        "kad.flow.publish",
        "kad.flow.search",
        "kad.frame.e4",
        "kad.frame.e5",
        "lowid.buddy-callback",
        "lowid.direct-callback",
        "lowid.relayed-reask",
        "lowid.server-callback",
        "nodes-dat.exact-size",
        "nodes-dat.restart",
        "nodes-dat.v0",
        "nodes-dat.v1",
        "nodes-dat.v2",
        "nodes-dat.v3-bootstrap",
        "nodes-dat.v3-normal",
        "peer.boundary.uint32",
        "peer.boundary.uint32-minus-one",
        "peer.boundary.uint32-plus-one",
        "peer.framing.c5",
        "peer.framing.coalesced",
        "peer.framing.d4",
        "peer.framing.e3",
        "peer.framing.fragmented",
        "peer.profile.edonkey",
        "peer.profile.emule-modern",
        "peer.profile.emule-old",
        "peer.startup.aich",
        "peer.startup.crypt",
        "peer.startup.large-file",
        "peer.startup.metadata-recovery",
        "peer.startup.multipacket",
        "peer.startup.multipacket-ext",
        "peer.startup.multipacket-ext2",
        "peer.startup.sx2",
        "queue.abuse-escalation",
        "queue.admission",
        "queue.rank-transition",
        "upload.slot-promotion",
        "upload.slot-recycle",
        "server.connect.fallback",
        "server.connect.obfuscated",
        "server.connect.plaintext",
        "server.login.request",
        "server.reply.callback",
        "server.reply.search",
        "server.reply.sources",
        "server.reply.tcp-ident",
        "server.reply.tcp-status",
        "server.reply.udp-description",
        "server.reply.udp-status",
        "server.search.advanced",
        "server.search.keyword",
        "server.source.tcp-obfuscated",
        "server.source.tcp-plain",
        "server.source.udp-v1",
        "server.source.udp-v2",
        "sx2.crypt-options",
        "sx2.part-needed-filter",
        "sx2.v1",
        "sx2.v2",
        "sx2.v3",
        "sx2.v4",
        "tags.bsob",
        "tags.fixed-vocabulary",
        "tags.malformed-bounds",
        "tags.str1-str22",
        "tags.unknown-name",
        "transfer.block.compressed",
        "transfer.block.compression-bomb",
        "transfer.block.invalid-zlib",
        "transfer.block.uncompressed",
    }
)

KAD_OPCODE_NAME_BY_HEX = {
    "0x01": "KADEMLIA2_BOOTSTRAP_REQ",
    "0x09": "KADEMLIA2_BOOTSTRAP_RES",
    "0x11": "KADEMLIA2_HELLO_REQ",
    "0x19": "KADEMLIA2_HELLO_RES",
    "0x20": "KADEMLIA2_HELLO_RES_ACK",
    "0x21": "KADEMLIA2_REQ",
    "0x29": "KADEMLIA2_RES",
    "0x33": "KADEMLIA2_SEARCH_KEY_REQ",
    "0x34": "KADEMLIA2_SEARCH_SOURCE_REQ",
    "0x35": "KADEMLIA2_SEARCH_NOTES_REQ",
    "0x3B": "KADEMLIA2_SEARCH_RES",
    "0x43": "KADEMLIA2_PUBLISH_KEY_REQ",
    "0x44": "KADEMLIA2_PUBLISH_SOURCE_REQ",
    "0x45": "KADEMLIA2_PUBLISH_NOTES_REQ",
    "0x4B": "KADEMLIA2_PUBLISH_RES",
    "0x4C": "KADEMLIA2_PUBLISH_RES_ACK",
    "0x50": "KADEMLIA_FIREWALLED_REQ",
    "0x53": "KADEMLIA2_FIREWALLED2_REQ",
    "0x58": "KADEMLIA2_FIREWALLED_RES",
    "0x59": "KADEMLIA2_FIREWALLED_ACK_RES",
    "0x60": "KADEMLIA2_FIREWALLUDP",
    "0x61": "KADEMLIA2_FIREWALLUDP",
    "0x62": "KADEMLIA_FINDBUDDY_REQ",
    "0x63": "KADEMLIA_FINDBUDDY_RES",
    "0x64": "KADEMLIA_CALLBACK_REQ",
    "0x65": "KADEMLIA2_PING",
    "0x66": "KADEMLIA2_PONG",
}


@dataclass(frozen=True)
class ProtocolCatalogValidation:
    """Result of validating the tracked protocol-parity catalog."""

    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Reports whether the manifest passed all validation checks."""

        return not self.errors


def default_catalog_path(test_repo_root: Path) -> Path:
    """Returns the tracked protocol-parity catalog path."""

    return test_repo_root.resolve() / "manifests" / "protocol-parity-catalog.json"


def load_json(path: Path) -> Any:
    """Loads one UTF-8 JSON document."""

    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Loads UTF-8 JSONL records from one tracing artifact."""

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: JSONL rows must be objects")
            records.append(value)
    return records


def normalize_udp_records(records: Iterable[dict[str, Any]], *, scenario_id: str) -> list[dict[str, Any]]:
    """Normalizes diagnostic UDP packet JSONL rows into compact oracle records."""

    normalized: list[dict[str, Any]] = []
    for record in records:
        direction = _clean_token(record.get("direction") or "-")
        family = _clean_token(record.get("family") or "udp")
        opcode = _normalize_opcode(record.get("opcode"))
        opcode_name = _clean_token(record.get("opcode_name") or KAD_OPCODE_NAME_BY_HEX.get(opcode, "UNKNOWN"))
        transport_mode = _clean_token(record.get("transport_mode") or _infer_udp_transport_mode(record))
        digest_source = _first_hex_value(record, ("decoded_hex", "wire_hex"))
        normalized.append(
            {
                "scenarioId": scenario_id,
                "recordType": "udp-packet",
                "protocol": "kad2" if family == "kad" else family,
                "transport": "udp",
                "direction": direction,
                "transportMode": transport_mode,
                "opcode": opcode,
                "opcodeName": opcode_name,
                "wireLength": _read_int(record.get("wire_len")),
                "payloadDigest": _sha256_hex_digest(digest_source),
            }
        )
    return sorted(normalized, key=_record_sort_key)


def normalize_ed2k_records(records: Iterable[dict[str, Any]], *, scenario_id: str) -> list[dict[str, Any]]:
    """Normalizes diagnostic eD2K TCP JSONL rows into compact oracle records."""

    normalized: list[dict[str, Any]] = []
    for record in records:
        flow = _clean_token(record.get("flow") or "unknown")
        phase = _clean_token(record.get("phase") or record.get("state_label") or "session")
        direction = _clean_token(record.get("direction") or "meta")
        opcode = _normalize_opcode(record.get("opcode"))
        opcode_name = _clean_token(record.get("opcode_name") or "NONE")
        payload_hex = str(record.get("payload_hex") or record.get("raw_hex") or "")
        entry = {
            "scenarioId": scenario_id,
            "recordType": "ed2k-state",
            "protocol": "ed2k",
            "transport": "tcp",
            "direction": direction,
            "flow": flow,
            "stateId": _clean_token(record.get("state_id") or f"{flow}.{phase}"),
            "stateLabel": phase,
            "transportMode": _clean_token(record.get("transport_mode") or "unknown"),
            "opcode": opcode,
            "opcodeName": opcode_name,
            "payloadLength": _read_int(record.get("payload_len") or record.get("raw_len")),
            "payloadDigest": _sha256_hex_digest(payload_hex),
        }
        normalized.append(entry)
    return sorted(normalized, key=_record_sort_key)


def summarize_state_sequences(records: Iterable[dict[str, Any]], *, scenario_id: str) -> list[dict[str, Any]]:
    """Builds compact state-machine sequence records from normalized eD2K rows."""

    traces: dict[str, list[str]] = defaultdict(list)
    for record in records:
        trace_key = _clean_token(record.get("trace_key") or f"{record.get('flow', 'unknown')}:redacted")
        traces[trace_key].append(_clean_token(record.get("state_id") or record.get("phase") or "unknown"))

    sequence_counter: Counter[str] = Counter(" -> ".join(states) for states in traces.values() if states)
    sequence_records = [
        {
            "scenarioId": scenario_id,
            "recordType": "state-sequence",
            "protocol": "ed2k",
            "transport": "tcp",
            "sequence": sequence,
            "count": count,
        }
        for sequence, count in sorted(sequence_counter.items())
    ]
    return sorted(sequence_records, key=_record_sort_key)


def validate_protocol_catalog(path: Path, *, workspace_root: Path | None = None) -> ProtocolCatalogValidation:
    """Validates the tracked protocol-parity catalog."""

    errors: list[str] = []
    payload = load_json(path)
    if not isinstance(payload, dict):
        return ProtocolCatalogValidation(("catalog must be a JSON object",))
    if payload.get("schema") != CATALOG_SCHEMA:
        errors.append(f"schema must be {CATALOG_SCHEMA}")
    _validate_catalog_contract(
        payload,
        errors,
        repo_root=path.resolve().parent.parent,
        workspace_root=workspace_root,
    )
    scenarios = payload.get("scenarios")
    records = payload.get("records")
    if not isinstance(scenarios, list) or not scenarios:
        errors.append("scenarios must be a non-empty list")
        scenarios = []
    if not isinstance(records, list) or not records:
        errors.append("records must be a non-empty list")
        records = []

    scenario_ids = _validate_scenarios(scenarios, errors)
    _validate_records(records, scenario_ids, errors)
    _validate_stock_oracle(payload, records, errors, workspace_root=workspace_root)
    _validate_no_sensitive_payload(payload, errors)
    return ProtocolCatalogValidation(tuple(errors))


def render_validation_lines(validation: ProtocolCatalogValidation, path: Path) -> list[str]:
    """Renders a concise validation summary for operators and CI logs."""

    lines = [f"Protocol-parity catalog: {path}", f"Protocol-parity catalog validation: {'PASS' if validation.passed else 'FAIL'}"]
    for error in validation.errors:
        lines.append(f"FAIL {error}")
    return lines


def build_catalog_report(
    payload: dict[str, Any],
    validation: ProtocolCatalogValidation,
) -> dict[str, Any]:
    """Builds the machine-readable current coverage and evidence report."""

    groups = payload.get("coverageGroups")
    group_rows = [group for group in groups if isinstance(group, dict)] if isinstance(groups, list) else []
    evidence = payload.get("coverageEvidence")
    evidence_rows = [row for row in evidence if isinstance(row, dict)] if isinstance(evidence, list) else []
    evidence_by_coverage_id = {
        str(row.get("coverageId")): row
        for row in evidence_rows
        if isinstance(row.get("coverageId"), str)
    }
    id_verdict_counts: Counter[str] = Counter()
    group_verdict_counts: Counter[str] = Counter()
    entries: list[dict[str, Any]] = []
    for group in group_rows:
        coverage_rows: list[dict[str, Any]] = []
        for coverage_id in _string_list(group.get("coverageIds")):
            recorded = evidence_by_coverage_id.get(coverage_id)
            if recorded is None:
                row = {
                    "coverageId": coverage_id,
                    "reason": "No current-head execution receipt is registered for this coverage ID.",
                    "receiptIds": [],
                    "verdict": "evidence-incomplete",
                }
            else:
                row = {
                    "coverageId": coverage_id,
                    "reason": recorded.get("reason"),
                    "receiptIds": _string_list(recorded.get("receiptIds")),
                    "verdict": str(recorded.get("verdict") or "evidence-incomplete"),
                }
            id_verdict_counts[row["verdict"]] += 1
            coverage_rows.append(row)
        verdicts = {row["verdict"] for row in coverage_rows}
        if "divergence" in verdicts:
            group_verdict = "divergence"
        elif "evidence-incomplete" in verdicts:
            group_verdict = "evidence-incomplete"
        elif "not-observed" in verdicts:
            group_verdict = "not-observed"
        elif "intentional-difference" in verdicts:
            group_verdict = "intentional-difference"
        else:
            group_verdict = "parity"
        group_verdict_counts[group_verdict] += 1
        entries.append(
            {
                "authorityIds": _string_list(group.get("authorityIds")),
                "campaignIds": _string_list(group.get("campaignIds")),
                "coverageEvidence": coverage_rows,
                "coverageIdCount": len(_string_list(group.get("coverageIds"))),
                "coveredCoverageIdCount": sum(
                    row["verdict"] in {"parity", "intentional-difference"}
                    for row in coverage_rows
                ),
                "deterministicRunner": group.get("deterministicRunner"),
                "groupId": group.get("groupId"),
                "protocolDomain": group.get("protocolDomain"),
                "publicDiscoveryRunner": group.get("publicDiscoveryRunner"),
                "requiredEvidenceLayers": _string_list(group.get("requiredEvidenceLayers")),
                "verdict": group_verdict,
            }
        )
    covered_groups = group_verdict_counts["parity"] + group_verdict_counts["intentional-difference"]
    covered_ids = id_verdict_counts["parity"] + id_verdict_counts["intentional-difference"]
    authorities = payload.get("authorities")
    authority_rows = [row for row in authorities if isinstance(row, dict)] if isinstance(authorities, list) else []
    campaigns = payload.get("campaigns")
    campaign_rows = [row for row in campaigns if isinstance(row, dict)] if isinstance(campaigns, list) else []
    assets = payload.get("assetClassifications")
    asset_rows = [row for row in assets if isinstance(row, dict)] if isinstance(assets, list) else []
    asset_counts = Counter(str(row.get("classification") or "unclassified") for row in asset_rows)
    return {
        "schema": "emulebb-build-tests.protocol-parity-catalog-report",
        "catalogSchema": payload.get("schema"),
        "valid": validation.passed,
        "validationErrors": list(validation.errors),
        "authorityCount": len(authority_rows),
        "unconfiguredAuthorityIds": sorted(
            str(row.get("authorityId")) for row in authority_rows if row.get("status") == "not-configured"
        ),
        "campaignCount": len(campaign_rows),
        "assets": {
            "classificationCounts": {
                classification: asset_counts.get(classification, 0)
                for classification in sorted(CATALOG_ASSET_CLASSIFICATIONS)
            },
            "classifiedCount": len(asset_rows),
            "cleanupCandidates": sorted(
                str(row.get("path"))
                for row in asset_rows
                if row.get("classification") in {"duplicate", "historical"}
            ),
        },
        "coverage": {
            "coveredGroupCount": covered_groups,
            "coveredIdCount": covered_ids,
            "groupVerdictCounts": {
                verdict: group_verdict_counts.get(verdict, 0)
                for verdict in CATALOG_VERDICTS
            },
            "idVerdictCounts": {
                verdict: id_verdict_counts.get(verdict, 0)
                for verdict in CATALOG_VERDICTS
            },
            "requiredGroupCount": len(group_rows),
            "requiredIdCount": sum(len(_string_list(group.get("coverageIds"))) for group in group_rows),
        },
        "entries": sorted(entries, key=lambda row: str(row.get("groupId") or "")),
    }


def render_catalog_report_lines(report: dict[str, Any]) -> list[str]:
    """Renders a concise coverage summary without hiding uncovered entries."""

    coverage = report["coverage"]
    id_counts = coverage["idVerdictCounts"]
    group_counts = coverage["groupVerdictCounts"]
    lines = [
        f"Protocol coverage IDs covered: {coverage['coveredIdCount']}/{coverage['requiredIdCount']}",
        f"Protocol groups fully covered: {coverage['coveredGroupCount']}/{coverage['requiredGroupCount']}",
        "Coverage ID verdicts: "
        + ", ".join(f"{verdict}={id_counts[verdict]}" for verdict in CATALOG_VERDICTS),
        "Group verdicts: "
        + ", ".join(f"{verdict}={group_counts[verdict]}" for verdict in CATALOG_VERDICTS),
        "Protocol assets: "
        + ", ".join(
            f"{classification}={count}"
            for classification, count in report["assets"]["classificationCounts"].items()
        ),
    ]
    unconfigured = report["unconfiguredAuthorityIds"]
    if unconfigured:
        lines.append("Unconfigured authorities: " + ", ".join(unconfigured))
    for entry in report["entries"]:
        if entry["verdict"] not in {"parity", "intentional-difference"}:
            uncovered = [
                row["coverageId"]
                for row in entry["coverageEvidence"]
                if row["verdict"] not in {"parity", "intentional-difference"}
            ]
            label = "PARTIAL" if entry["coveredCoverageIdCount"] else "UNCOVERED"
            lines.append(
                f"{label} {entry['groupId']}: {entry['coveredCoverageIdCount']}/{entry['coverageIdCount']} covered; "
                f"remaining={','.join(uncovered)}"
            )
    return lines


def write_normalized_evidence(path: Path, *, scenarios: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    """Writes one normalized protocol evidence artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": NORMALIZED_EVIDENCE_SCHEMA,
        "description": "Normalized Kad/eD2K protocol oracle evidence. Raw packet captures stay in generated reports.",
        "scenarios": sorted(scenarios, key=lambda item: str(item.get("scenarioId") or "")),
        "records": sorted(records, key=_record_sort_key),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compare_record_sets(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[str]:
    """Compares two normalized protocol record sets and returns human-readable differences."""

    left_counter = Counter(_stable_record_key(record) for record in left)
    right_counter = Counter(_stable_record_key(record) for record in right)
    lines: list[str] = []
    for key in sorted(set(left_counter) | set(right_counter)):
        left_count = left_counter.get(key, 0)
        right_count = right_counter.get(key, 0)
        if left_count != right_count:
            lines.append(f"record={key} left={left_count} right={right_count}")
    return lines


def pcap_tool_status() -> dict[str, str | None]:
    """Returns passive capture tool availability without starting a capture."""

    return {
        "dumpcap": shutil.which("dumpcap"),
        "tshark": shutil.which("tshark"),
        "pktmon": shutil.which("pktmon"),
    }


def build_dumpcap_command(*, output_path: Path, capture_filter: str, interface: str | None = None) -> tuple[str, ...]:
    """Builds a passive dumpcap command line for operator-run packet capture."""

    dumpcap = shutil.which("dumpcap")
    if dumpcap is None:
        raise RuntimeError("dumpcap is not available")
    command = [dumpcap, "-w", str(output_path), "-f", capture_filter]
    if interface:
        command.extend(["-i", interface])
    return tuple(command)


def run_validate_cli(argv: list[str] | None = None) -> int:
    """Runs the protocol-parity catalog validator CLI."""

    parser = argparse.ArgumentParser(description="Validate the tracked protocol-parity catalog.")
    parser.add_argument("--test-repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--manifest-path", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    manifest_path = (args.manifest_path or default_catalog_path(args.test_repo_root)).resolve()
    workspace_root = Path(os.environ["EMULEBB_WORKSPACE_ROOT"]) if os.environ.get("EMULEBB_WORKSPACE_ROOT") else None
    validation = validate_protocol_catalog(manifest_path, workspace_root=workspace_root)
    payload = load_json(manifest_path)
    report = build_catalog_report(payload, validation) if isinstance(payload, dict) else {
        "schema": "emulebb-build-tests.protocol-parity-catalog-report",
        "valid": False,
        "validationErrors": list(validation.errors),
    }
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for line in render_validation_lines(validation, manifest_path):
            print(line)
        for line in render_catalog_report_lines(report):
            print(line)
    return 0 if validation.passed else 1


def run_normalize_cli(argv: list[str] | None = None) -> int:
    """Runs the diagnostic JSONL evidence normalizer CLI."""

    parser = argparse.ArgumentParser(description="Normalize protocol diagnostic JSONL into comparable evidence records.")
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--udp-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--ed2k-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    records: list[dict[str, Any]] = []
    raw_ed2k_records: list[dict[str, Any]] = []
    for path in args.udp_jsonl:
        records.extend(normalize_udp_records(load_jsonl(path), scenario_id=args.scenario_id))
    for path in args.ed2k_jsonl:
        loaded = load_jsonl(path)
        raw_ed2k_records.extend(loaded)
        records.extend(normalize_ed2k_records(loaded, scenario_id=args.scenario_id))
    records.extend(summarize_state_sequences(raw_ed2k_records, scenario_id=args.scenario_id))
    write_normalized_evidence(
        args.output,
        scenarios=[
            {
                "scenarioId": args.scenario_id,
                "protocol": "mixed",
                "source": "diagnostic-capture",
            }
        ],
        records=records,
    )
    return 0


def run_compare_cli(argv: list[str] | None = None) -> int:
    """Runs the normalized oracle record comparator CLI."""

    parser = argparse.ArgumentParser(description="Compare two normalized protocol oracle manifests.")
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    args = parser.parse_args(argv)
    left = load_json(args.left)
    right = load_json(args.right)
    lines = compare_record_sets(left.get("records", []), right.get("records", []))
    if lines:
        for line in lines:
            print(line)
        return 1
    print("Protocol oracle records match")
    return 0


def run_pcap_cli(argv: list[str] | None = None) -> int:
    """Runs an operator-facing passive capture helper."""

    parser = argparse.ArgumentParser(description="Inspect or launch optional passive packet capture helpers.")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--capture-filter", default="tcp or udp")
    parser.add_argument("--interface")
    parser.add_argument("--print-command", action="store_true")
    args = parser.parse_args(argv)

    if args.status:
        print(json.dumps(pcap_tool_status(), indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --status is used")
    command = build_dumpcap_command(output_path=args.output, capture_filter=args.capture_filter, interface=args.interface)
    if args.print_command:
        print(subprocess.list2cmdline(command))
        return 0
    return subprocess.call(command)


def _validate_catalog_contract(
    payload: dict[str, Any],
    errors: list[str],
    *,
    repo_root: Path,
    workspace_root: Path | None,
) -> None:
    """Validates catalog ownership, evidence semantics, and executable routes."""

    contract = payload.get("contract")
    if not isinstance(contract, dict):
        errors.append("contract must be an object")
    else:
        _require_exact_string_list(contract, "evidenceLayers", CATALOG_EVIDENCE_LAYERS, "contract", errors)
        _require_exact_string_list(contract, "provenanceRequired", CATALOG_PROVENANCE_FIELDS, "contract", errors)
        _require_exact_string_list(contract, "verdicts", CATALOG_VERDICTS, "contract", errors)

    authorities = payload.get("authorities")
    authority_ids: set[str] = set()
    if not isinstance(authorities, list) or not authorities:
        errors.append("authorities must be a non-empty list")
        authorities = []
    for index, authority in enumerate(authorities):
        if not isinstance(authority, dict):
            errors.append(f"authorities[{index}] must be an object")
            continue
        authority_id = authority.get("authorityId")
        role = authority.get("role")
        if not isinstance(authority_id, str) or not authority_id:
            errors.append(f"authorities[{index}].authorityId must be a non-empty string")
            continue
        if authority_id in authority_ids:
            errors.append(f"duplicate authorityId: {authority_id}")
        authority_ids.add(authority_id)
        if role not in CATALOG_AUTHORITY_ROLES:
            errors.append(f"authorities[{index}].role is unsupported")
        path_value = authority.get("path")
        revision = authority.get("revision")
        status = authority.get("status")
        if path_value is None:
            if status != "not-configured":
                errors.append(f"authorities[{index}] without path must be not-configured")
            if revision is not None:
                errors.append(f"authorities[{index}] without path cannot pin a revision")
            continue
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"authorities[{index}].path must be a non-empty string")
            continue
        if revision is not None and (not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None):
            errors.append(f"authorities[{index}].revision must be a lowercase 40-character git revision")
        if workspace_root is not None:
            _validate_authority_checkout(
                workspace_root.resolve(),
                authority_id,
                path_value,
                revision,
                errors,
            )

    groups = payload.get("coverageGroups")
    group_ids = {
        group.get("groupId")
        for group in groups
        if isinstance(groups, list) and isinstance(group, dict) and isinstance(group.get("groupId"), str)
    } if isinstance(groups, list) else set()

    campaigns = payload.get("campaigns")
    campaign_ids: set[str] = set()
    group_campaign_owner: dict[str, str] = {}
    if not isinstance(campaigns, list) or not campaigns:
        errors.append("campaigns must be a non-empty list")
        campaigns = []
    for index, campaign in enumerate(campaigns):
        if not isinstance(campaign, dict):
            errors.append(f"campaigns[{index}] must be an object")
            continue
        campaign_id = campaign.get("campaignId")
        if not isinstance(campaign_id, str) or not campaign_id:
            errors.append(f"campaigns[{index}].campaignId must be a non-empty string")
            continue
        if campaign_id in campaign_ids:
            errors.append(f"duplicate campaignId: {campaign_id}")
        campaign_ids.add(campaign_id)
        selected_groups = _string_list(campaign.get("coverageGroupIds"))
        if not selected_groups:
            errors.append(f"campaigns[{index}].coverageGroupIds must be a non-empty string list")
        for group_id in selected_groups:
            if group_id not in group_ids:
                errors.append(f"campaign {campaign_id} references unknown coverage group {group_id}")
            previous = group_campaign_owner.get(group_id)
            if previous is not None:
                errors.append(f"coverage group {group_id} belongs to both {previous} and {campaign_id}")
            group_campaign_owner[group_id] = campaign_id

    for group_id in sorted(group_ids - set(group_campaign_owner)):
        errors.append(f"coverage group {group_id} is not selected by a campaign")

    if isinstance(groups, list):
        for index, group in enumerate(groups):
            if isinstance(group, dict):
                _validate_catalog_group(
                    group,
                    index,
                    authority_ids=authority_ids,
                    campaign_ids=campaign_ids,
                    campaign_owner=group_campaign_owner,
                    repo_root=repo_root,
                    errors=errors,
                )
        _validate_catalog_evidence(
            payload,
            groups=groups,
            authority_ids=authority_ids,
            repo_root=repo_root,
            errors=errors,
        )
    _validate_asset_classifications(
        payload,
        campaign_ids=campaign_ids,
        groups=groups if isinstance(groups, list) else [],
        repo_root=repo_root,
        errors=errors,
    )


def _validate_catalog_group(
    group: dict[str, Any],
    index: int,
    *,
    authority_ids: set[str],
    campaign_ids: set[str],
    campaign_owner: dict[str, str],
    repo_root: Path,
    errors: list[str],
) -> None:
    """Validates one state-machine coverage group in the catalog."""

    prefix = f"coverageGroups[{index}]"
    group_id = group.get("groupId")
    if not isinstance(group_id, str) or not group_id:
        return
    protocol_domain = group.get("protocolDomain")
    if not isinstance(protocol_domain, str) or not protocol_domain:
        errors.append(f"{prefix}.protocolDomain must be a non-empty string")

    selected_authorities = _string_list(group.get("authorityIds"))
    if not selected_authorities:
        errors.append(f"{prefix}.authorityIds must be a non-empty string list")
    for authority_id in selected_authorities:
        if authority_id not in authority_ids:
            errors.append(f"coverage group {group_id} references unknown authority {authority_id}")
        if authority_id == "amule-head":
            errors.append(f"coverage group {group_id} cannot use analysis-only amule-head as parity authority")

    selected_campaigns = _string_list(group.get("campaignIds"))
    expected_campaign = campaign_owner.get(group_id)
    if len(selected_campaigns) != 1 or selected_campaigns[0] not in campaign_ids:
        errors.append(f"{prefix}.campaignIds must select one declared campaign")
    elif expected_campaign is not None and selected_campaigns[0] != expected_campaign:
        errors.append(
            f"coverage group {group_id} declares campaign {selected_campaigns[0]} but is owned by {expected_campaign}"
        )

    state_model = group.get("stateModel")
    if not isinstance(state_model, dict):
        errors.append(f"{prefix}.stateModel must be an object")
    else:
        for field in ("start", "stimulus", "expected"):
            if not isinstance(state_model.get(field), str) or not state_model[field]:
                errors.append(f"{prefix}.stateModel.{field} must be a non-empty string")

    layers = _string_list(group.get("requiredEvidenceLayers"))
    unknown_layers = set(layers) - set(CATALOG_EVIDENCE_LAYERS)
    if unknown_layers:
        errors.append(f"coverage group {group_id} has unknown evidence layers: {sorted(unknown_layers)}")
    for required in ("codec-transcript", "deterministic-state-machine"):
        if required not in layers:
            errors.append(f"coverage group {group_id} must require {required} evidence")
    if "public-discovery" in layers:
        errors.append(f"coverage group {group_id} cannot require public-discovery as parity evidence")

    _validate_repo_runner(group.get("deterministicRunner"), f"{prefix}.deterministicRunner", repo_root, errors, required=True)
    _validate_repo_runner(group.get("publicDiscoveryRunner"), f"{prefix}.publicDiscoveryRunner", repo_root, errors, required=False)

    if "latestEvidence" in group:
        errors.append(f"{prefix}.latestEvidence is obsolete; register top-level per-ID coverageEvidence")


def _validate_catalog_evidence(
    payload: dict[str, Any],
    *,
    groups: list[Any],
    authority_ids: set[str],
    repo_root: Path,
    errors: list[str],
) -> None:
    """Validates immutable receipts and their per-coverage-ID assessments."""

    group_by_coverage_id: dict[str, dict[str, Any]] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        for coverage_id in _string_list(group.get("coverageIds")):
            group_by_coverage_id[coverage_id] = group

    receipts = payload.get("evidenceReceipts")
    if not isinstance(receipts, list):
        errors.append("evidenceReceipts must be a list")
        receipts = []
    receipt_by_id: dict[str, dict[str, Any]] = {}
    receipt_subject_ids: dict[str, set[str]] = {}
    for index, receipt in enumerate(receipts):
        prefix = f"evidenceReceipts[{index}]"
        if not isinstance(receipt, dict):
            errors.append(f"{prefix} must be an object")
            continue
        receipt_id = receipt.get("receiptId")
        if not isinstance(receipt_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9.-]*", receipt_id) is None:
            errors.append(f"{prefix}.receiptId must be a lowercase stable identifier")
            continue
        if receipt_id in receipt_by_id:
            errors.append(f"duplicate evidence receipt: {receipt_id}")
        receipt_by_id[receipt_id] = receipt
        receipt_subject_ids[receipt_id] = _validate_evidence_receipt(
            receipt,
            prefix=prefix,
            authority_ids=authority_ids,
            repo_root=repo_root,
            errors=errors,
        )

    evidence = payload.get("coverageEvidence")
    if not isinstance(evidence, list):
        errors.append("coverageEvidence must be a list")
        evidence = []
    observed_coverage_ids: set[str] = set()
    referenced_receipt_ids: set[str] = set()
    registered_receipt_claims: dict[str, set[str]] = defaultdict(set)
    previous_coverage_id: str | None = None
    for index, row in enumerate(evidence):
        prefix = f"coverageEvidence[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{prefix} must be an object")
            continue
        coverage_id = row.get("coverageId")
        if not isinstance(coverage_id, str) or not coverage_id:
            errors.append(f"{prefix}.coverageId must be a non-empty string")
            continue
        if previous_coverage_id is not None and coverage_id <= previous_coverage_id:
            errors.append("coverageEvidence must be sorted by unique coverageId")
        previous_coverage_id = coverage_id
        if coverage_id in observed_coverage_ids:
            errors.append(f"duplicate coverage evidence: {coverage_id}")
        observed_coverage_ids.add(coverage_id)
        group = group_by_coverage_id.get(coverage_id)
        if group is None:
            errors.append(f"{prefix}.coverageId references unknown coverage ID {coverage_id}")
            continue

        verdict = row.get("verdict")
        if verdict not in CATALOG_VERDICTS:
            errors.append(f"{prefix}.verdict is unsupported")
        elif verdict == "evidence-incomplete":
            errors.append(f"{prefix}.verdict cannot be evidence-incomplete; absence represents missing evidence")
        if not isinstance(row.get("reason"), str) or not row["reason"]:
            errors.append(f"{prefix}.reason must be a non-empty string")

        expected_layers = _string_list(group.get("requiredEvidenceLayers"))
        if row.get("evidenceLayers") != expected_layers:
            errors.append(f"{prefix}.evidenceLayers must equal the owning coverage group's required layers")

        receipt_ids = _string_list(row.get("receiptIds"))
        if not receipt_ids:
            errors.append(f"{prefix}.receiptIds must be a non-empty string list")
        elif receipt_ids != sorted(set(receipt_ids)):
            errors.append(f"{prefix}.receiptIds must be sorted and unique")
        expected_runner = group.get("deterministicRunner")
        selected_authorities = set(_string_list(group.get("authorityIds")))
        for receipt_id in receipt_ids:
            referenced_receipt_ids.add(receipt_id)
            receipt = receipt_by_id.get(receipt_id)
            if receipt is None:
                errors.append(f"{prefix}.receiptIds references unknown receipt {receipt_id}")
                continue
            if receipt.get("runnerPath") != expected_runner:
                errors.append(f"{prefix} receipt {receipt_id} was produced by a different runner")
            if coverage_id not in _string_list(receipt.get("coverageIds")):
                errors.append(f"{prefix} receipt {receipt_id} does not claim {coverage_id}")
            else:
                registered_receipt_claims[receipt_id].add(coverage_id)
            if row.get("evidenceLayers") != receipt.get("evidenceLayers"):
                errors.append(f"{prefix} evidence layers differ from receipt {receipt_id}")
            subject_ids = receipt_subject_ids.get(receipt_id, set())
            if "rust-product" not in subject_ids:
                errors.append(f"{prefix} receipt {receipt_id} must include rust-product")
            if "local-cross-client" in expected_layers:
                executable_oracles = selected_authorities - {"stock-source"}
                if not subject_ids.intersection(executable_oracles):
                    errors.append(
                        f"{prefix} receipt {receipt_id} must include one selected executable oracle"
                    )

    unused_receipts = set(receipt_by_id) - referenced_receipt_ids
    if unused_receipts:
        errors.append(f"evidenceReceipts contains unreferenced receipts: {sorted(unused_receipts)}")
    for receipt_id, receipt in receipt_by_id.items():
        unregistered_claims = set(_string_list(receipt.get("coverageIds"))) - registered_receipt_claims[receipt_id]
        if unregistered_claims:
            errors.append(
                f"evidence receipt {receipt_id} has unregistered coverage claims: {sorted(unregistered_claims)}"
            )


def _validate_evidence_receipt(
    receipt: dict[str, Any],
    *,
    prefix: str,
    authority_ids: set[str],
    repo_root: Path,
    errors: list[str],
) -> set[str]:
    """Validates one compact immutable receipt and returns its subjects."""

    locator = receipt.get("artifactLocator")
    if not isinstance(locator, str) or not locator.startswith("output-root:"):
        errors.append(f"{prefix}.artifactLocator must use output-root:<relative-path>")
    else:
        relative = locator.removeprefix("output-root:")
        if not relative or relative.startswith("/") or "\\" in relative or ".." in relative.split("/"):
            errors.append(f"{prefix}.artifactLocator must be a normalized output-root-relative path")
        if "/latest/" in f"/{relative}/":
            errors.append(f"{prefix}.artifactLocator must identify an immutable timestamped artifact")

    artifact_sha256 = receipt.get("artifactSha256")
    if not isinstance(artifact_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None:
        errors.append(f"{prefix}.artifactSha256 must be a lowercase SHA-256")
    _validate_repo_runner(receipt.get("runnerPath"), f"{prefix}.runnerPath", repo_root, errors, required=True)
    runner_revision = receipt.get("runnerRevision")
    if not isinstance(runner_revision, str) or re.fullmatch(r"[0-9a-f]{40}", runner_revision) is None:
        errors.append(f"{prefix}.runnerRevision must be a lowercase git revision")
    if not isinstance(receipt.get("profileAuthority"), str) or not receipt["profileAuthority"]:
        errors.append(f"{prefix}.profileAuthority must be a non-empty string")

    coverage_ids = _string_list(receipt.get("coverageIds"))
    if not coverage_ids:
        errors.append(f"{prefix}.coverageIds must be a non-empty string list")
    elif coverage_ids != sorted(set(coverage_ids)):
        errors.append(f"{prefix}.coverageIds must be sorted and unique")
    unknown_coverage_ids = set(coverage_ids) - REQUIRED_STOCK_COVERAGE_IDS
    if unknown_coverage_ids:
        errors.append(f"{prefix}.coverageIds contains unknown IDs: {sorted(unknown_coverage_ids)}")
    evidence_layers = _string_list(receipt.get("evidenceLayers"))
    if not evidence_layers:
        errors.append(f"{prefix}.evidenceLayers must be a non-empty string list")
    unknown_layers = set(evidence_layers) - set(CATALOG_EVIDENCE_LAYERS)
    if unknown_layers:
        errors.append(f"{prefix}.evidenceLayers contains unknown layers: {sorted(unknown_layers)}")
    elif evidence_layers != sorted(set(evidence_layers), key=CATALOG_EVIDENCE_LAYERS.index):
        errors.append(f"{prefix}.evidenceLayers must be unique and use canonical order")

    subjects = receipt.get("subjects")
    subject_ids: set[str] = set()
    if not isinstance(subjects, list) or not subjects:
        errors.append(f"{prefix}.subjects must be a non-empty list")
        return subject_ids
    for subject_index, subject in enumerate(subjects):
        subject_prefix = f"{prefix}.subjects[{subject_index}]"
        if not isinstance(subject, dict):
            errors.append(f"{subject_prefix} must be an object")
            continue
        subject_id = subject.get("authorityId")
        if subject_id not in authority_ids:
            errors.append(f"{subject_prefix}.authorityId must reference a declared authority")
        elif subject_id in subject_ids:
            errors.append(f"{subject_prefix}.authorityId is duplicated")
        else:
            subject_ids.add(subject_id)
        source_revision = subject.get("sourceRevision")
        if not isinstance(source_revision, str) or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
            errors.append(f"{subject_prefix}.sourceRevision must be a lowercase git revision")
        executable_sha256 = subject.get("executableSha256")
        if not isinstance(executable_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", executable_sha256) is None:
            errors.append(f"{subject_prefix}.executableSha256 must be a lowercase SHA-256")
    return subject_ids


def _validate_asset_classifications(
    payload: dict[str, Any],
    *,
    campaign_ids: set[str],
    groups: list[Any],
    repo_root: Path,
    errors: list[str],
) -> None:
    """Validates the catalog's explicit active-test ownership decisions."""

    assets = payload.get("assetClassifications")
    if not isinstance(assets, list) or not assets:
        errors.append("assetClassifications must be a non-empty list")
        return
    assets_by_path: dict[str, dict[str, Any]] = {}
    for index, asset in enumerate(assets):
        prefix = f"assetClassifications[{index}]"
        if not isinstance(asset, dict):
            errors.append(f"{prefix} must be an object")
            continue
        relative_path = asset.get("path")
        classification = asset.get("classification")
        selected_campaigns = _string_list(asset.get("campaignIds"))
        reason = asset.get("reason")
        if not isinstance(relative_path, str) or not relative_path:
            errors.append(f"{prefix}.path must be a non-empty string")
            continue
        if relative_path in assets_by_path:
            errors.append(f"duplicate asset classification: {relative_path}")
        assets_by_path[relative_path] = asset
        _validate_repo_runner(relative_path, f"{prefix}.path", repo_root, errors, required=True)
        if classification not in CATALOG_ASSET_CLASSIFICATIONS:
            errors.append(f"{prefix}.classification is unsupported")
        if not isinstance(reason, str) or not reason:
            errors.append(f"{prefix}.reason must be a non-empty string")
        unknown_campaigns = set(selected_campaigns) - campaign_ids
        if unknown_campaigns:
            errors.append(f"{prefix}.campaignIds contains unknown campaigns: {sorted(unknown_campaigns)}")
        if classification == "canonical" and not selected_campaigns:
            errors.append(f"{prefix}.campaignIds must not be empty for a canonical asset")
        if classification in {"duplicate", "product-only", "historical"} and selected_campaigns:
            errors.append(f"{prefix}.campaignIds must be empty for classification {classification}")
        replacement = asset.get("replacementPath")
        if classification == "duplicate":
            if not isinstance(replacement, str) or not replacement or replacement == relative_path:
                errors.append(f"{prefix}.replacementPath must identify a different asset")
        elif replacement is not None:
            errors.append(f"{prefix}.replacementPath is valid only for duplicate assets")

    for relative_path, asset in assets_by_path.items():
        replacement = asset.get("replacementPath")
        if isinstance(replacement, str) and replacement not in assets_by_path:
            errors.append(f"duplicate asset {relative_path} references unclassified replacement {replacement}")

    canonical_campaigns = {
        campaign_id
        for asset in assets_by_path.values()
        if asset.get("classification") == "canonical"
        for campaign_id in _string_list(asset.get("campaignIds"))
    }
    for campaign_id in sorted(campaign_ids - canonical_campaigns):
        errors.append(f"campaign {campaign_id} has no canonical test asset")

    for group in groups:
        if not isinstance(group, dict):
            continue
        group_id = str(group.get("groupId") or "")
        deterministic_runner = group.get("deterministicRunner")
        deterministic_asset = assets_by_path.get(deterministic_runner) if isinstance(deterministic_runner, str) else None
        if deterministic_asset is None:
            errors.append(f"coverage group {group_id} deterministic runner is not classified")
        elif deterministic_asset.get("classification") != "canonical":
            errors.append(f"coverage group {group_id} deterministic runner must be canonical")
        discovery_runner = group.get("publicDiscoveryRunner")
        if isinstance(discovery_runner, str):
            discovery_asset = assets_by_path.get(discovery_runner)
            if discovery_asset is None:
                errors.append(f"coverage group {group_id} public discovery runner is not classified")
            elif discovery_asset.get("classification") != "support":
                errors.append(f"coverage group {group_id} public discovery runner must be support")


def _validate_repo_runner(
    value: Any,
    field: str,
    repo_root: Path,
    errors: list[str],
    *,
    required: bool,
) -> None:
    if value is None and not required:
        return
    if not isinstance(value, str) or not value:
        errors.append(f"{field} must be a non-empty repository-relative path" if required else f"{field} must be null or a path")
        return
    path = (repo_root / value).resolve()
    if repo_root not in path.parents or not path.is_file():
        errors.append(f"{field} does not resolve to a tracked file: {value}")


def _validate_authority_checkout(
    workspace_root: Path,
    authority_id: str,
    relative_path: str,
    revision: Any,
    errors: list[str],
) -> None:
    root = (workspace_root / relative_path).resolve()
    if workspace_root not in root.parents or not root.is_dir():
        errors.append(f"authority {authority_id} path is missing: {root}")
        return
    if revision is None:
        return
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    observed = completed.stdout.strip() if completed.returncode == 0 else "unavailable"
    if observed != revision:
        errors.append(f"authority {authority_id} revision drift: expected {revision}, got {observed}")


def _require_exact_string_list(
    value: dict[str, Any],
    field: str,
    expected: tuple[str, ...],
    prefix: str,
    errors: list[str],
) -> None:
    observed = value.get(field)
    if observed != list(expected):
        errors.append(f"{prefix}.{field} must equal {list(expected)}")


def _validate_scenarios(scenarios: list[Any], errors: list[str]) -> set[str]:
    scenario_ids: set[str] = set()
    for index, value in enumerate(scenarios):
        if not isinstance(value, dict):
            errors.append(f"scenarios[{index}] must be an object")
            continue
        scenario_id = value.get("scenarioId")
        protocol = value.get("protocol")
        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append(f"scenarios[{index}].scenarioId must be a non-empty string")
            continue
        if scenario_id in scenario_ids:
            errors.append(f"duplicate scenarioId: {scenario_id}")
        scenario_ids.add(scenario_id)
        if protocol not in {"ed2k", "kad2", "mixed"}:
            errors.append(f"scenarios[{index}].protocol must be ed2k, kad2, or mixed")
    return scenario_ids


def _validate_records(records: list[Any], scenario_ids: set[str], errors: list[str]) -> None:
    previous_key: tuple[str, ...] | None = None
    seen_required = {"ed2k", "kad2"}
    observed_protocols: set[str] = set()
    for index, value in enumerate(records):
        if not isinstance(value, dict):
            errors.append(f"records[{index}] must be an object")
            continue
        scenario_id = value.get("scenarioId")
        if scenario_id not in scenario_ids:
            errors.append(f"records[{index}].scenarioId must reference a declared scenario")
        protocol = value.get("protocol")
        if protocol not in {"ed2k", "kad2", "server_udp", "client_udp"}:
            errors.append(f"records[{index}].protocol has unsupported value")
        else:
            observed_protocols.add(protocol)
        record_type = value.get("recordType")
        if record_type not in {"wire-vector", "udp-packet", "ed2k-state", "state-sequence"}:
            errors.append(f"records[{index}].recordType has unsupported value")
        digest = value.get("payloadDigest")
        if digest is not None and (not isinstance(digest, str) or DIGEST_RE.match(digest) is None):
            errors.append(f"records[{index}].payloadDigest is malformed")
        key = _record_sort_key(value)
        if previous_key is not None and key < previous_key:
            errors.append("records must be sorted by scenarioId, recordType, transport, direction, opcodeName, stateId")
            break
        previous_key = key
    missing_protocols = seen_required - observed_protocols
    for protocol in sorted(missing_protocols):
        errors.append(f"records must include at least one {protocol} scenario record")


def _validate_stock_oracle(
    payload: dict[str, Any],
    records: list[Any],
    errors: list[str],
    *,
    workspace_root: Path | None,
) -> None:
    """Validates the source-anchored Phase-4 stock oracle coverage contract."""

    oracle = payload.get("stockAuthority")
    groups = payload.get("coverageGroups")
    if oracle is None and groups is None:
        return
    if not isinstance(oracle, dict):
        errors.append("stockAuthority must be an object")
        return
    if not isinstance(groups, list) or not groups:
        errors.append("coverageGroups must be a non-empty list")
        return

    source_path = oracle.get("sourcePath")
    source_revision = oracle.get("sourceRevision")
    if not isinstance(source_path, str) or not source_path:
        errors.append("stockAuthority.sourcePath must be a non-empty string")
    if not isinstance(source_revision, str) or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        errors.append("stockAuthority.sourceRevision must be a lowercase 40-character git revision")
    if oracle.get("requiredCoverageCount") != len(REQUIRED_STOCK_COVERAGE_IDS):
        errors.append(
            "stockAuthority.requiredCoverageCount must equal "
            f"{len(REQUIRED_STOCK_COVERAGE_IDS)}"
        )

    records_by_id: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(records):
        if not isinstance(value, dict) or "recordId" not in value:
            continue
        record_id = value.get("recordId")
        if not isinstance(record_id, str) or not record_id:
            errors.append(f"records[{index}].recordId must be a non-empty string")
            continue
        if record_id in records_by_id:
            errors.append(f"duplicate recordId: {record_id}")
        records_by_id[record_id] = value
        _validate_stock_record(value, index, errors)

    observed_coverage: set[str] = set()
    coverage_owner: dict[str, str] = {}
    observed_group_ids: set[str] = set()
    source_anchors: list[tuple[str, list[str], str]] = []
    rust_proofs: list[tuple[str, str, str]] = []
    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            errors.append(f"coverageGroups[{index}] must be an object")
            continue
        group_id = group.get("groupId")
        if not isinstance(group_id, str) or not group_id:
            errors.append(f"coverageGroups[{index}].groupId must be a non-empty string")
            continue
        if group_id in observed_group_ids:
            errors.append(f"duplicate coverage group: {group_id}")
        observed_group_ids.add(group_id)

        coverage_ids = _string_list(group.get("coverageIds"))
        record_ids = _string_list(group.get("recordIds"))
        if not coverage_ids:
            errors.append(f"coverageGroups[{index}].coverageIds must be a non-empty string list")
        if not record_ids:
            errors.append(f"coverageGroups[{index}].recordIds must be a non-empty string list")
        for coverage_id in coverage_ids:
            previous_owner = coverage_owner.get(coverage_id)
            if previous_owner is not None:
                errors.append(
                    f"stock coverage ID {coverage_id} is owned by both {previous_owner} and {group_id}"
                )
            coverage_owner[coverage_id] = group_id
            observed_coverage.add(coverage_id)

        record_coverage: set[str] = set()
        for record_id in record_ids:
            record = records_by_id.get(record_id)
            if record is None:
                errors.append(f"coverage group {group_id} references missing recordId {record_id}")
                continue
            record_coverage.update(_string_list(record.get("coverageIds")))
        missing_from_records = set(coverage_ids) - record_coverage
        if missing_from_records:
            errors.append(
                f"coverage group {group_id} has IDs absent from its records: {sorted(missing_from_records)}"
            )

        anchors = group.get("sourceAnchors")
        if not isinstance(anchors, list) or not anchors:
            errors.append(f"coverageGroups[{index}].sourceAnchors must be a non-empty list")
        else:
            for anchor_index, anchor in enumerate(anchors):
                if not isinstance(anchor, dict):
                    errors.append(f"coverageGroups[{index}].sourceAnchors[{anchor_index}] must be an object")
                    continue
                path = anchor.get("path")
                contains = _string_list(anchor.get("contains"))
                if not isinstance(path, str) or not path or not contains:
                    errors.append(
                        f"coverageGroups[{index}].sourceAnchors[{anchor_index}] requires path and contains"
                    )
                    continue
                source_anchors.append((path, contains, group_id))

        proofs = group.get("rustProofs")
        if not isinstance(proofs, list) or not proofs:
            errors.append(f"coverageGroups[{index}].rustProofs must be a non-empty list")
        else:
            for proof_index, proof in enumerate(proofs):
                if not isinstance(proof, dict):
                    errors.append(f"coverageGroups[{index}].rustProofs[{proof_index}] must be an object")
                    continue
                path = proof.get("path")
                selector = proof.get("selector")
                if not isinstance(path, str) or not path or not isinstance(selector, str) or not selector:
                    errors.append(f"coverageGroups[{index}].rustProofs[{proof_index}] requires path and selector")
                    continue
                rust_proofs.append((path, selector, group_id))

    missing = REQUIRED_STOCK_COVERAGE_IDS - observed_coverage
    unexpected = observed_coverage - REQUIRED_STOCK_COVERAGE_IDS
    if missing:
        errors.append(f"stock oracle missing required coverage IDs: {sorted(missing)}")
    if unexpected:
        errors.append(f"stock oracle has unknown coverage IDs: {sorted(unexpected)}")

    if workspace_root is not None and isinstance(source_path, str) and isinstance(source_revision, str):
        _validate_stock_workspace_anchors(
            workspace_root.resolve(),
            source_path,
            source_revision,
            source_anchors,
            rust_proofs,
            errors,
        )


def _validate_stock_record(record: dict[str, Any], index: int, errors: list[str]) -> None:
    coverage_ids = _string_list(record.get("coverageIds"))
    if not coverage_ids:
        errors.append(f"records[{index}].coverageIds must be a non-empty string list")
    unknown = set(coverage_ids) - REQUIRED_STOCK_COVERAGE_IDS
    if unknown:
        errors.append(f"records[{index}] has unknown stock coverage IDs: {sorted(unknown)}")

    fixture = record.get("fixtureBase64")
    state = record.get("oracleState")
    if fixture is None and state is None:
        errors.append(f"records[{index}] stock record requires fixtureBase64 or oracleState")
        return
    if fixture is not None:
        if not isinstance(fixture, str):
            errors.append(f"records[{index}].fixtureBase64 must be a string")
            return
        try:
            decoded = base64.b64decode(fixture, validate=True)
        except (ValueError, binascii.Error):
            errors.append(f"records[{index}].fixtureBase64 is malformed")
            return
        if record.get("fixtureLength") != len(decoded):
            errors.append(f"records[{index}].fixtureLength does not match fixtureBase64")
        expected = "sha256:" + hashlib.sha256(decoded).hexdigest()
        if record.get("payloadDigest") != expected:
            errors.append(f"records[{index}].payloadDigest does not match fixtureBase64")
        _validate_stock_ed2k_vector(record, index, decoded, coverage_ids, errors)
    if state is not None:
        canonical = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
        if record.get("stateDigest") != expected:
            errors.append(f"records[{index}].stateDigest does not match oracleState")


def _validate_stock_ed2k_vector(
    record: dict[str, Any],
    index: int,
    decoded: bytes,
    coverage_ids: list[str],
    errors: list[str],
) -> None:
    contract_ids = sorted(set(coverage_ids) & STOCK_ED2K_VECTOR_CONTRACTS.keys())
    if not contract_ids:
        return
    if len(coverage_ids) != 1 or len(contract_ids) != 1:
        errors.append(f"records[{index}] transport-exact stock vector must own exactly one coverage ID")
        return

    coverage_id = contract_ids[0]
    contract = STOCK_ED2K_VECTOR_CONTRACTS[coverage_id]
    prefix = f"records[{index}] ({coverage_id})"
    for field in ("direction", "opcodeName", "transport"):
        if record.get(field) != contract[field]:
            errors.append(f"{prefix}.{field} must be {contract[field]}")
    if record.get("fixtureEncoding") != contract["encoding"]:
        errors.append(f"{prefix}.fixtureEncoding must be {contract['encoding']}")

    expected_opcode = int(contract["opcode"])
    if record.get("opcode") != f"0x{expected_opcode:02X}":
        errors.append(f"{prefix}.opcode must be 0x{expected_opcode:02X}")

    if contract["encoding"] == "ed2k-frame":
        if len(decoded) < 6:
            errors.append(f"{prefix} ED2K frame is shorter than its header and opcode")
            return
        if decoded[0] != 0xE3:
            errors.append(f"{prefix} ED2K frame must use protocol marker 0xE3")
        declared_length = int.from_bytes(decoded[1:5], "little")
        if declared_length != len(decoded) - 5:
            errors.append(
                f"{prefix} ED2K frame declares {declared_length} bytes but contains {len(decoded) - 5}"
            )
        actual_opcode = decoded[5]
    else:
        if len(decoded) < 2:
            errors.append(f"{prefix} server UDP datagram is shorter than its marker and opcode")
            return
        if decoded[0] != 0xE3:
            errors.append(f"{prefix} server UDP datagram must use protocol marker 0xE3")
        actual_opcode = decoded[1]

    if actual_opcode != expected_opcode:
        errors.append(
            f"{prefix} encoded opcode is 0x{actual_opcode:02X}, expected 0x{expected_opcode:02X}"
        )


def _validate_stock_workspace_anchors(
    workspace_root: Path,
    source_path: str,
    source_revision: str,
    source_anchors: list[tuple[str, list[str], str]],
    rust_proofs: list[tuple[str, str, str]],
    errors: list[str],
) -> None:
    baseline_root = (workspace_root / source_path).resolve()
    rust_root = (workspace_root / "repos" / "emulebb-rust").resolve()
    if not baseline_root.is_dir():
        errors.append(f"stock oracle baseline path is missing: {baseline_root}")
        return
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=baseline_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if revision.returncode != 0 or revision.stdout.strip() != source_revision:
        errors.append(
            "stock authority revision drift: "
            f"expected {source_revision}, got {revision.stdout.strip() or 'unavailable'}"
        )

    anchored_paths = sorted({relative_path for relative_path, _, _ in source_anchors})
    source_status = subprocess.run(
        ["git", "status", "--porcelain", "--", *anchored_paths],
        cwd=baseline_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if source_status.returncode != 0:
        errors.append("stock source anchor cleanliness could not be verified")
    elif source_status.stdout.strip():
        errors.append(f"stock source anchors are dirty: {source_status.stdout.strip()}")

    for relative_path, tokens, group_id in source_anchors:
        path = (baseline_root / relative_path).resolve()
        if baseline_root not in path.parents or not path.is_file():
            errors.append(f"stock source anchor missing for {group_id}: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in tokens:
            if token not in text:
                errors.append(f"stock source anchor drift for {group_id}: {relative_path} lacks {token!r}")

    for relative_path, selector, group_id in rust_proofs:
        path = (rust_root / relative_path).resolve()
        if rust_root not in path.parents or not path.is_file():
            errors.append(f"Rust proof path missing for {group_id}: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if selector not in text:
            errors.append(f"Rust proof selector drift for {group_id}: {relative_path} lacks {selector!r}")


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        return []
    return value


def _validate_no_sensitive_payload(value: Any, errors: list[str], path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in SENSITIVE_FIELD_NAMES:
                errors.append(f"{child_path} is not allowed in tracked protocol goldens")
            _validate_no_sensitive_payload(child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_sensitive_payload(child, errors, f"{path}[{index}]")
    elif isinstance(value, str) and IPV4_RE.search(value):
        errors.append(f"{path} contains an unredacted IPv4 address")


def _record_sort_key(record: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(record.get("scenarioId") or ""),
        str(record.get("recordType") or ""),
        str(record.get("transport") or ""),
        str(record.get("direction") or ""),
        str(record.get("opcodeName") or ""),
        str(record.get("flow") or ""),
        str(record.get("stateId") or ""),
        str(record.get("sequence") or ""),
    )


def _stable_record_key(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _normalize_opcode(value: Any) -> str:
    if value is None:
        return "NONE"
    if isinstance(value, int):
        return f"0x{value:02X}"
    text = str(value).strip()
    if not text or text.lower() == "null":
        return "NONE"
    if text.lower().startswith("0x"):
        return f"0x{int(text, 16):02X}"
    return f"0x{int(text):02X}"


def _clean_token(value: Any) -> str:
    text = str(value).strip()
    return text if text else "unknown"


def _read_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _first_hex_value(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and HEX_RE.match(value):
            return value
    return ""


def _sha256_hex_digest(hex_value: str) -> str:
    if not hex_value:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    if len(hex_value) % 2 != 0:
        raise ValueError("hex payload must have an even number of characters")
    return "sha256:" + hashlib.sha256(bytes.fromhex(hex_value)).hexdigest()


def _infer_udp_transport_mode(record: dict[str, Any]) -> str:
    wire_hex = str(record.get("wire_hex") or "")
    if len(wire_hex) < 2:
        return "unknown"
    first_byte = int(wire_hex[:2], 16)
    if first_byte in {0xE3, 0xE4, 0xE5, 0xA3, 0xC5, 0xD4}:
        return "plaintext"
    if (first_byte & 0x03) == 0x02:
        return "receiver_verify_key"
    return "node_id"


if __name__ == "__main__":
    raise SystemExit(run_validate_cli(sys.argv[1:]))
