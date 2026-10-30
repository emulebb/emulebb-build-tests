"""Bounded exact diagnostic proof for one long-running transfer capture."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Iterable

from . import diag_event_runs
from .diag_event_schema import DIAG_EVENT_SCHEMA

SCHEMA = "emulebb-build-tests.transfer-coverage-evidence.v1"

PROOF_SLOTS = (
    "download_attempt_started",
    "server_source_request",
    "server_source_response",
    "kad_file_lookup_started",
    "kad_file_lookup_complete",
    "source_engaged",
    "queue_rank",
    "queued_detached_udp_reask",
    "download_payload_accepted",
    "client_udp_attempt",
    "client_udp_terminal",
    "reask_sent",
)
TARGET_SLOTS = ("client_udp_attempt", "client_udp_terminal")
PROTOCOL_CHAIN_SLOTS = (
    "download_attempt_started",
    "source_engaged",
    "queue_rank",
    "queued_detached_udp_reask",
    "client_udp_attempt",
    "client_udp_terminal",
    "reask_sent",
)

_SOURCE_REQUEST_OPCODES = (
    "OP_GETSOURCES",
    "OP_GETSOURCES2",
    "OP_GLOBGETSOURCES",
    "OP_GLOBGETSOURCES2",
    "OP_REQUESTSOURCES",
    "OP_REQUESTSOURCES2",
)
_SOURCE_RESPONSE_OPCODES = (
    "OP_FOUNDSOURCES",
    "OP_GLOBFOUNDSOURCES",
    "OP_ANSWERSOURCES",
    "OP_ANSWERSOURCES2",
)
_QUEUE_OPCODES = frozenset({"OP_QUEUERANK", "OP_QUEUERANKING"})
_CLIENT_UDP_REQUEST_OPCODES = frozenset(
    {"OP_REASKFILEPING", "OP_REASKCALLBACKUDP"}
)
_CLIENT_UDP_REQUEST_ROLES = frozenset(
    {"reask_request", "buddy_relay_request"}
)


class TransferCoverageEvidenceError(ValueError):
    """Raised when compact transfer proof cannot be retained losslessly."""


def new_evidence(
    *,
    client: str,
    process_id: int,
    run_id: str,
    fixture_hashes: Iterable[str],
    observed_utc: str,
) -> dict[str, Any]:
    """Creates one empty exact-run transfer proof artifact."""

    normalized_hashes = sorted({_file_hash(value) for value in fixture_hashes})
    if client not in {"rust", "mfc"}:
        raise TransferCoverageEvidenceError(f"unsupported client: {client!r}")
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise TransferCoverageEvidenceError("process_id must be a positive integer")
    if not isinstance(run_id, str) or not run_id:
        raise TransferCoverageEvidenceError("run_id must be a non-empty string")
    if not isinstance(observed_utc, str) or not observed_utc:
        raise TransferCoverageEvidenceError("observed_utc must be a non-empty string")
    evidence = {
        "schema": SCHEMA,
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "fixtureHashes": normalized_hashes,
        "createdUtc": observed_utc,
        "updatedUtc": observed_utc,
        "source": {
            "closedSegmentsScanned": 0,
            "lastClosedSegmentId": None,
        },
        "proof": {},
        "coverage": {slot: False for slot in PROOF_SLOTS},
        "target": {
            "name": "client-udp-request-lifecycle",
            "requiredSlots": list(TARGET_SLOTS),
            "complete": False,
        },
        "protocolChainComplete": False,
        "complete": False,
    }
    return _validated_copy(evidence)


def advance_evidence(
    evidence: dict[str, Any],
    processed_segments: Iterable[dict[str, Any]],
    *,
    observed_utc: str,
) -> dict[str, Any]:
    """Consumes newly closed scanner segments before the source ring can evict them."""

    updated = _validated_copy(evidence)
    for metadata in processed_segments:
        segment = _segment_snapshot(metadata)
        _require_snapshot_metadata(segment, metadata)
        segment_provenance = _segment_provenance(metadata)
        for record in segment.records:
            _require_record_identity(updated, record)
            slot = _proof_slot(record, fixture_hashes=updated["fixtureHashes"])
            if slot is None:
                continue
            _retain_record(updated["proof"], slot, record, segment_provenance)
        source = updated["source"]
        source["closedSegmentsScanned"] += 1
        source["lastClosedSegmentId"] = metadata["segmentId"]
    updated["updatedUtc"] = observed_utc
    _refresh_coverage(updated)
    return _validated_copy(updated)


def write_evidence(
    path: Path,
    evidence: dict[str, Any],
    *,
    max_bytes: int,
) -> int:
    """Atomically persists a validated proof without truncating its exact records."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise TransferCoverageEvidenceError("max_bytes must be a positive integer")
    validated = _validated_copy(evidence)
    payload = (json.dumps(validated, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > max_bytes:
        raise TransferCoverageEvidenceError(
            f"transfer coverage evidence exceeds its byte limit: {len(payload)} > {max_bytes}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return len(payload)


def load_evidence(path: Path) -> dict[str, Any]:
    """Loads one strict current-contract transfer proof artifact."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise TransferCoverageEvidenceError(
            f"could not load transfer coverage evidence {path}: {error}"
        ) from error
    return _validated_copy(payload)


def evidence_records(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns retained exact envelopes in process-sequence order."""

    validated = _validated_copy(evidence)
    records = [copy.deepcopy(item["record"]) for item in validated["proof"].values()]
    return sorted(records, key=lambda record: (record["seq"], record["streamSeq"]))


def _retain_record(
    proof: dict[str, Any],
    slot: str,
    record: dict[str, Any],
    segment: dict[str, Any],
) -> None:
    if slot == "client_udp_attempt":
        if "client_udp_terminal" not in proof:
            proof[slot] = {"segment": copy.deepcopy(segment), "record": copy.deepcopy(record)}
        return
    if slot == "client_udp_terminal":
        attempt = proof.get("client_udp_attempt")
        if attempt is None:
            return
        attempt_id = _field(attempt["record"], "sendAttemptId")
        if attempt_id is None or _field(record, "sendAttemptId") != attempt_id:
            return
    proof.setdefault(
        slot,
        {"segment": copy.deepcopy(segment), "record": copy.deepcopy(record)},
    )


def _proof_slot(
    record: dict[str, Any], *, fixture_hashes: Iterable[str]
) -> str | None:
    if not _record_matches_fixture(record, fixture_hashes):
        return None
    family = record.get("family")
    event = record.get("event")
    if family == "sched":
        return {
            "download_attempt_started": "download_attempt_started",
            "source_engaged": "source_engaged",
            "download_payload_accepted": "download_payload_accepted",
            "reask_sent": "reask_sent",
        }.get(event)
    if family == "kad_event" and event == "lookup" and _field(record, "searchKind") == "file":
        milestone = _field(record, "milestone")
        if milestone == "lookup_started":
            return "kad_file_lookup_started"
        if milestone in {"lookup_complete", "lookup_not_dispatched"}:
            return "kad_file_lookup_complete"
    if family in {"ed2k_tcp", "ed2k_server_udp"}:
        opcode_name = str(_field(record, "opcodeName") or "")
        if any(opcode_name.startswith(prefix) for prefix in _SOURCE_REQUEST_OPCODES):
            return "server_source_request"
        if any(opcode_name.startswith(prefix) for prefix in _SOURCE_RESPONSE_OPCODES):
            return "server_source_response"
        if family == "ed2k_tcp" and opcode_name in _QUEUE_OPCODES:
            return "queue_rank"
        if (
            family == "ed2k_tcp"
            and event == "state"
            and _field(record, "phase") == "queued_detached_udp_reask"
        ):
            return "queued_detached_udp_reask"
    if family == "ed2k_client_udp":
        role = _field(record, "role")
        opcode_name = _field(record, "opcodeName")
        if (
            event == "packet"
            and _field(record, "direction") == "send"
            and (
                role in _CLIENT_UDP_REQUEST_ROLES
                or opcode_name in _CLIENT_UDP_REQUEST_OPCODES
            )
        ):
            return "client_udp_attempt"
        if event == "send_outcome" and _field(record, "direction") == "send":
            return "client_udp_terminal"
    return None


def _record_matches_fixture(
    record: dict[str, Any], fixture_hashes: Iterable[str]
) -> bool:
    expected = set(fixture_hashes)
    observed = {
        value.lower()
        for container in (record.get("keys"), record.get("body"))
        if isinstance(container, dict)
        for name, value in container.items()
        if name in {"fileHash", "file_hash"}
        and isinstance(value, str)
        and len(value) == 32
    }
    return not observed or bool(observed & expected)


def _field(record: dict[str, Any], name: str) -> object:
    for container_name in ("body", "keys"):
        container = record.get(container_name)
        if isinstance(container, dict) and name in container:
            return container[name]
    return None


def _segment_snapshot(metadata: dict[str, Any]) -> diag_event_runs.DiagnosticSegmentSnapshot:
    if not isinstance(metadata, dict):
        raise TransferCoverageEvidenceError("processed segment metadata must be an object")
    source = metadata.get("source")
    if not isinstance(source, str) or not source:
        raise TransferCoverageEvidenceError("processed segment source is invalid")
    try:
        return diag_event_runs.load_diag_event_segment_snapshot(Path(source))
    except (OSError, ValueError) as error:
        raise TransferCoverageEvidenceError(
            f"could not reload processed diagnostic segment {source}: {error}"
        ) from error


def _require_snapshot_metadata(
    snapshot: diag_event_runs.DiagnosticSegmentSnapshot,
    metadata: dict[str, Any],
) -> None:
    expected = {
        "fileName": snapshot.path.name,
        "source": str(snapshot.path),
        "bytes": snapshot.byte_count,
        "modifiedNs": snapshot.modified_ns,
        "sha256": snapshot.sha256,
        "recordCount": len(snapshot.records),
    }
    mismatches = {
        name: {"actual": metadata.get(name), "expected": value}
        for name, value in expected.items()
        if metadata.get(name) != value
    }
    if mismatches:
        raise TransferCoverageEvidenceError(
            f"processed diagnostic segment changed after indexing: {mismatches}"
        )


def _segment_provenance(metadata: dict[str, Any]) -> dict[str, Any]:
    fields = ("segmentId", "fileName", "bytes", "modifiedNs", "sha256", "recordCount")
    return {name: metadata[name] for name in fields}


def _require_record_identity(evidence: dict[str, Any], record: dict[str, Any]) -> None:
    expected = (
        DIAG_EVENT_SCHEMA,
        evidence["client"],
        evidence["processId"],
        evidence["runId"],
    )
    actual = (
        record.get("schema"),
        record.get("client"),
        record.get("processId"),
        record.get("runId"),
    )
    if actual != expected:
        raise TransferCoverageEvidenceError(
            f"diagnostic record identity mismatch: {actual!r} != {expected!r}"
        )


def _refresh_coverage(evidence: dict[str, Any]) -> None:
    proof = evidence["proof"]
    coverage = {slot: slot in proof for slot in PROOF_SLOTS}
    target_complete = all(coverage[slot] for slot in TARGET_SLOTS)
    evidence["coverage"] = coverage
    evidence["target"]["complete"] = target_complete
    evidence["protocolChainComplete"] = all(
        coverage[slot] for slot in PROTOCOL_CHAIN_SLOTS
    )
    evidence["complete"] = target_complete


def _validated_copy(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise TransferCoverageEvidenceError("transfer coverage evidence schema is invalid")
    expected_fields = {
        "schema",
        "client",
        "processId",
        "runId",
        "fixtureHashes",
        "createdUtc",
        "updatedUtc",
        "source",
        "proof",
        "coverage",
        "target",
        "protocolChainComplete",
        "complete",
    }
    if set(value) != expected_fields:
        raise TransferCoverageEvidenceError("transfer coverage evidence fields are invalid")
    client = value.get("client")
    process_id = value.get("processId")
    run_id = value.get("runId")
    if client not in {"rust", "mfc"}:
        raise TransferCoverageEvidenceError("transfer coverage evidence client is invalid")
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise TransferCoverageEvidenceError("transfer coverage evidence processId is invalid")
    if not isinstance(run_id, str) or not run_id:
        raise TransferCoverageEvidenceError("transfer coverage evidence runId is invalid")
    hashes = value.get("fixtureHashes")
    if not isinstance(hashes, list) or hashes != sorted(set(hashes)):
        raise TransferCoverageEvidenceError("transfer coverage fixtureHashes are invalid")
    for file_hash in hashes:
        _file_hash(file_hash)
    if any(not isinstance(value.get(name), str) or not value[name] for name in ("createdUtc", "updatedUtc")):
        raise TransferCoverageEvidenceError("transfer coverage timestamps are invalid")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {
        "closedSegmentsScanned",
        "lastClosedSegmentId",
    }:
        raise TransferCoverageEvidenceError("transfer coverage source is invalid")
    scanned = source["closedSegmentsScanned"]
    last_segment = source["lastClosedSegmentId"]
    if isinstance(scanned, bool) or not isinstance(scanned, int) or scanned < 0:
        raise TransferCoverageEvidenceError("closedSegmentsScanned is invalid")
    if last_segment is not None and (
        isinstance(last_segment, bool) or not isinstance(last_segment, int) or last_segment < 0
    ):
        raise TransferCoverageEvidenceError("lastClosedSegmentId is invalid")
    proof = value.get("proof")
    if not isinstance(proof, dict) or not set(proof).issubset(PROOF_SLOTS):
        raise TransferCoverageEvidenceError("transfer coverage proof is invalid")
    for slot, item in proof.items():
        _validate_proof_item(value, slot, item)
    expected_coverage = {slot: slot in proof for slot in PROOF_SLOTS}
    if value.get("coverage") != expected_coverage:
        raise TransferCoverageEvidenceError("transfer coverage flags are inconsistent")
    target = value.get("target")
    target_complete = all(expected_coverage[slot] for slot in TARGET_SLOTS)
    if target != {
        "name": "client-udp-request-lifecycle",
        "requiredSlots": list(TARGET_SLOTS),
        "complete": target_complete,
    }:
        raise TransferCoverageEvidenceError("transfer coverage target is inconsistent")
    chain_complete = all(expected_coverage[slot] for slot in PROTOCOL_CHAIN_SLOTS)
    if value.get("protocolChainComplete") is not chain_complete:
        raise TransferCoverageEvidenceError("protocolChainComplete is inconsistent")
    if value.get("complete") is not target_complete:
        raise TransferCoverageEvidenceError("transfer coverage completion is inconsistent")
    return copy.deepcopy(value)


def _validate_proof_item(
    evidence: dict[str, Any], slot: str, item: object
) -> None:
    if not isinstance(item, dict) or set(item) != {"segment", "record"}:
        raise TransferCoverageEvidenceError(f"transfer coverage proof {slot} is invalid")
    segment = item["segment"]
    record = item["record"]
    if not isinstance(segment, dict) or set(segment) != {
        "segmentId",
        "fileName",
        "bytes",
        "modifiedNs",
        "sha256",
        "recordCount",
    }:
        raise TransferCoverageEvidenceError(f"transfer coverage proof {slot} provenance is invalid")
    if not isinstance(record, dict):
        raise TransferCoverageEvidenceError(f"transfer coverage proof {slot} record is invalid")
    _require_record_identity(evidence, record)
    if record.get("segmentId") != segment.get("segmentId"):
        raise TransferCoverageEvidenceError(f"transfer coverage proof {slot} segment is inconsistent")
    if _proof_slot(record, fixture_hashes=evidence["fixtureHashes"]) != slot:
        raise TransferCoverageEvidenceError(f"transfer coverage proof {slot} classification is invalid")


def _file_hash(value: object) -> str:
    if not isinstance(value, str) or len(value) != 32:
        raise TransferCoverageEvidenceError(f"invalid eD2K file hash: {value!r}")
    normalized = value.lower()
    if any(character not in "0123456789abcdef" for character in normalized):
        raise TransferCoverageEvidenceError(f"invalid eD2K file hash: {value!r}")
    return normalized
