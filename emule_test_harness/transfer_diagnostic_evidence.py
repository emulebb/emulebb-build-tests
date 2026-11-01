"""Causal ``diag_event_v2`` evidence for one deterministic peer transfer."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

SCHEMA = "emulebb-build-tests.deterministic-transfer-diagnostics.v1"
ED2K_HASH_PATTERN = re.compile(r"^[0-9a-f]{32}$")
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
UNCOMPRESSED_PAYLOAD_OPCODES = frozenset({"OP_SENDINGPART", "OP_SENDINGPART_I64"})
COMPRESSED_PAYLOAD_OPCODES = frozenset({"OP_COMPRESSEDPART", "OP_COMPRESSEDPART_I64"})


def normalize_ed2k_hash(value: str) -> str:
    """Returns one canonical lowercase eD2K hash or raises."""

    normalized = value.strip().lower()
    if not ED2K_HASH_PATTERN.fullmatch(normalized):
        raise ValueError(f"Invalid eD2K hash: {value!r}.")
    return normalized


def record_file_hash(record: dict[str, Any]) -> str | None:
    """Returns a record's exact ``keys.fileHash`` when present and valid."""

    keys = record.get("keys")
    if not isinstance(keys, dict):
        return None
    value = keys.get("fileHash")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if ED2K_HASH_PATTERN.fullmatch(normalized) else None


def _sequence(record: dict[str, Any]) -> int:
    for field in ("seq", "streamSeq"):
        value = record.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return -1


def _body(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("body")
    return body if isinstance(body, dict) else {}


def _matches(
    records: Iterable[dict[str, Any]],
    *,
    family: str,
    event: str,
    file_hash: str | None = None,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for record in records:
        if record.get("family") != family or record.get("event") != event:
            continue
        if file_hash is not None and record_file_hash(record) != file_hash:
            continue
        if predicate is not None and not predicate(record):
            continue
        matched.append(record)
    return matched


def _check(
    name: str,
    records: list[dict[str, Any]],
    *,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": name,
        "ok": bool(records),
        "matchingRecordCount": len(records),
        "firstStreamSeq": _sequence(records[0]) if records else None,
        "lastStreamSeq": _sequence(records[-1]) if records else None,
    }
    if detail:
        row.update(detail)
    return row


def _published_hash(record: dict[str, Any], file_hash: str) -> bool:
    hashes = _body(record).get("fileHashes")
    return isinstance(hashes, list) and file_hash in {
        str(item).strip().lower() for item in hashes
    }


def _positive_body_field(record: dict[str, Any], field: str) -> bool:
    value = _body(record).get(field)
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _outcome(record: dict[str, Any], field: str, expected: str) -> bool:
    return str(_body(record).get(field) or "").strip().lower() == expected


def _ordered(checks: dict[str, dict[str, Any]], names: tuple[str, ...]) -> dict[str, Any]:
    positions = [checks[name]["firstStreamSeq"] for name in names]
    complete = all(isinstance(value, int) and value >= 0 for value in positions)
    return {
        "name": " -> ".join(names),
        "ok": complete and positions == sorted(positions),
        "positions": dict(zip(names, positions, strict=True)),
    }


def _packet_frame_key(record: dict[str, Any]) -> tuple[int, int, str] | None:
    keys = record.get("keys")
    body = _body(record)
    if not isinstance(keys, dict):
        return None
    marker = keys.get("protocolMarker", body.get("protocolMarker"))
    opcode = keys.get("opcode", body.get("opcode"))
    clear_frame_hex = body.get("clearFrameHex")
    if (
        not isinstance(marker, int)
        or isinstance(marker, bool)
        or not isinstance(opcode, int)
        or isinstance(opcode, bool)
        or not isinstance(clear_frame_hex, str)
        or not clear_frame_hex
    ):
        return None
    return marker, opcode, clear_frame_hex.lower()


def _packet_records(
    records: Iterable[dict[str, Any]],
    *,
    file_hash: str,
    direction: str,
    outcome: str,
    opcode_names: set[str],
    require_complete_write: bool = False,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for record in _matches(
        records,
        family="ed2k_tcp",
        event="packet",
        file_hash=file_hash,
    ):
        body = _body(record)
        if body.get("direction") != direction or body.get("outcome") != outcome:
            continue
        if body.get("opcodeName") not in opcode_names or _packet_frame_key(record) is None:
            continue
        if require_complete_write:
            attempted = body.get("attemptedLen")
            written = body.get("writtenLen")
            if (
                not isinstance(attempted, int)
                or isinstance(attempted, bool)
                or attempted <= 0
                or written != attempted
            ):
                continue
        selected.append(record)
    return selected


def _paired_packet_check(
    name: str,
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
) -> dict[str, Any]:
    left_frames = Counter(
        key for record in left if (key := _packet_frame_key(record)) is not None
    )
    right_frames = Counter(
        key for record in right if (key := _packet_frame_key(record)) is not None
    )
    matched = left_frames & right_frames
    matched_count = sum(matched.values())
    left_count = sum(left_frames.values())
    right_count = sum(right_frames.values())
    return {
        "name": name,
        "ok": matched_count > 0 and matched == left_frames == right_frames,
        "matchedFrameCount": matched_count,
        "leftFrameCount": left_count,
        "rightFrameCount": right_count,
        "unmatchedLeftFrameCount": left_count - matched_count,
        "unmatchedRightFrameCount": right_count - matched_count,
        "opcodes": sorted(
            {
                str(_body(record).get("opcodeName"))
                for record in (*left, *right)
                if _body(record).get("opcodeName")
            }
        ),
    }


def build_transfer_diagnostic_evidence(
    *,
    file_hash: str,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Builds the mandatory hash-correlated diagnostics gate for Rust <- MFC."""

    normalized_hash = normalize_ed2k_hash(file_hash)
    rust = list(rust_records)
    mfc = list(mfc_records)

    rust_hash_records = [record for record in rust if record_file_hash(record) == normalized_hash]
    mfc_hash_records = [record for record in mfc if record_file_hash(record) == normalized_hash]
    publication = _matches(
        mfc,
        family="sched",
        event="shared_publish_offer_batch",
        predicate=lambda record: _published_hash(record, normalized_hash),
    )
    rust_request_packets = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names={"OP_REQUESTPARTS"},
        require_complete_write=True,
    )
    mfc_request_packets = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names={"OP_REQUESTPARTS"},
    )
    payload_opcodes = {
        "OP_SENDINGPART",
        "OP_COMPRESSEDPART",
        "OP_SENDINGPART_I64",
        "OP_COMPRESSEDPART_I64",
    }
    mfc_payload_packets = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names=payload_opcodes,
    )
    rust_payload_packets = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names=payload_opcodes,
    )
    wire_checks = {
        "requestFrames": _paired_packet_check(
            "Rust request frames exactly match MFC receive frames",
            rust_request_packets,
            mfc_request_packets,
        ),
        "payloadFrames": _paired_packet_check(
            "MFC payload frames exactly match Rust receive frames",
            mfc_payload_packets,
            rust_payload_packets,
        ),
    }
    rust_checks = {
        "sourceEngaged": _check(
            "Rust accepted the exact source",
            _matches(
                rust,
                family="sched",
                event="source_engaged",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "outcome", "engaged"),
            ),
        ),
        "payloadAccepted": _check(
            "Rust accepted payload for the exact file",
            _matches(
                rust,
                family="sched",
                event="download_payload_accepted",
                file_hash=normalized_hash,
                predicate=lambda record: _positive_body_field(record, "bytes"),
            ),
        ),
        "taskSettled": _check(
            "Rust settled the exact download task as completed",
            _matches(
                rust,
                family="sched",
                event="download_task_settled",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "state", "completed"),
            ),
        ),
    }
    mfc_checks = {
        "published": _check("MFC published the exact file hash", publication),
        "uploadSlotOpened": _check(
            "MFC opened an upload slot for the exact file",
            _matches(
                mfc,
                family="sched",
                event="upload_slot_opened",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "outcome", "opened"),
            ),
        ),
        "uploadRequestServed": _check(
            "MFC admitted an upload request for the exact file",
            _matches(
                mfc,
                family="sched",
                event="upload_request_outcome",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "outcomeClass", "served"),
            ),
        ),
        "uploadPayloadSent": _check(
            "MFC sent payload for the exact file",
            _matches(
                mfc,
                family="sched",
                event="upload_payload_accounting",
                file_hash=normalized_hash,
                predicate=lambda record: _positive_body_field(record, "sentFileBytes"),
            ),
            detail={
                "sentFileBytes": sum(
                    int(_body(record).get("sentFileBytes") or 0)
                    for record in _matches(
                        mfc,
                        family="sched",
                        event="upload_payload_accounting",
                        file_hash=normalized_hash,
                    )
                )
            },
        ),
    }
    ordering = {
        "rust": _ordered(
            rust_checks,
            ("sourceEngaged", "payloadAccepted", "taskSettled"),
        ),
        "mfc": _ordered(
            mfc_checks,
            ("published", "uploadSlotOpened", "uploadRequestServed", "uploadPayloadSent"),
        ),
    }
    required_checks = [
        *wire_checks.values(),
        *rust_checks.values(),
        *mfc_checks.values(),
        *ordering.values(),
    ]
    failures = [str(check["name"]) for check in required_checks if not check["ok"]]
    eligible_coverage_ids: list[str] = []
    if not failures:
        eligible_coverage_ids.append("queue.admission")
        observed_payload_opcodes = set(wire_checks["payloadFrames"]["opcodes"])
        if observed_payload_opcodes.intersection(UNCOMPRESSED_PAYLOAD_OPCODES):
            eligible_coverage_ids.append("transfer.block.uncompressed")
        if observed_payload_opcodes.intersection(COMPRESSED_PAYLOAD_OPCODES):
            eligible_coverage_ids.append("transfer.block.compressed")
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "fileHash": normalized_hash,
        "failures": failures,
        "coverageClaims": {
            "eligibleCoverageIds": sorted(eligible_coverage_ids),
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
        "wireChecks": wire_checks,
        "clients": {
            "rust": {
                "recordCount": len(rust),
                "hashCorrelatedRecordCount": len(rust_hash_records),
                "checks": rust_checks,
                "schedRecords": [
                    record for record in rust_hash_records if record.get("family") == "sched"
                ],
            },
            "mfc": {
                "recordCount": len(mfc),
                "hashCorrelatedRecordCount": len(mfc_hash_records) + len(publication),
                "checks": mfc_checks,
                "schedRecords": [
                    *publication,
                    *(
                        record
                        for record in mfc_hash_records
                        if record.get("family") == "sched"
                    ),
                ],
            },
        },
        "ordering": ordering,
    }


def require_transfer_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises when one deterministic transfer lacks its mandatory causal chain."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic transfer diagnostics report has an unexpected schema.")
    if report.get("ok") is not True:
        failures = report.get("failures")
        raise RuntimeError(f"Deterministic transfer diagnostics are incomplete: {failures!r}")
