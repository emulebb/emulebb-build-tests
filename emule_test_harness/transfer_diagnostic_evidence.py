"""Causal ``diag_event_v2`` evidence for one deterministic peer transfer."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

SCHEMA = "emulebb-build-tests.deterministic-transfer-diagnostics.v1"
ED2K_HASH_PATTERN = re.compile(r"^[0-9a-f]{32}$")


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
    for field in ("streamSeq", "seq"):
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
        "peerPacket": _check(
            "Rust recorded exact-hash peer protocol traffic",
            _matches(rust, family="ed2k_tcp", event="packet", file_hash=normalized_hash),
        ),
        "downloadCompleted": _check(
            "Rust completed the exact download attempt",
            _matches(
                rust,
                family="sched",
                event="download_attempt_outcome",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "state", "completed"),
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
        "peerPacket": _check(
            "MFC recorded exact-hash peer protocol traffic",
            _matches(mfc, family="ed2k_tcp", event="packet", file_hash=normalized_hash),
        ),
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
            ("sourceEngaged", "downloadCompleted", "taskSettled"),
        ),
        "mfc": _ordered(
            mfc_checks,
            ("published", "uploadSlotOpened", "uploadRequestServed", "uploadPayloadSent"),
        ),
    }
    required_checks = [*rust_checks.values(), *mfc_checks.values(), *ordering.values()]
    failures = [str(check["name"]) for check in required_checks if not check["ok"]]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "fileHash": normalized_hash,
        "failures": failures,
        "clients": {
            "rust": {
                "recordCount": len(rust),
                "hashCorrelatedRecordCount": len(rust_hash_records),
                "checks": rust_checks,
                "hashCorrelatedRecords": rust_hash_records,
            },
            "mfc": {
                "recordCount": len(mfc),
                "hashCorrelatedRecordCount": len(mfc_hash_records) + len(publication),
                "checks": mfc_checks,
                "hashCorrelatedRecords": [*publication, *mfc_hash_records],
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
