"""Compact incremental indexes for one current ``diag_event_v2`` process run."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterable

from .diag_event_runs import (
    DIAGNOSTIC_WRITER_HEALTH_FIELDS,
    diagnostic_writer_health_violations,
)
from .diag_event_schema import DIAG_EVENT_SCHEMA

SCHEMA = "emulebb-build-tests.diagnostic-run-index.v2"
MAX_FAMILIES = 128
MAX_EVENTS_PER_FAMILY = 256
MAX_OUTCOMES_PER_FAMILY = 256
MAX_OPCODES_PER_FAMILY = 2_048
MAX_OPCODE_NAMES = 8
MAX_KEYS_PER_FAMILY = 256

_WRITER_MONOTONIC_FIELDS = (
    "activeSegmentId",
    "recordsWritten",
    "bytesWritten",
    "droppedEvents",
    "encodeErrors",
    "writeErrors",
    "rotations",
    "retentionDeletes",
    "retentionDeleteErrors",
    "retentionScanErrors",
    "freeSpaceProbeErrors",
    "retentionPolicyErrors",
    "storagePolicyDrops",
    "storageFaultDrops",
    "retentionLimitDrops",
    "aggregateLimitDrops",
    "minimumFreeSpaceDrops",
    "writerFaultDrops",
)
_INTERESTING_TOKENS = (
    "cancel",
    "disconnect",
    "drop",
    "error",
    "fail",
    "reject",
    "timed_out",
    "timeout",
)


class DiagnosticRunIndexError(ValueError):
    """Raised when a run cannot be indexed without losing integrity."""


@dataclass(frozen=True)
class IndexAdvance:
    """One immutable index update plus raw-segment pinning candidates."""

    index: dict[str, Any]
    interesting_segments: dict[int, tuple[str, ...]]


def new_index(*, client: str, process_id: int, run_id: str) -> dict[str, Any]:
    """Returns the empty JSON-serializable index for one exact writer run."""

    if client not in {"rust", "mfc"}:
        raise ValueError("client must be 'rust' or 'mfc'.")
    if (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
    ):
        raise ValueError("process_id must be a positive integer.")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be a non-empty string.")
    return {
        "schema": SCHEMA,
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "recordCount": 0,
        "processSequence": {
            "first": None,
            "last": None,
            "omittedPrefix": None,
        },
        "segments": {
            "first": None,
            "last": None,
            "omittedPrefix": None,
        },
        "families": {},
        "writerHealth": {
            "samples": 0,
            "firstObservedUtc": None,
            "latestObservedUtc": None,
            "first": None,
            "latest": None,
            "violationsSeen": [],
        },
    }


def advance_records(
    index: dict[str, Any], records: Iterable[dict[str, Any]]
) -> IndexAdvance:
    """Adds ordered records while enforcing process and family sequence continuity."""

    updated = copy.deepcopy(index)
    _require_index_identity(updated)
    interesting: dict[int, set[str]] = {}
    for record in records:
        _advance_record(updated, record, interesting)
    return IndexAdvance(
        index=updated,
        interesting_segments={
            segment_id: tuple(sorted(reasons))
            for segment_id, reasons in sorted(interesting.items())
        },
    )


def advance_writer_health(
    index: dict[str, Any], health: dict[str, Any], *, observed_utc: str
) -> dict[str, Any]:
    """Adds one exact writer-health sample and rejects counter regression."""

    updated = copy.deepcopy(index)
    _require_index_identity(updated)
    if not isinstance(observed_utc, str) or not observed_utc:
        raise ValueError("observed_utc must be a non-empty string.")
    expected_fields = set(DIAGNOSTIC_WRITER_HEALTH_FIELDS)
    actual_fields = set(health)
    if actual_fields != expected_fields:
        missing = sorted(expected_fields - actual_fields)
        unexpected = sorted(actual_fields - expected_fields)
        raise DiagnosticRunIndexError(
            f"writer health fields are invalid: missing={missing!r}, unexpected={unexpected!r}"
        )
    if (
        health.get("processId") != updated["processId"]
        or health.get("runId") != updated["runId"]
    ):
        raise DiagnosticRunIndexError(
            "writer health identity does not match the run index"
        )

    writer = updated["writerHealth"]
    previous = writer["latest"]
    if previous is not None:
        for name in _WRITER_MONOTONIC_FIELDS:
            before = previous.get(name)
            after = health.get(name)
            if (
                isinstance(before, int)
                and not isinstance(before, bool)
                and isinstance(after, int)
                and not isinstance(after, bool)
                and after < before
            ):
                raise DiagnosticRunIndexError(
                    f"writer health counter regressed for {name}: {before} -> {after}"
                )

    snapshot = copy.deepcopy(health)
    if writer["first"] is None:
        writer["first"] = snapshot
        writer["firstObservedUtc"] = observed_utc
    writer["latest"] = snapshot
    writer["latestObservedUtc"] = observed_utc
    writer["samples"] += 1
    violations = set(writer["violationsSeen"])
    violations.update(diagnostic_writer_health_violations(health))
    writer["violationsSeen"] = sorted(violations)
    return updated


def _require_index_identity(index: dict[str, Any]) -> None:
    if index.get("schema") != SCHEMA:
        raise DiagnosticRunIndexError(
            f"unexpected diagnostic run index schema: {index.get('schema')!r}"
        )
    if index.get("client") not in {"rust", "mfc"}:
        raise DiagnosticRunIndexError("diagnostic run index client is invalid")
    if (
        isinstance(index.get("processId"), bool)
        or not isinstance(index.get("processId"), int)
        or index["processId"] <= 0
    ):
        raise DiagnosticRunIndexError("diagnostic run index processId is invalid")
    if not isinstance(index.get("runId"), str) or not index["runId"]:
        raise DiagnosticRunIndexError("diagnostic run index runId is invalid")


def _advance_record(
    index: dict[str, Any],
    record: dict[str, Any],
    interesting: dict[int, set[str]],
) -> None:
    if not isinstance(record, dict) or record.get("schema") != DIAG_EVENT_SCHEMA:
        raise DiagnosticRunIndexError(
            "record does not use the current diagnostic schema"
        )
    identity = (record.get("client"), record.get("processId"), record.get("runId"))
    expected = (index["client"], index["processId"], index["runId"])
    if identity != expected:
        raise DiagnosticRunIndexError(
            f"record identity {identity!r} does not match index identity {expected!r}"
        )

    segment_id = _positive_or_zero_integer(record.get("segmentId"), "segmentId")
    sequence = _positive_integer(record.get("seq"), "seq")
    stream_sequence = _positive_integer(record.get("streamSeq"), "streamSeq")
    family = _nonempty_string(record.get("family"), "family")
    event = _nonempty_string(record.get("event"), "event")
    severity = _nonempty_string(record.get("severity"), "severity")
    body = record.get("body")
    if not isinstance(body, dict):
        raise DiagnosticRunIndexError("record body must be an object")
    keys = record.get("keys")
    if not isinstance(keys, dict):
        raise DiagnosticRunIndexError("record keys must be an object")

    _advance_sequence(index["processSequence"], sequence, label="process")
    _advance_segment(index["segments"], segment_id)
    family_index = _family_index(index, family, stream_sequence)
    family_index["records"] += 1
    for key_name in keys:
        _increment_bounded(
            family_index["keyPresence"],
            _nonempty_string(key_name, "keys field name"),
            maximum=MAX_KEYS_PER_FAMILY,
            label=f"{family} key names",
        )
    _increment_bounded(
        family_index["events"],
        event,
        maximum=MAX_EVENTS_PER_FAMILY,
        label=f"{family} events",
    )
    _increment_bounded(
        family_index["severities"],
        severity,
        maximum=MAX_OUTCOMES_PER_FAMILY,
        label=f"{family} severities",
    )

    outcome = body.get("outcome")
    if outcome is not None:
        outcome = _nonempty_string(outcome, "body.outcome")
        _increment_bounded(
            family_index["outcomes"],
            outcome,
            maximum=MAX_OUTCOMES_PER_FAMILY,
            label=f"{family} outcomes",
        )

    opcode = body.get("opcode", keys.get("opcode"))
    marker = body.get("protocolMarker", keys.get("protocolMarker"))
    if opcode is not None:
        opcode_value = _positive_or_zero_integer(opcode, "body.opcode")
        marker_value = (
            None
            if marker is None
            else _positive_or_zero_integer(marker, "body.protocolMarker")
        )
        _advance_opcode(
            family_index,
            marker=marker_value,
            opcode=opcode_value,
            opcode_name=body.get("opcodeName"),
            direction=body.get("direction"),
            event=event,
            outcome=outcome,
            key_names=keys.keys(),
        )

    index["recordCount"] += 1
    reasons = _interesting_reasons(event=event, severity=severity, outcome=outcome)
    if reasons:
        interesting.setdefault(segment_id, set()).update(reasons)


def _family_index(
    index: dict[str, Any], family: str, stream_sequence: int
) -> dict[str, Any]:
    families = index["families"]
    if family not in families:
        if len(families) >= MAX_FAMILIES:
            raise DiagnosticRunIndexError(
                f"diagnostic run exceeded {MAX_FAMILIES} distinct families"
            )
        families[family] = {
            "records": 0,
            "streamSequence": {
                "first": None,
                "last": None,
                "omittedPrefix": None,
            },
            "events": {},
            "outcomes": {},
            "severities": {},
            "keyPresence": {},
            "opcodes": {},
        }
    family_index = families[family]
    _advance_sequence(
        family_index["streamSequence"], stream_sequence, label=f"{family} stream"
    )
    return family_index


def _advance_sequence(
    sequence_index: dict[str, Any], value: int, *, label: str
) -> None:
    previous = sequence_index["last"]
    if previous is None:
        sequence_index["first"] = value
        sequence_index["omittedPrefix"] = value - 1
    elif value != previous + 1:
        raise DiagnosticRunIndexError(
            f"non-contiguous {label} sequence: {previous} -> {value}"
        )
    sequence_index["last"] = value


def _advance_segment(segment_index: dict[str, Any], segment_id: int) -> None:
    previous = segment_index["last"]
    if previous is None:
        segment_index["first"] = segment_id
        segment_index["omittedPrefix"] = segment_id
    elif segment_id < previous or segment_id > previous + 1:
        raise DiagnosticRunIndexError(
            f"non-contiguous diagnostic segment IDs: {previous} -> {segment_id}"
        )
    segment_index["last"] = segment_id


def _advance_opcode(
    family_index: dict[str, Any],
    *,
    marker: int | None,
    opcode: int,
    opcode_name: object,
    direction: object,
    event: str,
    outcome: str | None,
    key_names: Iterable[str],
) -> None:
    opcodes = family_index["opcodes"]
    key = f"{'null' if marker is None else marker}:{opcode}"
    if key not in opcodes:
        if len(opcodes) >= MAX_OPCODES_PER_FAMILY:
            raise DiagnosticRunIndexError(
                f"diagnostic family exceeded {MAX_OPCODES_PER_FAMILY} distinct opcodes"
            )
        opcodes[key] = {
            "protocolMarker": marker,
            "opcode": opcode,
            "records": 0,
            "names": [],
            "directions": {},
            "events": {},
            "outcomes": {},
            "keyPresence": {},
        }
    entry = opcodes[key]
    entry["records"] += 1
    if opcode_name is not None:
        name = _nonempty_string(opcode_name, "body.opcodeName")
        names = set(entry["names"])
        names.add(name)
        if len(names) > MAX_OPCODE_NAMES:
            raise DiagnosticRunIndexError(
                f"opcode {key} exceeded {MAX_OPCODE_NAMES} distinct names"
            )
        entry["names"] = sorted(names)
    if direction is not None:
        _increment_bounded(
            entry["directions"],
            _nonempty_string(direction, "body.direction"),
            maximum=16,
            label=f"opcode {key} directions",
        )
    _increment_bounded(
        entry["events"], event, maximum=MAX_EVENTS_PER_FAMILY, label="opcode events"
    )
    if outcome is not None:
        _increment_bounded(
            entry["outcomes"],
            outcome,
            maximum=MAX_OUTCOMES_PER_FAMILY,
            label="opcode outcomes",
        )
    for key_name in key_names:
        _increment_bounded(
            entry["keyPresence"],
            _nonempty_string(key_name, "keys field name"),
            maximum=MAX_KEYS_PER_FAMILY,
            label=f"opcode {key} key names",
        )


def _interesting_reasons(
    *, event: str, severity: str, outcome: str | None
) -> tuple[str, ...]:
    reasons: list[str] = []
    normalized_severity = severity.casefold()
    if normalized_severity not in {"trace", "debug", "info"}:
        reasons.append(f"severity:{normalized_severity}")
    for field, value in (("event", event), ("outcome", outcome)):
        if value is None:
            continue
        normalized = value.casefold()
        if any(token in normalized for token in _INTERESTING_TOKENS):
            reasons.append(f"{field}:{normalized}")
    return tuple(reasons)


def _increment_bounded(
    values: dict[str, int], key: str, *, maximum: int, label: str
) -> None:
    if key not in values and len(values) >= maximum:
        raise DiagnosticRunIndexError(f"{label} exceeded {maximum} distinct values")
    values[key] = values.get(key, 0) + 1


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DiagnosticRunIndexError(f"{label} must be a positive integer")
    return value


def _positive_or_zero_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DiagnosticRunIndexError(f"{label} must be a non-negative integer")
    return value


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DiagnosticRunIndexError(f"{label} must be a non-empty string")
    return value
