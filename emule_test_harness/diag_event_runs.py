"""Strict run-aware discovery and loading for current diagnostic event segments."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from emule_test_harness.diag_event_schema import DIAG_EVENT_SCHEMA


class DiagnosticTraceError(ValueError):
    """Raised when a current diagnostic run is incomplete or internally inconsistent."""


@dataclass(frozen=True)
class DiagnosticSegmentSnapshot:
    """One stable, hash-bearing read of an immutable diagnostic segment."""

    path: Path
    byte_count: int
    modified_ns: int
    sha256: str
    tail_terminated: bool
    incomplete_tail_ignored: bool
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class DiagnosticRunSnapshot:
    """One exact diagnostic run with immutable segment provenance."""

    client: str
    process_id: int
    run_id: str
    segments: tuple[DiagnosticSegmentSnapshot, ...]
    records: tuple[dict[str, Any], ...]


_SEGMENT_NAMES = {
    "rust": re.compile(
        r"^emulebb-rust-diag-(?P<process_id>\d+)-(?P<run_id>.+)-(?P<segment_id>\d{6,})\.jsonl$"
    ),
    "mfc": re.compile(
        r"^emulebb-mfc-diag-(?P<process_id>\d+)-(?P<run_id>.+)-(?P<segment_id>\d{6,})\.jsonl$"
    ),
}

DIAGNOSTIC_WRITER_HEALTH_FIELDS = (
    "schema",
    "enabled",
    "configured",
    "initialized",
    "runId",
    "processId",
    "activeSegmentId",
    "activeFileName",
    "activeSegmentBytes",
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
    "retainedSegmentCount",
    "retainedBytes",
    "availableBytes",
    "storageAuthorityFaulted",
    "writerIoFaulted",
    "storageBlockReason",
    "storagePolicySatisfied",
    "maximumGrowthBytes",
    "maxSegmentBytes",
    "maxSegmentSeconds",
    "retainedSegments",
    "maxTotalBytes",
    "maxRetainedSeconds",
    "minimumFreeBytes",
    "initializationFailure",
)

_WRITER_FAULT_COUNTER_FIELDS = (
    "droppedEvents",
    "encodeErrors",
    "writeErrors",
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

_WRITER_NONNEGATIVE_INTEGER_FIELDS = (
    "activeSegmentId",
    "activeSegmentBytes",
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
    "retainedBytes",
    "availableBytes",
    "maximumGrowthBytes",
    "maxSegmentBytes",
    "maxSegmentSeconds",
    "retainedSegments",
    "maxTotalBytes",
    "maxRetainedSeconds",
    "minimumFreeBytes",
)


def diagnostic_writer_health_violations(health: object) -> tuple[str, ...]:
    """Returns strict current-contract and lossless-writer violations."""

    if not isinstance(health, dict):
        return (f"health={type(health).__name__} expected object",)

    violations: list[str] = []
    expected_fields = set(DIAGNOSTIC_WRITER_HEALTH_FIELDS)
    actual_fields = set(health)
    missing = sorted(expected_fields - actual_fields)
    unexpected = sorted(actual_fields - expected_fields)
    if missing:
        violations.append(f"missingFields={missing!r}")
    if unexpected:
        violations.append(f"unexpectedFields={unexpected!r}")

    expected_values = {
        "schema": DIAG_EVENT_SCHEMA,
        "enabled": True,
        "configured": True,
        "initialized": True,
        "storageAuthorityFaulted": False,
        "writerIoFaulted": False,
        "storageBlockReason": None,
        "storagePolicySatisfied": True,
        "initializationFailure": None,
    }
    violations.extend(
        f"{name}={health.get(name)!r} expected {expected!r}"
        for name, expected in expected_values.items()
        if health.get(name) != expected
    )

    for name in ("runId", "activeFileName"):
        value = health.get(name)
        if not isinstance(value, str) or not value:
            violations.append(f"{name}={value!r} expected non-empty string")

    process_id = health.get("processId")
    if (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
    ):
        violations.append(f"processId={process_id!r} expected positive integer")

    retained_count = health.get("retainedSegmentCount")
    if (
        isinstance(retained_count, bool)
        or not isinstance(retained_count, int)
        or retained_count <= 0
    ):
        violations.append(
            f"retainedSegmentCount={retained_count!r} expected positive integer"
        )

    for name in _WRITER_NONNEGATIVE_INTEGER_FIELDS:
        value = health.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            violations.append(f"{name}={value!r} expected non-negative integer")

    for name in _WRITER_FAULT_COUNTER_FIELDS:
        if health.get(name) != 0:
            violations.append(f"{name}={health.get(name)!r} expected 0")

    bounds = (
        ("retainedSegmentCount", "retainedSegments"),
        ("retainedBytes", "maxTotalBytes"),
        ("minimumFreeBytes", "availableBytes"),
        ("maxSegmentBytes", "maximumGrowthBytes"),
    )
    for lower_name, upper_name in bounds:
        lower = health.get(lower_name)
        upper = health.get(upper_name)
        if (
            isinstance(lower, int)
            and not isinstance(lower, bool)
            and isinstance(upper, int)
            and not isinstance(upper, bool)
            and lower > upper
        ):
            violations.append(f"{lower_name}={lower!r} exceeds {upper_name}={upper!r}")
    return tuple(violations)


def diag_segment_identity(path: Path, *, client: str) -> tuple[int, str, int] | None:
    """Returns ``(process_id, run_id, segment_id)`` for one current segment name."""

    try:
        pattern = _SEGMENT_NAMES[client]
    except KeyError as error:
        raise ValueError(
            f"client must be one of {sorted(_SEGMENT_NAMES)}, got {client!r}"
        ) from error
    match = pattern.fullmatch(path.name)
    if match is None:
        return None
    return (
        int(match.group("process_id")),
        match.group("run_id"),
        int(match.group("segment_id")),
    )


def select_latest_diag_run(
    paths: Iterable[Path],
    *,
    client: str,
    process_id: int | None = None,
) -> list[Path]:
    """Selects one newest current run and returns its segments in numeric order."""

    files = sorted({path.resolve() for path in paths if path.is_file()})
    grouped: dict[tuple[int, str], list[tuple[int, Path]]] = {}
    unrecognized: list[Path] = []
    for path in files:
        identity = diag_segment_identity(path, client=client)
        if identity is None:
            unrecognized.append(path)
            continue
        candidate_process_id, run_id, segment_id = identity
        grouped.setdefault((candidate_process_id, run_id), []).append(
            (segment_id, path)
        )

    if files and not grouped:
        names = ", ".join(path.name for path in unrecognized)
        raise DiagnosticTraceError(
            f"no {DIAG_EVENT_SCHEMA} {client} segments were found in: {names}"
        )

    eligible = {
        key: segments
        for key, segments in grouped.items()
        if process_id is None or key[0] == process_id
    }
    if not eligible:
        return []

    _, selected = max(
        eligible.items(),
        key=lambda item: (
            max(path.stat().st_mtime_ns for _, path in item[1]),
            item[0],
        ),
    )
    ordered = sorted(selected)
    segment_ids = [segment_id for segment_id, _ in ordered]
    if len(segment_ids) != len(set(segment_ids)):
        raise DiagnosticTraceError(
            f"duplicate segment IDs in selected {client} diagnostic run"
        )
    if segment_ids != list(range(segment_ids[0], segment_ids[-1] + 1)):
        raise DiagnosticTraceError(
            f"non-contiguous segment IDs in selected {client} diagnostic run: {segment_ids}"
        )
    return [path for _, path in ordered]


def select_diag_run(
    paths: Iterable[Path],
    *,
    client: str,
    process_id: int,
    run_id: str,
) -> list[Path]:
    """Selects one exact current-schema run without falling back to another run."""

    if (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
    ):
        raise ValueError("process_id must be a positive integer")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")

    selected: list[tuple[int, Path]] = []
    for path in sorted({path.resolve() for path in paths if path.is_file()}):
        identity = diag_segment_identity(path, client=client)
        if identity is None:
            continue
        candidate_process_id, candidate_run_id, segment_id = identity
        if candidate_process_id == process_id and candidate_run_id == run_id:
            selected.append((segment_id, path))

    if not selected:
        return []
    selected.sort()
    segment_ids = [segment_id for segment_id, _ in selected]
    if len(segment_ids) != len(set(segment_ids)):
        raise DiagnosticTraceError(
            f"duplicate segment IDs in selected {client} diagnostic run"
        )
    if segment_ids != list(range(segment_ids[0], segment_ids[-1] + 1)):
        raise DiagnosticTraceError(
            f"non-contiguous segment IDs in selected {client} diagnostic run: {segment_ids}"
        )
    return [path for _, path in selected]


def load_diag_event_segment(
    path: Path, *, allow_incomplete_tail: bool = False
) -> list[dict[str, Any]]:
    """Loads one current segment and rejects malformed or foreign-schema records."""

    snapshot = load_diag_event_segment_snapshot(
        path, allow_incomplete_tail=allow_incomplete_tail
    )
    return list(snapshot.records)


def load_diag_event_segment_snapshot(
    path: Path, *, allow_incomplete_tail: bool = False
) -> DiagnosticSegmentSnapshot:
    """Reads one bounded segment snapshot and returns its records and digest."""

    if path.is_symlink():
        raise DiagnosticTraceError(f"diagnostic segment must not be a symlink: {path}")
    try:
        before = path.stat()
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(opened.st_size)
            read_complete = os.fstat(stream.fileno())
        after = path.stat()
    except OSError as error:
        raise DiagnosticTraceError(
            f"unable to read diagnostic segment {path}: {error}"
        ) from error

    path_identity = (before.st_dev, before.st_ino)
    opened_identity = (opened.st_dev, opened.st_ino)
    read_complete_identity = (read_complete.st_dev, read_complete.st_ino)
    after_identity = (after.st_dev, after.st_ino)
    identity_changed = not (
        path_identity == opened_identity == read_complete_identity == after_identity
    )
    if allow_incomplete_tail:
        changed_during_read = (
            identity_changed
            or len(payload) != opened.st_size
            or read_complete.st_size < opened.st_size
            or after.st_size < opened.st_size
        )
    else:
        before_state = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        opened_state = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        read_complete_state = (
            read_complete.st_dev,
            read_complete.st_ino,
            read_complete.st_size,
            read_complete.st_mtime_ns,
            read_complete.st_ctime_ns,
        )
        after_state = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        changed_during_read = not (
            before_state == opened_state == read_complete_state == after_state
        ) or len(payload) != opened.st_size
    if changed_during_read:
        raise DiagnosticTraceError(
            f"diagnostic segment changed while being read: {path}"
        )
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise DiagnosticTraceError(
            f"diagnostic segment is not valid UTF-8: {path}: {error}"
        ) from error
    records, incomplete_tail_ignored = _parse_diag_event_segment_text(
        text,
        path=path,
        allow_incomplete_tail=allow_incomplete_tail,
    )
    return DiagnosticSegmentSnapshot(
        path=path.resolve(),
        byte_count=len(payload),
        modified_ns=opened.st_mtime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
        tail_terminated=not text or text.endswith(("\n", "\r")),
        incomplete_tail_ignored=incomplete_tail_ignored,
        records=tuple(records),
    )


def _parse_diag_event_segment_text(
    text: str, *, path: Path, allow_incomplete_tail: bool
) -> tuple[list[dict[str, Any]], bool]:
    lines = text.splitlines(keepends=True)
    records: list[dict[str, Any]] = []
    incomplete_tail_ignored = False
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            is_incomplete_tail = (
                allow_incomplete_tail
                and line_number == len(lines)
                and not raw_line.endswith(("\n", "\r"))
            )
            if is_incomplete_tail:
                incomplete_tail_ignored = True
                continue
            raise DiagnosticTraceError(
                f"malformed JSON in diagnostic segment {path} at line {line_number}: {error.msg}"
            ) from error
        if not isinstance(record, dict):
            raise DiagnosticTraceError(
                f"diagnostic segment {path} line {line_number} is not a JSON object"
            )
        if record.get("schema") != DIAG_EVENT_SCHEMA:
            raise DiagnosticTraceError(
                f"unexpected diagnostic schema in {path}: {record.get('schema')!r}"
            )
        records.append(record)
    return records, incomplete_tail_ignored


def load_latest_diag_records(
    paths: Iterable[Path],
    *,
    client: str,
    process_id: int | None = None,
    allow_incomplete_active_tail: bool = False,
) -> list[dict[str, Any]]:
    """Loads and validates one current run in segment and process-sequence order."""

    selected = select_latest_diag_run(paths, client=client, process_id=process_id)
    if not selected:
        return []
    first_identity = diag_segment_identity(selected[0], client=client)
    assert first_identity is not None
    selected_process_id, selected_run_id, _ = first_identity
    return list(
        load_exact_diag_run_snapshot(
            selected,
            client=client,
            process_id=selected_process_id,
            run_id=selected_run_id,
            allow_incomplete_active_tail=allow_incomplete_active_tail,
        ).records
    )


def load_exact_diag_run_snapshot(
    paths: Iterable[Path],
    *,
    client: str,
    process_id: int,
    run_id: str,
    allow_incomplete_active_tail: bool = False,
) -> DiagnosticRunSnapshot:
    """Loads one pinned run and retains exact provenance for every selected segment."""

    selected = select_diag_run(
        paths,
        client=client,
        process_id=process_id,
        run_id=run_id,
    )
    if not selected:
        raise DiagnosticTraceError(
            f"no exact {DIAG_EVENT_SCHEMA} {client} run was found for "
            f"processId={process_id}, runId={run_id!r}"
        )

    snapshots: list[DiagnosticSegmentSnapshot] = []
    records: list[dict[str, Any]] = []
    previous_sequence: int | None = None
    for path_index, path in enumerate(selected):
        identity = diag_segment_identity(path, client=client)
        assert identity is not None
        _, _, segment_id = identity
        snapshot = load_diag_event_segment_snapshot(
            path,
            allow_incomplete_tail=(
                allow_incomplete_active_tail and path_index == len(selected) - 1
            ),
        )
        for record in snapshot.records:
            if record.get("client") != client:
                raise DiagnosticTraceError(
                    f"unexpected diagnostic client in {path}: {record.get('client')!r}"
                )
            if (
                record.get("processId") != process_id
                or record.get("runId") != run_id
                or record.get("segmentId") != segment_id
            ):
                raise DiagnosticTraceError(
                    f"mixed run identity in diagnostic segment {path}"
                )
            sequence = record.get("seq")
            stream_sequence = record.get("streamSeq")
            if not isinstance(sequence, int) or sequence <= 0:
                raise DiagnosticTraceError(
                    f"invalid process sequence in diagnostic segment {path}"
                )
            if not isinstance(stream_sequence, int) or stream_sequence <= 0:
                raise DiagnosticTraceError(
                    f"invalid stream sequence in diagnostic segment {path}"
                )
            if previous_sequence is not None and sequence != previous_sequence + 1:
                raise DiagnosticTraceError(
                    f"non-contiguous process sequence in selected {client} run: "
                    f"{previous_sequence} -> {sequence}"
                )
            previous_sequence = sequence
            records.append(record)
        snapshots.append(snapshot)

    return DiagnosticRunSnapshot(
        client=client,
        process_id=process_id,
        run_id=run_id,
        segments=tuple(snapshots),
        records=tuple(records),
    )


def load_and_validate_writer_health(
    path: Path,
    *,
    client: str,
    selected_segments: list[Path],
) -> dict[str, Any]:
    """Loads writer health and requires it to describe the selected lossless run."""

    if not selected_segments:
        raise DiagnosticTraceError(
            "writer health validation requires selected segments"
        )
    try:
        health = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise DiagnosticTraceError(
            f"unable to read diagnostic writer health {path}: {error}"
        ) from error
    if not isinstance(health, dict):
        raise DiagnosticTraceError(
            f"diagnostic writer health {path} is not a JSON object"
        )

    violations = diagnostic_writer_health_violations(health)
    if violations:
        raise DiagnosticTraceError(
            "diagnostic writer health is not lossless: " + "; ".join(violations)
        )

    first_identity = diag_segment_identity(selected_segments[0], client=client)
    last_identity = diag_segment_identity(selected_segments[-1], client=client)
    assert first_identity is not None and last_identity is not None
    process_id, run_id, _ = first_identity
    _, _, last_segment_id = last_identity
    expected = {
        "schema": DIAG_EVENT_SCHEMA,
        "processId": process_id,
        "runId": run_id,
        "activeSegmentId": last_segment_id,
        "activeFileName": selected_segments[-1].name,
    }
    mismatches = {
        key: {"expected": value, "actual": health.get(key)}
        for key, value in expected.items()
        if health.get(key) != value
    }
    if mismatches:
        raise DiagnosticTraceError(
            f"diagnostic writer health identity mismatch: {mismatches}"
        )

    return health
