"""Strict run-aware discovery and loading for current diagnostic event segments."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from emule_test_harness.diag_event_schema import DIAG_EVENT_SCHEMA


class DiagnosticTraceError(ValueError):
    """Raised when a current diagnostic run is incomplete or internally inconsistent."""


_SEGMENT_NAMES = {
    "rust": re.compile(
        r"^emulebb-rust-diag-(?P<process_id>\d+)-(?P<run_id>.+)-(?P<segment_id>\d{6,})\.jsonl$"
    ),
    "mfc": re.compile(
        r"^emulebb-mfc-diag-(?P<process_id>\d+)-(?P<run_id>.+)-(?P<segment_id>\d{6,})\.jsonl$"
    ),
}


def diag_segment_identity(path: Path, *, client: str) -> tuple[int, str, int] | None:
    """Returns ``(process_id, run_id, segment_id)`` for one current segment name."""

    try:
        pattern = _SEGMENT_NAMES[client]
    except KeyError as error:
        raise ValueError(f"client must be one of {sorted(_SEGMENT_NAMES)}, got {client!r}") from error
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
        grouped.setdefault((candidate_process_id, run_id), []).append((segment_id, path))

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
        raise DiagnosticTraceError(f"duplicate segment IDs in selected {client} diagnostic run")
    if segment_ids != list(range(segment_ids[0], segment_ids[-1] + 1)):
        raise DiagnosticTraceError(
            f"non-contiguous segment IDs in selected {client} diagnostic run: {segment_ids}"
        )
    return [path for _, path in ordered]


def _load_segment(path: Path, *, allow_incomplete_tail: bool) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig")
    lines = text.splitlines(keepends=True)
    records: list[dict[str, Any]] = []
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
                continue
            raise DiagnosticTraceError(
                f"malformed JSON in diagnostic segment {path} at line {line_number}: {error.msg}"
            ) from error
        if not isinstance(record, dict):
            raise DiagnosticTraceError(
                f"diagnostic segment {path} line {line_number} is not a JSON object"
            )
        records.append(record)
    return records


def load_latest_diag_records(
    paths: Iterable[Path],
    *,
    client: str,
    process_id: int | None = None,
) -> list[dict[str, Any]]:
    """Loads and validates one current run in segment and process-sequence order."""

    selected = select_latest_diag_run(paths, client=client, process_id=process_id)
    if not selected:
        return []
    first_identity = diag_segment_identity(selected[0], client=client)
    assert first_identity is not None
    selected_process_id, selected_run_id, _ = first_identity
    records: list[dict[str, Any]] = []
    previous_sequence: int | None = None
    for path_index, path in enumerate(selected):
        identity = diag_segment_identity(path, client=client)
        assert identity is not None
        _, _, selected_segment_id = identity
        for record in _load_segment(
            path, allow_incomplete_tail=path_index == len(selected) - 1
        ):
            if record.get("schema") != DIAG_EVENT_SCHEMA:
                raise DiagnosticTraceError(
                    f"unexpected diagnostic schema in {path}: {record.get('schema')!r}"
                )
            if record.get("client") != client:
                raise DiagnosticTraceError(
                    f"unexpected diagnostic client in {path}: {record.get('client')!r}"
                )
            if (
                record.get("processId") != selected_process_id
                or record.get("runId") != selected_run_id
                or record.get("segmentId") != selected_segment_id
            ):
                raise DiagnosticTraceError(f"mixed run identity in diagnostic segment {path}")
            sequence = record.get("seq")
            stream_sequence = record.get("streamSeq")
            if not isinstance(sequence, int) or sequence <= 0:
                raise DiagnosticTraceError(f"invalid process sequence in diagnostic segment {path}")
            if not isinstance(stream_sequence, int) or stream_sequence <= 0:
                raise DiagnosticTraceError(f"invalid stream sequence in diagnostic segment {path}")
            if previous_sequence is not None and sequence != previous_sequence + 1:
                raise DiagnosticTraceError(
                    f"non-contiguous process sequence in selected {client} run: "
                    f"{previous_sequence} -> {sequence}"
                )
            previous_sequence = sequence
            records.append(record)
    return records


def load_and_validate_writer_health(
    path: Path,
    *,
    client: str,
    selected_segments: list[Path],
) -> dict[str, Any]:
    """Loads writer health and requires it to describe the selected lossless run."""

    if not selected_segments:
        raise DiagnosticTraceError("writer health validation requires selected segments")
    try:
        health = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise DiagnosticTraceError(f"unable to read diagnostic writer health {path}: {error}") from error
    if not isinstance(health, dict):
        raise DiagnosticTraceError(f"diagnostic writer health {path} is not a JSON object")

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
        raise DiagnosticTraceError(f"diagnostic writer health identity mismatch: {mismatches}")

    unhealthy_flags = [
        key for key in ("enabled", "configured", "initialized") if health.get(key) is not True
    ]
    unhealthy_counters = [
        key
        for key in ("droppedEvents", "encodeErrors", "writeErrors", "retentionDeleteErrors")
        if health.get(key) != 0
    ]
    if health.get("initializationFailure") is not None:
        unhealthy_flags.append("initializationFailure")
    if unhealthy_flags or unhealthy_counters:
        raise DiagnosticTraceError(
            "diagnostic writer health is not lossless: "
            f"flags={unhealthy_flags}, counters={unhealthy_counters}"
        )
    return health
