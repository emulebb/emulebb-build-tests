"""Restart-safe indexing of immutable diagnostic segments during live soaks."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import diag_event_runs, diagnostic_run_index

CHECKPOINT_SCHEMA = "emulebb-build-tests.diagnostic-run-checkpoint.v2"


class DiagnosticRunScanError(ValueError):
    """Raised when closed-segment progress cannot be advanced losslessly."""


@dataclass(frozen=True)
class ClosedSegmentAdvance:
    """One immutable checkpoint update and its newly indexed segment metadata."""

    checkpoint: dict[str, Any]
    processed_segments: tuple[dict[str, Any], ...]


def scan_closed_segments(
    *,
    profile_dir: Path,
    client: str,
    writer_health: dict[str, Any],
    observed_utc: str,
    checkpoint: dict[str, Any] | None = None,
) -> ClosedSegmentAdvance:
    """Indexes every newly closed segment while leaving the active file untouched."""

    resolved_profile = profile_dir.resolve()
    if not resolved_profile.is_dir():
        raise DiagnosticRunScanError(
            f"diagnostic profile directory does not exist: {resolved_profile}"
        )
    process_id = _positive_integer(writer_health.get("processId"), "processId")
    run_id = _nonempty_string(writer_health.get("runId"), "runId")
    active_segment_id = _nonnegative_integer(
        writer_health.get("activeSegmentId"), "activeSegmentId"
    )
    active_file_name = _nonempty_string(
        writer_health.get("activeFileName"), "activeFileName"
    )
    active_identity = diag_event_runs.diag_segment_identity(
        Path(active_file_name), client=client
    )
    expected_active_identity = (process_id, run_id, active_segment_id)
    if active_identity != expected_active_identity:
        raise DiagnosticRunScanError(
            "writer health active file identity does not match its run identity: "
            f"{active_identity!r} != {expected_active_identity!r}"
        )

    index, source = _load_checkpoint(
        checkpoint,
        profile_dir=resolved_profile,
        client=client,
        process_id=process_id,
        run_id=run_id,
    )
    if source["finalized"]:
        raise DiagnosticRunScanError("diagnostic run checkpoint is already finalized")
    index = diagnostic_run_index.advance_writer_health(
        index,
        writer_health,
        observed_utc=observed_utc,
    )
    previous_active_segment_id = source["activeSegmentId"]
    if (
        previous_active_segment_id is not None
        and active_segment_id < previous_active_segment_id
    ):
        raise DiagnosticRunScanError(
            "writer active segment regressed: "
            f"{previous_active_segment_id} -> {active_segment_id}"
        )

    closed_segments = _closed_run_segments(
        resolved_profile,
        client=client,
        process_id=process_id,
        run_id=run_id,
        active_segment_id=active_segment_id,
    )
    last_closed_segment_id = source["lastClosedSegmentId"]
    new_segments = {
        segment_id: path
        for segment_id, path in closed_segments.items()
        if last_closed_segment_id is None or segment_id > last_closed_segment_id
    }
    _require_closed_suffix(
        tuple(new_segments),
        active_segment_id=active_segment_id,
        last_closed_segment_id=last_closed_segment_id,
    )

    index, processed = _advance_segments(
        index,
        source,
        new_segments,
        client=client,
        process_id=process_id,
        run_id=run_id,
    )

    source["activeSegmentId"] = active_segment_id
    source["finalized"] = False
    source["finalizedUtc"] = None
    source["coverage"] = _coverage(source)
    updated = {
        "schema": CHECKPOINT_SCHEMA,
        "profileDir": str(resolved_profile),
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "updatedUtc": observed_utc,
        "source": source,
        "index": index,
        "evidencePins": _checkpoint_evidence_pins(checkpoint),
    }
    return ClosedSegmentAdvance(
        checkpoint=updated,
        processed_segments=tuple(processed),
    )


def finalize_stopped_run(
    *,
    profile_dir: Path,
    client: str,
    observed_utc: str,
    checkpoint: dict[str, Any] | None = None,
    writer_health: dict[str, Any] | None = None,
) -> ClosedSegmentAdvance:
    """Indexes the complete retained run after its writer has stopped."""

    resolved_profile = profile_dir.resolve()
    if not resolved_profile.is_dir():
        raise DiagnosticRunScanError(
            f"diagnostic profile directory does not exist: {resolved_profile}"
        )
    if checkpoint is None:
        if writer_health is None:
            raise DiagnosticRunScanError(
                "writer health is required to finalize a run without a checkpoint"
            )
        process_id, run_id, last_observed_active_segment_id = _writer_identity(
            writer_health, client=client
        )
    else:
        process_id = _positive_integer(checkpoint.get("processId"), "processId")
        run_id = _nonempty_string(checkpoint.get("runId"), "runId")
        last_observed_active_segment_id = None

    index, source = _load_checkpoint(
        checkpoint,
        profile_dir=resolved_profile,
        client=client,
        process_id=process_id,
        run_id=run_id,
    )
    if source["finalized"]:
        raise DiagnosticRunScanError("diagnostic run checkpoint is already finalized")
    if source["activeSegmentId"] is not None:
        last_observed_active_segment_id = source["activeSegmentId"]
    if checkpoint is None:
        assert writer_health is not None
        index = diagnostic_run_index.advance_writer_health(
            index,
            writer_health,
            observed_utc=observed_utc,
        )

    run_segments = _run_segments(
        resolved_profile,
        client=client,
        process_id=process_id,
        run_id=run_id,
    )
    last_closed_segment_id = source["lastClosedSegmentId"]
    new_segments = {
        segment_id: path
        for segment_id, path in run_segments.items()
        if last_closed_segment_id is None or segment_id > last_closed_segment_id
    }
    _require_final_suffix(
        tuple(new_segments),
        last_closed_segment_id=last_closed_segment_id,
        last_observed_active_segment_id=last_observed_active_segment_id,
    )
    processed = _advance_segments(
        index,
        source,
        new_segments,
        client=client,
        process_id=process_id,
        run_id=run_id,
    )
    index = processed[0]
    source["activeSegmentId"] = None
    source["finalized"] = True
    source["finalizedUtc"] = observed_utc
    source["coverage"] = _coverage(source)
    updated = {
        "schema": CHECKPOINT_SCHEMA,
        "profileDir": str(resolved_profile),
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "updatedUtc": observed_utc,
        "source": source,
        "index": index,
        "evidencePins": _checkpoint_evidence_pins(checkpoint),
    }
    return ClosedSegmentAdvance(
        checkpoint=updated,
        processed_segments=tuple(processed[1]),
    )


def _load_checkpoint(
    checkpoint: dict[str, Any] | None,
    *,
    profile_dir: Path,
    client: str,
    process_id: int,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if checkpoint is None:
        return (
            diagnostic_run_index.new_index(
                client=client,
                process_id=process_id,
                run_id=run_id,
            ),
            {
                "coverage": "awaiting-first-closed-segment",
                "activeSegmentId": None,
                "finalized": False,
                "finalizedUtc": None,
                "firstClosedSegmentId": None,
                "lastClosedSegmentId": None,
                "omittedSegmentPrefix": None,
                "closedSegmentCount": 0,
                "lastClosedSegment": None,
            },
        )
    if (
        not isinstance(checkpoint, dict)
        or checkpoint.get("schema") != CHECKPOINT_SCHEMA
    ):
        raise DiagnosticRunScanError("diagnostic run checkpoint schema is invalid")
    expected_checkpoint_fields = {
        "schema",
        "profileDir",
        "client",
        "processId",
        "runId",
        "updatedUtc",
        "source",
        "index",
        "evidencePins",
    }
    if set(checkpoint) != expected_checkpoint_fields:
        raise DiagnosticRunScanError("diagnostic run checkpoint fields are invalid")
    expected_identity = {
        "profileDir": str(profile_dir),
        "client": client,
        "processId": process_id,
        "runId": run_id,
    }
    mismatches = {
        name: {"actual": checkpoint.get(name), "expected": expected}
        for name, expected in expected_identity.items()
        if checkpoint.get(name) != expected
    }
    if mismatches:
        raise DiagnosticRunScanError(
            f"diagnostic run checkpoint identity mismatch: {mismatches}"
        )
    index = checkpoint.get("index")
    source = checkpoint.get("source")
    if not isinstance(index, dict) or not isinstance(source, dict):
        raise DiagnosticRunScanError("diagnostic run checkpoint payload is invalid")
    expected_source_fields = {
        "coverage",
        "activeSegmentId",
        "finalized",
        "finalizedUtc",
        "firstClosedSegmentId",
        "lastClosedSegmentId",
        "omittedSegmentPrefix",
        "closedSegmentCount",
        "lastClosedSegment",
    }
    if set(source) != expected_source_fields:
        raise DiagnosticRunScanError(
            "diagnostic run checkpoint source fields are invalid"
        )
    for name in (
        "activeSegmentId",
        "firstClosedSegmentId",
        "lastClosedSegmentId",
        "omittedSegmentPrefix",
    ):
        value = source[name]
        if value is not None:
            _nonnegative_integer(value, f"source.{name}")
    _nonnegative_integer(source["closedSegmentCount"], "source.closedSegmentCount")
    if not isinstance(source["finalized"], bool):
        raise DiagnosticRunScanError("source.finalized must be a boolean")
    if source["finalizedUtc"] is not None:
        _nonempty_string(source["finalizedUtc"], "source.finalizedUtc")
    if source["coverage"] not in {
        "awaiting-first-closed-segment",
        "from-run-start",
        "retained-suffix",
    }:
        raise DiagnosticRunScanError("diagnostic run checkpoint coverage is invalid")
    _require_source_consistency(source)
    return copy.deepcopy(index), copy.deepcopy(source)


def _checkpoint_evidence_pins(
    checkpoint: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if checkpoint is None:
        return []
    pins = checkpoint.get("evidencePins")
    if not isinstance(pins, list) or len(pins) > 4_096:
        raise DiagnosticRunScanError(
            "diagnostic run checkpoint evidencePins are invalid"
        )
    if any(not isinstance(pin, dict) for pin in pins):
        raise DiagnosticRunScanError(
            "diagnostic run checkpoint evidencePins are invalid"
        )
    return copy.deepcopy(pins)


def _closed_run_segments(
    profile_dir: Path,
    *,
    client: str,
    process_id: int,
    run_id: str,
    active_segment_id: int,
) -> dict[int, Path]:
    return {
        segment_id: path
        for segment_id, path in _run_segments(
            profile_dir,
            client=client,
            process_id=process_id,
            run_id=run_id,
        ).items()
        if segment_id < active_segment_id
    }


def _run_segments(
    profile_dir: Path,
    *,
    client: str,
    process_id: int,
    run_id: str,
) -> dict[int, Path]:
    selected: dict[int, Path] = {}
    for path in profile_dir.glob("*.jsonl"):
        if not path.is_file():
            continue
        identity = diag_event_runs.diag_segment_identity(path, client=client)
        if identity is None:
            continue
        candidate_process_id, candidate_run_id, segment_id = identity
        if (
            candidate_process_id != process_id
            or candidate_run_id != run_id
        ):
            continue
        if segment_id in selected:
            raise DiagnosticRunScanError(
                f"duplicate closed diagnostic segment ID: {segment_id}"
            )
        selected[segment_id] = path.resolve()
    return dict(sorted(selected.items()))


def _advance_segments(
    index: dict[str, Any],
    source: dict[str, Any],
    segments: dict[int, Path],
    *,
    client: str,
    process_id: int,
    run_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    processed: list[dict[str, Any]] = []
    for segment_id, path in segments.items():
        snapshot = diag_event_runs.load_diag_event_segment_snapshot(path)
        _require_segment_envelopes(
            snapshot.records,
            client=client,
            process_id=process_id,
            run_id=run_id,
            segment_id=segment_id,
            path=path,
        )
        advanced = diagnostic_run_index.advance_records(index, snapshot.records)
        index = advanced.index
        reasons = list(advanced.interesting_segments.get(segment_id, ()))
        metadata = {
            "segmentId": segment_id,
            "fileName": path.name,
            "source": str(snapshot.path),
            "bytes": snapshot.byte_count,
            "modifiedNs": snapshot.modified_ns,
            "sha256": snapshot.sha256,
            "recordCount": len(snapshot.records),
            "interestingReasons": reasons,
        }
        processed.append(metadata)
        if source["firstClosedSegmentId"] is None:
            source["firstClosedSegmentId"] = segment_id
            source["omittedSegmentPrefix"] = segment_id
        source["lastClosedSegmentId"] = segment_id
        source["closedSegmentCount"] += 1
        source["lastClosedSegment"] = copy.deepcopy(metadata)
    return index, processed


def _require_closed_suffix(
    segment_ids: tuple[int, ...],
    *,
    active_segment_id: int,
    last_closed_segment_id: int | None,
) -> None:
    if last_closed_segment_id is None:
        if active_segment_id == 0:
            expected: tuple[int, ...] = ()
        elif segment_ids:
            expected = tuple(range(segment_ids[0], active_segment_id))
        else:
            raise DiagnosticRunScanError(
                "no retained closed diagnostic segment is available before active segment "
                f"{active_segment_id}"
            )
    else:
        if last_closed_segment_id >= active_segment_id:
            raise DiagnosticRunScanError(
                "checkpoint closed segment is not before the active segment: "
                f"{last_closed_segment_id} >= {active_segment_id}"
            )
        expected = tuple(range(last_closed_segment_id + 1, active_segment_id))
    if segment_ids != expected:
        raise DiagnosticRunScanError(
            "closed diagnostic segment suffix is incomplete: "
            f"expected={expected!r}, actual={segment_ids!r}"
        )


def _require_final_suffix(
    segment_ids: tuple[int, ...],
    *,
    last_closed_segment_id: int | None,
    last_observed_active_segment_id: int | None,
) -> None:
    if not segment_ids:
        raise DiagnosticRunScanError(
            "no retained stopped diagnostic segment is available for finalization"
        )
    final_segment_id = segment_ids[-1]
    if (
        last_observed_active_segment_id is not None
        and final_segment_id < last_observed_active_segment_id
    ):
        raise DiagnosticRunScanError(
            "stopped diagnostic segment suffix does not reach the last observed active "
            f"segment: {final_segment_id} < {last_observed_active_segment_id}"
        )
    first_expected = (
        segment_ids[0]
        if last_closed_segment_id is None
        else last_closed_segment_id + 1
    )
    expected = tuple(range(first_expected, final_segment_id + 1))
    if segment_ids != expected:
        raise DiagnosticRunScanError(
            "stopped diagnostic segment suffix is incomplete: "
            f"expected={expected!r}, actual={segment_ids!r}"
        )


def _require_segment_envelopes(
    records: tuple[dict[str, Any], ...],
    *,
    client: str,
    process_id: int,
    run_id: str,
    segment_id: int,
    path: Path,
) -> None:
    expected = (client, process_id, run_id, segment_id)
    for record in records:
        actual = (
            record.get("client"),
            record.get("processId"),
            record.get("runId"),
            record.get("segmentId"),
        )
        if actual != expected:
            raise DiagnosticRunScanError(
                f"diagnostic segment envelope mismatch in {path}: {actual!r} != {expected!r}"
            )


def _coverage(source: dict[str, Any]) -> str:
    first_segment_id = source["firstClosedSegmentId"]
    if first_segment_id is None:
        return "awaiting-first-closed-segment"
    if first_segment_id == 0:
        return "from-run-start"
    return "retained-suffix"


def _require_source_consistency(source: dict[str, Any]) -> None:
    active_segment_id = source["activeSegmentId"]
    finalized = source["finalized"]
    finalized_utc = source["finalizedUtc"]
    if finalized and (active_segment_id is not None or finalized_utc is None):
        raise DiagnosticRunScanError(
            "finalized diagnostic run checkpoint source state is inconsistent"
        )
    if not finalized and (active_segment_id is None or finalized_utc is not None):
        raise DiagnosticRunScanError(
            "live diagnostic run checkpoint source state is inconsistent"
        )
    first_segment_id = source["firstClosedSegmentId"]
    last_segment_id = source["lastClosedSegmentId"]
    omitted_prefix = source["omittedSegmentPrefix"]
    segment_count = source["closedSegmentCount"]
    last_segment = source["lastClosedSegment"]
    if segment_count == 0:
        if (
            any(
                value is not None
                for value in (
                    first_segment_id,
                    last_segment_id,
                    omitted_prefix,
                    last_segment,
                )
            )
            or source["coverage"] != "awaiting-first-closed-segment"
        ):
            raise DiagnosticRunScanError(
                "empty diagnostic run checkpoint source state is inconsistent"
            )
        return
    if (
        first_segment_id is None
        or last_segment_id is None
        or omitted_prefix != first_segment_id
        or first_segment_id > last_segment_id
        or segment_count != last_segment_id - first_segment_id + 1
        or (
            not finalized
            and active_segment_id is not None
            and active_segment_id <= last_segment_id
        )
        or not isinstance(last_segment, dict)
        or last_segment.get("segmentId") != last_segment_id
        or source["coverage"] != _coverage(source)
    ):
        raise DiagnosticRunScanError(
            "non-empty diagnostic run checkpoint source state is inconsistent"
        )


def _writer_identity(
    writer_health: dict[str, Any], *, client: str
) -> tuple[int, str, int]:
    process_id = _positive_integer(writer_health.get("processId"), "processId")
    run_id = _nonempty_string(writer_health.get("runId"), "runId")
    active_segment_id = _nonnegative_integer(
        writer_health.get("activeSegmentId"), "activeSegmentId"
    )
    active_file_name = _nonempty_string(
        writer_health.get("activeFileName"), "activeFileName"
    )
    active_identity = diag_event_runs.diag_segment_identity(
        Path(active_file_name), client=client
    )
    expected_active_identity = (process_id, run_id, active_segment_id)
    if active_identity != expected_active_identity:
        raise DiagnosticRunScanError(
            "writer health active file identity does not match its run identity: "
            f"{active_identity!r} != {expected_active_identity!r}"
        )
    return process_id, run_id, active_segment_id


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DiagnosticRunScanError(f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DiagnosticRunScanError(f"{label} must be a non-negative integer")
    return value


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DiagnosticRunScanError(f"{label} must be a non-empty string")
    return value
