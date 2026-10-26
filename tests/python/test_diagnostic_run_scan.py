from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import diagnostic_run_scan
from tests.python.diagnostic_fixtures import current_diagnostic_writer_health


def _segment_name(client: str, segment_id: int, *, run_id: str = "run-a") -> str:
    prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
    return f"{prefix}-diag-42-{run_id}-{segment_id:06}.jsonl"


def _record(
    sequence: int,
    *,
    segment_id: int,
    stream_sequence: int | None = None,
    event: str = "packet",
    severity: str = "info",
    outcome: str | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {
        "direction": "send",
        "protocolMarker": 0xE3,
        "opcode": 1,
        "opcodeName": "OP_01",
    }
    if outcome is not None:
        body["outcome"] = outcome
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "processId": 42,
        "runId": "run-a",
        "segmentId": segment_id,
        "seq": sequence,
        "streamSeq": stream_sequence if stream_sequence is not None else sequence,
        "family": "ed2k_tcp",
        "event": event,
        "severity": severity,
        "keys": {},
        "body": body,
    }


def _write_segment(
    profile: Path, segment_id: int, records: list[dict[str, object]]
) -> Path:
    path = profile / _segment_name("rust", segment_id)
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


def _health(active_segment_id: int, *, records_written: int) -> dict[str, object]:
    health = current_diagnostic_writer_health(segment_id=active_segment_id)
    health["recordsWritten"] = records_written
    health["rotations"] = active_segment_id
    return health


def test_scan_indexes_only_closed_segments_and_reports_pin_reasons(
    tmp_path: Path,
) -> None:
    _write_segment(tmp_path, 0, [_record(1, segment_id=0)])
    second = _write_segment(
        tmp_path,
        1,
        [
            _record(
                2,
                segment_id=1,
                event="request_timeout",
                severity="warning",
                outcome="timed_out",
            )
        ],
    )
    active = tmp_path / _segment_name("rust", 2)
    active.write_text("{incomplete", encoding="utf-8")

    advanced = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(2, records_written=2),
        observed_utc="2026-10-25T12:00:00+00:00",
    )

    assert advanced.checkpoint["source"]["coverage"] == "from-run-start"
    assert advanced.checkpoint["source"]["closedSegmentCount"] == 2
    assert advanced.checkpoint["index"]["recordCount"] == 2
    assert [item["segmentId"] for item in advanced.processed_segments] == [0, 1]
    assert advanced.processed_segments[1]["source"] == str(second.resolve())
    assert advanced.processed_segments[1]["interestingReasons"] == [
        "event:request_timeout",
        "outcome:timed_out",
        "severity:warning",
    ]


def test_scan_resumes_after_retention_deleted_previously_indexed_segments(
    tmp_path: Path,
) -> None:
    first = _write_segment(tmp_path, 0, [_record(1, segment_id=0)])
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(1, records_written=1),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    first.unlink()
    _write_segment(tmp_path, 1, [_record(2, segment_id=1)])

    resumed = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(2, records_written=2),
        observed_utc="2026-10-25T12:01:00+00:00",
        checkpoint=initial.checkpoint,
    )

    assert [item["segmentId"] for item in resumed.processed_segments] == [1]
    assert resumed.checkpoint["source"]["closedSegmentCount"] == 2
    assert resumed.checkpoint["index"]["processSequence"]["last"] == 2
    assert resumed.checkpoint["index"]["writerHealth"]["samples"] == 2


def test_scan_preserves_bounded_evidence_pin_metadata(tmp_path: Path) -> None:
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(0, records_written=0),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    initial.checkpoint["evidencePins"] = [{"segmentId": 7}]

    resumed = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(0, records_written=0),
        observed_utc="2026-10-25T12:01:00+00:00",
        checkpoint=initial.checkpoint,
    )

    assert resumed.checkpoint["evidencePins"] == [{"segmentId": 7}]


def test_scan_classifies_a_contiguous_retained_suffix(tmp_path: Path) -> None:
    _write_segment(tmp_path, 3, [_record(10, segment_id=3, stream_sequence=10)])
    _write_segment(tmp_path, 4, [_record(11, segment_id=4, stream_sequence=11)])

    advanced = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(5, records_written=11),
        observed_utc="2026-10-25T12:00:00+00:00",
    )

    assert advanced.checkpoint["source"]["coverage"] == "retained-suffix"
    assert advanced.checkpoint["source"]["omittedSegmentPrefix"] == 3
    assert advanced.checkpoint["index"]["processSequence"]["omittedPrefix"] == 9


def test_scan_rejects_a_gap_after_the_checkpoint(tmp_path: Path) -> None:
    _write_segment(tmp_path, 0, [_record(1, segment_id=0)])
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(1, records_written=1),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    _write_segment(tmp_path, 2, [_record(2, segment_id=2)])

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError, match="suffix is incomplete"
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=_health(3, records_written=2),
            observed_utc="2026-10-25T12:01:00+00:00",
            checkpoint=initial.checkpoint,
        )


def test_scan_rejects_segment_envelope_mismatch(tmp_path: Path) -> None:
    foreign = _record(1, segment_id=0)
    foreign["segmentId"] = 7
    _write_segment(tmp_path, 0, [foreign])

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError, match="envelope mismatch"
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=_health(1, records_written=1),
            observed_utc="2026-10-25T12:00:00+00:00",
        )


def test_scan_rejects_active_file_identity_mismatch(tmp_path: Path) -> None:
    health = _health(0, records_written=0)
    health["activeFileName"] = _segment_name("rust", 1)

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError, match="active file identity"
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=health,
            observed_utc="2026-10-25T12:00:00+00:00",
        )


def test_scan_rejects_checkpoint_identity_mismatch(tmp_path: Path) -> None:
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(0, records_written=0),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    changed = dict(initial.checkpoint)
    changed["runId"] = "other"

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError, match="identity mismatch"
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=_health(0, records_written=0),
            observed_utc="2026-10-25T12:01:00+00:00",
            checkpoint=changed,
        )


def test_scan_rejects_inconsistent_checkpoint_source_state(tmp_path: Path) -> None:
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(0, records_written=0),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    changed = dict(initial.checkpoint)
    changed["source"] = dict(initial.checkpoint["source"])
    changed["source"]["closedSegmentCount"] = 1

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError, match="source state is inconsistent"
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=_health(0, records_written=0),
            observed_utc="2026-10-25T12:01:00+00:00",
            checkpoint=changed,
        )


def test_scan_rejects_active_segment_regression(tmp_path: Path) -> None:
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(0, records_written=0),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    changed = dict(initial.checkpoint)
    changed["source"] = dict(initial.checkpoint["source"])
    changed["source"]["activeSegmentId"] = 1

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError,
        match="active segment regressed",
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=_health(0, records_written=0),
            observed_utc="2026-10-25T12:01:00+00:00",
            checkpoint=changed,
        )


def test_finalize_indexes_the_former_active_segment_and_seals_checkpoint(
    tmp_path: Path,
) -> None:
    _write_segment(tmp_path, 0, [_record(1, segment_id=0)])
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(1, records_written=2),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    _write_segment(tmp_path, 1, [_record(2, segment_id=1)])

    finalized = diagnostic_run_scan.finalize_stopped_run(
        profile_dir=tmp_path,
        client="rust",
        observed_utc="2026-10-25T12:01:00+00:00",
        checkpoint=initial.checkpoint,
    )

    assert [item["segmentId"] for item in finalized.processed_segments] == [1]
    assert finalized.checkpoint["source"]["activeSegmentId"] is None
    assert finalized.checkpoint["source"]["finalized"] is True
    assert (
        finalized.checkpoint["source"]["finalizedUtc"]
        == "2026-10-25T12:01:00+00:00"
    )
    assert finalized.checkpoint["source"]["closedSegmentCount"] == 2
    assert finalized.checkpoint["index"]["recordCount"] == 2
    assert finalized.checkpoint["index"]["writerHealth"]["samples"] == 1


def test_finalize_bootstraps_from_writer_health_without_a_checkpoint(
    tmp_path: Path,
) -> None:
    _write_segment(tmp_path, 0, [_record(1, segment_id=0)])

    finalized = diagnostic_run_scan.finalize_stopped_run(
        profile_dir=tmp_path,
        client="rust",
        observed_utc="2026-10-25T12:01:00+00:00",
        writer_health=_health(0, records_written=1),
    )

    assert [item["segmentId"] for item in finalized.processed_segments] == [0]
    assert finalized.checkpoint["source"]["coverage"] == "from-run-start"
    assert finalized.checkpoint["source"]["finalized"] is True
    assert finalized.checkpoint["index"]["writerHealth"]["samples"] == 1


def test_finalize_rejects_a_gap_after_the_last_closed_segment(tmp_path: Path) -> None:
    _write_segment(tmp_path, 0, [_record(1, segment_id=0)])
    initial = diagnostic_run_scan.scan_closed_segments(
        profile_dir=tmp_path,
        client="rust",
        writer_health=_health(1, records_written=1),
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    _write_segment(tmp_path, 2, [_record(2, segment_id=2)])

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError,
        match="stopped diagnostic segment suffix is incomplete",
    ):
        diagnostic_run_scan.finalize_stopped_run(
            profile_dir=tmp_path,
            client="rust",
            observed_utc="2026-10-25T12:01:00+00:00",
            checkpoint=initial.checkpoint,
        )


def test_scan_rejects_a_finalized_checkpoint(tmp_path: Path) -> None:
    _write_segment(tmp_path, 0, [_record(1, segment_id=0)])
    finalized = diagnostic_run_scan.finalize_stopped_run(
        profile_dir=tmp_path,
        client="rust",
        observed_utc="2026-10-25T12:00:00+00:00",
        writer_health=_health(0, records_written=1),
    )

    with pytest.raises(
        diagnostic_run_scan.DiagnosticRunScanError, match="already finalized"
    ):
        diagnostic_run_scan.scan_closed_segments(
            profile_dir=tmp_path,
            client="rust",
            writer_health=_health(1, records_written=1),
            observed_utc="2026-10-25T12:01:00+00:00",
            checkpoint=finalized.checkpoint,
        )

    repeated = diagnostic_run_scan.finalize_stopped_run(
        profile_dir=tmp_path,
        client="rust",
        observed_utc="2026-10-25T12:02:00+00:00",
        checkpoint=finalized.checkpoint,
    )
    assert repeated.processed_segments == ()
    assert repeated.checkpoint == finalized.checkpoint
