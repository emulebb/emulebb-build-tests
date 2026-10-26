from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from emule_test_harness.diag_event_runs import (
    DIAGNOSTIC_WRITER_HEALTH_FIELDS,
    DiagnosticTraceError,
    diagnostic_writer_health_violations,
    diag_segment_identity,
    load_and_validate_writer_health,
    load_diag_event_segment_snapshot,
    load_exact_diag_run_snapshot,
    load_latest_diag_records,
    select_diag_run,
    select_latest_diag_run,
)


def _writer_health(*, segment_name: str) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "enabled": True,
        "configured": True,
        "initialized": True,
        "runId": "active",
        "processId": 42,
        "activeSegmentId": 7,
        "activeFileName": segment_name,
        "activeSegmentBytes": 10,
        "recordsWritten": 1,
        "bytesWritten": 10,
        "droppedEvents": 0,
        "encodeErrors": 0,
        "writeErrors": 0,
        "rotations": 0,
        "retentionDeletes": 0,
        "retentionDeleteErrors": 0,
        "retentionScanErrors": 0,
        "freeSpaceProbeErrors": 0,
        "retentionPolicyErrors": 0,
        "storagePolicyDrops": 0,
        "storageFaultDrops": 0,
        "retentionLimitDrops": 0,
        "aggregateLimitDrops": 0,
        "minimumFreeSpaceDrops": 0,
        "writerFaultDrops": 0,
        "retainedSegmentCount": 1,
        "retainedBytes": 10,
        "availableBytes": 10_000,
        "storageAuthorityFaulted": False,
        "writerIoFaulted": False,
        "storageBlockReason": None,
        "storagePolicySatisfied": True,
        "maximumGrowthBytes": 100,
        "maxSegmentBytes": 100,
        "maxSegmentSeconds": 60,
        "retainedSegments": 2,
        "maxTotalBytes": 200,
        "maxRetainedSeconds": 3_600,
        "minimumFreeBytes": 500,
        "initializationFailure": None,
    }


def _record(
    run_id: str,
    process_id: int,
    segment_id: int,
    seq: int,
    *,
    client: str = "rust",
) -> str:
    return json.dumps(
        {
            "schema": "diag_event_v2",
            "client": client,
            "runId": run_id,
            "processId": process_id,
            "segmentId": segment_id,
            "seq": seq,
            "streamSeq": seq,
            "family": "sched",
        }
    )


def _segment_name(client: str, process_id: int, run_id: str, segment_id: int) -> str:
    prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
    return f"{prefix}-diag-{process_id}-{run_id}-{segment_id:06}.jsonl"


@pytest.mark.parametrize("client", ["rust", "mfc"])
def test_segment_identity_parses_run_ids_with_hyphens(
    tmp_path: Path, client: str
) -> None:
    path = tmp_path / _segment_name(client, 42, "run-with-hyphens", 123)
    assert diag_segment_identity(path, client=client) == (42, "run-with-hyphens", 123)


@pytest.mark.parametrize("client", ["rust", "mfc"])
def test_loader_selects_one_newest_run_and_orders_its_segments(
    tmp_path: Path, client: str
) -> None:
    stale = tmp_path / _segment_name(client, 41, "stale", 0)
    stale.write_text(
        _record("stale", 41, 0, 99, client=client) + "\n", encoding="utf-8"
    )
    first = tmp_path / _segment_name(client, 42, "active", 0)
    first.write_text(
        _record("active", 42, 0, 1, client=client) + "\n", encoding="utf-8"
    )
    second = tmp_path / _segment_name(client, 42, "active", 1)
    second.write_text(
        _record("active", 42, 1, 2, client=client) + "\n{", encoding="utf-8"
    )
    os.utime(stale, ns=(1, 1))
    os.utime(first, ns=(2, 2))
    os.utime(second, ns=(3, 3))

    selected = select_latest_diag_run(tmp_path.glob("*.jsonl"), client=client)
    assert selected == [first.resolve(), second.resolve()]
    assert [
        record["seq"]
        for record in load_latest_diag_records(
            selected, client=client, allow_incomplete_active_tail=True
        )
    ] == [
        1,
        2,
    ]


def test_process_selection_never_falls_back_to_another_process(tmp_path: Path) -> None:
    other = tmp_path / _segment_name("rust", 43, "newer", 0)
    other.write_text(_record("newer", 43, 0, 1) + "\n", encoding="utf-8")
    assert (
        select_latest_diag_run(tmp_path.iterdir(), client="rust", process_id=42) == []
    )


@pytest.mark.parametrize("client", ["rust", "mfc"])
def test_exact_run_selection_never_falls_forward_to_a_newer_run(
    tmp_path: Path, client: str
) -> None:
    pinned = tmp_path / _segment_name(client, 42, "pinned", 0)
    pinned.write_text(
        _record("pinned", 42, 0, 1, client=client) + "\n", encoding="utf-8"
    )
    newer = tmp_path / _segment_name(client, 42, "newer", 0)
    newer.write_text(_record("newer", 42, 0, 1, client=client) + "\n", encoding="utf-8")
    os.utime(pinned, ns=(1, 1))
    os.utime(newer, ns=(2, 2))

    assert select_diag_run(
        tmp_path.iterdir(),
        client=client,
        process_id=42,
        run_id="pinned",
    ) == [pinned.resolve()]
    assert (
        select_diag_run(
            tmp_path.iterdir(),
            client=client,
            process_id=42,
            run_id="missing",
        )
        == []
    )


def test_exact_run_snapshot_retains_segment_provenance(tmp_path: Path) -> None:
    first = tmp_path / _segment_name("rust", 42, "pinned", 3)
    second = tmp_path / _segment_name("rust", 42, "pinned", 4)
    first_payload = (_record("pinned", 42, 3, 17) + "\n").encode()
    second_payload = (_record("pinned", 42, 4, 18) + "\n").encode()
    first.write_bytes(first_payload)
    second.write_bytes(second_payload)
    os.utime(first, ns=(10, 10))
    os.utime(second, ns=(20, 20))
    expected_modified_ns = [first.stat().st_mtime_ns, second.stat().st_mtime_ns]

    snapshot = load_exact_diag_run_snapshot(
        tmp_path.iterdir(),
        client="rust",
        process_id=42,
        run_id="pinned",
    )

    assert snapshot.client == "rust"
    assert snapshot.process_id == 42
    assert snapshot.run_id == "pinned"
    assert [segment.path for segment in snapshot.segments] == [
        first.resolve(),
        second.resolve(),
    ]
    assert [segment.byte_count for segment in snapshot.segments] == [
        len(first_payload),
        len(second_payload),
    ]
    assert [
        segment.modified_ns for segment in snapshot.segments
    ] == expected_modified_ns
    assert [segment.sha256 for segment in snapshot.segments] == [
        hashlib.sha256(first_payload).hexdigest(),
        hashlib.sha256(second_payload).hexdigest(),
    ]
    assert [segment.tail_terminated for segment in snapshot.segments] == [True, True]
    assert [segment.incomplete_tail_ignored for segment in snapshot.segments] == [
        False,
        False,
    ]
    assert [record["seq"] for record in snapshot.records] == [17, 18]


def test_exact_run_snapshot_rejects_missing_pinned_run(tmp_path: Path) -> None:
    other = tmp_path / _segment_name("rust", 42, "other", 0)
    other.write_text(_record("other", 42, 0, 1) + "\n", encoding="utf-8")

    with pytest.raises(DiagnosticTraceError, match="no exact diag_event_v2 rust run"):
        load_exact_diag_run_snapshot(
            tmp_path.iterdir(),
            client="rust",
            process_id=42,
            run_id="pinned",
        )


def test_loader_rejects_legacy_schema_without_explicit_adapter(tmp_path: Path) -> None:
    legacy = tmp_path / "emulebb-rust-diag-42.jsonl"
    legacy.write_text(
        json.dumps({"schema": "diag_event_v1", "seq": 1}) + "\n", encoding="utf-8"
    )
    with pytest.raises(DiagnosticTraceError, match="no diag_event_v2"):
        load_latest_diag_records([legacy], client="rust")


def test_loader_rejects_malformed_complete_line(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(_record("active", 42, 0, 1) + "\n{bad}\n", encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="malformed JSON"):
        load_latest_diag_records([segment], client="rust")


def test_loader_rejects_unterminated_tail_for_completed_run(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(_record("active", 42, 0, 1) + "\n{", encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="malformed JSON"):
        load_latest_diag_records([segment], client="rust")


def test_segment_snapshot_hashes_the_exact_stable_bytes(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    payload = ("\ufeff" + _record("active", 42, 0, 1) + "\n").encode()
    segment.write_bytes(payload)

    snapshot = load_diag_event_segment_snapshot(segment)

    assert snapshot.path == segment.resolve()
    assert snapshot.byte_count == len(payload)
    assert snapshot.modified_ns == segment.stat().st_mtime_ns
    assert snapshot.sha256 == hashlib.sha256(payload).hexdigest()
    assert snapshot.tail_terminated is True
    assert snapshot.incomplete_tail_ignored is False
    assert [record["seq"] for record in snapshot.records] == [1]


def test_segment_snapshot_reports_ignored_incomplete_tail(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(
        _record("active", 42, 0, 1) + '\n{"schema"',
        encoding="utf-8",
    )

    snapshot = load_diag_event_segment_snapshot(
        segment,
        allow_incomplete_tail=True,
    )

    assert snapshot.tail_terminated is False
    assert snapshot.incomplete_tail_ignored is True
    assert [record["seq"] for record in snapshot.records] == [1]


def test_segment_snapshot_distinguishes_complete_unterminated_json(
    tmp_path: Path,
) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(_record("active", 42, 0, 1), encoding="utf-8")

    snapshot = load_diag_event_segment_snapshot(
        segment,
        allow_incomplete_tail=True,
    )

    assert snapshot.tail_terminated is False
    assert snapshot.incomplete_tail_ignored is False
    assert [record["seq"] for record in snapshot.records] == [1]


class _MutatingSegmentReader:
    def __init__(self, raw, mutate) -> None:
        self._raw = raw
        self._mutate = mutate

    def __enter__(self):
        self._raw.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return self._raw.__exit__(exc_type, exc_value, traceback)

    def fileno(self) -> int:
        return self._raw.fileno()

    def read(self, size: int = -1) -> bytes:
        payload = self._raw.read(size)
        self._mutate()
        return payload


def test_active_segment_snapshot_accepts_append_only_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    first_payload = (_record("active", 42, 0, 1) + "\n").encode()
    second_payload = (_record("active", 42, 0, 2) + "\n").encode()
    segment.write_bytes(first_payload)
    original_open = Path.open

    def open_with_append(path: Path, mode: str = "r", *args, **kwargs):
        raw = original_open(path, mode, *args, **kwargs)
        if path != segment or mode != "rb":
            return raw

        def append_record() -> None:
            with original_open(segment, "ab") as writer:
                writer.write(second_payload)

        return _MutatingSegmentReader(raw, append_record)

    monkeypatch.setattr(Path, "open", open_with_append)

    snapshot = load_diag_event_segment_snapshot(
        segment,
        allow_incomplete_tail=True,
    )

    assert snapshot.byte_count == len(first_payload)
    assert snapshot.sha256 == hashlib.sha256(first_payload).hexdigest()
    assert [record["seq"] for record in snapshot.records] == [1]
    with original_open(segment, "rb") as reader:
        assert reader.read() == first_payload + second_payload


def test_closed_segment_snapshot_rejects_append_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    segment = tmp_path / _segment_name("rust", 42, "closed", 0)
    segment.write_text(_record("closed", 42, 0, 1) + "\n", encoding="utf-8")
    original_open = Path.open

    def open_with_append(path: Path, mode: str = "r", *args, **kwargs):
        raw = original_open(path, mode, *args, **kwargs)
        if path != segment or mode != "rb":
            return raw

        def append_record() -> None:
            with original_open(segment, "ab") as writer:
                writer.write((_record("closed", 42, 0, 2) + "\n").encode())

        return _MutatingSegmentReader(raw, append_record)

    monkeypatch.setattr(Path, "open", open_with_append)

    with pytest.raises(DiagnosticTraceError, match="changed while being read"):
        load_diag_event_segment_snapshot(segment)


def test_active_segment_snapshot_rejects_truncation_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(_record("active", 42, 0, 1) + "\n", encoding="utf-8")
    original_open = Path.open

    def open_with_truncation(path: Path, mode: str = "r", *args, **kwargs):
        raw = original_open(path, mode, *args, **kwargs)
        if path != segment or mode != "rb":
            return raw

        def truncate_segment() -> None:
            with original_open(segment, "r+b") as writer:
                writer.truncate(0)

        return _MutatingSegmentReader(raw, truncate_segment)

    monkeypatch.setattr(Path, "open", open_with_truncation)

    with pytest.raises(DiagnosticTraceError, match="changed while being read"):
        load_diag_event_segment_snapshot(segment, allow_incomplete_tail=True)


def test_segment_snapshot_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / _segment_name("rust", 42, "active", 0)
    target.write_text(_record("active", 42, 0, 1) + "\n", encoding="utf-8")
    link = tmp_path / "linked.jsonl"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(DiagnosticTraceError, match="must not be a symlink"):
        load_diag_event_segment_snapshot(link)


def test_loader_rejects_mixed_run_identity(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("mfc", 42, "active", 0)
    segment.write_text(
        _record("other", 42, 0, 1, client="mfc") + "\n", encoding="utf-8"
    )
    with pytest.raises(DiagnosticTraceError, match="mixed run identity"):
        load_latest_diag_records([segment], client="mfc")


def test_loader_rejects_sequence_gap(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(
        _record("active", 42, 0, 1) + "\n" + _record("active", 42, 0, 3) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(DiagnosticTraceError, match="non-contiguous process sequence"):
        load_latest_diag_records([segment], client="rust")


def test_writer_health_must_match_selected_lossless_run(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("mfc", 42, "active", 7)
    segment.write_text(
        _record("active", 42, 7, 99, client="mfc") + "\n", encoding="utf-8"
    )
    health_path = tmp_path / "emulebb-mfc-diag-health.json"
    health = _writer_health(segment_name=segment.name)
    health_path.write_text(json.dumps(health), encoding="utf-8")
    assert (
        load_and_validate_writer_health(
            health_path, client="mfc", selected_segments=[segment]
        )
        == health
    )

    health["droppedEvents"] = 1
    health_path.write_text(json.dumps(health), encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="not lossless"):
        load_and_validate_writer_health(
            health_path, client="mfc", selected_segments=[segment]
        )


def test_writer_health_integrity_requires_exact_current_contract() -> None:
    health = _writer_health(segment_name="emulebb-mfc-diag-42-active-000007.jsonl")
    assert tuple(health) == DIAGNOSTIC_WRITER_HEALTH_FIELDS
    assert diagnostic_writer_health_violations(health) == ()

    del health["retentionScanErrors"]
    health["legacyField"] = 0
    violations = diagnostic_writer_health_violations(health)
    assert "missingFields=['retentionScanErrors']" in violations
    assert "unexpectedFields=['legacyField']" in violations


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("retentionScanErrors", 1),
        ("freeSpaceProbeErrors", 1),
        ("storagePolicyDrops", 1),
        ("storageAuthorityFaulted", True),
        ("writerIoFaulted", True),
        ("storageBlockReason", "aggregateByteLimit"),
        ("storagePolicySatisfied", False),
        ("initializationFailure", "open failed"),
    ],
)
def test_writer_health_integrity_rejects_every_fault_class(
    field: str, value: object
) -> None:
    health = _writer_health(segment_name="emulebb-mfc-diag-42-active-000007.jsonl")
    health[field] = value
    assert any(
        field in violation for violation in diagnostic_writer_health_violations(health)
    )
