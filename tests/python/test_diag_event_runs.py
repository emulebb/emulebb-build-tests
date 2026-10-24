from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from emule_test_harness.diag_event_runs import (
    DiagnosticTraceError,
    diag_segment_identity,
    load_and_validate_writer_health,
    load_latest_diag_records,
    select_latest_diag_run,
)


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
def test_segment_identity_parses_run_ids_with_hyphens(tmp_path: Path, client: str) -> None:
    path = tmp_path / _segment_name(client, 42, "run-with-hyphens", 123)
    assert diag_segment_identity(path, client=client) == (42, "run-with-hyphens", 123)


@pytest.mark.parametrize("client", ["rust", "mfc"])
def test_loader_selects_one_newest_run_and_orders_its_segments(
    tmp_path: Path, client: str
) -> None:
    stale = tmp_path / _segment_name(client, 41, "stale", 0)
    stale.write_text(_record("stale", 41, 0, 99, client=client) + "\n", encoding="utf-8")
    first = tmp_path / _segment_name(client, 42, "active", 0)
    first.write_text(_record("active", 42, 0, 1, client=client) + "\n", encoding="utf-8")
    second = tmp_path / _segment_name(client, 42, "active", 1)
    second.write_text(
        _record("active", 42, 1, 2, client=client) + "\n{", encoding="utf-8"
    )
    os.utime(stale, ns=(1, 1))
    os.utime(first, ns=(2, 2))
    os.utime(second, ns=(3, 3))

    selected = select_latest_diag_run(tmp_path.glob("*.jsonl"), client=client)
    assert selected == [first.resolve(), second.resolve()]
    assert [record["seq"] for record in load_latest_diag_records(selected, client=client)] == [
        1,
        2,
    ]


def test_process_selection_never_falls_back_to_another_process(tmp_path: Path) -> None:
    other = tmp_path / _segment_name("rust", 43, "newer", 0)
    other.write_text(_record("newer", 43, 0, 1) + "\n", encoding="utf-8")
    assert select_latest_diag_run(tmp_path.iterdir(), client="rust", process_id=42) == []


def test_loader_rejects_legacy_schema_without_explicit_adapter(tmp_path: Path) -> None:
    legacy = tmp_path / "emulebb-rust-diag-42.jsonl"
    legacy.write_text(json.dumps({"schema": "diag_event_v1", "seq": 1}) + "\n", encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="no diag_event_v2"):
        load_latest_diag_records([legacy], client="rust")


def test_loader_rejects_malformed_complete_line(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("rust", 42, "active", 0)
    segment.write_text(_record("active", 42, 0, 1) + "\n{bad}\n", encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="malformed JSON"):
        load_latest_diag_records([segment], client="rust")


def test_loader_rejects_mixed_run_identity(tmp_path: Path) -> None:
    segment = tmp_path / _segment_name("mfc", 42, "active", 0)
    segment.write_text(_record("other", 42, 0, 1, client="mfc") + "\n", encoding="utf-8")
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
    segment.write_text(_record("active", 42, 7, 99, client="mfc") + "\n", encoding="utf-8")
    health_path = tmp_path / "emulebb-mfc-diag-health.json"
    health = {
        "schema": "diag_event_v2",
        "enabled": True,
        "configured": True,
        "initialized": True,
        "runId": "active",
        "processId": 42,
        "activeSegmentId": 7,
        "activeFileName": segment.name,
        "droppedEvents": 0,
        "encodeErrors": 0,
        "writeErrors": 0,
        "retentionDeleteErrors": 0,
        "initializationFailure": None,
    }
    health_path.write_text(json.dumps(health), encoding="utf-8")
    assert load_and_validate_writer_health(
        health_path, client="mfc", selected_segments=[segment]
    ) == health

    health["droppedEvents"] = 1
    health_path.write_text(json.dumps(health), encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="not lossless"):
        load_and_validate_writer_health(health_path, client="mfc", selected_segments=[segment])
