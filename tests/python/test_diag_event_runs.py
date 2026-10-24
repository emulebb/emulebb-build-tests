from __future__ import annotations

import json
import os
from pathlib import Path

from emule_test_harness.diag_event_runs import (
    load_latest_rust_diag_records,
    rust_diag_segment_identity,
    select_latest_rust_diag_run,
)


def _record(run_id: str, process_id: int, segment_id: int, seq: int) -> str:
    return json.dumps(
        {
            "schema": "diag_event_v2",
            "runId": run_id,
            "processId": process_id,
            "segmentId": segment_id,
            "seq": seq,
            "family": "sched",
        }
    )


def test_segment_identity_parses_run_ids_with_hyphens(tmp_path: Path) -> None:
    path = tmp_path / "emulebb-rust-diag-42-run-with-hyphens-000123.jsonl"
    assert rust_diag_segment_identity(path) == (42, "run-with-hyphens", 123)


def test_loader_selects_one_newest_run_and_orders_its_segments(tmp_path: Path) -> None:
    stale = tmp_path / "emulebb-rust-diag-41-stale-000000.jsonl"
    stale.write_text(_record("stale", 41, 0, 99) + "\n", encoding="utf-8")
    first = tmp_path / "emulebb-rust-diag-42-active-000000.jsonl"
    first.write_text(_record("active", 42, 0, 1) + "\n", encoding="utf-8")
    second = tmp_path / "emulebb-rust-diag-42-active-000001.jsonl"
    second.write_text(_record("active", 42, 1, 2) + "\n{", encoding="utf-8")
    os.utime(stale, ns=(1, 1))
    os.utime(first, ns=(2, 2))
    os.utime(second, ns=(3, 3))

    selected = select_latest_rust_diag_run(tmp_path.glob("emulebb-rust-diag-*.jsonl"))
    assert selected == [first.resolve(), second.resolve()]
    assert [record["seq"] for record in load_latest_rust_diag_records(selected)] == [1, 2]


def test_process_selection_prefers_matching_run(tmp_path: Path) -> None:
    requested = tmp_path / "emulebb-rust-diag-42-requested-000000.jsonl"
    requested.write_text(_record("requested", 42, 0, 1) + "\n", encoding="utf-8")
    newer = tmp_path / "emulebb-rust-diag-43-newer-000000.jsonl"
    newer.write_text(_record("newer", 43, 0, 1) + "\n", encoding="utf-8")
    os.utime(requested, ns=(1, 1))
    os.utime(newer, ns=(2, 2))

    assert select_latest_rust_diag_run(tmp_path.iterdir(), process_id=42) == [requested.resolve()]


def test_loader_falls_back_to_legacy_v1_files(tmp_path: Path) -> None:
    legacy = tmp_path / "emulebb-rust-diag-42.jsonl"
    legacy.write_text(
        "not-json\n"
        + json.dumps({"schema": "diag_event_v1", "seq": 2})
        + "\n"
        + json.dumps({"schema": "diag_event_v1", "seq": 1})
        + "\n",
        encoding="utf-8",
    )

    assert [record["seq"] for record in load_latest_rust_diag_records([legacy])] == [1, 2]
