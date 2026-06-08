from __future__ import annotations

import json

import pytest

from emule_test_harness.startup_diagnostics import (
    STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME,
    STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID,
    count_phases_between,
    parse_startup_diagnostics,
    parse_startup_diagnostics_counters,
    summarize_shared_files_readiness,
)


def phase(name: str, phase_id: str, absolute_us: int) -> dict[str, object]:
    return {"name": name, "ph": "i", "ts": absolute_us, "args": {"phase_id": phase_id}}


def counter(counter_id: str, absolute_us: int, value: int) -> dict[str, object]:
    return {"name": counter_id, "ph": "C", "ts": absolute_us, "args": {"counter_id": counter_id, "value": value}}


def trace_text(extra_events: list[dict[str, object]] | None = None) -> str:
    events: list[dict[str, object]] = [
        phase("StartupTimer complete", STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID, 1000),
        phase("shared.scan.complete", STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID, 1100),
        phase("shared.tree.populated", STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID, 1200),
        phase("shared.model.populated", STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID, 1300),
        counter("shared.model.pending_hashes", 1900, 2),
        phase("ui.shared_files_ready", STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID, 2000),
    ]
    events.extend(extra_events or [])
    events.append(phase("ui.shared_files_hashing_done", STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID, 3000))
    return json.dumps({"traceEvents": events})


def test_count_phases_between_excludes_boundary_start_and_includes_end() -> None:
    phases = parse_startup_diagnostics(
        trace_text(
            [
                {"name": STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, "ph": "X", "ts": 2000, "dur": 1},
                {"name": STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, "ph": "X", "ts": 2500, "dur": 1},
                {"name": STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, "ph": "X", "ts": 3000, "dur": 1},
            ]
        )
    )

    assert count_phases_between(phases, STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, 2000, 3000) == 2


def test_summarize_shared_files_readiness_accepts_one_reload_during_hash_drain() -> None:
    text = trace_text(
        [
            {"name": STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, "ph": "X", "ts": 2500, "dur": 1},
        ]
    )

    summary = summarize_shared_files_readiness(
        parse_startup_diagnostics(text),
        parse_startup_diagnostics_counters(text),
    )

    assert summary["metrics"]["shared_list_reloads_during_hash_drain"] == 1
    assert summary["metrics"]["shared_pending_hashes_at_readiness"] == 2
    assert summary["metrics"]["shared_files_hashing_done_observed"] == 1


def test_summarize_shared_files_readiness_rejects_reload_loop_during_hash_drain() -> None:
    text = trace_text(
        [
            {"name": STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, "ph": "X", "ts": 2400, "dur": 1},
            {"name": STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME, "ph": "X", "ts": 2500, "dur": 1},
        ]
    )

    with pytest.raises(RuntimeError, match="reloaded the Shared Files list 2 times"):
        summarize_shared_files_readiness(
            parse_startup_diagnostics(text),
            parse_startup_diagnostics_counters(text),
        )
