from __future__ import annotations

import json

import pytest

from emule_test_harness.startup_diagnostics import (
    STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID,
    STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME,
    STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID,
    STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID,
    count_phases_between,
    enforce_deferred_shared_hashing_boundary,
    get_top_slowest_phases,
    parse_startup_diagnostics,
    parse_startup_diagnostics_counters,
    summarize_startup_diagnostics,
    summarize_startup_diagnostics_counters,
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


def test_startup_diagnostics_summary_helpers_project_stable_rows() -> None:
    text = json.dumps(
        {
            "traceEvents": [
                {"name": "quick", "ph": "X", "ts": 1000, "dur": 100, "cat": "startup", "args": {"phase_id": "quick"}},
                {"name": "slow", "ph": "X", "ts": 2000, "dur": 900, "cat": "startup", "args": {"phase_id": "slow"}},
                {"name": "later", "ph": "X", "ts": 3000, "dur": 900, "cat": "startup", "args": {"phase_id": "later"}},
                {"name": "rows", "ph": "C", "ts": 1500, "args": {"counter_id": "shared.model.visible_rows", "value": 4}},
                {"name": "rows", "ph": "C", "ts": 2500, "args": {"counter_id": "shared.model.visible_rows", "value": 7}},
            ],
        }
    )

    phases = parse_startup_diagnostics(text)
    counters = parse_startup_diagnostics_counters(text)

    assert summarize_startup_diagnostics(phases, ["slow", "missing"]) == {
        "slow": {
            "phase_id": "slow",
            "category": "startup",
            "event_type": "complete",
            "absolute_us": 2000,
            "duration_us": 900,
            "absolute_ms": 2.0,
            "duration_ms": 0.9,
        }
    }
    assert [phase["name"] for phase in get_top_slowest_phases(phases, limit=2)] == ["later", "slow"]
    assert summarize_startup_diagnostics_counters(counters)["shared.model.visible_rows"]["value"] == 7


def test_summarize_shared_files_readiness_accepts_one_reload_during_hash_drain() -> None:
    text = trace_text(
        [
            counter("shared.model.visible_rows", 1901, 12),
            counter("shared.model.shared_files", 1902, 15),
            counter("shared.model.hidden_shared_files", 1903, 3),
            counter("shared.model.hashing_done_visible_rows", 2901, 15),
            counter("shared.model.hashing_done_shared_files", 2902, 15),
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
    assert summary["metrics"]["shared_visible_rows_at_readiness"] == 12
    assert summary["metrics"]["shared_files_at_hashing_done"] == 15
    assert summary["phases"][STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID]["phase_id"] == (
        STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID
    )
    assert summary["counters"]["shared.model.shared_files"]["value"] == 15


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


def test_enforce_deferred_shared_hashing_boundary_rejects_large_lead_and_late_start() -> None:
    large_lead = parse_startup_diagnostics(
        json.dumps(
            {
                "traceEvents": [
                    phase("shared.hashing.deferred_start", STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID, 0),
                    phase("StartupTimer complete", STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID, 500000),
                ],
            }
        )
    )
    late_start = parse_startup_diagnostics(
        json.dumps(
            {
                "traceEvents": [
                    phase("StartupTimer complete", STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID, 1000),
                    phase("shared.hashing.deferred_start", STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID, 2000),
                ],
            }
        )
    )

    with pytest.raises(RuntimeError, match="500.000 ms before startup.complete"):
        enforce_deferred_shared_hashing_boundary(large_lead, "large-lead")
    with pytest.raises(RuntimeError, match="occurred after startup.complete"):
        enforce_deferred_shared_hashing_boundary(late_start, "late-start")
