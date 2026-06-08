"""Pure startup-diagnostics parsing and readiness validation helpers."""

from __future__ import annotations

import json

STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID = "startup.complete"
STARTUP_DIAGNOSTICS_COMPLETE_PHASE_NAME = "StartupTimer complete"
STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID = "shared.scan.complete"
STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID = "shared.tree.populated"
STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID = "shared.model.populated"
STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID = "ui.shared_files_ready"
STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID = "ui.shared_files_hashing_done"
STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME = "CSharedFilesCtrl::ReloadFileList total"
STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID = "shared.hashing.deferred_start"
STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_MAX_LEAD_MS = 250.0
STARTUP_DIAGNOSTICS_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN = 1


def load_startup_diagnostics_trace_events(text: str) -> list[dict[str, object]]:
    """Parses a Chrome Trace payload and returns trace-event dictionaries."""

    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError("Startup diagnostics trace payload must be one JSON object.")
    trace_events = payload.get("traceEvents")
    if not isinstance(trace_events, list):
        raise RuntimeError("Startup diagnostics trace payload is missing a traceEvents list.")
    return [event for event in trace_events if isinstance(event, dict)]


def parse_startup_diagnostics(text: str) -> list[dict[str, object]]:
    """Parses Chrome Trace phase rows used by startup-diagnostics summaries."""

    phases: list[dict[str, object]] = []
    for event in load_startup_diagnostics_trace_events(text):
        phase_type = str(event.get("ph") or "")
        if phase_type not in {"X", "i"}:
            continue
        args = event.get("args")
        if not isinstance(args, dict):
            args = {}
        absolute_us = int(event.get("ts", 0) or 0)
        duration_us = int(event.get("dur", 0) or 0)
        phases.append(
            {
                "name": str(event.get("name") or ""),
                "phase_id": str(args.get("phase_id") or ""),
                "category": str(event.get("cat") or ""),
                "event_type": "complete" if phase_type == "X" else "instant",
                "absolute_us": absolute_us,
                "duration_us": duration_us,
                "absolute_ms": round(absolute_us / 1000.0, 3),
                "duration_ms": round(duration_us / 1000.0, 3),
            }
        )
    phases.sort(key=lambda phase: (int(phase["absolute_us"]), str(phase["name"])))
    return phases


def parse_startup_diagnostics_counters(text: str) -> list[dict[str, object]]:
    """Parses Chrome Trace counter rows used by startup-diagnostics summaries."""

    counters: list[dict[str, object]] = []
    for event in load_startup_diagnostics_trace_events(text):
        if str(event.get("ph") or "") != "C":
            continue
        args = event.get("args")
        if not isinstance(args, dict):
            continue
        values = {
            str(key): value
            for key, value in args.items()
            if key != "counter_id" and isinstance(value, (int, float))
        }
        if not values:
            continue
        absolute_us = int(event.get("ts", 0) or 0)
        value_key, value = next(iter(values.items()))
        counters.append(
            {
                "name": str(event.get("name") or ""),
                "counter_id": str(args.get("counter_id") or event.get("name") or ""),
                "category": str(event.get("cat") or ""),
                "absolute_us": absolute_us,
                "absolute_ms": round(absolute_us / 1000.0, 3),
                "value_key": value_key,
                "value": value,
                "values": values,
            }
        )
    counters.sort(key=lambda counter: (int(counter["absolute_us"]), str(counter["counter_id"])))
    return counters


def summarize_startup_diagnostics(phases: list[dict[str, object]], interesting_names: list[str]) -> dict[str, object]:
    """Extracts highlighted timings for selected phase names from parsed startup-diagnostics rows."""

    by_name = {str(phase["name"]): phase for phase in phases}
    highlights = {}
    for name in interesting_names:
        phase = by_name.get(name)
        if phase is None:
            continue
        highlights[name] = {
            "phase_id": str(phase["phase_id"]),
            "category": str(phase["category"]),
            "event_type": str(phase["event_type"]),
            "absolute_us": int(phase["absolute_us"]),
            "duration_us": int(phase["duration_us"]),
            "absolute_ms": float(phase["absolute_ms"]),
            "duration_ms": float(phase["duration_ms"]),
        }
    return highlights


def get_top_slowest_phases(phases: list[dict[str, object]], limit: int = 10) -> list[dict[str, object]]:
    """Returns the slowest startup-diagnostics phases ordered by duration."""

    ranked = sorted(
        phases,
        key=lambda phase: (-int(phase["duration_us"]), -int(phase["absolute_us"]), str(phase["name"])),
    )
    return [
        {
            "name": str(phase["name"]),
            "phase_id": str(phase["phase_id"]),
            "category": str(phase["category"]),
            "event_type": str(phase["event_type"]),
            "absolute_us": int(phase["absolute_us"]),
            "duration_us": int(phase["duration_us"]),
            "absolute_ms": float(phase["absolute_ms"]),
            "duration_ms": float(phase["duration_ms"]),
        }
        for phase in ranked[:limit]
    ]


def summarize_startup_diagnostics_counters(counters: list[dict[str, object]]) -> dict[str, object]:
    """Collapses startup-diagnostics counters to the latest value per stable counter id."""

    summarized: dict[str, object] = {}
    for counter in counters:
        entry = {
            "name": str(counter["name"]),
            "category": str(counter["category"]),
            "absolute_us": int(counter["absolute_us"]),
            "absolute_ms": float(counter["absolute_ms"]),
            "value_key": str(counter["value_key"]),
            "value": counter["value"],
            "values": dict(counter["values"]),
        }
        summarized[str(counter["counter_id"])] = entry
    return summarized


def get_phase_by_id(phases: list[dict[str, object]], phase_id: str) -> dict[str, object] | None:
    """Returns the latest parsed phase row for one stable phase id."""

    for phase in reversed(phases):
        if str(phase.get("phase_id") or "") == phase_id:
            return phase
    return None


def get_counter_by_id(counters: list[dict[str, object]], counter_id: str) -> dict[str, object] | None:
    """Returns the latest parsed counter row for one stable counter id."""

    for counter in reversed(counters):
        if str(counter.get("counter_id") or "") == counter_id:
            return counter
    return None


def count_phases_between(
    phases: list[dict[str, object]],
    phase_name: str,
    start_absolute_us: int,
    end_absolute_us: int | None,
) -> int:
    """Counts named phases after one timestamp and before an optional end timestamp."""

    return sum(
        1
        for phase in phases
        if str(phase.get("name") or "") == phase_name
        and int(phase["absolute_us"]) > start_absolute_us
        and (end_absolute_us is None or int(phase["absolute_us"]) <= end_absolute_us)
    )


def summarize_shared_files_readiness(
    phases: list[dict[str, object]],
    counters: list[dict[str, object]],
) -> dict[str, object]:
    """Validates the Shared Files startup-readiness contract and returns metrics."""

    startup_complete = _require_phase(phases, STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID)
    shared_scan_complete = _require_phase(phases, STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID)
    shared_tree_populated = _require_phase(phases, STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID)
    shared_model_populated = _require_phase(phases, STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID)
    shared_files_ready = _require_phase(phases, STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID)
    if int(shared_files_ready["absolute_us"]) < int(startup_complete["absolute_us"]):
        raise RuntimeError("Startup diagnostics reached ui.shared_files_ready before startup.complete.")
    for phase_id, phase in (
        (STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID, shared_scan_complete),
        (STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID, shared_tree_populated),
        (STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID, shared_model_populated),
    ):
        if int(phase["absolute_us"]) > int(shared_files_ready["absolute_us"]):
            raise RuntimeError(f"Startup diagnostics milestone {phase_id} occurs after ui.shared_files_ready.")

    pending_hashes_at_readiness = get_counter_by_id(counters, "shared.model.pending_hashes")
    pending_hash_count = int(pending_hashes_at_readiness["value"]) if pending_hashes_at_readiness is not None else 0
    shared_files_hashing_done = get_phase_by_id(phases, STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID)
    if shared_files_hashing_done is not None and int(shared_files_hashing_done["absolute_us"]) < int(shared_files_ready["absolute_us"]):
        raise RuntimeError("Startup diagnostics reached ui.shared_files_hashing_done before ui.shared_files_ready.")

    shared_list_reloads_during_hash_drain = count_phases_between(
        phases,
        STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME,
        int(shared_files_ready["absolute_us"]),
        int(shared_files_hashing_done["absolute_us"]) if shared_files_hashing_done is not None else None,
    )
    if (
        pending_hash_count > 0
        and shared_files_hashing_done is not None
        and shared_list_reloads_during_hash_drain > STARTUP_DIAGNOSTICS_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN
    ):
        raise RuntimeError(
            "Startup diagnostics reloaded the Shared Files list "
            f"{shared_list_reloads_during_hash_drain} times during shared hash drain."
        )

    visible_rows = get_counter_by_id(counters, "shared.model.visible_rows")
    shared_files = get_counter_by_id(counters, "shared.model.shared_files")
    hidden_files = get_counter_by_id(counters, "shared.model.hidden_shared_files")
    active_filter = get_counter_by_id(counters, "shared.model.active_filter")
    hashing_done_visible_rows = get_counter_by_id(counters, "shared.model.hashing_done_visible_rows")
    hashing_done_shared_files = get_counter_by_id(counters, "shared.model.hashing_done_shared_files")

    metrics: dict[str, object] = {
        "shared_files_ready_absolute_ms": float(shared_files_ready["absolute_ms"]),
        "shared_files_ready_after_startup_complete_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(startup_complete["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_scan_to_ready_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(shared_scan_complete["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_tree_to_ready_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(shared_tree_populated["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_model_to_ready_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(shared_model_populated["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_files_hashing_done_observed": 1 if shared_files_hashing_done is not None else 0,
        "shared_list_reloads_during_hash_drain": shared_list_reloads_during_hash_drain,
    }
    if visible_rows is not None:
        metrics["shared_visible_rows_at_readiness"] = int(visible_rows["value"])
    if shared_files is not None:
        metrics["shared_files_at_readiness"] = int(shared_files["value"])
    if hidden_files is not None:
        metrics["shared_hidden_files_at_readiness"] = int(hidden_files["value"])
    if active_filter is not None:
        metrics["shared_active_filter_at_readiness"] = int(active_filter["value"])
    if pending_hashes_at_readiness is not None:
        metrics["shared_pending_hashes_at_readiness"] = pending_hash_count
    if shared_files_hashing_done is not None:
        metrics["shared_files_hashing_done_absolute_ms"] = float(shared_files_hashing_done["absolute_ms"])
        metrics["shared_files_hashing_done_after_ready_ms"] = round(
            (int(shared_files_hashing_done["absolute_us"]) - int(shared_files_ready["absolute_us"])) / 1000.0,
            3,
        )
    if hashing_done_visible_rows is not None:
        metrics["shared_visible_rows_at_hashing_done"] = int(hashing_done_visible_rows["value"])
    if hashing_done_shared_files is not None:
        metrics["shared_files_at_hashing_done"] = int(hashing_done_shared_files["value"])

    return {
        "phases": {
            "startup.complete": dict(startup_complete),
            STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID: dict(shared_scan_complete),
            STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID: dict(shared_tree_populated),
            STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID: dict(shared_model_populated),
            STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID: dict(shared_files_ready),
            STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID: (
                dict(shared_files_hashing_done) if shared_files_hashing_done is not None else None
            ),
        },
        "counters": {
            "shared.model.pending_hashes": (
                dict(pending_hashes_at_readiness) if pending_hashes_at_readiness is not None else None
            ),
            "shared.model.visible_rows": dict(visible_rows) if visible_rows is not None else None,
            "shared.model.shared_files": dict(shared_files) if shared_files is not None else None,
            "shared.model.hidden_shared_files": dict(hidden_files) if hidden_files is not None else None,
            "shared.model.active_filter": dict(active_filter) if active_filter is not None else None,
            "shared.model.hashing_done_visible_rows": (
                dict(hashing_done_visible_rows) if hashing_done_visible_rows is not None else None
            ),
            "shared.model.hashing_done_shared_files": (
                dict(hashing_done_shared_files) if hashing_done_shared_files is not None else None
            ),
        },
        "metrics": metrics,
    }


def enforce_deferred_shared_hashing_boundary(
    phases: list[dict[str, object]],
    scenario_name: str,
) -> None:
    """Fails when deferred shared hashing starts well before startup finalization."""

    startup_complete = get_phase_by_id(phases, STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID)
    deferred_start = get_phase_by_id(phases, STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID)
    if startup_complete is None or deferred_start is None:
        return

    lead_us = int(startup_complete["absolute_us"]) - int(deferred_start["absolute_us"])
    if lead_us < 0:
        raise RuntimeError(
            f"Deferred shared hashing boundary regression in '{scenario_name}': "
            "shared.hashing.deferred_start occurred after startup.complete."
        )

    lead_ms = lead_us / 1000.0
    if lead_ms > STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_MAX_LEAD_MS:
        raise RuntimeError(
            f"Deferred shared hashing boundary regression in '{scenario_name}': "
            f"shared.hashing.deferred_start occurred {lead_ms:.3f} ms before startup.complete."
        )


def _require_phase(phases: list[dict[str, object]], phase_id: str) -> dict[str, object]:
    """Returns one required phase or raises the same diagnostic shape as the live helper."""

    phase = get_phase_by_id(phases, phase_id)
    if phase is None:
        raise RuntimeError(f"Startup diagnostics is missing the {phase_id} milestone.")
    return phase
