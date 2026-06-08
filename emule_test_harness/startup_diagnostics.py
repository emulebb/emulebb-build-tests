"""Pure startup-diagnostics parsing and readiness validation helpers."""

from __future__ import annotations

import json

STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID = "startup.complete"
STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID = "shared.scan.complete"
STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID = "shared.tree.populated"
STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID = "shared.model.populated"
STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID = "ui.shared_files_ready"
STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID = "ui.shared_files_hashing_done"
STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME = "CSharedFilesCtrl::ReloadFileList total"
STARTUP_DIAGNOSTICS_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN = 1


def load_startup_diagnostics_trace_events(text: str) -> list[dict[str, object]]:
    """Parses a Chrome Trace payload and returns trace-event dictionaries."""

    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError("Startup profile trace payload must be one JSON object.")
    trace_events = payload.get("traceEvents")
    if not isinstance(trace_events, list):
        raise RuntimeError("Startup profile trace payload is missing a traceEvents list.")
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
        raise RuntimeError("Startup profile reached ui.shared_files_ready before startup.complete.")
    for phase_id, phase in (
        (STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID, shared_scan_complete),
        (STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID, shared_tree_populated),
        (STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID, shared_model_populated),
    ):
        if int(phase["absolute_us"]) > int(shared_files_ready["absolute_us"]):
            raise RuntimeError(f"Startup profile milestone {phase_id} occurs after ui.shared_files_ready.")

    pending_hashes_at_readiness = get_counter_by_id(counters, "shared.model.pending_hashes")
    pending_hash_count = int(pending_hashes_at_readiness["value"]) if pending_hashes_at_readiness is not None else 0
    shared_files_hashing_done = get_phase_by_id(phases, STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID)
    if shared_files_hashing_done is not None and int(shared_files_hashing_done["absolute_us"]) < int(shared_files_ready["absolute_us"]):
        raise RuntimeError("Startup profile reached ui.shared_files_hashing_done before ui.shared_files_ready.")

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
            "Startup profile reloaded the Shared Files list "
            f"{shared_list_reloads_during_hash_drain} times during shared hash drain."
        )

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
    if pending_hashes_at_readiness is not None:
        metrics["shared_pending_hashes_at_readiness"] = pending_hash_count
    if shared_files_hashing_done is not None:
        metrics["shared_files_hashing_done_absolute_ms"] = float(shared_files_hashing_done["absolute_ms"])
        metrics["shared_files_hashing_done_after_ready_ms"] = round(
            (int(shared_files_hashing_done["absolute_us"]) - int(shared_files_ready["absolute_us"])) / 1000.0,
            3,
        )
    return {"metrics": metrics}


def _require_phase(phases: list[dict[str, object]], phase_id: str) -> dict[str, object]:
    """Returns one required phase or raises the same diagnostic shape as the live helper."""

    phase = get_phase_by_id(phases, phase_id)
    if phase is None:
        raise RuntimeError(f"Startup profile is missing the {phase_id} milestone.")
    return phase
