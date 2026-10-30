"""Bounded cumulative state for the converged diagnostics observer."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta
import hashlib
import json
from typing import Any

from . import observer_action_report
from .soak_storage import PersistedArtifact

SCHEMA = "emulebb-build-tests.converged-observer-state.v9"
PARITY_METHODS = ("server", "kad")
_TOP_LEVEL_FIELDS = {
    "schema",
    "campaignId",
    "configurationDigest",
    "limits",
    "observed",
    "nextActionSeq",
    "totals",
    "histograms",
    "parityGate",
    "checkpoints",
    "driver",
    "scheduler",
    "pendingAction",
    "retention",
    "recentActions",
    "recentAnomalies",
}
_VERDICT_BUCKETS = (
    "coverage-parity",
    "divergence",
    "one-sided",
    "no-traffic",
    "unpaired",
    "not-assessable",
    "evidence-incomplete",
    "other",
)
_TOTAL_BUCKETS = {
    "coverage-parity": "coverageParity",
    "divergence": "divergence",
    "one-sided": "oneSided",
    "no-traffic": "noTraffic",
    "unpaired": "unpaired",
    "not-assessable": "notAssessable",
    "evidence-incomplete": "evidenceIncomplete",
    "other": "other",
}
_KIND_BUCKETS = ("search", "download", "other")
_METHOD_BUCKETS = ("server", "global", "kad", "automatic", "none", "other")
_CLIENTS = ("rust", "mfc")


def new_state(
    campaign_id: str,
    *,
    configuration_digest: str,
    recent_action_limit: int,
    recent_anomaly_limit: int,
    success_target_per_method: int = 4,
) -> dict[str, Any]:
    """Returns one empty, strictly bounded cumulative observer state."""

    _require_nonempty_string(campaign_id, "campaign_id")
    _validate_sha256(configuration_digest, "configuration_digest")
    _require_positive_integer(recent_action_limit, "recent_action_limit")
    _require_positive_integer(recent_anomaly_limit, "recent_anomaly_limit")
    _require_positive_integer(
        success_target_per_method,
        "success_target_per_method",
    )
    return {
        "schema": SCHEMA,
        "campaignId": campaign_id,
        "configurationDigest": configuration_digest,
        "limits": {
            "recentActions": recent_action_limit,
            "recentAnomalies": recent_anomaly_limit,
        },
        "observed": {"firstUtc": None, "latestUtc": None},
        "nextActionSeq": 1,
        "totals": {
            "actions": 0,
            "coverageParity": 0,
            "divergence": 0,
            "oneSided": 0,
            "noTraffic": 0,
            "unpaired": 0,
            "notAssessable": 0,
            "evidenceIncomplete": 0,
            "other": 0,
        },
        "histograms": {
            "kind": {bucket: 0 for bucket in _KIND_BUCKETS},
            "method": {bucket: 0 for bucket in _METHOD_BUCKETS},
            "verdict": {bucket: 0 for bucket in _VERDICT_BUCKETS},
        },
        "parityGate": {
            "targets": {
                method: success_target_per_method for method in PARITY_METHODS
            },
            "successful": {method: 0 for method in PARITY_METHODS},
            "retryable": {method: 0 for method in PARITY_METHODS},
            "confirmedDivergences": 0,
            "status": "pending",
            "greenAtUtc": None,
            "firstConfirmedDivergence": None,
        },
        "checkpoints": {
            "count": 0,
            "firstUtc": None,
            "latestUtc": None,
            "latest": None,
        },
        "driver": {
            "cycles": 0,
            "cycleErrors": 0,
            "downloadsScheduled": 0,
            "connectivitySkips": 0,
            "latestCycle": None,
            "latestConnectivitySkip": None,
        },
        "scheduler": {
            "nextCycle": 1,
            "nextScheduleSlot": 1,
            "nextActionAtUtc": None,
        },
        "pendingAction": None,
        "retention": {
            "actions": _empty_retention(),
            "checkpoints": _empty_retention(),
        },
        "recentActions": [],
        "recentAnomalies": [],
    }


def validate_state(
    payload: object,
    *,
    campaign_id: str | None = None,
    configuration_digest: str | None = None,
    success_target_per_method: int | None = None,
) -> dict[str, Any]:
    """Returns a deep copy after strict schema and invariant validation."""

    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise RuntimeError("Converged observer state fields are invalid.")
    if payload.get("schema") != SCHEMA:
        raise RuntimeError("Converged observer state schema is invalid.")
    observed_campaign = payload.get("campaignId")
    _require_nonempty_string(observed_campaign, "campaignId")
    if campaign_id is not None and observed_campaign != campaign_id:
        raise RuntimeError("Converged observer state campaign identity is invalid.")
    observed_configuration_digest = payload.get("configurationDigest")
    _validate_sha256(observed_configuration_digest, "configurationDigest")
    if (
        configuration_digest is not None
        and observed_configuration_digest != configuration_digest
    ):
        raise RuntimeError("Converged observer configuration identity is invalid.")

    limits = payload.get("limits")
    if not isinstance(limits, dict) or set(limits) != {
        "recentActions",
        "recentAnomalies",
    }:
        raise RuntimeError("Converged observer state limits are invalid.")
    action_limit = _require_positive_integer(
        limits.get("recentActions"), "limits.recentActions"
    )
    anomaly_limit = _require_positive_integer(
        limits.get("recentAnomalies"), "limits.recentAnomalies"
    )

    observed = payload.get("observed")
    if not isinstance(observed, dict) or set(observed) != {"firstUtc", "latestUtc"}:
        raise RuntimeError("Converged observer observed-time state is invalid.")
    _validate_optional_timestamp(observed["firstUtc"])
    _validate_optional_timestamp(observed["latestUtc"])

    next_action_seq = _require_positive_integer(
        payload.get("nextActionSeq"), "nextActionSeq"
    )
    totals = payload.get("totals")
    expected_total_fields = {"actions", *_TOTAL_BUCKETS.values()}
    if not isinstance(totals, dict) or set(totals) != expected_total_fields:
        raise RuntimeError("Converged observer totals are invalid.")
    for name, value in totals.items():
        _require_nonnegative_integer(value, f"totals.{name}")
    if totals["actions"] != next_action_seq - 1:
        raise RuntimeError("Converged observer action sequence is discontinuous.")
    if sum(totals[name] for name in _TOTAL_BUCKETS.values()) != totals["actions"]:
        raise RuntimeError("Converged observer verdict totals are inconsistent.")

    histograms = payload.get("histograms")
    if not isinstance(histograms, dict) or set(histograms) != {
        "kind",
        "method",
        "verdict",
    }:
        raise RuntimeError("Converged observer histograms are invalid.")
    _validate_histogram(histograms["kind"], _KIND_BUCKETS, totals["actions"])
    _validate_histogram(histograms["method"], _METHOD_BUCKETS, totals["actions"])
    _validate_histogram(histograms["verdict"], _VERDICT_BUCKETS, totals["actions"])
    parity_gate = payload.get("parityGate")
    _validate_parity_gate(parity_gate)
    if success_target_per_method is not None:
        _require_positive_integer(
            success_target_per_method,
            "success_target_per_method",
        )
        if any(
            parity_gate["targets"][method] != success_target_per_method
            for method in PARITY_METHODS
        ):
            raise RuntimeError("Converged observer parity gate target is inconsistent.")

    checkpoints = payload.get("checkpoints")
    if not isinstance(checkpoints, dict) or set(checkpoints) != {
        "count",
        "firstUtc",
        "latestUtc",
        "latest",
    }:
        raise RuntimeError("Converged observer checkpoint state is invalid.")
    _require_nonnegative_integer(checkpoints["count"], "checkpoints.count")
    _validate_optional_timestamp(checkpoints["firstUtc"])
    _validate_optional_timestamp(checkpoints["latestUtc"])
    if checkpoints["latest"] is not None and not isinstance(
        checkpoints["latest"], dict
    ):
        raise RuntimeError("Converged observer latest checkpoint is invalid.")

    driver = payload.get("driver")
    if not isinstance(driver, dict) or set(driver) != {
        "cycles",
        "cycleErrors",
        "downloadsScheduled",
        "connectivitySkips",
        "latestCycle",
        "latestConnectivitySkip",
    }:
        raise RuntimeError("Converged observer driver state is invalid.")
    for name in (
        "cycles",
        "cycleErrors",
        "downloadsScheduled",
        "connectivitySkips",
    ):
        _require_nonnegative_integer(driver[name], f"driver.{name}")
    for name in ("latestCycle", "latestConnectivitySkip"):
        if driver[name] is not None and not isinstance(driver[name], dict):
            raise RuntimeError(f"Converged observer driver {name} is invalid.")

    scheduler = payload.get("scheduler")
    if not isinstance(scheduler, dict) or set(scheduler) != {
        "nextCycle",
        "nextScheduleSlot",
        "nextActionAtUtc",
    }:
        raise RuntimeError("Converged observer scheduler state is invalid.")
    next_cycle = _require_positive_integer(
        scheduler["nextCycle"], "scheduler.nextCycle"
    )
    next_schedule_slot = _require_positive_integer(
        scheduler["nextScheduleSlot"], "scheduler.nextScheduleSlot"
    )
    next_action_at_utc = scheduler["nextActionAtUtc"]
    _validate_optional_utc_timestamp(
        next_action_at_utc,
        "scheduler.nextActionAtUtc",
    )
    pending_action = payload.get("pendingAction")
    if pending_action is None:
        if next_cycle != driver["cycles"] + 1:
            raise RuntimeError("Converged observer driver cycle is discontinuous.")
        if next_schedule_slot != driver["cycles"] + driver["connectivitySkips"] + 1:
            raise RuntimeError("Converged observer schedule slot is discontinuous.")
    else:
        if next_action_at_utc is not None:
            raise RuntimeError(
                "Converged observer pending action cannot retain a scheduler deadline."
            )
        _validate_pending_action(
            pending_action,
            next_action_seq=next_action_seq,
            driver_cycles=driver["cycles"],
            connectivity_skips=driver["connectivitySkips"],
            next_cycle=next_cycle,
            next_schedule_slot=next_schedule_slot,
        )

    retention = payload.get("retention")
    if not isinstance(retention, dict) or set(retention) != {
        "actions",
        "checkpoints",
    }:
        raise RuntimeError("Converged observer retention state is invalid.")
    _validate_retention(retention["actions"], totals["actions"])
    _validate_retention(retention["checkpoints"], checkpoints["count"])

    recent_actions = payload.get("recentActions")
    recent_anomalies = payload.get("recentAnomalies")
    if (
        not isinstance(recent_actions, list)
        or len(recent_actions) > action_limit
        or any(not isinstance(item, dict) for item in recent_actions)
        or not isinstance(recent_anomalies, list)
        or len(recent_anomalies) > anomaly_limit
        or any(not isinstance(item, dict) for item in recent_anomalies)
    ):
        raise RuntimeError("Converged observer recent evidence is invalid.")
    return copy.deepcopy(payload)


def record_action(state: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Folds one sequenced action report into bounded cumulative state."""

    updated = validate_state(state)
    if updated["pendingAction"] is not None:
        raise RuntimeError(
            "Converged observer pending reports require commit_action_report."
        )
    return _fold_action_report(updated, report)


def _fold_action_report(
    updated: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise RuntimeError("Converged observer action report is invalid.")
    if report.get("campaignId") != updated["campaignId"]:
        raise RuntimeError("Converged observer action campaign identity is invalid.")
    sequence = report.get("seq")
    if sequence != updated["nextActionSeq"]:
        raise RuntimeError("Converged observer action sequence is discontinuous.")
    observed_utc = _action_observed_utc(report)
    _update_observed(updated, observed_utc)

    verdict = _bucket(report.get("verdict"), _VERDICT_BUCKETS, "other")
    kind = _bucket(report.get("kind"), _KIND_BUCKETS, "other")
    method_value = report.get("method")
    method = (
        "none"
        if method_value is None or not str(method_value).strip()
        else _bucket(method_value, _METHOD_BUCKETS, "other")
    )
    updated["totals"]["actions"] += 1
    updated["totals"][_TOTAL_BUCKETS[verdict]] += 1
    updated["histograms"]["verdict"][verdict] += 1
    updated["histograms"]["kind"][kind] += 1
    updated["histograms"]["method"][method] += 1
    updated["nextActionSeq"] += 1
    _fold_parity_gate(updated["parityGate"], report, observed_utc)

    compact = {
        "seq": sequence,
        "observedUtc": observed_utc,
        "kind": report.get("kind"),
        "method": report.get("method"),
        "key": report.get("key"),
        "label": report.get("label"),
        "verdict": report.get("verdict"),
        "coverageOk": report.get("coverageOk"),
        "byteMatch": report.get("byteMatch"),
        "diagOk": report.get("diagOk"),
    }
    _append_bounded(
        updated["recentActions"],
        compact,
        updated["limits"]["recentActions"],
    )
    if verdict != "coverage-parity":
        _append_bounded(
            updated["recentAnomalies"],
            compact,
            updated["limits"]["recentAnomalies"],
        )
    return updated


def _fold_parity_gate(
    gate: dict[str, Any],
    report: dict[str, Any],
    observed_utc: str,
) -> None:
    method = report.get("method")
    if method not in PARITY_METHODS:
        return
    outcome = observer_action_report.classify_validated_parity_gate_outcome(report)
    if outcome == observer_action_report.GATE_SUCCESS:
        gate["successful"][method] += 1
        if gate["status"] == "pending" and all(
            gate["successful"][candidate] >= gate["targets"][candidate]
            for candidate in PARITY_METHODS
        ):
            gate["status"] = "green"
            gate["greenAtUtc"] = observed_utc
        return
    if outcome == observer_action_report.GATE_CONFIRMED_DIVERGENCE:
        gate["confirmedDivergences"] += 1
        if gate["firstConfirmedDivergence"] is None:
            encoded = json.dumps(
                report,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            gate["firstConfirmedDivergence"] = {
                "seq": report["seq"],
                "actionId": report["actionId"],
                "cycle": report["cycle"],
                "method": method,
                "observedUtc": observed_utc,
                "reportSha256": hashlib.sha256(encoded).hexdigest(),
            }
        gate["status"] = "failed"
        return
    gate["retryable"][method] += 1


def record_checkpoint(
    state: dict[str, Any], checkpoint: dict[str, Any]
) -> dict[str, Any]:
    """Folds one periodic checkpoint into cumulative state."""

    updated = validate_state(state)
    if (
        not isinstance(checkpoint, dict)
        or checkpoint.get("schema") != "soak_checkpoint_v1"
    ):
        raise RuntimeError("Converged observer checkpoint is invalid.")
    observed_utc = checkpoint.get("ts_utc")
    _require_nonempty_string(observed_utc, "checkpoint.ts_utc")
    packet_records = checkpoint.get("packetRecords")
    if not isinstance(packet_records, dict):
        raise RuntimeError("Converged observer checkpoint packetRecords are invalid.")
    _update_observed(updated, observed_utc)
    checkpoint_state = updated["checkpoints"]
    checkpoint_state["count"] += 1
    checkpoint_state["firstUtc"] = checkpoint_state["firstUtc"] or observed_utc
    checkpoint_state["latestUtc"] = observed_utc
    checkpoint_state["latest"] = {
        "tsUtc": observed_utc,
        "rustAlive": checkpoint.get("rustAlive"),
        "packetRecords": copy.deepcopy(packet_records),
        "actions": (checkpoint.get("totals") or {}).get("actions")
        if isinstance(checkpoint.get("totals"), dict)
        else None,
        "errorLogHitCount": len(checkpoint.get("errorLogHits") or ())
        if isinstance(checkpoint.get("errorLogHits"), list)
        else None,
    }
    return updated


def set_next_action_deadline(
    state: dict[str, Any], next_action_at_utc: str | None
) -> dict[str, Any]:
    """Persists the restart-safe UTC deadline for the next scheduled action."""

    updated = validate_state(state)
    _validate_optional_utc_timestamp(
        next_action_at_utc,
        "scheduler.nextActionAtUtc",
    )
    if next_action_at_utc is not None and updated["pendingAction"] is not None:
        raise RuntimeError(
            "Converged observer pending action cannot set a scheduler deadline."
        )
    updated["scheduler"]["nextActionAtUtc"] = next_action_at_utc
    return validate_state(updated)


def reserve_driver_cycle(
    state: dict[str, Any],
    *,
    query: str,
    method: str,
    reserved_at_utc: str,
    diagnostic_runs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Reserves one cycle before either client receives a public action."""

    updated = validate_state(state)
    if updated["pendingAction"] is not None:
        raise RuntimeError("Converged observer already has a pending action.")
    _require_nonempty_string(query, "query")
    if method not in {"server", "global", "kad"}:
        raise RuntimeError("Converged observer pending action method is invalid.")
    _require_nonempty_string(reserved_at_utc, "reserved_at_utc")
    _validate_diagnostic_runs(diagnostic_runs)
    cycle = updated["scheduler"]["nextCycle"]
    schedule_slot = updated["scheduler"]["nextScheduleSlot"]
    action_id = driver_action_id(updated["campaignId"], cycle)
    updated["scheduler"]["nextActionAtUtc"] = None
    updated["pendingAction"] = {
        "actionId": action_id,
        "reportSeq": updated["nextActionSeq"],
        "cycle": cycle,
        "queryIndex": schedule_slot - 1,
        "query": query,
        "method": method,
        "reservedAtUtc": reserved_at_utc,
        "diagnosticRuns": copy.deepcopy(diagnostic_runs),
        "clients": {
            client: {"create": None, "resultPoll": None, "results": None}
            for client in _CLIENTS
        },
        "driverOutcome": None,
        "evidence": None,
    }
    updated["scheduler"]["nextCycle"] = cycle + 1
    updated["scheduler"]["nextScheduleSlot"] = schedule_slot + 1
    return validate_state(updated)


def driver_action_id(campaign_id: str, cycle: int) -> str:
    """Returns the stable identity for one reserved cycle."""

    _require_nonempty_string(campaign_id, "campaign_id")
    _require_positive_integer(cycle, "cycle")
    return f"{campaign_id}-cycle-{cycle:08d}"


def prepare_search_create(
    state: dict[str, Any],
    *,
    client: str,
    prepared_at_utc: str,
) -> dict[str, Any]:
    """Persists one client's create intent before the public POST."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    client_state = _pending_client(pending, client)
    if client_state["create"] is not None:
        raise RuntimeError("Converged observer search create is already prepared.")
    _require_nonempty_string(prepared_at_utc, "prepared_at_utc")
    client_state["create"] = {
        "status": "prepared",
        "preparedAtUtc": prepared_at_utc,
        "completedAtUtc": None,
        "searchId": None,
        "error": None,
    }
    return validate_state(updated)


def complete_search_create(
    state: dict[str, Any],
    *,
    client: str,
    completed_at_utc: str,
    search_id: str | None,
    error: dict[str, Any] | None,
) -> dict[str, Any]:
    """Records one prepared search-create outcome exactly once."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    client_state = _pending_client(pending, client)
    create = client_state["create"]
    if not isinstance(create, dict) or create.get("status") != "prepared":
        raise RuntimeError("Converged observer search create is not prepared.")
    _require_nonempty_string(completed_at_utc, "completed_at_utc")
    if (search_id is None) == (error is None):
        raise RuntimeError(
            "Converged observer search create requires exactly one result or error."
        )
    if search_id is not None:
        _require_nonempty_string(search_id, "search_id")
    _validate_optional_error(error)
    create["status"] = "succeeded" if search_id is not None else "failed"
    create["completedAtUtc"] = completed_at_utc
    create["searchId"] = search_id
    create["error"] = copy.deepcopy(error)
    return validate_state(updated)


def skip_search_create(
    state: dict[str, Any],
    *,
    client: str,
    completed_at_utc: str,
    error: dict[str, Any],
) -> dict[str, Any]:
    """Records an exact fail-closed reason for not issuing a client's POST."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    client_state = _pending_client(pending, client)
    if client_state["create"] is not None:
        raise RuntimeError("Converged observer search create is already prepared.")
    _require_nonempty_string(completed_at_utc, "completed_at_utc")
    _validate_optional_error(error)
    client_state["create"] = {
        "status": "skipped",
        "preparedAtUtc": None,
        "completedAtUtc": completed_at_utc,
        "searchId": None,
        "error": copy.deepcopy(error),
    }
    return validate_state(updated)


def start_search_results_poll(
    state: dict[str, Any],
    *,
    client: str,
    started_at_utc: str,
    deadline_utc: str,
) -> dict[str, Any]:
    """Starts one restart-safe incremental result poll for a created search."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    client_state = _pending_client(pending, client)
    create = client_state["create"]
    if not isinstance(create, dict) or create.get("status") != "succeeded":
        raise RuntimeError("Converged observer search result poll requires a search ID.")
    if client_state["resultPoll"] is not None:
        raise RuntimeError("Converged observer search result poll is already active.")
    if client_state["results"] is not None:
        raise RuntimeError("Converged observer search results are already recorded.")
    started = _parse_utc_timestamp(started_at_utc, "started_at_utc")
    deadline = _parse_utc_timestamp(deadline_utc, "deadline_utc")
    if deadline <= started:
        raise RuntimeError(
            "Converged observer search result poll deadline must follow its start."
        )
    client_state["resultPoll"] = {
        "startedAtUtc": started_at_utc,
        "deadlineUtc": deadline_utc,
        "nextAttemptAtUtc": started_at_utc,
        "attempts": 0,
        "errorCount": 0,
        "latestAttemptAtUtc": None,
        "lastObservedReturnedCount": None,
        "lastObservedTotalCount": None,
        "lastAttemptError": None,
        "latestError": None,
    }
    return validate_state(updated)


def record_search_results_poll_attempt(
    state: dict[str, Any],
    *,
    client: str,
    attempted_at_utc: str,
    next_attempt_at_utc: str | None,
    completed: bool,
    returned_count: int | None,
    total_count: int | None,
    error: dict[str, Any] | None,
) -> dict[str, Any]:
    """Records one GET outcome and either reschedules or closes its poll."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    client_state = _pending_client(pending, client)
    poll = client_state["resultPoll"]
    if not isinstance(poll, dict):
        raise RuntimeError("Converged observer search result poll is not active.")
    attempted = _parse_utc_timestamp(attempted_at_utc, "attempted_at_utc")
    due = _parse_utc_timestamp(poll["nextAttemptAtUtc"], "nextAttemptAtUtc")
    deadline = _parse_utc_timestamp(poll["deadlineUtc"], "deadlineUtc")
    if attempted < due:
        raise RuntimeError("Converged observer search result poll attempt is premature.")
    if not isinstance(completed, bool):
        raise RuntimeError("Converged observer search result completion is invalid.")
    if (returned_count is None) != (total_count is None):
        raise RuntimeError(
            "Converged observer search result page requires both returned and total counts."
        )
    if returned_count is not None:
        _require_nonnegative_integer(returned_count, "returned_count")
        _require_nonnegative_integer(total_count, "total_count")
        if total_count < returned_count:
            raise RuntimeError(
                "Converged observer search result total cannot be smaller than its page."
            )
    _validate_optional_error(error)
    if (total_count is None) == (error is None):
        raise RuntimeError(
            "Converged observer search result poll requires exactly one result or error."
        )
    if completed and error is not None:
        raise RuntimeError("Completed observer search results are inconsistent.")

    poll["attempts"] += 1
    poll["latestAttemptAtUtc"] = attempted_at_utc
    if total_count is not None:
        poll["lastObservedReturnedCount"] = returned_count
        poll["lastObservedTotalCount"] = total_count
    poll["lastAttemptError"] = copy.deepcopy(error)
    if error is not None:
        poll["errorCount"] += 1
        poll["latestError"] = copy.deepcopy(error)

    if completed or attempted >= deadline:
        if next_attempt_at_utc is not None:
            raise RuntimeError(
                "Terminal observer search result poll cannot be rescheduled."
            )
        client_state["results"] = _terminal_search_results(
            poll,
            completed_at_utc=attempted_at_utc,
            completed=completed,
            returned_count=poll["lastObservedReturnedCount"],
            total_count=poll["lastObservedTotalCount"],
            error=error,
            termination="completed" if completed else "deadline",
        )
        client_state["resultPoll"] = None
        return validate_state(updated)

    if next_attempt_at_utc is None:
        raise RuntimeError(
            "Incomplete observer search result poll requires a next attempt."
        )
    next_attempt = _parse_utc_timestamp(
        next_attempt_at_utc,
        "next_attempt_at_utc",
    )
    if next_attempt <= attempted or next_attempt > deadline:
        raise RuntimeError(
            "Converged observer search result poll next attempt is invalid."
        )
    poll["nextAttemptAtUtc"] = next_attempt_at_utc
    return validate_state(updated)


def expire_search_results_poll(
    state: dict[str, Any],
    *,
    client: str,
    completed_at_utc: str,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Closes an elapsed poll from its last persisted count and exact error."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    client_state = _pending_client(pending, client)
    poll = client_state["resultPoll"]
    if not isinstance(poll, dict):
        raise RuntimeError("Converged observer search result poll is not active.")
    completed_at = _parse_utc_timestamp(completed_at_utc, "completed_at_utc")
    deadline = _parse_utc_timestamp(poll["deadlineUtc"], "deadlineUtc")
    if completed_at < deadline:
        raise RuntimeError("Converged observer search result poll has not expired.")
    _validate_optional_error(error)
    terminal_error = error if error is not None else poll["lastAttemptError"]
    if poll["lastObservedTotalCount"] is None and terminal_error is None:
        raise RuntimeError(
            "Expired observer search result poll requires counts or an exact error."
        )
    client_state["results"] = _terminal_search_results(
        poll,
        completed_at_utc=completed_at_utc,
        completed=False,
        returned_count=poll["lastObservedReturnedCount"],
        total_count=poll["lastObservedTotalCount"],
        error=terminal_error,
        termination="expired",
    )
    client_state["resultPoll"] = None
    return validate_state(updated)


def _terminal_search_results(
    poll: dict[str, Any],
    *,
    completed_at_utc: str,
    completed: bool,
    returned_count: int | None,
    total_count: int | None,
    error: dict[str, Any] | None,
    termination: str,
) -> dict[str, Any]:
    """Builds one terminal result with retained bounded poll provenance."""

    return {
        "completedAtUtc": completed_at_utc,
        "completed": completed,
        "returnedCount": returned_count,
        "totalCount": total_count,
        "error": copy.deepcopy(error),
        "poll": {
            "startedAtUtc": poll["startedAtUtc"],
            "deadlineUtc": poll["deadlineUtc"],
            "attempts": poll["attempts"],
            "errorCount": poll["errorCount"],
            "latestAttemptAtUtc": poll["latestAttemptAtUtc"],
            "latestError": copy.deepcopy(poll["latestError"]),
            "termination": termination,
        },
    }


def mark_evidence_pending(
    state: dict[str, Any], *, window_end_utc: str
) -> dict[str, Any]:
    """Closes the action window after both client outcomes become terminal."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    if pending["driverOutcome"] is None:
        raise RuntimeError("Converged observer driver outcome is not recorded.")
    if pending["evidence"] is not None:
        raise RuntimeError("Converged observer evidence is already pending.")
    if not all(pending_client_is_terminal(pending, client) for client in _CLIENTS):
        raise RuntimeError("Converged observer client outcomes are incomplete.")
    _require_nonempty_string(window_end_utc, "window_end_utc")
    pending["evidence"] = {
        "status": "pending",
        "windowEndUtc": window_end_utc,
    }
    return validate_state(updated)


def commit_action_report(
    state: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    """Commits one matching report and clears its persisted pending action."""

    updated = validate_state(state)
    pending = _require_pending_action(updated)
    if pending["driverOutcome"] is None or pending["evidence"] is None:
        raise RuntimeError("Converged observer pending action is not reportable.")
    if not isinstance(report, dict):
        raise RuntimeError("Converged observer action report is invalid.")
    if report.get("actionId") != pending["actionId"]:
        raise RuntimeError("Converged observer action report identity is invalid.")
    if report.get("seq") != pending["reportSeq"]:
        raise RuntimeError("Converged observer action report sequence is invalid.")
    if report.get("cycle") != pending["cycle"]:
        raise RuntimeError("Converged observer action report cycle is invalid.")
    updated = _fold_action_report(updated, report)
    updated["pendingAction"] = None
    return validate_state(updated)


def record_driver_cycle(state: dict[str, Any], cycle: dict[str, Any]) -> dict[str, Any]:
    """Records cumulative driver-cycle outcomes without retaining an unbounded list."""

    updated = validate_state(state)
    if not isinstance(cycle, dict):
        raise RuntimeError("Converged observer driver cycle is invalid.")
    cycle_number = _require_positive_integer(cycle.get("cycle"), "cycle.cycle")
    expected_cycle = updated["driver"]["cycles"] + 1
    if cycle_number != expected_cycle:
        raise RuntimeError("Converged observer driver cycle is discontinuous.")
    pending = updated["pendingAction"]
    if pending is None:
        if updated["scheduler"]["nextCycle"] != cycle_number:
            raise RuntimeError("Converged observer driver cycle is discontinuous.")
        updated["scheduler"]["nextCycle"] = cycle_number + 1
        updated["scheduler"]["nextScheduleSlot"] += 1
    else:
        if pending["cycle"] != cycle_number:
            raise RuntimeError("Converged observer pending cycle is inconsistent.")
        if cycle.get("actionId") != pending["actionId"]:
            raise RuntimeError("Converged observer pending action identity is invalid.")
        if pending["driverOutcome"] is not None:
            raise RuntimeError("Converged observer driver cycle is already recorded.")
        if not all(pending_client_is_terminal(pending, client) for client in _CLIENTS):
            raise RuntimeError("Converged observer driver cycle is premature.")
    updated["driver"]["cycles"] += 1
    if cycle.get("error") or cycle.get("ok") is False or cycle.get("errors"):
        updated["driver"]["cycleErrors"] += 1
    download = cycle.get("download")
    if isinstance(download, dict) and download.get("scheduled") is True:
        updated["driver"]["downloadsScheduled"] += 1
    updated["driver"]["latestCycle"] = copy.deepcopy(cycle)
    if pending is not None:
        pending["driverOutcome"] = copy.deepcopy(cycle)
    return validate_state(updated)


def record_connectivity_skip(
    state: dict[str, Any], skip: dict[str, Any]
) -> dict[str, Any]:
    """Records one skipped driver cycle without retaining an unbounded list."""

    updated = validate_state(state)
    if not isinstance(skip, dict):
        raise RuntimeError("Converged observer connectivity skip is invalid.")
    recorded_skip = copy.deepcopy(skip)
    recorded_skip["scheduleSlot"] = updated["scheduler"]["nextScheduleSlot"]
    updated["driver"]["connectivitySkips"] += 1
    updated["driver"]["latestConnectivitySkip"] = recorded_skip
    updated["scheduler"]["nextScheduleSlot"] += 1
    return validate_state(updated)


def record_stream_retention(
    state: dict[str, Any],
    *,
    stream: str,
    persisted: PersistedArtifact,
) -> dict[str, Any]:
    """Records exact retained-window watermarks after one durable stream write."""

    updated = validate_state(state)
    if stream not in {"actions", "checkpoints"}:
        raise ValueError("stream must be 'actions' or 'checkpoints'.")
    seen = (
        updated["totals"]["actions"]
        if stream == "actions"
        else updated["checkpoints"]["count"]
    )
    entry = updated["retention"][stream]
    entry["seen"] = seen
    entry["retained"] = persisted.retained_count
    entry["omitted"] = max(seen - persisted.retained_count, 0)
    entry["retainedBytes"] = persisted.retained_bytes
    entry["latestFile"] = persisted.path.name
    return updated


def canonical_bytes(state: dict[str, Any]) -> bytes:
    """Returns the deterministic persisted representation of validated state."""

    validated = validate_state(state)
    return (
        json.dumps(
            validated,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _validate_pending_action(
    value: object,
    *,
    next_action_seq: int,
    driver_cycles: int,
    connectivity_skips: int,
    next_cycle: int,
    next_schedule_slot: int,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "actionId",
        "reportSeq",
        "cycle",
        "queryIndex",
        "query",
        "method",
        "reservedAtUtc",
        "diagnosticRuns",
        "clients",
        "driverOutcome",
        "evidence",
    }:
        raise RuntimeError("Converged observer pending action is invalid.")
    action_id = _require_nonempty_string(value["actionId"], "pendingAction.actionId")
    report_seq = _require_positive_integer(
        value["reportSeq"], "pendingAction.reportSeq"
    )
    if report_seq != next_action_seq:
        raise RuntimeError("Converged observer pending report sequence is invalid.")
    cycle = _require_positive_integer(value["cycle"], "pendingAction.cycle")
    query_index = _require_nonnegative_integer(
        value["queryIndex"], "pendingAction.queryIndex"
    )
    if query_index != next_schedule_slot - 2:
        raise RuntimeError("Converged observer pending query index is invalid.")
    _require_nonempty_string(value["query"], "pendingAction.query")
    if value["method"] not in {"server", "global", "kad"}:
        raise RuntimeError("Converged observer pending action method is invalid.")
    _require_nonempty_string(value["reservedAtUtc"], "pendingAction.reservedAtUtc")
    _validate_diagnostic_runs(value["diagnosticRuns"])
    clients = value["clients"]
    if not isinstance(clients, dict) or set(clients) != set(_CLIENTS):
        raise RuntimeError("Converged observer pending clients are invalid.")
    for client in _CLIENTS:
        _validate_pending_client(clients[client], client)

    driver_outcome = value["driverOutcome"]
    if driver_outcome is None:
        if cycle != driver_cycles + 1 or next_cycle != cycle + 1:
            raise RuntimeError("Converged observer reserved cycle is discontinuous.")
        if next_schedule_slot != driver_cycles + connectivity_skips + 2:
            raise RuntimeError("Converged observer reserved schedule slot is discontinuous.")
    else:
        if not isinstance(driver_outcome, dict):
            raise RuntimeError("Converged observer pending driver outcome is invalid.")
        if (
            driver_outcome.get("cycle") != cycle
            or driver_outcome.get("actionId") != action_id
        ):
            raise RuntimeError(
                "Converged observer pending driver outcome is inconsistent."
            )
        if cycle != driver_cycles or next_cycle != cycle + 1:
            raise RuntimeError("Converged observer completed cycle is discontinuous.")
        if next_schedule_slot != driver_cycles + connectivity_skips + 1:
            raise RuntimeError("Converged observer completed schedule slot is discontinuous.")

    evidence = value["evidence"]
    if evidence is not None:
        if not isinstance(evidence, dict) or set(evidence) != {
            "status",
            "windowEndUtc",
        }:
            raise RuntimeError("Converged observer pending evidence is invalid.")
        if evidence["status"] != "pending":
            raise RuntimeError("Converged observer pending evidence status is invalid.")
        _require_nonempty_string(
            evidence["windowEndUtc"], "pendingAction.evidence.windowEndUtc"
        )
        if driver_outcome is None or not all(
            pending_client_is_terminal(value, client) for client in _CLIENTS
        ):
            raise RuntimeError("Converged observer pending evidence is premature.")


def _validate_diagnostic_runs(value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(_CLIENTS):
        raise RuntimeError("Converged observer diagnostic run identities are invalid.")
    for client in _CLIENTS:
        identity = value[client]
        if not isinstance(identity, dict) or set(identity) != {"processId", "runId"}:
            raise RuntimeError(
                f"Converged observer {client} diagnostic identity is invalid."
            )
        _require_positive_integer(
            identity["processId"], f"diagnosticRuns.{client}.processId"
        )
        _require_nonempty_string(identity["runId"], f"diagnosticRuns.{client}.runId")


def _validate_pending_client(value: object, client: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "create",
        "resultPoll",
        "results",
    }:
        raise RuntimeError(f"Converged observer pending {client} state is invalid.")
    create = value["create"]
    if create is not None:
        if not isinstance(create, dict) or set(create) != {
            "status",
            "preparedAtUtc",
            "completedAtUtc",
            "searchId",
            "error",
        }:
            raise RuntimeError(
                f"Converged observer pending {client} create outcome is invalid."
            )
        status = create["status"]
        if status not in {"prepared", "succeeded", "failed", "skipped"}:
            raise RuntimeError(
                f"Converged observer pending {client} create status is invalid."
            )
        prepared_at_utc = create["preparedAtUtc"]
        completed_at_utc = create["completedAtUtc"]
        search_id = create["searchId"]
        error = create["error"]
        if status == "prepared":
            _require_nonempty_string(
                prepared_at_utc,
                f"pendingAction.clients.{client}.preparedAtUtc",
            )
            if (
                completed_at_utc is not None
                or search_id is not None
                or error is not None
            ):
                raise RuntimeError(
                    f"Converged observer pending {client} prepared create is inconsistent."
                )
        elif status == "succeeded":
            _require_nonempty_string(
                prepared_at_utc,
                f"pendingAction.clients.{client}.preparedAtUtc",
            )
            _require_nonempty_string(
                completed_at_utc,
                f"pendingAction.clients.{client}.completedAtUtc",
            )
            _require_nonempty_string(
                search_id, f"pendingAction.clients.{client}.searchId"
            )
            if error is not None:
                raise RuntimeError(
                    f"Converged observer pending {client} successful create is inconsistent."
                )
        elif status == "failed":
            _require_nonempty_string(
                prepared_at_utc,
                f"pendingAction.clients.{client}.preparedAtUtc",
            )
            _require_nonempty_string(
                completed_at_utc,
                f"pendingAction.clients.{client}.completedAtUtc",
            )
            if search_id is not None or error is None:
                raise RuntimeError(
                    f"Converged observer pending {client} failed create is inconsistent."
                )
        elif (
            prepared_at_utc is not None
            or search_id is not None
            or completed_at_utc is None
            or error is None
        ):
            raise RuntimeError(
                f"Converged observer pending {client} skipped create is inconsistent."
            )
        if completed_at_utc is not None:
            _require_nonempty_string(
                completed_at_utc,
                f"pendingAction.clients.{client}.completedAtUtc",
            )
        _validate_optional_error(error)

    result_poll = value["resultPoll"]
    if result_poll is not None:
        if not isinstance(create, dict) or create.get("status") != "succeeded":
            raise RuntimeError(
                f"Converged observer pending {client} result poll lacks a search ID."
            )
        if value["results"] is not None:
            raise RuntimeError(
                f"Converged observer pending {client} result poll is already terminal."
            )
        _validate_search_results_poll(result_poll, client)
        poll_started = _parse_utc_timestamp(
            result_poll["startedAtUtc"],
            f"pendingAction.clients.{client}.resultPoll.startedAtUtc",
        )
        create_completed = _parse_utc_timestamp(
            create["completedAtUtc"],
            f"pendingAction.clients.{client}.create.completedAtUtc",
        )
        if poll_started < create_completed:
            raise RuntimeError(
                f"Converged observer pending {client} result poll predates creation."
            )

    results = value["results"]
    if results is None:
        return
    if not isinstance(results, dict) or set(results) != {
        "completedAtUtc",
        "completed",
        "returnedCount",
        "totalCount",
        "error",
        "poll",
    }:
        raise RuntimeError(
            f"Converged observer pending {client} result outcome is invalid."
        )
    if not isinstance(create, dict) or create.get("status") != "succeeded":
        raise RuntimeError(
            f"Converged observer pending {client} results lack a search ID."
        )
    completed_at = _parse_utc_timestamp(
        results["completedAtUtc"],
        f"pendingAction.clients.{client}.completedAtUtc",
    )
    create_completed = _parse_utc_timestamp(
        create["completedAtUtc"],
        f"pendingAction.clients.{client}.create.completedAtUtc",
    )
    if completed_at < create_completed:
        raise RuntimeError(
            f"Converged observer pending {client} results predate creation."
        )
    if not isinstance(results["completed"], bool):
        raise RuntimeError(
            f"Converged observer pending {client} completion is invalid."
        )
    returned_count = results["returnedCount"]
    total_count = results["totalCount"]
    if (returned_count is None) != (total_count is None):
        raise RuntimeError(
            f"Converged observer pending {client} result counts are incomplete."
        )
    if total_count is not None:
        _require_nonnegative_integer(
            returned_count, f"pendingAction.clients.{client}.returnedCount"
        )
        _require_nonnegative_integer(
            total_count, f"pendingAction.clients.{client}.totalCount"
        )
        if total_count < returned_count:
            raise RuntimeError(
                f"Converged observer pending {client} result total is invalid."
            )
    _validate_optional_error(results["error"])
    if total_count is None and results["error"] is None:
        raise RuntimeError(f"Converged observer pending {client} results are empty.")
    if results["completed"] and (total_count is None or results["error"] is not None):
        raise RuntimeError(
            f"Converged observer pending {client} completion is inconsistent."
        )
    _validate_terminal_search_results_poll(
        results["poll"],
        client=client,
        completed=results["completed"],
        completed_at=completed_at,
        create_completed_at=create_completed,
        total_count=total_count,
        terminal_error=results["error"],
    )


def _validate_search_results_poll(value: object, client: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "startedAtUtc",
        "deadlineUtc",
        "nextAttemptAtUtc",
        "attempts",
        "errorCount",
        "latestAttemptAtUtc",
        "lastObservedReturnedCount",
        "lastObservedTotalCount",
        "lastAttemptError",
        "latestError",
    }:
        raise RuntimeError(
            f"Converged observer pending {client} result poll is invalid."
        )
    started = _parse_utc_timestamp(
        value["startedAtUtc"],
        f"pendingAction.clients.{client}.resultPoll.startedAtUtc",
    )
    deadline = _parse_utc_timestamp(
        value["deadlineUtc"],
        f"pendingAction.clients.{client}.resultPoll.deadlineUtc",
    )
    next_attempt = _parse_utc_timestamp(
        value["nextAttemptAtUtc"],
        f"pendingAction.clients.{client}.resultPoll.nextAttemptAtUtc",
    )
    if deadline <= started or next_attempt < started or next_attempt > deadline:
        raise RuntimeError(
            f"Converged observer pending {client} result poll schedule is invalid."
        )
    attempts = _require_nonnegative_integer(
        value["attempts"],
        f"pendingAction.clients.{client}.resultPoll.attempts",
    )
    error_count = _require_nonnegative_integer(
        value["errorCount"],
        f"pendingAction.clients.{client}.resultPoll.errorCount",
    )
    if error_count > attempts:
        raise RuntimeError(
            f"Converged observer pending {client} result poll errors are invalid."
        )
    latest_attempt_at_utc = value["latestAttemptAtUtc"]
    last_observed_returned_count = value["lastObservedReturnedCount"]
    last_observed_total_count = value["lastObservedTotalCount"]
    last_attempt_error = value["lastAttemptError"]
    latest_error = value["latestError"]
    if (last_observed_returned_count is None) != (last_observed_total_count is None):
        raise RuntimeError(
            f"Converged observer pending {client} result poll counts are incomplete."
        )
    if last_observed_total_count is not None:
        _require_nonnegative_integer(
            last_observed_returned_count,
            f"pendingAction.clients.{client}.resultPoll.lastObservedReturnedCount",
        )
        _require_nonnegative_integer(
            last_observed_total_count,
            f"pendingAction.clients.{client}.resultPoll.lastObservedTotalCount",
        )
        if last_observed_total_count < last_observed_returned_count:
            raise RuntimeError(
                f"Converged observer pending {client} result poll total is invalid."
            )
    _validate_optional_error(last_attempt_error)
    _validate_optional_error(latest_error)
    if (error_count == 0) != (latest_error is None):
        raise RuntimeError(
            f"Converged observer pending {client} result poll error history is invalid."
        )
    if last_attempt_error is not None and last_attempt_error != latest_error:
        raise RuntimeError(
            f"Converged observer pending {client} latest result poll error is invalid."
        )
    if attempts == 0:
        if (
            error_count != 0
            or latest_attempt_at_utc is not None
            or last_observed_total_count is not None
            or last_attempt_error is not None
            or latest_error is not None
            or next_attempt != started
        ):
            raise RuntimeError(
                f"Converged observer pending {client} unstarted result poll is inconsistent."
            )
        return
    if attempts == error_count and (
        last_observed_total_count is not None or last_attempt_error is None
    ):
        raise RuntimeError(
            f"Converged observer pending {client} result poll success history is invalid."
        )
    latest_attempt = _parse_utc_timestamp(
        latest_attempt_at_utc,
        f"pendingAction.clients.{client}.resultPoll.latestAttemptAtUtc",
    )
    if (
        latest_attempt < started
        or latest_attempt >= next_attempt
        or latest_attempt >= deadline
        or (last_observed_total_count is None and last_attempt_error is None)
    ):
        raise RuntimeError(
            f"Converged observer pending {client} result poll progress is invalid."
        )


def _validate_terminal_search_results_poll(
    value: object,
    *,
    client: str,
    completed: bool,
    completed_at: datetime,
    create_completed_at: datetime,
    total_count: int | None,
    terminal_error: object,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "startedAtUtc",
        "deadlineUtc",
        "attempts",
        "errorCount",
        "latestAttemptAtUtc",
        "latestError",
        "termination",
    }:
        raise RuntimeError(
            f"Converged observer pending {client} terminal result poll is invalid."
        )
    started = _parse_utc_timestamp(
        value["startedAtUtc"],
        f"pendingAction.clients.{client}.results.poll.startedAtUtc",
    )
    deadline = _parse_utc_timestamp(
        value["deadlineUtc"],
        f"pendingAction.clients.{client}.results.poll.deadlineUtc",
    )
    if (
        deadline <= started
        or started < create_completed_at
        or completed_at < started
    ):
        raise RuntimeError(
            f"Converged observer pending {client} terminal result poll schedule is invalid."
        )
    attempts = _require_nonnegative_integer(
        value["attempts"],
        f"pendingAction.clients.{client}.results.poll.attempts",
    )
    error_count = _require_nonnegative_integer(
        value["errorCount"],
        f"pendingAction.clients.{client}.results.poll.errorCount",
    )
    if error_count > attempts:
        raise RuntimeError(
            f"Converged observer pending {client} terminal result poll errors are invalid."
        )
    latest_error = value["latestError"]
    _validate_optional_error(latest_error)
    if (error_count == 0) != (latest_error is None):
        raise RuntimeError(
            f"Converged observer pending {client} terminal error history is invalid."
        )
    latest_attempt_at_utc = value["latestAttemptAtUtc"]
    latest_attempt = None
    if latest_attempt_at_utc is not None:
        latest_attempt = _parse_utc_timestamp(
            latest_attempt_at_utc,
            f"pendingAction.clients.{client}.results.poll.latestAttemptAtUtc",
        )
    if attempts == 0:
        if latest_attempt is not None:
            raise RuntimeError(
                f"Converged observer pending {client} terminal result poll is inconsistent."
            )
    elif (
        latest_attempt is None
        or latest_attempt < started
        or latest_attempt > completed_at
    ):
        raise RuntimeError(
            f"Converged observer pending {client} terminal result poll attempt is invalid."
        )
    termination = value["termination"]
    if termination not in {"completed", "deadline", "expired"}:
        raise RuntimeError(
            f"Converged observer pending {client} terminal result poll reason is invalid."
        )
    if total_count is not None and attempts == error_count:
        raise RuntimeError(
            f"Converged observer pending {client} terminal poll success history is invalid."
        )
    if completed != (termination == "completed"):
        raise RuntimeError(
            f"Converged observer pending {client} terminal completion is inconsistent."
        )
    if termination == "completed":
        if attempts == 0 or latest_attempt != completed_at:
            raise RuntimeError(
                f"Converged observer pending {client} completed poll is inconsistent."
            )
    elif termination == "deadline":
        if (
            attempts == 0
            or latest_attempt != completed_at
            or completed_at < deadline
            or (terminal_error is not None and terminal_error != latest_error)
        ):
            raise RuntimeError(
                f"Converged observer pending {client} deadline poll is inconsistent."
            )
    elif (
        completed_at < deadline
        or (latest_attempt is not None and latest_attempt >= deadline)
    ):
        raise RuntimeError(
            f"Converged observer pending {client} expired poll is inconsistent."
        )


def _require_pending_action(state: dict[str, Any]) -> dict[str, Any]:
    pending = state["pendingAction"]
    if not isinstance(pending, dict):
        raise RuntimeError("Converged observer has no pending action.")
    return pending


def _pending_client(pending: dict[str, Any], client: str) -> dict[str, Any]:
    if client not in _CLIENTS:
        raise ValueError("client must be 'rust' or 'mfc'.")
    return pending["clients"][client]


def pending_client_is_terminal(pending: dict[str, Any], client: str) -> bool:
    """Returns whether one pending client needs no further public REST work."""

    client_state = _pending_client(pending, client)
    create = client_state["create"]
    if not isinstance(create, dict):
        return False
    if create.get("status") in {"failed", "skipped"}:
        return True
    return create.get("status") == "succeeded" and client_state["results"] is not None


def _validate_optional_error(value: object) -> None:
    if value is not None and not isinstance(value, dict):
        raise RuntimeError("Converged observer exact error is invalid.")


def _validate_sha256(value: object, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"{name} must be a lowercase SHA-256 digest.")


def _empty_retention() -> dict[str, Any]:
    return {
        "seen": 0,
        "retained": 0,
        "omitted": 0,
        "retainedBytes": 0,
        "latestFile": None,
    }


def _validate_retention(value: object, maximum_seen: int) -> None:
    if not isinstance(value, dict) or set(value) != {
        "seen",
        "retained",
        "omitted",
        "retainedBytes",
        "latestFile",
    }:
        raise RuntimeError("Converged observer retention entry is invalid.")
    for name in ("seen", "retained", "omitted", "retainedBytes"):
        _require_nonnegative_integer(value[name], f"retention.{name}")
    if value["seen"] > maximum_seen or value["retained"] > value["seen"]:
        raise RuntimeError("Converged observer retention counts are invalid.")
    if value["omitted"] != value["seen"] - value["retained"]:
        raise RuntimeError("Converged observer retention omission count is invalid.")
    latest_file = value["latestFile"]
    if latest_file is not None:
        _require_nonempty_string(latest_file, "retention.latestFile")


def _validate_histogram(value: object, buckets: tuple[str, ...], total: int) -> None:
    if not isinstance(value, dict) or set(value) != set(buckets):
        raise RuntimeError("Converged observer histogram is invalid.")
    for name in buckets:
        _require_nonnegative_integer(value[name], f"histograms.{name}")
    if sum(value.values()) != total:
        raise RuntimeError("Converged observer histogram total is inconsistent.")


def _validate_parity_gate(value: object) -> None:
    fields = {
        "targets",
        "successful",
        "retryable",
        "confirmedDivergences",
        "status",
        "greenAtUtc",
        "firstConfirmedDivergence",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError("Converged observer parity gate is invalid.")
    for field in ("targets", "successful", "retryable"):
        counts = value[field]
        if not isinstance(counts, dict) or set(counts) != set(PARITY_METHODS):
            raise RuntimeError(
                f"Converged observer parity gate {field} counts are invalid."
            )
        for method, count in counts.items():
            if field == "targets":
                _require_positive_integer(count, f"parityGate.{field}.{method}")
            else:
                _require_nonnegative_integer(count, f"parityGate.{field}.{method}")
    divergence_count = _require_nonnegative_integer(
        value["confirmedDivergences"],
        "parityGate.confirmedDivergences",
    )
    status = value["status"]
    if status not in {"pending", "green", "failed"}:
        raise RuntimeError("Converged observer parity gate status is invalid.")
    _validate_optional_utc_timestamp(value["greenAtUtc"], "parityGate.greenAtUtc")
    target_reached = all(
        value["successful"][method] >= value["targets"][method]
        for method in PARITY_METHODS
    )
    receipt = value["firstConfirmedDivergence"]
    if status == "pending":
        if target_reached or value["greenAtUtc"] is not None or divergence_count:
            raise RuntimeError("Converged observer pending parity gate is inconsistent.")
        if receipt is not None:
            raise RuntimeError("Converged observer pending parity gate receipt is invalid.")
        return
    if status == "green":
        if not target_reached or value["greenAtUtc"] is None or divergence_count:
            raise RuntimeError("Converged observer green parity gate is inconsistent.")
        if receipt is not None:
            raise RuntimeError("Converged observer green parity gate receipt is invalid.")
        return
    if divergence_count <= 0 or not isinstance(receipt, dict):
        raise RuntimeError("Converged observer failed parity gate receipt is missing.")
    receipt_fields = {
        "seq",
        "actionId",
        "cycle",
        "method",
        "observedUtc",
        "reportSha256",
    }
    if set(receipt) != receipt_fields:
        raise RuntimeError("Converged observer parity divergence receipt is invalid.")
    _require_positive_integer(receipt["seq"], "parityGate.receipt.seq")
    _require_nonempty_string(receipt["actionId"], "parityGate.receipt.actionId")
    _require_positive_integer(receipt["cycle"], "parityGate.receipt.cycle")
    if receipt["method"] not in PARITY_METHODS:
        raise RuntimeError("Converged observer parity divergence method is invalid.")
    _parse_utc_timestamp(receipt["observedUtc"], "parityGate.receipt.observedUtc")
    _validate_sha256(receipt["reportSha256"], "parityGate.receipt.reportSha256")


def _action_observed_utc(report: dict[str, Any]) -> str:
    window = report.get("window")
    if isinstance(window, dict) and isinstance(window.get("t1"), str) and window["t1"]:
        return window["t1"]
    observed = report.get("observed")
    if isinstance(observed, dict):
        values = sorted(
            value for value in observed.values() if isinstance(value, str) and value
        )
        if values:
            return values[-1]
    raise RuntimeError("Converged observer action observed time is invalid.")


def _update_observed(state: dict[str, Any], observed_utc: str) -> None:
    state["observed"]["firstUtc"] = state["observed"]["firstUtc"] or observed_utc
    state["observed"]["latestUtc"] = observed_utc


def _bucket(value: object, buckets: tuple[str, ...], fallback: str) -> str:
    normalized = str(value).strip().lower() if value is not None else ""
    return normalized if normalized in buckets else fallback


def _append_bounded(
    items: list[dict[str, Any]], item: dict[str, Any], limit: int
) -> None:
    items.append(copy.deepcopy(item))
    del items[:-limit]


def _validate_optional_timestamp(value: object) -> None:
    if value is not None:
        _require_nonempty_string(value, "timestamp")


def _validate_optional_utc_timestamp(value: object, name: str) -> None:
    if value is None:
        return
    _parse_utc_timestamp(value, name)


def _parse_utc_timestamp(value: object, name: str) -> datetime:
    text = _require_nonempty_string(value, name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError(f"{name} must be an ISO-8601 UTC timestamp.") from error
    if parsed.utcoffset() != timedelta(0):
        raise RuntimeError(f"{name} must be an ISO-8601 UTC timestamp.")
    return parsed


def _require_nonempty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{name} must be a non-empty string.")
    return value


def _require_positive_integer(value: object, name: str) -> int:
    integer = _require_nonnegative_integer(value, name)
    if integer == 0:
        raise RuntimeError(f"{name} must be greater than zero.")
    return integer


def _require_nonnegative_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"{name} must be a non-negative integer.")
    return value
