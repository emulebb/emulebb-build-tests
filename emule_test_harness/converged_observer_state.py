"""Bounded cumulative state for the converged diagnostics observer."""

from __future__ import annotations

import copy
import json
from typing import Any

from .soak_storage import PersistedArtifact

SCHEMA = "emulebb-build-tests.converged-observer-state.v1"
_TOP_LEVEL_FIELDS = {
    "schema",
    "campaignId",
    "limits",
    "observed",
    "nextActionSeq",
    "totals",
    "histograms",
    "checkpoints",
    "driver",
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
    "other",
)
_TOTAL_BUCKETS = {
    "coverage-parity": "coverageParity",
    "divergence": "divergence",
    "one-sided": "oneSided",
    "no-traffic": "noTraffic",
    "unpaired": "unpaired",
    "other": "other",
}
_KIND_BUCKETS = ("search", "download", "other")
_METHOD_BUCKETS = ("server", "global", "kad", "automatic", "none", "other")


def new_state(
    campaign_id: str,
    *,
    recent_action_limit: int,
    recent_anomaly_limit: int,
) -> dict[str, Any]:
    """Returns one empty, strictly bounded cumulative observer state."""

    _require_nonempty_string(campaign_id, "campaign_id")
    _require_positive_integer(recent_action_limit, "recent_action_limit")
    _require_positive_integer(recent_anomaly_limit, "recent_anomaly_limit")
    return {
        "schema": SCHEMA,
        "campaignId": campaign_id,
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
            "other": 0,
        },
        "histograms": {
            "kind": {bucket: 0 for bucket in _KIND_BUCKETS},
            "method": {bucket: 0 for bucket in _METHOD_BUCKETS},
            "verdict": {bucket: 0 for bucket in _VERDICT_BUCKETS},
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


def record_driver_cycle(state: dict[str, Any], cycle: dict[str, Any]) -> dict[str, Any]:
    """Records cumulative driver-cycle outcomes without retaining an unbounded list."""

    updated = validate_state(state)
    if not isinstance(cycle, dict):
        raise RuntimeError("Converged observer driver cycle is invalid.")
    updated["driver"]["cycles"] += 1
    if cycle.get("error"):
        updated["driver"]["cycleErrors"] += 1
    download = cycle.get("download")
    if isinstance(download, dict) and download.get("scheduled") is True:
        updated["driver"]["downloadsScheduled"] += 1
    updated["driver"]["latestCycle"] = copy.deepcopy(cycle)
    return updated


def record_connectivity_skip(
    state: dict[str, Any], skip: dict[str, Any]
) -> dict[str, Any]:
    """Records one skipped driver cycle without retaining an unbounded list."""

    updated = validate_state(state)
    if not isinstance(skip, dict):
        raise RuntimeError("Converged observer connectivity skip is invalid.")
    updated["driver"]["connectivitySkips"] += 1
    updated["driver"]["latestConnectivitySkip"] = copy.deepcopy(skip)
    return updated


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
