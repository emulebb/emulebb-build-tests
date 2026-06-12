"""Diagnostic log analysis helpers for eMuleBB instrumented builds."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BAD_PEER_LOG_NAME = "emulebb-diagnostics-bad-peer.log"
UPLOAD_SLOT_LOG_NAME = "emulebb-diagnostics-upload-slot.log"
DOWNLOAD_SLOT_LOG_NAME = "emulebb-diagnostics-download-slot.log"


def analyze_diagnostic_logs(logs_dir: Path, *, window_minutes: float = 15.0, top_count: int = 12) -> dict[str, Any]:
    """Analyzes eMuleBB diagnostics logs in one profile log directory."""

    logs_dir = logs_dir.expanduser().resolve()
    if not logs_dir.is_dir():
        raise RuntimeError(f"Diagnostics log directory does not exist: {logs_dir}")

    bad_peer_paths = _diagnostic_log_paths(logs_dir, BAD_PEER_LOG_NAME)
    bad_peer_events = _read_bad_peer_events(bad_peer_paths)
    latest = max((_parse_utc(event.get("ts_utc")) for event in bad_peer_events), default=None)
    cutoff = latest - timedelta(minutes=window_minutes) if latest else None
    recent_events = [
        event
        for event in bad_peer_events
        if cutoff is None or (_parse_utc(event.get("ts_utc")) or datetime.min.replace(tzinfo=UTC)) >= cutoff
    ]

    no_request_events = [event for event in recent_events if str(event.get("event", "")).startswith("upload_no_request")]
    repeat_block_events = [
        event for event in recent_events if event.get("event") == "upload_repeat_block_request_observed"
    ]
    repeat_file_events = [
        event for event in recent_events if event.get("event") == "upload_repeat_file_request_observed"
    ]
    ban_events = [event for event in recent_events if _is_ban_event(event)]
    ban_decisions = _ban_decision_events(ban_events)
    ban_scope_counts = Counter(_ban_scope(event) for event in ban_decisions)
    ban_scope_counts.pop("", None)

    return {
        "logs_dir": str(logs_dir),
        "bad_peer": {
            "total_events": len(bad_peer_events),
            "log_files": len(bad_peer_paths),
            "latest_utc": latest.isoformat().replace("+00:00", "Z") if latest else None,
            "window_start_utc": cutoff.isoformat().replace("+00:00", "Z") if cutoff else None,
            "window_minutes": window_minutes,
            "recent_events": len(recent_events),
            "cooldowns": sum(1 for event in recent_events if event.get("action") == "cooldown"),
            "bans": sum(
                1 for event in recent_events if event.get("action") == "ban" or "ban" in str(event.get("event", ""))
            ),
            "ban_events": len(ban_events),
            "ban_decisions": len(ban_decisions),
            "hash_bans": ban_scope_counts.get("hash", 0),
            "ip_bans": ban_scope_counts.get("ip", 0) + ban_scope_counts.get("both", 0),
            "cooldown_only": sum(1 for event in recent_events if event.get("action") == "cooldown"),
            "productive_no_request": sum(
                1 for event in no_request_events if _mapping(event.get("evidence")).get("productive") is True
            ),
            "unproductive_no_request": sum(
                1 for event in no_request_events if _mapping(event.get("evidence")).get("productive") is False
            ),
            "repeat_block_requests": len(repeat_block_events),
            "repeat_file_churn": len(repeat_file_events),
            "top_events": _counter_rows(Counter(str(event.get("event", "")) for event in recent_events), top_count),
            "top_reasons": _counter_rows(Counter(str(event.get("reason", "")) for event in recent_events), top_count),
            "top_peers": _counter_rows(Counter(_peer_key(event) for event in recent_events if _peer_key(event)), top_count),
            "ban_scopes": _counter_rows(ban_scope_counts, top_count),
            "top_cooldown_rejections": _peer_event_rows(recent_events, top_count, "upload_queued_request_rejected"),
            "top_repeat_block_peers": _peer_event_rows(repeat_block_events, top_count),
            "top_repeat_file_peers": _peer_event_rows(repeat_file_events, top_count),
            "top_unproductive_no_request_peers": _peer_event_rows(
                no_request_events,
                top_count,
                productive=False,
            ),
            "top_productive_no_request_peers": _peer_event_rows(
                no_request_events,
                top_count,
                productive=True,
            ),
            "top_banned_peers": _top_banned_peer_rows(recent_events, top_count),
            "max_strikes": _max_strike_rows(recent_events, top_count),
        },
        "upload_slot": _analyze_summary_log(
            _diagnostic_log_paths(logs_dir, UPLOAD_SLOT_LOG_NAME),
            "UploadSlotDiagnostics: summary ",
        ),
        "download_slot": _analyze_summary_log(
            _diagnostic_log_paths(logs_dir, DOWNLOAD_SLOT_LOG_NAME),
            "DownloadSlotDiagnostics: summary ",
        ),
    }


def format_diagnostic_log_analysis(analysis: dict[str, Any]) -> str:
    """Formats diagnostic log analysis for operator-facing CLI output."""

    bad_peer = analysis["bad_peer"]
    lines = [
        f"Diagnostics logs: {analysis['logs_dir']}",
        (
            "Bad peer window: "
            f"{bad_peer['recent_events']} events in {bad_peer['window_minutes']:g} min "
            f"(cooldowns={bad_peer['cooldowns']}, cooldown_only={bad_peer['cooldown_only']}, "
            f"ban_events={bad_peer['ban_events']}, ban_decisions={bad_peer['ban_decisions']}, "
            f"hash_bans={bad_peer['hash_bans']}, ip_bans={bad_peer['ip_bans']}, "
            f"productive_no_request={bad_peer['productive_no_request']}, "
            f"unproductive_no_request={bad_peer['unproductive_no_request']}, "
            f"repeat_block_requests={bad_peer['repeat_block_requests']}, "
            f"repeat_file_churn={bad_peer['repeat_file_churn']})"
        ),
    ]
    if bad_peer["latest_utc"]:
        lines.append(f"Latest bad-peer event: {bad_peer['latest_utc']}")
    lines.extend(_format_rows("Top bad-peer events", bad_peer["top_events"]))
    lines.extend(_format_rows("Top bad-peer reasons", bad_peer["top_reasons"]))
    lines.extend(_format_rows("Top bad-peer identities", bad_peer["top_peers"]))
    lines.extend(_format_rows("Ban scopes", bad_peer["ban_scopes"]))
    lines.extend(_format_peer_event_rows("Cooldown re-entry rejections", bad_peer["top_cooldown_rejections"]))
    lines.extend(_format_peer_event_rows("Top repeated upload block requests", bad_peer["top_repeat_block_peers"]))
    lines.extend(_format_peer_event_rows("Top repeated same-file upload churn", bad_peer["top_repeat_file_peers"]))
    lines.extend(_format_peer_event_rows("Top unproductive no-request peers", bad_peer["top_unproductive_no_request_peers"]))
    lines.extend(_format_peer_event_rows("Top productive no-request peers", bad_peer["top_productive_no_request_peers"]))
    lines.extend(_format_banned_peer_rows(bad_peer["top_banned_peers"]))
    lines.extend(_format_strike_rows(bad_peer["max_strikes"]))
    lines.extend(_format_summary("Latest upload summary", analysis["upload_slot"]))
    lines.extend(_format_summary("Latest download summary", analysis["download_slot"]))
    return "\n".join(lines)


def _diagnostic_log_paths(logs_dir: Path, log_name: str) -> list[Path]:
    active_path = logs_dir / log_name
    stem = active_path.stem
    suffix = active_path.suffix
    paths = [path for path in logs_dir.glob(f"{stem}-*{suffix}") if path.is_file()]
    if active_path.is_file():
        paths.append(active_path)
    return sorted(paths, key=lambda path: (path.stat().st_mtime, path.name))


def _read_bad_peer_events(paths: list[Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    events.append(payload)
    return events


def _analyze_summary_log(paths: list[Path], prefix: str) -> dict[str, Any]:
    if not paths:
        return {"exists": False, "last_summary": None, "log_files": 0}
    last_summary: dict[str, Any] | None = None
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith(prefix):
                    last_summary = _parse_key_value_summary(line.removeprefix(prefix))
    return {"exists": True, "last_summary": last_summary, "log_files": len(paths)}


def _parse_key_value_summary(text: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for token in text.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        values[key] = _parse_scalar(value)
    return values


def _parse_scalar(value: str) -> int | float | str:
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _counter_rows(counter: Counter[str], top_count: int) -> list[dict[str, Any]]:
    return [{"count": count, "name": name} for name, count in counter.most_common(top_count) if name]


def _peer_key(event: dict[str, Any]) -> str:
    peer = _mapping(event.get("peer"))
    return " ".join(
        str(peer.get(key, "")).strip()
        for key in ("user_hash", "address", "client_software", "user_name")
        if str(peer.get(key, "")).strip()
    )


def _is_ban_event(event: dict[str, Any]) -> bool:
    event_name = str(event.get("event", ""))
    return event.get("action") == "ban" or event_name.endswith("_ban") or event_name == "client_ban"


def _ban_scope(event: dict[str, Any]) -> str:
    evidence = _mapping(event.get("evidence"))
    for value in (event.get("scope"), evidence.get("scope"), evidence.get("ban_scope"), evidence.get("key_type")):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"hash", "ip", "both"}:
                return normalized
    return ""


def _ban_decision_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    policy_bans = [event for event in events if event.get("event") != "client_ban"]
    policy_ban_peers = {_peer_key(event) for event in policy_bans if _peer_key(event)}
    standalone_client_bans = [
        event
        for event in events
        if event.get("event") == "client_ban" and _peer_key(event) not in policy_ban_peers
    ]
    return [*policy_bans, *standalone_client_bans]


def _peer_event_rows(
    events: list[dict[str, Any]],
    top_count: int,
    event_name: str | None = None,
    *,
    productive: bool | None = None,
) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for event in events:
        if event_name is not None and event.get("event") != event_name:
            continue
        if productive is not None and _mapping(event.get("evidence")).get("productive") is not productive:
            continue
        peer_key = _peer_key(event)
        if peer_key:
            counter[peer_key] += 1
    return _counter_rows(counter, top_count)


def _file_key(event: dict[str, Any]) -> str:
    file_payload = _mapping(event.get("file"))
    file_hash = str(file_payload.get("hash") or "").strip()
    file_name = str(file_payload.get("name") or "").strip()
    return file_hash or file_name


def _top_banned_peer_rows(events: list[dict[str, Any]], top_count: int) -> list[dict[str, Any]]:
    rows_by_peer: dict[str, dict[str, Any]] = {}
    events_by_peer: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        peer_key = _peer_key(event)
        if peer_key:
            events_by_peer[peer_key].append(event)

    for peer_key, peer_events in events_by_peer.items():
        peer_bans = [event for event in peer_events if _is_ban_event(event)]
        if not peer_bans:
            continue

        timestamps = [_parse_utc(event.get("ts_utc")) for event in peer_events]
        timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
        strikes = [
            evidence["strikes"]
            for evidence in (_mapping(event.get("evidence")) for event in peer_events)
            if isinstance(evidence.get("strikes"), int)
        ]
        file_keys = {_file_key(event) for event in peer_events if _file_key(event)}
        ban_scopes = Counter(_ban_scope(event) for event in peer_bans)
        ban_scopes.pop("", None)
        ever_uploaded_payload = any(
            int(_mapping(event.get("peer")).get("session_up") or 0) > 0
            or _mapping(event.get("evidence")).get("productive") is True
            for event in peer_events
        )
        rows_by_peer[peer_key] = {
            "count": len(peer_bans),
            "name": peer_key,
            "first_strike_utc": min(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None,
            "last_strike_utc": max(timestamps).isoformat().replace("+00:00", "Z") if timestamps else None,
            "max_strikes": max(strikes) if strikes else None,
            "files_touched": len(file_keys),
            "ever_uploaded_payload": ever_uploaded_payload,
            "scope": ban_scopes.most_common(1)[0][0] if ban_scopes else "",
        }

    return sorted(
        rows_by_peer.values(),
        key=lambda row: (int(row["count"]), int(row["max_strikes"] or 0)),
        reverse=True,
    )[:top_count]


def _max_strike_rows(events: list[dict[str, Any]], top_count: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events:
        evidence = _mapping(event.get("evidence"))
        strikes = evidence.get("strikes")
        if not isinstance(strikes, int):
            continue
        peer = _mapping(event.get("peer"))
        rows.append(
            {
                "strikes": strikes,
                "cooldown_seconds": evidence.get("cooldown_seconds"),
                "threshold": evidence.get("threshold"),
                "ip": peer.get("address"),
                "hash": peer.get("user_hash"),
                "client": peer.get("client_software"),
                "event": event.get("event"),
            }
        )
    return sorted(rows, key=lambda row: int(row["strikes"]), reverse=True)[:top_count]


def _format_rows(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"{title}:"]
    if not rows:
        return [*lines, "  none"]
    lines.extend(f"  {row['count']:>5}  {row['name']}" for row in rows)
    return lines


def _format_peer_event_rows(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"{title}:"]
    if not rows:
        return [*lines, "  none"]
    lines.extend(f"  {row['count']:>5}  {row['name']}" for row in rows)
    return lines


def _format_banned_peer_rows(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["Top banned peers:"]
    if not rows:
        return [*lines, "  none"]
    for row in rows:
        lines.append(
            "  "
            f"{row['count']:>5} bans "
            f"scope={row['scope'] or 'unknown'} "
            f"max_strikes={row['max_strikes'] if row['max_strikes'] is not None else 'n/a'} "
            f"files={row['files_touched']} "
            f"uploaded_payload={str(row['ever_uploaded_payload']).lower()} "
            f"first={row['first_strike_utc'] or 'n/a'} "
            f"last={row['last_strike_utc'] or 'n/a'} "
            f"{row['name']}"
        )
    return lines


def _format_strike_rows(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["Max repeat-offender strikes:"]
    if not rows:
        return [*lines, "  none"]
    for row in rows:
        lines.append(
            "  "
            f"{row['strikes']}/{row['threshold']} "
            f"cooldown={row['cooldown_seconds']}s "
            f"{row['ip']} {row['client']} {row['hash']} {row['event']}"
        )
    return lines


def _format_summary(title: str, payload: dict[str, Any]) -> list[str]:
    summary = payload.get("last_summary")
    if not summary:
        return [f"{title}: none"]
    interesting = [
        "uploadSlots",
        "activeSlots",
        "waitingCooldown",
        "waitingNoRequestCooldown",
        "activeZeroRate",
        "activeNoRequest",
        "activeNoRequestNeverAccepted",
        "toNetworkBytesPerSec",
        "datarateBytesPerSec",
        "files",
        "readyFiles",
        "activeFiles",
        "sourceStarvedReadyFiles",
        "downloadingSources",
        "onQueueSources",
        "duplicateZeroWriteSources",
        "duplicateZeroWritePackets",
        "bufferedReadyBytes",
        "bufferedPendingBytes",
        "asyncWriteFiles",
    ]
    parts = [f"{key}={summary[key]}" for key in interesting if key in summary]
    return [f"{title}: " + (" ".join(parts) if parts else json.dumps(summary, sort_keys=True))]


UPLOAD_SLOT_SUMMARY_PREFIX = "UploadSlotDiagnostics: summary "


def read_summary_series(logs_dir: Path, log_name: str, prefix: str) -> list[dict[str, Any]]:
    """Returns every summary sample (full time series) from a summary diagnostics log."""

    samples: list[dict[str, Any]] = []
    for path in _diagnostic_log_paths(logs_dir.expanduser().resolve(), log_name):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith(prefix):
                    samples.append(_parse_key_value_summary(line.removeprefix(prefix)))
    return samples


def analyze_upload_bandwidth(
    logs_dir: Path,
    *,
    tail: int = 12,
    budget_bytes_per_sec: int | None = None,
    target_utilization: float = 0.98,
) -> dict[str, Any]:
    """Analyzes upload-slot summaries for upload-bandwidth utilization vs the configured budget.

    The goal metric is steady-state upload throughput relative to the configured upload
    budget. The verdict explains why utilization sits where it does: publish ramp,
    eligible-demand starvation, slot-promotion cadence, or slow-slot reclamation.
    """

    logs_dir = logs_dir.expanduser().resolve()
    samples = read_summary_series(logs_dir, UPLOAD_SLOT_LOG_NAME, UPLOAD_SLOT_SUMMARY_PREFIX)
    if not samples:
        return {"exists": False, "logs_dir": str(logs_dir), "samples": 0}

    latest = samples[-1]
    budget = int(budget_bytes_per_sec or _summary_int(latest, "configuredBudgetBytesPerSec"))
    rate = _summary_int(latest, "toNetworkBytesPerSec") or _summary_int(latest, "datarateBytesPerSec")
    active = _summary_int(latest, "activeSlots")
    cap = _summary_int(latest, "effectiveSlotCap")
    waiting = _summary_int(latest, "waiting")
    eligible = _summary_int(latest, "waitingEligible")
    underfilled = bool(_summary_int(latest, "underfilled"))
    slow = _summary_int(latest, "slowTracking")
    pending = _summary_int(latest, "ed2kPendingFiles")
    utilization = (rate / budget) if budget else None
    target_rate = int(budget * target_utilization) if budget else None

    verdict, reason = _upload_bandwidth_verdict(
        utilization=utilization,
        target_utilization=target_utilization,
        active=active,
        cap=cap,
        waiting=waiting,
        eligible=eligible,
        underfilled=underfilled,
        pending_publish=pending,
    )
    return {
        "exists": True,
        "logs_dir": str(logs_dir),
        "samples": len(samples),
        "budget_bytes_per_sec": budget,
        "rate_bytes_per_sec": rate,
        "utilization": utilization,
        "target_utilization": target_utilization,
        "target_rate_bytes_per_sec": target_rate,
        "target_gap_bytes_per_sec": (target_rate - rate) if target_rate is not None else None,
        "active_slots": active,
        "effective_slot_cap": cap,
        "waiting": waiting,
        "waiting_eligible": eligible,
        "underfilled": underfilled,
        "slow_tracking": slow,
        "ed2k_published_files": _summary_int(latest, "ed2kPublishedFiles"),
        "ed2k_pending_files": pending,
        "kad_publish_ready": _summary_int(latest, "kadPublishReady"),
        "verdict": verdict,
        "reason": reason,
        "series": [_upload_bandwidth_row(sample) for sample in samples[-tail:]],
    }


def _summary_int(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key)
    return int(value) if isinstance(value, (int, float)) else 0


def _upload_bandwidth_row(summary: dict[str, Any]) -> dict[str, Any]:
    rate = _summary_int(summary, "toNetworkBytesPerSec") or _summary_int(summary, "datarateBytesPerSec")
    return {
        "activeSlots": _summary_int(summary, "activeSlots"),
        "effectiveSlotCap": _summary_int(summary, "effectiveSlotCap"),
        "waiting": _summary_int(summary, "waiting"),
        "waitingEligible": _summary_int(summary, "waitingEligible"),
        "rateKiBps": rate // 1024,
        "underfilled": _summary_int(summary, "underfilled"),
        "ed2kPublishedFiles": _summary_int(summary, "ed2kPublishedFiles"),
        "kadPublishReady": _summary_int(summary, "kadPublishReady"),
    }


def _upload_bandwidth_verdict(
    *,
    utilization: float | None,
    target_utilization: float,
    active: int,
    cap: int,
    waiting: int,
    eligible: int,
    underfilled: bool,
    pending_publish: int,
) -> tuple[str, str]:
    if utilization is None:
        return "unknown", "No configured upload budget in the summary."
    if utilization >= target_utilization:
        return "target-met", f"Upload is at {utilization:.0%} of budget; target is {target_utilization:.0%}."
    if utilization >= 0.9:
        return "near-target", f"Upload is at {utilization:.0%} of budget; target is {target_utilization:.0%}."
    if not underfilled:
        return "healthy", f"Upload at {utilization:.0%} of budget and not flagged underfilled."
    if eligible > 0 and active < cap:
        return (
            "promotion-limited",
            f"{eligible} eligible waiting client(s) but only {active}/{cap} slots active while underfilled; "
            "slot-promotion cadence is the binding constraint, not demand or budget.",
        )
    if waiting == 0:
        return "demand-empty", "Underfilled with an empty waiting queue; no upload demand to fill the budget."
    if eligible == 0:
        return (
            "demand-eligibility-limited",
            f"{waiting} waiting client(s) but 0 eligible (all in reask/cooldown); "
            "demand exists but is not promotable yet (normal eD2K reask churn).",
        )
    if pending_publish > 0:
        return "publish-ramp", f"Underfilled with {pending_publish} files still pending publish; discovery is ramping."
    return "ramping", f"Underfilled at {utilization:.0%} of budget; throughput still ramping."


def format_upload_bandwidth(analysis: dict[str, Any]) -> str:
    """Formats upload-bandwidth utilization analysis for operator-facing CLI output."""

    if not analysis.get("exists"):
        return f"Upload-slot diagnostics: none found under {analysis.get('logs_dir')}"
    budget_kib = analysis["budget_bytes_per_sec"] // 1024
    rate_kib = analysis["rate_bytes_per_sec"] // 1024
    target_kib = analysis["target_rate_bytes_per_sec"] // 1024 if analysis.get("target_rate_bytes_per_sec") is not None else 0
    gap_kib = analysis["target_gap_bytes_per_sec"] // 1024 if analysis.get("target_gap_bytes_per_sec") is not None else 0
    util = analysis["utilization"]
    util_text = f"{util:.1%} of cap" if util is not None else "no budget"
    lines = [
        f"Upload bandwidth ({analysis['logs_dir']}):",
        (
            f"  rate={rate_kib} KiB/s of budget={budget_kib} KiB/s ({util_text}); "
            f"target={target_kib} KiB/s gap={gap_kib} KiB/s"
        ),
        (
            f"  slots: active={analysis['active_slots']}/{analysis['effective_slot_cap']} "
            f"waiting={analysis['waiting']} eligible={analysis['waiting_eligible']} "
            f"underfilled={int(analysis['underfilled'])} slowTracking={analysis['slow_tracking']}"
        ),
        (
            f"  publish: ed2k {analysis['ed2k_published_files']} published / "
            f"{analysis['ed2k_pending_files']} pending, kadPublishReady={analysis['kad_publish_ready']}"
        ),
        f"  verdict: {analysis['verdict']} - {analysis['reason']}",
        "  recent samples (rateKiBps  active/cap  waiting/eligible  ed2kPub):",
    ]
    for row in analysis["series"]:
        lines.append(
            f"    {row['rateKiBps']:>6}  {row['activeSlots']:>2}/{row['effectiveSlotCap']:<2}  "
            f"{row['waiting']:>3}/{row['waitingEligible']:<3}  ed2kPub={row['ed2kPublishedFiles']}"
        )
    return "\n".join(lines)


def summarize_upload_bandwidth_watch(samples: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarizes repeated upload-bandwidth analyses from live monitoring."""

    usable = [sample for sample in samples if sample.get("exists")]
    if not usable:
        return {"exists": False, "samples": len(samples)}
    rates = [int(sample["rate_bytes_per_sec"]) for sample in usable]
    utilizations = [float(sample["utilization"]) for sample in usable if sample.get("utilization") is not None]
    verdicts: dict[str, int] = {}
    for sample in usable:
        verdict = str(sample.get("verdict", "unknown"))
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
    return {
        "exists": True,
        "samples": len(usable),
        "budget_bytes_per_sec": usable[-1].get("budget_bytes_per_sec"),
        "target_utilization": usable[-1].get("target_utilization"),
        "target_rate_bytes_per_sec": usable[-1].get("target_rate_bytes_per_sec"),
        "avg_rate_bytes_per_sec": sum(rates) / len(rates),
        "min_rate_bytes_per_sec": min(rates),
        "max_rate_bytes_per_sec": max(rates),
        "last_rate_bytes_per_sec": rates[-1],
        "avg_utilization": (sum(utilizations) / len(utilizations)) if utilizations else None,
        "min_utilization": min(utilizations) if utilizations else None,
        "max_utilization": max(utilizations) if utilizations else None,
        "last_utilization": utilizations[-1] if utilizations else None,
        "avg_waiting": sum(int(sample["waiting"]) for sample in usable) / len(usable),
        "max_waiting": max(int(sample["waiting"]) for sample in usable),
        "avg_waiting_eligible": sum(int(sample["waiting_eligible"]) for sample in usable) / len(usable),
        "max_waiting_eligible": max(int(sample["waiting_eligible"]) for sample in usable),
        "max_active_slots": max(int(sample["active_slots"]) for sample in usable),
        "last_active_slots": int(usable[-1]["active_slots"]),
        "last_effective_slot_cap": int(usable[-1]["effective_slot_cap"]),
        "verdict_counts": verdicts,
    }


def format_upload_bandwidth_watch(summary: dict[str, Any]) -> str:
    """Formats a repeated upload-bandwidth monitor summary."""

    if not summary.get("exists"):
        return f"Upload monitor rollup: no usable samples ({summary.get('samples', 0)} sample(s))."
    avg_rate_kib = int(summary["avg_rate_bytes_per_sec"]) // 1024
    max_rate_kib = int(summary["max_rate_bytes_per_sec"]) // 1024
    last_rate_kib = int(summary["last_rate_bytes_per_sec"]) // 1024
    target_rate_kib = int(summary["target_rate_bytes_per_sec"] or 0) // 1024
    avg_util = summary.get("avg_utilization")
    max_util = summary.get("max_utilization")
    last_util = summary.get("last_utilization")
    verdicts = ", ".join(f"{name}={count}" for name, count in sorted(summary["verdict_counts"].items()))
    return "\n".join(
        [
            "Upload monitor rollup:",
            (
                f"  samples={summary['samples']} avg={avg_rate_kib} KiB/s "
                f"max={max_rate_kib} KiB/s last={last_rate_kib} KiB/s target={target_rate_kib} KiB/s"
            ),
            (
                f"  utilization avg={avg_util:.1%} max={max_util:.1%} last={last_util:.1%} "
                f"target={summary['target_utilization']:.1%}"
            ),
            (
                f"  slots last={summary['last_active_slots']}/{summary['last_effective_slot_cap']} "
                f"maxActive={summary['max_active_slots']} waitingAvg={summary['avg_waiting']:.1f} "
                f"waitingMax={summary['max_waiting']} eligibleAvg={summary['avg_waiting_eligible']:.1f} "
                f"eligibleMax={summary['max_waiting_eligible']}"
            ),
            f"  verdicts: {verdicts}",
        ]
    )
