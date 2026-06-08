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
