"""Diagnostic log analysis helpers for eMuleBB instrumented builds."""

from __future__ import annotations

import json
from collections import Counter
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

    bad_peer_events = _read_bad_peer_events(logs_dir / BAD_PEER_LOG_NAME)
    latest = max((_parse_utc(event.get("ts_utc")) for event in bad_peer_events), default=None)
    cutoff = latest - timedelta(minutes=window_minutes) if latest else None
    recent_events = [
        event
        for event in bad_peer_events
        if cutoff is None or (_parse_utc(event.get("ts_utc")) or datetime.min.replace(tzinfo=UTC)) >= cutoff
    ]

    peer_events = [event for event in recent_events if _mapping(event.get("peer")).get("user_hash")]
    no_request_events = [event for event in recent_events if str(event.get("event", "")).startswith("upload_no_request")]

    return {
        "logs_dir": str(logs_dir),
        "bad_peer": {
            "total_events": len(bad_peer_events),
            "latest_utc": latest.isoformat().replace("+00:00", "Z") if latest else None,
            "window_start_utc": cutoff.isoformat().replace("+00:00", "Z") if cutoff else None,
            "window_minutes": window_minutes,
            "recent_events": len(recent_events),
            "cooldowns": sum(1 for event in recent_events if event.get("action") == "cooldown"),
            "bans": sum(
                1 for event in recent_events if event.get("action") == "ban" or "ban" in str(event.get("event", ""))
            ),
            "productive_no_request": sum(
                1 for event in no_request_events if _mapping(event.get("evidence")).get("productive") is True
            ),
            "unproductive_no_request": sum(
                1 for event in no_request_events if _mapping(event.get("evidence")).get("productive") is False
            ),
            "top_events": _counter_rows(Counter(str(event.get("event", "")) for event in recent_events), top_count),
            "top_reasons": _counter_rows(Counter(str(event.get("reason", "")) for event in recent_events), top_count),
            "top_peers": _counter_rows(Counter(_peer_key(event) for event in peer_events), top_count),
            "max_strikes": _max_strike_rows(recent_events, top_count),
        },
        "upload_slot": _analyze_summary_log(logs_dir / UPLOAD_SLOT_LOG_NAME, "UploadSlotDiagnostics: summary "),
        "download_slot": _analyze_summary_log(logs_dir / DOWNLOAD_SLOT_LOG_NAME, "DownloadSlotDiagnostics: summary "),
    }


def format_diagnostic_log_analysis(analysis: dict[str, Any]) -> str:
    """Formats diagnostic log analysis for operator-facing CLI output."""

    bad_peer = analysis["bad_peer"]
    lines = [
        f"Diagnostics logs: {analysis['logs_dir']}",
        (
            "Bad peer window: "
            f"{bad_peer['recent_events']} events in {bad_peer['window_minutes']:g} min "
            f"(cooldowns={bad_peer['cooldowns']}, bans={bad_peer['bans']}, "
            f"productive_no_request={bad_peer['productive_no_request']}, "
            f"unproductive_no_request={bad_peer['unproductive_no_request']})"
        ),
    ]
    if bad_peer["latest_utc"]:
        lines.append(f"Latest bad-peer event: {bad_peer['latest_utc']}")
    lines.extend(_format_rows("Top bad-peer events", bad_peer["top_events"]))
    lines.extend(_format_rows("Top bad-peer reasons", bad_peer["top_reasons"]))
    lines.extend(_format_rows("Top bad-peer identities", bad_peer["top_peers"]))
    lines.extend(_format_strike_rows(bad_peer["max_strikes"]))
    lines.extend(_format_summary("Latest upload summary", analysis["upload_slot"]))
    lines.extend(_format_summary("Latest download summary", analysis["download_slot"]))
    return "\n".join(lines)


def _read_bad_peer_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
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


def _analyze_summary_log(path: Path, prefix: str) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "last_summary": None}
    last_summary: dict[str, Any] | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if line.startswith(prefix):
                last_summary = _parse_key_value_summary(line.removeprefix(prefix))
    return {"exists": True, "last_summary": last_summary}


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
