"""Control and sample a persisted emulebb-rust soak profile.

This is intentionally operational glue, not a scenario runner. It keeps the
common long-soak chores reusable:

* sample sanitized Rust REST counters;
* gracefully restart the diagnostics daemon against an existing runtime dir;
* restart the upload parity monitor with the current PID-specific Rust diag log;
* run reusable long-soak cadence checks without shell loops.

Private operator paths, such as the MFC upload diagnostics log, must be passed at
runtime and are never embedded here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import hideme_split_tunnel
from emule_test_harness import mfc_known_met
from emule_test_harness import soak_launch
from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready
from emule_test_harness.live_profiles import write_shared_directories_file
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.soak_launch import (
    DEFAULT_MFC_SEED_CONFIG_DIR,
    MFC_ED2K_PORT,
    MFC_API_KEY,
    MFC_KAD_PORT,
    MFC_SERVER_UDP_PORT,
    OPERATOR_SERVER,
    RUST_API_KEY,
    existing_shared_roots,
    load_shareddir_root_entries,
    normalize_shared_root_entry,
    shared_root_is_recursive,
    shared_root_path,
)
from emule_test_harness.windows_processes import (
    collect_processes,
    process_command_line,
    process_creation_date,
    terminate_process_tree,
)

ED2K_OFFER_BATCH_SIZE = 200
ED2K_OFFER_INTERVAL_SECONDS = 60


def output_root() -> Path:
    """Returns the configured workspace output root."""

    return get_workspace_output_root()


def default_mfc_upload_log_search_roots() -> list[Path]:
    """Returns bounded generated-output roots likely to contain MFC diagnostics."""

    root = output_root()
    return [root / "soak", root / "logs"]


def default_live_wire_inputs() -> Path:
    """Returns the default local shared-root input contract for soak launch."""

    return REPO_ROOT / "live-wire-inputs.local.json"


def default_runtime_dir() -> Path:
    """Returns the persistent Rust soak runtime directory."""

    return output_root() / "soak" / "rust-runtime"


def default_mfc_shareddir_file() -> Path:
    """Returns the default persisted MFC shareddir.dat for the soak profile."""

    return output_root() / "soak" / "mfc-profile" / "config" / "shareddir.dat"


def default_mfc_profile_dir() -> Path:
    """Returns the default persistent MFC soak profile-base directory."""

    return output_root() / "soak" / "mfc-profile" / "profiles" / "converged-soak" / "profile-base"


def resolve_mfc_start_profile(args: argparse.Namespace) -> tuple[Path | None, str]:
    """Chooses the MFC profile mode for a soak restart."""

    if args.direct_profile_dir is not None:
        return args.direct_profile_dir, "explicit-direct"
    if args.rebuild_profile_from_inputs:
        return None, "prepared-from-inputs"
    candidate = default_mfc_profile_dir()
    if (candidate / "config" / "preferences.ini").is_file():
        return candidate, "default-direct"
    return None, "prepared-from-inputs"


def discover_mfc_shareddir_file() -> Path | None:
    """Finds the newest shareddir.dat below the generated soak output tree."""

    soak_root = output_root() / "soak"
    if not soak_root.is_dir():
        return None
    candidates = [
        path
        for path in soak_root.glob("**/shareddir.dat")
        if path.is_file()
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0]


def command_line_profile_dir(command_line: str) -> Path | None:
    """Extracts an eMule-style -c profile directory from a command line."""

    match = re.search(r'(?:^|\s)-c\s+(?:"([^"]+)"|(\S+))', command_line, flags=re.IGNORECASE)
    if not match:
        return None
    value = match.group(1) or match.group(2)
    return Path(value) if value else None


def discover_mfc_known_met_from_processes() -> Path | None:
    """Finds MFC known.met from a running eMule-family process command line."""

    for process in collect_processes():
        command_line = process_command_line(process)
        identity = f"{getattr(process, 'name', '')} {command_line}".lower()
        if "emule" not in identity or "emulebb-rust" in identity:
            continue
        profile_dir = command_line_profile_dir(command_line)
        if profile_dir is None:
            continue
        known_met = profile_dir / "config" / "known.met"
        if known_met.is_file():
            return known_met
    return None


def discover_mfc_known_met_from_soak_output() -> Path | None:
    """Finds the newest known.met below generated soak output."""

    soak_root = output_root() / "soak"
    if soak_root.is_dir():
        candidates = [path for path in soak_root.glob("**/known.met") if path.is_file()]
        candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        if candidates:
            return candidates[0]
    return None


def mfc_upload_log_candidates(search_roots: list[Path], *, limit: int = 20) -> list[dict[str, object]]:
    """Returns newest MFC upload-slot diagnostics logs under the given roots."""

    candidates: dict[Path, tuple[float, int]] = {}
    for search_root in search_roots:
        if not search_root.is_dir():
            continue
        for path in search_root.glob("**/emulebb-diagnostics-upload-slot*.log"):
            if not path.is_file():
                continue
            try:
                stat = path.stat()
                candidates[path.resolve()] = (stat.st_mtime, stat.st_size)
            except OSError:
                continue
    rows = []
    for path, (mtime, size) in sorted(candidates.items(), key=lambda item: item[1][0], reverse=True)[:limit]:
        last_write = datetime.fromtimestamp(mtime, UTC)
        rows.append(
            {
                "path": str(path),
                "lastWriteUtc": last_write.isoformat(),
                "ageSeconds": round(max(0.0, (datetime.now(UTC) - last_write).total_seconds()), 2),
                "length": size,
            }
        )
    return rows


def discover_mfc_upload_log(search_roots: list[Path], *, max_age_seconds: float = 900.0) -> Path | None:
    """Finds the newest non-stale MFC upload-slot diagnostics log."""

    for row in mfc_upload_log_candidates(search_roots, limit=25):
        age = row.get("ageSeconds")
        path = row.get("path")
        if isinstance(age, (int, float)) and age <= max_age_seconds and isinstance(path, str):
            return Path(path)
    return None


def mfc_upload_logs(args: argparse.Namespace) -> dict[str, object]:
    """Lists MFC upload-slot diagnostics log candidates for parity monitoring."""

    roots = args.search_root or default_mfc_upload_log_search_roots()
    rows = mfc_upload_log_candidates(roots, limit=args.limit)
    for row in rows:
        age = row.get("ageSeconds")
        row["stale"] = not isinstance(age, (int, float)) or age > args.fresh_seconds
    return {
        "searchRoots": [str(path) for path in roots],
        "freshSeconds": args.fresh_seconds,
        "count": len(rows),
        "logs": rows,
    }


DIAGNOSTIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("upnp", re.compile(r"\bupnp\b", re.IGNORECASE)),
    ("ed2k", re.compile(r"\bed2k\b", re.IGNORECASE)),
    ("kad", re.compile(r"\bkad(?:emlia)?\b", re.IGNORECASE)),
    ("high-id", re.compile(r"\bhigh[\s_-]*id\b", re.IGNORECASE)),
    ("low-id", re.compile(r"\blow[\s_-]*id\b", re.IGNORECASE)),
    ("firewall", re.compile(r"\bfirewall(?:ed)?\b", re.IGNORECASE)),
    ("listen", re.compile(r"\blisten(?:ing)?\b", re.IGNORECASE)),
    ("port", re.compile(r"\bport\b", re.IGNORECASE)),
    ("upload-slot", re.compile(r"\bupload[\s_-]*slot\b", re.IGNORECASE)),
    ("ban", re.compile(r"\bban(?:ned|ning)?\b", re.IGNORECASE)),
)

DIAGNOSTIC_BODY_BUCKET_FIELDS: dict[str, tuple[str, ...]] = {
    "anti_flood_ban": ("action", "behavior"),
    "anti_flood_drop": ("action", "behavior"),
    "capacity_snapshot": ("elasticUnderfill",),
    "upload_request_outcome": ("outcome", "firstSkipReason"),
    "upload_slot_recycled": ("reason",),
}

DIAGNOSTIC_BODY_NUMERIC_FIELDS: dict[str, tuple[str, ...]] = {
    "capacity_snapshot": (
        "activeSlots",
        "baseSlots",
        "effectiveSlotCap",
        "elasticSlots",
        "underfillSinceMs",
        "uploadLimitBytesPerSec",
        "uploadRateBytesPerSec",
        "waitingSessions",
    ),
    "shared_publish_offer_batch": (
        "entriesSent",
        "totalEntries",
        "cursorBefore",
        "nextCursor",
    ),
    "upload_payload_accounting": (
        "sentCompleteFileBytes",
        "sentFileBytes",
        "sentPartFileBytes",
        "sentPayloadBytes",
    ),
    "upload_request_outcome": (
        "payloadPackets",
        "payloadReadMs",
        "requestedBytes",
        "requestedRanges",
        "readCacheHits",
        "readCacheMisses",
        "readDiskBytes",
        "servedBytes",
        "servedRanges",
        "skippedRanges",
        "throttleDelayMs",
        "verifiedReaderOpenMs",
    ),
}


def tail_text_lines(path: Path, *, max_bytes: int) -> list[str]:
    """Reads a bounded text tail without returning file content to callers."""

    with path.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        if size > max_bytes:
            handle.seek(-max_bytes, os.SEEK_END)
            handle.readline()
        else:
            handle.seek(0)
        return handle.read().decode("utf-8", errors="replace").splitlines()


def diagnostic_json_value(value: object) -> str | None:
    """Returns a compact, non-private bucket value from a diagnostics JSON row."""

    if not isinstance(value, str) or not value:
        return None
    if len(value) > 80:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    if any(separator in value for separator in ("\\", "/", ":", "@")):
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    return value


def diagnostic_json_bucket_value(value: object) -> str | None:
    """Returns a safe aggregate bucket for selected diagnostics body fields."""

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return diagnostic_json_value(value)


def diagnostic_json_numeric_value(value: object) -> float | None:
    """Returns a numeric diagnostics value while rejecting bool-like buckets."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number != number:
        return None
    return number


def compact_numeric_values(values: list[float]) -> dict[str, object]:
    """Builds compact descriptive stats for one diagnostics numeric field."""

    total = sum(values)
    return {
        "count": len(values),
        "sum": round(total, 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "average": round(total / len(values), 3),
    }


def compact_numeric_distribution(values: list[float]) -> dict[str, object]:
    """Builds compact stats plus percentiles for soak performance evidence."""

    stats = compact_numeric_values(values)
    ordered = sorted(values)
    for percentile in (50, 90, 95, 99):
        stats[f"p{percentile}"] = percentile_value(ordered, percentile)
    return stats


def percentile_value(ordered_values: list[float], percentile: int) -> float:
    """Returns a rounded percentile from an already sorted numeric series."""

    if not ordered_values:
        return 0.0
    if len(ordered_values) == 1:
        return round(ordered_values[0], 3)
    rank = (len(ordered_values) - 1) * percentile / 100.0
    lower_index = int(rank)
    upper_index = min(len(ordered_values) - 1, lower_index + 1)
    fraction = rank - lower_index
    value = ordered_values[lower_index] * (1.0 - fraction) + ordered_values[upper_index] * fraction
    return round(value, 3)


def selected_diagnostics_logs(args: argparse.Namespace) -> tuple[list[Path], list[Path]]:
    """Returns newest diagnostics logs from explicit files and directories."""

    log_files = list(args.log_file or [])
    raw_log_dirs = args.log_dir or []
    log_dirs = list(raw_log_dirs) if isinstance(raw_log_dirs, list) else [raw_log_dirs]
    for log_dir in log_dirs:
        if log_dir.is_dir():
            log_files.extend(path for path in log_dir.glob("emulebb*.log") if path.is_file())
            log_files.extend(path for path in log_dir.glob("emulebb*.jsonl") if path.is_file())
    unique_files = sorted(
        {path.resolve() for path in log_files if path.is_file()},
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return unique_files[: args.limit], log_dirs


def summarize_diagnostics_log(path: Path, *, max_bytes: int) -> dict[str, object]:
    """Summarizes one diagnostics log without exposing raw lines or private names."""

    stat = path.stat()
    lines = tail_text_lines(path, max_bytes=max_bytes)
    pattern_counts: Counter[str] = Counter()
    json_counts: dict[str, Counter[str]] = {
        "schema": Counter(),
        "marker": Counter(),
        "event": Counter(),
        "severity": Counter(),
        "action": Counter(),
    }
    json_body_counts: dict[str, Counter[str]] = {}
    json_body_numeric: dict[str, list[float]] = {}
    json_rows = 0
    malformed_json_rows = 0
    timestamps: list[datetime] = []
    for line in lines:
        for name, pattern in DIAGNOSTIC_PATTERNS:
            if pattern.search(line):
                pattern_counts[name] += 1
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            malformed_json_rows += 1
            continue
        if not isinstance(parsed, dict):
            continue
        json_rows += 1
        for field, counter in json_counts.items():
            bucket = diagnostic_json_value(parsed.get(field))
            if bucket is not None:
                counter[bucket] += 1
        event = diagnostic_json_value(parsed.get("event"))
        body = parsed.get("body")
        if event is not None and isinstance(body, dict):
            for field in DIAGNOSTIC_BODY_BUCKET_FIELDS.get(event, ()):
                bucket = diagnostic_json_bucket_value(body.get(field))
                if bucket is not None:
                    json_body_counts.setdefault(f"{event}.{field}", Counter())[bucket] += 1
            for field in DIAGNOSTIC_BODY_NUMERIC_FIELDS.get(event, ()):
                number = diagnostic_json_numeric_value(body.get(field))
                if number is not None:
                    json_body_numeric.setdefault(f"{event}.{field}", []).append(number)
        timestamp = parse_iso_timestamp(
            parsed.get("ts") or parsed.get("ts_utc") or parsed.get("timestamp") or parsed.get("timestampUtc")
        )
        if timestamp is not None:
            timestamps.append(timestamp)

    now = datetime.now(UTC)
    last_write = datetime.fromtimestamp(stat.st_mtime, UTC)
    result: dict[str, object] = {
        "pathFingerprint": private_path_fingerprint(str(path)),
        "name": path.name,
        "length": stat.st_size,
        "lastWriteUtc": last_write.isoformat(),
        "ageSeconds": round(max(0.0, (now - last_write).total_seconds()), 2),
        "scannedLineCount": len(lines),
        "jsonRowCount": json_rows,
        "malformedJsonRowCount": malformed_json_rows,
        "patternCounts": dict(sorted(pattern_counts.items())),
    }
    if timestamps:
        result["jsonTimeRange"] = {
            "firstUtc": min(timestamps).isoformat(),
            "lastUtc": max(timestamps).isoformat(),
        }
    compact_json_counts = {
        field: dict(counter.most_common(12))
        for field, counter in json_counts.items()
        if counter
    }
    if compact_json_counts:
        result["jsonCounts"] = compact_json_counts
    compact_body_counts = {
        field: dict(counter.most_common(12))
        for field, counter in json_body_counts.items()
        if counter
    }
    if compact_body_counts:
        result["jsonBodyCounts"] = compact_body_counts
    compact_body_numeric = {
        field: compact_numeric_values(values)
        for field, values in sorted(json_body_numeric.items())
        if values
    }
    if compact_body_numeric:
        result["jsonBodyNumeric"] = compact_body_numeric
    return result


def diagnostics_summary(args: argparse.Namespace) -> dict[str, object]:
    """Summarizes diagnostics logs while keeping operator-owned content private."""

    selected, log_dirs = selected_diagnostics_logs(args)
    files = [summarize_diagnostics_log(path, max_bytes=args.max_bytes) for path in selected]
    aggregate_patterns: Counter[str] = Counter()
    for file_summary in files:
        pattern_counts = file_summary.get("patternCounts")
        if isinstance(pattern_counts, dict):
            for name, count in pattern_counts.items():
                if isinstance(name, str) and isinstance(count, int):
                    aggregate_patterns[name] += count
    aggregate_json_counts = aggregate_diagnostics_json_counts(files)
    return {
        "logDir": None,
        "logDirFingerprint": private_path_fingerprint(str(log_dirs[0])) if len(log_dirs) == 1 else None,
        "logDirs": [private_path_fingerprint(str(log_dir)) for log_dir in log_dirs],
        "limit": args.limit,
        "maxBytes": args.max_bytes,
        "fileCount": len(files),
        "aggregatePatternCounts": dict(sorted(aggregate_patterns.items())),
        "aggregateJsonCounts": aggregate_json_counts,
        "files": files,
    }


def safe_upload_outcome_row(path: Path, parsed: dict[str, object]) -> dict[str, object]:
    """Builds a privacy-safe upload outcome row for worst-case diagnostics."""

    body = parsed.get("body") if isinstance(parsed.get("body"), dict) else {}
    row: dict[str, object] = {
        "logName": path.name,
        "pathFingerprint": private_path_fingerprint(str(path)),
    }
    timestamp = parse_iso_timestamp(
        parsed.get("ts") or parsed.get("ts_utc") or parsed.get("timestamp") or parsed.get("timestampUtc")
    )
    if timestamp is not None:
        row["timestampUtc"] = timestamp.isoformat()
    outcome = diagnostic_json_bucket_value(body.get("outcome"))
    first_skip = diagnostic_json_bucket_value(body.get("firstSkipReason"))
    if outcome is not None:
        row["outcome"] = outcome
    if first_skip is not None:
        row["firstSkipReason"] = first_skip
    for field in DIAGNOSTIC_BODY_NUMERIC_FIELDS["upload_request_outcome"]:
        number = diagnostic_json_numeric_value(body.get(field))
        if number is not None:
            row[field] = round(number, 3)
    return row


def upload_efficiency_summary(args: argparse.Namespace) -> dict[str, object]:
    """Summarizes upload outcome latency and efficiency without raw live data."""

    selected, log_dirs = selected_diagnostics_logs(args)
    numeric: dict[str, list[float]] = {}
    outcomes: Counter[str] = Counter()
    first_skip_reasons: Counter[str] = Counter()
    timestamps: list[datetime] = []
    worst_rows: list[dict[str, object]] = []
    row_count = 0
    slow_read_count = 0
    for path in selected:
        for line in tail_text_lines(path, max_bytes=args.max_bytes):
            stripped = line.strip()
            if not stripped.startswith("{") or "upload_request_outcome" not in stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict) or parsed.get("event") != "upload_request_outcome":
                continue
            body = parsed.get("body")
            if not isinstance(body, dict):
                continue
            row_count += 1
            timestamp = parse_iso_timestamp(
                parsed.get("ts")
                or parsed.get("ts_utc")
                or parsed.get("timestamp")
                or parsed.get("timestampUtc")
            )
            if timestamp is not None:
                timestamps.append(timestamp)
            outcome = diagnostic_json_bucket_value(body.get("outcome"))
            first_skip = diagnostic_json_bucket_value(body.get("firstSkipReason"))
            if outcome is not None:
                outcomes[outcome] += 1
            if first_skip is not None:
                first_skip_reasons[first_skip] += 1
            for field in DIAGNOSTIC_BODY_NUMERIC_FIELDS["upload_request_outcome"]:
                number = diagnostic_json_numeric_value(body.get(field))
                if number is not None:
                    numeric.setdefault(field, []).append(number)
            read_ms = diagnostic_json_numeric_value(body.get("payloadReadMs"))
            if read_ms is not None and read_ms >= args.slow_read_ms:
                slow_read_count += 1
            if read_ms is not None:
                row = safe_upload_outcome_row(path, parsed)
                row["_sortPayloadReadMs"] = read_ms
                worst_rows.append(row)
    worst_rows.sort(key=lambda row: safe_float(row.get("_sortPayloadReadMs")) or 0.0, reverse=True)
    for row in worst_rows:
        row.pop("_sortPayloadReadMs", None)
    requested_bytes = sum(numeric.get("requestedBytes", []))
    served_bytes = sum(numeric.get("servedBytes", []))
    read_cache_hits = sum(numeric.get("readCacheHits", []))
    read_cache_misses = sum(numeric.get("readCacheMisses", []))
    read_disk_bytes = sum(numeric.get("readDiskBytes", []))
    result: dict[str, object] = {
        "logDir": None,
        "logDirFingerprint": private_path_fingerprint(str(log_dirs[0])) if len(log_dirs) == 1 else None,
        "logDirs": [private_path_fingerprint(str(log_dir)) for log_dir in log_dirs],
        "limit": args.limit,
        "maxBytes": args.max_bytes,
        "fileCount": len(selected),
        "rowCount": row_count,
        "slowReadThresholdMs": args.slow_read_ms,
        "slowReadCount": slow_read_count,
        "outcomes": dict(outcomes.most_common(12)),
        "firstSkipReasons": dict(first_skip_reasons.most_common(12)),
        "numeric": {
            field: compact_numeric_distribution(values)
            for field, values in sorted(numeric.items())
            if values
        },
        "worstPayloadReads": worst_rows[: args.outlier_limit],
    }
    if row_count > 0:
        result["slowReadRatio"] = round(slow_read_count / row_count, 4)
    if requested_bytes > 0:
        result["servedToRequestedRatio"] = round(served_bytes / requested_bytes, 4)
    if read_cache_hits + read_cache_misses > 0:
        result["readCacheHitRatio"] = round(read_cache_hits / (read_cache_hits + read_cache_misses), 4)
    if served_bytes > 0 and read_disk_bytes > 0:
        result["readDiskToServedRatio"] = round(read_disk_bytes / served_bytes, 4)
    if timestamps:
        result["timeRange"] = {
            "firstUtc": min(timestamps).isoformat(),
            "lastUtc": max(timestamps).isoformat(),
        }
    return result


def anti_flood_summary(args: argparse.Namespace) -> dict[str, object]:
    """Summarizes anti-flood diagnostics bursts with sanitized peer identities."""

    selected, log_dirs = selected_diagnostics_logs(args)
    peers: dict[str, dict[str, object]] = {}
    recent_events: list[dict[str, object]] = []
    seen_events: set[tuple[object, ...]] = set()
    raw_event_rows = 0
    duplicate_event_rows = 0
    total_events = 0
    max_repeat_count = 0
    timestamps: list[datetime] = []
    severity_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    behavior_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    window_counts: Counter[str] = Counter()
    udp_tracker_rows = 0
    udp_tracker_bucket_counts: Counter[str] = Counter()
    udp_tracker_action_counts: Counter[str] = Counter()
    udp_tracker_reason_counts: Counter[str] = Counter()
    udp_tracker_opcode_counts: Counter[str] = Counter()
    recent_udp_tracker_drops: list[dict[str, object]] = []
    for path in selected:
        for line in tail_text_lines(path, max_bytes=args.max_bytes):
            stripped = line.strip()
            if not stripped.startswith("{") or (
                "anti_flood" not in stripped and "tracker_action" not in stripped
            ):
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed.get("schema") == "udp_packet_v1":
                tracker_action = diagnostic_json_bucket_value(parsed.get("tracker_action"))
                if tracker_action not in {"drop", "massive_drop"}:
                    continue
                udp_tracker_rows += 1
                tracker_bucket = diagnostic_json_bucket_value(parsed.get("tracker_bucket"))
                drop_reason = diagnostic_json_bucket_value(parsed.get("drop_reason"))
                opcode_name = diagnostic_json_bucket_value(parsed.get("opcode_name"))
                observed_packets = diagnostic_json_numeric_value(parsed.get("tracker_observed_packets"))
                max_packets = diagnostic_json_numeric_value(parsed.get("tracker_max_packets"))
                timestamp = parse_iso_timestamp(
                    parsed.get("ts")
                    or parsed.get("ts_utc")
                    or parsed.get("timestamp")
                    or parsed.get("timestampUtc")
                )
                peer = parsed.get("peer") if isinstance(parsed.get("peer"), str) else ""
                peer_fingerprint = private_path_fingerprint(peer)
                if tracker_bucket is not None:
                    udp_tracker_bucket_counts[tracker_bucket] += 1
                if tracker_action is not None:
                    udp_tracker_action_counts[tracker_action] += 1
                if drop_reason is not None:
                    udp_tracker_reason_counts[drop_reason] += 1
                if opcode_name is not None:
                    udp_tracker_opcode_counts[opcode_name] += 1
                recent_udp_tracker_drops.append(
                    {
                        "timestampUtc": timestamp.isoformat() if timestamp is not None else None,
                        "peerFingerprint": peer_fingerprint,
                        "trackerBucket": tracker_bucket,
                        "trackerAction": tracker_action,
                        "dropReason": drop_reason,
                        "opcodeName": opcode_name,
                        "observedPackets": int(observed_packets) if observed_packets is not None else None,
                        "maxPackets": int(max_packets) if max_packets is not None else None,
                        "sourceFile": path.name,
                    }
                )
                continue
            if not isinstance(parsed, dict) or parsed.get("event") not in {"anti_flood_drop", "anti_flood_ban"}:
                continue
            raw_event_rows += 1
            total_events += 1
            severity = diagnostic_json_value(parsed.get("severity")) or "unknown"
            body = parsed.get("body") if isinstance(parsed.get("body"), dict) else {}
            repeat_count = diagnostic_json_numeric_value(body.get("repeatCount")) if isinstance(body, dict) else None
            action = diagnostic_json_bucket_value(body.get("action")) if isinstance(body, dict) else None
            behavior = diagnostic_json_bucket_value(body.get("behavior")) if isinstance(body, dict) else None
            reason = diagnostic_json_bucket_value(body.get("reason")) if isinstance(body, dict) else None
            window_seconds = (
                diagnostic_json_numeric_value(body.get("windowSeconds")) if isinstance(body, dict) else None
            )
            timestamp = parse_iso_timestamp(
                parsed.get("ts") or parsed.get("ts_utc") or parsed.get("timestamp") or parsed.get("timestampUtc")
            )
            keys = parsed.get("keys") if isinstance(parsed.get("keys"), dict) else {}
            peer = keys.get("peer") if isinstance(keys, dict) else None
            peer_fingerprint = private_path_fingerprint(peer or "")
            event_key = (
                path.name,
                parsed.get("event"),
                timestamp.isoformat() if timestamp is not None else None,
                peer_fingerprint,
                int(repeat_count) if repeat_count is not None else None,
                action,
                behavior,
                reason,
                int(window_seconds) if window_seconds is not None else None,
            )
            if event_key in seen_events:
                duplicate_event_rows += 1
                total_events -= 1
                continue
            seen_events.add(event_key)
            severity_counts[severity] += 1
            if repeat_count is not None:
                max_repeat_count = max(max_repeat_count, int(repeat_count))
            if timestamp is not None:
                timestamps.append(timestamp)
            if action is not None:
                action_counts[action] += 1
            if behavior is not None:
                behavior_counts[behavior] += 1
            if reason is not None:
                reason_counts[reason] += 1
            if window_seconds is not None:
                window_counts[str(int(window_seconds))] += 1
            peer_row = peers.setdefault(
                peer_fingerprint,
                {
                    "peerFingerprint": peer_fingerprint,
                    "events": 0,
                    "dropEvents": 0,
                    "banEvents": 0,
                    "maxRepeatCount": 0,
                    "firstUtc": None,
                    "lastUtc": None,
                },
            )
            peer_row["events"] = int(peer_row["events"]) + 1
            if parsed.get("event") == "anti_flood_drop":
                peer_row["dropEvents"] = int(peer_row["dropEvents"]) + 1
            if parsed.get("event") == "anti_flood_ban":
                peer_row["banEvents"] = int(peer_row["banEvents"]) + 1
            if repeat_count is not None:
                peer_row["maxRepeatCount"] = max(int(peer_row["maxRepeatCount"]), int(repeat_count))
            if timestamp is not None:
                timestamp_text = timestamp.isoformat()
                first_utc = peer_row.get("firstUtc")
                last_utc = peer_row.get("lastUtc")
                if first_utc is None or timestamp_text < str(first_utc):
                    peer_row["firstUtc"] = timestamp_text
                if last_utc is None or timestamp_text > str(last_utc):
                    peer_row["lastUtc"] = timestamp_text
            recent_events.append(
                {
                    "timestampUtc": timestamp.isoformat() if timestamp is not None else None,
                    "event": parsed.get("event"),
                    "severity": severity,
                    "peerFingerprint": peer_fingerprint,
                    "repeatCount": int(repeat_count) if repeat_count is not None else None,
                    "action": action,
                    "behavior": behavior,
                    "reason": reason,
                    "windowSeconds": int(window_seconds) if window_seconds is not None else None,
                    "sourceFile": path.name,
                }
            )
    recent_events.sort(key=lambda row: str(row.get("timestampUtc") or ""))
    recent_udp_tracker_drops.sort(key=lambda row: str(row.get("timestampUtc") or ""))
    peer_rows = sorted(
        peers.values(),
        key=lambda row: (int(row.get("events", 0)), int(row.get("maxRepeatCount", 0))),
        reverse=True,
    )[: args.peer_limit]
    result: dict[str, object] = {
        "logDir": None,
        "logDirFingerprint": private_path_fingerprint(str(log_dirs[0])) if len(log_dirs) == 1 else None,
        "logDirs": [private_path_fingerprint(str(log_dir)) for log_dir in log_dirs],
        "limit": args.limit,
        "maxBytes": args.max_bytes,
        "fileCount": len(selected),
        "totalEvents": total_events,
        "rawEventRows": raw_event_rows,
        "duplicateEventRows": duplicate_event_rows,
        "uniquePeers": len(peers),
        "maxRepeatCount": max_repeat_count,
        "severityCounts": dict(severity_counts.most_common()),
        "actionCounts": dict(action_counts.most_common()),
        "behaviorCounts": dict(behavior_counts.most_common()),
        "reasonCounts": dict(reason_counts.most_common()),
        "windowSecondsCounts": dict(window_counts.most_common()),
        "udpTrackerDrops": {
            "rows": udp_tracker_rows,
            "bucketCounts": dict(udp_tracker_bucket_counts.most_common(12)),
            "actionCounts": dict(udp_tracker_action_counts.most_common(12)),
            "reasonCounts": dict(udp_tracker_reason_counts.most_common(12)),
            "opcodeCounts": dict(udp_tracker_opcode_counts.most_common(12)),
            "recent": recent_udp_tracker_drops[-args.event_limit :],
        },
        "topPeers": peer_rows,
        "recentEvents": recent_events[-args.event_limit :],
    }
    if timestamps:
        result["timeRange"] = {
            "firstUtc": min(timestamps).isoformat(),
            "lastUtc": max(timestamps).isoformat(),
        }
    return result


def aggregate_diagnostics_json_counts(files: list[dict[str, object]]) -> dict[str, dict[str, int]]:
    """Aggregates safe JSON count buckets across diagnostics file summaries."""

    aggregate: dict[str, Counter[str]] = {}
    for file_summary in files:
        json_counts = file_summary.get("jsonCounts")
        if not isinstance(json_counts, dict):
            continue
        for field, counts in json_counts.items():
            if not isinstance(field, str) or not isinstance(counts, dict):
                continue
            counter = aggregate.setdefault(field, Counter())
            for bucket, count in counts.items():
                if isinstance(bucket, str) and isinstance(count, int):
                    counter[bucket] += count
    return {
        field: dict(counter.most_common(24))
        for field, counter in sorted(aggregate.items())
        if counter
    }


def default_vpn_executables() -> list[Path]:
    """Returns the diagnostics executables that should be VPN allow-listed."""

    executables = [default_executable()]
    try:
        executables.append(clw.resolve_mfc_diagnostics_exe(output_root()))
    except FileNotFoundError:
        pass
    return executables


def vpn_allowlist_status(args: argparse.Namespace) -> dict[str, object]:
    """Reports hide.me split-tunnel status without mutating VPN settings."""

    executables = args.exe or default_vpn_executables()
    rows = []
    for exe in executables:
        try:
            whitelisted = hideme_split_tunnel.is_whitelisted(exe, settings_path=args.settings_path)
            error = ""
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            whitelisted = False
            error = type(exc).__name__
        rows.append(
            {
                "name": exe.name,
                "pathFingerprint": private_path_fingerprint(str(exe)),
                "exists": exe.is_file(),
                "whitelisted": whitelisted,
                "error": error,
            }
        )
    adapter_up = None
    bind_ip_present = None
    adapter_error = ""
    if args.check_adapter:
        try:
            adapter_up = hideme_split_tunnel.hideme_adapter_up()
            bind_ip_present = bool(hideme_split_tunnel.hideme_adapter_ipv4()) if adapter_up else False
        except RuntimeError as exc:
            adapter_up = False
            bind_ip_present = False
            adapter_error = type(exc).__name__
    return {
        "settingsPathFingerprint": (
            private_path_fingerprint(str(args.settings_path)) if args.settings_path is not None else None
        ),
        "allWhitelisted": all(bool(row["whitelisted"]) for row in rows) if rows else False,
        "adapterChecked": args.check_adapter,
        "adapterUp": adapter_up,
        "bindIpPresent": bind_ip_present,
        "adapterError": adapter_error,
        "executables": rows,
    }


def optional_watch_diagnostics(args: argparse.Namespace) -> dict[str, object] | None:
    """Returns optional sanitized diagnostics evidence for a watch sample."""

    log_files = list(getattr(args, "diagnostics_log_file", None) or [])
    log_dirs = list(getattr(args, "diagnostics_log_dir", None) or [])
    if not log_files and not log_dirs:
        return None
    files: list[dict[str, object]] = []
    sources: list[dict[str, object]] = []
    aggregate_patterns: Counter[str] = Counter()
    aggregate_json_counts: dict[str, Counter[str]] = {}
    limit = int(getattr(args, "diagnostics_limit", 8) or 8)
    max_bytes = int(getattr(args, "diagnostics_max_bytes", 262_144) or 262_144)
    for log_dir in log_dirs:
        summary = diagnostics_summary(
            argparse.Namespace(
                log_dir=log_dir,
                log_file=None,
                limit=limit,
                max_bytes=max_bytes,
            )
        )
        summary_files = summary.get("files", [])
        if isinstance(summary_files, list):
            files.extend(summary_files)
        summary_patterns = summary.get("aggregatePatternCounts") or {}
        sources.append(
            {
                "kind": "directory",
                "pathFingerprint": private_path_fingerprint(str(log_dir)),
                "fileCount": summary.get("fileCount"),
                "aggregatePatternCounts": summary_patterns,
                "files": summary_files,
            }
        )
        for name, count in summary_patterns.items():
            if isinstance(name, str) and isinstance(count, int):
                aggregate_patterns[name] += count
        for field, counts in (summary.get("aggregateJsonCounts") or {}).items():
            if not isinstance(field, str) or not isinstance(counts, dict):
                continue
            counter = aggregate_json_counts.setdefault(field, Counter())
            for bucket, count in counts.items():
                if isinstance(bucket, str) and isinstance(count, int):
                    counter[bucket] += count
    if log_files:
        summary = diagnostics_summary(
            argparse.Namespace(
                log_dir=None,
                log_file=log_files,
                limit=limit,
                max_bytes=max_bytes,
            )
        )
        summary_files = summary.get("files", [])
        if isinstance(summary_files, list):
            files.extend(summary_files)
        summary_patterns = summary.get("aggregatePatternCounts") or {}
        sources.append(
            {
                "kind": "files",
                "fileCount": summary.get("fileCount"),
                "aggregatePatternCounts": summary_patterns,
                "files": summary_files,
            }
        )
        for name, count in summary_patterns.items():
            if isinstance(name, str) and isinstance(count, int):
                aggregate_patterns[name] += count
        for field, counts in (summary.get("aggregateJsonCounts") or {}).items():
            if not isinstance(field, str) or not isinstance(counts, dict):
                continue
            counter = aggregate_json_counts.setdefault(field, Counter())
            for bucket, count in counts.items():
                if isinstance(bucket, str) and isinstance(count, int):
                    counter[bucket] += count
    anti_flood = anti_flood_summary(
        argparse.Namespace(
            log_dir=log_dirs,
            log_file=log_files,
            limit=limit,
            max_bytes=max_bytes,
            peer_limit=8,
            event_limit=8,
        )
    )
    result: dict[str, object] = {
        "fileCount": len(files),
        "aggregatePatternCounts": dict(sorted(aggregate_patterns.items())),
        "aggregateJsonCounts": {
            field: dict(counter.most_common(24))
            for field, counter in sorted(aggregate_json_counts.items())
            if counter
        },
        "sources": sources,
        "files": files[:limit],
    }
    if (
        int(anti_flood.get("totalEvents") or 0) > 0
        or int((anti_flood.get("udpTrackerDrops") or {}).get("rows") or 0) > 0
    ):
        result["antiFloodSummary"] = anti_flood
    return result


def optional_watch_vpn(args: argparse.Namespace) -> dict[str, object] | None:
    """Returns optional VPN allow-list evidence for a watch sample."""

    if not getattr(args, "include_vpn_status", False):
        return None
    return vpn_allowlist_status(
        argparse.Namespace(
            exe=getattr(args, "vpn_exe", None),
            settings_path=getattr(args, "vpn_settings_path", None),
            check_adapter=getattr(args, "check_vpn_adapter", False),
        )
    )


def default_executable() -> Path:
    """Returns the diagnostics executable built by the workspace orchestrator."""

    target = output_root() / "builds" / "rust" / "target"
    target_triple = target / "x86_64-pc-windows-msvc" / "release" / "emulebb-rust-diagnostics.exe"
    if target_triple.exists():
        return target_triple
    return target / "release" / "emulebb-rust-diagnostics.exe"


def default_rust_repo() -> Path:
    """Returns the sibling emulebb-rust checkout used by metadata seed helpers."""

    return REPO_ROOT.parent / "emulebb-rust"


def default_metadata_db() -> Path:
    """Returns the persistent Rust metadata database path."""

    return default_runtime_dir() / "metadata.sqlite"


def default_base_url() -> str:
    """Builds the default Rust REST base URL from X_LOCAL_IP when available."""

    host = os.environ.get("X_LOCAL_IP", "127.0.0.1").strip() or "127.0.0.1"
    return f"http://{host}:4731/api/v1"


def default_mfc_base_url() -> str:
    """Builds the default MFC REST base URL from X_LOCAL_IP when available."""

    host = os.environ.get("X_LOCAL_IP", "127.0.0.1").strip() or "127.0.0.1"
    return f"http://{host}:4732/api/v1"


def api_url(base_url: str, path: str) -> str:
    """Combines a base URL and API path without double slashes."""

    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def request_json(
    base_url: str,
    path: str,
    *,
    api_key: str,
    method: str = "GET",
    body: dict[str, object] | None = None,
    timeout_seconds: float = 8.0,
) -> dict[str, object]:
    """Runs one authenticated Rust REST request and unwraps the v1 data envelope."""

    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        api_url(base_url, path),
        data=payload,
        method=method,
        headers={"X-API-Key": api_key, "Accept": "application/json"},
    )
    if payload is not None:
        request.add_header("Content-Type", "application/json; charset=utf-8")
    with urlopen(request, timeout=timeout_seconds) as response:
        text = response.read().decode("utf-8")
    parsed = json.loads(text) if text else {}
    if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
        return parsed["data"]  # type: ignore[return-value]
    if isinstance(parsed, dict):
        return parsed
    raise RuntimeError(f"Rust REST returned a non-object payload for {method} {path}: {parsed!r}")


def request_json_attempt(
    base_url: str,
    path: str,
    *,
    api_key: str,
    method: str = "GET",
    body: dict[str, object] | None = None,
    timeout_seconds: float = 8.0,
) -> dict[str, object]:
    """Runs one REST request and returns a compact success/error envelope."""

    try:
        return {
            "ok": True,
            "path": path,
            "method": method,
            "data": request_json(
                base_url,
                path,
                api_key=api_key,
                method=method,
                body=body,
                timeout_seconds=timeout_seconds,
            ),
        }
    except HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        try:
            payload: object = json.loads(text) if text else {}
        except json.JSONDecodeError:
            payload = {"body": text[:512]}
        return {
            "ok": False,
            "path": path,
            "method": method,
            "status": exc.code,
            "reason": exc.reason,
            "error": payload,
        }
    except URLError as exc:
        return {
            "ok": False,
            "path": path,
            "method": method,
            "error": type(exc.reason).__name__ if hasattr(exc, "reason") else type(exc).__name__,
        }


def rust_p2p_start(args: argparse.Namespace) -> dict[str, object]:
    """Applies live-wire P2P preferences and asks Rust to connect."""

    steps: list[dict[str, object]] = []
    if args.ensure_preferences:
        steps.append(
            request_json_attempt(
                args.base_url,
                "/app/preferences",
                api_key=args.api_key,
                method="PATCH",
                body={
                    "autoConnect": True,
                    "reconnect": True,
                    "networkKademlia": True,
                    "networkEd2k": True,
                },
                timeout_seconds=args.timeout_seconds,
            )
        )
    steps.append(
        request_json_attempt(
            args.base_url,
            "/servers/operations/connect",
            api_key=args.api_key,
            method="POST",
            body={},
            timeout_seconds=args.timeout_seconds,
        )
    )
    if args.start_kad:
        steps.append(
            request_json_attempt(
                args.base_url,
                "/kad/operations/start",
                api_key=args.api_key,
                method="POST",
                body={},
                timeout_seconds=args.timeout_seconds,
            )
        )
    return {"steps": steps, "sample": sample(args.base_url, args.api_key)}


def safe_int(value: object) -> int | None:
    """Converts JSON-ish values to int when possible."""

    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ed2k_visibility_projection(published: object, pending: object) -> dict[str, object]:
    """Estimates remaining ED2K server visibility at the MFC-compatible cadence."""

    published_count = safe_int(published)
    pending_count = safe_int(pending)
    if published_count is None or pending_count is None:
        return {}
    total = published_count + pending_count
    percent = round((published_count / total) * 100.0, 2) if total > 0 else 100.0
    batches_remaining = (pending_count + ED2K_OFFER_BATCH_SIZE - 1) // ED2K_OFFER_BATCH_SIZE
    return {
        "ed2kOfferBatchSize": ED2K_OFFER_BATCH_SIZE,
        "ed2kOfferIntervalSeconds": ED2K_OFFER_INTERVAL_SECONDS,
        "ed2kVisibilityPercent": percent,
        "ed2kVisibilityEtaSeconds": batches_remaining * ED2K_OFFER_INTERVAL_SECONDS,
    }


def sanitize_status(status: dict[str, object]) -> dict[str, object]:
    """Extracts parity-relevant counters without file names, paths, or peer IDs."""

    stats = status.get("stats") if isinstance(status.get("stats"), dict) else {}
    kad = status.get("kad") if isinstance(status.get("kad"), dict) else {}
    servers = status.get("servers") if isinstance(status.get("servers"), dict) else {}
    runtime = status.get("runtimeDiagnostics") if isinstance(status.get("runtimeDiagnostics"), dict) else {}
    ed2k_publish = runtime.get("ed2kPublish") if isinstance(runtime.get("ed2kPublish"), dict) else {}
    kad_publish = runtime.get("kadPublish") if isinstance(runtime.get("kadPublish"), dict) else {}
    shared_reload = runtime.get("sharedReload") if isinstance(runtime.get("sharedReload"), dict) else {}
    ed2k_published = ed2k_publish.get("publishedEntries")
    ed2k_pending = ed2k_publish.get("pendingEntries")
    sanitized = {
        "ed2kConnected": servers.get("connected"),
        "ed2kHighId": not bool(servers.get("lowId")),
        "kadConnected": kad.get("connected"),
        "kadFirewalled": kad.get("firewalled"),
        "kadContactCount": kad.get("contactCount"),
        "kadUsers": kad.get("users"),
        "kadFiles": kad.get("files"),
        "activeUploads": stats.get("activeUploads"),
        "waitingUploads": stats.get("waitingUploads"),
        "uploadSpeedKiBps": round(float(stats.get("uploadSpeedKiBps") or 0.0), 2),
        "sharedHashingActive": stats.get("sharedHashingActive"),
        "sharedHashingCount": stats.get("sharedHashingCount"),
        "knownFileCount": runtime.get("knownFileCount"),
        "sharedFileCount": runtime.get("sharedFileCount"),
        "sharedReloadPhase": shared_reload.get("phase"),
        "sharedReloadScannedCount": shared_reload.get("scannedCount"),
        "sharedReloadPlannedHashCount": shared_reload.get("plannedHashCount"),
        "sharedReloadReusedCount": shared_reload.get("reusedCount"),
        "sharedReloadSkippedFailedCount": shared_reload.get("skippedFailedCount"),
        "sharedReloadSkippedIntakeCount": shared_reload.get("skippedIntakeCount"),
        "sharedReloadPrunedCount": shared_reload.get("prunedCount"),
        "ed2kPublishedEntries": ed2k_published,
        "ed2kPendingEntries": ed2k_pending,
        "ed2kPublishPhase": ed2k_publish.get("phase"),
        "kadPublishPhase": kad_publish.get("phase"),
        "kadGateAllowed": kad_publish.get("gateAllowed"),
        "kadGateBlockReason": kad_publish.get("gateBlockReason"),
        "kadInFlightCount": kad_publish.get("inFlightCount"),
        "kadInFlightBudget": kad_publish.get("inFlightBudget"),
        "kadAvailableSearchPermits": kad_publish.get("availableSearchPermits"),
        "kadActiveKeywordPublishes": kad_publish.get("activeKeywordPublishes"),
        "kadActiveSourcePublishes": kad_publish.get("activeSourcePublishes"),
        "kadActiveNotesPublishes": kad_publish.get("activeNotesPublishes"),
        "kadKeywordDueCount": kad_publish.get("keywordDueCount"),
        "kadSourceDueCount": kad_publish.get("sourceDueCount"),
        "kadNotesDueCount": kad_publish.get("notesDueCount"),
        "kadKeywordAttempted": kad_publish.get("keywordAttempted"),
        "kadSourceAttempted": kad_publish.get("sourceAttempted"),
        "kadNotesAttempted": kad_publish.get("notesAttempted"),
        "kadBusyCount": kad_publish.get("busyCount"),
        "kadTimedOutCount": kad_publish.get("timedOutCount"),
        "kadSourcePublishedTotal": kad_publish.get("sourcePublishedTotal"),
        "kadSourceAttemptedContactsTotal": kad_publish.get("sourceAttemptedContactsTotal"),
        "kadSourceAckedContactsTotal": kad_publish.get("sourceAckedContactsTotal"),
        "kadSourceContactTimeoutsTotal": kad_publish.get("sourceContactTimeoutsTotal"),
        "kadSourceFailed": kad_publish.get("sourceFailed"),
        "kadKeywordPublishedTotal": kad_publish.get("keywordPublishedTotal"),
        "kadKeywordAttemptedContactsTotal": kad_publish.get("keywordAttemptedContactsTotal"),
        "kadKeywordAckedContactsTotal": kad_publish.get("keywordAckedContactsTotal"),
        "kadKeywordContactTimeoutsTotal": kad_publish.get("keywordContactTimeoutsTotal"),
        "kadKeywordFailed": kad_publish.get("keywordFailed"),
    }
    sanitized.update(ed2k_visibility_projection(ed2k_published, ed2k_pending))
    return sanitized


def sample(base_url: str, api_key: str) -> dict[str, object]:
    """Returns a sanitized live Rust status sample."""

    return sanitize_status(request_json(base_url, "/status", api_key=api_key))


def normalize_private_path(value: object) -> str:
    """Returns a comparable path string that is never emitted directly."""

    text = str(value or "").strip().replace("/", "\\")
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    while len(text) > 3 and text.endswith("\\"):
        text = text[:-1]
    return text.lower()


def private_path_fingerprint(value: object) -> str:
    """Returns a stable short fingerprint for a private operator path."""

    normalized = normalize_private_path(value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def private_path_prefix_fingerprint(value: object, depth: int) -> str:
    """Returns a stable fingerprint for the first normalized path components."""

    normalized = normalize_private_path(value)
    parts = [part for part in normalized.split("\\") if part]
    if not parts:
        return private_path_fingerprint("")
    prefix = "\\".join(parts[: max(1, depth)])
    return private_path_fingerprint(prefix)


def summarize_shared_directory_rows(
    rows: object,
    *,
    include_fingerprints: bool = False,
    sample_limit: int = 20,
) -> dict[str, object]:
    """Summarizes shared-directory rows without returning paths."""

    if not isinstance(rows, list):
        rows = []
    summaries: list[dict[str, object]] = []
    fingerprints: list[str] = []
    duplicate_count = 0
    seen: set[str] = set()
    counts = {
        "accessible": 0,
        "inaccessible": 0,
        "shareable": 0,
        "unshareable": 0,
        "recursive": 0,
        "nonRecursive": 0,
        "monitorOwned": 0,
        "userOwned": 0,
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        path_fingerprint = private_path_fingerprint(row.get("path"))
        if path_fingerprint in seen:
            duplicate_count += 1
        seen.add(path_fingerprint)
        fingerprints.append(path_fingerprint)
        accessible = bool(row.get("accessible"))
        shareable = bool(row.get("shareable"))
        recursive = bool(row.get("recursive"))
        monitor_owned = bool(row.get("monitorOwned"))
        counts["accessible" if accessible else "inaccessible"] += 1
        counts["shareable" if shareable else "unshareable"] += 1
        counts["recursive" if recursive else "nonRecursive"] += 1
        counts["monitorOwned" if monitor_owned else "userOwned"] += 1
        summaries.append(
            {
                "fingerprint": path_fingerprint,
                "accessible": accessible,
                "shareable": shareable,
                "recursive": recursive,
                "monitorOwned": monitor_owned,
            }
        )
    fingerprints = sorted(fingerprints)
    summaries.sort(key=lambda row: str(row["fingerprint"]))
    summary: dict[str, object] = {
        "count": len(summaries),
        "duplicateCount": duplicate_count,
        "counts": counts,
        "fingerprintCount": len(fingerprints),
        "fingerprintSample": fingerprints[:sample_limit],
    }
    if include_fingerprints:
        summary["fingerprints"] = fingerprints
        summary["rows"] = summaries
    return summary


def shared_directory_fingerprints(rows: object) -> list[str]:
    """Returns full path fingerprints for internal comparison."""

    if not isinstance(rows, list):
        return []
    return sorted(
        private_path_fingerprint(row.get("path"))
        for row in rows
        if isinstance(row, dict)
    )


def summarize_shared_directories(
    base_url: str,
    api_key: str,
    label: str,
    *,
    include_fingerprints: bool = False,
    sample_limit: int = 20,
) -> dict[str, object]:
    """Returns sanitized shared-directory and shared-file totals for one client."""

    directories = request_json(base_url, "/shared-directories", api_key=api_key)
    files = request_json(base_url, "/shared-files?offset=0&limit=1", api_key=api_key)
    root_fingerprints = shared_directory_fingerprints(directories.get("roots"))
    item_fingerprints = shared_directory_fingerprints(directories.get("items"))
    roots = summarize_shared_directory_rows(
        directories.get("roots"),
        include_fingerprints=include_fingerprints,
        sample_limit=sample_limit,
    )
    items = summarize_shared_directory_rows(
        directories.get("items"),
        include_fingerprints=include_fingerprints,
        sample_limit=sample_limit,
    )
    reload_diag = directories.get("reload") if isinstance(directories.get("reload"), dict) else {}
    total = files.get("total")
    root_set = set(root_fingerprints)
    item_set = set(item_fingerprints)
    return {
        "label": label,
        "baseUrl": base_url,
        "sharedFilesTotal": total,
        "roots": roots,
        "items": items,
        "rootFingerprints": root_fingerprints if include_fingerprints else root_fingerprints[:sample_limit],
        "itemFingerprints": item_fingerprints if include_fingerprints else item_fingerprints[:sample_limit],
        "rootFingerprintCount": len(root_fingerprints),
        "itemFingerprintCount": len(item_fingerprints),
        "monitorOwnedCount": len(directories.get("monitorOwned") or []),
        "rootsMissingFromItems": sorted(root_set - item_set)[:sample_limit],
        "itemsMissingFromRoots": sorted(item_set - root_set)[:sample_limit],
        "rootsMissingFromItemsCount": len(root_set - item_set),
        "itemsMissingFromRootsCount": len(item_set - root_set),
        "hashingCount": directories.get("hashingCount"),
        "reload": {
            "phase": reload_diag.get("phase"),
            "running": reload_diag.get("running"),
            "pending": reload_diag.get("pending"),
            "scannedCount": reload_diag.get("scannedCount"),
            "plannedHashCount": reload_diag.get("plannedHashCount"),
            "reusedCount": reload_diag.get("reusedCount"),
            "skippedIntakeCount": reload_diag.get("skippedIntakeCount"),
            "prunedCount": reload_diag.get("prunedCount"),
            "staleHashCount": reload_diag.get("staleHashCount"),
        },
    }


def compare_shared_summaries(rust: dict[str, object], mfc: dict[str, object] | None) -> dict[str, object]:
    """Compares sanitized shared-directory summaries."""

    if mfc is None:
        return {"enabled": False}
    if mfc.get("available") is False or mfc.get("error"):
        return {"enabled": False, "reason": "mfc-unavailable"}
    rust_roots = rust.get("roots") if isinstance(rust.get("roots"), dict) else {}
    mfc_roots = mfc.get("roots") if isinstance(mfc.get("roots"), dict) else {}
    rust_fingerprints = set(rust.get("rootFingerprints") or rust_roots.get("fingerprints") or [])
    mfc_fingerprints = set(mfc.get("rootFingerprints") or mfc_roots.get("fingerprints") or [])
    rust_total = safe_int(rust.get("sharedFilesTotal"))
    mfc_total = safe_int(mfc.get("sharedFilesTotal"))
    rust_only = sorted(rust_fingerprints - mfc_fingerprints)
    mfc_only = sorted(mfc_fingerprints - rust_fingerprints)
    return {
        "enabled": True,
        "rootFingerprintsMatch": rust_fingerprints == mfc_fingerprints,
        "rustOnlyRootFingerprintCount": len(rust_only),
        "mfcOnlyRootFingerprintCount": len(mfc_only),
        "rustOnlyRootFingerprints": rust_only[:20],
        "mfcOnlyRootFingerprints": mfc_only[:20],
        "sharedFilesDeltaRustMinusMfc": None
        if rust_total is None or mfc_total is None
        else rust_total - mfc_total,
    }


def compact_shared_endpoint_summary(summary: dict[str, object], sample_limit: int) -> dict[str, object]:
    """Drops full fingerprint lists from one endpoint summary."""

    compact = dict(summary)
    for key in ("rootFingerprints", "itemFingerprints", "rootsMissingFromItems", "itemsMissingFromRoots"):
        value = compact.get(key)
        if isinstance(value, list):
            compact[key] = value[:sample_limit]
    for key in ("roots", "items"):
        value = compact.get(key)
        if isinstance(value, dict):
            row = dict(value)
            fingerprints = row.pop("fingerprints", None)
            row.pop("rows", None)
            if isinstance(fingerprints, list):
                row["fingerprintSample"] = fingerprints[:sample_limit]
            compact[key] = row
    return compact


def unavailable_shared_endpoint_summary(label: str, exc: BaseException) -> dict[str, object]:
    """Returns a sanitized optional endpoint failure for retained soak evidence."""

    return {
        "label": label,
        "available": False,
        "error": exc.__class__.__name__,
    }


def shared_file_row_hash(row: dict[str, object]) -> str:
    """Returns the lowercase ED2K hash from a shared-file REST row."""

    return str(row.get("hash") or row.get("fileHash") or "").strip().lower()


def shared_file_hash_fingerprint(file_hash: str) -> str:
    """Returns a short fingerprint for a shared-file hash."""

    return hashlib.sha256(file_hash.encode("ascii", errors="ignore")).hexdigest()[:16]


def shared_file_page_items(payload: dict[str, object]) -> tuple[list[dict[str, object]], int | None]:
    """Extracts one shared-files page from either envelope shape."""

    items = payload.get("items")
    if not isinstance(items, list):
        raise RuntimeError("shared-files response did not contain an items list")
    total = safe_int(payload.get("total"))
    return [item for item in items if isinstance(item, dict)], total


def fetch_shared_file_hashes(
    base_url: str,
    api_key: str,
    *,
    page_size: int,
    timeout_seconds: float,
    sleep_seconds: float,
) -> dict[str, object]:
    """Fetches all shared-file hashes without retaining names or paths."""

    hashes: list[str] = []
    offset = 0
    total: int | None = None
    while total is None or len(hashes) < total:
        page, page_total = shared_file_page_items(
            request_json(
                base_url,
                f"/shared-files?offset={offset}&limit={page_size}",
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
        )
        if total is None:
            total = page_total
        page_hashes = [shared_file_row_hash(row) for row in page]
        page_hashes = [file_hash for file_hash in page_hashes if file_hash]
        hashes.extend(page_hashes)
        if not page:
            break
        offset += len(page)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    counts = Counter(hashes)
    duplicate_hashes = sorted(file_hash for file_hash, count in counts.items() if count > 1)
    return {
        "total": total,
        "rowCount": len(hashes),
        "uniqueHashCount": len(counts),
        "duplicateHashCount": len(duplicate_hashes),
        "hashes": set(counts),
        "duplicateHashFingerprints": [shared_file_hash_fingerprint(file_hash) for file_hash in duplicate_hashes[:20]],
    }


def shared_file_row_path(row: dict[str, object]) -> str:
    """Returns a normalized private path from a shared-file REST row."""

    path = str(row.get("path") or "").strip()
    if path:
        return normalize_private_path(path)
    directory = str(row.get("directory") or "").strip()
    name = str(row.get("name") or "").strip()
    if directory and name:
        return normalize_private_path(str(Path(directory) / name))
    return ""


def fetch_shared_file_catalog(
    base_url: str,
    api_key: str,
    *,
    page_size: int,
    timeout_seconds: float,
    sleep_seconds: float,
) -> dict[str, object]:
    """Fetches all shared-file rows as path fingerprints and hashes only."""

    by_path: dict[str, str] = {}
    path_duplicates = 0
    row_count = 0
    offset = 0
    total: int | None = None
    while total is None or row_count < total:
        page, page_total = shared_file_page_items(
            request_json(
                base_url,
                f"/shared-files?offset={offset}&limit={page_size}",
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
        )
        if total is None:
            total = page_total
        for row in page:
            file_hash = shared_file_row_hash(row)
            path = shared_file_row_path(row)
            if not file_hash or not path:
                continue
            path_fingerprint = private_path_fingerprint(path)
            if path_fingerprint in by_path:
                path_duplicates += 1
            by_path[path_fingerprint] = file_hash
        row_count += len(page)
        if not page:
            break
        offset += len(page)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    return {
        "total": total,
        "rowCount": row_count,
        "pathCount": len(by_path),
        "duplicatePathCount": path_duplicates,
        "byPath": by_path,
    }


def shared_root_paths(directories: dict[str, object]) -> list[str]:
    """Returns normalized share roots used for path grouping."""

    rows = directories.get("items")
    if not isinstance(rows, list):
        rows = directories.get("roots")
    if not isinstance(rows, list):
        return []
    roots = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("shareable") is False or row.get("accessible") is False:
            continue
        root = normalize_private_path(row.get("path"))
        if root:
            roots.append(root)
    return sorted(set(roots), key=lambda value: (-len(value), value))


def shared_root_for_path(path: str, roots: list[str]) -> str:
    """Returns the longest matching normalized root for one normalized path."""

    for root in sorted(roots, key=lambda value: (-len(value), value)):
        if path == root or path.startswith(root + "\\"):
            return private_path_fingerprint(root)
    return "unmatched"


def add_unmatched_prefix_groups(
    groups_by_depth: dict[int, dict[str, dict[str, object]]],
    path: str,
    file_hash: str,
) -> None:
    """Adds one unmatched shared-file path to sanitized prefix buckets."""

    for depth in (2, 3, 4):
        prefix = private_path_prefix_fingerprint(path, depth)
        groups = groups_by_depth.setdefault(depth, {})
        group = groups.setdefault(
            prefix,
            {
                "prefixFingerprint": prefix,
                "rowCount": 0,
                "hashes": set(),
            },
        )
        group["rowCount"] = int(group["rowCount"]) + 1
        hashes = group["hashes"]
        assert isinstance(hashes, set)
        hashes.add(file_hash)


def compact_unmatched_prefix_groups(
    groups_by_depth: dict[int, dict[str, dict[str, object]]],
    *,
    sample_limit: int = 20,
) -> dict[str, list[dict[str, object]]]:
    """Returns bounded sanitized prefix groups for unmatched shared files."""

    result: dict[str, list[dict[str, object]]] = {}
    for depth, groups in sorted(groups_by_depth.items()):
        rows = []
        for group in groups.values():
            hashes = group["hashes"]
            assert isinstance(hashes, set)
            rows.append(
                {
                    "prefixFingerprint": group["prefixFingerprint"],
                    "rowCount": group["rowCount"],
                    "uniqueHashCount": len(hashes),
                }
            )
        rows.sort(key=lambda row: (-int(row["rowCount"]), str(row["prefixFingerprint"])))
        result[f"depth{depth}"] = rows[:sample_limit]
    return result


def fetch_shared_file_catalog_by_root(
    base_url: str,
    api_key: str,
    *,
    page_size: int,
    timeout_seconds: float,
    sleep_seconds: float,
) -> dict[str, object]:
    """Fetches shared-file catalog counts grouped by sanitized shared root."""

    directories = request_json(base_url, "/shared-directories", api_key=api_key)
    roots = shared_root_paths(directories)
    groups: dict[str, dict[str, object]] = {}
    unmatched_prefix_groups: dict[int, dict[str, dict[str, object]]] = {}
    row_count = 0
    offset = 0
    total: int | None = None
    while total is None or row_count < total:
        page, page_total = shared_file_page_items(
            request_json(
                base_url,
                f"/shared-files?offset={offset}&limit={page_size}",
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
        )
        if total is None:
            total = page_total
        for row in page:
            file_hash = shared_file_row_hash(row)
            path = shared_file_row_path(row)
            if not file_hash or not path:
                continue
            root = shared_root_for_path(path, roots)
            if root == "unmatched":
                add_unmatched_prefix_groups(unmatched_prefix_groups, path, file_hash)
            group = groups.setdefault(
                root,
                {
                    "rootFingerprint": root,
                    "rowCount": 0,
                    "pathFingerprints": set(),
                    "hashes": set(),
                },
            )
            group["rowCount"] = int(group["rowCount"]) + 1
            path_fingerprints = group["pathFingerprints"]
            hashes = group["hashes"]
            assert isinstance(path_fingerprints, set)
            assert isinstance(hashes, set)
            path_fingerprints.add(private_path_fingerprint(path))
            hashes.add(file_hash)
        row_count += len(page)
        if not page:
            break
        offset += len(page)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    compact_groups = []
    for group in groups.values():
        path_fingerprints = group["pathFingerprints"]
        hashes = group["hashes"]
        assert isinstance(path_fingerprints, set)
        assert isinstance(hashes, set)
        compact_groups.append(
            {
                "rootFingerprint": group["rootFingerprint"],
                "rowCount": group["rowCount"],
                "pathCount": len(path_fingerprints),
                "uniqueHashCount": len(hashes),
            }
        )
    compact_groups.sort(key=lambda group: (-int(group["rowCount"]), str(group["rootFingerprint"])))
    return {
        "total": total,
        "rowCount": row_count,
        "rootCount": len(roots),
        "groupCount": len(compact_groups),
        "groups": compact_groups,
        "unmatchedPrefixGroups": compact_unmatched_prefix_groups(unmatched_prefix_groups),
    }


def fetch_shared_file_rows(
    base_url: str,
    api_key: str,
    *,
    page_size: int,
    timeout_seconds: float,
    sleep_seconds: float,
) -> list[dict[str, object]]:
    """Fetches all shared-file rows from one REST endpoint."""

    rows: list[dict[str, object]] = []
    offset = 0
    total: int | None = None
    while total is None or len(rows) < total:
        page, page_total = shared_file_page_items(
            request_json(
                base_url,
                f"/shared-files?offset={offset}&limit={page_size}",
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
        )
        if total is None:
            total = page_total
        rows.extend(row for row in page if isinstance(row, dict))
        if not page:
            break
        offset += len(page)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    return rows


def compact_shared_catalog_summary(summary: dict[str, object]) -> dict[str, object]:
    """Drops path-to-hash maps from a shared-file catalog summary."""

    compact = dict(summary)
    compact.pop("byPath", None)
    return compact


def compact_shared_root_catalog_summary(
    summary: dict[str, object],
    *,
    sample_limit: int = 20,
) -> dict[str, object]:
    """Keeps root-group diagnostics bounded unless a full dump is requested."""

    compact = dict(summary)
    groups = compact.pop("groups", [])
    compact["topGroups"] = groups[:sample_limit] if isinstance(groups, list) else []
    return compact


def compare_shared_file_root_groups(
    rust: dict[str, object],
    mfc: dict[str, object],
) -> dict[str, object]:
    """Compares per-root shared-file catalog counts."""

    rust_groups = {
        str(group.get("rootFingerprint")): group
        for group in rust.get("groups", [])
        if isinstance(group, dict)
    }
    mfc_groups = {
        str(group.get("rootFingerprint")): group
        for group in mfc.get("groups", [])
        if isinstance(group, dict)
    }
    roots = sorted(set(rust_groups) | set(mfc_groups))
    deltas = []
    for root in roots:
        rust_group = rust_groups.get(root, {})
        mfc_group = mfc_groups.get(root, {})
        rust_rows = safe_int(rust_group.get("rowCount")) or 0
        mfc_rows = safe_int(mfc_group.get("rowCount")) or 0
        rust_hashes = safe_int(rust_group.get("uniqueHashCount")) or 0
        mfc_hashes = safe_int(mfc_group.get("uniqueHashCount")) or 0
        if rust_rows == mfc_rows and rust_hashes == mfc_hashes:
            continue
        deltas.append(
            {
                "rootFingerprint": root,
                "rustRows": rust_rows,
                "mfcRows": mfc_rows,
                "rowDeltaRustMinusMfc": rust_rows - mfc_rows,
                "rustUniqueHashes": rust_hashes,
                "mfcUniqueHashes": mfc_hashes,
                "uniqueHashDeltaRustMinusMfc": rust_hashes - mfc_hashes,
            }
        )
    deltas.sort(
        key=lambda row: (
            -abs(int(row["rowDeltaRustMinusMfc"])),
            str(row["rootFingerprint"]),
        )
    )
    return {
        "enabled": True,
        "rootGroupsMatch": not deltas,
        "differingRootGroupCount": len(deltas),
        "topDeltas": deltas[:20],
    }


def compare_shared_file_catalogs(
    rust: dict[str, object],
    mfc: dict[str, object],
) -> dict[str, object]:
    """Compares path-fingerprint keyed shared-file catalogs."""

    rust_by_path = rust.get("byPath") if isinstance(rust.get("byPath"), dict) else {}
    mfc_by_path = mfc.get("byPath") if isinstance(mfc.get("byPath"), dict) else {}
    rust_paths = set(rust_by_path)
    mfc_paths = set(mfc_by_path)
    rust_only_paths = sorted(rust_paths - mfc_paths)
    mfc_only_paths = sorted(mfc_paths - rust_paths)
    changed_paths = sorted(
        path for path in rust_paths & mfc_paths if rust_by_path.get(path) != mfc_by_path.get(path)
    )
    return {
        "enabled": True,
        "pathFingerprintsMatch": rust_paths == mfc_paths,
        "rustOnlyPathCount": len(rust_only_paths),
        "mfcOnlyPathCount": len(mfc_only_paths),
        "changedHashForSamePathCount": len(changed_paths),
        "rustOnlyPathFingerprints": rust_only_paths[:20],
        "mfcOnlyPathFingerprints": mfc_only_paths[:20],
        "changedPathFingerprints": changed_paths[:20],
        "changedPathHashFingerprints": [
            {
                "path": path,
                "rust": shared_file_hash_fingerprint(str(rust_by_path.get(path) or "")),
                "mfc": shared_file_hash_fingerprint(str(mfc_by_path.get(path) or "")),
            }
            for path in changed_paths[:20]
        ],
    }


def compact_shared_hash_summary(summary: dict[str, object]) -> dict[str, object]:
    """Drops full file-hash sets from a shared-file hash summary."""

    compact = dict(summary)
    compact.pop("hashes", None)
    return compact


def compare_shared_file_hashes(
    rust: dict[str, object],
    mfc: dict[str, object],
) -> dict[str, object]:
    """Compares Rust and MFC shared-file hash sets."""

    rust_hashes = set(rust.get("hashes") or [])
    mfc_hashes = set(mfc.get("hashes") or [])
    rust_only = sorted(rust_hashes - mfc_hashes)
    mfc_only = sorted(mfc_hashes - rust_hashes)
    return {
        "enabled": True,
        "uniqueHashesMatch": rust_hashes == mfc_hashes,
        "rustOnlyUniqueHashCount": len(rust_only),
        "mfcOnlyUniqueHashCount": len(mfc_only),
        "rustOnlyHashFingerprints": [shared_file_hash_fingerprint(file_hash) for file_hash in rust_only[:20]],
        "mfcOnlyHashFingerprints": [shared_file_hash_fingerprint(file_hash) for file_hash in mfc_only[:20]],
        "rustDuplicateHashCount": rust.get("duplicateHashCount"),
        "mfcDuplicateHashCount": mfc.get("duplicateHashCount"),
        "uniqueHashDeltaRustMinusMfc": len(rust_hashes) - len(mfc_hashes),
        "rowCountDeltaRustMinusMfc": safe_int(rust.get("rowCount")) - safe_int(mfc.get("rowCount"))
        if safe_int(rust.get("rowCount")) is not None and safe_int(mfc.get("rowCount")) is not None
        else None,
    }


def shared_summary(args: argparse.Namespace) -> dict[str, object]:
    """Returns sanitized shared-library parity metadata for Rust and optional MFC."""

    rust = summarize_shared_directories(
        args.base_url,
        args.api_key,
        "rust",
        include_fingerprints=True,
        sample_limit=args.fingerprint_sample_limit,
    )
    mfc = None
    if args.mfc_base_url:
        try:
            mfc = summarize_shared_directories(
                args.mfc_base_url,
                args.mfc_api_key,
                "mfc",
                include_fingerprints=True,
                sample_limit=args.fingerprint_sample_limit,
            )
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as exc:
            mfc = unavailable_shared_endpoint_summary("mfc", exc)
    comparison = compare_shared_summaries(rust, mfc)
    if not args.include_fingerprints:
        rust = compact_shared_endpoint_summary(rust, args.fingerprint_sample_limit)
        mfc = compact_shared_endpoint_summary(mfc, args.fingerprint_sample_limit) if mfc is not None else None
    result: dict[str, object] = {"rust": rust, "mfc": mfc, "comparison": comparison}
    if args.compare_shared_file_hashes:
        if not args.mfc_base_url:
            raise RuntimeError("--compare-shared-file-hashes requires --mfc-base-url")
        if mfc is not None and mfc.get("available") is False:
            raise RuntimeError("MFC shared summary unavailable; cannot compare shared-file hashes")
        rust_hashes = fetch_shared_file_hashes(
            args.base_url,
            args.api_key,
            page_size=args.shared_file_page_size,
            timeout_seconds=args.shared_file_timeout_seconds,
            sleep_seconds=args.shared_file_sleep_seconds,
        )
        mfc_hashes = fetch_shared_file_hashes(
            args.mfc_base_url,
            args.mfc_api_key,
            page_size=args.shared_file_page_size,
            timeout_seconds=args.shared_file_timeout_seconds,
            sleep_seconds=args.shared_file_sleep_seconds,
        )
        result["sharedFileHashes"] = {
            "rust": compact_shared_hash_summary(rust_hashes),
            "mfc": compact_shared_hash_summary(mfc_hashes),
            "comparison": compare_shared_file_hashes(rust_hashes, mfc_hashes),
        }
    if args.compare_shared_file_paths:
        if not args.mfc_base_url:
            raise RuntimeError("--compare-shared-file-paths requires --mfc-base-url")
        if mfc is not None and mfc.get("available") is False:
            raise RuntimeError("MFC shared summary unavailable; cannot compare shared-file paths")
        rust_catalog = fetch_shared_file_catalog(
            args.base_url,
            args.api_key,
            page_size=args.shared_file_page_size,
            timeout_seconds=args.shared_file_timeout_seconds,
            sleep_seconds=args.shared_file_sleep_seconds,
        )
        mfc_catalog = fetch_shared_file_catalog(
            args.mfc_base_url,
            args.mfc_api_key,
            page_size=args.shared_file_page_size,
            timeout_seconds=args.shared_file_timeout_seconds,
            sleep_seconds=args.shared_file_sleep_seconds,
        )
        result["sharedFilePaths"] = {
            "rust": compact_shared_catalog_summary(rust_catalog),
            "mfc": compact_shared_catalog_summary(mfc_catalog),
            "comparison": compare_shared_file_catalogs(rust_catalog, mfc_catalog),
        }
    if args.compare_shared_file_roots:
        if not args.mfc_base_url:
            raise RuntimeError("--compare-shared-file-roots requires --mfc-base-url")
        if mfc is not None and mfc.get("available") is False:
            raise RuntimeError("MFC shared summary unavailable; cannot compare shared-file roots")
        rust_root_catalog = fetch_shared_file_catalog_by_root(
            args.base_url,
            args.api_key,
            page_size=args.shared_file_page_size,
            timeout_seconds=args.shared_file_timeout_seconds,
            sleep_seconds=args.shared_file_sleep_seconds,
        )
        mfc_root_catalog = fetch_shared_file_catalog_by_root(
            args.mfc_base_url,
            args.mfc_api_key,
            page_size=args.shared_file_page_size,
            timeout_seconds=args.shared_file_timeout_seconds,
            sleep_seconds=args.shared_file_sleep_seconds,
        )
        result["sharedFileRootGroups"] = {
            "rust": rust_root_catalog
            if args.include_root_groups
            else compact_shared_root_catalog_summary(
                rust_root_catalog,
                sample_limit=args.fingerprint_sample_limit,
            ),
            "mfc": mfc_root_catalog
            if args.include_root_groups
            else compact_shared_root_catalog_summary(
                mfc_root_catalog,
                sample_limit=args.fingerprint_sample_limit,
            ),
            "comparison": compare_shared_file_root_groups(rust_root_catalog, mfc_root_catalog),
        }
    return result


def apply_mfc_shared_roots(args: argparse.Namespace) -> dict[str, object]:
    """Applies MFC persisted shared-root intent to the Rust REST profile."""

    shareddir_file = args.shared_dir_file
    if not shareddir_file.is_file():
        discovered = discover_mfc_shareddir_file() if args.auto_discover else None
        if discovered is None:
            raise RuntimeError("--shared-dir-file does not exist")
        shareddir_file = discovered
    root_entries = load_shareddir_root_entries(
        shareddir_file,
        extra_roots=[args.extra_root] if args.extra_root is not None else None,
    )
    existing_entries, skipped_inaccessible = existing_shared_roots(root_entries)
    payload_roots = [normalize_shared_root_entry(root) for root in existing_entries]
    response = request_json(
        args.base_url,
        "/shared-directories",
        api_key=args.api_key,
        method="PATCH",
        body={"confirmReplaceRoots": True, "roots": payload_roots},
        timeout_seconds=args.timeout_seconds,
    )
    roots = response.get("roots")
    items = response.get("items")
    recursive_count = sum(1 for root in existing_entries if shared_root_is_recursive(root))
    return {
        "applied": True,
        "source": {
            "shareddirPresent": True,
            "shareddirSource": "explicit" if shareddir_file == args.shared_dir_file else "discovered",
            "inputRootCount": len(root_entries),
            "existingRootCount": len(existing_entries),
            "skippedInaccessibleRootCount": skipped_inaccessible,
            "recursiveRootCount": recursive_count,
            "flatRootCount": len(existing_entries) - recursive_count,
        },
        "rust": {
            "roots": summarize_shared_directory_rows(roots),
            "items": summarize_shared_directory_rows(items),
            "hashingCount": response.get("hashingCount"),
            "reload": response.get("reload"),
        },
    }


def mfc_rest_shared_root_entries(
    mfc_base_url: str,
    mfc_api_key: str,
    *,
    collection: str,
) -> list[object]:
    """Loads shared-directory roots/items from the live MFC REST model."""

    model = request_json(mfc_base_url, "/shared-directories", api_key=mfc_api_key, timeout_seconds=120.0)
    roots = model.get(collection)
    if not isinstance(roots, list):
        return []
    entries: list[object] = []
    for row in roots:
        if not isinstance(row, dict):
            continue
        if row.get("accessible") is False or row.get("shareable") is False:
            continue
        path = str(row.get("path") or "").strip()
        if not path:
            continue
        if row.get("recursive") is True:
            entries.append({"path": path, "recursive": True})
        else:
            entries.append(path)
    return entries


def shared_directory_model_persistence_lists(model: dict[str, object]) -> dict[str, list[str]]:
    """Builds MFC shared-directory persistence lists from one REST model."""

    roots = model.get("roots") if isinstance(model.get("roots"), list) else []
    items = model.get("items") if isinstance(model.get("items"), list) else []

    def usable_row_path(row: object) -> str:
        if not isinstance(row, dict):
            return ""
        if row.get("accessible") is False or row.get("shareable") is False:
            return ""
        return shared_root_path(normalize_shared_root_entry(row.get("path")))

    shared_dirs = [path for path in (usable_row_path(row) for row in items) if path]
    shared_keys = {normalize_private_path(path) for path in shared_dirs}
    monitored_roots = [
        path
        for path in (usable_row_path(row) for row in roots if isinstance(row, dict) and row.get("recursive") is True)
        if path and normalize_private_path(path) in shared_keys
    ]

    row_monitor_owned = [
        path
        for path in (usable_row_path(row) for row in items if isinstance(row, dict) and row.get("monitorOwned") is True)
        if path
    ]
    top_level_monitor_owned: list[str] = []
    monitor_owned_value = model.get("monitorOwned")
    if isinstance(monitor_owned_value, list):
        for entry in monitor_owned_value:
            path = shared_root_path(normalize_shared_root_entry(entry))
            if path and normalize_private_path(path) in shared_keys:
                top_level_monitor_owned.append(path)

    monitor_owned = row_monitor_owned + top_level_monitor_owned

    def dedupe_paths(paths: list[str]) -> list[str]:
        return [shared_root_path(root) for root in soak_launch.dedupe_shared_roots(list(paths))]

    return {
        "shared": dedupe_paths(shared_dirs),
        "monitored": dedupe_paths(monitored_roots),
        "monitorOwned": dedupe_paths(monitor_owned),
    }


def write_mfc_shareddir_from_rest(args: argparse.Namespace) -> dict[str, object]:
    """Writes MFC shared-directory profile files from a live REST model."""

    target_config_dir = args.target_profile_dir / "config"
    if not target_config_dir.is_dir():
        raise RuntimeError(f"Target MFC profile is missing a config directory: {target_config_dir}")

    model = request_json(
        args.source_base_url,
        "/shared-directories",
        api_key=args.source_api_key,
        timeout_seconds=args.timeout_seconds,
    )
    lists = shared_directory_model_persistence_lists(model)
    if not lists["shared"]:
        raise RuntimeError("Source REST shared-directory model did not contain any shareable item paths")

    targets = {
        "shared": target_config_dir / "shareddir.dat",
        "monitored": target_config_dir / "shareddir.monitored.dat",
        "monitorOwned": target_config_dir / "shareddir.monitor-owned.dat",
    }
    if not args.dry_run:
        for key, path in targets.items():
            write_shared_directories_file(path, lists[key])

    return {
        "written": not args.dry_run,
        "sourceBaseUrl": args.source_base_url,
        "targetConfigDir": str(target_config_dir),
        "counts": {key: len(value) for key, value in lists.items()},
        "fingerprintSamples": {
            key: [private_path_fingerprint(path) for path in value[: args.fingerprint_sample_limit]]
            for key, value in lists.items()
        },
        "files": {key: str(path) for key, path in targets.items()},
    }


def apply_mfc_rest_shared_roots(args: argparse.Namespace) -> dict[str, object]:
    """Applies the live MFC REST configured shared roots to Rust."""

    root_entries = mfc_rest_shared_root_entries(
        args.mfc_base_url,
        args.mfc_api_key,
        collection=args.collection,
    )
    if not root_entries:
        raise RuntimeError("MFC REST returned no shared-directory entries")
    payload_roots = [normalize_shared_root_entry(root) for root in root_entries]
    response = request_json(
        args.base_url,
        "/shared-directories",
        api_key=args.api_key,
        method="PATCH",
        body={"confirmReplaceRoots": True, "roots": payload_roots},
        timeout_seconds=args.timeout_seconds,
    )
    roots = response.get("roots")
    items = response.get("items")
    recursive_count = sum(1 for root in root_entries if shared_root_is_recursive(root))
    return {
        "applied": True,
        "source": {
            "mfcRestCollection": args.collection,
            "mfcRestRootCount": len(root_entries),
            "recursiveRootCount": recursive_count,
            "flatRootCount": len(root_entries) - recursive_count,
        },
        "rust": {
            "roots": summarize_shared_directory_rows(roots),
            "items": summarize_shared_directory_rows(items),
            "hashingCount": response.get("hashingCount"),
            "reload": response.get("reload"),
        },
    }


def repair_rust_metadata_from_mfc_rest(args: argparse.Namespace) -> dict[str, object]:
    """Seeds Rust metadata from live MFC REST shared files plus MFC known.met."""

    if args.known_met is not None:
        known_met = args.known_met
        known_met_source = "explicit"
    else:
        known_met = discover_mfc_known_met_from_processes()
        known_met_source = "process"
        if known_met is None and args.allow_known_met_fallback:
            known_met = discover_mfc_known_met_from_soak_output()
            known_met_source = "soak-output"
    if known_met is None or not known_met.is_file():
        raise RuntimeError("MFC known.met could not be resolved")
    rows = fetch_shared_file_rows(
        args.mfc_base_url,
        args.mfc_api_key,
        page_size=args.shared_file_page_size,
        timeout_seconds=args.shared_file_timeout_seconds,
        sleep_seconds=args.shared_file_sleep_seconds,
    )
    root_entries = mfc_rest_shared_root_entries(
        args.mfc_base_url,
        args.mfc_api_key,
        collection="items",
    )
    shared_roots = [Path(shared_root_path(root)) for root in root_entries]
    for extra_root in args.extra_root or []:
        shared_roots.append(Path(shared_root_path(normalize_shared_root_entry(str(extra_root)))))
    raw = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=args.rust_repo,
        metadata_db=args.metadata_db,
        known_met=known_met,
        shared_file_rows=rows,
        shared_roots=shared_roots,
        dry_run=args.dry_run,
    )
    return {
        "enabled": True,
        "status": "imported" if not args.dry_run else "dry-run",
        "knownMetResolved": True,
        "knownMetSource": known_met_source,
        "mfcSharedFileRowsFetched": len(rows),
        "mfcSharedRootItems": len(shared_roots),
        "knownMetRecords": raw["knownMetRecords"],
        "sharedFileRows": raw["sharedFileRows"],
        "matchedRows": raw["matchedRows"],
        "importedRows": raw["importedRows"],
        "dryRun": raw["dryRun"],
        "skipped": raw["skipped"],
    }


def pid_exists(pid: int) -> bool:
    """Returns whether a process id is currently live."""

    if pid <= 0:
        return False
    if os.name == "nt":
        return any(process.pid == pid for process in collect_processes())
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_pid_exit(pid: int, timeout_seconds: float) -> bool:
    """Waits for one process id to exit."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not pid_exists(pid):
            return True
        time.sleep(0.5)
    return not pid_exists(pid)


def terminate_pid_tree(pid: int, *, markers: tuple[str, ...] = (), timeout_seconds: float = 15.0) -> None:
    """Terminates one process tree after optional command-line marker checks."""

    if pid <= 0 or not pid_exists(pid):
        return
    if os.name == "nt":
        terminate_process_tree(
            pid,
            timeout_seconds=timeout_seconds,
            expected_command_line_markers=markers,
            expected_root_creation_date=process_creation_date(pid),
        )
        return
    os.kill(pid, signal.SIGTERM)
    if not wait_pid_exit(pid, timeout_seconds):
        os.kill(pid, signal.SIGKILL)


def request_rust_shutdown(base_url: str, api_key: str) -> None:
    """Requests Rust's graceful network/profile shutdown."""

    try:
        request_json(
            base_url,
            "/app/shutdown",
            api_key=api_key,
            method="POST",
            body={"confirmShutdown": True},
            timeout_seconds=10.0,
        )
    except (HTTPError, URLError, TimeoutError, OSError, RuntimeError):
        pass


def wait_rest_ready(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until Rust REST responds to /stats."""

    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return request_json(base_url, "/stats", api_key=api_key, timeout_seconds=5.0)
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as exc:
            last_error = exc
            time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for Rust REST readiness: {last_error}")


def wait_connected(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until Rust reports both ED2K and Kad connected."""

    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, object] = {}
    while time.monotonic() < deadline:
        latest = sample(base_url, api_key)
        if latest.get("ed2kConnected") is True and latest.get("kadConnected") is True:
            return latest
        time.sleep(2.0)
    raise RuntimeError(f"Timed out waiting for ED2K+Kad connected: {latest}")


def latest_diag_log(log_dir: Path, rust_pid: int | None = None) -> Path | None:
    """Returns the PID-specific Rust diagnostics JSONL when available."""

    if rust_pid is not None:
        candidate = log_dir / f"emulebb-rust-diag-{rust_pid}.jsonl"
        if candidate.exists():
            return candidate
    matches = sorted(log_dir.glob("emulebb-rust-diag-*.jsonl"), key=lambda path: path.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def start_rust(args: argparse.Namespace) -> dict[str, object]:
    """Starts the diagnostics daemon against the persisted runtime."""

    runtime_dir = args.runtime_dir
    log_dir = args.log_dir or runtime_dir / "packet-dump"
    config_path = args.config or runtime_dir / "emulebb-rust.toml"
    exe = args.exe
    if not exe.is_file():
        raise RuntimeError(f"Rust diagnostics executable was not found: {exe}")
    if not config_path.is_file():
        raise RuntimeError(f"Rust config was not found: {config_path}")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["EMULEBB_RUST_LOG_DIR"] = str(log_dir)
    stdout = (runtime_dir / "daemon.out").open("ab", buffering=0)
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    process = subprocess.Popen(
        [str(exe), "--config", str(config_path)],
        cwd=str(runtime_dir),
        env=env,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    wait_rest_ready(args.base_url, args.api_key, args.rest_timeout_seconds)
    if args.start_kad:
        request_json(args.base_url, "/kad/operations/start", api_key=args.api_key, method="POST", body={})
    connected = wait_connected(args.base_url, args.api_key, args.connect_timeout_seconds) if args.wait_connected else {}
    diag = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        diag = latest_diag_log(log_dir, process.pid)
        if diag is not None:
            break
        time.sleep(1.0)
    return {
        "rustPid": process.pid,
        "runtimeDir": str(runtime_dir),
        "logDir": str(log_dir),
        "diagLog": str(diag) if diag is not None else None,
        "connected": connected,
    }


def stop_rust(args: argparse.Namespace) -> dict[str, object]:
    """Stops Rust gracefully and falls back to exact process-tree termination."""

    request_rust_shutdown(args.base_url, args.api_key)
    exited = wait_pid_exit(args.pid, args.shutdown_timeout_seconds) if args.pid else True
    if args.pid and not exited:
        terminate_pid_tree(args.pid, markers=("emulebb-rust-diagnostics",), timeout_seconds=15.0)
    return {"rustPid": args.pid, "stopped": not args.pid or not pid_exists(args.pid)}


def rust_processes(_: argparse.Namespace) -> dict[str, object]:
    """Returns current eMuleBB Rust process rows through the Python WMI helper."""

    matches = [
        process
        for process in collect_processes()
        if process.name.lower().startswith("emulebb-rust")
    ]
    matches.sort(key=lambda process: (process.name.lower(), process.pid))
    return {
        "processes": [
            {
                "pid": process.pid,
                "parentPid": process.parent_pid,
                "name": process.name,
                "creationDate": process.creation_date,
                "commandLine": process.command_line,
            }
            for process in matches
        ]
    }


def mfc_processes(_: argparse.Namespace) -> dict[str, object]:
    """Returns sanitized running eMule-family process rows."""

    rows = []
    for process in collect_processes():
        command_line = process_command_line(process)
        identity = f"{process.name} {command_line}".lower()
        if "emule" not in identity or "emulebb-rust" in identity:
            continue
        profile_dir = command_line_profile_dir(command_line)
        known_met = profile_dir / "config" / "known.met" if profile_dir is not None else None
        rows.append(
            {
                "pid": process.pid,
                "parentPid": process.parent_pid,
                "name": process.name,
                "creationDate": process.creation_date,
                "hasProfileArg": profile_dir is not None,
                "knownMetPresent": bool(known_met and known_met.is_file()),
                "commandLineFingerprint": hashlib.sha256(command_line.encode("utf-8")).hexdigest()[:16],
            }
        )
    rows.sort(key=lambda row: (str(row["name"]).lower(), int(row["pid"])))
    return {"processes": rows}


def stop_mfc(args: argparse.Namespace) -> dict[str, object]:
    """Stops the MFC diagnostics client through REST and a bounded PID fallback."""

    request_rust_shutdown(args.base_url, args.api_key)
    exited = wait_pid_exit(args.pid, args.shutdown_timeout_seconds) if args.pid else True
    if args.pid and not exited:
        terminate_pid_tree(args.pid, markers=("emulebb-diagnostics",), timeout_seconds=15.0)
    return {"mfcPid": args.pid, "stopped": not args.pid or not pid_exists(args.pid)}


def start_mfc(args: argparse.Namespace) -> dict[str, object]:
    """Starts the MFC diagnostics client against the persistent soak profile."""

    rest_addr = args.rest_host or os.environ.get("X_LOCAL_IP", "").strip()
    if not rest_addr:
        raise RuntimeError("X_LOCAL_IP must be set or --rest-host supplied for MFC REST binding.")
    workspace_output = output_root()
    exe_path = args.exe or clw.resolve_mfc_diagnostics_exe(
        workspace_output,
        variant=args.mfc_variant,
        arch=args.mfc_arch,
        configuration=args.mfc_configuration,
    )
    if not args.skip_vpn_check:
        ensure_vpn_ready(exe_path, name="eMuleBB MFC")
    mods = soak_launch.load_helper_modules("mfc-restart")
    direct_profile_dir, profile_mode = resolve_mfc_start_profile(args)
    if direct_profile_dir is None:
        inputs_path = args.inputs or default_live_wire_inputs()
        rust_mod = mods["rust"]
        shared_roots = rust_mod.load_shared_roots(inputs_path)
        if not shared_roots:
            raise RuntimeError(f"No shared roots found in {inputs_path}")
    else:
        shared_roots = []
    handles = soak_launch.bring_up_mfc(
        live_common=mods["live_common"],
        rest_smoke=mods["rest_smoke"],
        shared_dirs_mod=mods["shared_dirs"],
        exe_path=exe_path,
        artifacts_dir=args.artifacts_dir,
        seed_config_dir=args.profile_seed_dir,
        direct_profile_dir=direct_profile_dir,
        rest_host=rest_addr,
        rest_port=args.rest_port,
        shared_roots=shared_roots,
        server_endpoint=args.server,
        obfuscation=not args.no_obfuscation,
        timeouts={"rest": args.rest_timeout_seconds, "connect": args.connect_timeout_seconds},
        upload_limit_kibps=args.upload_limit_kibps,
        ed2k_port=args.ed2k_port,
        kad_port=args.kad_port,
        server_udp_port=args.server_udp_port,
    )
    app = handles["app"]
    mfc_pid = mods["live_common"].resolve_app_process_id(app)
    log_dir = Path(str(handles["packetDumpDir"]))
    return {
        "mfcPid": mfc_pid,
        "baseUrl": handles["baseUrl"],
        "profileMode": profile_mode,
        "profileDir": str(direct_profile_dir) if direct_profile_dir is not None else None,
        "logDir": str(log_dir),
        "uploadLog": str(log_dir / "emulebb-diagnostics-upload-slot.log"),
    }


def stop_upload_monitor(output_dir: Path, timeout_seconds: float = 20.0) -> dict[str, object]:
    """Requests the upload parity monitor to stop through its stop file."""

    pid_path = output_dir / "upload-parity-monitor.pid"
    stop_path = output_dir / "upload-parity-monitor.stop"
    pid = int(pid_path.read_text(encoding="ascii").strip()) if pid_path.exists() else 0
    stop_path.parent.mkdir(parents=True, exist_ok=True)
    stop_path.write_text("stop\n", encoding="ascii")
    stopped = wait_pid_exit(pid, timeout_seconds) if pid else True
    if pid and not stopped:
        terminate_pid_tree(pid, markers=("upload-parity-monitor.py",), timeout_seconds=15.0)
    return {"monitorPid": pid or None, "stopped": not pid or not pid_exists(pid)}


def extract_command_line_option(command_line: str, option: str) -> str:
    """Extracts a quoted or unquoted option value from a process command line."""

    pattern = rf"(?:^|\s){re.escape(option)}\s+(?:\"([^\"]+)\"|(\S+))"
    match = re.search(pattern, command_line)
    if match is None:
        return ""
    return match.group(1) or match.group(2) or ""


def existing_monitor_mfc_upload_log(output_dir: Path) -> Path | None:
    """Returns the current monitor's MFC upload log argument without exposing it."""

    pid_path = output_dir / "upload-parity-monitor.pid"
    pid = int(pid_path.read_text(encoding="ascii").strip()) if pid_path.exists() else 0
    if not pid:
        return None
    command_line = process_command_line(pid)
    if not command_line:
        return None
    value = extract_command_line_option(command_line, "--mfc-upload-log")
    return Path(value) if value else None


def start_upload_monitor(args: argparse.Namespace) -> dict[str, object]:
    """Starts the existing upload parity monitor as a detached helper."""

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    stop_path = output_dir / "upload-parity-monitor.stop"
    if stop_path.exists():
        stop_path.unlink()
    diag_log = args.rust_diag_log or latest_diag_log(args.log_dir, args.rust_pid)
    script = SCRIPT_PATH.parent / "upload-parity-monitor.py"
    mfc_upload_log = args.mfc_upload_log or existing_monitor_mfc_upload_log(output_dir)
    if mfc_upload_log is None:
        mfc_upload_log = discover_mfc_upload_log(
            default_mfc_upload_log_search_roots(),
            max_age_seconds=getattr(args, "mfc_log_stale_seconds", 900.0),
        )
    if diag_log is None:
        raise RuntimeError(f"No Rust diagnostics log found under {args.log_dir}.")
    if mfc_upload_log is None:
        raise RuntimeError(
            "No fresh MFC upload diagnostics log was provided, discovered, or reusable from the monitor command line. "
            "Run mfc-upload-logs to inspect candidates."
        )
    stdout = (output_dir / "upload-parity-monitor.stdout.log").open("ab", buffering=0)
    stderr = (output_dir / "upload-parity-monitor.stderr.log").open("ab", buffering=0)
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    command = [
        sys.executable,
        str(script),
        "--rust-base-url",
        args.base_url,
        "--rust-api-key",
        args.api_key,
        "--rust-diag-log",
        str(diag_log),
        "--mfc-upload-log",
        str(mfc_upload_log),
        "--output-dir",
        str(output_dir),
        "--interval-seconds",
        str(args.interval_seconds),
        "--mfc-log-stale-seconds",
        str(getattr(args, "mfc_log_stale_seconds", 900.0)),
    ]
    process = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdout=stdout,
        stderr=stderr,
        creationflags=creationflags,
    )
    return {"monitorPid": process.pid, "rustDiagLog": str(diag_log), "outputDir": str(output_dir)}


def restart_upload_monitor(args: argparse.Namespace) -> dict[str, object]:
    """Stops then starts the upload parity monitor."""

    if args.mfc_upload_log is None:
        args.mfc_upload_log = existing_monitor_mfc_upload_log(args.output_dir)
    stopped = stop_upload_monitor(args.output_dir)
    started = start_upload_monitor(args)
    return {"stopped": stopped, "started": started}


def latest_monitor_record(output_dir: Path) -> dict[str, object]:
    """Returns the most recent upload parity monitor JSONL record."""

    jsonl_path = output_dir / "upload-parity-monitor.jsonl"
    if not jsonl_path.exists():
        return {}
    latest = ""
    with jsonl_path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - 1024 * 1024), os.SEEK_SET)
        if size > 1024 * 1024:
            handle.readline()
        for line in handle.read().decode("utf-8", errors="replace").splitlines():
            if line.strip():
                latest = line
    return json.loads(latest) if latest else {}


def timestamp_age_seconds(timestamp: object) -> float | None:
    """Returns the age in seconds for an ISO-8601 timestamp."""

    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - parsed.astimezone(UTC)).total_seconds())


def upload_monitor_sample(args: argparse.Namespace) -> dict[str, object]:
    """Returns a sanitized summary of the live upload parity monitor state."""

    output_dir = args.output_dir
    heartbeat_path = output_dir / "upload-parity-monitor.heartbeat.txt"
    pid_path = output_dir / "upload-parity-monitor.pid"
    heartbeat = heartbeat_path.read_text(encoding="utf-8", errors="replace").strip() if heartbeat_path.exists() else ""
    pid = int(pid_path.read_text(encoding="ascii").strip()) if pid_path.exists() else 0
    record = latest_monitor_record(output_dir)
    latest_age_seconds = timestamp_age_seconds(record.get("timestamp")) if record else None
    monitor_stale = latest_age_seconds is None or latest_age_seconds > args.stale_seconds
    if not record:
        return {
            "heartbeat": heartbeat,
            "latestAgeSeconds": latest_age_seconds,
            "monitorStale": monitor_stale,
            "monitorPid": pid or None,
            "monitorAlive": pid_exists(pid) if pid else False,
            "latestRecord": None,
        }
    if "error" in record:
        latest: dict[str, object] = {
            "timestamp": record.get("timestamp"),
            "error": record.get("error"),
        }
    else:
        rust = record.get("rust") if isinstance(record.get("rust"), dict) else {}
        sched = record.get("rustSched") if isinstance(record.get("rustSched"), dict) else {}
        action = record.get("action") if isinstance(record.get("action"), dict) else {}
        latest = {
            "timestamp": record.get("timestamp"),
            "rustKiBps": rust.get("uploadSpeedKiBps"),
            "rustUploads": rust.get("activeUploads"),
            "rustWaiting": rust.get("waitingUploads"),
            "mfcKiBps": action.get("mfcEffectiveKiBps"),
            "mfcWaiting": action.get("mfcWaitingDemand"),
            "mfcLogLastWrite": action.get("mfcLogLastWrite"),
            "mfcLogAgeSeconds": action.get("mfcLogAgeSeconds"),
            "mfcLogStale": action.get("mfcLogStale"),
            "mfcDiagnosticsFresh": action.get("mfcDiagnosticsFresh"),
            "parityGap": action.get("parityGap"),
            "postVisibilityDemandGap": action.get("postVisibilityDemandGap"),
            "rustEd2kPending": rust.get("ed2kPendingEntries"),
            "rustKadFirewalled": rust.get("kadFirewalled"),
            "rustKadSource": {
                "published": rust.get("kadSourcePublishedTotal"),
                "attemptedContacts": rust.get("kadSourceAttemptedContactsTotal"),
                "ackedContacts": rust.get("kadSourceAckedContactsTotal"),
                "timeouts": rust.get("kadSourceContactTimeoutsTotal"),
                "failed": rust.get("kadSourceFailed"),
            },
            "diagKadPublish": {
                "events": sched.get("kadPublishEvents"),
                "attemptedContacts": sched.get("kadPublishAttemptedContacts"),
                "ackedContacts": sched.get("kadPublishAckedContacts"),
                "timeouts": sched.get("kadPublishTimedOutContacts"),
                "failedContacts": sched.get("kadPublishFailedContacts"),
            },
            "lastCapacity": sched.get("lastCapacity"),
        }
    return {
        "heartbeat": heartbeat,
        "latestAgeSeconds": latest_age_seconds,
        "monitorStale": monitor_stale,
        "monitorPid": pid or None,
        "monitorAlive": pid_exists(pid) if pid else False,
        "latestRecord": latest,
    }


def watch_findings(
    rust: dict[str, object],
    monitor: dict[str, object],
    mfc: dict[str, object] | None = None,
    diagnostics: dict[str, object] | None = None,
) -> list[str]:
    """Returns compact operator-facing findings for one soak cadence check."""

    findings: list[str] = []
    latest = monitor.get("latestRecord") if isinstance(monitor.get("latestRecord"), dict) else {}
    if monitor.get("monitorAlive") is False:
        findings.append("monitor-not-running")
    if monitor.get("monitorStale") is True:
        findings.append("monitor-stale")
    if latest.get("mfcLogStale") is True:
        findings.append("mfc-upload-log-stale")
    if rust.get("sharedHashingActive") is True or int(rust.get("sharedHashingCount") or 0) > 0:
        findings.append("rust-hashing-active")
    if rust.get("ed2kConnected") is not True:
        findings.append("rust-ed2k-disconnected")
    if rust.get("ed2kHighId") is not True:
        findings.append("rust-ed2k-not-high-id")
    if rust.get("kadConnected") is not True:
        findings.append("rust-kad-disconnected")
    if rust.get("kadFirewalled") is True:
        findings.append("rust-kad-firewalled")
    gate_reason = str(rust.get("kadGateBlockReason") or "")
    if gate_reason == "dhtSearchBusy":
        findings.append("rust-kad-search-capacity-busy")
    elif rust.get("kadGateAllowed") is False:
        findings.append("rust-kad-publish-gated")
    if latest.get("postVisibilityDemandGap") is True:
        findings.append("post-visibility-demand-gap")
    if latest.get("parityGap") is True and int(rust.get("ed2kPendingEntries") or 0) > 0:
        findings.append("visibility-still-maturing")
    elif latest.get("parityGap") is True:
        findings.append("upload-parity-gap")
    findings.extend(watch_diagnostic_findings(diagnostics))
    if mfc is not None:
        if "error" in mfc:
            findings.append("mfc-status-error")
        else:
            if mfc.get("sharedHashingActive") is True or int(mfc.get("sharedHashingCount") or 0) > 0:
                findings.append("mfc-hashing-active")
            if mfc.get("ed2kConnected") is not True:
                findings.append("mfc-ed2k-disconnected")
            if mfc.get("ed2kHighId") is not True:
                findings.append("mfc-ed2k-not-high-id")
            if mfc.get("kadConnected") is not True:
                findings.append("mfc-kad-disconnected")
            if mfc.get("kadFirewalled") is True:
                findings.append("mfc-kad-firewalled")
    return findings


def diagnostics_count(diagnostics: dict[str, object] | None, group: str, name: str) -> int:
    """Reads an aggregate diagnostics counter without exposing raw log content."""

    if not isinstance(diagnostics, dict):
        return 0
    counts = diagnostics.get("aggregateJsonCounts")
    if not isinstance(counts, dict):
        return 0
    group_counts = counts.get(group)
    if not isinstance(group_counts, dict):
        return 0
    value = group_counts.get(name)
    return int(value) if isinstance(value, int) else 0


def watch_diagnostic_findings(diagnostics: dict[str, object] | None) -> list[str]:
    """Returns compact findings derived from retained diagnostics counters."""

    findings: list[str] = []
    if diagnostics_count(diagnostics, "event", "anti_flood_drop") > 0:
        findings.append("rust-anti-flood-drop-observed")
    if diagnostics_count(diagnostics, "event", "anti_flood_ban") > 0:
        findings.append("rust-anti-flood-ban-observed")
    return findings


def watch_recommendations(
    findings: list[str],
    rust: dict[str, object],
    monitor: dict[str, object],
    mfc: dict[str, object] | None = None,
    vpn: dict[str, object] | None = None,
) -> list[str]:
    """Returns compact next-action guidance for one soak sample."""

    del rust, monitor
    recommendations: list[str] = []
    if "monitor-not-running" in findings or "monitor-stale" in findings or "mfc-upload-log-stale" in findings:
        recommendations.append("repair-upload-monitor")
    if vpn is not None and (
        vpn.get("allWhitelisted") is False
        or vpn.get("adapterUp") is False
        or vpn.get("bindIpPresent") is False
    ):
        recommendations.append("repair-vpn-before-p2p")
    rust_findings = [
        finding
        for finding in findings
        if finding.startswith("rust-") and not finding.startswith("rust-anti-flood-")
    ]
    if rust_findings:
        recommendations.append("inspect-rust-p2p")
    if any(finding.startswith("rust-anti-flood-") for finding in findings):
        recommendations.append("review-rust-anti-flood-diagnostics")
    mfc_connectivity_gap = any(
        finding in findings
        for finding in (
            "mfc-ed2k-disconnected",
            "mfc-ed2k-not-high-id",
            "mfc-kad-disconnected",
            "mfc-kad-firewalled",
        )
    )
    mfc_hashing_active = "mfc-hashing-active" in findings
    if mfc_hashing_active and mfc_connectivity_gap:
        recommendations.append("preserve-mfc-hashing-before-connectivity-restart")
    elif mfc_connectivity_gap:
        recommendations.append("restart-mfc-connectivity-path")
    elif mfc_hashing_active:
        recommendations.append("continue-mfc-hashing")
    if mfc is not None and "error" in mfc:
        recommendations.append("repair-mfc-status-sampling")
    if not recommendations:
        recommendations.append("continue-soak")
    return recommendations


def watch_once(args: argparse.Namespace) -> dict[str, object]:
    """Runs one reusable long-soak cadence check and optional monitor repair."""

    rust = sample(args.base_url, args.api_key)
    mfc: dict[str, object] | None = None
    if args.mfc_base_url:
        try:
            mfc = sample(args.mfc_base_url, args.mfc_api_key)
        except Exception as error:
            mfc = {"error": f"{type(error).__name__}: {error}"}
    monitor_args = argparse.Namespace(output_dir=args.output_dir, stale_seconds=args.stale_seconds)
    monitor = upload_monitor_sample(monitor_args)
    action: dict[str, object] = {"monitorRestarted": False}
    if args.restart_stale_monitor and (
        monitor.get("monitorAlive") is False or monitor.get("monitorStale") is True
    ):
        restart_args = argparse.Namespace(
            base_url=args.base_url,
            api_key=args.api_key,
            output_dir=args.output_dir,
            log_dir=args.log_dir,
            rust_pid=args.rust_pid,
            rust_diag_log=args.rust_diag_log,
            mfc_upload_log=args.mfc_upload_log,
            interval_seconds=args.interval_seconds,
            mfc_log_stale_seconds=args.mfc_log_stale_seconds,
        )
        try:
            action = {"monitorRestarted": True, "restart": restart_upload_monitor(restart_args)}
            monitor = upload_monitor_sample(monitor_args)
        except Exception as error:
            action = {"monitorRestarted": False, "monitorRestartError": str(error)}
    diagnostics = optional_watch_diagnostics(args)
    vpn = optional_watch_vpn(args)
    findings = watch_findings(rust, monitor, mfc, diagnostics)
    payload = {
        "timestampUtc": datetime.now(UTC).isoformat(),
        "rust": rust,
        "monitor": monitor,
        "findings": findings,
        "recommendations": watch_recommendations(findings, rust, monitor, mfc, vpn),
        "action": action,
    }
    if mfc is not None:
        payload["mfc"] = mfc
    if diagnostics is not None:
        payload["diagnostics"] = diagnostics
    if vpn is not None:
        payload["vpn"] = vpn
    if getattr(args, "append_jsonl", False):
        append_jsonl(args.watch_jsonl, payload)
        write_watch_heartbeat(args.watch_heartbeat, payload)
    if getattr(args, "report", "full") == "brief":
        report_args = argparse.Namespace(
            watch_pid_file=getattr(args, "watch_pid_file", args.output_dir / "rust-soak-watch.pid"),
            watch_jsonl=args.watch_jsonl,
            watch_stop_file=getattr(args, "watch_stop_file", args.output_dir / "rust-soak-watch.stop"),
            stale_seconds=args.stale_seconds,
            limit=getattr(args, "report_limit", 12),
        )
        trend = watch_trend(argparse.Namespace(watch_jsonl=args.watch_jsonl, limit=report_args.limit))
        return watch_brief_from_record(payload, report_args, trend)
    return payload


def append_jsonl(path: Path, payload: dict[str, object]) -> None:
    """Appends one JSON record to a retained soak evidence file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def write_watch_heartbeat(path: Path, payload: dict[str, object]) -> None:
    """Writes a compact heartbeat for a long-running watch loop."""

    rust = payload.get("rust") if isinstance(payload.get("rust"), dict) else {}
    mfc = payload.get("mfc") if isinstance(payload.get("mfc"), dict) else {}
    monitor = payload.get("monitor") if isinstance(payload.get("monitor"), dict) else {}
    diagnostics = payload.get("diagnostics") if isinstance(payload.get("diagnostics"), dict) else {}
    vpn = payload.get("vpn") if isinstance(payload.get("vpn"), dict) else {}
    latest = monitor.get("latestRecord") if isinstance(monitor.get("latestRecord"), dict) else {}
    lines = [
        f"timestampUtc={payload.get('timestampUtc')}",
        f"findings={','.join(str(item) for item in payload.get('findings', []))}",
        f"recommendations={','.join(str(item) for item in payload.get('recommendations', []))}",
        f"rustKiBps={rust.get('uploadSpeedKiBps')}",
        f"rustUploads={rust.get('activeUploads')}",
        f"rustWaiting={rust.get('waitingUploads')}",
        f"ed2kPublished={rust.get('ed2kPublishedEntries')}",
        f"ed2kPending={rust.get('ed2kPendingEntries')}",
        f"ed2kVisibilityPercent={rust.get('ed2kVisibilityPercent')}",
        f"kadFirewalled={rust.get('kadFirewalled')}",
        f"monitorSample={latest.get('timestamp')}",
        f"monitorParityGap={latest.get('parityGap')}",
        f"monitorPostVisibilityDemandGap={latest.get('postVisibilityDemandGap')}",
        f"monitorMfcLogStale={latest.get('mfcLogStale')}",
    ]
    if mfc:
        lines.extend(
            [
                f"mfcKiBps={mfc.get('uploadSpeedKiBps')}",
                f"mfcUploads={mfc.get('activeUploads')}",
                f"mfcSharedFiles={mfc.get('sharedFileCount')}",
                f"mfcHashing={mfc.get('sharedHashingCount')}",
                f"mfcEd2kHighId={mfc.get('ed2kHighId')}",
                f"mfcKadFirewalled={mfc.get('kadFirewalled')}",
            ]
        )
    if vpn:
        lines.extend(
            [
                f"vpnAllWhitelisted={vpn.get('allWhitelisted')}",
                f"vpnAdapterUp={vpn.get('adapterUp')}",
                f"vpnBindIpPresent={vpn.get('bindIpPresent')}",
            ]
        )
    if diagnostics:
        lines.extend(
            [
                f"diagnosticsFiles={diagnostics.get('fileCount')}",
                f"diagnosticsPatterns={','.join(sorted((diagnostics.get('aggregatePatternCounts') or {}).keys()))}",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def watch_loop(args: argparse.Namespace) -> dict[str, object]:
    """Runs repeated long-soak cadence checks and retains JSONL evidence."""

    sample_count = 0
    last_result: dict[str, object] | None = None
    while args.max_samples <= 0 or sample_count < args.max_samples:
        if args.watch_stop_file.exists():
            break
        last_result = watch_once(args)
        append_jsonl(args.watch_jsonl, last_result)
        write_watch_heartbeat(args.watch_heartbeat, last_result)
        sample_count += 1
        print(json.dumps(last_result, sort_keys=True), flush=True)
        if args.max_samples > 0 and sample_count >= args.max_samples:
            break
        time.sleep(args.watch_interval_seconds)

    return {
        "samples": sample_count,
        "watchJsonl": str(args.watch_jsonl),
        "watchHeartbeat": str(args.watch_heartbeat),
        "lastResult": last_result,
    }


def start_watch_loop(args: argparse.Namespace) -> dict[str, object]:
    """Starts the retained soak watch loop as a detached Python process."""

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.watch_stop_file.unlink(missing_ok=True)
    stdout = (args.output_dir / "rust-soak-watch.stdout.log").open("ab", buffering=0)
    stderr = (args.output_dir / "rust-soak-watch.stderr.log").open("ab", buffering=0)
    command = [
        sys.executable,
        str(SCRIPT_PATH),
        "--base-url",
        args.base_url,
        "--api-key",
        args.api_key,
        "watch-loop",
        "--output-dir",
        str(args.output_dir),
        "--stale-seconds",
        str(args.stale_seconds),
        "--log-dir",
        str(args.log_dir),
        "--interval-seconds",
        str(args.interval_seconds),
        "--watch-interval-seconds",
        str(args.watch_interval_seconds),
        "--max-samples",
        str(args.max_samples),
        "--watch-jsonl",
        str(args.watch_jsonl),
        "--watch-heartbeat",
        str(args.watch_heartbeat),
        "--watch-stop-file",
        str(args.watch_stop_file),
    ]
    if args.rust_pid is not None:
        command.extend(["--rust-pid", str(args.rust_pid)])
    if args.rust_diag_log is not None:
        command.extend(["--rust-diag-log", str(args.rust_diag_log)])
    if args.mfc_upload_log is not None:
        command.extend(["--mfc-upload-log", str(args.mfc_upload_log)])
    if args.mfc_base_url:
        command.extend(["--mfc-base-url", args.mfc_base_url, "--mfc-api-key", args.mfc_api_key])
    command.extend(["--mfc-log-stale-seconds", str(args.mfc_log_stale_seconds)])
    if args.include_vpn_status:
        command.append("--include-vpn-status")
    if args.check_vpn_adapter:
        command.append("--check-vpn-adapter")
    if args.vpn_settings_path is not None:
        command.extend(["--vpn-settings-path", str(args.vpn_settings_path)])
    for exe in args.vpn_exe or []:
        command.extend(["--vpn-exe", str(exe)])
    for log_dir in args.diagnostics_log_dir or []:
        command.extend(["--diagnostics-log-dir", str(log_dir)])
    for log_file in args.diagnostics_log_file or []:
        command.extend(["--diagnostics-log-file", str(log_file)])
    command.extend(["--diagnostics-limit", str(args.diagnostics_limit)])
    command.extend(["--diagnostics-max-bytes", str(args.diagnostics_max_bytes)])
    if not args.restart_stale_monitor:
        command.append("--no-restart-stale-monitor")

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdout=stdout,
        stderr=stderr,
        stdin=subprocess.DEVNULL,
        close_fds=False,
        creationflags=creationflags,
    )
    pid_path = args.output_dir / "rust-soak-watch.pid"
    pid_path.write_text(f"{process.pid}\n", encoding="utf-8", newline="\n")
    return {
        "watchPid": process.pid,
        "watchPidFile": str(pid_path),
        "watchJsonl": str(args.watch_jsonl),
        "watchHeartbeat": str(args.watch_heartbeat),
        "watchStopFile": str(args.watch_stop_file),
    }


def stop_watch_loop(args: argparse.Namespace) -> dict[str, object]:
    """Requests a detached soak watch loop to stop."""

    args.watch_stop_file.parent.mkdir(parents=True, exist_ok=True)
    args.watch_stop_file.write_text(datetime.now(UTC).isoformat() + "\n", encoding="utf-8", newline="\n")
    pid = None
    if args.watch_pid_file.exists():
        text = args.watch_pid_file.read_text(encoding="utf-8", errors="replace").strip()
        if text.isdigit():
            pid = int(text)
    if args.terminate and pid is not None:
        terminate_pid_tree(pid, markers=("rust-soak-control.py", "watch-loop"), timeout_seconds=15.0)
    return {
        "watchPid": pid,
        "watchAlive": pid_exists(pid) if pid is not None else False,
        "watchStopFile": str(args.watch_stop_file),
        "stopRequested": True,
    }


def latest_jsonl_record(path: Path) -> dict[str, object] | None:
    """Returns the last JSONL record from a retained evidence file."""

    if not path.exists():
        return None
    with path.open("rb") as handle:
        size = path.stat().st_size
        if size > 1_000_000:
            handle.seek(-1_000_000, os.SEEK_END)
            handle.readline()
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def jsonl_tail_records(path: Path, *, limit: int, max_bytes: int = 1_000_000) -> list[dict[str, object]]:
    """Returns up to ``limit`` retained JSONL records from the end of a file."""

    if limit <= 0 or not path.exists():
        return []
    with path.open("rb") as handle:
        size = path.stat().st_size
        if size > max_bytes:
            handle.seek(-max_bytes, os.SEEK_END)
            handle.readline()
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    records: list[dict[str, object]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records[-limit:]


def parse_iso_timestamp(timestamp: object) -> datetime | None:
    """Parses an ISO-8601 timestamp into UTC."""

    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def record_path_value(record: dict[str, object], path: tuple[str, ...]) -> object:
    """Reads a nested value from one retained watch record."""

    current: object = record
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def safe_float(value: object) -> float | None:
    """Converts JSON-ish values to float when possible."""

    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def trend_counter(
    records: list[dict[str, object]],
    path: tuple[str, ...],
    *,
    include_remaining_eta: bool = False,
    reset_on_decrease: bool = False,
    reset_on_increase: bool = False,
) -> dict[str, object]:
    """Returns first/last/delta/rate metadata for one nested numeric counter."""

    numeric: list[tuple[float, datetime | None]] = []
    for record in records:
        value = safe_float(record_path_value(record, path))
        if value is not None:
            numeric.append((value, parse_iso_timestamp(record.get("timestampUtc"))))
    if not numeric:
        return {"samples": 0}
    original_samples = len(numeric)
    reset_index = 0
    for index, ((previous, _), (current, _)) in enumerate(zip(numeric, numeric[1:]), start=1):
        if (reset_on_decrease and current < previous) or (reset_on_increase and current > previous):
            reset_index = index
    if reset_index:
        numeric = numeric[reset_index:]
    first = numeric[0][0]
    last = numeric[-1][0]
    delta = last - first
    first_timestamp = numeric[0][1]
    last_timestamp = numeric[-1][1]
    elapsed_seconds = (
        (last_timestamp - first_timestamp).total_seconds()
        if first_timestamp is not None and last_timestamp is not None
        else 0.0
    )
    result: dict[str, object] = {
        "samples": len(numeric),
        "first": first,
        "last": last,
        "delta": delta,
        "average": round(sum(value for value, _ in numeric) / len(numeric), 3),
    }
    if reset_index:
        result["resetSegment"] = True
        result["droppedSamples"] = original_samples - len(numeric)
    if first_timestamp is not None:
        result["startUtc"] = first_timestamp.isoformat()
    if last_timestamp is not None:
        result["endUtc"] = last_timestamp.isoformat()
    if len(numeric) >= 2:
        result["elapsedSeconds"] = round(max(0.0, elapsed_seconds), 3)
    if elapsed_seconds > 0 and len(numeric) >= 2:
        per_minute = delta * 60.0 / elapsed_seconds
        result["perMinute"] = round(per_minute, 3)
        if include_remaining_eta and last > 0 and per_minute < 0:
            remaining_minutes = last / abs(per_minute)
            result["remainingEtaMinutes"] = round(remaining_minutes, 2)
            result["remainingEtaHours"] = round(remaining_minutes / 60.0, 2)
    return result


def latest_diagnostics_body_counts(record: dict[str, object]) -> dict[str, dict[str, int]]:
    """Aggregates safe body buckets from the latest retained diagnostics sample."""

    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return {}
    files = diagnostics.get("files")
    if not isinstance(files, list):
        return {}
    aggregate: dict[str, Counter[str]] = {}
    for file_summary in files:
        if not isinstance(file_summary, dict):
            continue
        body_counts = file_summary.get("jsonBodyCounts")
        if not isinstance(body_counts, dict):
            continue
        for field, counts in body_counts.items():
            if not isinstance(field, str) or not isinstance(counts, dict):
                continue
            counter = aggregate.setdefault(field, Counter())
            for bucket, count in counts.items():
                if isinstance(bucket, str) and isinstance(count, int):
                    counter[bucket] += count
    return {
        field: dict(counter.most_common(12))
        for field, counter in sorted(aggregate.items())
        if counter
    }


def latest_diagnostics_body_numeric(record: dict[str, object]) -> dict[str, dict[str, object]]:
    """Aggregates safe numeric body stats from the latest retained diagnostics sample."""

    diagnostics = record.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return {}
    files = diagnostics.get("files")
    if not isinstance(files, list):
        return {}
    aggregate: dict[str, dict[str, float]] = {}
    for file_summary in files:
        if not isinstance(file_summary, dict):
            continue
        body_numeric = file_summary.get("jsonBodyNumeric")
        if not isinstance(body_numeric, dict):
            continue
        for field, stats in body_numeric.items():
            if not isinstance(field, str) or not isinstance(stats, dict):
                continue
            count = safe_float(stats.get("count"))
            total = safe_float(stats.get("sum"))
            minimum = safe_float(stats.get("min"))
            maximum = safe_float(stats.get("max"))
            if count is None or total is None or minimum is None or maximum is None or count <= 0:
                continue
            current = aggregate.setdefault(
                field,
                {"count": 0.0, "sum": 0.0, "min": minimum, "max": maximum},
            )
            current["count"] += count
            current["sum"] += total
            current["min"] = min(current["min"], minimum)
            current["max"] = max(current["max"], maximum)
    return {
        field: {
            "count": int(stats["count"]),
            "sum": round(stats["sum"], 3),
            "min": round(stats["min"], 3),
            "max": round(stats["max"], 3),
            "average": round(stats["sum"] / stats["count"], 3),
        }
        for field, stats in sorted(aggregate.items())
        if stats["count"] > 0
    }


def latest_upload_efficiency(
    body_counts: dict[str, dict[str, int]],
    body_numeric: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Returns derived upload-efficiency ratios from retained diagnostics stats."""

    requested_bytes = safe_float(
        body_numeric.get("upload_request_outcome.requestedBytes", {}).get("sum")
    )
    served_bytes = safe_float(body_numeric.get("upload_request_outcome.servedBytes", {}).get("sum"))
    sent_payload_bytes = safe_float(
        body_numeric.get("upload_payload_accounting.sentPayloadBytes", {}).get("sum")
    )
    sent_file_bytes = safe_float(
        body_numeric.get("upload_payload_accounting.sentFileBytes", {}).get("sum")
    )
    read_ms = safe_float(body_numeric.get("upload_request_outcome.payloadReadMs", {}).get("average"))
    throttle_ms = safe_float(
        body_numeric.get("upload_request_outcome.throttleDelayMs", {}).get("average")
    )
    read_cache_hits = safe_float(
        body_numeric.get("upload_request_outcome.readCacheHits", {}).get("sum")
    )
    read_cache_misses = safe_float(
        body_numeric.get("upload_request_outcome.readCacheMisses", {}).get("sum")
    )
    read_disk_bytes = safe_float(
        body_numeric.get("upload_request_outcome.readDiskBytes", {}).get("sum")
    )
    outcome_counts = body_counts.get("upload_request_outcome.outcome", {})
    skip_counts = body_counts.get("upload_request_outcome.firstSkipReason", {})
    efficiency: dict[str, object] = {
        "outcomes": outcome_counts,
        "firstSkipReasons": skip_counts,
    }
    if requested_bytes is not None:
        efficiency["requestedBytes"] = requested_bytes
    if served_bytes is not None:
        efficiency["servedBytes"] = served_bytes
    if requested_bytes and served_bytes is not None:
        efficiency["servedToRequestedRatio"] = round(served_bytes / requested_bytes, 4)
    if sent_payload_bytes is not None:
        efficiency["sentPayloadBytes"] = sent_payload_bytes
    if sent_file_bytes is not None:
        efficiency["sentFileBytes"] = sent_file_bytes
    if sent_payload_bytes is not None and sent_file_bytes is not None:
        overhead = max(0.0, sent_payload_bytes - sent_file_bytes)
        efficiency["payloadOverheadBytes"] = round(overhead, 3)
        if sent_file_bytes > 0:
            efficiency["payloadOverheadRatio"] = round(overhead / sent_file_bytes, 6)
    if read_ms is not None:
        efficiency["averagePayloadReadMs"] = read_ms
    if throttle_ms is not None:
        efficiency["averageThrottleDelayMs"] = throttle_ms
    if read_cache_hits is not None:
        efficiency["readCacheHits"] = read_cache_hits
    if read_cache_misses is not None:
        efficiency["readCacheMisses"] = read_cache_misses
    if read_cache_hits is not None and read_cache_misses is not None:
        read_cache_total = read_cache_hits + read_cache_misses
        if read_cache_total > 0:
            efficiency["readCacheHitRatio"] = round(read_cache_hits / read_cache_total, 4)
    if read_disk_bytes is not None:
        efficiency["readDiskBytes"] = read_disk_bytes
    if read_disk_bytes is not None and served_bytes and served_bytes > 0:
        efficiency["readDiskToServedRatio"] = round(read_disk_bytes / served_bytes, 4)
    if isinstance(outcome_counts, dict) and outcome_counts:
        total_outcomes = sum(count for count in outcome_counts.values() if isinstance(count, int))
        duplicate_done = skip_counts.get("duplicateDone") if isinstance(skip_counts, dict) else None
        if total_outcomes > 0 and isinstance(duplicate_done, int):
            efficiency["duplicateDoneOutcomeRatio"] = round(duplicate_done / total_outcomes, 4)
    return efficiency


def compact_upload_efficiency_summary(summary: dict[str, object]) -> dict[str, object]:
    """Returns upload-efficiency fields suitable for compact live watch briefs."""

    compact: dict[str, object] = {
        "source": "rustDiagLog",
        "rowCount": summary.get("rowCount"),
        "timeRange": summary.get("timeRange"),
        "outcomes": summary.get("outcomes"),
        "firstSkipReasons": summary.get("firstSkipReasons"),
    }
    numeric = summary.get("numeric")
    if isinstance(numeric, dict):
        for field in (
            "requestedBytes",
            "servedBytes",
            "sentPayloadBytes",
            "sentFileBytes",
            "payloadReadMs",
            "throttleDelayMs",
            "readCacheHits",
            "readCacheMisses",
            "readDiskBytes",
        ):
            stats = numeric.get(field)
            if isinstance(stats, dict):
                compact[field] = {
                    key: stats.get(key)
                    for key in ("count", "sum", "average", "max")
                    if stats.get(key) is not None
                }
    for field in (
        "servedToRequestedRatio",
        "payloadOverheadBytes",
        "payloadOverheadRatio",
        "readCacheHitRatio",
        "readDiskToServedRatio",
        "slowReadCount",
        "slowReadRatio",
    ):
        if field in summary:
            compact[field] = summary[field]
    return compact


def watch_trend(args: argparse.Namespace) -> dict[str, object]:
    """Summarizes retained soak watch JSONL counters over a bounded window."""

    records = jsonl_tail_records(args.watch_jsonl, limit=args.limit)
    timestamps = [parse_iso_timestamp(record.get("timestampUtc")) for record in records]
    timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    elapsed_seconds = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) >= 2 else 0.0
    latest = records[-1] if records else {}
    latest_findings = latest.get("findings") if isinstance(latest.get("findings"), list) else []
    latest_recommendations = (
        latest.get("recommendations")
        if isinstance(latest.get("recommendations"), list)
        else []
    )
    latest_body_counts = latest_diagnostics_body_counts(latest)
    latest_body_numeric = latest_diagnostics_body_numeric(latest)
    latest_upload = latest_upload_efficiency(latest_body_counts, latest_body_numeric)
    counters = {
        "rustUploadKiBps": trend_counter(records, ("rust", "uploadSpeedKiBps")),
        "rustActiveUploads": trend_counter(records, ("rust", "activeUploads")),
        "rustEd2kPublished": trend_counter(
            records,
            ("rust", "ed2kPublishedEntries"),
            reset_on_decrease=True,
        ),
        "rustEd2kPending": trend_counter(
            records,
            ("rust", "ed2kPendingEntries"),
            include_remaining_eta=True,
            reset_on_increase=True,
        ),
        "rustKadSourcePublished": trend_counter(
            records,
            ("rust", "kadSourcePublishedTotal"),
            reset_on_decrease=True,
        ),
        "mfcSharedFiles": trend_counter(records, ("mfc", "sharedFileCount")),
        "mfcHashingRemaining": trend_counter(records, ("mfc", "sharedHashingCount")),
        "mfcUploadKiBps": trend_counter(records, ("mfc", "uploadSpeedKiBps")),
        "mfcActiveUploads": trend_counter(records, ("mfc", "activeUploads")),
        "monitorRustUploadKiBps": trend_counter(records, ("monitor", "latestRecord", "rustKiBps")),
        "monitorMfcUploadKiBps": trend_counter(records, ("monitor", "latestRecord", "mfcKiBps")),
    }
    mfc_hashing = counters["mfcHashingRemaining"]
    if isinstance(mfc_hashing, dict) and isinstance(mfc_hashing.get("delta"), (int, float)):
        mfc_hashing["completedDelta"] = -float(mfc_hashing["delta"])
        counter_elapsed_seconds = safe_float(mfc_hashing.get("elapsedSeconds")) or 0.0
        if counter_elapsed_seconds > 0 and int(mfc_hashing.get("samples") or 0) >= 2:
            completed_per_minute = -float(mfc_hashing["delta"]) * 60.0 / counter_elapsed_seconds
            mfc_hashing["completedPerMinute"] = round(
                completed_per_minute,
                3,
            )
            remaining = safe_float(mfc_hashing.get("last")) or 0.0
            if remaining > 0 and completed_per_minute > 0:
                remaining_minutes = remaining / completed_per_minute
                mfc_hashing["remainingEtaMinutes"] = round(remaining_minutes, 2)
                mfc_hashing["remainingEtaHours"] = round(remaining_minutes / 60.0, 2)
    return {
        "watchJsonl": str(args.watch_jsonl),
        "sampleCount": len(records),
        "window": {
            "startUtc": timestamps[0].isoformat() if timestamps else None,
            "endUtc": timestamps[-1].isoformat() if timestamps else None,
            "elapsedSeconds": round(max(0.0, elapsed_seconds), 3),
        },
        "latestFindings": latest_findings,
        "latestRecommendations": latest_recommendations,
        "latestDiagnosticsBodyCounts": latest_body_counts,
        "latestDiagnosticsBodyNumeric": latest_body_numeric,
        "latestUploadEfficiency": latest_upload,
        "counters": counters,
    }


def watch_status(args: argparse.Namespace) -> dict[str, object]:
    """Returns detached soak watch loop health without shell process listings."""

    pid = None
    if args.watch_pid_file.exists():
        text = args.watch_pid_file.read_text(encoding="utf-8", errors="replace").strip()
        if text.isdigit():
            pid = int(text)
    heartbeat = args.watch_heartbeat.read_text(encoding="utf-8", errors="replace") if args.watch_heartbeat.exists() else ""
    latest = latest_jsonl_record(args.watch_jsonl)
    latest_age_seconds = timestamp_age_seconds(latest.get("timestampUtc")) if latest else None
    watch_alive = pid_exists(pid) if pid is not None else False
    watch_stale = latest_age_seconds is None or latest_age_seconds > args.stale_seconds
    findings: list[str] = []
    if not watch_alive:
        findings.append("watch-not-running")
    if watch_stale:
        findings.append("watch-stale")
    return {
        "watchPid": pid,
        "watchAlive": watch_alive,
        "watchStale": watch_stale,
        "latestAgeSeconds": latest_age_seconds,
        "findings": findings,
        "watchPidFile": str(args.watch_pid_file),
        "watchJsonl": str(args.watch_jsonl),
        "watchHeartbeat": heartbeat,
        "watchStopFilePresent": args.watch_stop_file.exists(),
        "latestRecord": latest,
    }


def watch_brief(args: argparse.Namespace) -> dict[str, object]:
    """Returns a compact long-soak status summary for regular monitoring."""

    latest = latest_jsonl_record(args.watch_jsonl) or {}
    trend = watch_trend(argparse.Namespace(watch_jsonl=args.watch_jsonl, limit=args.limit))
    return watch_brief_from_record(latest, args, trend)


def watch_brief_from_record(
    latest: dict[str, object],
    args: argparse.Namespace,
    trend: dict[str, object],
) -> dict[str, object]:
    """Builds the compact watch report shape from one retained sample."""

    pid = None
    if args.watch_pid_file.exists():
        text = args.watch_pid_file.read_text(encoding="utf-8", errors="replace").strip()
        if text.isdigit():
            pid = int(text)
    latest_age_seconds = timestamp_age_seconds(latest.get("timestampUtc")) if latest else None
    watch_alive = pid_exists(pid) if pid is not None else False
    watch_stale = latest_age_seconds is None or latest_age_seconds > args.stale_seconds
    rust = latest.get("rust") if isinstance(latest.get("rust"), dict) else {}
    mfc = latest.get("mfc") if isinstance(latest.get("mfc"), dict) else {}
    monitor = latest.get("monitor") if isinstance(latest.get("monitor"), dict) else {}
    monitor_latest = monitor.get("latestRecord") if isinstance(monitor.get("latestRecord"), dict) else {}
    diagnostics = latest.get("diagnostics") if isinstance(latest.get("diagnostics"), dict) else {}
    upload_efficiency = trend.get("latestUploadEfficiency")
    rust_diag_log = getattr(args, "rust_diag_log", None)
    if rust_diag_log is not None:
        current_upload = upload_efficiency_summary(
            argparse.Namespace(
                log_dir=None,
                log_file=[rust_diag_log],
                limit=1,
                max_bytes=getattr(args, "upload_efficiency_max_bytes", 33_554_432),
                slow_read_ms=getattr(args, "slow_read_ms", 100.0),
                outlier_limit=0,
            )
        )
        upload_efficiency = compact_upload_efficiency_summary(current_upload)
    vpn = latest.get("vpn") if isinstance(latest.get("vpn"), dict) else {}
    counters = trend.get("counters") if isinstance(trend.get("counters"), dict) else {}
    findings = list(latest.get("findings") if isinstance(latest.get("findings"), list) else [])
    findings.extend(watch_diagnostic_findings(diagnostics))
    if not watch_alive:
        findings.append("watch-not-running")
    if watch_stale:
        findings.append("watch-stale")
    return {
        "watch": {
            "pid": pid,
            "alive": watch_alive,
            "stale": watch_stale,
            "latestAgeSeconds": latest_age_seconds,
            "stopFilePresent": args.watch_stop_file.exists(),
        },
        "timestampUtc": latest.get("timestampUtc"),
        "findings": sorted(set(str(item) for item in findings)),
        "recommendations": latest.get("recommendations") if isinstance(latest.get("recommendations"), list) else [],
        "rust": {
            "uploadSpeedKiBps": rust.get("uploadSpeedKiBps"),
            "activeUploads": rust.get("activeUploads"),
            "waitingUploads": rust.get("waitingUploads"),
            "sharedHashingCount": rust.get("sharedHashingCount"),
            "ed2kConnected": rust.get("ed2kConnected"),
            "ed2kHighId": rust.get("ed2kHighId"),
            "ed2kPublishedEntries": rust.get("ed2kPublishedEntries"),
            "ed2kPendingEntries": rust.get("ed2kPendingEntries"),
            "ed2kVisibilityPercent": rust.get("ed2kVisibilityPercent"),
            "kadConnected": rust.get("kadConnected"),
            "kadFirewalled": rust.get("kadFirewalled"),
            "kadSourcePublishedTotal": rust.get("kadSourcePublishedTotal"),
        },
        "mfc": {
            "uploadSpeedKiBps": mfc.get("uploadSpeedKiBps"),
            "activeUploads": mfc.get("activeUploads"),
            "sharedFileCount": mfc.get("sharedFileCount"),
            "sharedHashingCount": mfc.get("sharedHashingCount"),
            "ed2kConnected": mfc.get("ed2kConnected"),
            "ed2kHighId": mfc.get("ed2kHighId"),
            "kadConnected": mfc.get("kadConnected"),
            "kadFirewalled": mfc.get("kadFirewalled"),
        },
        "monitor": {
            "alive": monitor.get("monitorAlive"),
            "stale": monitor.get("monitorStale"),
            "latestAgeSeconds": monitor.get("latestAgeSeconds"),
            "rustKiBps": monitor_latest.get("rustKiBps"),
            "rustUploads": monitor_latest.get("rustUploads"),
            "mfcKiBps": monitor_latest.get("mfcKiBps"),
            "mfcWaiting": monitor_latest.get("mfcWaiting"),
            "parityGap": monitor_latest.get("parityGap"),
            "mfcLogStale": monitor_latest.get("mfcLogStale"),
        },
        "vpn": {
            "allWhitelisted": vpn.get("allWhitelisted"),
            "adapterUp": vpn.get("adapterUp"),
            "bindIpPresent": vpn.get("bindIpPresent"),
        },
        "diagnostics": {
            "fileCount": diagnostics.get("fileCount"),
            "patterns": diagnostics.get("aggregatePatternCounts"),
            "jsonCounts": diagnostics.get("aggregateJsonCounts"),
            "antiFlood": compact_watch_anti_flood_summary(diagnostics.get("antiFloodSummary")),
            "uploadEfficiency": upload_efficiency,
        },
        "trend": {
            "sampleCount": trend.get("sampleCount"),
            "window": trend.get("window"),
            "rustUploadKiBps": counters.get("rustUploadKiBps"),
            "monitorRustUploadKiBps": counters.get("monitorRustUploadKiBps"),
            "rustEd2kPending": counters.get("rustEd2kPending"),
            "rustEd2kPublished": counters.get("rustEd2kPublished"),
            "rustKadSourcePublished": counters.get("rustKadSourcePublished"),
            "mfcHashingRemaining": counters.get("mfcHashingRemaining"),
            "mfcUploadKiBps": counters.get("mfcUploadKiBps"),
        },
    }


def compact_watch_anti_flood_summary(summary: object) -> dict[str, object] | None:
    """Returns the compact anti-flood fields useful in regular watch briefs."""

    if not isinstance(summary, dict):
        return None
    udp = summary.get("udpTrackerDrops") if isinstance(summary.get("udpTrackerDrops"), dict) else {}
    result: dict[str, object] = {
        "totalEvents": summary.get("totalEvents"),
        "maxRepeatCount": summary.get("maxRepeatCount"),
        "actionCounts": summary.get("actionCounts"),
        "behaviorCounts": summary.get("behaviorCounts"),
        "reasonCounts": summary.get("reasonCounts"),
        "windowSecondsCounts": summary.get("windowSecondsCounts"),
        "udpTrackerDrops": {
            "rows": udp.get("rows"),
            "bucketCounts": udp.get("bucketCounts"),
            "actionCounts": udp.get("actionCounts"),
            "reasonCounts": udp.get("reasonCounts"),
            "opcodeCounts": udp.get("opcodeCounts"),
        },
    }
    return result


def add_watch_evidence_args(parser: argparse.ArgumentParser) -> None:
    """Adds optional retained evidence knobs shared by watch commands."""

    parser.add_argument("--include-vpn-status", action="store_true")
    parser.add_argument("--check-vpn-adapter", action="store_true")
    parser.add_argument("--vpn-exe", type=Path, action="append")
    parser.add_argument("--vpn-settings-path", type=Path)
    parser.add_argument("--diagnostics-log-dir", type=Path, action="append")
    parser.add_argument("--diagnostics-log-file", type=Path, action="append")
    parser.add_argument("--diagnostics-limit", type=int, default=8)
    parser.add_argument("--diagnostics-max-bytes", type=int, default=262_144)


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=default_base_url())
    parser.add_argument("--api-key", default=RUST_API_KEY)
    sub = parser.add_subparsers(dest="command", required=True)

    sample_parser = sub.add_parser("sample", help="Print sanitized Rust status counters.")
    sample_parser.set_defaults(func=lambda args: sample(args.base_url, args.api_key))

    rust_p2p_parser = sub.add_parser("rust-p2p-start", help="Apply Rust P2P startup preferences and connect.")
    rust_p2p_parser.add_argument("--timeout-seconds", type=float, default=30.0)
    rust_p2p_parser.add_argument("--ensure-preferences", action=argparse.BooleanOptionalAction, default=True)
    rust_p2p_parser.add_argument("--start-kad", action=argparse.BooleanOptionalAction, default=True)
    rust_p2p_parser.set_defaults(func=rust_p2p_start)

    shared_summary_parser = sub.add_parser(
        "shared-summary",
        help="Print sanitized shared-directory and shared-file parity metadata.",
    )
    shared_summary_parser.add_argument(
        "--mfc-base-url",
        default=None,
        help=f"Optional MFC REST base URL, for example {default_mfc_base_url()}",
    )
    shared_summary_parser.add_argument("--mfc-api-key", default=MFC_API_KEY)
    shared_summary_parser.add_argument(
        "--include-fingerprints",
        action="store_true",
        help="Include full path-fingerprint lists and row summaries in the output.",
    )
    shared_summary_parser.add_argument("--fingerprint-sample-limit", type=int, default=20)
    shared_summary_parser.add_argument(
        "--compare-shared-file-hashes",
        action="store_true",
        help="Fetch all shared-file pages and compare unique ED2K hash sets.",
    )
    shared_summary_parser.add_argument(
        "--compare-shared-file-paths",
        action="store_true",
        help="Fetch all shared-file pages and compare path fingerprints to hashes.",
    )
    shared_summary_parser.add_argument(
        "--compare-shared-file-roots",
        action="store_true",
        help="Fetch all shared-file pages and compare sanitized per-root catalog counts.",
    )
    shared_summary_parser.add_argument(
        "--include-root-groups",
        action="store_true",
        help="Include every sanitized per-root group when comparing shared-file roots.",
    )
    shared_summary_parser.add_argument("--shared-file-page-size", type=int, default=1000)
    shared_summary_parser.add_argument("--shared-file-timeout-seconds", type=float, default=120.0)
    shared_summary_parser.add_argument("--shared-file-sleep-seconds", type=float, default=0.05)
    shared_summary_parser.set_defaults(func=shared_summary)

    apply_roots_parser = sub.add_parser(
        "apply-mfc-shared-roots",
        help="Apply MFC persisted shared-root intent to the Rust profile.",
    )
    apply_roots_parser.add_argument("--shared-dir-file", type=Path, default=default_mfc_shareddir_file())
    apply_roots_parser.add_argument("--extra-root", type=Path)
    apply_roots_parser.add_argument(
        "--auto-discover",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Opt in to searching generated soak output for a shareddir.dat when --shared-dir-file is absent.",
    )
    apply_roots_parser.add_argument("--timeout-seconds", type=float, default=120.0)
    apply_roots_parser.set_defaults(func=apply_mfc_shared_roots)

    apply_rest_roots_parser = sub.add_parser(
        "apply-mfc-rest-shared-roots",
        help="Apply the live MFC REST configured shared roots to Rust.",
    )
    apply_rest_roots_parser.add_argument(
        "--mfc-base-url",
        default=default_mfc_base_url(),
        help=f"MFC REST base URL, for example {default_mfc_base_url()}",
    )
    apply_rest_roots_parser.add_argument("--mfc-api-key", default=MFC_API_KEY)
    apply_rest_roots_parser.add_argument("--collection", choices=("roots", "items"), default="roots")
    apply_rest_roots_parser.add_argument("--timeout-seconds", type=float, default=120.0)
    apply_rest_roots_parser.set_defaults(func=apply_mfc_rest_shared_roots)

    write_mfc_shareddir_parser = sub.add_parser(
        "write-mfc-shareddir-from-rest",
        help="Write MFC persisted shared-directory files from a live REST shared-directory model.",
    )
    write_mfc_shareddir_parser.add_argument("--source-base-url", default=default_base_url())
    write_mfc_shareddir_parser.add_argument("--source-api-key", default=RUST_API_KEY)
    write_mfc_shareddir_parser.add_argument("--target-profile-dir", type=Path, default=default_mfc_profile_dir())
    write_mfc_shareddir_parser.add_argument("--timeout-seconds", type=float, default=120.0)
    write_mfc_shareddir_parser.add_argument("--fingerprint-sample-limit", type=int, default=20)
    write_mfc_shareddir_parser.add_argument("--dry-run", action="store_true")
    write_mfc_shareddir_parser.set_defaults(func=write_mfc_shareddir_from_rest)

    repair_parser = sub.add_parser(
        "repair-rust-metadata-from-mfc-rest",
        help="Seed Rust metadata from live MFC shared-files REST rows and known.met.",
    )
    repair_parser.add_argument("--mfc-base-url", default=default_mfc_base_url())
    repair_parser.add_argument("--mfc-api-key", default=MFC_API_KEY)
    repair_parser.add_argument("--metadata-db", type=Path, default=default_metadata_db())
    repair_parser.add_argument("--rust-repo", type=Path, default=default_rust_repo())
    repair_parser.add_argument("--known-met", type=Path)
    repair_parser.add_argument("--extra-root", action="append", type=Path, default=[])
    repair_parser.add_argument("--allow-known-met-fallback", action="store_true")
    repair_parser.add_argument("--dry-run", action="store_true")
    repair_parser.add_argument("--shared-file-page-size", type=int, default=1000)
    repair_parser.add_argument("--shared-file-timeout-seconds", type=float, default=120.0)
    repair_parser.add_argument("--shared-file-sleep-seconds", type=float, default=0.05)
    repair_parser.set_defaults(func=repair_rust_metadata_from_mfc_rest)

    stop_parser = sub.add_parser("stop-rust", help="Gracefully stop a running Rust diagnostics daemon.")
    stop_parser.add_argument("--pid", type=int, required=True)
    stop_parser.add_argument("--shutdown-timeout-seconds", type=float, default=45.0)
    stop_parser.set_defaults(func=stop_rust)

    rust_processes_parser = sub.add_parser("rust-processes", help="List Rust process rows through Python WMI.")
    rust_processes_parser.set_defaults(func=rust_processes)

    mfc_processes_parser = sub.add_parser("mfc-processes", help="List sanitized MFC process rows through Python WMI.")
    mfc_processes_parser.set_defaults(func=mfc_processes)

    stop_mfc_parser = sub.add_parser("stop-mfc", help="Gracefully stop a running MFC diagnostics client.")
    stop_mfc_parser.add_argument("--pid", type=int, required=True)
    stop_mfc_parser.add_argument("--shutdown-timeout-seconds", type=float, default=45.0)
    stop_mfc_parser.set_defaults(func=stop_mfc)

    start_mfc_parser = sub.add_parser("start-mfc", help="Start MFC diagnostics against the persistent soak profile.")
    start_mfc_parser.add_argument("--rest-host")
    start_mfc_parser.add_argument("--rest-port", type=int, default=4732)
    start_mfc_parser.add_argument("--inputs", type=Path, default=default_live_wire_inputs())
    start_mfc_parser.add_argument("--artifacts-dir", type=Path, default=output_root() / "soak" / "mfc-profile")
    start_mfc_parser.add_argument("--profile-seed-dir", type=Path, default=DEFAULT_MFC_SEED_CONFIG_DIR)
    start_mfc_parser.add_argument("--direct-profile-dir", type=Path)
    start_mfc_parser.add_argument(
        "--rebuild-profile-from-inputs",
        action="store_true",
        help="Prepare or replace the persistent MFC profile from --inputs instead of reusing an existing profile-base.",
    )
    start_mfc_parser.add_argument("--exe", type=Path)
    start_mfc_parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    start_mfc_parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    start_mfc_parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    start_mfc_parser.add_argument("--server", default=OPERATOR_SERVER)
    start_mfc_parser.add_argument("--ed2k-port", type=int, default=MFC_ED2K_PORT)
    start_mfc_parser.add_argument("--kad-port", type=int, default=MFC_KAD_PORT)
    start_mfc_parser.add_argument("--server-udp-port", type=int, default=MFC_SERVER_UDP_PORT)
    start_mfc_parser.add_argument("--upload-limit-kibps", type=int, default=soak_launch.DEFAULT_UPLOAD_LIMIT_KIBPS)
    start_mfc_parser.add_argument("--rest-timeout-seconds", type=float, default=90.0)
    start_mfc_parser.add_argument("--connect-timeout-seconds", type=float, default=180.0)
    start_mfc_parser.add_argument("--skip-vpn-check", action="store_true")
    start_mfc_parser.add_argument("--no-obfuscation", action="store_true")
    start_mfc_parser.set_defaults(func=start_mfc)

    mfc_logs_parser = sub.add_parser("mfc-upload-logs", help="List MFC upload-slot diagnostics log candidates.")
    mfc_logs_parser.add_argument("--search-root", type=Path, action="append")
    mfc_logs_parser.add_argument("--fresh-seconds", type=float, default=900.0)
    mfc_logs_parser.add_argument("--limit", type=int, default=20)
    mfc_logs_parser.set_defaults(func=mfc_upload_logs)

    diagnostics_parser = sub.add_parser(
        "diagnostics-summary",
        help="Summarize diagnostics logs without exposing private live data.",
    )
    diagnostics_parser.add_argument("--log-dir", type=Path, action="append")
    diagnostics_parser.add_argument("--log-file", type=Path, action="append")
    diagnostics_parser.add_argument("--limit", type=int, default=12)
    diagnostics_parser.add_argument("--max-bytes", type=int, default=1_048_576)
    diagnostics_parser.set_defaults(func=diagnostics_summary)

    upload_efficiency_parser = sub.add_parser(
        "upload-efficiency-summary",
        help="Summarize upload outcome latency and efficiency from diagnostics logs.",
    )
    upload_efficiency_parser.add_argument("--log-dir", type=Path, action="append")
    upload_efficiency_parser.add_argument("--log-file", type=Path, action="append")
    upload_efficiency_parser.add_argument("--limit", type=int, default=12)
    upload_efficiency_parser.add_argument("--max-bytes", type=int, default=1_048_576)
    upload_efficiency_parser.add_argument("--slow-read-ms", type=float, default=100.0)
    upload_efficiency_parser.add_argument("--outlier-limit", type=int, default=8)
    upload_efficiency_parser.set_defaults(func=upload_efficiency_summary)

    anti_flood_parser = sub.add_parser(
        "anti-flood-summary",
        help="Summarize anti-flood diagnostics bursts with sanitized peer fingerprints.",
    )
    anti_flood_parser.add_argument("--log-dir", type=Path, action="append")
    anti_flood_parser.add_argument("--log-file", type=Path, action="append")
    anti_flood_parser.add_argument("--limit", type=int, default=12)
    anti_flood_parser.add_argument("--max-bytes", type=int, default=1_048_576)
    anti_flood_parser.add_argument("--peer-limit", type=int, default=12)
    anti_flood_parser.add_argument("--event-limit", type=int, default=12)
    anti_flood_parser.set_defaults(func=anti_flood_summary)

    vpn_parser = sub.add_parser(
        "vpn-allowlist-status",
        help="Report hide.me split-tunnel allow-list status without changing settings.",
    )
    vpn_parser.add_argument("--exe", type=Path, action="append")
    vpn_parser.add_argument("--settings-path", type=Path)
    vpn_parser.add_argument("--check-adapter", action="store_true")
    vpn_parser.set_defaults(func=vpn_allowlist_status)

    start_parser = sub.add_parser("start-rust", help="Start Rust diagnostics against a persisted runtime.")
    start_parser.add_argument("--runtime-dir", type=Path, default=default_runtime_dir())
    start_parser.add_argument("--log-dir", type=Path)
    start_parser.add_argument("--config", type=Path)
    start_parser.add_argument("--exe", type=Path, default=default_executable())
    start_parser.add_argument("--rest-timeout-seconds", type=float, default=90.0)
    start_parser.add_argument("--connect-timeout-seconds", type=float, default=180.0)
    start_parser.add_argument("--start-kad", action="store_true", default=True)
    start_parser.add_argument("--no-start-kad", action="store_false", dest="start_kad")
    start_parser.add_argument("--wait-connected", action="store_true", default=True)
    start_parser.add_argument("--no-wait-connected", action="store_false", dest="wait_connected")
    start_parser.set_defaults(func=start_rust)

    stop_monitor_parser = sub.add_parser("stop-monitor", help="Stop the upload parity monitor via its stop file.")
    stop_monitor_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    stop_monitor_parser.set_defaults(func=lambda args: stop_upload_monitor(args.output_dir))

    sample_monitor_parser = sub.add_parser("monitor-sample", help="Print the latest upload parity monitor summary.")
    sample_monitor_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    sample_monitor_parser.add_argument(
        "--stale-seconds",
        type=float,
        default=600.0,
        help="Age threshold for reporting the latest monitor sample as stale.",
    )
    sample_monitor_parser.set_defaults(func=upload_monitor_sample)

    monitor_parser = sub.add_parser("restart-monitor", help="Restart the upload parity monitor.")
    monitor_parser.add_argument("--mfc-upload-log", type=Path)
    monitor_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    monitor_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    monitor_parser.add_argument("--rust-pid", type=int)
    monitor_parser.add_argument("--rust-diag-log", type=Path)
    monitor_parser.add_argument("--interval-seconds", type=float, default=300.0)
    monitor_parser.add_argument("--mfc-log-stale-seconds", type=float, default=900.0)
    monitor_parser.set_defaults(func=restart_upload_monitor)

    watch_parser = sub.add_parser("watch-once", help="Run one long-soak cadence check and optional monitor repair.")
    watch_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    watch_parser.add_argument("--stale-seconds", type=float, default=900.0)
    watch_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    watch_parser.add_argument("--rust-pid", type=int)
    watch_parser.add_argument("--rust-diag-log", type=Path)
    watch_parser.add_argument("--mfc-upload-log", type=Path)
    watch_parser.add_argument("--mfc-base-url", default=None)
    watch_parser.add_argument("--mfc-api-key", default=MFC_API_KEY)
    watch_parser.add_argument("--interval-seconds", type=float, default=300.0)
    watch_parser.add_argument("--mfc-log-stale-seconds", type=float, default=900.0)
    watch_parser.add_argument("--restart-stale-monitor", action="store_true", default=True)
    watch_parser.add_argument("--no-restart-stale-monitor", action="store_false", dest="restart_stale_monitor")
    watch_parser.add_argument(
        "--append-jsonl",
        action="store_true",
        help="Append this one-shot sample to the retained watch JSONL and heartbeat.",
    )
    watch_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    watch_parser.add_argument(
        "--watch-pid-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.pid",
        help="Detached watch PID file used when --report brief includes loop health.",
    )
    watch_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
        help="Detached watch stop-file path used when --report brief includes loop health.",
    )
    watch_parser.add_argument(
        "--report",
        choices=("full", "brief"),
        default="full",
        help="Print full evidence or a compact one-shot monitoring report.",
    )
    watch_parser.add_argument(
        "--report-limit",
        type=int,
        default=12,
        help="Retained watch samples to include in --report brief trend counters.",
    )
    add_watch_evidence_args(watch_parser)
    watch_parser.set_defaults(func=watch_once)

    watch_loop_parser = sub.add_parser("watch-loop", help="Run repeated long-soak cadence checks.")
    watch_loop_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    watch_loop_parser.add_argument("--stale-seconds", type=float, default=900.0)
    watch_loop_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    watch_loop_parser.add_argument("--rust-pid", type=int)
    watch_loop_parser.add_argument("--rust-diag-log", type=Path)
    watch_loop_parser.add_argument("--mfc-upload-log", type=Path)
    watch_loop_parser.add_argument("--mfc-base-url", default=None)
    watch_loop_parser.add_argument("--mfc-api-key", default=MFC_API_KEY)
    watch_loop_parser.add_argument("--interval-seconds", type=float, default=300.0)
    watch_loop_parser.add_argument("--mfc-log-stale-seconds", type=float, default=900.0)
    watch_loop_parser.add_argument("--restart-stale-monitor", action="store_true", default=True)
    watch_loop_parser.add_argument("--no-restart-stale-monitor", action="store_false", dest="restart_stale_monitor")
    watch_loop_parser.add_argument(
        "--watch-interval-seconds",
        type=float,
        default=300.0,
        help="Seconds to sleep between watch samples.",
    )
    watch_loop_parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Maximum samples to take; 0 means run until interrupted.",
    )
    watch_loop_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_loop_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    watch_loop_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    add_watch_evidence_args(watch_loop_parser)
    watch_loop_parser.set_defaults(func=watch_loop)

    start_watch_loop_parser = sub.add_parser("start-watch-loop", help="Start detached repeated soak checks.")
    start_watch_loop_parser.add_argument("--output-dir", type=Path, default=output_root() / "soak" / "parity-monitor")
    start_watch_loop_parser.add_argument("--stale-seconds", type=float, default=900.0)
    start_watch_loop_parser.add_argument("--log-dir", type=Path, default=default_runtime_dir() / "packet-dump")
    start_watch_loop_parser.add_argument("--rust-pid", type=int)
    start_watch_loop_parser.add_argument("--rust-diag-log", type=Path)
    start_watch_loop_parser.add_argument("--mfc-upload-log", type=Path)
    start_watch_loop_parser.add_argument("--mfc-base-url", default=None)
    start_watch_loop_parser.add_argument("--mfc-api-key", default=MFC_API_KEY)
    start_watch_loop_parser.add_argument("--interval-seconds", type=float, default=300.0)
    start_watch_loop_parser.add_argument("--mfc-log-stale-seconds", type=float, default=900.0)
    start_watch_loop_parser.add_argument("--restart-stale-monitor", action="store_true", default=True)
    start_watch_loop_parser.add_argument(
        "--no-restart-stale-monitor",
        action="store_false",
        dest="restart_stale_monitor",
    )
    start_watch_loop_parser.add_argument("--watch-interval-seconds", type=float, default=300.0)
    start_watch_loop_parser.add_argument("--max-samples", type=int, default=0)
    start_watch_loop_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    start_watch_loop_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    start_watch_loop_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    add_watch_evidence_args(start_watch_loop_parser)
    start_watch_loop_parser.set_defaults(func=start_watch_loop)

    stop_watch_loop_parser = sub.add_parser("stop-watch-loop", help="Request the detached soak watch loop to stop.")
    stop_watch_loop_parser.add_argument(
        "--watch-pid-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.pid",
    )
    stop_watch_loop_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    stop_watch_loop_parser.add_argument("--terminate", action="store_true")
    stop_watch_loop_parser.set_defaults(func=stop_watch_loop)

    watch_status_parser = sub.add_parser("watch-status", help="Print detached soak watch loop health.")
    watch_status_parser.add_argument(
        "--stale-seconds",
        type=float,
        default=900.0,
        help="Age threshold for reporting the latest watch sample as stale.",
    )
    watch_status_parser.add_argument(
        "--watch-pid-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.pid",
    )
    watch_status_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_status_parser.add_argument(
        "--watch-heartbeat",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.heartbeat.txt",
    )
    watch_status_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    watch_status_parser.set_defaults(func=watch_status)

    watch_brief_parser = sub.add_parser("watch-brief", help="Print compact long-soak watch health and trend summary.")
    watch_brief_parser.add_argument(
        "--stale-seconds",
        type=float,
        default=900.0,
        help="Age threshold for reporting the latest watch sample as stale.",
    )
    watch_brief_parser.add_argument(
        "--watch-pid-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.pid",
    )
    watch_brief_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_brief_parser.add_argument(
        "--watch-stop-file",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.stop",
    )
    watch_brief_parser.add_argument(
        "--rust-diag-log",
        type=Path,
        help="Current Rust diagnostics JSONL log to use for upload-efficiency evidence.",
    )
    watch_brief_parser.add_argument(
        "--upload-efficiency-max-bytes",
        type=int,
        default=33_554_432,
        help="Bytes to scan from --rust-diag-log for compact upload-efficiency evidence.",
    )
    watch_brief_parser.add_argument("--slow-read-ms", type=float, default=100.0)
    watch_brief_parser.add_argument("--limit", type=int, default=12)
    watch_brief_parser.set_defaults(func=watch_brief)

    watch_trend_parser = sub.add_parser("watch-trend", help="Summarize retained soak watch JSONL trends.")
    watch_trend_parser.add_argument(
        "--watch-jsonl",
        type=Path,
        default=output_root() / "soak" / "parity-monitor" / "rust-soak-watch.jsonl",
    )
    watch_trend_parser.add_argument("--limit", type=int, default=24)
    watch_trend_parser.set_defaults(func=watch_trend)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the helper CLI."""

    args = build_parser().parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
