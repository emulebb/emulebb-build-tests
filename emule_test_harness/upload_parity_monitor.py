"""Aggregate upload parity monitor for live Rust-vs-MFC soak sessions."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_INTERVAL_SECONDS = 300.0
DEFAULT_RUST_UNDERFILL_KIBPS = 2048.0
DEFAULT_MFC_SATURATED_KIBPS = 2500.0
DEFAULT_RUST_MFC_RATIO_FLOOR = 0.85
DEFAULT_MIN_PARITY_GAP_KIBPS = 512.0
DEFAULT_TAIL_BYTES = 16_000_000

SLOT_RE = re.compile(
    r"UploadSlotDiagnostics: slot=(?P<slot>\d+) live=(?P<live>\d+).*?"
    r"state=(?P<state>\S+).*?rateBytesPerSec=(?P<rate>\d+).*?"
    r"pendingIO=(?P<pending>\d+).*?reqRejected=(?P<rejected>\d+)"
)
SUMMARY_PREFIX = "UploadSlotDiagnostics: summary "
SUMMARY_FIELD_RE = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\S+)")


@dataclass(frozen=True)
class MonitorConfig:
    """Runtime configuration for one aggregate parity monitor."""

    rust_base_url: str
    rust_api_key: str
    rust_diag_log: Path | None
    mfc_upload_log: Path
    output_dir: Path
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS
    rust_underfill_kibps: float = DEFAULT_RUST_UNDERFILL_KIBPS
    mfc_saturated_kibps: float = DEFAULT_MFC_SATURATED_KIBPS
    rust_mfc_ratio_floor: float = DEFAULT_RUST_MFC_RATIO_FLOOR
    min_parity_gap_kibps: float = DEFAULT_MIN_PARITY_GAP_KIBPS
    tail_bytes: int = DEFAULT_TAIL_BYTES
    once: bool = False

    @property
    def jsonl_path(self) -> Path:
        return self.output_dir / "upload-parity-monitor.jsonl"

    @property
    def heartbeat_path(self) -> Path:
        return self.output_dir / "upload-parity-monitor.heartbeat.txt"

    @property
    def pid_path(self) -> Path:
        return self.output_dir / "upload-parity-monitor.pid"

    @property
    def stop_path(self) -> Path:
        return self.output_dir / "upload-parity-monitor.stop"


def now_iso() -> str:
    """Returns the current UTC timestamp for monitor artifacts."""

    return datetime.now(timezone.utc).isoformat()


def tail_lines(path: Path, *, max_bytes: int = DEFAULT_TAIL_BYTES) -> list[str]:
    """Reads the tail of a diagnostics log without loading rotated-size files."""

    if not path.exists():
        return []
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(-max_bytes, os.SEEK_END)
            handle.readline()
        data = handle.read()
    return data.decode("utf-8", errors="replace").splitlines()


def mfc_upload_summary(path: Path, *, tail_bytes: int = DEFAULT_TAIL_BYTES) -> dict[str, object]:
    """Summarizes MFC upload-slot diagnostics without retaining peer or file names."""

    summary: dict[str, object] = {
        "logPresent": path.exists(),
        "logLastWrite": None,
        "slotsSeen": 0,
        "liveSlots": 0,
        "uploadingSlots": 0,
        "nonzeroRateSlots": 0,
        "sumRateKiBps": 0.0,
        "pendingIOSum": 0,
        "reqRejectedSum": 0,
        "summaryPresent": False,
    }
    if not path.exists():
        return summary

    summary["logLastWrite"] = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    latest: dict[int, dict[str, int | str]] = {}
    latest_summary: dict[str, int] = {}
    for line in tail_lines(path, max_bytes=tail_bytes):
        if SUMMARY_PREFIX in line:
            latest_summary = {
                match.group("key"): int(match.group("value"))
                for match in SUMMARY_FIELD_RE.finditer(line)
                if match.group("value").lstrip("-").isdigit()
            }
        match = SLOT_RE.search(line)
        if not match:
            continue
        slot = int(match.group("slot"))
        latest[slot] = {
            "live": int(match.group("live")),
            "state": match.group("state"),
            "rateBps": int(match.group("rate")),
            "pendingIO": int(match.group("pending")),
            "reqRejected": int(match.group("rejected")),
        }

    rows = list(latest.values())
    summary["slotsSeen"] = len(rows)
    summary["liveSlots"] = sum(1 for row in rows if row["live"] == 1)
    summary["uploadingSlots"] = sum(1 for row in rows if row["state"] == "Uploading")
    summary["nonzeroRateSlots"] = sum(1 for row in rows if row["rateBps"] > 0)
    summary["sumRateKiBps"] = round(sum(int(row["rateBps"]) for row in rows) / 1024, 2)
    summary["pendingIOSum"] = sum(int(row["pendingIO"]) for row in rows)
    summary["reqRejectedSum"] = sum(int(row["reqRejected"]) for row in rows)
    if latest_summary:
        summary["summaryPresent"] = True
        for key in (
            "waiting",
            "waitingEligible",
            "activeSlots",
            "baseSlotTarget",
            "effectiveSlotCap",
            "cap",
            "configuredBudgetBytesPerSec",
            "toNetworkBytesPerSec",
            "datarateBytesPerSec",
            "underfilled",
            "sharedFiles",
            "ed2kPublishedFiles",
            "ed2kPendingFiles",
            "ed2kPendingLargeUnsupportedFiles",
            "kadPublishReady",
            "kadSourceDueFiles",
            "kadSourceBackoffFiles",
            "kadSourceSearches",
            "kadSourceSearchCap",
            "kadKeywordSearches",
            "kadKeywordSearchCap",
        ):
            if key in latest_summary:
                summary[key] = latest_summary[key]
        if "datarateBytesPerSec" in latest_summary:
            summary["summaryRateKiBps"] = round(latest_summary["datarateBytesPerSec"] / 1024, 2)
    return summary


def rust_sched_summary(path: Path | None, *, tail_bytes: int = DEFAULT_TAIL_BYTES) -> dict[str, object]:
    """Summarizes Rust scheduler diag events without retaining peer or file identifiers."""

    summary: dict[str, object] = {
        "logPresent": path is not None and path.exists(),
        "logLastWrite": None,
        "schedEvents": 0,
        "eventCounts": {},
        "kadPublishEvents": {},
        "kadPublishFailureClasses": {},
        "kadPublishAttemptedContacts": {},
        "kadPublishAckedContacts": {},
        "kadPublishTimedOutContacts": {},
        "kadPublishFailedContacts": {},
        "requestOutcomes": {},
        "recycleReasons": {},
        "payloadAccountingEvents": 0,
        "servedBytes": 0,
        "throttleDelayMs": 0,
        "verifiedReaderOpenMs": 0,
        "payloadReadMs": 0,
        "lastCapacity": None,
    }
    if path is None or not path.exists():
        return summary

    summary["logLastWrite"] = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    event_counts: Counter[str] = Counter()
    kad_publish_events: Counter[str] = Counter()
    kad_publish_failure_classes: Counter[str] = Counter()
    kad_publish_attempted_contacts: Counter[str] = Counter()
    kad_publish_acked_contacts: Counter[str] = Counter()
    kad_publish_timed_out_contacts: Counter[str] = Counter()
    kad_publish_failed_contacts: Counter[str] = Counter()
    request_outcomes: Counter[str] = Counter()
    recycle_reasons: Counter[str] = Counter()
    payload_accounting_events = 0
    served_bytes = 0
    throttle_delay_ms = 0
    verified_reader_open_ms = 0
    payload_read_ms = 0
    last_capacity: dict[str, object] | None = None

    for line in tail_lines(path, max_bytes=tail_bytes):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        family = record.get("family")
        event = str(record.get("event") or "")
        body = record.get("body") or {}
        if not isinstance(body, dict):
            body = {}
        if family == "kad_event" and event in {"kad_keyword_publish", "kad_source_publish", "kad_notes_publish"}:
            publish_kind = str(body.get("publishKind") or event.removeprefix("kad_").removesuffix("_publish"))
            milestone = str(body.get("milestone") or "")
            kad_publish_events[f"{publish_kind}:{milestone}"] += 1
            failure_class = str(body.get("failureClass") or "")
            if failure_class:
                kad_publish_failure_classes[f"{publish_kind}:{failure_class}"] += 1
            kad_publish_attempted_contacts[publish_kind] += int(body.get("attemptedContacts") or 0)
            kad_publish_acked_contacts[publish_kind] += int(body.get("ackedContacts") or 0)
            kad_publish_timed_out_contacts[publish_kind] += int(body.get("timedOutContacts") or 0)
            kad_publish_failed_contacts[publish_kind] += int(body.get("failedContacts") or 0)
            continue
        if family != "sched":
            continue
        event_counts[event] += 1
        if event == "capacity_snapshot":
            last_capacity = {
                key: body.get(key)
                for key in (
                    "activeSlots",
                    "baseSlots",
                    "effectiveSlotCap",
                    "elasticSlots",
                    "elasticUnderfill",
                    "underfillSinceMs",
                    "uploadLimitBytesPerSec",
                    "uploadRateBytesPerSec",
                    "waitingSessions",
                )
            }
        elif event == "upload_slot_recycled":
            recycle_reasons[str(body.get("reason") or "unknown")] += 1
        elif event == "upload_request_outcome":
            request_outcomes[str(body.get("outcome") or "unknown")] += 1
            served_bytes += int(body.get("servedBytes") or 0)
            throttle_delay_ms += int(body.get("throttleDelayMs") or 0)
            verified_reader_open_ms += int(body.get("verifiedReaderOpenMs") or 0)
            payload_read_ms += int(body.get("payloadReadMs") or 0)
        elif event == "upload_payload_accounting":
            payload_accounting_events += 1

    summary["schedEvents"] = sum(event_counts.values())
    summary["eventCounts"] = dict(event_counts)
    summary["kadPublishEvents"] = dict(kad_publish_events)
    summary["kadPublishFailureClasses"] = dict(kad_publish_failure_classes)
    summary["kadPublishAttemptedContacts"] = dict(kad_publish_attempted_contacts)
    summary["kadPublishAckedContacts"] = dict(kad_publish_acked_contacts)
    summary["kadPublishTimedOutContacts"] = dict(kad_publish_timed_out_contacts)
    summary["kadPublishFailedContacts"] = dict(kad_publish_failed_contacts)
    summary["requestOutcomes"] = dict(request_outcomes)
    summary["recycleReasons"] = dict(recycle_reasons)
    summary["payloadAccountingEvents"] = payload_accounting_events
    summary["servedBytes"] = served_bytes
    summary["throttleDelayMs"] = throttle_delay_ms
    summary["verifiedReaderOpenMs"] = verified_reader_open_ms
    summary["payloadReadMs"] = payload_read_ms
    summary["lastCapacity"] = last_capacity
    return summary


def fetch_json(base_url: str, path: str, *, api_key: str, timeout_seconds: float = 8.0) -> dict[str, object]:
    """Fetches one JSON REST endpoint from a running emulebb-rust instance."""

    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    request = Request(url, headers={"X-API-Key": api_key})
    with urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def rust_summary(config: MonitorConfig) -> dict[str, object]:
    """Summarizes Rust upload and publishing counters from REST."""

    stats_payload = fetch_json(config.rust_base_url, "/stats", api_key=config.rust_api_key)
    status_payload = fetch_json(config.rust_base_url, "/status", api_key=config.rust_api_key)
    uploads_payload = fetch_json(config.rust_base_url, "/uploads", api_key=config.rust_api_key)

    stats = stats_payload["data"]  # type: ignore[index]
    status = status_payload["data"]  # type: ignore[index]
    uploads = uploads_payload["data"].get("items", [])  # type: ignore[union-attr]
    runtime = status.get("runtimeDiagnostics", {})  # type: ignore[union-attr]
    kad = status.get("kad", {})  # type: ignore[union-attr]
    ed2k_publish = runtime.get("ed2kPublish", {}) or {}
    kad_publish = runtime.get("kadPublish", {}) or {}

    return {
        "restOk": True,
        "activeUploads": stats.get("activeUploads"),  # type: ignore[union-attr]
        "waitingUploads": stats.get("waitingUploads"),  # type: ignore[union-attr]
        "uploadSpeedKiBps": round(float(stats.get("uploadSpeedKiBps") or 0.0), 2),  # type: ignore[union-attr]
        "sessionUploadedBytes": stats.get("sessionUploadedBytes"),  # type: ignore[union-attr]
        "uploadLimitBytesPerSec": stats.get("uploadLimitBytesPerSec"),  # type: ignore[union-attr]
        "uploadBaseSlots": stats.get("uploadBaseSlots"),  # type: ignore[union-attr]
        "uploadEffectiveSlotCap": stats.get("uploadEffectiveSlotCap"),  # type: ignore[union-attr]
        "uploadElasticSlots": stats.get("uploadElasticSlots"),  # type: ignore[union-attr]
        "uploadElasticUnderfill": stats.get("uploadElasticUnderfill"),  # type: ignore[union-attr]
        "sharedHashingActive": stats.get("sharedHashingActive"),  # type: ignore[union-attr]
        "sharedHashingCount": stats.get("sharedHashingCount"),  # type: ignore[union-attr]
        "ed2kConnected": stats.get("ed2kConnected"),  # type: ignore[union-attr]
        "ed2kHighId": stats.get("ed2kHighId"),  # type: ignore[union-attr]
        "kadConnected": stats.get("kadConnected"),  # type: ignore[union-attr]
        "kadFirewalled": stats.get("kadFirewalled"),  # type: ignore[union-attr]
        "kadFirewalledStatus": kad.get("firewalled") if isinstance(kad, dict) else None,
        "kadContactCount": kad.get("contactCount") if isinstance(kad, dict) else None,
        "kadIndexedSources": kad.get("indexedSources") if isinstance(kad, dict) else None,
        "kadIndexedKeywords": kad.get("indexedKeywords") if isinstance(kad, dict) else None,
        "knownFileCount": runtime.get("knownFileCount"),
        "sharedFileCount": runtime.get("sharedFileCount"),
        "ed2kPublishedEntries": ed2k_publish.get("publishedEntries"),
        "ed2kPendingEntries": ed2k_publish.get("pendingEntries"),
        "ed2kPublishQueuedCount": ed2k_publish.get("queuedCount"),
        "ed2kPublishPhase": ed2k_publish.get("phase"),
        "kadSourcePublishedTotal": kad_publish.get("sourcePublishedTotal"),
        "kadSourceAttemptedContactsTotal": kad_publish.get("sourceAttemptedContactsTotal"),
        "kadSourceAckedContactsTotal": kad_publish.get("sourceAckedContactsTotal"),
        "kadSourceContactTimeoutsTotal": kad_publish.get("sourceContactTimeoutsTotal"),
        "kadSourceFailed": kad_publish.get("sourceFailed"),
        "kadSourceDueCount": kad_publish.get("sourceDueCount"),
        "kadKeywordPublishedTotal": kad_publish.get("keywordPublishedTotal"),
        "kadKeywordAttemptedContactsTotal": kad_publish.get("keywordAttemptedContactsTotal"),
        "kadKeywordAckedContactsTotal": kad_publish.get("keywordAckedContactsTotal"),
        "kadKeywordContactTimeoutsTotal": kad_publish.get("keywordContactTimeoutsTotal"),
        "kadKeywordFailed": kad_publish.get("keywordFailed"),
        "kadGateAllowed": kad_publish.get("gateAllowed"),
        "kadGateBlockReason": kad_publish.get("gateBlockReason"),
        "uploadRows": len(uploads),
        "nonzeroUploadRows": sum(1 for row in uploads if float(row.get("uploadSpeedKiBps") or 0) > 0),
    }


def build_record(config: MonitorConfig) -> dict[str, object]:
    """Builds one aggregate parity record."""

    rust = rust_summary(config)
    rust_sched = rust_sched_summary(config.rust_diag_log, tail_bytes=config.tail_bytes)
    mfc = mfc_upload_summary(config.mfc_upload_log, tail_bytes=config.tail_bytes)
    rust_kibps = float(rust["uploadSpeedKiBps"])
    mfc_kibps = float(mfc.get("summaryRateKiBps") or mfc["sumRateKiBps"])
    throughput_gap_kibps = round(max(0.0, mfc_kibps - rust_kibps), 2)
    rust_mfc_ratio = round(rust_kibps / mfc_kibps, 4) if mfc_kibps > 0.0 else None
    rust_ed2k_pending = int(rust.get("ed2kPendingEntries") or 0)
    rust_ed2k_total = int(rust.get("ed2kPublishedEntries") or 0) + rust_ed2k_pending
    mfc_ed2k_pending = int(mfc.get("ed2kPendingFiles") or 0)
    rust_waiting = int(rust.get("waitingUploads") or 0)
    mfc_waiting = int(mfc.get("waiting") or 0)
    action = {
        "throughputGapKiBps": throughput_gap_kibps,
        "rustMfcThroughputRatio": rust_mfc_ratio,
        "mfcEffectiveKiBps": mfc_kibps,
        "rustUnderfilled": rust_kibps < config.rust_underfill_kibps,
        "rustDemandStarved": rust_waiting == 0 and rust_kibps < config.rust_underfill_kibps,
        "mfcSaturating": mfc_kibps > config.mfc_saturated_kibps,
        "rustEd2kPublishComplete": rust_ed2k_total > 0 and rust_ed2k_pending == 0,
        "mfcEd2kPublishComplete": mfc.get("summaryPresent") is True and mfc_ed2k_pending == 0,
        "rustVisibilityMaturing": rust_ed2k_pending > 0,
        "rustWaitingDemand": rust_waiting,
        "mfcWaitingDemand": mfc_waiting,
    }
    relative_gap = (
        rust_mfc_ratio is not None
        and rust_mfc_ratio < config.rust_mfc_ratio_floor
        and throughput_gap_kibps >= config.min_parity_gap_kibps
    )
    action["relativeThroughputGap"] = action["mfcSaturating"] and relative_gap
    action["parityGap"] = action["mfcSaturating"] and (action["rustUnderfilled"] or relative_gap)
    action["postVisibilityDemandGap"] = (
        action["parityGap"]
        and action["rustEd2kPublishComplete"]
        and action["mfcEd2kPublishComplete"]
        and rust_waiting == 0
        and mfc_waiting > 0
    )
    return {"timestamp": now_iso(), "rust": rust, "rustSched": rust_sched, "mfc": mfc, "action": action}


def append_record(config: MonitorConfig, record: dict[str, object]) -> None:
    """Appends one JSONL record and updates the human-readable heartbeat."""

    config.output_dir.mkdir(parents=True, exist_ok=True)
    with config.jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    if "error" in record:
        text = f"lastSample={record['timestamp']} error={record['error']}\n"
    else:
        rust = record["rust"]  # type: ignore[index]
        mfc = record["mfc"]  # type: ignore[index]
        action = record["action"]  # type: ignore[index]
        text = (
            f"lastSample={record['timestamp']} "
            f"rustKiBps={rust['uploadSpeedKiBps']} "
            f"rustUploads={rust['activeUploads']} "
            f"mfcKiBps={action.get('mfcEffectiveKiBps', mfc['sumRateKiBps'])} "
            f"parityGap={action['parityGap']}\n"
        )
    config.heartbeat_path.write_text(text, encoding="utf-8")


def run_monitor(config: MonitorConfig) -> int:
    """Runs the monitor until --once completes or the stop file is created."""

    config.output_dir.mkdir(parents=True, exist_ok=True)
    config.pid_path.write_text(str(os.getpid()), encoding="ascii")
    while not config.stop_path.exists():
        try:
            append_record(config, build_record(config))
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError) as exc:
            append_record(config, {"timestamp": now_iso(), "error": repr(exc)})
        if config.once:
            return 0
        for _ in range(max(1, int(config.interval_seconds))):
            if config.stop_path.exists():
                return 0
            time.sleep(1)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-base-url", required=True, help="Base Rust REST URL, for example http://host:port/api/v1.")
    parser.add_argument("--rust-api-key", required=True)
    parser.add_argument("--rust-diag-log", type=Path)
    parser.add_argument("--mfc-upload-log", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS)
    parser.add_argument("--rust-underfill-kibps", type=float, default=DEFAULT_RUST_UNDERFILL_KIBPS)
    parser.add_argument("--mfc-saturated-kibps", type=float, default=DEFAULT_MFC_SATURATED_KIBPS)
    parser.add_argument("--rust-mfc-ratio-floor", type=float, default=DEFAULT_RUST_MFC_RATIO_FLOOR)
    parser.add_argument("--min-parity-gap-kibps", type=float, default=DEFAULT_MIN_PARITY_GAP_KIBPS)
    parser.add_argument("--tail-bytes", type=int, default=DEFAULT_TAIL_BYTES)
    parser.add_argument("--once", action="store_true")
    return parser


def config_from_args(args: argparse.Namespace) -> MonitorConfig:
    """Creates monitor configuration from parsed arguments."""

    return MonitorConfig(
        rust_base_url=args.rust_base_url,
        rust_api_key=args.rust_api_key,
        rust_diag_log=args.rust_diag_log,
        mfc_upload_log=args.mfc_upload_log,
        output_dir=args.output_dir,
        interval_seconds=args.interval_seconds,
        rust_underfill_kibps=args.rust_underfill_kibps,
        mfc_saturated_kibps=args.mfc_saturated_kibps,
        rust_mfc_ratio_floor=args.rust_mfc_ratio_floor,
        min_parity_gap_kibps=args.min_parity_gap_kibps,
        tail_bytes=args.tail_bytes,
        once=args.once,
    )


def main(argv: list[str] | None = None) -> int:
    """Runs the upload parity monitor CLI."""

    parser = build_parser()
    args = parser.parse_args(argv)
    return run_monitor(config_from_args(args))
