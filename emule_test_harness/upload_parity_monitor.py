"""Aggregate upload parity monitor for live Rust-vs-MFC soak sessions."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_INTERVAL_SECONDS = 300.0
DEFAULT_RUST_UNDERFILL_KIBPS = 2048.0
DEFAULT_MFC_SATURATED_KIBPS = 2500.0
DEFAULT_TAIL_BYTES = 2_000_000

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
    mfc_upload_log: Path
    output_dir: Path
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS
    rust_underfill_kibps: float = DEFAULT_RUST_UNDERFILL_KIBPS
    mfc_saturated_kibps: float = DEFAULT_MFC_SATURATED_KIBPS
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
        "ed2kPublishedEntries": ed2k_publish.get("publishedEntries"),
        "ed2kPendingEntries": ed2k_publish.get("pendingEntries"),
        "ed2kPublishQueuedCount": ed2k_publish.get("queuedCount"),
        "ed2kPublishPhase": ed2k_publish.get("phase"),
        "kadSourcePublishedTotal": kad_publish.get("sourcePublishedTotal"),
        "kadSourceDueCount": kad_publish.get("sourceDueCount"),
        "kadGateAllowed": kad_publish.get("gateAllowed"),
        "kadGateBlockReason": kad_publish.get("gateBlockReason"),
        "uploadRows": len(uploads),
        "nonzeroUploadRows": sum(1 for row in uploads if float(row.get("uploadSpeedKiBps") or 0) > 0),
    }


def build_record(config: MonitorConfig) -> dict[str, object]:
    """Builds one aggregate parity record."""

    rust = rust_summary(config)
    mfc = mfc_upload_summary(config.mfc_upload_log, tail_bytes=config.tail_bytes)
    action = {
        "rustUnderfilled": float(rust["uploadSpeedKiBps"]) < config.rust_underfill_kibps,
        "rustDemandStarved": rust["waitingUploads"] == 0
        and float(rust["uploadSpeedKiBps"]) < config.rust_underfill_kibps,
        "mfcSaturating": float(mfc["sumRateKiBps"]) > config.mfc_saturated_kibps,
        "parityGap": float(mfc["sumRateKiBps"]) > config.mfc_saturated_kibps
        and float(rust["uploadSpeedKiBps"]) < config.rust_underfill_kibps,
    }
    return {"timestamp": now_iso(), "rust": rust, "mfc": mfc, "action": action}


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
            f"mfcKiBps={mfc['sumRateKiBps']} "
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
    parser.add_argument("--mfc-upload-log", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS)
    parser.add_argument("--rust-underfill-kibps", type=float, default=DEFAULT_RUST_UNDERFILL_KIBPS)
    parser.add_argument("--mfc-saturated-kibps", type=float, default=DEFAULT_MFC_SATURATED_KIBPS)
    parser.add_argument("--tail-bytes", type=int, default=DEFAULT_TAIL_BYTES)
    parser.add_argument("--once", action="store_true")
    return parser


def config_from_args(args: argparse.Namespace) -> MonitorConfig:
    """Creates monitor configuration from parsed arguments."""

    return MonitorConfig(
        rust_base_url=args.rust_base_url,
        rust_api_key=args.rust_api_key,
        mfc_upload_log=args.mfc_upload_log,
        output_dir=args.output_dir,
        interval_seconds=args.interval_seconds,
        rust_underfill_kibps=args.rust_underfill_kibps,
        mfc_saturated_kibps=args.mfc_saturated_kibps,
        tail_bytes=args.tail_bytes,
        once=args.once,
    )


def main(argv: list[str] | None = None) -> int:
    """Runs the upload parity monitor CLI."""

    parser = build_parser()
    args = parser.parse_args(argv)
    return run_monitor(config_from_args(args))
