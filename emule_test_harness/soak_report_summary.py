"""Sanitized reporting helpers for converged rust<->MFC soak campaigns."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from . import soak_action_diff

CHECKPOINT_RE = re.compile(
    r"\[soak\] checkpoint: packets rust=(?P<rust>\d+) mfc=(?P<mfc>\d+) actions=(?P<actions>\d+)"
)


def read_json(path: Path) -> dict[str, Any]:
    """Reads a JSON object from ``path``."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a JSON object")
    return payload


def load_action_reports(report_dir: Path) -> list[dict[str, Any]]:
    """Loads per-action reports from a converged soak report directory."""

    actions_dir = report_dir / "actions"
    if not actions_dir.is_dir():
        return []
    reports = [read_json(path) for path in sorted(actions_dir.glob("*.json"))]
    return sorted(reports, key=lambda report: int(report.get("seq") or 0))


def load_checkpoint_reports(report_dir: Path) -> list[dict[str, Any]]:
    """Loads structured checkpoint reports from a converged soak report directory."""

    checkpoints_dir = report_dir / "checkpoints"
    if not checkpoints_dir.is_dir():
        return []
    reports = [read_json(path) for path in sorted(checkpoints_dir.glob("*.json"))]
    return sorted(reports, key=lambda report: str(report.get("ts_utc") or ""))


def parse_checkpoint_lines(log_path: Path | None) -> list[dict[str, int]]:
    """Extracts packet/action checkpoint counters from the runner log."""

    if log_path is None or not log_path.is_file():
        return []
    checkpoints: list[dict[str, int]] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = CHECKPOINT_RE.search(line)
        if match is None:
            continue
        checkpoints.append(
            {
                "rustPackets": int(match.group("rust")),
                "mfcPackets": int(match.group("mfc")),
                "actions": int(match.group("actions")),
            }
        )
    return checkpoints


def log_finished(log_path: Path | None) -> bool:
    """Returns true when the runner log includes the final-summary marker."""

    if log_path is None or not log_path.is_file():
        return False
    text = log_path.read_text(encoding="utf-8", errors="replace")
    return "[soak] final summary:" in text


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _gap_counts(report: dict[str, Any]) -> list[dict[str, Any]]:
    coverage = (report.get("packetDiff") or {}).get("opcodeCoverage")
    if not isinstance(coverage, dict):
        return []
    gaps: list[dict[str, Any]] = []
    for channel in coverage.get("channels") or []:
        if not isinstance(channel, dict):
            continue
        only_rust = channel.get("onlyRust") if isinstance(channel.get("onlyRust"), list) else []
        only_mfc = channel.get("onlyEmule") if isinstance(channel.get("onlyEmule"), list) else []
        if only_rust or only_mfc:
            gaps.append(
                {
                    "channel": channel.get("channel"),
                    "direction": channel.get("direction"),
                    "onlyRustOpcodes": len(only_rust),
                    "onlyMfcOpcodes": len(only_mfc),
                }
            )
    return gaps


def _action_coverage(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("verdict") == "unpaired":
        return {"ok": None, "mode": "unpaired", "required": []}
    coverage = report.get("actionCoverage")
    if isinstance(coverage, dict):
        return coverage
    packet_diff = report.get("packetDiff") if isinstance(report.get("packetDiff"), dict) else {}
    return soak_action_diff.build_action_coverage(str(report.get("kind") or ""), packet_diff)


def _action_verdict(report: dict[str, Any], action_coverage: dict[str, Any]) -> str:
    if report.get("verdict") == "unpaired":
        return "unpaired"
    packets = report.get("packets") if isinstance(report.get("packets"), dict) else {}
    rust_count = int(packets.get("rust") or 0)
    mfc_count = int(packets.get("mfc") or 0)
    if rust_count == 0 and mfc_count == 0:
        return "no-traffic"
    if rust_count == 0 or mfc_count == 0:
        return "one-sided"
    if bool(action_coverage.get("ok")) and report.get("diagOk") is not False:
        return "coverage-parity"
    return "divergence"


def summarize_actions(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Builds a privacy-safe aggregate over per-action reports."""

    verdict_counts: Counter[str] = Counter()
    action_verdict_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    verdicts_by_kind: dict[str, Counter[str]] = defaultdict(Counter)
    diag_failures = 0
    coverage_failures = 0
    action_coverage_failures = 0
    download_start_ok = 0
    download_payload_ok = 0
    download_payload_missing = 0
    divergence_samples: list[dict[str, Any]] = []
    action_divergence_samples: list[dict[str, Any]] = []
    for report in reports:
        kind = str(report.get("kind") or "unknown")
        verdict = str(report.get("verdict") or "unknown")
        action_coverage = _action_coverage(report)
        action_verdict = _action_verdict(report, action_coverage)
        kind_counts[kind] += 1
        verdict_counts[verdict] += 1
        action_verdict_counts[action_verdict] += 1
        verdicts_by_kind[kind][verdict] += 1
        if report.get("diagOk") is False:
            diag_failures += 1
        if report.get("coverageOk") is False:
            coverage_failures += 1
        if action_coverage.get("ok") is False and action_verdict != "unpaired":
            action_coverage_failures += 1
        if kind == soak_action_diff.DOWNLOAD and action_coverage.get("mode") == "action-required-opcodes":
            if action_coverage.get("downloadStartOk") is True:
                download_start_ok += 1
                if action_coverage.get("downloadPayloadOk") is True:
                    download_payload_ok += 1
                else:
                    download_payload_missing += 1
        if verdict != "coverage-parity" and len(divergence_samples) < 10:
            divergence_samples.append(
                {
                    "seq": report.get("seq"),
                    "kind": kind,
                    "verdict": verdict,
                    "coverageOk": report.get("coverageOk"),
                    "actionCoverageOk": action_coverage.get("ok"),
                    "actionCoverageMode": action_coverage.get("mode"),
                    "downloadStartOk": action_coverage.get("downloadStartOk"),
                    "downloadPayloadOk": action_coverage.get("downloadPayloadOk"),
                    "fullCoverageOk": report.get("fullCoverageOk", report.get("coverageOk")),
                    "diagOk": report.get("diagOk"),
                    "packets": report.get("packets"),
                    "opcodeGapChannels": _gap_counts(report),
                }
            )
        if action_verdict != "coverage-parity" and len(action_divergence_samples) < 10:
            action_divergence_samples.append(
                {
                    "seq": report.get("seq"),
                    "kind": kind,
                    "verdict": action_verdict,
                    "actionCoverageOk": action_coverage.get("ok"),
                    "actionCoverageMode": action_coverage.get("mode"),
                    "downloadStartOk": action_coverage.get("downloadStartOk"),
                    "downloadPayloadOk": action_coverage.get("downloadPayloadOk"),
                    "diagOk": report.get("diagOk"),
                    "packets": report.get("packets"),
                    "opcodeGapChannels": _gap_counts(report),
                }
            )
    return {
        "actions": len(reports),
        "kindCounts": _counter_dict(kind_counts),
        "verdictCounts": _counter_dict(verdict_counts),
        "actionVerdictCounts": _counter_dict(action_verdict_counts),
        "verdictsByKind": {
            kind: _counter_dict(counter) for kind, counter in sorted(verdicts_by_kind.items())
        },
        "coverageFailures": coverage_failures,
        "actionCoverageFailures": action_coverage_failures,
        "downloadCoverage": {
            "startParity": download_start_ok,
            "payloadParity": download_payload_ok,
            "payloadMissingAfterStartParity": download_payload_missing,
        },
        "diagFailures": diag_failures,
        "divergenceSamples": divergence_samples,
        "actionDivergenceSamples": action_divergence_samples,
    }


def summarize_action_report_inventory(
    summary: dict[str, Any], reports: list[dict[str, Any]]
) -> dict[str, int | None]:
    """Compares summary action totals with loadable per-action JSON reports."""

    totals = summary.get("totals") if isinstance(summary.get("totals"), dict) else {}
    expected = totals.get("actions")
    expected_count = int(expected) if isinstance(expected, int) else None
    loaded_count = len(reports)
    return {
        "expected": expected_count,
        "loaded": loaded_count,
        "missing": max(expected_count - loaded_count, 0) if expected_count is not None else None,
    }


def summarize_driver(summary: dict[str, Any]) -> dict[str, Any]:
    """Builds a compact driver-cycle aggregate from ``summary.json``."""

    driver = summary.get("driver") if isinstance(summary.get("driver"), dict) else {}
    cycles = driver.get("cycles") if isinstance(driver.get("cycles"), list) else []
    downloads = [
        cycle.get("download")
        for cycle in cycles
        if isinstance(cycle, dict) and isinstance(cycle.get("download"), dict)
    ]
    failure_reasons: Counter[str] = Counter()
    for download in downloads:
        if download.get("ok") is not False:
            continue
        reason = download.get("reason") or str(download.get("error") or "").split(":", 1)[0]
        failure_reasons[str(reason or "unknown")] += 1
    return {
        "autoDrive": bool(driver.get("autoDrive")),
        "cycles": len(cycles),
        "downloadEvery": driver.get("downloadEvery"),
        "searchIntervalSeconds": driver.get("searchIntervalSeconds"),
        "downloadDelaySeconds": driver.get("downloadDelaySeconds"),
        "downloadRequestedCycles": sum(
            1 for cycle in cycles if isinstance(cycle, dict) and bool(cycle.get("downloadRequested"))
        ),
        "downloadOk": sum(1 for download in downloads if download.get("ok") is True),
        "downloadFailed": sum(1 for download in downloads if download.get("ok") is False),
        "downloadPending": sum(1 for download in downloads if download.get("ok") is None),
        "downloadFailureReasons": _counter_dict(failure_reasons),
    }


def _rest_status(checkpoint: dict[str, Any], client: str) -> dict[str, Any]:
    rest_status = checkpoint.get("restStatus")
    if not isinstance(rest_status, dict):
        return {}
    status = rest_status.get(client)
    return status if isinstance(status, dict) else {}


def summarize_checkpoints(
    checkpoint_reports: list[dict[str, Any]], log_checkpoints: list[dict[str, int]]
) -> dict[str, Any]:
    """Builds upload/share/process stability evidence from checkpoints."""

    if not checkpoint_reports:
        return {
            "count": len(log_checkpoints),
            "last": log_checkpoints[-1] if log_checkpoints else None,
            "structuredCount": 0,
        }

    rust_statuses = [_rest_status(checkpoint, "rust") for checkpoint in checkpoint_reports]
    mfc_statuses = [_rest_status(checkpoint, "mfc") for checkpoint in checkpoint_reports]
    last = checkpoint_reports[-1]
    last_rust = rust_statuses[-1] if rust_statuses else {}
    last_mfc = mfc_statuses[-1] if mfc_statuses else {}
    error_hits = [
        hit
        for checkpoint in checkpoint_reports
        for hit in (checkpoint.get("errorLogHits") or [])
        if isinstance(hit, dict)
    ]
    return {
        "count": len(log_checkpoints),
        "last": log_checkpoints[-1] if log_checkpoints else None,
        "structuredCount": len(checkpoint_reports),
        "firstTsUtc": checkpoint_reports[0].get("ts_utc"),
        "lastTsUtc": last.get("ts_utc"),
        "rustAliveAll": all(bool(checkpoint.get("rustAlive")) for checkpoint in checkpoint_reports),
        "connectedAll": {
            "rust": all(status.get("connected") is True for status in rust_statuses),
            "mfc": all(status.get("connected") is True for status in mfc_statuses),
        },
        "lowIdObserved": {
            "rust": any(status.get("lowId") is True for status in rust_statuses),
            "mfc": any(status.get("lowId") is True for status in mfc_statuses),
        },
        "activeUploadMax": {
            "rust": max((int(status.get("activeUploads") or 0) for status in rust_statuses), default=0),
            "mfc": max((int(status.get("activeUploads") or 0) for status in mfc_statuses), default=0),
        },
        "lastRestStatus": {
            "rust": {
                "activeUploads": last_rust.get("activeUploads"),
                "waitingUploads": last_rust.get("waitingUploads"),
                "sharedFileCount": last_rust.get("sharedFileCount"),
                "sharedHashingCount": last_rust.get("sharedHashingCount"),
            },
            "mfc": {
                "activeUploads": last_mfc.get("activeUploads"),
                "waitingUploads": last_mfc.get("waitingUploads"),
                "sharedFileCount": last_mfc.get("sharedFileCount"),
                "sharedHashingCount": last_mfc.get("sharedHashingCount"),
            },
        },
        "errorLogHitCount": len(error_hits),
    }


def summarize_report(report_dir: Path, *, log_path: Path | None = None) -> dict[str, Any]:
    """Returns a sanitized summary for one converged soak report directory."""

    summary = read_json(report_dir / "summary.json")
    action_reports = load_action_reports(report_dir)
    log_checkpoints = parse_checkpoint_lines(log_path)
    checkpoint_reports = load_checkpoint_reports(report_dir)
    return {
        "schema": "converged_soak_report_summary_v1",
        "campaignId": summary.get("campaignId"),
        "finished": log_finished(log_path),
        "totals": summary.get("totals"),
        "baseline": summary.get("baseline"),
        "driver": summarize_driver(summary),
        "vpn": {
            "sameBindIp": (summary.get("vpn") or {}).get("sameBindIp")
            if isinstance(summary.get("vpn"), dict)
            else None,
            "bindIpPresent": bool(summary.get("bindIp") or (summary.get("vpn") or {}).get("sameBindIp")),
        },
        "environmentParity": summary.get("environmentParity"),
        "actionReports": summarize_action_report_inventory(summary, action_reports),
        "actions": summarize_actions(action_reports),
        "checkpoints": summarize_checkpoints(checkpoint_reports, log_checkpoints),
    }
