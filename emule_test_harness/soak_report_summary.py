"""Sanitized reporting helpers for converged rust<->MFC soak campaigns."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

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


def summarize_actions(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Builds a privacy-safe aggregate over per-action reports."""

    verdict_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    verdicts_by_kind: dict[str, Counter[str]] = defaultdict(Counter)
    diag_failures = 0
    coverage_failures = 0
    divergence_samples: list[dict[str, Any]] = []
    for report in reports:
        kind = str(report.get("kind") or "unknown")
        verdict = str(report.get("verdict") or "unknown")
        kind_counts[kind] += 1
        verdict_counts[verdict] += 1
        verdicts_by_kind[kind][verdict] += 1
        if report.get("diagOk") is False:
            diag_failures += 1
        if report.get("coverageOk") is False:
            coverage_failures += 1
        if verdict != "coverage-parity" and len(divergence_samples) < 10:
            divergence_samples.append(
                {
                    "seq": report.get("seq"),
                    "kind": kind,
                    "verdict": verdict,
                    "coverageOk": report.get("coverageOk"),
                    "diagOk": report.get("diagOk"),
                    "packets": report.get("packets"),
                    "opcodeGapChannels": _gap_counts(report),
                }
            )
    return {
        "actions": len(reports),
        "kindCounts": _counter_dict(kind_counts),
        "verdictCounts": _counter_dict(verdict_counts),
        "verdictsByKind": {
            kind: _counter_dict(counter) for kind, counter in sorted(verdicts_by_kind.items())
        },
        "coverageFailures": coverage_failures,
        "diagFailures": diag_failures,
        "divergenceSamples": divergence_samples,
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
    }


def summarize_report(report_dir: Path, *, log_path: Path | None = None) -> dict[str, Any]:
    """Returns a sanitized summary for one converged soak report directory."""

    summary = read_json(report_dir / "summary.json")
    action_reports = load_action_reports(report_dir)
    checkpoints = parse_checkpoint_lines(log_path)
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
        "actions": summarize_actions(action_reports),
        "checkpoints": {
            "count": len(checkpoints),
            "last": checkpoints[-1] if checkpoints else None,
        },
    }
