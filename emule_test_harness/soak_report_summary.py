"""Bounded reporting helpers for converged rust<->MFC soak campaigns."""

from __future__ import annotations

import copy
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from . import converged_observer_state, observer_action_report, soak_action_diff

SCHEMA = "emulebb-build-tests.converged-soak-report.v3"
CONSISTENCY_ATTEMPTS = 5
CONSISTENCY_RETRY_SECONDS = 0.1

CHECKPOINT_RE = re.compile(
    r"\[soak\] checkpoint: packets rust=(?P<rust>\d+) mfc=(?P<mfc>\d+) actions=(?P<actions>\d+)"
)


class SoakReportSummaryError(RuntimeError):
    """Raised when cumulative state and its retained files disagree."""


def read_json(path: Path) -> dict[str, Any]:
    """Reads a JSON object from ``path``."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a JSON object")
    return payload


def load_action_reports(report_dir: Path) -> list[dict[str, Any]]:
    """Loads and validates current per-action reports."""

    actions_dir = report_dir / "actions"
    if not actions_dir.is_dir():
        return []
    reports = [
        observer_action_report.validate_observer_action_report(read_json(path))
        for path in sorted(actions_dir.glob("*.json"))
    ]
    return sorted(reports, key=lambda report: int(report.get("seq") or 0))


def load_checkpoint_reports(report_dir: Path) -> list[dict[str, Any]]:
    """Loads current structured checkpoint reports."""

    checkpoints_dir = report_dir / "checkpoints"
    if not checkpoints_dir.is_dir():
        return []
    reports = [read_json(path) for path in sorted(checkpoints_dir.glob("*.json"))]
    for report in reports:
        if (
            report.get("schema") != "soak_checkpoint_v1"
            or not isinstance(report.get("campaignId"), str)
            or not isinstance(report.get("ts_utc"), str)
            or not isinstance(report.get("packetRecords"), dict)
            or not isinstance(report.get("diagnosticWriters"), dict)
        ):
            raise SoakReportSummaryError("Retained observer checkpoint is invalid.")
    return sorted(reports, key=lambda report: str(report["ts_utc"]))


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


def _assessment(report: dict[str, Any]) -> dict[str, Any]:
    value = report.get("assessment")
    return value if isinstance(value, dict) else report


def summarize_full_run_diagnostics(gate: dict[str, Any]) -> dict[str, Any]:
    """Compacts required-family and transport lifecycle gate evidence."""

    family_gate = (
        gate.get("familyConformance")
        if isinstance(gate.get("familyConformance"), dict)
        else {}
    )
    required_failures = [
        {
            "family": row.get("family"),
            "rustPresent": row.get("rustPresent"),
            "mfcPresent": row.get("mfcPresent"),
        }
        for row in family_gate.get("requiredFamilies") or []
        if isinstance(row, dict) and row.get("ok") is not True
    ]
    lifecycle_gate = (
        gate.get("clientUdpLifecycle")
        if isinstance(gate.get("clientUdpLifecycle"), dict)
        else {}
    )
    lifecycle: dict[str, Any] = {}
    for side in ("rust", "mfc"):
        audit = lifecycle_gate.get(side) if isinstance(lifecycle_gate.get(side), dict) else {}
        violation_counts = Counter(
            str(violation.get("kind") or "unknown")
            for violation in audit.get("violations") or []
            if isinstance(violation, dict)
        )
        lifecycle[side] = {
            "ok": audit.get("ok"),
            "attempts": int(audit.get("attemptCount") or 0),
            "terminals": int(audit.get("terminalCount") or 0),
            "outcomes": audit.get("outcomes") if isinstance(audit.get("outcomes"), dict) else {},
            "violationCounts": _counter_dict(violation_counts),
        }
    server_gate = (
        gate.get("serverConnectionLifecycle")
        if isinstance(gate.get("serverConnectionLifecycle"), dict)
        else {}
    )
    server_lifecycle: dict[str, Any] = {}
    for side in ("rust", "mfc"):
        audit = server_gate.get(side) if isinstance(server_gate.get(side), dict) else {}
        violation_counts = Counter(
            str(violation.get("kind") or "unknown")
            for violation in audit.get("violations") or []
            if isinstance(violation, dict)
        )
        server_lifecycle[side] = {
            "ok": audit.get("ok"),
            "attempts": int(audit.get("attemptCount") or 0),
            "events": int(audit.get("eventCount") or 0),
            "outcomes": audit.get("outcomes") if isinstance(audit.get("outcomes"), dict) else {},
            "violationCounts": _counter_dict(violation_counts),
        }
    return {
        "ok": gate.get("ok"),
        "requiredFamiliesOk": family_gate.get("requiredFamiliesOk"),
        "missingRequiredFamilies": required_failures,
        "clientUdpLifecycle": lifecycle,
        "serverConnectionLifecycle": server_lifecycle,
    }


def _gap_counts(report: dict[str, Any]) -> list[dict[str, Any]]:
    coverage = (_assessment(report).get("packetDiff") or {}).get("opcodeCoverage")
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
    coverage = _assessment(report).get("actionCoverage")
    if not isinstance(coverage, dict):
        raise SoakReportSummaryError(
            "Observer action report is missing current action coverage."
        )
    return coverage


def _action_verdict(report: dict[str, Any], action_coverage: dict[str, Any]) -> str:
    if report.get("verdict") == "unpaired":
        return "unpaired"
    packets = _assessment(report).get("packets")
    packets = packets if isinstance(packets, dict) else {}
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
    """Builds one bounded aggregate over retained per-action reports."""

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
    response_status_counts: Counter[str] = Counter()
    response_reason_counts: Counter[str] = Counter()
    result_polls: dict[str, dict[str, Any]] = {
        client: {
            "polls": 0,
            "attempts": 0,
            "errors": 0,
            "terminationCounts": Counter(),
        }
        for client in ("rust", "mfc")
    }
    for report in reports:
        assessment = _assessment(report)
        kind = str(report.get("kind") or "unknown")
        verdict = str(report.get("verdict") or "unknown")
        action_coverage = _action_coverage(report)
        response_assessment = action_coverage.get("responseAssessment")
        if isinstance(response_assessment, dict):
            response_status_counts[
                str(response_assessment.get("status") or "invalid")
            ] += 1
            response_reason_counts[
                str(response_assessment.get("reason") or "invalid")
            ] += 1
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
                    "packets": assessment.get("packets"),
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
                    "packets": assessment.get("packets"),
                    "opcodeGapChannels": _gap_counts(report),
                }
            )
        driver_outcome = report.get("driverOutcome")
        searches = (
            driver_outcome.get("searches")
            if isinstance(driver_outcome, dict)
            and isinstance(driver_outcome.get("searches"), dict)
            else {}
        )
        for client in ("rust", "mfc"):
            search = searches.get(client)
            results = (
                search.get("results")
                if isinstance(search, dict)
                and isinstance(search.get("results"), dict)
                else {}
            )
            poll = results.get("poll")
            if not isinstance(poll, dict):
                continue
            result_polls[client]["polls"] += 1
            result_polls[client]["attempts"] += int(poll.get("attempts") or 0)
            result_polls[client]["errors"] += int(poll.get("errorCount") or 0)
            result_polls[client]["terminationCounts"][
                str(poll.get("termination") or "unknown")
            ] += 1
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
        "serverResponseAssessment": {
            "statusCounts": _counter_dict(response_status_counts),
            "reasonCounts": _counter_dict(response_reason_counts),
        },
        "divergenceSamples": divergence_samples,
        "actionDivergenceSamples": action_divergence_samples,
        "resultPolls": {
            client: {
                **{key: value for key, value in values.items() if key != "terminationCounts"},
                "terminationCounts": _counter_dict(values["terminationCounts"]),
            }
            for client, values in result_polls.items()
        },
    }


def summarize_action_report_inventory(
    summary: dict[str, Any], reports: list[dict[str, Any]]
) -> dict[str, int]:
    """Returns cumulative and retained action counts without conflating rotation."""

    retention = summary["retention"]["actions"]
    loaded = len(reports)
    return {
        "seen": retention["seen"],
        "retained": retention["retained"],
        "loaded": loaded,
        "omittedByRetention": retention["omitted"],
        "unexpectedMissing": max(retention["retained"] - loaded, 0),
        "unexpectedExtra": max(loaded - retention["retained"], 0),
        "retainedBytes": retention["retainedBytes"],
    }


def summarize_checkpoints(
    checkpoint_reports: list[dict[str, Any]], log_checkpoints: list[dict[str, int]]
) -> dict[str, Any]:
    """Builds bounded current writer evidence from retained checkpoints."""

    if not checkpoint_reports:
        return {
            "retained": 0,
            "firstTsUtc": None,
            "lastTsUtc": None,
            "lastPacketRecords": None,
            "maxPacketRecords": {"rust": 0, "mfc": 0},
            "lastDiagnosticWriters": None,
            "logCount": len(log_checkpoints),
            "lastLogCounters": log_checkpoints[-1] if log_checkpoints else None,
        }

    last = checkpoint_reports[-1]
    return {
        "retained": len(checkpoint_reports),
        "firstTsUtc": checkpoint_reports[0]["ts_utc"],
        "lastTsUtc": last["ts_utc"],
        "lastPacketRecords": copy.deepcopy(last["packetRecords"]),
        "maxPacketRecords": {
            client: max(
                int(checkpoint["packetRecords"].get(client) or 0)
                for checkpoint in checkpoint_reports
            )
            for client in ("rust", "mfc")
        },
        "lastDiagnosticWriters": copy.deepcopy(last["diagnosticWriters"]),
        "logCount": len(log_checkpoints),
        "lastLogCounters": log_checkpoints[-1] if log_checkpoints else None,
    }


def _retained_paths(report_dir: Path, stream: str) -> list[Path]:
    return sorted((report_dir / stream).glob("*.json"))


def _poll_provenance(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    provenance: list[dict[str, Any]] = []
    for report in reports:
        driver = report["driverOutcome"]
        searches = driver.get("searches") if isinstance(driver, dict) else None
        clients: dict[str, Any] = {}
        for client in ("rust", "mfc"):
            search = searches.get(client) if isinstance(searches, dict) else None
            results = search.get("results") if isinstance(search, dict) else None
            poll = results.get("poll") if isinstance(results, dict) else None
            clients[client] = copy.deepcopy(poll)
        provenance.append(
            {
                "seq": report["seq"],
                "actionId": report["actionId"],
                "clients": clients,
            }
        )
    return provenance


def _validate_retained_stream(
    *,
    report_dir: Path,
    state: dict[str, Any],
    stream: str,
    reports: list[dict[str, Any]],
) -> dict[str, Any]:
    retention = state["retention"][stream]
    cumulative_seen = (
        state["totals"]["actions"]
        if stream == "actions"
        else state["checkpoints"]["count"]
    )
    if retention["seen"] != cumulative_seen:
        raise SoakReportSummaryError(
            f"Retained {stream} watermark disagrees with cumulative observer state."
        )
    paths = _retained_paths(report_dir, stream)
    if len(paths) != len(reports) or len(reports) != retention["retained"]:
        raise SoakReportSummaryError(
            f"Retained {stream} count disagrees with observer state."
        )
    retained_bytes = sum(path.stat().st_size for path in paths)
    if retained_bytes != retention["retainedBytes"]:
        raise SoakReportSummaryError(
            f"Retained {stream} bytes disagree with observer state."
        )
    latest_file = paths[-1].name if paths else None
    if latest_file != retention["latestFile"]:
        raise SoakReportSummaryError(
            f"Retained {stream} latest file disagrees with observer state."
        )
    if any(report.get("campaignId") != state["campaignId"] for report in reports):
        raise SoakReportSummaryError(
            f"Retained {stream} campaign identity disagrees with observer state."
        )
    inventory = {
        "seen": retention["seen"],
        "retained": retention["retained"],
        "omittedByRetention": retention["omitted"],
        "unexpectedMissing": 0,
        "retainedBytes": retained_bytes,
        "latestFile": latest_file,
    }
    if stream == "actions":
        sequences = [int(report["seq"]) for report in reports]
        first_sequence = retention["seen"] - retention["retained"] + 1
        expected = list(range(first_sequence, retention["seen"] + 1))
        if sequences != expected:
            raise SoakReportSummaryError(
                "Retained action sequence is not the authoritative suffix."
            )
        inventory["firstRetainedSeq"] = sequences[0] if sequences else None
        inventory["lastRetainedSeq"] = sequences[-1] if sequences else None
    else:
        timestamps = [str(report["ts_utc"]) for report in reports]
        parsed = [
            soak_action_diff.parse_utc_timestamp(
                timestamp,
                label="retained observer checkpoint timestamp",
            )
            for timestamp in timestamps
        ]
        if any(left >= right for left, right in zip(parsed, parsed[1:])):
            raise SoakReportSummaryError(
                "Retained checkpoint timestamps are not strictly increasing."
            )
        inventory["firstRetainedUtc"] = timestamps[0] if timestamps else None
        inventory["lastRetainedUtc"] = timestamps[-1] if timestamps else None
    return inventory


def _load_consistent_report_inputs(
    report_dir: Path,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    last_error: Exception | None = None
    for attempt in range(CONSISTENCY_ATTEMPTS):
        before = converged_observer_state.validate_state(
            read_json(report_dir / "summary.json")
        )
        try:
            actions = load_action_reports(report_dir)
            checkpoints = load_checkpoint_reports(report_dir)
            after = converged_observer_state.validate_state(
                read_json(report_dir / "summary.json")
            )
            if before != after:
                raise SoakReportSummaryError(
                    "Observer state changed while loading its retained window."
                )
            action_inventory = _validate_retained_stream(
                report_dir=report_dir,
                state=after,
                stream="actions",
                reports=actions,
            )
            checkpoint_inventory = _validate_retained_stream(
                report_dir=report_dir,
                state=after,
                stream="checkpoints",
                reports=checkpoints,
            )
            return (
                after,
                actions,
                checkpoints,
                action_inventory,
                checkpoint_inventory,
            )
        except (OSError, RuntimeError, ValueError) as error:
            last_error = error
            if attempt + 1 < CONSISTENCY_ATTEMPTS:
                time.sleep(CONSISTENCY_RETRY_SECONDS)
                continue
            break
    raise SoakReportSummaryError(
        "Could not load one consistent observer state and retained window."
    ) from last_error


def summarize_report(report_dir: Path, *, log_path: Path | None = None) -> dict[str, Any]:
    """Returns the sole current cumulative-plus-retained soak report."""

    (
        state,
        action_reports,
        checkpoint_reports,
        action_inventory,
        checkpoint_inventory,
    ) = _load_consistent_report_inputs(report_dir)
    log_checkpoints = parse_checkpoint_lines(log_path)
    action_inventory["summary"] = summarize_actions(action_reports)
    action_inventory["pollProvenance"] = _poll_provenance(action_reports)
    checkpoint_inventory["summary"] = summarize_checkpoints(
        checkpoint_reports,
        log_checkpoints,
    )
    return {
        "schema": SCHEMA,
        "campaignId": state["campaignId"],
        "finished": log_finished(log_path),
        "parityGate": copy.deepcopy(state["parityGate"]),
        "observerState": state,
        "retainedWindow": {
            "actions": action_inventory,
            "checkpoints": checkpoint_inventory,
        },
    }
