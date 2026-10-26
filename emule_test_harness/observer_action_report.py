"""Pure report assembly for one completed converged-observer action."""

from __future__ import annotations

import copy
from datetime import datetime
import json
from typing import Any

from . import diag_event_diff, observer_action_evidence, soak_action_diff

SCHEMA = "emulebb-build-tests.observer-action-report.v1"
_CLIENTS = ("rust", "mfc")
_VERDICTS = {
    "coverage-parity",
    "divergence",
    "one-sided",
    "no-traffic",
    "unpaired",
    "not-assessable",
    "evidence-incomplete",
}
_REPORT_FIELDS = {
    "schema",
    "campaignId",
    "seq",
    "actionId",
    "cycle",
    "kind",
    "method",
    "key",
    "label",
    "window",
    "observed",
    "verdict",
    "coverageOk",
    "fullCoverageOk",
    "byteMatch",
    "diagOk",
    "diagStrictOk",
    "driverOutcome",
    "diagnosticEvidence",
    "assessment",
}
_ASSESSMENT_FIELDS = {
    "kind",
    "key",
    "method",
    "label",
    "window",
    "observed",
    "packets",
    "assessmentRecords",
    "verdict",
    "coverageOk",
    "fullCoverageOk",
    "byteMatch",
    "diagOk",
    "diagStrictOk",
    "actionCoverage",
    "packetDiff",
    "diagDiff",
    "diagConformance",
}


class ObserverActionReportError(RuntimeError):
    """Raised when a pending action cannot produce one exact report."""


def build_observer_action_report(
    *,
    campaign_id: str,
    pending_action: dict[str, Any],
    evidence: observer_action_evidence.ActionDiagnosticEvidence,
) -> dict[str, Any]:
    """Combines one terminal driver action with its exact diagnostic evidence."""

    _require_nonempty_string(campaign_id, "campaign_id")
    _validate_pending_action(pending_action)
    if not isinstance(evidence, observer_action_evidence.ActionDiagnosticEvidence):
        raise ObserverActionReportError(
            "evidence must be an ActionDiagnosticEvidence instance"
        )
    _validate_evidence_authority(pending_action, evidence)

    pair = _action_pair(pending_action)
    rust_diagnostics = list(evidence.rust.window_records)
    mfc_diagnostics = list(evidence.mfc.window_records)
    assessment = soak_action_diff.diff_action(
        pair,
        rust_packets=diag_event_diff.ed2k_tcp_packet_views(rust_diagnostics),
        mfc_packets=diag_event_diff.ed2k_tcp_packet_views(mfc_diagnostics),
        rust_diag=rust_diagnostics,
        mfc_diag=mfc_diagnostics,
        search_result_counts=copy.deepcopy(
            pending_action["driverOutcome"]["resultCounts"]
        ),
        action_window=evidence.window,
    )
    driver_complete = pending_action["driverOutcome"]["ok"] is True
    verdict = (
        assessment["verdict"]
        if evidence.complete and driver_complete
        else "evidence-incomplete"
    )
    report = {
        "schema": SCHEMA,
        "campaignId": campaign_id,
        "seq": pending_action["reportSeq"],
        "actionId": pending_action["actionId"],
        "cycle": pending_action["cycle"],
        "kind": assessment["kind"],
        "method": assessment["method"],
        "key": assessment["key"],
        "label": assessment["label"],
        "window": copy.deepcopy(assessment["window"]),
        "observed": copy.deepcopy(assessment["observed"]),
        "verdict": verdict,
        "coverageOk": assessment["coverageOk"],
        "fullCoverageOk": assessment["fullCoverageOk"],
        "byteMatch": assessment["byteMatch"],
        "diagOk": assessment["diagOk"],
        "diagStrictOk": assessment["diagStrictOk"],
        "driverOutcome": copy.deepcopy(pending_action["driverOutcome"]),
        "diagnosticEvidence": evidence.report_payload(),
        "assessment": copy.deepcopy(assessment),
    }
    return validate_observer_action_report_for_pending(report, pending_action)


def validate_observer_action_report(report: object) -> dict[str, Any]:
    """Returns a detached validated report using the single current contract."""

    if not isinstance(report, dict) or set(report) != _REPORT_FIELDS:
        raise ObserverActionReportError("Observer action report fields are invalid.")
    if report.get("schema") != SCHEMA:
        raise ObserverActionReportError("Observer action report schema is invalid.")
    _require_nonempty_string(report.get("campaignId"), "campaignId")
    _require_positive_integer(report.get("seq"), "seq")
    _require_nonempty_string(report.get("actionId"), "actionId")
    _require_positive_integer(report.get("cycle"), "cycle")
    if report.get("kind") != soak_action_diff.SEARCH:
        raise ObserverActionReportError("Observer action report kind is invalid.")
    if report.get("method") not in {
        soak_action_diff.SEARCH_METHOD_SERVER,
        soak_action_diff.SEARCH_METHOD_GLOBAL,
        soak_action_diff.SEARCH_METHOD_KAD,
    }:
        raise ObserverActionReportError("Observer action report method is invalid.")
    _require_nonempty_string(report.get("key"), "key")
    _require_nonempty_string(report.get("label"), "label")
    if report.get("verdict") not in _VERDICTS:
        raise ObserverActionReportError("Observer action report verdict is invalid.")
    for field in (
        "coverageOk",
        "fullCoverageOk",
        "byteMatch",
        "diagOk",
        "diagStrictOk",
    ):
        if not isinstance(report.get(field), bool):
            raise ObserverActionReportError(
                f"Observer action report {field} must be boolean."
            )

    window = _validate_window(report.get("window"), "window")
    observed = report.get("observed")
    if not isinstance(observed, dict) or set(observed) != set(_CLIENTS):
        raise ObserverActionReportError("Observer action report observations are invalid.")
    for client in _CLIENTS:
        observed_at = _parse_utc(observed[client], f"observed.{client}")
        if observed_at < window[0] or observed_at > window[1]:
            raise ObserverActionReportError(
                f"Observer action report {client} observation is outside the window."
            )

    driver = report.get("driverOutcome")
    if not isinstance(driver, dict):
        raise ObserverActionReportError("Observer action driver outcome is invalid.")
    if not isinstance(driver.get("ok"), bool):
        raise ObserverActionReportError(
            "Observer action driver outcome ok flag is invalid."
        )
    if (
        driver.get("actionId") != report["actionId"]
        or driver.get("cycle") != report["cycle"]
        or driver.get("method") != report["method"]
        or driver.get("query") != report["label"]
    ):
        raise ObserverActionReportError("Observer action driver identity is inconsistent.")
    if report["key"] != report["label"].strip().lower():
        raise ObserverActionReportError("Observer action correlation key is inconsistent.")

    diagnostic_evidence = _validate_diagnostic_evidence_payload(
        report.get("diagnosticEvidence")
    )
    evidence_status = diagnostic_evidence["status"]
    evidence_window = diagnostic_evidence["window"]
    if (
        _parse_utc(evidence_window["startUtc"], "diagnosticEvidence.window.startUtc")
        != window[0]
        or _parse_utc(evidence_window["endUtc"], "diagnosticEvidence.window.endUtc")
        != window[1]
    ):
        raise ObserverActionReportError(
            "Observer diagnostic evidence window is inconsistent."
        )

    assessment = report.get("assessment")
    if not isinstance(assessment, dict) or set(assessment) != _ASSESSMENT_FIELDS:
        raise ObserverActionReportError("Observer action assessment is invalid.")
    for field in (
        "kind",
        "method",
        "key",
        "label",
        "window",
        "observed",
        "coverageOk",
        "fullCoverageOk",
        "byteMatch",
        "diagOk",
        "diagStrictOk",
    ):
        if assessment.get(field) != report[field]:
            raise ObserverActionReportError(
                f"Observer action assessment {field} is inconsistent."
            )
    if assessment.get("verdict") not in _VERDICTS:
        raise ObserverActionReportError("Observer action assessment verdict is invalid.")
    expected_verdict = (
        "evidence-incomplete"
        if evidence_status == "incomplete" or not driver["ok"]
        else assessment["verdict"]
    )
    if report["verdict"] != expected_verdict:
        raise ObserverActionReportError("Observer action report verdict is inconsistent.")

    try:
        json.dumps(report, allow_nan=False, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as error:
        raise ObserverActionReportError(
            "Observer action report is not deterministic JSON."
        ) from error
    return copy.deepcopy(report)


def validate_observer_action_report_for_pending(
    report: object,
    pending_action: dict[str, Any],
) -> dict[str, Any]:
    """Validates one persisted report against its exact pending action."""

    _validate_pending_action(pending_action)
    validated = validate_observer_action_report(report)
    if (
        validated["actionId"] != pending_action["actionId"]
        or validated["seq"] != pending_action["reportSeq"]
        or validated["cycle"] != pending_action["cycle"]
        or validated["method"] != pending_action["method"]
        or validated["label"] != pending_action["query"]
        or validated["key"] != pending_action["query"].strip().lower()
        or validated["driverOutcome"] != pending_action["driverOutcome"]
    ):
        raise ObserverActionReportError(
            "Observer action report does not match the pending action."
        )
    expected_window = {
        "t0": _parse_utc(
            pending_action["reservedAtUtc"], "pending_action.reservedAtUtc"
        ).isoformat(),
        "t1": _parse_utc(
            pending_action["evidence"]["windowEndUtc"],
            "pending_action.evidence.windowEndUtc",
        ).isoformat(),
    }
    if validated["window"] != expected_window:
        raise ObserverActionReportError(
            "Observer action report window does not match the pending action."
        )
    expected_observed = {
        client: _client_observed_at(pending_action, client).isoformat()
        for client in _CLIENTS
    }
    if validated["observed"] != expected_observed:
        raise ObserverActionReportError(
            "Observer action report observations do not match the pending action."
        )
    clients = validated["diagnosticEvidence"]["clients"]
    for client in _CLIENTS:
        if clients[client]["identity"] != pending_action["diagnosticRuns"][client]:
            raise ObserverActionReportError(
                f"Observer action report {client} diagnostic identity does not match "
                "the pending action."
            )
    return validated


def _action_pair(pending_action: dict[str, Any]) -> soak_action_diff.ActionPair:
    query = pending_action["query"]
    method = pending_action["method"]
    correlation_key = query.strip().lower()
    actions = {
        client: soak_action_diff.Action(
            client=client,
            kind=soak_action_diff.SEARCH,
            action_id=_client_action_id(pending_action, client),
            key=correlation_key,
            label=query,
            observed_at=_client_observed_at(pending_action, client),
            method=method,
        )
        for client in _CLIENTS
    }
    return soak_action_diff.ActionPair(
        kind=soak_action_diff.SEARCH,
        key=correlation_key,
        rust=actions["rust"],
        mfc=actions["mfc"],
    )


def _client_action_id(pending_action: dict[str, Any], client: str) -> str:
    create = pending_action["clients"][client]["create"]
    search_id = create.get("searchId")
    if create.get("status") == "succeeded" and search_id is not None:
        return str(search_id)
    return f"{pending_action['actionId']}:{client}"


def _client_observed_at(
    pending_action: dict[str, Any], client: str
) -> datetime:
    client_state = pending_action["clients"][client]
    results = client_state["results"]
    source = results if isinstance(results, dict) else client_state["create"]
    return _parse_utc(source.get("completedAtUtc"), f"clients.{client}.completedAtUtc")


def _validate_pending_action(pending: object) -> None:
    if not isinstance(pending, dict):
        raise ObserverActionReportError("pending_action must be a dictionary")
    for field in (
        "actionId",
        "reportSeq",
        "cycle",
        "query",
        "method",
        "reservedAtUtc",
        "diagnosticRuns",
        "clients",
        "driverOutcome",
        "evidence",
    ):
        if field not in pending:
            raise ObserverActionReportError(f"pending_action.{field} is required")
    _require_nonempty_string(pending["actionId"], "pending_action.actionId")
    _require_positive_integer(pending["reportSeq"], "pending_action.reportSeq")
    _require_positive_integer(pending["cycle"], "pending_action.cycle")
    _require_nonempty_string(pending["query"], "pending_action.query")
    if pending["method"] not in {
        soak_action_diff.SEARCH_METHOD_SERVER,
        soak_action_diff.SEARCH_METHOD_GLOBAL,
        soak_action_diff.SEARCH_METHOD_KAD,
    }:
        raise ObserverActionReportError("pending_action.method is invalid")
    _parse_utc(pending["reservedAtUtc"], "pending_action.reservedAtUtc")

    diagnostic_runs = pending["diagnosticRuns"]
    if not isinstance(diagnostic_runs, dict) or set(diagnostic_runs) != set(_CLIENTS):
        raise ObserverActionReportError("pending_action diagnostic runs are invalid")
    clients = pending["clients"]
    if not isinstance(clients, dict) or set(clients) != set(_CLIENTS):
        raise ObserverActionReportError("pending_action clients are invalid")
    for client in _CLIENTS:
        identity = diagnostic_runs[client]
        if not isinstance(identity, dict) or set(identity) != {"processId", "runId"}:
            raise ObserverActionReportError(
                f"pending_action {client} diagnostic identity is invalid"
            )
        _require_positive_integer(
            identity["processId"], f"pending_action.diagnosticRuns.{client}.processId"
        )
        _require_nonempty_string(
            identity["runId"], f"pending_action.diagnosticRuns.{client}.runId"
        )
        _validate_pending_client(clients[client], client)

    driver = pending["driverOutcome"]
    if not isinstance(driver, dict):
        raise ObserverActionReportError("pending_action driver outcome is missing")
    if not isinstance(driver.get("ok"), bool):
        raise ObserverActionReportError(
            "pending_action driver outcome ok flag is invalid"
        )
    if (
        driver.get("actionId") != pending["actionId"]
        or driver.get("cycle") != pending["cycle"]
        or driver.get("method") != pending["method"]
        or driver.get("query") != pending["query"]
    ):
        raise ObserverActionReportError("pending_action driver outcome is inconsistent")
    _parse_utc(driver.get("completedAtUtc"), "driverOutcome.completedAtUtc")

    pending_evidence = pending["evidence"]
    if (
        not isinstance(pending_evidence, dict)
        or set(pending_evidence) != {"status", "windowEndUtc"}
        or pending_evidence.get("status") != "pending"
    ):
        raise ObserverActionReportError("pending_action evidence marker is invalid")
    window_end = _parse_utc(
        pending_evidence["windowEndUtc"], "pending_action.evidence.windowEndUtc"
    )
    if window_end != _parse_utc(
        driver["completedAtUtc"], "driverOutcome.completedAtUtc"
    ):
        raise ObserverActionReportError(
            "pending_action evidence window does not match driver completion"
        )


def _validate_pending_client(value: object, client: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "create",
        "resultPoll",
        "results",
    }:
        raise ObserverActionReportError(f"pending_action {client} client state is invalid")
    if value["resultPoll"] is not None:
        raise ObserverActionReportError(
            f"pending_action {client} result poll is not terminal"
        )
    create = value["create"]
    if not isinstance(create, dict):
        raise ObserverActionReportError(f"pending_action {client} create is not terminal")
    status = create.get("status")
    if status == "succeeded":
        _require_nonempty_string(
            create.get("searchId"),
            f"pending_action.clients.{client}.create.searchId",
        )
        if not isinstance(value["results"], dict):
            raise ObserverActionReportError(
                f"pending_action {client} results are not terminal"
            )
    elif status in {"failed", "skipped"}:
        if value["results"] is not None:
            raise ObserverActionReportError(
                f"pending_action {client} failed create has results"
            )
    else:
        raise ObserverActionReportError(f"pending_action {client} create is not terminal")
    _client_observed_at({"clients": {client: value}}, client)


def _validate_evidence_authority(
    pending_action: dict[str, Any],
    evidence: observer_action_evidence.ActionDiagnosticEvidence,
) -> None:
    expected_start = _parse_utc(
        pending_action["reservedAtUtc"], "pending_action.reservedAtUtc"
    )
    expected_end = _parse_utc(
        pending_action["evidence"]["windowEndUtc"],
        "pending_action.evidence.windowEndUtc",
    )
    if evidence.window.start_utc != expected_start or evidence.window.end_utc != expected_end:
        raise ObserverActionReportError(
            "Diagnostic evidence window does not match the pending action."
        )
    for client in _CLIENTS:
        client_evidence = getattr(evidence, client)
        expected_identity = pending_action["diagnosticRuns"][client]
        if (
            client_evidence.source.client != client
            or client_evidence.source.process_id != expected_identity["processId"]
            or client_evidence.source.run_id != expected_identity["runId"]
        ):
            raise ObserverActionReportError(
                f"Diagnostic evidence {client} identity does not match the pending action."
            )
        if (
            client_evidence.snapshot.client != client
            or client_evidence.snapshot.process_id != client_evidence.source.process_id
            or client_evidence.snapshot.run_id != client_evidence.source.run_id
        ):
            raise ObserverActionReportError(
                f"Diagnostic evidence {client} snapshot identity is inconsistent."
            )


def _validate_window(value: object, label: str) -> tuple[datetime, datetime]:
    if not isinstance(value, dict) or set(value) != {"t0", "t1"}:
        raise ObserverActionReportError(f"Observer action report {label} is invalid.")
    start = _parse_utc(value["t0"], f"{label}.t0")
    end = _parse_utc(value["t1"], f"{label}.t1")
    if end < start:
        raise ObserverActionReportError(
            f"Observer action report {label} end precedes its start."
        )
    return start, end


def _validate_diagnostic_evidence_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "window",
        "clients",
    }:
        raise ObserverActionReportError("Observer diagnostic evidence is invalid.")
    if value["schema"] != observer_action_evidence.ACTION_DIAGNOSTIC_EVIDENCE_SCHEMA:
        raise ObserverActionReportError("Observer diagnostic evidence schema is invalid.")
    if value["status"] not in {"complete", "incomplete"}:
        raise ObserverActionReportError("Observer diagnostic evidence status is invalid.")
    window = value["window"]
    if not isinstance(window, dict) or set(window) != {"startUtc", "endUtc"}:
        raise ObserverActionReportError("Observer diagnostic evidence window is invalid.")
    start = _parse_utc(window["startUtc"], "diagnosticEvidence.window.startUtc")
    end = _parse_utc(window["endUtc"], "diagnosticEvidence.window.endUtc")
    if end < start:
        raise ObserverActionReportError(
            "Observer diagnostic evidence window end precedes its start."
        )
    clients = value["clients"]
    if not isinstance(clients, dict) or set(clients) != set(_CLIENTS):
        raise ObserverActionReportError("Observer diagnostic evidence clients are invalid.")
    client_statuses = {
        client: _validate_client_evidence_payload(clients[client], client)
        for client in _CLIENTS
    }
    expected_status = (
        "complete"
        if all(status == "complete" for status in client_statuses.values())
        else "incomplete"
    )
    if value["status"] != expected_status:
        raise ObserverActionReportError(
            "Observer diagnostic evidence aggregate status is inconsistent."
        )
    return value


def _validate_client_evidence_payload(value: object, client: str) -> str:
    fields = {
        "status",
        "findings",
        "directory",
        "identity",
        "recordCount",
        "windowRecordCount",
        "segments",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} payload is invalid."
        )
    if value["status"] not in {"complete", "incomplete"}:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} status is invalid."
        )
    _require_nonempty_string(value["directory"], f"diagnosticEvidence.{client}.directory")
    identity = value["identity"]
    if not isinstance(identity, dict) or set(identity) != {"processId", "runId"}:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} identity is invalid."
        )
    _require_positive_integer(
        identity["processId"], f"diagnosticEvidence.{client}.identity.processId"
    )
    _require_nonempty_string(
        identity["runId"], f"diagnosticEvidence.{client}.identity.runId"
    )
    record_count = _require_nonnegative_integer(
        value["recordCount"], f"diagnosticEvidence.{client}.recordCount"
    )
    window_record_count = _require_nonnegative_integer(
        value["windowRecordCount"],
        f"diagnosticEvidence.{client}.windowRecordCount",
    )
    if window_record_count > record_count:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} window count is invalid."
        )
    findings = value["findings"]
    if not isinstance(findings, list) or any(
        not isinstance(finding, str) or not finding for finding in findings
    ):
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} findings are invalid."
        )
    segments = value["segments"]
    if not isinstance(segments, list) or not segments:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} segments are invalid."
        )
    expected_findings = []
    segment_records = 0
    segment_window_records = 0
    for segment in segments:
        finding, segment_record_count, segment_window_count = (
            _validate_evidence_segment(segment, client)
        )
        if finding is not None:
            expected_findings.append(finding)
        segment_records += segment_record_count
        segment_window_records += segment_window_count
    if segment_records != record_count or segment_window_records != window_record_count:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} segment counts are inconsistent."
        )
    if findings != expected_findings:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} findings are inconsistent."
        )
    expected_status = "complete" if not expected_findings else "incomplete"
    if value["status"] != expected_status:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} status is inconsistent."
        )
    return expected_status


def _validate_evidence_segment(
    value: object, client: str
) -> tuple[str | None, int, int]:
    fields = {
        "segmentId",
        "path",
        "byteCount",
        "modifiedNs",
        "sha256",
        "recordCount",
        "windowRecordCount",
        "tailTerminated",
        "incompleteTailIgnored",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} segment is invalid."
        )
    segment_id = _require_nonnegative_integer(
        value["segmentId"], f"diagnosticEvidence.{client}.segmentId"
    )
    _require_nonempty_string(value["path"], f"diagnosticEvidence.{client}.path")
    _require_nonnegative_integer(
        value["byteCount"], f"diagnosticEvidence.{client}.byteCount"
    )
    _require_nonnegative_integer(
        value["modifiedNs"], f"diagnosticEvidence.{client}.modifiedNs"
    )
    _validate_sha256(value["sha256"], f"diagnosticEvidence.{client}.sha256")
    record_count = _require_nonnegative_integer(
        value["recordCount"], f"diagnosticEvidence.{client}.recordCount"
    )
    window_record_count = _require_nonnegative_integer(
        value["windowRecordCount"],
        f"diagnosticEvidence.{client}.windowRecordCount",
    )
    if window_record_count > record_count:
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} segment window count is invalid."
        )
    tail_terminated = value["tailTerminated"]
    incomplete_tail_ignored = value["incompleteTailIgnored"]
    if not isinstance(tail_terminated, bool) or not isinstance(
        incomplete_tail_ignored, bool
    ):
        raise ObserverActionReportError(
            f"Observer diagnostic evidence {client} tail provenance is invalid."
        )
    finding = None
    if incomplete_tail_ignored:
        finding = f"segment-{segment_id:06d}:incomplete-tail-ignored"
    elif not tail_terminated:
        finding = f"segment-{segment_id:06d}:unterminated-tail"
    return finding, record_count, window_record_count


def _parse_utc(value: object, label: str) -> datetime:
    try:
        return soak_action_diff.parse_utc_timestamp(value, label=label)
    except soak_action_diff.ActionTraceError as error:
        raise ObserverActionReportError(str(error)) from error


def _require_nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ObserverActionReportError(f"{label} must be a non-empty string")
    return value


def _require_positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ObserverActionReportError(f"{label} must be a positive integer")
    return value


def _require_nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ObserverActionReportError(f"{label} must be a nonnegative integer")
    return value


def _validate_sha256(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ObserverActionReportError(f"{label} must be a lowercase SHA-256 digest")
