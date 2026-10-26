from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from emule_test_harness import observer_action_evidence, observer_action_report
from emule_test_harness import soak_action_diff
from emule_test_harness.diag_event_runs import (
    DiagnosticRunSnapshot,
    DiagnosticSegmentSnapshot,
)

pytestmark = pytest.mark.unit


def _ts(seconds: float) -> datetime:
    return datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc) + timedelta(
        seconds=seconds
    )


def _utc(seconds: float) -> str:
    return _ts(seconds).isoformat()


def _kad_record(
    *,
    client: str,
    process_id: int,
    run_id: str,
    sequence: int,
    seconds: float,
    opcode: int,
    direction: str,
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "segmentId": 0,
        "seq": sequence,
        "streamSeq": sequence,
        "ts": _ts(seconds).isoformat().replace("+00:00", "Z"),
        "family": soak_action_diff.KAD_UDP_FAMILY,
        "event": "packet",
        "severity": "info",
        "keys": {"opcode": opcode},
        "body": {"direction": direction, "opcode": opcode},
    }


def _client_evidence(
    root: Path,
    *,
    client: str,
    process_id: int,
    run_id: str,
    records: list[dict[str, object]],
    tail_terminated: bool = True,
    incomplete_tail_ignored: bool = False,
) -> observer_action_evidence.ClientActionDiagnosticEvidence:
    directory = root / client
    directory.mkdir(parents=True)
    prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
    path = directory / f"{prefix}-diag-{process_id}-{run_id}-000000.jsonl"
    segment = DiagnosticSegmentSnapshot(
        path=path,
        byte_count=512,
        modified_ns=123,
        sha256=("a" if client == "rust" else "b") * 64,
        tail_terminated=tail_terminated,
        incomplete_tail_ignored=incomplete_tail_ignored,
        records=tuple(records),
    )
    snapshot = DiagnosticRunSnapshot(
        client=client,
        process_id=process_id,
        run_id=run_id,
        segments=(segment,),
        records=tuple(records),
    )
    return observer_action_evidence.ClientActionDiagnosticEvidence(
        source=observer_action_evidence.PinnedDiagnosticRun(
            client=client,
            directory=directory,
            process_id=process_id,
            run_id=run_id,
        ),
        snapshot=snapshot,
        window_records=tuple(records),
        segment_window_records=(tuple(records),),
    )


def _evidence(
    tmp_path: Path,
    *,
    rust_records: list[dict[str, object]] | None = None,
    mfc_records: list[dict[str, object]] | None = None,
    rust_tail_terminated: bool = True,
    rust_incomplete_tail_ignored: bool = False,
    start_seconds: float = 0,
    end_seconds: float = 10,
) -> observer_action_evidence.ActionDiagnosticEvidence:
    return observer_action_evidence.ActionDiagnosticEvidence(
        window=soak_action_diff.ActionWindow(
            start_utc=_ts(start_seconds), end_utc=_ts(end_seconds)
        ),
        rust=_client_evidence(
            tmp_path,
            client="rust",
            process_id=4101,
            run_id="rust-run",
            records=rust_records or [],
            tail_terminated=rust_tail_terminated,
            incomplete_tail_ignored=rust_incomplete_tail_ignored,
        ),
        mfc=_client_evidence(
            tmp_path,
            client="mfc",
            process_id=4201,
            run_id="mfc-run",
            records=mfc_records or [],
        ),
    )


def _successful_client(client: str, completed_seconds: float) -> dict[str, object]:
    poll = {
        "startedAtUtc": _utc(2),
        "deadlineUtc": _utc(12),
        "attempts": 1,
        "errorCount": 0,
        "latestAttemptAtUtc": _utc(completed_seconds),
        "latestError": None,
        "termination": "completed",
    }
    return {
        "create": {
            "status": "succeeded",
            "preparedAtUtc": _utc(1),
            "completedAtUtc": _utc(2),
            "searchId": f"{client}-search-1",
            "error": None,
        },
        "resultPoll": None,
        "results": {
            "completedAtUtc": _utc(completed_seconds),
            "completed": True,
            "resultCount": 2,
            "error": None,
            "poll": poll,
        },
    }


def _failed_client(client: str, completed_seconds: float) -> dict[str, object]:
    error = {
        "client": client,
        "phase": "search-create",
        "type": "SyntheticFailure",
        "message": f"{client} failed exactly",
    }
    return {
        "create": {
            "status": "failed",
            "preparedAtUtc": _utc(1),
            "completedAtUtc": _utc(completed_seconds),
            "searchId": None,
            "error": error,
        },
        "resultPoll": None,
        "results": None,
    }


def _pending_action(
    *,
    rust_succeeded: bool = True,
    mfc_succeeded: bool = True,
) -> dict[str, object]:
    clients = {
        "rust": _successful_client("rust", 8)
        if rust_succeeded
        else _failed_client("rust", 3),
        "mfc": _successful_client("mfc", 9)
        if mfc_succeeded
        else _failed_client("mfc", 4),
    }
    searches = {}
    search_ids = {}
    result_counts = {}
    errors = []
    for client, client_state in clients.items():
        create = client_state["create"]
        results = client_state["results"]
        if create["status"] == "succeeded":
            searches[client] = {
                "create": {"ok": True, "searchId": create["searchId"]},
                "results": {
                    "ok": True,
                    "count": results["resultCount"],
                    "completed": True,
                    "poll": results["poll"],
                },
            }
            search_ids[client] = create["searchId"]
            result_counts[client] = results["resultCount"]
        else:
            searches[client] = {
                "create": {"ok": False, "error": create["error"]},
                "results": {"ok": False, "skipped": "search-create-failed"},
            }
            errors.append(create["error"])
    action_id = "20261026T120000Z-cycle-00000001"
    driver_outcome = {
        "cycle": 1,
        "actionId": action_id,
        "queryIndex": 0,
        "method": "kad",
        "query": "Ubuntu ISO",
        "downloadRequested": False,
        "ok": not errors,
        "searches": searches,
        "searchIds": search_ids,
        "resultCounts": result_counts,
        "errors": errors,
        "startedAtUtc": _utc(0),
        "completedAtUtc": _utc(10),
    }
    return {
        "actionId": action_id,
        "reportSeq": 1,
        "cycle": 1,
        "queryIndex": 0,
        "query": "Ubuntu ISO",
        "method": "kad",
        "reservedAtUtc": _utc(0),
        "diagnosticRuns": {
            "rust": {"processId": 4101, "runId": "rust-run"},
            "mfc": {"processId": 4201, "runId": "mfc-run"},
        },
        "clients": clients,
        "driverOutcome": driver_outcome,
        "evidence": {"status": "pending", "windowEndUtc": _utc(10)},
    }


def _kad_records(client: str, process_id: int, run_id: str) -> list[dict[str, object]]:
    return [
        _kad_record(
            client=client,
            process_id=process_id,
            run_id=run_id,
            sequence=1,
            seconds=5,
            opcode=soak_action_diff.KAD2_SEARCH_KEY_REQ,
            direction="send",
        ),
        _kad_record(
            client=client,
            process_id=process_id,
            run_id=run_id,
            sequence=2,
            seconds=6,
            opcode=soak_action_diff.KAD2_SEARCH_RES,
            direction="recv",
        ),
    ]


def test_build_report_combines_driver_evidence_and_method_assessment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pending = _pending_action()
    evidence = _evidence(
        tmp_path,
        rust_records=_kad_records("rust", 4101, "rust-run"),
        mfc_records=_kad_records("mfc", 4201, "mfc-run"),
    )

    seen_result_counts = None
    original_diff_action = soak_action_diff.diff_action

    def capture_result_counts(*args, **kwargs):
        nonlocal seen_result_counts
        seen_result_counts = kwargs.get("search_result_counts")
        return original_diff_action(*args, **kwargs)

    monkeypatch.setattr(soak_action_diff, "diff_action", capture_result_counts)
    report = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=pending,
        evidence=evidence,
    )

    assert report["schema"] == observer_action_report.SCHEMA
    assert report["actionId"] == pending["actionId"]
    assert report["kind"] == "search"
    assert report["method"] == "kad"
    assert report["key"] == "ubuntu iso"
    assert report["label"] == "Ubuntu ISO"
    assert report["verdict"] == "coverage-parity"
    assert report["coverageOk"] is True
    assert report["driverOutcome"] == pending["driverOutcome"]
    assert seen_result_counts == {"rust": 2, "mfc": 2}
    assert report["diagnosticEvidence"]["status"] == "complete"
    assert report["diagnosticEvidence"]["clients"]["rust"]["identity"] == {
        "processId": 4101,
        "runId": "rust-run",
    }
    assert report["assessment"]["assessmentRecords"] == {
        "requiredFamilies": ["kad_udp"],
        "rust": 2,
        "mfc": 2,
    }
    assert report["assessment"]["packets"] == {"rust": 0, "mfc": 0}


def test_incomplete_exact_tail_overrides_an_otherwise_parity_verdict(
    tmp_path: Path,
) -> None:
    report = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=_pending_action(),
        evidence=_evidence(
            tmp_path,
            rust_records=_kad_records("rust", 4101, "rust-run"),
            mfc_records=_kad_records("mfc", 4201, "mfc-run"),
            rust_tail_terminated=False,
            rust_incomplete_tail_ignored=True,
        ),
    )

    assert report["assessment"]["verdict"] == "coverage-parity"
    assert report["verdict"] == "evidence-incomplete"
    assert report["diagnosticEvidence"]["status"] == "incomplete"
    assert report["diagnosticEvidence"]["clients"]["rust"]["findings"] == [
        "segment-000000:incomplete-tail-ignored"
    ]


@pytest.mark.parametrize(
    ("rust_succeeded", "mfc_succeeded", "expected_assessment_verdict"),
    [
        (True, False, "evidence-incomplete"),
        (False, False, "no-traffic"),
    ],
)
def test_failed_driver_outcomes_still_produce_deterministic_reports(
    tmp_path: Path,
    rust_succeeded: bool,
    mfc_succeeded: bool,
    expected_assessment_verdict: str,
) -> None:
    pending = _pending_action(
        rust_succeeded=rust_succeeded,
        mfc_succeeded=mfc_succeeded,
    )
    rust_records = (
        _kad_records("rust", 4101, "rust-run") if rust_succeeded else []
    )
    evidence = _evidence(tmp_path, rust_records=rust_records, mfc_records=[])

    first = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=pending,
        evidence=evidence,
    )
    second = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=pending,
        evidence=evidence,
    )

    assert first == second
    assert first["verdict"] == "evidence-incomplete"
    assert first["assessment"]["verdict"] == expected_assessment_verdict
    assert first["driverOutcome"]["ok"] is False
    assert first["driverOutcome"]["errors"]


def test_failed_driver_outcome_does_not_promote_raw_divergence(
    tmp_path: Path,
) -> None:
    pending = _pending_action(rust_succeeded=True, mfc_succeeded=False)
    evidence = _evidence(
        tmp_path,
        rust_records=_kad_records("rust", 4101, "rust-run"),
        mfc_records=[
            _kad_record(
                client="mfc",
                process_id=4201,
                run_id="mfc-run",
                sequence=1,
                seconds=6,
                opcode=soak_action_diff.KAD2_SEARCH_RES,
                direction="recv",
            )
        ],
    )

    report = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=pending,
        evidence=evidence,
    )

    assert report["assessment"]["verdict"] == "divergence"
    assert report["verdict"] == "evidence-incomplete"
    assert report["driverOutcome"]["ok"] is False


def test_report_rejects_evidence_from_a_different_window(tmp_path: Path) -> None:
    with pytest.raises(
        observer_action_report.ObserverActionReportError,
        match="window does not match",
    ):
        observer_action_report.build_observer_action_report(
            campaign_id="20261026T120000Z",
            pending_action=_pending_action(),
            evidence=_evidence(tmp_path, start_seconds=-1),
        )


def test_report_rejects_evidence_from_a_different_writer(tmp_path: Path) -> None:
    pending = _pending_action()
    pending["diagnosticRuns"]["rust"]["runId"] = "other-run"

    with pytest.raises(
        observer_action_report.ObserverActionReportError,
        match="rust identity does not match",
    ):
        observer_action_report.build_observer_action_report(
            campaign_id="20261026T120000Z",
            pending_action=pending,
            evidence=_evidence(tmp_path),
        )


def test_validator_rejects_schema_and_assessment_drift(tmp_path: Path) -> None:
    report = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=_pending_action(),
        evidence=_evidence(
            tmp_path,
            rust_records=_kad_records("rust", 4101, "rust-run"),
            mfc_records=_kad_records("mfc", 4201, "mfc-run"),
        ),
    )
    wrong_schema = dict(report)
    wrong_schema["schema"] = "emulebb-build-tests.observer-action-report.v2"
    with pytest.raises(
        observer_action_report.ObserverActionReportError,
        match="schema is invalid",
    ):
        observer_action_report.validate_observer_action_report(wrong_schema)

    inconsistent = dict(report)
    inconsistent["assessment"] = dict(report["assessment"])
    inconsistent["assessment"]["method"] = "server"
    with pytest.raises(
        observer_action_report.ObserverActionReportError,
        match="assessment method is inconsistent",
    ):
        observer_action_report.validate_observer_action_report(inconsistent)


def test_pending_validator_rejects_a_valid_report_for_another_action(
    tmp_path: Path,
) -> None:
    original_pending = _pending_action()
    report = observer_action_report.build_observer_action_report(
        campaign_id="20261026T120000Z",
        pending_action=original_pending,
        evidence=_evidence(
            tmp_path,
            rust_records=_kad_records("rust", 4101, "rust-run"),
            mfc_records=_kad_records("mfc", 4201, "mfc-run"),
        ),
    )
    different_pending = _pending_action()
    different_pending["query"] = "Debian ISO"
    different_pending["driverOutcome"]["query"] = "Debian ISO"

    with pytest.raises(
        observer_action_report.ObserverActionReportError,
        match="does not match the pending action",
    ):
        observer_action_report.validate_observer_action_report_for_pending(
            report,
            different_pending,
        )
