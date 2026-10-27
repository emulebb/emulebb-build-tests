from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import converged_observer_state as observer_state
from emule_test_harness import soak_report_summary, soak_storage

pytestmark = pytest.mark.unit

CAMPAIGN_ID = "20261026T120000Z"
CONFIGURATION_DIGEST = "a" * 64


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _poll(seq: int, *, termination: str = "completed") -> dict[str, object]:
    return {
        "startedAtUtc": f"2026-10-26T12:0{seq}:01+00:00",
        "deadlineUtc": f"2026-10-26T12:0{seq}:31+00:00",
        "attempts": seq,
        "errorCount": seq - 1,
        "latestAttemptAtUtc": f"2026-10-26T12:0{seq}:03+00:00",
        "latestError": None
        if seq == 1
        else {
            "client": "rust",
            "phase": "search-results",
            "type": "RuntimeError",
            "message": f"exact retained error {seq}",
        },
        "termination": termination,
    }


def _action_report(seq: int, *, verdict: str) -> dict[str, object]:
    rust_poll = _poll(seq)
    mfc_poll = _poll(seq, termination="deadline" if seq == 2 else "completed")
    action_id = f"{CAMPAIGN_ID}-cycle-{seq:08d}"
    assessment = {
        "packets": {"rust": seq * 2, "mfc": seq * 3},
        "actionCoverage": {
            "ok": verdict == "coverage-parity",
            "mode": "action-required-opcodes",
            "required": [],
            "optional": [],
        },
        "packetDiff": {"opcodeCoverage": {"channels": []}},
    }
    return {
        "schema": "emulebb-build-tests.observer-action-report.v1",
        "campaignId": CAMPAIGN_ID,
        "seq": seq,
        "actionId": action_id,
        "cycle": seq,
        "kind": "search",
        "method": "kad",
        "key": f"private live term {seq}",
        "label": f"Private Live Term {seq}",
        "window": {
            "t0": f"2026-10-26T12:0{seq}:00+00:00",
            "t1": f"2026-10-26T12:0{seq}:10+00:00",
        },
        "observed": {},
        "verdict": verdict,
        "coverageOk": verdict == "coverage-parity",
        "fullCoverageOk": verdict == "coverage-parity",
        "byteMatch": verdict == "coverage-parity",
        "diagOk": True,
        "diagStrictOk": True,
        "driverOutcome": {
            "cycle": seq,
            "actionId": action_id,
            "ok": True,
            "searches": {
                "rust": {"results": {"ok": True, "poll": rust_poll}},
                "mfc": {"results": {"ok": True, "poll": mfc_poll}},
            },
            "errors": [],
        },
        "diagnosticEvidence": {},
        "assessment": assessment,
    }


def _checkpoint(seq: int, *, actions: int) -> dict[str, object]:
    return {
        "schema": "soak_checkpoint_v1",
        "campaignId": CAMPAIGN_ID,
        "ts_utc": f"2026-10-26T12:{seq:02d}:00+00:00",
        "rustAlive": True,
        "packetRecords": {"rust": seq * 10, "mfc": seq * 20},
        "diagnosticWriters": {
            "rust": {"recordsWritten": seq * 10, "lastError": None},
            "mfc": {"recordsWritten": seq * 20, "lastError": None},
        },
        "totals": {"actions": actions},
    }


def _persistence(
    path: Path,
    *,
    retained_count: int,
    retained_bytes: int,
) -> soak_storage.PersistedArtifact:
    return soak_storage.PersistedArtifact(
        path=path,
        byte_count=path.stat().st_size,
        sha256="0" * 64,
        deleted_paths=(),
        retained_count=retained_count,
        retained_bytes=retained_bytes,
    )


def _build_current_report_dir(
    tmp_path: Path,
    *,
    action_count: int = 3,
    retained_actions: int = 1,
    written_actions: int | None = None,
    checkpoint_count: int = 2,
    retained_checkpoints: int = 1,
) -> tuple[Path, dict[str, object]]:
    report_dir = tmp_path / "report"
    actions = [
        _action_report(
            seq,
            verdict="coverage-parity" if seq == 1 else "divergence",
        )
        for seq in range(1, action_count + 1)
    ]
    checkpoints = [
        _checkpoint(seq, actions=action_count)
        for seq in range(1, checkpoint_count + 1)
    ]

    state = observer_state.new_state(
        CAMPAIGN_ID,
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=2,
    )
    for action in actions:
        state = observer_state.record_driver_cycle(state, action["driverOutcome"])
        state = observer_state.record_action(state, action)
    for checkpoint in checkpoints:
        state = observer_state.record_checkpoint(state, checkpoint)

    action_write_count = retained_actions if written_actions is None else written_actions
    action_paths: list[Path] = []
    for action in actions[-action_write_count:]:
        path = report_dir / "actions" / f"{int(action['seq']):08d}-search.json"
        _write_json(path, action)
        action_paths.append(path)
    checkpoint_paths: list[Path] = []
    for checkpoint in checkpoints[-retained_checkpoints:]:
        path = (
            report_dir
            / "checkpoints"
            / f"{str(checkpoint['ts_utc']).replace(':', '').replace('-', '')}.json"
        )
        _write_json(path, checkpoint)
        checkpoint_paths.append(path)

    state = observer_state.record_stream_retention(
        state,
        stream="actions",
        persisted=_persistence(
            action_paths[-1],
            retained_count=retained_actions,
            retained_bytes=sum(path.stat().st_size for path in action_paths),
        ),
    )
    state = observer_state.record_stream_retention(
        state,
        stream="checkpoints",
        persisted=_persistence(
            checkpoint_paths[-1],
            retained_count=retained_checkpoints,
            retained_bytes=sum(path.stat().st_size for path in checkpoint_paths),
        ),
    )
    _write_json(report_dir / "summary.json", state)
    return report_dir, state


def _accept_synthetic_action_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        soak_report_summary.observer_action_report,
        "validate_observer_action_report",
        lambda report: report,
    )


def test_summarize_report_combines_exact_state_and_rotated_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _accept_synthetic_action_reports(monkeypatch)
    report_dir, state = _build_current_report_dir(tmp_path)
    log_path = tmp_path / "runner.log"
    log_path.write_text(
        "\n".join(
            [
                "[soak] checkpoint: packets rust=20 mfc=40 actions=3",
                "[soak] final summary: summary.json",
            ]
        ),
        encoding="utf-8",
    )

    report = soak_report_summary.summarize_report(report_dir, log_path=log_path)

    assert report["schema"] == "emulebb-build-tests.converged-soak-report.v2"
    assert report["finished"] is True
    assert report["observerState"] == state
    assert report["observerState"]["totals"]["actions"] == 3
    assert report["observerState"]["histograms"]["verdict"] == {
        "coverage-parity": 1,
        "divergence": 2,
        "evidence-incomplete": 0,
        "no-traffic": 0,
        "not-assessable": 0,
        "one-sided": 0,
        "other": 0,
        "unpaired": 0,
    }
    assert report["observerState"]["recentActions"][-1]["label"] == (
        "Private Live Term 3"
    )

    actions = report["retainedWindow"]["actions"]
    assert actions["seen"] == 3
    assert actions["retained"] == 1
    assert actions["omittedByRetention"] == 2
    assert actions["unexpectedMissing"] == 0
    assert actions["firstRetainedSeq"] == 3
    assert actions["lastRetainedSeq"] == 3
    assert actions["summary"]["actions"] == 1
    assert actions["summary"]["verdictCounts"] == {"divergence": 1}
    assert actions["summary"]["resultPolls"]["rust"] == {
        "polls": 1,
        "attempts": 3,
        "errors": 2,
        "terminationCounts": {"completed": 1},
    }
    assert actions["pollProvenance"][0]["clients"]["rust"]["latestError"] == {
        "client": "rust",
        "phase": "search-results",
        "type": "RuntimeError",
        "message": "exact retained error 3",
    }

    checkpoints = report["retainedWindow"]["checkpoints"]
    assert checkpoints["seen"] == 2
    assert checkpoints["retained"] == 1
    assert checkpoints["omittedByRetention"] == 1
    assert checkpoints["unexpectedMissing"] == 0
    assert checkpoints["summary"]["lastPacketRecords"] == {
        "rust": 20,
        "mfc": 40,
    }
    assert checkpoints["summary"]["lastDiagnosticWriters"]["rust"] == {
        "recordsWritten": 20,
        "lastError": None,
    }
    assert checkpoints["summary"]["lastLogCounters"] == {
        "rustPackets": 20,
        "mfcPackets": 40,
        "actions": 3,
    }
    assert "Private Live Term 3" in json.dumps(report, sort_keys=True)


def test_summarize_report_marks_complete_unrotated_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _accept_synthetic_action_reports(monkeypatch)
    report_dir, _state = _build_current_report_dir(
        tmp_path,
        action_count=1,
        retained_actions=1,
        checkpoint_count=1,
        retained_checkpoints=1,
    )

    report = soak_report_summary.summarize_report(report_dir)

    actions = report["retainedWindow"]["actions"]
    checkpoints = report["retainedWindow"]["checkpoints"]
    assert actions["seen"] == actions["retained"] == 1
    assert actions["omittedByRetention"] == 0
    assert checkpoints["seen"] == checkpoints["retained"] == 1
    assert checkpoints["omittedByRetention"] == 0


@pytest.mark.parametrize("corruption", ["missing", "bytes", "latest"])
def test_summarize_report_fails_closed_on_retained_window_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    _accept_synthetic_action_reports(monkeypatch)
    monkeypatch.setattr(soak_report_summary, "CONSISTENCY_ATTEMPTS", 1)
    report_dir, state = _build_current_report_dir(
        tmp_path,
        retained_actions=2 if corruption == "missing" else 1,
        written_actions=1,
    )
    if corruption == "bytes":
        state["retention"]["actions"]["retainedBytes"] += 1
        _write_json(report_dir / "summary.json", state)
    elif corruption == "latest":
        state["retention"]["actions"]["latestFile"] = "wrong.json"
        _write_json(report_dir / "summary.json", state)

    with pytest.raises(
        soak_report_summary.SoakReportSummaryError,
        match="consistent observer state and retained window",
    ):
        soak_report_summary.summarize_report(report_dir)


def test_summarize_report_retries_when_state_changes_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _accept_synthetic_action_reports(monkeypatch)
    report_dir, current = _build_current_report_dir(
        tmp_path,
        action_count=1,
        retained_actions=1,
        checkpoint_count=1,
        retained_checkpoints=1,
    )
    stale = observer_state.new_state(
        CAMPAIGN_ID,
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=2,
    )
    original_read_json = soak_report_summary.read_json
    summary_reads = iter([stale, current, current, current])
    sleeps: list[float] = []

    def changing_read(path: Path) -> dict[str, object]:
        if path.name == "summary.json":
            return next(summary_reads)
        return original_read_json(path)

    monkeypatch.setattr(soak_report_summary, "read_json", changing_read)
    monkeypatch.setattr(soak_report_summary.time, "sleep", sleeps.append)

    report = soak_report_summary.summarize_report(report_dir)

    assert report["observerState"] == current
    assert sleeps == [0.1]


def test_load_action_reports_rejects_noncurrent_contract(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    _write_json(report_dir / "actions" / "00000001-search.json", {"seq": 1})

    with pytest.raises(
        soak_report_summary.observer_action_report.ObserverActionReportError,
        match="fields are invalid",
    ):
        soak_report_summary.load_action_reports(report_dir)


def test_parse_checkpoint_lines_tolerates_missing_log(tmp_path: Path) -> None:
    assert soak_report_summary.parse_checkpoint_lines(tmp_path / "missing.log") == []
    assert soak_report_summary.log_finished(tmp_path / "missing.log") is False


def test_summarize_full_run_diagnostics_exposes_missing_family_and_lifecycle_counts() -> None:
    summary = soak_report_summary.summarize_full_run_diagnostics(
        {
            "ok": False,
            "familyConformance": {
                "requiredFamiliesOk": False,
                "requiredFamilies": [
                    {
                        "family": "ed2k_client_udp",
                        "rustPresent": True,
                        "mfcPresent": False,
                        "ok": False,
                    }
                ],
            },
            "clientUdpLifecycle": {
                "rust": {
                    "ok": False,
                    "attemptCount": 3,
                    "terminalCount": 2,
                    "outcomes": {"send_succeeded": 2},
                    "violations": [
                        {"kind": "missing_terminal", "sendAttemptId": 7},
                        {"kind": "missing_terminal", "sendAttemptId": 9},
                    ],
                },
                "mfc": {
                    "ok": False,
                    "attemptCount": 1,
                    "terminalCount": 2,
                    "outcomes": {"send_cancelled": 2},
                    "violations": [
                        {"kind": "orphan_terminal", "sendAttemptId": 2}
                    ],
                },
            },
            "serverConnectionLifecycle": {
                "rust": {
                    "ok": True,
                    "attemptCount": 1,
                    "eventCount": 3,
                    "outcomes": {
                        "attempt_started": 1,
                        "transport_connected": 1,
                        "login_accepted": 1,
                    },
                    "violations": [],
                },
                "mfc": {
                    "ok": False,
                    "attemptCount": 2,
                    "eventCount": 3,
                    "outcomes": {
                        "attempt_started": 2,
                        "connection_failed": 1,
                    },
                    "violations": [
                        {"kind": "missing_attempt_start", "traceId": 4}
                    ],
                },
            },
        }
    )

    assert summary == {
        "ok": False,
        "requiredFamiliesOk": False,
        "missingRequiredFamilies": [
            {"family": "ed2k_client_udp", "rustPresent": True, "mfcPresent": False}
        ],
        "clientUdpLifecycle": {
            "rust": {
                "ok": False,
                "attempts": 3,
                "terminals": 2,
                "outcomes": {"send_succeeded": 2},
                "violationCounts": {"missing_terminal": 2},
            },
            "mfc": {
                "ok": False,
                "attempts": 1,
                "terminals": 2,
                "outcomes": {"send_cancelled": 2},
                "violationCounts": {"orphan_terminal": 1},
            },
        },
        "serverConnectionLifecycle": {
            "rust": {
                "ok": True,
                "attempts": 1,
                "events": 3,
                "outcomes": {
                    "attempt_started": 1,
                    "transport_connected": 1,
                    "login_accepted": 1,
                },
                "violationCounts": {},
            },
            "mfc": {
                "ok": False,
                "attempts": 2,
                "events": 3,
                "outcomes": {
                    "attempt_started": 2,
                    "connection_failed": 1,
                },
                "violationCounts": {"missing_attempt_start": 1},
            },
        },
    }


def test_summarize_actions_counts_download_payload_gap_separately() -> None:
    summary = soak_report_summary.summarize_actions(
        [
            {
                "seq": 1,
                "kind": "download",
                "verdict": "divergence",
                "diagOk": True,
                "packets": {"rust": 10, "mfc": 12},
                "actionCoverage": {
                    "ok": True,
                    "mode": "action-required-opcodes",
                    "downloadStartOk": True,
                    "downloadPayloadOk": False,
                    "required": [],
                    "optional": [],
                },
            }
        ]
    )

    assert summary["actionVerdictCounts"] == {"coverage-parity": 1}
    assert summary["actionCoverageFailures"] == 0
    assert summary["downloadCoverage"] == {
        "startParity": 1,
        "payloadParity": 0,
        "payloadMissingAfterStartParity": 1,
    }


def test_summarize_actions_keeps_unpaired_separate_from_coverage_failure() -> None:
    summary = soak_report_summary.summarize_actions(
        [{"seq": 1, "kind": "search", "verdict": "unpaired"}]
    )

    assert summary["actionVerdictCounts"] == {"unpaired": 1}
    assert summary["actionCoverageFailures"] == 0
    assert summary["actionDivergenceSamples"][0]["verdict"] == "unpaired"
