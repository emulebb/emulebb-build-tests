from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import soak_report_summary

pytestmark = pytest.mark.unit


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_summarize_report_omits_live_action_labels_and_hashes(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    _write_json(
        report_dir / "summary.json",
        {
            "campaignId": "camp-1",
            "totals": {"actions": 1, "divergence": 1},
            "baseline": {"rustTransfers": 3, "mfcTransfers": 0},
            "vpn": {"sameBindIp": True},
            "environmentParity": {"sameServer": True, "sameKadBootstrap": True},
            "driver": {
                "autoDrive": True,
                "downloadEvery": 2,
                "searchIntervalSeconds": 1800,
                "downloadDelaySeconds": 90,
                "cycles": [
                    {
                        "query": "private live term",
                        "downloadRequested": True,
                        "download": {"hash": "a" * 32, "ok": True},
                    },
                    {
                        "query": "private live term 2",
                        "downloadRequested": True,
                        "download": {"ok": False, "reason": "no common safe candidate"},
                    },
                ],
            },
        },
    )
    _write_json(
        report_dir / "actions" / "00001-search.json",
        {
            "seq": 1,
            "kind": "search",
            "key": "private live term",
            "label": "private live term",
            "verdict": "divergence",
            "coverageOk": False,
            "diagOk": True,
            "packets": {"rust": 7, "mfc": 3},
            "packetDiff": {
                "opcodeCoverage": {
                    "channels": [
                        {
                            "channel": "server",
                            "direction": "recv",
                            "shared": [
                                {
                                    "protocolMarker": 0xE3,
                                    "opcode": 0x33,
                                    "rustCount": 1,
                                    "emuleCount": 1,
                                }
                            ],
                            "onlyRust": [],
                            "onlyEmule": [],
                        },
                        {
                            "channel": "server",
                            "direction": "send",
                            "shared": [
                                {
                                    "protocolMarker": 0xE3,
                                    "opcode": 0x16,
                                    "rustCount": 1,
                                    "emuleCount": 1,
                                }
                            ],
                            "onlyRust": [{"opcode": 1}],
                            "onlyEmule": [{"opcode": 2}, {"opcode": 3}],
                        }
                    ]
                }
            },
        },
    )
    _write_json(
        report_dir / "checkpoints" / "120000Z.json",
        {
            "schema": "soak_checkpoint_v1",
            "ts_utc": "2026-06-26T12:00:00+00:00",
            "rustAlive": True,
            "restStatus": {
                "rust": {
                    "connected": True,
                    "lowId": False,
                    "activeUploads": 2,
                    "waitingUploads": 0,
                    "sharedFileCount": 10,
                    "sharedHashingCount": 0,
                },
                "mfc": {
                    "connected": True,
                    "lowId": False,
                    "activeUploads": 1,
                    "waitingUploads": 0,
                    "sharedFileCount": 8,
                    "sharedHashingCount": 2,
                },
            },
            "errorLogHits": [],
        },
    )
    _write_json(
        report_dir / "checkpoints" / "120500Z.json",
        {
            "schema": "soak_checkpoint_v1",
            "ts_utc": "2026-06-26T12:05:00+00:00",
            "rustAlive": True,
            "restStatus": {
                "rust": {
                    "connected": True,
                    "lowId": False,
                    "activeUploads": 3,
                    "waitingUploads": 1,
                    "sharedFileCount": 10,
                    "sharedHashingCount": 0,
                },
                "mfc": {
                    "connected": True,
                    "lowId": False,
                    "activeUploads": 2,
                    "waitingUploads": 0,
                    "sharedFileCount": 10,
                    "sharedHashingCount": 0,
                },
            },
            "errorLogHits": [{"path": "daemon.out", "pattern": "warning"}],
        },
    )
    log_path = tmp_path / "runner.log"
    log_path.write_text(
        "\n".join(
            [
                "[soak] checkpoint: packets rust=10 mfc=20 actions=1",
                "[soak] final summary: summary.json",
            ]
        ),
        encoding="utf-8",
    )

    summary = soak_report_summary.summarize_report(report_dir, log_path=log_path)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["finished"] is True
    assert summary["driver"]["cycles"] == 2
    assert summary["driver"]["downloadOk"] == 1
    assert summary["driver"]["downloadFailed"] == 1
    assert summary["driver"]["downloadFailureReasons"] == {"no common safe candidate": 1}
    assert summary["actionReports"] == {"expected": 1, "loaded": 1, "missing": 0}
    assert summary["actions"]["verdictCounts"] == {"divergence": 1}
    assert summary["actions"]["actionVerdictCounts"] == {"coverage-parity": 1}
    assert summary["actions"]["coverageFailures"] == 1
    assert summary["actions"]["actionCoverageFailures"] == 0
    assert summary["actions"]["divergenceSamples"][0]["opcodeGapChannels"] == [
        {
            "channel": "server",
            "direction": "send",
            "onlyRustOpcodes": 1,
            "onlyMfcOpcodes": 2,
        }
    ]
    assert summary["actions"]["divergenceSamples"][0]["actionCoverageOk"] is True
    assert summary["actions"]["actionDivergenceSamples"] == []
    assert summary["checkpoints"]["last"] == {"rustPackets": 10, "mfcPackets": 20, "actions": 1}
    assert summary["checkpoints"]["structuredCount"] == 2
    assert summary["checkpoints"]["rustAliveAll"] is True
    assert summary["checkpoints"]["connectedAll"] == {"rust": True, "mfc": True}
    assert summary["checkpoints"]["lowIdObserved"] == {"rust": False, "mfc": False}
    assert summary["checkpoints"]["activeUploadMax"] == {"rust": 3, "mfc": 2}
    assert summary["checkpoints"]["lastRestStatus"]["mfc"]["sharedHashingCount"] == 0
    assert summary["checkpoints"]["errorLogHitCount"] == 1
    assert "private live term" not in serialized
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in serialized


def test_parse_checkpoint_lines_tolerates_missing_log(tmp_path: Path) -> None:
    assert soak_report_summary.parse_checkpoint_lines(tmp_path / "missing.log") == []
    assert soak_report_summary.log_finished(tmp_path / "missing.log") is False


def test_summarize_report_flags_missing_action_reports(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    _write_json(report_dir / "summary.json", {"campaignId": "camp-1", "totals": {"actions": 2}})
    _write_json(
        report_dir / "actions" / "00001-search.json",
        {"seq": 1, "kind": "search", "verdict": "divergence"},
    )

    summary = soak_report_summary.summarize_report(report_dir)

    assert summary["actionReports"] == {"expected": 2, "loaded": 1, "missing": 1}


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


def test_summarize_report_keeps_unpaired_separate_from_action_coverage_failure(
    tmp_path: Path,
) -> None:
    report_dir = tmp_path / "report"
    _write_json(report_dir / "summary.json", {"campaignId": "camp-1", "totals": {"actions": 1}})
    _write_json(
        report_dir / "actions" / "00001-search.json",
        {"seq": 1, "kind": "search", "verdict": "unpaired"},
    )

    summary = soak_report_summary.summarize_report(report_dir)

    assert summary["actions"]["actionVerdictCounts"] == {"unpaired": 1}
    assert summary["actions"]["actionCoverageFailures"] == 0
    assert summary["actions"]["actionDivergenceSamples"][0]["verdict"] == "unpaired"
    assert summary["actions"]["actionDivergenceSamples"][0]["actionCoverageOk"] is None
