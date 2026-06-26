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
                    }
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
                            "direction": "send",
                            "onlyRust": [{"opcode": 1}],
                            "onlyEmule": [{"opcode": 2}, {"opcode": 3}],
                        }
                    ]
                }
            },
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
    assert summary["driver"]["cycles"] == 1
    assert summary["driver"]["downloadOk"] == 1
    assert summary["actions"]["verdictCounts"] == {"divergence": 1}
    assert summary["actions"]["divergenceSamples"][0]["opcodeGapChannels"] == [
        {
            "channel": "server",
            "direction": "send",
            "onlyRustOpcodes": 1,
            "onlyMfcOpcodes": 2,
        }
    ]
    assert summary["checkpoints"]["last"] == {"rustPackets": 10, "mfcPackets": 20, "actions": 1}
    assert "private live term" not in serialized
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in serialized


def test_parse_checkpoint_lines_tolerates_missing_log(tmp_path: Path) -> None:
    assert soak_report_summary.parse_checkpoint_lines(tmp_path / "missing.log") == []
    assert soak_report_summary.log_finished(tmp_path / "missing.log") is False
