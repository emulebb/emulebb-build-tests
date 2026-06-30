from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from emule_test_harness import upload_parity_monitor


def test_mfc_upload_summary_keeps_only_aggregate_slot_counters(tmp_path: Path) -> None:
    log = tmp_path / "emulebb-diagnostics-upload-slot.log"
    log.write_text(
        "\n".join(
            [
                "UploadSlotDiagnostics: slot=1 live=1 client=ignored state=Uploading "
                "rateBytesPerSec=1024 sessionUp=1.00 MB pendingIO=0 reqRejected=0",
                "UploadSlotDiagnostics: slot=2 live=1 client=ignored state=Uploading "
                "rateBytesPerSec=2048 sessionUp=2.00 MB pendingIO=1 reqRejected=3",
                "UploadSlotDiagnostics: slot=1 live=1 client=ignored state=Uploading "
                "rateBytesPerSec=4096 sessionUp=3.00 MB pendingIO=0 reqRejected=0",
                "UploadSlotDiagnostics: summary uploadSlots=22 waiting=9 waitingEligible=6 "
                "activeSlots=22 baseSlotTarget=12 effectiveSlotCap=22 cap=22 "
                "configuredBudgetBytesPerSec=3145728 toNetworkBytesPerSec=3038450 "
                "datarateBytesPerSec=3038450 underfilled=1 sharedFiles=66654 "
                "ed2kPublishedFiles=66654 ed2kPendingFiles=0 kadPublishReady=1 "
                "kadSourceDueFiles=64769 kadSourceSearches=4 kadSourceSearchCap=4",
            ]
        ),
        encoding="utf-8",
    )

    summary = upload_parity_monitor.mfc_upload_summary(log)

    assert summary["slotsSeen"] == 2
    assert summary["liveSlots"] == 2
    assert summary["uploadingSlots"] == 2
    assert summary["nonzeroRateSlots"] == 2
    assert summary["sumRateKiBps"] == 6.0
    assert summary["pendingIOSum"] == 1
    assert summary["reqRejectedSum"] == 3
    assert summary["summaryPresent"] is True
    assert summary["waiting"] == 9
    assert summary["effectiveSlotCap"] == 22
    assert summary["toNetworkBytesPerSec"] == 3038450
    assert summary["ed2kPublishedFiles"] == 66654
    assert summary["ed2kPendingFiles"] == 0
    assert summary["kadSourceDueFiles"] == 64769
    assert "client" not in json.dumps(summary)


def test_append_record_writes_jsonl_and_heartbeat(tmp_path: Path) -> None:
    config = upload_parity_monitor.MonitorConfig(
        rust_base_url="http://example.invalid/api/v1",
        rust_api_key="placeholder",
        rust_diag_log=None,
        mfc_upload_log=tmp_path / "missing.log",
        output_dir=tmp_path / "out",
    )
    record = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "rust": {"uploadSpeedKiBps": 1024.0, "activeUploads": 3},
        "mfc": {"sumRateKiBps": 3072.0},
        "action": {"parityGap": True},
    }

    upload_parity_monitor.append_record(config, record)

    assert config.heartbeat_path.read_text(encoding="utf-8").strip() == (
        "lastSample=2026-01-01T00:00:00+00:00 rustKiBps=1024.0 "
        "rustUploads=3 mfcKiBps=3072.0 parityGap=True"
    )
    assert json.loads(config.jsonl_path.read_text(encoding="utf-8")) == record


def test_build_record_flags_relative_gap_when_rust_is_below_mfc(monkeypatch: Any, tmp_path: Path) -> None:
    config = upload_parity_monitor.MonitorConfig(
        rust_base_url="http://example.invalid/api/v1",
        rust_api_key="placeholder",
        rust_diag_log=None,
        mfc_upload_log=tmp_path / "missing.log",
        output_dir=tmp_path / "out",
    )

    monkeypatch.setattr(
        upload_parity_monitor,
        "rust_summary",
        lambda _config: {
            "uploadSpeedKiBps": 2400.0,
            "activeUploads": 22,
            "waitingUploads": 0,
            "ed2kPublishedEntries": 64000,
            "ed2kPendingEntries": 2960,
        },
    )
    monkeypatch.setattr(
        upload_parity_monitor,
        "mfc_upload_summary",
        lambda _path, *, tail_bytes: {
            "sumRateKiBps": 3100.0,
            "summaryPresent": True,
            "ed2kPendingFiles": 0,
        },
    )

    record = upload_parity_monitor.build_record(config)

    assert record["action"]["throughputGapKiBps"] == 700.0
    assert record["action"]["rustMfcThroughputRatio"] == 0.7742
    assert record["action"]["relativeThroughputGap"] is True
    assert record["action"]["parityGap"] is True
    assert record["action"]["rustVisibilityMaturing"] is True


def test_rust_sched_summary_keeps_only_aggregate_counters(tmp_path: Path) -> None:
    log = tmp_path / "emulebb-rust-diag.jsonl"
    log.write_text(
        "\n".join(
            [
                json.dumps({"family": "other", "event": "ignored", "body": {"peer": "hidden"}}),
                json.dumps(
                    {
                        "family": "sched",
                        "event": "capacity_snapshot",
                        "keys": {"peer": "hidden"},
                        "body": {
                            "activeSlots": 22,
                            "baseSlots": 12,
                            "effectiveSlotCap": 22,
                            "elasticSlots": 10,
                            "elasticUnderfill": True,
                            "underfillSinceMs": 541542,
                            "uploadLimitBytesPerSec": 3145728,
                            "uploadRateBytesPerSec": 2252002,
                            "waitingSessions": 2,
                        },
                    }
                ),
                json.dumps(
                    {
                        "family": "sched",
                        "event": "upload_slot_recycled",
                        "keys": {"peer": "hidden", "fileHash": "hidden"},
                        "body": {"reason": "slowUnderfill", "slotRateBytesPerSec": 12624},
                    }
                ),
                json.dumps(
                    {
                        "family": "sched",
                        "event": "upload_request_outcome",
                        "keys": {"peer": "hidden", "fileHash": "hidden"},
                        "body": {"outcome": "served", "servedBytes": 4096, "throttleDelayMs": 25},
                    }
                ),
                json.dumps(
                    {
                        "family": "sched",
                        "event": "upload_payload_accounting",
                        "keys": {"peer": "hidden", "fileHash": "hidden"},
                        "body": {"sentPayloadBytes": 4096},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    summary = upload_parity_monitor.rust_sched_summary(log)

    assert summary["schedEvents"] == 4
    assert summary["eventCounts"] == {
        "capacity_snapshot": 1,
        "upload_slot_recycled": 1,
        "upload_request_outcome": 1,
        "upload_payload_accounting": 1,
    }
    assert summary["recycleReasons"] == {"slowUnderfill": 1}
    assert summary["requestOutcomes"] == {"served": 1}
    assert summary["servedBytes"] == 4096
    assert summary["throttleDelayMs"] == 25
    assert summary["lastCapacity"]["waitingSessions"] == 2
    assert "hidden" not in json.dumps(summary)
