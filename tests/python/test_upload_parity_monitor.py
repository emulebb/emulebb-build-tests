from __future__ import annotations

import json
from pathlib import Path

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
