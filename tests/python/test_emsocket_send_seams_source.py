from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_consume_queued_file_payload_rejects_null_counter() -> None:
    source = (app_source_root() / "EMSocketSendSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pnRemainingPayloadBytes != NULL);\n\tif (pnRemainingPayloadBytes == NULL)\n\t\treturn false;" in source
    assert "if (nActualPayloadSize > *pnRemainingPayloadBytes)\n\t\treturn false;" in source


def test_standard_upload_send_queue_budget_is_broadband_sized() -> None:
    source = (app_source_root() / "EMSocketSendSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "kMinEMSocketQueuedStandardBytes = 16ull * 1024ull * 1024ull" in source
    assert "kMaxEMSocketQueuedStandardBytes = 256ull * 1024ull * 1024ull" in source
    assert "GetBroadbandEMSocketQueuedStandardBytes(" in source
