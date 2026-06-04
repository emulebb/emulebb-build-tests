from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_upload_queue_position_helpers_reject_null_positions() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pClient != NULL);\n\tif (pUploadClientStruct == NULL || pClient == NULL)\n\t\treturn;" in source
    assert "void CUploadQueue::InvalidateUploadClientStructWithoutClient(UploadingToClient_Struct *pUploadClientStruct)\n{\n\tASSERT(pUploadClientStruct != NULL);\n\tif (pUploadClientStruct == NULL)\n\t\treturn;" in source
    assert "static_cast<float>(uTargetPerSlot) * fFactor" in source
    assert "sum / static_cast<float>(count)" in source
    assert "UpdateConnectionStats(static_cast<float>(theApp.uploadqueue->GetDatarate()) / 1024.0f, static_cast<float>(theApp.downloadqueue->GetDatarate()) / 1024.0f)" in source
    assert "SetCurrentRate(static_cast<float>(theApp.uploadqueue->GetDatarate()) / 1024.0f, static_cast<float>(theApp.downloadqueue->GetDatarate()) / 1024.0f)" in source
    assert "ASSERT(pos != NULL);\n\tif (pUploadClientStruct == NULL || pos == NULL)\n\t\treturn {NULL};" in source
    assert "ASSERT(pos != NULL);\n\tif (pUploadClientStruct == NULL || pClient == NULL || pos == NULL)\n\t\treturn;" in source
    assert "ASSERT(pos != NULL);\n\tif (pUploadClientStruct == NULL || pos == NULL)\n\t\treturn;" in source
    assert "void CUploadQueue::RemoveFromWaitingQueue(POSITION pos, bool updatewindow)\n{\n\tASSERT(pos != NULL);\n\tif (pos == NULL)\n\t\treturn;" in source
    assert "void CUploadQueue::RemoveStaleWaitingClient(POSITION pos)\n{\n\tASSERT(pos != NULL);\n\tif (pos == NULL)\n\t\treturn;" in source
    assert "CUpDownClient* CUploadQueue::GetQueueClientAt(POSITION &curpos) const\n{\n\tif (curpos == NULL)\n\t\treturn NULL;" in source
    assert "CUpDownClient* CUploadQueue::GetWaitClientAt(POSITION &curpos) const\n{\n\tif (curpos == NULL)\n\t\treturn NULL;" in source


def test_broadband_retained_slot_logs_are_throttled() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "static ULONGLONG s_ullLastBroadbandRetainedSlotLogTick = 0;" in source
    assert "static UINT s_uSuppressedBroadbandRetainedSlotLogs = 0;" in source
    assert "bool ShouldLogBroadbandRetainedSlot(UINT &uSuppressedLogs)" in source
    assert "constexpr ULONGLONG ullLogIntervalMs = SEC2MS(30);" in source
    assert "++s_uSuppressedBroadbandRetainedSlotLogs;" in source
    assert "Suppressed retained-slot logs: %u." in source
    assert source.count("if (!ShouldLogBroadbandRetainedSlot(uSuppressedLogs))\n\t\t\t\t\treturn false;") == 1
    assert source.count("if (!ShouldLogBroadbandRetainedSlot(uSuppressedLogs))\n\t\t\t\treturn false;") == 1


def test_underfilled_upload_queue_can_probe_cooldown_only_waiters() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "UploadQueue.h").read_text(encoding="utf-8", errors="ignore")
    seams = (app_source_root() / "UploadQueueSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "ShouldProbeUploadCooldownCandidate" in seams
    assert "bool\tHasUploadCooldownProbeCandidate(ULONGLONG curTick);" in header
    assert "bool CUploadQueue::HasUploadCooldownProbeCandidate(ULONGLONG curTick)" in source

    find_best_block = source[
        source.index("CUpDownClient* CUploadQueue::FindBestClientInQueue()") :
        source.index("void CUploadQueue::InsertInUploadingList")
    ]
    assert "CUpDownClient *cooldownProbeClient = NULL;" in find_best_block
    assert "const bool bAllowCooldownProbe = ShouldProbeUploadCooldownCandidate" in find_best_block
    assert "const ULONGLONG ullCooldownRemaining = cur_client->GetSlowUploadCooldownRemaining();" in find_best_block
    assert "ullCooldownRemaining < ullBestCooldownProbeRemaining" in find_best_block
    assert "return newclient != NULL ? newclient : cooldownProbeClient;" in find_best_block

    force_new_block = source[
        source.index("bool CUploadQueue::ForceNewClient") :
        source.index("uint32 CUploadQueue::GetConfiguredUploadBudgetBytesPerSec")
    ]
    assert "const bool bHasAdmissionCandidate = HasUploadAdmissionCandidate(curTick);" in force_new_block
    assert "const bool bHasCooldownProbeCandidate = !bHasAdmissionCandidate && HasUploadCooldownProbeCandidate(curTick);" in force_new_block
    assert "bHasAdmissionCandidate || bHasCooldownProbeCandidate" in force_new_block
