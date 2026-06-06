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
    assert "kUnproductiveNoRequestCooldownProbeRemainingMs = 30000u" in seams
    assert "kProductiveNoRequestCooldownProbeRemainingMs = 5000u" in seams
    assert "ShouldProbeUnproductiveNoRequestCooldownCandidate" in seams
    assert "ShouldProbeNoRequestCooldownCandidate" in seams
    assert "ullCooldownRemainingMs <= ullMaxProbeRemainingMs" in seams
    assert "ullCooldownRemainingMs <= ullMaxProductiveProbeRemainingMs" in seams
    assert "bool\tHasUploadCooldownProbeCandidate(ULONGLONG curTick);" in header
    assert "bool\tCanProbeUploadCooldownCandidate(CUpDownClient *client, ULONGLONG curTick) const;" in header
    assert "bool CUploadQueue::HasUploadCooldownProbeCandidate(ULONGLONG curTick)" in source
    assert "bool CUploadQueue::CanProbeUploadCooldownCandidate(CUpDownClient *client, ULONGLONG curTick) const" in source

    find_best_block = source[
        source.index("CUpDownClient* CUploadQueue::FindBestClientInQueue()") :
        source.index("void CUploadQueue::InsertInUploadingList")
    ]
    assert "CUpDownClient *cooldownProbeClient = NULL;" in find_best_block
    assert "const bool bAllowCooldownProbe = ShouldProbeUploadCooldownCandidate" in find_best_block
    assert "const ULONGLONG ullCooldownRemaining = cur_client->GetSlowUploadCooldownRemaining();" in find_best_block
    assert "CanProbeUploadCooldownCandidate(cur_client, curTick)" in find_best_block
    assert find_best_block.index("CanProbeUploadCooldownCandidate(cur_client, curTick)") < find_best_block.index("ullCooldownRemaining < ullBestCooldownProbeRemaining")
    assert "return newclient != NULL ? newclient : cooldownProbeClient;" in find_best_block

    cooldown_probe_block = source[
        source.index("bool CUploadQueue::CanProbeUploadCooldownCandidate") :
        source.index("void CUploadQueue::SetUploadRetryCooldown")
    ]
    assert "client == NULL || client->GetSlowUploadCooldownRemaining() == 0" in cooldown_probe_block
    assert "m_noRequestUploadRetryCooldownByIP.find(dwCooldownIP)" in cooldown_probe_block
    assert "itNoRequest->second.ullCooldownUntil > curTick" in cooldown_probe_block
    assert "already contributed payload" in cooldown_probe_block
    assert "before zero-byte peers" in cooldown_probe_block
    assert "const ULONGLONG ullCooldownRemainingMs = itNoRequest->second.ullCooldownUntil - curTick;" in cooldown_probe_block
    assert "ShouldProbeNoRequestCooldownCandidate(" in cooldown_probe_block
    assert "kProductiveNoRequestCooldownProbeRemainingMs" in cooldown_probe_block
    assert "kUnproductiveNoRequestCooldownProbeRemainingMs" in cooldown_probe_block
    assert "ShouldProbeUploadCooldownCandidate(HasSustainedBroadbandUnderfill(curTick), uploadinglist.GetCount(), GetSoftMaxUploadSlots())" in cooldown_probe_block
    assert cooldown_probe_block.index("ShouldProbeNoRequestCooldownCandidate") < cooldown_probe_block.rindex("return true;")

    has_probe_block = source[
        source.index("bool CUploadQueue::HasUploadCooldownProbeCandidate") :
        source.index("bool CUploadQueue::CanProbeUploadCooldownCandidate")
    ]
    assert "CanProbeUploadCooldownCandidate(cur_client, curTick)" in has_probe_block
    assert "cur_client->GetSlowUploadCooldownRemaining() != 0" not in has_probe_block

    force_new_block = source[
        source.index("bool CUploadQueue::ForceNewClient") :
        source.index("uint32 CUploadQueue::GetConfiguredUploadBudgetBytesPerSec")
    ]
    assert "const bool bHasAdmissionCandidate = HasUploadAdmissionCandidate(curTick);" in force_new_block
    assert "const bool bHasCooldownProbeCandidate = !bHasAdmissionCandidate && HasUploadCooldownProbeCandidate(curTick);" in force_new_block
    assert "bHasAdmissionCandidate || bHasCooldownProbeCandidate" in force_new_block


def test_broadband_upload_buffer_depth_scales_with_per_slot_target() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    seams = (app_source_root() / "UploadQueueSeams.h").read_text(encoding="utf-8", errors="ignore")
    disk_io = (app_source_root() / "UploadDiskIOThread.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "GetBroadbandUploadBufferBlockCount(" in seams
    assert "uTargetBufferSeconds = 8u" in seams
    assert "uMaxBlocks = 768u" in seams
    assert "ShouldUseBroadbandBigSendBuffer(" in seams
    assert "uHighTargetBytesPerSec = 512u * 1024u" in seams
    assert "GetBroadbandUnderfillMarginBytesPerSec(" in seams
    assert "uTargetFillPercent = 98u" in seams
    assert "return GetBroadbandUploadBufferBlockCount(uTargetPerSlot, uClientDatarate);" in source
    assert "return ShouldUseBroadbandBigSendBuffer(uTargetPerSlot, uClientDatarate);" in source
    assert "return GetBroadbandTcpUploadSendBufferBytes(GetTargetClientDataRateBroadband());" in source
    assert "return GetBroadbandEMSocketQueuedStandardBytes(GetTargetClientDataRateBroadband());" in source
    assert "return ::GetBroadbandUnderfillMarginBytesPerSec(uBudgetBytesPerSec);" in source
    assert "GetBroadbandPendingReadBlocksPerClient(" in disk_io
    assert "GetBroadbandPendingReadBlocksPerThread(" in disk_io


def test_auto_broadband_io_diagnostics_distinguish_download_and_upload_buffers() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")

    assert '{"downloadAutoBroadbandIo", thePrefs.IsDownloadAutoBroadbandIOEnabled()}' in source
    assert '{"downloadAutoBroadbandIoScope", "downloadDiskWriteBufferOnly"}' in source
    assert '{"uploadSendPipeline", nlohmann::json{' in source
    assert '{"controlledByDownloadAutoBroadbandIo", false}' in source


def test_nonzero_slow_slots_keep_accumulated_slow_tracking_for_recycle_path() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    idle_recycle_block = source[
        source.index("bool CUploadQueue::ShouldRecycleIdleUploadSlot") :
        source.index("CUpDownClient* CUploadQueue::GetWaitingClientByIP_UDP")
    ]
    check_for_time_over_block = source[
        source.index("bool CUploadQueue::CheckForTimeOver") :
        source.index("void CUploadQueue::DeleteAll")
    ]

    assert "nonzero but slow slots are evaluated by the broader slow-rate" in idle_recycle_block
    assert "client->UpdateSlowUploadTracking(curTick, GetSlowUploadRateThreshold());\n\telse\n\t\tclient->ResetSlowUploadTracking();" not in idle_recycle_block
    assert "client->UpdateSlowUploadTracking(curTick, GetSlowUploadRateThreshold());" in check_for_time_over_block
    assert "client->ShouldRecycleSlowUpload(SEC2MS(thePrefs.GetSlowUploadGraceSeconds()), SEC2MS(thePrefs.GetZeroUploadRateGraceSeconds()))" in check_for_time_over_block


def test_queued_upload_wait_time_uses_current_tick_until_slot_starts() -> None:
    header = (app_source_root() / "UpdownClient.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "UploadClient.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ULONGLONG\t\tGetWaitTime() const;" in header
    assert "m_dwUploadTime - GetWaitStartTime()" not in header

    wait_time_block = source[
        source.index("ULONGLONG CUpDownClient::GetWaitTime() const") :
        source.index("void CUpDownClient::SetWaitStartTime")
    ]
    assert "const ULONGLONG ullWaitStart = GetWaitStartTime();" in wait_time_block
    assert "if (ullWaitStart == 0)\n\t\treturn 0;" in wait_time_block
    assert "const ULONGLONG ullWaitEnd = IsDownloading() ? m_dwUploadTime : ::GetTickCount64();" in wait_time_block
    assert "queued clients do not have an upload-start timestamp yet" in wait_time_block
    assert "return ullWaitEnd >= ullWaitStart ? ullWaitEnd - ullWaitStart : 0;" in wait_time_block
