from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_transfer_bar_percentage_preference_uses_transfer_wide_text() -> None:
    resources = read_app_source("emule.rc")
    preferences_source = read_app_source("Preferences.cpp")

    assert 'IDS_SHOWDWLPERCENTAGE   "Show transfer percentages in progress bars"' in resources
    assert "Shows download and upload progress percentages inside transfer progress bars." in resources
    assert 'ini.WriteBool(_T("ShowDwlPercentage"), m_bShowDwlPercentage);' in preferences_source
    assert 'ini.GetBool(_T("ShowDwlPercentage"), true);' in preferences_source


def test_upload_slot_instrumentation_reports_cooldown_pressure() -> None:
    source = read_app_source("UploadQueue.cpp")
    header = read_app_source("UploadQueue.h")
    seams_header = read_app_source("UploadQueueSeams.h")
    log_header = read_app_source("Log.h")
    artifacts = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")
    block = source[source.index("void CUploadQueue::LogUploadSlotInstrumentation") : source.index("void CUploadQueue::Process()")]

    assert "UploadSlotDiagnosticsLogLine(" in block
    assert "AddDebugLogLine(DLP_DEFAULT, false," not in block
    assert "extern CLogFile theUploadSlotDiagnosticsLog;" in log_header
    assert "void UploadSlotDiagnosticsLogLine(LPCTSTR pszFmt, ...);" in log_header
    assert 'return _T("emulebb-diagnostics-upload-slot.log");' in artifacts
    assert "LogArtifactNames::UploadSlotDiagnosticsLogFileName()" in app_source
    assert "waitingCooldownMinMs=%I64u" in block
    assert "waitingCooldownAvgMs=%I64u" in block
    assert "waitingCooldownMaxMs=%I64u" in block
    assert "waitingRetryCooldown=%Id" in block
    assert "waitingNoRequestCooldown=%Id" in block
    assert "waitingNoRequestProductive=%Id" in block
    assert "waitingNoRequestUnproductive=%Id" in block
    assert "waitingClientOnlyCooldown=%Id" in block
    assert "waitingRetryNoRequest=%Id" in block
    assert "waitingRetryChurn=%Id" in block
    assert "waitingRetryStalled=%Id" in block
    assert "waitingRetrySlow=%Id" in block
    assert "waitingRetryUnknown=%Id" in block
    assert "activeZeroRate=%Id" in block
    assert "activeNoRequest=%Id" in block
    assert "activeNoRequestDrained=%Id" in block
    assert "activeNoRequestDrainedZeroRate=%Id" in block
    assert "activeNoRequestDrainedNonzeroRate=%Id" in block
    assert "activeNoRequestPendingIO=%Id" in block
    assert "activeNoRequestBufferedPayload=%Id" in block
    assert "activeNoRequestSocketBacklog=%Id" in block
    assert "activeNoRequestNeverAccepted=%Id" in block
    assert "activeNoRequestRecycleEligible=%Id" in block
    assert "activeNoRequestRecycleGraceBlocked=%Id" in block
    assert "activeNoRequestRecycleUnderfillBlocked=%Id" in block
    assert "activeNoRequestAgeAvgMs=%I64u" in block
    assert "activeNoRequestAgeMaxMs=%I64u" in block
    assert "activeNoRequestLastAcceptedAgeMaxMs=%I64u" in block
    assert "activeNoRequestZeroMaxMs=%I64u" in block
    assert "activeQueuedRequests=%Id" in block
    assert "activePendingIO=%Id" in block
    assert "activeBufferedPayload=%Id" in block
    assert "activeSocketBacklog=%Id" in block
    assert "pUploadingClient->m_BlockRequests_queue.GetCount()" in block
    assert "pUploadingClient->m_nPendingIOBlocks.load()" in block
    assert "pUploadingClient->m_ullLastAcceptedReqBlockTick.load()" in block
    assert "pActiveClient->GetUpStartTimeDelay()" in block
    assert "pActiveClient->GetAccumulatedZeroUploadMs()" in block
    assert "pActiveClient->GetPayloadInBuffer()" in block
    assert "pUploadSocket->DbgGetStdQueueCount()" in block
    assert "iActiveNoRequestDrainedClients" in block
    assert "iActiveNoRequestDrainedZeroRateClients" in block
    assert "iActiveNoRequestDrainedNonzeroRateClients" in block
    assert "iActiveNoRequestPendingIOClients" in block
    assert "iActiveNoRequestBufferedPayloadClients" in block
    assert "iActiveNoRequestSocketBacklogClients" in block
    assert "iActiveNoRequestNeverAcceptedClients" in block
    assert "iActiveNoRequestRecycleEligibleClients" in block
    assert "iActiveNoRequestRecycleGraceBlockedClients" in block
    assert "iActiveNoRequestRecycleUnderfillBlockedClients" in block
    assert "bSustainedBroadbandUnderfill" in block
    assert "ullNoRequestGraceMs" in block
    assert "bHasAcceptedReqBlock" in block
    assert "ullLastAcceptedReqBlockAgeMs" in block
    assert "ShouldRecycleNoRequestBroadbandUploadSlot(" in block
    assert "ullActiveNoRequestAgeAvgMs" in block
    assert "ullActiveNoRequestAgeMaxMs" in block
    assert "ullActiveNoRequestLastAcceptedAgeMaxMs" in block
    assert "ullActiveNoRequestZeroMaxMs" in block
    assert "retryCooldowns=%u" in block
    assert "noRequestCooldowns=%u" in block
    assert "sharedFiles=%Id" in block
    assert "ed2kPublishedFiles=%u" in block
    assert "ed2kPendingFiles=%u" in block
    assert "ed2kPendingLargeUnsupportedFiles=%u" in block
    assert "ed2kOfferLimit=%u" in block
    assert "kadPublishReady=%u" in block
    assert "kadSourceDueFiles=%u" in block
    assert "kadSourceBackoffFiles=%u" in block
    assert "kadSourceSearches=%u" in block
    assert "kadSourceSearchCap=%u" in block
    assert "kadKeywordSearches=%u" in block
    assert "kadKeywordSearchCap=%u" in block
    assert "kadNotesSearches=%u" in block
    assert "kadNotesSearchCap=%u" in block
    assert "CSharedFileList::SharedPublishInstrumentationSnapshot sharedPublish = {};" in block
    assert "theApp.sharedfiles->GetPublishInstrumentationSnapshot(sharedPublish);" in block
    assert "GetSlowUploadCooldownRemaining()" in block
    assert "GetUploadRetryCooldownIP(pWaitingClient)" in block
    assert "ullCooldownUntil > curTick" in block
    assert "itRetryCooldown->second.eReason" in block
    assert "m_uploadRetryCooldownByIP.size()" in block
    assert "m_noRequestUploadRetryCooldownByIP.size()" in block
    assert "bProductiveRecycle" in header
    assert "SetNoRequestUploadRetryCooldown(client, ullCooldownUntil, ullTrackUntil, bProductiveNoRequestRecycle)" in source
    no_request_recycle_block = source[
        source.index("if (ShouldRecycleNoRequestBroadbandUploadSlot(") :
        source.index("if (!HasCompletedSlowUploadWarmup(client))")
    ]
    assert "GetProductiveNoRequestCooldownPayloadBytes(GetTargetClientDataRateBroadband())" in no_request_recycle_block
    assert "GetNoRequestUploadRecycleGraceMs(GetZeroUploadGraceSecondsForBudget(thePrefs.GetZeroUploadRateGraceSeconds(), uBudgetBytesPerSec))" in source
    assert "ShouldDeferProductiveNoRequestUploadRecycle(" in no_request_recycle_block
    assert "SEC2MS(GetSlowUploadWarmupSecondsForBudget(thePrefs.GetSlowUploadWarmupSeconds(), uBudgetBytesPerSec))" in no_request_recycle_block
    assert "fast\n\t\t\t// clients can keep carrying upload bandwidth" in no_request_recycle_block
    assert no_request_recycle_block.index("const bool bProductiveNoRequestRecycle") < no_request_recycle_block.index("if (ShouldCooldownNoRequestUploadRecycle(false))")
    assert no_request_recycle_block.index("ShouldDeferProductiveNoRequestUploadRecycle(") < no_request_recycle_block.index("if (ShouldCooldownNoRequestUploadRecycle(false))")
    assert "const UINT uProductiveCooldownSeconds = GetNoRequestUploadRetryCooldownSeconds" in no_request_recycle_block
    assert "const UINT uBaseCooldownSeconds = GetNoRequestRepeatBaseCooldownSeconds" in no_request_recycle_block
    assert "NoRequestRepeatPenalty repeatPenalty = {};" in no_request_recycle_block
    assert "repeatPenalty = TrackNoRequestRepeatOffender(client, curTick, uBaseCooldownSeconds);" in no_request_recycle_block
    assert "uCooldownSeconds = repeatPenalty.uCooldownSeconds;" in no_request_recycle_block
    assert "GetNoRequestRepeatCooldownSeconds(uBaseCooldownSeconds, penalty.uStrikes)" in source
    assert "upload_no_request_repeat_cooldown" in no_request_recycle_block
    assert "upload_no_request_repeat_ban" in no_request_recycle_block
    assert "Repeated zero-request upload slot abuse" in no_request_recycle_block
    assert "if (pbRequeue != NULL && client->IsBanned())" in source
    assert "const ULONGLONG ullCooldownUntil = curTick + SEC2MS(uCooldownSeconds);" in no_request_recycle_block
    assert "const ULONGLONG ullTrackUntil = curTick + SEC2MS(GetNoRequestUploadRetryTrackSeconds(uCooldownSeconds, uConfiguredCooldownSeconds));" in no_request_recycle_block
    no_request_cooldown_start = no_request_recycle_block.index("const UINT uBaseCooldownSeconds")
    no_request_cooldown_block = no_request_recycle_block[
        no_request_cooldown_start :
        no_request_recycle_block.index("client->SetSlowUploadCooldownUntil", no_request_cooldown_start)
    ]
    assert no_request_cooldown_block.index("const UINT uBaseCooldownSeconds") < no_request_cooldown_block.index("const UINT uInitialCooldownSeconds")
    assert no_request_cooldown_block.index("const UINT uInitialCooldownSeconds") < no_request_cooldown_block.index("UINT uCooldownSeconds = uInitialCooldownSeconds;")
    assert no_request_cooldown_block.index("UINT uCooldownSeconds = uInitialCooldownSeconds;") < no_request_cooldown_block.index("const ULONGLONG ullCooldownUntil")
    assert no_request_cooldown_block.index("const ULONGLONG ullCooldownUntil") < no_request_cooldown_block.index("const ULONGLONG ullTrackUntil")
    apply_cooldown_block = source[
        source.index("bool CUploadQueue::ApplyUploadRetryCooldown") :
        source.index("bool CUploadQueue::HasUploadAdmissionCandidate")
    ]
    assert "SelectUploadRetryCooldownUntil" in seams_header
    assert "m_uploadRetryCooldownByIP.find(dwCooldownIP)" in apply_cooldown_block
    assert "m_noRequestUploadRetryCooldownByIP.find(dwCooldownIP)" in apply_cooldown_block
    assert "SelectUploadRetryCooldownUntil" in apply_cooldown_block
    assert apply_cooldown_block.index("m_uploadRetryCooldownByIP.find(dwCooldownIP)") < apply_cooldown_block.index("SelectUploadRetryCooldownUntil")
    assert apply_cooldown_block.index("m_noRequestUploadRetryCooldownByIP.find(dwCooldownIP)") < apply_cooldown_block.index("SelectUploadRetryCooldownUntil")
    assert "Broadband productive no-request recycle" in no_request_recycle_block
    assert "Broadband unproductive no-request recycle" in no_request_recycle_block
    assert "_T(\"productive\") : _T(\"unproductive\")" in no_request_recycle_block
    check_for_time_over_block = source[
        source.index("bool CUploadQueue::CheckForTimeOver") :
        source.index("void CUploadQueue::DeleteAll")
    ]
    assert "if (ShouldRecycleIdleUploadSlot(client, curTick, pstrReason))" in check_for_time_over_block
    assert "!bShouldTrackSlowUploadSlots && ShouldRecycleIdleUploadSlot" not in check_for_time_over_block
    assert check_for_time_over_block.index("ShouldRecycleIdleUploadSlot(client, curTick, pstrReason)") < check_for_time_over_block.index("if (waitinglist.IsEmpty())")
    assert check_for_time_over_block.index("ShouldRecycleIdleUploadSlot(client, curTick, pstrReason)") < check_for_time_over_block.index("if (bShouldTrackSlowUploadSlots)")
    assert "UploadRetryCooldownReason eReason" in header
    assert "UploadRetryCooldownReason eReason);" in header
    for reason in (
        "uploadRetryCooldownFailedAdmission",
        "uploadRetryCooldownNoSocket",
        "uploadRetryCooldownNoRequest",
        "uploadRetryCooldownIdle",
        "uploadRetryCooldownStalled",
        "uploadRetryCooldownShortFailed",
        "uploadRetryCooldownZeroUpload",
        "uploadRetryCooldownSlowUpload",
    ):
        assert reason in header
        assert reason in source
    assert block.index("GetSlowUploadCooldownRemaining()") < block.index("waitingCooldownMinMs=%I64u")


def test_stalled_upload_retry_cooldown_is_bounded() -> None:
    source = read_app_source("UploadQueue.cpp")
    stalled_block = source[
        source.index("const bool bShouldRecycleIdle = ShouldRecycleIdleBroadbandUploadSlot") :
        source.index("if (thePrefs.GetLogUlDlEvents())", source.index("const bool bShouldRecycleIdle = ShouldRecycleIdleBroadbandUploadSlot"))
    ]

    assert "GetUploadChurnRetryCooldownSecondsForBudget(" in stalled_block
    assert "GetConfiguredUploadBudgetBytesPerSec()" in stalled_block
    assert "uploadRetryCooldownIdle : uploadRetryCooldownStalled" in stalled_block
    assert "bStalledRecycleWarmupComplete" not in stalled_block
    assert "ShouldRecycleStalledBroadbandUploadSlot(\n\t\ttrue,\n\t\tbSlowUploadWarmupComplete," in stalled_block
    assert "normal\n\t// broadband warmup" in source


def test_queued_block_request_can_reopen_upload_slot_after_cooldown_clear() -> None:
    client_source = read_app_source("UploadClient.cpp")
    queue_source = read_app_source("UploadQueue.cpp")
    queue_header = read_app_source("UploadQueue.h")
    seams_header = read_app_source("UploadQueueSeams.h")
    not_uploading_block = client_source[
        client_source.index("if (GetUploadState() != US_UPLOADING)") :
        client_source.index("if (HasCollectionUploadSlot())")
    ]
    direct_admit_block = queue_source[
        queue_source.index("QueuedBlockRequestAdmissionResult CUploadQueue::TryAdmitQueuedBlockRequestClient") :
        queue_source.index("void CUploadQueue::PurgeExpiredUploadRetryCooldowns")
    ]

    assert "QueuedBlockRequestAdmissionResult TryAdmitQueuedBlockRequestClient(CUpDownClient *client, bool bQueuedRequestCooldownCleared)" in queue_header
    assert "QueuedBlockRequestAdmissionResult CUploadQueue::TryAdmitQueuedBlockRequestClient" in queue_source
    assert "ClassifyQueuedBlockRequestAdmission" in seams_header
    assert "ShouldAdmitQueuedBlockRequestToUploadSlot" in seams_header
    assert "ShouldAttemptUploadRetryCooldownClearOnQueuedRequest" in seams_header
    assert "bool bProductiveNoRequestRecycle" in seams_header
    assert "return !bNoRequestCooldownTracked\n\t\t|| !bQueuedRequestClearAlreadyUsed;" in seams_header
    assert "ShouldAttemptUploadRetryCooldownClearOnQueuedRequest" in not_uploading_block
    assert "LPCTSTR pszCooldownClearInstrumentationReason = NULL;" in not_uploading_block
    assert "const bool bCooldownCleared = theApp.uploadqueue->ClearUploadRetryCooldown(this, &pszCooldownClearInstrumentationReason);" in not_uploading_block
    assert "TryAdmitQueuedBlockRequestClient(this, bCooldownCleared)" in not_uploading_block
    assert "accept-queued-request-direct-admit" in not_uploading_block
    assert "eQueuedRequestAdmissionResult == queuedBlockRequestCooldownNotCleared && pszCooldownClearInstrumentationReason != NULL" in not_uploading_block
    assert "GetQueuedBlockRequestAdmissionInstrumentationReason(eQueuedRequestAdmissionResult)" in not_uploading_block
    assert not_uploading_block.index("accept-queued-request-direct-admit") < not_uploading_block.index("GetQueuedBlockRequestAdmissionInstrumentationReason")
    assert "bool ClearUploadRetryCooldown(CUpDownClient *client, LPCTSTR *ppszInstrumentationReason = NULL)" in queue_header
    assert "bool CUploadQueue::ClearUploadRetryCooldown(CUpDownClient *client, LPCTSTR *ppszInstrumentationReason)" in queue_source
    clear_cooldown_block = queue_source[
        queue_source.index("bool CUploadQueue::ClearUploadRetryCooldown") :
        queue_source.index("QueuedBlockRequestAdmissionResult CUploadQueue::TryAdmitQueuedBlockRequestClient")
    ]
    assert "const bool bProductiveNoRequestRecycle = itNoRequest->second.bProductiveRecycle;" in queue_source
    assert "ShouldAllowNoRequestCooldownClear(true, itNoRequest->second.bQueuedRequestClearUsed)" in queue_source
    assert "reject-not-uploading-no-request-clear-used" in queue_source
    assert "bClearedProductiveNoRequestCooldown = true;" in queue_source
    assert "bool bClearedUnderfilledNoRequestCooldown = false;" in clear_cooldown_block
    assert "ShouldClearActiveNoRequestCooldownOnQueuedRequest" in seams_header
    assert "HasSustainedBroadbandUnderfill(curTick)" in clear_cooldown_block
    assert "uploadinglist.GetCount()" in clear_cooldown_block
    assert "GetSoftMaxUploadSlots()" in clear_cooldown_block
    assert "fresh demand" in clear_cooldown_block
    assert "bClearedUnderfilledNoRequestCooldown = true;" in clear_cooldown_block
    assert "ShouldBlockQueuedRequestRetryClearForActiveNoRequest" in seams_header
    assert "ShouldBlockQueuedRequestRetryClearForActiveNoRequest(bHadNoRequestCooldown, bClearedProductiveNoRequestCooldown, bClearedUnderfilledNoRequestCooldown)" in clear_cooldown_block
    assert "reject-not-uploading-unproductive-no-request-active" in clear_cooldown_block
    assert clear_cooldown_block.index("ShouldBlockQueuedRequestRetryClearForActiveNoRequest(bHadNoRequestCooldown, bClearedProductiveNoRequestCooldown, bClearedUnderfilledNoRequestCooldown)") < clear_cooldown_block.index("m_uploadRetryCooldownByIP.find(dwCooldownIP)")
    assert "bHadClientCooldown || bHadIPCooldown || bClearedProductiveNoRequestCooldown || bClearedUnderfilledNoRequestCooldown" in queue_source
    assert "reject-not-uploading-retry-clear-used" in queue_source
    assert "reject-not-uploading-no-request-only-cooldown" in queue_source
    assert "reject-not-uploading-no-active-cooldown" in queue_source
    assert "AcceptNewClient(uploadinglist.GetCount())" in direct_admit_block
    assert "ForceNewClient(true)" in direct_admit_block
    assert "AddUpNextClient(_T(\"Direct add after queued block request.\"), client)" in direct_admit_block
    for reason in (
        "reject-not-uploading-cooldown-not-cleared",
        "reject-not-uploading-not-on-queue",
        "reject-not-uploading-already-uploading",
        "reject-not-uploading-cap-full",
        "reject-not-uploading-admission-deferred",
        "reject-not-uploading-direct-add-failed",
    ):
        assert reason in client_source


def test_upload_list_membership_honors_queued_refresh_timing() -> None:
    queue_source = read_app_source("UploadQueue.cpp")
    list_source = read_app_source("UploadListCtrl.cpp")
    sync_block = list_source[
        list_source.index("bool CUploadListCtrl::SyncLiveClientItems") :
        list_source.index("CObject* CUploadListCtrl::WalkToLiveClientItem")
    ]
    refresh_block = list_source[
        list_source.index("void CUploadListCtrl::RefreshVisibleItems") :
        list_source.index("void CUploadListCtrl::ShowSelectedUserDetails")
    ]

    assert "QueueUploadListDisplayRefresh()" in queue_source
    assert "QueueDisplayRefresh(DISPLAY_REFRESH_UPLOAD_LIST)" in queue_source
    assert "GetUploadList()->AddClient" not in queue_source
    assert "GetUploadList()->RemoveClient" not in queue_source
    assert "GetFirstFromUploadList()" in sync_block
    assert "InsertItem(LVIF_TEXT | LVIF_PARAM" in sync_block
    assert "PruneStaleClientItems()" in sync_block
    assert "SyncLiveClientItems();" in refresh_block


def test_queue_list_membership_honors_queued_refresh_timing() -> None:
    queue_source = read_app_source("UploadQueue.cpp")
    list_source = read_app_source("QueueListCtrl.cpp")
    sync_block = list_source[
        list_source.index("bool CQueueListCtrl::SyncLiveClientItems") :
        list_source.index("CObject* CQueueListCtrl::WalkToLiveClientItem")
    ]
    refresh_block = list_source[
        list_source.index("void CQueueListCtrl::RefreshVisibleItems") :
        list_source.index("void CQueueListCtrl::ShowSelectedUserDetails")
    ]

    assert "QueueWaitingListDisplayRefresh()" in queue_source
    assert "QueueDisplayRefresh(DISPLAY_REFRESH_QUEUE_LIST)" in queue_source
    assert "GetQueueList()->AddClient" not in queue_source
    assert "GetQueueList()->RemoveClient" not in queue_source
    assert "client->SetWaitStartTime();" in queue_source
    assert "client->SetAskedCount(1);" in queue_source
    assert "GetNextClient(client)" in sync_block
    assert "InsertItem(LVIF_TEXT | LVIF_PARAM" in sync_block
    assert "PruneStaleClientItems()" in sync_block
    assert "SyncLiveClientItems();" in refresh_block


def test_upload_part_counts_are_distinct_text_columns_and_bars_remain() -> None:
    upload_list_source = read_app_source("UploadListCtrl.cpp")
    queue_list_source = read_app_source("QueueListCtrl.cpp")
    progress_seams = read_app_source("UploadPartProgressSeams.h")
    project_source = read_app_source("emule.vcxproj")
    upload_localize = upload_list_source[
        upload_list_source.index("void CUploadListCtrl::Localize") :
        upload_list_source.index("void CUploadListCtrl::OnSysColorChange")
    ]
    queue_localize = queue_list_source[
        queue_list_source.index("void CQueueListCtrl::Localize") :
        queue_list_source.index("void CQueueListCtrl::OnSysColorChange")
    ]
    upload_draw = upload_list_source[
        upload_list_source.index("void CUploadListCtrl::DrawItem") :
        upload_list_source.index("CString  CUploadListCtrl::GetItemDisplayText")
    ]
    queue_draw = queue_list_source[
        queue_list_source.index("void CQueueListCtrl::DrawItem") :
        queue_list_source.index("CString CQueueListCtrl::GetItemDisplayText")
    ]

    for source, new_column in ((upload_list_source, "InsertColumn(22"), (queue_list_source, "InsertColumn(22")):
        assert "CString FormatUploadPartProgressText" in source
        assert '"%u / %u"' in source
        assert "client->HasUpPartStatusReported()" in source
        assert 'strText = _T("-");' in source
        assert "GetUpAvailablePartCount()" in source
        assert new_column in source
        assert "case 22:" in source

    assert "IDS_EFFECTIVE_SCORE, IDS_DL_PROGRESS, IDS_GEOLOCATION" in upload_localize
    assert "IDS_CLIENT_HASH, IDS_PERCENTAGE, IDS_FILE_SIZE" in upload_localize
    assert "IDS_COOLDOWN, IDS_DL_PROGRESS, IDS_GEOLOCATION" in queue_localize
    assert "client->DrawUpStatusBar(dc, &rcItem, false, thePrefs.UseFlatBar());" in upload_draw
    assert "client->DrawUpStatusBar(dc, &rcItem, false, thePrefs.UseFlatBar());" in queue_draw
    assert '<ClInclude Include="UploadPartProgressSeams.h" />' in project_source
    assert "inline uint64 GetEstimatedProgressBytes" in progress_seams
    assert "inline double GetProgressPercent" in progress_seams
    assert "inline CString FormatProgressPercentText" in progress_seams
    assert "inline uint64 GetMissingBytes" in progress_seams
    assert "const uint64 uBaseline = min(client->GetUpPartStatusSessionUpBaseline(), uSessionBytes);" in progress_seams
    assert "uEstimatedBytes += uSessionBytes - uBaseline;" in progress_seams
    assert "if (fPercent > 0.0)" in progress_seams
    for source, draw in ((upload_list_source, upload_draw), (queue_list_source, queue_draw)):
        assert "GetUpAvailablePartCount()" in source
        assert '#include "UploadPartProgressSeams.h"' in source
        assert "UploadPartProgressSeams::FormatProgressPercentText" in source
        assert "DrawCenteredTransferBarPercent" in source
        assert '"TransferBarPercentFg"' in source
        assert "if (thePrefs.GetUseDwlPercentage())" in draw
        assert "DrawCenteredTransferBarPercent(dc, rcItem, client, file);" in draw
        assert "GetUploadPartBytesForPart" not in source
        assert "GetReportedUploadPartProgressBytes" not in source
        assert "GetEstimatedUploadPartProgressBytes" not in source
        assert "FormatUploadPartProgressPercentText" not in source

    upload_percent_display = upload_list_source[
        upload_list_source.index("case 18:", upload_list_source.index("CString  CUploadListCtrl::GetItemDisplayText")) :
        upload_list_source.index("case 19:", upload_list_source.index("CString  CUploadListCtrl::GetItemDisplayText"))
    ]
    upload_percent_sort = upload_list_source[
        upload_list_source.index("case 18:", upload_list_source.index("int CALLBACK CUploadListCtrl::SortProc")) :
        upload_list_source.index("case 19:", upload_list_source.index("int CALLBACK CUploadListCtrl::SortProc"))
    ]
    upload_progress_sort = upload_list_source[
        upload_list_source.index("case 11:", upload_list_source.index("int CALLBACK CUploadListCtrl::SortProc")) :
        upload_list_source.index("case 22:", upload_list_source.index("int CALLBACK CUploadListCtrl::SortProc"))
    ]
    queue_progress_sort = queue_list_source[
        queue_list_source.index("case 13:", queue_list_source.index("int CALLBACK CQueueListCtrl::SortProc")) :
        queue_list_source.index("case 22:", queue_list_source.index("int CALLBACK CQueueListCtrl::SortProc"))
    ]
    assert "sText = UploadPartProgressSeams::FormatProgressPercentText(client, GetUploadClientFile(client));" in upload_percent_display
    assert "inline int GetProgressPercentSortValue" in progress_seams
    assert "inline int CompareProgressPercent" in progress_seams
    assert "return static_cast<int>(fPercent * 10.0 + 0.5);" in progress_seams
    assert "UploadPartProgressSeams::CompareProgressPercent(item1, GetUploadClientFile(item1), item2, GetUploadClientFile(item2))" in upload_progress_sort
    assert "UploadPartProgressSeams::CompareProgressPercent(item1, GetUploadClientFile(item1), item2, GetUploadClientFile(item2))" in upload_percent_sort
    assert "CompareUnsigned(item1->GetUpPartCount(), item2->GetUpPartCount())" not in upload_progress_sort
    assert "GetProgressPercent(item1" not in upload_percent_sort
    assert "GetProgressPercent(item2" not in upload_percent_sort
    assert "UploadPartProgressSeams::CompareProgressPercent(item1, GetQueueClientFile(item1), item2, GetQueueClientFile(item2))" in queue_progress_sort
    assert "CompareUnsigned(item1->GetUpPartCount(), item2->GetUpPartCount())" not in queue_progress_sort
    assert "GetSessionUp()" not in upload_percent_display


def test_upload_eta_and_percent_use_same_estimated_obtained_bytes() -> None:
    upload_list_source = read_app_source("UploadListCtrl.cpp")
    progress_seams = read_app_source("UploadPartProgressSeams.h")
    upload_eta_display = upload_list_source[
        upload_list_source.index("case 20:", upload_list_source.index("CString  CUploadListCtrl::GetItemDisplayText")) :
        upload_list_source.index("case 21:", upload_list_source.index("CString  CUploadListCtrl::GetItemDisplayText"))
    ]
    upload_eta_sort = upload_list_source[
        upload_list_source.index("case 20:", upload_list_source.index("int CALLBACK CUploadListCtrl::SortProc")) :
        upload_list_source.index("case 21:", upload_list_source.index("int CALLBACK CUploadListCtrl::SortProc"))
    ]

    assert "inline uint64 GetEstimatedProgressBytes" in progress_seams
    assert "inline uint64 GetMissingBytes" in progress_seams
    assert "const uint64 uEstimatedBytes = GetEstimatedProgressBytes(client, file);" in progress_seams
    assert "return uEstimatedBytes < uFileSize ? uFileSize - uEstimatedBytes : 0;" in progress_seams
    assert "client->IsUpPartAvailable(uPart)" in progress_seams
    assert "uint64 GetMissingBytes" not in upload_list_source
    assert "UploadPartProgressSeams::GetMissingBytes(client, file)" in upload_list_source
    assert "uint64 GetUploadClientCompletionEtaSeconds" in upload_list_source
    assert "(uMissingBytes + uDataRate - 1) / uDataRate" in upload_list_source
    assert "GetUploadClientCompletionEtaSeconds(client, file)" in upload_eta_display
    assert "GetUploadClientCompletionEtaSeconds(item1, file1)" in upload_eta_sort
    assert "GetUploadClientCompletionEtaSeconds(item2, file2)" in upload_eta_sort
    assert "GetSessionUp()" not in upload_eta_display


def test_upload_part_status_report_flag_tracks_protocol_bitmap_presence() -> None:
    client_header = read_app_source("UpDownClient.h")
    base_client_source = read_app_source("BaseClient.cpp")
    upload_client_source = read_app_source("UploadClient.cpp")
    process_extended_info = upload_client_source[
        upload_client_source.index("bool CUpDownClient::ProcessExtendedInfo") :
        upload_client_source.index("void CUpDownClient::SetUploadFileID")
    ]
    set_upload_file_id = upload_client_source[
        upload_client_source.index("void CUpDownClient::SetUploadFileID") :
        upload_client_source.index("void CUpDownClient::AddReqBlock")
    ]

    assert "HasUpPartStatusReported() const" in client_header
    assert "GetUpPartStatusSessionUpBaseline() const" in client_header
    assert "m_bUpPartStatusReported;" in client_header
    assert "m_nUpPartStatusSessionUpBaseline;" in client_header
    assert "m_bUpPartStatusReported = false;" in base_client_source
    assert "m_nUpPartStatusSessionUpBaseline = 0;" in base_client_source
    assert "m_bUpPartStatusReported = false;" in process_extended_info
    assert "m_nUpPartStatusSessionUpBaseline = 0;" in process_extended_info
    no_bitmap_block = process_extended_info[
        process_extended_info.index("if (!nED2KUpPartCount)") :
        process_extended_info.index("} else {")
    ]
    bitmap_block = process_extended_info[
        process_extended_info.index("} else {") :
        process_extended_info.index("if (GetExtendedRequestsVersion() > 1)")
    ]
    assert "m_bUpPartStatusReported = true;" not in no_bitmap_block
    assert "m_bUpPartStatusReported = true;" in bitmap_block
    assert "m_nUpPartStatusSessionUpBaseline = GetSessionUp();" in bitmap_block
    assert "m_bUpPartStatusReported = false;" in set_upload_file_id
    assert "m_nUpPartStatusSessionUpBaseline = 0;" in set_upload_file_id
