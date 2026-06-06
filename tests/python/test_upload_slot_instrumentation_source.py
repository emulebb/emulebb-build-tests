from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_upload_slot_instrumentation_reports_cooldown_pressure() -> None:
    source = read_app_source("UploadQueue.cpp")
    header = read_app_source("UploadQueue.h")
    seams_header = read_app_source("UploadQueueSeams.h")
    block = source[source.index("void CUploadQueue::LogUploadSlotInstrumentation") : source.index("void CUploadQueue::Process()")]

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
    assert "const UINT uCooldownSeconds = GetNoRequestUploadRetryCooldownSeconds" in no_request_recycle_block
    assert "const ULONGLONG ullCooldownUntil = curTick + SEC2MS(uCooldownSeconds);" in no_request_recycle_block
    assert "const ULONGLONG ullTrackUntil = curTick + SEC2MS(GetNoRequestUploadRetryTrackSeconds(uCooldownSeconds, uConfiguredCooldownSeconds));" in no_request_recycle_block
    no_request_cooldown_start = no_request_recycle_block.index("const UINT uCooldownSeconds")
    no_request_cooldown_block = no_request_recycle_block[
        no_request_cooldown_start :
        no_request_recycle_block.index("client->SetSlowUploadCooldownUntil", no_request_cooldown_start)
    ]
    assert no_request_cooldown_block.index("const UINT uCooldownSeconds") < no_request_cooldown_block.index("const ULONGLONG ullCooldownUntil")
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

    assert "GetUploadChurnRetryCooldownSeconds(thePrefs.GetSlowUploadCooldownSeconds())" in stalled_block
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


def test_upload_part_status_columns_report_requester_parts() -> None:
    upload_list_source = read_app_source("UploadListCtrl.cpp")
    queue_list_source = read_app_source("QueueListCtrl.cpp")

    for source in (upload_list_source, queue_list_source):
        assert "CString FormatUploadPartProgressText" in source
        assert '"%u / %u"' in source
        assert "GetUpAvailablePartCount()" in source
        assert "DrawCenteredBarText(dc, FormatUploadPartProgressText(client), rcItem)" in source
