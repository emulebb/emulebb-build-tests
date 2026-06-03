from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_upload_slot_instrumentation_reports_cooldown_pressure() -> None:
    source = read_app_source("UploadQueue.cpp")
    header = read_app_source("UploadQueue.h")
    block = source[source.index("void CUploadQueue::LogUploadSlotInstrumentation") : source.index("void CUploadQueue::Process()")]

    assert "waitingCooldownMinMs=%I64u" in block
    assert "waitingCooldownAvgMs=%I64u" in block
    assert "waitingCooldownMaxMs=%I64u" in block
    assert "waitingRetryCooldown=%Id" in block
    assert "waitingNoRequestCooldown=%Id" in block
    assert "waitingClientOnlyCooldown=%Id" in block
    assert "waitingRetryNoRequest=%Id" in block
    assert "waitingRetryChurn=%Id" in block
    assert "waitingRetryStalled=%Id" in block
    assert "waitingRetrySlow=%Id" in block
    assert "waitingRetryUnknown=%Id" in block
    assert "retryCooldowns=%u" in block
    assert "noRequestCooldowns=%u" in block
    assert "GetSlowUploadCooldownRemaining()" in block
    assert "GetUploadRetryCooldownIP(pWaitingClient)" in block
    assert "ullCooldownUntil > curTick" in block
    assert "itRetryCooldown->second.eReason" in block
    assert "m_uploadRetryCooldownByIP.size()" in block
    assert "m_noRequestUploadRetryCooldownByIP.size()" in block
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
        queue_source.index("bool CUploadQueue::TryAdmitQueuedBlockRequestClient") :
        queue_source.index("void CUploadQueue::PurgeExpiredUploadRetryCooldowns")
    ]

    assert "TryAdmitQueuedBlockRequestClient(CUpDownClient *client, bool bQueuedRequestCooldownCleared)" in queue_header
    assert "ShouldAdmitQueuedBlockRequestToUploadSlot" in seams_header
    assert "const bool bCooldownCleared = theApp.uploadqueue->ClearUploadRetryCooldown(this);" in not_uploading_block
    assert "TryAdmitQueuedBlockRequestClient(this, bCooldownCleared)" in not_uploading_block
    assert "accept-queued-request-direct-admit" in not_uploading_block
    assert "reject-not-uploading" in not_uploading_block
    assert not_uploading_block.index("accept-queued-request-direct-admit") < not_uploading_block.index("reject-not-uploading")
    assert "AcceptNewClient(uploadinglist.GetCount())" in direct_admit_block
    assert "ForceNewClient(true)" in direct_admit_block
    assert "AddUpNextClient(_T(\"Direct add after queued block request.\"), client)" in direct_admit_block
