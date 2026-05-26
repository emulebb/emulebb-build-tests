from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_out_of_part_reqs_packet_uses_client_owned_handler() -> None:
    listen_socket = read_app_source("ListenSocket.cpp")
    block = listen_socket[
        listen_socket.index("case OP_OUTOFPARTREQS:") :
        listen_socket.index("case OP_CHANGE_CLIENT_ID:")
    ]

    assert "client->ProcessInboundOutOfPartReqs();" in block
    assert "client->SetDownloadState(DS_ONQUEUE" not in block


def test_inbound_out_of_part_reqs_records_before_download_state_demotion() -> None:
    download_client = read_app_source("DownloadClient.cpp")
    block = download_client[
        download_client.index("void CUpDownClient::ProcessInboundOutOfPartReqs()") :
        download_client.index("void CUpDownClient::ProcessAcceptUpload()")
    ]

    assert "if (GetDownloadState() != DS_DOWNLOADING)\n\t\treturn;" in block
    assert block.index("NoteInboundOutOfPartReqs();") < block.index("SetDownloadState(DS_ONQUEUE")


def test_accept_upload_checks_out_of_part_reqs_guard_before_start_download() -> None:
    download_client = read_app_source("DownloadClient.cpp")
    block = download_client[
        download_client.index("void CUpDownClient::ProcessAcceptUpload()") :
        download_client.index("void CUpDownClient::ProcessEdonkeyQueueRank")
    ]

    assert block.index("CanAcceptUploadSlotAfterOutOfPartReqs(&strOutOfPartReqsGuardReason)") < block.index("StartDownload();")
    assert block.index("return;") < block.index("StartDownload();")
    assert "if (socket != NULL && IsEd2kClient())\n\t\t\t\t\tSendCancelTransfer();" in block
    assert block.index("SetSentCancelTransfer(0);") > block.index("CanAcceptUploadSlotAfterOutOfPartReqs")


def test_out_of_part_reqs_guard_thresholds_are_balanced_and_client_global() -> None:
    header = read_app_source("UpdownClient.h")
    download_client = read_app_source("DownloadClient.cpp")

    assert "Client-global, app-session guard" in header
    assert "constexpr UINT kOutOfPartReqsCooldownThreshold = 3;" in download_client
    assert "constexpr ULONGLONG kOutOfPartReqsShortWindowMs = SEC2MS(30);" in download_client
    assert "constexpr ULONGLONG kOutOfPartReqsCooldownMs = MIN2MS(2);" in download_client
    assert "constexpr UINT kOutOfPartReqsCooldownBurstQuarantineThreshold = 2;" in download_client
    assert "constexpr UINT kOutOfPartReqsQuarantineThreshold = 10;" in download_client
    assert "constexpr ULONGLONG kOutOfPartReqsLongWindowMs = MIN2MS(5);" in download_client
    assert "m_bOutOfPartReqsQuarantined = true;" in download_client
    assert "m_ullOutOfPartReqsCooldownUntil = 0;" in download_client
    assert "m_uOutOfPartReqsCooldownBurstCount = 0;" in download_client
    assert "++m_uOutOfPartReqsCooldownBurstCount;" in download_client
    assert "void CUpDownClient::NoteOutOfPartReqsLoopSuppression()" in download_client
    assert "NoteOutOfPartReqsLoopSuppression();" in download_client
    assert "ResetOutOfPartReqsLoopGuard();" in read_app_source("BaseClient.cpp")


def test_out_of_part_reqs_guard_logs_transitions_and_suppression_with_context() -> None:
    download_client = read_app_source("DownloadClient.cpp")

    assert "DebugLogWarning(_T(\"Cooling down download source after repeated OP_OutOfPartReqs loops." in download_client
    assert "DebugLogWarning(_T(\"Quarantined download source after repeated OP_OutOfPartReqs loops." in download_client
    assert "DebugLogWarning(_T(\"Quarantined download source after repeated OP_OutOfPartReqs cooldown bursts." in download_client
    assert "DebugLogWarning(_T(\"Quarantined download source after repeated suppressed OP_AcceptUploadReq during OP_OutOfPartReqs cooldown." in download_client
    assert "DebugLog(_T(\"Suppressed OP_AcceptUploadReq after repeated OP_OutOfPartReqs loops." in download_client
    assert "constexpr ULONGLONG kOutOfPartReqsSuppressionLogMs = SEC2MS(30);" in download_client
    assert "m_ullOutOfPartReqsLastSuppressionLog" in download_client
    assert download_client.count("DbgGetClientInfo()") >= 3
