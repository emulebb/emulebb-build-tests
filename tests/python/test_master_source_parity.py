"""Data-driven eMuleBB master C++ source-parity suite.

This module consolidates the formerly separate ``tests/python/test_*_source.py``
files (one per master source unit) into a single parametrized suite. Each former
test function is preserved verbatim and registered as one parametrized case, so
every assertion that previously ran still runs here -- no coverage is lost. The
duplicated path/read boilerplate that each old module re-declared now comes from
``emule_test_harness.master_source``.
"""

from __future__ import annotations

import re  # noqa: F401  (used by some consolidated checks)
import xml.etree.ElementTree as ET  # noqa: F401  (used by some consolidated checks)
from pathlib import Path  # noqa: F401  (used by some consolidated checks)

import pytest

from emule_test_harness.master_source import (
    app_root,
    app_source_root,
    build_root,
    read_app_source,
    workspace_root,
)

# Compatibility aliases for the path constants the former modules referenced at
# module scope; the consolidated check bodies are kept verbatim.
WORKSPACE_ROOT = workspace_root()
APP_ROOT = app_root()
SRC_ROOT = app_source_root()
BUILD_ROOT = build_root()


# --- consolidated from tests/python/test_aich_sync_thread_source.py ---


def _check_aich_sync_thread_source__aich_sync_thread_is_owned_and_joined_before_shared_file_teardown() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "EmuleDlg.h").read_text(encoding="utf-8", errors="ignore")

    assert "CWinThread\t\t*m_pAICHSyncThread;" in header
    assert "void StartAICHSyncThread();" in header
    assert "void WaitForAICHSyncThreadShutdown();" in header
    assert "void CemuleDlg::StartAICHSyncThread()" in source
    assert "AfxBeginThread(RUNTIME_CLASS(CAICHSyncThread), THREAD_PRIORITY_IDLE, 0, CREATE_SUSPENDED)" in source
    assert "HelperThreadLaunchSeams::OwnAndResumeSuspendedThread(m_pAICHSyncThread, pThread, dwResumeError)" in source
    assert "void CemuleDlg::WaitForAICHSyncThreadShutdown()" in source
    assert "::WaitForSingleObject(hThread, kAICHSyncThreadShutdownWaitMs)" in source
    assert "::WaitForSingleObject(hThread, INFINITE)" in source
    assert "AfxBeginThread(RUNTIME_CLASS(CAICHSyncThread), THREAD_PRIORITY_IDLE, 0);" not in source
    assert source.index("WaitForAICHSyncThreadShutdown();") < source.index("ShutdownSharedHashWorkerStep")


def _check_aich_sync_thread_source__aich_sync_worker_guards_shared_and_known_file_globals() -> None:
    source = (app_source_root() / "AICHSyncThread.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ResolveSharedAICHSyncFileNoLock(CSharedFileList *pSharedFiles" in source
    assert "if (pSharedFiles == NULL || theApp.IsClosing())" in source
    assert "CSingleLock sharelock(&pSharedFiles->m_mutWriteList, TRUE);" in source
    assert "theApp.knownfiles != NULL && theApp.knownfiles->ShouldPurgeAICHHashset(aichHash)" in source
    assert "if (theApp.IsClosing() || pSharedFiles == NULL)\n\t\t\t\t\treturn 0;" in source
    assert "CSingleLock hashingLock(&theApp.hashing_mut); // only one file hash at a time" in source
    assert "while (!hashingLock.Lock(kAICHSyncHashingLockPollMs))" in source
    assert "if (theApp.IsClosing())\n\t\t\t\t\treturn 0;" in source
    assert "theApp.sharedfiles->m_mutWriteList" not in source
    assert "theApp.sharedfiles->GetHashingCount()" not in source


def _check_aich_sync_thread_source__known2_met_recovery_truncate_failure_logs_exception_details() -> None:
    source = (app_source_root() / "AICHSyncThread.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("LogError(LOG_STATUSBAR, GetResString(IDS_ERR_MET_BAD), KNOWN2_MET_FILENAME);") : source.index("ex->Delete();")]

    assert '#include "OtherFunctions.h"' in source
    assert 'DebugLogError(_T("Failed to truncate corrupt %s to byte %I64u%s"), KNOWN2_MET_FILENAME, ullLastVerifiedPos, (LPCTSTR)CExceptionStrDash(*ex2));' in block
    assert block.index("CExceptionStrDash(*ex2)") < block.index("ex2->Delete();")


def _check_aich_sync_thread_source__aich_known2_rewrite_uses_exact_reads_and_owned_buffers() -> None:
    source = (app_source_root() / "AICHSyncThread.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "#include <limits>" in source
    assert "#include <vector>" in source
    assert "UINT GetAICHHashsetPayloadByteCount(CFile &file, const uint32 nHashCount)" in source
    assert "(std::numeric_limits<UINT>::max)()" in source
    assert "void ReadAICHHashsetPayloadExact(CFile &file, std::vector<BYTE> &rBuffer, const UINT uBytes)" in source
    assert "const UINT uActualRead = file.Read(rBuffer.data(), uBytes);" in source
    assert "if (uActualRead != uBytes)\n\t\t\tAfxThrowFileException(CFileException::endOfFile, 0, file.GetFilePath());" in source
    assert source.count("std::vector<BYTE> buffer;") == 2
    assert source.count("ReadAICHHashsetPayloadExact(") == 3
    assert "BYTE *buffer = new BYTE[nHashCount * (size_t)CAICHHash::GetHashSize()];" not in source
    assert "delete[] buffer;" not in source
    assert "file.Read(buffer, nHashCount * CAICHHash::GetHashSize());" not in source
    assert "oldfile.Read(buffer, nHashCount * CAICHHash::GetHashSize());" not in source


# --- consolidated from tests/python/test_async_socket_ex_layer_source.py ---


def _check_async_socket_ex_layer_source__layered_sockets_apply_configured_bind_interface_after_bind() -> None:
    source = (app_source_root() / "AsyncSocketExLayer.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "Bind(m_nSocketPort, m_sSocketAddress) || !m_pOwnerSocket->ApplyConfiguredIpv4UnicastInterface()" in source
    assert "Bind(nSocketPort, sSocketAddress) || !m_pOwnerSocket->ApplyConfiguredIpv4UnicastInterface()" in source
    assert "Bind(m_nSocketPort, m_sSocketAddress) && m_pOwnerSocket->ApplyConfiguredIpv4UnicastInterface()" in source


# --- consolidated from tests/python/test_async_socket_ex_source.py ---


def _check_async_socket_ex_source__connect_completion_revalidates_socket_after_on_connect_callback() -> None:
    source = (APP_ROOT / "srchybrid" / "AsyncSocketEx.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool IsCurrentSocket(const CAsyncSocketEx *pSocket, int nSocketIndex, SOCKET hSocket) const" in source
    assert "pSocket->OnConnect(nErrorCode);\n\t\t\t\t\t\t\t// WHY: server connect failures can synchronously" in source
    assert "if (!pWnd->IsCurrentSocket(pSocket, nSocketIndex, hSocket))\n\t\t\t\t\t\t\t\tbreak;" in source
    assert "if (pWnd->IsCurrentSocket(pSocket, nSocketIndex, hSocket))\n\t\t\t\t\t\t\tpSocket->m_nPendingEvents = 0;" in source
    assert "pSocket->OnConnect(nErrorCode);\n\t\t\t\t\t\t\t// WHY: OnConnect handlers may close and delete" in source
    assert "if (!pWnd->IsCurrentSocket(pSocket, nSocketIndex, pMsg->hSocket))\n\t\t\t\t\t\t\t\tbreak;" in source
    assert "if (pWnd->IsCurrentSocket(pSocket, nSocketIndex, pMsg->hSocket))\n\t\t\t\t\t\t\tpSocket->m_nPendingEvents = 0;" in source


# --- consolidated from tests/python/test_bad_peer_diagnostics_source.py ---


def _check_bad_peer_diagnostics_source__bad_peer_diagnostics_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:BadPeerDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableBadPeerDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_BAD_PEER_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(BadPeerDiagnosticsPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(DownloadSlotDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "$(BadPeerDiagnosticsPreprocessorDefinition)"
        )
        assert config_definitions.index("$(BadPeerDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def _check_bad_peer_diagnostics_source__bad_peer_diagnostics_build_and_release_plumbing() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")
    release_source = (BUILD_ROOT / "emule_workspace" / "release.py").read_text(encoding="utf-8")

    assert '"EMULEBB_ENABLE_BAD_PEER_DIAGNOSTICS", "EnableBadPeerDiagnostics"' in build_source
    assert 'extra_properties.append(f"/p:{property_name}=' in build_source
    assert "BAD_PEER_DIAGNOSTICS_BINARY_MARKERS" in release_source
    assert "emulebb-diagnostics-bad-peer.log" in release_source
    assert "enable_bad_peer_diagnostics" in release_source


def _check_bad_peer_diagnostics_source__bad_peer_diagnostics_logger_is_compile_gated() -> None:
    header = read_app_source("BadPeerDiagnosticsSeams.h")
    source = read_app_source("BadPeerDiagnosticsSeams.cpp")
    artifact_names = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")

    assert "constexpr LPCTSTR kBinaryMarker = _T(\"BadPeerDiagnostics:\");" in header
    assert "#if EMULEBB_HAS_BAD_PEER_DIAGNOSTICS" in header
    assert "inline void LogClientEvent" in header
    assert "inline void LogIpEvent" in header
    assert "inline void LogSearchEvent" in header
    assert "inline void LogUploadBlockRequestBehavior" in header
    assert "inline void TrackUploadFileBehavior" in header
    assert "CLogFile g_badPeerDiagnosticsLog;" in source
    assert "g_badPeerBehaviorLedger" in source
    assert "kBadPeerBehaviorLedgerWindowMs = MIN2MS(60)" in source
    assert "LogUploadBlockRequestBehavior" in source
    assert "TrackUploadFileBehavior" in source
    assert "bad_peer_event_v1" in source
    assert "InitializeDiagnosticsLog(g_badPeerDiagnosticsLog, pszLogPath, uMaxLogFileSize)" in source
    assert "WriteDiagnosticsJsonEvent(" in source
    assert "g_badPeerDiagnosticsLogLock" in source
    assert "BadPeerDiagnosticsLogFileName" in artifact_names
    assert 'return _T("emulebb-diagnostics-bad-peer.log");' in artifact_names
    assert "BadPeerDiagnosticsSeams::InitializeLog" in app_source


def _check_bad_peer_diagnostics_source__bad_peer_diagnostics_covers_evidence_categories() -> None:
    joined = "\n".join(
        read_app_source(name)
        for name in (
            "BaseClient.cpp",
            "ClientList.cpp",
            "UploadClient.cpp",
            "DownloadClient.cpp",
            "DownloadQueue.cpp",
            "ListenSocket.cpp",
            "UploadQueue.cpp",
            "BadPeerDiagnosticsSeams.cpp",
            "SearchList.cpp",
            "FakeFileDetector.cpp",
        )
    )

    for event in (
        "identity_userhash_changed",
        "identity_userhash_invalid_collision",
        "tcp_error_flood",
        "file_request_flood",
        "chat_spam_heuristic",
        "client_ban",
        "download_source_file_mismatch",
        "download_first_payload_timeout",
        "download_no_data_slot_cooldown",
        "download_out_of_part_reqs_quarantine",
        "download_queue_rank_flood",
        "download_stale_block_packet_abort",
        "download_accept_suppressed_no_data_cooldown",
        "packet_invalid_multipacket_subopcode",
        "packet_compression_decode_failed",
        "packet_processing_error",
        "packet_unrequested_kad_fw_ack",
        "packet_unknown_edonkey_opcode",
        "packet_unknown_emule_opcode",
        "packet_unknown_client_tcp_packet",
        "upload_queued_request_direct_admit",
        "upload_queued_request_rejected",
        "upload_duplicate_done_block_rejected",
        "upload_duplicate_queued_block_rejected",
        "upload_repeat_block_request_observed",
        "upload_repeat_file_request_observed",
        "upload_no_request_recycle",
        "upload_short_failed_slot_cooldown",
        "upload_zero_rate_recycle",
        "search_spam_detected",
        "fake_file_search_detected",
        "fake_file_part_detected",
    ):
        assert event in joined


def _check_bad_peer_diagnostics_source__bad_peer_diagnostics_tracks_upload_clog_patterns() -> None:
    upload_client = read_app_source("UploadClient.cpp")
    upload_queue = read_app_source("UploadQueue.cpp")

    assert "reject-duplicate-done-block" in upload_client
    assert "_T(\"upload_duplicate_done_block_rejected\")" in upload_client
    assert "reject-duplicate-queued-block" in upload_client
    assert "_T(\"upload_duplicate_queued_block_rejected\")" in upload_client
    assert "BadPeerDiagnosticsSeams::LogUploadBlockRequestBehavior" in upload_client
    assert upload_queue.count("BadPeerDiagnosticsSeams::TrackUploadFileBehavior") >= 6
    for behavior in (
        "failed_admission",
        "no_socket",
        "no_request",
        "idle_no_request",
        "stalled_zero_rate",
        "short_failed_slot",
        "zero_rate",
        "slow_rate",
    ):
        assert f'_T("{behavior}")' in upload_queue


# --- consolidated from tests/python/test_bad_peer_repeat_policy_source.py ---


def _h_bad_peer_repeat_policy_source__read_tooling_file(name: str) -> str:
    return (Path(__file__).resolve().parents[4] / "repos" / "emulebb-tooling" / name).read_text(encoding="utf-8", errors="ignore")


def _check_bad_peer_repeat_policy_source__repeated_no_request_policy_is_configured_hash_aware_and_bounded() -> None:
    seams = read_app_source("UploadQueueSeams.h")
    queue_header = read_app_source("UploadQueue.h")
    queue_source = read_app_source("UploadQueue.cpp")
    client_list_header = read_app_source("ClientList.h")
    client_list_source = read_app_source("ClientList.cpp")
    client_state_header = read_app_source("ClientStateDefs.h")
    ban_menu_header = read_app_source("ClientBanMenuSeams.h")
    base_client_source = read_app_source("BaseClient.cpp")
    listen_socket_source = read_app_source("ListenSocket.cpp")
    listen_socket_header = read_app_source("ListenSocket.h")
    upload_client_source = read_app_source("UploadClient.cpp")
    project_source = read_app_source("emule.vcxproj")
    opcodes = read_app_source("Opcodes.h")

    assert "#define CLIENTBANTIME\t\t\tHR2MS(4)\t// 4h" in opcodes
    assert "kNoRequestRepeatStrikeWindowSeconds = 4u * 60u * 60u" in seams
    assert "kNoRequestRepeatBanThreshold = 8u" in seams
    assert "kBroadbandNoRequestRepeatBanThreshold = 16u" in seams
    assert "kNoRequestRepeatHashRotationBanThreshold = 3u" in seams
    assert "kNoRequestRepeatHashRotationStrikeThreshold = 5u" in seams
    assert "kNoRequestRepeatCooldownMaxSeconds = 60u * 60u" in seams
    assert "kNoRequestRepeatCleanupIntervalSeconds = 60u" in seams
    assert "GetNoRequestRepeatBanThresholdForBudget(" in seams
    assert "GetNoRequestRepeatCooldownSeconds(" in seams
    assert "ullCooldownSeconds = uBaseCooldownSeconds;" in seams
    assert "ullCooldownSeconds *= 2u;" in seams
    assert "ShouldBanNoRequestRepeatOffender(" in seams

    assert "enum ClientBanScope : uint8" in client_state_header
    assert "clientBanScopeHash" in client_state_header
    assert "clientBanScopeIP" in client_state_header
    assert "clientBanScopeBoth" in client_state_header

    assert "std::map<NoRequestRepeatHashKey, NoRequestRepeatOffenderState> m_noRequestRepeatOffendersByHash;" in queue_header
    assert "std::map<uint32, NoRequestRepeatOffenderState> m_noRequestRepeatOffendersByIP;" in queue_header
    assert "std::map<uint32, NoRequestRepeatIPHashState> m_noRequestRepeatHashesByIP;" in queue_header
    assert "ULONGLONG m_ullLastNoRequestRepeatCleanup;" in queue_header
    assert "UINT uTotalStrikes;" in queue_header
    assert "UINT uIPRotationStrikes;" in queue_header
    assert "TrackNoRequestRepeatOffender(CUpDownClient *client, ULONGLONG curTick, UINT uBaseCooldownSeconds, UINT uMaxCooldownSeconds, UINT uBanThreshold)" in queue_header
    assert "m_noRequestRepeatOffendersByHash[key]" in queue_source
    assert "m_noRequestRepeatOffendersByIP[dwCooldownIP]" in queue_source
    assert "m_noRequestRepeatHashesByIP[dwCooldownIP]" in queue_source
    assert "++ipHashState.uTotalStrikes;" in queue_source
    assert "penalty.uIPRotationStrikes = ipHashState.uTotalStrikes;" in queue_source
    assert "penalty.bShouldIPBan = penalty.uDistinctIPHashes >= kNoRequestRepeatHashRotationBanThreshold\n\t\t\t\t&& penalty.uIPRotationStrikes >= kNoRequestRepeatHashRotationStrikeThreshold;" in queue_source
    assert "penalty.bShouldBan = ShouldBanNoRequestRepeatOffender(penalty.uStrikes, uBanThreshold);" in queue_source
    assert "client->Ban(repeatPenalty.bShouldIPBan" in queue_source
    assert "repeatPenalty.bShouldIPBan ? clientBanScopeBoth : clientBanScopeHash" in queue_source
    assert "GetNoRequestRepeatBaseCooldownSeconds(" not in seams
    assert "const UINT uBaseCooldownSeconds = uConfiguredCooldownSeconds;" in queue_source
    assert "const UINT uRepeatCooldownMaxSeconds = GetRepeatedNoRequestUploadCooldownMaxSecondsForBudget(uBudgetBytesPerSec);" in queue_source
    assert "const UINT uRepeatBanThreshold = GetNoRequestRepeatBanThresholdForBudget(uBudgetBytesPerSec);" in queue_source
    assert "TrackNoRequestRepeatOffender(client, curTick, uBaseCooldownSeconds, uRepeatCooldownMaxSeconds, uRepeatBanThreshold)" in queue_source
    assert "uRepeatBanThreshold," in queue_source
    assert "GetNoRequestRepeatCooldownSeconds(uBaseCooldownSeconds, penalty.uStrikes, uMaxCooldownSeconds)" in queue_source
    assert "m_ullLastNoRequestRepeatCleanup + SEC2MS(kNoRequestRepeatCleanupIntervalSeconds)" in queue_source
    assert "m_ullLastNoRequestRepeatCleanup = curTick;" in queue_source

    assert "void\tAddBannedClient(const CUpDownClient *pClient, ClientBanScope eScope = clientBanScopeHash);" in client_list_header
    assert "bool\tIsBannedClient(const CUpDownClient *pClient) const;" in client_list_header
    assert "bool\tIsBannedClient(const CUpDownClient *pClient, ClientBanScope eScope) const;" in client_list_header
    assert "void\tRemoveBannedClient(const CUpDownClient *pClient, ClientBanScope eScope = clientBanScopeBoth);" in client_list_header
    assert "CMap<CSKey, const CSKey&, ULONGLONG, ULONGLONG> m_bannedHashList;" in client_list_header
    assert "void CClientList::AddBannedClient(const CUpDownClient *pClient, ClientBanScope eScope)" in client_list_source
    assert "const bool bBanHash = pClient->HasValidHash()" in client_list_source
    assert "const bool bBanIP = eScope == clientBanScopeIP || eScope == clientBanScopeBoth || !bBanHash;" in client_list_source
    assert "m_bannedHashList[CSKey(pClient->GetUserHash())]" in client_list_source
    assert "m_bannedHashList.GetCount() != 0\n\t\t&& pClient->HasValidHash()" in client_list_source
    assert "m_bannedHashList.Lookup(CSKey(pClient->GetUserHash()), dwBantime)" in client_list_source
    assert "bool CClientList::IsBannedClient(const CUpDownClient *pClient, ClientBanScope eScope) const" in client_list_source
    assert "const bool bCheckHash = pClient->HasValidHash()" in client_list_source
    assert "const bool bCheckIP = eScope == clientBanScopeIP || eScope == clientBanScopeBoth || !bCheckHash;" in client_list_source
    assert "return (!bCheckHash || bHashBanned) && (!bCheckIP || bIPBanned) && (bCheckHash || bCheckIP);" in client_list_source
    assert "m_bannedHashList.RemoveKey(CSKey(pClient->GetUserHash()))" in client_list_source
    assert "m_bannedHashList.RemoveAll();" in client_list_source
    assert "m_bannedHashList.GetStartPosition()" in client_list_source
    assert '<ClInclude Include="ClientBanMenuSeams.h" />' in project_source
    assert "inline bool CanBanByHash(const CUpDownClient *pClient)" in ban_menu_header
    assert "inline bool CanBanByIP(const CUpDownClient *pClient)" in ban_menu_header
    assert "pClient->HasValidHash()" in ban_menu_header
    assert "pClient->GetIP() != 0" in ban_menu_header
    assert "theApp.clientlist->IsBannedClient(pClient, clientBanScopeHash)" in ban_menu_header
    assert "theApp.clientlist->IsBannedClient(pClient, clientBanScopeIP)" in ban_menu_header
    assert "pClient->Ban(pszReason, clientBanScopeHash);" in ban_menu_header
    assert "pClient->Ban(pszReason, clientBanScopeIP);" in ban_menu_header

    assert "theApp.clientlist->IsBannedClient(this) || theApp.clientlist->IsBannedClient(uClientIP)" in base_client_source
    assert "return theApp.clientlist->IsBannedClient(this);" in base_client_source
    assert "void CUpDownClient::Ban(LPCTSTR pszReason, ClientBanScope eScope)" in upload_client_source
    assert "LPCTSTR GetClientBanScopeDiagnosticsToken(const CUpDownClient *pClient, ClientBanScope eScope)" in upload_client_source
    assert "strBanEvidence.Format(_T(\"{\\\"scope\\\":\\\"%s\\\"}\"), GetClientBanScopeDiagnosticsToken(this, eScope));" in upload_client_source
    assert "const bool bRequestedScopeAlreadyBanned = theApp.clientlist->IsBannedClient(this, eScope);" in upload_client_source
    assert "if (!bRequestedScopeAlreadyBanned)" in upload_client_source
    assert "theApp.clientlist->AddBannedClient(this, eScope);" in upload_client_source
    assert "theApp.clientlist->RemoveBannedClient(this);" in upload_client_source
    assert "void\t\t\tBan(LPCTSTR pszReason = NULL, ClientBanScope eScope = clientBanScopeHash);" in read_app_source("UpDownClient.h")
    assert "bool\tDisconnectIfBannedAfterHello(LPCTSTR pszStage, LPCTSTR pszDisconnectReason);" in listen_socket_header
    assert "bool CClientReqSocket::DisconnectIfBannedAfterHello" in listen_socket_source
    assert "Refused banned client after %s %s" in listen_socket_source
    assert "Disconnect(pszDisconnectReason);" in listen_socket_source
    assert "DisconnectIfBannedAfterHello(_T(\"hello answer\"), _T(\"Banned client after hello answer\"))" in listen_socket_source
    assert "DisconnectIfBannedAfterHello(_T(\"hello\"), _T(\"Banned client after hello\"))" in listen_socket_source


def _check_bad_peer_repeat_policy_source__manual_peer_menus_can_ban_hash_or_ip_scope() -> None:
    resources = read_app_source("emule.rc")
    resource_header = read_app_source("Resource.h")
    menu_cmds = read_app_source("MenuCmds.h")
    required_ids = _h_bad_peer_repeat_policy_source__read_tooling_file("helpers/rc-release-localization-ids.txt")

    assert "#define MP_BAN_BY_IP\t\t10463" in menu_cmds
    assert "#define IDS_BAN_BY_HASH                 1717" in resource_header
    assert "#define IDS_BAN_BY_IP                   1718" in resource_header
    assert 'IDS_BAN_BY_HASH         "Ban by &Hash"' in resources
    assert 'IDS_BAN_BY_IP           "Ban by &IP"' in resources
    assert "IDS_BAN_BY_HASH" in required_ids
    assert "IDS_BAN_BY_IP" in required_ids

    for name in (
        "ClientListCtrl.cpp",
        "DownloadClientsCtrl.cpp",
        "DownloadListCtrl.cpp",
        "QueueListCtrl.cpp",
        "UploadListCtrl.cpp",
    ):
        source = read_app_source(name)
        assert '#include "ClientBanMenuSeams.h"' in source
        assert "ClientBanMenuSeams::CanBanByHash(client)" in source
        assert "ClientBanMenuSeams::CanBanByIP(client)" in source
        assert "MP_BAN, GetResString(IDS_BAN_BY_HASH)" in source
        assert "MP_BAN_BY_IP, GetResString(IDS_BAN_BY_IP)" in source
        assert "case MP_BAN_BY_IP:" in source
        assert "ClientBanMenuSeams::BanByHash" in source
        assert "ClientBanMenuSeams::BanByIP" in source

    lang_dir = app_source_root() / "lang"
    language_files = sorted(lang_dir.glob("*.rc"))
    assert len(language_files) == 43
    for path in language_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "IDS_BAN_BY_HASH" in text
        assert "IDS_BAN_BY_IP" in text


# --- consolidated from tests/python/test_bar_shader_source.py ---


def _check_bar_shader_source__bar_shader_restores_empty_span_fallback_before_range_and_draw() -> None:
    source = (app_source_root() / "BarShader.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "BarShader.h").read_text(encoding="utf-8", errors="ignore")

    assert "void EnsureSpanFallback();" in header
    assert "void CBarShader::EnsureSpanFallback()" in source
    assert "if (m_Spans.GetHeadPosition() == NULL)\n\t\tFill(0);" in source
    assert "int count = HALF(max(m_iHeight, 1));" in source
    assert "double increment = count > 1 ? piOverDepth / (count - 1) : 0.0;" in source
    assert "EnsureSpanFallback();\n\tconst uint64 uEndLookup = end != static_cast<uint64>(-1) ? end + 1 : end;" in source
    assert "POSITION endpos = m_Spans.FindFirstKeyAfter(uEndLookup);" in source
    assert "ASSERT(endpos != NULL);\n\tif (endpos == NULL)\n\t\treturn;" in source
    assert "if (m_iWidth <= 0 || m_iHeight <= 0)\n\t\treturn;" in source
    assert "EnsureSpanFallback();\n\n\t//FillSolidRect()" in source
    assert "if (pos == NULL)\n\t\treturn;\n\tCOLORREF color = m_Spans.GetNextValue(pos);" in source
    assert "if (pos == NULL) {\n\t\trectSpan.left = rectSpan.right;" in source


# --- consolidated from tests/python/test_buddy_button_source.py ---


def _check_buddy_button_source__buddy_button_subclass_callback_guards_missing_state() -> None:
    source = (app_source_root() / "BuddyButton.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (pfnOldWndProc == NULL) {" in source
    assert "return ::DefWindowProc(hWnd, uMessage, wParam, lParam);" in source
    assert "if (pBuddyData == NULL) {" in source
    assert "::SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)pfnOldWndProc);" in source
    assert "::RemoveProp(hWnd, s_szPropOldWndProc);" in source
    assert "if (lpNCCS != NULL)\n\t\t\t\tlpNCCS->rgrc[0].right -= pBuddyData->m_uButtonWidth;" in source
    assert "if (pBuddyData->m_hwndButton == NULL || !::IsWindow(pBuddyData->m_hwndButton))\n\t\t\t\tbreak;" in source


def _check_buddy_button_source__add_buddy_button_rolls_back_half_installed_subclass() -> None:
    source = (app_source_root() / "BuddyButton.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (hwndEdit == NULL || hwndButton == NULL || !::IsWindow(hwndEdit) || !::IsWindow(hwndButton))\n\t\treturn;" in source
    assert "if (lpfnOldWndProc == NULL)\n\t\treturn;" in source
    assert "if (!::SetProp(hwndEdit, s_szPropOldWndProc, (HANDLE)lpfnOldWndProc)) {\n\t\t::SetWindowLongPtr(hwndEdit, GWLP_WNDPROC, (LONG_PTR)lpfnOldWndProc);\n\t\treturn;\n\t}" in source
    assert "if (!::SetProp(hwndEdit, s_szPropBuddyData, (HANDLE)pBuddyData)) {\n\t\tdelete pBuddyData;\n\t\t::RemoveProp(hwndEdit, s_szPropOldWndProc);\n\t\t::SetWindowLongPtr(hwndEdit, GWLP_WNDPROC, (LONG_PTR)lpfnOldWndProc);\n\t\treturn;\n\t}" in source


# --- consolidated from tests/python/test_check_updates_menu_source.py ---


def _h_check_updates_menu_source___app_source_dir() -> Path:
    return (
        Path(__file__).resolve().parents[4]
        / "workspaces"
        / "workspace"
        / "app"
        / "emulebb-main"
        / "srchybrid"
    )


def _check_check_updates_menu_source__tools_menu_check_for_updates_runs_manual_version_check() -> None:
    app_source = _h_check_updates_menu_source___app_source_dir()
    menu_cmds = (app_source / "MenuCmds.h").read_text(encoding="utf-8", errors="ignore")
    emule_dlg = (app_source / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    resource_h = (app_source / "Resource.h").read_text(encoding="utf-8", errors="ignore")

    assert "#define MP_HM_CHECK_FOR_UPDATES\t10464" in menu_cmds
    assert "#define IDS_TOOLS_STATUS_CHECK_FOR_UPDATES 3334" in resource_h

    status_map = re.search(
        r"case MP_HM_CHECK_FOR_UPDATES:\s*"
        r"return IDS_TOOLS_STATUS_CHECK_FOR_UPDATES;",
        emule_dlg,
    )
    assert status_map is not None

    command_handler = re.search(
        r"case MP_HM_CHECK_FOR_UPDATES:\s*"
        r"DoVersioncheck\(true\);\s*"
        r"break;",
        emule_dlg,
    )
    assert command_handler is not None

    network_updates_block = re.search(
        r"networkUpdates\.AppendMenu\(MF_STRING, MP_HM_IPFILTER,.*?"
        r"networkUpdates\.AppendMenu\(uGeoLocationMenuFlags, MP_HM_GEOLOCATION_DOWNLOAD,",
        emule_dlg,
        re.DOTALL,
    )
    assert network_updates_block is not None
    assert (
        "networkUpdates.AppendMenu(MF_STRING, MP_HM_CHECK_FOR_UPDATES, "
        "GetResString(IDS_CHECK4UPDATE), _T(\"WEB\"));"
        in network_updates_block.group(0)
    )


def _check_check_updates_menu_source__check_for_updates_status_string_is_release_localized() -> None:
    app_source = _h_check_updates_menu_source___app_source_dir()
    expected_id = "IDS_TOOLS_STATUS_CHECK_FOR_UPDATES"

    rc_files = [app_source / "emule.rc", *sorted((app_source / "lang").glob("*.rc"))]
    for rc_file in rc_files:
        rc_text = rc_file.read_text(encoding="utf-8-sig", errors="ignore")
        assert expected_id in rc_text, rc_file


# --- consolidated from tests/python/test_client_credits_source.py ---


def _check_client_credits_source__client_credit_signature_helpers_reject_null_inputs() -> None:
    source = (app_source_root() / "ClientCredits.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pTarget != NULL && pachOutput != NULL);\n\tif (pTarget == NULL || pachOutput == NULL)\n\t\treturn GetClientCreditsSignatureFailureResult();" in source
    assert "ASSERT(pTarget);\n\tASSERT(pachSignature);\n\tif (pTarget == NULL || pachSignature == NULL)\n\t\treturn false;" in source


# --- consolidated from tests/python/test_color_button_source.py ---


def _check_color_button_source__color_button_ddx_guards_missing_control_and_wrong_subclass() -> None:
    source = (app_source_root() / "ColorButton.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pDX != NULL);\n\tif (pDX == NULL)\n\t\treturn;" in source
    assert "ASSERT(hWndCtrl != NULL);\n\tif (hWndCtrl == NULL)\n\t\treturn;" in source
    assert "CColorButton *pColourButton = DYNAMIC_DOWNCAST(CColorButton, CWnd::FromHandlePermanent(hWndCtrl));" in source
    assert "ASSERT(pColourButton != NULL);\n\tif (pColourButton == NULL)\n\t\treturn;" in source


# --- consolidated from tests/python/test_crash_dump_source.py ---


def _check_crash_dump_source__crash_handler_can_use_configured_full_dump_type() -> None:
    root = app_source_root()
    header = (root / "Mdump.h").read_text(encoding="utf-8", errors="ignore")
    source = (root / "Mdump.cpp").read_text(encoding="utf-8", errors="ignore")
    emule = (root / "Emule.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool bCaptureFullCrashDump;" in header
    assert "MINIDUMP_TYPE GetCrashDumpType(bool bFullMemoryDump)" in source
    assert "return bFullMemoryDump ? GetManualDumpType(true) : MiniDumpNormal;" in source
    assert "const MINIDUMP_TYPE eDumpType = GetCrashDumpType(theCrashDumper.bCaptureFullCrashDump);" in source
    assert "::MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, eDumpType, &ExInfo, NULL, NULL)" in source
    assert "::MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &ExInfo, NULL, NULL)" not in source
    assert 'GetProfileInt(_T("eMule"), _T("CaptureFullCrashDump"), 0) != 0' in emule


def _check_crash_dump_source__capture_full_crash_dump_preference_is_persisted_and_exposed_in_tweaks() -> None:
    root = app_source_root()
    preferences_h = (root / "Preferences.h").read_text(encoding="utf-8", errors="ignore")
    preferences_cpp = (root / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")
    tweaks_h = (root / "PPgTweaks.h").read_text(encoding="utf-8", errors="ignore")
    tweaks_cpp = (root / "PPgTweaks.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "static bool\t\tm_bCaptureFullCrashDump;" in preferences_h
    assert "static bool\t\tGetCaptureFullCrashDump()" in preferences_h
    assert "static void\t\tSetCaptureFullCrashDump(bool bEnabled)" in preferences_h
    assert 'ini.WriteBool(_T("CaptureFullCrashDump"), m_bCaptureFullCrashDump);' in preferences_cpp
    assert 'SetCaptureFullCrashDump(ini.GetBool(_T("CaptureFullCrashDump"), GetDefaultCaptureFullCrashDump()));' in preferences_cpp

    assert "HTREEITEM m_htiCaptureFullCrashDump;" in tweaks_h
    assert "bool m_bCaptureFullCrashDump;" in tweaks_h
    assert "m_htiCaptureFullCrashDump = m_ctrlTreeOptions.InsertCheckBox(GetResString(IDS_TWEAKS_CAPTURE_FULL_CRASH_DUMP), m_htiLoggingGroup, m_bCaptureFullCrashDump);" in tweaks_cpp
    assert "LocalizeItemText(m_htiCaptureFullCrashDump, IDS_TWEAKS_CAPTURE_FULL_CRASH_DUMP);" in tweaks_cpp
    assert "DDX_TreeCheck(pDX, IDC_EXT_OPTS, m_htiCaptureFullCrashDump, m_bCaptureFullCrashDump);" in tweaks_cpp
    assert "m_bCaptureFullCrashDump = thePrefs.GetCaptureFullCrashDump();" in tweaks_cpp
    assert "thePrefs.SetCaptureFullCrashDump(m_bCaptureFullCrashDump);" in tweaks_cpp
    assert "theCrashDumper.bCaptureFullCrashDump = thePrefs.GetCaptureFullCrashDump();" in tweaks_cpp


# --- consolidated from tests/python/test_dead_source_list_source.py ---


def _check_dead_source_list_source__dead_source_list_skips_unidentifiable_clients_before_hashing() -> None:
    source = (app_source_root() / "DeadSourceList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "DeadSourceList.h").read_text(encoding="utf-8", errors="ignore")

    assert "bool HasValidKey() const;" in header
    assert "if (isnulmd4(ds.m_aucHash))\n\t\treturn 0;" in header
    assert "bool CDeadSource::HasValidKey() const\n{\n\treturn m_dwID != 0 || !isnulmd4(m_aucHash);\n}" in source
    assert "if (!deadSource.HasValidKey())\n\t\treturn false;" in source
    assert "if (!deadSource.HasValidKey()) {" in source
    assert "inserting their all-zero key trips MFC's CMap hash" in source


# --- consolidated from tests/python/test_download_list_ctrl_source.py ---


def _check_download_list_ctrl_source__remove_file_rejects_null_before_matching_owner_rows() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(toremove != NULL);\n\tif (toremove == NULL)\n\t\treturn bResult;\n\tRemoveVideoThumbnailCache(toremove);" in source
    assert "if (delItem->owner == toremove || delItem->value == (void*)toremove)" in source


def _check_download_list_ctrl_source__add_source_rejects_stale_owner_before_parent_lookup() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (owner == NULL || theApp.downloadqueue == NULL || !theApp.downloadqueue->IsPartFile(owner) || !IsLiveDownloadClient(source))\n\t\treturn;" in source
    assert "if (cur_item == NULL)\n\t\t\tcontinue;" in source
    assert "ASSERT(ownerIt != m_ListItems.end());\n\tif (ownerIt == m_ListItems.end() || ownerIt->second == NULL || ownerIt->second->type != FILE_TYPE || ownerIt->second->value != owner)\n\t\treturn;" in source


def _check_download_list_ctrl_source__draw_item_checks_next_row_before_tree_line_deref() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const CtrlItem_Struct *nextContent = notLast ? reinterpret_cast<CtrlItem_Struct*>(GetItemData(lpDrawItemStruct->itemID + 1)) : NULL;\n\t\tbool hasNext = nextContent != NULL && nextContent->type != FILE_TYPE;" in source


def _check_download_list_ctrl_source__thumbnail_completion_resumes_deferred_part_file_delete_after_preview_release() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("LRESULT CDownloadListCtrl::OnVideoThumbnailFinished") : source.index("void CDownloadListCtrl::SetAllIcons")]

    assert "CPartFile *pFileToDelete = bFileStillTracked && pResult->pPartFile->IsDeleting() ? pResult->pPartFile : NULL;" in block
    assert block.index("pResult->pPartFile->m_bPreviewing = false;") < block.index("pFileToDelete->DeletePartFile();")
    assert block.index("UpdateItem(pResult->pPartFile);") < block.index("delete pResult;")
    assert "delete pResult;\n\tif (pFileToDelete != NULL)\n\t\tpFileToDelete->DeletePartFile();\n\tStartNextVideoThumbnailWorker();" in block


def _check_download_list_ctrl_source__download_filename_suffix_only_uses_live_thumbnail_cache() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    helper = source[source.index("bool CDownloadListCtrl::HasCachedVideoThumbnail") : source.index("bool CDownloadListCtrl::IsVideoThumbnailCandidate")]
    display = source[source.index("CString CDownloadListCtrl::GetFileItemDisplayText") : source.index("void CDownloadListCtrl::ShowFilesCount")]

    assert "m_videoThumbnailCache.Lookup(strKey, pEntry)" in helper
    assert "GetCachedVideoThumbnail" not in helper
    assert "ReadVideoThumbnailBitmapFile" not in helper
    assert "PathExists" not in helper
    assert "sText.AppendChar(static_cast<TCHAR>(0x25A3));" in display


def _check_download_list_ctrl_source__download_infotip_wraps_long_lines_before_tooltip_suffix() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    helper = source[source.index("CString WrapDownloadInfoTipLine") : source.index("bool IsSourceCtrlItem")]
    infotip = source[source.index("void CDownloadListCtrl::OnLvnGetInfoTip") : source.index("void CDownloadListCtrl::ShowFileDialog")]

    assert "const int kDownloadInfoTipMaxLineChars = 240;" in source
    assert 'rstrLine == _T("<br>")' in helper
    assert 'rstrLine == _T("<br_head>")' in helper
    assert "_istspace(ch) != 0 || ch == _T('-') || ch == _T(',') || ch == _T(')')" in helper
    assert "info = WrapDownloadInfoTipText(info);\n\t\t\tinfo += TOOLTIP_AUTOFORMAT_SUFFIX_CH;" in infotip


def _check_download_list_ctrl_source__download_obtained_parts_are_a_distinct_text_column() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    helper = source[source.index("CString FormatDownloadObtainedPartsText") : source.index("CString WrapDownloadInfoTipLine")]
    draw = source[source.index("void CDownloadListCtrl::DrawFileItem") : source.index("CString CDownloadListCtrl::GetSourceItemDisplayText")]
    display = source[source.index("CString CDownloadListCtrl::GetFileItemDisplayText") : source.index("void CDownloadListCtrl::ShowFilesCount")]
    localize = source[source.index("void CDownloadListCtrl::Localize") : source.index("void CDownloadListCtrl::AddFile")]

    assert "GetCompletedPartCount()" in helper
    assert '"%u / %u"' in helper
    assert "InsertColumn(19" in source
    assert "IDS_UPSTATUS" in localize
    assert "FormatDownloadObtainedPartsText(pPartFile)" not in draw
    assert "FormatDownloadObtainedPartsText(lpPartFile)" in display
    assert '"%s: %.1f%%"' in display


# --- consolidated from tests/python/test_download_queue_source.py ---


def _check_download_queue_source__download_queue_priority_sort_guards_list_positions_before_access() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pos1 != NULL);\n\tASSERT(pos2 != NULL);\n\tif (pos1 == NULL || pos2 == NULL)\n\t\treturn false;" in source
    assert "ASSERT(pos1 != NULL);\n\tASSERT(pos2 != NULL);\n\tif (pos1 == NULL || pos2 == NULL || pos1 == pos2)\n\t\treturn;" in source
    assert "POSITION pos1 = filelist.FindIndex(first);\n\tASSERT(pos1 != NULL);\n\tif (pos1 == NULL)\n\t\treturn;" in source
    assert "POSITION pos2 = filelist.FindIndex(r2);\n\t\tASSERT(pos2 != NULL);\n\t\tif (pos2 == NULL)\n\t\t\treturn;" in source
    assert "ASSERT(pos3 != NULL);\n\t\t\tif (pos3 != NULL && !CompareParts(pos2, pos3))" in source
    assert "SwapParts(filelist.FindIndex(0), filelist.FindIndex(i - 1));" not in source
    assert "POSITION posFirst = filelist.FindIndex(0);" in source
    assert "POSITION posLast = filelist.FindIndex(i - 1);" in source
    assert "if (posFirst == NULL || posLast == NULL)\n\t\t\tbreak;" in source


def _check_download_queue_source__download_queue_waits_for_completion_worker_before_deleting_part_files() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    part_file = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    part_file_header = (app_source_root() / "PartFile.h").read_text(encoding="utf-8", errors="ignore")

    assert "CPartFile *pPartFile = filelist.RemoveHead();" in source
    assert "!pPartFile->WaitForFileCompletionWorkerForShutdown()" in source
    assert source.index("!pPartFile->WaitForFileCompletionWorkerForShutdown()") < source.index("delete pPartFile;")
    assert "bool\tWaitForFileCompletionWorkerForShutdown();" in part_file_header
    assert "bool CPartFile::WaitForFileCompletionWorkerForShutdown()" in part_file
    assert "lock.Lock(PartFileCompletionSeams::kCompletionOwnerShutdownWaitMs)" in part_file
    assert "return false;" in part_file
    assert "lock.Lock(INFINITE)" not in part_file
    assert "Hold the owner mutex until after the result is queued; shutdown waits on" in part_file
    assert "sLock.Unlock();\n\n\tif (!PostPartFileCompletionThreadResult(this, FILE_COMPLETION_THREAD_SUCCESS" not in part_file


def _check_download_queue_source__search_result_source_addition_logs_file_exception_details() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CDownloadQueue::AddSearchToDownload(CSearchFile *toadd") :
        source.index("void CDownloadQueue::AddSearchToDownload(const CString &link")
    ]

    assert 'DebugLogWarning(_T("Failed to add search-result source %u:%u for \\"%s\\"%s"), toadd->GetClientID(), toadd->GetClientPort(), (LPCTSTR)newfile->GetFileName(), (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert 'DebugLogWarning(_T("Failed to add global UDP search-result source %u:%u for \\"%s\\"%s"), aClients[i].m_nIP, aClients[i].m_nPort, (LPCTSTR)newfile->GetFileName(), (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert block.count("CExceptionStrDash(*ex)") == 2
    assert block.count("ASSERT(0);") == 2


def _check_download_queue_source__startup_part_file_hash_jobs_are_released_after_part_scan() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    scoped_block = source[source.index("class CScopedPartFileHashStartupScheduling") : source.index("enum ProtectedDiskRoleMask")]
    init_block = source[source.index("void CDownloadQueue::Init()") : source.index("CDownloadQueue::~CDownloadQueue()")]

    assert "BeginPartFileHashStartupScheduling();" in scoped_block
    assert "EndPartFileHashStartupScheduling();" in scoped_block
    assert "CScopedPartFileHashStartupScheduling startupHashScheduling;" in init_block
    assert init_block.index("CScopedPartFileHashStartupScheduling startupHashScheduling;") < init_block.index("PathHelpers::ForEachMatchingEntry(PathHelpers::AppendPathComponent(strTempDir, _T(\"*.part.met\"))")
    assert "EndPartFileHashStartupScheduling();" not in init_block
    assert init_block.index("CScopedPartFileHashStartupScheduling startupHashScheduling;") < init_block.index("SortByPriority();")


def _check_download_queue_source__local_server_source_requests_prefer_starved_files_before_wait_order() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CDownloadQueue::ProcessLocalRequests()") :
        source.index("void CDownloadQueue::SendLocalSrcRequest")
    ]

    assert "const int iValidSources = cur_file->GetValidSourcesCount();" in block
    assert "const UINT uSourceCount = cur_file->GetSourceCount();" in block
    assert "iValidSources < iBestValidSources" in block
    assert "uSourceCount < uBestSourceCount" in block
    assert "uSourceCount == uBestSourceCount && ullWaitTime < ullBestWaitTime" in block
    assert "spending each" in block
    assert "frame on files with the fewest usable sources improves" in block
    assert block.index("int iBestValidSources = (std::numeric_limits<int>::max)();") < block.index("UINT uBestSourceCount = _UI32_MAX;")
    assert block.index("UINT uBestSourceCount = _UI32_MAX;") < block.index("ULONGLONG ullBestWaitTime = _UI64_MAX;")
    assert block.index("const int iValidSources") < block.index("const UINT uSourceCount")
    assert block.index("const UINT uSourceCount") < block.index("const ULONGLONG ullWaitTime")
    assert block.index("iValidSources < iBestValidSources") < block.index("uSourceCount < uBestSourceCount")
    assert block.index("uSourceCount < uBestSourceCount") < block.index("uSourceCount == uBestSourceCount && ullWaitTime < ullBestWaitTime")
    assert block.index("iBestValidSources = iValidSources;") < block.index("posNextRequest = pos2;")
    assert block.index("uBestSourceCount = uSourceCount;") < block.index("posNextRequest = pos2;")
    assert block.index("ullBestWaitTime = ullWaitTime;") < block.index("posNextRequest = pos2;")


def _check_download_queue_source__local_server_source_requests_prune_stale_entries_before_spending_credit() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    predicate = source[
        source.index("bool ShouldSendLocalServerSourceRequest") :
        source.index("}\n}\n\nCDownloadQueue::CDownloadQueue()")
    ]
    block = source[
        source.index("void CDownloadQueue::ProcessLocalRequests()") :
        source.index("void CDownloadQueue::SendLocalSrcRequest")
    ]

    assert "pFile->GetMaxSourcePerFileSoft() <= pFile->GetSourceCount()" in predicate
    assert "pCurrentServer != NULL && pCurrentServer->SupportsLargeFilesTCP()" in predicate
    assert "ShouldSendLocalServerSourceRequest(cur_file, pCurrentServer)" in block
    assert "cur_file->m_bLocalSrcReqQueued = false;" in block
    assert "not sent because it is no longer eligible" in block
    assert "if (iFiles > 0)" in block
    assert "kLocalServerSourceRequestsPerTcpFrame = 15" in source
    assert "kLocalServerSourceRequestTcpFrameIntervalMs" in source
    assert "m_dwNextTCPSrcReq = curTick + kLocalServerSourceRequestTcpFrameIntervalMs;" in block


def _check_download_queue_source__download_summary_reports_source_discovery_pressure() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CDownloadQueue::LogDownloadSlotDiagnostics") :
        source.index("//This method is called every 100 ms")
    ]

    for field in (
        "localServerQueuedFiles=%Id",
        "localServerQueuedReadyFiles=%u",
        "localServerQueuedEligibleFiles=%u",
        "localServerQueuedSourceStarvedEligibleFiles=%u",
        "localServerQueuedDueAgeMaxMs=%I64u",
        "localServerQueuedEstimatedDrainMs=%I64u",
        "localServerMarkedReadyFiles=%u",
        "sourceStarvedLocalQueuedReadyFiles=%u",
        "nextTcpSourceRequestWaitMs=%I64u",
        "udpSearchActive=%u",
        "udpSearchedServers=%u",
        "udpRequestsSentToServer=%u",
        "udpFileReasks=%u",
        "udpFailedFileReasks=%u",
        "udpLastSearchAgeMs=%I64u",
        "kadConnected=%u",
        "kadTotalFileSearches=%u",
        "kadSearchingReadyFiles=%u",
        "kadEligibleReadyFiles=%u",
        "kadDueReadyFiles=%u",
        "kadBackoffReadyFiles=%u",
        "sourceStarvedKadSearchingReadyFiles=%u",
        "sourceStarvedKadEligibleReadyFiles=%u",
        "sourceStarvedKadDueReadyFiles=%u",
        "sourceStarvedKadBackoffReadyFiles=%u",
    ):
        assert field in block

    assert "m_localServerReqQueue.GetCount()" in block
    assert "uLocalServerQueueEligibleFiles" in block
    assert "uLocalServerQueueSourceStarvedEligibleFiles" in block
    assert "ullLocalServerQueueDueAgeMaxMs" in block
    assert "ullLocalServerQueueEstimatedDrainMs" in block
    assert "EstimateLocalServerSourceRequestQueueDrainMs" in block
    assert "ShouldSendLocalServerSourceRequest(pQueuedFile, pCurrentServer)" in block
    assert "pQueuedFile->GetValidSourcesCount() <= 0" in block
    assert "if (pQueuedFile->m_LastSearchTime != 0)" in block
    assert "pQueuedFile->m_LastSearchTime + SERVERREASKTIME" in block
    assert "const bool bSourceStarvedFile = iFileValidSources <= 0;" in block
    assert "cur_file->m_bLocalSrcReqQueued" in block
    assert "bSourceStarvedFile" in block
    assert "cur_file->GetKadFileSearchID() != 0" in block
    assert "cur_file->GetMaxSourcePerFileUDP() > cur_file->GetSourceCount()" in block
    assert "Kademlia::CKademlia::GetTotalFile()" in block


def _check_download_queue_source__kad_source_searches_prefer_starved_ready_files_without_expanding_kad_budget() -> None:
    queue_source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    queue_header = (app_source_root() / "DownloadQueue.h").read_text(encoding="utf-8", errors="ignore")
    part_file_source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    helper_block = queue_source[
        queue_source.index("bool CDownloadQueue::IsBestKademliaFileRequestCandidate") :
        queue_source.index("void CDownloadQueue::KademliaSearchFile")
    ]
    predicate_block = queue_source[
        queue_source.index("bool IsKademliaFileRequestCandidate") :
        queue_source.index("}\n}\n\nCDownloadQueue::CDownloadQueue()")
    ]
    part_gate = part_file_source[
        part_file_source.index("if (GetMaxSourcePerFileUDP() > GetSourceCount())") :
        part_file_source.index("// check if we want new sources from server")
    ]

    assert "bool\tIsBestKademliaFileRequestCandidate(const CPartFile *pCandidate, ULONGLONG curTick) const;" in queue_header
    assert "pFile->GetKadFileSearchID() != 0" in predicate_block
    assert "pFile->GetMaxSourcePerFileUDP() <= pFile->GetSourceCount()" in predicate_block
    assert "curTick >= pFile->m_LastSearchTimeKad" in predicate_block
    assert "const int iCandidateValidSources = pCandidate->GetValidSourcesCount();" in helper_block
    assert "const UINT uCandidateSourceCount = pCandidate->GetSourceCount();" in helper_block
    assert "const int iValidSources = cur_file->GetValidSourcesCount();" in helper_block
    assert "const UINT uSourceCount = cur_file->GetSourceCount();" in helper_block
    assert "iValidSources < iCandidateValidSources" in helper_block
    assert "iValidSources == iCandidateValidSources && uSourceCount <= uCandidateSourceCount" in helper_block
    assert "KADEMLIATOTALFILE" not in helper_block
    assert "KADEMLIAASKTIME" not in helper_block
    assert "Kademlia::CSearchManager::PrepareLookup" not in helper_block
    assert "DoKademliaFileRequest()" in part_gate
    assert "Kademlia::CKademlia::GetTotalFile() < KADEMLIATOTALFILE" in part_gate
    assert "IsBestKademliaFileRequestCandidate(this, curTick)" in part_gate
    assert part_gate.index("DoKademliaFileRequest()") < part_gate.index("IsBestKademliaFileRequestCandidate(this, curTick)")


# --- consolidated from tests/python/test_download_slot_diagnostics_source.py ---


def _check_download_slot_diagnostics_source__download_slot_diagnostics_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:DownloadSlotDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableDownloadSlotDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(UploadSlotDiagnosticsPreprocessorDefinition)" in config_definitions
        assert "$(DownloadSlotDiagnosticsPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(UploadSlotDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "$(DownloadSlotDiagnosticsPreprocessorDefinition)"
        )
        assert config_definitions.index("$(DownloadSlotDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def _check_download_slot_diagnostics_source__download_slot_diagnostics_build_env_override_is_plumbed() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")

    assert '"EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS", "EnableDownloadSlotDiagnostics"' in build_source
    assert 'extra_properties.append(f"/p:{property_name}=' in build_source


def _check_download_slot_diagnostics_source__download_slot_diagnostics_logs_queue_and_client_state() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    queue_source = read_app_source("DownloadQueue.cpp")
    queue_header = read_app_source("DownloadQueue.h")
    log_header = read_app_source("Log.h")
    artifacts = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")
    client_header = read_app_source("UpDownClient.h")
    base_client_source = read_app_source("BaseClient.cpp")

    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS\nvoid CUpDownClient::LogDownloadSlotDiagnostics" in client_source
    assert "DownloadSlotDiagnostics: client reason=%s" in client_source
    assert "DownloadSlotDiagnosticsLogLine(" in client_source
    assert "DownloadSlotDiagnosticsLogLine(" in queue_source
    assert "extern CLogFile theDownloadSlotDiagnosticsLog;" in log_header
    assert "void DownloadSlotDiagnosticsLogLine(LPCTSTR pszFmt, ...);" in log_header
    assert 'return _T("emulebb-diagnostics-download-slot.log");' in artifacts
    assert "LogArtifactNames::DownloadSlotDiagnosticsLogFileName()" in app_source
    for anchor in (
        "block-reserved",
        "block-reserve-empty",
        "request-sent",
        "block-complete",
        "block-advanced-duplicate-complete",
        "block-cleared-duplicate-complete",
        "block-cleared-duplicate-whole-complete",
        "packet-zero-write",
        "request-empty-nnp",
        "out-of-part-reqs",
        "accept-suppressed-out-of-part-cooldown",
        "accept-suppressed-no-data-cooldown",
        "timeout",
        "disconnect-downloading",
    ):
        assert anchor in client_source or anchor in base_client_source

    throttle_block = client_source[
        client_source.index("bool IsDownloadSlotDiagnosticsHighVolumeReason") :
        client_source.index("bool IsTickInsideWindow")
    ]
    assert '_T("request-empty-nnp")' in throttle_block
    assert '_T("block-advanced-duplicate-complete")' in throttle_block
    assert '_T("block-cleared-duplicate-complete")' in throttle_block
    assert '_T("block-cleared-duplicate-whole-complete")' in throttle_block
    assert '_T("packet-dropped-no-pending-block")' in throttle_block
    assert '_T("disconnect-downloading")' in throttle_block
    assert '_T("state-leave-downloading")' in throttle_block
    assert '_T("state-leave-downloading-nnp")' in throttle_block

    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS\nvoid CDownloadQueue::LogDownloadSlotDiagnostics" in queue_source
    assert "DownloadSlotDiagnostics: summary" in queue_source
    assert 'CDiagnosticsKeyValueLineBuilder summary(_T("DownloadSlotDiagnostics: summary"));' in queue_source
    assert 'DownloadSlotDiagnosticsLogLine(_T("%s"), (LPCTSTR)summary.GetLine());' in queue_source
    assert "LogDownloadSlotDiagnostics(curTick);" in queue_source
    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS\n\tvoid\tLogDownloadSlotDiagnostics" in queue_header
    assert "m_ullDownloadBlockRequestsReserved" in client_header
    assert "m_ullDownloadDuplicateZeroWritePackets" in client_header
    assert "m_ullDownloadDuplicateZeroWriteBytes" in client_header
    assert "GetDownloadDuplicateZeroWritePackets" in client_header
    assert "GetDownloadDuplicateZeroWriteBytes" in client_header
    assert "m_uDownloadOutOfPartReqsSuppressions" in client_header
    assert "highVolumeSuppressed=%I64u" in client_source
    assert "duplicateZeroWritePackets=%I64u" in client_source
    assert "duplicateZeroWriteBytes=%I64u" in client_source
    assert "PartFileBufferedDataStateSnapshot bufferSnapshot" in queue_source
    assert "cur_file->GetBufferedDataStateSnapshot(bufferSnapshot);" in queue_source
    assert "cur_source->GetDownloadDuplicateZeroWritePackets();" in queue_source
    assert "cur_source->GetDownloadDuplicateZeroWriteBytes();" in queue_source
    for field in (
        "sourceStarvedReadyFiles=%u",
        "sourceStarvedLocalQueuedReadyFiles=%u",
        "sourceStarvedKadSearchingReadyFiles=%u",
        "sourceStarvedKadEligibleReadyFiles=%u",
        "sourceStarvedKadDueReadyFiles=%u",
        "sourceStarvedKadBackoffReadyFiles=%u",
        "sourceThinReadyFiles=%u",
        "sourceRichReadyFiles=%u",
        "a4afReadyFiles=%u",
        "connectedSources=%u",
        "connectingSources=%u",
        "callbackSources=%u",
        "hashsetSources=%u",
        "lowToLowIPSources=%u",
        "bannedSources=%u",
        "idleSources=%u",
        "duplicateZeroWriteSources=%u",
        "duplicateZeroWritePackets=%I64u",
        "duplicateZeroWriteBytes=%I64u",
        "effectiveFileBufferBytes=%I64u",
        "autoBroadbandIO=%u",
        "bufferedReadyBytes=%I64u",
        "bufferedPendingBytes=%I64u",
        "bufferedWrittenBytes=%I64u",
        "bufferedErrorBytes=%I64u",
        "bufferedReadyItems=%u",
        "bufferedPendingItems=%u",
        "bufferedWrittenItems=%u",
        "bufferedErrorItems=%u",
        "bufferedReadyFiles=%u",
        "bufferedPendingFiles=%u",
        "bufferedWrittenFiles=%u",
        "bufferedErrorFiles=%u",
        "maxBufferedReadyBytes=%I64u",
        "maxBufferedPendingBytes=%I64u",
        "maxBufferedWrittenBytes=%I64u",
        "maxBufferedReadyItems=%u",
        "maxBufferedPendingItems=%u",
        "maxBufferedWrittenItems=%u",
        "asyncWriteFiles=%u",
        "maxAsyncWriteRefsPerFile=%ld",
        "asyncWriteRefs=%Id",
    ):
        assert field in queue_source
    for aggregate in (
        "++uSourceStarvedReadyFiles;",
        "++uSourceStarvedLocalQueuedReadyFiles;",
        "++uSourceStarvedKadSearchingReadyFiles;",
        "++uSourceStarvedKadEligibleReadyFiles;",
        "++uSourceStarvedKadDueReadyFiles;",
        "++uSourceStarvedKadBackoffReadyFiles;",
        "++uSourceThinReadyFiles;",
        "++uSourceRichReadyFiles;",
        "++uA4AFReadyFiles;",
        "uConnectedSources += cur_file->GetSrcStatisticsValue(DS_CONNECTED);",
        "uConnectingSources += cur_file->GetSrcStatisticsValue(DS_CONNECTING);",
        "uCallbackSources += cur_file->GetSrcStatisticsValue(DS_WAITCALLBACK);",
        "uCallbackSources += cur_file->GetSrcStatisticsValue(DS_WAITCALLBACKKAD);",
        "uHashsetSources += cur_file->GetSrcStatisticsValue(DS_REQHASHSET);",
        "uLowToLowIPSources += cur_file->GetSrcStatisticsValue(DS_LOWTOLOWIP);",
        "uBannedSources += cur_file->GetSrcStatisticsValue(DS_BANNED);",
        "uIdleSources += cur_file->GetSrcStatisticsValue(DS_NONE);",
        "uMaxBufferedReadyBytes = max(uMaxBufferedReadyBytes, bufferSnapshot.uReadyBytes);",
        "uMaxBufferedPendingBytes = max(uMaxBufferedPendingBytes, bufferSnapshot.uPendingBytes);",
        "uMaxBufferedWrittenBytes = max(uMaxBufferedWrittenBytes, bufferSnapshot.uWrittenBytes);",
        "uMaxBufferedReadyItems = max(uMaxBufferedReadyItems, bufferSnapshot.uReadyCount);",
        "uMaxBufferedPendingItems = max(uMaxBufferedPendingItems, bufferSnapshot.uPendingCount);",
        "uMaxBufferedWrittenItems = max(uMaxBufferedWrittenItems, bufferSnapshot.uWrittenCount);",
        "++uAsyncWriteFiles;",
        "nMaxAsyncWriteRefsPerFile = max(nMaxAsyncWriteRefsPerFile, bufferSnapshot.nAsyncWriteCount);",
    ):
        assert aggregate in queue_source
    assert 'summary.AppendFormat(_T("effectiveFileBufferBytes=%I64u"), static_cast<uint64>(GetEffectiveFileBufferSizeBytes()))' in queue_source
    assert 'summary.AppendFormat(_T("autoBroadbandIO=%u"), static_cast<UINT>(thePrefs.IsDownloadAutoBroadbandIOEnabled()))' in queue_source
    assert '_tcscmp(pszReason, _T("block-reserve-empty")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("start-download")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("state-enter-downloading")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("state-transition")) == 0' in client_source
    assert "noDataSuppressions=%u" in client_source


def _check_download_slot_diagnostics_source__download_buffer_diagnostics_splits_part_file_flush_states() -> None:
    part_header = read_app_source("PartFile.h")
    part_source = read_app_source("PartFile.cpp")
    queue_source = read_app_source("DownloadQueue.cpp")

    assert "struct PartFileBufferedDataStateSnapshot" in part_header
    assert "void\tGetBufferedDataStateSnapshot(PartFileBufferedDataStateSnapshot &rSnapshot) const;" in part_header
    assert "void CPartFile::GetBufferedDataStateSnapshot(PartFileBufferedDataStateSnapshot &rSnapshot) const" in part_source
    assert "rSnapshot.nAsyncWriteCount = GetAsyncWriteCount();" in part_source
    assert "GetPartFileBufferedDataFlushState(*item)" in part_source
    for state in ("PB_READY", "PB_PENDING", "PB_WRITTEN", "PB_ERROR"):
        assert state in part_source
    for aggregate in (
        "uBufferedReadyBytes += bufferSnapshot.uReadyBytes;",
        "uBufferedPendingBytes += bufferSnapshot.uPendingBytes;",
        "uBufferedWrittenBytes += bufferSnapshot.uWrittenBytes;",
        "uBufferedErrorBytes += bufferSnapshot.uErrorBytes;",
        "iAsyncWriteRefs += bufferSnapshot.nAsyncWriteCount;",
    ):
        assert aggregate in queue_source


def _check_download_slot_diagnostics_source__download_slot_no_data_and_out_of_part_guards_are_conservative() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    client_header = read_app_source("UpDownClient.h")

    timeout_block = client_source[
        client_source.index("void CUpDownClient::CheckDownloadTimeout()") :
        client_source.index("uint16 CUpDownClient::GetAvailablePartCount() const")
    ]

    assert "kDownloadNoDataSlotCooldownThreshold = 2" in client_source
    assert "kDownloadNoDataSlotPayloadThresholdBytes = EMBLOCKSIZE" in client_source
    assert "kDownloadFirstPayloadTimeoutMs = SEC2MS(60)" in client_source
    assert "timeout-first-payload" in timeout_block
    assert "!m_PendingBlocks_list.IsEmpty()" in timeout_block
    assert "GetSessionPayloadDown() == 0" in timeout_block
    assert "GetSessionDown() == 0" in timeout_block
    assert "thePrefs.GetDownloadTimeout() > kDownloadFirstPayloadTimeoutMs" in timeout_block
    assert "First payload timeout. More than %u seconds since the first requested block without payload." in timeout_block
    assert timeout_block.index("timeout-first-payload") < timeout_block.index('LogDownloadSlotDiagnostics(_T("timeout"))')
    assert "CanAcceptUploadSlotAfterDownloadNoData" in client_header
    assert "NoteDownloadNoDataSlotFailure(pszReason)" in client_source
    assert "Suppressed OP_AcceptUploadReq after repeated no-data download slots" in client_source
    assert "kOutOfPartReqsCooldownThreshold = 3" in client_source


def _check_download_slot_diagnostics_source__duplicate_complete_download_block_advances_and_retires_stale_pending_request() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    block = client_source[
        client_source.index("const bool bCompletedDuplicateRange = !packed") :
        client_source.index("Stop looping and exit")
    ]

    assert "lenWritten == 0" in block
    assert "m_reqfile->IsComplete(cur_block->block->StartOffset, nEndPos)" in block
    assert "const bool bCompletedDuplicateBlock = bCompletedDuplicateRange && nEndPos == cur_block->block->EndOffset;" in block
    assert "const bool bCompletedDuplicateWholeBlock = !packed" in block
    assert "m_reqfile->IsComplete(cur_block->block->StartOffset, cur_block->block->EndOffset)" in block
    assert "const bool bDuplicateZeroWrite = !packed" in block
    assert "m_reqfile->IsComplete(nStartPos, nEndPos)" in block
    assert "bool bProgressedPendingBlock = false;" in block
    assert "if (lenWritten > 0 ? nEndPos == cur_block->block->EndOffset : (bCompletedDuplicateBlock || bCompletedDuplicateWholeBlock))" in block
    assert block.index("m_reqfile->IsComplete(cur_block->block->StartOffset, nEndPos)") < block.index("const uint64 uDuplicateProgressBytes")
    assert "bCompletedDuplicateWholeBlock" in block
    assert "cur_block->block->transferred = uDuplicateProgressBytes;" in block
    duplicate_progress_block = block[
        block.index("const uint64 uDuplicateProgressBytes") :
        block.index('#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS', block.index("const uint64 uDuplicateProgressBytes"))
    ]
    assert "bProgressedPendingBlock = true;" not in duplicate_progress_block
    assert "bProgressedPendingBlock = true;" in block
    assert 'LogDownloadSlotDiagnostics(_T("block-advanced-duplicate-complete")' in block
    assert "m_nTransferredDown += uTransferredFileDataSize;" in block
    assert block.index("if (lenWritten > 0)") < block.index("m_nTransferredDown += uTransferredFileDataSize;")
    assert '_T("block-cleared-duplicate-complete")' in block
    assert '_T("block-cleared-duplicate-whole-complete")' in block
    assert "ClearPendingBlockRequest(cur_block);" in block
    assert block.index("ClearPendingBlockRequest(cur_block);") < block.index("SendBlockRequests();")
    assert "if (bProgressedPendingBlock)\n\t\t\tResetDownloadStaleBlockPacketGuard();" in block
    assert block.index("SendBlockRequests();") < block.index("if (bProgressedPendingBlock)")


def _check_download_slot_diagnostics_source__stale_block_packets_abort_only_after_conservative_burst() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    client_header = read_app_source("UpDownClient.h")
    base_client_source = read_app_source("BaseClient.cpp")

    process_block = client_source[
        client_source.index("void CUpDownClient::ProcessBlockPacket") :
        client_source.index("int CUpDownClient::unzip")
    ]
    packet_drop_block = process_block[
        process_block.index('LogDownloadSlotDiagnostics(_T("packet-dropped-no-pending-block")') :
        process_block.index("int CUpDownClient::unzip") if "int CUpDownClient::unzip" in process_block else len(process_block)
    ]
    helper_block = client_source[
        client_source.index("bool CUpDownClient::ShouldAbortAfterStaleBlockPacket") :
        client_source.index("void CUpDownClient::ProcessInboundOutOfPartReqs")
    ]
    start_download_block = client_source[
        client_source.index("void CUpDownClient::StartDownload()") :
        client_source.index("void CUpDownClient::SendCancelTransfer()")
    ]

    assert "kDownloadStaleBlockPacketThreshold = 32" in client_source
    assert "kDownloadStaleBlockPacketWindowMs = SEC2MS(15)" in client_source
    assert "ResetDownloadStaleBlockPacketGuard();" in start_download_block
    assert "ResetDownloadStaleBlockPacketGuard();" in base_client_source
    assert "void\tResetDownloadStaleBlockPacketGuard();" in client_header
    assert "bool\tShouldAbortAfterStaleBlockPacket(CString *pReason = NULL);" in client_header
    assert "m_ullDownloadStaleBlockPacketWindowStart" in client_header
    assert "m_uDownloadStaleBlockPacketWindowCount" in client_header
    assert process_block.index("ResetDownloadStaleBlockPacketGuard();") < process_block.index(
        'LogDownloadSlotDiagnostics(_T("packet-dropped-no-pending-block")'
    )
    assert "GetDownloadState() != DS_DOWNLOADING" in helper_block
    assert "m_reqfile == NULL" in helper_block
    assert "m_PendingBlocks_list.IsEmpty()" in helper_block
    assert "m_uDownloadStaleBlockPacketWindowCount < kDownloadStaleBlockPacketThreshold" in helper_block
    assert "Sustained stale block packets." in helper_block
    assert "did not make useful download progress" in helper_block
    assert '_T("stale-block-packet-abort")' in packet_drop_block
    assert "SendCancelTransfer();" in packet_drop_block
    assert "SetDownloadState(DS_ONQUEUE, strReason);" in packet_drop_block
    assert packet_drop_block.index("ShouldAbortAfterStaleBlockPacket(&strReason)") < packet_drop_block.index("SendCancelTransfer();")
    assert packet_drop_block.index("SendCancelTransfer();") < packet_drop_block.index("SetDownloadState(DS_ONQUEUE, strReason);")
    assert "standard cancel returns it to queue while preserving protocol semantics" in packet_drop_block


def _check_download_slot_diagnostics_source__duplicate_zero_write_blocks_feed_stale_packet_guard() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    part_file_source = read_app_source("PartFile.cpp")
    base_client_source = read_app_source("BaseClient.cpp")
    client_header = read_app_source("UpDownClient.h")
    process_block = client_source[
        client_source.index("void CUpDownClient::ProcessBlockPacket") :
        client_source.index("int CUpDownClient::unzip")
    ]
    duplicate_guard_block = process_block[
        process_block.index("else if (bDuplicateZeroWrite)") :
        process_block.index("Stop looping and exit")
    ]

    assert "m_ullDownloadDuplicateZeroWritePackets" in client_header
    assert "m_ullDownloadDuplicateZeroWriteBytes" in client_header
    assert "NoteDownloadDuplicateZeroWrite" in client_header
    assert "m_ullDownloadDuplicateZeroWritePackets = 0;" in base_client_source
    assert "m_ullDownloadDuplicateZeroWriteBytes = 0;" in base_client_source
    assert "++m_ullDownloadDuplicateZeroWritePackets;" in client_source
    assert "m_ullDownloadDuplicateZeroWriteBytes += uPayloadBytes;" in client_source
    duplicate_write_block = part_file_source[
        part_file_source.index("PrcBlkPkt: Already written block") - 220 :
        part_file_source.index("PrcBlkPkt: Already written block") + 220
    ]
    assert "client->NoteDownloadDuplicateZeroWrite(transize);" in duplicate_write_block
    assert "client == NULL" in duplicate_write_block
    assert "ShouldAbortAfterStaleBlockPacket(&strReason)" in duplicate_guard_block
    assert '_T("stale-duplicate-block-packet-abort")' in duplicate_guard_block
    assert "SendCancelTransfer();" in duplicate_guard_block
    assert "SetDownloadState(DS_ONQUEUE, strReason);" in duplicate_guard_block
    assert "stock transfer control" in duplicate_guard_block
    assert duplicate_guard_block.index("ShouldAbortAfterStaleBlockPacket(&strReason)") < duplicate_guard_block.index(
        "SendCancelTransfer();"
    )
    assert 'else if (lenWritten == 0)\n\t\t\tResetDownloadStaleBlockPacketGuard();' in process_block


# --- consolidated from tests/python/test_emsocket_send_seams_source.py ---


def _check_emsocket_send_seams_source__consume_queued_file_payload_rejects_null_counter() -> None:
    source = (app_source_root() / "EMSocketSendSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pnRemainingPayloadBytes != NULL);\n\tif (pnRemainingPayloadBytes == NULL)\n\t\treturn false;" in source
    assert "if (nActualPayloadSize > *pnRemainingPayloadBytes)\n\t\treturn false;" in source


def _check_emsocket_send_seams_source__standard_upload_send_queue_budget_is_broadband_sized() -> None:
    source = (app_source_root() / "EMSocketSendSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "kMinEMSocketQueuedStandardBytes = 16ull * 1024ull * 1024ull" in source
    assert "kMaxEMSocketQueuedStandardBytes = 256ull * 1024ull * 1024ull" in source
    assert "GetBroadbandEMSocketQueuedStandardBytes(" in source


# --- consolidated from tests/python/test_emule_dlg_source.py ---


def _check_emule_dlg_source__startup_initialization_logs_mfc_exception_details() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    server_block = source[source.index("theApp.serverlist->Init();") : source.index("StartupTimer stage 2: serverlist->Init")]
    download_block = source[source.index("theApp.downloadqueue->Init();") : source.index("StartupTimer stage 4: downloadqueue->Init")]

    assert "catch (CException *ex)" in server_block
    assert 'LogError(LOG_STATUSBAR, _T("Failed to initialize server list%s"), (LPCTSTR)CExceptionStrDash(*ex));' in server_block
    assert "ex->Delete();" in server_block
    assert "catch (CException *ex)" in download_block
    assert 'LogError(LOG_STATUSBAR, _T("Failed to initialize download queue%s"), (LPCTSTR)CExceptionStrDash(*ex));' in download_block
    assert "ex->Delete();" in download_block
    assert "bError = true;" in download_block


def _check_emule_dlg_source__shutdown_keeps_part_file_writer_alive_through_download_queue_teardown() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    shutdown_block = source[
        source.index("updateShutdownPhase(30, _T(\"Closing eMuleBB\")") :
        source.index("updateShutdownPhase(100, _T(\"Closing eMuleBB\")")
    ]

    assert "keeping part-file writer alive for download teardown" in shutdown_block
    assert "theApp.m_pUploadDiskIOThread->EndThread();" in shutdown_block
    assert shutdown_block.index("theApp.m_pUploadDiskIOThread->EndThread();") < shutdown_block.index("delete theApp.downloadqueue;")
    assert shutdown_block.index("delete theApp.downloadqueue;") < shutdown_block.index("theApp.m_pPartFileWriteThread->EndThread();")
    assert shutdown_block.index("theApp.m_pPartFileWriteThread->EndThread();") < shutdown_block.index("delete theApp.m_pPartFileWriteThread;")


def _check_emule_dlg_source__stored_search_startup_stage_closes_progress_dialog_without_extra_queued_hop() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    startup_block = source[source.index("void CemuleDlg::OnStartupTimer() noexcept") : source.index("void CemuleDlg::StopTimer()")]
    stored_search_block = startup_block[startup_block.index("case 5:") : startup_block.index("default:")]
    final_block = startup_block[startup_block.index("default:") : startup_block.index("VERIFY(PostMessage(UM_STARTUP_NEXT_STAGE) != 0);")]

    assert "theApp.searchlist->LoadSearches();" in stored_search_block
    assert "IDS_STARTUP_PROGRESS_LOADING_STORED_SEARCHES" not in stored_search_block
    assert "UpdateStartupProgress(" not in stored_search_block
    assert stored_search_block.index("status = 6;") < stored_search_block.index("FinishStartupProgress();")
    assert stored_search_block.index("FinishStartupProgress();") < stored_search_block.index("theApp.searchlist->LoadSearches();")
    assert 'LogError(LOG_STATUSBAR, _T("Failed to restore stored searches%s"), (LPCTSTR)CExceptionStrDash(*ex));' in stored_search_block
    assert 'LogError(LOG_STATUSBAR, _T("Failed to restore stored searches - Unknown exception"));' in stored_search_block
    assert "[[fallthrough]];" in stored_search_block
    assert "break;" not in stored_search_block
    assert "UpdateStartupProgress(" not in final_block
    assert "CloseStartupProgressIfRunning();" in final_block
    assert "StopTimer();" in final_block


def _check_emule_dlg_source__startup_progress_dialog_destruction_flushes_pending_window_messages() -> None:
    dialog_source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    app_source = (app_source_root() / "Emule.cpp").read_text(encoding="utf-8", errors="ignore")
    lifecycle_source = (app_source_root() / "LifecycleProgressDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    destroy_startup_block = dialog_source[dialog_source.index("void CemuleDlg::DestroyStartupProgress()") : dialog_source.index("BOOL CemuleApp::IsIdleMessage")]
    destroy_early_block = app_source[app_source.index("void CemuleApp::DestroyEarlyStartupProgress()") : app_source.index("bool CemuleApp::ProcessCommandline")]
    pump_block = lifecycle_source[lifecycle_source.index("void PumpLifecycleProgressMessages") :]
    close_if_running_block = dialog_source[dialog_source.index("void CemuleDlg::CloseStartupProgressIfRunning()") : dialog_source.index("BOOL CemuleApp::IsIdleMessage")]
    show_block = dialog_source[dialog_source.index("void CemuleDlg::ShowStartupProgress()") : dialog_source.index("void CemuleDlg::UpdateStartupProgress")]
    update_block = dialog_source[dialog_source.index("void CemuleDlg::UpdateStartupProgress") : dialog_source.index("void CemuleDlg::DestroyStartupProgress")]
    orphan_cleanup_block = dialog_source[
        dialog_source.index("static BOOL CALLBACK DestroyOrphanedStartupProgressWindowProc") :
        dialog_source.index("bool CemuleDlg::ShouldShowLifecycleProgressDialog")
    ]

    assert destroy_startup_block.index("m_pStartupProgressDlg->ShowWindow(SW_HIDE);") < destroy_startup_block.index("m_pStartupProgressDlg->DestroyWindow();")
    assert "m_pStartupProgressDlg->DestroyWindow();" in destroy_startup_block
    assert destroy_startup_block.index("m_pStartupProgressDlg = NULL;") < destroy_startup_block.index("PumpLifecycleProgressMessages(NULL);")
    assert destroy_early_block.index("m_pEarlyStartupProgressDlg->ShowWindow(SW_HIDE);") < destroy_early_block.index("m_pEarlyStartupProgressDlg->DestroyWindow();")
    assert "m_pEarlyStartupProgressDlg->DestroyWindow();" in destroy_early_block
    assert destroy_early_block.index("m_pEarlyStartupProgressDlg = NULL;") < destroy_early_block.index("PumpLifecycleProgressMessages(NULL);")
    assert "PM_NOREMOVE" in pump_block
    assert "msg.message == UM_STARTUP_NEXT_STAGE" in pump_block
    assert "if (m_bStartupProgressFinished)" in show_block
    assert show_block.index("if (m_bStartupProgressFinished)") < show_block.index("if (m_pStartupProgressDlg != NULL)")
    assert show_block.index("if (theApp.IsRunning())") < show_block.index("if (m_bStartupProgressFinished)")
    assert "if (m_bStartupProgressFinished)" in update_block
    assert update_block.index("if (m_bStartupProgressFinished)") < update_block.index("if (m_pStartupProgressDlg == NULL)")
    assert update_block.index("if (theApp.IsRunning())") < update_block.index("if (m_bStartupProgressFinished)")
    assert "m_bStartupProgressFinished = true;" in close_if_running_block
    assert "theApp.DestroyEarlyStartupProgress();" in close_if_running_block
    assert "DestroyStartupProgress();" in close_if_running_block
    assert "DestroyOrphanedStartupProgressWindows(m_hWnd);" in close_if_running_block
    assert "theApp.IsRunning()" in close_if_running_block
    assert "CloseStartupProgressIfRunning();" in dialog_source[dialog_source.index("LRESULT CemuleDlg::OnStartupNextStage") : dialog_source.index("LRESULT CemuleDlg::OnBindInterfaceChanged")]
    assert "CloseStartupProgressIfRunning();" in dialog_source[dialog_source.index("void CemuleDlg::OnTimer") : dialog_source.index("BOOL CemuleDlg::OnDeviceChange")]
    assert "IDC_SHUTDOWN_STEP" in orphan_cleanup_block
    assert "IDC_PROGRESS1" in orphan_cleanup_block
    assert "GetResString(IDS_STARTING_EMULE)" in orphan_cleanup_block
    assert "::GetWindowThreadProcessId(hWnd, &dwWindowProcessId);" in orphan_cleanup_block
    assert "::GetCurrentProcessId()" in orphan_cleanup_block
    assert "EnumWindows(DestroyOrphanedStartupProgressWindowProc" in orphan_cleanup_block
    assert "EnumThreadWindows(" not in orphan_cleanup_block

    running_state_block = dialog_source[
        dialog_source.index("theApp.m_app_state = APP_STATE_RUNNING; //initialization completed") :
        dialog_source.index("UpdateBindLossMonitor(false);")
    ]
    assert "FinishStartupProgress();" in running_state_block


def _check_emule_dlg_source__upnp_startup_and_refresh_log_suppressed_exception_details() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    start_block = source[source.index("void CemuleDlg::StartUPnP") : source.index("void CemuleDlg::RefreshUPnP")]
    refresh_block = source[source.index("void CemuleDlg::RefreshUPnP") : source.index("void CemuleDlg::OnTimer")]

    assert 'CString strImplementationName(_T("<unknown>"));' in start_block
    assert "strImplementationName = impl->GetImplementationName();" in start_block
    assert "DebugLogWarning(_T(\"NAT mapping startup failed in backend '%s'\"), (LPCTSTR)strImplementationName);" in start_block
    assert "DebugLogWarning(_T(\"NAT mapping startup failed in backend '%s'%s\"), (LPCTSTR)strImplementationName, (LPCTSTR)CExceptionStrDash(*ex));" in start_block
    assert 'CString strImplementationName(_T("<unknown>"));' in refresh_block
    assert "strImplementationName = impl->GetImplementationName();" in refresh_block
    assert "DebugLogWarning(_T(\"NAT mapping refresh failed in backend '%s'\"), (LPCTSTR)strImplementationName);" in refresh_block
    assert "DebugLogWarning(_T(\"NAT mapping refresh failed in backend '%s'%s\"), (LPCTSTR)strImplementationName, (LPCTSTR)CExceptionStrDash(*ex));" in refresh_block


def _check_emule_dlg_source__upnp_result_logs_backend_diagnostic_details() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    result_block = source[source.index("LRESULT CemuleDlg::OnUPnPResult") : source.index("LRESULT CemuleDlg::OnPowerBroadcast")]

    assert "impl->GetLastResultSummary()" in result_block
    assert "mapping attempt timed out" in result_block
    assert "NAT mapping backend '%s' did not complete successfully: %s" in result_block
    assert "Trying fallback NAT mapping backend '%s' after failure: %s" in result_block
    assert "No more available NAT mapping backends left after failure: %s" in result_block
    assert "NAT mapping active via %s: %s" in result_block
    assert "NAT mapping diagnostic: %s" in result_block
    assert "NAT mapping refresh completed in backend '%s': %s" in result_block
    assert "NAT mapping refresh failed in backend '%s': %s" in result_block


def _check_emule_dlg_source__upnp_periodic_refresh_timer_lifecycle() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "EmuleDlg.h").read_text(encoding="utf-8", errors="ignore")
    connection_source = (app_source_root() / "PPgConnection.cpp").read_text(encoding="utf-8", errors="ignore")

    result_block = source[source.index("LRESULT CemuleDlg::OnUPnPResult") : source.index("LRESULT CemuleDlg::OnPowerBroadcast")]
    timer_block = source[source.index("void CemuleDlg::OnTimer") : source.index("BOOL CemuleDlg::OnDeviceChange")]
    start_timer_block = source[source.index("void CemuleDlg::StartUPnPRefreshTimer") : source.index("void CemuleDlg::StopUPnPRefreshTimer")]
    stop_timer_block = source[source.index("void CemuleDlg::StopUPnPRefreshTimer") : source.index("void CemuleDlg::OnTimer")]
    shutdown_block = source[source.index("// close uPnP Ports") : source.index("thePrefs.Save();")]
    resume_block = source[source.index("LRESULT CemuleDlg::OnPowerBroadcast") : source.index("void CemuleDlg::StartUPnP")]
    disable_block = connection_source[
        connection_source.index("if (thePrefs.IsUPnPEnabled() != (IsDlgButtonChecked(IDC_PREF_UPNPONSTART) != 0))") :
        connection_source.index("theApp.scheduler->SaveOriginals();")
    ]

    assert "static const UINT_PTR kUPnPRefreshTimerId = 0xB10F;" in source
    assert "static const UINT kUPnPRefreshIntervalMs = MIN2MS(20);" in source
    assert "UINT_PTR m_uUPnPRefreshTimer;" in header
    assert ", m_uUPnPRefreshTimer()" in source
    assert "StartUPnPRefreshTimer();" in result_block
    assert result_block.index("StartUPnPRefreshTimer();") < result_block.index("StopUPnPRefreshTimer();")
    assert "if (nIDEvent == kUPnPRefreshTimerId)" in timer_block
    assert "else if (m_hUPnPTimeOutTimer == 0)" in timer_block
    assert "RefreshUPnP(false);" in timer_block
    assert "SetTimer(kUPnPRefreshTimerId, kUPnPRefreshIntervalMs, NULL)" in start_timer_block
    assert "KillTimer(m_uUPnPRefreshTimer)" in stop_timer_block
    assert "StopUPnPRefreshTimer();" in disable_block
    assert "StopUPnPRefreshTimer();" in shutdown_block
    assert "RefreshUPnP(true);" not in resume_block


# --- consolidated from tests/python/test_friend_source.py ---


def _check_friend_source__set_linked_client_skips_refresh_after_friendlist_teardown() -> None:
    source = (app_source_root() / "Friend.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (theApp.friendlist != NULL)\n\t\ttheApp.friendlist->RefreshFriend(this);" in source


def _check_friend_source__try_to_connect_rejects_null_listener_before_queue_or_callback() -> None:
    source = (app_source_root() / "Friend.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pConnectionReport != NULL);\n\tif (pConnectionReport == NULL)\n\t\treturn false;\n\n\tif (m_FriendConnectState != FCS_NONE)" in source


# --- consolidated from tests/python/test_frozen_legacy_surfaces_source.py ---


def _check_frozen_legacy_surfaces_source__legacy_frozen_surfaces_are_called_out_at_class_boundary() -> None:
    app_root = app_source_root()

    web_server = (app_root / "WebServer.h").read_text(encoding="utf-8", errors="ignore")
    archive_recovery = (app_root / "ArchiveRecovery.h").read_text(encoding="utf-8", errors="ignore")
    archive_preview = (app_root / "ArchivePreviewDlg.h").read_text(encoding="utf-8", errors="ignore")

    assert "FROZEN DEPRECATED SURFACE: this is the legacy HTML/template Web Interface." in web_server
    assert web_server.index("FROZEN DEPRECATED SURFACE") < web_server.index("class CWebServer")
    assert "FROZEN DEPRECATED SURFACE: archive recovery is retained only for legacy" in archive_recovery
    assert archive_recovery.index("FROZEN DEPRECATED SURFACE") < archive_recovery.index("class CArchiveRecovery")
    assert "FROZEN DEPRECATED SURFACE: archive preview UI remains for legacy" in archive_preview
    assert archive_preview.index("FROZEN DEPRECATED SURFACE") < archive_preview.index("class CArchivePreviewDlg")


# --- consolidated from tests/python/test_irc_channel_tab_source.py ---


def _check_irc_channel_tab_source__remove_channel_checks_list_position_before_remove_at() -> None:
    source = (app_source_root() / "IrcChannelTabCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "m_lstChannels.RemoveAt(m_lstChannels.Find(pChannel));" not in source
    assert "POSITION posChannel = m_lstChannels.Find(pChannel);" in source
    assert "ASSERT(posChannel != NULL);" in source
    assert "if (posChannel != NULL)\n\t\tm_lstChannels.RemoveAt(posChannel);" in source


# --- consolidated from tests/python/test_kad_contact_quality_source.py ---


def _check_kad_contact_quality_source__kad_contact_quality_score_is_local_and_health_weighted() -> None:
    header = read_app_source("kademlia/routing/Contact.h")
    source = read_app_source("kademlia/routing/Contact.cpp")

    assert "UINT\tGetLocalQualityScore(time_t tNow = 0) const;" in header
    assert "bool\tIsWeakForReplacement(time_t tNow = 0) const;" in header
    assert "UINT CContact::GetLocalQualityScore(time_t tNow) const" in source
    assert "bool CContact::IsWeakForReplacement(time_t tNow) const" in source
    assert ", m_bReceivedHelloPacket()" in source
    assert ", m_bBootstrapContact()" in source
    assert "m_bIPVerified" in source
    assert "m_bReceivedHelloPacket" in source
    assert "!m_cUDPKey.IsEmpty()" in source
    assert "GetKadVersionQuality" in source
    assert "KADEMLIA_VERSION8_49b" in source


def _check_kad_contact_quality_source__kad_routing_uses_quality_for_probe_and_weak_replacement_only() -> None:
    routing_bin_header = read_app_source("kademlia/routing/RoutingBin.h")
    routing_bin_source = read_app_source("kademlia/routing/RoutingBin.cpp")
    routing_zone_source = read_app_source("kademlia/routing/RoutingZone.cpp")

    assert "GetLowestQualityExpiredContact(time_t tNow)" in routing_bin_header
    assert "ReplaceWeakContact(CContact *pContact" in routing_bin_header
    assert "KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN = 120" in routing_bin_source
    assert "GetWeakestReplaceableContact" in routing_bin_source
    assert "CanAcceptContactIPLimits" in routing_bin_source
    assert "m_pBin->ReplaceWeakContact" in routing_zone_source
    assert "replace-weak-contact" in routing_zone_source
    assert "weak-local-quality" in routing_zone_source
    assert "GetLowestQualityExpiredContact(tNow)" in routing_zone_source
    assert "GetRandomContact(uint32 nMaxType, uint32 nMinKadVersion)" in routing_bin_source


def _check_kad_contact_quality_source__kad_diagnostics_exposes_contact_quality_score() -> None:
    diagnostics = read_app_source("KadDiagnosticsSeams.cpp")
    routing_zone = read_app_source("kademlia/routing/RoutingZone.cpp")

    assert "local_quality_score" in diagnostics
    assert "GetLocalQualityScore(tNow)" in diagnostics
    assert "removed_quality_score" in routing_zone
    assert "new_quality_score" in routing_zone


# --- consolidated from tests/python/test_kad_diagnostics_source.py ---


def _check_kad_diagnostics_source__kad_diagnostics_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:KadDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableKadDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_KAD_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(KadDiagnosticsPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(BadPeerDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "$(KadDiagnosticsPreprocessorDefinition)"
        )
        assert config_definitions.index("$(KadDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def _check_kad_diagnostics_source__kad_diagnostics_build_and_release_plumbing() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")
    release_source = (BUILD_ROOT / "emule_workspace" / "release.py").read_text(encoding="utf-8")

    assert '"EMULEBB_ENABLE_KAD_DIAGNOSTICS", "EnableKadDiagnostics"' in build_source
    assert "/p:EnableKadDiagnostics=" in release_source
    assert "KAD_DIAGNOSTICS_BINARY_MARKERS" in release_source
    assert "emulebb-diagnostics-kad.log" in release_source
    assert "enable_kad_diagnostics" in release_source
    assert "kad-diagnostics" in release_source


def _check_kad_diagnostics_source__kad_diagnostics_logger_is_compile_gated() -> None:
    header = read_app_source("KadDiagnosticsSeams.h")
    source = read_app_source("KadDiagnosticsSeams.cpp")
    artifacts = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")

    assert "constexpr LPCTSTR kBinaryMarker = _T(\"KadDiagnostics:\");" in header
    assert "#if EMULEBB_HAS_KAD_DIAGNOSTICS" in header
    assert "inline void LogRoutingSummary" in header
    assert "inline void LogContactEvent" in header
    assert "inline void LogRawContactEvent" in header
    assert "inline void LogPacketEvent" in header
    assert "inline void LogSearchResponseEvent" in header
    assert "CLogFile g_kadDiagnosticsLog;" in source
    assert "kad_event_v1" in source
    assert "kad_routing_summary_v1" in source
    assert "WriteDiagnosticsJsonEvent(" in source
    assert "InitializeDiagnosticsLog(g_kadDiagnosticsLog, pszLogPath, uMaxLogFileSize)" in source
    assert "KadDiagnosticsLogFileName" in artifacts
    assert 'return _T("emulebb-diagnostics-kad.log");' in artifacts
    assert "KadDiagnosticsSeams::InitializeLog" in app_source


def _check_kad_diagnostics_source__kad_diagnostics_covers_health_and_bad_behavior_categories() -> None:
    joined = "\n".join(
        read_app_source(name)
        for name in (
            "kademlia/kademlia/Kademlia.cpp",
            "kademlia/kademlia/Search.cpp",
            "kademlia/net/PacketTracking.cpp",
            "kademlia/routing/RoutingZone.cpp",
            "KadDiagnosticsSeams.cpp",
        )
    )

    for event in (
        "kad_contact_added",
        "kad_contact_updated",
        "kad_contact_update_rejected",
        "kad_contact_rejected",
        "kad_contact_removed",
        "kad_contact_probe",
        "kad_contact_verified",
        "kad_request_flood",
        "kad_request_massive_flood",
        "kad_lookup_response_rejected",
        "kad_lookup_contact_rejected",
        "kad_keyword_result_tag_filtered",
        "kad_keyword_result_tag_rejected",
    ):
        assert event in joined

    assert "EMULEBB_KAD_LOG_ROUTING_SUMMARY" in joined
    assert "legacy_v2_to_v5" in joined
    assert "modern_v8_or_newer" in joined
    assert "version_histogram" in joined


# --- consolidated from tests/python/test_kad_routing_bin_source.py ---


def _check_kad_routing_bin_source__routing_bin_rejects_null_contact_inputs_before_deref() -> None:
    source = (app_source_root() / "kademlia" / "routing" / "RoutingBin.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool CRoutingBin::AddContact(CContact *pContact)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn false;" in source
    assert "void CRoutingBin::SetAlive(const CContact *pContact)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn;" in source
    assert "void CRoutingBin::RemoveContact(CContact *const pContact, bool bNoTrackingAdjust)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn;" in source
    assert "bool CRoutingBin::ChangeContactIPAddress(CContact *pContact, uint32 uNewIP)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn false;" in source
    assert "void CRoutingBin::PushToBottom(CContact *pContact) // puts an existing contact from X to the end of the list\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn;" in source


def _check_kad_routing_bin_source__routing_bin_skips_stale_null_entries_while_checking_duplicates() -> None:
    source = (app_source_root() / "kademlia" / "routing" / "RoutingBin.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const CContact *pExistingContact = *itContact;\n\t\tif (pExistingContact == NULL || pExistingContact == pIgnoredContact)\n\t\t\tcontinue;" in source
    assert "if (pContact->GetClientID() == pExistingContact->m_uClientID)\n\t\t\treturn false;" in source


# --- consolidated from tests/python/test_kad_ui_source.py ---


def _h_kad_ui_source__read_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def _check_kad_ui_source__kademlia_window_rejects_null_contacts_before_deref() -> None:
    source = _h_kad_ui_source__read_source("KademliaWnd.cpp")

    assert "bool CKademliaWnd::ContactAdd(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn false;" in source
    assert "void CKademliaWnd::ContactRem(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn;" in source
    assert "void CKademliaWnd::ContactRef(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn;" in source


def _check_kad_ui_source__kad_contact_controls_reject_null_contacts() -> None:
    histogram = _h_kad_ui_source__read_source("KadContactHistogramCtrl.cpp")
    contact_list = _h_kad_ui_source__read_source("KadContactListCtrl.cpp")

    assert "bool CKadContactHistogramCtrl::ContactAdd(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn false;" in histogram
    assert "void CKadContactHistogramCtrl::ContactRem(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn;" in histogram
    assert "ASSERT(contact != NULL);\n\t\tif (contact == NULL)\n\t\t\treturn false;" in contact_list
    assert contact_list.count("ASSERT(contact != NULL);\n\t\tif (contact == NULL)\n\t\t\treturn;") >= 2


def _check_kad_ui_source__kad_search_list_rejects_null_searches_before_lparam_lookup() -> None:
    source = _h_kad_ui_source__read_source("KadSearchListCtrl.cpp")

    assert source.count("ASSERT(search != NULL);\n\t\tif (search == NULL)\n\t\t\treturn;") >= 3
    assert "find.lParam = reinterpret_cast<LPARAM>(search);" in source


# --- consolidated from tests/python/test_known_file_list_source.py ---


def _check_known_file_list_source__known_file_stat_merge_rejects_null_inputs_before_size_compare() -> None:
    source = (app_source_root() / "KnownFileList.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pKeep != NULL);\n\t\tASSERT(pDiscard != NULL);\n\t\tif (pKeep == NULL || pDiscard == NULL)\n\t\t\treturn;\n\t\tASSERT(pKeep->GetFileSize() == pDiscard->GetFileSize());" in source


# --- consolidated from tests/python/test_known_file_source.py ---


def _check_known_file_source__known_file_hash_creation_rejects_missing_inputs() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.index('#include "EmuleMD4.h"') < source.index('#include "Kademlia/Kademlia/SearchManager.h"')
    assert "ROUND(static_cast<float>(uUserRatings) / static_cast<float>(uRatings))" in source
    assert "static_cast<double>(statistic.GetTransferred()) / static_cast<double>(nFileSize)" in source
    assert "static_cast<double>(statistic.GetAllTimeTransferred()) / static_cast<double>(nFileSize)" in source
    assert "ASSERT(pBlockAICHHashTree != NULL);\n\t\t\tif (pBlockAICHHashTree == NULL) {\n\t\t\t\tfclose(file);\n\t\t\t\treturn false;\n\t\t\t}" in source
    assert "ASSERT(pBlockAICHHashTree != NULL);\n\t\tif (pBlockAICHHashTree == NULL) {\n\t\t\tfclose(file);\n\t\t\treturn false;\n\t\t}" in source
    assert "ASSERT(!Length || pFile);\n\tASSERT(pMd4HashOut != NULL || pShaHashOut != NULL);\n\tif ((Length != 0 && pFile == NULL) || (pMd4HashOut == NULL && pShaHashOut == NULL))\n\t\treturn false;" in source
    assert "ASSERT(uSize == 0 || fp != NULL);\n\tif (uSize != 0 && fp == NULL)\n\t\treturn false;" in source
    assert "ASSERT(uSize == 0 || pucData != NULL);\n\tif (uSize != 0 && pucData == NULL)\n\t\treturn false;" in source


def _check_known_file_source__known_file_hash_creation_checks_short_reads_in_release_builds() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CKnownFile::CreateHash(CFile *pFile") : source.index("bool CKnownFile::CreateHash(FILE *fp")]

    assert "VERIFY(pFile->Read(X, uRead) == uRead);" not in block
    assert "std::unique_ptr<CAICHHashAlgo> pHashAlg" in block
    assert "const UINT uActualRead = pFile->Read(X, uRead);" in block
    assert "if (uActualRead != uRead)\n\t\t\tAfxThrowFileException(CFileException::endOfFile, 0, pFile->GetFilePath());" in block
    assert "static_assert(kHashReadBufferBytes < EMBLOCKSIZE" in block
    assert "pShaHashOut->SetBlockHash(EMBLOCKSIZE, posCurrentEMBlock, pHashAlg.get());" in block


def _check_known_file_source__known_file_hash_wrappers_log_exception_details() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogWarning(_T("CreateHash failed while reading stdio-backed data%s"), (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("CreateHash failed while reading memory-backed data%s"), (LPCTSTR)CExceptionStrDash(*ex));' in source


def _check_known_file_source__known_file_metadata_extractors_log_exception_details() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogWarning(_T("Unhandled exception while extracting file meta data through MediaInfo.dll from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting built-in file meta data from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting fallback media metadata from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting MP3 file meta data from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting file meta data through MediaInfo.dll from \\"%s\\" - unexpected exception"), (LPCTSTR)strFullPath);' in source


# --- consolidated from tests/python/test_list_box_st_source.py ---


def _check_list_box_st_source__list_box_item_data_helpers_reject_invalid_slots_before_deref() -> None:
    source = (app_source_root() / "ListBoxST.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (nIndex < 0 || nIndex >= GetCount())\n\t\treturn LB_ERR;\n\n\t// Get pointer to associated data (if any)" in source
    assert "if (lpLBData == (LPVOID)-1)\n\t\treturn LB_ERR;" in source
    assert "if (nIndex < 0 || nIndex >= GetCount())\n\t\treturn;\n\n\t// Get pointer to associated data (if any)" in source
    assert "if (lpLBData != NULL && lpLBData != (LPVOID)-1)\n\t\tdelete lpLBData;" in source
    assert "if (lpLBData != NULL && lpLBData != (LPVOID)-1)\n\t\treturn lpLBData->dwItemData;" in source
    assert "return (lpLBData != NULL && lpLBData != (LPVOID)-1) ? lpLBData->pData : (LPVOID)-1;" in source


def _check_list_box_st_source__list_box_move_stops_when_reinsert_fails() -> None:
    source = (app_source_root() / "ListBoxST.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "int nInsertedIndex = InsertString(nNewIndex, sText);\n\tif (nInsertedIndex == LB_ERR || nInsertedIndex == LB_ERRSPACE)\n\t\treturn nInsertedIndex;\n\n\t// Restore associated data" in source


# --- consolidated from tests/python/test_list_view_property_sheet_source.py ---


def _check_list_view_property_sheet_source__list_view_property_sheet_insert_page_rejects_null_page() -> None:
    source = (app_source_root() / "ListViewWalkerPropertySheet.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pPage != NULL);\n\tif (pPage == NULL)\n\t\treturn;\n\tASSERT_KINDOF(CPropertyPage, pPage);" in source


# --- consolidated from tests/python/test_listen_socket_source.py ---


def _check_listen_socket_source__packet_received_preserves_mfc_exception_details_before_generic_unknown() -> None:
    source = (APP_ROOT / "srchybrid" / "ListenSocket.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CClientReqSocket::PacketReceived(Packet *packet)") : source.index("void CClientReqSocket::OnReceive")]
    catch_block = block[block.index("} catch (CException *ex) {") : block.index("#ifndef _DEBUG")]

    assert "} catch (CException *ex) {" in block
    assert "} catch (CClientException *) {\n\t\t\tthrow;\n\t\t} catch (CFileException *ex) {" in block
    assert "} catch (const CString &) {\n\t\t\tthrow;\n#ifndef _DEBUG" in block
    assert block.index("} catch (CClientException *) {") < block.index("} catch (CException *ex) {")
    assert block.index("} catch (const CString &) {") < block.index("} catch (...) {\n\t\t\tthrowCStr(_T(\"Unknown exception\"));")
    assert 'strError.Format(_T("%s%s"), (LPCTSTR)GetResString(IDS_ERR_INVALIDPACKET), (LPCTSTR)CExceptionStrDash(*ex));' in catch_block
    assert catch_block.index("CExceptionStrDash(*ex)") < catch_block.index("ex->Delete();")
    assert block.index("} catch (CException *ex) {") < block.index("} catch (...) {\n\t\t\tthrowCStr(_T(\"Unknown exception\"));")


def _check_listen_socket_source__shared_browse_requests_use_shared_file_snapshots() -> None:
    source = (APP_ROOT / "srchybrid" / "ListenSocket.cpp").read_text(encoding="utf-8", errors="ignore")
    full_list_block = source[source.index("case OP_ASKSHAREDFILES:") : source.index("case OP_ASKSHAREDFILESANSWER:")]
    directory_block = source[source.index("case OP_ASKSHAREDFILESDIR:") : source.index("case OP_ASKSHAREDFILESDIRANS:")]

    assert "CopyAllSharedFiles(sharedFiles);" in full_list_block
    assert "CopySingleSharedFiles(singleSharedFiles);" in directory_block
    assert "CopySharedFilesForDirectory(strReqDir, directoryFiles);" in directory_block
    assert "m_Files_map.PGetFirstAssoc" not in full_list_block
    assert "m_Files_map.PGetFirstAssoc" not in directory_block
    assert "ShouldBeShared(cur_file->GetSharedDirectory(), NULL, false)" not in directory_block


# --- consolidated from tests/python/test_live_dump_regression_source.py ---


def _check_live_dump_regression_source__low_id_upload_callback_does_not_assert_on_upload_connecting_state() -> None:
    source = (app_source_root() / "BaseClient.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("// 6) Server Callback + 7) Kad Callback") : source.index("if (theApp.serverconnect->IsLocalServer")]

    assert "Upload admission deliberately marks a not-yet-connected slot" in block
    assert "ConnectionEstablished sends OP_ACCEPTUPLOADREQ" in block
    assert "ASSERT(0)" not in block
    assert "LowID upload callback while US_CONNECTING" in block


def _check_live_dump_regression_source__client_list_cleanup_uses_full_delete_readiness_predicate() -> None:
    client_list = (app_source_root() / "ClientList.cpp").read_text(encoding="utf-8", errors="ignore")
    delete_seams = (app_source_root() / "UpDownClientDeleteSeams.cpp").read_text(encoding="utf-8", errors="ignore")
    delete_header = (app_source_root() / "UpDownClientDeleteSeams.h").read_text(encoding="utf-8", errors="ignore")
    cleanup = client_list[client_list.index("void CClientList::CleanUpClientList") : client_list.index("CDeletedClient::CDeletedClient")]
    predicate = delete_seams[delete_seams.index("bool UpDownClientDeleteSeams::IsReadyForClientListCleanup") : delete_seams.index("void UpDownClientDeleteSeams::AssertReadyToDelete")]

    assert "bool IsReadyForClientListCleanup(const CUpDownClient *pClient);" in delete_header
    assert "IsReadyForClientListCleanup(pCurClient)" in cleanup
    assert "request-file" in cleanup
    assert "use-after-free" in cleanup
    assert "pClient->GetRequestFile() != NULL" in predicate
    assert "pClient->m_OtherRequests_list.IsEmpty()" in predicate
    assert "theApp.downloadqueue->IsInList(pClient)" in predicate
    assert "theApp.uploadqueue->IsOnUploadQueue" in predicate


def _check_live_dump_regression_source__corruption_blackbox_recomputes_merge_target_after_record_mutation() -> None:
    source = (app_source_root() / "CorruptionBlackBox.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CCorruptionBlackBox::ReceivedData") : source.index("void CCorruptionBlackBox::VerifiedData")]

    assert "Any merge index" in block
    assert "after normalization is complete" in block
    assert "if (posMerge < 0 || !m_aaRecords[nPart][posMerge].Merge" in block
    assert "VERIFY(m_aaRecords[nPart][posMerge].Merge" not in block
    assert "ndbgRewritten += nRelEndPos - cbbRec.m_nStartPos + 1;" in block
    assert "ndbgRewritten += cbbRec.m_nEndPos - nRelStartPos + 1;" in block


def _check_live_dump_regression_source__disconnect_deletes_only_after_request_file_detach() -> None:
    source = (app_source_root() / "BaseClient.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CUpDownClient::Disconnected") : source.index("// Returned bool is not about whether the connect attempt succeeded.")]

    assert "while the same CUpDownClient is still the upload slot owner" in block
    assert "upload queue will keep using" in block
    assert "bDelete = false;" in block
    assert "a client can be banned after it entered the waiting queue" in block
    assert "theApp.uploadqueue->RemoveFromWaitingQueue(this, true);" in block
    assert "live disconnect dumps showed a client in DS_NONE/US_NONE" in block
    assert "return \"delete me\" with that pointer still set" in block
    assert "RemoveSource is the central mirror cleanup" in block
    assert "if (bDelete && m_reqfile != NULL)" in block
    assert "theApp.downloadqueue->RemoveSource(this);" in block


def _check_live_dump_regression_source__banned_waiting_upload_client_is_detached_before_banned_state() -> None:
    source = (app_source_root() / "UploadClient.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CUpDownClient::Ban") : source.index("ULONGLONG CUpDownClient::GetWaitStartTime")]

    assert "the waiting queue stores raw CUpDownClient pointers" in block
    assert "Drop the waiting-list edge before setting US_BANNED" in block
    assert "theApp.uploadqueue->RemoveFromWaitingQueue(this, true);" in block
    assert block.index("RemoveFromWaitingQueue(this, true);") < block.index("SetUploadState(US_BANNED);")


def _check_live_dump_regression_source__duplicate_temp_source_detaches_request_file_before_attach_delete() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CDownloadQueue::CheckAndAddSource") : source.index("bool CDownloadQueue::RemoveSource")]

    assert "server/source-exchange probes are constructed with sender as their" in block
    assert "AttachToAlreadyKnown" in block
    assert "deletes the temporary probe immediately" in block
    assert "source->SetRequestFile(NULL);" in block
    assert "const bool bAttachedKnownClient = theApp.clientlist->AttachToAlreadyKnown(&source, NULL);" in block


# --- consolidated from tests/python/test_log_source.py ---


def _check_log_source__log_helpers_reject_null_format_strings() -> None:
    source = (app_source_root() / "Log.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.count("ASSERT(pszLine != NULL);\n\tif (pszLine == NULL)\n\t\treturn;") >= 4
    assert "void AddLogTextV(UINT uFlags, EDebugLogPriority dlpPriority, LPCTSTR pszLine, va_list argptr)" in source


def _check_log_source__main_dialog_keeps_disk_log_lines_complete_when_ui_rows_are_truncated() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    helper_block = source[source.index("constexpr int kMaxUiLogLineChars") : source.index("void CemuleDlg::AddLogText")]
    add_log_block = source[source.index("void CemuleDlg::AddLogText") : source.index("void CemuleDlg::BeginLogBatchUpdate")]

    assert "CString BuildLogLine(const CTime &timestamp, LPCTSTR pszText)" in helper_block
    assert "CString BuildUiLogLine(const CTime &timestamp, LPCTSTR pszText)" in helper_block
    assert "strLogLine.Truncate(kMaxUiLogLineChars - 2);" in helper_block
    assert 'strLogLine += _T("\\r\\n");' in helper_block

    assert "const CString strUiLogLine(BuildUiLogLine(timestamp, pszText));" in add_log_block
    assert "const CString strDiskLogLine(BuildLogLine(timestamp, pszText));" in add_log_block
    assert "serverwnd->logbox->AddTyped(strUiLogLine, iUiLen" in add_log_block
    assert "serverwnd->debuglog->AddTyped(strUiLogLine, iUiLen" in add_log_block
    assert "theLog.Log(strDiskLogLine, iDiskLen);" in add_log_block
    assert "theVerboseLog.Log(strDiskLogLine, iDiskLen);" in add_log_block
    assert "theLog.Log(strUiLogLine" not in add_log_block
    assert "theVerboseLog.Log(strUiLogLine" not in add_log_block


# --- consolidated from tests/python/test_mule_list_ctrl_source.py ---


def _check_mule_list_ctrl_source__end_scroll_cleanup_releases_window_dc() -> None:
    source = (app_source_root() / "MuleListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CMuleListCtrl::OnLvnEndScrollList") : source.index("void CMuleListCtrl::InitItemMemDC")]

    assert "GetDC()->" not in block
    assert "CDC *pDC = GetDC();" in block
    assert "pDC->FillSolidRect(&rcClient, GetBkColor());" in block
    assert "ReleaseDC(pDC);" in block


def _check_mule_list_ctrl_source__shadow_param_list_resyncs_before_position_access() -> None:
    source = (app_source_root() / "MuleListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "MuleListCtrl.h").read_text(encoding="utf-8", errors="ignore")

    assert "bool CMuleListCtrl::EnsureParamSnapshot(bool bForce)" in source
    assert "m_Params.AddTail(CListCtrl::GetItemData(i));" in source
    assert "if (!EnsureParamSnapshot())\n\t\treturn iItem;" in source
    assert "if (pos == NULL)\n\t\t\treturn iItem;" in source
    assert "EnsureParamSnapshot(true);" in source
    assert "MLC_ASSERT(m_Params.GetAt(m_Params.FindIndex(wParam))" not in source
    assert "m_Params.RemoveAt(m_Params.FindIndex(wParam));" not in source
    assert "m_Params.InsertAfter(m_Params.FindIndex(lResult - 1)" not in source
    assert "bool EnsureParamSnapshot(bool bForce = false);" in header
    assert "if (pos == NULL)\n\t\t\treturn (iPos >= 0 && iPos < GetItemCount())" in header


def _check_mule_list_ctrl_source__view_preset_command_pairs_live_lists_with_explicit_profiles() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CemuleDlg::ApplyViewPresetCommand") : source.index("void CemuleDlg::ShowToolPopupAt")]

    assert "{transferwnd != NULL ? transferwnd->GetUploadList() : NULL, _T(\"UploadListCtrl\")}" in block
    assert "{transferwnd != NULL ? transferwnd->GetQueueList() : NULL, _T(\"QueueListCtrl\")}" in block
    assert "MuleListCtrlViewPresets::FindProfile(liveList.pszProfileName)" in block
    assert "liveList.pList->SetViewPresetProfile(*profile);" in block
    assert "liveList.pList->ApplyViewPreset(ePreset, eWidthMode);" in block


# --- consolidated from tests/python/test_oscope_ctrl_source.py ---


def _h_oscope_ctrl_source___app_source_root() -> Path:
    workspace_root = Path(__file__).resolve().parents[4]
    return workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def _check_oscope_ctrl_source__oscope_recreate_graph_does_not_trust_only_first_trend_iterator() -> None:
    source = (_h_oscope_ctrl_source___app_source_root() / "OScopeCtrl.cpp").read_text(
        encoding="utf-8",
        errors="ignore",
    )

    assert "while (pPosArray[0] != NULL)" not in source
    assert "new POSITION[m_NTrends]" not in source
    assert "new double[m_NTrends]" not in source
    assert "std::vector<POSITION> posArray" in source
    assert "nPointsToDraw = min(nPointsToDraw, m_PlotData[iTrend].lstPoints.GetCount())" in source
    assert "if (posArray[iTrend] == NULL)" in source


def _check_oscope_ctrl_source__oscope_public_trend_api_checks_indices_in_release() -> None:
    source = (_h_oscope_ctrl_source___app_source_root() / "OScopeCtrl.cpp").read_text(
        encoding="utf-8",
        errors="ignore",
    )
    header = (_h_oscope_ctrl_source___app_source_root() / "OScopeCtrl.h").read_text(
        encoding="utf-8",
        errors="ignore",
    )

    assert "bool IsValidTrendIndex(int iTrend) const;" in header
    assert "m_NTrends = NTrends > 0 ? NTrends : 1;" in source
    assert "bool COScopeCtrl::IsValidTrendIndex(int iTrend) const" in source
    assert "return m_PlotData != NULL && iTrend >= 0 && iTrend < m_NTrends;" in source
    assert "if (!IsValidTrendIndex(iTrend) || iRatio == 0)\n\t\treturn;" in source
    assert "if (!IsValidTrendIndex(iTrend))\n\t\treturn;" in source
    assert "if (dUpper <= dLower || !IsValidTrendIndex(iTrend))\n\t\treturn;" in source
    assert "return CLR_INVALID;" in source
    assert "if (dNewPoint == NULL || m_PlotData == NULL)\n\t\treturn;" in source
    assert "reinterpret_cast<HMENU>(static_cast<UINT_PTR>(nID))" in source
    assert "static_cast<float>(shownsecs) / static_cast<float>(plotRect.Width())" in source


def _check_oscope_ctrl_source__oscope_invalidate_does_not_require_parent_window() -> None:
    source = (_h_oscope_ctrl_source___app_source_root() / "OScopeCtrl.cpp").read_text(
        encoding="utf-8",
        errors="ignore",
    )

    assert "CWnd *pParentWnd = GetParent();\n\t\tHBRUSH hbr = pParentWnd != NULL ? (HBRUSH)pParentWnd->SendMessage(WM_CTLCOLORSTATIC, (WPARAM)dc.m_hDC, (LPARAM)m_hWnd) : NULL;" in source


# --- consolidated from tests/python/test_out_of_part_reqs_loop_guard_source.py ---


def _check_out_of_part_reqs_loop_guard_source__out_of_part_reqs_packet_uses_client_owned_handler() -> None:
    listen_socket = read_app_source("ListenSocket.cpp")
    block = listen_socket[
        listen_socket.index("case OP_OUTOFPARTREQS:") :
        listen_socket.index("case OP_CHANGE_CLIENT_ID:")
    ]

    assert "client->ProcessInboundOutOfPartReqs();" in block
    assert "client->SetDownloadState(DS_ONQUEUE" not in block


def _check_out_of_part_reqs_loop_guard_source__inbound_out_of_part_reqs_records_before_download_state_demotion() -> None:
    download_client = read_app_source("DownloadClient.cpp")
    block = download_client[
        download_client.index("void CUpDownClient::ProcessInboundOutOfPartReqs()") :
        download_client.index("void CUpDownClient::ProcessAcceptUpload()")
    ]

    assert "if (GetDownloadState() != DS_DOWNLOADING)\n\t\treturn;" in block
    assert block.index("NoteInboundOutOfPartReqs();") < block.index("SetDownloadState(DS_ONQUEUE")


def _check_out_of_part_reqs_loop_guard_source__accept_upload_checks_out_of_part_reqs_guard_before_start_download() -> None:
    download_client = read_app_source("DownloadClient.cpp")
    block = download_client[
        download_client.index("void CUpDownClient::ProcessAcceptUpload()") :
        download_client.index("void CUpDownClient::ProcessEdonkeyQueueRank")
    ]

    assert block.index("CanAcceptUploadSlotAfterOutOfPartReqs(&strOutOfPartReqsGuardReason)") < block.index("StartDownload();")
    assert block.index("return;") < block.index("StartDownload();")
    assert "if (socket != NULL && IsEd2kClient())\n\t\t\t\t\tSendCancelTransfer();" in block
    assert block.index("SetSentCancelTransfer(0);") > block.index("CanAcceptUploadSlotAfterOutOfPartReqs")


def _check_out_of_part_reqs_loop_guard_source__out_of_part_reqs_guard_thresholds_are_balanced_and_client_global() -> None:
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


def _check_out_of_part_reqs_loop_guard_source__out_of_part_reqs_guard_logs_transitions_and_suppression_with_context() -> None:
    download_client = read_app_source("DownloadClient.cpp")

    assert "DebugLogWarning(_T(\"Cooling down download source after repeated OP_OutOfPartReqs loops." in download_client
    assert "DebugLogWarning(_T(\"Quarantined download source after repeated OP_OutOfPartReqs loops." in download_client
    assert "DebugLogWarning(_T(\"Quarantined download source after repeated OP_OutOfPartReqs cooldown bursts." in download_client
    assert "DebugLogWarning(_T(\"Quarantined download source after repeated suppressed OP_AcceptUploadReq during OP_OutOfPartReqs cooldown." in download_client
    assert "DebugLog(_T(\"Suppressed OP_AcceptUploadReq after repeated OP_OutOfPartReqs loops." in download_client
    assert "constexpr ULONGLONG kOutOfPartReqsSuppressionLogMs = SEC2MS(30);" in download_client
    assert "m_ullOutOfPartReqsLastSuppressionLog" in download_client
    assert download_client.count("DbgGetClientInfo()") >= 3


# --- consolidated from tests/python/test_packet_diagnostics_source.py ---


def _h_packet_diagnostics_source__read_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def _h_packet_diagnostics_source__read_build_source(name: str) -> str:
    return (BUILD_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def _check_packet_diagnostics_source__packet_diagnostics_compile_flag_is_opt_in() -> None:
    project = _h_packet_diagnostics_source__read_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:PacketDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnablePacketDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_PACKET_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(PacketDiagnosticsPreprocessorDefinition)" in config_definitions
        assert "MBEDTLS_ALLOW_PRIVATE_ACCESS" in config_definitions
        assert config_definitions.index("$(PacketDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )
    release_definitions = [
        config_definitions for config_definitions in preprocessor_definitions if "NDEBUG" in config_definitions
    ]
    assert len(release_definitions) == 1
    assert "$(StartupDiagnosticsPreprocessorDefinition)" in release_definitions[0]


def _check_packet_diagnostics_source__packet_diagnostics_build_env_override_is_available() -> None:
    build_source = _h_packet_diagnostics_source__read_build_source("emule_workspace/build.py")

    assert '"EMULEBB_ENABLE_PACKET_DIAGNOSTICS", "EnablePacketDiagnostics"' in build_source
    assert 'extra_properties.append(f"/p:{property_name}=' in build_source


def _check_packet_diagnostics_source__startup_diagnostics_compile_flag_is_opt_in() -> None:
    project = _h_packet_diagnostics_source__read_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:StartupDiagnosticsPreprocessorDefinition", namespace)

    assert "<EnableStartupDiagnostics Condition=\"'$(EnableStartupDiagnostics)'==''\">false</EnableStartupDiagnostics>" in project
    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableStartupDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_STARTUP_DIAGNOSTICS;"


def _check_packet_diagnostics_source__startup_diagnostics_trace_uses_log_artifact_name() -> None:
    emule_source = _h_packet_diagnostics_source__read_source("Emule.cpp")
    artifacts = _h_packet_diagnostics_source__read_source("LogArtifactNames.h")

    assert "inline LPCTSTR StartupDiagnosticsTraceFileName()" in artifacts
    assert 'return _T("emulebb-diagnostics-startup.trace.json");' in artifacts
    assert (
        "m_strStartupDiagnosticsPath = thePrefs.GetMuleDirectory(EMULE_LOGDIR, false) + "
        "LogArtifactNames::StartupDiagnosticsTraceFileName();"
    ) in emule_source
    assert '"startup-diagnostics.trace.json"' not in emule_source


def _check_packet_diagnostics_source__retired_diagnostic_flags_are_rejected_at_feature_header_only() -> None:
    feature_header = _h_packet_diagnostics_source__read_source("BuildFeatures.h")
    combined_sources = "\n".join(
        _h_packet_diagnostics_source__read_source(name)
        for name in [
            "AsyncSocketEx.cpp",
            "AsyncSocketEx.h",
            "AsyncSocketExLayer.cpp",
            "Emule.cpp",
            "EmuleDlg.cpp",
            "EMSocket.cpp",
            "Preferences.cpp",
            "Preferences.h",
        ]
    )

    for flag in (
        "EMULEBB_DISABLE_SOCKET_STATES",
        "EMULEBB_DEV_BUILD",
        "EMULEBB_ENABLE_DEBUG_DEVICE",
        "EMULEBB_DEBUG_EMSOCKET",
    ):
        assert f"#if defined({flag})" in feature_header
        assert flag not in combined_sources

    assert "EMULEBB_STARTUP_DIAGNOSTICS" not in combined_sources


def _check_packet_diagnostics_source__packet_diagnostics_logging_api_is_compile_guarded() -> None:
    log_header = _h_packet_diagnostics_source__read_source("Log.h")
    log_source = _h_packet_diagnostics_source__read_source("Log.cpp")
    emule_source = _h_packet_diagnostics_source__read_source("Emule.cpp")
    artifacts = _h_packet_diagnostics_source__read_source("LogArtifactNames.h")

    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nextern CLogFile thePacketDiagnosticsLog;" in log_header
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\n#include \"Opcodes.h\"\n#endif" in log_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nconstexpr UINT kMaxPacketDiagnosticsPayloadHexBytes = 4 * 1024;" in log_source
    assert "CCriticalSection g_packetDiagnosticsLogLock;" in log_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nvoid PacketDiagnosticsLogInvalidSubOpcode(" in log_source
    assert '\\"schema\\":\\"ed2k_invalid_sub_opcode_v1\\"' in log_source
    assert '\\"context_hex\\":\\"%s\\",\\"payload_hex_truncated\\":%s,\\"payload_hex\\":\\"%s\\"' in log_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nCLogFile thePacketDiagnosticsLog;" in emule_source
    assert "InitializeDiagnosticsLog(thePacketDiagnosticsLog, strDiagnosticsLogDir + LogArtifactNames::PacketDiagnosticsLogFileName(), thePrefs.GetMaxLogFileSize())" in emule_source
    assert "WriteDiagnosticsLogLine(thePacketDiagnosticsLog, g_packetDiagnosticsLogLock, strJson)" in log_source
    assert "bool InitializeDiagnosticsLog(CLogFile &rLog, LPCTSTR pszLogPath, UINT uMaxLogFileSize)" in log_header
    assert "void WriteDiagnosticsLogLine(CLogFile &rLog, CCriticalSection &rLock, const CString &rstrLine)" in log_header
    assert "void WriteDiagnosticsLogLineV(CLogFile &rLog, CCriticalSection &rLock, LPCTSTR pszFmt, va_list argp)" in log_header
    assert "void WriteDiagnosticsLogLineF(CLogFile &rLog, CCriticalSection &rLock, LPCTSTR pszFmt, ...)" in log_header
    assert "CString NormalizeDiagnosticsJsonPayload(LPCTSTR pszJsonOrText);" in log_header
    assert "void WriteDiagnosticsJsonEvent(" in log_header
    assert "NormalizeDiagnosticsJsonPayload" in log_source
    assert "WriteDiagnosticsJsonEvent" in log_source
    assert "class CDiagnosticsKeyValueLineBuilder" in log_header
    assert "void AppendFormat(LPCTSTR pszKeyValueFmt, ...);" in log_header
    assert "CDiagnosticsKeyValueLineBuilder::AppendFormat" in log_source
    assert "VERIFY(rLog.SetFlushOnWrite(true));" in log_source
    assert "WriteDiagnosticsLogLineV(theUploadSlotDiagnosticsLog, g_uploadSlotDiagnosticsLogLock, pszFmt, argp)" in log_source
    assert "WriteDiagnosticsLogLineV(theDownloadSlotDiagnosticsLog, g_downloadSlotDiagnosticsLogLock, pszFmt, argp)" in log_source
    assert "constexpr ULONGLONG kDiagnosticsDiskFlushIntervalMs = 1000;" in log_source
    assert "bool FlushToDisk();" in log_header
    assert "bool CLogFile::FlushToDisk()" in log_source
    assert "_commit(_fileno(m_fp)) == 0" in log_source
    assert "FlushDiagnosticsLogToDiskIfDue(rLog, s_ullLastDiagnosticsDiskFlushTick, ::GetTickCount64());" in log_source
    assert "LogArtifactNames::PacketDiagnosticsLogFileName()" in emule_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\ninline LPCTSTR PacketDiagnosticsLogFileName()" in artifacts
    assert 'return _T("emulebb-diagnostics-packet.log");' in artifacts


def _check_packet_diagnostics_source__rest_recent_log_ring_is_bounded_and_clearable() -> None:
    log_header = _h_packet_diagnostics_source__read_source("Log.h")
    log_source = _h_packet_diagnostics_source__read_source("Log.cpp")
    rest_source = _h_packet_diagnostics_source__read_source("WebServerJson.cpp")

    assert "void ClearRecentLogEntries();" in log_header
    assert "constexpr int kMaxRecentLogEntryChars = 4 * 1024;" in log_source
    assert "TruncateLogLine(CString(pszText != NULL ? pszText : _T(\"\")), kMaxRecentLogEntryChars)" in log_source
    assert "void ClearRecentLogEntries()\n{" in log_source
    assert "ClearRecentLogEntries();" in rest_source


def _check_packet_diagnostics_source__invalid_sub_opcode_diagnostics_call_sites_are_guarded() -> None:
    source = _h_packet_diagnostics_source__read_source("ListenSocket.cpp")

    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nCString BuildPacketDiagnosticsPeerLabel(" in source
    assert "void LogInvalidMultipacketSubOpcode(" in source
    assert "const ULONGLONG ullInvalidOffset = (ullPosition > 0) ? (ullPosition - 1) : 0;" in source
    assert "const ULONGLONG ullBytesRemaining = (ullLength > ullPosition) ? (ullLength - ullPosition) : 0;" in source

    request_block = source[source.index("case OP_MULTIPACKET_EXT2:") : source.index("case OP_MULTIPACKETANSWER:")]
    answer_block = source[source.index("case OP_MULTIPACKETANSWER:") : source.index("case OP_EMULEINFO:")]

    shared_guard = "#if defined(EMULEBB_ENABLE_PACKET_DIAGNOSTICS) || EMULEBB_HAS_BAD_PEER_DIAGNOSTICS\n\t\t\tint iPreviousSubOpcode = -1;\n#endif"
    assert shared_guard in request_block
    assert shared_guard in answer_block
    assert "LogInvalidMultipacketSubOpcode(_T(\"multipacket_request\"), client, opcode, packet, size, opcode_in, data_in, iPreviousSubOpcode);" in request_block
    assert "LogInvalidMultipacketSubOpcode(_T(\"multipacket_answer\"), client, opcode, packet, size, opcode_in, data_in, iPreviousSubOpcode);" in answer_block
    assert request_block.index("LogInvalidMultipacketSubOpcode(_T(\"multipacket_request\")") < request_block.index("strError.Format(_T(\"Invalid sub opcode 0x%02x received\"), opcode_in);")
    assert answer_block.index("LogInvalidMultipacketSubOpcode(_T(\"multipacket_answer\")") < answer_block.index("strError.Format(_T(\"Invalid sub opcode 0x%02x received\"), opcode_in);")


def _check_packet_diagnostics_source__packet_diagnostics_emit_converged_ed2k_packet_v1_schema() -> None:
    # Both eMuleBB packet emitters converge on the shared ed2k_packet_v1 schema so
    # the trace diffs 1:1 against the emulebb-rust client-to-client packet dump.
    log_header = _h_packet_diagnostics_source__read_source("Log.h")
    log_source = _h_packet_diagnostics_source__read_source("Log.cpp")

    # Client-to-client (peer) emitter declared + defined alongside the server one.
    assert "void PacketDiagnosticsLogClientPacket(" in log_header
    assert "void PacketDiagnosticsLogClientPacket(" in log_source
    assert "void PacketDiagnosticsLogServerPacket(" in log_source

    # Shared emitter + converged schema with a flow discriminator + trace_key.
    assert "static void PacketDiagnosticsLogEd2kPacket(" in log_source
    assert '\\"schema\\":\\"ed2k_packet_v1\\"' in log_source
    assert '\\"flow\\":\\"%s\\"' in log_source
    assert '\\"trace_key\\":\\"%s\\"' in log_source
    # The retired per-family schema name must be gone (fully converged).
    assert "ed2k_server_packet_v1" not in log_source

    # Server uses flow="server", client uses flow="client".
    assert 'PacketDiagnosticsLogEd2kPacket(_T("server")' in log_source
    assert 'PacketDiagnosticsLogEd2kPacket(_T("client")' in log_source


def _check_packet_diagnostics_source__packet_diagnostics_client_packet_call_sites_are_guarded() -> None:
    # The client-to-client recv dispatch and send path both emit one ed2k_packet_v1
    # record per packet, compile-gated on EMULEBB_ENABLE_PACKET_DIAGNOSTICS.
    source = _h_packet_diagnostics_source__read_source("ListenSocket.cpp")

    recv = source[source.index("bool CClientReqSocket::PacketReceived(") : source.index("void CClientReqSocket::SendPacket(")]
    send = source[source.index("void CClientReqSocket::SendPacket(") :]
    send = send[: send.index("CListenSocket::")]

    for block, direction in ((recv, "recv"), (send, "send")):
        assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS" in block
        assert "PacketDiagnosticsLogClientPacket(BuildPacketDiagnosticsPeerLabel(client)," in block
        assert "GetPacketDiagnosticsTransportMode(client)" in block
        assert f'_T("{direction}")' in block
        assert "packet->prot, packet->opcode, (const BYTE*)packet->pBuffer, packet->size)" in block


def _check_packet_diagnostics_source__packet_diagnostics_does_not_port_full_tracing_harness() -> None:
    combined = "\n".join(_h_packet_diagnostics_source__read_source(name) for name in ["ListenSocket.cpp", "Log.cpp", "Log.h", "Emule.cpp"])

    assert "OracleEd2kTcpDump" not in combined
    assert "OracleUdpDump" not in combined


# --- consolidated from tests/python/test_part_file_source.py ---


def _check_part_file_source__part_file_buffer_errors_do_not_report_success_as_unknown_write_error() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "item->dwError != ERROR_SUCCESS ? item->dwError : ERROR_WRITE_FAULT" in source
    assert "CFileException::ThrowOsError((LONG)item->dwError, m_hpartfile.GetFileName());" not in source


def _check_part_file_source__part_file_flush_retires_written_buffers_before_sizing_unwritten_data() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "PartFile.h").read_text(encoding="utf-8", errors="ignore")
    flush_block = source[source.index("void CPartFile::FlushBuffer") : source.index("void CPartFile::FlushBuffersExceptionHandler")]
    process_start = source.index("uint32 CPartFile::Process")
    process_block = source[process_start : source.index("bool CPartFile::CanAddSource", process_start)]
    cleanup_block = source[source.index("void CPartFile::DeleteWrittenItems()") : source.index("void CPartFile::SetCategory")]
    write_thread = (app_source_root() / "PartFileWriteThread.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "void\tDeleteWrittenItems();" in header
    assert "volatile LONG m_bBufferedWriteCompletionsPending;" in header
    assert "void\tNoteBufferedWriteCompletion()" in header
    assert "bool\tHasBufferedWriteCompletionsPending() const;" in header
    assert "bool\tConsumeBufferedWriteCompletionsPending();" in header
    assert "DeleteWrittenItems();" in flush_block
    assert flush_block.index("DeleteWrittenItems();") < flush_block.index("ULONGLONG cursize = m_hpartfile.GetLength();")
    assert "GetPartFileBufferedDataFlushState(*item) == PB_WRITTEN" in cleanup_block
    assert "DeleteWrittenItem(posCurrent);" in cleanup_block
    assert "PartFileNumericSeams::ShouldCleanupCompletedBufferedWrites" in process_block
    assert process_block.index("PartFileNumericSeams::ShouldCleanupCompletedBufferedWrites") < process_block.index("m_nTotalBufferData > uEffectiveFileBufferSize")
    assert "(void)ConsumeBufferedWriteCompletionsPending();\n\t\tFlushBuffer();" in process_block
    assert "SetPartFileBufferedDataFlushState(*pBuffer, PB_WRITTEN);\n\t\t\t\tpFile->NoteBufferedWriteCompletion();" in write_thread


def _check_part_file_source__part_file_shutdown_flush_wait_allows_broadband_write_drain() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "constexpr DWORD kShutdownFlushWaitMs = 15000;" in source
    assert "skips .part.met saves and forces costly" in source
    assert source.count("kShutdownFlushWaitMs") == 3


def _check_part_file_source__part_file_preview_copy_logs_file_exception_details() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CPartFile::CopyPartFile") : source.index("void CPartFile::GetLeftToTransferAndAdditionalNeededSpace")]

    assert 'DebugLogError(_T("Failed to copy part-file data from \\"%s\\" to \\"%s\\"%s")' in source
    assert "(LPCTSTR)CExceptionStrDash(*ex)" in source
    assert 'DebugLogError(_T("Failed to copy part-file data from \\"%s\\" to \\"%s\\" - unexpected exception")' in source
    assert block.count("m_bPreviewing = false;") >= 4


def _check_part_file_source__part_file_delete_defers_while_preview_worker_holds_reference() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CPartFile::DeletePartFile()") : source.index("void CPartFile::SetDownPriority")]

    assert "ASSERT(!m_bPreviewing);" in block
    assert block.index("StopFile(true);") < block.index("if (m_bPreviewing)")
    assert 'DebugLogWarning(_T("Deferring part-file deletion for \\"%s\\" until preview generation releases the file object.")' in block
    assert "m_bDelayDelete = true;" in block
    assert "return;\n\t}\n\n\tif (GetFileOp() != PFOP_NONE)" in block


def _check_part_file_source__part_file_completion_worker_posts_result_object_for_ui_thread_state_transition() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "PartFile.h").read_text(encoding="utf-8", errors="ignore")
    dialog = (app_source_root() / "emuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    worker = source[source.index("BOOL CPartFile::PerformFileComplete()") : source.index("// 'End' of file completion")]
    ui_end = source[source.index("void CPartFile::PerformFileCompleteEnd(void *pCompletionResult)") : source.index("void  CPartFile::RemoveAllSources")]

    assert "struct SPartFileCompletionThreadResult" in source
    assert "PostWorkerCompletion(theApp.IsClosing() && !bSuccessResult, hNotifyWnd, TM_FILECOMPLETED, dwResult, reinterpret_cast<LPARAM>(pResult))" in source
    assert "std::unique_ptr<SPartFileCompletionThreadResult> pSuccessResult(new SPartFileCompletionThreadResult);" in worker
    assert "m_fullname = strNewname;" not in worker
    assert "_SetStatus(PS_COMPLETE);" not in worker
    assert "m_CorruptionBlackBox.Free();" not in worker
    assert "m_fullname = pResult->strCompletedPath;" in ui_end
    assert "SetStatus(PS_ERROR);" in ui_end
    assert "bNoNewReads = false;" in ui_end
    assert "static CPartFile* GetCompletionResultFile(void *pCompletionResult);" in header
    assert "static void\tDiscardCompletionResult(void *pCompletionResult);" in header
    assert "CPartFile *partfile = CPartFile::GetCompletionResultFile(pCompletionResult);" in dialog
    assert "partfile->PerformFileCompleteEnd(pCompletionResult);" in dialog


def _check_part_file_source__zone_identifier_failures_are_logged_with_hresult() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void SetZoneIdentifier") : source.index("DWORD CALLBACK CopyProgressRoutine")]

    assert "VERIFY(SUCCEEDED(pPersistFile->Save" not in block
    assert 'DebugLogWarning(_T("Failed to create Zone.Identifier writer for \\"%s\\" (HRESULT 0x%08lX)")' in block
    assert 'DebugLogWarning(_T("Failed to save Zone.Identifier for \\"%s\\" (HRESULT 0x%08lX)")' in block


def _check_part_file_source__part_file_load_does_not_use_file_status_after_get_status_exception() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("if (!isnewstyle) { // not for importing") : source.index("if (m_tUtcLastModified != fdate)")]

    assert "CFileStatus filestatus = {};" in block
    assert "bool bHavePartFileStatus = false;" in block
    assert "bHavePartFileStatus = true;" in block
    assert "DebugLogWarning(_T(\"Failed to get file date of \\\"%s\\\" while loading part file \\\"%s\\\"%s\")" in block
    assert "time_t fdate = bHavePartFileStatus ? (time_t)filestatus.m_mtime.GetTime() : (time_t)-1;" in block
    assert "filestatus.m_szFullName" not in block


def _check_part_file_source__downloading_source_add_rejects_invalid_owner_and_tolerates_missing_ui() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CPartFile::AddDownloadingSource(CUpDownClient *client)") :
        source.index("bool CPartFile::DetachDownloadingSource")
    ]

    assert "if (client == NULL)\n\t\treturn;" in block
    assert "if (client->GetRequestFile() != this)" in block
    assert 'DebugLogWarning(_T("Rejected downloading source with mismatched request file for \\"%s\\" - %s")' in block
    assert "m_downloadingSourceList.AddTail(client);" in block
    assert "if (theApp.emuledlg != NULL && theApp.emuledlg->transferwnd != NULL)" in block


def _check_part_file_source__downloading_source_add_recovers_corrupt_list_before_mfc_mutation() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "PartFile.h").read_text(encoding="utf-8", errors="ignore")
    add_block = source[
        source.index("void CPartFile::AddDownloadingSource(CUpDownClient *client)") :
        source.index("bool CPartFile::DetachDownloadingSource")
    ]
    valid_block = source[
        source.index("bool CPartFile::IsDownloadingSourceListStructurallyValid() const") :
        source.index("void CPartFile::RecoverDownloadingSourceList")
    ]
    recover_block = source[
        source.index("void CPartFile::RecoverDownloadingSourceList(LPCTSTR pszContext)") :
        source.index("void CPartFile::RemoveStaleSource")
    ]

    assert "bool\tIsDownloadingSourceListStructurallyValid() const;" in header
    assert "void\tRecoverDownloadingSourceList(LPCTSTR pszContext);" in header
    assert "if (!IsDownloadingSourceListStructurallyValid())\n\t\tRecoverDownloadingSourceList(_T(\"add downloading source\"));" in add_block
    assert add_block.index("RecoverDownloadingSourceList") < add_block.index("m_downloadingSourceList.Find(client)")
    assert "const INT_PTR nCount = m_downloadingSourceList.GetCount();" in valid_block
    assert "const POSITION posHead = m_downloadingSourceList.GetHeadPosition();" in valid_block
    assert "const POSITION posTail = m_downloadingSourceList.GetTailPosition();" in valid_block
    assert "if (nCount < 0)\n\t\treturn false;" in valid_block
    assert "return posHead == NULL && posTail == NULL;" in valid_block
    assert "return posHead != NULL && posTail != NULL;" in valid_block
    assert 'DebugLogError(_T("Recovering corrupt downloading-source list for \\"%s\\"' in recover_block
    assert "(LPCTSTR)m_partmetfilename" in recover_block
    assert "m_downloadingSourceList.RemoveAll();" in recover_block


def _check_part_file_source__downloading_source_list_recovery_covers_remove_and_scan_entrypoints() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    detach_block = source[
        source.index("bool CPartFile::DetachDownloadingSource(CUpDownClient *client)") :
        source.index("void CPartFile::RemoveDownloadingSource")
    ]
    process_block = source[
        source.index("uint32 CPartFile::Process(uint32 reducedownload") :
        source.index("bool CPartFile::CanAddSource")
    ]
    endgame_block = source[
        source.index("bool CPartFile::TryStealEndgameBlockForFastPeer") :
        source.index("bool CPartFile::GetNextRequestedBlock")
    ]
    request_block = source[
        source.index("bool CPartFile::GetNextRequestedBlock") :
        source.index("CString CPartFile::GetInfoSummary")
    ]

    assert "RecoverDownloadingSourceList(_T(\"detach downloading source\"));" in detach_block
    assert detach_block.index("RecoverDownloadingSourceList") < detach_block.index("m_downloadingSourceList.Find(client)")
    assert "RecoverDownloadingSourceList(_T(\"download-rate pass\"));" in process_block
    assert process_block.index("RecoverDownloadingSourceList(_T(\"download-rate pass\"));") < process_block.index("m_downloadingSourceList.GetHeadPosition()")
    assert "RecoverDownloadingSourceList(_T(\"endgame steal pass\"));" in endgame_block
    assert endgame_block.index("RecoverDownloadingSourceList(_T(\"endgame steal pass\"));") < endgame_block.index("m_downloadingSourceList.GetHeadPosition()")
    assert "RecoverDownloadingSourceList(_T(\"faster-peer reservation pass\"));" in request_block
    assert "RecoverDownloadingSourceList(_T(\"chunk selection pass\"));" in request_block
    assert request_block.index("RecoverDownloadingSourceList(_T(\"chunk selection pass\"));") < request_block.index("uint16 transferringClientsScore = (uint16)m_downloadingSourceList.GetCount();")


def _check_part_file_source__endgame_steal_preserves_active_download_streams() -> None:
    source = (app_source_root() / "DownloadClient.cpp").read_text(encoding="utf-8", errors="ignore")
    steal_block = source[
        source.index("bool CUpDownClient::CancelEndgameReservationForFasterPeer") :
        source.index("void CUpDownClient::SetDownloadState")
    ]

    assert "GetSessionPayloadDown() > 0 || GetSessionDown() > 0" in steal_block
    assert steal_block.index("GetSessionPayloadDown() > 0 || GetSessionDown() > 0") < steal_block.index("m_fileEndgameCancelTimes.Lookup")
    assert "if (pending->fQueued)\n\t\t\tcontinue;" in steal_block
    assert steal_block.index("if (pending->fQueued)") < steal_block.index("PartFileEndgameSeams::ShouldStealEndgameReservation")
    assert "SetDownloadState(DS_ONQUEUE, _T(\"Endgame block reassigned to a faster source.\"));" in steal_block


def _check_part_file_source__downloading_source_list_recovery_rebuilds_from_live_sources() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    recover_block = source[
        source.index("void CPartFile::RecoverDownloadingSourceList(LPCTSTR pszContext)") :
        source.index("void CPartFile::RemoveStaleSource")
    ]

    assert "m_downloadingSourceList.RemoveAll();" in recover_block
    assert "UINT uRecoveredSources = 0;" in recover_block
    assert "for (POSITION pos = srclist.GetHeadPosition(); pos != NULL;)" in recover_block
    assert "pSource != NULL && pSource->GetRequestFile() == this && pSource->GetDownloadState() == DS_DOWNLOADING" in recover_block
    assert "m_downloadingSourceList.AddTail(pSource);" in recover_block
    assert "++uRecoveredSources;" in recover_block
    assert 'DebugLogWarning(_T("Rebuilt downloading-source list for \\"%s\\" from live sources (recovered=%u)")' in recover_block


def _check_part_file_source__completed_part_files_use_completion_hash_priority() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    completion_block = source[source.index("void CPartFile::CompleteFile(bool bIsHashingDone)") : source.index("BOOL CPartFile::PerformFileComplete()")]
    load_rehash_block = source[source.index("if (m_tUtcLastModified != fdate)") : source.index("UpdateCompletedInfos();")]

    assert "CreateSuspendedPartFileHashThread(mytemppath, RemoveFileExtension(m_partmetfilename), this, FHJP_PART_FILE_COMPLETION);" in completion_block
    assert "CreateSuspendedPartFileHashThread(GetPath(), m_hpartfile.GetFileName(), this);" in load_rehash_block
    assert "FHJP_PART_FILE_COMPLETION" not in load_rehash_block


# --- consolidated from tests/python/test_part_file_write_thread_source.py ---


def _check_part_file_write_thread_source__pending_part_file_writes_are_cancelled_and_drained_before_shutdown_cleanup() -> None:
    source = (app_source_root() / "PartFileWriteThread.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "PartFileWriteThread.h").read_text(encoding="utf-8", errors="ignore")

    assert "void\tCancelPendingWrites();" in header
    assert "void\tDrainPendingWrites();" in header
    assert "DrainPendingWrites();" in source
    assert "::CancelIoEx(pFile->m_hWrite" in source
    assert "WriteBuffers error: %s" in source
    assert "const DWORD dwEffectiveError = dwCompletionError != ERROR_SUCCESS ? dwCompletionError : ERROR_WRITE_FAULT;" in source
    assert "WriteCompletionRoutine(0, m_listPendingIO.RemoveHead(), ERROR_OPERATION_ABORTED);" not in source
    assert "Improper termination of asynchronous I/O follows" not in source
    assert "const BOOL bCompletionReceived = ::GetQueuedCompletionStatus(m_hPort, &dwBytesWritten, &completionKey, (LPOVERLAPPED*)&pCurIO, INFINITE);" in source


# --- consolidated from tests/python/test_persistence_diagnostics_source.py ---


def _check_persistence_diagnostics_source__preferences_load_failures_log_path_and_exception_details() -> None:
    source = (app_source_root() / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogWarning(_T("Failed to load path list \\"%s\\"%s"), (LPCTSTR)rstrFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Failed to load server.met address list \\"%s\\"%s"), (LPCTSTR)rstrFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Failed to load shared directory list \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source


def _check_persistence_diagnostics_source__kad_preferences_failures_log_path_and_exception_details() -> None:
    source = (app_source_root() / "kademlia" / "kademlia" / "Prefs.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogError(_T("Failed to read Kad preferences file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("Failed to read Kad preferences file \\"%s\\" after an unexpected exception"), (LPCTSTR)m_sFilename);' in source
    assert 'DebugLogError(_T("Failed to write Kad preferences file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("Failed to write Kad preferences file \\"%s\\" after an unexpected exception"), (LPCTSTR)m_sFilename);' in source
    assert 'TRACE("Exception in CPrefs::ReadFile\\n");' not in source
    assert 'TRACE("Exception in CPrefs::WriteFile\\n");' not in source


def _check_persistence_diagnostics_source__kad_contact_persistence_failures_log_path_and_exception_details() -> None:
    source = (app_source_root() / "kademlia" / "routing" / "RoutingZone.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogError(_T("Failed to read Kad contacts file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("Failed to write Kad contacts file \\"%s\\"%s"), (LPCTSTR)m_sFilename, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogError(_T("CFileException in CRoutingZone::readFile"));' not in source
    assert 'AddDebugLogLine(false, _T("CFileException in CRoutingZone::writeFile"));' not in source


# --- consolidated from tests/python/test_preview_source.py ---


def _check_preview_source__peer_preview_logs_exception_details_before_returning_empty_result() -> None:
    source = (app_source_root() / "Preview.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("BOOL CPeerPreviewThread::Run()") : source.index("void CPeerPreviewThread::SetValues")]

    assert 'DebugLogWarning(_T("Peer preview failed for \\"%s\\"%s"), (LPCTSTR)m_strInputPath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert 'DebugLogWarning(_T("Peer preview failed for \\"%s\\" after an unexpected exception"), (LPCTSTR)m_strInputPath);' in block
    assert block.index("DebugLogWarning") < block.index("ex->Delete();")


def _check_preview_source__video_thumbnail_logs_exception_details_before_reporting_worker_failure() -> None:
    source = (app_source_root() / "Preview.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("BOOL CVideoThumbnailThread::Run()") : source.index("void CVideoThumbnailThread::SetValues")]

    assert 'DebugLogWarning(_T("Video thumbnail failed for \\"%s\\" cache \\"%s\\"%s"), (LPCTSTR)m_strInputPath, (LPCTSTR)m_strCachePath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert 'DebugLogWarning(_T("Video thumbnail failed for \\"%s\\" cache \\"%s\\" after an unexpected exception"), (LPCTSTR)m_strInputPath, (LPCTSTR)m_strCachePath);' in block
    assert block.index("DebugLogWarning") < block.index("ex->Delete();")


# --- consolidated from tests/python/test_search_params_source.py ---


def _check_search_params_source__search_params_ignores_null_file_type_item_data() -> None:
    source = (app_source_root() / "SearchParamsWnd.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pszED2KFileType != NULL);\n\t\tif (pszED2KFileType != NULL)\n\t\t\tstrCurSelFileType = pszED2KFileType;" in source
    assert "ASSERT(pszED2KFileType != NULL);\n\t\tif (pszED2KFileType != NULL)\n\t\t\tstrFileType = pszED2KFileType;" in source


# --- consolidated from tests/python/test_search_results_source.py ---


def _check_search_results_source__search_results_refresh_layout_after_hidden_tab_changes() -> None:
    source = (app_source_root() / "SearchResultsWnd.cpp").read_text(encoding="utf-8", errors="ignore")
    refresh_block = source[source.index("void CSearchResultsWnd::RefreshResultLayout") : source.index("void CSearchResultsWnd::OnBnClickedClearAll")]
    create_tab_block = source[source.index("bool CSearchResultsWnd::CreateNewTab") : source.index("bool CSearchResultsWnd::SelectAdjacentSearchResultTab")]
    show_window_block = (app_source_root() / "SearchDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    show_window_block = show_window_block[show_window_block.index("void CSearchDlg::OnShowWindow") : show_window_block.index("void CSearchDlg::OnSetFocus")]

    assert "ArrangeLayout();" in refresh_block
    assert "PositionSearchStatusOverlay();" in refresh_block
    assert "RefreshResultLayout();" in create_tab_block
    assert "m_pwndResults->RefreshResultLayout();" in show_window_block


def _check_search_results_source__clean_shutdown_removes_tray_icon_before_long_teardown() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    close_start = source.index("void CemuleDlg::OnClose()")
    teardown_start = source.index("VersionCheckLaunchSeams::ClearQueuedOnOwnerTeardown", close_start)
    close_block = source[close_start:teardown_start]
    visibility_block = source[source.index("void CemuleDlg::UpdateTrayVisibility") : source.index("void CemuleDlg::ForceTrayBalloonFallbackForSession")]
    decision_block = source[source.index("bool CemuleDlg::ShouldTrayIconBeVisible") : source.index("void CemuleDlg::UpdateTrayVisibility")]

    assert "theApp.m_app_state = APP_STATE_SHUTTINGDOWN;" in close_block
    assert "TrayHide();" in close_block
    assert close_block.index("theApp.m_app_state = APP_STATE_SHUTTINGDOWN;") < close_block.index("TrayHide();")
    assert "if (theApp.IsClosing())" in decision_block
    assert "return false;" in decision_block
    assert "if (theApp.IsClosing()) {" in visibility_block
    assert "TrayHide();" in visibility_block
    assert visibility_block.index("if (theApp.IsClosing()) {") < visibility_block.index("if (ShouldTrayIconBeVisible())")


# --- consolidated from tests/python/test_server_list_source.py ---


def _check_server_list_source__get_server_at_rejects_invalid_indices_before_position_access() -> None:
    header = (app_source_root() / "ServerList.h").read_text(encoding="utf-8", errors="ignore")

    assert "if (pos < 0 || pos >= list.GetCount())\n\t\t\treturn NULL;" in header
    assert "POSITION serverPos = list.FindIndex(pos);" in header
    assert "return serverPos != NULL ? list.GetAt(serverPos) : NULL;" in header
    assert "return list.GetAt(list.FindIndex(pos));" not in header


# --- consolidated from tests/python/test_sha_hash_set_source.py ---


def _check_sha_hash_set_source__aich_recovery_hash_set_rejects_missing_owner_and_bad_part_ranges() -> None:
    source = (app_source_root() / "SHAHashSet.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "rResult.RemoveAll();\n\tif (m_pOwner == NULL)\n\t\treturn false;" in source
    assert "if (m_pOwner == NULL || !m_pOwner->IsPartFile())\n\t\treturn NULL;" in source
    assert "const uint64 uFileSize = static_cast<uint64>(m_pOwner->GetFileSize());" in source
    assert "const uint64 nPartStartPos = static_cast<uint64>(nPart) * PARTSIZE;\n\tif (nPartStartPos >= uFileSize)\n\t\treturn NULL;" in source
    assert "ASSERT(phtResult != NULL);\n\tif (phtResult == NULL)\n\t\treturn NULL;" in source
    assert "ASSERT(m_pOwner);\n\tif (m_pOwner == NULL)\n\t\treturn false;" in source
    assert "if (nPartStartPos >= uFileSize)\n\t\treturn false;" in source


# --- consolidated from tests/python/test_shared_directory_rule_index_source.py ---


def _check_shared_directory_rule_index_source__shared_directory_ops_owns_rule_index_and_key_helpers() -> None:
    header = (app_source_root() / "SharedDirectoryOps.h").read_text(encoding="utf-8", errors="ignore")

    assert "inline std::wstring MakeSharedDirectoryLookupKeyW" in header
    assert "struct SharedDirectoryRuleEntry" in header
    assert "struct SharedDirectoryRuleIndex" in header
    assert "LongPathSeams::FileSystemObjectIdentity identity" in header
    assert "bool ContainsEquivalentDirectoryObject" in header
    assert "bool HasDescendant" in header
    assert "bool RemovePathsWithinDirectory" in header
    assert "bDuplicateIdentity" in header
    assert "mounted folders and equivalent Win32 spellings" in header


def _check_shared_directory_rule_index_source__preferences_tree_uses_shared_directory_rule_index() -> None:
    header = (app_source_root() / "DirectoryTreeCtrl.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "DirectoryTreeCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert '#include "SharedDirectoryOps.h"' in header
    assert "SharedDirectoryOps::SharedDirectoryRuleIndex m_sharedDirectoryIndex;" in header
    assert "m_sharedDirectoryIndex.Rebuild(m_lstShared);" in source
    assert "m_sharedDirectoryIndex.HasDescendant(strDir);" in source
    assert "MakeSharedDirectoryLoadKey" not in source
    assert "m_sortedSharedDirectoryKeys" not in header
    assert "m_sortedSharedDirectoryKeys" not in source


def _check_shared_directory_rule_index_source__shared_files_tree_uses_shared_directory_rule_index() -> None:
    header = (app_source_root() / "SharedDirsTreeCtrl.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "SharedDirsTreeCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert '#include "SharedDirectoryOps.h"' in header
    assert "SharedDirectoryOps::SharedDirectoryRuleIndex m_sharedDirectoryIndex;" in header
    assert "return SharedDirectoryOps::MakeSharedDirectoryLookupKey(rstrPath);" in source
    assert "m_sharedDirectoryIndex.Rebuild(m_strliSharedDirs);" in source
    assert "m_sharedDirectoryIndex.ContainsExactPathKey(strDir);" in source
    assert "m_sharedDirectoryIndex.HasDescendant(strDir);" in source
    tree_builder = source[source.index("void BuildSharedDirectoryTree") : source.index("bool CSharedDirsTreeCtrl::IsSharedTreeDirectoryAccessible")]
    assert "const CString strParentKey(BuildSharedTreePathKey(strParent));" in tree_builder
    assert "strParentKey.MakeLower();" not in tree_builder
    assert "m_mapSharedDirectoryKeys" not in header
    assert "m_aSortedSharedDirectoryKeys" not in header


def _check_shared_directory_rule_index_source__preferences_directory_keys_delegate_to_shared_directory_ops() -> None:
    source = (app_source_root() / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("std::wstring MakeDirectoryListLookupKey") : source.index("bool IsStaleStartupConfigDefaultIncomingPath")]

    assert "return SharedDirectoryOps::MakeSharedDirectoryLookupKeyW(rstrDirectory);" in block
    assert "SharedDirectoryOps::IsDirectoryKeyParentOfCandidate" in source


# --- consolidated from tests/python/test_shared_file_list_source.py ---


def _check_shared_file_list_source__startup_cache_write_failures_keep_path_and_error_details() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("bool CSharedFileList::WriteStartupCacheFile") :
        source.index("bool CSharedFileList::WriteDuplicatePathCacheFile")
    ]

    assert 'DebugLogWarning(_T("Failed to open startup cache temp file \\"%s\\" for \\"%s\\" - %s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to replace startup cache \\"%s\\" with temp file \\"%s\\" - %s"), (LPCTSTR)strFullPath, (LPCTSTR)strTempPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to write startup cache temp file \\"%s\\" for \\"%s\\"%s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert block.index("CExceptionStrDash(*ex)") < block.index("ex->Delete();")


def _check_shared_file_list_source__duplicate_path_cache_write_failures_keep_path_and_error_details() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("bool CSharedFileList::WriteDuplicatePathCacheFile") :
        source.index("void CSharedFileList::RunStartupCacheSaveWorker")
    ]

    assert 'DebugLogWarning(_T("Failed to open duplicate path cache temp file \\"%s\\" for \\"%s\\" - %s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to replace duplicate path cache \\"%s\\" with temp file \\"%s\\" - %s"), (LPCTSTR)strFullPath, (LPCTSTR)strTempPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to write duplicate path cache temp file \\"%s\\" for \\"%s\\"%s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert block.index("CExceptionStrDash(*ex)") < block.index("ex->Delete();")


def _check_shared_file_list_source__interrupted_hashing_removes_startup_cache_sidecars() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    invalidate_block = source[
        source.index("void CSharedFileList::InvalidateStartupCachesAfterInterruptedHashing") :
        source.index("bool CSharedFileList::IsSharedHashInFlight")
    ]
    persist_block = source[
        source.index("bool CSharedFileList::PersistDuplicatePathCacheAfterInterruptedHashing") :
        source.index("void CSharedFileList::RememberDuplicateSharedPath")
    ]

    assert "bool\tPersistDuplicatePathCacheAfterInterruptedHashing();" in header
    assert "LongPathSeams::DeleteFileIfExists(GetStartupCachePath())" in invalidate_block
    assert "m_duplicateSharedPathRecords.clear();" in invalidate_block
    assert "LongPathSeams::DeleteFileIfExists(GetDuplicatePathCachePath())" in invalidate_block
    assert "PersistDuplicatePathCacheAfterInterruptedHashing()" not in invalidate_block
    assert "CaptureDuplicatePathCacheSnapshot(snapshot)" in persist_block
    assert "BuildDuplicatePathCacheRecordsFromSnapshot(snapshot, records);" in persist_block
    assert "WriteDuplicatePathCacheFile(GetDuplicatePathCachePath(), records)" in persist_block
    assert "persistedRecords.emplace(MakeDuplicatePathCacheKey(record.strFilePath), record);" in persist_block


def _check_shared_file_list_source__interrupted_hashing_marks_deferred_result_directories_interrupted() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    shutdown_block = source[
        source.index("void CSharedFileList::SignalSharedHashWorkerShutdown") :
        source.index("bool CSharedFileList::IsSharedHashWorkerShuttingDown")
    ]
    invalidate_block = source[
        source.index("void CSharedFileList::InvalidateStartupCachesAfterInterruptedHashing") :
        source.index("bool CSharedFileList::IsSharedHashInFlight")
    ]

    assert "bool\tPersistStartupCacheAfterInterruptedHashing(const std::unordered_set<std::wstring> &rInterruptedDirectoryKeys);" in header
    assert "void\tInvalidateStartupCachesAfterInterruptedHashing(const std::unordered_set<std::wstring> &rInterruptedDirectoryKeys = std::unordered_set<std::wstring>());" in header
    assert "std::unordered_set<std::wstring> interruptedDirectoryKeys;" in shutdown_block
    assert shutdown_block.index("interruptedDirectoryKeys.insert(MakeStartupCacheSnapshotKey(job.strDirectory));") < shutdown_block.index("m_sharedHashQueue.clear();")
    assert "!m_sharedHashDeferredResults.empty()" in shutdown_block
    assert "for (const CSharedFileHashResult *pResult : m_sharedHashDeferredResults)" in shutdown_block
    assert "interruptedDirectoryKeys.insert(MakeStartupCacheSnapshotKey(pResult->strDirectory));" in shutdown_block
    assert "InvalidateStartupCachesAfterInterruptedHashing(interruptedDirectoryKeys);" in shutdown_block
    assert "PersistStartupCacheAfterInterruptedHashing(rInterruptedDirectoryKeys)" not in invalidate_block
    assert '"interrupted_hashing_partial"' not in invalidate_block
    assert '"interrupted_hashing"' in invalidate_block


def _check_shared_file_list_source__shared_files_hashing_done_marker_is_not_emitted_during_close() -> None:
    source = (app_source_root() / "SharedFilesWnd.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CSharedFilesWnd::ReportStartupSharedFilesReadinessIfReady") :
        source.index("#endif", source.index("void CSharedFilesWnd::ReportStartupSharedFilesReadinessIfReady"))
    ]

    guard = "!m_bStartupSharedFilesHashingDoneReported && ullPendingHashes == 0 && !theApp.IsClosing()"
    assert "shutdown can clear shared-hash bookkeeping before the UI has accepted" in block
    assert guard in block
    assert block.index(guard) < block.index('_T("ui.shared_files_hashing_done")')


def _check_shared_file_list_source__close_interrupted_shared_hash_snapshot_precedes_shutdown_state() -> None:
    dialog = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    block = dialog[
        dialog.index("const auto sleepAndPumpSharedShutdownPoll") :
        dialog.index("TrayHide();")
    ]

    snapshot = "const bool bSharedHashingWasActiveOnClose = (theApp.sharedfiles != NULL && theApp.sharedfiles->HasSharedHashingWork());"
    state_change = "theApp.m_app_state = APP_STATE_SHUTTINGDOWN;"
    assert "setting APP_STATE_SHUTTINGDOWN can make shared-hash workers retire" in block
    assert snapshot in block
    assert state_change in block
    assert block.index(snapshot) < block.index(state_change)


def _check_shared_file_list_source__duplicate_path_sidecar_reuse_precedes_known_file_duplicate_reporting() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CSharedFileList::CheckAndAddSingleFileFromNormalizedDirectory") :
        source.index("bool CSharedFileList::AddKnownSharedFile")
    ]

    reuse_probe = "TryReuseRememberedDuplicateSharedPath(strFoundFilePath, static_cast<LONGLONG>(fdate), ullFoundFileSize)"
    known_lookup = "theApp.knownfiles->FindKnownFile(strFoundFileName, fdate, ullFoundFileSize)"
    assert reuse_probe in block
    assert known_lookup in block
    assert block.index(reuse_probe) < block.index(known_lookup)
    assert "++m_startupScanStats.uDuplicatePathsReused;" in block
    assert "return;\n\t}\n\n\tCKnownFile *toadd = theApp.knownfiles->FindKnownFile" in block


def _check_shared_file_list_source__startup_cache_loader_rejects_short_fixed_payload_reads() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")

    assert "static void ReadStartupCacheExact(CSafeBufferedFile &file, void *pBuffer, UINT uBytes);" in header
    assert "void CSharedFileList::ReadStartupCacheExact(CSafeBufferedFile &file, void *pBuffer, const UINT uBytes)" in source
    assert "const UINT uActualRead = file.Read(pBuffer, uBytes);" in source
    assert "if (uActualRead != uBytes)\n\t\tAfxThrowFileException(CFileException::endOfFile, 0, file.GetFilePath());" in source
    assert "ReadStartupCacheExact(file, buffer.data(), uCharCount * sizeof(WCHAR));" in source
    assert "ReadStartupCacheExact(file, record.identity.fileId.data(), static_cast<UINT>(record.identity.fileId.size()));" in source
    assert "ReadStartupCacheExact(file, record.directoryFileReference.identifier.data(), static_cast<UINT>(record.directoryFileReference.identifier.size()));" in source
    assert "ReadStartupCacheExact(file, record.canonicalFileHash.data(), static_cast<UINT>(record.canonicalFileHash.size()));" in source
    assert "file.Read(buffer.data(), uCharCount * sizeof(WCHAR));" not in source
    assert "file.Read(record.identity.fileId.data(), static_cast<UINT>(record.identity.fileId.size()));" not in source
    assert "file.Read(record.directoryFileReference.identifier.data(), static_cast<UINT>(record.directoryFileReference.identifier.size()));" not in source
    assert "file.Read(record.canonicalFileHash.data(), static_cast<UINT>(record.canonicalFileHash.size()));" not in source


def _check_shared_file_list_source__startup_cache_completion_uses_worker_payload_registry() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    dialog = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    worker_block = source[
        source.index("UINT AFX_CDECL CSharedFileList::StartupCacheSaveThreadProc") :
        source.index("void CSharedFileList::HandleStartupCacheSaveCompletion")
    ]

    assert "ULONG_PTR nCompletionOwnerKey = 0;" in header
    assert "~StartupCacheSaveThreadCompletion();" in header
    assert "void DiscardPendingResult();" in header
    assert "static void\t*TakeStartupCacheSaveCompletion(WPARAM wParam);" in header
    assert "pRequest->nCompletionOwnerKey = GetWorkerUiPayloadOwnerKey(this);" in source
    assert "DiscardPostedWorkerUiPayloadsForOwner(GetWorkerUiPayloadOwnerKey(this));" in source
    assert "bPosted = TryPostWorkerUiPayloadMessage(hNotifyWnd, NULL, nCompletionOwnerKey, UM_STARTUP_CACHE_SAVE_COMPLETE, std::move(pCompletion));" in worker_block
    assert "::PostMessage(hNotifyWnd, UM_STARTUP_CACHE_SAVE_COMPLETE" not in worker_block
    assert "CSharedFileList::StartupCacheSaveThreadCompletion::~StartupCacheSaveThreadCompletion()" in source
    assert "void CSharedFileList::StartupCacheSaveThreadCompletion::DiscardPendingResult()" in source
    assert "void *CSharedFileList::TakeStartupCacheSaveCompletion(WPARAM wParam)" in source
    assert "TakePostedWorkerUiPayload<StartupCacheSaveThreadCompletion>(wParam)" in source
    assert "void *pCompletion = CSharedFileList::TakeStartupCacheSaveCompletion(wParam);" in dialog
    assert "if (pCompletion == NULL && lParam != 0)" in dialog


def _check_shared_file_list_source__hash_workers_use_priority_gate_before_global_hash_mutex() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    add_thread_run = source[source.index("int CAddFileThread::Run()") : source.index("///////////////////////////////////////////////////////////////////////////////\n// CSharedFileHashThread")]
    shared_hash_run = source[source.index("void CSharedFileList::RunSharedHashJob") : source.index("bool CSharedFileList::MoveActiveSharedHashToPendingCompletion")]

    assert "enum EFileHashJobPriority" in header
    assert "FHJP_PART_FILE_COMPLETION = 2" in header
    assert "std::vector<SFileHashJobGateEntry> s_fileHashJobGateQueue;" in source
    assert "bool ShouldFileHashJobWaitLocked(const SFileHashJobGateEntry &rJob)" in source
    assert "bool IsFileHashJobGateBusy()" in source
    assert "s_bFileHashJobRunning || !s_fileHashJobGateQueue.empty() || s_bPartFileHashStartupScheduling" in source
    assert "if (s_bPartFileHashStartupScheduling || s_bFileHashJobRunning)\n\t\treturn true;" in source
    assert "if (iQueuedPriority > iOwnPriority)\n\t\t\treturn true;" in source
    assert "if (iQueuedPriority == iOwnPriority && rQueuedJob.uSequence < rJob.uSequence)\n\t\t\treturn true;" in source
    assert "CScopedFileHashJobGate fileHashJobGate(m_eHashJobPriority);" in add_thread_run
    assert add_thread_run.index("CScopedFileHashJobGate fileHashJobGate(m_eHashJobPriority);") < add_thread_run.index("CSingleLock hashingLock(&theApp.hashing_mut, TRUE);")
    assert "CScopedFileHashJobGate fileHashJobGate(FHJP_SHARED_FILE);" in shared_hash_run
    assert "CSingleLock hashingLock(&theApp.hashing_mut);" in shared_hash_run
    assert "while (!hashingLock.Lock(SharedFileListSeams::kSharedHashMutexShutdownPollMs))" in shared_hash_run
    assert "if (theApp.IsClosing() || IsSharedHashWorkerShuttingDown())" in shared_hash_run
    assert "AbandonActiveSharedHashJob(rJob);" in shared_hash_run
    assert shared_hash_run.index("CScopedFileHashJobGate fileHashJobGate(FHJP_SHARED_FILE);") < shared_hash_run.index("CSingleLock hashingLock(&theApp.hashing_mut);")


def _check_shared_file_list_source__shared_file_hot_path_indexes_are_maintained_together() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    add_indexes = source[source.index("void CSharedFileList::AddFileToSharedFileIndexes") : source.index("void CSharedFileList::RemoveFileFromSharedFileIndexes")]
    remove_indexes = source[source.index("void CSharedFileList::RemoveFileFromSharedFileIndexes") : source.index("void CSharedFileList::RebuildSharedFileIndexes")]
    get_by_path = source[source.index("CKnownFile* CSharedFileList::GetFileByPath") : source.index("bool CSharedFileList::EnsureSharedHashWorkerStarted")]
    page = source[source.index("void CSharedFileList::CopySharedFilePage") : source.index("CKnownFile* CSharedFileList::GetFileByPath")]
    rebuild = source[source.index("void CSharedFileList::RebuildSharedFileIndexes") : source.index("void CSharedFileList::CopySharedFilesForDirectory")]

    assert "struct SharedFileIndexSet" in header
    assert "std::vector<CKnownFile*> m_allSharedFiles;" in header
    assert "std::unordered_map<std::wstring, CKnownFile*> m_filesByPathKey;" in header
    assert "std::vector<CKnownFile*> m_singleSharedFiles;" in header
    assert "SSharedFilesSummarySnapshot m_sharedFilesSummary;" in header
    assert "uint64 m_uSharedFileIndexGeneration" in header
    assert "uint64 m_uKadPublishStateGeneration" in header
    assert "m_allSharedFiles.push_back(pFile);" in add_indexes
    assert "m_filesBySharedDirectoryKey[MakeSharedDirectoryIndexKey(pFile->GetSharedDirectory())].push_back(pFile);" in add_indexes
    assert "m_filesByPathKey[MakeSharedFileIndexKey(pFile->GetFilePath())] = pFile;" in add_indexes
    assert "m_singleSharedFiles.push_back(pFile);" in add_indexes
    assert "UpdateSharedFileSummaryForAdd(pFile);" in add_indexes
    assert "++m_uSharedFileIndexGeneration;" in add_indexes
    assert "removeFromVector(m_allSharedFiles);" in remove_indexes
    assert "removeFromVector(m_singleSharedFiles);" in remove_indexes
    assert "m_filesByPathKey.erase(MakeSharedFileIndexKey(pFile->GetFilePath()));" in remove_indexes
    assert "UpdateSharedFileSummaryForRemove(pFile);" in remove_indexes
    assert "++m_uSharedFileIndexGeneration;" in remove_indexes
    assert "m_filesByPathKey.find(MakeSharedFileIndexKey(strFilePath))" in get_by_path
    assert "m_Files_map.PGetFirstAssoc" not in get_by_path
    assert "m_allSharedFiles.size()" in page
    assert "m_Files_map.PGetFirstAssoc" not in page
    assert "SharedFileIndexSet indexes;" in rebuild
    assert "uObservedGeneration != m_uSharedFileIndexGeneration" in rebuild
    assert "m_allSharedFiles.swap(indexes.allSharedFiles);" in rebuild
    assert "readers never see the transient clear-and-repopulate state" in rebuild


def _check_shared_file_list_source__shared_file_path_index_is_updated_after_in_place_rename() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    ctrl = (app_source_root() / "SharedFilesCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CSharedFileList::UpdateSharedFilePath") : source.index("bool CSharedFileList::EnsureSharedHashWorkerStarted")]
    rename = ctrl[ctrl.index("case MP_RENAME:") : ctrl.index("case MP_REMOVE:")]

    assert "void\tUpdateSharedFilePath(CKnownFile *pFile, const CString &strOldFilePath, const CString &strNewFilePath);" in header
    assert "m_filesByPathKey.erase(itOld);" in block
    assert "m_filesByPathKey[MakeSharedFileIndexKey(strNewFilePath)] = pFile;" in block
    assert "REST remove-by-path" in block
    assert "const CString oldpath(pKnownFile->GetFilePath());" in rename
    assert "pKnownFile->SetFilePath(newpath);" in rename
    assert "theApp.sharedfiles->UpdateSharedFilePath(pKnownFile, oldpath, newpath);" in rename


def _check_shared_file_list_source__shared_publish_summary_recounts_after_publish_state_batches() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    refresh = source[source.index("void CSharedFileList::RefreshSharedFilePublishedED2KSummary") : source.index("void CSharedFileList::MarkKadPublishStateChanged")]
    send_list = source[source.index("void CSharedFileList::SendListToServer") : source.index("void CSharedFileList::ClearED2KPublishInfo")]
    clear_ed2k = source[source.index("void CSharedFileList::ClearED2KPublishInfo") : source.index("void CSharedFileList::ClearKadSourcePublishInfo")]
    clear_kad = source[source.index("void CSharedFileList::ClearKadSourcePublishInfo") : source.index("void CSharedFileList::CreateOfferedFilePacket")]

    assert "void\tRefreshSharedFilePublishedED2KSummary();" in header
    assert "void\tMarkKadPublishStateChanged();" in header
    assert "CSingleLock listlock(&m_mutWriteList, TRUE);" in refresh
    assert "for (const CKnownFile *pFile : m_allSharedFiles)" in refresh
    assert "cached UI summary out of sync" in refresh
    assert "RefreshSharedFilePublishedED2KSummary();" in send_list
    assert "RefreshSharedFilePublishedED2KSummary();" in clear_ed2k
    assert "MarkKadPublishStateChanged();" in clear_kad


def _check_shared_file_list_source__shared_hash_progress_logging_is_aggregate_only() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CSharedFileList::LogSharedHashProgress") :
        source.index("bool CSharedFileList::IsStartupDeferredHashingActive")
    ]
    find_shared_files = source[
        source.index("void CSharedFileList::FindSharedFiles") :
        source.index("void CSharedFileList::AddFilesFromDirectory")
    ]
    shared_hash_run = source[
        source.index("void CSharedFileList::RunSharedHashJob") :
        source.index("bool CSharedFileList::MoveActiveSharedHashToPendingCompletion")
    ]
    finished_block = source[
        source.index("void CSharedFileList::FileHashingFinished(CKnownFile *file)") :
        source.index("void CSharedFileList::FileHashingFinished(CSharedFileHashResult *pResult)")
    ]
    failed_block = source[
        source.index("void CSharedFileList::HashFailed(UnknownFile_Struct *hashed)") :
        source.index("void CSharedFileList::UpdateFile")
    ]
    process_block = source[
        source.index("void CSharedFileList::Process") :
        source.index("void CSharedFileList::Publish")
    ]

    assert "void\tLogSharedHashProgress(LPCTSTR pszReason, bool bForce = false);" in header
    assert "ULONGLONG m_ullLastSharedHashProgressLogTick;" in header
    assert "ULONGLONG m_uLastSharedHashProgressObservedFiles;" in header
    assert "Shared hash progress: reason=%s waiting=%I64u pending=%I64u deferred=%I64u active=%u total=%I64u completed=%I64u failed=%I64u gateBusy=%u" in block
    assert "strFilePath" not in block
    assert "strDirectory" not in block
    assert "strName" not in block
    assert "LogSharedHashProgress(_T(\"startup-scan\"), true);" in find_shared_files
    assert "LogSharedHashProgress(_T(\"start\"));" in shared_hash_run
    assert "LogSharedHashProgress(_T(\"complete\"));" in finished_block
    assert failed_block.count("LogSharedHashProgress(_T(\"failed\"));") == 2
    assert "LogSharedHashProgress(_T(\"drained\"), true);" in source
    assert "if (HasSharedHashingWork())\n\t\tLogSharedHashProgress(_T(\"heartbeat\"));" in process_block


def _check_shared_file_list_source__startup_cache_save_waits_for_file_hash_gate_to_go_idle() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("bool CSharedFileList::ShouldStartStartupCacheSaveNow") :
        source.index("void CSharedFileList::FindSharedFiles")
    ]

    assert "startup-cache snapshot walks all shared directories and known" in block
    assert "const bool bDeferredHashingActive = m_bStartupDeferredHashingActive || IsFileHashJobGateBusy();" in block
    assert "bDeferredHashingActive," in block


def _check_shared_file_list_source__shared_publish_diagnostics_reports_server_and_kad_backlog() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CSharedFileList::GetPublishDiagnosticsSnapshot") :
        source.index("void CSharedFileList::Process")
    ]

    assert "#ifdef EMULEBB_ENABLE_UPLOAD_SLOT_DIAGNOSTICS" in header
    assert "struct SharedPublishDiagnosticsSnapshot" in header
    for field in (
        "INT_PTR iSharedFiles",
        "UINT uED2KPublishedFiles",
        "UINT uED2KPendingFiles",
        "UINT uED2KPendingLargeUnsupportedFiles",
        "UINT uED2KOfferLimit",
        "UINT uKadPublishReady",
        "UINT uKadSourceDueFiles",
        "UINT uKadSourceBackoffFiles",
        "UINT uKadSourceSearches",
        "UINT uKadSourceSearchCap",
        "UINT uKadKeywordSearches",
        "UINT uKadKeywordSearchCap",
        "UINT uKadNotesSearches",
        "UINT uKadNotesSearchCap",
    ):
        assert field in header

    assert "void\tGetPublishDiagnosticsSnapshot(SharedPublishDiagnosticsSnapshot &rSnapshot) const;" in header
    assert "rSnapshot.iSharedFiles = m_Files_map.GetCount();" in block
    assert "rSnapshot.uKadSourceSearchCap = KADEMLIATOTALSTORESRC;" in block
    assert "rSnapshot.uKadKeywordSearchCap = KADEMLIATOTALSTOREKEY;" in block
    assert "rSnapshot.uKadNotesSearchCap = KADEMLIATOTALSTORENOTES;" in block
    assert "Kademlia::CKademlia::GetTotalStoreSrc()" in block
    assert "Kademlia::CKademlia::GetTotalStoreKey()" in block
    assert "Kademlia::CKademlia::GetTotalStoreNotes()" in block
    assert "pCurServer->SupportsLargeFilesTCP()" in block
    assert "Kademlia::CKademlia::GetPublish()" in block
    assert "Kademlia::CUDPFirewallTester::IsFirewalledUDP(true)" in block
    assert "IsKadSourcePublishDue(pFile, tNow)" in block
    assert "++rSnapshot.uKadSourceDueFiles;" in block
    assert "++rSnapshot.uKadSourceBackoffFiles;" in block


def _check_shared_file_list_source__shared_file_page_copy_is_server_side_bounded() -> None:
    # FEAT-068: the shared-file REST page must stay bounded on very large
    # libraries (50k+). CopySharedFilePage indexes straight to the offset, copies
    # at most `uLimit` pointers, and holds the write-list lock only for that copy
    # (JSON serialization happens after it returns), so one request never walks or
    # serializes the whole map.
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CSharedFileList::CopySharedFilePage(") : source.index("CKnownFile* CSharedFileList::GetFileByPath(")
    ]
    assert "*pTotal = m_allSharedFiles.size();" in block
    assert "for (size_t i = uOffset; i < m_allSharedFiles.size() && rFiles.size() < uLimit; ++i)" in block
    assert "CSingleLock listlock(&m_mutWriteList, TRUE);" in block


def _check_shared_file_list_source__snapshot_bounds_every_live_collection_for_large_profiles() -> None:
    # FEAT-068: the snapshot polling summary applies the caller-visible limit to
    # every live collection so one controller refresh cannot serialize an entire
    # large profile on the UI-owned state path.
    source = (app_source_root() / "WebServerJson.cpp").read_text(encoding="utf-8", errors="ignore")
    start = source.index('strCommand == "snapshot/get"')
    block = source[start : start + 1600]
    assert "BuildSharedFilesListJson(0, maxEntries)" in block
    assert "BuildTransfersListJson(json::object(), listError, false, maxEntries)" in block
    assert "BuildUploadsListJson(false, maxEntries)" in block
    assert "BuildUploadsListJson(true, maxEntries)" in block


# --- consolidated from tests/python/test_shared_files_ctrl_source.py ---


def _check_shared_files_ctrl_source__shared_files_addfile_uses_sorted_insert_not_full_resort() -> None:
    header = (app_source_root() / "SharedFilesCtrl.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "SharedFilesCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    add_file = source[source.index("void CSharedFilesCtrl::AddFile") : source.index("void CSharedFilesCtrl::RemoveFile")]
    insert = source[source.index("void CSharedFilesCtrl::InsertVisibleFileByCurrentSort") : source.index("void CSharedFilesCtrl::AddFile")]

    assert "void InsertVisibleFileByCurrentSort(CShareableFile *file);" in header
    assert "std::upper_bound" in insert
    assert "CompareVisibleFiles(pNewFile, pExistingFile, lParamSort) < 0" in insert
    assert "live CPU dumps from large-profile startup" in add_file
    assert "InsertVisibleFileByCurrentSort(const_cast<CShareableFile*>(file));" in add_file
    assert "SortVisibleFiles();" not in add_file


def _check_shared_files_ctrl_source__shared_files_count_uses_shared_summary_snapshot() -> None:
    source = (app_source_root() / "SharedFilesCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("CString CSharedFilesCtrl::FormatFilesCountText() const") : source.index("CSharedFilesCtrl::CSharedFilesCtrl")]

    assert "GetSharedFilesSummarySnapshot(summarySnapshot);" in block
    assert "summary.uFileCount = summarySnapshot.uFileCount;" in block
    assert "summary.uTotalSize = summarySnapshot.uTotalSize;" in block
    assert "summary.uPublishedED2KCount = summarySnapshot.uPublishedED2KCount;" in block
    assert "m_uKadSummaryModelGeneration == summarySnapshot.uModelGeneration" in block
    assert "m_uKadSummaryPublishStateGeneration == summarySnapshot.uKadPublishStateGeneration" in block
    assert "m_tKadSummaryCacheBucket == tKadCacheBucket" in block
    assert "m_bKadSummaryCacheConnected == kadContext.bKadConnected" in block
    assert "m_uKadSummaryCacheBuddyIP == kadContext.uBuddyIP" in block
    assert "m_uCachedPublishedKadCount" in block
    assert "large shares do not rescan" in block
    assert "CopyAllSharedFiles(sharedFiles);" in block
    assert "m_Files_map.PGetFirstAssoc" not in block


# --- consolidated from tests/python/test_shell_delete_source.py ---


def _check_shell_delete_source__shell_delete_ex_preserves_recycle_bin_and_direct_delete_diagnostics() -> None:
    root = app_source_root()
    header = (root / "OtherFunctions.h").read_text(encoding="utf-8", errors="ignore")
    source = (root / "OtherFunctions.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "struct SShellDeleteFileResult" in header
    assert "bool ShellDeleteFileEx(LPCTSTR pszFilePath, SShellDeleteFileResult &rResult);" in header
    assert "CString GetShellDeleteFileErrorMessage(const SShellDeleteFileResult &rResult);" in header
    assert "bool DeleteFileToRecycleBinIFileOperation(LPCTSTR pszFilePath, HWND hOwnerWindow, SShellDeleteFileResult *pResult)" in source
    assert "pResult->bAnyOperationsAborted = bAnyOperationsAborted;" in source
    assert "pResult->hResult = hr;" in source
    assert "rResult.dwLastError = bDeleted ? ERROR_SUCCESS : ::GetLastError();" in source
    assert "rResult.hResult = bDeleted ? S_OK : HRESULT_FROM_WIN32(rResult.dwLastError);" in source
    assert '_T(" (HRESULT 0x%08lX)")' in source


def _check_shell_delete_source__shell_delete_callers_report_shell_delete_result_not_ambient_last_error() -> None:
    root = app_source_root()
    caller_names = [
        "CollectionCreateDialog.cpp",
        "DownloadListCtrl.cpp",
        "SharedDirsTreeCtrl.cpp",
        "SharedFilesCtrl.cpp",
        "WebServerJson.cpp",
    ]

    for caller_name in caller_names:
        source = (root / caller_name).read_text(encoding="utf-8", errors="ignore")
        assert "ShellDeleteFileEx(" in source
        assert "GetShellDeleteFileErrorMessage(deleteResult)" in source
        assert "ShellDeleteFile(" not in source.replace("ShellDeleteFileEx(", "")


# --- consolidated from tests/python/test_taskbar_notifier_source.py ---


def _check_taskbar_notifier_source__taskbar_notifier_create_rejects_null_parent() -> None:
    source = (app_source_root() / "TaskbarNotifier.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pWndParent != NULL);\n\tif (pWndParent == NULL)\n\t\treturn FALSE;\n\tm_pWndParent = pWndParent;" in source
    assert "SetTimer(IDT_APPEARING, m_dwShowEvents, NULL);\n\t\t[[fallthrough]];\n\tcase IDT_APPEARING:" in source


# --- consolidated from tests/python/test_tooltip_ctrl_source.py ---


def _check_tooltip_ctrl_source__file_icon_tooltips_initialize_line_height_from_non_colon_lines() -> None:
    source = (app_source_root() / "ToolTipCtrlX.cpp").read_text(encoding="utf-8", errors="ignore")
    first_line = source[source.index("file name, printed bold on top") : source.index("} else if (!strLine.IsEmpty()")]
    plain_line = source[source.index("} else if (!strLine.IsEmpty()") : source.index("} else {", source.index("} else if (!strLine.IsEmpty()"))]

    assert "iTextHeight = max(iTextHeight, siz.cy + iLineHeightOff);" in first_line
    assert "iTextHeight = max(iTextHeight, siz.cy + iLineHeightOff);" in plain_line
    assert "iCaptionHeight = iCaptionLineCount * iTextHeight;" in source
    assert "sizText.cy = iTextLineCount * iTextHeight;" in source
    assert "const int iMaxTooltipWidth = max(1, m_rcScreen.Width() - 48);" in source
    assert "iMaxSingleLineWidth = min(iMaxTooltipWidth, iMaxSingleLineWidth);" in source
    assert "const int iLineLeft = (bShowFileIcon && iPos <= iCaptionEnd + strLine.GetLength()) ? ptText.x + iIconDrawingWidth : ptText.x;" in source
    assert "pdc->TabbedTextOut(iLineLeft, ptText.y, strLine" in source
    assert "ptText.y += siz.cy + iLineHeightOff;" not in source


# --- consolidated from tests/python/test_transfer_wnd_source.py ---


def _check_transfer_wnd_source__transfer_queue_footer_includes_broadband_upload_summary() -> None:
    seams = read_app_source("TransferWndSeams.h")
    source = read_app_source("TransferWnd.cpp")

    assert "CalculateUploadUtilizationPercent(" in seams
    assert "FormatUploadRateMbValue(" in seams
    assert "FormatQueueCountText(" in seams
    assert "MB/s" in seams
    assert "UL " in seams

    block = source[
        source.index("void CTransferWnd::ShowQueueCount") :
        source.index("void CTransferWnd::DoDataExchange")
    ]
    assert "void CTransferWnd::LayoutQueueFooter()" in source
    assert "pCount->MoveWindow(iLeft, rcCount.top, iRight - iLeft, rcCount.Height(), TRUE);" in source
    assert "pRefresh->IsWindowVisible()" in source
    assert "LayoutQueueFooter();" in block
    assert "TransferWndSeams::FormatQueueCountText(" in block
    assert "theApp.clientlist->GetBannedCount()" in block
    assert "theApp.uploadqueue->GetUploadQueueLength()" in block
    assert "theApp.uploadqueue->GetBroadbandBaseSlotTarget()" in block
    assert "theApp.uploadqueue->GetBroadbandSlotCap()" in block
    assert "theApp.uploadqueue->GetBroadbandUploadSlotElasticPercent()" in block
    assert "theApp.uploadqueue->GetToNetworkDatarate()" in block
    assert "theApp.uploadqueue->GetConfiguredUploadBudgetBytesPerSec()" in block
    assert "SetDlgItemText(IDC_QUEUECOUNT, strQueueTextValue);" in block


def _check_transfer_wnd_source__transfer_download_metrics_use_top_toolbar_row_and_buffer_sources() -> None:
    seams = read_app_source("TransferWndSeams.h")
    source = read_app_source("TransferWnd.cpp")
    header = read_app_source("TransferWnd.h")
    resource = read_app_source("emule.rc")
    resource_header = read_app_source("resource.h")

    assert "IDC_DOWNLOAD_METRICS" in resource_header
    assert 'CONTROL         "",IDC_DOWNLOAD_METRICS,"Static",SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX' in resource
    assert "void\tLayoutDownloadMetrics();" in header
    assert "void\tUpdateDownloadMetricsText();" in header
    assert "CalculateDownloadBufferUtilizationPercent(" in seams
    assert "FormatDownloadMetricsText(" in seams
    assert "kDownloadBufferUtilizationDisplayPercentMax" in seams
    assert 'L"DL buf "' in seams
    assert 'L" | f="' in seams
    assert 'L" lg="' in seams
    assert 'L" | cap="' in seams

    layout_block = source[
        source.index("void CTransferWnd::LayoutDownloadMetrics") :
        source.index("uint32 CTransferWnd::GetVisibleDisplayRefreshMask")
    ]
    assert "m_btnWnd1.GetWindowRect(&rcToolbar);" in layout_block
    assert "m_dlTab.GetWindowRect(&rcTab);" in layout_block
    assert "const int iLeft = rcToolbar.right + 5;" in layout_block
    assert "const int iRight = rcTab.left - 5;" in layout_block
    assert "SS_ENDELLIPSIS" in resource
    assert "pMetrics->ShowWindow(SW_HIDE);" in layout_block

    update_block = source[
        source.index("void CTransferWnd::UpdateDownloadMetricsText") :
        source.index("void CTransferWnd::ShowQueueCount")
    ]
    assert "theApp.downloadqueue->GetBufferedDownloadBytes()" in update_block
    assert "theApp.downloadqueue->GetAdaptiveGlobalDownloadBufferBudgetBytes()" in update_block
    assert "theApp.downloadqueue->GetBufferedDownloadFileCount()" in update_block
    assert "theApp.downloadqueue->GetLargestBufferedDownloadFileBytes()" in update_block
    assert "thePrefs.IsDownloadAutoBroadbandIOEnabled()" in update_block
    assert "if (bAutoBroadbandIoEnabled)" in update_block
    assert "TransferWndSeams::CalculateDownloadBufferUtilizationPercent(" in update_block
    assert "TransferWndSeams::FormatDownloadMetricsText(" in update_block
    assert "::GlobalMemoryStatusEx(&memory)" in update_block
    assert "CastItoXBytes(ullBufferedBytes)" in update_block
    assert "thePrefs.GetFileBufferSize()" in update_block
    assert "SetDlgItemText(IDC_DOWNLOAD_METRICS, strMetrics);" in update_block

    refresh_block = source[
        source.index("void CTransferWnd::FlushDisplayRefreshMask") :
        source.index("void CTransferWnd::UpdateDownloadMetricsText")
    ]
    assert "DISPLAY_REFRESH_TRANSFER_SUMMARY" in refresh_block
    assert "UpdateDownloadMetricsText();" in refresh_block


# --- consolidated from tests/python/test_tree_options_ddx_source.py ---


def _check_tree_options_ddx_source__tree_options_ddx_uses_checked_window_wrapper() -> None:
    source = (app_source_root() / "TreeOptionsCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "CTreeOptionsCtrl *PrepareTreeOptionsDDXCtrl(CDataExchange *pDX, int nIDC)" in source
    assert "if (pDX == NULL)\n\t\t\treturn NULL;" in source
    assert "if (hWndCtrl == NULL)\n\t\t\treturn NULL;" in source
    assert "DYNAMIC_DOWNCAST(CTreeOptionsCtrl, CWnd::FromHandlePermanent(hWndCtrl))" in source
    assert "static_cast<CTreeOptionsCtrl*>(CWnd::FromHandlePermanent(hWndCtrl))" not in source
    assert source.count("if (pCtrlTreeOptions == NULL)\n\t\treturn;") >= 11


def _check_tree_options_ddx_source__tree_options_ex_ddx_uses_checked_window_wrapper() -> None:
    source = (app_source_root() / "TreeOptionsCtrlEx.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "CTreeOptionsCtrl *PrepareTreeOptionsDDXCtrl(CDataExchange *pDX, int nIDC, bool bEditCtrl)" in source
    assert "if (pDX == NULL)\n\t\t\treturn NULL;" in source
    assert "if (hWndCtrl == NULL)\n\t\t\treturn NULL;" in source
    assert "DYNAMIC_DOWNCAST(CTreeOptionsCtrl, CWnd::FromHandlePermanent(hWndCtrl))" in source
    assert "static_cast<CTreeOptionsCtrl*>(CWnd::FromHandlePermanent(hWndCtrl))" not in source
    assert "if (pData == NULL)\n\t\treturn;" in source
    assert source.count("if (pCtrlTreeOptions == NULL)\n\t\treturn;") >= 3


# --- consolidated from tests/python/test_upload_bandwidth_throttler_source.py ---


def _check_upload_bandwidth_throttler_source__control_packets_wake_upload_throttler_wait_domains() -> None:
    source = (app_source_root() / "UploadBandwidthThrottler.cpp").read_text(encoding="utf-8", errors="ignore")

    queue_block = source[
        source.index("void UploadBandwidthThrottler::QueueForSendingControlPacket") :
        source.index("void UploadBandwidthThrottler::RemoveFromAllQueuesNoLock")
    ]
    assert "bool bQueuedControlPacket = false;" in queue_block
    assert "bQueuedControlPacket = true;" in queue_block
    assert "control work can arrive while the throttler is waiting" in queue_block
    assert "m_eventDataAvailable.SetEvent();" in queue_block
    assert "m_eventSocketAvailable.SetEvent();" in queue_block


def _check_upload_bandwidth_throttler_source__upload_throttler_pacing_wait_is_interruptible_by_new_data() -> None:
    source = (app_source_root() / "UploadBandwidthThrottler.cpp").read_text(encoding="utf-8", errors="ignore")

    wait_block = source[
        source.index("if (timeSinceLastLoop < sleepTime)") :
        source.index("if (!HelperThreadLaunchSeams::IsFlagSet(m_bRun))")
    ]
    assert "::WaitForSingleObject(m_eventDataAvailable, dwSleep);" in wait_block
    assert "::WaitForSingleObject(m_eventSocketAvailable, dwSleep);" in wait_block
    assert "::Sleep(dwSleep);" not in wait_block


# --- consolidated from tests/python/test_upload_disk_io_thread_source.py ---


def _check_upload_disk_io_thread_source__pending_upload_io_removes_by_pointer_not_stored_position() -> None:
    source = (app_source_root() / "UploadDiskIOThread.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "UploadDiskIOThread.h").read_text(encoding="utf-8", errors="ignore")

    assert "POSITION\t\t\t\tpos;" not in header
    # The pending I/O list is now mutated only through the AddPendingIo /
    # RemovePendingIoIfPresent helpers, which keep the list membership and the
    # atomic counter in lockstep. The membership is still keyed by pointer, not
    # by a position stored on the overlapped struct.
    assert "AddPendingIo(pOverlappedRead);" in source
    assert "m_listPendingIO.AddTail(pOvRead);" in source
    assert "pOverlappedRead->pos = m_listPendingIO.AddTail(pOverlappedRead);" not in source
    assert "m_listPendingIO.RemoveAt(pOvRead->pos);" not in source
    assert "DrainPendingReads();" in source
    assert "::CancelIoEx(pKnownFile->m_hRead" in source
    assert "throw _T(\"ReadFile Error: \") + GetErrorMessage(dwError, 1);" in source
    assert "throw _T(\"ReadFile Error: \") + GetErrorMessage(::GetLastError())" not in source
    assert "const DWORD dwEffectiveError = dwCompletionError != ERROR_SUCCESS ? dwCompletionError : ERROR_READ_FAULT;" in source
    assert "ReadCompletionRoutine(0, m_listPendingIO.RemoveHead(), ERROR_OPERATION_ABORTED);" not in source
    assert "Improper termination of asynchronous I/O follows" not in source
    # Removal finds the node by pointer inside RemovePendingIoIfPresent, and the
    # completion path drops the entry through that helper (const_cast at the call
    # site), never through a stored POSITION.
    assert "const POSITION posPending = m_listPendingIO.Find(pOvRead);" in source
    assert "if (posPending == NULL)\n\t\treturn false;\n\tm_listPendingIO.RemoveAt(posPending);" in source
    assert "RemovePendingIoIfPresent(const_cast<OverlappedRead_Struct*>(pOvRead))" in source
    assert "if (pKnownFile != NULL) {\n\t\t// Keep nInUse raised until every completion-path access to pKnownFile is done." in source
    assert "pKnownFile->ReleaseUploadReadReference();" in source
    assert "if (pStruct != NULL)\n\t\tpStruct->m_nPendingIOBlocks.fetch_sub(1);" in source


# --- consolidated from tests/python/test_upload_queue_source.py ---


def _check_upload_queue_source__upload_queue_position_helpers_reject_null_positions() -> None:
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


def _check_upload_queue_source__broadband_retained_slot_logs_are_throttled() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "static ULONGLONG s_ullLastBroadbandRetainedSlotLogTick = 0;" in source
    assert "static UINT s_uSuppressedBroadbandRetainedSlotLogs = 0;" in source
    assert "bool ShouldLogBroadbandRetainedSlot(UINT &uSuppressedLogs)" in source
    assert "constexpr ULONGLONG ullLogIntervalMs = SEC2MS(30);" in source
    assert "++s_uSuppressedBroadbandRetainedSlotLogs;" in source
    assert "Suppressed retained-slot logs: %u." in source
    assert source.count("if (!ShouldLogBroadbandRetainedSlot(uSuppressedLogs))\n\t\t\t\t\treturn false;") == 2
    assert source.count("if (!ShouldLogBroadbandRetainedSlot(uSuppressedLogs))\n\t\t\t\treturn false;") == 1


def _check_upload_queue_source__underfilled_upload_queue_probes_no_request_cooldowns_below_base_slots() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "UploadQueue.h").read_text(encoding="utf-8", errors="ignore")
    seams = (app_source_root() / "UploadQueueSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "ShouldProbeUploadCooldownCandidate" in seams
    assert "HasOpenBaseUploadSlotDuringBroadbandUnderfill" in seams
    assert "HasNoRequestUploadReplacementPressure" in seams
    assert "kProductiveNoRequestCooldownProbeRemainingMs = 5000u" in seams
    assert "ShouldProbeUnproductiveNoRequestCooldownCandidate" not in seams
    assert "ShouldProbeNoRequestCooldownCandidate" in seams
    assert "kUnproductiveNoRequestCooldownProbeRemainingMs" not in seams
    assert "iUploadSlots < iSoftMaxUploadSlots" in seams
    assert "return bOpenBaseSlotUnderfill;" in seams
    assert "return !bWaitingListEmpty && (bHasAdmissionCandidate || bHasCooldownProbeCandidate);" in seams
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
    assert "below the configured base slot target" in cooldown_probe_block
    assert "elastic overflow still treats those cooldowns as hard gates" in cooldown_probe_block
    assert "const ULONGLONG ullCooldownRemainingMs = itNoRequest->second.ullCooldownUntil - curTick;" in cooldown_probe_block
    assert "ShouldProbeNoRequestCooldownCandidate(" in cooldown_probe_block
    assert "kProductiveNoRequestCooldownProbeRemainingMs" in cooldown_probe_block
    assert "ShouldProbeUploadCooldownCandidate(HasSustainedBroadbandUnderfill(curTick), uploadinglist.GetCount(), GetSoftMaxUploadSlots())" in cooldown_probe_block
    assert cooldown_probe_block.index("ShouldProbeNoRequestCooldownCandidate") < cooldown_probe_block.rindex("return false;")

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
    assert "AcceptNewClient(curUploadSlots, curTick)" in force_new_block

    accept_block = source[
        source.index("bool CUploadQueue::AcceptNewClient") :
        source.index("uint32 CUploadQueue::GetTargetClientDataRate")
    ]
    assert "GetSoftMaxUploadSlots()" in accept_block
    assert "GetElasticMaxUploadSlots()" in accept_block
    assert "HasSustainedElasticBroadbandUnderfill(curTick)" in accept_block


def _check_upload_queue_source__broadband_upload_buffer_depth_scales_with_per_slot_target() -> None:
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


def _check_upload_queue_source__auto_broadband_io_diagnostics_distinguish_download_and_upload_buffers() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")

    assert '{"downloadAutoBroadbandIo", thePrefs.IsDownloadAutoBroadbandIOEnabled()}' in source
    assert '{"downloadAutoBroadbandIoScope", "downloadDiskWriteBufferOnly"}' in source
    assert '{"uploadSendPipeline", nlohmann::json{' in source
    assert '{"controlledByDownloadAutoBroadbandIo", false}' in source


def _check_upload_queue_source__nonzero_slow_slots_keep_accumulated_slow_tracking_for_recycle_path() -> None:
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
    assert "GetSlowUploadGraceSecondsForBudget(thePrefs.GetSlowUploadGraceSeconds(), uBudgetBytesPerSec)" in check_for_time_over_block
    assert "GetZeroUploadGraceSecondsForBudget(thePrefs.GetZeroUploadRateGraceSeconds(), uBudgetBytesPerSec)" in check_for_time_over_block


def _check_upload_queue_source__queued_upload_wait_time_uses_current_tick_until_slot_starts() -> None:
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


# --- consolidated from tests/python/test_upload_slot_diagnostics_source.py ---


def _check_upload_slot_diagnostics_source__transfer_bar_percentage_preference_uses_transfer_wide_text() -> None:
    resources = read_app_source("emule.rc")
    preferences_source = read_app_source("Preferences.cpp")

    assert 'IDS_SHOWDWLPERCENTAGE   "Show transfer percentages in progress bars"' in resources
    assert "Shows download and upload progress percentages inside transfer progress bars." in resources
    assert 'ini.WriteBool(_T("ShowDwlPercentage"), m_bShowDwlPercentage);' in preferences_source
    assert 'ini.GetBool(_T("ShowDwlPercentage"), true);' in preferences_source


def _check_upload_slot_diagnostics_source__upload_slot_diagnostics_reports_cooldown_pressure() -> None:
    source = read_app_source("UploadQueue.cpp")
    header = read_app_source("UploadQueue.h")
    seams_header = read_app_source("UploadQueueSeams.h")
    log_header = read_app_source("Log.h")
    artifacts = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")
    block = source[source.index("void CUploadQueue::LogUploadSlotDiagnostics") : source.index("void CUploadQueue::Process()")]

    assert "UploadSlotDiagnosticsLogLine(" in block
    assert 'CDiagnosticsKeyValueLineBuilder summary(_T("UploadSlotDiagnostics: summary"));' in block
    assert 'UploadSlotDiagnosticsLogLine(_T("%s"), (LPCTSTR)summary.GetLine());' in block
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
    assert "CSharedFileList::SharedPublishDiagnosticsSnapshot sharedPublish = {};" in block
    assert "theApp.sharedfiles->GetPublishDiagnosticsSnapshot(sharedPublish);" in block
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
    assert "HasNoRequestUploadReplacementPressure(" in no_request_recycle_block
    assert "const bool bHasAdmissionCandidate = HasUploadAdmissionCandidate(curTick);" in no_request_recycle_block
    assert "const bool bHasCooldownProbeCandidate = !bHasAdmissionCandidate && HasUploadCooldownProbeCandidate(curTick);" in no_request_recycle_block
    assert "Broadband no-request slot retained because no replacement is available" in no_request_recycle_block
    assert no_request_recycle_block.index("HasNoRequestUploadReplacementPressure(") < no_request_recycle_block.index("if (ShouldCooldownNoRequestUploadRecycle(false))")
    assert "const UINT uProductiveCooldownSeconds = GetNoRequestUploadRetryCooldownSeconds" in no_request_recycle_block
    assert "const UINT uRepeatCooldownMaxSeconds = GetRepeatedNoRequestUploadCooldownMaxSecondsForBudget(uBudgetBytesPerSec);" in no_request_recycle_block
    assert "const UINT uBaseCooldownSeconds = uConfiguredCooldownSeconds;" in no_request_recycle_block
    assert "const UINT uRepeatBanThreshold = GetNoRequestRepeatBanThresholdForBudget(uBudgetBytesPerSec);" in no_request_recycle_block
    assert "NoRequestRepeatPenalty repeatPenalty = {};" in no_request_recycle_block
    assert "repeatPenalty = TrackNoRequestRepeatOffender(client, curTick, uBaseCooldownSeconds, uRepeatCooldownMaxSeconds, uRepeatBanThreshold);" in no_request_recycle_block
    assert "uCooldownSeconds = repeatPenalty.uCooldownSeconds;" in no_request_recycle_block
    assert "uRepeatBanThreshold," in no_request_recycle_block
    assert "GetNoRequestRepeatCooldownSeconds(uBaseCooldownSeconds, penalty.uStrikes, uMaxCooldownSeconds)" in source
    assert "upload_no_request_repeat_cooldown" in no_request_recycle_block
    assert "upload_no_request_repeat_ban" in no_request_recycle_block
    assert '\\"max_cooldown_seconds\\":%u' in no_request_recycle_block
    assert '\\"key_type\\":\\"%s\\",\\"scope\\":\\"%s\\"' in no_request_recycle_block
    assert "LPCTSTR pszRepeatScope = repeatPenalty.bShouldIPBan || !repeatPenalty.bHashScoped ? _T(\"ip\") : _T(\"hash\");" in no_request_recycle_block
    assert "Repeated zero-request upload slot abuse" in no_request_recycle_block
    assert "if (pbRequeue != NULL && client->IsBanned())" in source
    assert "const ULONGLONG ullCooldownUntil = curTick + SEC2MS(uCooldownSeconds);" in no_request_recycle_block
    assert "const ULONGLONG ullTrackUntil = curTick + SEC2MS(GetNoRequestUploadRetryTrackSeconds(uCooldownSeconds, uConfiguredCooldownSeconds));" in no_request_recycle_block
    no_request_cooldown_start = no_request_recycle_block.index("const UINT uBaseCooldownSeconds")
    no_request_cooldown_block = no_request_recycle_block[
        no_request_cooldown_start :
        no_request_recycle_block.index("client->SetSlowUploadCooldownUntil", no_request_cooldown_start)
    ]
    assert no_request_recycle_block.index("const UINT uRepeatCooldownMaxSeconds") < no_request_recycle_block.index("const UINT uProductiveCooldownSeconds")
    assert no_request_cooldown_block.index("const UINT uBaseCooldownSeconds") < no_request_cooldown_block.index("const UINT uInitialCooldownSeconds")
    assert no_request_cooldown_block.index("const UINT uRepeatBanThreshold") < no_request_cooldown_block.index("TrackNoRequestRepeatOffender")
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


def _check_upload_slot_diagnostics_source__stalled_upload_retry_cooldown_is_bounded() -> None:
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


def _check_upload_slot_diagnostics_source__queued_block_request_can_reopen_upload_slot_after_cooldown_clear() -> None:
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
    assert "LPCTSTR pszCooldownClearDiagnosticsReason = NULL;" in not_uploading_block
    assert "const bool bCooldownCleared = theApp.uploadqueue->ClearUploadRetryCooldown(this, &pszCooldownClearDiagnosticsReason);" in not_uploading_block
    assert "TryAdmitQueuedBlockRequestClient(this, bCooldownCleared)" in not_uploading_block
    assert "accept-queued-request-direct-admit" in not_uploading_block
    assert "eQueuedRequestAdmissionResult == queuedBlockRequestCooldownNotCleared && pszCooldownClearDiagnosticsReason != NULL" in not_uploading_block
    assert "GetQueuedBlockRequestAdmissionDiagnosticsReason(eQueuedRequestAdmissionResult)" in not_uploading_block
    assert not_uploading_block.index("accept-queued-request-direct-admit") < not_uploading_block.index("GetQueuedBlockRequestAdmissionDiagnosticsReason")
    assert "bool ClearUploadRetryCooldown(CUpDownClient *client, LPCTSTR *ppszDiagnosticsReason = NULL)" in queue_header
    assert "bool CUploadQueue::ClearUploadRetryCooldown(CUpDownClient *client, LPCTSTR *ppszDiagnosticsReason)" in queue_source
    clear_cooldown_block = queue_source[
        queue_source.index("bool CUploadQueue::ClearUploadRetryCooldown") :
        queue_source.index("QueuedBlockRequestAdmissionResult CUploadQueue::TryAdmitQueuedBlockRequestClient")
    ]
    assert "const bool bProductiveNoRequestRecycle = itNoRequest->second.bProductiveRecycle;" in queue_source
    assert "ShouldAllowNoRequestCooldownClear(true, itNoRequest->second.bQueuedRequestClearUsed)" in queue_source
    assert "reject-not-uploading-no-request-clear-used" in queue_source
    assert "ShouldClearActiveNoRequestCooldownOnQueuedRequest" in seams_header
    assert "bClearedUnderfilledNoRequestCooldown" in clear_cooldown_block
    assert "bOpenBaseSlotUnderfill" in clear_cooldown_block
    assert "bClearedProductiveNoRequestCooldown = true;" in queue_source
    assert "fresh demand" not in clear_cooldown_block
    assert "ShouldBlockQueuedRequestRetryClearForActiveNoRequest" in seams_header
    assert "bClearedProductiveNoRequestCooldown || bClearedUnderfilledNoRequestCooldown" in clear_cooldown_block
    assert "reject-not-uploading-unproductive-no-request-active" in clear_cooldown_block
    assert clear_cooldown_block.index("ShouldBlockQueuedRequestRetryClearForActiveNoRequest") < clear_cooldown_block.index("m_uploadRetryCooldownByIP.find(dwCooldownIP)")
    assert "bHadClientCooldown || bHadIPCooldown || bClearedProductiveNoRequestCooldown || bClearedUnderfilledNoRequestCooldown" in queue_source
    assert "reject-not-uploading-retry-clear-used" in queue_source
    assert "reject-not-uploading-no-request-only-cooldown" in queue_source
    assert "reject-not-uploading-no-active-cooldown" in queue_source
    assert "AcceptNewClient(uploadinglist.GetCount(), ::GetTickCount64())" in direct_admit_block
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


def _check_upload_slot_diagnostics_source__upload_list_membership_honors_queued_refresh_timing() -> None:
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
    assert "m_pendingAutoAddTicks" in list_source
    assert "m_pendingAutoRemoveTicks" in list_source
    assert "ShouldCommitTransferListMembershipChange" in sync_block
    assert "PruneStaleClientItems(true, ullNowTick)" in sync_block
    assert "IsTrackedClientPointer(client)" in list_source
    assert "GetFirstFromUploadList()" in sync_block
    assert "InsertItem(LVIF_TEXT | LVIF_PARAM" in sync_block
    assert "SyncLiveClientItems();" in refresh_block


def _check_upload_slot_diagnostics_source__queue_list_membership_honors_queued_refresh_timing() -> None:
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
    assert "m_pendingAutoAddTicks" in list_source
    assert "m_pendingAutoRemoveTicks" in list_source
    assert "ShouldCommitTransferListMembershipChange" in sync_block
    assert "PruneStaleClientItems(true, ullNowTick)" in sync_block
    assert "IsTrackedClientPointer(client)" in list_source
    assert "GetNextClient(client)" in sync_block
    assert "InsertItem(LVIF_TEXT | LVIF_PARAM" in sync_block
    assert "SyncLiveClientItems();" in refresh_block


def _check_upload_slot_diagnostics_source__upload_part_counts_are_distinct_text_columns_and_bars_remain() -> None:
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


def _check_upload_slot_diagnostics_source__upload_eta_and_percent_use_same_estimated_obtained_bytes() -> None:
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


def _check_upload_slot_diagnostics_source__upload_part_status_report_flag_tracks_protocol_bitmap_presence() -> None:
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


# --- consolidated from tests/python/test_version_check_source.py ---


def _h_version_check_source___app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def _check_version_check_source__version_check_worker_does_not_keep_raw_dialog_queue_pointer() -> None:
    source_root = _h_version_check_source___app_source_root()
    emule_dlg_cpp = (source_root / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    emule_dlg_h = (source_root / "EmuleDlg.h").read_text(encoding="utf-8", errors="ignore")
    seams = (source_root / "VersionCheckLaunchSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "std::shared_ptr<VersionCheckLaunchSeams::SQueuedState> m_pVersionCheckState" in emule_dlg_h
    assert "std::shared_ptr<VersionCheckLaunchSeams::SQueuedState> pQueuedState" in emule_dlg_cpp
    assert "volatile LONG\tm_lVersionCheckQueued" not in emule_dlg_h
    assert "plQueued" not in emule_dlg_cpp
    assert "ClearQueuedOnOwnerTeardown(m_pVersionCheckState)" in emule_dlg_cpp
    assert "struct SQueuedState" in seams
    assert "PostCompletion(HWND hNotifyWnd, UINT uMessage, LPARAM lParam, const std::shared_ptr<SQueuedState>& pState)" in seams
    assert "volatile LONG *" not in seams


# --- consolidated from tests/python/test_wait_diagnostics_source.py ---


def _check_wait_diagnostics_source__shared_hash_worker_wait_failure_logs_error_message() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const DWORD dwWaitError = ::GetLastError();" in source
    assert 'DebugLogError(_T("Failed to wait for shared-file hash worker shutdown - %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source
    assert 'DebugLogError(_T("Failed to wait for shared-file hash worker shutdown - Error %lu"), ::GetLastError());' not in source


def _check_wait_diagnostics_source__rest_ui_dispatch_wait_failure_returns_error_message() -> None:
    source = (app_source_root() / "WebServerJson.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const DWORD dwWaitError = ::GetLastError();" in source
    assert 'rError.strMessage.Format(_T("failed to wait for REST UI dispatch completion - %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source
    assert 'rError.strMessage.Format(_T("failed to wait for REST UI dispatch completion - Error %lu"), ::GetLastError());' not in source


# --- consolidated from tests/python/test_web_socket_source.py ---


def _check_web_socket_source__web_bind_addr_resolution_rejects_null_output_pointer() -> None:
    source = (app_source_root() / "WebSocket.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool TryResolveWebBindAddr(in_addr *pAddr)\n\t{\n\t\tASSERT(pAddr != NULL);\n\t\tif (pAddr == NULL)\n\t\t\treturn false;\n\t\tpAddr->s_addr = INADDR_ANY;" in source


def _check_web_socket_source__web_socket_shutdown_defers_teardown_after_timeout() -> None:
    source = (app_source_root() / "WebSocket.cpp").read_text(encoding="utf-8", errors="ignore")
    seams = (app_source_root() / "WebSocketHttpSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "enum class ESocketThreadShutdownFollowUp" in seams
    assert "GetSocketThreadShutdownFollowUp(const bool bBoundedWaitSucceeded)" in seams
    assert "DeferShutdownCleanup" in seams
    assert "DebugLogError(_T(\"Web Interface listener thread is still using WebServer state; deferring socket teardown for process exit.\"));" in source
    assert "(void)::WaitForSingleObject(s_pSocketThread->m_hThread, INFINITE);" not in source
    assert "DebugLogError(_T(\"Web Interface accepted-client thread(s) are still using WebServer state; deferring socket teardown for process exit.\"));" in source
    assert "(void)WaitForAcceptedThreadHandles(INFINITE);" not in source


def _check_web_socket_source__web_socket_wait_failures_log_error_messages() -> None:
    source = (app_source_root() / "WebSocket.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.count("const DWORD dwWaitError = ::GetLastError();") >= 4
    assert 'DebugLogWarning(_T("Web Interface accepted-client thread wait failed while reaping finished threads: %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source
    assert 'DebugLogWarning(_T("Web Interface accepted-client thread wait failed during shutdown: %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source
    assert 'DebugLogError(_T("Web Interface listener thread wait failed: %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source

# --- parametrized registry: one case per former test function ---
_PARITY_CASES = [
    ("aich_sync_thread_source::test_aich_sync_thread_is_owned_and_joined_before_shared_file_teardown", _check_aich_sync_thread_source__aich_sync_thread_is_owned_and_joined_before_shared_file_teardown),
    ("aich_sync_thread_source::test_aich_sync_worker_guards_shared_and_known_file_globals", _check_aich_sync_thread_source__aich_sync_worker_guards_shared_and_known_file_globals),
    ("aich_sync_thread_source::test_known2_met_recovery_truncate_failure_logs_exception_details", _check_aich_sync_thread_source__known2_met_recovery_truncate_failure_logs_exception_details),
    ("aich_sync_thread_source::test_aich_known2_rewrite_uses_exact_reads_and_owned_buffers", _check_aich_sync_thread_source__aich_known2_rewrite_uses_exact_reads_and_owned_buffers),
    ("async_socket_ex_layer_source::test_layered_sockets_apply_configured_bind_interface_after_bind", _check_async_socket_ex_layer_source__layered_sockets_apply_configured_bind_interface_after_bind),
    ("async_socket_ex_source::test_connect_completion_revalidates_socket_after_on_connect_callback", _check_async_socket_ex_source__connect_completion_revalidates_socket_after_on_connect_callback),
    ("bad_peer_diagnostics_source::test_bad_peer_diagnostics_compile_flag_is_opt_in", _check_bad_peer_diagnostics_source__bad_peer_diagnostics_compile_flag_is_opt_in),
    ("bad_peer_diagnostics_source::test_bad_peer_diagnostics_build_and_release_plumbing", _check_bad_peer_diagnostics_source__bad_peer_diagnostics_build_and_release_plumbing),
    ("bad_peer_diagnostics_source::test_bad_peer_diagnostics_logger_is_compile_gated", _check_bad_peer_diagnostics_source__bad_peer_diagnostics_logger_is_compile_gated),
    ("bad_peer_diagnostics_source::test_bad_peer_diagnostics_covers_evidence_categories", _check_bad_peer_diagnostics_source__bad_peer_diagnostics_covers_evidence_categories),
    ("bad_peer_diagnostics_source::test_bad_peer_diagnostics_tracks_upload_clog_patterns", _check_bad_peer_diagnostics_source__bad_peer_diagnostics_tracks_upload_clog_patterns),
    ("bad_peer_repeat_policy_source::test_repeated_no_request_policy_is_configured_hash_aware_and_bounded", _check_bad_peer_repeat_policy_source__repeated_no_request_policy_is_configured_hash_aware_and_bounded),
    ("bad_peer_repeat_policy_source::test_manual_peer_menus_can_ban_hash_or_ip_scope", _check_bad_peer_repeat_policy_source__manual_peer_menus_can_ban_hash_or_ip_scope),
    ("bar_shader_source::test_bar_shader_restores_empty_span_fallback_before_range_and_draw", _check_bar_shader_source__bar_shader_restores_empty_span_fallback_before_range_and_draw),
    ("buddy_button_source::test_buddy_button_subclass_callback_guards_missing_state", _check_buddy_button_source__buddy_button_subclass_callback_guards_missing_state),
    ("buddy_button_source::test_add_buddy_button_rolls_back_half_installed_subclass", _check_buddy_button_source__add_buddy_button_rolls_back_half_installed_subclass),
    ("check_updates_menu_source::test_tools_menu_check_for_updates_runs_manual_version_check", _check_check_updates_menu_source__tools_menu_check_for_updates_runs_manual_version_check),
    ("check_updates_menu_source::test_check_for_updates_status_string_is_release_localized", _check_check_updates_menu_source__check_for_updates_status_string_is_release_localized),
    ("client_credits_source::test_client_credit_signature_helpers_reject_null_inputs", _check_client_credits_source__client_credit_signature_helpers_reject_null_inputs),
    ("color_button_source::test_color_button_ddx_guards_missing_control_and_wrong_subclass", _check_color_button_source__color_button_ddx_guards_missing_control_and_wrong_subclass),
    ("crash_dump_source::test_crash_handler_can_use_configured_full_dump_type", _check_crash_dump_source__crash_handler_can_use_configured_full_dump_type),
    ("crash_dump_source::test_capture_full_crash_dump_preference_is_persisted_and_exposed_in_tweaks", _check_crash_dump_source__capture_full_crash_dump_preference_is_persisted_and_exposed_in_tweaks),
    ("dead_source_list_source::test_dead_source_list_skips_unidentifiable_clients_before_hashing", _check_dead_source_list_source__dead_source_list_skips_unidentifiable_clients_before_hashing),
    ("download_list_ctrl_source::test_remove_file_rejects_null_before_matching_owner_rows", _check_download_list_ctrl_source__remove_file_rejects_null_before_matching_owner_rows),
    ("download_list_ctrl_source::test_add_source_rejects_stale_owner_before_parent_lookup", _check_download_list_ctrl_source__add_source_rejects_stale_owner_before_parent_lookup),
    ("download_list_ctrl_source::test_draw_item_checks_next_row_before_tree_line_deref", _check_download_list_ctrl_source__draw_item_checks_next_row_before_tree_line_deref),
    ("download_list_ctrl_source::test_thumbnail_completion_resumes_deferred_part_file_delete_after_preview_release", _check_download_list_ctrl_source__thumbnail_completion_resumes_deferred_part_file_delete_after_preview_release),
    ("download_list_ctrl_source::test_download_filename_suffix_only_uses_live_thumbnail_cache", _check_download_list_ctrl_source__download_filename_suffix_only_uses_live_thumbnail_cache),
    ("download_list_ctrl_source::test_download_infotip_wraps_long_lines_before_tooltip_suffix", _check_download_list_ctrl_source__download_infotip_wraps_long_lines_before_tooltip_suffix),
    ("download_list_ctrl_source::test_download_obtained_parts_are_a_distinct_text_column", _check_download_list_ctrl_source__download_obtained_parts_are_a_distinct_text_column),
    ("download_queue_source::test_download_queue_priority_sort_guards_list_positions_before_access", _check_download_queue_source__download_queue_priority_sort_guards_list_positions_before_access),
    ("download_queue_source::test_download_queue_waits_for_completion_worker_before_deleting_part_files", _check_download_queue_source__download_queue_waits_for_completion_worker_before_deleting_part_files),
    ("download_queue_source::test_search_result_source_addition_logs_file_exception_details", _check_download_queue_source__search_result_source_addition_logs_file_exception_details),
    ("download_queue_source::test_startup_part_file_hash_jobs_are_released_after_part_scan", _check_download_queue_source__startup_part_file_hash_jobs_are_released_after_part_scan),
    ("download_queue_source::test_local_server_source_requests_prefer_starved_files_before_wait_order", _check_download_queue_source__local_server_source_requests_prefer_starved_files_before_wait_order),
    ("download_queue_source::test_local_server_source_requests_prune_stale_entries_before_spending_credit", _check_download_queue_source__local_server_source_requests_prune_stale_entries_before_spending_credit),
    ("download_queue_source::test_download_summary_reports_source_discovery_pressure", _check_download_queue_source__download_summary_reports_source_discovery_pressure),
    ("download_queue_source::test_kad_source_searches_prefer_starved_ready_files_without_expanding_kad_budget", _check_download_queue_source__kad_source_searches_prefer_starved_ready_files_without_expanding_kad_budget),
    ("download_slot_diagnostics_source::test_download_slot_diagnostics_compile_flag_is_opt_in", _check_download_slot_diagnostics_source__download_slot_diagnostics_compile_flag_is_opt_in),
    ("download_slot_diagnostics_source::test_download_slot_diagnostics_build_env_override_is_plumbed", _check_download_slot_diagnostics_source__download_slot_diagnostics_build_env_override_is_plumbed),
    ("download_slot_diagnostics_source::test_download_slot_diagnostics_logs_queue_and_client_state", _check_download_slot_diagnostics_source__download_slot_diagnostics_logs_queue_and_client_state),
    ("download_slot_diagnostics_source::test_download_buffer_diagnostics_splits_part_file_flush_states", _check_download_slot_diagnostics_source__download_buffer_diagnostics_splits_part_file_flush_states),
    ("download_slot_diagnostics_source::test_download_slot_no_data_and_out_of_part_guards_are_conservative", _check_download_slot_diagnostics_source__download_slot_no_data_and_out_of_part_guards_are_conservative),
    ("download_slot_diagnostics_source::test_duplicate_complete_download_block_advances_and_retires_stale_pending_request", _check_download_slot_diagnostics_source__duplicate_complete_download_block_advances_and_retires_stale_pending_request),
    ("download_slot_diagnostics_source::test_stale_block_packets_abort_only_after_conservative_burst", _check_download_slot_diagnostics_source__stale_block_packets_abort_only_after_conservative_burst),
    ("download_slot_diagnostics_source::test_duplicate_zero_write_blocks_feed_stale_packet_guard", _check_download_slot_diagnostics_source__duplicate_zero_write_blocks_feed_stale_packet_guard),
    ("emsocket_send_seams_source::test_consume_queued_file_payload_rejects_null_counter", _check_emsocket_send_seams_source__consume_queued_file_payload_rejects_null_counter),
    ("emsocket_send_seams_source::test_standard_upload_send_queue_budget_is_broadband_sized", _check_emsocket_send_seams_source__standard_upload_send_queue_budget_is_broadband_sized),
    ("emule_dlg_source::test_startup_initialization_logs_mfc_exception_details", _check_emule_dlg_source__startup_initialization_logs_mfc_exception_details),
    ("emule_dlg_source::test_shutdown_keeps_part_file_writer_alive_through_download_queue_teardown", _check_emule_dlg_source__shutdown_keeps_part_file_writer_alive_through_download_queue_teardown),
    ("emule_dlg_source::test_stored_search_startup_stage_closes_progress_dialog_without_extra_queued_hop", _check_emule_dlg_source__stored_search_startup_stage_closes_progress_dialog_without_extra_queued_hop),
    ("emule_dlg_source::test_startup_progress_dialog_destruction_flushes_pending_window_messages", _check_emule_dlg_source__startup_progress_dialog_destruction_flushes_pending_window_messages),
    ("emule_dlg_source::test_upnp_startup_and_refresh_log_suppressed_exception_details", _check_emule_dlg_source__upnp_startup_and_refresh_log_suppressed_exception_details),
    ("emule_dlg_source::test_upnp_result_logs_backend_diagnostic_details", _check_emule_dlg_source__upnp_result_logs_backend_diagnostic_details),
    ("emule_dlg_source::test_upnp_periodic_refresh_timer_lifecycle", _check_emule_dlg_source__upnp_periodic_refresh_timer_lifecycle),
    ("friend_source::test_set_linked_client_skips_refresh_after_friendlist_teardown", _check_friend_source__set_linked_client_skips_refresh_after_friendlist_teardown),
    ("friend_source::test_try_to_connect_rejects_null_listener_before_queue_or_callback", _check_friend_source__try_to_connect_rejects_null_listener_before_queue_or_callback),
    ("frozen_legacy_surfaces_source::test_legacy_frozen_surfaces_are_called_out_at_class_boundary", _check_frozen_legacy_surfaces_source__legacy_frozen_surfaces_are_called_out_at_class_boundary),
    ("irc_channel_tab_source::test_remove_channel_checks_list_position_before_remove_at", _check_irc_channel_tab_source__remove_channel_checks_list_position_before_remove_at),
    ("kad_contact_quality_source::test_kad_contact_quality_score_is_local_and_health_weighted", _check_kad_contact_quality_source__kad_contact_quality_score_is_local_and_health_weighted),
    ("kad_contact_quality_source::test_kad_routing_uses_quality_for_probe_and_weak_replacement_only", _check_kad_contact_quality_source__kad_routing_uses_quality_for_probe_and_weak_replacement_only),
    ("kad_contact_quality_source::test_kad_diagnostics_exposes_contact_quality_score", _check_kad_contact_quality_source__kad_diagnostics_exposes_contact_quality_score),
    ("kad_diagnostics_source::test_kad_diagnostics_compile_flag_is_opt_in", _check_kad_diagnostics_source__kad_diagnostics_compile_flag_is_opt_in),
    ("kad_diagnostics_source::test_kad_diagnostics_build_and_release_plumbing", _check_kad_diagnostics_source__kad_diagnostics_build_and_release_plumbing),
    ("kad_diagnostics_source::test_kad_diagnostics_logger_is_compile_gated", _check_kad_diagnostics_source__kad_diagnostics_logger_is_compile_gated),
    ("kad_diagnostics_source::test_kad_diagnostics_covers_health_and_bad_behavior_categories", _check_kad_diagnostics_source__kad_diagnostics_covers_health_and_bad_behavior_categories),
    ("kad_routing_bin_source::test_routing_bin_rejects_null_contact_inputs_before_deref", _check_kad_routing_bin_source__routing_bin_rejects_null_contact_inputs_before_deref),
    ("kad_routing_bin_source::test_routing_bin_skips_stale_null_entries_while_checking_duplicates", _check_kad_routing_bin_source__routing_bin_skips_stale_null_entries_while_checking_duplicates),
    ("kad_ui_source::test_kademlia_window_rejects_null_contacts_before_deref", _check_kad_ui_source__kademlia_window_rejects_null_contacts_before_deref),
    ("kad_ui_source::test_kad_contact_controls_reject_null_contacts", _check_kad_ui_source__kad_contact_controls_reject_null_contacts),
    ("kad_ui_source::test_kad_search_list_rejects_null_searches_before_lparam_lookup", _check_kad_ui_source__kad_search_list_rejects_null_searches_before_lparam_lookup),
    ("known_file_list_source::test_known_file_stat_merge_rejects_null_inputs_before_size_compare", _check_known_file_list_source__known_file_stat_merge_rejects_null_inputs_before_size_compare),
    ("known_file_source::test_known_file_hash_creation_rejects_missing_inputs", _check_known_file_source__known_file_hash_creation_rejects_missing_inputs),
    ("known_file_source::test_known_file_hash_creation_checks_short_reads_in_release_builds", _check_known_file_source__known_file_hash_creation_checks_short_reads_in_release_builds),
    ("known_file_source::test_known_file_hash_wrappers_log_exception_details", _check_known_file_source__known_file_hash_wrappers_log_exception_details),
    ("known_file_source::test_known_file_metadata_extractors_log_exception_details", _check_known_file_source__known_file_metadata_extractors_log_exception_details),
    ("list_box_st_source::test_list_box_item_data_helpers_reject_invalid_slots_before_deref", _check_list_box_st_source__list_box_item_data_helpers_reject_invalid_slots_before_deref),
    ("list_box_st_source::test_list_box_move_stops_when_reinsert_fails", _check_list_box_st_source__list_box_move_stops_when_reinsert_fails),
    ("list_view_property_sheet_source::test_list_view_property_sheet_insert_page_rejects_null_page", _check_list_view_property_sheet_source__list_view_property_sheet_insert_page_rejects_null_page),
    ("listen_socket_source::test_packet_received_preserves_mfc_exception_details_before_generic_unknown", _check_listen_socket_source__packet_received_preserves_mfc_exception_details_before_generic_unknown),
    ("listen_socket_source::test_shared_browse_requests_use_shared_file_snapshots", _check_listen_socket_source__shared_browse_requests_use_shared_file_snapshots),
    ("live_dump_regression_source::test_low_id_upload_callback_does_not_assert_on_upload_connecting_state", _check_live_dump_regression_source__low_id_upload_callback_does_not_assert_on_upload_connecting_state),
    ("live_dump_regression_source::test_client_list_cleanup_uses_full_delete_readiness_predicate", _check_live_dump_regression_source__client_list_cleanup_uses_full_delete_readiness_predicate),
    ("live_dump_regression_source::test_corruption_blackbox_recomputes_merge_target_after_record_mutation", _check_live_dump_regression_source__corruption_blackbox_recomputes_merge_target_after_record_mutation),
    ("live_dump_regression_source::test_disconnect_deletes_only_after_request_file_detach", _check_live_dump_regression_source__disconnect_deletes_only_after_request_file_detach),
    ("live_dump_regression_source::test_banned_waiting_upload_client_is_detached_before_banned_state", _check_live_dump_regression_source__banned_waiting_upload_client_is_detached_before_banned_state),
    ("live_dump_regression_source::test_duplicate_temp_source_detaches_request_file_before_attach_delete", _check_live_dump_regression_source__duplicate_temp_source_detaches_request_file_before_attach_delete),
    ("log_source::test_log_helpers_reject_null_format_strings", _check_log_source__log_helpers_reject_null_format_strings),
    ("log_source::test_main_dialog_keeps_disk_log_lines_complete_when_ui_rows_are_truncated", _check_log_source__main_dialog_keeps_disk_log_lines_complete_when_ui_rows_are_truncated),
    ("mule_list_ctrl_source::test_end_scroll_cleanup_releases_window_dc", _check_mule_list_ctrl_source__end_scroll_cleanup_releases_window_dc),
    ("mule_list_ctrl_source::test_shadow_param_list_resyncs_before_position_access", _check_mule_list_ctrl_source__shadow_param_list_resyncs_before_position_access),
    ("mule_list_ctrl_source::test_view_preset_command_pairs_live_lists_with_explicit_profiles", _check_mule_list_ctrl_source__view_preset_command_pairs_live_lists_with_explicit_profiles),
    ("oscope_ctrl_source::test_oscope_recreate_graph_does_not_trust_only_first_trend_iterator", _check_oscope_ctrl_source__oscope_recreate_graph_does_not_trust_only_first_trend_iterator),
    ("oscope_ctrl_source::test_oscope_public_trend_api_checks_indices_in_release", _check_oscope_ctrl_source__oscope_public_trend_api_checks_indices_in_release),
    ("oscope_ctrl_source::test_oscope_invalidate_does_not_require_parent_window", _check_oscope_ctrl_source__oscope_invalidate_does_not_require_parent_window),
    ("out_of_part_reqs_loop_guard_source::test_out_of_part_reqs_packet_uses_client_owned_handler", _check_out_of_part_reqs_loop_guard_source__out_of_part_reqs_packet_uses_client_owned_handler),
    ("out_of_part_reqs_loop_guard_source::test_inbound_out_of_part_reqs_records_before_download_state_demotion", _check_out_of_part_reqs_loop_guard_source__inbound_out_of_part_reqs_records_before_download_state_demotion),
    ("out_of_part_reqs_loop_guard_source::test_accept_upload_checks_out_of_part_reqs_guard_before_start_download", _check_out_of_part_reqs_loop_guard_source__accept_upload_checks_out_of_part_reqs_guard_before_start_download),
    ("out_of_part_reqs_loop_guard_source::test_out_of_part_reqs_guard_thresholds_are_balanced_and_client_global", _check_out_of_part_reqs_loop_guard_source__out_of_part_reqs_guard_thresholds_are_balanced_and_client_global),
    ("out_of_part_reqs_loop_guard_source::test_out_of_part_reqs_guard_logs_transitions_and_suppression_with_context", _check_out_of_part_reqs_loop_guard_source__out_of_part_reqs_guard_logs_transitions_and_suppression_with_context),
    ("packet_diagnostics_source::test_packet_diagnostics_compile_flag_is_opt_in", _check_packet_diagnostics_source__packet_diagnostics_compile_flag_is_opt_in),
    ("packet_diagnostics_source::test_packet_diagnostics_build_env_override_is_available", _check_packet_diagnostics_source__packet_diagnostics_build_env_override_is_available),
    ("packet_diagnostics_source::test_startup_diagnostics_compile_flag_is_opt_in", _check_packet_diagnostics_source__startup_diagnostics_compile_flag_is_opt_in),
    ("packet_diagnostics_source::test_startup_diagnostics_trace_uses_log_artifact_name", _check_packet_diagnostics_source__startup_diagnostics_trace_uses_log_artifact_name),
    ("packet_diagnostics_source::test_retired_diagnostic_flags_are_rejected_at_feature_header_only", _check_packet_diagnostics_source__retired_diagnostic_flags_are_rejected_at_feature_header_only),
    ("packet_diagnostics_source::test_packet_diagnostics_logging_api_is_compile_guarded", _check_packet_diagnostics_source__packet_diagnostics_logging_api_is_compile_guarded),
    ("packet_diagnostics_source::test_rest_recent_log_ring_is_bounded_and_clearable", _check_packet_diagnostics_source__rest_recent_log_ring_is_bounded_and_clearable),
    ("packet_diagnostics_source::test_invalid_sub_opcode_diagnostics_call_sites_are_guarded", _check_packet_diagnostics_source__invalid_sub_opcode_diagnostics_call_sites_are_guarded),
    ("packet_diagnostics_source::test_packet_diagnostics_emit_converged_ed2k_packet_v1_schema", _check_packet_diagnostics_source__packet_diagnostics_emit_converged_ed2k_packet_v1_schema),
    ("packet_diagnostics_source::test_packet_diagnostics_client_packet_call_sites_are_guarded", _check_packet_diagnostics_source__packet_diagnostics_client_packet_call_sites_are_guarded),
    ("packet_diagnostics_source::test_packet_diagnostics_does_not_port_full_tracing_harness", _check_packet_diagnostics_source__packet_diagnostics_does_not_port_full_tracing_harness),
    ("part_file_source::test_part_file_buffer_errors_do_not_report_success_as_unknown_write_error", _check_part_file_source__part_file_buffer_errors_do_not_report_success_as_unknown_write_error),
    ("part_file_source::test_part_file_flush_retires_written_buffers_before_sizing_unwritten_data", _check_part_file_source__part_file_flush_retires_written_buffers_before_sizing_unwritten_data),
    ("part_file_source::test_part_file_shutdown_flush_wait_allows_broadband_write_drain", _check_part_file_source__part_file_shutdown_flush_wait_allows_broadband_write_drain),
    ("part_file_source::test_part_file_preview_copy_logs_file_exception_details", _check_part_file_source__part_file_preview_copy_logs_file_exception_details),
    ("part_file_source::test_part_file_delete_defers_while_preview_worker_holds_reference", _check_part_file_source__part_file_delete_defers_while_preview_worker_holds_reference),
    ("part_file_source::test_part_file_completion_worker_posts_result_object_for_ui_thread_state_transition", _check_part_file_source__part_file_completion_worker_posts_result_object_for_ui_thread_state_transition),
    ("part_file_source::test_zone_identifier_failures_are_logged_with_hresult", _check_part_file_source__zone_identifier_failures_are_logged_with_hresult),
    ("part_file_source::test_part_file_load_does_not_use_file_status_after_get_status_exception", _check_part_file_source__part_file_load_does_not_use_file_status_after_get_status_exception),
    ("part_file_source::test_downloading_source_add_rejects_invalid_owner_and_tolerates_missing_ui", _check_part_file_source__downloading_source_add_rejects_invalid_owner_and_tolerates_missing_ui),
    ("part_file_source::test_downloading_source_add_recovers_corrupt_list_before_mfc_mutation", _check_part_file_source__downloading_source_add_recovers_corrupt_list_before_mfc_mutation),
    ("part_file_source::test_downloading_source_list_recovery_covers_remove_and_scan_entrypoints", _check_part_file_source__downloading_source_list_recovery_covers_remove_and_scan_entrypoints),
    ("part_file_source::test_endgame_steal_preserves_active_download_streams", _check_part_file_source__endgame_steal_preserves_active_download_streams),
    ("part_file_source::test_downloading_source_list_recovery_rebuilds_from_live_sources", _check_part_file_source__downloading_source_list_recovery_rebuilds_from_live_sources),
    ("part_file_source::test_completed_part_files_use_completion_hash_priority", _check_part_file_source__completed_part_files_use_completion_hash_priority),
    ("part_file_write_thread_source::test_pending_part_file_writes_are_cancelled_and_drained_before_shutdown_cleanup", _check_part_file_write_thread_source__pending_part_file_writes_are_cancelled_and_drained_before_shutdown_cleanup),
    ("persistence_diagnostics_source::test_preferences_load_failures_log_path_and_exception_details", _check_persistence_diagnostics_source__preferences_load_failures_log_path_and_exception_details),
    ("persistence_diagnostics_source::test_kad_preferences_failures_log_path_and_exception_details", _check_persistence_diagnostics_source__kad_preferences_failures_log_path_and_exception_details),
    ("persistence_diagnostics_source::test_kad_contact_persistence_failures_log_path_and_exception_details", _check_persistence_diagnostics_source__kad_contact_persistence_failures_log_path_and_exception_details),
    ("preview_source::test_peer_preview_logs_exception_details_before_returning_empty_result", _check_preview_source__peer_preview_logs_exception_details_before_returning_empty_result),
    ("preview_source::test_video_thumbnail_logs_exception_details_before_reporting_worker_failure", _check_preview_source__video_thumbnail_logs_exception_details_before_reporting_worker_failure),
    ("search_params_source::test_search_params_ignores_null_file_type_item_data", _check_search_params_source__search_params_ignores_null_file_type_item_data),
    ("search_results_source::test_search_results_refresh_layout_after_hidden_tab_changes", _check_search_results_source__search_results_refresh_layout_after_hidden_tab_changes),
    ("search_results_source::test_clean_shutdown_removes_tray_icon_before_long_teardown", _check_search_results_source__clean_shutdown_removes_tray_icon_before_long_teardown),
    ("server_list_source::test_get_server_at_rejects_invalid_indices_before_position_access", _check_server_list_source__get_server_at_rejects_invalid_indices_before_position_access),
    ("sha_hash_set_source::test_aich_recovery_hash_set_rejects_missing_owner_and_bad_part_ranges", _check_sha_hash_set_source__aich_recovery_hash_set_rejects_missing_owner_and_bad_part_ranges),
    ("shared_directory_rule_index_source::test_shared_directory_ops_owns_rule_index_and_key_helpers", _check_shared_directory_rule_index_source__shared_directory_ops_owns_rule_index_and_key_helpers),
    ("shared_directory_rule_index_source::test_preferences_tree_uses_shared_directory_rule_index", _check_shared_directory_rule_index_source__preferences_tree_uses_shared_directory_rule_index),
    ("shared_directory_rule_index_source::test_shared_files_tree_uses_shared_directory_rule_index", _check_shared_directory_rule_index_source__shared_files_tree_uses_shared_directory_rule_index),
    ("shared_directory_rule_index_source::test_preferences_directory_keys_delegate_to_shared_directory_ops", _check_shared_directory_rule_index_source__preferences_directory_keys_delegate_to_shared_directory_ops),
    ("shared_file_list_source::test_startup_cache_write_failures_keep_path_and_error_details", _check_shared_file_list_source__startup_cache_write_failures_keep_path_and_error_details),
    ("shared_file_list_source::test_duplicate_path_cache_write_failures_keep_path_and_error_details", _check_shared_file_list_source__duplicate_path_cache_write_failures_keep_path_and_error_details),
    ("shared_file_list_source::test_interrupted_hashing_removes_startup_cache_sidecars", _check_shared_file_list_source__interrupted_hashing_removes_startup_cache_sidecars),
    ("shared_file_list_source::test_interrupted_hashing_marks_deferred_result_directories_interrupted", _check_shared_file_list_source__interrupted_hashing_marks_deferred_result_directories_interrupted),
    ("shared_file_list_source::test_shared_files_hashing_done_marker_is_not_emitted_during_close", _check_shared_file_list_source__shared_files_hashing_done_marker_is_not_emitted_during_close),
    ("shared_file_list_source::test_close_interrupted_shared_hash_snapshot_precedes_shutdown_state", _check_shared_file_list_source__close_interrupted_shared_hash_snapshot_precedes_shutdown_state),
    ("shared_file_list_source::test_duplicate_path_sidecar_reuse_precedes_known_file_duplicate_reporting", _check_shared_file_list_source__duplicate_path_sidecar_reuse_precedes_known_file_duplicate_reporting),
    ("shared_file_list_source::test_startup_cache_loader_rejects_short_fixed_payload_reads", _check_shared_file_list_source__startup_cache_loader_rejects_short_fixed_payload_reads),
    ("shared_file_list_source::test_startup_cache_completion_uses_worker_payload_registry", _check_shared_file_list_source__startup_cache_completion_uses_worker_payload_registry),
    ("shared_file_list_source::test_hash_workers_use_priority_gate_before_global_hash_mutex", _check_shared_file_list_source__hash_workers_use_priority_gate_before_global_hash_mutex),
    ("shared_file_list_source::test_shared_file_hot_path_indexes_are_maintained_together", _check_shared_file_list_source__shared_file_hot_path_indexes_are_maintained_together),
    ("shared_file_list_source::test_shared_file_path_index_is_updated_after_in_place_rename", _check_shared_file_list_source__shared_file_path_index_is_updated_after_in_place_rename),
    ("shared_file_list_source::test_shared_publish_summary_recounts_after_publish_state_batches", _check_shared_file_list_source__shared_publish_summary_recounts_after_publish_state_batches),
    ("shared_file_list_source::test_shared_hash_progress_logging_is_aggregate_only", _check_shared_file_list_source__shared_hash_progress_logging_is_aggregate_only),
    ("shared_file_list_source::test_startup_cache_save_waits_for_file_hash_gate_to_go_idle", _check_shared_file_list_source__startup_cache_save_waits_for_file_hash_gate_to_go_idle),
    ("shared_file_list_source::test_shared_publish_diagnostics_reports_server_and_kad_backlog", _check_shared_file_list_source__shared_publish_diagnostics_reports_server_and_kad_backlog),
    ("shared_file_list_source::test_shared_file_page_copy_is_server_side_bounded", _check_shared_file_list_source__shared_file_page_copy_is_server_side_bounded),
    ("shared_file_list_source::test_snapshot_bounds_every_live_collection_for_large_profiles", _check_shared_file_list_source__snapshot_bounds_every_live_collection_for_large_profiles),
    ("shared_files_ctrl_source::test_shared_files_addfile_uses_sorted_insert_not_full_resort", _check_shared_files_ctrl_source__shared_files_addfile_uses_sorted_insert_not_full_resort),
    ("shared_files_ctrl_source::test_shared_files_count_uses_shared_summary_snapshot", _check_shared_files_ctrl_source__shared_files_count_uses_shared_summary_snapshot),
    ("shell_delete_source::test_shell_delete_ex_preserves_recycle_bin_and_direct_delete_diagnostics", _check_shell_delete_source__shell_delete_ex_preserves_recycle_bin_and_direct_delete_diagnostics),
    ("shell_delete_source::test_shell_delete_callers_report_shell_delete_result_not_ambient_last_error", _check_shell_delete_source__shell_delete_callers_report_shell_delete_result_not_ambient_last_error),
    ("taskbar_notifier_source::test_taskbar_notifier_create_rejects_null_parent", _check_taskbar_notifier_source__taskbar_notifier_create_rejects_null_parent),
    ("tooltip_ctrl_source::test_file_icon_tooltips_initialize_line_height_from_non_colon_lines", _check_tooltip_ctrl_source__file_icon_tooltips_initialize_line_height_from_non_colon_lines),
    ("transfer_wnd_source::test_transfer_queue_footer_includes_broadband_upload_summary", _check_transfer_wnd_source__transfer_queue_footer_includes_broadband_upload_summary),
    ("transfer_wnd_source::test_transfer_download_metrics_use_top_toolbar_row_and_buffer_sources", _check_transfer_wnd_source__transfer_download_metrics_use_top_toolbar_row_and_buffer_sources),
    ("tree_options_ddx_source::test_tree_options_ddx_uses_checked_window_wrapper", _check_tree_options_ddx_source__tree_options_ddx_uses_checked_window_wrapper),
    ("tree_options_ddx_source::test_tree_options_ex_ddx_uses_checked_window_wrapper", _check_tree_options_ddx_source__tree_options_ex_ddx_uses_checked_window_wrapper),
    ("upload_bandwidth_throttler_source::test_control_packets_wake_upload_throttler_wait_domains", _check_upload_bandwidth_throttler_source__control_packets_wake_upload_throttler_wait_domains),
    ("upload_bandwidth_throttler_source::test_upload_throttler_pacing_wait_is_interruptible_by_new_data", _check_upload_bandwidth_throttler_source__upload_throttler_pacing_wait_is_interruptible_by_new_data),
    ("upload_disk_io_thread_source::test_pending_upload_io_removes_by_pointer_not_stored_position", _check_upload_disk_io_thread_source__pending_upload_io_removes_by_pointer_not_stored_position),
    ("upload_queue_source::test_upload_queue_position_helpers_reject_null_positions", _check_upload_queue_source__upload_queue_position_helpers_reject_null_positions),
    ("upload_queue_source::test_broadband_retained_slot_logs_are_throttled", _check_upload_queue_source__broadband_retained_slot_logs_are_throttled),
    ("upload_queue_source::test_underfilled_upload_queue_probes_no_request_cooldowns_below_base_slots", _check_upload_queue_source__underfilled_upload_queue_probes_no_request_cooldowns_below_base_slots),
    ("upload_queue_source::test_broadband_upload_buffer_depth_scales_with_per_slot_target", _check_upload_queue_source__broadband_upload_buffer_depth_scales_with_per_slot_target),
    ("upload_queue_source::test_auto_broadband_io_diagnostics_distinguish_download_and_upload_buffers", _check_upload_queue_source__auto_broadband_io_diagnostics_distinguish_download_and_upload_buffers),
    ("upload_queue_source::test_nonzero_slow_slots_keep_accumulated_slow_tracking_for_recycle_path", _check_upload_queue_source__nonzero_slow_slots_keep_accumulated_slow_tracking_for_recycle_path),
    ("upload_queue_source::test_queued_upload_wait_time_uses_current_tick_until_slot_starts", _check_upload_queue_source__queued_upload_wait_time_uses_current_tick_until_slot_starts),
    ("upload_slot_diagnostics_source::test_transfer_bar_percentage_preference_uses_transfer_wide_text", _check_upload_slot_diagnostics_source__transfer_bar_percentage_preference_uses_transfer_wide_text),
    ("upload_slot_diagnostics_source::test_upload_slot_diagnostics_reports_cooldown_pressure", _check_upload_slot_diagnostics_source__upload_slot_diagnostics_reports_cooldown_pressure),
    ("upload_slot_diagnostics_source::test_stalled_upload_retry_cooldown_is_bounded", _check_upload_slot_diagnostics_source__stalled_upload_retry_cooldown_is_bounded),
    ("upload_slot_diagnostics_source::test_queued_block_request_can_reopen_upload_slot_after_cooldown_clear", _check_upload_slot_diagnostics_source__queued_block_request_can_reopen_upload_slot_after_cooldown_clear),
    ("upload_slot_diagnostics_source::test_upload_list_membership_honors_queued_refresh_timing", _check_upload_slot_diagnostics_source__upload_list_membership_honors_queued_refresh_timing),
    ("upload_slot_diagnostics_source::test_queue_list_membership_honors_queued_refresh_timing", _check_upload_slot_diagnostics_source__queue_list_membership_honors_queued_refresh_timing),
    ("upload_slot_diagnostics_source::test_upload_part_counts_are_distinct_text_columns_and_bars_remain", _check_upload_slot_diagnostics_source__upload_part_counts_are_distinct_text_columns_and_bars_remain),
    ("upload_slot_diagnostics_source::test_upload_eta_and_percent_use_same_estimated_obtained_bytes", _check_upload_slot_diagnostics_source__upload_eta_and_percent_use_same_estimated_obtained_bytes),
    ("upload_slot_diagnostics_source::test_upload_part_status_report_flag_tracks_protocol_bitmap_presence", _check_upload_slot_diagnostics_source__upload_part_status_report_flag_tracks_protocol_bitmap_presence),
    ("version_check_source::test_version_check_worker_does_not_keep_raw_dialog_queue_pointer", _check_version_check_source__version_check_worker_does_not_keep_raw_dialog_queue_pointer),
    ("wait_diagnostics_source::test_shared_hash_worker_wait_failure_logs_error_message", _check_wait_diagnostics_source__shared_hash_worker_wait_failure_logs_error_message),
    ("wait_diagnostics_source::test_rest_ui_dispatch_wait_failure_returns_error_message", _check_wait_diagnostics_source__rest_ui_dispatch_wait_failure_returns_error_message),
    ("web_socket_source::test_web_bind_addr_resolution_rejects_null_output_pointer", _check_web_socket_source__web_bind_addr_resolution_rejects_null_output_pointer),
    ("web_socket_source::test_web_socket_shutdown_defers_teardown_after_timeout", _check_web_socket_source__web_socket_shutdown_defers_teardown_after_timeout),
    ("web_socket_source::test_web_socket_wait_failures_log_error_messages", _check_web_socket_source__web_socket_wait_failures_log_error_messages),
]


@pytest.mark.parametrize("case", _PARITY_CASES, ids=[c[0] for c in _PARITY_CASES])
def test_master_source_parity(case) -> None:
    _case_id, check = case
    check()
