from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def read_tooling_file(name: str) -> str:
    return (Path(__file__).resolve().parents[4] / "repos" / "emulebb-tooling" / name).read_text(encoding="utf-8", errors="ignore")


def test_repeated_no_request_policy_is_configured_hash_aware_and_bounded() -> None:
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
    assert "kNoRequestRepeatHashRotationBanThreshold = 3u" in seams
    assert "kNoRequestRepeatHashRotationStrikeThreshold = 5u" in seams
    assert "kNoRequestRepeatCooldownMaxSeconds = 60u * 60u" in seams
    assert "kNoRequestRepeatCleanupIntervalSeconds = 60u" in seams
    assert "GetNoRequestRepeatBaseCooldownSeconds(" in seams
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
    assert "TrackNoRequestRepeatOffender(CUpDownClient *client, ULONGLONG curTick, UINT uBaseCooldownSeconds)" in queue_header
    assert "m_noRequestRepeatOffendersByHash[key]" in queue_source
    assert "m_noRequestRepeatOffendersByIP[dwCooldownIP]" in queue_source
    assert "m_noRequestRepeatHashesByIP[dwCooldownIP]" in queue_source
    assert "++ipHashState.uTotalStrikes;" in queue_source
    assert "penalty.uIPRotationStrikes = ipHashState.uTotalStrikes;" in queue_source
    assert "penalty.bShouldIPBan = penalty.uDistinctIPHashes >= kNoRequestRepeatHashRotationBanThreshold\n\t\t\t\t&& penalty.uIPRotationStrikes >= kNoRequestRepeatHashRotationStrikeThreshold;" in queue_source
    assert "penalty.bShouldBan = ShouldBanNoRequestRepeatOffender(penalty.uStrikes);" in queue_source
    assert "client->Ban(repeatPenalty.bShouldIPBan" in queue_source
    assert "repeatPenalty.bShouldIPBan ? clientBanScopeBoth : clientBanScopeHash" in queue_source
    assert "GetNoRequestRepeatBaseCooldownSeconds(\n\t\t\t\tuConfiguredCooldownSeconds" in queue_source
    assert "GetNoRequestRepeatCooldownSeconds(uBaseCooldownSeconds, penalty.uStrikes)" in queue_source
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


def test_manual_peer_menus_can_ban_hash_or_ip_scope() -> None:
    resources = read_app_source("emule.rc")
    resource_header = read_app_source("Resource.h")
    menu_cmds = read_app_source("MenuCmds.h")
    required_ids = read_tooling_file("helpers/rc-release-localization-ids.txt")

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
