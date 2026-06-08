from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_repeated_no_request_policy_is_configured_hash_aware_and_bounded() -> None:
    seams = read_app_source("UploadQueueSeams.h")
    queue_header = read_app_source("UploadQueue.h")
    queue_source = read_app_source("UploadQueue.cpp")
    client_list_header = read_app_source("ClientList.h")
    client_list_source = read_app_source("ClientList.cpp")
    base_client_source = read_app_source("BaseClient.cpp")
    upload_client_source = read_app_source("UploadClient.cpp")
    opcodes = read_app_source("Opcodes.h")

    assert "#define CLIENTBANTIME\t\t\tHR2MS(4)\t// 4h" in opcodes
    assert "kNoRequestRepeatStrikeWindowSeconds = 4u * 60u * 60u" in seams
    assert "kNoRequestRepeatBanThreshold = 8u" in seams
    assert "kNoRequestRepeatHashRotationBanThreshold = 3u" in seams
    assert "kNoRequestRepeatCooldownMaxSeconds = 60u * 60u" in seams
    assert "GetNoRequestRepeatCooldownSeconds(" in seams
    assert "ullCooldownSeconds = uBaseCooldownSeconds;" in seams
    assert "ullCooldownSeconds *= 2u;" in seams
    assert "ShouldBanNoRequestRepeatOffender(" in seams

    assert "std::map<NoRequestRepeatHashKey, NoRequestRepeatOffenderState> m_noRequestRepeatOffendersByHash;" in queue_header
    assert "std::map<uint32, NoRequestRepeatOffenderState> m_noRequestRepeatOffendersByIP;" in queue_header
    assert "std::map<uint32, NoRequestRepeatIPHashState> m_noRequestRepeatHashesByIP;" in queue_header
    assert "TrackNoRequestRepeatOffender(CUpDownClient *client, ULONGLONG curTick, UINT uBaseCooldownSeconds)" in queue_header
    assert "m_noRequestRepeatOffendersByHash[key]" in queue_source
    assert "m_noRequestRepeatOffendersByIP[dwCooldownIP]" in queue_source
    assert "m_noRequestRepeatHashesByIP[dwCooldownIP]" in queue_source
    assert "penalty.bShouldIPBan = penalty.uDistinctIPHashes >= kNoRequestRepeatHashRotationBanThreshold;" in queue_source
    assert "penalty.bShouldBan = ShouldBanNoRequestRepeatOffender(penalty.uStrikes);" in queue_source
    assert "theApp.clientlist->AddBannedClient(dwCooldownIP);" in queue_source
    assert "client->Ban(repeatPenalty.bShouldIPBan" in queue_source

    assert "void\tAddBannedClient(const CUpDownClient *pClient);" in client_list_header
    assert "bool\tIsBannedClient(const CUpDownClient *pClient) const;" in client_list_header
    assert "void\tRemoveBannedClient(const CUpDownClient *pClient);" in client_list_header
    assert "CMap<CSKey, const CSKey&, ULONGLONG, ULONGLONG> m_bannedHashList;" in client_list_header
    assert "m_bannedHashList[CSKey(pClient->GetUserHash())]" in client_list_source
    assert "m_bannedHashList.Lookup(CSKey(pClient->GetUserHash()), dwBantime)" in client_list_source
    assert "m_bannedHashList.RemoveKey(CSKey(pClient->GetUserHash()))" in client_list_source
    assert "m_bannedHashList.RemoveAll();" in client_list_source
    assert "m_bannedHashList.GetStartPosition()" in client_list_source

    assert "theApp.clientlist->IsBannedClient(this) || theApp.clientlist->IsBannedClient(uClientIP)" in base_client_source
    assert "return theApp.clientlist->IsBannedClient(this);" in base_client_source
    assert "theApp.clientlist->AddBannedClient(this);" in upload_client_source
    assert "theApp.clientlist->RemoveBannedClient(this);" in upload_client_source
