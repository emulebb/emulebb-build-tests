from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_low_id_upload_callback_does_not_assert_on_upload_connecting_state() -> None:
    source = (app_source_root() / "BaseClient.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("// 6) Server Callback + 7) Kad Callback") : source.index("if (theApp.serverconnect->IsLocalServer")]

    assert "Upload admission deliberately marks a not-yet-connected slot" in block
    assert "ConnectionEstablished sends OP_ACCEPTUPLOADREQ" in block
    assert "ASSERT(0)" not in block
    assert "LowID upload callback while US_CONNECTING" in block


def test_client_list_cleanup_uses_full_delete_readiness_predicate() -> None:
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


def test_corruption_blackbox_recomputes_merge_target_after_record_mutation() -> None:
    source = (app_source_root() / "CorruptionBlackBox.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CCorruptionBlackBox::ReceivedData") : source.index("void CCorruptionBlackBox::VerifiedData")]

    assert "Any merge index" in block
    assert "after normalization is complete" in block
    assert "if (posMerge < 0 || !m_aaRecords[nPart][posMerge].Merge" in block
    assert "VERIFY(m_aaRecords[nPart][posMerge].Merge" not in block
    assert "ndbgRewritten += nRelEndPos - cbbRec.m_nStartPos + 1;" in block
    assert "ndbgRewritten += cbbRec.m_nEndPos - nRelStartPos + 1;" in block


def test_disconnect_deletes_only_after_request_file_detach() -> None:
    source = (app_source_root() / "BaseClient.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CUpDownClient::Disconnected") : source.index("// Returned bool is not about whether the connect attempt succeeded.")]

    assert "live disconnect dumps showed a client in DS_NONE/US_NONE" in block
    assert "return \"delete me\" with that pointer still set" in block
    assert "RemoveSource is the central mirror cleanup" in block
    assert "if (bDelete && m_reqfile != NULL)" in block
    assert "theApp.downloadqueue->RemoveSource(this);" in block


def test_duplicate_temp_source_detaches_request_file_before_attach_delete() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CDownloadQueue::CheckAndAddSource") : source.index("bool CDownloadQueue::RemoveSource")]

    assert "server/source-exchange probes are constructed with sender as their" in block
    assert "AttachToAlreadyKnown" in block
    assert "deletes the temporary probe immediately" in block
    assert "source->SetRequestFile(NULL);" in block
    assert "const bool bAttachedKnownClient = theApp.clientlist->AttachToAlreadyKnown(&source, NULL);" in block
