from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_part_file_buffer_errors_do_not_report_success_as_unknown_write_error() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "item->dwError != ERROR_SUCCESS ? item->dwError : ERROR_WRITE_FAULT" in source
    assert "CFileException::ThrowOsError((LONG)item->dwError, m_hpartfile.GetFileName());" not in source


def test_part_file_preview_copy_logs_file_exception_details() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CPartFile::CopyPartFile") : source.index("void CPartFile::GetLeftToTransferAndAdditionalNeededSpace")]

    assert 'DebugLogError(_T("Failed to copy part-file data from \\"%s\\" to \\"%s\\"%s")' in source
    assert "(LPCTSTR)CExceptionStrDash(*ex)" in source
    assert 'DebugLogError(_T("Failed to copy part-file data from \\"%s\\" to \\"%s\\" - unexpected exception")' in source
    assert block.count("m_bPreviewing = false;") >= 4


def test_part_file_delete_defers_while_preview_worker_holds_reference() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CPartFile::DeletePartFile()") : source.index("void CPartFile::SetDownPriority")]

    assert "ASSERT(!m_bPreviewing);" in block
    assert block.index("StopFile(true);") < block.index("if (m_bPreviewing)")
    assert 'DebugLogWarning(_T("Deferring part-file deletion for \\"%s\\" until preview generation releases the file object.")' in block
    assert "m_bDelayDelete = true;" in block
    assert "return;\n\t}\n\n\tif (GetFileOp() != PFOP_NONE)" in block


def test_part_file_completion_worker_posts_result_object_for_ui_thread_state_transition() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "PartFile.h").read_text(encoding="utf-8", errors="ignore")
    dialog = (app_source_root() / "emuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    worker = source[source.index("BOOL CPartFile::PerformFileComplete()") : source.index("// 'End' of file completion")]
    ui_end = source[source.index("void CPartFile::PerformFileCompleteEnd(void *pCompletionResult)") : source.index("void  CPartFile::RemoveAllSources")]

    assert "struct SPartFileCompletionThreadResult" in source
    assert "PostWorkerCompletion(theApp.IsClosing(), hNotifyWnd, TM_FILECOMPLETED, dwResult, reinterpret_cast<LPARAM>(pResult))" in source
    assert "std::unique_ptr<SPartFileCompletionThreadResult> pResult(new SPartFileCompletionThreadResult);" in worker
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


def test_zone_identifier_failures_are_logged_with_hresult() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void SetZoneIdentifier") : source.index("DWORD CALLBACK CopyProgressRoutine")]

    assert "VERIFY(SUCCEEDED(pPersistFile->Save" not in block
    assert 'DebugLogWarning(_T("Failed to create Zone.Identifier writer for \\"%s\\" (HRESULT 0x%08lX)")' in block
    assert 'DebugLogWarning(_T("Failed to save Zone.Identifier for \\"%s\\" (HRESULT 0x%08lX)")' in block


def test_part_file_load_does_not_use_file_status_after_get_status_exception() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("if (!isnewstyle) { // not for importing") : source.index("if (m_tUtcLastModified != fdate)")]

    assert "CFileStatus filestatus = {};" in block
    assert "bool bHavePartFileStatus = false;" in block
    assert "bHavePartFileStatus = true;" in block
    assert "DebugLogWarning(_T(\"Failed to get file date of \\\"%s\\\" while loading part file \\\"%s\\\"%s\")" in block
    assert "time_t fdate = bHavePartFileStatus ? (time_t)filestatus.m_mtime.GetTime() : (time_t)-1;" in block
    assert "filestatus.m_szFullName" not in block


def test_downloading_source_add_rejects_invalid_owner_and_tolerates_missing_ui() -> None:
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


def test_downloading_source_add_recovers_corrupt_list_before_mfc_mutation() -> None:
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


def test_downloading_source_list_recovery_covers_remove_and_scan_entrypoints() -> None:
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


def test_downloading_source_list_recovery_rebuilds_from_live_sources() -> None:
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


def test_completed_part_files_use_completion_hash_priority() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    completion_block = source[source.index("void CPartFile::CompleteFile(bool bIsHashingDone)") : source.index("BOOL CPartFile::PerformFileComplete()")]
    load_rehash_block = source[source.index("if (m_tUtcLastModified != fdate)") : source.index("UpdateCompletedInfos();")]

    assert "CreateSuspendedPartFileHashThread(mytemppath, RemoveFileExtension(m_partmetfilename), this, FHJP_PART_FILE_COMPLETION);" in completion_block
    assert "CreateSuspendedPartFileHashThread(GetPath(), m_hpartfile.GetFileName(), this);" in load_rehash_block
    assert "FHJP_PART_FILE_COMPLETION" not in load_rehash_block
