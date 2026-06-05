from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_startup_cache_write_failures_keep_path_and_error_details() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("bool CSharedFileList::WriteStartupCacheFile") :
        source.index("bool CSharedFileList::WriteDuplicatePathCacheFile")
    ]

    assert 'DebugLogWarning(_T("Failed to open startup cache temp file \\"%s\\" for \\"%s\\" - %s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to replace startup cache \\"%s\\" with temp file \\"%s\\" - %s"), (LPCTSTR)strFullPath, (LPCTSTR)strTempPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to write startup cache temp file \\"%s\\" for \\"%s\\"%s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert block.index("CExceptionStrDash(*ex)") < block.index("ex->Delete();")


def test_duplicate_path_cache_write_failures_keep_path_and_error_details() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("bool CSharedFileList::WriteDuplicatePathCacheFile") :
        source.index("void CSharedFileList::RunStartupCacheSaveWorker")
    ]

    assert 'DebugLogWarning(_T("Failed to open duplicate path cache temp file \\"%s\\" for \\"%s\\" - %s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to replace duplicate path cache \\"%s\\" with temp file \\"%s\\" - %s"), (LPCTSTR)strFullPath, (LPCTSTR)strTempPath, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));' in block
    assert 'DebugLogWarning(_T("Failed to write duplicate path cache temp file \\"%s\\" for \\"%s\\"%s"), (LPCTSTR)strTempPath, (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert block.index("CExceptionStrDash(*ex)") < block.index("ex->Delete();")


def test_interrupted_hashing_preserves_duplicate_path_sidecar() -> None:
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
    assert "(void)PersistDuplicatePathCacheAfterInterruptedHashing();" in invalidate_block
    assert "LongPathSeams::DeleteFileIfExists(GetStartupCachePath())" in invalidate_block
    assert "m_duplicateSharedPathRecords.clear();" not in invalidate_block
    assert "GetDuplicatePathCachePath()" not in invalidate_block
    assert "CaptureDuplicatePathCacheSnapshot(snapshot)" in persist_block
    assert "BuildDuplicatePathCacheRecordsFromSnapshot(snapshot, records);" in persist_block
    assert "WriteDuplicatePathCacheFile(GetDuplicatePathCachePath(), records)" in persist_block
    assert "persistedRecords.emplace(MakeDuplicatePathCacheKey(record.strFilePath), record);" in persist_block


def test_interrupted_hashing_persists_partial_startup_cache_for_stable_directories() -> None:
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
    persist_block = source[
        source.index("bool CSharedFileList::PersistStartupCacheAfterInterruptedHashing") :
        source.index("void CSharedFileList::RememberDuplicateSharedPath")
    ]

    assert "bool\tPersistStartupCacheAfterInterruptedHashing(const std::unordered_set<std::wstring> &rInterruptedDirectoryKeys);" in header
    assert "void\tInvalidateStartupCachesAfterInterruptedHashing(const std::unordered_set<std::wstring> &rInterruptedDirectoryKeys = std::unordered_set<std::wstring>());" in header
    assert "std::unordered_set<std::wstring> interruptedDirectoryKeys;" in shutdown_block
    assert shutdown_block.index("interruptedDirectoryKeys.insert(MakeStartupCacheSnapshotKey(job.strDirectory));") < shutdown_block.index("m_sharedHashQueue.clear();")
    assert "!m_sharedHashDeferredResults.empty()" in shutdown_block
    assert "for (const CSharedFileHashResult *pResult : m_sharedHashDeferredResults)" in shutdown_block
    assert "interruptedDirectoryKeys.insert(MakeStartupCacheSnapshotKey(pResult->strDirectory));" in shutdown_block
    assert "InvalidateStartupCachesAfterInterruptedHashing(interruptedDirectoryKeys);" in shutdown_block
    assert "const bool bPartialStartupCachePersisted = PersistStartupCacheAfterInterruptedHashing(rInterruptedDirectoryKeys);" in invalidate_block
    assert "bPartialStartupCachePersisted ? false : LongPathSeams::DeleteFileIfExists(GetStartupCachePath())" in invalidate_block
    assert '"interrupted_hashing_partial"' in invalidate_block
    assert "if (rInterruptedDirectoryKeys.empty())\n\t\treturn false;" in persist_block
    assert "CaptureStartupCacheSaveSnapshot(snapshot)" in persist_block
    assert "directory.bHasPendingHash = true;" in persist_block
    assert "RunStartupCacheSaveWorker(snapshot, std::shared_ptr<StartupCacheSaveOperation>(), result);" in persist_block
    assert "if (!result.bWriteSucceeded)\n\t\treturn false;" in persist_block


def test_duplicate_path_sidecar_reuse_precedes_known_file_duplicate_reporting() -> None:
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


def test_startup_cache_loader_rejects_short_fixed_payload_reads() -> None:
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


def test_startup_cache_completion_uses_worker_payload_registry() -> None:
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


def test_hash_workers_use_priority_gate_before_global_hash_mutex() -> None:
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


def test_shared_hash_progress_logging_is_aggregate_only() -> None:
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


def test_startup_cache_save_waits_for_file_hash_gate_to_go_idle() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("bool CSharedFileList::ShouldStartStartupCacheSaveNow") :
        source.index("void CSharedFileList::FindSharedFiles")
    ]

    assert "startup-cache snapshot walks all shared directories and known" in block
    assert "const bool bDeferredHashingActive = m_bStartupDeferredHashingActive || IsFileHashJobGateBusy();" in block
    assert "bDeferredHashingActive," in block


def test_shared_publish_instrumentation_reports_server_and_kad_backlog() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "SharedFileList.h").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CSharedFileList::GetPublishInstrumentationSnapshot") :
        source.index("void CSharedFileList::Process")
    ]

    assert "#ifdef EMULEBB_ENABLE_UPLOAD_SLOT_INSTRUMENTATION" in header
    assert "struct SharedPublishInstrumentationSnapshot" in header
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

    assert "void\tGetPublishInstrumentationSnapshot(SharedPublishInstrumentationSnapshot &rSnapshot) const;" in header
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
