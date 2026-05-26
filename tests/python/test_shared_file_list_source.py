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
