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
