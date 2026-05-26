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
