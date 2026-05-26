from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_shell_delete_ex_preserves_recycle_bin_and_direct_delete_diagnostics() -> None:
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


def test_shell_delete_callers_report_shell_delete_result_not_ambient_last_error() -> None:
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
