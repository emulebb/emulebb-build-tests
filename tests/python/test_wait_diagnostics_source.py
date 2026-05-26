from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_shared_hash_worker_wait_failure_logs_error_message() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const DWORD dwWaitError = ::GetLastError();" in source
    assert 'DebugLogError(_T("Failed to wait for shared-file hash worker shutdown - %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source
    assert 'DebugLogError(_T("Failed to wait for shared-file hash worker shutdown - Error %lu"), ::GetLastError());' not in source


def test_rest_ui_dispatch_wait_failure_returns_error_message() -> None:
    source = (app_source_root() / "WebServerJson.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const DWORD dwWaitError = ::GetLastError();" in source
    assert 'rError.strMessage.Format(_T("failed to wait for REST UI dispatch completion - %s"), (LPCTSTR)GetErrorMessage(dwWaitError, 1));' in source
    assert 'rError.strMessage.Format(_T("failed to wait for REST UI dispatch completion - Error %lu"), ::GetLastError());' not in source
