from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_startup_initialization_logs_mfc_exception_details() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    server_block = source[source.index("theApp.serverlist->Init();") : source.index("StartupTimer stage 2: serverlist->Init")]
    download_block = source[source.index("theApp.downloadqueue->Init();") : source.index("StartupTimer stage 4: downloadqueue->Init")]

    assert "catch (CException *ex)" in server_block
    assert 'LogError(LOG_STATUSBAR, _T("Failed to initialize server list%s"), (LPCTSTR)CExceptionStrDash(*ex));' in server_block
    assert "ex->Delete();" in server_block
    assert "catch (CException *ex)" in download_block
    assert 'LogError(LOG_STATUSBAR, _T("Failed to initialize download queue%s"), (LPCTSTR)CExceptionStrDash(*ex));' in download_block
    assert "ex->Delete();" in download_block
    assert "bError = true;" in download_block
