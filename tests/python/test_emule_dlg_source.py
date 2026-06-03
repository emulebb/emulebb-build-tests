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


def test_shutdown_keeps_part_file_writer_alive_through_download_queue_teardown() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    shutdown_block = source[
        source.index("updateShutdownPhase(30, _T(\"Closing eMuleBB\")") :
        source.index("updateShutdownPhase(100, _T(\"Closing eMuleBB\")")
    ]

    assert "keeping part-file writer alive for download teardown" in shutdown_block
    assert "theApp.m_pUploadDiskIOThread->EndThread();" in shutdown_block
    assert shutdown_block.index("theApp.m_pUploadDiskIOThread->EndThread();") < shutdown_block.index("delete theApp.downloadqueue;")
    assert shutdown_block.index("delete theApp.downloadqueue;") < shutdown_block.index("theApp.m_pPartFileWriteThread->EndThread();")
    assert shutdown_block.index("theApp.m_pPartFileWriteThread->EndThread();") < shutdown_block.index("delete theApp.m_pPartFileWriteThread;")


def test_stored_search_startup_stage_closes_progress_dialog_without_extra_queued_hop() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    startup_block = source[source.index("void CemuleDlg::OnStartupTimer() noexcept") : source.index("void CemuleDlg::StopTimer()")]
    stored_search_block = startup_block[startup_block.index("case 5:") : startup_block.index("default:")]
    final_block = startup_block[startup_block.index("default:") : startup_block.index("VERIFY(PostMessage(UM_STARTUP_NEXT_STAGE) != 0);")]

    assert "theApp.searchlist->LoadSearches();" in stored_search_block
    assert stored_search_block.index("DestroyStartupProgress();") < stored_search_block.index("theApp.searchlist->LoadSearches();")
    assert "[[fallthrough]];" in stored_search_block
    assert "break;" not in stored_search_block
    assert "StopTimer();" in final_block
    assert "DestroyStartupProgress();" in final_block


def test_upnp_startup_and_refresh_log_suppressed_exception_details() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    start_block = source[source.index("void CemuleDlg::StartUPnP") : source.index("void CemuleDlg::RefreshUPnP")]
    refresh_block = source[source.index("void CemuleDlg::RefreshUPnP") : source.index("void CemuleDlg::OnTimer")]

    assert 'CString strImplementationName(_T("<unknown>"));' in start_block
    assert "strImplementationName = impl->GetImplementationName();" in start_block
    assert "DebugLogWarning(_T(\"NAT mapping startup failed in backend '%s'\"), (LPCTSTR)strImplementationName);" in start_block
    assert "DebugLogWarning(_T(\"NAT mapping startup failed in backend '%s'%s\"), (LPCTSTR)strImplementationName, (LPCTSTR)CExceptionStrDash(*ex));" in start_block
    assert 'CString strImplementationName(_T("<unknown>"));' in refresh_block
    assert "strImplementationName = impl->GetImplementationName();" in refresh_block
    assert "DebugLogWarning(_T(\"NAT mapping refresh failed in backend '%s'\"), (LPCTSTR)strImplementationName);" in refresh_block
    assert "DebugLogWarning(_T(\"NAT mapping refresh failed in backend '%s'%s\"), (LPCTSTR)strImplementationName, (LPCTSTR)CExceptionStrDash(*ex));" in refresh_block
