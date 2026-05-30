from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_search_results_refresh_layout_after_hidden_tab_changes() -> None:
    source = (app_source_root() / "SearchResultsWnd.cpp").read_text(encoding="utf-8", errors="ignore")
    refresh_block = source[source.index("void CSearchResultsWnd::RefreshResultLayout") : source.index("void CSearchResultsWnd::OnBnClickedClearAll")]
    create_tab_block = source[source.index("bool CSearchResultsWnd::CreateNewTab") : source.index("bool CSearchResultsWnd::SelectAdjacentSearchResultTab")]
    show_window_block = (app_source_root() / "SearchDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    show_window_block = show_window_block[show_window_block.index("void CSearchDlg::OnShowWindow") : show_window_block.index("void CSearchDlg::OnSetFocus")]

    assert "ArrangeLayout();" in refresh_block
    assert "PositionSearchStatusOverlay();" in refresh_block
    assert "RefreshResultLayout();" in create_tab_block
    assert "m_pwndResults->RefreshResultLayout();" in show_window_block


def test_clean_shutdown_removes_tray_icon_before_long_teardown() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    close_start = source.index("void CemuleDlg::OnClose()")
    teardown_start = source.index("VersionCheckLaunchSeams::ClearQueuedOnOwnerTeardown", close_start)
    close_block = source[close_start:teardown_start]

    assert "theApp.m_app_state = APP_STATE_SHUTTINGDOWN;" in close_block
    assert "TrayHide();" in close_block
    assert close_block.index("theApp.m_app_state = APP_STATE_SHUTTINGDOWN;") < close_block.index("TrayHide();")
