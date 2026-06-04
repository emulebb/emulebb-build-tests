from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_log_helpers_reject_null_format_strings() -> None:
    source = (app_source_root() / "Log.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.count("ASSERT(pszLine != NULL);\n\tif (pszLine == NULL)\n\t\treturn;") >= 4
    assert "void AddLogTextV(UINT uFlags, EDebugLogPriority dlpPriority, LPCTSTR pszLine, va_list argptr)" in source


def test_main_dialog_keeps_disk_log_lines_complete_when_ui_rows_are_truncated() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    helper_block = source[source.index("constexpr int kMaxUiLogLineChars") : source.index("void CemuleDlg::AddLogText")]
    add_log_block = source[source.index("void CemuleDlg::AddLogText") : source.index("void CemuleDlg::BeginLogBatchUpdate")]

    assert "CString BuildLogLine(const CTime &timestamp, LPCTSTR pszText)" in helper_block
    assert "CString BuildUiLogLine(const CTime &timestamp, LPCTSTR pszText)" in helper_block
    assert "strLogLine.Truncate(kMaxUiLogLineChars - 2);" in helper_block
    assert 'strLogLine += _T("\\r\\n");' in helper_block

    assert "const CString strUiLogLine(BuildUiLogLine(timestamp, pszText));" in add_log_block
    assert "const CString strDiskLogLine(BuildLogLine(timestamp, pszText));" in add_log_block
    assert "serverwnd->logbox->AddTyped(strUiLogLine, iUiLen" in add_log_block
    assert "serverwnd->debuglog->AddTyped(strUiLogLine, iUiLen" in add_log_block
    assert "theLog.Log(strDiskLogLine, iDiskLen);" in add_log_block
    assert "theVerboseLog.Log(strDiskLogLine, iDiskLen);" in add_log_block
    assert "theLog.Log(strUiLogLine" not in add_log_block
    assert "theVerboseLog.Log(strUiLogLine" not in add_log_block
