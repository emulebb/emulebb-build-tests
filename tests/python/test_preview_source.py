from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_peer_preview_logs_exception_details_before_returning_empty_result() -> None:
    source = (app_source_root() / "Preview.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("BOOL CPeerPreviewThread::Run()") : source.index("void CPeerPreviewThread::SetValues")]

    assert 'DebugLogWarning(_T("Peer preview failed for \\"%s\\"%s"), (LPCTSTR)m_strInputPath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert 'DebugLogWarning(_T("Peer preview failed for \\"%s\\" after an unexpected exception"), (LPCTSTR)m_strInputPath);' in block
    assert block.index("DebugLogWarning") < block.index("ex->Delete();")
