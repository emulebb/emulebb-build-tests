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


def test_video_thumbnail_logs_exception_details_before_reporting_worker_failure() -> None:
    source = (app_source_root() / "Preview.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("BOOL CVideoThumbnailThread::Run()") : source.index("void CVideoThumbnailThread::SetValues")]

    assert 'DebugLogWarning(_T("Video thumbnail failed for \\"%s\\" cache \\"%s\\"%s"), (LPCTSTR)m_strInputPath, (LPCTSTR)m_strCachePath, (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert 'DebugLogWarning(_T("Video thumbnail failed for \\"%s\\" cache \\"%s\\" after an unexpected exception"), (LPCTSTR)m_strInputPath, (LPCTSTR)m_strCachePath);' in block
    assert block.index("DebugLogWarning") < block.index("ex->Delete();")
