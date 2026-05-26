from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_part_file_buffer_errors_do_not_report_success_as_unknown_write_error() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "item->dwError != ERROR_SUCCESS ? item->dwError : ERROR_WRITE_FAULT" in source
    assert "CFileException::ThrowOsError((LONG)item->dwError, m_hpartfile.GetFileName());" not in source


def test_part_file_preview_copy_logs_file_exception_details() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CPartFile::CopyPartFile") : source.index("void CPartFile::GetLeftToTransferAndAdditionalNeededSpace")]

    assert 'DebugLogError(_T("Failed to copy part-file data from \\"%s\\" to \\"%s\\"%s")' in source
    assert "(LPCTSTR)CExceptionStrDash(*ex)" in source
    assert 'DebugLogError(_T("Failed to copy part-file data from \\"%s\\" to \\"%s\\" - unexpected exception")' in source
    assert block.count("m_bPreviewing = false;") >= 4
