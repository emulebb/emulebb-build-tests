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


def test_part_file_delete_defers_while_preview_worker_holds_reference() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CPartFile::DeletePartFile()") : source.index("void CPartFile::SetDownPriority")]

    assert "ASSERT(!m_bPreviewing);" in block
    assert block.index("StopFile(true);") < block.index("if (m_bPreviewing)")
    assert 'DebugLogWarning(_T("Deferring part-file deletion for \\"%s\\" until preview generation releases the file object.")' in block
    assert "m_bDelayDelete = true;" in block
    assert "return;\n\t}\n\n\tif (GetFileOp() != PFOP_NONE)" in block
