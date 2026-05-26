from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_pending_upload_io_removes_by_pointer_not_stored_position() -> None:
    source = (app_source_root() / "UploadDiskIOThread.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "UploadDiskIOThread.h").read_text(encoding="utf-8", errors="ignore")

    assert "POSITION\t\t\t\tpos;" not in header
    assert "m_listPendingIO.AddTail(pOverlappedRead);" in source
    assert "pOverlappedRead->pos = m_listPendingIO.AddTail(pOverlappedRead);" not in source
    assert "m_listPendingIO.RemoveAt(pOvRead->pos);" not in source
    assert "DrainPendingReads();" in source
    assert "::CancelIoEx(pKnownFile->m_hRead" in source
    assert "throw _T(\"ReadFile Error: \") + GetErrorMessage(dwError, 1);" in source
    assert "throw _T(\"ReadFile Error: \") + GetErrorMessage(::GetLastError())" not in source
    assert "const DWORD dwEffectiveError = dwCompletionError != ERROR_SUCCESS ? dwCompletionError : ERROR_READ_FAULT;" in source
    assert "ReadCompletionRoutine(0, m_listPendingIO.RemoveHead(), ERROR_OPERATION_ABORTED);" not in source
    assert "Improper termination of asynchronous I/O follows" not in source
    assert "POSITION posPending = m_listPendingIO.Find(const_cast<OverlappedRead_Struct*>(pOvRead));" in source
    assert "if (posPending != NULL)\n\t\tm_listPendingIO.RemoveAt(posPending);" in source
    assert "if (pKnownFile != NULL)\n\t\t--pKnownFile->nInUse;" in source
    assert "if (pStruct != NULL)\n\t\tpStruct->m_nPendingIOBlocks.fetch_sub(1);" in source
