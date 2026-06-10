from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_pending_upload_io_removes_by_pointer_not_stored_position() -> None:
    source = (app_source_root() / "UploadDiskIOThread.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "UploadDiskIOThread.h").read_text(encoding="utf-8", errors="ignore")

    assert "POSITION\t\t\t\tpos;" not in header
    # The pending I/O list is now mutated only through the AddPendingIo /
    # RemovePendingIoIfPresent helpers, which keep the list membership and the
    # atomic counter in lockstep. The membership is still keyed by pointer, not
    # by a position stored on the overlapped struct.
    assert "AddPendingIo(pOverlappedRead);" in source
    assert "m_listPendingIO.AddTail(pOvRead);" in source
    assert "pOverlappedRead->pos = m_listPendingIO.AddTail(pOverlappedRead);" not in source
    assert "m_listPendingIO.RemoveAt(pOvRead->pos);" not in source
    assert "DrainPendingReads();" in source
    assert "::CancelIoEx(pKnownFile->m_hRead" in source
    assert "throw _T(\"ReadFile Error: \") + GetErrorMessage(dwError, 1);" in source
    assert "throw _T(\"ReadFile Error: \") + GetErrorMessage(::GetLastError())" not in source
    assert "const DWORD dwEffectiveError = dwCompletionError != ERROR_SUCCESS ? dwCompletionError : ERROR_READ_FAULT;" in source
    assert "ReadCompletionRoutine(0, m_listPendingIO.RemoveHead(), ERROR_OPERATION_ABORTED);" not in source
    assert "Improper termination of asynchronous I/O follows" not in source
    # Removal finds the node by pointer inside RemovePendingIoIfPresent, and the
    # completion path drops the entry through that helper (const_cast at the call
    # site), never through a stored POSITION.
    assert "const POSITION posPending = m_listPendingIO.Find(pOvRead);" in source
    assert "if (posPending == NULL)\n\t\treturn false;\n\tm_listPendingIO.RemoveAt(posPending);" in source
    assert "RemovePendingIoIfPresent(const_cast<OverlappedRead_Struct*>(pOvRead))" in source
    assert "if (pKnownFile != NULL) {\n\t\t// Keep nInUse raised until every completion-path access to pKnownFile is done." in source
    assert "pKnownFile->ReleaseUploadReadReference();" in source
    assert "if (pStruct != NULL)\n\t\tpStruct->m_nPendingIOBlocks.fetch_sub(1);" in source
