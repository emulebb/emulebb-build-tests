from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_pending_part_file_writes_are_cancelled_and_drained_before_shutdown_cleanup() -> None:
    source = (app_source_root() / "PartFileWriteThread.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "PartFileWriteThread.h").read_text(encoding="utf-8", errors="ignore")

    assert "void\tCancelPendingWrites();" in header
    assert "void\tDrainPendingWrites();" in header
    assert "DrainPendingWrites();" in source
    assert "::CancelIoEx(pFile->m_hWrite" in source
    assert "WriteBuffers error: %s" in source
    assert "const DWORD dwEffectiveError = dwCompletionError != ERROR_SUCCESS ? dwCompletionError : ERROR_WRITE_FAULT;" in source
    assert "WriteCompletionRoutine(0, m_listPendingIO.RemoveHead(), ERROR_OPERATION_ABORTED);" not in source
    assert "Improper termination of asynchronous I/O follows" not in source
    assert "const BOOL bCompletionReceived = ::GetQueuedCompletionStatus(m_hPort, &dwBytesWritten, &completionKey, (LPOVERLAPPED*)&pCurIO, INFINITE);" in source
