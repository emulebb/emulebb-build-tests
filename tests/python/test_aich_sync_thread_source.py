from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_aich_sync_thread_is_owned_and_joined_before_shared_file_teardown() -> None:
    source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "EmuleDlg.h").read_text(encoding="utf-8", errors="ignore")

    assert "CWinThread\t\t*m_pAICHSyncThread;" in header
    assert "void StartAICHSyncThread();" in header
    assert "void WaitForAICHSyncThreadShutdown();" in header
    assert "void CemuleDlg::StartAICHSyncThread()" in source
    assert "AfxBeginThread(RUNTIME_CLASS(CAICHSyncThread), THREAD_PRIORITY_IDLE, 0, CREATE_SUSPENDED)" in source
    assert "HelperThreadLaunchSeams::OwnAndResumeSuspendedThread(m_pAICHSyncThread, pThread, dwResumeError)" in source
    assert "void CemuleDlg::WaitForAICHSyncThreadShutdown()" in source
    assert "::WaitForSingleObject(hThread, kAICHSyncThreadShutdownWaitMs)" in source
    assert "::WaitForSingleObject(hThread, INFINITE)" in source
    assert "AfxBeginThread(RUNTIME_CLASS(CAICHSyncThread), THREAD_PRIORITY_IDLE, 0);" not in source
    assert source.index("WaitForAICHSyncThreadShutdown();") < source.index("const bool bSharedHashingWasActiveOnClose")


def test_aich_sync_worker_guards_shared_and_known_file_globals() -> None:
    source = (app_source_root() / "AICHSyncThread.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ResolveSharedAICHSyncFileNoLock(CSharedFileList *pSharedFiles" in source
    assert "if (pSharedFiles == NULL || theApp.IsClosing())" in source
    assert "CSingleLock sharelock(&pSharedFiles->m_mutWriteList, TRUE);" in source
    assert "theApp.knownfiles != NULL && theApp.knownfiles->ShouldPurgeAICHHashset(aichHash)" in source
    assert "if (theApp.IsClosing() || pSharedFiles == NULL)\n\t\t\t\t\treturn 0;" in source
    assert "CSingleLock hashingLock(&theApp.hashing_mut, TRUE); // only one file hash at a time\n\t\t\tif (theApp.IsClosing())\n\t\t\t\treturn 0;" in source
    assert "theApp.sharedfiles->m_mutWriteList" not in source
    assert "theApp.sharedfiles->GetHashingCount()" not in source
