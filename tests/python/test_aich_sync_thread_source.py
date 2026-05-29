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
    assert "CSingleLock hashingLock(&theApp.hashing_mut); // only one file hash at a time" in source
    assert "while (!hashingLock.Lock(kAICHSyncHashingLockPollMs))" in source
    assert "if (theApp.IsClosing())\n\t\t\t\t\treturn 0;" in source
    assert "theApp.sharedfiles->m_mutWriteList" not in source
    assert "theApp.sharedfiles->GetHashingCount()" not in source


def test_known2_met_recovery_truncate_failure_logs_exception_details() -> None:
    source = (app_source_root() / "AICHSyncThread.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("LogError(LOG_STATUSBAR, GetResString(IDS_ERR_MET_BAD), KNOWN2_MET_FILENAME);") : source.index("ex->Delete();")]

    assert '#include "OtherFunctions.h"' in source
    assert 'DebugLogError(_T("Failed to truncate corrupt %s to byte %I64u%s"), KNOWN2_MET_FILENAME, ullLastVerifiedPos, (LPCTSTR)CExceptionStrDash(*ex2));' in block
    assert block.index("CExceptionStrDash(*ex2)") < block.index("ex2->Delete();")


def test_aich_known2_rewrite_uses_exact_reads_and_owned_buffers() -> None:
    source = (app_source_root() / "AICHSyncThread.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "#include <limits>" in source
    assert "#include <vector>" in source
    assert "UINT GetAICHHashsetPayloadByteCount(CFile &file, const uint32 nHashCount)" in source
    assert "(std::numeric_limits<UINT>::max)()" in source
    assert "void ReadAICHHashsetPayloadExact(CFile &file, std::vector<BYTE> &rBuffer, const UINT uBytes)" in source
    assert "const UINT uActualRead = file.Read(rBuffer.data(), uBytes);" in source
    assert "if (uActualRead != uBytes)\n\t\t\tAfxThrowFileException(CFileException::endOfFile, 0, file.GetFilePath());" in source
    assert source.count("std::vector<BYTE> buffer;") == 2
    assert source.count("ReadAICHHashsetPayloadExact(") == 3
    assert "BYTE *buffer = new BYTE[nHashCount * (size_t)CAICHHash::GetHashSize()];" not in source
    assert "delete[] buffer;" not in source
    assert "file.Read(buffer, nHashCount * CAICHHash::GetHashSize());" not in source
    assert "oldfile.Read(buffer, nHashCount * CAICHHash::GetHashSize());" not in source
