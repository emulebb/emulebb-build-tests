from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_part_file_set_file_size_keeps_base_size_update_without_aich_set() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(m_pAICHRecoveryHashSet != NULL);\n\tif (m_pAICHRecoveryHashSet != NULL)\n\t\tm_pAICHRecoveryHashSet->SetFileSize(nFileSize);\n\tCKnownFile::SetFileSize(nFileSize);" in source


def test_part_file_defines_md4_policy_before_kad_headers() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.index('#include "EmuleMD4.h"') < source.index('#include "Kademlia/Kademlia/Kademlia.h"')


def test_part_file_hash_worker_drops_results_after_shutdown() -> None:
    source = (app_source_root() / "SharedFileList.cpp").read_text(encoding="utf-8", errors="ignore")
    dialog_source = (app_source_root() / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "CSingleLock hashingLock(&theApp.hashing_mut, TRUE); // hash only one file at a time\n\tif (theApp.IsClosing())" in source
    assert "PostPartFileHashWorkerResult(TM_FINISHEDHASHING" in source
    assert "PostPartFileHashWorkerResult(TM_HASHFAILED" in source
    assert "CanTouchPartFileHashTarget(m_partfile) && m_partfile->GetFileOp() == PFOP_HASHING" in source
    assert "theApp.emuledlg->PostMessage(TM_FINISHEDHASHING" not in source
    assert "theApp.emuledlg->PostMessage(TM_HASHFAILED" not in source
    assert "if (theApp.sharedfiles != NULL)\n\t\t\ttheApp.sharedfiles->FileHashingFinished(result);\n\t\telse\n\t\t\tdelete result;" in dialog_source
    assert "if (!theApp.IsClosing() && theApp.sharedfiles != NULL)\n\t\ttheApp.sharedfiles->HashFailed(pHashed);\n\telse\n\t\tdelete pHashed;" in dialog_source
