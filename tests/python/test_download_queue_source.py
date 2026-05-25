from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_download_queue_priority_sort_guards_list_positions_before_access() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pos1 != NULL);\n\tASSERT(pos2 != NULL);\n\tif (pos1 == NULL || pos2 == NULL)\n\t\treturn false;" in source
    assert "ASSERT(pos1 != NULL);\n\tASSERT(pos2 != NULL);\n\tif (pos1 == NULL || pos2 == NULL || pos1 == pos2)\n\t\treturn;" in source
    assert "POSITION pos1 = filelist.FindIndex(first);\n\tASSERT(pos1 != NULL);\n\tif (pos1 == NULL)\n\t\treturn;" in source
    assert "POSITION pos2 = filelist.FindIndex(r2);\n\t\tASSERT(pos2 != NULL);\n\t\tif (pos2 == NULL)\n\t\t\treturn;" in source
    assert "ASSERT(pos3 != NULL);\n\t\t\tif (pos3 != NULL && !CompareParts(pos2, pos3))" in source
    assert "SwapParts(filelist.FindIndex(0), filelist.FindIndex(i - 1));" not in source
    assert "POSITION posFirst = filelist.FindIndex(0);" in source
    assert "POSITION posLast = filelist.FindIndex(i - 1);" in source
    assert "if (posFirst == NULL || posLast == NULL)\n\t\t\tbreak;" in source


def test_download_queue_waits_for_completion_worker_before_deleting_part_files() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    part_file = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")
    part_file_header = (app_source_root() / "PartFile.h").read_text(encoding="utf-8", errors="ignore")

    assert "CPartFile *pPartFile = filelist.RemoveHead();" in source
    assert "pPartFile->WaitForFileCompletionWorkerForShutdown();" in source
    assert source.index("pPartFile->WaitForFileCompletionWorkerForShutdown();") < source.index("delete pPartFile;")
    assert "void\tWaitForFileCompletionWorkerForShutdown();" in part_file_header
    assert "void CPartFile::WaitForFileCompletionWorkerForShutdown()" in part_file
    assert "lock.Lock(PartFileCompletionSeams::kCompletionOwnerShutdownWaitMs)" in part_file
    assert "lock.Lock(INFINITE)" in part_file
    assert "Hold the owner mutex until after the result is queued; shutdown waits on" in part_file
    assert "sLock.Unlock();\n\n\tif (!PostPartFileCompletionThreadResult(this, FILE_COMPLETION_THREAD_SUCCESS" not in part_file
