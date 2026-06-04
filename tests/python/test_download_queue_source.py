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


def test_search_result_source_addition_logs_file_exception_details() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CDownloadQueue::AddSearchToDownload(CSearchFile *toadd") :
        source.index("void CDownloadQueue::AddSearchToDownload(const CString &link")
    ]

    assert 'DebugLogWarning(_T("Failed to add search-result source %u:%u for \\"%s\\"%s"), toadd->GetClientID(), toadd->GetClientPort(), (LPCTSTR)newfile->GetFileName(), (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert 'DebugLogWarning(_T("Failed to add global UDP search-result source %u:%u for \\"%s\\"%s"), aClients[i].m_nIP, aClients[i].m_nPort, (LPCTSTR)newfile->GetFileName(), (LPCTSTR)CExceptionStrDash(*ex));' in block
    assert block.count("CExceptionStrDash(*ex)") == 2
    assert block.count("ASSERT(0);") == 2


def test_startup_part_file_hash_jobs_are_released_after_part_scan() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    scoped_block = source[source.index("class CScopedPartFileHashStartupScheduling") : source.index("enum ProtectedDiskRoleMask")]
    init_block = source[source.index("void CDownloadQueue::Init()") : source.index("CDownloadQueue::~CDownloadQueue()")]

    assert "BeginPartFileHashStartupScheduling();" in scoped_block
    assert "EndPartFileHashStartupScheduling();" in scoped_block
    assert "CScopedPartFileHashStartupScheduling startupHashScheduling;" in init_block
    assert init_block.index("CScopedPartFileHashStartupScheduling startupHashScheduling;") < init_block.index("PathHelpers::ForEachMatchingEntry(PathHelpers::AppendPathComponent(strTempDir, _T(\"*.part.met\"))")
    assert "EndPartFileHashStartupScheduling();" not in init_block
    assert init_block.index("CScopedPartFileHashStartupScheduling startupHashScheduling;") < init_block.index("SortByPriority();")


def test_local_server_source_requests_prefer_starved_files_on_equal_wait() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CDownloadQueue::ProcessLocalRequests()") :
        source.index("void CDownloadQueue::SendLocalSrcRequest")
    ]

    assert "int iBestValidSources = (std::numeric_limits<int>::max)();" in block
    assert "UINT uBestSourceCount = _UI32_MAX;" in block
    assert "const int iValidSources = cur_file->GetValidSourcesCount();" in block
    assert "const UINT uSourceCount = cur_file->GetSourceCount();" in block
    assert "ullWaitTime < ullBestWaitTime" in block
    assert "iValidSources < iBestValidSources" in block
    assert "iValidSources == iBestValidSources && uSourceCount < uBestSourceCount" in block
    assert block.index("const ULONGLONG ullWaitTime") < block.index("const int iValidSources")
    assert block.index("const int iValidSources") < block.index("const UINT uSourceCount")
    assert block.index("iBestValidSources = iValidSources;") < block.index("posNextRequest = pos2;")
    assert block.index("uBestSourceCount = uSourceCount;") < block.index("posNextRequest = pos2;")


def test_local_server_source_requests_prune_stale_entries_before_spending_credit() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    predicate = source[
        source.index("bool ShouldSendLocalServerSourceRequest") :
        source.index("}\n}\n\nCDownloadQueue::CDownloadQueue()")
    ]
    block = source[
        source.index("void CDownloadQueue::ProcessLocalRequests()") :
        source.index("void CDownloadQueue::SendLocalSrcRequest")
    ]

    assert "pFile->GetMaxSourcePerFileSoft() <= pFile->GetSourceCount()" in predicate
    assert "pCurrentServer != NULL && pCurrentServer->SupportsLargeFilesTCP()" in predicate
    assert "ShouldSendLocalServerSourceRequest(cur_file, pCurrentServer)" in block
    assert "cur_file->m_bLocalSrcReqQueued = false;" in block
    assert "not sent because it is no longer eligible" in block
    assert "if (iFiles > 0)" in block
    assert "m_dwNextTCPSrcReq = curTick + SEC2MS(iMaxFilesPerTcpFrame * (16 + 4));" in block


def test_download_summary_reports_source_discovery_pressure() -> None:
    source = (app_source_root() / "DownloadQueue.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[
        source.index("void CDownloadQueue::LogDownloadSlotInstrumentation") :
        source.index("//This method is called every 100 ms")
    ]

    for field in (
        "localServerQueuedFiles=%Id",
        "localServerQueuedReadyFiles=%u",
        "localServerMarkedReadyFiles=%u",
        "nextTcpSourceRequestWaitMs=%I64u",
        "udpSearchActive=%u",
        "udpSearchedServers=%u",
        "udpRequestsSentToServer=%u",
        "udpFileReasks=%u",
        "udpFailedFileReasks=%u",
        "udpLastSearchAgeMs=%I64u",
        "kadConnected=%u",
        "kadTotalFileSearches=%u",
        "kadSearchingReadyFiles=%u",
        "kadEligibleReadyFiles=%u",
        "kadDueReadyFiles=%u",
        "kadBackoffReadyFiles=%u",
    ):
        assert field in block

    assert "m_localServerReqQueue.GetCount()" in block
    assert "cur_file->m_bLocalSrcReqQueued" in block
    assert "cur_file->GetKadFileSearchID() != 0" in block
    assert "cur_file->GetMaxSourcePerFileUDP() > cur_file->GetSourceCount()" in block
    assert "Kademlia::CKademlia::GetTotalFile()" in block
