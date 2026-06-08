from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
APP_ROOT = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"
SRC_ROOT = APP_ROOT / "srchybrid"
BUILD_ROOT = WORKSPACE_ROOT / "repos" / "emulebb-build"


def read_app_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def test_download_slot_diagnostics_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:DownloadSlotDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableDownloadSlotDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(UploadSlotDiagnosticsPreprocessorDefinition)" in config_definitions
        assert "$(DownloadSlotDiagnosticsPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(UploadSlotDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "$(DownloadSlotDiagnosticsPreprocessorDefinition)"
        )
        assert config_definitions.index("$(DownloadSlotDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def test_download_slot_diagnostics_build_env_override_is_plumbed() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")

    assert '"EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS", "EnableDownloadSlotDiagnostics"' in build_source
    assert 'extra_properties.append(f"/p:{property_name}=' in build_source


def test_download_slot_diagnostics_logs_queue_and_client_state() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    queue_source = read_app_source("DownloadQueue.cpp")
    queue_header = read_app_source("DownloadQueue.h")
    log_header = read_app_source("Log.h")
    artifacts = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")
    client_header = read_app_source("UpDownClient.h")
    base_client_source = read_app_source("BaseClient.cpp")

    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS\nvoid CUpDownClient::LogDownloadSlotDiagnostics" in client_source
    assert "DownloadSlotDiagnostics: client reason=%s" in client_source
    assert "DownloadSlotDiagnosticsLogLine(" in client_source
    assert "DownloadSlotDiagnosticsLogLine(" in queue_source
    assert "extern CLogFile theDownloadSlotDiagnosticsLog;" in log_header
    assert "void DownloadSlotDiagnosticsLogLine(LPCTSTR pszFmt, ...);" in log_header
    assert 'return _T("emulebb-diagnostics-download-slot.log");' in artifacts
    assert "LogArtifactNames::DownloadSlotDiagnosticsLogFileName()" in app_source
    for anchor in (
        "block-reserved",
        "block-reserve-empty",
        "request-sent",
        "block-complete",
        "block-advanced-duplicate-complete",
        "block-cleared-duplicate-complete",
        "block-cleared-duplicate-whole-complete",
        "packet-zero-write",
        "request-empty-nnp",
        "out-of-part-reqs",
        "accept-suppressed-out-of-part-cooldown",
        "accept-suppressed-no-data-cooldown",
        "timeout",
        "disconnect-downloading",
    ):
        assert anchor in client_source or anchor in base_client_source

    throttle_block = client_source[
        client_source.index("bool IsDownloadSlotDiagnosticsHighVolumeReason") :
        client_source.index("bool IsTickInsideWindow")
    ]
    assert '_T("request-empty-nnp")' in throttle_block
    assert '_T("block-advanced-duplicate-complete")' in throttle_block
    assert '_T("block-cleared-duplicate-complete")' in throttle_block
    assert '_T("block-cleared-duplicate-whole-complete")' in throttle_block
    assert '_T("packet-dropped-no-pending-block")' in throttle_block
    assert '_T("disconnect-downloading")' in throttle_block
    assert '_T("state-leave-downloading")' in throttle_block
    assert '_T("state-leave-downloading-nnp")' in throttle_block

    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS\nvoid CDownloadQueue::LogDownloadSlotDiagnostics" in queue_source
    assert "DownloadSlotDiagnostics: summary" in queue_source
    assert 'CDiagnosticsKeyValueLineBuilder summary(_T("DownloadSlotDiagnostics: summary"));' in queue_source
    assert 'DownloadSlotDiagnosticsLogLine(_T("%s"), (LPCTSTR)summary.GetLine());' in queue_source
    assert "LogDownloadSlotDiagnostics(curTick);" in queue_source
    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS\n\tvoid\tLogDownloadSlotDiagnostics" in queue_header
    assert "m_ullDownloadBlockRequestsReserved" in client_header
    assert "m_ullDownloadDuplicateZeroWritePackets" in client_header
    assert "m_ullDownloadDuplicateZeroWriteBytes" in client_header
    assert "GetDownloadDuplicateZeroWritePackets" in client_header
    assert "GetDownloadDuplicateZeroWriteBytes" in client_header
    assert "m_uDownloadOutOfPartReqsSuppressions" in client_header
    assert "highVolumeSuppressed=%I64u" in client_source
    assert "duplicateZeroWritePackets=%I64u" in client_source
    assert "duplicateZeroWriteBytes=%I64u" in client_source
    assert "PartFileBufferedDataStateSnapshot bufferSnapshot" in queue_source
    assert "cur_file->GetBufferedDataStateSnapshot(bufferSnapshot);" in queue_source
    assert "cur_source->GetDownloadDuplicateZeroWritePackets();" in queue_source
    assert "cur_source->GetDownloadDuplicateZeroWriteBytes();" in queue_source
    for field in (
        "sourceStarvedReadyFiles=%u",
        "sourceStarvedLocalQueuedReadyFiles=%u",
        "sourceStarvedKadSearchingReadyFiles=%u",
        "sourceStarvedKadEligibleReadyFiles=%u",
        "sourceStarvedKadDueReadyFiles=%u",
        "sourceStarvedKadBackoffReadyFiles=%u",
        "sourceThinReadyFiles=%u",
        "sourceRichReadyFiles=%u",
        "a4afReadyFiles=%u",
        "connectedSources=%u",
        "connectingSources=%u",
        "callbackSources=%u",
        "hashsetSources=%u",
        "lowToLowIPSources=%u",
        "bannedSources=%u",
        "idleSources=%u",
        "duplicateZeroWriteSources=%u",
        "duplicateZeroWritePackets=%I64u",
        "duplicateZeroWriteBytes=%I64u",
        "effectiveFileBufferBytes=%I64u",
        "autoBroadbandIO=%u",
        "bufferedReadyBytes=%I64u",
        "bufferedPendingBytes=%I64u",
        "bufferedWrittenBytes=%I64u",
        "bufferedErrorBytes=%I64u",
        "bufferedReadyItems=%u",
        "bufferedPendingItems=%u",
        "bufferedWrittenItems=%u",
        "bufferedErrorItems=%u",
        "bufferedReadyFiles=%u",
        "bufferedPendingFiles=%u",
        "bufferedWrittenFiles=%u",
        "bufferedErrorFiles=%u",
        "maxBufferedReadyBytes=%I64u",
        "maxBufferedPendingBytes=%I64u",
        "maxBufferedWrittenBytes=%I64u",
        "maxBufferedReadyItems=%u",
        "maxBufferedPendingItems=%u",
        "maxBufferedWrittenItems=%u",
        "asyncWriteFiles=%u",
        "maxAsyncWriteRefsPerFile=%ld",
        "asyncWriteRefs=%Id",
    ):
        assert field in queue_source
    for aggregate in (
        "++uSourceStarvedReadyFiles;",
        "++uSourceStarvedLocalQueuedReadyFiles;",
        "++uSourceStarvedKadSearchingReadyFiles;",
        "++uSourceStarvedKadEligibleReadyFiles;",
        "++uSourceStarvedKadDueReadyFiles;",
        "++uSourceStarvedKadBackoffReadyFiles;",
        "++uSourceThinReadyFiles;",
        "++uSourceRichReadyFiles;",
        "++uA4AFReadyFiles;",
        "uConnectedSources += cur_file->GetSrcStatisticsValue(DS_CONNECTED);",
        "uConnectingSources += cur_file->GetSrcStatisticsValue(DS_CONNECTING);",
        "uCallbackSources += cur_file->GetSrcStatisticsValue(DS_WAITCALLBACK);",
        "uCallbackSources += cur_file->GetSrcStatisticsValue(DS_WAITCALLBACKKAD);",
        "uHashsetSources += cur_file->GetSrcStatisticsValue(DS_REQHASHSET);",
        "uLowToLowIPSources += cur_file->GetSrcStatisticsValue(DS_LOWTOLOWIP);",
        "uBannedSources += cur_file->GetSrcStatisticsValue(DS_BANNED);",
        "uIdleSources += cur_file->GetSrcStatisticsValue(DS_NONE);",
        "uMaxBufferedReadyBytes = max(uMaxBufferedReadyBytes, bufferSnapshot.uReadyBytes);",
        "uMaxBufferedPendingBytes = max(uMaxBufferedPendingBytes, bufferSnapshot.uPendingBytes);",
        "uMaxBufferedWrittenBytes = max(uMaxBufferedWrittenBytes, bufferSnapshot.uWrittenBytes);",
        "uMaxBufferedReadyItems = max(uMaxBufferedReadyItems, bufferSnapshot.uReadyCount);",
        "uMaxBufferedPendingItems = max(uMaxBufferedPendingItems, bufferSnapshot.uPendingCount);",
        "uMaxBufferedWrittenItems = max(uMaxBufferedWrittenItems, bufferSnapshot.uWrittenCount);",
        "++uAsyncWriteFiles;",
        "nMaxAsyncWriteRefsPerFile = max(nMaxAsyncWriteRefsPerFile, bufferSnapshot.nAsyncWriteCount);",
    ):
        assert aggregate in queue_source
    assert 'summary.AppendFormat(_T("effectiveFileBufferBytes=%I64u"), static_cast<uint64>(GetEffectiveFileBufferSizeBytes()))' in queue_source
    assert 'summary.AppendFormat(_T("autoBroadbandIO=%u"), static_cast<UINT>(thePrefs.IsDownloadAutoBroadbandIOEnabled()))' in queue_source
    assert '_tcscmp(pszReason, _T("block-reserve-empty")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("start-download")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("state-enter-downloading")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("state-transition")) == 0' in client_source
    assert "noDataSuppressions=%u" in client_source


def test_download_buffer_diagnostics_splits_part_file_flush_states() -> None:
    part_header = read_app_source("PartFile.h")
    part_source = read_app_source("PartFile.cpp")
    queue_source = read_app_source("DownloadQueue.cpp")

    assert "struct PartFileBufferedDataStateSnapshot" in part_header
    assert "void\tGetBufferedDataStateSnapshot(PartFileBufferedDataStateSnapshot &rSnapshot) const;" in part_header
    assert "void CPartFile::GetBufferedDataStateSnapshot(PartFileBufferedDataStateSnapshot &rSnapshot) const" in part_source
    assert "rSnapshot.nAsyncWriteCount = GetAsyncWriteCount();" in part_source
    assert "GetPartFileBufferedDataFlushState(*item)" in part_source
    for state in ("PB_READY", "PB_PENDING", "PB_WRITTEN", "PB_ERROR"):
        assert state in part_source
    for aggregate in (
        "uBufferedReadyBytes += bufferSnapshot.uReadyBytes;",
        "uBufferedPendingBytes += bufferSnapshot.uPendingBytes;",
        "uBufferedWrittenBytes += bufferSnapshot.uWrittenBytes;",
        "uBufferedErrorBytes += bufferSnapshot.uErrorBytes;",
        "iAsyncWriteRefs += bufferSnapshot.nAsyncWriteCount;",
    ):
        assert aggregate in queue_source


def test_download_slot_no_data_and_out_of_part_guards_are_conservative() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    client_header = read_app_source("UpDownClient.h")

    timeout_block = client_source[
        client_source.index("void CUpDownClient::CheckDownloadTimeout()") :
        client_source.index("uint16 CUpDownClient::GetAvailablePartCount() const")
    ]

    assert "kDownloadNoDataSlotCooldownThreshold = 2" in client_source
    assert "kDownloadNoDataSlotPayloadThresholdBytes = EMBLOCKSIZE" in client_source
    assert "kDownloadFirstPayloadTimeoutMs = SEC2MS(60)" in client_source
    assert "timeout-first-payload" in timeout_block
    assert "!m_PendingBlocks_list.IsEmpty()" in timeout_block
    assert "GetSessionPayloadDown() == 0" in timeout_block
    assert "GetSessionDown() == 0" in timeout_block
    assert "thePrefs.GetDownloadTimeout() > kDownloadFirstPayloadTimeoutMs" in timeout_block
    assert "First payload timeout. More than %u seconds since the first requested block without payload." in timeout_block
    assert timeout_block.index("timeout-first-payload") < timeout_block.index('LogDownloadSlotDiagnostics(_T("timeout"))')
    assert "CanAcceptUploadSlotAfterDownloadNoData" in client_header
    assert "NoteDownloadNoDataSlotFailure(pszReason)" in client_source
    assert "Suppressed OP_AcceptUploadReq after repeated no-data download slots" in client_source
    assert "kOutOfPartReqsCooldownThreshold = 3" in client_source


def test_duplicate_complete_download_block_advances_and_retires_stale_pending_request() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    block = client_source[
        client_source.index("const bool bCompletedDuplicateRange = !packed") :
        client_source.index("Stop looping and exit")
    ]

    assert "lenWritten == 0" in block
    assert "m_reqfile->IsComplete(cur_block->block->StartOffset, nEndPos)" in block
    assert "const bool bCompletedDuplicateBlock = bCompletedDuplicateRange && nEndPos == cur_block->block->EndOffset;" in block
    assert "const bool bCompletedDuplicateWholeBlock = !packed" in block
    assert "m_reqfile->IsComplete(cur_block->block->StartOffset, cur_block->block->EndOffset)" in block
    assert "const bool bDuplicateZeroWrite = !packed" in block
    assert "m_reqfile->IsComplete(nStartPos, nEndPos)" in block
    assert "bool bProgressedPendingBlock = false;" in block
    assert "if (lenWritten > 0 ? nEndPos == cur_block->block->EndOffset : (bCompletedDuplicateBlock || bCompletedDuplicateWholeBlock))" in block
    assert block.index("m_reqfile->IsComplete(cur_block->block->StartOffset, nEndPos)") < block.index("const uint64 uDuplicateProgressBytes")
    assert "bCompletedDuplicateWholeBlock" in block
    assert "cur_block->block->transferred = uDuplicateProgressBytes;" in block
    duplicate_progress_block = block[
        block.index("const uint64 uDuplicateProgressBytes") :
        block.index('#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_DIAGNOSTICS', block.index("const uint64 uDuplicateProgressBytes"))
    ]
    assert "bProgressedPendingBlock = true;" not in duplicate_progress_block
    assert "bProgressedPendingBlock = true;" in block
    assert 'LogDownloadSlotDiagnostics(_T("block-advanced-duplicate-complete")' in block
    assert "m_nTransferredDown += uTransferredFileDataSize;" in block
    assert block.index("if (lenWritten > 0)") < block.index("m_nTransferredDown += uTransferredFileDataSize;")
    assert '_T("block-cleared-duplicate-complete")' in block
    assert '_T("block-cleared-duplicate-whole-complete")' in block
    assert "ClearPendingBlockRequest(cur_block);" in block
    assert block.index("ClearPendingBlockRequest(cur_block);") < block.index("SendBlockRequests();")
    assert "if (bProgressedPendingBlock)\n\t\t\tResetDownloadStaleBlockPacketGuard();" in block
    assert block.index("SendBlockRequests();") < block.index("if (bProgressedPendingBlock)")


def test_stale_block_packets_abort_only_after_conservative_burst() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    client_header = read_app_source("UpDownClient.h")
    base_client_source = read_app_source("BaseClient.cpp")

    process_block = client_source[
        client_source.index("void CUpDownClient::ProcessBlockPacket") :
        client_source.index("int CUpDownClient::unzip")
    ]
    packet_drop_block = process_block[
        process_block.index('LogDownloadSlotDiagnostics(_T("packet-dropped-no-pending-block")') :
        process_block.index("int CUpDownClient::unzip") if "int CUpDownClient::unzip" in process_block else len(process_block)
    ]
    helper_block = client_source[
        client_source.index("bool CUpDownClient::ShouldAbortAfterStaleBlockPacket") :
        client_source.index("void CUpDownClient::ProcessInboundOutOfPartReqs")
    ]
    start_download_block = client_source[
        client_source.index("void CUpDownClient::StartDownload()") :
        client_source.index("void CUpDownClient::SendCancelTransfer()")
    ]

    assert "kDownloadStaleBlockPacketThreshold = 32" in client_source
    assert "kDownloadStaleBlockPacketWindowMs = SEC2MS(15)" in client_source
    assert "ResetDownloadStaleBlockPacketGuard();" in start_download_block
    assert "ResetDownloadStaleBlockPacketGuard();" in base_client_source
    assert "void\tResetDownloadStaleBlockPacketGuard();" in client_header
    assert "bool\tShouldAbortAfterStaleBlockPacket(CString *pReason = NULL);" in client_header
    assert "m_ullDownloadStaleBlockPacketWindowStart" in client_header
    assert "m_uDownloadStaleBlockPacketWindowCount" in client_header
    assert process_block.index("ResetDownloadStaleBlockPacketGuard();") < process_block.index(
        'LogDownloadSlotDiagnostics(_T("packet-dropped-no-pending-block")'
    )
    assert "GetDownloadState() != DS_DOWNLOADING" in helper_block
    assert "m_reqfile == NULL" in helper_block
    assert "m_PendingBlocks_list.IsEmpty()" in helper_block
    assert "m_uDownloadStaleBlockPacketWindowCount < kDownloadStaleBlockPacketThreshold" in helper_block
    assert "Sustained stale block packets." in helper_block
    assert "did not make useful download progress" in helper_block
    assert '_T("stale-block-packet-abort")' in packet_drop_block
    assert "SendCancelTransfer();" in packet_drop_block
    assert "SetDownloadState(DS_ONQUEUE, strReason);" in packet_drop_block
    assert packet_drop_block.index("ShouldAbortAfterStaleBlockPacket(&strReason)") < packet_drop_block.index("SendCancelTransfer();")
    assert packet_drop_block.index("SendCancelTransfer();") < packet_drop_block.index("SetDownloadState(DS_ONQUEUE, strReason);")
    assert "standard cancel returns it to queue while preserving protocol semantics" in packet_drop_block


def test_duplicate_zero_write_blocks_feed_stale_packet_guard() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    part_file_source = read_app_source("PartFile.cpp")
    base_client_source = read_app_source("BaseClient.cpp")
    client_header = read_app_source("UpDownClient.h")
    process_block = client_source[
        client_source.index("void CUpDownClient::ProcessBlockPacket") :
        client_source.index("int CUpDownClient::unzip")
    ]
    duplicate_guard_block = process_block[
        process_block.index("else if (bDuplicateZeroWrite)") :
        process_block.index("Stop looping and exit")
    ]

    assert "m_ullDownloadDuplicateZeroWritePackets" in client_header
    assert "m_ullDownloadDuplicateZeroWriteBytes" in client_header
    assert "NoteDownloadDuplicateZeroWrite" in client_header
    assert "m_ullDownloadDuplicateZeroWritePackets = 0;" in base_client_source
    assert "m_ullDownloadDuplicateZeroWriteBytes = 0;" in base_client_source
    assert "++m_ullDownloadDuplicateZeroWritePackets;" in client_source
    assert "m_ullDownloadDuplicateZeroWriteBytes += uPayloadBytes;" in client_source
    duplicate_write_block = part_file_source[
        part_file_source.index("PrcBlkPkt: Already written block") - 220 :
        part_file_source.index("PrcBlkPkt: Already written block") + 220
    ]
    assert "client->NoteDownloadDuplicateZeroWrite(transize);" in duplicate_write_block
    assert "client == NULL" in duplicate_write_block
    assert "ShouldAbortAfterStaleBlockPacket(&strReason)" in duplicate_guard_block
    assert '_T("stale-duplicate-block-packet-abort")' in duplicate_guard_block
    assert "SendCancelTransfer();" in duplicate_guard_block
    assert "SetDownloadState(DS_ONQUEUE, strReason);" in duplicate_guard_block
    assert "stock transfer control" in duplicate_guard_block
    assert duplicate_guard_block.index("ShouldAbortAfterStaleBlockPacket(&strReason)") < duplicate_guard_block.index(
        "SendCancelTransfer();"
    )
    assert 'else if (lenWritten == 0)\n\t\t\tResetDownloadStaleBlockPacketGuard();' in process_block
