from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_app_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_transfer_queue_footer_includes_broadband_upload_summary() -> None:
    seams = read_app_source("TransferWndSeams.h")
    source = read_app_source("TransferWnd.cpp")

    assert "CalculateUploadUtilizationPercent(" in seams
    assert "FormatUploadRateMbValue(" in seams
    assert "FormatQueueCountText(" in seams
    assert "MB/s" in seams
    assert "UL " in seams

    block = source[
        source.index("void CTransferWnd::ShowQueueCount") :
        source.index("void CTransferWnd::DoDataExchange")
    ]
    assert "void CTransferWnd::LayoutQueueFooter()" in source
    assert "pCount->MoveWindow(iLeft, rcCount.top, iRight - iLeft, rcCount.Height(), TRUE);" in source
    assert "pRefresh->IsWindowVisible()" in source
    assert "LayoutQueueFooter();" in block
    assert "TransferWndSeams::FormatQueueCountText(" in block
    assert "theApp.clientlist->GetBannedCount()" in block
    assert "theApp.uploadqueue->GetUploadQueueLength()" in block
    assert "theApp.uploadqueue->GetBroadbandBaseSlotTarget()" in block
    assert "theApp.uploadqueue->GetBroadbandSlotCap()" in block
    assert "theApp.uploadqueue->GetBroadbandUploadSlotElasticPercent()" in block
    assert "theApp.uploadqueue->GetToNetworkDatarate()" in block
    assert "theApp.uploadqueue->GetConfiguredUploadBudgetBytesPerSec()" in block
    assert "SetDlgItemText(IDC_QUEUECOUNT, strQueueTextValue);" in block


def test_transfer_download_metrics_use_top_toolbar_row_and_buffer_sources() -> None:
    seams = read_app_source("TransferWndSeams.h")
    source = read_app_source("TransferWnd.cpp")
    header = read_app_source("TransferWnd.h")
    resource = read_app_source("emule.rc")
    resource_header = read_app_source("resource.h")

    assert "IDC_DOWNLOAD_METRICS" in resource_header
    assert 'CONTROL         "",IDC_DOWNLOAD_METRICS,"Static",SS_LEFT | SS_ENDELLIPSIS | SS_NOPREFIX' in resource
    assert "void\tLayoutDownloadMetrics();" in header
    assert "void\tUpdateDownloadMetricsText();" in header
    assert "CalculateDownloadBufferUtilizationPercent(" in seams
    assert "kDownloadBufferUtilizationDisplayPercentMax" in seams

    layout_block = source[
        source.index("void CTransferWnd::LayoutDownloadMetrics") :
        source.index("uint32 CTransferWnd::GetVisibleDisplayRefreshMask")
    ]
    assert "m_btnWnd1.GetWindowRect(&rcToolbar);" in layout_block
    assert "m_dlTab.GetWindowRect(&rcTab);" in layout_block
    assert "const int iLeft = rcToolbar.right + 5;" in layout_block
    assert "const int iRight = rcTab.left - 5;" in layout_block
    assert "SS_ENDELLIPSIS" in resource
    assert "pMetrics->ShowWindow(SW_HIDE);" in layout_block

    update_block = source[
        source.index("void CTransferWnd::UpdateDownloadMetricsText") :
        source.index("void CTransferWnd::ShowQueueCount")
    ]
    assert "theApp.downloadqueue->GetBufferedDownloadBytes()" in update_block
    assert "theApp.downloadqueue->GetAdaptiveGlobalDownloadBufferBudgetBytes()" in update_block
    assert "theApp.downloadqueue->GetBufferedDownloadFileCount()" in update_block
    assert "theApp.downloadqueue->GetLargestBufferedDownloadFileBytes()" in update_block
    assert "TransferWndSeams::CalculateDownloadBufferUtilizationPercent(" in update_block
    assert "::GlobalMemoryStatusEx(&memory)" in update_block
    assert "CastItoXBytes(ullBufferedBytes)" in update_block
    assert "SetDlgItemText(IDC_DOWNLOAD_METRICS, strMetrics);" in update_block

    refresh_block = source[
        source.index("void CTransferWnd::FlushDisplayRefreshMask") :
        source.index("void CTransferWnd::UpdateDownloadMetricsText")
    ]
    assert "DISPLAY_REFRESH_TRANSFER_SUMMARY" in refresh_block
    assert "UpdateDownloadMetricsText();" in refresh_block
