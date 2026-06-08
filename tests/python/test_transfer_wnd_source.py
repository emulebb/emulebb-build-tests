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
