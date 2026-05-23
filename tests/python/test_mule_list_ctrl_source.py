from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid"


def test_end_scroll_cleanup_releases_window_dc() -> None:
    source = (app_source_root() / "MuleListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CMuleListCtrl::OnLvnEndScrollList") : source.index("void CMuleListCtrl::InitItemMemDC")]

    assert "GetDC()->" not in block
    assert "CDC *pDC = GetDC();" in block
    assert "pDC->FillSolidRect(&rcClient, GetBkColor());" in block
    assert "ReleaseDC(pDC);" in block
