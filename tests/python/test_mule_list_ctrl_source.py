from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_end_scroll_cleanup_releases_window_dc() -> None:
    source = (app_source_root() / "MuleListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("void CMuleListCtrl::OnLvnEndScrollList") : source.index("void CMuleListCtrl::InitItemMemDC")]

    assert "GetDC()->" not in block
    assert "CDC *pDC = GetDC();" in block
    assert "pDC->FillSolidRect(&rcClient, GetBkColor());" in block
    assert "ReleaseDC(pDC);" in block


def test_shadow_param_list_resyncs_before_position_access() -> None:
    source = (app_source_root() / "MuleListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "MuleListCtrl.h").read_text(encoding="utf-8", errors="ignore")

    assert "bool CMuleListCtrl::EnsureParamSnapshot(bool bForce)" in source
    assert "m_Params.AddTail(CListCtrl::GetItemData(i));" in source
    assert "if (!EnsureParamSnapshot())\n\t\treturn iItem;" in source
    assert "if (pos == NULL)\n\t\t\treturn iItem;" in source
    assert "EnsureParamSnapshot(true);" in source
    assert "MLC_ASSERT(m_Params.GetAt(m_Params.FindIndex(wParam))" not in source
    assert "m_Params.RemoveAt(m_Params.FindIndex(wParam));" not in source
    assert "m_Params.InsertAfter(m_Params.FindIndex(lResult - 1)" not in source
    assert "bool EnsureParamSnapshot(bool bForce = false);" in header
    assert "if (pos == NULL)\n\t\t\treturn (iPos >= 0 && iPos < GetItemCount())" in header
