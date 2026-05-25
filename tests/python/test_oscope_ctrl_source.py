from __future__ import annotations

from pathlib import Path


def _app_source_root() -> Path:
    workspace_root = Path(__file__).resolve().parents[4]
    return workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_oscope_recreate_graph_does_not_trust_only_first_trend_iterator() -> None:
    source = (_app_source_root() / "OScopeCtrl.cpp").read_text(
        encoding="utf-8",
        errors="ignore",
    )

    assert "while (pPosArray[0] != NULL)" not in source
    assert "new POSITION[m_NTrends]" not in source
    assert "new double[m_NTrends]" not in source
    assert "std::vector<POSITION> posArray" in source
    assert "nPointsToDraw = min(nPointsToDraw, m_PlotData[iTrend].lstPoints.GetCount())" in source
    assert "if (posArray[iTrend] == NULL)" in source


def test_oscope_public_trend_api_checks_indices_in_release() -> None:
    source = (_app_source_root() / "OScopeCtrl.cpp").read_text(
        encoding="utf-8",
        errors="ignore",
    )
    header = (_app_source_root() / "OScopeCtrl.h").read_text(
        encoding="utf-8",
        errors="ignore",
    )

    assert "bool IsValidTrendIndex(int iTrend) const;" in header
    assert "m_NTrends = NTrends > 0 ? NTrends : 1;" in source
    assert "bool COScopeCtrl::IsValidTrendIndex(int iTrend) const" in source
    assert "return m_PlotData != NULL && iTrend >= 0 && iTrend < m_NTrends;" in source
    assert "if (!IsValidTrendIndex(iTrend) || iRatio == 0)\n\t\treturn;" in source
    assert "if (!IsValidTrendIndex(iTrend))\n\t\treturn;" in source
    assert "if (dUpper <= dLower || !IsValidTrendIndex(iTrend))\n\t\treturn;" in source
    assert "return CLR_INVALID;" in source
    assert "if (dNewPoint == NULL || m_PlotData == NULL)\n\t\treturn;" in source
    assert "reinterpret_cast<HMENU>(static_cast<UINT_PTR>(nID))" in source
    assert "static_cast<float>(shownsecs) / static_cast<float>(plotRect.Width())" in source
