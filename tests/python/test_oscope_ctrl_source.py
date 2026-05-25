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
