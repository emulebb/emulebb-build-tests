from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_generic_tooltip_lines_are_drawn_inside_calculated_width() -> None:
    source = (app_source_root() / "ToolTipCtrlX.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "CRect rcLine(ptText.x, ptText.y, ptText.x + iMaxSingleLineWidth, ptText.y + iTextHeight);" in source
    assert "const RECT rcLine{ptText.x, ptText.y, 32767, 32767}" not in source
    assert "TabbedTextOut(ptText.x, ptText.y, strLine" not in source
