from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_file_icon_tooltips_initialize_line_height_from_non_colon_lines() -> None:
    source = (app_source_root() / "ToolTipCtrlX.cpp").read_text(encoding="utf-8", errors="ignore")
    first_line = source[source.index("file name, printed bold on top") : source.index("} else if (!strLine.IsEmpty()")]
    plain_line = source[source.index("} else if (!strLine.IsEmpty()") : source.index("} else {", source.index("} else if (!strLine.IsEmpty()"))]

    assert "iTextHeight = max(iTextHeight, siz.cy + iLineHeightOff);" in first_line
    assert "iTextHeight = max(iTextHeight, siz.cy + iLineHeightOff);" in plain_line
