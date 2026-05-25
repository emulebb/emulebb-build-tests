from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_color_button_ddx_guards_missing_control_and_wrong_subclass() -> None:
    source = (app_source_root() / "ColorButton.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pDX != NULL);\n\tif (pDX == NULL)\n\t\treturn;" in source
    assert "ASSERT(hWndCtrl != NULL);\n\tif (hWndCtrl == NULL)\n\t\treturn;" in source
    assert "CColorButton *pColourButton = DYNAMIC_DOWNCAST(CColorButton, CWnd::FromHandlePermanent(hWndCtrl));" in source
    assert "ASSERT(pColourButton != NULL);\n\tif (pColourButton == NULL)\n\t\treturn;" in source
