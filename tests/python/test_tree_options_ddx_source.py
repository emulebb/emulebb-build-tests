from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_tree_options_ddx_uses_checked_window_wrapper() -> None:
    source = (app_source_root() / "TreeOptionsCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "CTreeOptionsCtrl *PrepareTreeOptionsDDXCtrl(CDataExchange *pDX, int nIDC)" in source
    assert "if (pDX == NULL)\n\t\t\treturn NULL;" in source
    assert "if (hWndCtrl == NULL)\n\t\t\treturn NULL;" in source
    assert "DYNAMIC_DOWNCAST(CTreeOptionsCtrl, CWnd::FromHandlePermanent(hWndCtrl))" in source
    assert "static_cast<CTreeOptionsCtrl*>(CWnd::FromHandlePermanent(hWndCtrl))" not in source
    assert source.count("if (pCtrlTreeOptions == NULL)\n\t\treturn;") >= 11


def test_tree_options_ex_ddx_uses_checked_window_wrapper() -> None:
    source = (app_source_root() / "TreeOptionsCtrlEx.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "CTreeOptionsCtrl *PrepareTreeOptionsDDXCtrl(CDataExchange *pDX, int nIDC, bool bEditCtrl)" in source
    assert "if (pDX == NULL)\n\t\t\treturn NULL;" in source
    assert "if (hWndCtrl == NULL)\n\t\t\treturn NULL;" in source
    assert "DYNAMIC_DOWNCAST(CTreeOptionsCtrl, CWnd::FromHandlePermanent(hWndCtrl))" in source
    assert "static_cast<CTreeOptionsCtrl*>(CWnd::FromHandlePermanent(hWndCtrl))" not in source
    assert "if (pData == NULL)\n\t\treturn;" in source
    assert source.count("if (pCtrlTreeOptions == NULL)\n\t\treturn;") >= 3
