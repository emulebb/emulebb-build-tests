from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_list_view_property_sheet_insert_page_rejects_null_page() -> None:
    source = (app_source_root() / "ListViewWalkerPropertySheet.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pPage != NULL);\n\tif (pPage == NULL)\n\t\treturn;\n\tASSERT_KINDOF(CPropertyPage, pPage);" in source
