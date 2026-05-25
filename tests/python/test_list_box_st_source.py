from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_list_box_item_data_helpers_reject_invalid_slots_before_deref() -> None:
    source = (app_source_root() / "ListBoxST.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (nIndex < 0 || nIndex >= GetCount())\n\t\treturn LB_ERR;\n\n\t// Get pointer to associated data (if any)" in source
    assert "if (lpLBData == (LPVOID)-1)\n\t\treturn LB_ERR;" in source
    assert "if (nIndex < 0 || nIndex >= GetCount())\n\t\treturn;\n\n\t// Get pointer to associated data (if any)" in source
    assert "if (lpLBData != NULL && lpLBData != (LPVOID)-1)\n\t\tdelete lpLBData;" in source
    assert "if (lpLBData != NULL && lpLBData != (LPVOID)-1)\n\t\treturn lpLBData->dwItemData;" in source
    assert "return (lpLBData != NULL && lpLBData != (LPVOID)-1) ? lpLBData->pData : (LPVOID)-1;" in source


def test_list_box_move_stops_when_reinsert_fails() -> None:
    source = (app_source_root() / "ListBoxST.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "int nInsertedIndex = InsertString(nNewIndex, sText);\n\tif (nInsertedIndex == LB_ERR || nInsertedIndex == LB_ERRSPACE)\n\t\treturn nInsertedIndex;\n\n\t// Restore associated data" in source
