from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_remove_file_rejects_null_before_matching_owner_rows() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(toremove != NULL);\n\tif (toremove == NULL)\n\t\treturn bResult;\n\tRemoveVideoThumbnailCache(toremove);" in source
    assert "if (delItem->owner == toremove || delItem->value == (void*)toremove)" in source


def test_add_source_rejects_stale_owner_before_parent_lookup() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (owner == NULL || theApp.downloadqueue == NULL || !theApp.downloadqueue->IsPartFile(owner) || !IsLiveDownloadClient(source))\n\t\treturn;" in source
    assert "if (cur_item == NULL)\n\t\t\tcontinue;" in source
    assert "ASSERT(ownerIt != m_ListItems.end());\n\tif (ownerIt == m_ListItems.end() || ownerIt->second == NULL || ownerIt->second->type != FILE_TYPE || ownerIt->second->value != owner)\n\t\treturn;" in source


def test_draw_item_checks_next_row_before_tree_line_deref() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const CtrlItem_Struct *nextContent = notLast ? reinterpret_cast<CtrlItem_Struct*>(GetItemData(lpDrawItemStruct->itemID + 1)) : NULL;\n\t\tbool hasNext = nextContent != NULL && nextContent->type != FILE_TYPE;" in source
