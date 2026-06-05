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


def test_thumbnail_completion_resumes_deferred_part_file_delete_after_preview_release() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("LRESULT CDownloadListCtrl::OnVideoThumbnailFinished") : source.index("void CDownloadListCtrl::SetAllIcons")]

    assert "CPartFile *pFileToDelete = bFileStillTracked && pResult->pPartFile->IsDeleting() ? pResult->pPartFile : NULL;" in block
    assert block.index("pResult->pPartFile->m_bPreviewing = false;") < block.index("pFileToDelete->DeletePartFile();")
    assert block.index("UpdateItem(pResult->pPartFile);") < block.index("delete pResult;")
    assert "delete pResult;\n\tif (pFileToDelete != NULL)\n\t\tpFileToDelete->DeletePartFile();\n\tStartNextVideoThumbnailWorker();" in block


def test_download_filename_suffix_only_uses_live_thumbnail_cache() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    helper = source[source.index("bool CDownloadListCtrl::HasCachedVideoThumbnail") : source.index("bool CDownloadListCtrl::IsVideoThumbnailCandidate")]
    display = source[source.index("CString CDownloadListCtrl::GetFileItemDisplayText") : source.index("void CDownloadListCtrl::ShowFilesCount")]

    assert "m_videoThumbnailCache.Lookup(strKey, pEntry)" in helper
    assert "GetCachedVideoThumbnail" not in helper
    assert "ReadVideoThumbnailBitmapFile" not in helper
    assert "PathExists" not in helper
    assert "sText.AppendChar(static_cast<TCHAR>(0x25A3));" in display


def test_download_infotip_compacts_only_first_filename_line() -> None:
    source = (app_source_root() / "DownloadListCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    helper = source[source.index("CString CompactDownloadInfoTipFileName") : source.index("uint32 GetClientGeoIP")]
    infotip = source[source.index("void CDownloadListCtrl::OnLvnGetInfoTip") : source.index("void CDownloadListCtrl::ShowFileDialog")]

    assert "const int kDownloadInfoTipMaxFileNameChars = 160;" in source
    assert "strCompacted += szEllipsis;" in helper
    assert "strCompacted += strExtension;" in helper
    assert "info.Replace(pPartFile->GetFileName() + _T('\\n'), CompactDownloadInfoTipFileName(pPartFile->GetFileName()) + _T('\\n'));" in infotip
