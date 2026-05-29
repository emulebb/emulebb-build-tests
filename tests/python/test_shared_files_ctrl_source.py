from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_shared_files_addfile_uses_sorted_insert_not_full_resort() -> None:
    header = (app_source_root() / "SharedFilesCtrl.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "SharedFilesCtrl.cpp").read_text(encoding="utf-8", errors="ignore")
    add_file = source[source.index("void CSharedFilesCtrl::AddFile") : source.index("void CSharedFilesCtrl::RemoveFile")]
    insert = source[source.index("void CSharedFilesCtrl::InsertVisibleFileByCurrentSort") : source.index("void CSharedFilesCtrl::AddFile")]

    assert "void InsertVisibleFileByCurrentSort(CShareableFile *file);" in header
    assert "std::upper_bound" in insert
    assert "CompareVisibleFiles(pNewFile, pExistingFile, lParamSort) < 0" in insert
    assert "live CPU dumps from large-profile startup" in add_file
    assert "InsertVisibleFileByCurrentSort(const_cast<CShareableFile*>(file));" in add_file
    assert "SortVisibleFiles();" not in add_file
