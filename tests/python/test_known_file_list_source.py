from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_known_file_stat_merge_rejects_null_inputs_before_size_compare() -> None:
    source = (app_source_root() / "KnownFileList.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pKeep != NULL);\n\t\tASSERT(pDiscard != NULL);\n\t\tif (pKeep == NULL || pDiscard == NULL)\n\t\t\treturn;\n\t\tASSERT(pKeep->GetFileSize() == pDiscard->GetFileSize());" in source
