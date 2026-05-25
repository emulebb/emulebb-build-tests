from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_search_params_ignores_null_file_type_item_data() -> None:
    source = (app_source_root() / "SearchParamsWnd.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pszED2KFileType != NULL);\n\t\tif (pszED2KFileType != NULL)\n\t\t\tstrCurSelFileType = pszED2KFileType;" in source
    assert "ASSERT(pszED2KFileType != NULL);\n\t\tif (pszED2KFileType != NULL)\n\t\t\tstrFileType = pszED2KFileType;" in source
