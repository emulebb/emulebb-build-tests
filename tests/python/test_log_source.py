from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_log_helpers_reject_null_format_strings() -> None:
    source = (app_source_root() / "Log.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.count("ASSERT(pszLine != NULL);\n\tif (pszLine == NULL)\n\t\treturn;") >= 4
    assert "void AddLogTextV(UINT uFlags, EDebugLogPriority dlpPriority, LPCTSTR pszLine, va_list argptr)" in source
