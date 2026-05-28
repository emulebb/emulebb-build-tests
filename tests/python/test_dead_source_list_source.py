from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_dead_source_list_skips_unidentifiable_clients_before_hashing() -> None:
    source = (app_source_root() / "DeadSourceList.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "DeadSourceList.h").read_text(encoding="utf-8", errors="ignore")

    assert "bool HasValidKey() const;" in header
    assert "if (isnulmd4(ds.m_aucHash))\n\t\treturn 0;" in header
    assert "bool CDeadSource::HasValidKey() const\n{\n\treturn m_dwID != 0 || !isnulmd4(m_aucHash);\n}" in source
    assert "if (!deadSource.HasValidKey())\n\t\treturn false;" in source
    assert "if (!deadSource.HasValidKey()) {" in source
    assert "inserting their all-zero key trips MFC's CMap hash" in source
