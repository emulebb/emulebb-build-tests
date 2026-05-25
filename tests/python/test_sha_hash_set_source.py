from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_aich_recovery_hash_set_rejects_missing_owner_and_bad_part_ranges() -> None:
    source = (app_source_root() / "SHAHashSet.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "rResult.RemoveAll();\n\tif (m_pOwner == NULL)\n\t\treturn false;" in source
    assert "if (m_pOwner == NULL || !m_pOwner->IsPartFile())\n\t\treturn NULL;" in source
    assert "const uint64 uFileSize = static_cast<uint64>(m_pOwner->GetFileSize());" in source
    assert "const uint64 nPartStartPos = static_cast<uint64>(nPart) * PARTSIZE;\n\tif (nPartStartPos >= uFileSize)\n\t\treturn NULL;" in source
    assert "ASSERT(phtResult != NULL);\n\tif (phtResult == NULL)\n\t\treturn NULL;" in source
    assert "ASSERT(m_pOwner);\n\tif (m_pOwner == NULL)\n\t\treturn false;" in source
    assert "if (nPartStartPos >= uFileSize)\n\t\treturn false;" in source
