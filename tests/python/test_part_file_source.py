from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_part_file_set_file_size_keeps_base_size_update_without_aich_set() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(m_pAICHRecoveryHashSet != NULL);\n\tif (m_pAICHRecoveryHashSet != NULL)\n\t\tm_pAICHRecoveryHashSet->SetFileSize(nFileSize);\n\tCKnownFile::SetFileSize(nFileSize);" in source


def test_part_file_defines_md4_policy_before_kad_headers() -> None:
    source = (app_source_root() / "PartFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.index('#include "EmuleMD4.h"') < source.index('#include "Kademlia/Kademlia/Kademlia.h"')
