from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_known_file_hash_creation_rejects_missing_inputs() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert source.index('#include "EmuleMD4.h"') < source.index('#include "Kademlia/Kademlia/SearchManager.h"')
    assert "ROUND(static_cast<float>(uUserRatings) / static_cast<float>(uRatings))" in source
    assert "static_cast<double>(statistic.GetTransferred()) / static_cast<double>(nFileSize)" in source
    assert "static_cast<double>(statistic.GetAllTimeTransferred()) / static_cast<double>(nFileSize)" in source
    assert "ASSERT(pBlockAICHHashTree != NULL);\n\t\t\tif (pBlockAICHHashTree == NULL) {\n\t\t\t\tfclose(file);\n\t\t\t\treturn false;\n\t\t\t}" in source
    assert "ASSERT(pBlockAICHHashTree != NULL);\n\t\tif (pBlockAICHHashTree == NULL) {\n\t\t\tfclose(file);\n\t\t\treturn false;\n\t\t}" in source
    assert "ASSERT(!Length || pFile);\n\tASSERT(pMd4HashOut != NULL || pShaHashOut != NULL);\n\tif ((Length != 0 && pFile == NULL) || (pMd4HashOut == NULL && pShaHashOut == NULL))\n\t\treturn false;" in source
    assert "ASSERT(uSize == 0 || fp != NULL);\n\tif (uSize != 0 && fp == NULL)\n\t\treturn false;" in source
    assert "ASSERT(uSize == 0 || pucData != NULL);\n\tif (uSize != 0 && pucData == NULL)\n\t\treturn false;" in source
