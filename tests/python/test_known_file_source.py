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


def test_known_file_hash_creation_checks_short_reads_in_release_builds() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CKnownFile::CreateHash(CFile *pFile") : source.index("bool CKnownFile::CreateHash(FILE *fp")]

    assert "VERIFY(pFile->Read(X, uRead) == uRead);" not in block
    assert "std::unique_ptr<CAICHHashAlgo> pHashAlg" in block
    assert "const UINT uActualRead = pFile->Read(X, uRead);" in block
    assert "if (uActualRead != uRead)\n\t\t\tAfxThrowFileException(CFileException::endOfFile, 0, pFile->GetFilePath());" in block
    assert "static_assert(kHashReadBufferBytes < EMBLOCKSIZE" in block
    assert "pShaHashOut->SetBlockHash(EMBLOCKSIZE, posCurrentEMBlock, pHashAlg.get());" in block


def test_known_file_hash_wrappers_log_exception_details() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogWarning(_T("CreateHash failed while reading stdio-backed data%s"), (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("CreateHash failed while reading memory-backed data%s"), (LPCTSTR)CExceptionStrDash(*ex));' in source


def test_known_file_metadata_extractors_log_exception_details() -> None:
    source = (app_source_root() / "KnownFile.cpp").read_text(encoding="utf-8", errors="ignore")

    assert 'DebugLogWarning(_T("Unhandled exception while extracting file meta data through MediaInfo.dll from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting built-in file meta data from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting fallback media metadata from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting MP3 file meta data from \\"%s\\"%s"), (LPCTSTR)strFullPath, (LPCTSTR)CExceptionStrDash(*ex));' in source
    assert 'DebugLogWarning(_T("Unhandled exception while extracting file meta data through MediaInfo.dll from \\"%s\\" - unexpected exception"), (LPCTSTR)strFullPath);' in source
