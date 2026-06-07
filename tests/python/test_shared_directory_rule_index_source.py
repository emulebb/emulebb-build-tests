from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_shared_directory_ops_owns_rule_index_and_key_helpers() -> None:
    header = (app_source_root() / "SharedDirectoryOps.h").read_text(encoding="utf-8", errors="ignore")

    assert "inline std::wstring MakeSharedDirectoryLookupKeyW" in header
    assert "struct SharedDirectoryRuleEntry" in header
    assert "struct SharedDirectoryRuleIndex" in header
    assert "LongPathSeams::FileSystemObjectIdentity identity" in header
    assert "bool ContainsEquivalentDirectoryObject" in header
    assert "bool HasDescendant" in header
    assert "bool RemovePathsWithinDirectory" in header
    assert "bDuplicateIdentity" in header
    assert "mounted folders and equivalent Win32 spellings" in header


def test_preferences_tree_uses_shared_directory_rule_index() -> None:
    header = (app_source_root() / "DirectoryTreeCtrl.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "DirectoryTreeCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert '#include "SharedDirectoryOps.h"' in header
    assert "SharedDirectoryOps::SharedDirectoryRuleIndex m_sharedDirectoryIndex;" in header
    assert "m_sharedDirectoryIndex.Rebuild(m_lstShared);" in source
    assert "m_sharedDirectoryIndex.HasDescendant(strDir);" in source
    assert "MakeSharedDirectoryLoadKey" not in source
    assert "m_sortedSharedDirectoryKeys" not in header
    assert "m_sortedSharedDirectoryKeys" not in source


def test_shared_files_tree_uses_shared_directory_rule_index() -> None:
    header = (app_source_root() / "SharedDirsTreeCtrl.h").read_text(encoding="utf-8", errors="ignore")
    source = (app_source_root() / "SharedDirsTreeCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert '#include "SharedDirectoryOps.h"' in header
    assert "SharedDirectoryOps::SharedDirectoryRuleIndex m_sharedDirectoryIndex;" in header
    assert "return SharedDirectoryOps::MakeSharedDirectoryLookupKey(rstrPath);" in source
    assert "m_sharedDirectoryIndex.Rebuild(m_strliSharedDirs);" in source
    assert "m_sharedDirectoryIndex.ContainsExactPathKey(strDir);" in source
    assert "m_sharedDirectoryIndex.HasDescendant(strDir);" in source
    assert "m_mapSharedDirectoryKeys" not in header
    assert "m_aSortedSharedDirectoryKeys" not in header


def test_preferences_directory_keys_delegate_to_shared_directory_ops() -> None:
    source = (app_source_root() / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("std::wstring MakeDirectoryListLookupKey") : source.index("bool IsStaleStartupConfigDefaultIncomingPath")]

    assert "return SharedDirectoryOps::MakeSharedDirectoryLookupKeyW(rstrDirectory);" in block
    assert "SharedDirectoryOps::IsDirectoryKeyParentOfCandidate" in source
