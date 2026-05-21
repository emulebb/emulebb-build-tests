from __future__ import annotations

from pathlib import Path


def _app_source_root() -> Path:
    workspace_root = Path(__file__).resolve().parents[4]
    return workspace_root / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid"


def test_startup_profile_directory_errors_are_non_modal() -> None:
    preferences = (_app_source_root() / "Preferences.cpp").read_text(encoding="utf-8")
    start = preferences.index("Startup must never block on profile folder errors")
    end = preferences.index("void CPreferences::Uninit", start)
    startup_directory_block = preferences[start:end]

    assert "AfxMessageBox" not in startup_directory_block
    assert "EnsureStartupDirectory" in startup_directory_block
    assert "RecordStartupError" in preferences


def test_startup_directories_use_recursive_long_path_creation() -> None:
    long_path_seams = (_app_source_root() / "LongPathSeams.h").read_text(encoding="utf-8")
    preferences = (_app_source_root() / "Preferences.cpp").read_text(encoding="utf-8")

    assert "bool CreateDirectoryPath(" in long_path_seams
    assert "LongPathSeams::CreateDirectoryPath" in preferences
