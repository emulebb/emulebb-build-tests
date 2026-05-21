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


def test_startup_storage_warnings_cover_profile_temp_and_incoming_dirs() -> None:
    emule_cpp = (_app_source_root() / "Emule.cpp").read_text(encoding="utf-8")
    emule_h = (_app_source_root() / "Emule.h").read_text(encoding="utf-8")

    assert "void WarnAboutStartupStoragePlacement();" in emule_h
    assert "void CemuleApp::WarnAboutStartupStoragePlacement()" in emule_cpp
    assert "EMULE_CONFIGDIR" in emule_cpp
    assert "GetTempDirCount()" in emule_cpp
    assert "GetTempDir(i)" in emule_cpp
    assert "EMULE_INCOMINGDIR" in emule_cpp
    assert "LOG_WARNING" in emule_cpp
    assert "storage root %s" in emule_cpp

    flush_call = emule_cpp.index("FlushStartupErrorsToLog();")
    warning_call = emule_cpp.index("WarnAboutStartupStoragePlacement();", flush_call)
    console_handler = emule_cpp.index("SetConsoleCtrlHandler", warning_call)
    assert flush_call < warning_call < console_handler


def test_startup_storage_classifier_maps_network_and_removable_drives() -> None:
    long_path_seams = (_app_source_root() / "LongPathSeams.h").read_text(encoding="utf-8")

    assert "enum class StoragePlacementRisk" in long_path_seams
    assert "StoragePlacementRisk::NetworkShare" in long_path_seams
    assert "StoragePlacementRisk::RemovableDrive" in long_path_seams
    assert "DRIVE_REMOTE" in long_path_seams
    assert "DRIVE_REMOVABLE" in long_path_seams
    assert "GetVolumePathName" in long_path_seams
    assert "GetDriveType" in long_path_seams
