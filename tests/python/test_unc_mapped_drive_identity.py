from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "unc-mapped-drive-identity.py"
    spec = importlib.util.spec_from_file_location("unc_mapped_drive_identity_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("win32"):
            pytest.skip(f"pywin32 live harness dependency is unavailable: {exc.name}")
        raise
    return module


def test_build_admin_fixture_config_uses_workspace_sibling_mount_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script_module()
    checked_paths: list[Path] = []
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "state" / "test-artifacts" / "run" / "source-artifacts")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=256, keep_admin_fixtures=False)

    monkeypatch.setattr(module, "reject_windows_temp_path", lambda path, _purpose: checked_paths.append(path))

    config = module.build_admin_fixture_config(paths, args)

    expected_mount_parent = paths.source_artifacts_dir.parent / "admin-mounts" / module.SUITE_NAME
    assert checked_paths == [expected_mount_parent]
    assert config.mount_root == expected_mount_parent / module.SUITE_NAME
    assert config.vhd_path == paths.source_artifacts_dir / "admin-volumes" / f"{module.SUITE_NAME}.vhdx"


def test_create_smb_share_command_grants_current_account() -> None:
    module = load_script_module()

    command = module.create_smb_share_command("EMULEBB_TEST", Path("Z:/share"), "DOMAIN/user")

    assert command[:3] == ["powershell.exe", "-NoProfile", "-Command"]
    assert "New-SmbShare" in command[3]
    assert command[-3:] == ["EMULEBB_TEST", "Z:\\share", "DOMAIN/user"]


def test_assert_warm_cache_reuse_reports_path_class_failures() -> None:
    module = load_script_module()

    errors = module.assert_warm_cache_reuse(
        {
            "startup_diagnostics_counters": {
                "shared.scan.directories_from_cache": {"value": 0},
                "shared.scan.files_queued_for_hash": {"value": 1},
                "shared.model.hashing_done_shared_files": {"value": 2},
            }
        },
        expected_files=3,
        phase="warm-relaunch",
    )

    assert errors == [
        "warm-relaunch: expected directories_from_cache>0, got 0",
        "warm-relaunch: expected files_queued_for_hash=0, got 1",
        "warm-relaunch: expected hashing_done_shared_files=3, got 2",
    ]


def test_classify_path_marks_unc_text_without_windows_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script_module()

    monkeypatch.setattr(module, "get_drive_type", lambda _root: module.DRIVE_REMOTE)
    monkeypatch.setattr(module, "get_volume_guid", lambda _root: None)

    classification = module.classify_path("\\\\localhost\\share\\shared\\")

    assert classification["is_unc"] is True
    assert classification["is_remote_drive"] is True
    assert classification["volume_guid"] is None
