from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "vhd-partfile-recovery.py"
    spec = importlib.util.spec_from_file_location("vhd_partfile_recovery_test", script_path)
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


def test_build_recovery_transfer_link_validates_inputs() -> None:
    module = load_script_module()

    assert module.build_recovery_transfer_link(1024, "ABCDEF1234567890ABCDEF1234567890") == (
        "ed2k://|file|vhd-partfile-recovery.bin|1024|ABCDEF1234567890ABCDEF1234567890|/"
    )
    with pytest.raises(ValueError):
        module.build_recovery_transfer_link(0)
    with pytest.raises(ValueError):
        module.build_recovery_transfer_link(1024, "not-a-hash")


def test_part_metadata_paths_returns_sorted_part_met_files(tmp_path: Path) -> None:
    module = load_script_module()

    (tmp_path / "002.part.met").write_text("b", encoding="utf-8")
    (tmp_path / "001.part.met").write_text("a", encoding="utf-8")
    (tmp_path / "001.part").write_text("data", encoding="utf-8")

    assert module.part_metadata_paths(tmp_path) == [
        str(tmp_path / "001.part.met"),
        str(tmp_path / "002.part.met"),
    ]


def test_missing_temp_directory_dialog_matcher_requires_specific_error() -> None:
    module = load_script_module()

    assert module.is_missing_temp_directory_dialog(
        "eMule",
        'Failed to create Temporary Files directory "Z:\\vhd-partfile-recovery\\temp\\" - The system cannot find the path specified.',
    )
    assert not module.is_missing_temp_directory_dialog("eMule", "Some unrelated startup warning")


def test_missing_temp_startup_log_helpers_use_profile_log_dir(tmp_path: Path) -> None:
    module = load_script_module()
    log_path = tmp_path / "logs" / "emulebb-startup-errors.log"
    log_path.parent.mkdir()
    log_path.write_text(
        '2026-05-23 16:25:38 Failed to create Temporary Files directory "Z:\\vhd-partfile-recovery\\temp\\" - The system cannot find the path specified.\n',
        encoding="utf-8",
    )

    assert module.startup_error_log_path(tmp_path) == log_path
    assert module.is_missing_temp_directory_dialog("eMule", module.read_startup_error_log(tmp_path))


def test_build_admin_fixture_config_defaults_to_large_vhd_and_sibling_mount(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_script_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "artifacts" / "vhd-partfile-recovery")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=6144, keep_admin_fixtures=False)

    config = module.build_admin_fixture_config(paths, args)

    assert config.vhd_path == paths.source_artifacts_dir / "admin-volumes" / "vhd-partfile-recovery.vhdx"
    assert config.mount_root == tmp_path / "artifacts" / "admin-mounts" / "vhd-partfile-recovery" / "vhd-partfile-recovery"
    assert config.local_control_root == paths.source_artifacts_dir / "local-control-volume"
    assert config.size_mb == 6144


def test_build_admin_fixture_config_enforces_minimum_vhd_size(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_script_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "artifacts")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=256, keep_admin_fixtures=False)

    config = module.build_admin_fixture_config(paths, args)

    assert config.size_mb == module.MIN_VHD_SIZE_MB
