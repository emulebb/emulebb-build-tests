from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

from emule_test_harness.admin_volume_fixtures import AdminVolumeFixture, CommandResult, VolumeIdentity


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "vhd-profile-isolation.py"
    spec = importlib.util.spec_from_file_location("vhd_profile_isolation_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def volume(root: Path) -> VolumeIdentity:
    return VolumeIdentity(
        root=str(root),
        volume_name=None,
        serial_hex="ABCDEF01",
        file_system="NTFS",
        label="EMULEBB_TEST",
        total_bytes=1024,
        free_bytes=512,
    )


def fixture(tmp_path: Path) -> AdminVolumeFixture:
    drive_root = tmp_path / "drive"
    mount_root = tmp_path / "mount"
    local_root = tmp_path / "local"
    for root in (drive_root, mount_root, local_root):
        root.mkdir()
    return AdminVolumeFixture(
        vhd_path=tmp_path / "fixture.vhdx",
        drive_root=drive_root,
        mount_root=mount_root,
        local_control_root=local_root,
        drive_identity=volume(drive_root),
        mount_identity=volume(mount_root),
        local_control_identity=volume(local_root),
        create_result=CommandResult(command=[], return_code=0, stdout="", stderr=""),
    )


def test_profile_isolation_cases_cover_vhd_drive_and_mount() -> None:
    module = load_script_module()

    cases = module.build_profile_isolation_cases()

    assert [case.name for case in cases] == ["profile-on-vhd-drive-letter", "profile-on-vhd-folder-mount"]
    assert [case.profile_role for case in cases] == [module.PROFILE_ROLE_VHD_DRIVE, module.PROFILE_ROLE_VHD_MOUNT]


def test_profile_role_root_returns_suite_scoped_vhd_roots(tmp_path: Path) -> None:
    module = load_script_module()
    admin_fixture = fixture(tmp_path)

    assert module.profile_role_root(admin_fixture, module.PROFILE_ROLE_VHD_DRIVE) == (
        admin_fixture.drive_root / "vhd-profile-isolation"
    )
    assert module.profile_role_root(admin_fixture, module.PROFILE_ROLE_VHD_MOUNT) == (
        admin_fixture.mount_root / "vhd-profile-isolation"
    )


def test_profile_path_isolation_reports_escaped_paths(tmp_path: Path) -> None:
    module = load_script_module()
    root = tmp_path / "vhd"
    root.mkdir()
    inside = root / "profile" / "config"
    inside.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    rows = [
        {"name": "inside", "path": str(inside), "exists": True},
        {"name": "outside", "path": str(outside), "exists": True},
    ]

    assert module.assert_profile_paths_isolated(rows, root) == ["outside"]


def test_build_admin_fixture_config_stays_under_source_artifacts(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "artifacts")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=320, keep_admin_fixtures=False)
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)

    config = module.build_admin_fixture_config(paths, args)

    assert config.vhd_path == tmp_path / "artifacts" / "admin-volumes" / "vhd-profile-isolation.vhdx"
    assert config.mount_root == tmp_path / "admin-mounts" / "vhd-profile-isolation" / "vhd-profile-isolation"
    assert config.local_control_root == tmp_path / "artifacts" / "local-control-volume"
    assert config.size_mb == 320
