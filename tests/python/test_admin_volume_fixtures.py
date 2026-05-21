from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import admin_volume_fixtures


def test_create_vhd_diskpart_script_assigns_drive_letter_and_mount_root(tmp_path: Path) -> None:
    script = admin_volume_fixtures.build_create_vhd_diskpart_script(
        vhd_path=tmp_path / "fixture.vhdx",
        size_mb=256,
        drive_letter="x:",
        mount_root=tmp_path / "mount",
    )

    assert "create vdisk" in script
    assert "maximum=256" in script
    assert "assign letter=X" in script
    assert "assign mount=" in script
    assert str((tmp_path / "mount").resolve()) in script


def test_cleanup_vhd_diskpart_script_keeps_vhd_when_requested(tmp_path: Path) -> None:
    script = admin_volume_fixtures.build_cleanup_vhd_diskpart_script(
        vhd_path=tmp_path / "fixture.vhdx",
        drive_letter="z",
        mount_root=tmp_path / "mount",
        delete_vdisk=False,
    )

    assert "remove mount=" in script
    assert "remove letter=Z noerr" in script
    assert "detach vdisk noerr" in script
    assert "delete vdisk" not in script


def test_attach_existing_vhd_diskpart_script_reuses_drive_letter_and_mount_root(tmp_path: Path) -> None:
    script = admin_volume_fixtures.build_attach_existing_vhd_diskpart_script(
        vhd_path=tmp_path / "fixture.vhdx",
        drive_letter="y:",
        mount_root=tmp_path / "mount",
    )

    assert "create vdisk" not in script
    assert "select vdisk" in script
    assert "attach vdisk" in script
    assert "select partition 1" in script
    assert "assign letter=Y" in script
    assert str((tmp_path / "mount").resolve()) in script


def test_normalize_drive_letter_accepts_common_forms() -> None:
    assert admin_volume_fixtures.normalize_drive_letter("q") == "Q"
    assert admin_volume_fixtures.normalize_drive_letter("q:\\") == "Q"


def test_normalize_drive_letter_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        admin_volume_fixtures.normalize_drive_letter("share")
    with pytest.raises(ValueError):
        admin_volume_fixtures.normalize_drive_letter("1")


def test_fixture_removes_owned_mount_directory_after_cleanup(tmp_path: Path, monkeypatch) -> None:
    vhd_path = tmp_path / "fixture.vhdx"
    mount_root = tmp_path / "mount"
    local_control_root = tmp_path / "control"
    calls: list[str] = []

    monkeypatch.setattr(admin_volume_fixtures, "require_windows_admin", lambda: None)
    monkeypatch.setattr(admin_volume_fixtures, "find_available_drive_letter", lambda _preferred=None: "Z")
    monkeypatch.setattr(
        admin_volume_fixtures,
        "run_diskpart_script",
        lambda _script, _script_dir: calls.append(str(_script_dir)) or admin_volume_fixtures.CommandResult([], 0, "", ""),
    )
    monkeypatch.setattr(
        admin_volume_fixtures,
        "get_volume_identity",
        lambda root: admin_volume_fixtures.VolumeIdentity(
            root=str(root),
            volume_name=None,
            serial_hex=None,
            file_system=None,
            label=None,
            total_bytes=1,
            free_bytes=1,
        ),
    )

    config = admin_volume_fixtures.AdminVolumeFixtureConfig(
        vhd_path=vhd_path,
        mount_root=mount_root,
        local_control_root=local_control_root,
        size_mb=64,
    )
    with admin_volume_fixtures.create_admin_volume_fixture(config):
        vhd_path.write_bytes(b"vhd")
        assert mount_root.is_dir()

    assert calls == [str(vhd_path.parent / "diskpart-scripts"), str(vhd_path.parent / "diskpart-scripts")]
    assert not vhd_path.exists()
    assert not mount_root.exists()


def test_fixture_keep_preserves_vhd_but_removes_owned_mount_directory(tmp_path: Path, monkeypatch) -> None:
    vhd_path = tmp_path / "fixture.vhdx"
    mount_root = tmp_path / "mount"
    local_control_root = tmp_path / "control"

    monkeypatch.setattr(admin_volume_fixtures, "require_windows_admin", lambda: None)
    monkeypatch.setattr(admin_volume_fixtures, "find_available_drive_letter", lambda _preferred=None: "Z")
    monkeypatch.setattr(
        admin_volume_fixtures,
        "run_diskpart_script",
        lambda _script, _script_dir: admin_volume_fixtures.CommandResult([], 0, "", ""),
    )
    monkeypatch.setattr(
        admin_volume_fixtures,
        "get_volume_identity",
        lambda root: admin_volume_fixtures.VolumeIdentity(
            root=str(root),
            volume_name=None,
            serial_hex=None,
            file_system=None,
            label=None,
            total_bytes=1,
            free_bytes=1,
        ),
    )

    config = admin_volume_fixtures.AdminVolumeFixtureConfig(
        vhd_path=vhd_path,
        mount_root=mount_root,
        local_control_root=local_control_root,
        size_mb=64,
        keep=True,
    )
    with admin_volume_fixtures.create_admin_volume_fixture(config):
        vhd_path.write_bytes(b"vhd")
        assert mount_root.is_dir()

    assert vhd_path.exists()
    assert not mount_root.exists()


def test_diskpart_script_is_written_under_requested_artifact_dir(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(command, *, stdout, stderr, text, check):
        captured["command"] = command
        return type("Completed", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()

    monkeypatch.setattr(admin_volume_fixtures.subprocess, "run", fake_run)
    monkeypatch.setattr(admin_volume_fixtures.time, "time_ns", lambda: 123)
    monkeypatch.setattr(admin_volume_fixtures.os, "getpid", lambda: 456)

    result = admin_volume_fixtures.run_diskpart_script("list volume\n", tmp_path / "scripts")

    assert result.return_code == 0
    assert captured["command"] == ["diskpart.exe", "/s", str(tmp_path / "scripts" / "diskpart-456-123.txt")]
    assert not (tmp_path / "scripts" / "diskpart-456-123.txt").exists()


def test_build_storage_topology_names_local_drive_and_mount_roots(tmp_path: Path) -> None:
    fixture = admin_volume_fixtures.AdminVolumeFixture(
        vhd_path=tmp_path / "fixture.vhdx",
        drive_root=Path("Z:\\"),
        mount_root=tmp_path / "mounted",
        local_control_root=tmp_path / "control",
        drive_identity=admin_volume_fixtures.VolumeIdentity("Z:\\", None, "1", "NTFS", "VHD", 1, 1),
        mount_identity=admin_volume_fixtures.VolumeIdentity(str(tmp_path / "mounted"), None, "1", "NTFS", "VHD", 1, 1),
        local_control_identity=admin_volume_fixtures.VolumeIdentity(str(tmp_path / "control"), None, "2", "NTFS", "LOCAL", 1, 1),
        create_result=admin_volume_fixtures.CommandResult([], 0, "", ""),
    )

    topology = admin_volume_fixtures.build_storage_topology(fixture, "suite")

    assert topology.local_control_root == tmp_path / "control" / "suite"
    assert topology.vhd_drive_root == Path("Z:\\") / "suite"
    assert topology.vhd_mount_root == tmp_path / "mounted" / "suite"
