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


def test_normalize_drive_letter_accepts_common_forms() -> None:
    assert admin_volume_fixtures.normalize_drive_letter("q") == "Q"
    assert admin_volume_fixtures.normalize_drive_letter("q:\\") == "Q"


def test_normalize_drive_letter_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        admin_volume_fixtures.normalize_drive_letter("share")
    with pytest.raises(ValueError):
        admin_volume_fixtures.normalize_drive_letter("1")
