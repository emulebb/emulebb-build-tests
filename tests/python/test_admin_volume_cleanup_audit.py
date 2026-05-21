from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "admin-volume-cleanup-audit.py"
    spec = importlib.util.spec_from_file_location("admin_volume_cleanup_audit_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_transient_path_detection_catches_workspace_artifacts() -> None:
    module = load_script_module()

    assert module.is_transient_harness_path(r"C:\repo\workspaces\workspace\state\test-artifacts\suite\crash-dumps")
    assert module.is_transient_harness_path(r"C:\repo\repos\eMule-build-tests\reports\old\crash-dumps")
    assert not module.is_transient_harness_path(r"C:\Users\operator\Documents\eMuleDumps")


def test_fixture_cleanup_audit_flags_leftover_paths(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()

    drive_root = tmp_path / "Z-drive"
    drive_root.mkdir()
    mount_root = tmp_path / "mount"
    mount_root.mkdir()
    vhd_path = tmp_path / "admin-volumes" / "fixture.vhdx"
    vhd_path.parent.mkdir()
    vhd_path.write_bytes(b"vhd")
    monkeypatch.setattr(module, "volume_mount_point_present", lambda path: path == mount_root)
    monkeypatch.setattr(module, "query_disk_image", lambda path: {"checked": True, "attached": True})

    result = module.audit_fixture_cleanup(
        vhd_path=vhd_path,
        drive_root=drive_root,
        mount_root=mount_root,
        keep_vhd=False,
    )

    assert result["status"] == "failed"
    assert set(result["errors"]) == {
        "drive_letter_removed",
        "mount_point_removed",
        "vhd_file_removed_or_kept_by_policy",
        "vhd_not_attached",
    }


def test_admin_artifact_tree_audit_fails_for_unexpected_vhd_and_scripts(tmp_path: Path) -> None:
    module = load_script_module()

    admin_volumes = tmp_path / "suite" / "admin-volumes"
    scripts = admin_volumes / "diskpart-scripts"
    scripts.mkdir(parents=True)
    (admin_volumes / "left.vhdx").write_bytes(b"vhd")
    (scripts / "diskpart-1.txt").write_text("select vdisk", encoding="utf-8")

    result = module.audit_admin_artifact_tree(tmp_path, keep_vhd=False)

    assert result["status"] == "failed"
    assert result["errors"] == ["unexpected_vhd_files", "diskpart_scripts_left"]


def test_query_disk_image_passes_image_path_to_powershell(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    vhd_path = tmp_path / "fixture.vhdx"
    calls: list[list[str]] = []
    monkeypatch.setattr(module.os, "name", "nt")

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='{"ImagePath":"fixture.vhdx","Attached":false}', stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = module.query_disk_image(vhd_path)

    assert result["attached"] is False
    assert calls
    assert "param([string]$ImagePath)" in calls[0][3]
    assert calls[0][4] == str(vhd_path)
