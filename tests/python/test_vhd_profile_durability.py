from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "vhd-profile-durability.py"
    spec = importlib.util.spec_from_file_location("vhd_profile_durability_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_missing_required_files_flags_absent_and_empty_files() -> None:
    module = load_script_module()

    states = {
        "ok": {"exists": True, "size_bytes": 5},
        "empty": {"exists": True, "size_bytes": 0},
        "missing": {"exists": False, "size_bytes": 0},
    }

    assert module.missing_required_files(states) == ["empty", "missing"]


def test_file_state_reports_size_and_presence(tmp_path: Path) -> None:
    module = load_script_module()
    path = tmp_path / "preferences.ini"
    path.write_text("profile", encoding="utf-8")

    state = module.file_state(path)

    assert state["exists"] is True
    assert state["size_bytes"] == len("profile")


def test_build_admin_fixture_config_uses_sibling_mount_parent(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "artifacts")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=384, keep_admin_fixtures=False)
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)

    config = module.build_admin_fixture_config(paths, args)

    assert config.vhd_path == tmp_path / "artifacts" / "admin-volumes" / "vhd-profile-durability.vhdx"
    assert config.mount_root == tmp_path / "admin-mounts" / "vhd-profile-durability" / "vhd-profile-durability"
    assert config.size_mb == 384
