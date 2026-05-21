from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def load_suite_module():
    """Loads the hyphenated local ED2K chaos script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-ed2k-chaos-mode.py"
    spec = importlib.util.spec_from_file_location("local_ed2k_chaos_mode_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_chaos_defaults_use_132_mib_and_optional_admin_volumes() -> None:
    module = load_suite_module()
    args = module.build_parser().parse_args([])

    assert args.p2p_bind_interface_name == ""
    assert args.fixture_size_bytes == 132 * 1024 * 1024
    assert args.admin_volume_fixtures is False
    assert args.vhd_size_mb == module.MIN_ADMIN_VHD_SIZE_MB
    assert args.rest_ready_timeout_seconds == 240.0


def test_path_layout_without_vhd_stays_under_source_artifacts(tmp_path: Path) -> None:
    module = load_suite_module()
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "run")

    layout = module.path_layout(paths, None)

    assert layout == {
        "initial_temp": tmp_path / "run" / "client1-storage" / "initial-temp",
        "initial_incoming": tmp_path / "run" / "client1-storage" / "initial-incoming",
        "churned_temp": tmp_path / "run" / "client1-storage" / "churned-temp",
        "churned_incoming": tmp_path / "run" / "client1-storage" / "churned-incoming",
    }


def test_corrupt_config_metadata_writes_expected_met_files(tmp_path: Path) -> None:
    module = load_suite_module()

    rows = module.corrupt_config_metadata(tmp_path)

    assert [Path(row["path"]).name for row in rows] == list(module.CORRUPT_CONFIG_FILES)
    assert all(Path(row["path"]).is_file() for row in rows)
    assert all(Path(row["path"]).read_bytes().startswith(b"\xE0\xFFcorrupt-local-ed2k-chaos") for row in rows)


def test_stale_corrupt_part_metadata_targets_old_temp_dir(tmp_path: Path) -> None:
    module = load_suite_module()

    rows = module.write_stale_corrupt_part_metadata(tmp_path / "old-temp")

    assert [Path(row["path"]).name for row in rows] == ["001.part.met", "001.part.met.bak"]
    assert all(Path(row["path"]).parent == tmp_path / "old-temp" for row in rows)


def test_admin_fixture_config_enforces_minimum_vhd_size(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "artifacts")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=256, keep_admin_fixtures=False)

    config = module.build_admin_fixture_config(paths, args)

    assert config.vhd_path == tmp_path / "artifacts" / "admin-volumes" / "local-ed2k-chaos-mode.vhdx"
    assert config.size_mb == module.MIN_ADMIN_VHD_SIZE_MB
