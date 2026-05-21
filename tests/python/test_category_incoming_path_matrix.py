from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "category-incoming-path-matrix.py"
    spec = importlib.util.spec_from_file_location("category_incoming_path_matrix_test", script_path)
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


def test_category_incoming_cases_cover_vhd_paths_and_selectors() -> None:
    module = load_script_module()

    cases = module.build_category_incoming_cases()

    assert [case.name for case in cases] == [
        "category-drive-incoming-by-id",
        "category-mount-incoming-by-id",
        "category-drive-incoming-by-name",
        "same-vhd-drive-temp-mount-category",
        "local-category-control-by-name",
    ]
    assert any(case.category_incoming_role == module.STORAGE_ROLE_VHD_DRIVE for case in cases)
    assert any(case.category_incoming_role == module.STORAGE_ROLE_VHD_MOUNT for case in cases)
    assert {case.selector for case in cases} == {module.CATEGORY_SELECTOR_ID, module.CATEGORY_SELECTOR_NAME}
    assert any(
        not case.expected_rejected
        and case.temp_role == module.STORAGE_ROLE_LOCAL
        and case.category_incoming_role == module.STORAGE_ROLE_LOCAL
        for case in cases
    )


def test_category_selector_payload_uses_exactly_one_selector() -> None:
    module = load_script_module()

    assert module.category_selector_payload(module.CATEGORY_SELECTOR_ID, 7, "Movies") == {"categoryId": 7}
    assert module.category_selector_payload(module.CATEGORY_SELECTOR_NAME, 7, "Movies") == {"categoryName": "Movies"}
    with pytest.raises(ValueError):
        module.category_selector_payload("both", 7, "Movies")


def test_find_category_row_matches_by_id_or_name() -> None:
    module = load_script_module()

    rows = [
        {"id": 1, "name": "Alpha", "path": "C:/incoming/a"},
        {"id": 2, "name": "Beta", "path": "C:/incoming/b"},
    ]

    assert module.find_category_row(rows, 2, "Missing") == rows[1]
    assert module.find_category_row(rows, 99, "Alpha") == rows[0]
    assert module.find_category_row(rows, 99, "Missing") is None


def test_build_admin_fixture_config_uses_sibling_mount_parent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_script_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)

    class Paths:
        source_artifacts_dir = tmp_path / "artifacts" / "category-incoming-path-matrix"

    class Args:
        mount_root = None
        vhd_size_mb = 384
        keep_admin_fixtures = False

    config = module.build_admin_fixture_config(Paths(), Args())

    assert config.vhd_path == Paths.source_artifacts_dir / "admin-volumes" / "category-incoming-path-matrix.vhdx"
    assert config.mount_root == tmp_path / "artifacts" / "admin-mounts" / "category-incoming-path-matrix" / "category-incoming-path-matrix"
    assert config.local_control_root == Paths.source_artifacts_dir / "local-control-volume"
    assert config.size_mb == 384
