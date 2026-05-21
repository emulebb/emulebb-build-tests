from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "shared-cache-invalidation.py"
    spec = importlib.util.spec_from_file_location("shared_cache_invalidation_test", script_path)
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


def test_base_and_mutated_shared_fixture_have_expected_shape(tmp_path: Path) -> None:
    module = load_script_module()

    base_summary = module.write_base_shared_fixture(tmp_path)
    mutated_summary = module.mutate_shared_fixture(tmp_path)

    assert base_summary["file_count"] == 3
    assert mutated_summary["file_count"] == 4
    assert (tmp_path / "shared" / "alpha.txt").read_bytes() == module.MUTATED_ALPHA_PAYLOAD
    assert (tmp_path / "shared" / "delta-new.txt").read_bytes() == module.ADDED_DELTA_PAYLOAD


def test_counter_assertions_require_warm_relaunch_to_queue_no_hash_work() -> None:
    module = load_script_module()

    errors = module.assert_counter_state(
        {
            "directories_from_cache": 3,
            "files_queued_for_hash": 1,
            "hash_waiting_queue_depth": 0,
            "hash_currently_hashing": 0,
            "hashing_done_shared_files": 4,
        },
        expected_shared_files=4,
        expect_cache_reuse=True,
        expected_min_queued=0,
        phase="post-mutation-warm-cache-reuse",
    )

    assert errors == ["post-mutation-warm-cache-reuse: expected files_queued_for_hash=0, got 1"]


def test_counter_assertions_allow_mutation_to_reuse_cache_and_queue_changed_files() -> None:
    module = load_script_module()

    errors = module.assert_counter_state(
        {
            "directories_from_cache": 3,
            "files_queued_for_hash": 2,
            "hash_waiting_queue_depth": 0,
            "hash_currently_hashing": 0,
            "hashing_done_shared_files": 4,
        },
        expected_shared_files=4,
        expect_cache_reuse=True,
        expected_min_queued=2,
        phase="mutated-cache-invalidation",
    )

    assert errors == []


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
