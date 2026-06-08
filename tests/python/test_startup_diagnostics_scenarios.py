from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path


def load_startup_diagnostics_module():
    """Loads the hyphenated startup-diagnostics script for pure helper tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "startup-diagnostics-scenarios.py"
    spec = importlib.util.spec_from_file_location("startup_diagnostics_scenarios_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["startup_diagnostics_scenarios_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_long_paths_recursive_excludes_persisted_shared_files_stress_fixture(tmp_path: Path) -> None:
    module = load_startup_diagnostics_module()

    long_path_leaf = tmp_path / "long_path_output" / "deep"
    long_path_leaf.mkdir(parents=True)
    (long_path_leaf / "included.txt").write_text("included", encoding="utf-8")

    persisted_stress_leaf = tmp_path / "shared_files_tree_stress_v2" / "branch"
    persisted_stress_leaf.mkdir(parents=True)
    (persisted_stress_leaf / "excluded.txt").write_text("excluded", encoding="utf-8")

    scenario = module.build_scenario_definition(
        name="long-paths-recursive",
        artifacts_dir=tmp_path / "artifacts",
        shared_root=tmp_path,
    )

    shared_dirs = "\n".join(scenario["shared_dirs"]).lower()
    longest_files = "\n".join(row["path"] for row in scenario["tree_summary"]["longest_files"]).lower()

    assert "shared_files_tree_stress" not in shared_dirs
    assert "shared_files_tree_stress" not in longest_files
    assert scenario["tree_summary"]["file_count"] == 1
    assert scenario["tree_summary"]["shared_directory_count"] == len(scenario["shared_dirs"])


def test_long_paths_root_only_metrics_exclude_persisted_shared_files_stress_fixture(tmp_path: Path) -> None:
    module = load_startup_diagnostics_module()

    long_path_leaf = tmp_path / "long_path_output" / "deep"
    long_path_leaf.mkdir(parents=True)
    (long_path_leaf / "included.txt").write_text("included", encoding="utf-8")

    persisted_stress_leaf = tmp_path / "shared_files_tree_stress_v2" / "branch"
    persisted_stress_leaf.mkdir(parents=True)
    (persisted_stress_leaf / "excluded.txt").write_text("excluded", encoding="utf-8")

    scenario = module.build_scenario_definition(
        name="long-paths-root-only",
        artifacts_dir=tmp_path / "artifacts",
        shared_root=tmp_path,
    )

    longest_files = "\n".join(row["path"] for row in scenario["tree_summary"]["longest_files"]).lower()

    assert scenario["tree_summary"]["shared_directory_count"] == 1
    assert scenario["shared_dirs"] == [module.live_common.win_path(tmp_path, trailing_slash=True)]
    assert "shared_files_tree_stress" not in longest_files
    assert scenario["tree_summary"]["file_count"] == 1


def test_wait_for_shared_cache_requires_known_met_records(tmp_path: Path) -> None:
    module = load_startup_diagnostics_module()

    shared_cache = tmp_path / "sharedcache.dat"
    known_met = tmp_path / "known.met"
    shared_cache.write_bytes(b"cache")
    known_met.write_bytes(b"\x0e" + struct.pack("<I", 2))

    ready = module.wait_for_shared_cache(shared_cache, expected_known_records=2, timeout=0.1)

    assert ready["shared_cache"]["size"] == 5
    assert ready["known_met_record_count"] == 2


def test_wait_for_shared_cache_rejects_incomplete_known_met(tmp_path: Path) -> None:
    module = load_startup_diagnostics_module()

    shared_cache = tmp_path / "sharedcache.dat"
    known_met = tmp_path / "known.met"
    shared_cache.write_bytes(b"cache")
    known_met.write_bytes(b"\x0e" + struct.pack("<I", 1))

    try:
        module.wait_for_shared_cache(shared_cache, expected_known_records=2, timeout=0.01)
    except RuntimeError as exc:
        assert "known_met_record_count" in str(exc)
    else:
        raise AssertionError("Expected incomplete known.met to fail the warm cache gate.")


def test_wait_for_shared_cache_can_require_rest_idle_clean(tmp_path: Path, monkeypatch) -> None:
    module = load_startup_diagnostics_module()

    shared_cache = tmp_path / "sharedcache.dat"
    known_met = tmp_path / "known.met"
    shared_cache.write_bytes(b"cache")
    known_met.write_bytes(b"\x0e" + struct.pack("<I", 2))
    status = {
        "available": True,
        "ready": True,
        "hashingCount": 0,
        "deferredHashingActive": False,
        "interruptedHashingInvalidatedCache": False,
        "save": {
            "running": False,
            "dirty": False,
            "phase": "idle",
        },
    }
    monkeypatch.setattr(module, "get_rest_shared_startup_cache_status", lambda _base_url, _api_key: status)

    ready = module.wait_for_shared_cache(
        shared_cache,
        expected_known_records=2,
        base_url="http://127.0.0.1:1",
        api_key="test",
        require_rest_status=True,
        timeout=0.1,
    )

    assert ready["shared_startup_cache"] == status
