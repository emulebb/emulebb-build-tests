from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_startup_profile_module():
    """Loads the hyphenated startup-profile script for pure helper tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "startup-profile-scenarios.py"
    spec = importlib.util.spec_from_file_location("startup_profile_scenarios_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["startup_profile_scenarios_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_long_paths_recursive_excludes_persisted_shared_files_stress_fixture(tmp_path: Path) -> None:
    module = load_startup_profile_module()

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
    module = load_startup_profile_module()

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
