from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_shared_files_module():
    """Loads the hyphenated shared-files script for pure helper tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "shared-files-ui-e2e.py"
    spec = importlib.util.spec_from_file_location("shared_files_ui_e2e_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["shared_files_ui_e2e_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def load_generated_fixture_module():
    """Loads the hyphenated generated-fixture script for pure helper tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "create-long-paths-tree.py"
    spec = importlib.util.spec_from_file_location("create_long_paths_tree_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["create_long_paths_tree_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_tree_label_matches_drive_accepts_bare_and_volume_labeled_drives() -> None:
    module = load_shared_files_module()

    assert module.tree_label_matches_drive("C:", "C:\\")
    assert module.tree_label_matches_drive("C:\\", "C:\\")
    assert module.tree_label_matches_drive("SYSC (C:)", "C:\\")
    assert module.tree_label_matches_drive("Local Disk (C:)", "C:\\")


def test_tree_label_matches_drive_rejects_other_drives() -> None:
    module = load_shared_files_module()

    assert not module.tree_label_matches_drive("DATA (D:)", "C:\\")
    assert not module.tree_label_matches_drive("C-drive backup", "D:\\")


def test_tree_refresh_stress_fixture_estimate_exceeds_r1_node_floor() -> None:
    module = load_generated_fixture_module()

    assert module.estimate_shared_files_tree_stress_observable_nodes() >= 10000
    assert module.estimate_shared_files_tree_stress_observable_nodes() >= module.TREE_STRESS_MIN_OBSERVABLE_NODES
