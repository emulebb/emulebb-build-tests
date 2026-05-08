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
    assert module.TREE_STRESS_BRANCH_COUNT * module.TREE_STRESS_FILES_PER_BRANCH >= 50000
    assert module.TREE_STRESS_BRANCH_COUNT * module.TREE_STRESS_FILES_PER_BRANCH >= module.TREE_STRESS_MIN_FILE_COUNT


def test_get_rest_shared_file_count_validates_row_shape(monkeypatch) -> None:
    module = load_shared_files_module()

    def fake_http_request(_base_url: str, _path: str, *, api_key: str, request_timeout_seconds: float = 5.0):
        return {
            "status": 200,
            "json": [
                {"name": "alpha.bin"},
                {"name": "beta.bin"},
            ],
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    assert module.get_rest_shared_file_count("http://127.0.0.1:1", "key") == 2


def test_get_rest_shared_file_count_uses_v1_collection_total(monkeypatch) -> None:
    module = load_shared_files_module()

    def fake_http_request(_base_url: str, _path: str, *, api_key: str, request_timeout_seconds: float = 5.0):
        return {
            "status": 200,
            "json": {
                "data": {
                    "items": [{"name": "first.bin"}, {"name": "second.bin"}],
                    "limit": 2,
                    "offset": 0,
                    "total": 50000,
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    assert module.get_rest_shared_file_count("http://127.0.0.1:1", "key") == 50000


def test_get_rest_shared_file_count_uses_unwrapped_collection_total(monkeypatch) -> None:
    module = load_shared_files_module()

    def fake_http_request(_base_url: str, _path: str, *, api_key: str, request_timeout_seconds: float = 5.0):
        return {
            "status": 200,
            "json": {
                "items": [{"name": "first.bin"}, {"name": "second.bin"}],
                "limit": 2,
                "offset": 0,
                "total": 50000,
            },
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    assert module.get_rest_shared_file_count("http://127.0.0.1:1", "key") == 50000


def test_get_rest_shared_file_count_rejects_invalid_rows(monkeypatch) -> None:
    module = load_shared_files_module()

    def fake_http_request(_base_url: str, _path: str, *, api_key: str, request_timeout_seconds: float = 5.0):
        return {"status": 200, "json": [{"name": None}], "body_text": ""}

    monkeypatch.setattr(module, "http_request", fake_http_request)

    try:
        module.get_rest_shared_file_count("http://127.0.0.1:1", "key")
    except RuntimeError as exc:
        assert "Unexpected shared-files REST row shape" in str(exc)
    else:
        raise AssertionError("Expected invalid shared-files REST row shape to fail.")


def test_build_tree_stress_cold_cached_metrics_compares_50k_relaunch() -> None:
    module = load_shared_files_module()

    summary = {
        "initial_row_count_progress": {
            "samples": [
                {"elapsed_seconds": 0.0, "ui_count": 0},
                {"elapsed_seconds": 177.8, "ui_count": 50000},
            ],
        },
        "cached_relaunch_row_count_progress": {
            "samples": [
                {"elapsed_seconds": 0.5, "ui_count": 50000},
            ],
        },
        "initial_rest_row_count": 50000,
        "cached_relaunch_rest_row_count": 50000,
        "first_launch_hashing_done": {"hashing_done_absolute_ms": 194704.1},
        "startup_profile_highlights": {
            "ui.shared_files_ready": {"absolute_ms": 16092.885},
            "Construct CSharedFileList (share cache/scan)": {"duration_ms": 15455.467},
            "CSharedFilesWnd::OnInitDialog total": {"duration_ms": 120.847},
        },
        "cached_relaunch_startup": {
            "startup_profile_highlights": {
                "ui.shared_files_ready": {"absolute_ms": 8022.788},
                "Construct CSharedFileList (share cache/scan)": {"duration_ms": 2216.584},
                "CSharedFilesWnd::OnInitDialog total": {"duration_ms": 3903.437},
            },
        },
        "cached_relaunch_files_queued_for_hash": 0,
        "cached_relaunch_pending_hashes": 0,
        "cached_relaunch_shared_files_after_scan": 50000,
        "shared_cache_size_bytes_after_first_launch": 5006488,
    }

    metrics = module.build_tree_stress_cold_cached_metrics(summary, 50000)

    assert metrics["cold_ui_rows_ready_seconds"] == 177.8
    assert metrics["cached_ui_rows_ready_seconds"] == 0.5
    assert metrics["cold_hashing_done_seconds"] == 194.704
    assert metrics["cached_queue_skip_verified"] is True
    assert metrics["cached_ui_ready_speedup_vs_cold_ui_ready"] == 355.6
    assert metrics["cached_scan_speedup_vs_cold_scan"] == 6.973


def test_evaluate_tree_stress_resources_accepts_r1_deltas() -> None:
    module = load_shared_files_module()

    evaluation = module.evaluate_tree_stress_resources(
        {
            "handles": 18,
            "gdi_objects": 3,
            "user_objects": 2,
            "private_bytes": 12918784,
            "working_set_bytes": 17395712,
        }
    )

    assert evaluation["ok"] is True
    assert evaluation["violations"] == []


def test_evaluate_tree_stress_resources_rejects_unbounded_growth() -> None:
    module = load_shared_files_module()

    evaluation = module.evaluate_tree_stress_resources(
        {
            "handles": 65,
            "gdi_objects": 0,
            "user_objects": 0,
            "private_bytes": 1,
            "working_set_bytes": 1,
        }
    )

    assert evaluation["ok"] is False
    assert evaluation["violations"][0]["resource"] == "handles"
