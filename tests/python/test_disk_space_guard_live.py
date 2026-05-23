from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "disk-space-guard-live.py"
    spec = importlib.util.spec_from_file_location("disk_space_guard_live_test", script_path)
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


def test_build_guard_transfer_link_validates_hash_and_size() -> None:
    module = load_script_module()

    assert module.build_guard_transfer_link(1024, "ABCDEF1234567890ABCDEF1234567890") == (
        "ed2k://|file|disk-space-guard-live.bin|1024|ABCDEF1234567890ABCDEF1234567890|/"
    )
    with pytest.raises(ValueError):
        module.build_guard_transfer_link(0)
    with pytest.raises(ValueError):
        module.build_guard_transfer_link(1024, "not-a-hash")


def test_disk_space_guard_cases_cover_required_storage_matrix() -> None:
    module = load_script_module()

    cases = module.build_disk_space_guard_cases()

    assert [case.name for case in cases] == [
        "drive-letter-temp-and-incoming",
        "mounted-folder-temp-and-incoming",
        "local-temp-vhd-incoming",
        "vhd-temp-local-incoming",
        "multi-temp-fallback-to-local",
    ]
    assert any(case.temp_role == module.STORAGE_ROLE_VHD_MOUNT for case in cases)
    assert any(case.incoming_role == module.STORAGE_ROLE_VHD_MOUNT for case in cases)
    assert any(case.extra_temp_roles == (module.STORAGE_ROLE_LOCAL,) and not case.expected_rejected for case in cases)


def test_download_queue_temp_selection_reaches_placement_seam_before_rejecting() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid" / "DownloadQueue.cpp"
    source = source_path.read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("CString CDownloadQueue::GetOptimalTempDir") : source.index("void CDownloadQueue::RefilterAllComments")]

    assert "SelectTempDirForProtectedVolumeSnapshot" in block
    assert "IsProtectedVolumeBreached" not in block


def test_case_hash_is_deterministic_unique_hex() -> None:
    module = load_script_module()

    assert module.case_hash(0) == "00000000000000000000000000000001"
    assert module.case_hash(15) == "00000000000000000000000000000010"
    with pytest.raises(ValueError):
        module.case_hash(-1)


def test_guard_result_passes_for_explicit_rejection_and_absent_transfer() -> None:
    module = load_script_module()

    result = module.summarize_guard_result(
        add_result={"status": 507, "json": {"error": "not enough disk space"}, "body_text": ""},
        transfer_lookup={"status": 404, "json": {"error": "not found"}, "body_text": ""},
        logs_result={"status": 200, "json": []},
    )

    assert result["status"] == "passed"
    assert result["rejected"] is True
    assert result["transfer_absent"] is True
    assert result["explicit_reason"] is True


def test_guard_result_fails_when_transfer_is_accepted() -> None:
    module = load_script_module()

    result = module.summarize_guard_result(
        add_result={"status": 200, "json": {"id": "accepted"}, "body_text": ""},
        transfer_lookup={"status": 200, "json": {"hash": "accepted"}, "body_text": ""},
        logs_result={"status": 200, "json": [{"message": "transfer accepted"}]},
    )

    assert result["status"] == "failed"
    assert result["rejected"] is False
    assert result["transfer_absent"] is False
    assert result["errors"]


def test_guard_result_passes_for_expected_fallback_acceptance() -> None:
    module = load_script_module()

    result = module.summarize_guard_result(
        add_result={"status": 200, "json": {"ok": True}, "body_text": ""},
        transfer_lookup={"status": 200, "json": {"hash": "accepted"}, "body_text": ""},
        logs_result={"status": 200, "json": []},
        expected_rejected=False,
    )

    assert result["status"] == "passed"
    assert result["expected_rejected"] is False
    assert result["rejected"] is False
    assert result["transfer_absent"] is False
