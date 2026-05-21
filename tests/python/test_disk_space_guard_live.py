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
