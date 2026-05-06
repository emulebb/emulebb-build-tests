from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


def load_harness_cli_common_module():
    """Loads the hyphenated harness CLI helper for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "harness-cli-common.py"
    spec = importlib.util.spec_from_file_location("harness_cli_common_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["harness_cli_common_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_publish_directory_snapshot_skips_generated_shared_hash_payloads(tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    scenario = source / "scenario"
    payload_dir = scenario / "shared-hash-root" / "branch"
    payload_dir.mkdir(parents=True)
    (payload_dir / "large-payload.bin").write_bytes(b"x" * 1024)
    (scenario / "result.json").write_text("{}", encoding="utf-8")
    (source / "suite-result.json").write_text("{}", encoding="utf-8")

    module.publish_directory_snapshot(source, destination)

    assert (destination / "suite-result.json").is_file()
    assert (destination / "scenario" / "result.json").is_file()
    assert not (destination / "scenario" / "shared-hash-root").exists()


def test_publish_directory_snapshot_preserves_exact_trailing_dot_space_names(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("exact Win32 trailing dot/space names require Windows extended-length paths")

    module = load_harness_cli_common_module()
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    exact_dir = Path(str(source / "exact-dir") + ". ")
    exact_file = exact_dir / "payload. "
    os.makedirs(module.to_windows_extended_path(exact_dir), exist_ok=True)
    with open(module.to_windows_extended_path(exact_file), "wb") as handle:
        handle.write(b"exact")

    module.publish_directory_snapshot(source, destination)

    copied_file = Path(str(destination / "exact-dir") + ". ") / "payload. "
    assert os.path.exists(module.to_windows_extended_path(copied_file))
    with open(module.to_windows_extended_path(copied_file), "rb") as handle:
        assert handle.read() == b"exact"


def test_cleanup_source_artifacts_leaves_locked_temp_payloads(monkeypatch, tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    source = tmp_path / "source"
    source.mkdir()

    attempts = {"count": 0}

    def fake_rmtree(_path: Path) -> None:
        attempts["count"] += 1
        raise PermissionError("locked")

    ticks = iter([0.0, 0.1, 10.1])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(module.shutil, "rmtree", fake_rmtree)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    paths = module.HarnessRunPaths(
        repo_root=tmp_path,
        workspace_root=tmp_path,
        app_root=tmp_path,
        app_exe=tmp_path / "emule.exe",
        seed_config_dir=tmp_path,
        configuration="Release",
        suite_name="locked-cleanup",
        source_artifacts_dir=source,
        run_report_dir=tmp_path / "reports" / "run",
        latest_report_dir=tmp_path / "reports" / "latest",
        keep_source_artifacts=False,
    )

    module.cleanup_source_artifacts(paths)

    assert attempts["count"] > 0
