from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script_path = REPO_ROOT / "scripts" / "rust-rest-openapi-ci.py"
    spec = importlib.util.spec_from_file_location("rust_rest_openapi_ci_for_tests", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_staged_executable_uses_host_suffix(tmp_path: Path) -> None:
    module = load_module()

    expected = "emulebb-rust.exe" if os.name == "nt" else "emulebb-rust"
    assert module.staged_executable(tmp_path) == tmp_path / "tools" / "emulebb-rust" / "bin" / expected


def test_api_key_meets_daemon_production_validation() -> None:
    module = load_module()

    assert len(module.API_KEY.encode("utf-8")) >= 32
    assert module.API_KEY.isascii()
    assert module.API_KEY.isprintable()
    assert not any(character.isspace() for character in module.API_KEY)


def test_source_revision_prefers_ci_revision(tmp_path: Path, monkeypatch) -> None:
    module = load_module()
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)

    assert module.source_revision(tmp_path) == "a" * 40


def test_main_rejects_nonpositive_ready_timeout() -> None:
    module = load_module()

    try:
        module.main(["--ready-timeout-seconds", "0"])
    except ValueError as exc:
        assert "must be positive" in str(exc)
    else:
        raise AssertionError("expected nonpositive timeout rejection")


def test_main_passes_explicit_sources(tmp_path, monkeypatch):
    module = load_module()
    rust, contract = tmp_path / "emulebb-rust", tmp_path / "REST-API-OPENAPI.yaml"
    observed = {}
    def campaign(**kwargs):
        observed.update(kwargs)
        return {"status": "passed", "teardown": "not-started"}, tmp_path / "report.json"
    monkeypatch.setattr(module, "run_campaign", campaign)
    assert module.main(["--rust-repo", str(rust), "--openapi-contract", str(contract)]) == 0
    assert observed["rust_repo"] == rust
    assert observed["openapi_contract"] == contract


def test_explicit_source_outside_workspace_fails_before_launch(tmp_path, monkeypatch):
    import pytest
    module = load_module()
    monkeypatch.setattr(module, "get_required_emule_workspace_root", lambda: tmp_path / "workspace")
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: tmp_path / "output")
    with pytest.raises(RuntimeError, match="workspace source boundaries"):
        module.run_campaign(rust_repo=tmp_path / "outside")
