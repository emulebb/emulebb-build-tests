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
