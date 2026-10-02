from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script = REPO_ROOT / "scripts" / "package-rust-linux-from-windows.py"
    spec = importlib.util.spec_from_file_location("package_rust_linux_from_windows_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_launcher_translates_inherited_operator_state(monkeypatch, tmp_path: Path) -> None:
    module = load_module()
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    build_repo = workspace / "repos" / "emulebb-build"
    cargo = output / "builds" / "rust" / "target"
    tool = output / "tools" / "appimagetool.AppImage"
    build_repo.mkdir(parents=True)
    cargo.mkdir(parents=True)
    tool.parent.mkdir(parents=True, exist_ok=True)
    tool.write_bytes(b"tool")
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(cargo))
    monkeypatch.setattr(module, "wsl_path", lambda path, _distribution: "/wsl/" + path.name)
    calls = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or SimpleNamespace(returncode=0),
    )

    result = module.main(
        [
            "--release-version",
            "0.1.0-beta.2",
            "--appimagetool",
            str(tool),
            "--skip-build",
        ]
    )

    assert result == 0
    command = calls[0][0]
    assert "EMULEBB_WORKSPACE_ROOT=/wsl/workspace" in command
    assert "EMULEBB_WORKSPACE_OUTPUT_ROOT=/wsl/output" in command
    assert "CARGO_TARGET_DIR=/wsl/target-wsl" in command
    assert "--skip-build" in command
    reports = list((output / "reports" / "rust-linux-package-launch").glob("*/wsl-boundary.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text(encoding="utf-8"))["exitCode"] == 0
