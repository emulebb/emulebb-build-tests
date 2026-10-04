from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script = REPO_ROOT / "scripts" / "run-rust-vpn-smoke-from-windows.py"
    spec = importlib.util.spec_from_file_location(
        "run_rust_vpn_smoke_from_windows_under_test", script
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_launcher_translates_paths_and_enables_strict_completion(
    monkeypatch, tmp_path: Path
) -> None:
    module = load_module()
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    cargo = output / "builds" / "rust" / "target"
    build_tests = workspace / "repos" / "emulebb-build-tests"
    private = tmp_path / "private"
    build_tests.mkdir(parents=True)
    cargo.mkdir(parents=True)
    private.mkdir()
    archive = output / "image.tar"
    compose = workspace / "compose.yaml"
    override = output / "override.yaml"
    inputs = workspace / "inputs.json"
    for path in (archive, compose, override, inputs):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    report = output / "proofs" / "gluetun.json"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(cargo))
    monkeypatch.setattr(module, "wsl_path", lambda path, _dist: "/wsl/" + path.name)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv) or SimpleNamespace(returncode=0),
    )

    result = module.main(
        [
            "--topology",
            "gluetun",
            "--archive",
            str(archive),
            "--compose",
            str(compose),
            "--compose-override",
            str(override),
            "--private-root",
            str(private),
            "--report",
            str(report),
            "--inputs",
            str(inputs),
            "--image",
            "local/emulebb-rust:test",
            "--expected-executable-sha256",
            "a" * 64,
            "--igd-url",
            "http://10.0.0.1/root.xml",
            "--allow-unsupported-nat",
        ]
    )

    assert result == 0
    command = calls[0]
    assert "EMULEBB_WORKSPACE_ROOT=/wsl/workspace" in command
    assert "EMULEBB_WORKSPACE_OUTPUT_ROOT=/wsl/output" in command
    assert "CARGO_TARGET_DIR=/wsl/target" in command
    assert "scripts/smoke-rust-gluetun.py" in command
    assert "--nat-matrix" in command
    assert "--complete-transfer" in command
    assert "--allow-unsupported-nat" in command
    assert "--compose-override" in command
    evidence = list((output / "reports" / "rust-vpn-smoke-launch").glob("*/wsl-boundary.json"))
    assert len(evidence) == 1
    assert json.loads(evidence[0].read_text(encoding="utf-8"))["exitCode"] == 0
