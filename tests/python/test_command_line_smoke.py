from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


def load_smoke_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "command-line-smoke.py"
    spec = importlib.util.spec_from_file_location("command_line_smoke_test_module", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_headless_cases_cover_strict_app_command_line_failures(tmp_path: Path) -> None:
    smoke = load_smoke_module()

    cases = smoke.build_headless_cases(tmp_path)
    case_names = {case.name for case in cases}

    assert case_names == {
        "help",
        "unknown-switch",
        "relative-profile-rejected",
        "partial-cert-generation-rejected",
    }
    assert next(case for case in cases if case.name == "unknown-switch").expected_return_code == 2
    assert next(case for case in cases if case.name == "relative-profile-rejected").arguments[:2] == (
        "-c",
        "relative\\profile",
    )


def test_run_case_fails_on_missing_expected_output(tmp_path: Path, monkeypatch) -> None:
    smoke = load_smoke_module()

    def fake_run(command, capture_output, text, timeout, check):
        assert capture_output is True
        assert text is True
        assert timeout == 20.0
        assert check is False
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="different error")

    monkeypatch.setattr(smoke.subprocess, "run", fake_run)

    result = smoke.run_case(
        tmp_path / "emulebb.exe",
        smoke.CommandLineCase(
            name="unknown-switch",
            arguments=("--unknown",),
            expected_return_code=2,
            stderr_contains=("Unknown command-line switch",),
        ),
    )

    assert result["status"] == "failed"
    assert "stderr did not contain" in result["errors"][0]


def test_certificate_generation_case_requires_output_files(tmp_path: Path, monkeypatch) -> None:
    smoke = load_smoke_module()

    def fake_run(command, capture_output, text, timeout, check):
        cert_path = Path(command[command.index("--cert") + 1])
        key_path = Path(command[command.index("--key") + 1])
        cert_path.write_text("cert", encoding="utf-8")
        key_path.write_text("key", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", fake_run)

    result = smoke.run_certificate_generation_case(tmp_path / "emulebb.exe", tmp_path)

    assert result["status"] == "passed"
    artifacts = result["artifacts"]
    assert artifacts["cert_exists"] is True
    assert artifacts["key_exists"] is True
