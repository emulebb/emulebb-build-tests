from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace


def load_suite_module():
    """Loads the hyphenated Rust overnight pytest proof script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "rust-overnight-pytest-proof.py"
    spec = importlib.util.spec_from_file_location("rust_overnight_pytest_proof_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_selected_cases_defaults_to_full_overnight_pytest_set() -> None:
    module = load_suite_module()

    cases = module.selected_cases(None)

    assert [case.case_id for case in cases] == ["local-client", "rest-contract"]


def test_run_pytest_case_invokes_workspace_orchestration(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[dict[str, object]] = []

    def fake_run(command, *, cwd, text, capture_output, check):
        calls.append(
            {
                "command": command,
                "cwd": cwd,
                "text": text,
                "capture_output": capture_output,
                "check": check,
            }
        )
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    report = module.run_pytest_case(module.selected_cases(["rest-contract"])[0], tmp_path / "emulebb-build")

    assert calls == [
        {
            "command": [
                sys.executable,
                "-m",
                "emule_workspace",
                "test",
                "python",
                "--path",
                "..\\emulebb-build-tests\\tests\\python\\test_emulebb_rust_rest_contract.py",
                "--quiet",
            ],
            "cwd": tmp_path / "emulebb-build",
            "text": True,
            "capture_output": True,
            "check": False,
        }
    ]
    assert report["status"] == "passed"
    assert report["evidence"]["pytestPassed"] is True
    assert report["evidence"]["restContractPytestPassed"] is True


def test_requirement_checks_require_both_pytest_cases() -> None:
    module = load_suite_module()
    cases = [
        {"id": case.case_id, "status": "passed", "evidence": {**case.evidence, "pytestPassed": True}}
        for case in module.PYTEST_CASES
    ]

    checks = module.build_requirement_checks(cases)

    assert checks == {
        "caseCount": 2,
        "allCasesPassed": True,
        "localClientPytestPassed": True,
        "restContractPytestPassed": True,
    }


def test_main_writes_report_under_workspace_output_root(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "output"
    build_repo = workspace_root / "repos" / "emulebb-build" / "emule_workspace"
    build_repo.mkdir(parents=True)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", os.fspath(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", os.fspath(output_root))
    monkeypatch.setattr(module, "utc_run_id", lambda: "20260612T010203Z")

    def fake_run_pytest_case(case, build_repo_path):
        return {
            "id": case.case_id,
            "title": case.title,
            "status": "passed",
            "returnCode": 0,
            "command": ["fake"],
            "paths": list(case.paths),
            "evidence": {**case.evidence, "pytestPassed": True},
            "stdoutTail": [],
            "stderrTail": [],
        }

    monkeypatch.setattr(module, "run_pytest_case", fake_run_pytest_case)

    assert module.main([]) == 0

    report_path = (
        output_root
        / "reports"
        / "rust-overnight-pytest-proof"
        / "latest"
        / "rust-overnight-pytest-proof-result.json"
    )
    assert report_path.is_file()
