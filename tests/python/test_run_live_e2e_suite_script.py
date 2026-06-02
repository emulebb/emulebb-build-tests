from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_runner_module():
    """Loads the hyphenated live E2E runner script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "run-live-e2e-suite.py"
    spec = importlib.util.spec_from_file_location("run_live_e2e_suite_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_main_returns_success_for_planned_summary(monkeypatch) -> None:
    module = load_runner_module()

    monkeypatch.setattr(module.live_e2e_suite, "run_live_e2e_suite", lambda _args, _common: {"status": "planned"})
    monkeypatch.setattr(sys, "argv", ["run-live-e2e-suite.py", "--plan-only"])

    assert module.main() == 0


def test_main_returns_failure_for_failed_summary(monkeypatch) -> None:
    module = load_runner_module()

    monkeypatch.setattr(module.live_e2e_suite, "run_live_e2e_suite", lambda _args, _common: {"status": "failed"})
    monkeypatch.setattr(sys, "argv", ["run-live-e2e-suite.py"])

    assert module.main() == 1
