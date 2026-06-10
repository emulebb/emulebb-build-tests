from __future__ import annotations

from pathlib import Path


def test_fast_harness_ci_checks_out_rust_client_for_contract_tests() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "fast-harness-ci.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "repository: emulebb/emulebb-rust" in text
    assert "path: repos/emulebb-rust" in text
