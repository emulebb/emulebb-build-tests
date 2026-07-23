from __future__ import annotations

from pathlib import Path


def test_fast_harness_ci_checks_out_rust_client_for_contract_tests() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "fast-harness-ci.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "repository: emulebb/emulebb-rust" in text
    assert "path: repos/emulebb-rust" in text


def test_fast_harness_ci_checks_out_app_main_for_source_parity() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "fast-harness-ci.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "repository: emulebb/emulebb\n          ref: main" in text
    assert "path: workspaces/workspace/app/emulebb-main" in text


def test_fast_harness_ci_sets_canonical_cargo_target_dir() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "fast-harness-ci.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "builds\\rust\\target" in text
    assert "CARGO_TARGET_DIR=$cargoTargetDir" in text


def test_fast_harness_ci_runs_rust_openapi_route_drift_check() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "fast-harness-ci.yml"
    text = workflow.read_text(encoding="utf-8")

    assert "Check Rust OpenAPI metadata drift" in text
    assert "python scripts/check-rust-openapi-routes.py" in text
