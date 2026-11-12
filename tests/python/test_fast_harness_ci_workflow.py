from __future__ import annotations

import json
from pathlib import Path

import yaml


def test_fast_harness_ci_checks_out_rust_client_for_contract_tests() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "fast-harness-ci.yml"
    )
    text = workflow.read_text(encoding="utf-8")

    assert "repository: emulebb/emulebb-rust" in text
    assert "path: repos/emulebb-rust" in text
    # The shared fixture writer requires the accepted schema-68 AICH authority
    # columns. Pin the delivered canonical source, not an older schema snapshot.
    workflow_data = yaml.safe_load(text)
    checkout = next(step["with"] for step in workflow_data["jobs"]["python-harness"]["steps"]
                    if step.get("with", {}).get("repository") == "emulebb/emulebb-rust")
    assert checkout["ref"] == "080a5dea70186da31dab958757b5b8c0fd883f82"


def test_fast_harness_ci_checks_out_app_main_for_source_parity() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "fast-harness-ci.yml"
    )
    text = workflow.read_text(encoding="utf-8")

    assert "repository: emulebb/emulebb\n          ref: main" in text
    assert "path: workspaces/workspace/app/emulebb-main" in text


def test_fast_harness_ci_materializes_pinned_protocol_authorities() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load(
        (repo_root / ".github" / "workflows" / "fast-harness-ci.yml").read_text(
            encoding="utf-8"
        )
    )
    catalog = json.loads(
        (repo_root / "manifests" / "protocol-parity-catalog.json").read_text(
            encoding="utf-8"
        )
    )
    authorities = {
        authority["authorityId"]: authority for authority in catalog["authorities"]
    }
    checkout_by_path = {
        step["with"]["path"]: step["with"]
        for step in workflow["jobs"]["python-harness"]["steps"]
        if step.get("uses") == "actions/checkout@v7" and "path" in step.get("with", {})
    }
    expected_repositories = {
        "stock-source": "irwir/eMule",
        "stock-instrumented": "emulebb/emulebb",
        "ed2k-server-dependency": "emulebb/ed2k-server",
        "amule-stable": "amule-org/amule",
        "amule-head": "amule-org/amule",
    }

    for authority_id, repository in expected_repositories.items():
        authority = authorities[authority_id]
        checkout = checkout_by_path[authority["path"]]
        assert checkout["repository"] == repository
        assert checkout["ref"] == authority["revision"]


def test_fast_harness_ci_sets_canonical_cargo_target_dir() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "fast-harness-ci.yml"
    )
    text = workflow.read_text(encoding="utf-8")

    assert "builds\\rust\\target" in text
    assert "CARGO_TARGET_DIR=$cargoTargetDir" in text


def test_fast_harness_ci_runs_rust_openapi_route_drift_check() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "fast-harness-ci.yml"
    )
    text = workflow.read_text(encoding="utf-8")

    assert "Check Rust OpenAPI metadata drift" in text
    assert "python scripts/check-rust-openapi-routes.py" in text
