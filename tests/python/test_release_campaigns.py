from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from emule_test_harness import release_campaigns


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_release_campaign_manifests_match_json_schema() -> None:
    root = repo_root()
    schema = json.loads((root / "manifests" / "release-campaigns" / "v1.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    for path in sorted((root / "manifests" / "release-campaigns").glob("*.json")):
        if path.name.endswith(".schema.json"):
            continue
        validator.validate(json.loads(path.read_text(encoding="utf-8")))


def test_default_template_defines_strict_phase_taxonomy() -> None:
    template = release_campaigns.load_release_campaign_template(repo_root())

    assert release_campaigns.validate_release_campaign_template(template) == []
    assert [phase["id"] for phase in template["taxonomy"]["phases"]] == list(release_campaigns.STRICT_PHASE_TAXONOMY)


def test_073_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emule-bb-0.7.3")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    scenario_ids = {
        scenario["id"]
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }
    covered_ids = {
        scenario_id
        for gate in campaign["releaseGates"]
        for scenario_id in gate["coveredBy"]
    }
    assert covered_ids <= scenario_ids
    assert {phase["id"] for phase in campaign["phases"]} == set(release_campaigns.STRICT_PHASE_TAXONOMY)


def test_campaign_validation_warns_for_unmapped_gate() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emule-bb-0.7.3"))
    campaign["releaseGates"].append({"id": "future-gate", "coveredBy": []})

    warnings = release_campaigns.validate_release_campaign(campaign, template)

    assert warnings == ["Release gate future-gate is not mapped to any feature-flow scenario."]


def test_campaign_validation_rejects_duplicate_scenario_ids() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emule-bb-0.7.3"))
    duplicate = copy.deepcopy(campaign["phases"][0]["scenarios"][0])
    campaign["phases"][0]["scenarios"].append(duplicate)

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="Duplicate release campaign scenario id"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_unknown_live_e2e_profile() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emule-bb-0.7.3"))
    campaign["phases"][2]["scenarios"][0]["liveE2eProfile"] = "unknown-profile"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="unknown live E2E profile"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_report_reads_latest_json_status(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    state_root = tmp_path / "state"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    latest = tests_root / "reports" / "live-e2e-suite-latest"
    latest.mkdir(parents=True)
    (latest / "result.json").write_text(json.dumps({"status": "passed", "profile": "release-expanded"}), encoding="utf-8")
    fast = state_root / "certification" / "20260517-010203-fast"
    fast.mkdir(parents=True)
    (fast / "result.json").write_text(json.dumps({"status": "inconclusive"}), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(
            tests_repo_root=tests_root,
            workspace_state_root=state_root,
        ),
        campaign_id="emule-bb-0.7.3",
    )

    scenarios = {scenario["id"]: scenario for scenario in report["scenarios"]}
    assert scenarios["emulebb.flow.certification.fast.matrix.v1"]["status"] == "inconclusive"
    assert scenarios["emulebb.flow.livewire.release-expanded.weak-path.v1"]["status"] == "passed"
    assert scenarios["emulebb.flow.package.core.x64.v1"]["status"] == "missing-evidence"


def test_terminal_report_contains_phase_status_and_warning(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(tests_repo_root=tests_root, workspace_state_root=tmp_path / "state"),
        campaign_id="emule-bb-0.7.3",
        phase_id="packaging-provenance",
    )
    text = release_campaigns.format_release_campaign_report(report)

    assert "packaging-provenance" in text
    assert "emulebb.flow.package.core.x64.v1" in text
    assert "missing required evidence" in text


def test_operator_script_help_loads() -> None:
    completed = subprocess.run(
        [sys.executable, str(repo_root() / "scripts" / "show-release-campaigns.py"), "--help"],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--campaign" in completed.stdout
    assert "--json" in completed.stdout
