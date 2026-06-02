from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from emule_test_harness import campaign_scenarios, release_campaigns, windows_vm_profiles


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


def test_release_campaign_schema_uses_emulebb_namespace() -> None:
    root = repo_root()
    schema = json.loads((root / "manifests" / "release-campaigns" / "v1.schema.json").read_text(encoding="utf-8"))

    assert schema["$id"] == release_campaigns.SCHEMA_VERSION
    assert "emulebb-build-tests" in release_campaigns.SCHEMA_VERSION


def test_default_template_defines_strict_phase_taxonomy() -> None:
    template = release_campaigns.load_release_campaign_template(repo_root())

    assert release_campaigns.validate_release_campaign_template(template) == []
    assert [phase["id"] for phase in template["taxonomy"]["phases"]] == list(release_campaigns.STRICT_PHASE_TAXONOMY)


def test_073_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emulebb-0.7.3")

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
    assert campaign["proofTier"] == "rc-blocking-quick"
    assert set(windows_vm_profiles.WINDOWS_VM_PROFILE_BY_SCENARIO_ID) <= scenario_ids
    installer_scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["id"] == "emulebb.flow.installer.controller-surface.materialized.v1"
    )
    assert installer_scenario["liveE2eProfile"] == "installer-controller-surface"
    assert "emulebb.flow.installer.controller-surface.materialized.v1" in {
        scenario_id
        for gate in campaign["releaseGates"]
        if gate["id"] == "installer-backed-controller-surface"
        for scenario_id in gate["coveredBy"]
    }
    assert "emulebb.flow.windows-vm.hideme.live-wire.v1" in {
        scenario_id
        for gate in campaign["releaseGates"]
        if gate["id"] == "quick-rc-live-proof"
        for scenario_id in gate["coveredBy"]
    }


def test_073_campaign_windows_vm_rows_match_profile_catalog() -> None:
    campaign = release_campaigns.load_release_campaign(repo_root(), "emulebb-0.7.3")
    scenarios = {
        scenario["id"]: scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }

    for spec in windows_vm_profiles.WINDOWS_VM_PROFILE_SPECS:
        scenario = scenarios[spec.scenario_id]
        assert scenario["phase"] == spec.release_phase
        if spec.scenario_id in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_SCENARIO_ID:
            shared = campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_SCENARIO_ID[spec.scenario_id]
            assert scenario["flowCategory"] == "local-vm-swarm"
            assert scenario["command"] == (
                "python -m emule_workspace test campaign-scenario "
                f"--scenario {spec.scenario_id} --mode vm --release-version 0.7.3-rc.1 --skip-build --swarm-tier 1"
            )
            assert scenario["localCommand"] == shared.command_for_mode("local")
            assert scenario["vmCommand"] == shared.command_for_mode("vm", release_version="0.7.3-rc.1")
            assert scenario["command"] == scenario["vmCommand"]
            assert scenario["executionMode"] == "vm"
            assert scenario["executionModes"] == ["local", "vm"]
            assert scenario["localProfile"] == shared.local_profile
            assert scenario["localSuites"] == list(shared.local_suites)
            assert scenario["vmProfile"] == spec.name
        else:
            assert scenario["flowCategory"] == "windows-vm"
            assert f"test windows-vm --matrix {','.join(spec.required_targets)}" in scenario["command"]
            assert f"--profile {spec.name}" in scenario["command"]
        evidence = scenario["evidence"][0]
        assert evidence["glob"] == "test-reports/windows-vm/*/windows-vm-result.json"
        assert evidence["matches"] == {"/profile": spec.name}


def test_073_overnight_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emulebb-0.7.3-overnight")

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
    assert campaign["proofTier"] == "overnight-full"
    assert {phase["id"] for phase in campaign["phases"]} == set(release_campaigns.STRICT_PHASE_TAXONOMY)


def test_p2p_overlord_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "p2p-overlord-0.1.1")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    assert campaign["releaseVersion"] == "0.1.1-rc.1"
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
    assert "emulebb.flow.p2p-overlord.rest.openapi-subset.v1" in scenario_ids
    assert campaign["proofTier"] == "future"


def test_campaign_validation_rejects_missing_proof_tier() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign.pop("proofTier")

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="proofTier"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_warns_for_unmapped_gate() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign["releaseGates"].append({"id": "future-gate", "coveredBy": []})

    warnings = release_campaigns.validate_release_campaign(campaign, template)

    assert warnings == ["Release gate future-gate is not mapped to any feature-flow scenario."]


def test_campaign_validation_rejects_duplicate_scenario_ids() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    duplicate = copy.deepcopy(campaign["phases"][0]["scenarios"][0])
    campaign["phases"][0]["scenarios"].append(duplicate)

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="Duplicate release campaign scenario id"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_unknown_live_e2e_profile() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign["phases"][2]["scenarios"][0]["liveE2eProfile"] = "unknown-profile"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="unknown live E2E profile"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_command_mismatch() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["executionMode"] = "local"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="command must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_catalog_command_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["localCommand"] = f"{scenario['localCommand']} --extra"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="localCommand must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_release_version_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign["releaseVersion"] = "0.7.4-rc.2"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="vmCommand must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_catalog_metadata_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["vmProfile"] = "other-vm-profile"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="vmProfile must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_report_reads_latest_json_status(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    state_root = tmp_path / "state"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    latest = state_root / "test-reports" / "live-e2e-suite" / "latest"
    latest.mkdir(parents=True)
    (latest / "live-e2e-suite-result.json").write_text(
        json.dumps({"status": "passed", "profile": "release-expanded-quick"}),
        encoding="utf-8",
    )
    fast = state_root / "certification" / "20260517-010203-fast"
    fast.mkdir(parents=True)
    (fast / "certification-result.json").write_text(json.dumps({"status": "inconclusive"}), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(
            tests_repo_root=tests_root,
            workspace_state_root=state_root,
        ),
        campaign_id="emulebb-0.7.3",
    )

    scenarios = {scenario["id"]: scenario for scenario in report["scenarios"]}
    assert scenarios["emulebb.flow.certification.fast.matrix.v1"]["status"] == "inconclusive"
    assert scenarios["emulebb.flow.livewire.release-expanded.weak-path.v1"]["status"] == "passed"
    assert scenarios["emulebb.flow.package.core.x64.v1"]["status"] == "missing-evidence"


def test_campaign_report_glob_selects_matching_vm_profile(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    state_root = tmp_path / "state"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    matching = state_root / "test-reports" / "windows-vm" / "20260602T010000Z" / "windows-vm-result.json"
    newer_other = state_root / "test-reports" / "windows-vm" / "20260602T020000Z" / "windows-vm-result.json"
    matching.parent.mkdir(parents=True)
    newer_other.parent.mkdir(parents=True)
    matching.write_text(json.dumps({"status": "passed", "profile": "package-smoke"}), encoding="utf-8")
    newer_other.write_text(json.dumps({"status": "passed", "profile": "hideme-live-wire"}), encoding="utf-8")
    os.utime(matching, (1000, 1000))
    os.utime(newer_other, (2000, 2000))

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(
            tests_repo_root=tests_root,
            workspace_state_root=state_root,
        ),
        campaign_id="emulebb-0.7.3",
        phase_id="packaging-provenance",
    )

    scenario = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["id"] == "emulebb.flow.windows-vm.package-smoke.release.v1"
    )
    assert scenario["status"] == "passed"
    assert scenario["evidence"][0]["path"] == str(matching.resolve())


def test_terminal_report_contains_phase_status_and_warning(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(tests_repo_root=tests_root, workspace_state_root=tmp_path / "state"),
        campaign_id="emulebb-0.7.3",
        phase_id="packaging-provenance",
    )
    text = release_campaigns.format_release_campaign_report(report)

    assert "packaging-provenance" in text
    assert "Proof tier: rc-blocking-quick" in text
    assert "emulebb.flow.package.core.x64.v1" in text
    assert "missing required evidence" in text


def test_terminal_report_shows_local_vm_swarm_commands(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(tests_repo_root=tests_root, workspace_state_root=tmp_path / "state"),
        campaign_id="emulebb-0.7.3",
        phase_id="controller-surface",
    )
    scenario = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["id"] == "emulebb.flow.controller.installer-swarm.v1"
    )
    text = release_campaigns.format_release_campaign_report(report)

    assert "--local-swarm-mode execute" in scenario["vmExecuteCommand"]
    assert scenario["vmPlanCommand"] == scenario["vmCommand"]
    assert "emulebb.flow.controller.installer-swarm.v1" in text
    assert "mode: vm (available: local, vm)" in text
    assert "local command: python -m emule_workspace test campaign-scenario" in text
    assert "vm command: python -m emule_workspace test campaign-scenario" in text
    assert "vm plan command: python -m emule_workspace test campaign-scenario" in text
    assert "vm execute command: python -m emule_workspace test campaign-scenario" in text
    assert "--mode local" in text
    assert "--mode vm" in text
    assert "--local-swarm-mode execute" in text


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
