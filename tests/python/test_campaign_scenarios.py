from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import campaign_scenarios, live_e2e_suite


def test_reusable_campaign_matrix_defines_local_vm_modes_and_swarm_topology() -> None:
    matrix = campaign_scenarios.build_campaign_scenario_matrix()

    assert matrix["executionModes"] == ["local", "vm"]
    assert matrix["vmLocalSwarmModes"] == ["plan", "execute"]
    assert matrix["networkContracts"] == {
        "controlBindScopes": ["lan"],
        "p2pModes": ["local-swarm", "live-wire"],
        "p2pBindScopes": ["lan", "hide.me"],
    }
    assert matrix["scenarios"][0]["localTestNetwork"] == "default"
    assert matrix["scenarios"][0]["localAllowedNetworkScopes"] == ["offline", "lan"]
    assert matrix["localSwarm"] == {
        "clientProducts": ["emulebb", "amule", "tracing-harness"],
        "tiers": [1, 2, 3],
        "defaultTier": 1,
        "tierOptions": campaign_scenarios.LOCAL_SWARM_TIER_OPTIONS,
        "ed2kServerTarget": "win10",
        "vmTargets": ["win10", "win11"],
    }
    assert matrix["localSwarm"]["tierOptions"][1]["stage"] == "launch-scale"
    assert matrix["localSwarm"]["tierOptions"][3]["adverse_kill_cycles"] == 2
    assert matrix["scenarioCount"] == 6
    json.dumps(matrix)


def test_reusable_campaigns_are_local_lan_scenarios_not_live_wire() -> None:
    matrix = campaign_scenarios.build_campaign_scenario_matrix()
    scenarios = {scenario["key"]: scenario for scenario in matrix["scenarios"]}

    assert set(scenarios) == {
        "installer-controller-surface",
        "amutorrent-clean-startup",
        "amutorrent-emulebb-ui",
        "arr-local-acquisition",
        "prowlarr-controller-handoff",
        "search-ui-local-swarm",
    }
    for scenario in scenarios.values():
        assert scenario["networkScope"] == "lan"
        assert scenario["executionModes"] == ["local", "vm"]
        assert "--local-swarm-mode plan" in scenario["localPlanCommand"]
        assert "--local-swarm-mode execute" in scenario["localExecuteCommand"]
        assert "--local-swarm-mode plan" in scenario["vmPlanCommand"]
        assert "--dry-run" in scenario["localPlanCommand"]
        assert "--dry-run" not in scenario["localExecuteCommand"]
        assert "--local-swarm-mode execute" in scenario["vmExecuteCommand"]
        assert scenario["localTestNetwork"] == "default"
        assert scenario["localAllowedNetworkScopes"] == ["offline", "lan"]
        assert scenario["usesLocalSwarm"] is True
        assert scenario["liveWire"] is False
        assert scenario["controlBindScope"] == "lan"
        assert scenario["amutorrentBindScope"] == "lan"
        assert scenario["p2pMode"] == "local-swarm"
        assert scenario["p2pBindScope"] == "lan"
        assert scenario["localSuites"]

    assert scenarios["search-ui-local-swarm"]["releasePhase"] == "ui-resource-depth"
    assert scenarios["search-ui-local-swarm"]["localSuites"] == [
        "local-ed2k-search-soak",
        "local-kad-swarm",
    ]
    assert scenarios["amutorrent-clean-startup"]["localSuites"] == [
        "amutorrent-local-ed2k-ui-live",
    ]
    assert scenarios["installer-controller-surface"]["localSuites"] == [
        "command-line-smoke",
        "amutorrent-browser-smoke",
        "package-helper-integration",
    ]
    assert scenarios["prowlarr-controller-handoff"]["localSuites"] == [
        "package-helper-integration",
    ]
    assert scenarios["arr-local-acquisition"]["localSuites"] == [
        "radarr-emulebb-local",
        "sonarr-emulebb-local",
    ]


def test_reusable_campaign_suites_stay_local_and_deterministic() -> None:
    suite_by_name = {spec.name: spec for spec in live_e2e_suite.SUITE_SPECS}
    allowed_scopes = set(campaign_scenarios.LOCAL_CAMPAIGN_ALLOWED_NETWORK_SCOPES)

    for scenario in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIOS:
        suites = list(scenario.local_suites)
        if scenario.uses_local_swarm:
            suites.append("godzilla-local-swarm")
        for suite_name in suites:
            suite = suite_by_name[suite_name]
            assert suite.network_scope in allowed_scopes, (scenario.key, suite.name, suite.network_scope)
            assert suite.uses_live_seed_refresh is False, (scenario.key, suite.name)
            assert suite.category != "live-wire", (scenario.key, suite.name)


class CampaignPlanHarnessCliCommon:
    def __init__(self, root: Path) -> None:
        self.root = root

    def prepare_run_paths(self, **kwargs):
        source_artifacts_dir = Path(kwargs["artifacts_dir"]).resolve()
        source_artifacts_dir.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            repo_root=self.root,
            workspace_root=Path(kwargs["workspace_root"]).resolve(),
            app_root=Path(kwargs["app_root"]).resolve(),
            app_exe=Path(kwargs["app_exe"]).resolve(),
            seed_config_dir=None,
            configuration=kwargs["configuration"],
            suite_name=kwargs["suite_name"],
            source_artifacts_dir=source_artifacts_dir,
            run_report_dir=self.root / "reports" / kwargs["suite_name"] / "run",
            latest_report_dir=self.root / "reports" / kwargs["suite_name"] / "latest",
            keep_source_artifacts=True,
            local_dumps={"dump_folder": str(source_artifacts_dir / "crash-dumps"), "image_names": ["emulebb.exe"]},
        )

    def find_python_executable(self) -> str:
        return "python"

    def write_json_file(self, path: Path, payload) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def publish_run_artifacts(self, paths) -> None:
        paths.run_report_dir.mkdir(parents=True, exist_ok=True)

    def publish_latest_report(self, paths) -> None:
        paths.latest_report_dir.mkdir(parents=True, exist_ok=True)

    def cleanup_source_artifacts(self, _paths) -> None:
        return None

    def collect_local_dump_files(self, _local_dumps):
        return {"count": 0, "files": []}


def test_all_reusable_campaign_local_modes_plan_declared_local_suites(tmp_path: Path) -> None:
    script_by_suite = {spec.name: spec.script_name for spec in live_e2e_suite.SUITE_SPECS}
    tier_options = campaign_scenarios.LOCAL_SWARM_TIER_OPTIONS[1]
    workspace_root = tmp_path / "workspace"
    app_root = workspace_root / "app" / "emulebb-main"
    app_exe = app_root / "srchybrid" / "x64" / "Release" / "emulebb.exe"
    app_exe.parent.mkdir(parents=True)
    app_exe.write_text("", encoding="utf-8")

    for scenario in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIOS:
        suites = list(scenario.local_suites)
        if scenario.uses_local_swarm and "godzilla-local-swarm" not in suites:
            suites.append("godzilla-local-swarm")
        argv = [
            "--workspace-root",
            str(workspace_root),
            "--app-root",
            str(app_root),
            "--app-exe",
            str(app_exe),
            "--artifacts-dir",
            str(tmp_path / "artifacts" / scenario.key),
            "--profile",
            scenario.local_profile,
            "--test-network",
            scenario.local_test_network,
            "--admin-volume-fixtures",
            "--plan-only",
            "--godzilla-stage",
            str(tier_options["stage"]),
            "--godzilla-total-client-count",
            str(tier_options["total_client_count"]),
            "--godzilla-peer-transfer-count",
            str(tier_options["peer_transfer_count"]),
            "--godzilla-harness-transfer-count",
            str(tier_options["harness_transfer_count"]),
            "--godzilla-emulebb-files",
            str(tier_options["emulebb_files"]),
            "--godzilla-extra-emulebb-files",
            str(tier_options["extra_emulebb_files"]),
            "--godzilla-harness-files",
            str(tier_options["harness_files"]),
            "--godzilla-amule-files",
            str(tier_options["amule_files"]),
            "--godzilla-adverse-kill-cycles",
            str(tier_options["adverse_kill_cycles"]),
            "--godzilla-adverse-kill-warmup-seconds",
            str(tier_options["adverse_kill_warmup_seconds"]),
            "--godzilla-adverse-recovery-timeout-seconds",
            str(tier_options["adverse_recovery_timeout_seconds"]),
        ]
        for suite in suites:
            argv.extend(["--suite", suite])

        args = live_e2e_suite.build_parser().parse_args(argv)
        summary = live_e2e_suite.run_live_e2e_suite(args, CampaignPlanHarnessCliCommon(tmp_path))
        planned_suites = summary["suites"]
        command_names = {Path(row["command"][1]).name for row in planned_suites}

        assert summary["status"] == "planned", scenario.key
        assert set(row["name"] for row in planned_suites) == set(suites)
        assert command_names == {script_by_suite[suite] for suite in suites}


def test_reusable_campaign_specs_build_local_and_vm_commands() -> None:
    for scenario in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIOS:
        local_command = scenario.command_for_mode("local", swarm_tier=2)
        assert local_command == (
            "python -m emule_workspace test campaign-scenario "
            f"--scenario {scenario.scenario_id} --mode local --swarm-tier 2 --local-swarm-mode execute"
        )

        local_plan_command = scenario.command_for_mode("local", swarm_tier=2, dry_run=True)
        assert local_plan_command == (
            "python -m emule_workspace test campaign-scenario "
            f"--scenario {scenario.scenario_id} --mode local --swarm-tier 2 --local-swarm-mode plan --dry-run"
        )

        explicit_local_plan_command = scenario.command_for_mode("local", swarm_tier=2, local_swarm_mode="plan")
        assert explicit_local_plan_command == (
            "python -m emule_workspace test campaign-scenario "
            f"--scenario {scenario.scenario_id} --mode local --swarm-tier 2 --local-swarm-mode plan --dry-run"
        )

        vm_plan_command = scenario.command_for_mode(
            "vm",
            release_version="0.7.4-rc.2",
            swarm_tier=3,
            local_swarm_mode="plan",
        )
        assert vm_plan_command == (
            "python -m emule_workspace test campaign-scenario "
            f"--scenario {scenario.scenario_id} --mode vm "
            "--release-version 0.7.4-rc.2 --skip-build --swarm-tier 3 --local-swarm-mode plan --dry-run"
        )

        vm_execute_command = scenario.command_for_mode(
            "vm",
            release_version="0.7.4-rc.2",
            swarm_tier=3,
            local_swarm_mode="execute",
        )
        assert vm_execute_command == (
            "python -m emule_workspace test campaign-scenario "
            f"--scenario {scenario.scenario_id} --mode vm "
            "--release-version 0.7.4-rc.2 --skip-build --swarm-tier 3 --local-swarm-mode execute"
        )

        matrix_row = scenario.as_matrix_row()
        assert matrix_row["localCommand"] == scenario.command_for_mode("local")
        assert matrix_row["localPlanCommand"] == scenario.command_for_mode("local", dry_run=True)
        assert matrix_row["localExecuteCommand"] == scenario.command_for_mode("local")
        assert matrix_row["vmCommand"] == scenario.command_for_mode("vm")
        assert matrix_row["vmPlanCommand"] == scenario.command_for_mode("vm", local_swarm_mode="plan")
        assert matrix_row["vmExecuteCommand"] == scenario.command_for_mode("vm", local_swarm_mode="execute")
        assert matrix_row["controlBindScope"] == scenario.control_bind_scope
        assert matrix_row["amutorrentBindScope"] == scenario.amutorrent_bind_scope
        assert matrix_row["p2pMode"] == scenario.p2p_mode
        assert matrix_row["p2pBindScope"] == scenario.p2p_bind_scope


def test_reusable_campaign_specs_reject_unsupported_command_options() -> None:
    scenario = campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_KEY["search-ui-local-swarm"]

    with pytest.raises(ValueError, match="execution mode"):
        scenario.command_for_mode("remote")
    with pytest.raises(ValueError, match="swarm tier"):
        scenario.command_for_mode("local", swarm_tier=99)
    with pytest.raises(ValueError, match="local swarm mode"):
        scenario.command_for_mode("vm", local_swarm_mode="remote")


def test_reusable_campaign_specs_reject_invalid_network_contracts() -> None:
    base = campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_KEY["search-ui-local-swarm"]

    with pytest.raises(ValueError, match="Local-swarm P2P"):
        campaign_scenarios.CampaignScenarioSpec(
            key="bad-local",
            title="Bad local",
            release_phase=base.release_phase,
            network_scope=base.network_scope,
            local_profile=base.local_profile,
            local_suites=base.local_suites,
            vm_profile="bad-local-vm",
            scenario_id="emulebb.flow.bad.local.v1",
            uses_local_swarm=True,
            p2p_mode="local-swarm",
            p2p_bind_scope="hide.me",
        )

    with pytest.raises(ValueError, match="Live-wire P2P"):
        campaign_scenarios.CampaignScenarioSpec(
            key="bad-live",
            title="Bad live",
            release_phase=base.release_phase,
            network_scope=base.network_scope,
            local_profile=base.local_profile,
            local_suites=base.local_suites,
            vm_profile="bad-live-vm",
            scenario_id="emulebb.flow.bad.live.v1",
            p2p_mode="live-wire",
            p2p_bind_scope="lan",
        )
