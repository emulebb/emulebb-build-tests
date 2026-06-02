from __future__ import annotations

import json

from emule_test_harness import campaign_scenarios, live_e2e_suite


def test_reusable_campaign_matrix_defines_local_vm_modes_and_swarm_topology() -> None:
    matrix = campaign_scenarios.build_campaign_scenario_matrix()

    assert matrix["executionModes"] == ["local", "vm"]
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
    assert matrix["scenarioCount"] == 5
    json.dumps(matrix)


def test_reusable_campaigns_are_local_lan_scenarios_not_live_wire() -> None:
    matrix = campaign_scenarios.build_campaign_scenario_matrix()
    scenarios = {scenario["key"]: scenario for scenario in matrix["scenarios"]}

    assert set(scenarios) == {
        "installer-controller-surface",
        "amutorrent-clean-startup",
        "amutorrent-emulebb-ui",
        "prowlarr-controller-handoff",
        "search-ui-local-swarm",
    }
    for scenario in scenarios.values():
        assert scenario["networkScope"] == "lan"
        assert scenario["executionModes"] == ["local", "vm"]
        assert scenario["localTestNetwork"] == "default"
        assert scenario["localAllowedNetworkScopes"] == ["offline", "lan"]
        assert scenario["usesLocalSwarm"] is True
        assert scenario["liveWire"] is False
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


def test_reusable_campaign_specs_build_local_and_vm_commands() -> None:
    scenarios = campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_KEY

    local_command = scenarios["search-ui-local-swarm"].command_for_mode("local")
    assert local_command == (
        "python -m emule_workspace test campaign-scenario "
        "--scenario emulebb.flow.ui.search.local-swarm.v1 --mode local --swarm-tier 1"
    )

    vm_command = scenarios["search-ui-local-swarm"].command_for_mode("vm", release_version="0.7.4-rc.2")
    assert vm_command == (
        "python -m emule_workspace test campaign-scenario "
        "--scenario emulebb.flow.ui.search.local-swarm.v1 --mode vm "
        "--release-version 0.7.4-rc.2 --skip-build --swarm-tier 1"
    )
