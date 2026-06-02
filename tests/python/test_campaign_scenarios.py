from __future__ import annotations

import json

from emule_test_harness import campaign_scenarios


def test_reusable_campaign_matrix_defines_local_vm_modes_and_swarm_topology() -> None:
    matrix = campaign_scenarios.build_campaign_scenario_matrix()

    assert matrix["executionModes"] == ["local", "vm"]
    assert matrix["localSwarm"] == {
        "clientProducts": ["emulebb", "amule", "tracing-harness"],
        "tiers": [1, 2, 3],
        "defaultTier": 1,
        "ed2kServerTarget": "win10",
        "vmTargets": ["win10", "win11"],
    }
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
