from __future__ import annotations

import json

from emule_test_harness import windows_vm_profiles
from emule_test_harness.campaign_scenarios import REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE


def test_windows_vm_profile_matrix_is_the_profile_authority() -> None:
    matrix = windows_vm_profiles.build_windows_vm_profile_matrix()
    profiles = {profile["name"]: profile for profile in matrix["profiles"]}

    assert tuple(profiles) == windows_vm_profiles.SUPPORTED_TEST_PROFILES
    assert profiles["package-smoke"]["networkScope"] == "offline"
    assert profiles["package-smoke"]["releasePhase"] == "packaging-provenance"
    assert profiles["package-smoke"]["requiredTargets"] == ["win10", "win11"]
    assert profiles["local-ed2k-transfer"]["networkScope"] == "lan"
    assert profiles["local-ed2k-transfer"]["releasePhase"] == "protocol-parity"
    assert profiles["hideme-live-wire"]["networkScope"] == "vpn"
    assert profiles["hideme-live-wire"]["releasePhase"] == "live-wire-release"
    assert profiles["rest-smoke-stress"]["networkScope"] == "offline"
    assert profiles["rest-smoke-stress"]["releasePhase"] == "controller-surface"
    assert profiles["crash-dump-smoke"]["releasePhase"] == "stabilization-stress"
    assert profiles["cpu-heavy-quick"]["releasePhase"] == "stabilization-stress"
    assert profiles["resource-ui-smoke"]["releasePhase"] == "ui-resource-depth"
    assert profiles["release-expanded-ui"]["releasePhase"] == "live-wire-release"
    assert profiles["package-helper-install"]["releasePhase"] == "packaging-provenance"
    assert profiles["vhd-profile-isolation"]["releasePhase"] == "stabilization-stress"
    assert profiles["shared-cache-filesystem"]["releasePhase"] == "ui-resource-depth"
    assert profiles["diagnostics-local-dumps"]["releasePhase"] == "stabilization-stress"
    assert profiles["ui-shared-files-depth"]["releasePhase"] == "ui-resource-depth"
    for profile_name, scenario in REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE.items():
        profile = profiles[profile_name]
        assert profile["networkScope"] == "lan"
        assert profile["releasePhase"] == scenario.release_phase
        assert profile["requiredTargets"] == ["win10", "win11"]
        assert profile["executionModes"] == ["local", "vm"]
        assert profile["localProfile"] == scenario.local_profile
        assert profile["localSuites"] == list(scenario.local_suites)
        assert profile["usesLocalSwarm"] is True
        assert profile["controlBindScope"] == scenario.control_bind_scope == "lan"
        assert profile["amutorrentBindScope"] == scenario.amutorrent_bind_scope == "lan"
        assert profile["p2pMode"] == scenario.p2p_mode == "local-swarm"
        assert profile["p2pBindScope"] == scenario.p2p_bind_scope == "lan"
        assert profile["scenarioId"] == scenario.scenario_id
    json.dumps(matrix)
