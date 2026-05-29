from __future__ import annotations

import json

from emule_test_harness import live_e2e_suite, scenario_matrix


def test_live_e2e_scenario_matrix_covers_every_registered_suite_once() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()

    assert matrix["schema"] == scenario_matrix.SCHEMA
    assert matrix["suiteCount"] == len(live_e2e_suite.SUITE_SPECS)
    assert [suite["name"] for suite in matrix["suites"]] == list(live_e2e_suite.SUITE_NAMES)
    json.dumps(matrix)


def test_live_e2e_scenario_matrix_profiles_reference_known_suites() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    known = set(live_e2e_suite.SUITE_NAMES)

    for profile, suite_names in matrix["profiles"].items():
        assert profile in live_e2e_suite.PROFILE_SUITE_NAMES
        assert set(suite_names) <= known


def test_live_e2e_scenario_matrix_classifies_swarm_and_hammer_lanes() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    by_name = {suite["name"]: suite for suite in matrix["suites"]}

    assert by_name["godzilla-local-swarm"]["topology"] == "large-local-swarm"
    assert by_name["godzilla-local-swarm"]["stressClass"] == "hammer"
    assert by_name["godzilla-local-swarm"]["adminVolumePolicy"] == "required"
    assert by_name["multi-client-p2p-matrix"]["topology"] == "local-swarm"
    assert by_name["local-ed2k-chaos-mode"]["stressClass"] == "chaos"
    assert by_name["rest-cold-start-dump-stress"]["stressClass"] == "stress"


def test_live_e2e_scenario_matrix_surfaces_known_policy_gaps() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    gaps = {(gap["suite"], gap["gap"]) for gap in matrix["gaps"]}

    assert (
        "godzilla-local-swarm",
        "large local swarm hammer is not RC-profile-visible",
    ) in gaps
    assert any(suite == "multi-client-p2p-matrix" for suite, _gap in gaps)
