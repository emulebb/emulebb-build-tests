from __future__ import annotations

import json

from emule_test_harness import live_e2e_suite, scenario_matrix


def test_live_e2e_scenario_matrix_covers_every_registered_suite_once() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()

    assert matrix["schema"] == scenario_matrix.SCHEMA
    assert matrix["suiteCount"] == len(live_e2e_suite.SUITE_SPECS)
    assert [suite["name"] for suite in matrix["suites"]] == list(live_e2e_suite.SUITE_NAMES)
    assert matrix["rollups"]["profileVisibleCount"] == sum(
        1 for suite in matrix["suites"] if suite["profiles"]
    )
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
    assert by_name["godzilla-local-swarm"]["profiles"] == ("release-expanded", "stabilization-stress")
    assert by_name["godzilla-local-swarm"]["profileStages"] == {
        "release-expanded": live_e2e_suite.RELEASE_EXPANDED_GODZILLA_STAGE,
        "stabilization-stress": live_e2e_suite.RELEASE_EXPANDED_GODZILLA_STAGE,
    }
    assert "mixed-client-readiness-evidence" in by_name["godzilla-local-swarm"]["diagnostics"]
    assert by_name["multi-client-p2p-matrix"]["topology"] == "local-swarm"
    assert by_name["multi-client-p2p-matrix"]["optionalClientPolicy"] == "mixed-clients-optional-with-required-control"
    assert "multi-client-p2p-required" in by_name["multi-client-p2p-matrix"]["profiles"]
    assert by_name["local-kad-mixed-client-swarm"]["optionalClientPolicy"] == "mixed-clients-required"
    assert by_name["local-ed2k-chaos-mode"]["stressClass"] == "chaos"
    assert by_name["rest-cold-start-dump-stress"]["stressClass"] == "stress"


def test_live_e2e_scenario_matrix_surfaces_known_policy_gaps() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    gaps = {(gap["suite"], gap["gap"]) for gap in matrix["gaps"]}

    assert (
        "godzilla-local-swarm",
        "large local swarm hammer is not RC-profile-visible",
    ) not in gaps
    assert (
        "godzilla-local-swarm",
        "large local swarm hammer is release-expanded only, not stabilization-stress visible",
    ) not in gaps
    assert not any(suite == "multi-client-p2p-matrix" for suite, _gap in gaps)
    assert not any(suite == "godzilla-local-swarm" for suite, _gap in gaps)
    assert not any(suite == "local-kad-mixed-client-swarm" for suite, _gap in gaps)
    assert (
        "live-process-monitor",
        "suite is neither default-enabled nor profile-visible",
    ) not in gaps
    assert not any(gap == "default aggregate only; no named profile owns this suite" for _suite, gap in gaps)


def test_live_e2e_scenario_matrix_reports_rollups_and_repetitions() -> None:
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    repetitions = {row["suite"]: row for row in matrix["repetitions"]}

    assert matrix["rollups"]["byStressClass"]["hammer"] == 1
    assert matrix["rollups"]["byTopology"]["local-swarm"] >= 3
    assert repetitions["rest-api"]["classification"] == "quick-and-full-release-overlap"
    assert repetitions["shared-directories-rest"]["profileCount"] >= 4
    assert "controller-local" in matrix["profiles"]
    assert matrix["profiles"]["installer-controller-surface"] == list(live_e2e_suite.PROFILE_SUITE_NAMES[
        "installer-controller-surface"
    ])
    assert "diagnostics-soak" in matrix["profiles"]
