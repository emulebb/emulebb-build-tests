"""Unit tests for the converged live-wire scenario-matrix pure logic."""

from __future__ import annotations

import pytest

from emule_test_harness import converged_scenarios as cs


def test_scenario_validates_search_method() -> None:
    with pytest.raises(ValueError):
        cs.ConvergedScenario(name="bad", search_method="ftp")


def test_scenario_validates_compression_fixture() -> None:
    with pytest.raises(ValueError):
        cs.ConvergedScenario(name="bad", compression_fixture="gzip")


def test_scenario_validates_name() -> None:
    with pytest.raises(ValueError):
        cs.ConvergedScenario(name="   ")


def test_scenario_none_compression_fixture_is_allowed() -> None:
    scenario = cs.ConvergedScenario(name="ok", compression_fixture=None)
    assert scenario.compression_fixture is None


def test_expects_high_id_flips_with_low_id() -> None:
    assert cs.ConvergedScenario(name="hi").expects_high_id() is True
    assert cs.ConvergedScenario(name="lo", low_id=True).expects_high_id() is False


def test_scenario_summary_shape() -> None:
    summary = cs.ConvergedScenario(
        name="x", search_method=cs.SEARCH_KAD, obfuscation=False, source_exchange=True
    ).summary()
    assert summary["name"] == "x"
    assert summary["searchMethod"] == "kad"
    assert summary["obfuscation"] is False
    assert summary["sourceExchange"] is True
    assert summary["lowId"] is False


def test_default_matrix_covers_required_axes() -> None:
    names = set(cs.list_scenario_names())
    # The required matrix from the task: server/kad search, obf on/off,
    # compression compressible/low, SX2 source-exchange, firewalled LowID.
    assert {
        "ed2k-server-search",
        "kad-search",
        "obfuscation-on",
        "obfuscation-off",
        "compression-compressible",
        "compression-low",
        "source-exchange-sx2",
        "firewalled-lowid",
    } <= names


def test_scenario_catalog_has_unique_names() -> None:
    catalog = cs.scenario_catalog()
    assert len(catalog) == len(cs.DEFAULT_SCENARIOS)


def test_select_scenarios_defaults_to_single_gentle_pass() -> None:
    selected = cs.select_scenarios(None)
    assert len(selected) == 1
    assert selected[0].name == "ed2k-server-search"
    assert cs.select_scenarios([]) == selected


def test_select_scenarios_preserves_order_and_dedupes() -> None:
    selected = cs.select_scenarios(["kad-search", "obfuscation-off", "kad-search"])
    assert [scenario.name for scenario in selected] == ["kad-search", "obfuscation-off"]


def test_select_scenarios_rejects_unknown() -> None:
    with pytest.raises(ValueError) as excinfo:
        cs.select_scenarios(["kad-search", "nope"])
    assert "nope" in str(excinfo.value)


def test_parse_scenarios_arg_variants() -> None:
    assert cs.parse_scenarios_arg(None) is None
    assert cs.parse_scenarios_arg("  ") is None
    assert cs.parse_scenarios_arg("kad-search, obfuscation-off") == ["kad-search", "obfuscation-off"]
    assert cs.parse_scenarios_arg("all") == cs.list_scenario_names()
    # "all" anywhere expands the whole matrix.
    assert cs.parse_scenarios_arg("kad-search,all") == cs.list_scenario_names()


def _matched_result(scenario: cs.ConvergedScenario, **kwargs: object) -> cs.ScenarioResult:
    base = {
        "rust_connected": True,
        "rust_high_id": scenario.expects_high_id(),
        "mfc_connected": True,
        "mfc_high_id": scenario.expects_high_id(),
        "both_traces_captured": True,
        "packet_diff": {"ok": True},
        "diag_diff": {"ok": True},
    }
    base.update(kwargs)
    return cs.ScenarioResult(scenario=scenario, **base)  # type: ignore[arg-type]


def test_packet_verdict_states() -> None:
    scenario = cs.ConvergedScenario(name="s")
    assert _matched_result(scenario).packet_verdict() == "matched"
    assert _matched_result(scenario, packet_diff={"ok": False}).packet_verdict() == "diff"
    assert _matched_result(scenario, both_traces_captured=False).packet_verdict() == "missing-trace"
    assert _matched_result(scenario, error="boom").packet_verdict() == "error"
    assert _matched_result(scenario, packet_diff=None).packet_verdict() == "no-diff"


def test_low_id_expectation() -> None:
    high = cs.ConvergedScenario(name="hi")
    low = cs.ConvergedScenario(name="lo", low_id=True)
    assert _matched_result(high).low_id_observed_as_expected() is True
    # LowID scenario: both clients must NOT be HighID.
    low_ok = cs.ScenarioResult(
        scenario=low,
        rust_connected=True,
        mfc_connected=True,
        rust_high_id=False,
        mfc_high_id=False,
        both_traces_captured=True,
        packet_diff={"ok": True},
    )
    assert low_ok.low_id_observed_as_expected() is True
    low_bad = cs.ScenarioResult(scenario=low, rust_high_id=True, mfc_high_id=True)
    assert low_bad.low_id_observed_as_expected() is False


def test_aggregate_scenario_summary_ok_when_all_matched() -> None:
    scenarios = cs.select_scenarios(["ed2k-server-search", "kad-search"])
    results = [_matched_result(scenario) for scenario in scenarios]
    summary = cs.aggregate_scenario_summary(results)
    assert summary["ok"] is True
    assert summary["scenarioCount"] == 2
    assert summary["verdictCounts"] == {"matched": 2}
    assert len(summary["scenarios"]) == 2


def test_aggregate_scenario_summary_not_ok_on_any_diff() -> None:
    scenarios = cs.select_scenarios(["ed2k-server-search", "kad-search"])
    results = [_matched_result(scenarios[0]), _matched_result(scenarios[1], packet_diff={"ok": False})]
    summary = cs.aggregate_scenario_summary(results)
    assert summary["ok"] is False
    assert summary["verdictCounts"] == {"diff": 1, "matched": 1}


def test_aggregate_scenario_summary_empty_is_not_ok() -> None:
    assert cs.aggregate_scenario_summary([])["ok"] is False
