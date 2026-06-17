from __future__ import annotations

from emule_test_harness import live_e2e_suite, test_inventory


def test_inventory_has_all_three_layers() -> None:
    inv = test_inventory.build_test_inventory()

    assert inv["schema"] == test_inventory.SCHEMA
    assert set(inv["layers"]) == {"native", "pythonHarness", "liveE2e"}


def test_native_layer_classifies_tier_and_dormant_suites() -> None:
    inv = test_inventory.build_test_inventory()
    suites = {s["suite"]: s for s in inv["layers"]["native"]["suites"]}

    # The three suites the tiers actually run are present and labeled test-all.
    for tag in test_inventory.TIER_NATIVE_SUITES:
        assert tag in suites
        assert suites[tag]["runBy"] == "test-all"

    # parity is the backbone; web_api carries the REST surface.
    assert suites["parity"]["fileCount"] > 50
    assert suites["web_api"]["caseCount"] > 50

    # A suite driven only by community-core coverage is not mislabeled dormant.
    assert suites["community-core-divergence"]["runBy"].startswith("orchestrated:")

    # There is real dormant surface (suites reached only by `test native`).
    dormant = [s for s in suites.values() if s["runBy"] == "targeted-only"]
    assert dormant
    assert inv["rollups"]["nativeDormantSuiteCount"] == len(dormant)


def test_live_layer_matches_suite_registry() -> None:
    inv = test_inventory.build_test_inventory()

    assert inv["layers"]["liveE2e"]["suiteCount"] == len(live_e2e_suite.SUITE_SPECS)
    # Each live suite carries a one-line purpose extracted from its script.
    verified = [s for s in inv["layers"]["liveE2e"]["suites"] if s["verifies"]]
    assert len(verified) >= inv["layers"]["liveE2e"]["suiteCount"] // 2


def test_python_layer_maps_self_tested_scripts() -> None:
    inv = test_inventory.build_test_inventory()
    modules = {m["module"]: m for m in inv["layers"]["pythonHarness"]["modules"]}

    assert inv["rollups"]["pythonModuleCount"] == len(modules)
    assert inv["rollups"]["pythonSelfTestCount"] > 0
    # A known 1:1 self-test maps back to its live script.
    kad = modules.get("tests/python/test_local_kad_swarm.py")
    assert kad is not None
    assert kad["selfTestsScript"] == "scripts/local-kad-swarm.py"
