from __future__ import annotations

import importlib.util
import sys
from collections import Counter
from pathlib import Path

from emule_test_harness.live_seed_sources import (
    EMULE_SECURITY_HOME_URL,
    default_seed_sources,
)
from emule_test_harness import live_e2e_suite, live_wire_inputs
from emule_test_harness.release_golden import load_release_live_wire_golden


def load_script_module(module_name: str, script_name: str):
    """Loads one hyphenated script module for golden-vector drift checks."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_release_live_wire_golden_manifest_matches_seed_sources() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    golden = load_release_live_wire_golden(repo_root)
    seed_sources = default_seed_sources()
    golden_sources = golden["seed_sources"]["files"]

    assert golden["seed_sources"]["home_url"] == EMULE_SECURITY_HOME_URL
    assert [(source.name, source.url, source.file_name, source.minimum_bytes) for source in seed_sources] == [
        (source["name"], source["url"], source["file_name"], source["minimum_bytes"])
        for source in golden_sources
    ]


def test_release_live_wire_golden_manifest_matches_rest_and_aggregate_runners() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    golden = load_release_live_wire_golden(repo_root)
    rest_smoke = load_script_module("rest_api_smoke_golden_test", "rest-api-smoke.py")
    prowlarr_live = load_script_module("prowlarr_emulebb_live_golden_test", "prowlarr-emulebb-live.py")
    arr_live = load_script_module("radarr_sonarr_emulebb_live_golden_test", "radarr-sonarr-emulebb-live.py")

    runtime_inputs = golden["operator_runtime_inputs"]
    assert runtime_inputs["schema"] == live_wire_inputs.SCHEMA
    assert runtime_inputs["default_file"] == live_wire_inputs.DEFAULT_INPUTS_FILE_NAME
    assert runtime_inputs["example_file"] == "live-wire-inputs.example.json"
    assert live_e2e_suite.DEFAULT_REST_SEARCH_COUNT == golden["rest"]["server_search_count"]
    assert live_e2e_suite.DEFAULT_REST_SEARCH_COUNT == golden["rest"]["kad_search_count"]
    assert live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT == golden["rest"]["download_trigger_count"]

    contract_routes = rest_smoke.REST_CONTRACT_ROUTES
    assert len(contract_routes) == golden["rest"]["contract_route_count"]
    assert len([route for route in contract_routes if route["safe"]]) == golden["rest"]["safe_contract_route_count"]
    assert [route["operationId"] for route in contract_routes if not route["safe"]] == golden["rest"]["unsafe_contract_operations"]
    assert dict(Counter(route["family"] for route in contract_routes)) == golden["rest"]["contract_family_counts"]

    operations = rest_smoke.build_rest_stress_operations("smoke")
    method_path_pairs = {(operation["method"], operation["path"]) for operation in operations}
    assert {
        (operation["method"], operation["path"])
        for operation in golden["rest"]["safe_stress_operations"]
    }.issubset(method_path_pairs)
    operations_by_scenario = {
        str(operation.get("scenario")): operation
        for operation in operations
        if operation.get("scenario") is not None
    }
    for operation in golden["rest"]["expected_error_stress_operations"]:
        live_operation = operations_by_scenario[operation["scenario"]]
        assert live_operation["method"] == operation["method"]
        assert live_operation["path"] == operation["path"]
        assert list(live_operation["expected_statuses"]) == operation["expected_statuses"]

    assert all(len(operation["expected_statuses"]) == 1 for operation in golden["rest"]["expected_error_stress_operations"])

    torznab_error_edges = [
        {
            "name": scenario["name"],
            "method": str(scenario.get("method") or "GET"),
            "path": scenario["path"],
            "expected_status": scenario["expected_status"],
        }
        for scenario in prowlarr_live.TORZNAB_DIRECT_ERROR_SCENARIOS
    ]
    assert torznab_error_edges == golden["arr"]["torznab_direct_error_edges"]
    assert golden["arr"]["media_categories"] == {
        "qbit_video": arr_live.TORZNAB_MOVIE_CATEGORY,
        "radarr_release": arr_live.TORZNAB_MOVIE_CATEGORY,
        "sonarr_release": arr_live.TORZNAB_TV_CATEGORY,
    }
    assert golden["arr"]["prowlarr_download_client_proof"] == {
        "category": prowlarr_live.PROWLARR_GRAB_CATEGORY,
        "check_keys": list(prowlarr_live.PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS),
        "cleanup_key": prowlarr_live.PROWLARR_DOWNLOAD_CLIENT_CLEANUP_KEY,
    }

    qbit_scenarios = [
        {
            "name": scenario["name"],
            "method": scenario["method"],
            "path": scenario["path"],
            "expected_statuses": list(scenario["expected_statuses"]),
        }
        for scenario in arr_live.QBIT_ROUTE_COMPLETENESS_SCENARIOS
    ]
    assert qbit_scenarios == golden["arr"]["qbit_route_completeness"]
    assert all(len(scenario["expected_statuses"]) == 1 for scenario in qbit_scenarios)


def test_release_live_wire_golden_manifest_keeps_runtime_values_external() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    golden = load_release_live_wire_golden(repo_root)

    assert "search_terms" not in golden
    assert "auto_browse" not in golden
