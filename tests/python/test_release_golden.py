from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from emule_test_harness.live_seed_sources import (
    EMULE_SECURITY_HOME_URL,
    default_seed_sources,
)
from emule_test_harness import live_e2e_suite
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

    search_terms = tuple(golden["search_terms"])

    assert rest_smoke.LIVE_WIRE_SEARCH_QUERIES == search_terms
    assert live_e2e_suite.LIVE_WIRE_SEARCH_QUERIES == search_terms
    assert live_e2e_suite.DEFAULT_REST_SEARCH_COUNT == golden["rest"]["server_search_count"]
    assert live_e2e_suite.DEFAULT_REST_SEARCH_COUNT == golden["rest"]["kad_search_count"]
    assert live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT == golden["rest"]["download_trigger_count"]

    operations = rest_smoke.build_rest_stress_operations("smoke")
    method_path_pairs = {(operation["method"], operation["path"]) for operation in operations}
    assert {
        (operation["method"], operation["path"])
        for operation in golden["rest"]["safe_stress_operations"]
    }.issubset(method_path_pairs)


def test_release_live_wire_golden_manifest_matches_auto_browse_runner() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    golden = load_release_live_wire_golden(repo_root)
    auto_browse = load_script_module("auto_browse_live_golden_test", "auto-browse-live.py")

    assert auto_browse.LIVE_WIRE_SEARCH_QUERIES == tuple(golden["search_terms"])
    assert auto_browse.BOOTSTRAP_TRANSFER_HASH == golden["auto_browse"]["bootstrap_transfer_hash"]
    assert auto_browse.build_direct_bootstrap_transfer_plan() == golden["auto_browse"]["direct_bootstrap_transfers"]
