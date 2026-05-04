from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def load_rest_api_smoke_module():
    """Loads the hyphenated REST smoke script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "rest-api-smoke.py"
    spec = importlib.util.spec_from_file_location("rest_api_smoke_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_nat_backend_order_accepts_upnp_first() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_upnp_backend_order(
        [
            {"message": "NAT mapping backend mode: Automatic"},
            {"message": "Attempting NAT mapping backend 'UPnP IGD (MiniUPnP)'"},
            {"message": "Trying fallback NAT mapping backend 'PCP/NAT-PMP'"},
            {"message": "Attempting NAT mapping backend 'PCP/NAT-PMP'"},
        ]
    )

    assert summary["backend_names"] == ["UPnP IGD (MiniUPnP)", "PCP/NAT-PMP"]
    assert summary["upnp_first"] is True
    assert summary["pcp_before_upnp"] is False


def test_nat_backend_order_rejects_pcp_first() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="Expected first NAT backend"):
        module.assert_upnp_backend_order(
            [
                {"message": "Attempting NAT mapping backend 'PCP/NAT-PMP'"},
                {"message": "Attempting NAT mapping backend 'UPnP IGD (MiniUPnP)'"},
            ]
        )


def test_nat_backend_order_requires_attempts() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="No NAT mapping backend attempts"):
        module.assert_upnp_backend_order([{"message": "eMule Version 0.72a x64 ready"}])


def test_live_server_unavailable_is_inconclusive_exit_code() -> None:
    module = load_rest_api_smoke_module()

    assert module.LIVE_NETWORK_UNAVAILABLE_EXIT_CODE == 2
    with pytest.raises(module.LiveNetworkUnavailableError, match="No server candidates"):
        module.connect_to_live_server("http://127.0.0.1:1", "api-key", [], 1.0)


def test_missing_transfer_bulk_result_requires_per_item_error() -> None:
    module = load_rest_api_smoke_module()

    result = module.require_missing_transfer_bulk_result(
        {
            "status": 200,
            "raw_json": {
                "data": {
                    "items": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": False,
                            "error": "transfer not found",
                        },
                    ],
                },
                "meta": {"apiVersion": "v1"},
            },
            "json": {
                "items": [
                    {
                        "hash": module.REST_SURFACE_MISSING_HASH,
                        "ok": False,
                        "error": "transfer not found",
                    },
                ],
            },
        }
    )

    assert result["hash"] == module.REST_SURFACE_MISSING_HASH


def test_rest_payload_unwraps_success_and_error_envelopes() -> None:
    module = load_rest_api_smoke_module()

    assert module.unwrap_rest_payload(
        {
            "data": {"items": [{"name": "file.bin"}]},
            "meta": {"apiVersion": "v1"},
        }
    ) == {"items": [{"name": "file.bin"}]}
    assert module.unwrap_rest_payload(
        {
            "error": {
                "code": "NOT_FOUND",
                "message": "transfer not found",
            }
        }
    ) == {"error": "NOT_FOUND", "message": "transfer not found"}


def test_missing_transfer_bulk_result_rejects_success_rows() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError):
        module.require_missing_transfer_bulk_result(
            {
                "status": 200,
                "raw_json": {
                    "data": {
                        "items": [
                            {
                                "hash": module.REST_SURFACE_MISSING_HASH,
                                "ok": True,
                            },
                        ],
                    },
                    "meta": {"apiVersion": "v1"},
                },
                "json": {
                    "items": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": True,
                        },
                    ],
                },
            }
        )


def test_rest_contract_registry_matches_openapi() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_contract_routes_match_openapi()

    assert summary["ok"] is True
    assert summary["operation_count"] == summary["openapi_route_count"]
    assert summary["duplicate_operation_ids"] == []
    assert summary["missing_from_registry"] == []
    assert summary["missing_from_openapi"] == []


def test_openapi_contract_routes_are_the_live_completeness_source() -> None:
    module = load_rest_api_smoke_module()

    routes_by_operation = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}

    assert routes_by_operation["getApp"]["path"] == "/api/v1/app"
    assert routes_by_operation["getSnapshot"]["path"] == "/api/v1/snapshot?limit=7"
    assert routes_by_operation["getTransfer"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}"
    assert routes_by_operation["downloadSearchResult"]["path"] == (
        f"/api/v1/searches/123/results/{module.REST_SURFACE_MISSING_HASH}/operations/download"
    )
    assert routes_by_operation["shutdownApp"]["safe"] is False


def test_rest_contract_registry_covers_release_families() -> None:
    module = load_rest_api_smoke_module()

    families = {route["family"] for route in module.REST_CONTRACT_ROUTES}

    assert families == {
        "app",
        "status",
        "categories",
                    "transfers",
                    "shared-directories",
                    "shared",
                    "uploads",
                    "servers",
                    "kad",
                    "searches",
                    "friends",
                    "logs",
                }
    assert any(route["operationId"] == "shutdownApp" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)


def test_rest_contract_summary_counts_outcomes_and_methods() -> None:
    module = load_rest_api_smoke_module()

    summary = module.build_contract_coverage_summary(
        [
            {
                "name": "getApp",
                "operationId": "getApp",
                "family": "app",
                "method": "GET",
                "path": "/api/v1/app",
                "safe": True,
                "skipped": False,
                "ok": True,
                "outcome": "success",
            },
            {
                "name": "getTransfer",
                "operationId": "getTransfer",
                "family": "transfers",
                "method": "GET",
                "path": f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}",
                "safe": True,
                "skipped": False,
                "ok": True,
                "outcome": "expected_error",
            },
            {
                "name": "shutdownApp",
                "operationId": "shutdownApp",
                "family": "app",
                "method": "POST",
                "path": "/api/v1/app/shutdown",
                "safe": False,
                "skipped": True,
                "ok": True,
                "outcome": "skipped_unsafe",
            },
        ],
        "contract",
    )

    assert summary["safe_route_count"] == 2
    assert summary["unsafe_route_count"] == 1
    assert summary["exercised_route_count"] == 2
    assert summary["success_count"] == 1
    assert summary["expected_error_count"] == 1
    assert summary["method_counts"] == {"GET": 2, "POST": 1}
    assert summary["outcome_counts"]["skipped_unsafe"] == 1


def test_live_search_plan_covers_release_query_corpus() -> None:
    module = load_rest_api_smoke_module()

    search_terms = ("linux", "ubuntu", "fedora", "freebsd", "debian", "emule")
    server_count = len(search_terms)
    kad_count = len(search_terms)
    plan = module.build_search_plan(server_count, kad_count, search_terms)

    assert [row["query"] for row in plan[:server_count]] == list(search_terms)
    assert [row["query_index"] for row in plan[:server_count]] == list(range(server_count))
    assert [row["network"] for row in plan[:server_count]] == ["server"] * server_count
    assert [row["query"] for row in plan[server_count:]] == list(search_terms)
    assert [row["query_index"] for row in plan[server_count:]] == list(range(kad_count))
    assert [row["network"] for row in plan[server_count:]] == ["kad"] * kad_count
    assert all("query" not in row for row in module.summarize_search_plan(plan))


def test_live_search_start_uses_broad_file_type_for_release_terms(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"id": "42"},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.start_live_search("http://127.0.0.1:1", "key", "server", "fedora", forced_method="server")

    assert result["ok"] is True
    assert requests[0]["path"] == "/api/v1/searches"
    assert requests[0]["json_body"] == {
        "query": "fedora",
        "method": "server",
        "type": "any",
    }


def test_live_download_candidate_filter_rejects_unsafe_rows() -> None:
    module = load_rest_api_smoke_module()

    safe = {
        "hash": "0123456789abcdef0123456789abcdef",
        "name": "linux.iso",
        "sizeBytes": 1024,
        "fileType": "cdimage",
        "sources": module.MIN_SAFE_LIVE_DOWNLOAD_SOURCES,
        "completeSources": 0,
    }

    assert module.is_safe_live_download_result(safe) is True
    assert module.is_safe_live_download_result({**safe, "name": "setup.exe"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "installer.msi"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "bundle.rar", "fileType": "Arc"}) is False
    assert module.is_safe_live_download_result({**safe, "fileType": "program"}) is False
    assert module.is_safe_live_download_result({**safe, "hash": "0123456789ABCDEF0123456789ABCDEF"}) is False
    assert module.is_safe_live_download_result({**safe, "sizeBytes": 0}) is False
    assert module.is_safe_live_download_result({**safe, "sizeBytes": module.MAX_SAFE_LIVE_DOWNLOAD_BYTES + 1}) is False
    assert module.is_safe_live_download_result({**safe, "sources": module.MIN_SAFE_LIVE_DOWNLOAD_SOURCES - 1}) is False


def test_live_download_trigger_posts_paused_download(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        if path.endswith("/operations/download"):
            return {
                "status": 200,
                "content_type": "application/json",
                "json": {"ok": True},
                "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
                "body_text": "{}",
            }
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {
                "id": "42",
                "query": "linux",
                "status": "running",
                "results": [
                    {
                        "hash": "0123456789abcdef0123456789abcdef",
                        "name": "linux.iso",
                        "sizeBytes": 1024,
                        "fileType": "cdimage",
                        "sources": 2,
                        "completeSources": 0,
                    }
                ],
            },
            "raw_json": {
                "data": {
                    "id": "42",
                    "query": "linux",
                    "status": "running",
                    "results": [
                        {
                            "hash": "0123456789abcdef0123456789abcdef",
                            "name": "linux.iso",
                            "sizeBytes": 1024,
                            "fileType": "cdimage",
                            "sources": 2,
                            "completeSources": 0,
                        }
                    ],
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.trigger_paused_download_from_search_result("http://127.0.0.1:1", "key", "42", 1.0)

    assert result["ok"] is True
    assert requests[-1]["path"] == "/api/v1/searches/42/results/0123456789abcdef0123456789abcdef/operations/download"
    assert requests[-1]["json_body"] == {"paused": True, "categoryId": 0}


def test_live_download_trigger_timeout_without_candidate_is_nonfatal(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url, _path, **_kwargs):
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {
                "id": "42",
                "query": "linux",
                "status": "running",
                "results": [],
            },
            "raw_json": {
                "data": {
                    "id": "42",
                    "query": "linux",
                    "status": "running",
                    "results": [],
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.trigger_paused_download_from_search_result("http://127.0.0.1:1", "key", "42", 0.01)

    assert result["ok"] is False
    assert result["reason"] == "timed out without a safe download candidate"
    assert result["observations"]


def test_rest_stress_config_rejects_invalid_values() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(ValueError, match="duration"):
        module.validate_rest_stress_config(
            budget="smoke",
            duration_seconds=0,
            concurrency=1,
            max_failures=0,
            request_timeout_seconds=1,
        )
    with pytest.raises(ValueError, match="concurrency"):
        module.validate_rest_stress_config(
            budget="smoke",
            duration_seconds=1,
            concurrency=0,
            max_failures=0,
            request_timeout_seconds=1,
        )


def test_rest_stress_operations_include_safe_mutation_routes() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    method_path_pairs = {(operation["method"], operation["path"]) for operation in operations}

    assert ("GET", "/api/v1/status") in method_path_pairs
    assert ("GET", "/api/v1/shared-directories") in method_path_pairs
    assert ("PATCH", "/api/v1/app/preferences") in method_path_pairs
    assert ("POST", "/api/v1/transfers") in method_path_pairs
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/operations/pause") in method_path_pairs
    assert ("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}") in method_path_pairs
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse") in method_path_pairs
    assert ("POST", "/api/v1/kad/operations/recheck-firewall") in method_path_pairs
    assert ("POST", "/api/v1/searches") in method_path_pairs
    assert ("DELETE", "/api/v1/searches/123") in method_path_pairs


def test_rest_stress_summary_is_bounded_and_deterministic() -> None:
    module = load_rest_api_smoke_module()

    summary = module.summarize_rest_stress_results(
        [
            {"path": "/ok", "status": 200, "ok": True, "duration_ms": 1.0},
            {"path": "/missing", "status": 404, "ok": True, "duration_ms": 4.0},
            {"path": "/boom", "status": "exception", "ok": False, "duration_ms": 9.0, "error": "timeout"},
        ],
        budget="smoke",
        duration_seconds=30.0,
        concurrency=4,
        max_failures=1,
    )

    assert summary["ok"] is True
    assert summary["budget"] == "smoke"
    assert summary["requests_completed"] == 3
    assert summary["status_counts"] == {"200": 1, "404": 1, "exception": 1}
    assert summary["method_counts"] == {"UNKNOWN": 3}
    assert summary["error_counts"] == {"timeout": 1}
    assert summary["latency_ms"]["max"] == 9.0
    assert len(summary["failures_sample"]) == 1


def test_server_connect_transport_loss_is_runtime_failure_signal() -> None:
    module = load_rest_api_smoke_module()

    assert module.did_rest_listener_disappear(
        [
            {"connected": False},
            {"transport_error": {"message": "<urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>"}},
        ]
    )
    assert not module.did_rest_listener_disappear([{"connected": False, "connecting": False}])


def test_rest_contract_completeness_skips_shutdown(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    observed_paths: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        observed_paths.append((method, path))
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert ("POST", "/api/v1/app/shutdown") not in observed_paths
    assert any(route["operationId"] == "shutdownApp" and route["skipped"] for route in summary["routes"])
