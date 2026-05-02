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
            "json": {
                "results": [
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
                "json": {
                    "results": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": True,
                        },
                    ],
                },
            }
        )


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
        "logs",
    }
    assert any(route["name"] == "app_shutdown" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)


def test_live_search_plan_covers_release_query_corpus() -> None:
    module = load_rest_api_smoke_module()

    server_count = len(module.LIVE_WIRE_SEARCH_QUERIES)
    kad_count = len(module.LIVE_WIRE_SEARCH_QUERIES)
    plan = module.build_search_plan(server_count, kad_count)

    assert module.LIVE_WIRE_SEARCH_QUERIES == ("linux", "ubuntu", "fedora", "freebsd", "debian", "emule")
    assert [row["query"] for row in plan[:server_count]] == list(module.LIVE_WIRE_SEARCH_QUERIES)
    assert [row["network"] for row in plan[:server_count]] == ["server"] * server_count
    assert [row["query"] for row in plan[server_count:]] == list(module.LIVE_WIRE_SEARCH_QUERIES)
    assert [row["network"] for row in plan[server_count:]] == ["kad"] * kad_count


def test_live_search_start_uses_broad_file_type_for_release_terms(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"search_id": "42"},
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


def test_rest_stress_config_rejects_invalid_values() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(ValueError, match="duration"):
        module.validate_rest_stress_config(
            profile="smoke",
            duration_seconds=0,
            concurrency=1,
            max_failures=0,
            request_timeout_seconds=1,
        )
    with pytest.raises(ValueError, match="concurrency"):
        module.validate_rest_stress_config(
            profile="smoke",
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
    assert ("PATCH", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}") in method_path_pairs
    assert ("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}") in method_path_pairs
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/browse") in method_path_pairs
    assert ("PATCH", "/api/v1/kad") in method_path_pairs
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
        profile="smoke",
        duration_seconds=30.0,
        concurrency=4,
        max_failures=1,
    )

    assert summary["ok"] is True
    assert summary["requests_completed"] == 3
    assert summary["status_counts"] == {"200": 1, "404": 1, "exception": 1}
    assert summary["method_counts"] == {"UNKNOWN": 3}
    assert summary["error_counts"] == {"timeout": 1}
    assert summary["latency_ms"]["max"] == 9.0
    assert len(summary["failures_sample"]) == 1


def test_rest_contract_completeness_skips_shutdown(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    observed_paths: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        observed_paths.append((method, path))
        return {"status": 200, "content_type": "application/json", "json": {"ok": True}, "body_text": "{}"}

    monkeypatch.setattr(module, "http_request", fake_http_request)

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert ("POST", "/api/v1/app/shutdown") not in observed_paths
    assert any(route["name"] == "app_shutdown" and route["skipped"] for route in summary["routes"])
