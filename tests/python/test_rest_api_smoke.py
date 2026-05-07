from __future__ import annotations

import importlib.util
from pathlib import Path
import re

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


def test_live_seed_import_evidence_records_sources_and_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[dict[str, object]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: object) -> dict[str, object]:
        calls.append({"base_url": base_url, "path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json",
            "raw_json": {"data": {"ok": True, "imported": True}, "meta": {"apiVersion": "v1"}},
            "json": {"ok": True, "imported": True},
            "headers": {},
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    summary = module.exercise_live_seed_imports(
        "http://127.0.0.1:1",
        "api-key",
        {
            "source_home_url": module.EMULE_SECURITY_HOME_URL,
            "files": [
                {
                    "name": "server_met",
                    "file_name": "server.met",
                    "url": module.EMULE_SECURITY_SERVER_MET_URL,
                    "bytes": 80,
                    "sha256": "s" * 64,
                },
                {
                    "name": "nodes_dat",
                    "file_name": "nodes.dat",
                    "url": module.EMULE_SECURITY_NODES_DAT_URL,
                    "bytes": 96,
                    "sha256": "n" * 64,
                },
            ],
        },
    )

    assert [call["path"] for call in calls] == [
        "/api/v1/servers/met-url-imports",
        "/api/v1/kad/nodes-url-imports",
    ]
    assert [call["json_body"] for call in calls] == [
        {"url": module.EMULE_SECURITY_SERVER_MET_URL},
        {"url": module.EMULE_SECURITY_NODES_DAT_URL},
    ]
    assert {entry["file_name"]: entry["imported"] for entry in summary["imports"]} == {
        "server.met": True,
        "nodes.dat": True,
    }
    assert {entry["file_name"]: entry["source_bytes"] for entry in summary["imports"]} == {
        "server.met": 80,
        "nodes.dat": 96,
    }


def test_live_seed_import_evidence_rejects_failed_import(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url: str, _path: str, **_kwargs: object) -> dict[str, object]:
        return {
            "status": 200,
            "content_type": "application/json",
            "raw_json": {"data": {"ok": False, "imported": False}, "meta": {"apiVersion": "v1"}},
            "json": {"ok": False, "imported": False},
            "headers": {},
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    with pytest.raises(AssertionError, match="imported"):
        module.exercise_live_seed_imports(
            "http://127.0.0.1:1",
            "api-key",
            {
                "source_home_url": module.EMULE_SECURITY_HOME_URL,
                "files": [
                    {
                        "name": "server_met",
                        "file_name": "server.met",
                        "url": module.EMULE_SECURITY_SERVER_MET_URL,
                        "bytes": 80,
                        "sha256": "s" * 64,
                    },
                    {
                        "name": "nodes_dat",
                        "file_name": "nodes.dat",
                        "url": module.EMULE_SECURITY_NODES_DAT_URL,
                        "bytes": 96,
                        "sha256": "n" * 64,
                    },
                ],
            },
        )


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


def test_transfer_details_payload_compaction_validates_release_shape() -> None:
    module = load_rest_api_smoke_module()

    compact = module.compact_transfer_details_payload(
        {
            "transfer": {"hash": module.REST_SURFACE_VALID_DOWNLOAD_HASH, "name": "rest-api-smoke.bin"},
            "parts": [
                {
                    "index": 0,
                    "start": 0,
                    "end": 1023,
                    "completedBytes": 0,
                    "gapBytes": 1024,
                    "complete": False,
                    "requested": False,
                    "corrupted": False,
                    "availableSources": 0,
                }
            ],
            "sources": [],
        },
        module.REST_SURFACE_VALID_DOWNLOAD_HASH,
    )

    assert compact["hash"] == module.REST_SURFACE_VALID_DOWNLOAD_HASH
    assert compact["part_count"] == 1
    assert compact["source_count"] == 0
    assert compact["first_part"]["gapBytes"] == 1024


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


def test_openapi_error_envelope_documents_stable_error_codes() -> None:
    openapi_path = Path(__file__).resolve().parents[3] / "eMule-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
    text = openapi_path.read_text(encoding="utf-8")
    error_schema = text[text.index("    ErrorEnvelope:\n") : text.index("    Collection:\n")]

    assert "required: [error]" in error_schema
    assert "required: [code, message]" in error_schema
    for code in (
        "INVALID_ARGUMENT",
        "UNAUTHORIZED",
        "METHOD_NOT_ALLOWED",
        "NOT_FOUND",
        "INVALID_STATE",
        "EMULE_UNAVAILABLE",
        "EMULE_ERROR",
    ):
        assert f"                - {code}" in error_schema
    assert "details:" in error_schema
    assert "additionalProperties: true" in error_schema


def test_rest_error_response_requires_json_not_html() -> None:
    module = load_rest_api_smoke_module()
    error_result = {
        "status": 404,
        "content_type": "application/json; charset=utf-8",
        "body_text": '{"error":{"code":"NOT_FOUND","message":"transfer not found","details":{}}}',
        "raw_json": {
            "error": {
                "code": "NOT_FOUND",
                "message": "transfer not found",
                "details": {},
            },
        },
        "json": {
            "error": "NOT_FOUND",
            "message": "transfer not found",
            "details": {},
        },
    }

    assert module.is_native_rest_json_response(error_result) is True
    assert module.response_matches_kind(error_result, "native-json") is True
    assert module.response_matches_kind(error_result, "json") is True
    assert module.require_error_response(error_result, 404, "NOT_FOUND")["error"] == "NOT_FOUND"

    method_not_allowed = {
        **error_result,
        "status": 405,
        "body_text": (
            '{"error":{"code":"METHOD_NOT_ALLOWED",'
            '"message":"HTTP method is not allowed for this API route","details":{}}}'
        ),
        "raw_json": {
            "error": {
                "code": "METHOD_NOT_ALLOWED",
                "message": "HTTP method is not allowed for this API route",
                "details": {},
            },
        },
        "json": {
            "error": "METHOD_NOT_ALLOWED",
            "message": "HTTP method is not allowed for this API route",
            "details": {},
        },
    }
    assert module.require_error_response(method_not_allowed, 405, "METHOD_NOT_ALLOWED")["error"] == "METHOD_NOT_ALLOWED"

    html_content_type = {**error_result, "content_type": "text/html; charset=utf-8"}
    assert module.is_native_rest_json_response(html_content_type) is False
    assert module.response_matches_kind({**html_content_type, "body_text": "<html></html>"}, "html") is True
    with pytest.raises(AssertionError):
        module.require_error_response(html_content_type, 404, "NOT_FOUND")

    html_body = {**error_result, "body_text": "<html><body>login</body></html>"}
    with pytest.raises(AssertionError):
        module.require_error_response(html_body, 404, "NOT_FOUND")


def test_legacy_response_helper_rejects_native_json_envelopes() -> None:
    module = load_rest_api_smoke_module()

    module.require_legacy_non_json_response(
        {
            "status": 200,
            "content_type": "text/html",
            "body_text": "<html></html>",
            "raw_json": None,
            "json": None,
        },
        200,
    )

    with pytest.raises(AssertionError):
        module.require_legacy_non_json_response(
            {
                "status": 404,
                "content_type": "application/json; charset=utf-8",
                "body_text": '{"error":{"code":"NOT_FOUND","message":"API route not found","details":{}}}',
                "raw_json": {
                    "error": {
                        "code": "NOT_FOUND",
                        "message": "API route not found",
                        "details": {},
                    },
                },
                "json": {
                    "error": "NOT_FOUND",
                    "message": "API route not found",
                    "details": {},
                },
            },
            404,
        )


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


def _csv_fields(value: str) -> set[str]:
    return {field for field in value.split(",") if field}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _component_ref_name(line: str, kind: str) -> str | None:
    match = re.search(rf"#/components/{kind}/([A-Za-z0-9_]+)", line)
    return match.group(1) if match else None


def _native_route_contracts() -> dict[tuple[str, str], dict[str, set[str]]]:
    workspace_root = Path(__file__).resolve().parents[4]
    route_header = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "WebServerJsonSeams.h"
    route_specs = re.findall(
        r'\{\s*"([A-Z]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\}',
        route_header.read_text(encoding="utf-8"),
    )

    return {
        (method, path): {
            "body": _csv_fields(body_fields),
            "query": _csv_fields(query_fields),
        }
        for method, path, body_fields, query_fields in route_specs
    }


def _openapi_component_parameters(lines: list[str]) -> dict[str, dict[str, str | None]]:
    parameters: dict[str, dict[str, str | None]] = {}
    in_components = False
    in_parameters = False
    current_name: str | None = None
    current_block: list[str] = []

    def commit() -> None:
        if current_name is None:
            return
        name = None
        location = None
        for line in current_block:
            stripped = line.strip()
            if stripped.startswith("name:"):
                name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("in:"):
                location = stripped.split(":", 1)[1].strip()
        parameters[current_name] = {"name": name, "in": location}

    for line in lines:
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        if line.startswith("  parameters:"):
            in_parameters = True
            continue
        if in_parameters and line.startswith("  ") and not line.startswith("    ") and not line.startswith("  parameters:"):
            commit()
            break
        if not in_parameters:
            continue
        match = re.match(r"    ([A-Za-z0-9_]+):\s*$", line)
        if match:
            commit()
            current_name = match.group(1)
            current_block = []
        elif current_name is not None:
            current_block.append(line)
    return parameters


def _openapi_schema_properties(lines: list[str]) -> dict[str, set[str]]:
    schemas: dict[str, set[str]] = {}
    in_components = False
    in_schemas = False
    current_name: str | None = None
    in_properties = False
    properties: set[str] = set()

    def commit() -> None:
        if current_name is not None:
            schemas[current_name] = set(properties)

    for line in lines:
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        if line.startswith("  schemas:"):
            in_schemas = True
            continue
        if not in_schemas:
            continue
        schema_match = re.match(r"    ([A-Za-z0-9_]+):\s*$", line)
        if schema_match:
            commit()
            current_name = schema_match.group(1)
            in_properties = False
            properties = set()
            continue
        if current_name is None:
            continue
        if line.startswith("      properties:"):
            in_properties = True
            continue
        if in_properties:
            prop_match = re.match(r"        ([A-Za-z0-9_]+):\s*$", line)
            if prop_match:
                properties.add(prop_match.group(1))
            elif line and _indent(line) <= 6:
                in_properties = False
    commit()
    return schemas


def _openapi_operation_contracts(openapi_path: Path) -> dict[tuple[str, str], dict[str, set[str]]]:
    lines = openapi_path.read_text(encoding="utf-8").splitlines()
    component_parameters = _openapi_component_parameters(lines)
    schema_properties = _openapi_schema_properties(lines)
    operations: dict[tuple[str, str], dict[str, set[str]]] = {}
    current_path: str | None = None
    current_method: str | None = None
    block: list[str] = []

    def parse_operation_block() -> dict[str, set[str]]:
        body_fields: set[str] = set()
        query_fields: set[str] = set()
        in_parameters = False
        in_request_body = False
        for index, line in enumerate(block):
            stripped = line.strip()
            if _indent(line) == 6 and stripped == "parameters:":
                in_parameters = True
                in_request_body = False
                continue
            if _indent(line) == 6 and stripped == "requestBody:":
                in_request_body = True
                in_parameters = False
                continue
            if _indent(line) <= 6 and stripped not in {"parameters:", "requestBody:"}:
                in_parameters = False
                in_request_body = False
            if in_parameters:
                parameter_ref = _component_ref_name(line, "parameters")
                if parameter_ref is not None:
                    parameter = component_parameters[parameter_ref]
                    if parameter["in"] == "query":
                        query_fields.add(str(parameter["name"]))
                direct_name = re.match(r"        - name: (.+)$", line)
                if direct_name:
                    location = None
                    for nested in block[index + 1 :]:
                        if re.match(r"        - ", nested) or _indent(nested) <= 6:
                            break
                        if nested.strip().startswith("in:"):
                            location = nested.strip().split(":", 1)[1].strip()
                    if location == "query":
                        query_fields.add(direct_name.group(1).strip())
            if in_request_body:
                schema_ref = _component_ref_name(line, "schemas")
                if schema_ref is not None:
                    body_fields.update(schema_properties.get(schema_ref, set()))
        return {"body": body_fields, "query": query_fields}

    def commit() -> None:
        if current_path is not None and current_method is not None:
            operations[(current_method, current_path)] = parse_operation_block()

    for line in lines:
        if line.startswith("components:"):
            commit()
            break
        path_match = re.match(r"  (/[^:]+):\s*$", line)
        if path_match:
            commit()
            current_path = path_match.group(1)
            current_method = None
            block = []
            continue
        method_match = re.match(r"    (get|post|patch|delete):\s*$", line)
        if method_match:
            commit()
            current_method = method_match.group(1).upper()
            block = []
            continue
        if current_method is not None:
            block.append(line)
    return operations


def test_native_route_specs_match_openapi_methods_paths_and_fields() -> None:
    module = load_rest_api_smoke_module()
    native_contracts = _native_route_contracts()
    openapi_contracts = _openapi_operation_contracts(module.OPENAPI_CONTRACT_PATH)

    assert native_contracts == openapi_contracts


def test_openapi_contract_routes_are_the_live_completeness_source() -> None:
    module = load_rest_api_smoke_module()

    routes_by_operation = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}

    assert routes_by_operation["getApp"]["path"] == "/api/v1/app"
    assert routes_by_operation["getApp"]["safety"] == "safe"
    assert routes_by_operation["getApp"]["successResponseStatuses"] == ["200"]
    assert routes_by_operation["getApp"]["successResponseRefs"] == ["AppResponse"]
    assert routes_by_operation["getApp"]["responseEnvelope"] == "AppResponse"
    assert routes_by_operation["getSnapshot"]["path"] == "/api/v1/snapshot?limit=7"
    assert routes_by_operation["getTransfer"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}"
    assert routes_by_operation["getTransfer"]["responseEnvelope"] == "TransferResponse"
    assert routes_by_operation["getTransferDetails"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details"
    assert routes_by_operation["getTransferDetails"]["responseEnvelope"] == "TransferDetailsResponse"
    assert routes_by_operation["downloadSearchResult"]["path"] == (
        f"/api/v1/searches/123/results/{module.REST_SURFACE_MISSING_HASH}/operations/download"
    )
    assert routes_by_operation["shutdownApp"]["safe"] is False
    assert routes_by_operation["shutdownApp"]["safety"] == "unsafe"
    assert routes_by_operation["shutdownApp"]["successResponseStatuses"] == ["200"]
    assert routes_by_operation["shutdownApp"]["responseEnvelope"] == "OkAcceptedResponse"
    assert all(len(route["successResponseRefs"]) == 1 for route in module.REST_CONTRACT_ROUTES)
    assert all(route["responseEnvelope"] == route["successResponseRefs"][0] for route in module.REST_CONTRACT_ROUTES)


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
                "safety": "safe",
                "responseEnvelope": "AppResponse",
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
                "safety": "safe",
                "responseEnvelope": "TransferResponse",
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
                "safety": "unsafe",
                "responseEnvelope": "OkAcceptedResponse",
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
    assert summary["response_envelope_counts"] == {"AppResponse": 1, "TransferResponse": 1, "OkAcceptedResponse": 1}
    assert summary["safety_counts"] == {"safe": 2, "unsafe": 1}
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
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert ("GET", "/api/v1/status") in method_path_pairs
    assert ("GET", "/api/v1/shared-directories") in method_path_pairs
    assert operations_by_pair[("GET", "/api/v1/status")]["expected_statuses"] == (200,)
    assert ("PATCH", "/api/v1/app/preferences") in method_path_pairs
    assert ("POST", "/api/v1/transfers") in method_path_pairs
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/operations/pause") in method_path_pairs
    assert ("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}") in method_path_pairs
    assert operations_by_pair[("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}")][
        "expected_statuses"
    ] == (400,)
    assert operations_by_pair[("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}")][
        "scenario"
    ] == "transfer_delete_requires_delete_files"
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse") in method_path_pairs
    assert operations_by_pair[
        ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse")
    ]["json_body"] == {}
    assert ("POST", "/api/v1/kad/operations/recheck-firewall") in method_path_pairs
    assert ("POST", "/api/v1/searches") in method_path_pairs
    assert ("DELETE", "/api/v1/searches/123") in method_path_pairs


def test_rest_stress_operations_include_expected_error_edges() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert operations_by_pair[("GET", "/api/v1/logs?limit=%2x")]["scenario"] == "malformed_percent_escape"
    assert operations_by_pair[("GET", "/api/v1/logs?limit=%2x")]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/api/v1/logs%2x?limit=10")]["scenario"] == "malformed_route_escape"
    assert operations_by_pair[("GET", "/api/v1/logs?limit=10&limit=20")]["scenario"] == "duplicate_query_parameter"
    assert operations_by_pair[("get", "/api/v1/app")]["scenario"] == "lowercase_method_rejected"
    assert operations_by_pair[("get", "/api/v1/app")]["expected_statuses"] == (400,)
    assert operations_by_pair[
        ("GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF")
    ]["scenario"] == "uppercase_hash_rejected"
    assert operations_by_pair[
        ("GET", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details")
    ]["scenario"] == "missing_transfer_details_rejected"
    assert operations_by_pair[
        ("GET", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details")
    ]["expected_statuses"] == (404,)
    assert operations_by_pair[("POST", "/api/v1/transfers")]["expected_statuses"] == (400,)
    assert any(
        operation["scenario"] == "conflicting_category_fields"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert any(
        operation["scenario"] == "unicode_query_length_rejected"
        and operation["expected_statuses"] == (400,)
        and "λ" in operation["json_body"]["query"]
        for operation in operations
    )
    assert any(
        operation["scenario"] == "long_unicode_shared_file_path_rejected"
        and operation["expected_statuses"] == (400,)
        and "λ" in operation["json_body"]["path"]
        and "例" in operation["json_body"]["path"]
        and "\\" not in operation["json_body"]["path"]
        for operation in operations
    )


def test_rest_stress_operations_include_adapter_and_legacy_traffic() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps")]["response_kind"] == "xml"
    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps&t=search")]["expected_statuses"] == (400,)
    assert operations_by_pair[
        ("GET", "/indexer/emulebb/api?t=search&season=abc&q=linux&apikey={api_key}")
    ]["api_key"] is False
    assert operations_by_pair[
        ("GET", "/indexer/emulebb/api?t=search&cat=abc&q=linux&apikey={api_key}")
    ]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/api/v2/app/webapiVersion")]["response_kind"] == "text"
    assert any(
        operation["method"] == "GET"
        and operation["path"] == "/api/v2/torrents/categories"
        and operation["scenario"] == "qbit_categories"
        and operation["extra_headers"] == {"Cookie": "{qbit_session_cookie}"}
        for operation in operations
    )
    assert any(
        operation["method"] == "GET"
        and operation["path"] == "/api/v2/torrents/categories"
        and operation["scenario"] == "qbit_wrong_cookie_rejected"
        and operation["expected_statuses"] == (403,)
        and operation["extra_headers"] == {"Cookie": "SID=wrong"}
        for operation in operations
    )
    assert operations_by_pair[
        ("GET", f"/api/v2/torrents/properties?hash={module.REST_SURFACE_MISSING_HASH}")
    ]["expected_statuses"] == (404,)
    assert operations_by_pair[("POST", "/api/v2/torrents/pause")]["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}"
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/delete"
        and operation["scenario"] == "qbit_missing_hash_delete"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&deleteFiles=false"
        and operation["expected_statuses"] == (200,)
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/delete"
        and operation["scenario"] == "qbit_bad_delete_boolean_rejected"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&deleteFiles=wat"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/setForceStart"
        and operation["scenario"] == "qbit_bad_force_start_boolean_rejected"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&value=wat"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert operations_by_pair[("GET", "/")]["response_kind"] == "html"


def test_rest_stress_summary_is_bounded_and_deterministic() -> None:
    module = load_rest_api_smoke_module()

    summary = module.summarize_rest_stress_results(
        [
            {
                "path": "/ok",
                "status": 200,
                "ok": True,
                "duration_ms": 1.0,
                "scenario": "read",
                "content_type": "application/json; charset=utf-8",
                "native_rest_json": True,
            },
            {
                "path": "/missing",
                "status": 404,
                "ok": True,
                "duration_ms": 4.0,
                "scenario": "safe_mutation",
                "content_type": "application/json; charset=utf-8",
                "native_rest_json": True,
            },
            {
                "path": "/boom",
                "status": "exception",
                "ok": False,
                "duration_ms": 9.0,
                "error": "timeout",
                "scenario": "read",
                "content_type": "text/html",
                "native_rest_json": False,
            },
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
    assert summary["scenario_counts"] == {"read": 2, "safe_mutation": 1}
    assert summary["content_type_counts"] == {"application/json; charset=utf-8": 2, "text/html": 1}
    assert summary["error_counts"] == {"timeout": 1}
    assert summary["timeout_count"] == 1
    assert summary["native_rest_non_json_count"] == 1
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


def test_close_app_cleanly_with_timing_records_shutdown_duration() -> None:
    module = load_rest_api_smoke_module()
    closed: list[object] = []

    result = module.close_app_cleanly_with_timing("app", close_func=closed.append)

    assert closed == ["app"]
    assert result["app_closed"] is True
    assert isinstance(result["shutdown_duration_ms"], float)
    assert result["shutdown_duration_ms"] >= 0.0


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


def test_rest_contract_completeness_rejects_undeclared_4xx(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "getApp",
                "operationId": "getApp",
                "family": "app",
                "method": "GET",
                "path": "/api/v1/app",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": False,
                "requestBodyRequired": False,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["AppResponse"],
                "responseEnvelope": "AppResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "bad request"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "bad request", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is False
    assert summary["failed_routes"] == ["getApp"]
    assert summary["routes"][0]["outcome"] == "unexpected_error"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200]


def test_rest_contract_completeness_accepts_declared_negative_probe(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "createSearch",
                "operationId": "createSearch",
                "family": "searches",
                "method": "POST",
                "path": "/api/v1/searches",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": True,
                "requestBodyRequired": True,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["SearchResponse"],
                "responseEnvelope": "SearchResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "query is required"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "query is required", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert summary["expected_error_count"] == 1
    assert summary["failed_routes"] == []
    assert summary["routes"][0]["outcome"] == "expected_error"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200, 400]


def test_rest_contract_completeness_accepts_category_create_negative_probe(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "createCategory",
                "operationId": "createCategory",
                "family": "categories",
                "method": "POST",
                "path": "/api/v1/categories",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": True,
                "requestBodyRequired": True,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["CategoryResponse"],
                "responseEnvelope": "CategoryResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "name is required"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "name is required", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert summary["expected_error_count"] == 1
    assert summary["routes"][0]["operationId"] == "createCategory"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200, 400]
