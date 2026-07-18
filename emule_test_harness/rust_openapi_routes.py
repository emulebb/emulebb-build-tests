"""Static route inventory drift checks for emulebb-rust OpenAPI coverage."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from .paths import get_required_emule_workspace_root
from .rust_rest_contract import REST_CONTRACT_VERSION, REST_CONTRACT_VERSION_HEADER

HTTP_METHODS = ("delete", "get", "patch", "post", "put")
API_KEY_SECURITY_SCHEME = "ApiKeyAuth"
API_KEY_HEADER = "X-API-Key"
METHOD_NOT_ALLOWED_RESPONSE_REF = "#/components/responses/MethodNotAllowedResponse"
CONTRACT_VERSION_HEADER_REF = "#/components/headers/ContractVersionHeader"


@dataclass(frozen=True, order=True)
class Route:
    """One HTTP method/path pair in the native Rust REST contract."""

    method: str
    path: str


@dataclass(frozen=True)
class RouteDriftReport:
    """Route, query, and body drift between Rust metadata and OpenAPI."""

    implemented_missing_from_openapi: tuple[Route, ...]
    openapi_missing_from_implemented: tuple[Route, ...]
    query_parameter_drift: tuple[QueryParameterDrift, ...] = ()
    body_field_drift: tuple[BodyFieldDrift, ...] = ()
    response_header_drift: tuple[ResponseHeaderDrift, ...] = ()
    auth_drift: tuple[AuthDrift, ...] = ()
    method_not_allowed_drift: tuple[MethodNotAllowedDrift, ...] = ()
    contract_version_drift: tuple[ContractVersionDrift, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            not self.implemented_missing_from_openapi
            and not self.openapi_missing_from_implemented
            and not self.query_parameter_drift
            and not self.body_field_drift
            and not self.response_header_drift
            and not self.auth_drift
            and not self.method_not_allowed_drift
            and not self.contract_version_drift
        )

    def as_json_dict(self) -> dict[str, list[dict[str, object]]]:
        return {
            "implementedMissingFromOpenapi": route_list_json(self.implemented_missing_from_openapi),
            "openapiMissingFromImplemented": route_list_json(self.openapi_missing_from_implemented),
            "queryParameterDrift": query_parameter_drift_json(self.query_parameter_drift),
            "bodyFieldDrift": body_field_drift_json(self.body_field_drift),
            "responseHeaderDrift": response_header_drift_json(self.response_header_drift),
            "authDrift": auth_drift_json(self.auth_drift),
            "methodNotAllowedDrift": method_not_allowed_drift_json(self.method_not_allowed_drift),
            "contractVersionDrift": contract_version_drift_json(self.contract_version_drift),
        }


@dataclass(frozen=True, order=True)
class QueryParameterDrift:
    """A route whose Rust query allowlist does not match OpenAPI query names."""

    route: Route
    rust_query_parameters: tuple[str, ...]
    openapi_query_parameters: tuple[str, ...]


@dataclass(frozen=True, order=True)
class BodyFieldDrift:
    """A route whose Rust JSON body allowlist does not match OpenAPI fields."""

    route: Route
    rust_body_fields: tuple[str, ...]
    openapi_body_fields: tuple[str, ...]


@dataclass(frozen=True, order=True)
class ResponseHeaderDrift:
    """A route response that does not document the native contract-version header."""

    route: Route
    status: str
    missing_header: str


@dataclass(frozen=True, order=True)
class AuthDrift:
    """An OpenAPI document or operation whose API-key contract is incomplete."""

    method: str
    path: str
    issue: str


@dataclass(frozen=True, order=True)
class MethodNotAllowedDrift:
    """An OpenAPI 405 response contract gap."""

    method: str
    path: str
    issue: str


@dataclass(frozen=True, order=True)
class ContractVersionDrift:
    """A Rust/OpenAPI/harness contract-version mismatch."""

    source: str
    issue: str


def route_list_json(routes: Iterable[Route]) -> list[dict[str, str]]:
    return [{"method": route.method, "path": route.path} for route in routes]


def query_parameter_drift_json(drifts: Iterable[QueryParameterDrift]) -> list[dict[str, object]]:
    return [
        {
            "method": drift.route.method,
            "path": drift.route.path,
            "rustQueryParameters": list(drift.rust_query_parameters),
            "openapiQueryParameters": list(drift.openapi_query_parameters),
        }
        for drift in drifts
    ]


def body_field_drift_json(drifts: Iterable[BodyFieldDrift]) -> list[dict[str, object]]:
    return [
        {
            "method": drift.route.method,
            "path": drift.route.path,
            "rustBodyFields": list(drift.rust_body_fields),
            "openapiBodyFields": list(drift.openapi_body_fields),
        }
        for drift in drifts
    ]


def response_header_drift_json(drifts: Iterable[ResponseHeaderDrift]) -> list[dict[str, object]]:
    return [
        {
            "method": drift.route.method,
            "path": drift.route.path,
            "status": drift.status,
            "missingHeader": drift.missing_header,
        }
        for drift in drifts
    ]


def auth_drift_json(drifts: Iterable[AuthDrift]) -> list[dict[str, str]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def method_not_allowed_drift_json(drifts: Iterable[MethodNotAllowedDrift]) -> list[dict[str, str]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def contract_version_drift_json(drifts: Iterable[ContractVersionDrift]) -> list[dict[str, str]]:
    return [
        {
            "source": drift.source,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def rust_route_inventory(routes_rs: Path) -> set[Route]:
    """Returns route method/path pairs declared in `crates/emulebb-rest/src/routes.rs`."""

    text = routes_rs.read_text(encoding="utf-8")
    routes: set[Route] = set()
    for chunk in text.split(".route(")[1:]:
        path_match = re.search(r'"([^"]+)"', chunk)
        if path_match is None:
            continue
        full_path = path_match.group(1)
        if not full_path.startswith("/api/v1/") or "{*" in full_path:
            continue
        path = full_path.removeprefix("/api/v1")
        for method in HTTP_METHODS:
            if re.search(rf"\b{method}\s*\(", chunk):
                routes.add(Route(method.upper(), path))
    return routes


def openapi_route_inventory(openapi_yaml: Path) -> set[Route]:
    """Returns server-relative OpenAPI method/path pairs from the top-level `paths` map."""

    routes: set[Route] = set()
    current_path: str | None = None
    for line in openapi_yaml.read_text(encoding="utf-8").splitlines():
        path_match = re.match(r"^  (/[^:]+):\s*$", line)
        if path_match is not None:
            current_path = path_match.group(1)
            continue
        if current_path is None:
            continue
        method_match = re.match(r"^    (delete|get|patch|post|put):\s*$", line)
        if method_match is not None:
            routes.add(Route(method_match.group(1).upper(), current_path))
    return routes


def rust_query_parameter_inventory(route_metadata_rs: Path, routes_rs: Path) -> dict[Route, tuple[str, ...]]:
    """Returns Rust middleware query allowlists for the declared router paths."""

    routes = rust_route_inventory(routes_rs)
    text = route_metadata_rs.read_text(encoding="utf-8")
    constants = query_constants(text)
    inventory = {route: () for route in routes}

    for method, path, constant in re.findall(r'\("([A-Z]+)",\s*"([^"]+)"\)\s*=>\s*Some\((\w+)\)', text):
        route = Route(method, path.removeprefix("/api/v1"))
        if route in inventory:
            inventory[route] = tuple(sorted(constants[constant]))

    for method, path, constant in exact_query_overrides(text):
        route = Route(method, path.removeprefix("/api/v1"))
        if route in inventory:
            inventory[route] = tuple(sorted(constants[constant]))

    for route, constant in parameterized_query_overrides(text).items():
        if route in inventory:
            inventory[route] = tuple(sorted(constants[constant]))

    return inventory


def query_constants(route_metadata_rs_text: str) -> dict[str, tuple[str, ...]]:
    constants: dict[str, tuple[str, ...]] = {}
    for name, values in re.findall(r"const\s+(\w+):\s*&\[&str\]\s*=\s*&\[([^\]]*)\]", route_metadata_rs_text):
        constants[name] = tuple(re.findall(r'"([^"]+)"', values))
    return constants


def exact_query_overrides(route_metadata_rs_text: str) -> list[tuple[str, str, str]]:
    overrides: list[tuple[str, str, str]] = []
    for path, method, constant in re.findall(
        r'"([^"]+)"\s+if\s+method\s*==\s*"([A-Z]+)"\s*=>\s*(\w+)', route_metadata_rs_text
    ):
        overrides.append((method, path, constant))
    return overrides


def parameterized_query_overrides(route_metadata_rs_text: str) -> dict[Route, str]:
    overrides: dict[Route, str] = {}
    parameterized = route_metadata_rs_text.split("fn route_query_fields_for_parameterized", 1)[-1]
    for pattern, method, path in (
        (r'\("GET",\s*\["searches", _\]\)\s*=>\s*Some\((\w+)\)', "GET", "/searches/{searchId}"),
        (r'\("DELETE",\s*\["transfers", _, "files"\]\)\s*=>\s*Some\((\w+)\)', "DELETE", "/transfers/{hash}/files"),
    ):
        match = re.search(pattern, parameterized)
        if match is not None:
            overrides[Route(method, path)] = match.group(1)
    return overrides


def openapi_query_parameter_inventory(openapi_yaml: Path) -> dict[Route, tuple[str, ...]]:
    """Returns OpenAPI query parameter names for every documented route."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    component_parameters = document.get("components", {}).get("parameters", {})
    inventory: dict[Route, tuple[str, ...]] = {}
    for path, path_item in (document.get("paths", {}) or {}).items():
        path_parameters = path_item.get("parameters", []) or []
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            parameters = [*path_parameters, *(operation.get("parameters", []) or [])]
            query_names = [
                parameter["name"]
                for parameter in resolved_parameters(parameters, component_parameters)
                if parameter.get("in") == "query"
            ]
            inventory[Route(method.upper(), path)] = tuple(sorted(query_names))
    return inventory


def rust_body_field_inventory(route_body_metadata_rs: Path, routes_rs: Path) -> dict[Route, tuple[str, ...]]:
    """Returns Rust middleware JSON body field allowlists for router paths."""

    routes = rust_route_inventory(routes_rs)
    text = route_body_metadata_rs.read_text(encoding="utf-8")
    constants = query_constants(text)
    inventory = {route: () for route in routes}

    for method, path, constant in exact_body_field_returns(text):
        route = Route(method, path.removeprefix("/api/v1"))
        if route in inventory:
            inventory[route] = tuple(sorted(constants[constant]))

    for route, constant in parameterized_body_field_returns(text).items():
        if route in inventory:
            inventory[route] = tuple(sorted(constants[constant]))

    return inventory


def exact_body_field_returns(route_body_metadata_rs_text: str) -> list[tuple[str, str, str]]:
    returns: list[tuple[str, str, str]] = []
    for method, path, constant in re.findall(
        r'if method == "([A-Z]+)" && path == "([^"]+)" \{\s*return Some\((\w+)\);',
        route_body_metadata_rs_text,
    ):
        returns.append((method, path, constant))

    url_import = re.search(
        r"fn uses_url_import_body[\s\S]+?matches!\(\s*path,\s*([^)]+?)\s*\)",
        route_body_metadata_rs_text,
    )
    if url_import is not None:
        for path in re.findall(r'"([^"]+)"', url_import.group(1)):
            returns.append(("POST", path, "URL_IMPORT"))
    return returns


def parameterized_body_field_returns(route_body_metadata_rs_text: str) -> dict[Route, str]:
    returns: dict[Route, str] = {}
    route_body_fields = route_body_metadata_rs_text.split("fn route_body_fields", 1)[-1]
    for pattern, method, path in (
        (r'\("PATCH",\s*\["transfers", _\]\)\s*=>\s*Some\((\w+)\)', "PATCH", "/transfers/{hash}"),
        (r'\("PATCH",\s*\["shared-files", _\]\)\s*=>\s*Some\((\w+)\)', "PATCH", "/shared-files/{hash}"),
        (r'\("PATCH",\s*\["servers", _\]\)\s*=>\s*Some\((\w+)\)', "PATCH", "/servers/{serverId}"),
        (r'\("PATCH",\s*\["categories", _\]\)\s*=>\s*Some\((\w+)\)', "PATCH", "/categories/{categoryId}"),
        (
            r'\("POST",\s*\["searches", _, "results", _, "operations", "download"\]\)\s*=>\s*\{\s*Some\((\w+)\)',
            "POST",
            "/searches/{searchId}/results/{hash}/operations/download",
        ),
    ):
        match = re.search(pattern, route_body_fields)
        if match is not None:
            returns[Route(method, path)] = match.group(1)
    return returns


def openapi_body_field_inventory(openapi_yaml: Path) -> dict[Route, tuple[str, ...]]:
    """Returns top-level JSON request body fields for documented routes."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    schemas = document.get("components", {}).get("schemas", {})
    inventory: dict[Route, tuple[str, ...]] = {}
    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            schema = (
                operation.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            inventory[Route(method.upper(), path)] = tuple(sorted(schema_property_names(schema, schemas)))
    return inventory


def openapi_response_header_drift(openapi_yaml: Path) -> tuple[ResponseHeaderDrift, ...]:
    """Returns documented native responses missing the contract-version header."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    component_responses = document.get("components", {}).get("responses", {}) or {}
    drift: list[ResponseHeaderDrift] = []
    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            route = Route(method.upper(), path)
            for status, response in (operation.get("responses", {}) or {}).items():
                resolved = resolved_response(response, component_responses)
                headers = resolved.get("headers", {}) if isinstance(resolved, dict) else {}
                if REST_CONTRACT_VERSION_HEADER not in headers:
                    drift.append(
                        ResponseHeaderDrift(
                            route=route,
                            status=str(status),
                            missing_header=REST_CONTRACT_VERSION_HEADER,
                        )
                    )
    return tuple(sorted(drift))


def openapi_auth_drift(openapi_yaml: Path) -> tuple[AuthDrift, ...]:
    """Returns native OpenAPI auth contract gaps for the global X-API-Key surface."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[AuthDrift] = []
    security = document.get("security", []) or []
    has_global_api_key = any(
        isinstance(requirement, dict) and API_KEY_SECURITY_SCHEME in requirement
        for requirement in security
    )
    if not has_global_api_key:
        drift.append(
            AuthDrift(
                method="",
                path="<document>",
                issue=f"missing top-level {API_KEY_SECURITY_SCHEME} security requirement",
            )
        )

    security_scheme = (
        document.get("components", {})
        .get("securitySchemes", {})
        .get(API_KEY_SECURITY_SCHEME)
    )
    expected_scheme = {
        "type": "apiKey",
        "in": "header",
        "name": API_KEY_HEADER,
    }
    if not isinstance(security_scheme, dict) or any(
        security_scheme.get(key) != value for key, value in expected_scheme.items()
    ):
        drift.append(
            AuthDrift(
                method="",
                path="<document>",
                issue=f"{API_KEY_SECURITY_SCHEME} must be an apiKey header named {API_KEY_HEADER}",
            )
        )

    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            operation_security = operation.get("security")
            if operation_security is not None and not has_api_key_requirement(operation_security):
                drift.append(
                    AuthDrift(
                        method=method.upper(),
                        path=path,
                        issue=f"operation security override must include {API_KEY_SECURITY_SCHEME}",
                    )
                )
            responses = operation.get("responses", {}) or {}
            if "401" not in responses:
                drift.append(
                    AuthDrift(
                        method=method.upper(),
                        path=path,
                        issue="missing 401 response",
                    )
                )
    return tuple(sorted(drift))


def openapi_method_not_allowed_drift(openapi_yaml: Path) -> tuple[MethodNotAllowedDrift, ...]:
    """Returns native OpenAPI gaps in the 405 MethodNotAllowedResponse contract."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[MethodNotAllowedDrift] = []
    method_not_allowed = (
        document.get("components", {})
        .get("responses", {})
        .get("MethodNotAllowedResponse")
    )
    headers = method_not_allowed.get("headers", {}) if isinstance(method_not_allowed, dict) else {}
    if "Allow" not in headers:
        drift.append(
            MethodNotAllowedDrift(
                method="",
                path="<components.responses.MethodNotAllowedResponse>",
                issue="missing Allow header",
            )
        )

    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            response = (operation.get("responses", {}) or {}).get("405")
            if not isinstance(response, dict):
                drift.append(
                    MethodNotAllowedDrift(
                        method=method.upper(),
                        path=path,
                        issue="missing 405 response",
                    )
                )
            elif response.get("$ref") != METHOD_NOT_ALLOWED_RESPONSE_REF:
                drift.append(
                    MethodNotAllowedDrift(
                        method=method.upper(),
                        path=path,
                        issue="405 response must reference MethodNotAllowedResponse",
                    )
                )
    return tuple(sorted(drift))


def rust_contract_version(responses_rs: Path) -> str | None:
    """Returns the Rust native REST contract version constant."""

    text = responses_rs.read_text(encoding="utf-8")
    match = re.search(r'const\s+CONTRACT_VERSION:\s*&str\s*=\s*"([^"]+)"', text)
    return match.group(1) if match is not None else None


def openapi_contract_version_drift(
    openapi_yaml: Path,
    responses_rs: Path,
    expected_version: str = REST_CONTRACT_VERSION,
) -> tuple[ContractVersionDrift, ...]:
    """Returns Rust/OpenAPI version-value drift from the shared harness constant."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[ContractVersionDrift] = []
    rust_version = rust_contract_version(responses_rs)
    if rust_version is None:
        drift.append(
            ContractVersionDrift(
                source=str(responses_rs),
                issue="missing CONTRACT_VERSION constant",
            )
        )
    elif rust_version != expected_version:
        drift.append(
            ContractVersionDrift(
                source=str(responses_rs),
                issue=f"CONTRACT_VERSION must be {expected_version}, got {rust_version}",
            )
        )

    info = document.get("info", {}) if isinstance(document, dict) else {}
    if info.get("version") != expected_version:
        drift.append(
            ContractVersionDrift(
                source="info.version",
                issue=f"must be {expected_version}, got {info.get('version')!r}",
            )
        )
    if info.get("x-contract-version") != expected_version:
        drift.append(
            ContractVersionDrift(
                source="info.x-contract-version",
                issue=f"must be {expected_version}, got {info.get('x-contract-version')!r}",
            )
        )

    components = document.get("components", {}) if isinstance(document, dict) else {}
    headers = components.get("headers", {}) if isinstance(components, dict) else {}
    contract_header = headers.get("ContractVersionHeader", {}) if isinstance(headers, dict) else {}
    contract_header_schema = contract_header.get("schema", {}) if isinstance(contract_header, dict) else {}
    append_contract_schema_value_drift(
        drift,
        "components.headers.ContractVersionHeader.schema.const",
        contract_header_schema.get("const") if isinstance(contract_header_schema, dict) else None,
        expected_version,
    )
    append_contract_schema_value_drift(
        drift,
        "components.headers.ContractVersionHeader.schema.example",
        contract_header_schema.get("example") if isinstance(contract_header_schema, dict) else None,
        expected_version,
    )

    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    capabilities = schemas.get("CapabilityDiscovery", {}) if isinstance(schemas, dict) else {}
    capabilities_properties = capabilities.get("properties", {}) if isinstance(capabilities, dict) else {}
    contract_version_property = (
        capabilities_properties.get("contractVersion", {})
        if isinstance(capabilities_properties, dict)
        else {}
    )
    append_contract_schema_value_drift(
        drift,
        "components.schemas.CapabilityDiscovery.properties.contractVersion.const",
        contract_version_property.get("const") if isinstance(contract_version_property, dict) else None,
        expected_version,
    )
    append_contract_schema_value_drift(
        drift,
        "components.schemas.CapabilityDiscovery.properties.contractVersion.example",
        contract_version_property.get("example") if isinstance(contract_version_property, dict) else None,
        expected_version,
    )

    for source in contract_header_reference_sources(document):
        drift.append(
            ContractVersionDrift(
                source=source,
                issue=f"must reference {CONTRACT_VERSION_HEADER_REF}",
            )
        )
    return tuple(sorted(drift))


def append_contract_schema_value_drift(
    drift: list[ContractVersionDrift],
    source: str,
    actual: object,
    expected: str,
) -> None:
    if actual != expected:
        drift.append(
            ContractVersionDrift(
                source=source,
                issue=f"must be {expected}, got {actual!r}",
            )
        )


def contract_header_reference_sources(document: dict[str, object]) -> tuple[str, ...]:
    """Returns response locations where X-Contract-Version is not the shared header ref."""

    components = document.get("components", {}) if isinstance(document, dict) else {}
    component_responses = components.get("responses", {}) if isinstance(components, dict) else {}
    drift_sources: list[str] = []
    if isinstance(component_responses, dict):
        for name, response in component_responses.items():
            headers = response.get("headers", {}) if isinstance(response, dict) else {}
            header = headers.get(REST_CONTRACT_VERSION_HEADER) if isinstance(headers, dict) else None
            if header is not None and (not isinstance(header, dict) or header.get("$ref") != CONTRACT_VERSION_HEADER_REF):
                drift_sources.append(f"components.responses.{name}.headers.{REST_CONTRACT_VERSION_HEADER}")

    for path, path_item in (document.get("paths", {}) or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for status, response in (operation.get("responses", {}) or {}).items():
                headers = response.get("headers", {}) if isinstance(response, dict) else {}
                header = headers.get(REST_CONTRACT_VERSION_HEADER) if isinstance(headers, dict) else None
                if header is not None and (
                    not isinstance(header, dict) or header.get("$ref") != CONTRACT_VERSION_HEADER_REF
                ):
                    drift_sources.append(f"paths.{path}.{method}.responses.{status}.headers.{REST_CONTRACT_VERSION_HEADER}")
    return tuple(sorted(drift_sources))


def has_api_key_requirement(security: object) -> bool:
    if not isinstance(security, list):
        return False
    return any(
        isinstance(requirement, dict) and API_KEY_SECURITY_SCHEME in requirement
        for requirement in security
    )


def resolved_response(
    response: object, component_responses: dict[str, dict[str, object]]
) -> dict[str, object]:
    if not isinstance(response, dict):
        return {}
    reference = response.get("$ref")
    if isinstance(reference, str):
        return component_responses[reference.rsplit("/", 1)[-1]]
    return response


def schema_property_names(schema: object, schemas: dict[str, dict[str, object]]) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    reference = schema.get("$ref")
    if isinstance(reference, str):
        schema = schemas[reference.rsplit("/", 1)[-1]]
    names: set[str] = set()
    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        names.update(properties.keys())
    for combiner in ("allOf", "anyOf", "oneOf"):
        children = schema.get(combiner, [])
        if isinstance(children, list):
            for child in children:
                names.update(schema_property_names(child, schemas))
    return names


def resolved_parameters(
    parameters: Iterable[dict[str, object]], component_parameters: dict[str, dict[str, object]]
) -> Iterable[dict[str, object]]:
    for parameter in parameters:
        reference = parameter.get("$ref")
        if isinstance(reference, str):
            name = reference.rsplit("/", 1)[-1]
            yield component_parameters[name]
        else:
            yield parameter


def compare_route_inventory(routes_rs: Path, openapi_yaml: Path) -> RouteDriftReport:
    implemented = rust_route_inventory(routes_rs)
    documented = openapi_route_inventory(openapi_yaml)
    return RouteDriftReport(
        implemented_missing_from_openapi=tuple(sorted(implemented - documented)),
        openapi_missing_from_implemented=tuple(sorted(documented - implemented)),
    )


def compare_route_contract(
    routes_rs: Path,
    route_metadata_rs: Path,
    route_body_metadata_rs: Path,
    openapi_yaml: Path,
    responses_rs: Path | None = None,
) -> RouteDriftReport:
    implemented = rust_route_inventory(routes_rs)
    documented = openapi_route_inventory(openapi_yaml)
    rust_queries = rust_query_parameter_inventory(route_metadata_rs, routes_rs)
    openapi_queries = openapi_query_parameter_inventory(openapi_yaml)
    rust_bodies = rust_body_field_inventory(route_body_metadata_rs, routes_rs)
    openapi_bodies = openapi_body_field_inventory(openapi_yaml)
    response_header_drift = openapi_response_header_drift(openapi_yaml)
    auth_drift = openapi_auth_drift(openapi_yaml)
    method_not_allowed_drift = openapi_method_not_allowed_drift(openapi_yaml)
    contract_version_drift = (
        openapi_contract_version_drift(openapi_yaml, responses_rs)
        if responses_rs is not None
        else ()
    )
    common_routes = implemented & documented
    query_drift = tuple(
        sorted(
            QueryParameterDrift(
                route=route,
                rust_query_parameters=rust_queries.get(route, ()),
                openapi_query_parameters=openapi_queries.get(route, ()),
            )
            for route in common_routes
            if rust_queries.get(route, ()) != openapi_queries.get(route, ())
        )
    )
    body_drift = tuple(
        sorted(
            BodyFieldDrift(
                route=route,
                rust_body_fields=rust_bodies.get(route, ()),
                openapi_body_fields=openapi_bodies.get(route, ()),
            )
            for route in common_routes
            if rust_bodies.get(route, ()) != openapi_bodies.get(route, ())
        )
    )
    return RouteDriftReport(
        implemented_missing_from_openapi=tuple(sorted(implemented - documented)),
        openapi_missing_from_implemented=tuple(sorted(documented - implemented)),
        query_parameter_drift=query_drift,
        body_field_drift=body_drift,
        response_header_drift=response_header_drift,
        auth_drift=auth_drift,
        method_not_allowed_drift=method_not_allowed_drift,
        contract_version_drift=contract_version_drift,
    )


def default_routes_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "routes.rs"


def default_route_metadata_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "route_metadata.rs"


def default_route_body_metadata_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "route_body_metadata.rs"


def default_responses_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "responses.rs"


def default_openapi_yaml(workspace_root: Path) -> Path:
    return (
        workspace_root
        / "repos"
        / "emulebb-tooling"
        / "docs"
        / "products"
        / "emulebb-rust"
        / "api"
        / "REST-API-OPENAPI.yaml"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check emulebb-rust router metadata against the OpenAPI contract.")
    parser.add_argument("--rust-routes", type=Path, help="Path to crates/emulebb-rest/src/routes.rs.")
    parser.add_argument("--route-metadata", type=Path, help="Path to crates/emulebb-rest/src/route_metadata.rs.")
    parser.add_argument(
        "--route-body-metadata",
        type=Path,
        help="Path to crates/emulebb-rest/src/route_body_metadata.rs.",
    )
    parser.add_argument("--rust-responses", type=Path, help="Path to crates/emulebb-rest/src/responses.rs.")
    parser.add_argument("--openapi", type=Path, help="Path to the emulebb-rust OpenAPI YAML artifact.")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report.")
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace_root = get_required_emule_workspace_root()
    routes_rs = args.rust_routes or default_routes_rs(workspace_root)
    route_metadata_rs = args.route_metadata or default_route_metadata_rs(workspace_root)
    route_body_metadata_rs = args.route_body_metadata or default_route_body_metadata_rs(workspace_root)
    responses_rs = args.rust_responses or default_responses_rs(workspace_root)
    openapi_yaml = args.openapi or default_openapi_yaml(workspace_root)
    report = compare_route_contract(routes_rs, route_metadata_rs, route_body_metadata_rs, openapi_yaml, responses_rs)
    if args.json:
        print(json.dumps(report.as_json_dict(), indent=2, sort_keys=True))
    elif report.ok:
        print("emulebb-rust OpenAPI route, query, body, auth, 405, contract-version, and response-header inventory matches the router metadata.")
    else:
        print_route_drift_report(report)
    return 0 if report.ok else 1


def print_route_drift_report(report: RouteDriftReport) -> None:
    if report.implemented_missing_from_openapi:
        print("Implemented routes missing from OpenAPI:")
        for route in report.implemented_missing_from_openapi:
            print(f"  {route.method} {route.path}")
    if report.openapi_missing_from_implemented:
        print("OpenAPI routes missing from the Rust router:")
        for route in report.openapi_missing_from_implemented:
            print(f"  {route.method} {route.path}")
    if report.query_parameter_drift:
        print("Query parameter drift:")
        for drift in report.query_parameter_drift:
            rust_names = ", ".join(drift.rust_query_parameters) or "<none>"
            openapi_names = ", ".join(drift.openapi_query_parameters) or "<none>"
            print(f"  {drift.route.method} {drift.route.path}: rust=[{rust_names}] openapi=[{openapi_names}]")
    if report.body_field_drift:
        print("JSON body field drift:")
        for drift in report.body_field_drift:
            rust_names = ", ".join(drift.rust_body_fields) or "<none>"
            openapi_names = ", ".join(drift.openapi_body_fields) or "<none>"
            print(f"  {drift.route.method} {drift.route.path}: rust=[{rust_names}] openapi=[{openapi_names}]")
    if report.response_header_drift:
        print("Response header drift:")
        for drift in report.response_header_drift:
            print(f"  {drift.route.method} {drift.route.path} {drift.status}: missing {drift.missing_header}")
    if report.auth_drift:
        print("Auth contract drift:")
        for drift in report.auth_drift:
            route = f"{drift.method} {drift.path}".strip()
            print(f"  {route}: {drift.issue}")
    if report.method_not_allowed_drift:
        print("405 method-not-allowed contract drift:")
        for drift in report.method_not_allowed_drift:
            route = f"{drift.method} {drift.path}".strip()
            print(f"  {route}: {drift.issue}")
    if report.contract_version_drift:
        print("Contract-version drift:")
        for drift in report.contract_version_drift:
            print(f"  {drift.source}: {drift.issue}")
