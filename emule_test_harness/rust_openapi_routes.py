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
ERROR_RESPONSE_REF = "#/components/responses/ErrorResponse"
ERROR_ENVELOPE_REF = "#/components/schemas/ErrorEnvelope"
ERROR_RESPONSE_STATUSES = ("400", "401", "404", "default")
METHOD_NOT_ALLOWED_RESPONSE_REF = "#/components/responses/MethodNotAllowedResponse"
CONTRACT_VERSION_HEADER_REF = "#/components/headers/ContractVersionHeader"
EVENT_STREAM_RESPONSE_COMPONENT = "EventStreamResponse"
DIAGNOSTIC_DUMP_REQUEST_COMPONENT = "DiagnosticDumpRequest"
QUERY_NUMERIC_PARAMETER_SCHEMAS = {
    "Limit": ("limit", 1, 1000),
    "Offset": ("offset", 0, 2_147_483_647),
    "TransferCategoryIdFilter": ("categoryId", 0, 4_294_967_295),
}
PATH_NUMERIC_PARAMETER_SCHEMAS = {
    "CategoryId": ("categoryId", 0, 4_294_967_295),
    "SearchId": ("searchId", 0, 4_294_967_295),
}
PATH_LOWERCASE_MD4_PARAMETER_SCHEMAS = {
    "FileHash": "hash",
    "UserHash": "userHash",
}
QUERY_BOOLEAN_PARAMETER_SCHEMAS = {
    "IncludeScoreBreakdown": "includeScoreBreakdown",
    "IncludeEvidence": "includeEvidence",
    "ExactTotal": "exactTotal",
}
TRANSFER_EVENT_COMPONENT = "TransferEvent"
TRANSFER_EVENT_VARIANTS = {
    "transfer.added": "TransferAddedEvent",
    "transfer.updated": "TransferUpdatedEvent",
    "transfer.removed": "TransferRemovedEvent",
    "sync.reset": "TransferSyncResetEvent",
}
TRANSFER_EVENT_REQUIRED_FIELDS = {
    "TransferAddedEvent": ("id", "transfer", "type"),
    "TransferUpdatedEvent": ("id", "transfer", "type"),
    "TransferRemovedEvent": ("hash", "id", "type"),
    "TransferSyncResetEvent": ("id", "reason", "type"),
}
TRANSFER_STATE_COMPONENT = "TransferState"
TRANSFER_STATE_VALUES = (
    "downloading",
    "paused",
    "queued",
    "checking",
    "completing",
    "completed",
    "error",
    "missingfiles",
)
TRANSFER_CREATE_REQUEST_COMPONENT = "TransferCreateRequest"
TRANSFER_ADD_LINK_PATTERN = r"^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$"
TRANSFER_PRIORITY_COMPONENT = "TransferPriority"
TRANSFER_PRIORITY_VALUES = ("auto", "verylow", "low", "normal", "high", "veryhigh")
TRANSFER_PATCH_COMPONENT = "TransferPatch"
TRANSFER_PATCH_MUTATION_FAMILIES = ("priority", "name", "categoryId", "categoryName")
TRANSFER_RENAME_PATTERN = r'^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
SHARED_FILE_PATCH_COMPONENT = "SharedFilePatch"
SHARED_FILE_PRIORITY_COMPONENT = "SharedFilePriority"
SHARED_FILE_PRIORITY_VALUES = ("auto", "verylow", "low", "normal", "high", "release")
SEARCH_CREATE_REQUEST_COMPONENT = "SearchCreateRequest"
SEARCH_QUERY_PATTERN = r"^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$"
SEARCH_METHOD_VALUES = ("automatic", "server", "global", "kad")
SEARCH_TYPE_VALUES = (
    "",
    "arc",
    "audio",
    "iso",
    "image",
    "pro",
    "video",
    "doc",
    "emulecollection",
)
SEARCH_RESULT_DOWNLOAD_REQUEST_COMPONENT = "SearchResultDownloadRequest"
URL_IMPORT_REQUEST_COMPONENT = "UrlImportRequest"
URL_IMPORT_PATTERN = r"^[hH][tT][tT][pP][sS]?://[^\s/?#\x00-\x1F\x7F-\x9F][^\s\x00-\x1F\x7F-\x9F]*$"
NON_EMPTY_AFTER_TRIM_PATTERN = r"\S"
SERVER_CREATE_REQUEST_COMPONENT = "ServerCreateRequest"
SERVER_PATCH_COMPONENT = "ServerPatch"
SERVER_PRIORITY_VALUES = ("low", "normal", "high")
KAD_BOOTSTRAP_REQUEST_COMPONENT = "KadBootstrapRequest"
FRIEND_CREATE_REQUEST_COMPONENT = "FriendCreateRequest"
CONTROL_FREE_TEXT_PATTERN = r"^[^\x00-\x1F\x7F-\x9F]*$"
FRIEND_USER_HASH_PATTERN = r"^[0-9a-f]{32}$"
CATEGORY_PRIORITY_INPUT_COMPONENT = "CategoryPriorityInput"
CATEGORY_PRIORITY_VALUES = ("verylow", "low", "normal", "high", "veryhigh")
CATEGORY_CREATE_REQUEST_COMPONENT = "CategoryCreateRequest"
CATEGORY_PATCH_COMPONENT = "CategoryPatch"
SHARED_DIRECTORY_ROOT_INPUT_COMPONENT = "SharedDirectoryRootInput"
GENERIC_SECTION_RESOURCE_RESPONSE_COMPONENTS = {
    "BulkOperationResponse",
    "OkResponse",
}
NON_EMPTY_UPDATE_SCHEMA_SUFFIXES = ("Patch", "Update")


@dataclass(frozen=True, order=True)
class Route:
    """One HTTP method/path pair in the native Rust REST contract."""

    method: str
    path: str


@dataclass(frozen=True, order=True)
class ComponentRefDrift:
    """An OpenAPI reference that is not a resolvable local component ref."""

    source: str
    reference: str
    issue: str


@dataclass(frozen=True)
class RouteDriftReport:
    """Route, query, and body drift between Rust metadata and OpenAPI."""

    implemented_missing_from_openapi: tuple[Route, ...]
    openapi_missing_from_implemented: tuple[Route, ...]
    component_ref_drift: tuple[ComponentRefDrift, ...] = ()
    operation_metadata_drift: tuple[OperationMetadataDrift, ...] = ()
    tag_taxonomy_drift: tuple[TagTaxonomyDrift, ...] = ()
    parameter_metadata_drift: tuple[ParameterMetadataDrift, ...] = ()
    parameter_ref_drift: tuple[ParameterRefDrift, ...] = ()
    schema_component_drift: tuple[SchemaComponentDrift, ...] = ()
    confirmation_contract_drift: tuple[ConfirmationContractDrift, ...] = ()
    query_parameter_drift: tuple[QueryParameterDrift, ...] = ()
    path_parameter_drift: tuple[PathParameterDrift, ...] = ()
    body_field_drift: tuple[BodyFieldDrift, ...] = ()
    request_body_metadata_drift: tuple[RequestBodyMetadataDrift, ...] = ()
    success_response_drift: tuple[SuccessResponseDrift, ...] = ()
    response_component_drift: tuple[ResponseComponentDrift, ...] = ()
    response_header_drift: tuple[ResponseHeaderDrift, ...] = ()
    auth_drift: tuple[AuthDrift, ...] = ()
    error_response_drift: tuple[ErrorResponseDrift, ...] = ()
    method_not_allowed_drift: tuple[MethodNotAllowedDrift, ...] = ()
    contract_version_drift: tuple[ContractVersionDrift, ...] = ()
    section_resource_openapi_drift: tuple[SettingsSectionResourceOpenApiDrift, ...] = ()
    section_resource_response_drift: tuple[SettingsSectionResourceResponseDrift, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            not self.implemented_missing_from_openapi
            and not self.openapi_missing_from_implemented
            and not self.component_ref_drift
            and not self.operation_metadata_drift
            and not self.tag_taxonomy_drift
            and not self.parameter_metadata_drift
            and not self.parameter_ref_drift
            and not self.schema_component_drift
            and not self.confirmation_contract_drift
            and not self.query_parameter_drift
            and not self.path_parameter_drift
            and not self.body_field_drift
            and not self.request_body_metadata_drift
            and not self.success_response_drift
            and not self.response_component_drift
            and not self.response_header_drift
            and not self.auth_drift
            and not self.error_response_drift
            and not self.method_not_allowed_drift
            and not self.contract_version_drift
            and not self.section_resource_openapi_drift
            and not self.section_resource_response_drift
        )

    def as_json_dict(self) -> dict[str, list[dict[str, object]]]:
        return {
            "implementedMissingFromOpenapi": route_list_json(self.implemented_missing_from_openapi),
            "openapiMissingFromImplemented": route_list_json(self.openapi_missing_from_implemented),
            "componentRefDrift": component_ref_drift_json(self.component_ref_drift),
            "operationMetadataDrift": operation_metadata_drift_json(self.operation_metadata_drift),
            "tagTaxonomyDrift": tag_taxonomy_drift_json(self.tag_taxonomy_drift),
            "parameterMetadataDrift": parameter_metadata_drift_json(self.parameter_metadata_drift),
            "parameterRefDrift": parameter_ref_drift_json(self.parameter_ref_drift),
            "schemaComponentDrift": schema_component_drift_json(self.schema_component_drift),
            "confirmationContractDrift": confirmation_contract_drift_json(self.confirmation_contract_drift),
            "queryParameterDrift": query_parameter_drift_json(self.query_parameter_drift),
            "pathParameterDrift": path_parameter_drift_json(self.path_parameter_drift),
            "bodyFieldDrift": body_field_drift_json(self.body_field_drift),
            "requestBodyMetadataDrift": request_body_metadata_drift_json(self.request_body_metadata_drift),
            "successResponseDrift": success_response_drift_json(self.success_response_drift),
            "responseComponentDrift": response_component_drift_json(self.response_component_drift),
            "responseHeaderDrift": response_header_drift_json(self.response_header_drift),
            "authDrift": auth_drift_json(self.auth_drift),
            "errorResponseDrift": error_response_drift_json(self.error_response_drift),
            "methodNotAllowedDrift": method_not_allowed_drift_json(self.method_not_allowed_drift),
            "contractVersionDrift": contract_version_drift_json(self.contract_version_drift),
            "sectionResourceOpenapiDrift": settings_section_resource_openapi_drift_json(
                self.section_resource_openapi_drift
            ),
            "sectionResourceResponseDrift": settings_section_resource_response_drift_json(
                self.section_resource_response_drift
            ),
        }


@dataclass(frozen=True, order=True)
class QueryParameterDrift:
    """A route whose Rust query allowlist does not match OpenAPI query names."""

    route: Route
    rust_query_parameters: tuple[str, ...]
    openapi_query_parameters: tuple[str, ...]


@dataclass(frozen=True, order=True)
class OperationMetadataDrift:
    """An OpenAPI operation whose generator-facing metadata is incomplete."""

    method: str
    path: str
    issue: str


@dataclass(frozen=True, order=True)
class TagTaxonomyDrift:
    """An OpenAPI tag that is undeclared, duplicated, invalid, or unused."""

    source: str
    tag: str
    issue: str


@dataclass(frozen=True, order=True)
class ParameterMetadataDrift:
    """An OpenAPI parameter whose client-facing metadata is incomplete."""

    source: str
    issue: str


@dataclass(frozen=True, order=True)
class ParameterRefDrift:
    """An OpenAPI operation/path parameter that bypasses shared components."""

    source: str
    issue: str


@dataclass(frozen=True, order=True)
class SchemaComponentDrift:
    """An OpenAPI schema component whose reusable shape is incomplete."""

    component: str
    issue: str


@dataclass(frozen=True, order=True)
class ConfirmationContractDrift:
    """A destructive-operation confirmation contract gap."""

    source: str
    issue: str


@dataclass(frozen=True, order=True)
class PathParameterDrift:
    """An OpenAPI path whose template placeholders do not match path parameters."""

    method: str
    path: str
    template_parameters: tuple[str, ...]
    documented_path_parameters: tuple[str, ...]
    issue: str


@dataclass(frozen=True, order=True)
class BodyFieldDrift:
    """A route whose Rust JSON body allowlist does not match OpenAPI fields."""

    route: Route
    rust_body_fields: tuple[str, ...]
    openapi_body_fields: tuple[str, ...]


@dataclass(frozen=True, order=True)
class RequestBodyMetadataDrift:
    """An OpenAPI request body that is ambiguous or bypasses shared JSON schemas."""

    method: str
    path: str
    issue: str


@dataclass(frozen=True, order=True)
class SuccessResponseDrift:
    """An OpenAPI success response that is missing or bypasses shared components."""

    method: str
    path: str
    status: str
    issue: str


@dataclass(frozen=True, order=True)
class ResponseComponentDrift:
    """An OpenAPI response component whose reusable metadata is incomplete."""

    component: str
    issue: str


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
class ErrorResponseDrift:
    """An OpenAPI shared error-envelope response contract gap."""

    method: str
    path: str
    status: str
    issue: str


@dataclass(frozen=True, order=True)
class ContractVersionDrift:
    """A Rust/OpenAPI/harness contract-version mismatch."""

    source: str
    issue: str


@dataclass(frozen=True, order=True)
class SettingsSectionResourceOpenApiDrift:
    """A Settings section resource route that is not documented as an OpenAPI GET operation."""

    name: str
    route: str
    issue: str


@dataclass(frozen=True, order=True)
class SettingsSectionResourceResponseDrift:
    """A Settings section resource OpenAPI response that is too weak for generated clients."""

    name: str
    route: str
    issue: str


def route_list_json(routes: Iterable[Route]) -> list[dict[str, str]]:
    return [{"method": route.method, "path": route.path} for route in routes]


def component_ref_drift_json(drifts: Iterable[ComponentRefDrift]) -> list[dict[str, str]]:
    return [
        {
            "source": drift.source,
            "reference": drift.reference,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


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


def operation_metadata_drift_json(drifts: Iterable[OperationMetadataDrift]) -> list[dict[str, str]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def tag_taxonomy_drift_json(drifts: Iterable[TagTaxonomyDrift]) -> list[dict[str, str]]:
    return [
        {
            "source": drift.source,
            "tag": drift.tag,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def parameter_metadata_drift_json(drifts: Iterable[ParameterMetadataDrift]) -> list[dict[str, str]]:
    return [
        {
            "source": drift.source,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def parameter_ref_drift_json(drifts: Iterable[ParameterRefDrift]) -> list[dict[str, str]]:
    return [
        {
            "source": drift.source,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def schema_component_drift_json(drifts: Iterable[SchemaComponentDrift]) -> list[dict[str, str]]:
    return [
        {
            "component": drift.component,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def confirmation_contract_drift_json(drifts: Iterable[ConfirmationContractDrift]) -> list[dict[str, str]]:
    return [
        {
            "source": drift.source,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def path_parameter_drift_json(drifts: Iterable[PathParameterDrift]) -> list[dict[str, object]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "templateParameters": list(drift.template_parameters),
            "documentedPathParameters": list(drift.documented_path_parameters),
            "issue": drift.issue,
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


def request_body_metadata_drift_json(drifts: Iterable[RequestBodyMetadataDrift]) -> list[dict[str, str]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def success_response_drift_json(drifts: Iterable[SuccessResponseDrift]) -> list[dict[str, str]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "status": drift.status,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def response_component_drift_json(drifts: Iterable[ResponseComponentDrift]) -> list[dict[str, str]]:
    return [
        {
            "component": drift.component,
            "issue": drift.issue,
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


def error_response_drift_json(drifts: Iterable[ErrorResponseDrift]) -> list[dict[str, str]]:
    return [
        {
            "method": drift.method,
            "path": drift.path,
            "status": drift.status,
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


def settings_section_resource_openapi_drift_json(
    drifts: Iterable[SettingsSectionResourceOpenApiDrift],
) -> list[dict[str, str]]:
    return [
        {
            "name": drift.name,
            "route": drift.route,
            "issue": drift.issue,
        }
        for drift in drifts
    ]


def settings_section_resource_response_drift_json(
    drifts: Iterable[SettingsSectionResourceResponseDrift],
) -> list[dict[str, str]]:
    return [
        {
            "name": drift.name,
            "route": drift.route,
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


def rust_settings_section_resource_inventory(settings_surface_rs: Path) -> dict[str, str]:
    """Returns Settings section resource names and full REST routes from `surface.rs`."""

    text = settings_surface_rs.read_text(encoding="utf-8")
    inventory_match = re.search(
        r"const\s+SETTINGS_SECTION_RESOURCES\s*:\s*&\[SettingsSectionResourceSpec\]\s*=\s*&\[(?P<body>.*?)\];",
        text,
        re.DOTALL,
    )
    if inventory_match is None:
        raise RuntimeError("Rust Settings section resource inventory is missing")

    resources: dict[str, str] = {}
    for resource_match in re.finditer(
        r"SettingsSectionResourceSpec\s*\{(?P<body>.*?)\}",
        inventory_match.group("body"),
        re.DOTALL,
    ):
        body = resource_match.group("body")
        name_match = re.search(r'name:\s*"([^"]+)"', body)
        route_match = re.search(r'route:\s*"([^"]+)"', body)
        if name_match is None or route_match is None:
            raise RuntimeError("Rust Settings section resource is missing name or route")
        resources[name_match.group(1)] = route_match.group(1)
    return resources


def settings_section_resource_openapi_drift(
    settings_surface_rs: Path,
    openapi_yaml: Path,
) -> tuple[SettingsSectionResourceOpenApiDrift, ...]:
    """Returns Settings section resources not documented as OpenAPI GET operations."""

    documented = openapi_route_inventory(openapi_yaml)
    drift: list[SettingsSectionResourceOpenApiDrift] = []
    for name, route in rust_settings_section_resource_inventory(settings_surface_rs).items():
        if not route.startswith("/api/v1/"):
            drift.append(
                SettingsSectionResourceOpenApiDrift(
                    name=name,
                    route=route,
                    issue="route must start with /api/v1/",
                )
            )
            continue

        if Route("GET", route.removeprefix("/api/v1")) not in documented:
            drift.append(
                SettingsSectionResourceOpenApiDrift(
                    name=name,
                    route=route,
                    issue="missing GET operation in OpenAPI paths",
                )
            )
    return tuple(sorted(drift))


def settings_section_resource_response_drift(
    settings_surface_rs: Path,
    openapi_yaml: Path,
) -> tuple[SettingsSectionResourceResponseDrift, ...]:
    """Returns Settings section resources whose documented response is not a closed named DTO."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    components = document.get("components", {}) if isinstance(document, dict) else {}
    responses = components.get("responses", {}) if isinstance(components, dict) else {}
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    paths = document.get("paths", {}) if isinstance(document, dict) else {}
    drift: list[SettingsSectionResourceResponseDrift] = []

    for name, route in rust_settings_section_resource_inventory(settings_surface_rs).items():
        if not route.startswith("/api/v1/"):
            continue
        openapi_path = route.removeprefix("/api/v1")
        operation = (paths.get(openapi_path, {}) or {}).get("get")
        if not isinstance(operation, dict):
            continue

        success_ref = operation_success_response_ref(operation)
        if success_ref is None:
            drift.append(
                SettingsSectionResourceResponseDrift(
                    name=name,
                    route=route,
                    issue="GET operation must reference exactly one 2xx response component",
                )
            )
            continue
        response_component = success_ref.rsplit("/", 1)[-1]
        if response_component in GENERIC_SECTION_RESOURCE_RESPONSE_COMPONENTS:
            drift.append(
                SettingsSectionResourceResponseDrift(
                    name=name,
                    route=route,
                    issue=f"GET operation must not use generic {response_component}",
                )
            )
            continue

        response = responses.get(response_component)
        envelope_ref = response_schema_ref(response)
        if envelope_ref is None:
            drift.append(
                SettingsSectionResourceResponseDrift(
                    name=name,
                    route=route,
                    issue=f"response component {response_component} must reference a named envelope schema",
                )
            )
            continue

        envelope_name = envelope_ref.rsplit("/", 1)[-1]
        envelope = schemas.get(envelope_name)
        if not schema_is_closed_object(envelope):
            drift.append(
                SettingsSectionResourceResponseDrift(
                    name=name,
                    route=route,
                    issue=f"envelope schema {envelope_name} must be closed",
                )
            )
            continue

        data_ref = envelope_data_ref(envelope)
        if data_ref is None:
            drift.append(
                SettingsSectionResourceResponseDrift(
                    name=name,
                    route=route,
                    issue=f"envelope schema {envelope_name} data must reference a named schema component",
                )
            )
            continue

        data_name = data_ref.rsplit("/", 1)[-1]
        data_schema = schemas.get(data_name)
        if not schema_is_closed_object(data_schema):
            drift.append(
                SettingsSectionResourceResponseDrift(
                    name=name,
                    route=route,
                    issue=f"data schema {data_name} must be a closed object",
                )
            )
    return tuple(sorted(drift))


def operation_success_response_ref(operation: dict[str, object]) -> str | None:
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return None
    success_statuses = tuple(sorted(status for status in responses if is_success_status(status)))
    if len(success_statuses) != 1:
        return None
    response = responses.get(success_statuses[0])
    reference = response.get("$ref") if isinstance(response, dict) else None
    if not isinstance(reference, str) or not reference.startswith("#/components/responses/"):
        return None
    return reference


def response_schema_ref(response: object) -> str | None:
    if not isinstance(response, dict):
        return None
    content = response.get("content", {})
    media = content.get("application/json", {}) if isinstance(content, dict) else {}
    schema = media.get("schema", {}) if isinstance(media, dict) else {}
    reference = schema.get("$ref") if isinstance(schema, dict) else None
    if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
        return reference
    return None


def envelope_data_ref(envelope: object) -> str | None:
    if not isinstance(envelope, dict):
        return None
    candidates = [envelope]
    all_of = envelope.get("allOf", [])
    if isinstance(all_of, list):
        candidates.extend(candidate for candidate in all_of if isinstance(candidate, dict))
    for candidate in candidates:
        properties = candidate.get("properties", {})
        data = properties.get("data") if isinstance(properties, dict) else None
        reference = data.get("$ref") if isinstance(data, dict) else None
        if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
            return reference
    return None


def schema_is_closed_object(schema: object) -> bool:
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == "object" and schema.get("additionalProperties") is False:
        return True
    if schema.get("unevaluatedProperties") is False:
        return True
    return False


def openapi_operation_metadata_drift(openapi_yaml: Path) -> tuple[OperationMetadataDrift, ...]:
    """Returns OpenAPI operations missing stable generator-facing metadata."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[OperationMetadataDrift] = []
    operation_ids: dict[str, Route] = {}
    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            route = Route(method.upper(), path)
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or operation_id.strip() == "":
                drift.append(
                    OperationMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="missing operationId",
                    )
                )
            elif operation_id in operation_ids:
                previous = operation_ids[operation_id]
                drift.append(
                    OperationMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue=f"duplicate operationId {operation_id!r} also used by {previous.method} {previous.path}",
                    )
                )
            else:
                operation_ids[operation_id] = route

            tags = operation.get("tags")
            if not isinstance(tags, list) or not tags or not all(isinstance(tag, str) and tag for tag in tags):
                drift.append(
                    OperationMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="missing tags",
                    )
                )
            summary = operation.get("summary")
            if not isinstance(summary, str) or summary.strip() == "":
                drift.append(
                    OperationMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="missing summary",
                    )
                )
    return tuple(sorted(drift))


def openapi_tag_taxonomy_drift(openapi_yaml: Path) -> tuple[TagTaxonomyDrift, ...]:
    """Returns OpenAPI tag taxonomy drift for generator/client grouping."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[TagTaxonomyDrift] = []
    declared_tags: set[str] = set()
    tag_items = document.get("tags", []) if isinstance(document, dict) else []
    if not isinstance(tag_items, list):
        drift.append(TagTaxonomyDrift(source="tags", tag="", issue="top-level tags must be a list"))
    else:
        for index, tag_item in enumerate(tag_items):
            name = tag_item.get("name") if isinstance(tag_item, dict) else None
            source = f"tags[{index}]"
            if not isinstance(name, str) or name.strip() == "":
                drift.append(TagTaxonomyDrift(source=source, tag="", issue="tag entry must have a non-empty name"))
            elif name in declared_tags:
                drift.append(TagTaxonomyDrift(source=source, tag=name, issue="duplicate top-level tag"))
            else:
                declared_tags.add(name)

    used_tags: set[str] = set()
    for path, path_item in (document.get("paths", {}) or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            tags = operation.get("tags", [])
            if not isinstance(tags, list):
                continue
            for tag in tags:
                if not isinstance(tag, str) or tag.strip() == "":
                    continue
                used_tags.add(tag)
                if tag not in declared_tags:
                    drift.append(
                        TagTaxonomyDrift(
                            source=f"paths.{path}.{method}.tags",
                            tag=tag,
                            issue="operation tag is not declared",
                        )
                    )

    for tag in declared_tags - used_tags:
        drift.append(TagTaxonomyDrift(source="tags", tag=tag, issue="declared tag is unused"))
    return tuple(sorted(drift))


def openapi_component_ref_drift(openapi_yaml: Path) -> tuple[ComponentRefDrift, ...]:
    """Returns OpenAPI $refs that are external, non-component, or unresolved."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[ComponentRefDrift] = []
    for source, reference in openapi_refs(document):
        if not isinstance(reference, str):
            drift.append(
                ComponentRefDrift(
                    source=source,
                    reference=repr(reference),
                    issue="$ref must be a string",
                )
            )
        elif not reference.startswith("#/components/"):
            drift.append(
                ComponentRefDrift(
                    source=source,
                    reference=reference,
                    issue="unsupported non-local component reference",
                )
            )
        elif not openapi_pointer_exists(document, reference):
            drift.append(
                ComponentRefDrift(
                    source=source,
                    reference=reference,
                    issue="missing local component target",
                )
            )
    return tuple(sorted(drift))


def openapi_refs(value: object, source: str = "$") -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        if "$ref" in value:
            yield (f"{source}.$ref", value["$ref"])
        for key, child in value.items():
            yield from openapi_refs(child, f"{source}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from openapi_refs(child, f"{source}[{index}]")


def openapi_pointer_exists(document: object, reference: str) -> bool:
    if not reference.startswith("#/"):
        return False
    value = document
    for raw_token in reference[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            if token not in value:
                return False
            value = value[token]
        elif isinstance(value, list) and token.isdecimal():
            index = int(token)
            if index >= len(value):
                return False
            value = value[index]
        else:
            return False
    return True


def openapi_parameter_metadata_drift(openapi_yaml: Path) -> tuple[ParameterMetadataDrift, ...]:
    """Returns parameters missing explicit generator-facing metadata."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[ParameterMetadataDrift] = []
    components = document.get("components", {}) if isinstance(document, dict) else {}
    component_parameters = components.get("parameters", {}) if isinstance(components, dict) else {}
    if isinstance(component_parameters, dict):
        for name, parameter in component_parameters.items():
            source = f"components.parameters.{name}"
            append_parameter_metadata_drift(drift, source, parameter)
            append_query_numeric_parameter_schema_drift(drift, name, source, parameter)
            append_path_numeric_parameter_schema_drift(drift, name, source, parameter)
            append_path_lowercase_md4_parameter_schema_drift(drift, name, source, parameter)
            append_query_boolean_parameter_schema_drift(drift, name, source, parameter)
            append_transfer_state_parameter_schema_drift(drift, name, source, parameter)

    for path, path_item in (document.get("paths", {}) or {}).items():
        if not isinstance(path_item, dict):
            continue
        for index, parameter in enumerate(path_item.get("parameters", []) or []):
            append_parameter_metadata_drift(drift, f"paths.{path}.parameters[{index}]", parameter)
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for index, parameter in enumerate(operation.get("parameters", []) or []):
                append_parameter_metadata_drift(drift, f"paths.{path}.{method}.parameters[{index}]", parameter)
    return tuple(sorted(drift))


def openapi_parameter_ref_drift(openapi_yaml: Path) -> tuple[ParameterRefDrift, ...]:
    """Returns path/operation parameters that bypass shared parameter components."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[ParameterRefDrift] = []
    for path, path_item in (document.get("paths", {}) or {}).items():
        if not isinstance(path_item, dict):
            continue
        for index, parameter in enumerate(path_item.get("parameters", []) or []):
            append_parameter_ref_drift(drift, f"paths.{path}.parameters[{index}]", parameter)
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for index, parameter in enumerate(operation.get("parameters", []) or []):
                append_parameter_ref_drift(drift, f"paths.{path}.{method}.parameters[{index}]", parameter)
    return tuple(sorted(drift))


def append_parameter_ref_drift(
    drift: list[ParameterRefDrift],
    source: str,
    parameter: object,
) -> None:
    reference = parameter.get("$ref") if isinstance(parameter, dict) else None
    if not isinstance(reference, str) or not reference.startswith("#/components/parameters/"):
        drift.append(
            ParameterRefDrift(
                source=source,
                issue="parameter must reference a shared parameter component",
            )
        )


def openapi_schema_component_drift(openapi_yaml: Path) -> tuple[SchemaComponentDrift, ...]:
    """Returns shared schema components with incomplete generator-facing shape."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    components = document.get("components", {}) if isinstance(document, dict) else {}
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    responses = components.get("responses", {}) if isinstance(components, dict) else {}
    if not isinstance(schemas, dict):
        return (
            SchemaComponentDrift(
                component="<components.schemas>",
                issue="components.schemas must be an object",
            ),
        )

    drift: list[SchemaComponentDrift] = []
    shape_keywords = {"allOf", "anyOf", "const", "enum", "oneOf", "type"}
    for name, schema in schemas.items():
        if not isinstance(schema, dict):
            drift.append(SchemaComponentDrift(component=name, issue="schema component must be an object"))
            continue
        if not schema:
            drift.append(SchemaComponentDrift(component=name, issue="schema component must not be empty"))
            continue
        if not any(keyword in schema for keyword in shape_keywords):
            drift.append(
                SchemaComponentDrift(
                    component=name,
                    issue="schema component must declare type, composition, enum, or const",
                )
            )
        enum_values = schema.get("enum")
        if enum_values is not None and (not isinstance(enum_values, list) or not enum_values):
            drift.append(SchemaComponentDrift(component=name, issue="enum must be a non-empty list"))
        if (
            name.endswith(NON_EMPTY_UPDATE_SCHEMA_SUFFIXES)
            and schema.get("type") == "object"
            and not schema_rejects_empty_object(schema)
        ):
            drift.append(
                SchemaComponentDrift(
                    component=name,
                    issue="patch/update schema must reject empty objects with minProperties: 1 or required-field composition",
                )
            )
    if TRANSFER_EVENT_COMPONENT in schemas or EVENT_STREAM_RESPONSE_COMPONENT in responses:
        append_transfer_event_schema_drift(drift, schemas)
    if DIAGNOSTIC_DUMP_REQUEST_COMPONENT in schemas:
        append_diagnostic_dump_schema_drift(drift, schemas)
    if TRANSFER_STATE_COMPONENT in schemas:
        assert_priority_enum_schema(
            drift,
            TRANSFER_STATE_COMPONENT,
            schemas.get(TRANSFER_STATE_COMPONENT),
            TRANSFER_STATE_VALUES,
            "transfer state",
        )
    if TRANSFER_CREATE_REQUEST_COMPONENT in schemas:
        append_transfer_create_schema_drift(drift, schemas)
    if TRANSFER_PRIORITY_COMPONENT in schemas:
        assert_priority_enum_schema(
            drift,
            TRANSFER_PRIORITY_COMPONENT,
            schemas.get(TRANSFER_PRIORITY_COMPONENT),
            TRANSFER_PRIORITY_VALUES,
            "transfer priority",
        )
    if TRANSFER_PATCH_COMPONENT in schemas:
        append_transfer_patch_schema_drift(drift, schemas)
    if SHARED_FILE_PRIORITY_COMPONENT in schemas:
        assert_priority_enum_schema(
            drift,
            SHARED_FILE_PRIORITY_COMPONENT,
            schemas.get(SHARED_FILE_PRIORITY_COMPONENT),
            SHARED_FILE_PRIORITY_VALUES,
            "shared file priority",
        )
    if SHARED_FILE_PATCH_COMPONENT in schemas:
        append_shared_file_patch_schema_drift(drift, schemas)
    if SEARCH_CREATE_REQUEST_COMPONENT in schemas:
        append_search_create_schema_drift(drift, schemas)
    if SEARCH_RESULT_DOWNLOAD_REQUEST_COMPONENT in schemas:
        append_search_result_download_schema_drift(drift, schemas)
    if URL_IMPORT_REQUEST_COMPONENT in schemas:
        append_url_import_schema_drift(drift, schemas)
    if SERVER_CREATE_REQUEST_COMPONENT in schemas:
        append_endpoint_request_schema_drift(
            drift,
            schemas,
            SERVER_CREATE_REQUEST_COMPONENT,
            "ServerCreateRequest.properties.address",
            "ServerCreateRequest.properties.port",
        )
        append_server_name_schema_drift(drift, schemas, SERVER_CREATE_REQUEST_COMPONENT)
        append_server_priority_schema_drift(drift, schemas, SERVER_CREATE_REQUEST_COMPONENT)
        append_server_boolean_schema_drift(
            drift,
            schemas,
            SERVER_CREATE_REQUEST_COMPONENT,
            ("static", "connect"),
        )
    if SERVER_PATCH_COMPONENT in schemas:
        append_server_name_schema_drift(drift, schemas, SERVER_PATCH_COMPONENT)
        append_server_priority_schema_drift(drift, schemas, SERVER_PATCH_COMPONENT)
        append_server_boolean_schema_drift(
            drift,
            schemas,
            SERVER_PATCH_COMPONENT,
            ("static", "enabled"),
        )
    if KAD_BOOTSTRAP_REQUEST_COMPONENT in schemas:
        append_endpoint_request_schema_drift(
            drift,
            schemas,
            KAD_BOOTSTRAP_REQUEST_COMPONENT,
            "KadBootstrapRequest.properties.address",
            "KadBootstrapRequest.properties.port",
        )
    if CATEGORY_PRIORITY_INPUT_COMPONENT in schemas:
        assert_category_priority_input_schema(
            drift,
            schemas.get(CATEGORY_PRIORITY_INPUT_COMPONENT),
        )
    if FRIEND_CREATE_REQUEST_COMPONENT in schemas:
        append_friend_create_schema_drift(drift, schemas)
    if CATEGORY_CREATE_REQUEST_COMPONENT in schemas:
        append_category_mutation_schema_drift(
            drift,
            schemas,
            CATEGORY_CREATE_REQUEST_COMPONENT,
        )
    if CATEGORY_PATCH_COMPONENT in schemas:
        append_category_mutation_schema_drift(drift, schemas, CATEGORY_PATCH_COMPONENT)
    if SHARED_DIRECTORY_ROOT_INPUT_COMPONENT in schemas:
        append_shared_directory_root_schema_drift(drift, schemas)
    return tuple(sorted(drift))


def schema_rejects_empty_object(schema: dict[str, object]) -> bool:
    """Returns whether a schema component rejects `{}` without relying on prose."""

    min_properties = schema.get("minProperties")
    if isinstance(min_properties, int) and min_properties >= 1:
        return True
    for combiner in ("anyOf", "oneOf"):
        branches = schema.get(combiner)
        if not isinstance(branches, list) or not branches:
            continue
        if all(
            isinstance(branch, dict)
            and isinstance(branch.get("required"), list)
            and bool(branch.get("required"))
            for branch in branches
        ):
            return True
    return False


def append_transfer_create_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(TRANSFER_CREATE_REQUEST_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_CREATE_REQUEST_COMPONENT,
                issue="missing transfer create request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_CREATE_REQUEST_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_transfer_create_link_choice_schema(drift, schema)
    assert_transfer_link_text_schema(
        drift,
        "TransferCreateRequest.properties.link",
        properties.get("link"),
    )
    links = properties.get("links")
    if not isinstance(links, dict):
        drift.append(
            SchemaComponentDrift(
                component="TransferCreateRequest.properties.links",
                issue="links must be an array schema",
            )
        )
        return
    if links.get("minItems") != 1:
        drift.append(
            SchemaComponentDrift(
                component="TransferCreateRequest.properties.links",
                issue="links minItems must be 1",
            )
        )
    if links.get("maxItems") != 100:
        drift.append(
            SchemaComponentDrift(
                component="TransferCreateRequest.properties.links",
                issue="links maxItems must be 100",
            )
        )
    assert_transfer_link_text_schema(
        drift,
        "TransferCreateRequest.properties.links.items",
        links.get("items"),
    )
    assert_category_selector_name_schema(
        drift,
        "TransferCreateRequest.properties.categoryName",
        properties.get("categoryName"),
    )
    assert_category_selector_id_schema(
        drift,
        "TransferCreateRequest.properties.categoryId",
        properties.get("categoryId"),
    )
    assert_category_selector_exclusion_schema(
        drift,
        TRANSFER_CREATE_REQUEST_COMPONENT,
        schema,
    )
    assert_paused_boolean_schema(
        drift,
        "TransferCreateRequest.properties.paused",
        properties.get("paused"),
    )


def assert_transfer_create_link_choice_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    branches = schema.get("oneOf")
    if not isinstance(branches, list) or len(branches) != 2:
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_CREATE_REQUEST_COMPONENT,
                issue="transfer create schema must require exactly one of link or links",
            )
        )
        return
    choices: set[tuple[str, str]] = set()
    for branch in branches:
        if not isinstance(branch, dict):
            break
        required = branch.get("required")
        not_schema = branch.get("not")
        if (
            not isinstance(required, list)
            or len(required) != 1
            or not isinstance(required[0], str)
            or not isinstance(not_schema, dict)
        ):
            break
        excluded = not_schema.get("required")
        if (
            not isinstance(excluded, list)
            or len(excluded) != 1
            or not isinstance(excluded[0], str)
        ):
            break
        choices.add((required[0], excluded[0]))
    else:
        if choices == {("link", "links"), ("links", "link")}:
            return
    drift.append(
        SchemaComponentDrift(
            component=TRANSFER_CREATE_REQUEST_COMPONENT,
            issue="transfer create schema must require exactly one of link or links",
        )
    )


def assert_transfer_link_text_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="link text schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="link text type must be string",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="link text minLength must be 1",
            )
        )
    if schema.get("maxLength") != 2048:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="link text maxLength must be 2048",
            )
        )
    if schema.get("pattern") != TRANSFER_ADD_LINK_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="link text pattern must require case-insensitive ed2k:// without whitespace or controls",
            )
        )


def append_diagnostic_dump_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(DIAGNOSTIC_DUMP_REQUEST_COMPONENT)
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    assert_diagnostic_full_memory_schema(drift, properties.get("fullMemory"))


def assert_diagnostic_full_memory_schema(
    drift: list[SchemaComponentDrift],
    schema: object,
) -> None:
    component = "DiagnosticDumpRequest.properties.fullMemory"
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="diagnostic dump fullMemory schema must be an object",
            )
        )
        return
    if schema.get("type") != "boolean":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="diagnostic dump fullMemory type must be boolean",
            )
        )


def assert_priority_enum_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
    expected_values: tuple[str, ...],
    label: str,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} type must be string",
            )
        )
    if schema.get("enum") != list(expected_values):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} enum must be {', '.join(expected_values)}",
            )
        )


def assert_priority_ref_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
    expected_ref: str,
    label: str,
) -> None:
    if schema is None:
        return
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} schema must be an object",
            )
        )
        return
    if schema.get("$ref") != expected_ref:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} must reference {expected_ref}",
            )
        )


def append_transfer_patch_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(TRANSFER_PATCH_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_PATCH_COMPONENT,
                issue="missing transfer patch request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_PATCH_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_transfer_patch_mutation_family_schema(drift, schema)
    assert_transfer_rename_schema(drift, properties.get("name"))
    assert_priority_ref_schema(
        drift,
        "TransferPatch.properties.priority",
        properties.get("priority"),
        "#/components/schemas/TransferPriority",
        "transfer patch priority",
    )
    assert_category_selector_id_schema(
        drift,
        "TransferPatch.properties.categoryId",
        properties.get("categoryId"),
    )
    assert_category_selector_name_schema(
        drift,
        "TransferPatch.properties.categoryName",
        properties.get("categoryName"),
    )


def assert_transfer_patch_mutation_family_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    branches = schema.get("oneOf")
    if not isinstance(branches, list) or len(branches) != len(TRANSFER_PATCH_MUTATION_FAMILIES):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_PATCH_COMPONENT,
                issue="transfer patch schema must allow exactly one mutation family",
            )
        )
        return
    expected_choices = {
        (
            field,
            tuple(sorted(other for other in TRANSFER_PATCH_MUTATION_FAMILIES if other != field)),
        )
        for field in TRANSFER_PATCH_MUTATION_FAMILIES
    }
    actual_choices: set[tuple[str, tuple[str, ...]]] = set()
    for branch in branches:
        if not isinstance(branch, dict):
            break
        required = branch.get("required")
        not_schema = branch.get("not")
        if (
            not isinstance(required, list)
            or len(required) != 1
            or not isinstance(required[0], str)
            or not isinstance(not_schema, dict)
        ):
            break
        any_of = not_schema.get("anyOf")
        if not isinstance(any_of, list):
            break
        excluded: list[str] = []
        for exclusion in any_of:
            if not isinstance(exclusion, dict):
                break
            exclusion_required = exclusion.get("required")
            if (
                not isinstance(exclusion_required, list)
                or len(exclusion_required) != 1
                or not isinstance(exclusion_required[0], str)
            ):
                break
            excluded.append(exclusion_required[0])
        else:
            actual_choices.add((required[0], tuple(sorted(excluded))))
            continue
        break
    else:
        if actual_choices == expected_choices:
            return
    drift.append(
        SchemaComponentDrift(
            component=TRANSFER_PATCH_COMPONENT,
            issue="transfer patch schema must allow exactly one mutation family",
        )
    )


def assert_transfer_rename_schema(
    drift: list[SchemaComponentDrift],
    schema: object,
) -> None:
    component = "TransferPatch.properties.name"
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="transfer rename schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="transfer rename type must be string",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="transfer rename minLength must be 1",
            )
        )
    if "maxLength" in schema:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="transfer rename schema must not claim an unsupported maxLength",
            )
        )
    if schema.get("pattern") != TRANSFER_RENAME_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=(
                    "transfer rename pattern must reject trim-empty text, "
                    "Windows-forbidden filename characters, and controls"
                ),
            )
        )


def append_shared_file_patch_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(SHARED_FILE_PATCH_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=SHARED_FILE_PATCH_COMPONENT,
                issue="missing shared file patch request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=SHARED_FILE_PATCH_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_shared_file_comment_rating_dependency_schema(drift, schema)
    assert_priority_ref_schema(
        drift,
        "SharedFilePatch.properties.priority",
        properties.get("priority"),
        "#/components/schemas/SharedFilePriority",
        "shared file patch priority",
    )
    rating = properties.get("rating")
    if not isinstance(rating, dict):
        drift.append(
            SchemaComponentDrift(
                component="SharedFilePatch.properties.rating",
                issue="shared file rating schema must be an object",
            )
        )
        return
    if rating.get("type") != "integer":
        drift.append(
            SchemaComponentDrift(
                component="SharedFilePatch.properties.rating",
                issue="shared file rating type must be integer",
            )
        )
    if rating.get("minimum") != 0 or rating.get("maximum") != 5:
        drift.append(
            SchemaComponentDrift(
                component="SharedFilePatch.properties.rating",
                issue="shared file rating range must be 0..5",
            )
        )
    comment = properties.get("comment")
    if not isinstance(comment, dict):
        drift.append(
            SchemaComponentDrift(
                component="SharedFilePatch.properties.comment",
                issue="shared file comment schema must be an object",
            )
        )
        return
    if comment.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component="SharedFilePatch.properties.comment",
                issue="shared file comment type must be string",
            )
        )


def assert_shared_file_comment_rating_dependency_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    if schema.get("dependentRequired") == {
        "comment": ["rating"],
        "rating": ["comment"],
    }:
        return
    drift.append(
        SchemaComponentDrift(
            component=SHARED_FILE_PATCH_COMPONENT,
            issue="shared file comment and rating must be mutually dependent",
        )
    )


def append_search_create_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(SEARCH_CREATE_REQUEST_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=SEARCH_CREATE_REQUEST_COMPONENT,
                issue="missing search create request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=SEARCH_CREATE_REQUEST_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_search_create_required_fields_schema(drift, schema)
    assert_search_query_schema(drift, properties.get("query"))
    assert_search_enum_schema(
        drift,
        "SearchCreateRequest.properties.method",
        properties.get("method"),
        SEARCH_METHOD_VALUES,
        "search method",
    )
    assert_search_enum_schema(
        drift,
        "SearchCreateRequest.properties.type",
        properties.get("type"),
        SEARCH_TYPE_VALUES,
        "search type",
    )
    assert_search_string_schema(
        drift,
        "SearchCreateRequest.properties.extension",
        properties.get("extension"),
        "search extension",
    )
    assert_search_unsigned_integer_schema(
        drift,
        "SearchCreateRequest.properties.minSizeBytes",
        properties.get("minSizeBytes"),
        "search minSizeBytes",
        maximum=None,
    )
    assert_search_unsigned_integer_schema(
        drift,
        "SearchCreateRequest.properties.maxSizeBytes",
        properties.get("maxSizeBytes"),
        "search maxSizeBytes",
        maximum=None,
    )
    assert_search_unsigned_integer_schema(
        drift,
        "SearchCreateRequest.properties.minAvailability",
        properties.get("minAvailability"),
        "search minAvailability",
        maximum=1_000_000,
    )


def assert_search_create_required_fields_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    if schema.get("required") != ["query"]:
        drift.append(
            SchemaComponentDrift(
                component=SEARCH_CREATE_REQUEST_COMPONENT,
                issue="search create schema must require query",
            )
        )


def assert_search_query_schema(
    drift: list[SchemaComponentDrift],
    schema: object,
) -> None:
    component = "SearchCreateRequest.properties.query"
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="search query schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="search query type must be string",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="search query minLength must be 1",
            )
        )
    if schema.get("maxLength") != 160:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="search query maxLength must be 160",
            )
        )
    if schema.get("pattern") != SEARCH_QUERY_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=(
                    "search query pattern must require non-whitespace text "
                    "and reject non-whitespace control characters"
                ),
            )
        )


def assert_search_enum_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
    expected_values: tuple[str, ...],
    label: str,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} type must be string",
            )
        )
    if tuple(schema.get("enum", ())) != expected_values:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} enum must be {search_enum_values_label(expected_values)}",
            )
        )


def search_enum_values_label(values: tuple[str, ...]) -> str:
    return ", ".join(value if value != "" else '""' for value in values)


def assert_search_string_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
    label: str,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} type must be string",
            )
        )


def assert_search_unsigned_integer_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
    label: str,
    *,
    maximum: int | None,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} schema must be an object",
            )
        )
        return
    if schema.get("type") != "integer":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} type must be integer",
            )
        )
    if schema.get("minimum") != 0:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} minimum must be 0",
            )
        )
    if maximum is not None and schema.get("maximum") != maximum:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"{label} maximum must be {maximum}",
            )
        )


def append_search_result_download_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(SEARCH_RESULT_DOWNLOAD_REQUEST_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=SEARCH_RESULT_DOWNLOAD_REQUEST_COMPONENT,
                issue="missing search result download request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=SEARCH_RESULT_DOWNLOAD_REQUEST_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_category_selector_name_schema(
        drift,
        "SearchResultDownloadRequest.properties.categoryName",
        properties.get("categoryName"),
    )
    assert_category_selector_id_schema(
        drift,
        "SearchResultDownloadRequest.properties.categoryId",
        properties.get("categoryId"),
    )
    assert_category_selector_exclusion_schema(
        drift,
        SEARCH_RESULT_DOWNLOAD_REQUEST_COMPONENT,
        schema,
    )
    assert_paused_boolean_schema(
        drift,
        "SearchResultDownloadRequest.properties.paused",
        properties.get("paused"),
    )


def assert_paused_boolean_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="paused schema must be an object",
            )
        )
        return
    if schema.get("type") != "boolean":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="paused type must be boolean",
            )
        )


def assert_category_selector_name_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if schema is None:
        return
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector name schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector name type must be string",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector name minLength must be 1",
            )
        )
    if schema.get("pattern") != NON_EMPTY_AFTER_TRIM_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector name pattern must require at least one non-whitespace character",
            )
        )


def assert_category_selector_id_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if schema is None:
        return
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector id schema must be an object",
            )
        )
        return
    if schema.get("type") != "integer":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector id type must be integer",
            )
        )
    if schema.get("minimum") != 0 or schema.get("maximum") != 4294967295:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector id range must be 0..4294967295",
            )
        )


def assert_category_selector_exclusion_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: dict[str, object],
) -> None:
    not_schema = schema.get("not")
    if not isinstance(not_schema, dict) or not_schema.get("required") != ["categoryId", "categoryName"]:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category selector schema must reject categoryId and categoryName together",
            )
        )


def assert_category_priority_input_schema(
    drift: list[SchemaComponentDrift],
    schema: object,
) -> None:
    component = CATEGORY_PRIORITY_INPUT_COMPONENT
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category priority input schema must be an object",
            )
        )
        return
    variants = schema.get("oneOf")
    if not isinstance(variants, list) or len(variants) != 2:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category priority input must be oneOf string enum or u32 integer",
            )
        )
        return
    string_variant = next(
        (variant for variant in variants if isinstance(variant, dict) and variant.get("type") == "string"),
        None,
    )
    integer_variant = next(
        (variant for variant in variants if isinstance(variant, dict) and variant.get("type") == "integer"),
        None,
    )
    if not isinstance(string_variant, dict) or string_variant.get("enum") != list(CATEGORY_PRIORITY_VALUES):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"category priority string enum must be {', '.join(CATEGORY_PRIORITY_VALUES)}",
            )
        )
    if (
        not isinstance(integer_variant, dict)
        or integer_variant.get("minimum") != 0
        or integer_variant.get("maximum") != 4294967295
    ):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category priority integer range must be 0..4294967295",
            )
        )


def append_url_import_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(URL_IMPORT_REQUEST_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=URL_IMPORT_REQUEST_COMPONENT,
                issue="missing URL import request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=URL_IMPORT_REQUEST_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_url_import_required_fields_schema(drift, schema)
    assert_url_import_text_schema(
        drift,
        "UrlImportRequest.properties.url",
        properties.get("url"),
    )


def assert_url_import_required_fields_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    if schema.get("required") != ["url"]:
        drift.append(
            SchemaComponentDrift(
                component=URL_IMPORT_REQUEST_COMPONENT,
                issue="URL import request schema must require url",
            )
        )


def assert_url_import_text_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="URL import text schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="URL import text type must be string",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="URL import text minLength must be 1",
            )
        )
    if schema.get("maxLength") != 2048:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="URL import text maxLength must be 2048",
            )
        )
    if schema.get("pattern") != URL_IMPORT_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="URL import text pattern must require case-insensitive http(s) with a host and no whitespace or controls",
            )
        )


def append_endpoint_request_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
    component: str,
    address_component: str,
    port_component: str,
) -> None:
    schema = schemas.get(component)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="missing endpoint request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="must declare request properties",
            )
        )
        return
    assert_endpoint_required_fields_schema(drift, component, schema)
    assert_endpoint_address_schema(drift, address_component, properties.get("address"))
    assert_endpoint_port_schema(drift, port_component, properties.get("port"))


def assert_endpoint_required_fields_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: dict[str, object],
) -> None:
    required = schema.get("required")
    if not isinstance(required, list):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint request schema must require address and port",
            )
        )
        return
    if set(required) != {"address", "port"} or len(required) != 2:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint request schema must require address and port",
            )
        )


def assert_endpoint_address_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint address schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint address type must be string",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint address minLength must be 1",
            )
        )
    if schema.get("pattern") != NON_EMPTY_AFTER_TRIM_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint address pattern must require at least one non-whitespace character",
            )
        )


def assert_endpoint_port_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint port schema must be an object",
            )
        )
        return
    if schema.get("type") != "integer":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint port type must be integer",
            )
        )
    if schema.get("minimum") != 1 or schema.get("maximum") != 65535:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="endpoint port range must be 1..65535",
            )
        )


def append_server_name_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
    component: str,
) -> None:
    schema = schemas.get(component)
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    assert_server_name_schema(
        drift,
        f"{component}.properties.name",
        properties.get("name"),
    )


def assert_server_name_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="server name schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="server name type must be string",
            )
        )


def append_server_priority_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
    component: str,
) -> None:
    schema = schemas.get(component)
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    priority = properties.get("priority")
    if priority is None:
        return
    assert_priority_enum_schema(
        drift,
        f"{component}.properties.priority",
        priority,
        SERVER_PRIORITY_VALUES,
        "server priority",
    )


def append_server_boolean_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
    component: str,
    fields: tuple[str, ...],
) -> None:
    schema = schemas.get(component)
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    for field in fields:
        assert_server_boolean_schema(
            drift,
            f"{component}.properties.{field}",
            properties.get(field),
        )


def assert_server_boolean_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="server boolean control schema must be an object",
            )
        )
        return
    if schema.get("type") != "boolean":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="server boolean control type must be boolean",
            )
        )


def append_category_mutation_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
    component: str,
) -> None:
    schema = schemas.get(component)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="missing category mutation schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="must declare request properties",
            )
        )
        return
    if component == CATEGORY_CREATE_REQUEST_COMPONENT:
        assert_category_create_required_fields_schema(drift, schema)
    assert_trim_non_empty_text_schema(
        drift,
        f"{component}.properties.name",
        properties.get("name"),
        nullable=False,
    )
    assert_trim_non_empty_text_schema(
        drift,
        f"{component}.properties.path",
        properties.get("path"),
        nullable=True,
    )
    assert_category_comment_schema(
        drift,
        f"{component}.properties.comment",
        properties.get("comment"),
    )
    assert_category_color_schema(
        drift,
        f"{component}.properties.color",
        properties.get("color"),
    )
    assert_priority_ref_schema(
        drift,
        f"{component}.properties.priority",
        properties.get("priority"),
        "#/components/schemas/CategoryPriorityInput",
        "category priority",
    )


def assert_category_create_required_fields_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    required = schema.get("required")
    if required != ["name"]:
        drift.append(
            SchemaComponentDrift(
                component=CATEGORY_CREATE_REQUEST_COMPONENT,
                issue="category create schema must require name",
            )
        )


def assert_category_comment_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category comment schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category comment type must be string",
            )
        )


def assert_category_color_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
) -> None:
    if schema is None:
        return
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category color schema must be an object",
            )
        )
        return
    if schema.get("type") != ["integer", "null"]:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category color type must be ['integer', 'null']",
            )
        )
    if schema.get("minimum") != 0 or schema.get("maximum") != 16777215:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="category color range must be 0..16777215",
            )
        )


def assert_trim_non_empty_text_schema(
    drift: list[SchemaComponentDrift],
    component: str,
    schema: object,
    *,
    nullable: bool,
) -> None:
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="trim-non-empty text schema must be an object",
            )
        )
        return
    expected_type: object = ["string", "null"] if nullable else "string"
    if schema.get("type") != expected_type:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue=f"trim-non-empty text type must be {expected_type!r}",
            )
        )
    if schema.get("minLength") != 1:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="trim-non-empty text minLength must be 1",
            )
        )
    if schema.get("pattern") != NON_EMPTY_AFTER_TRIM_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="trim-non-empty text pattern must require at least one non-whitespace character",
            )
        )


def append_shared_directory_root_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(SHARED_DIRECTORY_ROOT_INPUT_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=SHARED_DIRECTORY_ROOT_INPUT_COMPONENT,
                issue="missing shared-directory root input schema component",
            )
        )
        return
    one_of = schema.get("oneOf")
    if not isinstance(one_of, list) or len(one_of) != 2:
        drift.append(
            SchemaComponentDrift(
                component=SHARED_DIRECTORY_ROOT_INPUT_COMPONENT,
                issue="shared-directory root input must have string and object oneOf branches",
            )
        )
        return
    assert_trim_non_empty_text_schema(
        drift,
        "SharedDirectoryRootInput.oneOf[0]",
        one_of[0],
        nullable=False,
    )
    object_branch = one_of[1]
    if not isinstance(object_branch, dict):
        drift.append(
            SchemaComponentDrift(
                component="SharedDirectoryRootInput.oneOf[1]",
                issue="shared-directory root object branch must be an object schema",
            )
        )
        return
    if object_branch.get("type") != "object":
        drift.append(
            SchemaComponentDrift(
                component="SharedDirectoryRootInput.oneOf[1]",
                issue="shared-directory root object branch type must be object",
            )
        )
    if object_branch.get("additionalProperties") is not False:
        drift.append(
            SchemaComponentDrift(
                component="SharedDirectoryRootInput.oneOf[1]",
                issue="shared-directory root object branch must reject unknown fields",
            )
        )
    if object_branch.get("required") != ["path"]:
        drift.append(
            SchemaComponentDrift(
                component="SharedDirectoryRootInput.oneOf[1]",
                issue="shared-directory root object branch must require path",
            )
        )
    properties = object_branch.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component="SharedDirectoryRootInput.oneOf[1]",
                issue="shared-directory root object branch must declare properties",
            )
        )
        return
    assert_trim_non_empty_text_schema(
        drift,
        "SharedDirectoryRootInput.oneOf[1].properties.path",
        properties.get("path"),
        nullable=False,
    )


def append_friend_create_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    schema = schemas.get(FRIEND_CREATE_REQUEST_COMPONENT)
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=FRIEND_CREATE_REQUEST_COMPONENT,
                issue="missing friend create request schema component",
            )
        )
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        drift.append(
            SchemaComponentDrift(
                component=FRIEND_CREATE_REQUEST_COMPONENT,
                issue="must declare request properties",
            )
        )
        return
    assert_friend_create_required_fields_schema(drift, schema)
    assert_friend_user_hash_schema(drift, properties.get("userHash"))
    assert_friend_name_schema(drift, properties.get("name"))


def assert_friend_create_required_fields_schema(
    drift: list[SchemaComponentDrift],
    schema: dict[str, object],
) -> None:
    if schema.get("required") != ["userHash"]:
        drift.append(
            SchemaComponentDrift(
                component=FRIEND_CREATE_REQUEST_COMPONENT,
                issue="friend create schema must require userHash",
            )
        )


def assert_friend_user_hash_schema(
    drift: list[SchemaComponentDrift],
    schema: object,
) -> None:
    component = "FriendCreateRequest.properties.userHash"
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend userHash schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend userHash type must be string",
            )
        )
    if schema.get("pattern") != FRIEND_USER_HASH_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend userHash pattern must be lowercase 32-character hex",
            )
        )


def assert_friend_name_schema(
    drift: list[SchemaComponentDrift],
    schema: object,
) -> None:
    component = "FriendCreateRequest.properties.name"
    if not isinstance(schema, dict):
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend name schema must be an object",
            )
        )
        return
    if schema.get("type") != "string":
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend name type must be string",
            )
        )
    if schema.get("maxLength") != 128:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend name maxLength must be 128",
            )
        )
    if schema.get("pattern") != CONTROL_FREE_TEXT_PATTERN:
        drift.append(
            SchemaComponentDrift(
                component=component,
                issue="friend name pattern must reject C0 and C1 control characters",
            )
        )


def append_transfer_event_schema_drift(
    drift: list[SchemaComponentDrift],
    schemas: dict[str, object],
) -> None:
    transfer_event = schemas.get(TRANSFER_EVENT_COMPONENT)
    if not isinstance(transfer_event, dict):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_EVENT_COMPONENT,
                issue="missing transfer event schema component",
            )
        )
        return

    expected_refs = tuple(
        f"#/components/schemas/{component}"
        for component in TRANSFER_EVENT_VARIANTS.values()
    )
    actual_refs = tuple(
        entry.get("$ref")
        for entry in transfer_event.get("oneOf", [])
        if isinstance(entry, dict)
    )
    if actual_refs != expected_refs:
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_EVENT_COMPONENT,
                issue="must oneOf the transfer event variant schemas in event-name order",
            )
        )

    discriminator = transfer_event.get("discriminator")
    expected_mapping = {
        event_name: f"#/components/schemas/{component}"
        for event_name, component in TRANSFER_EVENT_VARIANTS.items()
    }
    if not isinstance(discriminator, dict):
        drift.append(
            SchemaComponentDrift(
                component=TRANSFER_EVENT_COMPONENT,
                issue="must declare a type discriminator",
            )
        )
    else:
        if discriminator.get("propertyName") != "type":
            drift.append(
                SchemaComponentDrift(
                    component=TRANSFER_EVENT_COMPONENT,
                    issue="discriminator propertyName must be type",
                )
            )
        if discriminator.get("mapping") != expected_mapping:
            drift.append(
                SchemaComponentDrift(
                    component=TRANSFER_EVENT_COMPONENT,
                    issue="discriminator mapping must cover every transfer event variant",
                )
            )

    for event_name, component in TRANSFER_EVENT_VARIANTS.items():
        schema = schemas.get(component)
        if not isinstance(schema, dict):
            drift.append(
                SchemaComponentDrift(
                    component=component,
                    issue="missing transfer event variant schema component",
                )
            )
            continue
        if schema.get("type") != "object":
            drift.append(
                SchemaComponentDrift(
                    component=component,
                    issue="transfer event variant must be an object",
                )
            )
        if schema.get("additionalProperties") is not False:
            drift.append(
                SchemaComponentDrift(
                    component=component,
                    issue="transfer event variant must set additionalProperties: false",
                )
            )
        required = tuple(sorted(schema.get("required", []))) if isinstance(schema.get("required"), list) else ()
        if required != TRANSFER_EVENT_REQUIRED_FIELDS[component]:
            drift.append(
                SchemaComponentDrift(
                    component=component,
                    issue=f"required fields must be {list(TRANSFER_EVENT_REQUIRED_FIELDS[component])}",
                )
            )
        properties = schema.get("properties", {}) if isinstance(schema.get("properties"), dict) else {}
        type_schema = properties.get("type") if isinstance(properties, dict) else None
        type_values = type_schema.get("enum") if isinstance(type_schema, dict) else None
        if type_values != [event_name]:
            drift.append(
                SchemaComponentDrift(
                    component=component,
                    issue=f"type enum must be [{event_name}]",
                )
            )


def openapi_confirmation_contract_drift(openapi_yaml: Path) -> tuple[ConfirmationContractDrift, ...]:
    """Returns destructive confirmation schemas that are not explicit true sentinels."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    components = document.get("components", {}) if isinstance(document, dict) else {}
    parameters = components.get("parameters", {}) if isinstance(components, dict) else {}
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    drift: list[ConfirmationContractDrift] = []

    confirm_parameter = parameters.get("Confirm") if isinstance(parameters, dict) else None
    if not isinstance(confirm_parameter, dict):
        drift.append(
            ConfirmationContractDrift(
                source="components.parameters.Confirm",
                issue="missing shared destructive confirmation parameter",
            )
        )
    else:
        if confirm_parameter.get("required") is not True:
            drift.append(
                ConfirmationContractDrift(
                    source="components.parameters.Confirm.required",
                    issue="confirm query parameter must be required",
                )
            )
        assert_true_boolean_schema(
            drift,
            "components.parameters.Confirm.schema",
            confirm_parameter.get("schema"),
        )

    if isinstance(schemas, dict):
        for name, schema in schemas.items():
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            if not isinstance(properties, dict):
                continue
            required = schema.get("required", []) if isinstance(schema, dict) else []
            required_names = set(required) if isinstance(required, list) else set()
            for property_name, property_schema in properties.items():
                if not isinstance(property_name, str) or not property_name.startswith("confirm"):
                    continue
                source = f"components.schemas.{name}.properties.{property_name}"
                if property_name not in required_names:
                    drift.append(
                        ConfirmationContractDrift(
                            source=source,
                            issue="confirmation property must be required",
                        )
                    )
                assert_true_boolean_schema(drift, source, property_schema)
    return tuple(sorted(drift))


def assert_true_boolean_schema(
    drift: list[ConfirmationContractDrift],
    source: str,
    schema: object,
) -> None:
    if not isinstance(schema, dict):
        drift.append(ConfirmationContractDrift(source=source, issue="confirmation schema must be an object"))
        return
    if schema.get("type") != "boolean":
        drift.append(ConfirmationContractDrift(source=source, issue="confirmation schema type must be boolean"))
    if schema.get("enum") != [True]:
        drift.append(ConfirmationContractDrift(source=source, issue="confirmation schema enum must be [true]"))


def append_parameter_metadata_drift(
    drift: list[ParameterMetadataDrift],
    source: str,
    parameter: object,
) -> None:
    if not isinstance(parameter, dict):
        drift.append(ParameterMetadataDrift(source=source, issue="parameter must be an object"))
        return
    if "$ref" in parameter:
        return
    name = parameter.get("name")
    if not isinstance(name, str) or name.strip() == "":
        drift.append(ParameterMetadataDrift(source=source, issue="missing name"))
    location = parameter.get("in")
    if location not in {"cookie", "header", "path", "query"}:
        drift.append(ParameterMetadataDrift(source=source, issue="in must be one of cookie, header, path, query"))
    if not isinstance(parameter.get("required"), bool):
        drift.append(ParameterMetadataDrift(source=source, issue="required must be an explicit boolean"))
    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        drift.append(ParameterMetadataDrift(source=source, issue="schema must be an object"))


def append_query_numeric_parameter_schema_drift(
    drift: list[ParameterMetadataDrift],
    component_name: str,
    source: str,
    parameter: object,
) -> None:
    expected = QUERY_NUMERIC_PARAMETER_SCHEMAS.get(component_name)
    if expected is None or not isinstance(parameter, dict):
        return
    label, minimum, maximum = expected
    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        return
    schema_source = f"{source}.schema"
    if schema.get("type") != "integer":
        drift.append(
            ParameterMetadataDrift(
                source=schema_source,
                issue=f"{label} query parameter type must be integer",
            )
        )
    if schema.get("minimum") != minimum or schema.get("maximum") != maximum:
        drift.append(
            ParameterMetadataDrift(
                source=schema_source,
                issue=f"{label} query parameter range must be {minimum}..{maximum}",
            )
        )


def append_path_numeric_parameter_schema_drift(
    drift: list[ParameterMetadataDrift],
    component_name: str,
    source: str,
    parameter: object,
) -> None:
    expected = PATH_NUMERIC_PARAMETER_SCHEMAS.get(component_name)
    if expected is None or not isinstance(parameter, dict):
        return
    label, minimum, maximum = expected
    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        return
    schema_source = f"{source}.schema"
    if schema.get("type") != "integer":
        drift.append(
            ParameterMetadataDrift(
                source=schema_source,
                issue=f"{label} path parameter type must be integer",
            )
        )
    if schema.get("minimum") != minimum or schema.get("maximum") != maximum:
        drift.append(
            ParameterMetadataDrift(
                source=schema_source,
                issue=f"{label} path parameter range must be {minimum}..{maximum}",
            )
        )


def append_path_lowercase_md4_parameter_schema_drift(
    drift: list[ParameterMetadataDrift],
    component_name: str,
    source: str,
    parameter: object,
) -> None:
    label = PATH_LOWERCASE_MD4_PARAMETER_SCHEMAS.get(component_name)
    if label is None or not isinstance(parameter, dict):
        return
    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        return
    schema_source = f"{source}.schema"
    if schema.get("type") != "string":
        drift.append(
            ParameterMetadataDrift(
                source=schema_source,
                issue=f"{label} path parameter type must be string",
            )
        )
    if schema.get("pattern") != FRIEND_USER_HASH_PATTERN:
        drift.append(
            ParameterMetadataDrift(
                source=schema_source,
                issue=f"{label} path parameter pattern must be lowercase 32-character hex",
            )
        )


def append_query_boolean_parameter_schema_drift(
    drift: list[ParameterMetadataDrift],
    component_name: str,
    source: str,
    parameter: object,
) -> None:
    label = QUERY_BOOLEAN_PARAMETER_SCHEMAS.get(component_name)
    if label is None or not isinstance(parameter, dict):
        return
    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        return
    if schema.get("type") != "boolean":
        drift.append(
            ParameterMetadataDrift(
                source=f"{source}.schema",
                issue=f"{label} query parameter type must be boolean",
            )
        )


def append_transfer_state_parameter_schema_drift(
    drift: list[ParameterMetadataDrift],
    component_name: str,
    source: str,
    parameter: object,
) -> None:
    if component_name != "TransferStateFilter" or not isinstance(parameter, dict):
        return
    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        return
    if schema.get("$ref") != "#/components/schemas/TransferState":
        drift.append(
            ParameterMetadataDrift(
                source=f"{source}.schema",
                issue="state query parameter must reference #/components/schemas/TransferState",
            )
        )


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


def openapi_path_parameter_drift(openapi_yaml: Path) -> tuple[PathParameterDrift, ...]:
    """Returns OpenAPI path-template parameters that are missing, extra, or not required."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    component_parameters = document.get("components", {}).get("parameters", {})
    drift: list[PathParameterDrift] = []
    for path, path_item in (document.get("paths", {}) or {}).items():
        template_parameters = tuple(sorted(re.findall(r"\{([^}]+)\}", path)))
        path_parameters = path_item.get("parameters", []) or []
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            parameters = [*path_parameters, *(operation.get("parameters", []) or [])]
            documented = [
                parameter
                for parameter in resolved_parameters(parameters, component_parameters)
                if parameter.get("in") == "path"
            ]
            documented_names = tuple(sorted(str(parameter.get("name")) for parameter in documented))
            if documented_names != template_parameters:
                drift.append(
                    PathParameterDrift(
                        method=method.upper(),
                        path=path,
                        template_parameters=template_parameters,
                        documented_path_parameters=documented_names,
                        issue="path template parameters must match documented path parameters",
                    )
                )
            for parameter in documented:
                if parameter.get("required") is not True:
                    drift.append(
                        PathParameterDrift(
                            method=method.upper(),
                            path=path,
                            template_parameters=template_parameters,
                            documented_path_parameters=documented_names,
                            issue=f"path parameter {parameter.get('name')!r} must be required",
                        )
                    )
    return tuple(sorted(drift))


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


def openapi_request_body_metadata_drift(openapi_yaml: Path) -> tuple[RequestBodyMetadataDrift, ...]:
    """Returns request bodies that are ambiguous for JSON-only native clients."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    components = document.get("components", {}) if isinstance(document, dict) else {}
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    drift: list[RequestBodyMetadataDrift] = []
    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            request_body = operation.get("requestBody")
            if request_body is None:
                continue
            route = Route(method.upper(), path)
            if not isinstance(request_body, dict):
                drift.append(
                    RequestBodyMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="requestBody must be an object",
                    )
                )
                continue
            if not isinstance(request_body.get("required"), bool):
                drift.append(
                    RequestBodyMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="requestBody.required must be explicit true or false",
                    )
                )
            content = request_body.get("content", {})
            media_types = tuple(sorted(content.keys())) if isinstance(content, dict) else ()
            if media_types != ("application/json",):
                drift.append(
                    RequestBodyMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="requestBody content must contain only application/json",
                    )
                )
                continue
            media = content.get("application/json", {})
            schema = media.get("schema") if isinstance(media, dict) else None
            reference = schema.get("$ref") if isinstance(schema, dict) else None
            if not isinstance(reference, str) or not reference.startswith("#/components/schemas/"):
                drift.append(
                    RequestBodyMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue="requestBody application/json schema must reference a shared schema component",
                    )
                )
                continue
            component_name = reference.rsplit("/", 1)[-1]
            schema_component = schemas.get(component_name) if isinstance(schemas, dict) else None
            if not isinstance(schema_component, dict):
                continue
            if schema_component.get("type") != "object":
                drift.append(
                    RequestBodyMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue=f"requestBody schema component {component_name} must be an object",
                    )
                )
            if schema_component.get("additionalProperties") is not False:
                drift.append(
                    RequestBodyMetadataDrift(
                        method=route.method,
                        path=route.path,
                        issue=f"requestBody schema component {component_name} must set additionalProperties: false",
                    )
                )
    return tuple(sorted(drift))


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


def openapi_response_component_drift(openapi_yaml: Path) -> tuple[ResponseComponentDrift, ...]:
    """Returns shared response components that weaken client-facing metadata."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    components = document.get("components", {}) if isinstance(document, dict) else {}
    component_responses = components.get("responses", {}) if isinstance(components, dict) else {}
    drift: list[ResponseComponentDrift] = []
    if not isinstance(component_responses, dict):
        return (
            ResponseComponentDrift(
                component="<components.responses>",
                issue="components.responses must be an object",
            ),
        )

    for name, response in component_responses.items():
        if not isinstance(response, dict):
            drift.append(ResponseComponentDrift(component=name, issue="response component must be an object"))
            continue
        description = response.get("description")
        if not isinstance(description, str) or description.strip() == "":
            drift.append(ResponseComponentDrift(component=name, issue="description must be non-empty"))
        headers = response.get("headers", {})
        header = headers.get(REST_CONTRACT_VERSION_HEADER) if isinstance(headers, dict) else None
        if not isinstance(header, dict) or header.get("$ref") != CONTRACT_VERSION_HEADER_REF:
            drift.append(
                ResponseComponentDrift(
                    component=name,
                    issue=f"must reference {CONTRACT_VERSION_HEADER_REF}",
                )
            )
        if name == EVENT_STREAM_RESPONSE_COMPONENT:
            for header_name in ("Cache-Control", "X-Accel-Buffering"):
                event_header = headers.get(header_name) if isinstance(headers, dict) else None
                if not isinstance(event_header, dict):
                    drift.append(
                        ResponseComponentDrift(
                            component=name,
                            issue=f"must document {header_name} header",
                        )
                    )
        content = response.get("content", {})
        expected_media_types = ("text/event-stream",) if name == EVENT_STREAM_RESPONSE_COMPONENT else ("application/json",)
        actual_media_types = tuple(sorted(content)) if isinstance(content, dict) else ()
        if actual_media_types != expected_media_types:
            drift.append(
                ResponseComponentDrift(
                    component=name,
                    issue=f"content media types must be {', '.join(expected_media_types)}",
                )
            )
        if isinstance(content, dict):
            for media_type in expected_media_types:
                media = content.get(media_type, {})
                schema = media.get("schema") if isinstance(media, dict) else None
                if not isinstance(schema, dict) or not schema:
                    drift.append(
                        ResponseComponentDrift(
                            component=name,
                            issue=f"{media_type} schema must be an object",
                        )
                    )
    return tuple(sorted(drift))


def openapi_success_response_drift(openapi_yaml: Path) -> tuple[SuccessResponseDrift, ...]:
    """Returns success responses that are absent, ambiguous, inline, or schema-less."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    component_responses = document.get("components", {}).get("responses", {}) or {}
    drift: list[SuccessResponseDrift] = []
    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            responses = operation.get("responses", {}) or {}
            success_statuses = tuple(sorted(status for status in responses if is_success_status(status)))
            if not success_statuses:
                drift.append(
                    SuccessResponseDrift(
                        method=method.upper(),
                        path=path,
                        status="",
                        issue="missing 2xx response",
                    )
                )
                continue
            if len(success_statuses) > 1:
                drift.append(
                    SuccessResponseDrift(
                        method=method.upper(),
                        path=path,
                        status=",".join(success_statuses),
                        issue="must document exactly one 2xx response",
                    )
                )
            for status in success_statuses:
                response = responses.get(status)
                reference = response.get("$ref") if isinstance(response, dict) else None
                if not isinstance(reference, str) or not reference.startswith("#/components/responses/"):
                    drift.append(
                        SuccessResponseDrift(
                            method=method.upper(),
                            path=path,
                            status=str(status),
                            issue="2xx response must reference a shared response component",
                        )
                    )
                    continue
                component_name = reference.rsplit("/", 1)[-1]
                component = component_responses.get(component_name)
                if not response_component_has_media_schema(component):
                    drift.append(
                        SuccessResponseDrift(
                            method=method.upper(),
                            path=path,
                            status=str(status),
                            issue=f"response component {component_name} must define a media schema",
                        )
                    )
    return tuple(sorted(drift))


def is_success_status(status: object) -> bool:
    status_text = str(status)
    return len(status_text) == 3 and status_text.startswith("2") and status_text.isdecimal()


def response_component_has_media_schema(component: object) -> bool:
    if not isinstance(component, dict):
        return False
    content = component.get("content", {})
    if not isinstance(content, dict):
        return False
    for media in content.values():
        schema = media.get("schema") if isinstance(media, dict) else None
        if isinstance(schema, dict) and schema:
            return True
    return False


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


def openapi_error_response_drift(openapi_yaml: Path) -> tuple[ErrorResponseDrift, ...]:
    """Returns native OpenAPI gaps in shared ErrorResponse references."""

    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8")) or {}
    drift: list[ErrorResponseDrift] = []
    error_response = (
        document.get("components", {})
        .get("responses", {})
        .get("ErrorResponse")
    )
    error_schema = (
        error_response.get("content", {})
        .get("application/json", {})
        .get("schema", {})
        if isinstance(error_response, dict)
        else {}
    )
    if not isinstance(error_response, dict):
        drift.append(
            ErrorResponseDrift(
                method="",
                path="<components.responses.ErrorResponse>",
                status="",
                issue="missing shared ErrorResponse component",
            )
        )
    elif not isinstance(error_schema, dict) or error_schema.get("$ref") != ERROR_ENVELOPE_REF:
        drift.append(
            ErrorResponseDrift(
                method="",
                path="<components.responses.ErrorResponse>",
                status="",
                issue=f"ErrorResponse must reference {ERROR_ENVELOPE_REF}",
            )
        )

    for path, path_item in (document.get("paths", {}) or {}).items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            responses = operation.get("responses", {}) or {}
            for status in ERROR_RESPONSE_STATUSES:
                response = responses.get(status)
                if not isinstance(response, dict):
                    drift.append(
                        ErrorResponseDrift(
                            method=method.upper(),
                            path=path,
                            status=status,
                            issue="missing error response",
                        )
                    )
                elif response.get("$ref") != ERROR_RESPONSE_REF:
                    drift.append(
                        ErrorResponseDrift(
                            method=method.upper(),
                            path=path,
                            status=status,
                            issue="must reference ErrorResponse",
                        )
                    )
            for status, response in responses.items():
                status_text = str(status)
                if status_text in ERROR_RESPONSE_STATUSES or status_text == "405" or is_success_status(status_text):
                    continue
                if not isinstance(response, dict) or response.get("$ref") != ERROR_RESPONSE_REF:
                    drift.append(
                        ErrorResponseDrift(
                            method=method.upper(),
                            path=path,
                            status=status_text,
                            issue="documented non-success responses must reference ErrorResponse",
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
        return component_responses.get(reference.rsplit("/", 1)[-1], {})
    return response


def schema_property_names(schema: object, schemas: dict[str, dict[str, object]]) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    reference = schema.get("$ref")
    if isinstance(reference, str):
        schema = schemas.get(reference.rsplit("/", 1)[-1], {})
    if not isinstance(schema, dict):
        return set()
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
        if not isinstance(parameter, dict):
            continue
        reference = parameter.get("$ref")
        if isinstance(reference, str):
            name = reference.rsplit("/", 1)[-1]
            yield component_parameters.get(name, {})
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
    settings_surface_rs: Path | None = None,
) -> RouteDriftReport:
    implemented = rust_route_inventory(routes_rs)
    documented = openapi_route_inventory(openapi_yaml)
    component_ref_drift = openapi_component_ref_drift(openapi_yaml)
    operation_metadata_drift = openapi_operation_metadata_drift(openapi_yaml)
    tag_taxonomy_drift = openapi_tag_taxonomy_drift(openapi_yaml)
    parameter_metadata_drift = openapi_parameter_metadata_drift(openapi_yaml)
    parameter_ref_drift = openapi_parameter_ref_drift(openapi_yaml)
    schema_component_drift = openapi_schema_component_drift(openapi_yaml)
    confirmation_contract_drift = openapi_confirmation_contract_drift(openapi_yaml)
    rust_queries = rust_query_parameter_inventory(route_metadata_rs, routes_rs)
    openapi_queries = openapi_query_parameter_inventory(openapi_yaml)
    path_parameter_drift = openapi_path_parameter_drift(openapi_yaml)
    rust_bodies = rust_body_field_inventory(route_body_metadata_rs, routes_rs)
    openapi_bodies = openapi_body_field_inventory(openapi_yaml)
    request_body_metadata_drift = openapi_request_body_metadata_drift(openapi_yaml)
    success_response_drift = openapi_success_response_drift(openapi_yaml)
    response_component_drift = openapi_response_component_drift(openapi_yaml)
    response_header_drift = openapi_response_header_drift(openapi_yaml)
    auth_drift = openapi_auth_drift(openapi_yaml)
    error_response_drift = openapi_error_response_drift(openapi_yaml)
    method_not_allowed_drift = openapi_method_not_allowed_drift(openapi_yaml)
    contract_version_drift = (
        openapi_contract_version_drift(openapi_yaml, responses_rs)
        if responses_rs is not None
        else ()
    )
    section_resource_drift = (
        settings_section_resource_openapi_drift(settings_surface_rs, openapi_yaml)
        if settings_surface_rs is not None
        else ()
    )
    section_resource_response_drift = (
        settings_section_resource_response_drift(settings_surface_rs, openapi_yaml)
        if settings_surface_rs is not None
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
        component_ref_drift=component_ref_drift,
        operation_metadata_drift=operation_metadata_drift,
        tag_taxonomy_drift=tag_taxonomy_drift,
        parameter_metadata_drift=parameter_metadata_drift,
        parameter_ref_drift=parameter_ref_drift,
        schema_component_drift=schema_component_drift,
        confirmation_contract_drift=confirmation_contract_drift,
        query_parameter_drift=query_drift,
        path_parameter_drift=path_parameter_drift,
        body_field_drift=body_drift,
        request_body_metadata_drift=request_body_metadata_drift,
        success_response_drift=success_response_drift,
        response_component_drift=response_component_drift,
        response_header_drift=response_header_drift,
        auth_drift=auth_drift,
        error_response_drift=error_response_drift,
        method_not_allowed_drift=method_not_allowed_drift,
        contract_version_drift=contract_version_drift,
        section_resource_openapi_drift=section_resource_drift,
        section_resource_response_drift=section_resource_response_drift,
    )


def default_routes_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "routes.rs"


def default_route_metadata_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "route_metadata.rs"


def default_route_body_metadata_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "route_body_metadata.rs"


def default_responses_rs(workspace_root: Path) -> Path:
    return workspace_root / "repos" / "emulebb-rust" / "crates" / "emulebb-rest" / "src" / "responses.rs"


def default_settings_surface_rs(workspace_root: Path) -> Path:
    return (
        workspace_root
        / "repos"
        / "emulebb-rust"
        / "crates"
        / "emulebb-settings"
        / "src"
        / "surface.rs"
    )


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
    parser.add_argument("--settings-surface", type=Path, help="Path to crates/emulebb-settings/src/surface.rs.")
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
    settings_surface_rs = args.settings_surface or default_settings_surface_rs(workspace_root)
    openapi_yaml = args.openapi or default_openapi_yaml(workspace_root)
    report = compare_route_contract(
        routes_rs,
        route_metadata_rs,
        route_body_metadata_rs,
        openapi_yaml,
        responses_rs,
        settings_surface_rs,
    )
    if args.json:
        print(json.dumps(report.as_json_dict(), indent=2, sort_keys=True))
    elif report.ok:
        print("emulebb-rust OpenAPI route, component ref, operation metadata, tag taxonomy, parameter metadata, parameter ref, schema component, confirmation, path, query, request body, success, response component, auth, error, 405, contract-version, response-header, Settings section-resource inventory, and Settings section-resource response shape matches the router metadata.")
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
    if report.component_ref_drift:
        print("Component reference drift:")
        for drift in report.component_ref_drift:
            print(f"  {drift.source}: {drift.reference}: {drift.issue}")
    if report.operation_metadata_drift:
        print("Operation metadata drift:")
        for drift in report.operation_metadata_drift:
            print(f"  {drift.method} {drift.path}: {drift.issue}")
    if report.tag_taxonomy_drift:
        print("Tag taxonomy drift:")
        for drift in report.tag_taxonomy_drift:
            print(f"  {drift.source}: {drift.tag}: {drift.issue}")
    if report.parameter_metadata_drift:
        print("Parameter metadata drift:")
        for drift in report.parameter_metadata_drift:
            print(f"  {drift.source}: {drift.issue}")
    if report.parameter_ref_drift:
        print("Parameter ref drift:")
        for drift in report.parameter_ref_drift:
            print(f"  {drift.source}: {drift.issue}")
    if report.schema_component_drift:
        print("Schema component drift:")
        for drift in report.schema_component_drift:
            print(f"  {drift.component}: {drift.issue}")
    if report.confirmation_contract_drift:
        print("Confirmation contract drift:")
        for drift in report.confirmation_contract_drift:
            print(f"  {drift.source}: {drift.issue}")
    if report.query_parameter_drift:
        print("Query parameter drift:")
        for drift in report.query_parameter_drift:
            rust_names = ", ".join(drift.rust_query_parameters) or "<none>"
            openapi_names = ", ".join(drift.openapi_query_parameters) or "<none>"
            print(f"  {drift.route.method} {drift.route.path}: rust=[{rust_names}] openapi=[{openapi_names}]")
    if report.path_parameter_drift:
        print("Path parameter drift:")
        for drift in report.path_parameter_drift:
            template_names = ", ".join(drift.template_parameters) or "<none>"
            documented_names = ", ".join(drift.documented_path_parameters) or "<none>"
            print(f"  {drift.method} {drift.path}: template=[{template_names}] openapi=[{documented_names}] {drift.issue}")
    if report.body_field_drift:
        print("JSON body field drift:")
        for drift in report.body_field_drift:
            rust_names = ", ".join(drift.rust_body_fields) or "<none>"
            openapi_names = ", ".join(drift.openapi_body_fields) or "<none>"
            print(f"  {drift.route.method} {drift.route.path}: rust=[{rust_names}] openapi=[{openapi_names}]")
    if report.request_body_metadata_drift:
        print("Request body metadata drift:")
        for drift in report.request_body_metadata_drift:
            print(f"  {drift.method} {drift.path}: {drift.issue}")
    if report.success_response_drift:
        print("Success response contract drift:")
        for drift in report.success_response_drift:
            route = f"{drift.method} {drift.path}".strip()
            print(f"  {route} {drift.status}: {drift.issue}")
    if report.response_component_drift:
        print("Response component drift:")
        for drift in report.response_component_drift:
            print(f"  {drift.component}: {drift.issue}")
    if report.response_header_drift:
        print("Response header drift:")
        for drift in report.response_header_drift:
            print(f"  {drift.route.method} {drift.route.path} {drift.status}: missing {drift.missing_header}")
    if report.auth_drift:
        print("Auth contract drift:")
        for drift in report.auth_drift:
            route = f"{drift.method} {drift.path}".strip()
            print(f"  {route}: {drift.issue}")
    if report.error_response_drift:
        print("Error response contract drift:")
        for drift in report.error_response_drift:
            route = f"{drift.method} {drift.path}".strip()
            print(f"  {route} {drift.status}: {drift.issue}")
    if report.method_not_allowed_drift:
        print("405 method-not-allowed contract drift:")
        for drift in report.method_not_allowed_drift:
            route = f"{drift.method} {drift.path}".strip()
            print(f"  {route}: {drift.issue}")
    if report.contract_version_drift:
        print("Contract-version drift:")
        for drift in report.contract_version_drift:
            print(f"  {drift.source}: {drift.issue}")
    if report.section_resource_openapi_drift:
        print("Settings section-resource OpenAPI drift:")
        for drift in report.section_resource_openapi_drift:
            print(f"  {drift.name} {drift.route}: {drift.issue}")
    if report.section_resource_response_drift:
        print("Settings section-resource response drift:")
        for drift in report.section_resource_response_drift:
            print(f"  {drift.name} {drift.route}: {drift.issue}")
