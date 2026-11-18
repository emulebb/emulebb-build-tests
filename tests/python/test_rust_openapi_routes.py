from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest
import yaml

from emule_test_harness.rust_openapi_responses import (
    load_openapi_document,
    openapi_operation_response,
    openapi_schema_component,
    response_json_schema,
    validate_openapi_schema,
)
from emule_test_harness.workspace_layout import resolve_selected_workspace_repo

from emule_test_harness.rust_openapi_routes import (
    AuthDrift,
    BodyFieldDrift,
    ConfirmationContractDrift,
    ComponentRefDrift,
    ErrorResponseDrift,
    MethodNotAllowedDrift,
    OperationMetadataDrift,
    ParameterMetadataDrift,
    ParameterRefDrift,
    PathParameterDrift,
    PRIVATE_DIAGNOSTICS_ROUTES,
    QueryParameterDrift,
    Route,
    RequestBodyMetadataDrift,
    ResponseComponentDrift,
    ResponseHeaderDrift,
    SchemaComponentDrift,
    SettingsSectionResourceOpenApiDrift,
    SettingsSectionResourceResponseDrift,
    SuccessResponseDrift,
    TagTaxonomyDrift,
    assert_nullable_category_ref_schema,
    compare_route_contract,
    openapi_contract_version_drift,
    compare_route_inventory,
    openapi_auth_drift,
    openapi_body_field_inventory,
    openapi_confirmation_contract_drift,
    openapi_component_ref_drift,
    openapi_error_response_drift,
    openapi_method_not_allowed_drift,
    openapi_operation_metadata_drift,
    openapi_parameter_metadata_drift,
    openapi_parameter_ref_drift,
    openapi_path_parameter_drift,
    openapi_query_parameter_inventory,
    openapi_request_body_metadata_drift,
    openapi_response_component_drift,
    openapi_response_header_drift,
    openapi_route_inventory,
    openapi_schema_component_drift,
    openapi_success_response_drift,
    openapi_tag_taxonomy_drift,
    rust_settings_section_resource_inventory,
    settings_section_resource_openapi_drift,
    settings_section_resource_response_drift,
    rust_contract_version,
    rust_body_field_inventory,
    rust_query_parameter_inventory,
    rust_route_inventory,
)


@pytest.fixture(scope="module")
def selected_rust_openapi():
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    path = tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    return path, load_openapi_document(path)


PERSISTENCE_ERROR_STATUSES = {
    "PERSISTENCE_BUSY": 503,
    "PERSISTENCE_CLOSING": 503,
    "PERSISTENCE_TOO_LARGE": 413,
    "PERSISTENCE_FAILED": 500,
    "PERSISTENCE_UNAVAILABLE": 503,
    "PERSISTENCE_COMMITTED": 503,
}


@pytest.mark.parametrize("code", PERSISTENCE_ERROR_STATUSES)
def test_selected_error_envelope_accepts_persistence_failure_fields(selected_rust_openapi, code):
    _, document = selected_rust_openapi
    schema = openapi_schema_component(document, "ErrorEnvelope")
    details = {"committed": True} if code == "PERSISTENCE_COMMITTED" else {}
    payload = {"error": {"code": code, "message": "Persistence operation outcome", "details": details}}
    validate_openapi_schema(document, schema, payload)
    # The optional flag on other outcomes cannot imply that missing means rollback.
    if code != "PERSISTENCE_COMMITTED":
        for committed in (False, True):
            payload["error"]["details"] = {"committed": committed}
            validate_openapi_schema(document, schema, payload)


@pytest.mark.parametrize("details", [{}, {"committed": False}])
def test_selected_committed_error_requires_true_commit_flag(selected_rust_openapi, details):
    _, document = selected_rust_openapi
    schema = openapi_schema_component(document, "ErrorEnvelope")
    payload = {"error": {"code": "PERSISTENCE_COMMITTED", "message": "Mutation committed", "details": details}}
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, schema, payload)


def test_selected_friend_frontdoors_document_current_persistence_errors(selected_rust_openapi):
    _, document = selected_rust_openapi
    schema = openapi_schema_component(document, "ErrorEnvelope")
    codes = schema["properties"]["error"]["properties"]["code"]["enum"]
    assert {code for code in codes if code.startswith("PERSISTENCE_")} == set(PERSISTENCE_ERROR_STATUSES)
    mutations = [("post", "/friends"), ("delete", "/friends/{userHash}")]
    for prefix in ("/downloads/{id}/sources/{clientId}", "/uploads/{clientId}", "/upload-queue/{clientId}"):
        mutations.extend(("post", f"{prefix}/operations/{operation}")
                         for operation in ("add-friend", "remove-friend"))
    assert len(mutations) == 8
    for method, path in mutations:
        operation = document["paths"][path][method]
        for code, status in PERSISTENCE_ERROR_STATUSES.items():
            assert code in operation["responses"][str(status)]["description"], (method, path, status, code)
            response = openapi_operation_response(document, method, path, status)
            details = {"committed": True} if code == "PERSISTENCE_COMMITTED" else {}
            validate_openapi_schema(document, response_json_schema(response, f"{method} {path} {status}"),
                                    {"error": {"code": code, "message": "Persistence outcome", "details": details}})
    # Listing is the ninth frontdoor: its read maps failure to unavailable,
    # whereas admission/payload/storage mutation errors belong to writers above.
    listing = document["paths"]["/friends"]["get"]
    assert "PERSISTENCE_UNAVAILABLE" in listing["responses"]["503"]["description"]
    response = openapi_operation_response(document, "get", "/friends", 503)
    validate_openapi_schema(document, response_json_schema(response, "GET /friends 503"),
                            {"error": {"code": "PERSISTENCE_UNAVAILABLE", "message": "Friend read unavailable", "details": {}}})


def test_selected_category_mutations_document_conflict_and_committed_failure(selected_rust_openapi):
    _, document = selected_rust_openapi
    operation = document["paths"]["/categories"]["post"]
    conflict = operation["responses"]["409"]
    assert "CATEGORY_NAME_CONFLICT" in conflict["description"]
    assert conflict["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorEnvelope"
    }
    for method, path in (("post", "/categories"), ("patch", "/categories/{categoryName}"),
                         ("delete", "/categories/{categoryName}")):
        operation = document["paths"][path][method]
        assert operation["responses"]["503"] == {"$ref": "#/components/responses/ErrorResponse"}
        assert "PERSISTENCE_COMMITTED" in operation["description"]


def test_selected_rust_route_contract_matches_selected_openapi(selected_rust_openapi):
    openapi, _ = selected_rust_openapi
    rust = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    rest = rust / "crates/emulebb-rest/src"
    report = compare_route_contract(
        rest / "routes.rs", rest / "route_metadata.rs", rest / "route_body_metadata.rs", openapi,
        rest / "responses.rs", rust / "crates/emulebb-settings/src/surface.rs",
        private_routes=PRIVATE_DIAGNOSTICS_ROUTES,
    )
    assert report.ok, json.dumps(
        {name: entries for name, entries in report.as_json_dict().items() if entries},
        sort_keys=True,
    )


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_rust_route_inventory_reads_chained_axum_methods(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new()
            .route("/api/v1/app", get(app))
            .route(
                "/api/v1/categories/{categoryName}",
                get(category).patch(update_category).delete(delete_category),
            )
            .route("/api/v1/{*path}", any(fallback));
        ''',
    )

    assert rust_route_inventory(routes_rs) == {
        Route("GET", "/app"),
        Route("DELETE", "/categories/{categoryName}"),
        Route("GET", "/categories/{categoryName}"),
        Route("PATCH", "/categories/{categoryName}"),
    }


def test_rust_route_inventory_does_not_borrow_methods_from_later_source(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new().route(
            "/api/v1/diagnostics/protocol-fixtures/queued-lowid-sources",
            post(create_fixture),
        );

        async fn unrelated() {
            let _handler = get(read_something);
        }
        ''',
    )

    assert rust_route_inventory(routes_rs) == {
        Route("POST", "/diagnostics/protocol-fixtures/queued-lowid-sources"),
    }


def test_openapi_route_inventory_reads_path_methods(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
openapi: 3.1.0
paths:
  /app:
    get:
      responses: {}
  /categories/{categoryName}:
    get:
      responses: {}
    patch:
      responses: {}
    delete:
      responses: {}
""",
    )

    assert openapi_route_inventory(openapi_yaml) == {
        Route("GET", "/app"),
        Route("DELETE", "/categories/{categoryName}"),
        Route("GET", "/categories/{categoryName}"),
        Route("PATCH", "/categories/{categoryName}"),
    }


def test_rust_settings_section_resource_inventory_reads_full_rest_routes(tmp_path: Path) -> None:
    surface_rs = write(
        tmp_path / "surface.rs",
        '''
        const SETTINGS_SECTION_RESOURCES: &[SettingsSectionResourceSpec] = &[
            SettingsSectionResourceSpec {
                name: "diagnostics",
                class: SettingSurfaceClass::ExistingSectionResource,
                route: "/api/v1/diagnostics",
                ui_section: "Diagnostics",
                description: "Runtime diagnostics.",
            },
            SettingsSectionResourceSpec {
                name: "nat",
                class: SettingSurfaceClass::ExistingSectionResource,
                route: "/api/v1/nat",
                ui_section: "NAT",
                description: "Live NAT status.",
            },
        ];
        ''',
    )

    assert rust_settings_section_resource_inventory(surface_rs) == {
        "diagnostics": "/api/v1/diagnostics",
        "nat": "/api/v1/nat",
    }


def test_settings_section_resource_openapi_drift_requires_documented_get_operations(tmp_path: Path) -> None:
    surface_rs = write(
        tmp_path / "surface.rs",
        '''
        const SETTINGS_SECTION_RESOURCES: &[SettingsSectionResourceSpec] = &[
            SettingsSectionResourceSpec {
                name: "diagnostics",
                route: "/api/v1/diagnostics",
                ui_section: "Diagnostics",
                description: "Runtime diagnostics.",
            },
            SettingsSectionResourceSpec {
                name: "nat",
                route: "/api/v1/nat",
                ui_section: "NAT",
                description: "Live NAT status.",
            },
            SettingsSectionResourceSpec {
                name: "external",
                route: "https://example.invalid/external",
                ui_section: "External",
                description: "Invalid external route.",
            },
        ];
        ''',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /diagnostics:
    get:
      responses: {}
  /nat:
    post:
      responses: {}
""",
    )

    assert settings_section_resource_openapi_drift(surface_rs, openapi_yaml) == (
        SettingsSectionResourceOpenApiDrift(
            name="external",
            route="https://example.invalid/external",
            issue="route must start with /api/v1/",
        ),
        SettingsSectionResourceOpenApiDrift(
            name="nat",
            route="/api/v1/nat",
            issue="missing GET operation in OpenAPI paths",
        ),
    )


def test_settings_section_resource_response_drift_requires_named_closed_data_dtos(tmp_path: Path) -> None:
    surface_rs = write(
        tmp_path / "surface.rs",
        '''
        const SETTINGS_SECTION_RESOURCES: &[SettingsSectionResourceSpec] = &[
            SettingsSectionResourceSpec {
                name: "diagnostics",
                route: "/api/v1/diagnostics",
                ui_section: "Diagnostics",
                description: "Runtime diagnostics.",
            },
            SettingsSectionResourceSpec {
                name: "nat",
                route: "/api/v1/nat",
                ui_section: "NAT",
                description: "Live NAT status.",
            },
            SettingsSectionResourceSpec {
                name: "ipFilter",
                route: "/api/v1/ip-filter",
                ui_section: "IP Filter",
                description: "IP filter status.",
            },
            SettingsSectionResourceSpec {
                name: "servers",
                route: "/api/v1/servers",
                ui_section: "Servers",
                description: "Servers.",
            },
        ];
        ''',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /diagnostics:
    get:
      responses:
        "200":
          $ref: "#/components/responses/RuntimeDiagnosticsResponse"
  /nat:
    get:
      responses:
        "200":
          $ref: "#/components/responses/NatResponse"
  /ip-filter:
    get:
      responses:
        "200":
          $ref: "#/components/responses/OkResponse"
  /servers:
    get:
      responses:
        "200":
          $ref: "#/components/responses/ServerListResponse"
components:
  responses:
    RuntimeDiagnosticsResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/RuntimeDiagnosticsEnvelope"
    NatResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/NatStatusEnvelope"
    OkResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/OkEnvelope"
    ServerListResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ServerListEnvelope"
  schemas:
    RuntimeDiagnosticsEnvelope:
      unevaluatedProperties: false
      allOf:
        - type: object
          properties:
            data:
              $ref: "#/components/schemas/RuntimeDiagnostics"
    RuntimeDiagnostics:
      type: object
      additionalProperties: false
    NatStatusEnvelope:
      unevaluatedProperties: false
      allOf:
        - type: object
          properties:
            data:
              $ref: "#/components/schemas/NatStatus"
    NatStatus:
      type: object
    OkEnvelope:
      unevaluatedProperties: false
    ServerListEnvelope:
      unevaluatedProperties: false
      allOf:
        - type: object
          properties:
            data:
              type: object
              additionalProperties: false
""",
    )

    assert settings_section_resource_response_drift(surface_rs, openapi_yaml) == (
        SettingsSectionResourceResponseDrift(
            name="ipFilter",
            route="/api/v1/ip-filter",
            issue="GET operation must not use generic OkResponse",
        ),
        SettingsSectionResourceResponseDrift(
            name="nat",
            route="/api/v1/nat",
            issue="data schema NatStatus must be a closed object",
        ),
        SettingsSectionResourceResponseDrift(
            name="servers",
            route="/api/v1/servers",
            issue="envelope schema ServerListEnvelope data must reference a named schema component",
        ),
    )


def test_openapi_component_ref_drift_rejects_missing_and_external_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /app:
    get:
      parameters:
        - $ref: "#/components/parameters/MissingParameter"
      responses:
        "200":
          $ref: "#/components/responses/MissingResponse"
  /imports:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "https://example.invalid/schema.json"
      responses:
        "200":
          $ref: "#/components/responses/ImportResponse"
components:
  responses:
    ImportResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ImportResult"
  schemas:
    ImportResult:
      type: object
""",
    )

    assert openapi_component_ref_drift(openapi_yaml) == (
        ComponentRefDrift(
            source="$.paths./app.get.parameters[0].$ref",
            reference="#/components/parameters/MissingParameter",
            issue="missing local component target",
        ),
        ComponentRefDrift(
            source="$.paths./app.get.responses.200.$ref",
            reference="#/components/responses/MissingResponse",
            issue="missing local component target",
        ),
        ComponentRefDrift(
            source="$.paths./imports.post.requestBody.content.application/json.schema.$ref",
            reference="https://example.invalid/schema.json",
            issue="unsupported non-local component reference",
        ),
    )


def test_compare_route_inventory_reports_exact_placeholder_drift(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        'Router::new().route("/api/v1/searches/{search_id}", get(search));',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /searches/{searchId}:
    get:
      responses: {}
""",
    )

    report = compare_route_inventory(routes_rs, openapi_yaml)

    assert report.implemented_missing_from_openapi == (Route("GET", "/searches/{search_id}"),)
    assert report.openapi_missing_from_implemented == (Route("GET", "/searches/{searchId}"),)


def test_openapi_operation_metadata_drift_requires_ids_tags_summaries_and_unique_ids(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /app:
    get:
      operationId: getApp
      summary: Return app state.
      tags: [App]
      responses: {}
    post:
      operationId: getApp
      summary: Duplicate operation ID.
      tags: []
      responses: {}
  /status:
    get:
      summary: Return status.
      tags: [Stats]
      responses: {}
  /stats:
    get:
      operationId: getStats
      responses: {}
""",
    )

    assert openapi_operation_metadata_drift(openapi_yaml) == (
        OperationMetadataDrift(
            method="GET",
            path="/stats",
            issue="missing summary",
        ),
        OperationMetadataDrift(
            method="GET",
            path="/stats",
            issue="missing tags",
        ),
        OperationMetadataDrift(
            method="GET",
            path="/status",
            issue="missing operationId",
        ),
        OperationMetadataDrift(
            method="POST",
            path="/app",
            issue="duplicate operationId 'getApp' also used by GET /app",
        ),
        OperationMetadataDrift(
            method="POST",
            path="/app",
            issue="missing tags",
        ),
    )


def test_openapi_tag_taxonomy_drift_requires_declared_used_unique_tags(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
tags:
  - name: App
  - name: App
  - name: Unused
  - description: missing name
paths:
  /app:
    get:
      operationId: getApp
      tags: [App]
      responses: {}
  /diagnostics:
    get:
      operationId: getDiagnostics
      tags: [Diagnostics]
      responses: {}
""",
    )

    assert openapi_tag_taxonomy_drift(openapi_yaml) == (
        TagTaxonomyDrift(
            source="paths./diagnostics.get.tags",
            tag="Diagnostics",
            issue="operation tag is not declared",
        ),
        TagTaxonomyDrift(
            source="tags",
            tag="Unused",
            issue="declared tag is unused",
        ),
        TagTaxonomyDrift(
            source="tags[1]",
            tag="App",
            issue="duplicate top-level tag",
        ),
        TagTaxonomyDrift(
            source="tags[3]",
            tag="",
            issue="tag entry must have a non-empty name",
        ),
    )


def test_openapi_parameter_metadata_drift_requires_explicit_client_metadata(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /events:
    get:
      parameters:
        - name: Last-Event-ID
          in: header
          required: false
          schema:
            type: string
        - name: state
          in: query
          schema:
            type: string
        - in: query
          required: false
          schema:
            type: string
        - name: broken
          in: body
          required: "false"
      responses: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
      schema:
        type: integer
        minimum: 1
        maximum: 1000
    FileHash:
      name: hash
      in: path
      required: true
      schema:
        type: string
        pattern: "^[0-9a-f]{32}$"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.Limit",
            issue="required must be an explicit boolean",
        ),
        ParameterMetadataDrift(
            source="paths./events.get.parameters[1]",
            issue="required must be an explicit boolean",
        ),
        ParameterMetadataDrift(
            source="paths./events.get.parameters[2]",
            issue="missing name",
        ),
        ParameterMetadataDrift(
            source="paths./events.get.parameters[3]",
            issue="in must be one of cookie, header, path, query",
        ),
        ParameterMetadataDrift(
            source="paths./events.get.parameters[3]",
            issue="required must be an explicit boolean",
        ),
        ParameterMetadataDrift(
            source="paths./events.get.parameters[3]",
            issue="schema must be an object",
        ),
    )


def test_openapi_parameter_metadata_drift_requires_numeric_query_bounds(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    Limit:
      name: limit
      in: query
      required: false
      schema:
        type: number
        minimum: 0
        maximum: 1000
    Offset:
      name: offset
      in: query
      required: false
      schema:
        type: integer
        minimum: 0
        maximum: 4294967295
    DownloadCategory:
      name: category
      in: query
      required: false
      schema:
        type: integer
        minimum: 1
        maximum: 4294967295
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.DownloadCategory.schema",
            issue="download parameter must use current job-ID or bounded page shape",
        ),
        ParameterMetadataDrift(
            source="components.parameters.Limit.schema",
            issue="limit query parameter range must be 1..1000",
        ),
        ParameterMetadataDrift(
            source="components.parameters.Limit.schema",
            issue="limit query parameter type must be integer",
        ),
        ParameterMetadataDrift(
            source="components.parameters.Offset.schema",
            issue="offset query parameter range must be 0..2147483647",
        ),
    )


def test_openapi_parameter_metadata_drift_accepts_numeric_query_bounds(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    Limit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
        minimum: 1
        maximum: 1000
    Offset:
      name: offset
      in: query
      required: false
      schema:
        type: integer
        minimum: 0
        maximum: 2147483647
    LogsLimit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
        minimum: 1
        maximum: 1000
        default: 200
    DownloadCategory:
      name: category
      in: query
      required: false
      schema:
        $ref: "#/components/schemas/CategoryName"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == ()


def test_openapi_parameter_metadata_drift_requires_logs_limit_default(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    LogsLimit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
        minimum: 1
        maximum: 1000
        default: 100
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.LogsLimit.schema",
            issue="limit query parameter default must be 200",
        ),
    )


def test_openapi_parameter_metadata_drift_accepts_logs_limit_default(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    LogsLimit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
        minimum: 1
        maximum: 1000
        default: 200
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == ()


def test_openapi_parameter_metadata_drift_requires_identity_schema_references(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    CategoryName:
      name: categoryName
      in: path
      required: true
      schema:
        type: number
        minimum: 0
        maximum: 4294967295
    SearchId:
      name: searchId
      in: path
      required: true
      schema:
        type: boolean
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.CategoryName.schema",
            issue="category name parameter must reference CategoryName",
        ),
        ParameterMetadataDrift(
            source="components.parameters.SearchId.schema",
            issue="search ID parameter must reference SearchId",
        ),
    )


def test_openapi_parameter_metadata_drift_accepts_identity_schema_references(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    CategoryName:
      name: categoryName
      in: path
      required: true
      schema:
        $ref: "#/components/schemas/CategoryName"
    SearchId:
      name: searchId
      in: path
      required: true
      schema:
        $ref: "#/components/schemas/SearchId"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == ()


def test_openapi_parameter_metadata_drift_requires_lowercase_md4_path_patterns(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    FileHash:
      name: hash
      in: path
      required: true
      schema:
        type: string
        pattern: "^[0-9A-F]{32}$"
    UserHash:
      name: userHash
      in: path
      required: true
      schema:
        type: integer
        pattern: "^[0-9a-f]{32}$"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.FileHash.schema",
            issue="hash path parameter pattern must be lowercase 32-character hex",
        ),
        ParameterMetadataDrift(
            source="components.parameters.UserHash.schema",
            issue="userHash path parameter type must be string",
        ),
    )


def test_openapi_parameter_metadata_drift_accepts_lowercase_md4_path_patterns(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    FileHash:
      name: hash
      in: path
      required: true
      schema:
        type: string
        pattern: "^[0-9a-f]{32}$"
    UserHash:
      name: userHash
      in: path
      required: true
      schema:
        type: string
        pattern: "^[0-9a-f]{32}$"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == ()


def test_openapi_parameter_metadata_drift_requires_endpoint_path_token_patterns(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    ServerId:
      name: serverId
      in: path
      required: true
      schema:
        type: string
        pattern: "^[^/]+:[0-9]+$"
    ClientId:
      name: clientId
      in: path
      required: true
      schema:
        type: integer
        pattern: "^[0-9a-f]{32}$"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.ClientId.schema",
            issue="clientId path parameter pattern must match REST path-token validation",
        ),
        ParameterMetadataDrift(
            source="components.parameters.ClientId.schema",
            issue="clientId path parameter type must be string",
        ),
        ParameterMetadataDrift(
            source="components.parameters.ServerId.schema",
            issue="serverId path parameter pattern must match REST path-token validation",
        ),
    )


def test_openapi_parameter_metadata_drift_accepts_endpoint_path_token_patterns(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    ServerId:
      name: serverId
      in: path
      required: true
      schema:
        type: string
        pattern: "^[^/]+:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$"
    ClientId:
      name: clientId
      in: path
      required: true
      schema:
        type: string
        pattern: "^([0-9a-f]{32}|[^/]+:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}))$"
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == ()


def test_openapi_parameter_metadata_drift_requires_boolean_query_types(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    IncludeScoreBreakdown:
      name: includeScoreBreakdown
      in: query
      required: false
      schema:
        type: string
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == (
        ParameterMetadataDrift(
            source="components.parameters.IncludeScoreBreakdown.schema",
            issue="includeScoreBreakdown query parameter type must be boolean",
        ),
    )


def test_openapi_parameter_metadata_drift_accepts_boolean_query_types(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    IncludeScoreBreakdown:
      name: includeScoreBreakdown
      in: query
      required: false
      schema:
        type: boolean
        default: false
""",
    )

    assert openapi_parameter_metadata_drift(openapi_yaml) == ()


def test_openapi_parameter_ref_drift_requires_shared_parameter_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /downloads/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      parameters:
        - name: view
          in: query
          required: false
          schema:
            type: string
        - $ref: "#/components/parameters/Limit"
      responses: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
""",
    )

    assert openapi_parameter_ref_drift(openapi_yaml) == (
        ParameterRefDrift(
            source="paths./downloads/{id}.get.parameters[0]",
            issue="parameter must reference a shared parameter component",
        ),
        ParameterRefDrift(
            source="paths./downloads/{id}.parameters[0]",
            issue="parameter must reference a shared parameter component",
        ),
    )


def test_openapi_parameter_ref_drift_requires_logs_limit_parameter(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /logs:
    get:
      parameters:
        - $ref: "#/components/parameters/Limit"
      responses: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
""",
    )

    assert openapi_parameter_ref_drift(openapi_yaml) == (
        ParameterRefDrift(
            source="paths./logs.get.parameters[0]",
            issue="GET /logs must reference #/components/parameters/LogsLimit",
        ),
    )


def test_openapi_parameter_ref_drift_accepts_logs_limit_parameter(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /logs:
    get:
      parameters:
        - $ref: "#/components/parameters/LogsLimit"
      responses: {}
components:
  parameters:
    LogsLimit:
      name: limit
      in: query
      required: false
      schema:
        type: integer
""",
    )

    assert openapi_parameter_ref_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_reusable_schema_shape(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  schemas:
    Empty: {}
    NotObject: true
    NoShape:
      description: Missing a concrete shape.
    EmptyEnum:
      type: string
      enum: []
    GoodObject:
      type: object
      properties: {}
    GoodComposition:
      allOf:
        - $ref: "#/components/schemas/GoodObject"
    GoodEnum:
      type: string
      enum: [one]
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="Empty",
            issue="schema component must not be empty",
        ),
        SchemaComponentDrift(
            component="EmptyEnum",
            issue="enum must be a non-empty list",
        ),
        SchemaComponentDrift(
            component="NoShape",
            issue="schema component must declare type, composition, enum, or const",
        ),
        SchemaComponentDrift(
            component="NotObject",
            issue="schema component must be an object",
        ),
    )


def test_openapi_schema_component_drift_requires_search_session_status_reason(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  schemas:
    SearchSession:
      type: object
      additionalProperties: false
      required: [id, query, method, type, status, resultCount]
      properties:
        status:
          type: string
          enum: [queued, running, completed, error, stopped]
        statusReason:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchSession",
            issue="search session schema must require statusReason",
        ),
        SchemaComponentDrift(
            component="SearchSession.properties.statusReason",
            issue="search session schema statusReason must be nullable string",
        ),
    )


def test_openapi_schema_component_drift_accepts_search_session_status_reason(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  schemas:
    SearchSession:
      type: object
      additionalProperties: false
      required: [id, query, method, type, status, statusReason, resultCount]
      properties:
        status:
          type: string
          enum: [queued, running, completed, error, stopped]
        statusReason:
          type: [string, "null"]
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_search_status_values(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  schemas:
    SearchSession:
      type: object
      additionalProperties: false
      required: [id, query, method, type, status, statusReason, resultCount]
      properties:
        status:
          type: string
          enum: [running, error]
        statusReason:
          type: [string, "null"]
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchSession.properties.status",
            issue="search session schema status enum must be queued, running, completed, error, stopped",
        ),
    )


def test_openapi_schema_component_drift_requires_search_result_extension(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  schemas:
    SearchResult:
      type: object
      additionalProperties: false
      required: [searchId, method, type, hash, name, sizeBytes]
      properties:
        extension:
          type: [string, "null"]
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchResult",
            issue="search result schema must require extension",
        ),
        SchemaComponentDrift(
            component="SearchResult.properties.extension",
            issue="search result extension schema must be string",
        ),
    )


def test_openapi_schema_component_drift_accepts_search_result_extension(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  schemas:
    SearchResult:
      type: object
      additionalProperties: false
      required: [searchId, method, type, hash, name, sizeBytes, extension]
      properties:
        extension:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_non_empty_update_shapes(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    AppSettingsUpdate:
      type: object
      additionalProperties: false
      properties:
        core:
          $ref: "#/components/schemas/CoreSettingsUpdate"
    CoreSettingsUpdate:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        maxUploadSlots:
          type: integer
    SharedFilePriority:
      type: string
      enum: [auto, not-published, verylow, low, normal, high, release]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      dependentRequired:
        comment: [rating]
        rating: [comment]
      properties:
        priority:
          $ref: "#/components/schemas/SharedFilePriority"
        rating:
          type: integer
          minimum: 0
          maximum: 5
        comment:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="AppSettingsUpdate",
            issue="patch/update schema must reject empty objects with minProperties: 1 or required-field composition",
        ),
    )


def test_openapi_schema_component_drift_requires_search_query_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 255
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.query",
            issue="search query maxLength must be 160",
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.query",
            issue=(
                "search query pattern must require non-whitespace text "
                "and reject non-whitespace control characters"
            ),
        ),
    )


def test_openapi_schema_component_drift_accepts_search_query_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_search_create_required_fields(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchCreateRequest",
            issue="search create schema must require query",
        ),
    )


def test_openapi_schema_component_drift_accepts_search_create_required_fields(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_search_mode_type_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [server, global, kad]
        type:
          type: integer
          enum: [audio, video]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.method",
            issue="search method enum must be automatic, server, global, kad",
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.type",
            issue=(
                'search type enum must be "", arc, audio, iso, image, pro, '
                "video, doc, emulecollection"
            ),
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.type",
            issue="search type type must be string",
        ),
    )


def test_openapi_schema_component_drift_accepts_search_mode_type_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_search_extension_schema(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: integer
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.extension",
            issue="search extension type must be string",
        ),
    )


def test_openapi_schema_component_drift_accepts_search_extension_schema(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_search_numeric_filter_schemas(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: number
          minimum: -1
        maxSizeBytes:
          type: integer
        minAvailability:
          type: integer
          minimum: 1
          maximum: 999999
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.maxSizeBytes",
            issue="search maxSizeBytes minimum must be 0",
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.minAvailability",
            issue="search minAvailability maximum must be 1000000",
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.minAvailability",
            issue="search minAvailability minimum must be 0",
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.minSizeBytes",
            issue="search minSizeBytes minimum must be 0",
        ),
        SchemaComponentDrift(
            component="SearchCreateRequest.properties.minSizeBytes",
            issue="search minSizeBytes type must be integer",
        ),
    )


def test_openapi_schema_component_drift_accepts_search_numeric_filter_schemas(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SearchCreateRequest:
      type: object
      additionalProperties: false
      required: [query]
      properties:
        query:
          type: string
          minLength: 1
          maxLength: 160
          pattern: '^(?=.*\S)[^\x00-\x08\x0E-\x1F\x7F-\x9F]*$'
        method:
          type: string
          enum: [automatic, server, global, kad]
        type:
          type: string
          enum: ["", arc, audio, iso, image, pro, video, doc, emulecollection]
        extension:
          type: string
        minSizeBytes:
          type: integer
          minimum: 0
        maxSizeBytes:
          type: integer
          minimum: 0
        minAvailability:
          type: integer
          minimum: 0
          maximum: 1000000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_url_import_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    UrlImportRequest:
      type: object
      additionalProperties: false
      required: [url]
      properties:
        url:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[hH][tT][tT][pP][sS]?://[^\s/?#][^\s]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="UrlImportRequest.properties.url",
            issue="URL import text pattern must require case-insensitive http(s) with a host and no whitespace or controls",
        ),
    )


def test_openapi_schema_component_drift_accepts_url_import_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    UrlImportRequest:
      type: object
      additionalProperties: false
      required: [url]
      properties:
        url:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[hH][tT][tT][pP][sS]?://[^\s/?#\x00-\x1F\x7F-\x9F][^\s\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_url_import_required_fields(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    UrlImportRequest:
      type: object
      additionalProperties: false
      properties:
        url:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[hH][tT][tT][pP][sS]?://[^\s/?#\x00-\x1F\x7F-\x9F][^\s\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="UrlImportRequest",
            issue="URL import request schema must require url",
        ),
    )


def test_openapi_schema_component_drift_accepts_url_import_required_fields(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    UrlImportRequest:
      type: object
      additionalProperties: false
      required: [url]
      properties:
        url:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[hH][tT][tT][pP][sS]?://[^\s/?#\x00-\x1F\x7F-\x9F][^\s\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_priority_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedFilePriority:
      type: string
      enum: [auto, verylow, low, normal, high]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      dependentRequired:
        comment: [rating]
        rating: [comment]
      properties:
        priority:
          type: string
          enum: [auto, normal, release]
        rating:
          type: integer
          minimum: 1
          maximum: 5
        comment:
          type: string
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        priority:
          type: string
          enum: [normal, high]
        static:
          type: boolean
        connect:
          type: boolean
    ServerPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
        priority:
          type: string
          enum: [normal, high]
        static:
          type: boolean
        enabled:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.priority",
            issue="server priority enum must be low, normal, high",
        ),
        SchemaComponentDrift(
            component="ServerPatch.properties.priority",
            issue="server priority enum must be low, normal, high",
        ),
        SchemaComponentDrift(
            component="SharedFilePatch.properties.priority",
            issue="shared file patch priority must reference #/components/schemas/SharedFilePriority",
        ),
        SchemaComponentDrift(
            component="SharedFilePatch.properties.rating",
            issue="shared file rating range must be 0..5",
        ),
        SchemaComponentDrift(
            component="SharedFilePriority",
            issue="shared file priority enum must be auto, not-published, verylow, low, normal, high, release",
        ),
    )


def test_openapi_schema_component_drift_accepts_priority_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedFilePriority:
      type: string
      enum: [auto, not-published, verylow, low, normal, high, release]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      dependentRequired:
        comment: [rating]
        rating: [comment]
      properties:
        priority:
          $ref: "#/components/schemas/SharedFilePriority"
        rating:
          type: integer
          minimum: 0
          maximum: 5
        comment:
          type: string
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        priority:
          type: string
          enum: [low, normal, high]
        static:
          type: boolean
        connect:
          type: boolean
    ServerPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
        priority:
          type: string
          enum: [low, normal, high]
        static:
          type: boolean
        enabled:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_shared_file_comment_rating_dependency(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedFilePriority:
      type: string
      enum: [auto, not-published, verylow, low, normal, high, release]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        priority:
          $ref: "#/components/schemas/SharedFilePriority"
        rating:
          type: integer
          minimum: 0
          maximum: 5
        comment:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SharedFilePatch",
            issue="shared file comment and rating must be mutually dependent",
        ),
    )


def test_openapi_schema_component_drift_requires_shared_file_comment_schema(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedFilePriority:
      type: string
      enum: [auto, not-published, verylow, low, normal, high, release]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      dependentRequired:
        comment: [rating]
        rating: [comment]
      properties:
        priority:
          $ref: "#/components/schemas/SharedFilePriority"
        rating:
          type: integer
          minimum: 0
          maximum: 5
        comment:
          type: integer
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SharedFilePatch.properties.comment",
            issue="shared file comment type must be string",
        ),
    )


def test_openapi_schema_component_drift_accepts_shared_file_comment_schema(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedFilePriority:
      type: string
      enum: [auto, not-published, verylow, low, normal, high, release]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      dependentRequired:
        comment: [rating]
        rating: [comment]
      properties:
        priority:
          $ref: "#/components/schemas/SharedFilePriority"
        rating:
          type: integer
          minimum: 0
          maximum: 5
        comment:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_accepts_shared_file_comment_rating_dependency(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedFilePriority:
      type: string
      enum: [auto, not-published, verylow, low, normal, high, release]
    SharedFilePatch:
      type: object
      additionalProperties: false
      minProperties: 1
      dependentRequired:
        comment: [rating]
        rating: [comment]
      properties:
        priority:
          $ref: "#/components/schemas/SharedFilePriority"
        rating:
          type: integer
          minimum: 0
          maximum: 5
        comment:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_endpoint_address_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    KadBootstrapRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
        port:
          type: integer
          minimum: 1
          maximum: 65535
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="KadBootstrapRequest.properties.address",
            issue="endpoint address pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.address",
            issue="endpoint address pattern must require at least one non-whitespace character",
        ),
    )


def test_openapi_schema_component_drift_accepts_endpoint_address_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    KadBootstrapRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_server_boolean_controls(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: string
        connect:
          type: string
    ServerPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
        static:
          type: string
        enabled:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.connect",
            issue="server boolean control type must be boolean",
        ),
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.static",
            issue="server boolean control type must be boolean",
        ),
        SchemaComponentDrift(
            component="ServerPatch.properties.enabled",
            issue="server boolean control type must be boolean",
        ),
        SchemaComponentDrift(
            component="ServerPatch.properties.static",
            issue="server boolean control type must be boolean",
        ),
    )


def test_openapi_schema_component_drift_accepts_server_boolean_controls(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    ServerPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
        static:
          type: boolean
        enabled:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_server_name_schema(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        static:
          type: boolean
        connect:
          type: boolean
    ServerPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: integer
        static:
          type: boolean
        enabled:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.name",
            issue="server name schema must be an object",
        ),
        SchemaComponentDrift(
            component="ServerPatch.properties.name",
            issue="server name type must be string",
        ),
    )


def test_openapi_schema_component_drift_accepts_server_name_schema(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    ServerPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
        static:
          type: boolean
        enabled:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_endpoint_port_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: number
          minimum: 0
          maximum: 70000
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    KadBootstrapRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: number
          minimum: 0
          maximum: 70000
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="KadBootstrapRequest.properties.port",
            issue="endpoint port range must be 1..65535",
        ),
        SchemaComponentDrift(
            component="KadBootstrapRequest.properties.port",
            issue="endpoint port type must be integer",
        ),
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.port",
            issue="endpoint port range must be 1..65535",
        ),
        SchemaComponentDrift(
            component="ServerCreateRequest.properties.port",
            issue="endpoint port type must be integer",
        ),
    )


def test_openapi_schema_component_drift_accepts_endpoint_port_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    KadBootstrapRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_endpoint_required_fields(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    KadBootstrapRequest:
      type: object
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="KadBootstrapRequest",
            issue="endpoint request schema must require address and port",
        ),
        SchemaComponentDrift(
            component="ServerCreateRequest",
            issue="endpoint request schema must require address and port",
        ),
    )


def test_openapi_schema_component_drift_accepts_endpoint_required_fields(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    ServerCreateRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
        name:
          type: string
        static:
          type: boolean
        connect:
          type: boolean
    KadBootstrapRequest:
      type: object
      required: [address, port]
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
        port:
          type: integer
          minimum: 1
          maximum: 65535
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_nullable_category_ref_accepts_null_default_but_rejects_shape_changes() -> None:
    component = "DownloadCreateRequest.properties.category"
    reference = {"$ref": "#/components/schemas/NullableCategory"}
    for valid in (reference, {**reference, "default": None},
                  {**reference, "description": "Saved name or null", "default": None}):
        drift: list[SchemaComponentDrift] = []
        assert_nullable_category_ref_schema(drift, component, valid)
        assert drift == []
    for invalid in ({**reference, "default": "Alpha"}, {**reference, "type": "string"},
                    {"$ref": "#/components/schemas/CategoryName", "default": None}):
        drift = []
        assert_nullable_category_ref_schema(drift, component, invalid)
        assert drift == [SchemaComponentDrift(
            component=component, issue="category must reference NullableCategory",
        )]


def test_selected_download_shapes_use_job_ids_nullable_metadata_and_per_id_results(selected_rust_openapi) -> None:
    openapi, document = selected_rust_openapi
    assert not [drift for drift in openapi_schema_component_drift(openapi)
                if drift.component.startswith("Download")]
    for action in ("start", "stop", "verify", "remove"):
        operation = document["paths"][f"/downloads/{action}"]["post"]
        assert {code for code in operation["responses"] if code.isdigit() and code.startswith("2")} == {"207"}
        component = "DownloadRemoveRequest" if action == "remove" else "DownloadActionRequest"
        assert operation["requestBody"]["content"]["application/json"]["schema"] == {
            "$ref": f"#/components/schemas/{component}",
        }
    identity = openapi_schema_component(document, "DownloadId")
    for valid in ("1", "9223372036854775807"):
        validate_openapi_schema(document, identity, valid)
    for invalid in ("0", "01", "1\n", 1, None, "1" * 20):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, identity, invalid)

    create = openapi_schema_component(document, "DownloadCreateRequest")
    validate_openapi_schema(document, create, {
        "source": {"type": "content", "hash": "a" * 32, "name": "Unknown size", "sizeBytes": None},
        "category": None, "intent": "stopped", "redownload": True,
    })
    link = "ed2k://|file|current.bin|1|" + "a" * 32 + "|/"
    validate_openapi_schema(document, create, {"source": {"type": "ed2k-link", "link": link}})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, create, {"source": {"type": "ed2k-link", "link": link + "\n"}})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, create, {"source": {"type": "content", "name": "Missing hash"}})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, create, {"source": {"type": "unknown", "hash": "a" * 32,
                                                              "name": "Unknown source"}})
    patch = openapi_schema_component(document, "DownloadPatch")
    validate_openapi_schema(document, patch, {"sizeBytes": 1024})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, patch, {"sizeBytes": None})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, patch, {"unexpectedField": "value"})

    summary = openapi_schema_component(document, "DownloadSummary")
    validate_openapi_schema(document, summary, {
        "id": "1", "hash": "a" * 32, "name": "Unknown size", "category": None,
        "sizeBytes": None, "progress": None, "intent": "stopped", "state": "waiting-metadata",
        "createdAt": 1, "updatedAt": 1, "completedAt": None,
    })
    batch = openapi_schema_component(document, "DownloadBatchItem")
    validate_openapi_schema(document, batch, {"id": "1", "status": "accepted", "httpStatus": 202})
    validate_openapi_schema(document, batch, {"id": "2", "status": "failed", "httpStatus": 404,
                                              "error": {"code": "NOT_FOUND", "message": "Missing", "details": {}}})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, batch, {"id": "2", "status": "failed", "httpStatus": 200})
    observation = openapi_schema_component(document, "DownloadFileNameObservation")
    reported = {"rawName": "raw", "normalizedName": "normalized", "origin": "peer",
                "reporterEndpoint": None, "observedAt": 1}
    validate_openapi_schema(document, observation, reported)
    for field, size in (("rawName", 65_537), ("normalizedName", 4_097)):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, observation, {**reported, field: "a" * size})


def test_download_schema_drift_reports_missing_current_properties(selected_rust_openapi, tmp_path: Path) -> None:
    _, document = selected_rust_openapi
    damaged = deepcopy(document)
    schemas = damaged["components"]["schemas"]
    for component, field in (("DownloadSummary", "hash"),
                             ("Ed2kLinkDownloadSource", "link"),
                             ("DownloadPageMeta", "nextCursor"),
                             ("DownloadBatchItem", "id")):
        del schemas[component]["properties"][field]
    path = tmp_path / "REST-API-OPENAPI.yaml"
    path.write_text(yaml.safe_dump(damaged, sort_keys=False), encoding="utf-8")
    components = {drift.component for drift in openapi_schema_component_drift(path)}
    assert {"DownloadSummary", "Ed2kLinkDownloadSource", "DownloadPageMeta",
            "DownloadBatchItem"} <= components


def test_category_name_and_response_schema_match_current_contract(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    CategoryName:
      type: string
      minLength: 1
      maxLength: 64
      pattern: '^[A-Za-z0-9][A-Za-z0-9-]{0,63}(?![\s\S])'
    NullableCategory:
      oneOf:
        - $ref: "#/components/schemas/CategoryName"
        - type: "null"
    Category:
      type: object
      additionalProperties: false
      required: [name, tempDir, destinationDir, comment]
      properties:
        name:
          $ref: "#/components/schemas/CategoryName"
        tempDir:
          type: [string, "null"]
        destinationDir:
          type: [string, "null"]
        comment:
          type: string
    Transfer:
      type: object
      required: [category]
      properties:
        category:
          $ref: "#/components/schemas/NullableCategory"
""",
    )
    assert openapi_schema_component_drift(openapi_yaml) == ()
    document = load_openapi_document(openapi_yaml)
    schema = openapi_schema_component(document, "Category")
    valid = {"name": "Alpha", "tempDir": None, "destinationDir": None, "comment": ""}
    validate_openapi_schema(document, schema, valid)
    for invalid_name in ("Alpha Beta", "Alpha.Beta", "Alpha_Beta", "-Alpha", "é", "Alpha\n", "A" * 65):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, schema, {**valid, "name": invalid_name})
    transfer_schema = openapi_schema_component(document, "Transfer")
    for valid_assignment in ({"category": None}, {"category": "Alpha"}):
        validate_openapi_schema(document, transfer_schema, valid_assignment)
    for invalid_assignment in ({}, {"category": "Alpha\n"}, {"category": 1}):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, transfer_schema, invalid_assignment)


def test_category_mutation_schema_requires_both_nullable_paths_and_comment(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    CategoryName:
      type: string
      minLength: 1
      maxLength: 64
      pattern: '^[A-Za-z0-9][A-Za-z0-9-]{0,63}(?![\s\S])'
    NullableCategory:
      oneOf:
        - $ref: "#/components/schemas/CategoryName"
        - type: "null"
    CategoryCreateRequest:
      type: object
      additionalProperties: false
      required: [name]
      properties:
        name: {$ref: "#/components/schemas/CategoryName"}
        tempDir: {type: [string, "null"], minLength: 1, pattern: '\S'}
        destinationDir: {type: [string, "null"], minLength: 1, pattern: '\S'}
        comment: {type: string}
    CategoryPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        tempDir: {type: [string, "null"], minLength: 1, pattern: '\S'}
        destinationDir: {type: [string, "null"], minLength: 1, pattern: '\S'}
        comment: {type: string}
""",
    )
    assert openapi_schema_component_drift(openapi_yaml) == ()
    document = load_openapi_document(openapi_yaml)
    patch = openapi_schema_component(document, "CategoryPatch")
    validate_openapi_schema(document, patch, {"tempDir": None})
    validate_openapi_schema(document, patch, {"destinationDir": None})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, patch, {})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, patch, {"name": "Renamed"})
    create = openapi_schema_component(document, "CategoryCreateRequest")
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, create, {"name": "Alpha\n"})


def test_openapi_schema_component_drift_requires_shared_directory_root_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedDirectoryRootInput:
      oneOf:
        - type: string
          minLength: 1
        - type: object
          additionalProperties: false
          required: [path]
          properties:
            path:
              type: string
              minLength: 1
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SharedDirectoryRootInput.oneOf[0]",
            issue="trim-non-empty text pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="SharedDirectoryRootInput.oneOf[1].properties.path",
            issue="trim-non-empty text pattern must require at least one non-whitespace character",
        ),
    )


def test_openapi_schema_component_drift_accepts_shared_directory_root_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    SharedDirectoryRootInput:
      oneOf:
        - type: string
          minLength: 1
          pattern: '\S'
        - type: object
          additionalProperties: false
          required: [path]
          properties:
            path:
              type: string
              minLength: 1
              pattern: '\S'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_friend_user_hash_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    FriendCreateRequest:
      type: object
      properties:
        userHash:
          type: string
          pattern: "^[0-9A-F]{32}$"
        name:
          type: string
          maxLength: 128
          pattern: '^[^\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="FriendCreateRequest",
            issue="friend create schema must require userHash",
        ),
        SchemaComponentDrift(
            component="FriendCreateRequest.properties.userHash",
            issue="friend userHash pattern must be lowercase 32-character hex",
        ),
    )


def test_openapi_schema_component_drift_accepts_friend_user_hash_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    FriendCreateRequest:
      type: object
      required: [userHash]
      properties:
        userHash:
          type: string
          pattern: "^[0-9a-f]{32}$"
        name:
          type: string
          maxLength: 128
          pattern: '^[^\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_friend_name_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    FriendCreateRequest:
      type: object
      required: [userHash]
      properties:
        userHash:
          type: string
          pattern: "^[0-9a-f]{32}$"
        name:
          type: string
          maxLength: 128
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="FriendCreateRequest.properties.name",
            issue="friend name pattern must reject C0 and C1 control characters",
        ),
    )


def test_openapi_schema_component_drift_accepts_friend_name_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    FriendCreateRequest:
      type: object
      required: [userHash]
      properties:
        userHash:
          type: string
          pattern: "^[0-9a-f]{32}$"
        name:
          type: string
          maxLength: 128
          pattern: '^[^\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_confirmation_contract_drift_requires_true_sentinels(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  parameters:
    Confirm:
      name: confirm
      in: query
      required: false
      schema:
        type: boolean
  schemas:
    ClearLogsRequest:
      type: object
      required: []
      properties:
        confirmClearLogs:
          type: boolean
    ShutdownRequest:
      type: object
      required: [confirmShutdown]
      properties:
        confirmShutdown:
          type: string
          enum: [true]
    GoodConfirmRequest:
      type: object
      required: [confirmDump]
      properties:
        confirmDump:
          type: boolean
          enum: [true]
""",
    )

    assert openapi_confirmation_contract_drift(openapi_yaml) == (
        ConfirmationContractDrift(
            source="components.parameters.Confirm.required",
            issue="confirm query parameter must be required",
        ),
        ConfirmationContractDrift(
            source="components.parameters.Confirm.schema",
            issue="confirmation schema enum must be [true]",
        ),
        ConfirmationContractDrift(
            source="components.schemas.ClearLogsRequest.properties.confirmClearLogs",
            issue="confirmation property must be required",
        ),
        ConfirmationContractDrift(
            source="components.schemas.ClearLogsRequest.properties.confirmClearLogs",
            issue="confirmation schema enum must be [true]",
        ),
        ConfirmationContractDrift(
            source="components.schemas.ShutdownRequest.properties.confirmShutdown",
            issue="confirmation schema type must be boolean",
        ),
    )


def test_openapi_query_parameter_inventory_resolves_refs_and_inline_params(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /downloads:
    get:
      parameters:
        - $ref: "#/components/parameters/Limit"
        - name: view
          in: query
      responses: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
""",
    )

    assert openapi_query_parameter_inventory(openapi_yaml) == {
        Route("GET", "/downloads"): ("limit", "view"),
    }


def test_openapi_path_parameter_drift_requires_template_parameter_docs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /downloads/{id}/sources/{clientId}:
    parameters:
      - $ref: "#/components/parameters/DownloadId"
      - name: extra
        in: path
        required: true
    get:
      parameters:
        - name: clientId
          in: path
      responses: {}
components:
  parameters:
    DownloadId:
      name: id
      in: path
      required: true
""",
    )

    assert set(openapi_path_parameter_drift(openapi_yaml)) == {
        PathParameterDrift(
            method="GET",
            path="/downloads/{id}/sources/{clientId}",
            template_parameters=("clientId", "id"),
            documented_path_parameters=("clientId", "extra", "id"),
            issue="path template parameters must match documented path parameters",
        ),
        PathParameterDrift(
            method="GET",
            path="/downloads/{id}/sources/{clientId}",
            template_parameters=("clientId", "id"),
            documented_path_parameters=("clientId", "extra", "id"),
            issue="path parameter 'clientId' must be required",
        ),
    }


def test_rust_query_parameter_inventory_reads_exact_and_parameterized_allowlists(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new()
            .route("/api/v1/app", get(app))
            .route("/api/v1/snapshot", get(snapshot))
            .route("/api/v1/upload-queue", get(upload_queue))
            .route("/api/v1/downloads", get(downloads))
            .route("/api/v1/searches/{searchId}/results", get(search_results));
        ''',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        '''
        fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const NONE: &[&str] = &[];
            const SNAPSHOT: &[&str] = &["limit"];
            const DOWNLOADS: &[&str] = &["view", "category", "cursor", "limit"];
            const SEARCH_RESULTS: &[&str] = &["limit", "cursor", "sort", "order"];
            const UPLOAD_QUEUE: &[&str] = &["offset", "limit", "includeScoreBreakdown"];
            match (method, path) {
                ("GET", "/api/v1/app")
                | ("GET", "/api/v1/upload-queue") => Some(match path {
                    "/api/v1/upload-queue" if method == "GET" => UPLOAD_QUEUE,
                    _ => NONE,
                }),
                ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
                ("GET", "/api/v1/downloads") => Some(DOWNLOADS),
                _ => route_query_fields_for_parameterized(method, path),
            }
        }

        fn route_query_fields_for_parameterized(
            method: &str,
            path: &str,
        ) -> Option<&'static [&'static str]> {
            const NONE: &[&str] = &[];
            const SEARCH_RESULTS: &[&str] = &["limit", "cursor", "sort", "order"];
            let segments = path.strip_prefix("/api/v1/")?.split('/').collect::<Vec<_>>();
            match (method, segments.as_slice()) {
                ("GET", ["searches", _, "results"]) => Some(SEARCH_RESULTS),
                _ => Some(NONE),
            }
        }
        ''',
    )

    assert rust_query_parameter_inventory(route_metadata_rs, routes_rs) == {
        Route("GET", "/app"): (),
        Route("GET", "/snapshot"): ("limit",),
        Route("GET", "/upload-queue"): ("includeScoreBreakdown", "limit", "offset"),
        Route("GET", "/downloads"): ("category", "cursor", "limit", "view"),
        Route("GET", "/searches/{searchId}/results"): ("cursor", "limit", "order", "sort"),
    }


def test_compare_route_contract_reports_query_parameter_drift(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        'Router::new().route("/api/v1/snapshot", get(snapshot));',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        '''
        fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const SNAPSHOT: &[&str] = &["limit"];
            match (method, path) {
                ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
                _ => None,
            }
        }
        ''',
    )
    route_body_metadata_rs = write(
        tmp_path / "route_body_metadata.rs",
        'fn route_body_fields(method: &str, path: &str) -> Option<&static [&static str]> { None }',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /snapshot:
    get:
      parameters:
        - name: since
          in: query
      responses: {}
""",
    )

    report = compare_route_contract(routes_rs, route_metadata_rs, route_body_metadata_rs, openapi_yaml)

    assert report.query_parameter_drift == (
        QueryParameterDrift(
            route=Route("GET", "/snapshot"),
            rust_query_parameters=("limit",),
            openapi_query_parameters=("since",),
        ),
    )


def test_openapi_body_field_inventory_reads_ref_schema_properties(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /downloads:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SampleRequest"
      responses: {}
components:
  schemas:
    SampleRequest:
      type: object
      properties:
        source: { type: object }
        category: { type: string }
        intent: { type: string }
        redownload: { type: boolean }
""",
    )

    assert openapi_body_field_inventory(openapi_yaml) == {
        Route("POST", "/downloads"): ("category", "intent", "redownload", "source"),
    }


def test_openapi_request_body_metadata_drift_requires_json_schema_ref_and_explicit_required(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /missing-required:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SampleRequest"
      responses: {}
  /extra-media:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SampleRequest"
          text/plain:
            schema: { type: string }
      responses: {}
  /inline-schema:
    patch:
      requestBody:
        required: false
        content:
          application/json:
            schema:
              type: object
      responses: {}
  /optional-body:
    post:
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SearchResultDownloadRequest"
      responses: {}
  /open-body:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/OpenRequest"
      responses: {}
  /array-body:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ArrayRequest"
      responses: {}
components:
  schemas:
    SampleRequest:
      type: object
      additionalProperties: false
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
    OpenRequest:
      type: object
    ArrayRequest:
      type: array
      additionalProperties: false
""",
    )

    assert openapi_request_body_metadata_drift(openapi_yaml) == (
        RequestBodyMetadataDrift(
            method="PATCH",
            path="/inline-schema",
            issue="requestBody application/json schema must reference a shared schema component",
        ),
        RequestBodyMetadataDrift(
            method="POST",
            path="/array-body",
            issue="requestBody schema component ArrayRequest must be an object",
        ),
        RequestBodyMetadataDrift(
            method="POST",
            path="/extra-media",
            issue="requestBody content must contain only application/json",
        ),
        RequestBodyMetadataDrift(
            method="POST",
            path="/missing-required",
            issue="requestBody.required must be explicit true or false",
        ),
        RequestBodyMetadataDrift(
            method="POST",
            path="/open-body",
            issue="requestBody schema component OpenRequest must set additionalProperties: false",
        ),
    )


def test_openapi_response_header_drift_resolves_response_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /app:
    get:
      responses:
        "200":
          $ref: "#/components/responses/AppResponse"
        "404":
          description: Route missing.
          headers: {}
components:
  responses:
    AppResponse:
      description: App response.
      headers:
        X-Contract-Version:
          $ref: "#/components/headers/ContractVersionHeader"
  headers:
    ContractVersionHeader:
      description: Native contract version.
      schema:
        type: string
""",
    )

    assert openapi_response_header_drift(openapi_yaml) == (
        ResponseHeaderDrift(
            route=Route("GET", "/app"),
            status="404",
            missing_header="X-Contract-Version",
        ),
    )


def test_openapi_response_component_drift_requires_shared_response_metadata(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  responses:
    BrokenJsonResponse:
      description: ""
      headers:
        X-Contract-Version:
          schema:
            type: string
      content:
        application/json: {}
        text/plain:
          schema:
            type: string
    EventStreamResponse:
      description: Event stream.
      headers:
        X-Contract-Version:
          $ref: "#/components/headers/ContractVersionHeader"
        Cache-Control:
          schema:
            type: string
        X-Accel-Buffering:
          schema:
            type: string
      content:
        text/event-stream:
          schema:
            type: string
""",
    )

    assert set(openapi_response_component_drift(openapi_yaml)) == {
        ResponseComponentDrift(
            component="BrokenJsonResponse",
            issue="application/json schema must be an object",
        ),
        ResponseComponentDrift(
            component="BrokenJsonResponse",
            issue="content media types must be application/json",
        ),
        ResponseComponentDrift(
            component="BrokenJsonResponse",
            issue="description must be non-empty",
        ),
        ResponseComponentDrift(
            component="BrokenJsonResponse",
            issue="must reference #/components/headers/ContractVersionHeader",
        ),
    }


def test_openapi_response_component_drift_requires_sse_proxy_headers(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  responses:
    EventStreamResponse:
      description: Event stream.
      headers:
        X-Contract-Version:
          $ref: "#/components/headers/ContractVersionHeader"
        Cache-Control:
          schema:
            type: string
      content:
        text/event-stream:
          schema:
            type: string
""",
    )

    assert openapi_response_component_drift(openapi_yaml) == (
        ResponseComponentDrift(
            component="EventStreamResponse",
            issue="must document X-Accel-Buffering header",
        ),
    )


def test_openapi_success_response_drift_validates_every_declared_success(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /missing:
    get:
      responses:
        "400": { description: Error }
  /inline:
    get:
      responses:
        "200":
          description: Inline response.
  /multiple:
    post:
      responses:
        "200":
          $ref: "#/components/responses/OkResponse"
        "201":
          $ref: "#/components/responses/AcceptedResponse"
  /multiple-bad:
    post:
      responses:
        "200":
          $ref: "#/components/responses/OkResponse"
        "201":
          $ref: "#/components/responses/NoSchemaResponse"
  /schema-less:
    get:
      responses:
        "200":
          $ref: "#/components/responses/NoSchemaResponse"
components:
  responses:
    OkResponse:
      content:
        application/json:
          schema:
            type: object
    AcceptedResponse:
      content:
        application/json:
          schema:
            type: object
    NoSchemaResponse:
      content:
        application/json: {}
""",
    )

    assert set(openapi_success_response_drift(openapi_yaml)) == {
        SuccessResponseDrift(
            method="GET",
            path="/inline",
            status="200",
            issue="2xx response must reference a shared response component",
        ),
        SuccessResponseDrift(
            method="GET",
            path="/missing",
            status="",
            issue="missing 2xx response",
        ),
        SuccessResponseDrift(
            method="POST",
            path="/multiple-bad",
            status="201",
            issue="response component NoSchemaResponse must define a media schema",
        ),
        SuccessResponseDrift(
            method="GET",
            path="/schema-less",
            status="200",
            issue="response component NoSchemaResponse must define a media schema",
        ),
    }


def test_openapi_auth_drift_requires_api_key_scheme_and_401_responses(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /app:
    get:
      responses:
        "200": { description: OK }
  /status:
    get:
      responses:
        "200": { description: OK }
        "401": { description: Unauthorized }
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: query
      name: api_key
""",
    )

    assert openapi_auth_drift(openapi_yaml) == (
        AuthDrift(
            method="",
            path="<document>",
            issue="ApiKeyAuth must be an apiKey header named X-API-Key",
        ),
        AuthDrift(
            method="",
            path="<document>",
            issue="missing top-level ApiKeyAuth security requirement",
        ),
        AuthDrift(
            method="GET",
            path="/app",
            issue="missing 401 response",
        ),
    )


def test_openapi_auth_drift_rejects_operation_security_override_without_api_key(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
security:
  - ApiKeyAuth: []
paths:
  /events:
    get:
      security: []
      responses:
        "200": { description: OK }
        "401": { description: Unauthorized }
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
""",
    )

    assert openapi_auth_drift(openapi_yaml) == (
        AuthDrift(
            method="GET",
            path="/events",
            issue="operation security override must include ApiKeyAuth",
        ),
    )


def test_openapi_error_response_drift_requires_shared_error_responses(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /app:
    get:
      responses:
        "200": { description: OK }
        "400": { description: Inline error }
        "404":
          $ref: "#/components/responses/AppMissingResponse"
        "500":
          description: Inline server error.
        default:
          $ref: "#/components/responses/ErrorResponse"
components:
  responses:
    ErrorResponse:
      description: Error envelope.
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/WrongEnvelope"
""",
    )

    assert openapi_error_response_drift(openapi_yaml) == (
        ErrorResponseDrift(
            method="",
            path="<components.responses.ErrorResponse>",
            status="",
            issue="ErrorResponse must reference #/components/schemas/ErrorEnvelope",
        ),
        ErrorResponseDrift(
            method="GET",
            path="/app",
            status="400",
            issue="must reference ErrorResponse",
        ),
        ErrorResponseDrift(
            method="GET",
            path="/app",
            status="401",
            issue="missing error response",
        ),
        ErrorResponseDrift(
            method="GET",
            path="/app",
            status="404",
            issue="documented non-success responses must reference ErrorResponse",
        ),
        ErrorResponseDrift(
            method="GET",
            path="/app",
            status="500",
            issue="documented non-success responses must reference ErrorResponse",
        ),
    )


def test_openapi_error_response_drift_requires_404_for_resource_paths_only(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /downloads:
    get:
      responses:
        "200": { $ref: "#/components/responses/OkResponse" }
        "400": { $ref: "#/components/responses/ErrorResponse" }
        "401": { $ref: "#/components/responses/ErrorResponse" }
        default: { $ref: "#/components/responses/ErrorResponse" }
  /downloads/start:
    post:
      responses:
        "207": { $ref: "#/components/responses/BatchResponse" }
        "400": { $ref: "#/components/responses/ErrorResponse" }
        "401": { $ref: "#/components/responses/ErrorResponse" }
        default: { $ref: "#/components/responses/ErrorResponse" }
  /downloads/{id}:
    get:
      responses:
        "200": { $ref: "#/components/responses/OkResponse" }
        "400": { $ref: "#/components/responses/ErrorResponse" }
        "401": { $ref: "#/components/responses/ErrorResponse" }
        default: { $ref: "#/components/responses/ErrorResponse" }
components:
  responses:
    ErrorResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorEnvelope"
""",
    )

    assert openapi_error_response_drift(openapi_yaml) == (
        ErrorResponseDrift(method="GET", path="/downloads/{id}", status="404",
                           issue="missing error response"),
    )
    document = yaml.safe_load(openapi_yaml.read_text(encoding="utf-8"))
    document["paths"]["/downloads/{id}"]["get"]["responses"]["404"] = {
        "$ref": "#/components/responses/ErrorResponse"
    }
    openapi_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert openapi_error_response_drift(openapi_yaml) == ()


def test_openapi_method_not_allowed_drift_requires_405_ref_and_allow_header(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /app:
    get:
      responses:
        "200": { description: OK }
  /status:
    get:
      responses:
        "200": { description: OK }
        "405": { description: Wrong shape }
components:
  responses:
    MethodNotAllowedResponse:
      description: Method not allowed.
      headers: {}
""",
    )

    assert openapi_method_not_allowed_drift(openapi_yaml) == (
        MethodNotAllowedDrift(
            method="",
            path="<components.responses.MethodNotAllowedResponse>",
            issue="missing Allow header",
        ),
        MethodNotAllowedDrift(
            method="GET",
            path="/app",
            issue="missing 405 response",
        ),
        MethodNotAllowedDrift(
            method="GET",
            path="/status",
            issue="405 response must reference MethodNotAllowedResponse",
        ),
    )


def test_openapi_contract_version_drift_requires_rust_openapi_and_header_ref_consistency(
    tmp_path: Path,
) -> None:
    responses_rs = write(
        tmp_path / "responses.rs",
        'pub(crate) const CONTRACT_VERSION: &str = "1.1.0";',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
info:
  version: 1.1.0
  x-contract-version: "1.0.0"
paths:
  /app:
    get:
      responses:
        "200":
          headers:
            X-Contract-Version:
              schema: { type: string }
components:
  headers:
    ContractVersionHeader:
      schema:
        type: string
        const: "1.1.0"
        example: "1.1.0"
  responses:
    AppResponse:
      description: App response.
      headers:
        X-Contract-Version:
          schema: { type: string }
  schemas:
    CapabilityDiscovery:
      type: object
      properties:
        contractVersion:
          type: string
          example: "1.0.0"
""",
    )

    drift_by_source = {
        drift.source: drift.issue
        for drift in openapi_contract_version_drift(openapi_yaml, responses_rs)
    }

    assert drift_by_source[str(responses_rs)] == "CONTRACT_VERSION must be 2.0.0, got 1.1.0"
    assert drift_by_source["info.version"] == "must be 2.0.0, got '1.1.0'"
    assert drift_by_source["info.x-contract-version"] == "must be 2.0.0, got '1.0.0'"
    assert (
        drift_by_source["components.headers.ContractVersionHeader.schema.const"]
        == "must be 2.0.0, got '1.1.0'"
    )
    assert (
        drift_by_source["components.headers.ContractVersionHeader.schema.example"]
        == "must be 2.0.0, got '1.1.0'"
    )
    assert (
        drift_by_source["components.schemas.CapabilityDiscovery.properties.contractVersion.const"]
        == "must be 2.0.0, got None"
    )
    assert (
        drift_by_source["components.schemas.CapabilityDiscovery.properties.contractVersion.example"]
        == "must be 2.0.0, got '1.0.0'"
    )
    assert (
        drift_by_source["components.responses.AppResponse.headers.X-Contract-Version"]
        == "must reference #/components/headers/ContractVersionHeader"
    )
    assert (
        drift_by_source["paths./app.get.responses.200.headers.X-Contract-Version"]
        == "must reference #/components/headers/ContractVersionHeader"
    )


def test_openapi_contract_version_drift_accepts_shared_version_and_header_refs(tmp_path: Path) -> None:
    responses_rs = write(
        tmp_path / "responses.rs",
        'pub(crate) const CONTRACT_VERSION: &str = "2.0.0";',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
info:
  version: 2.0.0
  x-contract-version: "2.0.0"
paths:
  /app:
    get:
      responses:
        "200":
          headers:
            X-Contract-Version:
              $ref: "#/components/headers/ContractVersionHeader"
components:
  headers:
    ContractVersionHeader:
      schema:
        type: string
        const: "2.0.0"
        example: "2.0.0"
  schemas:
    CapabilityDiscovery:
      type: object
      properties:
        contractVersion:
          type: string
          const: "2.0.0"
          example: "2.0.0"
""",
    )

    assert rust_contract_version(responses_rs) == "2.0.0"
    assert openapi_contract_version_drift(openapi_yaml, responses_rs) == ()


@pytest.mark.parametrize("braced_search_arm", [False, True])
def test_rust_body_field_inventory_reads_exact_and_parameterized_allowlists(tmp_path: Path, braced_search_arm: bool) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new()
            .route("/api/v1/app", get(app))
            .route("/api/v1/downloads", post(create_download))
            .route("/api/v1/downloads/{id}", patch(update_download))
            .route("/api/v1/downloads/start", post(start_downloads))
            .route("/api/v1/shared-directories/ignores/defaults/{ruleKey}", patch(update_ignore))
            .route("/api/v1/servers/operations/import-met-url", post(import_servers))
            .route("/api/v1/searches/{searchId}/results/{resultId}/download", post(download));
        ''',
    )
    route_body_metadata_rs = write(
        tmp_path / "route_body_metadata.rs",
        '''
        fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const DOWNLOAD_CREATE: &[&str] = &["source", "category", "intent", "redownload"];
            const DOWNLOAD_PATCH: &[&str] = &["name", "category", "sizeBytes"];
            const DOWNLOAD_ACTION: &[&str] = &["ids"];
            const SEARCH_RESULT_DOWNLOAD: &[&str] = &["category", "intent", "redownload"];
            const SHARED_FILE_IGNORE_RULE: &[&str] = &["enabled"];
            const URL_IMPORT: &[&str] = &["url"];
            if method == "POST" && path == "/api/v1/downloads" {
                return Some(DOWNLOAD_CREATE);
            }
            if method == "POST" && path == "/api/v1/downloads/start" {
                return Some(DOWNLOAD_ACTION);
            }
            if uses_url_import_body(method, path) {
                return Some(URL_IMPORT);
            }
            let segments = api_segments(path)?;
            match (method, segments.as_slice()) {
                ("PATCH", ["downloads", _]) => Some(DOWNLOAD_PATCH),
                ("PATCH", ["shared-directories", "ignores", "defaults", _]) => {
                    Some(SHARED_FILE_IGNORE_RULE)
                }
                ("POST", ["searches", _, "results", _, "download"]) => {
                    Some(SEARCH_RESULT_DOWNLOAD)
                }
                _ => None,
            }
        }
        fn uses_url_import_body(method: &str, path: &str) -> bool {
            method == "POST"
                && matches!(
                    path,
                    "/api/v1/servers/operations/import-met-url" | "/api/v1/kad/operations/import-nodes-url"
                )
        }
        ''',
    )

    if not braced_search_arm:
        source = route_body_metadata_rs.read_text(encoding="utf-8")
        source = source.replace(
            '=> {\n                    Some(SEARCH_RESULT_DOWNLOAD)\n                }',
            '=> Some(SEARCH_RESULT_DOWNLOAD)',
        )
        route_body_metadata_rs.write_text(source, encoding="utf-8", newline="\n")

    assert rust_body_field_inventory(route_body_metadata_rs, routes_rs) == {
        Route("GET", "/app"): (),
        Route("PATCH", "/shared-directories/ignores/defaults/{ruleKey}"): ("enabled",),
        Route("POST", "/downloads"): ("category", "intent", "redownload", "source"),
        Route("PATCH", "/downloads/{id}"): ("category", "name", "sizeBytes"),
        Route("POST", "/downloads/start"): ("ids",),
        Route("POST", "/servers/operations/import-met-url"): ("url",),
        Route("POST", "/searches/{searchId}/results/{resultId}/download"): (
            "category",
            "intent",
            "redownload",
        ),
    }


def test_compare_route_contract_reports_body_field_drift(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        'Router::new().route("/api/v1/downloads", post(create_download));',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        'fn route_query_fields(method: &str, path: &str) -> Option<&static [&static str]> { None }',
    )
    route_body_metadata_rs = write(
        tmp_path / "route_body_metadata.rs",
        '''
        fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const DOWNLOAD_CREATE: &[&str] = &["source"];
            if method == "POST" && path == "/api/v1/downloads" {
                return Some(DOWNLOAD_CREATE);
            }
            None
        }
        ''',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /downloads:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                source: { type: object }
                category: { type: string }
      responses: {}
""",
    )

    report = compare_route_contract(routes_rs, route_metadata_rs, route_body_metadata_rs, openapi_yaml)

    assert report.body_field_drift == (
        BodyFieldDrift(
            route=Route("POST", "/downloads"),
            rust_body_fields=("source",),
            openapi_body_fields=("category", "source"),
        ),
    )


@pytest.mark.parametrize("event", [
    {"type": "download.changed", "id": 1, "downloadId": "1"},
    {"type": "download.removed", "id": 2, "downloadId": "1"},
    {"type": "sync.reset", "id": 0, "reason": "initial"},
    {"type": "sync.reset", "id": 7, "reason": "reconnect"},
    {"type": "sync.reset", "id": 8, "reason": "lagged", "missed": 2},
    {"type": "sync.reset", "id": 0, "reason": "epoch-changed"},
])
def test_selected_download_events_require_epoch_and_valid_revision(selected_rust_openapi, event):
    _, document = selected_rust_openapi
    schema = openapi_schema_component(document, "DownloadEvent")
    payload = {**event, "epoch": "00000000-0000-4000-8000-000000000001"}
    validate_openapi_schema(document, schema, payload)
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, schema, event)
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, schema, {**payload, "id": -1})


def test_selected_download_parts_are_a_bounded_independent_page(selected_rust_openapi):
    _, document = selected_rust_openapi
    schema = response_json_schema(openapi_operation_response(document, "get", "/downloads/{id}/parts", "200"), "download parts")
    validate_openapi_schema(document, schema, {
        "data": [], "meta": {"apiVersion": "2.0.0", "nextCursor": None, "hasMore": False},
    })


def test_selected_download_detail_and_nonempty_parts_match_checkpointed_projection(selected_rust_openapi):
    _, document = selected_rust_openapi
    detail = {
        "id": "1", "hash": "a" * 32, "name": "Sample.bin", "category": None,
        "sizeBytes": 4096, "progress": 0, "intent": "started", "state": "failed",
        "createdAt": 1, "updatedAt": 2, "completedAt": None, "payloadVerified": False,
        "delivery": {"path": None, "state": "pending", "ownership": "none"},
        "failure": {"code": "STORAGE_UNAVAILABLE", "message": "Storage is unavailable", "failedAt": 2},
    }
    validate_openapi_schema(document, openapi_schema_component(document, "Download"), detail)
    schema = response_json_schema(openapi_operation_response(document, "get", "/downloads/{id}/parts", "200"), "download parts")
    validate_openapi_schema(document, schema, {
        "data": [{"index": 0, "start": 0, "end": 4095, "sizeBytes": 4096,
                  "presentBytes": 1024, "complete": False, "corrupted": False}],
        "meta": {"apiVersion": "2.0.0", "nextCursor": None, "hasMore": False},
    })


def test_selected_library_tags_have_name_identity_and_bounded_bulk_contract(selected_rust_openapi):
    _, document = selected_rust_openapi
    from emule_test_harness.rust_openapi_responses import openapi_schema_component, validate_openapi_schema
    validate_openapi_schema(document, openapi_schema_component(document, "ErrorEnvelope"),
                            {"error": {"code": "TAG_NAME_CONFLICT", "message": "tag name already exists", "details": {}}})
    tag = openapi_schema_component(document, "LibraryTag")
    validate_openapi_schema(document, tag, {"name": "Rotate-1"})
    assignment = openapi_schema_component(document, "LibraryTagAssignmentRequest")
    validate_openapi_schema(document, assignment, {"tag": "Rotate-1", "hashes": ["01" * 16]})
    for value in ([], ["01" * 16] * 2, [f"{i:032x}" for i in range(101)]):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, assignment, {"tag": "Rotate-1", "hashes": value})
    result = openapi_schema_component(document, "LibraryTagBatchItem")
    validate_openapi_schema(document, result, {"hash": "01" * 16, "status": "accepted", "httpStatus": 200})
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, result, {"hash": "01" * 16, "status": "failed", "httpStatus": 404})
    parameters = document["components"]["parameters"]
    assert parameters["LibraryTagLimit"]["schema"]["default"] == 100
    assert parameters["LibraryTagLimit"]["schema"]["maximum"] == 200
    assert parameters["LibraryTagCursor"]["schema"]["maxLength"] == 512


def test_no_content_contract_preserves_headers_and_forbids_body(tmp_path: Path):
    text = """
paths:
  /item:
    delete:
      responses:
        "204":
          $ref: '#/components/responses/NoContentResponse'
components:
  responses:
    NoContentResponse:
      description: Removed.
      headers:
        X-Contract-Version:
          $ref: '#/components/headers/ContractVersionHeader'
"""
    contract = write(tmp_path / "contract.yaml", text)
    assert openapi_success_response_drift(contract) == ()
    assert openapi_response_component_drift(contract) == ()
    contract.write_text(text + "      content: {application/json: {schema: {type: object}}}\n", encoding="utf-8")
    assert any("must not define content" in item.issue for item in openapi_success_response_drift(contract))
    assert any("must not define content" in item.issue for item in openapi_response_component_drift(contract))


def test_selected_library_sharing_requires_explicit_bool_and_bounded_distinct_hashes(selected_rust_openapi):
    _, document = selected_rust_openapi
    schema = openapi_schema_component(document, "LibrarySharingRequest")
    valid = {"enabled": False, "hashes": ["ab" * 16]}
    validate_openapi_schema(document, schema, valid)
    for invalid in ({"hashes": valid["hashes"]}, {**valid, "enabled": None}, {**valid, "enabled": "false"},
                    {**valid, "hashes": []}, {**valid, "hashes": ["ab" * 16] * 2},
                    {**valid, "hashes": [f"{i:032x}" for i in range(101)]}, {**valid, "hashes": ["AB" * 16]}):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, schema, invalid)
    operation = document["paths"]["/library/files/sharing"]["post"]
    assert operation["operationId"] == "setLibrarySharing"
    assert operation["requestBody"]["required"] is True


def test_selected_library_sharing_outcomes_preserve_error_status_and_commit_meaning(selected_rust_openapi):
    _, document = selected_rust_openapi
    schema = openapi_schema_component(document, "LibrarySharingBatchItem")
    for status in ("accepted", "unchanged"):
        validate_openapi_schema(document, schema, {"hash": "01" * 16, "status": status, "httpStatus": 200})
    committed = {"hash": "01" * 16, "status": "failed", "httpStatus": 503,
                 "error": {"code": "PERSISTENCE_COMMITTED", "message": "publication failed", "details": {"committed": True}}}
    validate_openapi_schema(document, schema, committed)
    for invalid in ({**committed, "httpStatus": 500}, {**committed, "status": "accepted"},
                    {**committed, "error": {**committed["error"], "details": {"committed": False}}},
                    {"hash": "01" * 16, "status": "failed", "httpStatus": 404}):
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, schema, invalid)
