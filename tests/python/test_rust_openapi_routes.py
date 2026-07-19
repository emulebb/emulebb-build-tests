from __future__ import annotations

from pathlib import Path

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
                "/api/v1/categories/{categoryId}",
                get(category).patch(update_category).delete(delete_category),
            )
            .route("/api/v1/{*path}", any(fallback));
        ''',
    )

    assert rust_route_inventory(routes_rs) == {
        Route("GET", "/app"),
        Route("DELETE", "/categories/{categoryId}"),
        Route("GET", "/categories/{categoryId}"),
        Route("PATCH", "/categories/{categoryId}"),
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
  /categories/{categoryId}:
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
        Route("DELETE", "/categories/{categoryId}"),
        Route("GET", "/categories/{categoryId}"),
        Route("PATCH", "/categories/{categoryId}"),
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
    FileHash:
      name: hash
      in: path
      required: true
      schema:
        type: string
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


def test_openapi_parameter_ref_drift_requires_shared_parameter_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /transfers/{hash}:
    parameters:
      - name: hash
        in: path
        required: true
        schema:
          type: string
    get:
      parameters:
        - name: state
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
            source="paths./transfers/{hash}.get.parameters[0]",
            issue="parameter must reference a shared parameter component",
        ),
        ParameterRefDrift(
            source="paths./transfers/{hash}.parameters[0]",
            issue="parameter must reference a shared parameter component",
        ),
    )


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
    TransferPriority:
      type: string
      enum: [auto, verylow, low, normal, high, veryhigh]
    TransferPatch:
      type: object
      additionalProperties: false
      oneOf:
        - required: [priority]
        - required: [name]
      properties:
        priority:
          $ref: "#/components/schemas/TransferPriority"
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
    SharedFilePriority:
      type: string
      enum: [auto, verylow, low, normal, high, release]
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


def test_openapi_schema_component_drift_requires_transfer_rename_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 255
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="TransferPatch.properties.name",
            issue=(
                "transfer rename pattern must reject trim-empty text, "
                "Windows-forbidden filename characters, and controls"
            ),
        ),
        SchemaComponentDrift(
            component="TransferPatch.properties.name",
            issue="transfer rename schema must not claim an unsupported maxLength",
        ),
    )


def test_openapi_schema_component_drift_accepts_transfer_rename_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_transfer_link_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://\S+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://\S+$'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="TransferCreateRequest.properties.link",
            issue="link text pattern must require case-insensitive ed2k:// without whitespace or controls",
        ),
        SchemaComponentDrift(
            component="TransferCreateRequest.properties.links.items",
            issue="link text pattern must require case-insensitive ed2k:// without whitespace or controls",
        ),
    )


def test_openapi_schema_component_drift_requires_transfer_create_link_choice(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="TransferCreateRequest",
            issue="transfer create schema must require exactly one of link or links",
        ),
    )


def test_openapi_schema_component_drift_accepts_transfer_create_link_choice(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_paused_boolean_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        paused:
          type: string
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        paused:
          type: string
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchResultDownloadRequest.properties.paused",
            issue="paused type must be boolean",
        ),
        SchemaComponentDrift(
            component="TransferCreateRequest.properties.paused",
            issue="paused type must be boolean",
        ),
    )


def test_openapi_schema_component_drift_accepts_paused_boolean_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        paused:
          type: boolean
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_accepts_transfer_link_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


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


def test_openapi_schema_component_drift_requires_category_selector_name_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        categoryName:
          type: string
          minLength: 1
        paused:
          type: boolean
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
        categoryName:
          type: string
          minLength: 1
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        categoryName:
          type: string
          minLength: 1
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchResultDownloadRequest.properties.categoryName",
            issue="category selector name pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="TransferCreateRequest.properties.categoryName",
            issue="category selector name pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="TransferPatch.properties.categoryName",
            issue="category selector name pattern must require at least one non-whitespace character",
        ),
    )


def test_openapi_schema_component_drift_accepts_category_selector_name_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_category_selector_exclusion(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      properties:
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchResultDownloadRequest",
            issue="category selector schema must reject categoryId and categoryName together",
        ),
        SchemaComponentDrift(
            component="TransferCreateRequest",
            issue="category selector schema must reject categoryId and categoryName together",
        ),
    )


def test_openapi_schema_component_drift_accepts_category_selector_exclusion(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_category_selector_id_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        categoryId:
          type: number
          minimum: 1
          maximum: 255
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
        priority:
          $ref: "#/components/schemas/TransferPriority"
        categoryId:
          type: number
          minimum: 1
          maximum: 255
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        categoryId:
          type: number
          minimum: 1
          maximum: 255
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="SearchResultDownloadRequest.properties.categoryId",
            issue="category selector id range must be 0..4294967295",
        ),
        SchemaComponentDrift(
            component="SearchResultDownloadRequest.properties.categoryId",
            issue="category selector id type must be integer",
        ),
        SchemaComponentDrift(
            component="TransferCreateRequest.properties.categoryId",
            issue="category selector id range must be 0..4294967295",
        ),
        SchemaComponentDrift(
            component="TransferCreateRequest.properties.categoryId",
            issue="category selector id type must be integer",
        ),
        SchemaComponentDrift(
            component="TransferPatch.properties.categoryId",
            issue="category selector id range must be 0..4294967295",
        ),
        SchemaComponentDrift(
            component="TransferPatch.properties.categoryId",
            issue="category selector id type must be integer",
        ),
    )


def test_openapi_schema_component_drift_accepts_category_selector_id_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    TransferPriority:
      type: string
      enum: [auto, verylow, low, normal, high, veryhigh]
    TransferCreateRequest:
      type: object
      additionalProperties: false
      oneOf:
        - required: [link]
          not:
            required: [links]
        - required: [links]
          not:
            required: [link]
      not:
        required: [categoryId, categoryName]
      properties:
        link:
          type: string
          minLength: 1
          maxLength: 2048
          pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        links:
          type: array
          minItems: 1
          maxItems: 100
          items:
            type: string
            minLength: 1
            maxLength: 2048
            pattern: '^[eE][dD]2[kK]://[^\s\x00-\x1F\x7F-\x9F]+$'
        categoryId:
          type: integer
          minimum: 0
          maximum: 4294967295
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
        priority:
          $ref: "#/components/schemas/TransferPriority"
        categoryId:
          type: integer
          minimum: 0
          maximum: 4294967295
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
    SearchResultDownloadRequest:
      type: object
      additionalProperties: false
      not:
        required: [categoryId, categoryName]
      properties:
        categoryId:
          type: integer
          minimum: 0
          maximum: 4294967295
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
        paused:
          type: boolean
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
    TransferPriority:
      type: string
      enum: [auto, verylow, low, normal, high]
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
        priority:
          type: string
          enum: [low, normal, high]
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
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
    CategoryPriorityInput:
      oneOf:
        - type: string
          enum: [low, normal, high]
        - type: integer
          minimum: 1
          maximum: 255
    ServerCreateRequest:
      type: object
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
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
            component="CategoryPriorityInput",
            issue="category priority integer range must be 0..4294967295",
        ),
        SchemaComponentDrift(
            component="CategoryPriorityInput",
            issue="category priority string enum must be verylow, low, normal, high, veryhigh",
        ),
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
            issue="shared file priority enum must be auto, verylow, low, normal, high, release",
        ),
        SchemaComponentDrift(
            component="TransferPatch.properties.priority",
            issue="transfer patch priority must reference #/components/schemas/TransferPriority",
        ),
        SchemaComponentDrift(
            component="TransferPriority",
            issue="transfer priority enum must be auto, verylow, low, normal, high, veryhigh",
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
    TransferPriority:
      type: string
      enum: [auto, verylow, low, normal, high, veryhigh]
    TransferPatch:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '^(?=.*\S)[^<>:"/\\|?*\x00-\x1F\x7F-\x9F]*$'
        priority:
          $ref: "#/components/schemas/TransferPriority"
        categoryName:
          type: string
          minLength: 1
          pattern: '\S'
    SharedFilePriority:
      type: string
      enum: [auto, verylow, low, normal, high, release]
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
    CategoryPriorityInput:
      oneOf:
        - type: string
          enum: [verylow, low, normal, high, veryhigh]
        - type: integer
          minimum: 0
          maximum: 4294967295
    ServerCreateRequest:
      type: object
      properties:
        address:
          type: string
          minLength: 1
          pattern: '\S'
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
      enum: [auto, verylow, low, normal, high, release]
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
      enum: [auto, verylow, low, normal, high, release]
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
      enum: [auto, verylow, low, normal, high, release]
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
      enum: [auto, verylow, low, normal, high, release]
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
      properties:
        address:
          type: string
          minLength: 1
        port:
          type: integer
          minimum: 1
          maximum: 65535
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
          type: string
        connect:
          type: string
    ServerPatch:
      type: object
      minProperties: 1
      properties:
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
        static:
          type: boolean
        enabled:
          type: boolean
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_category_text_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    CategoryCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
        path:
          type:
            - string
            - "null"
          minLength: 1
    CategoryPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
        path:
          type:
            - string
            - "null"
          minLength: 1
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="CategoryCreateRequest.properties.name",
            issue="trim-non-empty text pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="CategoryCreateRequest.properties.path",
            issue="trim-non-empty text pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="CategoryPatch.properties.name",
            issue="trim-non-empty text pattern must require at least one non-whitespace character",
        ),
        SchemaComponentDrift(
            component="CategoryPatch.properties.path",
            issue="trim-non-empty text pattern must require at least one non-whitespace character",
        ),
    )


def test_openapi_schema_component_drift_accepts_category_text_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    CategoryCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          pattern: '\S'
        path:
          type:
            - string
            - "null"
          minLength: 1
          pattern: '\S'
    CategoryPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '\S'
        path:
          type:
            - string
            - "null"
          minLength: 1
          pattern: '\S'
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


def test_openapi_schema_component_drift_requires_category_mutation_field_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    CategoryCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          pattern: '\S'
        path:
          type:
            - string
            - "null"
          minLength: 1
          pattern: '\S'
        color:
          type: integer
          minimum: 1
          maximum: 255
        priority:
          type: string
          enum: [normal]
    CategoryPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '\S'
        path:
          type:
            - string
            - "null"
          minLength: 1
          pattern: '\S'
        color:
          type: integer
          minimum: 1
          maximum: 255
        priority:
          type: string
          enum: [normal]
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="CategoryCreateRequest.properties.color",
            issue="category color range must be 0..16777215",
        ),
        SchemaComponentDrift(
            component="CategoryCreateRequest.properties.color",
            issue="category color type must be ['integer', 'null']",
        ),
        SchemaComponentDrift(
            component="CategoryCreateRequest.properties.priority",
            issue="category priority must reference #/components/schemas/CategoryPriorityInput",
        ),
        SchemaComponentDrift(
            component="CategoryPatch.properties.color",
            issue="category color range must be 0..16777215",
        ),
        SchemaComponentDrift(
            component="CategoryPatch.properties.color",
            issue="category color type must be ['integer', 'null']",
        ),
        SchemaComponentDrift(
            component="CategoryPatch.properties.priority",
            issue="category priority must reference #/components/schemas/CategoryPriorityInput",
        ),
    )


def test_openapi_schema_component_drift_accepts_category_mutation_field_constraints(
    tmp_path: Path,
) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        r"""
components:
  schemas:
    CategoryCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          pattern: '\S'
        path:
          type:
            - string
            - "null"
          minLength: 1
          pattern: '\S'
        color:
          type:
            - integer
            - "null"
          minimum: 0
          maximum: 16777215
        priority:
          $ref: "#/components/schemas/CategoryPriorityInput"
    CategoryPatch:
      type: object
      minProperties: 1
      properties:
        name:
          type: string
          minLength: 1
          pattern: '\S'
        path:
          type:
            - string
            - "null"
          minLength: 1
          pattern: '\S'
        color:
          type:
            - integer
            - "null"
          minimum: 0
          maximum: 16777215
        priority:
          $ref: "#/components/schemas/CategoryPriorityInput"
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == ()


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


def test_openapi_schema_component_drift_requires_transfer_event_variants(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  responses:
    EventStreamResponse:
      description: Event stream.
  schemas:
    TransferEvent:
      oneOf:
        - $ref: "#/components/schemas/TransferAddedEvent"
        - $ref: "#/components/schemas/WrongUpdatedEvent"
        - $ref: "#/components/schemas/TransferRemovedEvent"
        - $ref: "#/components/schemas/TransferSyncResetEvent"
      discriminator:
        propertyName: event
        mapping:
          transfer.added: "#/components/schemas/TransferAddedEvent"
    TransferAddedEvent:
      type: object
      additionalProperties: true
      required: [id, type]
      properties:
        type:
          type: string
          enum: [transfer.added, transfer.updated]
    TransferUpdatedEvent:
      type: object
      additionalProperties: false
      required: [id, type, transfer]
      properties:
        type:
          type: string
          enum: [transfer.updated]
    TransferRemovedEvent:
      type: object
      additionalProperties: false
      required: [id, type, hash]
      properties:
        type:
          type: string
          enum: [transfer.removed]
    TransferSyncResetEvent:
      type: object
      additionalProperties: false
      required: [id, type]
      properties:
        type:
          type: string
          enum: [sync.reset]
""",
    )

    assert openapi_schema_component_drift(openapi_yaml) == (
        SchemaComponentDrift(
            component="TransferAddedEvent",
            issue="required fields must be ['id', 'transfer', 'type']",
        ),
        SchemaComponentDrift(
            component="TransferAddedEvent",
            issue="transfer event variant must set additionalProperties: false",
        ),
        SchemaComponentDrift(
            component="TransferAddedEvent",
            issue="type enum must be [transfer.added]",
        ),
        SchemaComponentDrift(
            component="TransferEvent",
            issue="discriminator mapping must cover every transfer event variant",
        ),
        SchemaComponentDrift(
            component="TransferEvent",
            issue="discriminator propertyName must be type",
        ),
        SchemaComponentDrift(
            component="TransferEvent",
            issue="must oneOf the transfer event variant schemas in event-name order",
        ),
        SchemaComponentDrift(
            component="TransferSyncResetEvent",
            issue="required fields must be ['id', 'reason', 'type']",
        ),
    )


def test_openapi_schema_component_drift_accepts_transfer_event_variants(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
components:
  responses:
    EventStreamResponse:
      description: Event stream.
  schemas:
    TransferEvent:
      oneOf:
        - $ref: "#/components/schemas/TransferAddedEvent"
        - $ref: "#/components/schemas/TransferUpdatedEvent"
        - $ref: "#/components/schemas/TransferRemovedEvent"
        - $ref: "#/components/schemas/TransferSyncResetEvent"
      discriminator:
        propertyName: type
        mapping:
          transfer.added: "#/components/schemas/TransferAddedEvent"
          transfer.updated: "#/components/schemas/TransferUpdatedEvent"
          transfer.removed: "#/components/schemas/TransferRemovedEvent"
          sync.reset: "#/components/schemas/TransferSyncResetEvent"
    TransferAddedEvent:
      type: object
      additionalProperties: false
      required: [id, type, transfer]
      properties:
        type:
          type: string
          enum: [transfer.added]
    TransferUpdatedEvent:
      type: object
      additionalProperties: false
      required: [id, type, transfer]
      properties:
        type:
          type: string
          enum: [transfer.updated]
    TransferRemovedEvent:
      type: object
      additionalProperties: false
      required: [id, type, hash]
      properties:
        type:
          type: string
          enum: [transfer.removed]
    TransferSyncResetEvent:
      type: object
      additionalProperties: false
      required: [id, type, reason]
      properties:
        type:
          type: string
          enum: [sync.reset]
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
  /transfers:
    get:
      parameters:
        - $ref: "#/components/parameters/Limit"
        - name: state
          in: query
        - name: hash
          in: path
      responses: {}
components:
  parameters:
    Limit:
      name: limit
      in: query
""",
    )

    assert openapi_query_parameter_inventory(openapi_yaml) == {
        Route("GET", "/transfers"): ("limit", "state"),
    }


def test_openapi_path_parameter_drift_requires_template_parameter_docs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /transfers/{hash}/sources/{clientId}:
    parameters:
      - $ref: "#/components/parameters/FileHash"
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
    FileHash:
      name: hash
      in: path
      required: true
""",
    )

    assert set(openapi_path_parameter_drift(openapi_yaml)) == {
        PathParameterDrift(
            method="GET",
            path="/transfers/{hash}/sources/{clientId}",
            template_parameters=("clientId", "hash"),
            documented_path_parameters=("clientId", "extra", "hash"),
            issue="path template parameters must match documented path parameters",
        ),
        PathParameterDrift(
            method="GET",
            path="/transfers/{hash}/sources/{clientId}",
            template_parameters=("clientId", "hash"),
            documented_path_parameters=("clientId", "extra", "hash"),
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
            .route("/api/v1/searches/{searchId}", get(search))
            .route("/api/v1/transfers/{hash}/files", delete(transfer_delete_files));
        ''',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        '''
        fn route_query_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const NONE: &[&str] = &[];
            const SNAPSHOT: &[&str] = &["limit"];
            const CONFIRM: &[&str] = &["confirm"];
            const SEARCH: &[&str] = &["offset", "limit", "includeEvidence", "exactTotal"];
            const UPLOAD_QUEUE: &[&str] = &["offset", "limit", "includeScoreBreakdown"];
            match (method, path) {
                ("GET", "/api/v1/app")
                | ("GET", "/api/v1/upload-queue") => Some(match path {
                    "/api/v1/upload-queue" if method == "GET" => UPLOAD_QUEUE,
                    _ => NONE,
                }),
                ("GET", "/api/v1/snapshot") => Some(SNAPSHOT),
                _ => route_query_fields_for_parameterized(method, path),
            }
        }

        fn route_query_fields_for_parameterized(
            method: &str,
            path: &str,
        ) -> Option<&'static [&'static str]> {
            const NONE: &[&str] = &[];
            const CONFIRM: &[&str] = &["confirm"];
            const SEARCH: &[&str] = &["offset", "limit", "includeEvidence", "exactTotal"];
            let segments = path.strip_prefix("/api/v1/")?.split('/').collect::<Vec<_>>();
            match (method, segments.as_slice()) {
                ("GET", ["searches", _]) => Some(SEARCH),
                ("DELETE", ["transfers", _, "files"]) => Some(CONFIRM),
                _ => Some(NONE),
            }
        }
        ''',
    )

    assert rust_query_parameter_inventory(route_metadata_rs, routes_rs) == {
        Route("GET", "/app"): (),
        Route("GET", "/snapshot"): ("limit",),
        Route("GET", "/upload-queue"): ("includeScoreBreakdown", "limit", "offset"),
        Route("GET", "/searches/{searchId}"): ("exactTotal", "includeEvidence", "limit", "offset"),
        Route("DELETE", "/transfers/{hash}/files"): ("confirm",),
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
  /transfers:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/TransferCreateRequest"
      responses: {}
components:
  schemas:
    TransferCreateRequest:
      type: object
      properties:
        link: { type: string }
        links: { type: array }
        paused: { type: boolean }
""",
    )

    assert openapi_body_field_inventory(openapi_yaml) == {
        Route("POST", "/transfers"): ("link", "links", "paused"),
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
              $ref: "#/components/schemas/TransferCreateRequest"
      responses: {}
  /extra-media:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/TransferCreateRequest"
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
    TransferCreateRequest:
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


def test_openapi_success_response_drift_requires_single_shared_schema_response(tmp_path: Path) -> None:
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
        "202":
          $ref: "#/components/responses/AcceptedResponse"
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
            path="/multiple",
            status="200,202",
            issue="must document exactly one 2xx response",
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
            issue="must reference ErrorResponse",
        ),
        ErrorResponseDrift(
            method="GET",
            path="/app",
            status="500",
            issue="documented non-success responses must reference ErrorResponse",
        ),
    )


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

    assert drift_by_source[str(responses_rs)] == "CONTRACT_VERSION must be 1.2.0, got 1.1.0"
    assert drift_by_source["info.version"] == "must be 1.2.0, got '1.1.0'"
    assert drift_by_source["info.x-contract-version"] == "must be 1.2.0, got '1.0.0'"
    assert (
        drift_by_source["components.headers.ContractVersionHeader.schema.const"]
        == "must be 1.2.0, got '1.1.0'"
    )
    assert (
        drift_by_source["components.headers.ContractVersionHeader.schema.example"]
        == "must be 1.2.0, got '1.1.0'"
    )
    assert (
        drift_by_source["components.schemas.CapabilityDiscovery.properties.contractVersion.const"]
        == "must be 1.2.0, got None"
    )
    assert (
        drift_by_source["components.schemas.CapabilityDiscovery.properties.contractVersion.example"]
        == "must be 1.2.0, got '1.0.0'"
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
        'pub(crate) const CONTRACT_VERSION: &str = "1.2.0";',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
info:
  version: 1.2.0
  x-contract-version: "1.2.0"
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
        const: "1.2.0"
        example: "1.2.0"
  schemas:
    CapabilityDiscovery:
      type: object
      properties:
        contractVersion:
          type: string
          const: "1.2.0"
          example: "1.2.0"
""",
    )

    assert rust_contract_version(responses_rs) == "1.2.0"
    assert openapi_contract_version_drift(openapi_yaml, responses_rs) == ()


def test_rust_body_field_inventory_reads_exact_and_parameterized_allowlists(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        '''
        Router::new()
            .route("/api/v1/app", get(app))
            .route("/api/v1/transfers", post(create_transfer))
            .route("/api/v1/transfers/{hash}", patch(update_transfer))
            .route("/api/v1/servers/operations/import-met-url", post(import_servers))
            .route("/api/v1/searches/{searchId}/results/{hash}/operations/download", post(download));
        ''',
    )
    route_body_metadata_rs = write(
        tmp_path / "route_body_metadata.rs",
        '''
        fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const TRANSFER_ADD: &[&str] = &["link", "links", "categoryId", "categoryName", "paused"];
            const TRANSFER_PATCH: &[&str] = &["name", "priority", "categoryId", "categoryName"];
            const SEARCH_RESULT_DOWNLOAD: &[&str] = &["categoryId", "categoryName", "paused"];
            const URL_IMPORT: &[&str] = &["url"];
            if method == "POST" && path == "/api/v1/transfers" {
                return Some(TRANSFER_ADD);
            }
            if uses_url_import_body(method, path) {
                return Some(URL_IMPORT);
            }
            let segments = api_segments(path)?;
            match (method, segments.as_slice()) {
                ("PATCH", ["transfers", _]) => Some(TRANSFER_PATCH),
                ("POST", ["searches", _, "results", _, "operations", "download"]) => {
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

    assert rust_body_field_inventory(route_body_metadata_rs, routes_rs) == {
        Route("GET", "/app"): (),
        Route("POST", "/transfers"): ("categoryId", "categoryName", "link", "links", "paused"),
        Route("PATCH", "/transfers/{hash}"): ("categoryId", "categoryName", "name", "priority"),
        Route("POST", "/servers/operations/import-met-url"): ("url",),
        Route("POST", "/searches/{searchId}/results/{hash}/operations/download"): (
            "categoryId",
            "categoryName",
            "paused",
        ),
    }


def test_compare_route_contract_reports_body_field_drift(tmp_path: Path) -> None:
    routes_rs = write(
        tmp_path / "routes.rs",
        'Router::new().route("/api/v1/transfers", post(create_transfer));',
    )
    route_metadata_rs = write(
        tmp_path / "route_metadata.rs",
        'fn route_query_fields(method: &str, path: &str) -> Option<&static [&static str]> { None }',
    )
    route_body_metadata_rs = write(
        tmp_path / "route_body_metadata.rs",
        '''
        fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
            const TRANSFER_ADD: &[&str] = &["link"];
            if method == "POST" && path == "/api/v1/transfers" {
                return Some(TRANSFER_ADD);
            }
            None
        }
        ''',
    )
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
paths:
  /transfers:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                link: { type: string }
                paused: { type: boolean }
      responses: {}
""",
    )

    report = compare_route_contract(routes_rs, route_metadata_rs, route_body_metadata_rs, openapi_yaml)

    assert report.body_field_drift == (
        BodyFieldDrift(
            route=Route("POST", "/transfers"),
            rust_body_fields=("link",),
            openapi_body_fields=("link", "paused"),
        ),
    )
