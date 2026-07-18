from __future__ import annotations

from pathlib import Path

from emule_test_harness.rust_openapi_routes import (
    AuthDrift,
    BodyFieldDrift,
    ComponentRefDrift,
    ErrorResponseDrift,
    MethodNotAllowedDrift,
    OperationMetadataDrift,
    ParameterMetadataDrift,
    PathParameterDrift,
    QueryParameterDrift,
    Route,
    RequestBodyMetadataDrift,
    ResponseComponentDrift,
    ResponseHeaderDrift,
    SchemaComponentDrift,
    SuccessResponseDrift,
    TagTaxonomyDrift,
    compare_route_contract,
    openapi_contract_version_drift,
    compare_route_inventory,
    openapi_auth_drift,
    openapi_body_field_inventory,
    openapi_component_ref_drift,
    openapi_error_response_drift,
    openapi_method_not_allowed_drift,
    openapi_operation_metadata_drift,
    openapi_parameter_metadata_drift,
    openapi_path_parameter_drift,
    openapi_query_parameter_inventory,
    openapi_request_body_metadata_drift,
    openapi_response_component_drift,
    openapi_response_header_drift,
    openapi_route_inventory,
    openapi_schema_component_drift,
    openapi_success_response_drift,
    openapi_tag_taxonomy_drift,
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
components:
  schemas:
    TransferCreateRequest:
      type: object
    SearchResultDownloadRequest:
      type: object
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
            path="/extra-media",
            issue="requestBody content must contain only application/json",
        ),
        RequestBodyMetadataDrift(
            method="POST",
            path="/missing-required",
            issue="requestBody.required must be explicit true or false",
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
