from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest

from emule_test_harness.rust_openapi_responses import (
    get_openapi_operation_response_schema,
    get_openapi_response_schema,
    load_openapi_document,
    validate_openapi_schema_component_payload,
    validate_openapi_operation_response_payload,
    validate_openapi_response_payload,
)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("component,field,nullable", [
    ("EnvelopeMeta", "generatedAt", False), ("DiagnosticBundle", "capturedAt", False),
    ("Server", "hostNameResolvedAt", True), ("KadNode", "hostNameResolvedAt", True),
    ("KadNode", "createdAt", False), ("KadNode", "lastSeen", False),
    ("LogEntry", "timestamp", False),
    ("ProcessResources", "sampledAt", True),
    ("SharedFilePublishLane", "lastSuccessAt", True),
    ("SharedFileKadKeywordPublish", "lastSuccessAt", True),
    ("Ed2kPublishDiagnostics", "lastAttemptAt", True),
    ("Ed2kPublishDiagnostics", "lastSuccessAt", True),
    ("Ed2kPublishDiagnostics", "updatedAt", True),
    ("KadPublishDiagnostics", "updatedAt", True),
])
@pytest.mark.parametrize("value", [None, 0, 1_800_000_000, -1, 1.5, True])
def test_native_calendar_fields_use_nullable_or_required_integer_seconds(component, field, nullable, value):
    from emule_test_harness.rust_openapi_responses import validate_openapi_schema
    document = load_openapi_document()
    schema = document["components"]["schemas"][component]["properties"][field]
    valid = value is None and nullable or type(value) is int and value >= 0
    if valid:
        validate_openapi_schema(document, schema, value)
    else:
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, schema, value)


@pytest.mark.parametrize("value,valid", [(None, True), (0, True), (1_800_000_000, True), (-1, False), (1.5, False), (True, False)])
def test_friend_calendar_time_is_nullable_nonnegative_integer_seconds(value, valid):
    payload = {"userHash": "11" * 16, "lastSeen": value}
    if valid:
        validate_openapi_schema_component_payload("Friend", payload)
    else:
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema_component_payload("Friend", payload)


@pytest.mark.parametrize("mode,limit,valid", [
    ("automatic", None, True), ("fixed", 16, True),
    ("automatic", 16, False), ("fixed", None, False), ("fixed", 0, False),
])
def test_download_resource_summary_enforces_concurrency_mode_and_limit(mode, limit, valid):
    payload = {
        "active": 17, "preparing": 2, "waiting": 981,
        "concurrency": {"mode": mode, "configuredLimit": limit, "target": 16, "burstActive": 1},
        "residentMemory": {"usedBytes": 33554432, "softTargetBytes": 67108864, "limitBytes": 134217728},
    }
    if valid:
        validate_openapi_schema_component_payload("DownloadResources", payload)
    else:
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema_component_payload("DownloadResources", payload)


def test_download_resources_are_required_in_stats_and_counts_are_nonnegative():
    schemas = load_openapi_document()["components"]["schemas"]
    assert "downloadResources" in schemas["Stats"]["required"]
    for component, fields in {
        "DownloadResources": ("active", "preparing", "waiting"),
        "DownloadConcurrency": ("target", "burstActive"),
        "DownloadResidentMemory": ("usedBytes", "softTargetBytes", "limitBytes"),
    }.items():
        for field in fields:
            assert schemas[component]["properties"][field]["minimum"] == 0


@pytest.mark.parametrize("component", ["DownloadSummary", "Download"])
def test_download_waiting_reason_is_closed_and_matches_lifecycle(component):
    from emule_test_harness.rust_openapi_responses import validate_openapi_schema
    document = load_openapi_document()
    schema = document["components"]["schemas"][component]
    payload = {"id": "1", "hash": "11" * 16, "name": "Sample.bin", "category": None,
               "sizeBytes": 16, "progress": 0, "intent": "started", "state": "queued",
               "waitingReason": "sources", "createdAt": 1, "updatedAt": 1, "completedAt": None}
    if component == "Download":
        payload.update(payloadVerified=False, delivery=None, failure=None)
    for reason in ("network", "sources", "resources"):
        payload["waitingReason"] = reason
        validate_openapi_schema(document, schema, payload)
    for reason in (None, "unknown"):
        payload["waitingReason"] = reason
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, schema, payload)
    for state in document["components"]["schemas"]["DownloadState"]["enum"]:
        if state == "queued":
            continue
        payload.update(state=state, waitingReason=None)
        validate_openapi_schema(document, schema, payload)
        payload["waitingReason"] = "resources"
        with pytest.raises(jsonschema.ValidationError):
            validate_openapi_schema(document, schema, payload)
    del payload["waitingReason"]
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema(document, schema, payload)


@pytest.mark.parametrize("method,path,status,code,details", [
    ("GET", "/uploads", 409, "CONFLICT", {}),
    ("GET", "/upload-queue", 409, "CONFLICT", {}),
    ("POST", "/library/roots", 409, "ROOT_CONFLICT", {}),
    ("DELETE", "/library/roots/{id}", 409, "ROOT_MANAGED", {}),
    ("GET", "/shared-files", 500, "INTERNAL_ERROR", {}),
    ("GET", "/library/ignores", 500, "INTERNAL_ERROR", {}),
    ("POST", "/diagnostics/bundles", 503, "SERVICE_BUSY", {}),
    *[("POST", "/downloads", 409, "LOCAL_CONTENT_CHOICE_REQUIRED", {"availability": value})
      for value in ("present", "unavailable", "absent")],
])
def test_current_operation_errors_match_the_closed_schema(method, path, status, code, details):
    validate_openapi_operation_response_payload(method, path, status,
        {"error": {"code": code, "message": "Current operation outcome", "details": details}})


@pytest.mark.parametrize("details", [{}, {"availability": None}, {"availability": "unknown"}, {"availability": 1}])
def test_local_content_choice_requires_typed_availability(details):
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_operation_response_payload("POST", "/downloads", 409,
            {"error": {"code": "LOCAL_CONTENT_CHOICE_REQUIRED", "message": "Explicit choice required", "details": details}})


def test_response_component_schema_resolves_validation_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
openapi: 3.1.0
components:
  responses:
    AppResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/AppEnvelope"
  schemas:
    AppEnvelope:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          type: object
          additionalProperties: false
          required: [name]
          properties:
            name: { type: string }
""",
    )

    assert get_openapi_response_schema("AppResponse", openapi_yaml) == {"$ref": "#/components/schemas/AppEnvelope"}
    validate_openapi_response_payload("AppResponse", {"data": {"name": "emulebb-rust"}}, openapi_yaml)
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_response_payload("AppResponse", {"data": {"name": "emulebb-rust", "extra": 1}}, openapi_yaml)


def test_operation_response_schema_resolves_response_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
openapi: 3.1.0
paths:
  /app:
    get:
      responses:
        "200":
          $ref: "#/components/responses/AppResponse"
components:
  responses:
    AppResponse:
      content:
        application/json:
          schema:
            type: object
            additionalProperties: false
            required: [data]
            properties:
              data:
                type: object
                additionalProperties: false
                required: [name]
                properties:
                  name: { type: string }
""",
    )

    schema = get_openapi_operation_response_schema("GET", "/app", 200, openapi_yaml)

    assert schema["required"] == ["data"]
    validate_openapi_operation_response_payload("GET", "/app", 200, {"data": {"name": "emulebb-rust"}}, openapi_yaml)
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_operation_response_payload("GET", "/app", 200, {"data": {}}, openapi_yaml)


def test_schema_component_payload_validation_resolves_component_refs(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
openapi: 3.1.0
components:
  schemas:
    DownloadEvent:
      oneOf:
        - $ref: "#/components/schemas/DownloadSyncResetEvent"
    DownloadSyncResetEvent:
      type: object
      additionalProperties: false
      required: [id, epoch, type, reason]
      properties:
        id: { type: integer, minimum: 0 }
        epoch: { type: string, format: uuid }
        type:
          type: string
          enum: [sync.reset]
        reason:
          type: string
          enum: [reconnect]
""",
    )

    validate_openapi_schema_component_payload(
        "DownloadEvent",
        {"id": 1, "epoch": "00000000-0000-4000-8000-000000000001", "type": "sync.reset", "reason": "reconnect"},
        openapi_yaml,
    )
    with pytest.raises(jsonschema.ValidationError):
        validate_openapi_schema_component_payload(
            "DownloadEvent",
            {"id": 1, "epoch": "00000000-0000-4000-8000-000000000001", "type": "sync.reset"},
            openapi_yaml,
        )


def test_operation_response_schema_reports_missing_contract_entries(tmp_path: Path) -> None:
    openapi_yaml = write(
        tmp_path / "REST-API-OPENAPI.yaml",
        """
openapi: 3.1.0
paths:
  /app:
    get:
      responses: {}
""",
    )
    document = load_openapi_document(openapi_yaml)

    assert document["openapi"] == "3.1.0"
    with pytest.raises(RuntimeError, match="OpenAPI operation response is missing: GET /app 200"):
        get_openapi_operation_response_schema("GET", "/app", 200, openapi_yaml)


@pytest.mark.parametrize("payload", [None, {}, "", []])
def test_operation_no_content_response_requires_absent_payload(tmp_path: Path, payload) -> None:
    contract = write(tmp_path / "contract.yaml", """
openapi: 3.1.0
paths:
  /item:
    delete:
      responses:
        "204":
          $ref: "#/components/responses/NoContent"
components:
  responses:
    NoContent:
      description: Deleted
""")
    if payload is None:
        validate_openapi_operation_response_payload("DELETE", "/item", 204, payload, contract)
    else:
        with pytest.raises(RuntimeError, match="no body"):
            validate_openapi_operation_response_payload("DELETE", "/item", 204, payload, contract)
    contract.write_text(contract.read_text(encoding="utf-8").replace("description: Deleted", "content: {application/json: {schema: {type: object}}}"), encoding="utf-8")
    with pytest.raises(RuntimeError, match="no body"):
        validate_openapi_operation_response_payload("DELETE", "/item", 204, None, contract)


@pytest.mark.parametrize("drift", [None, "constraint", "missing", "extra"])
def test_settings_surface_requires_exact_declaration_generated_components(drift) -> None:
    from copy import deepcopy
    from emule_test_harness.rust_openapi_responses import validate_openapi_schema

    generated = {"SettingsValues": {"type": "integer", "minimum": 1}}
    document = {"components": {"schemas": {
        **deepcopy(generated),
        "SettingsSurface": {"properties": {"schemas": {"required": list(generated)}}},
        "SettingsSurfaceEnvelope": {"type": "object", "required": ["data"]},
    }}}
    payload = {"data": {"schemas": deepcopy(generated)}}
    if drift == "constraint":
        payload["data"]["schemas"]["SettingsValues"]["minimum"] = 2
    elif drift == "missing":
        payload["data"]["schemas"].clear()
    elif drift == "extra":
        payload["data"]["schemas"]["Other"] = {"type": "string"}
    schema = {"$ref": "#/components/schemas/SettingsSurfaceEnvelope"}
    if drift is None:
        validate_openapi_schema(document, schema, payload)
    else:
        with pytest.raises(jsonschema.ValidationError, match="Settings surface schema"):
            validate_openapi_schema(document, schema, payload)
