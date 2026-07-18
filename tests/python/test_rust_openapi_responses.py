from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest

from emule_test_harness.rust_openapi_responses import (
    get_openapi_operation_response_schema,
    get_openapi_response_schema,
    load_openapi_document,
    validate_openapi_operation_response_payload,
    validate_openapi_response_payload,
)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


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
