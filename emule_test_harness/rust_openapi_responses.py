"""OpenAPI response-schema helpers for emulebb-rust REST contract checks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from emule_test_harness.paths import get_emule_workspace_root

REPO_ROOT = Path(__file__).resolve().parents[1]
OPENAPI_CONTRACT_PATH = Path(
    os.environ.get(
        "EMULEBB_REST_OPENAPI_CONTRACT_PATH",
        str(get_emule_workspace_root(REPO_ROOT) / "repos" / "emulebb-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"),
    )
)
JSON_MEDIA_TYPE = "application/json"


def load_openapi_document(openapi_path: Path = OPENAPI_CONTRACT_PATH) -> dict[str, Any]:
    """Loads the OpenAPI document with the harness-pinned YAML parser."""

    document = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError(f"OpenAPI document is not an object: {openapi_path}")
    return document


def get_openapi_response_schema(response_name: str, openapi_path: Path = OPENAPI_CONTRACT_PATH) -> dict[str, Any]:
    """Returns the JSON schema for one named OpenAPI response component."""

    document = load_openapi_document(openapi_path)
    response = openapi_component_response(document, response_name)
    return response_json_schema(response, f"response component {response_name}")


def get_openapi_operation_response_schema(
    method: str,
    path: str,
    status: int | str,
    openapi_path: Path = OPENAPI_CONTRACT_PATH,
) -> dict[str, Any]:
    """Returns the JSON schema for one operation/status response."""

    document = load_openapi_document(openapi_path)
    response = openapi_operation_response(document, method, path, status)
    return response_json_schema(response, f"{method.upper()} {path} {status}")


def validate_openapi_response_payload(
    response_name: str,
    payload: object,
    openapi_path: Path = OPENAPI_CONTRACT_PATH,
) -> None:
    """Validates one REST response payload against its OpenAPI response schema."""

    document = load_openapi_document(openapi_path)
    schema = response_json_schema(openapi_component_response(document, response_name), f"response component {response_name}")
    validate_openapi_schema(document, schema, payload)


def validate_openapi_operation_response_payload(
    method: str,
    path: str,
    status: int | str,
    payload: object,
    openapi_path: Path = OPENAPI_CONTRACT_PATH,
) -> None:
    """Validates one REST response payload against its operation/status OpenAPI schema."""

    document = load_openapi_document(openapi_path)
    response = openapi_operation_response(document, method, path, status)
    schema = response_json_schema(response, f"{method.upper()} {path} {status}")
    validate_openapi_schema(document, schema, payload)


def openapi_component_response(document: dict[str, Any], response_name: str) -> dict[str, Any]:
    response = (((document.get("components") or {}).get("responses") or {}).get(response_name) or {})
    if not isinstance(response, dict):
        raise RuntimeError(f"OpenAPI response component is not an object: {response_name}")
    if not response:
        raise RuntimeError(f"OpenAPI response component is missing: {response_name}")
    return response


def openapi_operation_response(
    document: dict[str, Any],
    method: str,
    path: str,
    status: int | str,
) -> dict[str, Any]:
    operation = (((document.get("paths") or {}).get(path) or {}).get(method.lower()) or {})
    if not isinstance(operation, dict) or not operation:
        raise RuntimeError(f"OpenAPI operation is missing: {method.upper()} {path}")

    responses = operation.get("responses") or {}
    if not isinstance(responses, dict):
        raise RuntimeError(f"OpenAPI operation responses are not an object: {method.upper()} {path}")

    response = responses.get(str(status))
    if response is None:
        raise RuntimeError(f"OpenAPI operation response is missing: {method.upper()} {path} {status}")
    if not isinstance(response, dict):
        raise RuntimeError(f"OpenAPI operation response is not an object: {method.upper()} {path} {status}")
    return resolve_response_ref(document, response, f"{method.upper()} {path} {status}")


def resolve_response_ref(document: dict[str, Any], response: dict[str, Any], label: str) -> dict[str, Any]:
    reference = response.get("$ref")
    if not isinstance(reference, str):
        return response
    prefix = "#/components/responses/"
    if not reference.startswith(prefix):
        raise RuntimeError(f"OpenAPI response uses unsupported ref {reference!r}: {label}")
    return openapi_component_response(document, reference.removeprefix(prefix))


def response_json_schema(response: dict[str, Any], label: str) -> dict[str, Any]:
    content = response.get("content") if isinstance(response, dict) else None
    media_type = (content or {}).get(JSON_MEDIA_TYPE) if isinstance(content, dict) else None
    schema = (media_type or {}).get("schema") if isinstance(media_type, dict) else None
    if not isinstance(schema, dict):
        raise RuntimeError(f"OpenAPI response does not define an {JSON_MEDIA_TYPE} schema: {label}")
    return schema


def validate_openapi_schema(document: dict[str, Any], schema: dict[str, Any], payload: object) -> None:
    validator = jsonschema.Draft202012Validator(document).evolve(schema=schema)
    validator.validate(payload)
