"""Runs a live Prowlarr check against the eMuleBB Torznab bridge."""

from __future__ import annotations

import argparse
import importlib.util
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_env

TORZNAB_MOVIE_CATEGORY = 2000
TORZNAB_TV_CATEGORY = 5000
TORZNAB_DOCUMENT_CATEGORY = 7000
TORZNAB_LIVE_CATEGORY = TORZNAB_DOCUMENT_CATEGORY
PROWLARR_GRAB_CATEGORY = "prowlarr_grabs_cat"
PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS = ("download_client", "search_results", "download_client_grab")
PROWLARR_DOWNLOAD_CLIENT_CLEANUP_KEY = "cleanup_download_clients"
TORZNAB_DIRECT_REQUEST_TIMEOUT_SECONDS = 70.0
DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS = 60.0
DEFAULT_SEARCH_TIMEOUT_SECONDS = 90.0
DEFAULT_DOCUMENT_DOWNLOAD_TIMEOUT_SECONDS = 300.0
PROWLARR_LIVE_SEARCH_TIMEOUT_SECONDS = DEFAULT_SEARCH_TIMEOUT_SECONDS

TORZNAB_DIRECT_ERROR_SCENARIOS: tuple[dict[str, object], ...] = (
    {
        "name": "malformed_percent_escape",
        "path": "/indexer/emulebb/api?t=search&q=bad%2xescape&apikey={api_key}",
        "expected_status": 400,
    },
    {
        "name": "malformed_path_escape",
        "path": "/indexer/emulebb/api%2x?t=search&q=linux&apikey={api_key}",
        "expected_status": 400,
    },
    {
        "name": "unsupported_method",
        "method": "POST",
        "path": "/indexer/emulebb/api?t=search&q=linux&apikey={api_key}",
        "expected_status": 404,
    },
    {
        "name": "duplicate_t_parameter",
        "path": "/indexer/emulebb/api?t=search&t=movie&q=linux&apikey={api_key}",
        "expected_status": 400,
    },
    {
        "name": "unicode_query_length_rejected",
        "path": "/indexer/emulebb/api?t=search&q={long_unicode_query}&apikey={api_key}",
        "expected_status": 400,
    },
)


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
rest_smoke = load_local_module("rest_api_smoke", "rest-api-smoke.py")
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
live_wire_inputs = rest_smoke.live_wire_inputs


def prowlarr_request(
    prowlarr_url: str,
    api_key: str,
    path: str,
    *,
    method: str = "GET",
    json_body: object | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Performs one Prowlarr API request without exposing credentials."""

    data = None
    headers = {"X-Api-Key": api_key}
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(
        prowlarr_url.rstrip("/") + path,
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body_text = response.read().decode("utf-8", errors="replace")
            payload = json.loads(body_text) if body_text else None
            return {"status": int(response.status), "json": payload, "body_text": body_text}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        payload = None
        if body_text:
            try:
                payload = json.loads(body_text)
            except json.JSONDecodeError:
                payload = None
        return {"status": int(exc.code), "json": payload, "body_text": body_text}


def require_success(result: dict[str, Any], description: str) -> Any:
    """Returns a JSON payload from a successful Prowlarr response."""

    status = int(result.get("status") or 0)
    if status < 200 or status >= 300:
        body = str(result.get("body_text") or "")
        raise RuntimeError(f"{description} failed with HTTP {status}: {body[:500]}")
    return result.get("json")


def is_no_results_validation_error(result: dict[str, Any]) -> bool:
    """Returns true when Prowlarr rejected a valid indexer only for no results."""

    status = int(result.get("status") or 0)
    if status < 400 or status >= 500:
        return False
    body_text = str(result.get("body_text") or "").lower()
    return "no results were returned from your indexer" in body_text


def should_force_save_indexer_validation(result: dict[str, Any]) -> bool:
    """Returns true when a live-validated indexer should be force-saved."""

    status = int(result.get("status") or 0)
    return is_no_results_validation_error(result) or (status >= 400 and status < 500)


def compact_body_preview(result: dict[str, Any], limit: int = 240) -> str:
    """Returns a compact response body preview without logging credentials."""

    body_text = str(result.get("body_text") or "")
    return " ".join(body_text.split())[:limit]


def get_generic_torznab_schema(prowlarr_url: str, api_key: str) -> dict[str, Any]:
    """Loads the Generic Torznab indexer schema from Prowlarr."""

    schemas = require_success(
        prowlarr_request(prowlarr_url, api_key, "/api/v1/indexer/schema"),
        "Prowlarr indexer schema lookup",
    )
    if not isinstance(schemas, list):
        raise RuntimeError("Prowlarr indexer schema response was not a list.")
    for schema in schemas:
        if isinstance(schema, dict) and schema.get("implementation") == "Torznab" and schema.get("name") == "Generic Torznab":
            return schema
    raise RuntimeError("Prowlarr did not expose the Generic Torznab indexer schema.")


def set_field_value(indexer: dict[str, Any], field_name: str, value: object) -> None:
    """Updates one Prowlarr indexer field by name."""

    fields = indexer.get("fields")
    if not isinstance(fields, list):
        raise RuntimeError("Prowlarr indexer payload does not contain a fields array.")
    for field in fields:
        if isinstance(field, dict) and field.get("name") == field_name:
            field["value"] = value
            return
    raise RuntimeError(f"Prowlarr indexer payload is missing field: {field_name}")


def set_optional_field_value(provider: dict[str, Any], field_name: str, value: object) -> bool:
    """Updates one provider field when the current Prowlarr schema exposes it."""

    fields = provider.get("fields")
    if not isinstance(fields, list):
        return False
    for field in fields:
        if isinstance(field, dict) and field.get("name") == field_name:
            field["value"] = value
            return True
    return False


def apply_disposable_local_certificate_policy(provider: dict[str, Any]) -> dict[str, object]:
    """Disables provider TLS validation only for schemas that expose the local-only policy."""

    return {
        "certificateValidation": set_optional_field_value(provider, "certificateValidation", 1),
    }


def public_provider_payload(provider: dict[str, Any]) -> dict[str, Any]:
    """Returns a provider payload without harness-only report metadata."""

    return {key: value for key, value in provider.items() if not str(key).startswith("_emulebb")}


def set_prowlarr_local_certificate_validation(
    prowlarr_url: str,
    api_key: str,
    policy: str = "disabledForLocalAddresses",
) -> dict[str, object]:
    """Sets Prowlarr host TLS validation policy for disposable local HTTPS endpoints."""

    current = require_success(
        prowlarr_request(prowlarr_url, api_key, "/api/v1/config/host"),
        "Prowlarr host config lookup",
    )
    if not isinstance(current, dict):
        raise RuntimeError("Prowlarr host config response was not an object.")
    previous = str(current.get("certificateValidation") or "")
    if previous == policy:
        return {"changed": False, "previous": previous, "current": previous}
    updated = json.loads(json.dumps(current))
    # WHY: Prowlarr 2.3 no longer exposes per-provider certificate validation
    # fields for Torznab/qBittorrent. The disposable controller is materialized
    # only for this live run, so relaxing local-address cert validation belongs
    # on that controller instance instead of mutating the Windows trust store.
    updated["certificateValidation"] = policy
    saved = require_success(
        prowlarr_request(prowlarr_url, api_key, "/api/v1/config/host", method="PUT", json_body=updated),
        "Prowlarr host config certificate validation update",
    )
    if not isinstance(saved, dict):
        raise RuntimeError("Prowlarr host config update response was not an object.")
    return {
        "changed": True,
        "previous": previous,
        "current": saved.get("certificateValidation"),
    }


def build_indexer_payload(
    base_payload: dict[str, Any],
    *,
    name: str,
    torznab_base_url: str,
    emule_api_key: str,
    tags: list[int] | None = None,
) -> dict[str, Any]:
    """Builds the persistent Generic Torznab indexer payload for eMuleBB."""

    payload = json.loads(json.dumps(base_payload))
    payload["name"] = name
    payload["enable"] = True
    payload["appProfileId"] = int(payload.get("appProfileId") or 1)
    payload["priority"] = int(payload.get("priority") or 25)
    payload["downloadClientId"] = int(payload.get("downloadClientId") or 0)
    payload["implementation"] = "Torznab"
    payload["implementationName"] = "Torznab"
    payload["configContract"] = "TorznabSettings"
    if tags is not None:
        payload["tags"] = tags
    set_field_value(payload, "baseUrl", torznab_base_url.rstrip("/"))
    set_field_value(payload, "apiPath", "/api")
    set_field_value(payload, "apiKey", emule_api_key)
    set_field_value(payload, "torrentBaseSettings.preferMagnetUrl", True)
    uses_https = torznab_base_url.lower().startswith("https://")
    payload["_emulebbCertificatePolicy"] = (
        apply_disposable_local_certificate_policy(payload)
        if uses_https
        else {"certificateValidation": False}
    )
    if uses_https and not any(payload["_emulebbCertificatePolicy"].values()):
        payload["_emulebbCertificatePolicy"]["prowlarrHostConfig"] = "disabledForLocalAddresses"
    return payload


def get_qbit_download_client_schema(prowlarr_url: str, api_key: str) -> dict[str, Any]:
    """Loads Prowlarr's qBittorrent download-client schema."""

    schemas = require_success(
        prowlarr_request(prowlarr_url, api_key, "/api/v1/downloadclient/schema"),
        "Prowlarr download client schema lookup",
    )
    if not isinstance(schemas, list):
        raise RuntimeError("Prowlarr download client schema response was not a list.")
    for schema in schemas:
        if isinstance(schema, dict) and schema.get("implementation") == "QBittorrent":
            return schema
    raise RuntimeError("Prowlarr did not expose the qBittorrent download client schema.")


def get_provider_field_names(provider: dict[str, Any]) -> set[str]:
    """Returns provider field names from one Prowlarr schema or saved provider."""

    fields = provider.get("fields")
    if not isinstance(fields, list):
        return set()
    return {
        str(field.get("name"))
        for field in fields
        if isinstance(field, dict) and isinstance(field.get("name"), str)
    }


def summarize_qbit_download_client_schema(schema: dict[str, Any]) -> dict[str, object]:
    """Builds a report-safe qBittorrent download-client schema summary."""

    field_names = get_provider_field_names(schema)
    required_fields = {"host", "port", "username", "password", "initialState", "category"}
    missing_fields = sorted(required_fields - field_names)
    return {
        "implementation": schema.get("implementation"),
        "implementationName": schema.get("implementationName"),
        "protocol": schema.get("protocol"),
        "configContract": schema.get("configContract"),
        "required_field_count": len(required_fields),
        "missing_required_fields": missing_fields,
        "ok": not missing_fields,
    }


def build_qbit_download_client_payload(
    base_payload: dict[str, Any],
    *,
    name: str,
    host: str,
    port: int,
    emule_api_key: str,
    category: str,
    use_ssl: bool = False,
) -> dict[str, Any]:
    """Builds the managed Prowlarr qBittorrent client payload for eMuleBB."""

    schema_summary = summarize_qbit_download_client_schema(base_payload)
    if not bool(schema_summary["ok"]):
        raise RuntimeError(f"Prowlarr qBittorrent schema is missing required fields: {schema_summary['missing_required_fields']!r}")

    payload = json.loads(json.dumps(base_payload))
    payload["name"] = name
    payload["enable"] = True
    payload["priority"] = int(payload.get("priority") or 1)
    payload["implementation"] = "QBittorrent"
    payload["implementationName"] = "qBittorrent"
    payload["configContract"] = "QBittorrentSettings"
    payload["protocol"] = "torrent"
    set_field_value(payload, "host", host)
    set_field_value(payload, "port", int(port))
    set_field_value(payload, "useSsl", bool(use_ssl))
    set_field_value(payload, "urlBase", "")
    set_field_value(payload, "username", "emule")
    set_field_value(payload, "password", emule_api_key)
    set_field_value(payload, "category", category)
    set_field_value(payload, "initialState", 2)
    payload["_emulebbCertificatePolicy"] = (
        apply_disposable_local_certificate_policy(payload)
        if use_ssl
        else {"certificateValidation": False}
    )
    if use_ssl and not any(payload["_emulebbCertificatePolicy"].values()):
        payload["_emulebbCertificatePolicy"]["prowlarrHostConfig"] = "disabledForLocalAddresses"
    return payload


def delete_download_client(prowlarr_url: str, api_key: str, client_id: int) -> dict[str, object]:
    """Deletes one Prowlarr download client by id."""

    result = prowlarr_request(prowlarr_url, api_key, f"/api/v1/downloadclient/{client_id}", method="DELETE")
    return {"id": client_id, "status": int(result.get("status") or 0)}


def test_qbit_download_client(prowlarr_url: str, api_key: str, client: dict[str, Any]) -> int:
    """Runs Prowlarr's download-client self-test and returns the HTTP status."""

    test_payload = public_provider_payload(json.loads(json.dumps(client)))
    test_result = prowlarr_request(
        prowlarr_url,
        api_key,
        "/api/v1/downloadclient/test",
        method="POST",
        json_body=test_payload,
        timeout_seconds=60.0,
    )
    require_success(test_result, "Prowlarr eMuleBB qBittorrent client test")
    return int(test_result.get("status") or 0)


def create_temp_qbit_download_client(
    prowlarr_url: str,
    api_key: str,
    *,
    name: str,
    host: str,
    port: int,
    emule_api_key: str,
    category: str,
    use_ssl: bool = False,
) -> dict[str, Any]:
    """Creates and validates a temporary Prowlarr qBittorrent client."""

    created_client_id: int | None = None
    schema = get_qbit_download_client_schema(prowlarr_url, api_key)
    schema_summary = summarize_qbit_download_client_schema(schema)
    payload = build_qbit_download_client_payload(
        schema,
        name=name,
        host=host,
        port=port,
        emule_api_key=emule_api_key,
        category=category,
        use_ssl=use_ssl,
    )
    try:
        saved = require_success(
            prowlarr_request(
                prowlarr_url,
                api_key,
                "/api/v1/downloadclient?forceSave=true",
                method="POST",
                json_body=public_provider_payload(payload),
            ),
            "Prowlarr eMuleBB qBittorrent client create",
        )
        if not isinstance(saved, dict) or not saved.get("id"):
            raise RuntimeError("Prowlarr did not return a created qBittorrent client id.")
        created_client_id = int(saved["id"])

        saved["_emulebbSchemaSummary"] = schema_summary
        saved["_emulebbCertificatePolicy"] = payload.get("_emulebbCertificatePolicy")
        saved["_emulebbTemporary"] = True
        saved["_emulebbTestStatus"] = test_qbit_download_client(prowlarr_url, api_key, saved)
        return saved
    except Exception as exc:
        if created_client_id is not None:
            try:
                delete_download_client(prowlarr_url, api_key, created_client_id)
            except Exception as cleanup_exc:
                if hasattr(exc, "add_note"):
                    exc.add_note(f"Temporary Prowlarr download client cleanup failed: {cleanup_exc}")
        raise


def summarize_qbit_download_client(client: dict[str, Any], *, category: str) -> dict[str, object]:
    """Builds a compact report for the temporary Prowlarr qBit client."""

    return {
        "id": int(client["id"]),
        "name": client.get("name"),
        "implementation": client.get("implementation"),
        "protocol": client.get("protocol"),
        "enable": bool(client.get("enable")),
        "category": category,
        "temporary": bool(client.get("_emulebbTemporary")),
        "schema": client.get("_emulebbSchemaSummary"),
        "test_status": client.get("_emulebbTestStatus"),
        "certificate_policy": client.get("_emulebbCertificatePolicy"),
    }


def get_existing_indexer(prowlarr_url: str, api_key: str, indexer_name: str) -> dict[str, Any] | None:
    """Finds the configured Prowlarr indexer by exact name."""

    indexers = require_success(
        prowlarr_request(prowlarr_url, api_key, "/api/v1/indexer"),
        "Prowlarr indexer list",
    )
    if not isinstance(indexers, list):
        raise RuntimeError("Prowlarr indexer list response was not a list.")
    for indexer in indexers:
        if isinstance(indexer, dict) and indexer.get("name") == indexer_name:
            return indexer
    return None


def get_indexer_by_id(prowlarr_url: str, api_key: str, indexer_id: int) -> dict[str, Any]:
    """Loads one saved Prowlarr indexer by id."""

    payload = require_success(
        prowlarr_request(prowlarr_url, api_key, f"/api/v1/indexer/{indexer_id}"),
        "Prowlarr saved indexer lookup",
    )
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError(f"Prowlarr did not return saved indexer id {indexer_id}.")
    return payload


def delete_indexer(prowlarr_url: str, api_key: str, indexer_id: int) -> dict[str, object]:
    """Deletes one Prowlarr indexer by id."""

    result = prowlarr_request(prowlarr_url, api_key, f"/api/v1/indexer/{indexer_id}", method="DELETE")
    return {"id": indexer_id, "status": int(result.get("status") or 0)}


def get_indexer_statuses(prowlarr_url: str, api_key: str) -> list[dict[str, Any]]:
    """Returns Prowlarr indexer status rows."""

    statuses = require_success(
        prowlarr_request(prowlarr_url, api_key, "/api/v1/indexerstatus"),
        "Prowlarr indexer status",
    )
    if not isinstance(statuses, list):
        raise RuntimeError("Prowlarr indexer status response was not a list.")
    return [status for status in statuses if isinstance(status, dict)]


def indexer_is_unavailable(statuses: list[dict[str, Any]], indexer_id: int) -> bool:
    """Returns true when Prowlarr has marked the indexer unavailable."""

    return indexer_unavailable_status(statuses, indexer_id) is not None


def indexer_unavailable_status(statuses: list[dict[str, Any]], indexer_id: int) -> dict[str, Any] | None:
    """Returns the Prowlarr unavailable-status row for one indexer."""

    for status in statuses:
        if int(status.get("indexerId") or 0) == int(indexer_id) and status.get("disabledTill"):
            return status
    return None


def wait_for_indexer_available(
    prowlarr_url: str,
    api_key: str,
    indexer_id: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until Prowlarr stops suppressing one indexer after recent failures."""

    attempts: list[dict[str, object]] = []
    started_at = time.monotonic()
    deadline = started_at + timeout_seconds
    while time.monotonic() < deadline:
        statuses = get_indexer_statuses(prowlarr_url, api_key)
        status = indexer_unavailable_status(statuses, indexer_id)
        if status is None:
            return {
                "status": "available",
                "indexer_id": indexer_id,
                "attempt_count": len(attempts) + 1,
                "waited_seconds": round(time.monotonic() - started_at, 3),
            }
        attempts.append(
            {
                "indexerId": status.get("indexerId"),
                "disabledTill": status.get("disabledTill"),
                "mostRecentFailure": status.get("mostRecentFailure"),
                "initialFailure": status.get("initialFailure"),
            }
        )
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5.0, remaining))
    raise RuntimeError(
        "Prowlarr indexer remained unavailable before timeout. "
        f"Indexer: {indexer_id}. Attempts: {attempts!r}"
    )


def upsert_indexer(
    prowlarr_url: str,
    api_key: str,
    *,
    indexer_name: str,
    torznab_base_url: str,
    emule_api_key: str,
    tags: list[int] | None = None,
) -> dict[str, Any]:
    """Creates or updates the persistent Prowlarr indexer and returns it."""

    existing = get_existing_indexer(prowlarr_url, api_key, indexer_name)
    unavailable_at_upsert = False
    if existing is not None and existing.get("id"):
        statuses = get_indexer_statuses(prowlarr_url, api_key)
        unavailable_at_upsert = indexer_is_unavailable(statuses, int(existing["id"]))
    base_payload = existing if existing is not None else get_generic_torznab_schema(prowlarr_url, api_key)
    payload = build_indexer_payload(
        base_payload,
        name=indexer_name,
        torznab_base_url=torznab_base_url,
        emule_api_key=emule_api_key,
        tags=tags,
    )
    forced_save = False
    if existing is not None and existing.get("id"):
        path = f"/api/v1/indexer/{int(existing['id'])}"
        forced_save = True
        result = prowlarr_request(
            prowlarr_url,
            api_key,
            path + "?forceSave=true",
            method="PUT",
            json_body=public_provider_payload(payload),
        )
    else:
        forced_save = True
        result = prowlarr_request(
            prowlarr_url,
            api_key,
            "/api/v1/indexer?forceSave=true",
            method="POST",
            json_body=public_provider_payload(payload),
        )
        if should_force_save_indexer_validation(result):
            disabled_payload = json.loads(json.dumps(payload))
            disabled_payload["enable"] = False
            create_result = prowlarr_request(
                prowlarr_url,
                api_key,
                "/api/v1/indexer?forceSave=true",
                method="POST",
                json_body=public_provider_payload(disabled_payload),
            )
            created = require_success(create_result, "Prowlarr disabled eMuleBB indexer create")
            if not isinstance(created, dict) or not created.get("id"):
                raise RuntimeError("Prowlarr did not return a created indexer id.")
            payload["id"] = int(created["id"])
            result = prowlarr_request(
                prowlarr_url,
                api_key,
                f"/api/v1/indexer/{int(created['id'])}?forceSave=true",
                method="PUT",
                json_body=public_provider_payload(payload),
            )
    saved = require_success(result, "Prowlarr eMuleBB indexer upsert")
    if not isinstance(saved, dict) or not saved.get("id"):
        if payload.get("id"):
            saved = get_indexer_by_id(prowlarr_url, api_key, int(payload["id"]))
        else:
            raise RuntimeError("Prowlarr did not return a saved indexer id.")
    saved["_emulebbCertificatePolicy"] = payload.get("_emulebbCertificatePolicy")
    saved["_emulebbForcedSave"] = forced_save
    saved["_emulebbRecreatedAfterUnavailable"] = False
    saved["_emulebbUnavailableAtUpsert"] = unavailable_at_upsert
    return saved


def test_indexer(prowlarr_url: str, api_key: str, indexer_payload: dict[str, Any]) -> dict[str, object]:
    """Runs Prowlarr's indexer test endpoint for the eMuleBB indexer."""

    result = prowlarr_request(
        prowlarr_url,
        api_key,
        "/api/v1/indexer/test",
        method="POST",
        json_body=public_provider_payload(indexer_payload),
        timeout_seconds=90.0,
    )
    if is_no_results_validation_error(result):
        return {
            "status": "no_results_validation",
            "http_status": int(result.get("status") or 0),
            "body_preview": compact_body_preview(result),
        }
    require_success(result, "Prowlarr eMuleBB indexer test")
    return {"status": "passed", "http_status": int(result.get("status") or 0)}


def check_direct_caps(base_url: str, emule_api_key: str) -> dict[str, object]:
    """Validates the direct eMuleBB Torznab caps endpoint."""

    path = "/indexer/emulebb/api?t=caps&apikey=" + urllib.parse.quote(emule_api_key)
    result = rest_smoke.http_request(base_url, path, request_timeout_seconds=20.0)
    if int(result.get("status") or 0) != 200:
        raise RuntimeError(f"Direct Torznab caps returned HTTP {result.get('status')}")
    body_text = str(result.get("body_text") or "")
    root = ET.fromstring(body_text)
    if root.tag != "caps":
        raise RuntimeError(f"Direct Torznab caps returned unexpected root: {root.tag}")
    return {"status": 200, "root": root.tag, "length": len(body_text)}


def build_direct_torznab_search_path(
    emule_api_key: str,
    query: str,
    category_id: int | None,
    *,
    extra_params: dict[str, object] | None = None,
) -> str:
    """Builds one direct eMuleBB Torznab search path."""

    params: dict[str, object] = {"t": "search"}
    if category_id is not None:
        params["cat"] = int(category_id)
    if extra_params:
        params.update(extra_params)
    params["q"] = query
    params["apikey"] = emule_api_key
    return "/indexer/emulebb/api?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def build_prowlarr_search_path(query: str, category_id: int, indexer_id: int) -> str:
    """Builds one Prowlarr search API path for a specific Torznab category."""

    encoded_query = urllib.parse.quote(query)
    return f"/api/v1/search?query={encoded_query}&categories={int(category_id)}&indexerIds={int(indexer_id)}"


def check_direct_rss_results(
    base_url: str,
    emule_api_key: str,
    queries: tuple[str, ...],
    *,
    category_id: int,
    source: str,
) -> dict[str, object]:
    """Validates direct Torznab RSS with explicit live-wire terms and category."""

    if not queries:
        raise RuntimeError("Direct Torznab RSS validation requires at least one query.")
    attempts: list[dict[str, object]] = []
    for query_index, query in enumerate(queries):
        path = build_direct_torznab_search_path(emule_api_key, query, category_id)
        result = rest_smoke.http_request(base_url, path, request_timeout_seconds=TORZNAB_DIRECT_REQUEST_TIMEOUT_SECONDS)
        status = int(result.get("status") or 0)
        body_text = str(result.get("body_text") or "")
        count = count_torznab_items(body_text) if status == 200 and body_text else 0
        attempt = {"query_index": query_index, "query_present": bool(query), "status": status, "count": count}
        attempts.append(attempt)
        if status == 200 and count > 0:
            return {
                "status": status,
                "count": count,
                "category": int(category_id),
                "source": source,
                "term_count": len(queries),
                "attempts": attempts,
            }
    raise RuntimeError(
        f"Direct Torznab RSS validation returned no {source} item(s) "
        f"for category {int(category_id)}. Attempts: {attempts!r}"
    )


def check_direct_auth_rejection(base_url: str) -> dict[str, object]:
    """Validates that the direct Torznab endpoint rejects unauthenticated calls."""

    result = rest_smoke.http_request(base_url, "/indexer/emulebb/api?t=caps", request_timeout_seconds=20.0)
    status = int(result.get("status") or 0)
    if status != 401:
        raise RuntimeError(f"Direct Torznab auth rejection returned HTTP {status}, expected 401.")
    return {"status": status}


def check_direct_unknown_query_tolerance(base_url: str, emule_api_key: str) -> dict[str, object]:
    """Validates that Torznab ignores unknown extension parameters."""

    path = (
        "/indexer/emulebb/api?t=caps&unknownProviderField=ignored&apikey="
        + urllib.parse.quote(emule_api_key)
    )
    result = rest_smoke.http_request(base_url, path, request_timeout_seconds=20.0)
    status = int(result.get("status") or 0)
    body_text = str(result.get("body_text") or "")
    if status != 200:
        raise RuntimeError(f"Direct Torznab unknown query tolerance returned HTTP {status}, expected 200.")
    root = ET.fromstring(body_text)
    if root.tag != "caps":
        raise RuntimeError(f"Direct Torznab unknown query tolerance returned unexpected root: {root.tag}")
    return {"status": status, "root": root.tag}


def check_direct_torznab_error_edges(base_url: str, emule_api_key: str) -> dict[str, object]:
    """Validates strict Torznab parser rejections used by Arr live-wire runs."""

    api_key = urllib.parse.quote(emule_api_key)
    long_query = urllib.parse.quote("unicode-lambda-" + ("λ" * 161))
    results = []
    for scenario in TORZNAB_DIRECT_ERROR_SCENARIOS:
        path = str(scenario["path"]).format(api_key=api_key, long_unicode_query=long_query)
        result = rest_smoke.http_request(
            base_url,
            path,
            method=str(scenario.get("method") or "GET"),
            request_timeout_seconds=20.0,
        )
        status = int(result.get("status") or 0)
        if status != scenario["expected_status"]:
            raise RuntimeError(
                f"Direct Torznab {scenario['name']} returned HTTP {status}, "
                f"expected {scenario['expected_status']}."
            )
        body_text = str(result.get("body_text") or "")
        root = ET.fromstring(body_text)
        if root.tag != "error":
            raise RuntimeError(f"Direct Torznab {scenario['name']} returned unexpected error root: {root.tag}")
        if root.attrib.get("code") != str(status):
            raise RuntimeError(
                f"Direct Torznab {scenario['name']} returned error code {root.attrib.get('code')!r}, "
                f"expected {status}."
            )
        results.append(
            {
                "name": scenario["name"],
                "status": status,
                "expected_status": scenario["expected_status"],
                "root": root.tag,
                "code": root.attrib.get("code"),
                "description_present": bool(root.attrib.get("description")),
            }
        )
    return {"ok": True, "scenarios": results}


def count_torznab_items(body_text: str) -> int:
    """Counts RSS items in a Torznab XML response."""

    root = ET.fromstring(body_text)
    if root.tag.lower() != "rss":
        raise RuntimeError(f"Direct Torznab search returned unexpected root: {root.tag}")
    channel = root.find("channel")
    if channel is None:
        return 0
    return len(channel.findall("item"))


def torznab_response_attrs(body_text: str) -> dict[str, int | None]:
    """Returns Torznab paging metadata from one RSS response."""

    root = ET.fromstring(body_text)
    response = root.find(".//{http://torznab.com/schemas/2015/feed}response")
    if response is None:
        return {"offset": None, "total": None}

    def parse_int(name: str) -> int | None:
        value = response.attrib.get(name)
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    return {"offset": parse_int("offset"), "total": parse_int("total")}


def wait_for_direct_torznab_results(
    base_url: str,
    emule_api_key: str,
    queries: tuple[str, ...],
    timeout_seconds: float,
    *,
    category_id: int = TORZNAB_LIVE_CATEGORY,
) -> dict[str, object]:
    """Polls direct Torznab searches until the eMule bridge returns at least one item."""

    attempts: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for query_index, query in enumerate(queries):
            path = build_direct_torznab_search_path(emule_api_key, query, category_id)
            try:
                result = rest_smoke.http_request(base_url, path, request_timeout_seconds=TORZNAB_DIRECT_REQUEST_TIMEOUT_SECONDS)
            except (ConnectionResetError, TimeoutError, OSError) as exc:
                attempts.append({"query_index": query_index, "query_present": bool(query), "status": type(exc).__name__, "count": 0})
                continue
            status = int(result.get("status") or 0)
            body_text = str(result.get("body_text") or "")
            count = count_torznab_items(body_text) if status == 200 and body_text else 0
            attempts.append({"query_index": query_index, "query_present": bool(query), "status": status, "count": count})
            if status == 200 and count > 0:
                return {"query": query, "count": count, "attempts": attempts}
        time.sleep(5.0)
    raise RuntimeError(f"Direct eMuleBB Torznab search returned no results before timeout. Attempts: {attempts!r}")


def stress_cached_direct_torznab_search(
    base_url: str,
    emule_api_key: str,
    query: str,
    count: int,
    *,
    category_id: int = TORZNAB_LIVE_CATEGORY,
) -> dict[str, object]:
    """Repeatedly exercises one cached direct Torznab search result."""

    attempts: list[dict[str, object]] = []
    path = build_direct_torznab_search_path(emule_api_key, query, category_id)
    for ordinal in range(1, count + 1):
        started = time.monotonic()
        result = rest_smoke.http_request(base_url, path, request_timeout_seconds=20.0)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        status = int(result.get("status") or 0)
        body_text = str(result.get("body_text") or "")
        item_count = count_torznab_items(body_text) if status == 200 and body_text else 0
        attempt = {"ordinal": ordinal, "status": status, "count": item_count, "elapsed_ms": elapsed_ms}
        attempts.append(attempt)
        if status != 200 or item_count <= 0:
            raise RuntimeError(f"Cached direct Torznab search stress failed: {attempts!r}")
    return {"query_present": bool(query), "requests": count, "attempts": attempts}


def check_cached_direct_torznab_offset_page(
    base_url: str,
    emule_api_key: str,
    query: str,
    *,
    category_id: int = TORZNAB_LIVE_CATEGORY,
    timeout_seconds: float = PROWLARR_LIVE_SEARCH_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Proves non-zero Torznab offsets can page a cached first-page result set."""

    attempts: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        first_path = build_direct_torznab_search_path(
            emule_api_key,
            query,
            category_id,
            extra_params={"limit": 1},
        )
        first_result = rest_smoke.http_request(base_url, first_path, request_timeout_seconds=TORZNAB_DIRECT_REQUEST_TIMEOUT_SECONDS)
        first_status = int(first_result.get("status") or 0)
        first_body = str(first_result.get("body_text") or "")
        first_count = count_torznab_items(first_body) if first_status == 200 and first_body else 0

        offset_path = build_direct_torznab_search_path(
            emule_api_key,
            query,
            category_id,
            extra_params={"offset": 1, "limit": 1},
        )
        offset_result = rest_smoke.http_request(base_url, offset_path, request_timeout_seconds=20.0)
        offset_status = int(offset_result.get("status") or 0)
        offset_body = str(offset_result.get("body_text") or "")
        offset_count = count_torznab_items(offset_body) if offset_status == 200 and offset_body else 0
        attrs = torznab_response_attrs(offset_body) if offset_status == 200 and offset_body else {"offset": None, "total": None}
        attempt = {
            "first_status": first_status,
            "first_count": first_count,
            "offset_status": offset_status,
            "offset_count": offset_count,
            "offset": attrs.get("offset"),
            "total": attrs.get("total"),
        }
        attempts.append(attempt)
        if first_status == 200 and first_count > 0 and offset_status == 200 and attrs.get("offset") == 1 and offset_count > 0:
            return {
                "query_present": bool(query),
                "category": int(category_id),
                "first_count": first_count,
                "offset_count": offset_count,
                "offset": attrs.get("offset"),
                "total": attrs.get("total"),
                "attempts": attempts,
            }
        time.sleep(5.0)
    raise RuntimeError(f"Direct Torznab cached offset page failed before timeout. Attempts: {attempts!r}")


def stress_direct_torznab_search_terms(
    base_url: str,
    emule_api_key: str,
    queries: tuple[str, ...],
    count: int,
    *,
    category_id: int = TORZNAB_LIVE_CATEGORY,
) -> dict[str, object]:
    """Exercises direct Torznab searches across configured live-wire terms."""

    if not queries:
        raise RuntimeError("Direct Torznab search stress requires at least one query.")
    attempts: list[dict[str, object]] = []
    item_total = 0
    for ordinal in range(1, count + 1):
        query_index = (ordinal - 1) % len(queries)
        query = queries[query_index]
        path = build_direct_torznab_search_path(emule_api_key, query, category_id)
        started = time.monotonic()
        result = rest_smoke.http_request(base_url, path, request_timeout_seconds=TORZNAB_DIRECT_REQUEST_TIMEOUT_SECONDS)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        status = int(result.get("status") or 0)
        body_text = str(result.get("body_text") or "")
        item_count = count_torznab_items(body_text) if status == 200 and body_text else 0
        item_total += item_count
        attempt = {
            "ordinal": ordinal,
            "query_index": query_index,
            "query_present": bool(query),
            "status": status,
            "count": item_count,
            "elapsed_ms": elapsed_ms,
        }
        attempts.append(attempt)
        if status != 200:
            raise RuntimeError(f"Direct Torznab search stress failed: {attempts!r}")
    if item_total <= 0:
        raise RuntimeError(f"Direct Torznab search stress returned no items: {attempts!r}")
    return {"requests": count, "term_count": len(queries), "item_total": item_total, "attempts": attempts}


def stress_prowlarr_search_terms(
    prowlarr_url: str,
    api_key: str,
    indexer_id: int,
    queries: tuple[str, ...],
    count: int,
    *,
    category_id: int = TORZNAB_LIVE_CATEGORY,
) -> dict[str, object]:
    """Exercises Prowlarr release searches across configured live-wire terms."""

    if not queries:
        raise RuntimeError("Prowlarr search stress requires at least one query.")
    attempts: list[dict[str, object]] = []
    row_total = 0
    for ordinal in range(1, count + 1):
        query_index = (ordinal - 1) % len(queries)
        query = queries[query_index]
        path = build_prowlarr_search_path(query, category_id, indexer_id)
        result = prowlarr_request(prowlarr_url, api_key, path, timeout_seconds=90.0)
        status = int(result.get("status") or 0)
        payload = result.get("json")
        count_rows = len(payload) if isinstance(payload, list) else 0
        row_total += count_rows
        attempt = {
            "ordinal": ordinal,
            "query_index": query_index,
            "query_present": bool(query),
            "status": status,
            "count": count_rows,
        }
        if status < 200 or status >= 300:
            attempt["body_preview"] = compact_body_preview(result)
        attempts.append(attempt)
        if status < 200 or status >= 300 or not isinstance(payload, list):
            raise RuntimeError(f"Prowlarr search stress failed: {attempts!r}")
    if row_total <= 0:
        raise RuntimeError(f"Prowlarr search stress returned no rows: {attempts!r}")
    return {"requests": count, "term_count": len(queries), "row_total": row_total, "attempts": attempts}


def stress_direct_media_category_searches(
    base_url: str,
    emule_api_key: str,
    radarr_movie_terms: tuple[str, ...],
    sonarr_series_terms: tuple[str, ...],
    count: int,
) -> dict[str, object]:
    """Exercises direct Torznab media searches for Radarr and Sonarr categories."""

    return {
        "radarr_movies": stress_direct_torznab_search_terms(
            base_url,
            emule_api_key,
            radarr_movie_terms,
            count,
            category_id=TORZNAB_MOVIE_CATEGORY,
        ),
        "sonarr_series": stress_direct_torznab_search_terms(
            base_url,
            emule_api_key,
            sonarr_series_terms,
            count,
            category_id=TORZNAB_TV_CATEGORY,
        ),
    }


def stress_prowlarr_media_category_searches(
    prowlarr_url: str,
    api_key: str,
    indexer_id: int,
    radarr_movie_terms: tuple[str, ...],
    sonarr_series_terms: tuple[str, ...],
    count: int,
) -> dict[str, object]:
    """Exercises Prowlarr-mediated media searches for Radarr and Sonarr categories."""

    return {
        "radarr_movies": stress_prowlarr_search_terms(
            prowlarr_url,
            api_key,
            indexer_id,
            radarr_movie_terms,
            count,
            category_id=TORZNAB_MOVIE_CATEGORY,
        ),
        "sonarr_series": stress_prowlarr_search_terms(
            prowlarr_url,
            api_key,
            indexer_id,
            sonarr_series_terms,
            count,
            category_id=TORZNAB_TV_CATEGORY,
        ),
    }


def first_live_wire_term(terms: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    """Returns the first operator-provided live-wire term for a focused check."""

    if not terms:
        raise RuntimeError(f"live-wire inputs field {field_name!r} must include at least one term.")
    return (terms[0],)


def redact_term_result(result: dict[str, object], *, source: str, term_count: int) -> dict[str, object]:
    """Redacts exact search terms and titles from one live-wire result."""

    redacted: dict[str, object] = {
        "source": source,
        "term_count": term_count,
        "count": result.get("count"),
        "attempt_count": len(result.get("attempts", [])) if isinstance(result.get("attempts"), list) else 0,
    }
    if "query" in result:
        redacted["query_present"] = bool(result.get("query"))
    if "first_title" in result:
        redacted["first_title_present"] = bool(result.get("first_title"))
    return redacted


def lower_file_extension(name: str) -> str:
    """Returns one lower-case file extension without exposing the file name."""

    dot_index = name.rfind(".")
    if dot_index < 0 or dot_index + 1 >= len(name):
        return ""
    extension = name[dot_index + 1 :].lower()
    return extension if extension.isascii() and extension.isalnum() else ""


def summarize_media_result_buckets(rows: list[dict[str, object]]) -> dict[str, object]:
    """Summarizes result media shape without persisting titles or links."""

    video_extensions = {"avi", "mkv", "mp4", "m4v", "mov", "mpg", "mpeg", "ts", "wmv", "webm", "iso"}
    extension_counts: dict[str, int] = {}
    video_extension_count = 0
    extensionless_large_count = 0
    non_video_count = 0
    size_present_count = 0
    for row in rows:
        name = str(row.get("name") or row.get("title") or "")
        extension = lower_file_extension(name)
        if extension:
            extension_counts[extension] = extension_counts.get(extension, 0) + 1
        size_value = row.get("size") if row.get("size") is not None else row.get("sizeBytes")
        try:
            size_bytes = int(size_value or 0)
        except (TypeError, ValueError):
            size_bytes = 0
        if size_bytes > 0:
            size_present_count += 1
        if extension in video_extensions:
            video_extension_count += 1
        elif not extension and size_bytes >= 100 * 1024 * 1024:
            extensionless_large_count += 1
        else:
            non_video_count += 1
    return {
        "result_count": len(rows),
        "title_present_count": sum(1 for row in rows if bool(row.get("name") or row.get("title"))),
        "size_present_count": size_present_count,
        "video_extension_count": video_extension_count,
        "extensionless_large_count": extensionless_large_count,
        "non_video_count": non_video_count,
        "extension_counts": dict(sorted(extension_counts.items())),
    }


def parse_torznab_item_summaries(body_text: str) -> list[dict[str, object]]:
    """Parses Torznab RSS items into redacted title and size summaries."""

    if not body_text:
        return []
    root = ET.fromstring(body_text)
    items: list[dict[str, object]] = []
    for item in root.findall("./channel/item"):
        title = item.findtext("title") or ""
        size = 0
        for child in list(item):
            if child.tag.endswith("attr") and child.attrib.get("name") == "size":
                try:
                    size = int(child.attrib.get("value") or 0)
                except ValueError:
                    size = 0
                break
        items.append({"name": title, "size": size})
    return items


def direct_torznab_term_diagnostic(base_url: str, emule_api_key: str, query: str, category_id: int | None) -> dict[str, object]:
    """Runs one direct Torznab diagnostic search for a live-wire term."""

    result = rest_smoke.http_request(
        base_url,
        build_direct_torznab_search_path(emule_api_key, query, category_id),
        request_timeout_seconds=TORZNAB_DIRECT_REQUEST_TIMEOUT_SECONDS,
    )
    status = int(result.get("status") or 0)
    rows = parse_torznab_item_summaries(str(result.get("body_text") or "")) if status == 200 else []
    summary = {
        "status": status,
        "category": category_id,
        "query_present": bool(query),
        "buckets": summarize_media_result_buckets(rows),
    }
    if status < 200 or status >= 300:
        summary["body_preview"] = compact_body_preview(result)
    return summary


def prowlarr_term_diagnostic(prowlarr_url: str, api_key: str, query: str, indexer_id: int, category_id: int) -> dict[str, object]:
    """Runs one Prowlarr diagnostic search for a live-wire term."""

    result = prowlarr_request(
        prowlarr_url,
        api_key,
        build_prowlarr_search_path(query, category_id, indexer_id),
        timeout_seconds=90.0,
    )
    status = int(result.get("status") or 0)
    payload = result.get("json")
    rows = payload if isinstance(payload, list) else []
    summary = {
        "status": status,
        "category": category_id,
        "query_present": bool(query),
        "buckets": summarize_media_result_buckets(rows),
    }
    if status < 200 or status >= 300:
        summary["body_preview"] = compact_body_preview(result)
    return summary


def diagnostic_result_count(summary: dict[str, object]) -> int:
    """Returns the result count from one redacted diagnostic summary."""

    buckets = summary.get("buckets")
    if not isinstance(buckets, dict):
        return 0
    try:
        return int(buckets.get("result_count") or 0)
    except (TypeError, ValueError):
        return 0


def is_prowlarr_indexer_unavailable_result(summary: dict[str, object]) -> bool:
    """Returns true when Prowlarr suppressed the search because the indexer is unavailable."""

    if int(summary.get("status") or 0) != 400:
        return False
    return "all selected indexers being unavailable" in str(summary.get("body_preview") or "").lower()


def compact_search_network_snapshot(base_url: str, api_key: str) -> dict[str, object]:
    """Collects a compact network status snapshot for live search readiness reports."""

    snapshot: dict[str, object] = {"observed_at": round(time.time(), 3)}
    try:
        server_result = rest_smoke.http_request(base_url, "/api/v1/status", api_key=api_key, request_timeout_seconds=10.0)
        if int(server_result.get("status") or 0) == 200:
            server_payload = rest_smoke.get_server_status_payload(rest_smoke.require_json_object(server_result, 200))
            snapshot["server"] = rest_smoke.compact_server_status(server_payload)
        else:
            snapshot["server_status"] = int(server_result.get("status") or 0)
    except Exception as exc:  # pragma: no cover - diagnostics must not mask search readiness
        snapshot["server_error"] = type(exc).__name__

    try:
        kad_result = rest_smoke.http_request(base_url, "/api/v1/kad", api_key=api_key, request_timeout_seconds=10.0)
        if int(kad_result.get("status") or 0) == 200:
            snapshot["kad"] = rest_smoke.compact_kad_status(rest_smoke.require_json_object(kad_result, 200))
        else:
            snapshot["kad_status"] = int(kad_result.get("status") or 0)
    except Exception as exc:  # pragma: no cover - diagnostics must not mask search readiness
        snapshot["kad_error"] = type(exc).__name__

    return snapshot


def diagnose_radarr_movie_terms(
    *,
    base_url: str,
    emule_api_key: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    indexer_id: int,
    terms: tuple[str, ...],
) -> dict[str, object]:
    """Compares direct and Prowlarr movie search behavior for each Radarr term."""

    diagnostics = []
    for term_index, term in enumerate(terms):
        diagnostics.append(
            {
                "term_index": term_index,
                "term_present": bool(term),
                "direct_any": direct_torznab_term_diagnostic(base_url, emule_api_key, term, None),
                "direct_movie": direct_torznab_term_diagnostic(base_url, emule_api_key, term, TORZNAB_MOVIE_CATEGORY),
                "prowlarr_movie": prowlarr_term_diagnostic(prowlarr_url, prowlarr_api_key, term, indexer_id, TORZNAB_MOVIE_CATEGORY),
            }
        )
    first = diagnostics[0] if diagnostics else None
    first_movie_count = 0
    if isinstance(first, dict):
        prowlarr_movie = first.get("prowlarr_movie")
        if isinstance(prowlarr_movie, dict):
            buckets = prowlarr_movie.get("buckets")
            if isinstance(buckets, dict):
                first_movie_count = int(buckets.get("result_count") or 0)
    return {
        "term_count": len(terms),
        "first_term_movie_result_count": first_movie_count,
        "first_term_movie_results_ok": first_movie_count > 0,
        "terms": diagnostics,
    }


def wait_for_primary_radarr_movie_term_results(
    *,
    base_url: str,
    emule_api_key: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    indexer_id: int,
    terms: tuple[str, ...],
    timeout_seconds: float,
    poll_interval_seconds: float = 5.0,
    monotonic_seconds=time.monotonic,
    sleep_seconds=time.sleep,
) -> dict[str, object]:
    """Polls the primary Radarr movie term through the startup search window."""

    if not terms:
        raise RuntimeError("Primary Radarr movie readiness requires at least one live-wire term.")
    if timeout_seconds <= 0:
        raise RuntimeError("Primary Radarr movie readiness timeout must be greater than zero.")
    if poll_interval_seconds <= 0:
        raise RuntimeError("Primary Radarr movie readiness poll interval must be greater than zero.")

    primary_term = terms[0]
    attempts: list[dict[str, object]] = []
    started = monotonic_seconds()
    deadline = started + timeout_seconds
    attempt_index = 0
    while True:
        attempt_started = monotonic_seconds()
        direct_movie = direct_torznab_term_diagnostic(base_url, emule_api_key, primary_term, TORZNAB_MOVIE_CATEGORY)
        direct_count = diagnostic_result_count(direct_movie)
        if direct_count > 0:
            prowlarr_movie = prowlarr_term_diagnostic(
                prowlarr_url,
                prowlarr_api_key,
                primary_term,
                indexer_id,
                TORZNAB_MOVIE_CATEGORY,
            )
        else:
            prowlarr_movie = {
                "status": "skipped_until_direct_movie_results",
                "category": TORZNAB_MOVIE_CATEGORY,
                "query_present": bool(primary_term),
                "buckets": summarize_media_result_buckets([]),
            }
        attempt = {
            "attempt_index": attempt_index,
            "elapsed_ms": int((monotonic_seconds() - started) * 1000),
            "request_elapsed_ms": int((monotonic_seconds() - attempt_started) * 1000),
            "term_present": bool(primary_term),
            "direct_movie": direct_movie,
            "prowlarr_movie": prowlarr_movie,
            "network": compact_search_network_snapshot(base_url, emule_api_key),
        }
        attempts.append(attempt)
        prowlarr_count = diagnostic_result_count(prowlarr_movie)
        if direct_count > 0 and prowlarr_count > 0:
            return {
                "ok": True,
                "term_index": 0,
                "term_count": len(terms),
                "attempt_count": len(attempts),
                "elapsed_ms": int((monotonic_seconds() - started) * 1000),
                "result_count": prowlarr_count,
                "attempts": attempts,
            }
        if direct_count > 0 and is_prowlarr_indexer_unavailable_result(prowlarr_movie):
            return {
                "ok": False,
                "term_index": 0,
                "term_count": len(terms),
                "attempt_count": len(attempts),
                "elapsed_ms": int((monotonic_seconds() - started) * 1000),
                "result_count": 0,
                "prowlarr_indexer_unavailable": True,
                "attempts": attempts,
            }
        remaining = deadline - monotonic_seconds()
        if remaining <= 0:
            return {
                "ok": False,
                "term_index": 0,
                "term_count": len(terms),
                "attempt_count": len(attempts),
                "elapsed_ms": int((monotonic_seconds() - started) * 1000),
                "result_count": 0,
                "attempts": attempts,
            }
        sleep_seconds(min(poll_interval_seconds, remaining))
        attempt_index += 1


def require_first_radarr_movie_term_results(diagnostic: dict[str, object]) -> None:
    """Fails fast when the primary Radarr movie term has no movie results."""

    ok = diagnostic.get("ok")
    if ok is None:
        ok = diagnostic.get("first_term_movie_results_ok")
    if not bool(ok):
        raise RuntimeError("Primary Radarr movie live-wire term returned no Prowlarr movie-category rows.")


def ed2k_hash_from_magnet(magnet: str) -> str:
    """Extracts the eMuleBB fake BTIH hash from a magnet URL."""

    parsed = urllib.parse.urlparse(magnet)
    query = urllib.parse.parse_qs(parsed.query)
    xt = query.get("xt", [""])[0].lower()
    prefix = "urn:btih:"
    if not xt.startswith(prefix) or len(xt) < len(prefix) + 40:
        raise RuntimeError("Magnet does not contain an eMuleBB fake BTIH hash.")
    return xt[len(prefix) : len(prefix) + 32]


def transfer_hashes(base_url: str, emule_api_key: str) -> set[str]:
    """Returns currently visible native transfer hashes."""

    result = retry_emule_rest_request(
        base_url,
        "/api/v1/transfers",
        api_key=emule_api_key,
        timeout_seconds=60.0,
        request_timeout_seconds=15.0,
    )
    rows = rest_smoke.require_json_array(result, 200)
    return {
        str(row.get("hash") or "").lower()
        for row in rows
        if isinstance(row, dict) and str(row.get("hash") or "").strip()
    }


def wait_for_new_category_transfer(
    base_url: str,
    emule_api_key: str,
    *,
    category: str,
    before_hashes: set[str],
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until a newly grabbed transfer appears in the expected category."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, object] | None = None
    while time.monotonic() < deadline:
        request_timeout = min(30.0, max(1.0, deadline - time.monotonic()))
        result = retry_emule_rest_request(
            base_url,
            "/api/v1/transfers",
            api_key=emule_api_key,
            timeout_seconds=request_timeout,
            request_timeout_seconds=request_timeout,
        )
        rows = rest_smoke.require_json_array(result, 200)
        for row in rows:
            if not isinstance(row, dict):
                continue
            transfer_hash = str(row.get("hash") or "").lower()
            last = {
                "hash_present": bool(transfer_hash),
                "name_present": bool(row.get("name")),
                "state": row.get("state"),
                "categoryName": row.get("categoryName"),
            }
            if transfer_hash and transfer_hash not in before_hashes and str(row.get("categoryName") or "") == category:
                return last
        time.sleep(2.0)
    raise RuntimeError(f"Prowlarr grab did not create a new transfer in category {category!r}. Last: {last!r}")


def ensure_emule_category(base_url: str, api_key: str, name: str, path: Path) -> dict[str, object]:
    """Ensures the live eMuleBB profile has a named category for the grab proof."""

    path.mkdir(parents=True, exist_ok=True)
    path_text = live_common.win_path(path.resolve(), trailing_slash=True)
    categories = rest_smoke.http_request(base_url, "/api/v1/categories", api_key=api_key, request_timeout_seconds=20.0)
    rows = rest_smoke.require_json_array(categories, 200)
    for row in rows:
        if not isinstance(row, dict) or row.get("name") != name:
            continue
        category_id = int(row.get("id") or 0)
        current_path = str(row.get("path") or "")
        if current_path.lower() != path_text.lower():
            patched = rest_smoke.http_request(
                base_url,
                f"/api/v1/categories/{category_id}",
                method="PATCH",
                api_key=api_key,
                json_body={"path": path_text},
                request_timeout_seconds=20.0,
            )
            updated = rest_smoke.require_json_object(patched, 200)
            return {"id": category_id, "name": name, "path": updated.get("path"), "created": False, "updated": True}
        return {"id": category_id, "name": name, "path": current_path, "created": False, "updated": False}

    created = rest_smoke.http_request(
        base_url,
        "/api/v1/categories",
        method="POST",
        api_key=api_key,
        json_body={"name": name, "path": path_text},
        request_timeout_seconds=20.0,
    )
    payload = rest_smoke.require_json_object(created, 200)
    return {"id": int(payload.get("id") or 0), "name": payload.get("name"), "path": payload.get("path"), "created": True, "updated": False}


def retry_emule_rest_request(
    base_url: str,
    path: str,
    *,
    api_key: str,
    timeout_seconds: float,
    request_timeout_seconds: float,
    **kwargs: object,
) -> dict[str, object]:
    """Retries transient eMuleBB REST socket failures and keeps evidence."""

    observations: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            result = rest_smoke.http_request(
                base_url,
                path,
                api_key=api_key,
                request_timeout_seconds=request_timeout_seconds,
                **kwargs,
            )
            if observations:
                result = dict(result)
                result["transient_errors"] = observations[-5:]
            return result
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            observations.append(
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "observed_at": round(time.time(), 3),
                }
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"REST request {path} did not recover. Transient observations: {observations[-5:]}") from exc
            time.sleep(min(1.0, remaining))


def qbit_request(
    base_url: str,
    path: str,
    *,
    cookie: str | None = None,
    form: dict[str, object] | None = None,
    method: str | None = None,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Performs one qBittorrent-compatible request against eMuleBB."""

    data = None
    headers = {"Connection": "close"}
    if cookie:
        headers["Cookie"] = cookie
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method, headers=headers)
    urlopen_kwargs: dict[str, object] = {"timeout": timeout_seconds}
    context = rest_smoke.build_urlopen_context(base_url)
    if context is not None:
        urlopen_kwargs["context"] = context
    try:
        with urllib.request.urlopen(request, **urlopen_kwargs) as response:
            body_text = response.read().decode("utf-8", errors="replace")
            return {"status": int(response.status), "body_text": body_text, "headers": dict(response.headers.items())}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        return {"status": int(exc.code), "body_text": body_text, "headers": dict(exc.headers.items())}


def require_qbit_ok(result: dict[str, object], description: str) -> None:
    status = int(result.get("status") or 0)
    body_text = str(result.get("body_text") or "")
    if status != 200 or body_text != "Ok.":
        raise RuntimeError(f"{description} failed with HTTP {status}: {body_text[:100]}")


def qbit_login(base_url: str, emule_api_key: str) -> tuple[str, dict[str, object]]:
    """Authenticates to eMuleBB's qBittorrent-compatible API."""

    login = qbit_request(
        base_url,
        "/api/v2/auth/login",
        form={"username": "emule", "password": emule_api_key},
        method="POST",
    )
    require_qbit_ok(login, "qBit login")
    headers = login.get("headers") if isinstance(login.get("headers"), dict) else {}
    set_cookie = str(headers.get("Set-Cookie") or "")
    cookie = set_cookie.split(";", 1)[0]
    if not cookie.startswith("SID="):
        raise RuntimeError("qBit login did not return a SID cookie.")
    return cookie, login


def ed2k_hash_from_link(link: str) -> str:
    """Extracts the native MD4 hash from an eD2K file link."""

    parts = link.split("|")
    if len(parts) < 5 or parts[0] != "ed2k://" or parts[1] != "file":
        raise RuntimeError("eD2K link is not a file link.")
    value = parts[4].lower()
    if len(value) != 32 or any(char not in "0123456789abcdef" for char in value):
        raise RuntimeError("eD2K file link does not contain a native MD4 hash.")
    return value


def hash_from_download_link(download_link: str) -> str:
    """Extracts the native transfer hash from a supported live download link."""

    if download_link.startswith("magnet:?"):
        return ed2k_hash_from_magnet(download_link)
    if download_link.startswith("ed2k://"):
        return ed2k_hash_from_link(download_link)
    raise RuntimeError("Unsupported eMule download link.")


def get_release_download_link(release: dict[str, Any]) -> str:
    """Returns the eMule-compatible download link carried by one Prowlarr row."""

    for key in ("magnetUrl", "magneturl", "downloadUrl", "guid"):
        value = str(release.get(key) or "")
        if value.startswith("magnet:?") or value.startswith("ed2k://"):
            return value
    raise RuntimeError("Prowlarr release did not expose an eMule-compatible download link.")


def get_release_native_transfer_link(release: dict[str, Any]) -> str:
    """Returns the native ED2K transfer link from one Prowlarr row."""

    for key in ("downloadUrl", "guid", "magnetUrl", "magneturl"):
        value = str(release.get(key) or "")
        if value.startswith("ed2k://"):
            return value
    raise RuntimeError("Prowlarr release did not expose a native eD2K transfer link.")


def native_rest_transfer_add(
    base_url: str,
    emule_api_key: str,
    download_link: str,
    category: str,
) -> dict[str, object]:
    """Adds one Prowlarr-selected release through eMuleBB's native REST API."""

    added = retry_emule_rest_request(
        base_url,
        "/api/v1/transfers",
        api_key=emule_api_key,
        timeout_seconds=60.0,
        request_timeout_seconds=15.0,
        method="POST",
        json_body={"link": download_link, "categoryName": category, "paused": True},
    )
    payload = rest_smoke.require_json_object(added, 200)
    items = payload.get("items")
    if not isinstance(items, list) or not items or not isinstance(items[0], dict) or not items[0].get("ok"):
        raise RuntimeError(f"Native transfer add did not accept the selected release: {rest_smoke.compact_http_result(added)!r}")
    return {
        "add_status": int(added.get("status") or 0),
        "hash": hash_from_download_link(download_link),
        "transient_errors": added.get("transient_errors", []),
    }


def qbit_direct_add(
    base_url: str,
    emule_api_key: str,
    download_link: str,
    category: str,
) -> dict[str, object]:
    """Adds one Prowlarr-selected release through eMuleBB's qBit-compatible endpoint."""

    cookie, login = qbit_login(base_url, emule_api_key)
    add = qbit_request(
        base_url,
        "/api/v2/torrents/add",
        cookie=cookie,
        form={
            "urls": download_link,
            "category": category,
            "stopped": "true",
            "ratioLimit": "-1",
            "seedingTimeLimit": "-1",
            "inactiveSeedingTimeLimit": "-1",
        },
        method="POST",
        timeout_seconds=45.0,
    )
    require_qbit_ok(add, "qBit add")
    return {
        "add_status": int(add.get("status") or 0),
        "login_status": int(login.get("status") or 0),
        "hash": hash_from_download_link(download_link),
    }


def choose_listen_port(bind_addr: str) -> int:
    """Returns one free TCP port on the actual eMule web bind address."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((bind_addr, 0))
        return int(probe.getsockname()[1])


def wait_for_prowlarr_results(
    prowlarr_url: str,
    api_key: str,
    indexer_id: int,
    queries: tuple[str, ...],
    timeout_seconds: float,
    *,
    category_id: int = TORZNAB_LIVE_CATEGORY,
) -> dict[str, object]:
    """Polls Prowlarr searches until one query returns at least one item."""

    attempts: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for query_index, query in enumerate(queries):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            path = build_prowlarr_search_path(query, category_id, indexer_id)
            result = prowlarr_request(prowlarr_url, api_key, path, timeout_seconds=max(1.0, min(30.0, remaining)))
            status = int(result.get("status") or 0)
            payload = result.get("json")
            count = len(payload) if isinstance(payload, list) else 0
            attempt = {"query_index": query_index, "query_present": bool(query), "status": status, "count": count}
            if status < 200 or status >= 300:
                attempt["body_preview"] = compact_body_preview(result)
            attempts.append(attempt)
            if status >= 200 and status < 300 and count > 0:
                first = payload[0]
                return {
                    "query": query,
                    "count": count,
                    "first_title": first.get("title") if isinstance(first, dict) else None,
                    "attempts": attempts,
                }
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5.0, remaining))
    raise RuntimeError(f"Prowlarr did not return eMuleBB results before timeout. Attempts: {attempts!r}")


def normalized_match_text(value: object) -> str:
    """Normalizes one title/query string for redacted release ranking."""

    text = str(value or "").lower()
    return " ".join("".join(char if char.isalnum() else " " for char in text).split())


def numeric_release_field(row: dict[str, Any], *field_names: str) -> int:
    """Returns the largest non-negative integer value from possible source fields."""

    values: list[int] = []
    for field_name in field_names:
        try:
            values.append(max(0, int(row.get(field_name) or 0)))
        except (TypeError, ValueError):
            continue
    return max(values) if values else 0


def release_title_match_score(row: dict[str, Any], query: str) -> int:
    """Scores how closely a redacted release row title matches the query."""

    title_text = normalized_match_text(row.get("title") or row.get("name"))
    query_text = normalized_match_text(query)
    if not title_text or not query_text:
        return 0
    title_tokens = set(title_text.split())
    query_tokens = set(query_text.split())
    if title_text == query_text:
        return 300
    if query_tokens and query_tokens.issubset(title_tokens):
        return 200
    if query_text in title_text:
        return 150
    if query_tokens and title_tokens.intersection(query_tokens):
        return 50
    return 0


def release_source_count(row: dict[str, Any]) -> int:
    """Returns the strongest available source-count signal for an Arr release row."""

    return numeric_release_field(row, "sources", "sourceCount", "seeders", "peers")


def summarize_release_selection(release: dict[str, Any], query: str) -> dict[str, object]:
    """Builds a report-safe summary of the release ranking inputs."""

    return {
        "title_match_score": release_title_match_score(release, query),
        "source_count": release_source_count(release),
    }


def select_grabbable_release(rows: list[Any], indexer_id: int, query: str) -> dict[str, Any]:
    """Selects the best Prowlarr release row that can be posted back to grab."""

    candidates: list[tuple[int, int, int, dict[str, Any]]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if int(row.get("indexerId") or 0) != int(indexer_id):
            continue
        if not str(row.get("guid") or "").strip():
            continue
        candidates.append(
            (
                release_title_match_score(row, query),
                release_source_count(row),
                -len(candidates),
                json.loads(json.dumps(row)),
            )
        )
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][3]
    raise RuntimeError("Prowlarr search returned rows but none were grabbable for the eMuleBB indexer.")


def summarize_grabbed_release(release: dict[str, Any], query: str) -> dict[str, object]:
    """Builds a report-safe summary of the selected Prowlarr release."""

    hash_present = False
    try:
        hash_present = bool(hash_from_download_link(get_release_download_link(release)))
    except RuntimeError:
        hash_present = False
    return {
        "title_present": bool(release.get("title")),
        "guid_present": bool(release.get("guid")),
        "download_url_present": bool(release.get("downloadUrl")),
        "magnet_url_present": bool(release.get("magnetUrl")),
        "hash_present": hash_present,
        **summarize_release_selection(release, query),
    }


def prowlarr_download_client_grab_roundtrip(
    *,
    prowlarr_url: str,
    prowlarr_api_key: str,
    emule_base_url: str,
    emule_api_key: str,
    indexer_id: int,
    queries: tuple[str, ...],
    category_id: int,
    download_client_id: int,
    download_category: str,
    timeout_seconds: float,
    transfer_timeout_seconds: float,
) -> dict[str, object]:
    """Searches Prowlarr, grabs one result, and verifies eMule receives it."""

    attempts: list[dict[str, object]] = []
    before_hashes = transfer_hashes(emule_base_url, emule_api_key)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for query_index, query in enumerate(queries):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            path = build_prowlarr_search_path(query, category_id, indexer_id)
            result = prowlarr_request(prowlarr_url, prowlarr_api_key, path, timeout_seconds=max(1.0, min(30.0, remaining)))
            status = int(result.get("status") or 0)
            payload = result.get("json")
            rows = payload if isinstance(payload, list) else []
            attempt = {
                "query_index": query_index,
                "query_present": bool(query),
                "status": status,
                "count": len(rows),
            }
            if status < 200 or status >= 300:
                attempt["body_preview"] = compact_body_preview(result)
            attempts.append(attempt)
            if status < 200 or status >= 300 or not rows:
                continue

            release = select_grabbable_release(rows, indexer_id, query)
            download_link = get_release_native_transfer_link(release)
            added = native_rest_transfer_add(emule_base_url, emule_api_key, download_link, download_category)
            return {
                "status": "passed",
                "category": int(category_id),
                "download_client_id": int(download_client_id),
                "download_category": download_category,
                "handoff": "prowlarr-search-native-emulebb-rest-add",
                "release": summarize_grabbed_release(release, query),
                "grab_status": int(added.get("add_status") or 0),
                "download_link_hash_present": bool(added.get("hash")),
                "transient_errors": added.get("transient_errors", []),
                "transfer": wait_for_new_category_transfer(
                    emule_base_url,
                    emule_api_key,
                    category=download_category,
                    before_hashes=before_hashes,
                    timeout_seconds=transfer_timeout_seconds,
                ),
                "attempt_count": len(attempts),
            }
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5.0, remaining))
    raise RuntimeError(f"Prowlarr download-client grab proof found no grabbable rows. Attempts: {attempts!r}")


def build_parser() -> argparse.ArgumentParser:
    """Builds the Prowlarr eMuleBB live test argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--env-file", default=str((REPO_ROOT / live_env.DEFAULT_ENV_FILE_NAME).resolve()))
    parser.add_argument("--emule-api-key", default="prowlarr-emulebb-live-key")
    parser.add_argument("--bind-addr")
    parser.add_argument("--rest-webserver-scheme", choices=["http", "https"], default="https")
    parser.add_argument("--enable-upnp", action="store_true", default=True)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS)
    parser.add_argument("--emule-connection-timeout-seconds", type=float, default=DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS)
    parser.add_argument("--result-timeout-seconds", type=float, default=DEFAULT_SEARCH_TIMEOUT_SECONDS)
    parser.add_argument("--document-download-timeout-seconds", type=float, default=DEFAULT_DOCUMENT_DOWNLOAD_TIMEOUT_SECONDS)
    parser.add_argument("--prowlarr-indexer-availability-timeout-seconds", type=float, default=DEFAULT_DOCUMENT_DOWNLOAD_TIMEOUT_SECONDS)
    parser.add_argument("--cached-search-stress-count", type=int, default=12)
    parser.add_argument("--direct-search-stress-count", type=int, default=6)
    parser.add_argument("--prowlarr-search-stress-count", type=int, default=4)
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)),
    )
    return parser


def resolve_bind_addr(prowlarr_url: str, explicit_bind_addr: str | None) -> str:
    """Chooses the eMule web bind address reachable by local Prowlarr."""

    if explicit_bind_addr:
        return explicit_bind_addr
    parsed = urllib.parse.urlparse(prowlarr_url)
    if parsed.hostname and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        return parsed.hostname
    return "127.0.0.1"


def main() -> int:
    """Runs the live Prowlarr eMuleBB bridge test."""

    args = build_parser().parse_args()
    if args.cached_search_stress_count <= 0:
        raise ValueError("--cached-search-stress-count must be greater than zero.")
    if args.direct_search_stress_count <= 0:
        raise ValueError("--direct-search-stress-count must be greater than zero.")
    if args.prowlarr_search_stress_count <= 0:
        raise ValueError("--prowlarr-search-stress-count must be greater than zero.")
    if args.rest_ready_timeout_seconds <= 0:
        raise ValueError("--rest-ready-timeout-seconds must be greater than zero.")
    if args.emule_connection_timeout_seconds <= 0:
        raise ValueError("--emule-connection-timeout-seconds must be greater than zero.")
    if args.result_timeout_seconds <= 0:
        raise ValueError("--result-timeout-seconds must be greater than zero.")
    if args.document_download_timeout_seconds <= 0:
        raise ValueError("--document-download-timeout-seconds must be greater than zero.")
    if args.prowlarr_indexer_availability_timeout_seconds <= 0:
        raise ValueError("--prowlarr-indexer-availability-timeout-seconds must be greater than zero.")
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    generic_terms = first_live_wire_term(inputs.generic_open_terms, "search_terms.generic_open")
    env_values = live_env.load_env_values(
        ("PROWLARR_URL", "PROWLARR_API_KEY"),
        env_file=Path(args.env_file).resolve(),
        defaults={"EMULEBB_TEST_PROWLARR_INDEXER_NAME": "eMuleBB Local"},
    )
    prowlarr_url = env_values["PROWLARR_URL"].rstrip("/")
    prowlarr_api_key = env_values["PROWLARR_API_KEY"]
    indexer_name = env_values["EMULEBB_TEST_PROWLARR_INDEXER_NAME"]

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="prowlarr-emulebb-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    artifacts_dir = paths.source_artifacts_dir
    bind_addr = resolve_bind_addr(prowlarr_url, args.bind_addr)
    port = choose_listen_port(bind_addr)
    use_https = args.rest_webserver_scheme == "https"
    emule_base_url = f"{args.rest_webserver_scheme}://{bind_addr}:{port}"
    torznab_base_url = f"{emule_base_url}/indexer/emulebb"
    https_material = (
        rest_smoke.create_https_certificate_pair(paths.app_exe, artifacts_dir, hosts=(bind_addr,))
        if use_https
        else {"certificate": "", "key": "", "generator": ""}
    )
    rest_smoke.configure_https_trust(https_material["certificate"])

    profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="prowlarr-emulebb-live")
    seed_refresh = None
    if not args.skip_live_seed_refresh:
        seed_refresh = rest_smoke.refresh_seed_files(
            Path(profile["config_dir"]),
            timeout_seconds=args.seed_download_timeout_seconds,
        )
    rest_smoke.configure_webserver_profile(
        Path(profile["config_dir"]),
        paths.app_exe,
        args.emule_api_key,
        port,
        bind_addr,
        use_https=use_https,
        https_certificate=https_material["certificate"],
        https_key=https_material["key"],
    )
    if args.p2p_bind_interface_name:
        rest_smoke.apply_p2p_bind_interface_override(
            Path(profile["config_dir"]),
            args.p2p_bind_interface_name,
        )

    app = None
    cleanup_download_clients: list[tuple[str, str, int]] = []
    report: dict[str, object] = {
        "suite": "prowlarr-emulebb-live",
        "status": "running",
        "prowlarr_url": prowlarr_url,
        "indexer_name": indexer_name,
        "emule_base_url": emule_base_url,
        "torznab_base_url": torznab_base_url,
        "rest_webserver_scheme": args.rest_webserver_scheme,
        "https_material": https_material if use_https else None,
        "api_key_length": len(args.emule_api_key),
        "prowlarr_api_key_length": len(prowlarr_api_key),
        "seed_refresh": seed_refresh,
        "enable_upnp": True,
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "launch_inputs": {
            "app_exe": str(paths.app_exe),
            "bind_addr": bind_addr,
            "config_dir": str(profile["config_dir"]),
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "enable_upnp": True,
            "profile_base": str(profile["profile_base"]),
            "seed_config_dir": str(seed_config_dir),
        },
        "live_wire_inputs_file": str(inputs.path),
        "search_terms": {
            "generic_open": live_wire_inputs.summarize_terms(generic_terms),
        },
        "search_timeout_seconds": min(args.result_timeout_seconds, PROWLARR_LIVE_SEARCH_TIMEOUT_SECONDS),
        "emule_connection_timeout_seconds": args.emule_connection_timeout_seconds,
        "document_download_timeout_seconds": args.document_download_timeout_seconds,
        "prowlarr_indexer_availability_timeout_seconds": args.prowlarr_indexer_availability_timeout_seconds,
        "torznab_media_categories": {
            "movie": TORZNAB_MOVIE_CATEGORY,
            "tv": TORZNAB_TV_CATEGORY,
            "document": TORZNAB_DOCUMENT_CATEGORY,
        },
        "checks": {},
    }
    result_path = artifacts_dir / "prowlarr-emulebb-live-result.json"

    def record_phase(phase: str) -> None:
        report["current_phase"] = phase
        live_common.write_json(result_path, report)

    try:
        record_phase("launch_emule")
        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]))
        main_window = live_common.wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        record_phase("rest_ready")
        ready = rest_smoke.wait_for_rest_ready(emule_base_url, args.emule_api_key, args.rest_ready_timeout_seconds)
        report["checks"]["rest_ready"] = rest_smoke.compact_http_result(ready)
        record_phase("emule_grab_category")
        report["checks"]["emule_grab_category"] = ensure_emule_category(
            emule_base_url,
            args.emule_api_key,
            PROWLARR_GRAB_CATEGORY,
            Path(profile["incoming_dir"]) / PROWLARR_GRAB_CATEGORY,
        )
        record_phase("network_ready")
        servers = rest_smoke.http_request(emule_base_url, "/api/v1/servers", api_key=args.emule_api_key)
        server_rows = rest_smoke.require_json_array(servers, 200)
        report["checks"]["servers_list"] = {"count": len(server_rows)}
        report["checks"]["servers_connect"] = rest_smoke.connect_to_live_server(
            emule_base_url,
            args.emule_api_key,
            server_rows,
            args.emule_connection_timeout_seconds,
        )
        kad_connect = rest_smoke.http_request(
            emule_base_url,
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=args.emule_api_key,
            json_body={},
            request_timeout_seconds=20.0,
        )
        report["checks"]["kad_connect"] = rest_smoke.compact_http_result(kad_connect)
        if int(kad_connect["status"]) != 200:
            raise RuntimeError(f"Kad start returned HTTP {kad_connect['status']}")
        report["checks"]["kad_running"] = rest_smoke.wait_for_kad_running(
            emule_base_url,
            args.emule_api_key,
            args.emule_connection_timeout_seconds,
        )
        report["checks"]["network_ready"] = rest_smoke.wait_for_requested_networks(
            emule_base_url,
            args.emule_api_key,
            args.emule_connection_timeout_seconds,
            require_server_connected=False,
            require_kad_connected=True,
        )

        record_phase("direct_torznab_unknown_query_tolerance")
        report["checks"]["direct_torznab_unknown_query_tolerance"] = check_direct_unknown_query_tolerance(
            emule_base_url,
            args.emule_api_key,
        )

        record_phase("direct_torznab_error_edges")
        report["checks"]["direct_torznab_error_edges"] = check_direct_torznab_error_edges(
            emule_base_url,
            args.emule_api_key,
        )

        record_phase("direct_torznab_cached_offset_page")
        report["checks"]["direct_torznab_cached_offset_page"] = check_cached_direct_torznab_offset_page(
            emule_base_url,
            args.emule_api_key,
            generic_terms[0],
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )

        record_phase("prowlarr_indexer_upsert")
        status_payload = require_success(
            prowlarr_request(prowlarr_url, prowlarr_api_key, "/api/v1/system/status"),
            "Prowlarr system status",
        )
        report["checks"]["prowlarr_status"] = {
            "appName": status_payload.get("appName") if isinstance(status_payload, dict) else None,
            "version": status_payload.get("version") if isinstance(status_payload, dict) else None,
        }
        if use_https:
            report["checks"]["prowlarr_certificate_validation"] = set_prowlarr_local_certificate_validation(
                prowlarr_url,
                prowlarr_api_key,
            )
        saved_indexer = upsert_indexer(
            prowlarr_url,
            prowlarr_api_key,
            indexer_name=indexer_name,
            torznab_base_url=torznab_base_url,
            emule_api_key=args.emule_api_key,
        )
        report["checks"]["indexer_upsert"] = {
            "id": int(saved_indexer["id"]),
            "name": saved_indexer.get("name"),
            "implementation": saved_indexer.get("implementation"),
            "enable": bool(saved_indexer.get("enable")),
            "forcedSave": bool(saved_indexer.get("_emulebbForcedSave")),
            "recreatedAfterUnavailable": bool(saved_indexer.get("_emulebbRecreatedAfterUnavailable")),
            "certificate_policy": saved_indexer.get("_emulebbCertificatePolicy"),
        }
        indexer_statuses = get_indexer_statuses(prowlarr_url, prowlarr_api_key)
        report["checks"]["indexer_status"] = [
            {
                "indexerId": status.get("indexerId"),
                "disabledTill": status.get("disabledTill"),
                "mostRecentFailure": status.get("mostRecentFailure"),
            }
            for status in indexer_statuses
            if status.get("indexerId") == int(saved_indexer["id"])
        ]
        report["checks"]["indexer_availability"] = wait_for_indexer_available(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            args.prowlarr_indexer_availability_timeout_seconds,
        )
        report["checks"]["indexer_test"] = {
            "status": "skipped",
            "reason": "Prowlarr test can mark a live no-result validation as temporarily unavailable before searches.",
        }

        record_phase("prowlarr_download_client")
        qbit_client = create_temp_qbit_download_client(
            prowlarr_url,
            prowlarr_api_key,
            name=f"eMuleBB Live Prowlarr {port}",
            host=bind_addr,
            port=port,
            emule_api_key=args.emule_api_key,
            category=PROWLARR_GRAB_CATEGORY,
            use_ssl=use_https,
        )
        cleanup_download_clients.append((prowlarr_url, prowlarr_api_key, int(qbit_client["id"])))
        report["checks"][PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS[0]] = summarize_qbit_download_client(qbit_client, category=PROWLARR_GRAB_CATEGORY)
        prowlarr_timeout = min(args.result_timeout_seconds, PROWLARR_LIVE_SEARCH_TIMEOUT_SECONDS)
        record_phase("prowlarr_search")
        report["checks"][PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS[1]] = wait_for_prowlarr_results(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            generic_terms,
            prowlarr_timeout,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )
        report["checks"][PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS[1]] = redact_term_result(
            report["checks"][PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS[1]],
            source="generic_open",
            term_count=len(generic_terms),
        )
        record_phase("prowlarr_grab_to_emule_category")
        report["checks"][PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS[2]] = prowlarr_download_client_grab_roundtrip(
            prowlarr_url=prowlarr_url,
            prowlarr_api_key=prowlarr_api_key,
            emule_base_url=emule_base_url,
            emule_api_key=args.emule_api_key,
            indexer_id=int(saved_indexer["id"]),
            queries=generic_terms,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
            download_client_id=int(qbit_client["id"]),
            download_category=PROWLARR_GRAB_CATEGORY,
            timeout_seconds=prowlarr_timeout,
            transfer_timeout_seconds=args.document_download_timeout_seconds,
        )
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return 1
    finally:
        cleanup_report: list[dict[str, object]] = []
        for client_url, client_api_key, client_id in cleanup_download_clients:
            try:
                cleanup_report.append(delete_download_client(client_url, client_api_key, client_id))
            except Exception as exc:
                cleanup_report.append({"id": client_id, "status": "cleanup_failed", "error": str(exc)})
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if cleanup_report:
            report[PROWLARR_DOWNLOAD_CLIENT_CLEANUP_KEY] = cleanup_report
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
                report["cleanup"] = {"closed_app": True}
            except Exception as exc:
                report["cleanup"] = {"closed_app": False, "error": str(exc)}
                if report.get("status") == "passed":
                    report["status"] = "failed"
        live_common.write_json(result_path, report)
        paths.run_report_dir.parent.mkdir(parents=True, exist_ok=True)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
        print(f"Prowlarr eMuleBB live test {report['status']}. Report directory: {paths.run_report_dir}")


if __name__ == "__main__":
    raise SystemExit(main())
