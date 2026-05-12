"""Runs a live Radarr movie download check through Prowlarr and eMule BB."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
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

SYNTHETIC_TRIGGER_MAGNET = (
    "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000"
    "&dn=eMuleBB-Live-Wire-Trigger.bin"
    "&xl=1048576"
)
LIVE_SOURCE_UNAVAILABLE_EXIT_CODE = 2
TORZNAB_MOVIE_CATEGORY = 2000
TORZNAB_TV_CATEGORY = 5000
RADARR_IMPORT_CATEGORY = "radarr_movies_cat"
SONARR_IMPORT_CATEGORY = "sonarr_series_cat"
RADARR_DOWNLOAD_PROOF_CHECK_KEY = "radarr_movie_download_e2e"
SONARR_DOWNLOAD_PROOF_CHECK_KEY = "sonarr_series_download_e2e"
ARR_DOWNLOAD_CLIENT_CLEANUP_KEY = "cleanup_download_clients"
ARR_INDEXER_RESTORE_KEY = "cleanup_indexer_restore"
DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS = 60.0
DEFAULT_SEARCH_TIMEOUT_SECONDS = 90.0
DEFAULT_MEDIA_ACQUISITION_TIMEOUT_MINUTES = 30.0
DEFAULT_SHARED_HASH_IDLE_TIMEOUT_SECONDS = 60.0
ARR_LIVE_SEARCH_TIMEOUT_SECONDS = DEFAULT_SEARCH_TIMEOUT_SECONDS
DEFAULT_MEDIA_QUALITY_PROFILE_NAME = "AnyAnyLang"
MIN_ARR_RELEASE_SOURCES = 10
MIN_ARR_RELEASE_TITLE_MATCH_SCORE = 150
SONARR_EPISODE_TITLE_PATTERNS = (
    re.compile(r"\bs\d{1,2}e\d{1,3}\b", re.IGNORECASE),
    re.compile(r"\b\d{1,2}x\d{1,3}\b", re.IGNORECASE),
    re.compile(r"\bseason[ ._-]?\d{1,2}[ ._-]?episode[ ._-]?\d{1,3}\b", re.IGNORECASE),
)


class LiveSearchUnavailableError(RuntimeError):
    """Raised when the live P2P network returns no usable search rows."""


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


prowlarr_live = load_local_module("prowlarr_emulebb_live", "prowlarr-emulebb-live.py")
harness_cli_common = prowlarr_live.harness_cli_common
rest_smoke = prowlarr_live.rest_smoke
live_common = prowlarr_live.live_common
live_wire_inputs = prowlarr_live.live_wire_inputs

QBIT_ROUTE_COMPLETENESS_SCENARIOS: tuple[dict[str, object], ...] = (
    {"name": "public_webapi_version", "method": "GET", "path": "/api/v2/app/webapiVersion", "auth": False, "expected_statuses": (200,)},
    {"name": "login", "method": "POST", "path": "/api/v2/auth/login", "auth": False, "form": {"username": "emule"}, "expected_statuses": (200,)},
    {"name": "app_version", "method": "GET", "path": "/api/v2/app/version", "expected_statuses": (200,)},
    {"name": "app_preferences", "method": "GET", "path": "/api/v2/app/preferences", "expected_statuses": (200,)},
    {"name": "categories", "method": "GET", "path": "/api/v2/torrents/categories", "expected_statuses": (200,)},
    {
        "name": "create_category",
        "method": "POST",
        "path": "/api/v2/torrents/createCategory",
        "form": {"category": "LIVE_WIRE_ROUTE_CHECK"},
        "expected_statuses": (200,),
    },
    {"name": "info", "method": "GET", "path": "/api/v2/torrents/info", "expected_statuses": (200,)},
    {
        "name": "properties_missing_transfer",
        "method": "GET",
        "path": f"/api/v2/torrents/properties?hash={rest_smoke.REST_SURFACE_MISSING_HASH}",
        "expected_statuses": (404,),
    },
    {
        "name": "files_missing_transfer",
        "method": "GET",
        "path": f"/api/v2/torrents/files?hash={rest_smoke.REST_SURFACE_MISSING_HASH}",
        "expected_statuses": (404,),
    },
    {"name": "add_invalid_link", "method": "POST", "path": "/api/v2/torrents/add", "form": {"urls": "not-a-download-link"}, "expected_statuses": (400,)},
    {"name": "delete_missing_transfer", "method": "POST", "path": "/api/v2/torrents/delete", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {
        "name": "set_category_missing_transfer",
        "method": "POST",
        "path": "/api/v2/torrents/setCategory",
        "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH, "category": "LIVE_WIRE_ROUTE_CHECK"},
        "expected_statuses": (400,),
    },
    {"name": "pause_missing_transfer", "method": "POST", "path": "/api/v2/torrents/pause", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {"name": "stop_missing_transfer", "method": "POST", "path": "/api/v2/torrents/stop", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {"name": "resume_missing_transfer", "method": "POST", "path": "/api/v2/torrents/resume", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {"name": "start_missing_transfer", "method": "POST", "path": "/api/v2/torrents/start", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {"name": "set_share_limits", "method": "POST", "path": "/api/v2/torrents/setShareLimits", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {"name": "top_priority", "method": "POST", "path": "/api/v2/torrents/topPrio", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH}, "expected_statuses": (200,)},
    {"name": "set_force_start", "method": "POST", "path": "/api/v2/torrents/setForceStart", "form": {"hashes": rest_smoke.REST_SURFACE_MISSING_HASH, "value": "false"}, "expected_statuses": (200,)},
)


def arr_request(
    arr_url: str,
    api_key: str,
    path: str,
    *,
    method: str = "GET",
    json_body: object | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Performs one Radarr/Sonarr API request without logging credentials."""

    data = None
    headers = {"X-Api-Key": api_key}
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(arr_url.rstrip("/") + path, data=data, method=method, headers=headers)
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
    """Returns the JSON payload from one successful Arr response."""

    status = int(result.get("status") or 0)
    if status < 200 or status >= 300:
        body = str(result.get("body_text") or "")
        raise RuntimeError(f"{description} failed with HTTP {status}: {body[:500]}")
    return result.get("json")


def arr_health_rows(arr_url: str, api_key: str) -> list[dict[str, Any]]:
    """Returns Arr health rows, treating a missing health endpoint as empty."""

    result = arr_request(arr_url, api_key, "/api/v3/health", timeout_seconds=30.0)
    status = int(result.get("status") or 0)
    if status == 404:
        return []
    payload = require_success(result, "Arr health")
    if not isinstance(payload, list):
        return []
    return [row for row in payload if isinstance(row, dict)]


def arr_indexer_unavailable_due_to_failures(health_rows: list[dict[str, Any]], indexer_name: str) -> bool:
    """Returns true when Arr health has quarantined the eMule BB indexer."""

    expected = indexer_name.lower()
    for row in health_rows:
        if str(row.get("source") or "") != "IndexerStatusCheck":
            continue
        message = str(row.get("message") or "").lower()
        if "unavailable due to failures" in message and expected in message:
            return True
    return False


def set_field_value(provider: dict[str, Any], field_name: str, value: object) -> None:
    """Updates one provider field by name."""

    fields = provider.get("fields")
    if not isinstance(fields, list):
        raise RuntimeError("Provider payload does not contain a fields array.")
    for field in fields:
        if isinstance(field, dict) and field.get("name") == field_name:
            field["value"] = value
            return
    raise RuntimeError(f"Provider payload is missing field: {field_name}")


def get_tag_id(prowlarr_url: str, api_key: str, label: str) -> int | None:
    """Returns a Prowlarr tag id by label when the tag exists."""

    tags = require_success(
        prowlarr_live.prowlarr_request(prowlarr_url, api_key, "/api/v1/tag"),
        "Prowlarr tag list",
    )
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, dict) and str(tag.get("label") or "").lower() == label.lower():
            return int(tag["id"])
    return None


def normalize_application_base_url(url: str) -> str:
    """Normalizes one Arr application URL for Prowlarr application matching."""

    return str(url or "").strip().rstrip("/").lower()


def get_application_field_value(application: dict[str, Any], field_name: str) -> object | None:
    """Returns one Prowlarr application field value by field name."""

    fields = application.get("fields")
    if not isinstance(fields, list):
        return None
    for field in fields:
        if isinstance(field, dict) and field.get("name") == field_name:
            return field.get("value")
    return None


def get_enabled_application_tag_ids_for_arr(prowlarr_url: str, api_key: str, arr_url: str) -> tuple[bool, list[int]]:
    """Returns enabled Prowlarr application tag ids matching one Arr base URL."""

    applications = require_success(
        prowlarr_live.prowlarr_request(prowlarr_url, api_key, "/api/v1/applications"),
        "Prowlarr application list",
    )
    if not isinstance(applications, list):
        return False, []

    target_url = normalize_application_base_url(arr_url)
    found = False
    tag_ids: set[int] = set()
    for application in applications:
        if not isinstance(application, dict) or not bool(application.get("enable")):
            continue
        base_url = get_application_field_value(application, "baseUrl")
        if normalize_application_base_url(str(base_url or "")) != target_url:
            continue
        found = True
        tags = application.get("tags")
        if isinstance(tags, list):
            for tag_id in tags:
                try:
                    tag_ids.add(int(tag_id))
                except (TypeError, ValueError):
                    continue
    return found, sorted(tag_ids)


def resolve_prowlarr_indexer_sync_tags(prowlarr_url: str, api_key: str, arr_url: str) -> list[int] | None:
    """Chooses Prowlarr-side indexer tags that keep the matching Arr app synced."""

    found_application, tag_ids = get_enabled_application_tag_ids_for_arr(prowlarr_url, api_key, arr_url)
    if found_application:
        return tag_ids
    eng_tag_id = get_tag_id(prowlarr_url, api_key, "eng")
    if eng_tag_id is not None:
        return [eng_tag_id]
    return None


def force_prowlarr_application_sync(prowlarr_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Starts and waits for a Prowlarr application-indexer sync command."""

    result = prowlarr_live.prowlarr_request(
        prowlarr_url,
        api_key,
        "/api/v1/command",
        method="POST",
        json_body={"name": "ApplicationIndexerSync", "forceSync": True},
    )
    command = require_success(result, "Prowlarr application indexer sync command")
    command_id = int(command.get("id") or 0) if isinstance(command, dict) else 0
    if command_id <= 0:
        return {"id": command_id, "status": "submitted_without_id"}

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = require_success(
            prowlarr_live.prowlarr_request(prowlarr_url, api_key, f"/api/v1/command/{command_id}"),
            "Prowlarr application indexer sync command status",
        )
        status = str(last.get("status") or "").lower() if isinstance(last, dict) else ""
        if status in ("completed", "failed"):
            return {"id": command_id, "status": status}
        time.sleep(2.0)
    return {"id": command_id, "status": "timeout", "last": last}


def wait_for_synced_indexer(arr_url: str, api_key: str, indexer_name: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until Radarr/Sonarr exposes the synced eMule BB indexer."""

    attempts: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        indexers = require_success(arr_request(arr_url, api_key, "/api/v3/indexer"), "Arr indexer list")
        if not isinstance(indexers, list):
            raise RuntimeError("Arr indexer list was not a list.")
        names = [str(indexer.get("name") or "") for indexer in indexers if isinstance(indexer, dict)]
        for indexer in indexers:
            if not isinstance(indexer, dict):
                continue
            name = str(indexer.get("name") or "")
            if indexer_name.lower() in name.lower() or "emule bb" in name.lower():
                return indexer
        attempts.append({"names": names})
        time.sleep(5.0)
    raise RuntimeError(f"Synced eMule BB indexer did not appear before timeout: {attempts!r}")


def is_arr_indexer_enabled(indexer: dict[str, Any]) -> bool:
    """Returns true when Radarr/Sonarr can use the synced indexer for manual search."""

    if indexer.get("enable") is False:
        return False
    search_flags = [
        indexer.get("enableAutomaticSearch"),
        indexer.get("enableInteractiveSearch"),
    ]
    present_search_flags = [flag for flag in search_flags if flag is not None]
    if present_search_flags:
        return all(flag is not False for flag in present_search_flags)
    if "enable" in indexer:
        return bool(indexer.get("enable"))
    return indexer.get("enableRss") is not False


def is_emulebb_indexer_name(indexer_name: str, configured_name: str) -> bool:
    """Returns true when one Arr indexer name belongs to the live eMule bridge."""

    name = indexer_name.lower()
    return configured_name.lower() in name or "emule bb" in name


def is_arr_validation_blocker(result: dict[str, Any]) -> bool:
    """Returns true when Arr rejected a provider save during live validation."""

    status = int(result.get("status") or 0)
    if status < 400 or status >= 500:
        return False
    body_text = str(result.get("body_text") or "").lower()
    return (
        "no results in the configured categories" in body_text
        or "no results were returned" in body_text
        or "unable to connect to indexer" in body_text
        or "toomanyrequests" in body_text
    )


def get_arr_torznab_schema(arr_url: str, api_key: str) -> dict[str, Any]:
    """Loads the Arr Torznab indexer schema used for API-only repair."""

    schemas = require_success(arr_request(arr_url, api_key, "/api/v3/indexer/schema"), "Arr indexer schema")
    if not isinstance(schemas, list):
        raise RuntimeError("Arr indexer schema response was not a list.")
    for schema in schemas:
        if isinstance(schema, dict) and schema.get("implementation") == "Torznab":
            return schema
    raise RuntimeError("Arr did not expose the Torznab indexer schema.")


def find_arr_emule_indexer(arr_url: str, api_key: str, indexer_name: str) -> dict[str, Any] | None:
    """Finds the current eMule BB Arr indexer provider when it exists."""

    for indexer in list_arr_indexers(arr_url, api_key):
        if is_emulebb_indexer_name(str(indexer.get("name") or ""), indexer_name):
            return indexer
    return None


def build_arr_emule_indexer_payload(
    base_payload: dict[str, Any],
    *,
    indexer_name: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    category_id: int,
    enabled: bool,
) -> dict[str, Any]:
    """Builds an Arr Torznab provider pointed at Prowlarr's eMule proxy."""

    payload = json.loads(json.dumps(base_payload))
    payload["name"] = indexer_name
    payload["implementation"] = "Torznab"
    payload["implementationName"] = "Torznab"
    payload["configContract"] = "TorznabSettings"
    payload["protocol"] = "torrent"
    payload["priority"] = int(payload.get("priority") or 25)
    payload["downloadClientId"] = int(payload.get("downloadClientId") or 0)
    payload["tags"] = []
    if "enable" in payload:
        payload["enable"] = bool(enabled)
    payload["enableRss"] = False
    payload["enableAutomaticSearch"] = bool(enabled)
    payload["enableInteractiveSearch"] = bool(enabled)
    set_field_value(payload, "baseUrl", prowlarr_url.rstrip("/") + f"/{int(prowlarr_indexer_id)}/")
    set_field_value(payload, "apiPath", "/api")
    set_field_value(payload, "apiKey", prowlarr_api_key)
    set_field_value(payload, "categories", [int(category_id)])
    return payload


def save_arr_indexer_payload(
    arr_url: str,
    api_key: str,
    payload: dict[str, Any],
    *,
    existing_id: int | None,
    description: str,
) -> dict[str, Any]:
    """Saves one Arr indexer payload and returns the persisted provider."""

    if existing_id is not None and existing_id > 0:
        path = f"/api/v3/indexer/{existing_id}?forceSave=true"
        method = "PUT"
    else:
        path = "/api/v3/indexer?forceSave=true"
        method = "POST"
    result = arr_request(arr_url, api_key, path, method=method, json_body=payload, timeout_seconds=60.0)
    saved = require_success(result, description)
    if not isinstance(saved, dict) or int(saved.get("id") or 0) <= 0:
        raise RuntimeError(f"{description} did not return a saved indexer id.")
    return saved


def delete_arr_indexer_provider(arr_url: str, api_key: str, indexer_id: int) -> dict[str, object]:
    """Deletes one Arr indexer provider through the public Arr API."""

    result = arr_request(arr_url, api_key, f"/api/v3/indexer/{indexer_id}", method="DELETE", timeout_seconds=60.0)
    status = int(result.get("status") or 0)
    if status != 404 and (status < 200 or status >= 300):
        require_success(result, "Arr eMule BB indexer delete")
    return {"id": int(indexer_id), "status": status}


def save_enabled_arr_emule_indexer_with_validation_retry(
    *,
    arr_url: str,
    api_key: str,
    base_payload: dict[str, Any],
    existing_id: int | None,
    indexer_name: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    category_id: int,
) -> tuple[dict[str, Any], dict[str, object]]:
    """Saves the eMule BB Arr provider, retrying disabled-then-enabled on validation-only blockers."""

    payload = build_arr_emule_indexer_payload(
        base_payload,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=category_id,
        enabled=True,
    )

    result = arr_request(
        arr_url,
        api_key,
        f"/api/v3/indexer/{existing_id}?forceSave=true" if existing_id else "/api/v3/indexer?forceSave=true",
        method="PUT" if existing_id else "POST",
        json_body=payload,
        timeout_seconds=60.0,
    )
    status = int(result.get("status") or 0)
    if status >= 200 and status < 300:
        saved = result.get("json")
        if not isinstance(saved, dict) or int(saved.get("id") or 0) <= 0:
            raise RuntimeError("Arr eMule BB indexer repair did not return a saved indexer id.")
        return saved, {
            "mode": "updated" if existing_id else "created",
            "validation_retry": False,
            "category": int(category_id),
            "status": status,
        }

    if not is_arr_validation_blocker(result):
        require_success(result, "Arr eMule BB indexer repair")

    disabled_payload = build_arr_emule_indexer_payload(
        base_payload,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=category_id,
        enabled=False,
    )
    disabled_saved = save_arr_indexer_payload(
        arr_url,
        api_key,
        disabled_payload,
        existing_id=existing_id,
        description="Arr disabled eMule BB indexer repair",
    )
    enabled_payload = build_arr_emule_indexer_payload(
        disabled_saved,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=category_id,
        enabled=True,
    )
    enabled_saved = save_arr_indexer_payload(
        arr_url,
        api_key,
        enabled_payload,
        existing_id=int(disabled_saved["id"]),
        description="Arr enabled eMule BB indexer repair",
    )
    return enabled_saved, {
        "mode": "updated" if existing_id else "created",
        "validation_retry": True,
        "category": int(category_id),
        "initial_status": status,
        "disabled_id": int(disabled_saved["id"]),
    }


def recreate_arr_emule_indexer_if_unavailable(
    *,
    arr_url: str,
    api_key: str,
    indexer: dict[str, Any],
    indexer_name: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    category_id: int,
) -> tuple[dict[str, Any], dict[str, object]]:
    """Recreates the eMule BB provider when Arr health has quarantined its status."""

    health = arr_health_rows(arr_url, api_key)
    messages = [
        str(row.get("message") or "")
        for row in health
        if str(row.get("source") or "") == "IndexerStatusCheck"
    ]
    if not arr_indexer_unavailable_due_to_failures(health, indexer_name):
        return indexer, {"unavailable_due_to_failures": False, "indexer_status_messages": messages}

    old_id = int(indexer.get("id") or 0)
    if old_id <= 0:
        raise RuntimeError("Arr eMule BB indexer cannot be recreated because it has no provider id.")

    delete_summary = delete_arr_indexer_provider(arr_url, api_key, old_id)
    schema = get_arr_torznab_schema(arr_url, api_key)
    recreated, save_summary = save_enabled_arr_emule_indexer_with_validation_retry(
        arr_url=arr_url,
        api_key=api_key,
        base_payload=schema,
        existing_id=None,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=category_id,
    )
    return recreated, {
        "unavailable_due_to_failures": True,
        "mode": "recreated",
        "old_id": old_id,
        "new_id": int(recreated.get("id") or 0),
        "delete": delete_summary,
        "save": save_summary,
        "indexer_status_messages": messages,
    }


def ensure_arr_emule_indexer(
    *,
    arr_url: str,
    api_key: str,
    indexer_name: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    category_id: int,
) -> tuple[dict[str, Any], dict[str, object]]:
    """Repairs or creates the Arr eMule BB provider using public Arr APIs."""

    existing = find_arr_emule_indexer(arr_url, api_key, indexer_name)
    base_payload = existing if existing is not None else get_arr_torznab_schema(arr_url, api_key)
    existing_id = int(existing.get("id") or 0) if existing is not None else None
    return save_enabled_arr_emule_indexer_with_validation_retry(
        arr_url=arr_url,
        api_key=api_key,
        base_payload=base_payload,
        existing_id=existing_id,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=category_id,
    )


def ensure_arr_indexer_enabled(arr_url: str, api_key: str, indexer: dict[str, Any]) -> tuple[dict[str, Any], dict[str, object]]:
    """Ensures the synced Arr indexer is enabled before release-search proof."""

    indexer_id = int(indexer.get("id") or 0)
    if indexer_id <= 0:
        raise RuntimeError("Synced Arr indexer did not include a valid id.")
    if is_arr_indexer_enabled(indexer):
        return indexer, {"changed": False, "status": "already_enabled"}

    payload = json.loads(json.dumps(indexer))
    if "enable" in payload:
        payload["enable"] = True
    if "enableRss" in payload:
        payload["enableRss"] = False
    for flag_name in ("enableAutomaticSearch", "enableInteractiveSearch"):
        if flag_name in payload:
            payload[flag_name] = True
    result = arr_request(
        arr_url,
        api_key,
        f"/api/v3/indexer/{indexer_id}?forceSave=true",
        method="PUT",
        json_body=payload,
        timeout_seconds=60.0,
    )
    saved = require_success(result, "Arr eMule BB synced indexer enable")
    if not isinstance(saved, dict) or int(saved.get("id") or 0) != indexer_id:
        raise RuntimeError("Arr did not return the enabled synced indexer.")
    if not is_arr_indexer_enabled(saved):
        raise RuntimeError("Arr returned the synced indexer but it is still disabled.")
    return saved, {"changed": True, "status": int(result.get("status") or 0)}


def ensure_arr_indexer_untagged(arr_url: str, api_key: str, indexer: dict[str, Any]) -> tuple[dict[str, Any], dict[str, object]]:
    """Ensures the live synced Arr indexer is eligible for untagged temporary media."""

    indexer_id = int(indexer.get("id") or 0)
    if indexer_id <= 0:
        raise RuntimeError("Synced Arr indexer did not include a valid id.")
    existing_tags = indexer.get("tags")
    if not existing_tags:
        return indexer, {"changed": False, "status": "already_untagged"}

    payload = json.loads(json.dumps(indexer))
    payload["tags"] = []
    result = arr_request(
        arr_url,
        api_key,
        f"/api/v3/indexer/{indexer_id}?forceSave=true",
        method="PUT",
        json_body=payload,
        timeout_seconds=60.0,
    )
    saved = require_success(result, "Arr eMule BB synced indexer tag clear")
    if not isinstance(saved, dict) or int(saved.get("id") or 0) != indexer_id:
        raise RuntimeError("Arr did not return the untagged synced indexer.")
    if saved.get("tags"):
        raise RuntimeError("Arr returned the synced indexer but it still has tags.")
    return saved, {"changed": True, "previous_tag_count": len(existing_tags) if isinstance(existing_tags, list) else None, "status": int(result.get("status") or 0)}


def list_arr_indexers(arr_url: str, api_key: str) -> list[dict[str, Any]]:
    """Returns the configured Arr indexers as mutable JSON objects."""

    payload = require_success(arr_request(arr_url, api_key, "/api/v3/indexer"), "Arr indexer list")
    if not isinstance(payload, list):
        raise RuntimeError("Arr indexer list was not a list.")
    return [indexer for indexer in payload if isinstance(indexer, dict)]


def list_arr_download_clients(arr_url: str, api_key: str) -> list[dict[str, Any]]:
    """Returns configured Arr download clients."""

    payload = require_success(arr_request(arr_url, api_key, "/api/v3/downloadclient"), "Arr download client list")
    if not isinstance(payload, list):
        raise RuntimeError("Arr download client list was not a list.")
    return [client for client in payload if isinstance(client, dict)]


def delete_stale_live_download_clients(arr_url: str, api_key: str, *, kind: str) -> list[dict[str, object]]:
    """Removes stale live-test download clients left by interrupted runs."""

    prefix = f"eMule BB Live {kind} "
    removed: list[dict[str, object]] = []
    for client in list_arr_download_clients(arr_url, api_key):
        client_id = int(client.get("id") or 0)
        client_name = str(client.get("name") or "")
        if client_id <= 0 or not client_name.startswith(prefix):
            continue
        removed.append(delete_download_client(arr_url, api_key, client_id))
    return removed


def set_arr_indexer_search_state(arr_url: str, api_key: str, indexer: dict[str, Any], enabled: bool) -> dict[str, object]:
    """Sets the Arr search enable flags for one indexer and returns a compact result."""

    indexer_id = int(indexer.get("id") or 0)
    if indexer_id <= 0:
        raise RuntimeError("Arr indexer payload did not include a valid id.")
    payload = json.loads(json.dumps(indexer))
    if "enable" in payload:
        payload["enable"] = bool(enabled)
    if "enableRss" in payload:
        payload["enableRss"] = False
    for flag_name in ("enableAutomaticSearch", "enableInteractiveSearch"):
        if flag_name in payload:
            payload[flag_name] = bool(enabled)
    result = arr_request(
        arr_url,
        api_key,
        f"/api/v3/indexer/{indexer_id}?forceSave=true",
        method="PUT",
        json_body=payload,
        timeout_seconds=60.0,
    )
    require_success(result, "Arr indexer search-state update")
    return {"id": indexer_id, "enabled": bool(enabled), "status": int(result.get("status") or 0)}


def isolate_arr_indexer_search(arr_url: str, api_key: str, allowed_indexer_id: int) -> tuple[list[dict[str, Any]], list[dict[str, object]]]:
    """Temporarily leaves only the eMule BB indexer searchable for Arr release queries."""

    snapshots = list_arr_indexers(arr_url, api_key)
    changes: list[dict[str, object]] = []
    for indexer in snapshots:
        indexer_id = int(indexer.get("id") or 0)
        if indexer_id <= 0:
            continue
        desired_enabled = indexer_id == int(allowed_indexer_id)
        current_enabled = is_arr_indexer_enabled(indexer)
        if current_enabled != desired_enabled or desired_enabled:
            changes.append(set_arr_indexer_search_state(arr_url, api_key, indexer, desired_enabled))
    return snapshots, changes


def restore_arr_indexers(arr_url: str, api_key: str, snapshots: list[dict[str, Any]]) -> list[dict[str, object]]:
    """Restores Arr indexers captured before live search isolation."""

    restored: list[dict[str, object]] = []
    for snapshot in snapshots:
        indexer_id = int(snapshot.get("id") or 0)
        if indexer_id <= 0:
            continue
        result = arr_request(
            arr_url,
            api_key,
            f"/api/v3/indexer/{indexer_id}?forceSave=true",
            method="PUT",
            json_body=snapshot,
            timeout_seconds=60.0,
        )
        restored.append({"id": indexer_id, "status": int(result.get("status") or 0)})
        require_success(result, "Arr indexer restore")
    return restored


def delete_all_emule_searches(base_url: str, api_key: str) -> dict[str, object]:
    """Clears existing eMule search tabs before media acquisition starts."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/searches",
        method="DELETE",
        api_key=api_key,
        json_body={"confirmDeleteAllSearches": True},
        request_timeout_seconds=20.0,
    )
    payload = rest_smoke.require_json_object(result, 200)
    return {
        "status": int(result.get("status") or 0),
        "ok": bool(payload.get("ok", True)),
    }


def list_emule_searches(base_url: str, api_key: str) -> dict[str, object]:
    """Returns a compact search-tab summary without exposing query text."""

    result = rest_smoke.http_request(base_url, "/api/v1/searches", api_key=api_key, request_timeout_seconds=20.0)
    rows = rest_smoke.require_json_array(result, 200)
    return {
        "status": int(result.get("status") or 0),
        "count": len(rows),
        "query_present_count": sum(1 for row in rows if isinstance(row, dict) and bool(row.get("query"))),
    }


def get_qbit_schema(arr_url: str, api_key: str) -> dict[str, Any]:
    """Loads the qBittorrent download-client schema from Radarr/Sonarr."""

    schemas = require_success(arr_request(arr_url, api_key, "/api/v3/downloadclient/schema"), "Arr download client schema")
    if not isinstance(schemas, list):
        raise RuntimeError("Arr download client schema response was not a list.")
    for schema in schemas:
        if isinstance(schema, dict) and schema.get("implementation") == "QBittorrent":
            return schema
    raise RuntimeError("Arr did not expose the qBittorrent download client schema.")


def get_provider_field_names(provider: dict[str, Any]) -> set[str]:
    """Returns provider field names from one Arr schema or saved provider."""

    fields = provider.get("fields")
    if not isinstance(fields, list):
        return set()
    return {
        str(field.get("name"))
        for field in fields
        if isinstance(field, dict) and isinstance(field.get("name"), str)
    }


def summarize_qbit_schema(schema: dict[str, Any], *, category_field: str) -> dict[str, object]:
    """Builds a report-safe qBittorrent schema readiness summary."""

    field_names = get_provider_field_names(schema)
    required_fields = {"host", "port", "username", "password", "initialState", category_field}
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


def build_qbit_client_payload(
    schema: dict[str, Any],
    *,
    name: str,
    host: str,
    port: int,
    api_key: str,
    category_field: str,
    category: str,
) -> dict[str, Any]:
    """Builds a temporary qBittorrent client payload for eMule BB."""

    schema_summary = summarize_qbit_schema(schema, category_field=category_field)
    if not bool(schema_summary["ok"]):
        raise RuntimeError(f"Arr qBittorrent schema is missing required fields: {schema_summary['missing_required_fields']!r}")

    payload = json.loads(json.dumps(schema))
    payload["name"] = name
    payload["enable"] = True
    payload["priority"] = int(payload.get("priority") or 1)
    payload["implementation"] = "QBittorrent"
    payload["implementationName"] = "qBittorrent"
    payload["configContract"] = "QBittorrentSettings"
    payload["protocol"] = "torrent"
    payload["removeCompletedDownloads"] = False
    payload["removeFailedDownloads"] = False
    set_field_value(payload, "host", host)
    set_field_value(payload, "port", port)
    set_field_value(payload, "useSsl", False)
    set_field_value(payload, "urlBase", "")
    set_field_value(payload, "username", "emule")
    set_field_value(payload, "password", api_key)
    set_field_value(payload, category_field, category)
    set_field_value(payload, "initialState", 0)
    return payload


def create_temp_qbit_client(
    arr_url: str,
    api_key: str,
    *,
    name: str,
    host: str,
    port: int,
    emule_api_key: str,
    category_field: str,
    category: str,
) -> dict[str, Any]:
    """Creates a temporary qBittorrent client and validates it."""

    created_client_id: int | None = None
    schema = get_qbit_schema(arr_url, api_key)
    schema_summary = summarize_qbit_schema(schema, category_field=category_field)
    payload = build_qbit_client_payload(
        schema,
        name=name,
        host=host,
        port=port,
        api_key=emule_api_key,
        category_field=category_field,
        category=category,
    )
    try:
        created = require_success(
            arr_request(arr_url, api_key, "/api/v3/downloadclient?forceSave=true", method="POST", json_body=payload),
            "Arr eMule BB qBittorrent client create",
        )
        if not isinstance(created, dict) or not created.get("id"):
            raise RuntimeError("Arr did not return a created qBittorrent client id.")
        created_client_id = int(created["id"])

        test_payload = json.loads(json.dumps(created))
        test_result = arr_request(arr_url, api_key, "/api/v3/downloadclient/test", method="POST", json_body=test_payload, timeout_seconds=60.0)
        require_success(test_result, "Arr eMule BB qBittorrent client test")
        created["_emulebbSchemaSummary"] = schema_summary
        created["_emulebbTestStatus"] = int(test_result.get("status") or 0)
        return created
    except Exception as exc:
        if created_client_id is not None:
            try:
                delete_download_client(arr_url, api_key, created_client_id)
            except Exception as cleanup_exc:
                if hasattr(exc, "add_note"):
                    exc.add_note(f"Temporary Arr download client cleanup failed: {cleanup_exc}")
        raise


def summarize_arr_indexer(indexer: dict[str, Any]) -> dict[str, object]:
    """Builds a compact readiness summary for one synced Arr indexer."""

    return {
        "id": int(indexer.get("id") or 0),
        "name": indexer.get("name"),
        "implementation": indexer.get("implementation"),
        "enable": is_arr_indexer_enabled(indexer),
        "enableRss": indexer.get("enableRss"),
        "enableAutomaticSearch": indexer.get("enableAutomaticSearch"),
        "enableInteractiveSearch": indexer.get("enableInteractiveSearch"),
        "protocol": indexer.get("protocol"),
        "priority": indexer.get("priority"),
        "tag_count": len(indexer.get("tags") or []) if isinstance(indexer.get("tags"), list) else None,
    }


def summarize_arr_download_client(client: dict[str, Any], *, category: str) -> dict[str, object]:
    """Builds a compact readiness summary for the temporary Arr qBit client."""

    return {
        "id": int(client["id"]),
        "name": client.get("name"),
        "implementation": client.get("implementation"),
        "protocol": client.get("protocol"),
        "enable": bool(client.get("enable")),
        "category": category,
        "schema": client.get("_emulebbSchemaSummary"),
        "test_status": client.get("_emulebbTestStatus"),
    }


def require_radarr_import_movie_terms(inputs: Any) -> tuple[str, ...]:
    """Returns operator-configured Radarr import candidates from live-wire inputs."""

    terms = tuple(str(term).strip() for term in inputs.radarr_movie_terms if str(term).strip())
    if not terms:
        raise RuntimeError("live-wire inputs field 'search_terms.radarr_movies' must include a Radarr import title.")
    return terms


def require_sonarr_import_series_terms(inputs: Any) -> tuple[str, ...]:
    """Returns operator-configured Sonarr import candidates from live-wire inputs."""

    terms = tuple(str(term).strip() for term in inputs.sonarr_series_terms if str(term).strip())
    if not terms:
        raise RuntimeError("live-wire inputs field 'search_terms.sonarr_series' must include a Sonarr import title.")
    return terms


def is_emulebb_arr_release(row: dict[str, Any], indexer_id: int) -> bool:
    """Returns true when an Arr release row belongs to the eMule BB indexer."""

    return int(row.get("indexerId") or 0) == indexer_id or "emule bb" in str(row.get("indexer") or "").lower()


def arr_release_size_bytes(row: dict[str, Any]) -> int | None:
    """Returns the positive release size from an Arr/Prowlarr release row."""

    for key in ("size", "sizeBytes"):
        if row.get(key) is None:
            continue
        try:
            size = int(row.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if size > 0:
            return size
    return None


def parse_torznab_int(value: object) -> int:
    """Parses a non-negative Torznab integer field."""

    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def parse_direct_torznab_release_rows(body_text: str) -> list[dict[str, Any]]:
    """Parses direct eMule Torznab rows with source-count fields preserved."""

    if not body_text:
        return []
    root = ET.fromstring(body_text)
    rows: list[dict[str, Any]] = []
    for item in root.findall("./channel/item"):
        row: dict[str, Any] = {
            "title": item.findtext("title") or "",
            "guid": item.findtext("guid") or "",
            "downloadUrl": item.findtext("link") or "",
        }
        enclosure = item.find("enclosure")
        if enclosure is not None:
            if not row["downloadUrl"]:
                row["downloadUrl"] = enclosure.attrib.get("url") or ""
            row["size"] = parse_torznab_int(enclosure.attrib.get("length"))
        for child in list(item):
            if not child.tag.endswith("attr"):
                continue
            name = child.attrib.get("name")
            if not name:
                continue
            value = child.attrib.get("value")
            if name in {"size", "seeders", "peers", "grabs", "sources", "sourceCount"}:
                row[name] = parse_torznab_int(value)
            elif name in {"magneturl", "infohash"}:
                row[name] = value or ""
        row["sources"] = max(
            parse_torznab_int(row.get("sources")),
            parse_torznab_int(row.get("sourceCount")),
            parse_torznab_int(row.get("seeders")),
            parse_torznab_int(row.get("peers")),
        )
        rows.append(row)
    return rows


def direct_torznab_source_rows(
    emule_base_url: str,
    emule_api_key: str,
    query: str,
    category_id: int,
    timeout_seconds: float,
) -> tuple[list[dict[str, Any]], dict[str, object]]:
    """Fetches direct eMule Torznab rows for source-count enrichment."""

    result = rest_smoke.http_request(
        emule_base_url,
        prowlarr_live.build_direct_torznab_search_path(emule_api_key, query, category_id),
        request_timeout_seconds=max(1.0, min(90.0, timeout_seconds)),
    )
    status = int(result.get("status") or 0)
    rows = parse_direct_torznab_release_rows(str(result.get("body_text") or "")) if status == 200 else []
    return rows, {
        "status": status,
        "count": len(rows),
        "max_sources": max((prowlarr_live.release_source_count(row) for row in rows), default=0),
    }


def release_match_key(row: dict[str, Any]) -> tuple[str, int]:
    """Builds a report-safe release key for matching direct Torznab and Arr rows."""

    return (prowlarr_live.normalized_match_text(row.get("title") or row.get("name")), int(arr_release_size_bytes(row) or 0))


def enrich_arr_release_sources(rows: list[dict[str, Any]], source_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Copies direct eMule source counts onto matching Arr release rows."""

    source_by_key: dict[tuple[str, int], int] = {}
    for source_row in source_rows:
        source_count = prowlarr_live.release_source_count(source_row)
        if source_count <= 0:
            continue
        key = release_match_key(source_row)
        if key[0] and key[1] > 0:
            source_by_key[key] = max(source_by_key.get(key, 0), source_count)

    enriched: list[dict[str, Any]] = []
    enriched_count = 0
    for row in rows:
        copied = json.loads(json.dumps(row))
        if prowlarr_live.release_source_count(copied) <= 0:
            source_count = source_by_key.get(release_match_key(copied), 0)
            if source_count > 0:
                copied["sources"] = source_count
                copied["sourceCount"] = source_count
                copied["_emulebbSourceEnriched"] = True
                enriched_count += 1
        enriched.append(copied)
    return enriched, enriched_count


def sonarr_release_title_is_episode_like(row: dict[str, Any]) -> bool:
    """Returns true when a release title contains a parseable episode marker."""

    title = str(row.get("title") or row.get("name") or "")
    return any(pattern.search(title) for pattern in SONARR_EPISODE_TITLE_PATTERNS)


def sonarr_release_title_matches_series_episode(row: dict[str, Any], query: str) -> bool:
    """Rejects broad-series false positives where another series name appears before the episode marker."""

    title_text = prowlarr_live.normalized_match_text(row.get("title") or row.get("name"))
    query_text = prowlarr_live.normalized_match_text(query)
    title_tokens = title_text.split()
    query_tokens = query_text.split()
    if not title_tokens or not query_tokens or title_tokens[: len(query_tokens)] != query_tokens:
        return False
    if len(title_tokens) <= len(query_tokens):
        return False
    next_token = title_tokens[len(query_tokens)]
    if re.fullmatch(r"s\d{1,2}e\d{1,3}", next_token, re.IGNORECASE):
        return True
    if re.fullmatch(r"\d{1,2}x\d{1,3}", next_token, re.IGNORECASE):
        return True
    if next_token == "season" and len(title_tokens) > len(query_tokens) + 2:
        return title_tokens[len(query_tokens) + 2] == "episode"
    return False


def rank_arr_releases(
    rows: list[dict[str, Any]],
    query: str,
    *,
    min_sources: int = MIN_ARR_RELEASE_SOURCES,
    require_episode_like: bool = False,
) -> list[dict[str, Any]]:
    """Ranks manual Arr releases by the live acquisition policy."""

    candidates = []
    for index, row in enumerate(rows):
        title_score = prowlarr_live.release_title_match_score(row, query)
        size = arr_release_size_bytes(row)
        if (
            prowlarr_live.release_source_count(row) >= min_sources
            and size is not None
            and title_score >= MIN_ARR_RELEASE_TITLE_MATCH_SCORE
            and (
                not require_episode_like
                or (sonarr_release_title_is_episode_like(row) and sonarr_release_title_matches_series_episode(row, query))
            )
        ):
            candidates.append(
                (
                    size,
                    -title_score,
                    -prowlarr_live.release_source_count(row),
                    index,
                    json.loads(json.dumps(row)),
                )
            )
    candidates.sort()
    return [candidate[4] for candidate in candidates]


def select_best_arr_release(
    rows: list[dict[str, Any]],
    query: str,
    *,
    min_sources: int = MIN_ARR_RELEASE_SOURCES,
    require_episode_like: bool = False,
) -> dict[str, Any]:
    """Selects the smallest manual Arr release with enough sources and a matching title."""

    if not rows:
        raise RuntimeError("Arr release selection requires at least one row.")
    ranked = rank_arr_releases(rows, query, min_sources=min_sources, require_episode_like=require_episode_like)
    if ranked:
        return ranked[0]
    max_sources = max((prowlarr_live.release_source_count(row) for row in rows), default=0)
    max_title_score = max((prowlarr_live.release_title_match_score(row, query) for row in rows), default=0)
    episode_requirement = " and an episode-like title" if require_episode_like else ""
    raise RuntimeError(
        f"Arr release selection found no release with at least {min_sources} sources, "
        f"a positive size, a title match score of at least {MIN_ARR_RELEASE_TITLE_MATCH_SCORE}{episode_requirement}. "
        f"Rows={len(rows)}, max_sources={max_sources}, max_title_match_score={max_title_score}."
    )


def summarize_arr_release_indexers(rows: list[Any], limit: int = 8) -> list[dict[str, object]]:
    """Summarizes release indexer identities without exposing release titles."""

    seen: set[tuple[int, str]] = set()
    samples: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        indexer_id = int(row.get("indexerId") or 0)
        indexer_name = str(row.get("indexer") or "")
        key = (indexer_id, indexer_name)
        if key in seen:
            continue
        seen.add(key)
        samples.append(
            {
                "indexerId": indexer_id,
                "indexer_present": bool(indexer_name),
                "indexer_contains_emulebb": "emule bb" in indexer_name.lower(),
            }
        )
        if len(samples) >= limit:
            break
    return samples


def build_torznab_search_path(category_id: int, query: str, emule_api_key: str, *, request_type: str = "search") -> str:
    """Builds one direct Torznab search URL using an explicit media category."""

    return (
        f"/indexer/emulebb/api?t={request_type}&cat={category_id}&q="
        + urllib.parse.quote(query)
        + "&apikey="
        + urllib.parse.quote(emule_api_key)
    )


def delete_download_client(arr_url: str, api_key: str, client_id: int) -> dict[str, object]:
    """Deletes one temporary Arr download client."""

    result = arr_request(arr_url, api_key, f"/api/v3/downloadclient/{client_id}", method="DELETE")
    return {"id": client_id, "status": int(result.get("status") or 0)}


def delete_radarr_movie(arr_url: str, api_key: str, movie_id: int) -> dict[str, object]:
    """Deletes one temporary Radarr movie without deleting local media files."""

    result = arr_request(arr_url, api_key, f"/api/v3/movie/{movie_id}?deleteFiles=false&addImportExclusion=false", method="DELETE")
    return {"id": movie_id, "status": int(result.get("status") or 0)}


def resolve_radarr_root_path(root_path: Path | str, *, create_local_path: bool) -> str:
    """Returns the Radarr root folder path, optionally creating local roots."""

    if create_local_path:
        local_path = Path(root_path)
        local_path.mkdir(parents=True, exist_ok=True)
        return str(local_path.resolve())
    path_text = str(root_path).strip()
    if not path_text:
        raise RuntimeError("Radarr movie root path must not be empty.")
    return path_text


def build_radarr_root_environment_warning(radarr_url: str, root_path: Path | str, *, create_local_path: bool) -> dict[str, object] | None:
    """Builds a non-failing warning when the root path may not be visible to Radarr."""

    hostname = urllib.parse.urlparse(radarr_url).hostname or ""
    is_remote_arr = bool(hostname) and hostname.lower() not in {"localhost", "127.0.0.1", "::1"}
    path_text = str(root_path)
    looks_windows_local = (len(path_text) >= 3 and path_text[1:3] in {":\\", ":/"}) or path_text.startswith("\\\\")
    if is_remote_arr and (create_local_path or looks_windows_local):
        return {
            "remote_arr_url": True,
            "local_or_windows_root": True,
            "root_path_present": bool(path_text.strip()),
            "message": "Radarr is not local; ensure the configured movie root is visible from the Radarr host/container.",
        }
    return None


def build_arr_root_environment_warning(arr_url: str, root_path: Path | str, *, create_local_path: bool, kind: str) -> dict[str, object] | None:
    """Builds a non-failing warning when the root path may not be visible to the Arr host."""

    warning = build_radarr_root_environment_warning(arr_url, root_path, create_local_path=create_local_path)
    if warning is not None:
        warning["arr_kind"] = kind
    return warning


def ensure_emule_category(base_url: str, api_key: str, name: str, path: Path) -> dict[str, object]:
    """Ensures eMule has one named category with a dedicated incoming path."""

    path.mkdir(parents=True, exist_ok=True)
    path_text = str(path.resolve())
    categories = rest_smoke.http_request(base_url, "/api/v1/categories", api_key=api_key)
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


def first_arr_row(result: dict[str, Any], description: str) -> dict[str, Any]:
    """Returns the first object row from one Arr list response."""

    rows = require_success(result, description)
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise RuntimeError(f"{description} did not return any rows.")
    return rows[0]


def summarize_quality_profile(profile: dict[str, Any], preferred_name: str | None) -> dict[str, object]:
    """Returns the report-safe identity of one Arr quality profile."""

    return {
        "id": int(profile.get("id") or 0),
        "name": profile.get("name"),
        "preferred_name": preferred_name,
    }


def get_quality_profile(arr_url: str, api_key: str, kind: str, preferred_name: str | None = None) -> dict[str, Any]:
    """Returns the configured quality profile, preferring an operator-provided name."""

    profiles = require_success(arr_request(arr_url, api_key, "/api/v3/qualityprofile"), f"{kind} quality profiles")
    if not isinstance(profiles, list) or not profiles:
        raise RuntimeError(f"{kind} quality profile list did not return rows.")
    if preferred_name:
        for profile in profiles:
            if isinstance(profile, dict) and str(profile.get("name") or "").strip().lower() == preferred_name.strip().lower():
                profile_id = int(profile.get("id") or 0)
                if profile_id > 0:
                    return profile
        raise RuntimeError(f"{kind} quality profile {preferred_name!r} was not found.")
    for profile in profiles:
        if isinstance(profile, dict):
            profile_id = int(profile.get("id") or 0)
            if profile_id > 0:
                return profile
    raise RuntimeError(f"{kind} quality profiles did not include a valid id.")


def get_quality_profile_id(arr_url: str, api_key: str, kind: str, preferred_name: str | None = None) -> int:
    """Returns the configured quality profile id, preferring an operator-provided name."""

    return int(get_quality_profile(arr_url, api_key, kind, preferred_name).get("id") or 0)


def ensure_radarr_root_folder(
    arr_url: str,
    api_key: str,
    root_path: Path | str,
    *,
    create_local_path: bool = True,
) -> dict[str, object]:
    """Ensures Radarr can use one local root folder for import verification."""

    path_text = resolve_radarr_root_path(root_path, create_local_path=create_local_path)
    roots = require_success(arr_request(arr_url, api_key, "/api/v3/rootfolder"), "Radarr root folders")
    if isinstance(roots, list):
        for root in roots:
            if isinstance(root, dict) and str(root.get("path") or "").lower() == path_text.lower():
                return {"id": int(root.get("id") or 0), "path": root.get("path"), "created": False}
    created = require_success(
        arr_request(arr_url, api_key, "/api/v3/rootfolder", method="POST", json_body={"path": path_text}),
        "Radarr root folder create",
    )
    if not isinstance(created, dict):
        raise RuntimeError("Radarr root folder create did not return an object.")
    return {"id": int(created.get("id") or 0), "path": created.get("path"), "created": True}


def lookup_radarr_movie(arr_url: str, api_key: str, title: str) -> dict[str, Any]:
    """Looks up one Radarr movie by title."""

    rows = require_success(
        arr_request(arr_url, api_key, "/api/v3/movie/lookup?term=" + urllib.parse.quote(title), timeout_seconds=60.0),
        "Radarr movie lookup",
    )
    if not isinstance(rows, list):
        raise RuntimeError("Radarr movie lookup did not return a list.")
    for row in rows:
        if isinstance(row, dict) and str(row.get("title") or "").strip().lower() == title.lower():
            return row
    for row in rows:
        if isinstance(row, dict):
            return row
    raise RuntimeError(f"Radarr movie lookup returned no candidates for {title!r}.")


def arr_path_text_equal(left: object, right: object) -> bool:
    """Compares Arr paths across Windows and POSIX separators."""

    left_text = str(left or "").strip().rstrip("\\/")
    right_text = str(right or "").strip().rstrip("\\/")
    return left_text.replace("/", "\\").lower() == right_text.replace("/", "\\").lower()


def arr_path_under_root(path_text: object, root_path_text: str) -> bool:
    """Returns true when one Arr media path already lives under a root."""

    media_path = str(path_text or "").strip().rstrip("\\/")
    root_path = root_path_text.strip().rstrip("\\/")
    if not media_path or not root_path:
        return False
    media_windows = media_path.replace("/", "\\").lower()
    root_windows = root_path.replace("/", "\\").lower()
    return media_windows == root_windows or media_windows.startswith(root_windows + "\\")


def arr_media_folder_name(media: dict[str, object], fallback_title: str) -> str:
    """Returns a stable folder name for moving an existing Arr media item under a new root."""

    current_path = str(media.get("path") or "").strip().rstrip("\\/")
    if current_path:
        parts = [part for part in current_path.replace("\\", "/").split("/") if part]
        if parts:
            return parts[-1]
    folder_name = str(media.get("folderName") or "").strip()
    if folder_name:
        return folder_name
    return fallback_title.strip() or "media"


def arr_join_root_child(root_path_text: str, child_name: str) -> str:
    """Joins an Arr root and child path without assuming the host path style."""

    root = root_path_text.rstrip("\\/")
    separator = "\\" if "\\" in root or (len(root) > 1 and root[1] == ":") else "/"
    return f"{root}{separator}{child_name}"


def update_existing_arr_media_payload(
    media: dict[str, object],
    *,
    quality_profile_id: int,
    root_path_text: str,
    fallback_title: str,
    radarr_movie: bool,
) -> tuple[dict[str, object], bool]:
    """Builds a corrected Arr media payload when an existing item is reused."""

    payload = dict(media)
    changed = False
    if int(payload.get("qualityProfileId") or 0) != quality_profile_id:
        payload["qualityProfileId"] = quality_profile_id
        changed = True
    if not arr_path_text_equal(payload.get("rootFolderPath"), root_path_text) or not arr_path_under_root(payload.get("path"), root_path_text):
        payload["rootFolderPath"] = root_path_text
        payload["path"] = arr_join_root_child(root_path_text, arr_media_folder_name(payload, fallback_title))
        changed = True
    if payload.get("monitored") is not True:
        payload["monitored"] = True
        changed = True
    if radarr_movie and payload.get("minimumAvailability") != "released":
        payload["minimumAvailability"] = "released"
        changed = True
    if not radarr_movie and payload.get("seasonFolder") is not True:
        payload["seasonFolder"] = True
        changed = True
    return payload, changed


def ensure_radarr_movie(
    arr_url: str,
    api_key: str,
    title: str,
    root_path: Path | str,
    *,
    create_local_root_path: bool = True,
    quality_profile_name: str | None = None,
) -> dict[str, object]:
    """Ensures a temporary Radarr movie exists for the import E2E."""

    root_folder = ensure_radarr_root_folder(arr_url, api_key, root_path, create_local_path=create_local_root_path)
    root_path_text = str(root_folder.get("path") or resolve_radarr_root_path(root_path, create_local_path=False))
    quality_profile = get_quality_profile(arr_url, api_key, "radarr", quality_profile_name)
    quality_profile_id = int(quality_profile.get("id") or 0)
    movies = require_success(arr_request(arr_url, api_key, "/api/v3/movie"), "Radarr movie list")
    if isinstance(movies, list):
        for movie in movies:
            if isinstance(movie, dict) and str(movie.get("title") or "").strip().lower() == title.lower():
                selected_movie = movie
                payload, updated = update_existing_arr_media_payload(
                    movie,
                    quality_profile_id=quality_profile_id,
                    root_path_text=root_path_text,
                    fallback_title=title,
                    radarr_movie=True,
                )
                if updated:
                    updated_payload = require_success(
                        arr_request(
                            arr_url,
                            api_key,
                            f"/api/v3/movie/{int(movie.get('id') or 0)}",
                            method="PUT",
                            json_body=payload,
                            timeout_seconds=60.0,
                        ),
                        "Radarr movie quality profile update",
                    )
                    if isinstance(updated_payload, dict):
                        selected_movie = updated_payload
                return {
                    "id": int(movie.get("id") or 0),
                    "title": movie.get("title"),
                    "created": False,
                    "updated": updated,
                    "root_folder": root_folder,
                    "quality_profile": summarize_quality_profile(quality_profile, quality_profile_name),
                    "movie": selected_movie,
                }

    lookup = lookup_radarr_movie(arr_url, api_key, title)
    payload = dict(lookup)
    payload["qualityProfileId"] = quality_profile_id
    payload["rootFolderPath"] = root_path_text
    payload["monitored"] = True
    payload["minimumAvailability"] = "released"
    payload["addOptions"] = {"searchForMovie": False}
    created = require_success(
        arr_request(arr_url, api_key, "/api/v3/movie", method="POST", json_body=payload, timeout_seconds=60.0),
        "Radarr movie create",
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Radarr movie create did not return an id.")
    return {
        "id": int(created["id"]),
        "title": created.get("title"),
        "created": True,
        "updated": False,
        "root_folder": root_folder,
        "quality_profile": summarize_quality_profile(quality_profile, quality_profile_name),
        "movie": created,
    }


def delete_sonarr_series(arr_url: str, api_key: str, series_id: int) -> dict[str, object]:
    """Deletes one temporary Sonarr series without deleting local media files."""

    result = arr_request(arr_url, api_key, f"/api/v3/series/{series_id}?deleteFiles=false&addImportListExclusion=false", method="DELETE")
    return {"id": series_id, "status": int(result.get("status") or 0)}


def ensure_arr_root_folder(
    arr_url: str,
    api_key: str,
    root_path: Path | str,
    *,
    create_local_path: bool = True,
    kind: str,
) -> dict[str, object]:
    """Ensures Radarr/Sonarr can use one root folder for import verification."""

    path_text = resolve_radarr_root_path(root_path, create_local_path=create_local_path)
    roots = require_success(arr_request(arr_url, api_key, "/api/v3/rootfolder"), f"{kind} root folders")
    if isinstance(roots, list):
        for root in roots:
            if isinstance(root, dict) and str(root.get("path") or "").lower() == path_text.lower():
                return {"id": int(root.get("id") or 0), "path": root.get("path"), "created": False}
    created = require_success(
        arr_request(arr_url, api_key, "/api/v3/rootfolder", method="POST", json_body={"path": path_text}),
        f"{kind} root folder create",
    )
    if not isinstance(created, dict):
        raise RuntimeError(f"{kind} root folder create did not return an object.")
    return {"id": int(created.get("id") or 0), "path": created.get("path"), "created": True}


def lookup_sonarr_series(arr_url: str, api_key: str, title: str) -> dict[str, Any]:
    """Looks up one Sonarr series by title."""

    rows = require_success(
        arr_request(arr_url, api_key, "/api/v3/series/lookup?term=" + urllib.parse.quote(title), timeout_seconds=60.0),
        "Sonarr series lookup",
    )
    if not isinstance(rows, list):
        raise RuntimeError("Sonarr series lookup did not return a list.")
    for row in rows:
        if isinstance(row, dict) and str(row.get("title") or "").strip().lower() == title.lower():
            return row
    for row in rows:
        if isinstance(row, dict):
            return row
    raise RuntimeError(f"Sonarr series lookup returned no candidates for {title!r}.")


def ensure_sonarr_series(
    arr_url: str,
    api_key: str,
    title: str,
    root_path: Path | str,
    *,
    create_local_root_path: bool = True,
    quality_profile_name: str | None = None,
) -> dict[str, object]:
    """Ensures a temporary Sonarr series exists for the import E2E."""

    root_folder = ensure_arr_root_folder(arr_url, api_key, root_path, create_local_path=create_local_root_path, kind="sonarr")
    root_path_text = str(root_folder.get("path") or resolve_radarr_root_path(root_path, create_local_path=False))
    quality_profile = get_quality_profile(arr_url, api_key, "sonarr", quality_profile_name)
    quality_profile_id = int(quality_profile.get("id") or 0)
    series_rows = require_success(arr_request(arr_url, api_key, "/api/v3/series"), "Sonarr series list")
    if isinstance(series_rows, list):
        for series in series_rows:
            if isinstance(series, dict) and str(series.get("title") or "").strip().lower() == title.lower():
                selected_series = series
                payload, updated = update_existing_arr_media_payload(
                    series,
                    quality_profile_id=quality_profile_id,
                    root_path_text=root_path_text,
                    fallback_title=title,
                    radarr_movie=False,
                )
                if updated:
                    updated_payload = require_success(
                        arr_request(
                            arr_url,
                            api_key,
                            f"/api/v3/series/{int(series.get('id') or 0)}",
                            method="PUT",
                            json_body=payload,
                            timeout_seconds=60.0,
                        ),
                        "Sonarr series quality profile update",
                    )
                    if isinstance(updated_payload, dict):
                        selected_series = updated_payload
                return {
                    "id": int(series.get("id") or 0),
                    "title": series.get("title"),
                    "created": False,
                    "updated": updated,
                    "root_folder": root_folder,
                    "quality_profile": summarize_quality_profile(quality_profile, quality_profile_name),
                    "series": selected_series,
                }

    lookup = lookup_sonarr_series(arr_url, api_key, title)
    payload = dict(lookup)
    payload["qualityProfileId"] = quality_profile_id
    payload["rootFolderPath"] = root_path_text
    payload["monitored"] = True
    payload["seasonFolder"] = True
    payload["addOptions"] = {"searchForMissingEpisodes": False}
    created = require_success(
        arr_request(arr_url, api_key, "/api/v3/series", method="POST", json_body=payload, timeout_seconds=60.0),
        "Sonarr series create",
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Sonarr series create did not return an id.")
    return {
        "id": int(created["id"]),
        "title": created.get("title"),
        "created": True,
        "updated": False,
        "root_folder": root_folder,
        "quality_profile": summarize_quality_profile(quality_profile, quality_profile_name),
        "series": created,
    }


def build_arr_release_search_paths(kind: str, title: str, indexer_id: int, media_id: int | None = None) -> list[str]:
    """Builds bounded Arr release-search request paths for one media item."""

    quoted_title = urllib.parse.quote(title)
    paths: list[str] = []
    if media_id is not None and media_id > 0:
        media_key = "movieId" if kind == "radarr" else "seriesId"
        paths.append(f"/api/v3/release?{media_key}={media_id}&indexerIds={indexer_id}")
        paths.append(f"/api/v3/release?{media_key}={media_id}&indexerId={indexer_id}")
    paths.extend(
        [
            f"/api/v3/release?term={quoted_title}&indexerIds={indexer_id}",
            f"/api/v3/release?term={quoted_title}&indexerId={indexer_id}",
        ]
    )
    return paths


def grab_first_arr_release(
    arr_url: str,
    api_key: str,
    indexer_id: int,
    title: str,
    timeout_seconds: float,
    *,
    kind: str,
    media_id: int | None = None,
    emule_base_url: str | None = None,
    emule_api_key: str | None = None,
    category_id: int | None = None,
) -> dict[str, object]:
    """Searches Arr releases and grabs the best eMule BB indexer match."""

    deadline = time.monotonic() + timeout_seconds
    attempts: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        for path in build_arr_release_search_paths(kind, title, indexer_id, media_id):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                result = arr_request(arr_url, api_key, path, timeout_seconds=max(1.0, remaining))
            except TimeoutError as exc:
                attempts.append(
                    {
                        "kind": kind,
                        "term_present": bool(title),
                        "media_id": media_id,
                        "request_path": path.split("apikey=", 1)[0],
                        "status": "timeout",
                        "error": str(exc),
                    }
                )
                continue
            rows = result.get("json") if isinstance(result.get("json"), list) else []
            matches = [row for row in rows if isinstance(row, dict) and is_emulebb_arr_release(row, indexer_id)]
            attempts.append(
                {
                    "kind": kind,
                    "term_present": bool(title),
                    "media_id": media_id,
                    "request_path": path.split("apikey=", 1)[0],
                    "status": int(result.get("status") or 0),
                    "count": len(rows),
                    "matches": len(matches),
                    "indexers": summarize_arr_release_indexers(rows),
                }
            )
            if matches:
                min_sources = MIN_ARR_RELEASE_SOURCES if kind == "radarr" else 1
                require_episode_like = kind == "sonarr"
                ranked_matches = matches
                if (
                    max((prowlarr_live.release_source_count(row) for row in matches), default=0) < min_sources
                    and emule_base_url
                    and emule_api_key
                    and category_id is not None
                ):
                    source_rows, enrichment_summary = direct_torznab_source_rows(
                        emule_base_url,
                        emule_api_key,
                        title,
                        category_id,
                        max(1.0, deadline - time.monotonic()),
                    )
                    ranked_matches, enriched_count = enrich_arr_release_sources(matches, source_rows)
                    enrichment_summary["enriched_count"] = enriched_count
                    attempts[-1]["source_enrichment"] = enrichment_summary
                ranked = rank_arr_releases(ranked_matches, title, min_sources=min_sources, require_episode_like=require_episode_like)
                if not ranked:
                    select_best_arr_release(ranked_matches, title, min_sources=min_sources, require_episode_like=require_episode_like)
                rejected: list[dict[str, object]] = []
                for selected in ranked:
                    selected_download_url = str(selected.get("downloadUrl") or selected.get("guid") or "")
                    selected_hash = ""
                    if selected_download_url.startswith("magnet:?"):
                        try:
                            selected_hash = ed2k_hash_from_magnet(selected_download_url)
                        except RuntimeError:
                            selected_hash = ""
                    grab_result = arr_request(
                        arr_url,
                        api_key,
                        "/api/v3/release",
                        method="POST",
                        json_body=selected,
                        timeout_seconds=max(1.0, min(30.0, deadline - time.monotonic())),
                    )
                    status = int(grab_result.get("status") or 0)
                    if status >= 200 and status < 300:
                        grabbed = grab_result.get("json")
                        return {
                            "attempt_count": len(attempts),
                            "request_path": path,
                            "title_present": bool(selected.get("title")),
                            "downloadUrl_present": bool(selected.get("downloadUrl")),
                            "guid_present": bool(selected.get("guid")),
                            "indexer": selected.get("indexer"),
                            "selection": prowlarr_live.summarize_release_selection(selected, title),
                            "rejected_candidate_count": len(rejected),
                            "hash": selected_hash,
                            "hash_present": bool(selected_hash),
                            "grab_status": grabbed.get("status") if isinstance(grabbed, dict) else status,
                        }
                    rejected.append(
                        {
                            "status": status,
                            "selection": prowlarr_live.summarize_release_selection(selected, title),
                            "body_preview": str(grab_result.get("body_text") or "")[:160],
                        }
                    )
                raise RuntimeError(f"{kind} release grab rejected all ranked eMule BB rows: {rejected!r}")
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5.0, remaining))
    raise RuntimeError(f"{kind} release search returned no eMule BB rows before timeout. Attempts: {attempts!r}")


def grab_first_radarr_release(arr_url: str, api_key: str, indexer_id: int, title: str, timeout_seconds: float) -> dict[str, object]:
    """Searches Radarr releases and grabs the best eMule BB indexer match."""

    return grab_first_arr_release(arr_url, api_key, indexer_id, title, timeout_seconds, kind="radarr")


def grab_first_arr_release_or_fallback_to_prowlarr(
    *,
    kind: str,
    arr_url: str,
    arr_api_key: str,
    arr_indexer_id: int,
    arr_indexer_name: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    emule_base_url: str,
    emule_api_key: str,
    title: str,
    media_id: int,
    category_id: int,
    download_category: str,
    timeout_seconds: float,
    health_rows: list[dict[str, Any]],
) -> dict[str, object]:
    """Grabs through Arr, using Prowlarr as search source when Arr quarantined the provider."""

    indexer_unavailable = arr_indexer_unavailable_due_to_failures(health_rows, arr_indexer_name)
    if not indexer_unavailable:
        before_hashes = transfer_hashes(emule_base_url, emule_api_key)
        try:
            release_grab = grab_first_arr_release(
                arr_url,
                arr_api_key,
                arr_indexer_id,
                title,
                timeout_seconds,
                kind=kind,
                media_id=media_id,
                emule_base_url=emule_base_url,
                emule_api_key=emule_api_key,
                category_id=category_id,
            )
            release_grab["source"] = "arr_release_search"
            release_grab["arr_indexer_unavailable_due_to_failures"] = False
            try:
                new_transfer = wait_for_new_transfer_category(
                    emule_base_url,
                    emule_api_key,
                    category=download_category,
                    before_hashes=before_hashes,
                    timeout_seconds=180.0,
                )
                release_grab["hash"] = str(new_transfer.get("hash") or "")
                release_grab["hash_present"] = bool(release_grab["hash"])
                release_grab["category_transfer"] = {key: value for key, value in new_transfer.items() if key != "hash"}
            except RuntimeError:
                if not str(release_grab.get("hash") or ""):
                    raise
            return release_grab
        except RuntimeError as exc:
            direct_error = str(exc)
            if kind != "sonarr" or "release search returned no eMule BB rows" not in direct_error:
                raise RuntimeError(f"{kind} manual Arr release acquisition failed: {direct_error}") from exc
    else:
        direct_error = "Arr health reports the eMule BB indexer unavailable due to failures."

    release_grab = grab_first_arr_release_via_prowlarr(
        kind=kind,
        arr_url=arr_url,
        arr_api_key=arr_api_key,
        arr_indexer_id=arr_indexer_id,
        arr_indexer_name=arr_indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        emule_base_url=emule_base_url,
        emule_api_key=emule_api_key,
        title=title,
        category_id=category_id,
        download_category=download_category,
        timeout_seconds=timeout_seconds,
    )
    release_grab["arr_direct_search_error"] = direct_error[:500]
    release_grab["arr_indexer_unavailable_due_to_failures"] = indexer_unavailable
    return release_grab


def transfer_hashes(base_url: str, emule_api_key: str) -> set[str]:
    """Returns currently visible native transfer hashes."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/transfers",
        api_key=emule_api_key,
        request_timeout_seconds=30.0,
    )
    rows = rest_smoke.require_json_array(result, 200)
    return {
        str(row.get("hash") or "").lower()
        for row in rows
        if isinstance(row, dict) and str(row.get("hash") or "").strip()
    }


def shared_hashing_snapshot(base_url: str, emule_api_key: str, timeout_seconds: float = 5.0) -> dict[str, object]:
    """Returns the current shared-hashing state from the cheap status route."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/status",
        api_key=emule_api_key,
        request_timeout_seconds=timeout_seconds,
    )
    status = int(result.get("status") or 0)
    snapshot: dict[str, object] = {"status": status}
    if status != 200:
        snapshot["response"] = rest_smoke.compact_http_result(result)
        return snapshot

    payload = rest_smoke.require_json_object(result, 200)
    stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
    hashing_count = int(stats.get("sharedHashingCount") or 0)
    snapshot["hashingCount"] = hashing_count
    snapshot["hashingActive"] = bool(stats.get("sharedHashingActive") or hashing_count > 0)
    return snapshot


def wait_for_shared_hashing_idle(
    base_url: str,
    emule_api_key: str,
    timeout_seconds: float = DEFAULT_SHARED_HASH_IDLE_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Waits for shared hashing to finish before starting Arr acquisition."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, object] | None = None
    while time.monotonic() < deadline:
        try:
            last = shared_hashing_snapshot(base_url, emule_api_key, timeout_seconds=min(5.0, max(1.0, deadline - time.monotonic())))
        except TimeoutError as exc:
            last = {"status": "timeout", "error": str(exc)}
        except OSError as exc:
            last = {"status": type(exc).__name__, "error": str(exc)}

        status_value = last.get("status")
        if isinstance(status_value, int) and status_value == 200 and int(last.get("hashingCount") or 0) == 0:
            return {**last, "idle": True}
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))

    raise RuntimeError(f"Shared file hashing did not become idle before Arr acquisition. Last: {last!r}")


def wait_for_new_transfer_category(
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
        result = rest_smoke.http_request(
            base_url,
            "/api/v1/transfers",
            api_key=emule_api_key,
            request_timeout_seconds=request_timeout,
        )
        rows = rest_smoke.require_json_array(result, 200)
        for row in rows:
            if not isinstance(row, dict):
                continue
            transfer_hash = str(row.get("hash") or "").lower()
            last = {
                "hash": transfer_hash,
                "hash_present": bool(transfer_hash),
                "name_present": bool(row.get("name")),
                "state": row.get("state"),
                "categoryName": row.get("categoryName"),
            }
            if transfer_hash and transfer_hash not in before_hashes and str(row.get("categoryName") or "") == category:
                return last
        time.sleep(2.0)
    raise RuntimeError(f"Arr grab did not create a new transfer in category {category!r}. Last: {last!r}")


def get_release_magnet_url(release: dict[str, Any]) -> str:
    """Returns the eMule magnet URL carried by one Arr/Prowlarr release row."""

    for key in ("downloadUrl", "magnetUrl", "guid"):
        value = str(release.get(key) or "").strip()
        if value.startswith("magnet:?"):
            return value
    raise RuntimeError("Prowlarr release did not expose a magnet URL.")


def grab_first_arr_release_via_prowlarr(
    *,
    kind: str,
    arr_url: str,
    arr_api_key: str,
    arr_indexer_id: int,
    arr_indexer_name: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    emule_base_url: str,
    emule_api_key: str,
    title: str,
    category_id: int,
    download_category: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Searches the eMule Prowlarr indexer, then triggers the grab from Arr."""

    before_hashes = transfer_hashes(emule_base_url, emule_api_key)
    deadline = time.monotonic() + timeout_seconds
    attempts: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        path = prowlarr_live.build_prowlarr_search_path(title, category_id, prowlarr_indexer_id)
        try:
            result = prowlarr_live.prowlarr_request(
                prowlarr_url,
                prowlarr_api_key,
                path,
                timeout_seconds=max(1.0, remaining),
            )
        except TimeoutError as exc:
            attempts.append(
                {
                    "kind": kind,
                    "term_present": bool(title),
                    "request_path": path.split("apikey=", 1)[0],
                    "status": "timeout",
                    "error": str(exc),
                }
            )
            continue
        status = int(result.get("status") or 0)
        rows = result.get("json") if isinstance(result.get("json"), list) else []
        matches = [
            row
            for row in rows
            if isinstance(row, dict) and int(row.get("indexerId") or 0) == int(prowlarr_indexer_id)
        ]
        attempts.append(
            {
                "kind": kind,
                "term_present": bool(title),
                "request_path": path.split("apikey=", 1)[0],
                "status": status,
                "count": len(rows),
                "matches": len(matches),
                "indexers": summarize_arr_release_indexers(rows),
            }
        )
        if status >= 200 and status < 300 and matches:
            selected = prowlarr_live.select_grabbable_release(matches, prowlarr_indexer_id, title)
            try:
                magnet = get_release_magnet_url(selected)
            except RuntimeError:
                direct_rows, direct_summary = direct_torznab_source_rows(
                    emule_base_url,
                    emule_api_key,
                    title,
                    category_id,
                    max(1.0, deadline - time.monotonic()),
                )
                min_sources = MIN_ARR_RELEASE_SOURCES if kind == "radarr" else 1
                require_episode_like = kind == "sonarr"
                ranked_direct_rows = rank_arr_releases(
                    direct_rows,
                    title,
                    min_sources=min_sources,
                    require_episode_like=require_episode_like,
                )
                if not ranked_direct_rows:
                    select_best_arr_release(direct_rows, title, min_sources=min_sources, require_episode_like=require_episode_like)
                selected = ranked_direct_rows[0]
                magnet = get_release_magnet_url(selected)
                attempts[-1]["direct_torznab_magnet_fallback"] = direct_summary
            added = qbit_direct_add(
                emule_base_url,
                emule_api_key,
                magnet,
                download_category,
            )
            new_transfer = wait_for_new_transfer_category(
                emule_base_url,
                emule_api_key,
                category=download_category,
                before_hashes=before_hashes,
                timeout_seconds=min(120.0, max(1.0, deadline - time.monotonic())),
            )
            transfer_hash = str(new_transfer.get("hash") or "")
            return {
                "attempt_count": len(attempts),
                "source": "prowlarr_eMule_indexer_qbit_add",
                "title_present": bool(selected.get("title")),
                "downloadUrl_present": bool(selected.get("downloadUrl")),
                "guid_present": bool(selected.get("guid")),
                "indexer": arr_indexer_name,
                "selection": prowlarr_live.summarize_release_selection(selected, title),
                "hash": transfer_hash,
                "hash_present": bool(transfer_hash),
                "grab_status": int(added.get("add_status") or 0),
                "magnet_hash_present": bool(added.get("hash")),
                "category_transfer": {key: value for key, value in new_transfer.items() if key != "hash"},
            }
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(5.0, remaining))
    raise RuntimeError(f"{kind} eMule BB Prowlarr search returned no grabbable rows before timeout. Attempts: {attempts!r}")


def redact_direct_magnet(magnet: dict[str, object]) -> dict[str, object]:
    """Reports one direct magnet lookup without exposing operator terms or links."""

    redacted = {
        "query_present": bool(magnet.get("query")),
        "title_present": bool(magnet.get("title")),
        "magnet_present": bool(magnet.get("magnet")),
    }
    try:
        redacted["hash_present"] = bool(ed2k_hash_from_magnet(str(magnet.get("magnet") or "")))
    except RuntimeError:
        redacted["hash_present"] = False
    return redacted


def redact_collected_direct_magnets(result: dict[str, object]) -> dict[str, object]:
    """Redacts collected live magnet search details for persisted reports."""

    attempts = result.get("attempts") if isinstance(result.get("attempts"), list) else []
    magnets = result.get("magnets") if isinstance(result.get("magnets"), list) else []
    return {
        "attempts": [
            {
                "query_present": bool(attempt.get("query_present") or attempt.get("query")) if isinstance(attempt, dict) else False,
                "status": attempt.get("status") if isinstance(attempt, dict) else None,
                "items": attempt.get("items") if isinstance(attempt, dict) else None,
                "magnets": attempt.get("magnets") if isinstance(attempt, dict) else None,
            }
            for attempt in attempts
        ],
        "magnet_count": len(magnets),
        "magnets": [
            {
                "query_present": bool(magnet.get("query")) if isinstance(magnet, dict) else False,
                "title_present": bool(magnet.get("title")) if isinstance(magnet, dict) else False,
                "hash_present": bool(magnet.get("hash")) if isinstance(magnet, dict) else False,
            }
            for magnet in magnets
        ],
    }


def collect_direct_magnets(
    base_url: str,
    emule_api_key: str,
    queries: tuple[str, ...],
    max_magnets: int,
    *,
    category_id: int,
) -> dict[str, object]:
    """Collects unique direct Torznab magnets across multiple search terms."""

    magnets: list[dict[str, str]] = []
    attempts: list[dict[str, object]] = []
    seen_hashes: set[str] = set()
    for query_index, query in enumerate(queries):
        path = build_torznab_search_path(category_id, query, emule_api_key)
        result = rest_smoke.http_request(base_url, path, request_timeout_seconds=45.0)
        status = int(result.get("status") or 0)
        body_text = str(result.get("body_text") or "")
        item_count = 0
        if status == 200:
            root = ET.fromstring(body_text)
            for item in root.findall("./channel/item"):
                item_count += 1
                title = item.findtext("title") or ""
                link = item.findtext("link") or ""
                if not link.startswith("magnet:?"):
                    continue
                transfer_hash = ed2k_hash_from_magnet(link)
                if transfer_hash in seen_hashes:
                    continue
                seen_hashes.add(transfer_hash)
                magnets.append({"query": query, "title": title, "magnet": link, "hash": transfer_hash})
                if len(magnets) >= max_magnets:
                    break
        attempts.append(
            {
                "query_index": query_index,
                "query_present": bool(query),
                "status": status,
                "items": item_count,
                "magnets": len(magnets),
            }
        )
        if len(magnets) >= max_magnets:
            break

    if not magnets:
        raise RuntimeError(f"Direct Torznab magnet collection returned no magnets. Attempts: {attempts!r}")
    return {"magnets": magnets, "attempts": attempts}


def qbit_request(
    base_url: str,
    path: str,
    *,
    cookie: str | None = None,
    form: dict[str, object] | None = None,
    raw_body: bytes | str | None = None,
    content_type: str | None = None,
    method: str | None = None,
    timeout_seconds: float = 20.0,
) -> dict[str, object]:
    """Performs one qBittorrent-compatible API request and captures HTTP errors."""

    data = None
    headers = {"Connection": "close"}
    if cookie:
        headers["Cookie"] = cookie
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if raw_body is not None:
        data = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
        if content_type is not None:
            headers["Content-Type"] = content_type
    request = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body_text = response.read().decode("utf-8", errors="replace")
            return {"status": int(response.status), "body_text": body_text, "headers": dict(response.headers.items())}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        return {"status": int(exc.code), "body_text": body_text, "headers": dict(exc.headers.items())}


def require_qbit_ok(result: dict[str, object], description: str) -> None:
    """Requires one qBittorrent compatibility response to be HTTP 200 Ok."""

    status = int(result.get("status") or 0)
    body_text = str(result.get("body_text") or "")
    if status != 200 or body_text != "Ok.":
        raise RuntimeError(f"{description} failed with HTTP {status}: {body_text[:100]}")


def require_qbit_json(result: dict[str, object], description: str) -> Any:
    """Returns the JSON body from one successful qBittorrent response."""

    status = int(result.get("status") or 0)
    body_text = str(result.get("body_text") or "")
    if status != 200:
        raise RuntimeError(f"{description} failed with HTTP {status}: {body_text[:100]}")
    try:
        return json.loads(body_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{description} returned invalid JSON: {exc}") from exc


def qbit_login(base_url: str, emule_api_key: str) -> tuple[str, dict[str, object]]:
    """Authenticates to the qBittorrent-compatible API and returns a SID cookie."""

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


def qbit_route_completeness_checks(base_url: str, emule_api_key: str, cookie: str) -> dict[str, object]:
    """Exercises every qBittorrent-compatible route with bounded live-wire inputs."""

    checks: dict[str, object] = {}
    for scenario in QBIT_ROUTE_COMPLETENESS_SCENARIOS:
        form = dict(scenario.get("form") or {})
        if scenario["name"] == "login":
            form["password"] = emule_api_key
        result = qbit_request(
            base_url,
            str(scenario["path"]),
            cookie=cookie if scenario.get("auth", True) else None,
            method=str(scenario["method"]),
            form=form or None,
        )
        expected_statuses = tuple(int(value) for value in scenario["expected_statuses"])
        if len(expected_statuses) != 1:
            raise RuntimeError(f"qBit route completeness {scenario['name']} must declare exactly one expected HTTP status.")
        expected_status = expected_statuses[0]
        status = int(result.get("status") or 0)
        if status != expected_status:
            raise RuntimeError(
                f"qBit route completeness {scenario['name']} returned HTTP {status}, "
                f"expected {expected_status}: {str(result.get('body_text') or '')[:100]}"
            )
        checks[str(scenario["name"])] = {
            "method": scenario["method"],
            "path": scenario["path"],
            "status": status,
            "expected_status": expected_status,
        }
    return checks


def qbit_direct_add(
    base_url: str,
    emule_api_key: str,
    magnet: str,
    category: str,
    *,
    cookie: str | None = None,
) -> dict[str, object]:
    """Exercises the qBittorrent add endpoint directly against eMule BB."""

    login_status: int | None = None
    if cookie is None:
        cookie, login = qbit_login(base_url, emule_api_key)
        login_status = int(login.get("status") or 0)

    add = qbit_request(
        base_url,
        "/api/v2/torrents/add",
        cookie=cookie,
        form={
            "urls": magnet,
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
    result: dict[str, object] = {"add_status": int(add.get("status") or 0), "hash": ed2k_hash_from_magnet(magnet)}
    if login_status is not None:
        result["login_status"] = login_status
    return result


def qbit_direct_safety_checks(base_url: str, emule_api_key: str) -> dict[str, object]:
    """Exercises unauthenticated and invalid qBittorrent compatibility paths."""

    too_many_hashes = "|".join(f"{index + 1:032x}" for index in range(101))
    public_version = qbit_request(base_url, "/api/v2/app/webapiVersion")
    if int(public_version.get("status") or 0) != 200 or str(public_version.get("body_text") or "") != "2.11.0":
        raise RuntimeError(f"qBit public web API version check failed: {public_version!r}")

    unauthenticated_info = qbit_request(base_url, "/api/v2/torrents/info")
    if int(unauthenticated_info.get("status") or 0) != 403:
        raise RuntimeError(f"qBit unauthenticated protected endpoint returned {unauthenticated_info!r}")

    wrong_login = qbit_request(
        base_url,
        "/api/v2/auth/login",
        form={"username": "emule", "password": emule_api_key + "-wrong"},
        method="POST",
    )
    if int(wrong_login.get("status") or 0) != 200 or str(wrong_login.get("body_text") or "") != "Fails.":
        raise RuntimeError(f"qBit wrong login was not rejected: {wrong_login!r}")

    missing_username_login = qbit_request(
        base_url,
        "/api/v2/auth/login",
        form={"password": emule_api_key},
        method="POST",
    )
    if int(missing_username_login.get("status") or 0) != 200 or str(missing_username_login.get("body_text") or "") != "Fails.":
        raise RuntimeError(f"qBit missing-username login was not rejected: {missing_username_login!r}")

    wrong_username_login = qbit_request(
        base_url,
        "/api/v2/auth/login",
        form={"username": "not-emule", "password": emule_api_key},
        method="POST",
    )
    if int(wrong_username_login.get("status") or 0) != 200 or str(wrong_username_login.get("body_text") or "") != "Fails.":
        raise RuntimeError(f"qBit wrong-username login was not rejected: {wrong_username_login!r}")

    wrong_login_info = qbit_request(base_url, "/api/v2/torrents/info")
    if int(wrong_login_info.get("status") or 0) != 403:
        raise RuntimeError(f"qBit wrong-login session reached protected endpoint: {wrong_login_info!r}")

    cookie, login = qbit_login(base_url, emule_api_key)
    route_completeness = qbit_route_completeness_checks(base_url, emule_api_key, cookie)
    invalid_add = qbit_request(
        base_url,
        "/api/v2/torrents/add",
        cookie=cookie,
        form={"urls": "not-a-download-link", "category": "RADARR_ENG", "stopped": "true"},
        method="POST",
    )
    if int(invalid_add.get("status") or 0) != 400:
        raise RuntimeError(f"qBit invalid add was not rejected: {invalid_add!r}")

    wrong_methods = {
        "post_app_version": qbit_request(base_url, "/api/v2/app/version", cookie=cookie, method="POST"),
        "get_torrents_add": qbit_request(base_url, "/api/v2/torrents/add", cookie=cookie),
        "get_torrents_delete": qbit_request(base_url, "/api/v2/torrents/delete", cookie=cookie),
        "post_webapi_version": qbit_request(base_url, "/api/v2/app/webapiVersion", method="POST"),
    }
    unexpected_method_matches = {
        name: result
        for name, result in wrong_methods.items()
        if int(result.get("status") or 0) != 404
    }
    if unexpected_method_matches:
        raise RuntimeError(f"qBit wrong-method checks were not rejected: {unexpected_method_matches!r}")

    invalid_mutations = {
        "delete_all": qbit_request(
            base_url,
            "/api/v2/torrents/delete",
            cookie=cookie,
            form={"hashes": "all", "deleteFiles": "true"},
            method="POST",
        ),
        "delete_bad_hash": qbit_request(
            base_url,
            "/api/v2/torrents/delete",
            cookie=cookie,
            form={"hashes": "bad"},
            method="POST",
        ),
        "delete_duplicate_hash": qbit_request(
            base_url,
            "/api/v2/torrents/delete",
            cookie=cookie,
            form={
                "hashes": (
                    "0123456789abcdef0123456789abcdef|"
                    "0123456789ABCDEF0123456789ABCDEF"
                )
            },
            method="POST",
        ),
        "pause_too_many_hashes": qbit_request(
            base_url,
            "/api/v2/torrents/pause",
            cookie=cookie,
            form={"hashes": too_many_hashes},
            method="POST",
        ),
        "set_force_start_bad_hash": qbit_request(
            base_url,
            "/api/v2/torrents/setForceStart",
            cookie=cookie,
            form={"hashes": "bad", "value": "true"},
            method="POST",
        ),
        "set_share_limits_bad_ratio": qbit_request(
            base_url,
            "/api/v2/torrents/setShareLimits",
            cookie=cookie,
            form={"hashes": rest_smoke.REST_SURFACE_MISSING_HASH, "ratioLimit": "bad"},
            method="POST",
        ),
        "set_share_limits_bad_seed_time": qbit_request(
            base_url,
            "/api/v2/torrents/setShareLimits",
            cookie=cookie,
            form={"hashes": rest_smoke.REST_SURFACE_MISSING_HASH, "seedingTimeLimit": "1.5"},
            method="POST",
        ),
        "add_json_content_type": qbit_request(
            base_url,
            "/api/v2/torrents/add",
            cookie=cookie,
            raw_body='{"urls":"not-a-download-link"}',
            content_type="application/json",
            method="POST",
        ),
        "create_category_empty": qbit_request(
            base_url,
            "/api/v2/torrents/createCategory",
            cookie=cookie,
            form={"category": ""},
            method="POST",
        ),
        "create_category_control_character": qbit_request(
            base_url,
            "/api/v2/torrents/createCategory",
            cookie=cookie,
            form={"category": "bad\u0001name"},
            method="POST",
        ),
        "set_category_missing_category": qbit_request(
            base_url,
            "/api/v2/torrents/setCategory",
            cookie=cookie,
            form={"hashes": "0123456789abcdef0123456789abcdef"},
            method="POST",
        ),
        "pause_missing_hashes": qbit_request(
            base_url,
            "/api/v2/torrents/pause",
            cookie=cookie,
            form={},
            method="POST",
        ),
        "info_malformed_percent_category": qbit_request(base_url, "/api/v2/torrents/info?category=%2x", cookie=cookie),
        "info_duplicate_category": qbit_request(base_url, "/api/v2/torrents/info?category=Movies&category=TV", cookie=cookie),
        "info_control_character_category": qbit_request(base_url, "/api/v2/torrents/info?category=bad%01name", cookie=cookie),
        "properties_missing_hash": qbit_request(base_url, "/api/v2/torrents/properties", cookie=cookie),
        "files_bad_hash": qbit_request(base_url, "/api/v2/torrents/files?hash=bad", cookie=cookie),
        "files_malformed_percent_hash": qbit_request(base_url, "/api/v2/torrents/files?hash=%2x", cookie=cookie),
        "files_malformed_percent_path": qbit_request(base_url, "/api/v2/torrents/files%2x?hash=0123456789abcdef0123456789abcdef", cookie=cookie),
    }
    unexpected_successes = {
        name: result
        for name, result in invalid_mutations.items()
        if int(result.get("status") or 0) != 400
    }
    if unexpected_successes:
        raise RuntimeError(f"qBit invalid mutation checks were not rejected: {unexpected_successes!r}")

    checks = {
        "public_webapi_version": public_version,
        "unauthenticated_info": unauthenticated_info,
        "wrong_login": wrong_login,
        "missing_username_login": missing_username_login,
        "wrong_username_login": wrong_username_login,
        "wrong_login_info": wrong_login_info,
        "valid_login": login,
        "route_completeness": route_completeness,
        "invalid_add": invalid_add,
        "wrong_methods": wrong_methods,
        "invalid_mutations": invalid_mutations,
    }
    return checks


def ed2k_hash_from_magnet(magnet: str) -> str:
    """Extracts the eD2K hash carried by an eMule BB fake BTIH magnet."""

    parsed = urllib.parse.urlparse(magnet)
    query = urllib.parse.parse_qs(parsed.query)
    xt = query.get("xt", [""])[0].lower()
    prefix = "urn:btih:"
    if not xt.startswith(prefix) or len(xt) < len(prefix) + 40:
        raise RuntimeError("Magnet does not contain an eMule BB fake BTIH hash.")
    return xt[len(prefix) : len(prefix) + 32]


def wait_for_transfer(base_url: str, emule_api_key: str, transfer_hash: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until the direct qBit add appears in native eMule transfers."""

    expected_hash = transfer_hash.lower()
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        request_timeout = min(30.0, max(1.0, deadline - time.monotonic()))
        result = rest_smoke.http_request(
            base_url,
            "/api/v1/transfers",
            api_key=emule_api_key,
            request_timeout_seconds=request_timeout,
        )
        transfers = rest_smoke.require_json_array(result, 200)
        for transfer in transfers:
            if isinstance(transfer, dict) and str(transfer.get("hash") or "").lower() == expected_hash:
                return {
                    "hash": transfer.get("hash"),
                    "name": transfer.get("name"),
                    "state": transfer.get("state"),
                    "categoryName": transfer.get("categoryName"),
                }
        time.sleep(2.0)
    raise RuntimeError("Added qBit transfer did not appear before timeout.")


def wait_for_transfer_category(
    base_url: str,
    emule_api_key: str,
    transfer_hash: str,
    category: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until a native transfer reports the expected category."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, object] | None = None
    while time.monotonic() < deadline:
        last = wait_for_transfer(base_url, emule_api_key, transfer_hash, min(5.0, timeout_seconds))
        if str(last.get("categoryName") or "") == category:
            return last
        time.sleep(1.0)
    raise RuntimeError(f"Selected qBit transfer did not report category {category!r}. Last: {last!r}")


def wait_for_transfer_completion(base_url: str, emule_api_key: str, transfer_hash: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until an eMule transfer reaches a completed/importable state."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, object] | None = None
    observed_transfer = False
    while time.monotonic() < deadline:
        try:
            last = wait_for_transfer(base_url, emule_api_key, transfer_hash, min(10.0, timeout_seconds))
            observed_transfer = True
        except RuntimeError:
            if observed_transfer:
                return {
                    "hash": transfer_hash,
                    "state": "absent_after_seen",
                    "completed": True,
                    "last_seen": last,
                }
            raise
        state = str(last.get("state") or "").lower()
        if state in {"completed", "complete", "seeding", "uploading"} or "completed" in state:
            return {**last, "completed": True}
        time.sleep(5.0)
    raise RuntimeError(f"Selected transfer did not complete before timeout. Last: {last!r}")


def resume_transfer_if_paused(
    base_url: str,
    emule_api_key: str,
    transfer_hash: str,
    transfer: dict[str, object],
) -> dict[str, object]:
    """Resumes the selected native transfer when Arr left it paused."""

    state = str(transfer.get("state") or "").lower()
    if state != "paused":
        return {"resumed": False, "state": transfer.get("state")}

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{urllib.parse.quote(transfer_hash)}/operations/resume",
        method="POST",
        api_key=emule_api_key,
        request_timeout_seconds=30.0,
    )
    payload = rest_smoke.require_json_object(result, 200)
    return {
        "resumed": True,
        "state": transfer.get("state"),
        "status": int(result.get("status") or 0),
        "operation_result": payload.get("result"),
        "affected": payload.get("affected"),
    }


def wait_for_radarr_import(arr_url: str, api_key: str, movie_id: int, timeout_seconds: float) -> dict[str, object]:
    """Waits until Radarr reports the grabbed movie as imported."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        movie = require_success(arr_request(arr_url, api_key, f"/api/v3/movie/{movie_id}", timeout_seconds=30.0), "Radarr movie import status")
        if isinstance(movie, dict):
            last = movie
            movie_file = movie.get("movieFile")
            if bool(movie.get("hasFile")) or isinstance(movie_file, dict):
                return {
                    "movie_id": movie_id,
                    "hasFile": bool(movie.get("hasFile")),
                    "movieFile_present": isinstance(movie_file, dict),
                    "path": movie.get("path"),
                }
        time.sleep(10.0)
    raise RuntimeError(f"Radarr did not import movie before timeout. Last hasFile={bool(last.get('hasFile')) if last else None}.")


def trigger_arr_downloaded_scan(arr_url: str, api_key: str, kind: str, import_path: Path | str) -> dict[str, object]:
    """Asks Arr to scan the completed eMule category path for import."""

    command_name = "DownloadedMoviesScan" if kind == "radarr" else "DownloadedEpisodesScan"
    payload = {
        "name": command_name,
        "path": str(import_path),
        "importMode": "Move",
    }
    command = require_success(
        arr_request(arr_url, api_key, "/api/v3/command", method="POST", json_body=payload, timeout_seconds=60.0),
        f"{kind} downloaded scan command",
    )
    return {
        "name": command_name,
        "path_present": bool(str(import_path)),
        "id": int(command.get("id") or 0) if isinstance(command, dict) else 0,
        "status": command.get("status") if isinstance(command, dict) else None,
    }


def wait_for_sonarr_import(arr_url: str, api_key: str, series_id: int, timeout_seconds: float) -> dict[str, object]:
    """Waits until Sonarr reports at least one imported episode for the series."""

    deadline = time.monotonic() + timeout_seconds
    last_count = 0
    while time.monotonic() < deadline:
        episodes = require_success(arr_request(arr_url, api_key, f"/api/v3/episode?seriesId={series_id}", timeout_seconds=30.0), "Sonarr episode import status")
        rows = episodes if isinstance(episodes, list) else []
        imported = [
            episode
            for episode in rows
            if isinstance(episode, dict)
            and (bool(episode.get("hasFile")) or int(episode.get("episodeFileId") or 0) > 0 or isinstance(episode.get("episodeFile"), dict))
        ]
        last_count = len(imported)
        if imported:
            return {
                "series_id": series_id,
                "episode_count": len(rows),
                "imported_episode_count": len(imported),
            }
        time.sleep(10.0)
    raise RuntimeError(f"Sonarr did not import any episode before timeout. Imported count: {last_count}.")


def wait_for_transfer_absent(base_url: str, emule_api_key: str, transfer_hash: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until a native transfer hash disappears."""

    expected_hash = transfer_hash.lower()
    deadline = time.monotonic() + timeout_seconds
    last_count = 0
    while time.monotonic() < deadline:
        request_timeout = min(30.0, max(1.0, deadline - time.monotonic()))
        result = rest_smoke.http_request(
            base_url,
            "/api/v1/transfers",
            api_key=emule_api_key,
            request_timeout_seconds=request_timeout,
        )
        transfers = rest_smoke.require_json_array(result, 200)
        last_count = len(transfers)
        if not any(isinstance(transfer, dict) and str(transfer.get("hash") or "").lower() == expected_hash for transfer in transfers):
            return {"hash": expected_hash, "absent": True, "last_count": last_count}
        time.sleep(1.0)
    raise RuntimeError(f"Deleted qBit transfer still appeared before timeout ({last_count} transfers).")


def delete_transfer(base_url: str, emule_api_key: str, transfer_hash: str) -> dict[str, object]:
    """Removes one temporary transfer from the native eMule profile."""

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash}",
        method="DELETE",
        api_key=emule_api_key,
        json_body={"deleteFiles": True},
        request_timeout_seconds=20.0,
    )
    return rest_smoke.compact_http_result(result)


def qbit_direct_live_wire_roundtrip(
    base_url: str,
    emule_api_key: str,
    magnet: str,
    *,
    initial_category: str,
    updated_category: str,
    timeout_seconds: float,
    expected_save_path: str | None = None,
    progress: dict[str, object] | None = None,
) -> dict[str, object]:
    """Exercises qBittorrent-compatible add, mutate, verify, and delete flow."""

    report = progress if progress is not None else {}
    transfer_hash = ""
    qbit_delete_completed = False
    try:
        cookie, login = qbit_login(base_url, emule_api_key)
        report["login_status"] = int(login.get("status") or 0)
        added = qbit_direct_add(base_url, emule_api_key, magnet, initial_category, cookie=cookie)
        report["add"] = added
        transfer_hash = str(added["hash"])
        info_after_add = qbit_request(base_url, "/api/v2/torrents/info", cookie=cookie, timeout_seconds=30.0)
        info_rows = require_qbit_json(info_after_add, "qBit torrents info after add")
        if not isinstance(info_rows, list):
            raise RuntimeError("qBit torrents info after add did not return a list.")
        matching_info_rows = [row for row in info_rows if isinstance(row, dict) and str(row.get("hash") or "").lower() == transfer_hash]
        if not matching_info_rows:
            raise RuntimeError("qBit torrents info after add did not include the selected transfer.")
        matching_info_row = matching_info_rows[0]
        report["info_after_add"] = {"status": int(info_after_add.get("status") or 0), "count": len(info_rows)}

        filtered_info = qbit_request(
            base_url,
            "/api/v2/torrents/info?category=" + urllib.parse.quote(initial_category),
            cookie=cookie,
            timeout_seconds=30.0,
        )
        filtered_rows = require_qbit_json(filtered_info, "qBit category-filtered torrents info after add")
        if not isinstance(filtered_rows, list) or not any(
            isinstance(row, dict) and str(row.get("hash") or "").lower() == transfer_hash
            for row in filtered_rows
        ):
            raise RuntimeError("qBit category-filtered info did not include the selected transfer.")

        properties = qbit_request(
            base_url,
            "/api/v2/torrents/properties?hash=" + urllib.parse.quote(transfer_hash),
            cookie=cookie,
            timeout_seconds=30.0,
        )
        properties_body = require_qbit_json(properties, "qBit torrent properties after add")
        if not isinstance(properties_body, dict):
            raise RuntimeError("qBit torrent properties after add did not return an object.")

        files = qbit_request(
            base_url,
            "/api/v2/torrents/files?hash=" + urllib.parse.quote(transfer_hash),
            cookie=cookie,
            timeout_seconds=30.0,
        )
        files_body = require_qbit_json(files, "qBit torrent files after add")
        if not isinstance(files_body, list):
            raise RuntimeError("qBit torrent files after add did not return a list.")
        path_contract = summarize_qbit_import_path_contract(
            matching_info_row,
            properties_body,
            files_body,
            expected_save_path=expected_save_path,
        )
        if expected_save_path and (
            not path_contract.get("info_save_path_matches_expected")
            or not path_contract.get("properties_save_path_matches_expected")
            or not path_contract.get("content_path_matches_name")
        ):
            raise RuntimeError(f"qBit import path contract mismatch: {path_contract!r}")
        report["active_metadata"] = {
            "filtered_info_count": len(filtered_rows),
            "properties_status": int(properties.get("status") or 0),
            "files_count": len(files_body),
            "path_contract": path_contract,
        }

        set_category = qbit_request(
            base_url,
            "/api/v2/torrents/setCategory",
            cookie=cookie,
            form={"hashes": transfer_hash, "category": updated_category},
            method="POST",
        )
        require_qbit_ok(set_category, "qBit setCategory")
        report["set_category_status"] = int(set_category.get("status") or 0)
        report["updated_native_category"] = wait_for_transfer_category(
            base_url,
            emule_api_key,
            transfer_hash,
            updated_category,
            timeout_seconds,
        )

        resume = qbit_request(
            base_url,
            "/api/v2/torrents/resume",
            cookie=cookie,
            form={"hashes": transfer_hash},
            method="POST",
        )
        require_qbit_ok(resume, "qBit resume")
        report["resume_status"] = int(resume.get("status") or 0)

        pause = qbit_request(
            base_url,
            "/api/v2/torrents/pause",
            cookie=cookie,
            form={"hashes": transfer_hash},
            method="POST",
        )
        require_qbit_ok(pause, "qBit pause")
        report["pause_status"] = int(pause.get("status") or 0)

        delete = qbit_request(
            base_url,
            "/api/v2/torrents/delete",
            cookie=cookie,
            form={"hashes": transfer_hash, "deleteFiles": "true"},
            method="POST",
            timeout_seconds=30.0,
        )
        require_qbit_ok(delete, "qBit delete")
        qbit_delete_completed = True
        report["delete_status"] = int(delete.get("status") or 0)
        deleted_seen = wait_for_transfer_absent(base_url, emule_api_key, transfer_hash, timeout_seconds)
        report["deleted_transfer"] = deleted_seen
    finally:
        if transfer_hash and not qbit_delete_completed:
            try:
                report["native_cleanup_delete"] = delete_transfer(base_url, emule_api_key, transfer_hash)
            except Exception as cleanup_exc:
                report["native_cleanup_delete"] = {
                    "status": "cleanup_failed",
                    "error": str(cleanup_exc),
                }

    return report


def redact_qbit_roundtrip_report(report: dict[str, object]) -> dict[str, object]:
    """Redacts exact qBit live-wire transfer identifiers from one round report."""

    redacted: dict[str, object] = {
        "query_present": bool(report.get("query")),
        "title_present": bool(report.get("title")),
        "expected_hash_present": bool(report.get("expected_hash")),
    }
    for key in (
        "login_status",
        "info_after_add",
        "active_metadata",
        "set_category_status",
        "resume_status",
        "pause_status",
        "delete_status",
        "native_cleanup_delete",
    ):
        if key in report:
            redacted[key] = report[key]
    add = report.get("add")
    if isinstance(add, dict):
        redacted["add"] = {
            "add_status": add.get("add_status"),
            "login_status": add.get("login_status"),
            "hash_present": bool(add.get("hash")),
        }
    updated = report.get("updated_native_category")
    if isinstance(updated, dict):
        redacted["updated_native_category"] = {
            "hash_present": bool(updated.get("hash")),
            "name_present": bool(updated.get("name")),
            "state": updated.get("state"),
            "categoryName": updated.get("categoryName"),
        }
    deleted = report.get("deleted_transfer")
    if isinstance(deleted, dict):
        redacted["deleted_transfer"] = {
            "hash_present": bool(deleted.get("hash")),
            "absent": deleted.get("absent"),
            "last_count": deleted.get("last_count"),
        }
    return redacted


def normalize_path_for_compare(value: object) -> str:
    """Normalizes an adapter path enough for Windows-style contract checks."""

    return str(value or "").replace("/", "\\").rstrip("\\").lower()


def summarize_qbit_import_path_contract(
    info_row: dict[str, object],
    properties_body: dict[str, object],
    files_body: list[object],
    *,
    expected_save_path: str | None,
) -> dict[str, object]:
    """Returns redacted qBit import path contract diagnostics."""

    info_save_path = str(info_row.get("save_path") or "")
    properties_save_path = str(properties_body.get("save_path") or "")
    content_path = str(info_row.get("content_path") or properties_body.get("content_path") or "")
    first_file = files_body[0] if files_body and isinstance(files_body[0], dict) else {}
    file_name = str(first_file.get("name") or info_row.get("name") or "")
    expected_norm = normalize_path_for_compare(expected_save_path)
    info_norm = normalize_path_for_compare(info_save_path)
    properties_norm = normalize_path_for_compare(properties_save_path)
    content_norm = normalize_path_for_compare(content_path)
    file_norm = normalize_path_for_compare(file_name)
    rooted_content = bool(expected_norm) and content_norm.startswith(expected_norm + "\\")
    return {
        "expected_save_path_present": bool(expected_save_path),
        "info_save_path_present": bool(info_save_path),
        "properties_save_path_present": bool(properties_save_path),
        "info_save_path_matches_expected": None if not expected_save_path else info_norm == expected_norm,
        "properties_save_path_matches_expected": None if not expected_save_path else properties_norm == expected_norm,
        "content_path_present": bool(content_path),
        "file_name_present": bool(file_name),
        "content_path_under_save_path": None if not expected_save_path else rooted_content,
        "content_path_matches_name": bool(content_norm and file_norm and (content_norm == file_norm or content_norm.endswith("\\" + file_norm))),
    }


def qbit_direct_live_wire_stress(
    base_url: str,
    emule_api_key: str,
    magnets: list[dict[str, str]],
    *,
    rounds: int,
    timeout_seconds: float,
    initial_category: str = "RADARR_ENG",
    updated_category: str = RADARR_IMPORT_CATEGORY,
    expected_save_path: str | None = None,
) -> dict[str, object]:
    """Runs repeated qBittorrent add/mutate/delete live-wire rounds."""

    if rounds <= 0:
        raise RuntimeError("qBit live-wire stress requires at least one round.")
    if len(magnets) < rounds:
        raise RuntimeError(f"qBit live-wire stress needs {rounds} unique magnet(s), got {len(magnets)}.")
    runs: list[dict[str, object]] = []
    for index, magnet in enumerate(magnets[:rounds]):
        run_report: dict[str, object] = {
            "query": magnet.get("query"),
            "title": magnet.get("title"),
            "expected_hash": magnet.get("hash"),
        }
        qbit_direct_live_wire_roundtrip(
            base_url,
            emule_api_key,
            magnet["magnet"],
            initial_category=initial_category,
            updated_category=updated_category,
            timeout_seconds=timeout_seconds,
            expected_save_path=expected_save_path,
            progress=run_report,
        )
        runs.append(redact_qbit_roundtrip_report(run_report))
        if index + 1 >= rounds:
            break
    return {"rounds": len(runs), "runs": runs}


def wait_for_arr_release_results(
    arr_url: str,
    api_key: str,
    indexer_id: int,
    terms: tuple[str, ...],
    timeout_seconds: float,
) -> dict[str, object]:
    """Polls Radarr/Sonarr release RSS/search until the synced indexer appears."""

    attempts: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for term_index, term in enumerate(terms):
            path = f"/api/v3/release?term={urllib.parse.quote(term)}&indexerIds={indexer_id}"
            result = arr_request(arr_url, api_key, path, timeout_seconds=90.0)
            payload = result.get("json")
            rows = payload if isinstance(payload, list) else []
            matches = [row for row in rows if isinstance(row, dict) and is_emulebb_arr_release(row, indexer_id)]
            attempts.append(
                {
                    "term_index": term_index,
                    "term_present": bool(term),
                    "status": int(result.get("status") or 0),
                    "count": len(rows),
                    "matches": len(matches),
                }
            )
            if matches:
                selected = select_best_arr_release(matches, term)
                return {
                    "term_index": term_index,
                    "term_present": bool(term),
                    "count": len(matches),
                    "first_title_present": bool(selected.get("title")) if isinstance(selected, dict) else False,
                    "indexer": selected.get("indexer"),
                    "selection": prowlarr_live.summarize_release_selection(selected, term),
                    "attempt_count": len(attempts),
                }
        time.sleep(5.0)
    raise RuntimeError(f"Arr release searches returned no eMule BB rows before timeout. Attempts: {attempts!r}")


def build_parser() -> argparse.ArgumentParser:
    """Builds the Radarr/Sonarr eMule BB live test argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--env-file", default=str((REPO_ROOT / live_env.DEFAULT_ENV_FILE_NAME).resolve()))
    parser.add_argument("--emule-api-key", default="arr-emulebb-live-key")
    parser.add_argument("--bind-addr")
    parser.add_argument("--enable-upnp", action="store_true", default=True)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS)
    parser.add_argument("--emule-connection-timeout-seconds", type=float, default=DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS)
    parser.add_argument("--result-timeout-seconds", type=float, default=DEFAULT_SEARCH_TIMEOUT_SECONDS)
    parser.add_argument("--radarr-release-timeout-seconds", type=float, default=DEFAULT_SEARCH_TIMEOUT_SECONDS)
    parser.add_argument("--prowlarr-indexer-availability-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--arr-kind", choices=["radarr", "sonarr"], default="radarr")
    parser.add_argument("--acquisition-timeout-minutes", type=float)
    parser.add_argument(
        "--radarr-movie-root",
        help="Optional Radarr-visible root folder path for the import proof. Defaults to a local artifact folder.",
    )
    parser.add_argument(
        "--radarr-quality-profile-name",
        help="Radarr quality profile used by the movie acquisition proof. Defaults to AnyAnyLang or RADARR_QUALITY_PROFILE_NAME.",
    )
    parser.add_argument(
        "--sonarr-series-root",
        help="Optional Sonarr-visible root folder path for the import proof. Defaults to a local artifact folder.",
    )
    parser.add_argument(
        "--sonarr-quality-profile-name",
        help="Sonarr quality profile used by the series acquisition proof. Defaults to AnyAnyLang or SONARR_QUALITY_PROFILE_NAME.",
    )
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)),
    )
    return parser


def run_arr_checks(
    *,
    kind: str,
    arr_url: str,
    arr_api_key: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    prowlarr_indexer_id: int,
    bind_addr: str,
    port: int,
    emule_api_key: str,
    indexer_name: str,
    release_terms: tuple[str, ...],
    timeout_seconds: float,
    category_override: str | None = None,
    search_releases: bool = True,
) -> tuple[dict[str, object], int | None]:
    """Runs one Radarr or Sonarr live integration check."""

    category = category_override or RADARR_IMPORT_CATEGORY
    category_field = "movieCategory" if kind == "radarr" else "tvCategory"
    torznab_category = TORZNAB_MOVIE_CATEGORY if kind == "radarr" else TORZNAB_TV_CATEGORY
    temp_client_name = f"eMule BB Live {kind} {port}"
    status_payload = require_success(arr_request(arr_url, arr_api_key, "/api/v3/system/status"), f"{kind} status")
    synced_indexer, indexer_repair = ensure_arr_emule_indexer(
        arr_url=arr_url,
        api_key=arr_api_key,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=torznab_category,
    )
    synced_indexer, indexer_health_repair = recreate_arr_emule_indexer_if_unavailable(
        arr_url=arr_url,
        api_key=arr_api_key,
        indexer=synced_indexer,
        indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        category_id=torznab_category,
    )
    synced_indexer, indexer_enable = ensure_arr_indexer_enabled(arr_url, arr_api_key, synced_indexer)
    synced_indexer, indexer_tags = ensure_arr_indexer_untagged(arr_url, arr_api_key, synced_indexer)
    stale_clients = delete_stale_live_download_clients(arr_url, arr_api_key, kind=kind)
    client = create_temp_qbit_client(
        arr_url,
        arr_api_key,
        name=temp_client_name,
        host=bind_addr,
        port=port,
        emule_api_key=emule_api_key,
        category_field=category_field,
        category=category,
    )
    report: dict[str, object] = {
        "status": {
            "appName": status_payload.get("appName") if isinstance(status_payload, dict) else None,
            "version": status_payload.get("version") if isinstance(status_payload, dict) else None,
        },
        "indexer_repair": indexer_repair,
        "indexer_health_repair": indexer_health_repair,
        "indexer_enable": indexer_enable,
        "indexer_tags": indexer_tags,
        "stale_download_clients": stale_clients,
        "synced_indexer": summarize_arr_indexer(synced_indexer),
        "download_client": summarize_arr_download_client(client, category=category),
        "readiness": {
            "indexer_synced": int(synced_indexer.get("id") or 0) > 0,
            "indexer_enabled": is_arr_indexer_enabled(synced_indexer),
            "download_client_created": int(client["id"]) > 0,
            "download_client_tested": int(client.get("_emulebbTestStatus") or 0) >= 200
            and int(client.get("_emulebbTestStatus") or 0) < 300,
        },
    }
    if search_releases:
        try:
            report["release_search"] = wait_for_arr_release_results(
                arr_url,
                arr_api_key,
                int(synced_indexer.get("id") or 0),
                release_terms,
                timeout_seconds,
            )
        except Exception as exc:
            report["release_search"] = {"status": "inconclusive", "error": str(exc)}
    else:
        report["release_search"] = {
            "status": "skipped",
            "reason": "Radarr movie download proof owns the movie release search and grab.",
        }
    return report, int(client["id"])


def run_radarr_movie_download_e2e(
    *,
    radarr_url: str,
    radarr_api_key: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    emule_base_url: str,
    emule_api_key: str,
    indexer_id: int,
    indexer_name: str,
    prowlarr_indexer_id: int,
    movie_title: str,
    movie_root: Path | str,
    category_name: str,
    category_save_path: Path | str,
    movie_root_creates_local_path: bool,
    quality_profile_name: str | None,
    release_search_timeout_seconds: float,
    timeout_seconds: float,
) -> tuple[dict[str, object], int | None]:
    """Runs the Radarr movie grab-to-eMule-category proof."""

    movie = ensure_radarr_movie(
        radarr_url,
        radarr_api_key,
        movie_title,
        movie_root,
        create_local_root_path=movie_root_creates_local_path,
        quality_profile_name=quality_profile_name,
    )
    movie_id = int(movie["id"])
    report: dict[str, object] = {
        "movie_title_present": bool(movie_title),
        "movie_id": movie_id,
        "movie_created": bool(movie.get("created")),
        "movie_updated": bool(movie.get("updated")),
        "category": category_name,
        "root_folder": movie.get("root_folder"),
        "quality_profile": movie.get("quality_profile"),
    }
    health = arr_health_rows(radarr_url, radarr_api_key)
    report["indexer_health"] = {
        "unavailable_due_to_failures": arr_indexer_unavailable_due_to_failures(health, indexer_name),
        "indexer_status_messages": [
            str(row.get("message") or "")
            for row in health
            if str(row.get("source") or "") == "IndexerStatusCheck"
        ],
    }
    release_grab = grab_first_arr_release_or_fallback_to_prowlarr(
        kind="radarr",
        arr_url=radarr_url,
        arr_api_key=radarr_api_key,
        arr_indexer_id=indexer_id,
        arr_indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        emule_base_url=emule_base_url,
        emule_api_key=emule_api_key,
        title=movie_title,
        media_id=movie_id,
        category_id=TORZNAB_MOVIE_CATEGORY,
        download_category=category_name,
        timeout_seconds=min(release_search_timeout_seconds, ARR_LIVE_SEARCH_TIMEOUT_SECONDS),
        health_rows=health,
    )
    report["release_grab"] = {key: value for key, value in release_grab.items() if key != "hash"}
    transfer_hash = str(release_grab.get("hash") or "")
    if not transfer_hash:
        raise RuntimeError("Radarr release grab did not expose an eMule BB magnet hash.")
    if isinstance(release_grab.get("category_transfer"), dict):
        report["category_transfer"] = release_grab["category_transfer"]
    else:
        report["category_transfer"] = wait_for_transfer_category(
            emule_base_url,
            emule_api_key,
            transfer_hash,
            category_name,
            min(timeout_seconds, 120.0),
        )
    report["resume_if_paused"] = resume_transfer_if_paused(
        emule_base_url,
        emule_api_key,
        transfer_hash,
        report["category_transfer"],
    )
    report["completed_transfer"] = wait_for_transfer_completion(
        emule_base_url,
        emule_api_key,
        transfer_hash,
        timeout_seconds,
    )
    report["downloaded_scan"] = trigger_arr_downloaded_scan(
        radarr_url,
        radarr_api_key,
        "radarr",
        category_save_path,
    )
    report["arr_import"] = wait_for_radarr_import(radarr_url, radarr_api_key, movie_id, timeout_seconds)
    return report, movie_id if bool(movie.get("created")) else None


def run_sonarr_series_download_e2e(
    *,
    sonarr_url: str,
    sonarr_api_key: str,
    prowlarr_url: str,
    prowlarr_api_key: str,
    emule_base_url: str,
    emule_api_key: str,
    indexer_id: int,
    indexer_name: str,
    prowlarr_indexer_id: int,
    series_title: str,
    series_root: Path | str,
    category_name: str,
    category_save_path: Path | str,
    series_root_creates_local_path: bool,
    quality_profile_name: str | None,
    release_search_timeout_seconds: float,
    timeout_seconds: float,
) -> tuple[dict[str, object], int | None]:
    """Runs the Sonarr series grab-to-import proof."""

    series = ensure_sonarr_series(
        sonarr_url,
        sonarr_api_key,
        series_title,
        series_root,
        create_local_root_path=series_root_creates_local_path,
        quality_profile_name=quality_profile_name,
    )
    series_id = int(series["id"])
    report: dict[str, object] = {
        "series_title_present": bool(series_title),
        "series_id": series_id,
        "series_created": bool(series.get("created")),
        "series_updated": bool(series.get("updated")),
        "category": category_name,
        "root_folder": series.get("root_folder"),
        "quality_profile": series.get("quality_profile"),
    }
    health = arr_health_rows(sonarr_url, sonarr_api_key)
    report["indexer_health"] = {
        "unavailable_due_to_failures": arr_indexer_unavailable_due_to_failures(health, indexer_name),
        "indexer_status_messages": [
            str(row.get("message") or "")
            for row in health
            if str(row.get("source") or "") == "IndexerStatusCheck"
        ],
    }
    release_grab = grab_first_arr_release_or_fallback_to_prowlarr(
        kind="sonarr",
        arr_url=sonarr_url,
        arr_api_key=sonarr_api_key,
        arr_indexer_id=indexer_id,
        arr_indexer_name=indexer_name,
        prowlarr_url=prowlarr_url,
        prowlarr_api_key=prowlarr_api_key,
        prowlarr_indexer_id=prowlarr_indexer_id,
        emule_base_url=emule_base_url,
        emule_api_key=emule_api_key,
        title=series_title,
        media_id=series_id,
        category_id=TORZNAB_TV_CATEGORY,
        download_category=category_name,
        timeout_seconds=min(release_search_timeout_seconds, ARR_LIVE_SEARCH_TIMEOUT_SECONDS),
        health_rows=health,
    )
    report["release_grab"] = {key: value for key, value in release_grab.items() if key != "hash"}
    transfer_hash = str(release_grab.get("hash") or "")
    if not transfer_hash:
        raise RuntimeError("Sonarr release grab did not expose an eMule BB magnet hash.")
    if isinstance(release_grab.get("category_transfer"), dict):
        report["category_transfer"] = release_grab["category_transfer"]
    else:
        report["category_transfer"] = wait_for_transfer_category(
            emule_base_url,
            emule_api_key,
            transfer_hash,
            category_name,
            min(timeout_seconds, 120.0),
        )
    report["resume_if_paused"] = resume_transfer_if_paused(
        emule_base_url,
        emule_api_key,
        transfer_hash,
        report["category_transfer"],
    )
    report["completed_transfer"] = wait_for_transfer_completion(
        emule_base_url,
        emule_api_key,
        transfer_hash,
        timeout_seconds,
    )
    report["downloaded_scan"] = trigger_arr_downloaded_scan(
        sonarr_url,
        sonarr_api_key,
        "sonarr",
        category_save_path,
    )
    report["arr_import"] = wait_for_sonarr_import(sonarr_url, sonarr_api_key, series_id, timeout_seconds)
    return report, series_id if bool(series.get("created")) else None


def require_arr_check_passed(kind: str, report: dict[str, object]) -> None:
    """Fails the live suite when a Radarr/Sonarr proof only recorded diagnostics."""

    readiness = report.get("readiness")
    if not isinstance(readiness, dict) or not all(bool(value) for value in readiness.values()):
        raise RuntimeError(f"{kind} eMule BB readiness failed: {readiness!r}")
    release_search = report.get("release_search")
    if isinstance(release_search, dict) and release_search.get("status") == "inconclusive":
        raise RuntimeError(f"{kind} eMule BB release search failed: {release_search!r}")


def read_log_tail(path: Path, max_lines: int = 80) -> list[str]:
    """Reads a bounded tail from a live eMule log file."""

    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def summarize_live_logs(profile: dict[str, object]) -> dict[str, object]:
    """Builds report metadata proving live logs were enabled and persisted."""

    log_dir = Path(profile["log_dir"])
    main_log = log_dir / "eMule.log"
    verbose_log = log_dir / "eMule_Verbose.log"
    return {
        "log_dir": str(log_dir),
        "main_log": str(main_log),
        "verbose_log": str(verbose_log),
        "main_log_present": main_log.is_file(),
        "verbose_log_present": verbose_log.is_file(),
        "main_log_size": main_log.stat().st_size if main_log.is_file() else 0,
        "verbose_log_size": verbose_log.stat().st_size if verbose_log.is_file() else 0,
    }


def append_failure_log_tails(report: dict[str, object], profile: dict[str, object]) -> None:
    """Adds bounded eMule log tails to a failed live report."""

    log_dir = Path(profile["log_dir"])
    report["failure_log_tails"] = {
        "eMule.log": read_log_tail(log_dir / "eMule.log"),
        "eMule_Verbose.log": read_log_tail(log_dir / "eMule_Verbose.log"),
    }


def parse_timeout_minutes(value: str | None, default_minutes: float) -> float:
    """Parses an optional timeout in minutes from dotenv values."""

    if value is None or not str(value).strip():
        return default_minutes
    parsed = float(value)
    if parsed <= 0:
        raise ValueError("Acquisition timeout minutes must be greater than zero.")
    return parsed


def main() -> int:
    """Runs the live Radarr/Sonarr eMule BB bridge test."""

    args = build_parser().parse_args()
    kind = args.arr_kind
    if args.radarr_release_timeout_seconds <= 0:
        raise ValueError("--radarr-release-timeout-seconds must be greater than zero.")
    if args.rest_ready_timeout_seconds <= 0:
        raise ValueError("--rest-ready-timeout-seconds must be greater than zero.")
    if args.emule_connection_timeout_seconds <= 0:
        raise ValueError("--emule-connection-timeout-seconds must be greater than zero.")
    if args.result_timeout_seconds <= 0:
        raise ValueError("--result-timeout-seconds must be greater than zero.")
    if args.prowlarr_indexer_availability_timeout_seconds <= 0:
        raise ValueError("--prowlarr-indexer-availability-timeout-seconds must be greater than zero.")
    env_values = live_env.load_env_values(
        (
            "PROWLARR_URL",
            "PROWLARR_API_KEY",
            "RADARR_URL",
            "RADARR_API_KEY",
            "SONARR_URL",
            "SONARR_API_KEY",
        ),
        env_file=Path(args.env_file).resolve(),
        defaults={"PROWLARR_EMULEBB_INDEXER_NAME": "eMule BB Local"},
    )
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    if kind == "radarr":
        media_terms = prowlarr_live.first_live_wire_term(
            require_radarr_import_movie_terms(inputs),
            "search_terms.radarr_movies",
        )
        arr_url = env_values["RADARR_URL"].rstrip("/")
        arr_api_key = env_values["RADARR_API_KEY"]
        arr_category = RADARR_IMPORT_CATEGORY
        arr_category_key = "emule_radarr_category"
        arr_term_key = "radarr_movies"
        arr_media_category_key = "radarr_release"
        torznab_media_category = TORZNAB_MOVIE_CATEGORY
        suite_name = "radarr-emulebb-live"
        acquisition_check_key = RADARR_DOWNLOAD_PROOF_CHECK_KEY
        root_arg = args.radarr_movie_root
        media_root: Path | str = root_arg.strip() if root_arg else None  # type: ignore[assignment]
        quality_profile_name = args.radarr_quality_profile_name or DEFAULT_MEDIA_QUALITY_PROFILE_NAME
    else:
        media_terms = prowlarr_live.first_live_wire_term(
            require_sonarr_import_series_terms(inputs),
            "search_terms.sonarr_series",
        )
        arr_url = env_values["SONARR_URL"].rstrip("/")
        arr_api_key = env_values["SONARR_API_KEY"]
        arr_category = SONARR_IMPORT_CATEGORY
        arr_category_key = "emule_sonarr_category"
        arr_term_key = "sonarr_series"
        arr_media_category_key = "sonarr_release"
        torznab_media_category = TORZNAB_TV_CATEGORY
        suite_name = "sonarr-emulebb-live"
        acquisition_check_key = SONARR_DOWNLOAD_PROOF_CHECK_KEY
        root_arg = args.sonarr_series_root
        media_root = root_arg.strip() if root_arg else None  # type: ignore[assignment]
        quality_profile_name = args.sonarr_quality_profile_name or DEFAULT_MEDIA_QUALITY_PROFILE_NAME
    prowlarr_url = env_values["PROWLARR_URL"].rstrip("/")
    prowlarr_api_key = env_values["PROWLARR_API_KEY"]
    indexer_name = env_values["PROWLARR_EMULEBB_INDEXER_NAME"]
    bind_addr = prowlarr_live.resolve_bind_addr(prowlarr_url, args.bind_addr)
    port = prowlarr_live.choose_listen_port(bind_addr)
    emule_base_url = f"http://{bind_addr}:{port}"
    torznab_base_url = f"{emule_base_url}/indexer/emulebb"

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=suite_name,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    artifacts_dir = paths.source_artifacts_dir
    result_path = artifacts_dir / "result.json"
    if media_root is None:
        media_root = artifacts_dir / arr_category
    media_root_creates_local_path = not bool(root_arg)
    media_root_warning = build_arr_root_environment_warning(
        arr_url,
        media_root,
        create_local_path=media_root_creates_local_path,
        kind=kind,
    )
    acquisition_timeout_seconds = 60.0 * (
        args.acquisition_timeout_minutes
        if args.acquisition_timeout_minutes is not None
        else parse_timeout_minutes(env_values.get("ACQUISITION_ATTEMPT_TIMEOUT_MINUTES"), DEFAULT_MEDIA_ACQUISITION_TIMEOUT_MINUTES)
    )
    profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
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
    )
    if args.p2p_bind_interface_name:
        rest_smoke.apply_p2p_bind_interface_override(
            Path(profile["config_dir"]),
            args.p2p_bind_interface_name,
        )

    app = None
    main_window = None
    cleanup_clients: list[tuple[str, str, int]] = []
    cleanup_radarr_movies: list[tuple[str, str, int]] = []
    cleanup_sonarr_series: list[tuple[str, str, int]] = []
    indexer_restore_target: tuple[str, str, list[dict[str, Any]]] | None = None
    report: dict[str, object] = {
        "suite": suite_name,
        "arr_kind": kind,
        "status": "running",
        "emule_base_url": emule_base_url,
        "torznab_base_url": torznab_base_url,
        "indexer_name": indexer_name,
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
            "log_dir": str(profile["log_dir"]),
        },
        "live_logs": summarize_live_logs(profile),
        "live_wire_inputs_file": str(inputs.path),
        "live_wire_search_terms": {
            arr_term_key: live_wire_inputs.summarize_terms(media_terms),
        },
        "torznab_media_categories": {
            arr_media_category_key: torznab_media_category,
        },
        f"{kind}_acquisition": {
            "title_present": any(bool(term) for term in media_terms),
            "category": arr_category,
            "root_configured": bool(root_arg),
            "root_path_present": bool(str(media_root).strip()),
            "root_creates_local_path": media_root_creates_local_path,
            "quality_profile_name": quality_profile_name,
            "environment_warning": media_root_warning,
            "acquisition_timeout_seconds": acquisition_timeout_seconds,
            "search_timeout_seconds": min(args.radarr_release_timeout_seconds, ARR_LIVE_SEARCH_TIMEOUT_SECONDS),
            "emule_connection_timeout_seconds": args.emule_connection_timeout_seconds,
            "prowlarr_indexer_availability_timeout_seconds": args.prowlarr_indexer_availability_timeout_seconds,
        },
        "checks": {},
    }

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
        report["checks"]["shared_hashing_idle_after_rest_ready"] = wait_for_shared_hashing_idle(
            emule_base_url,
            args.emule_api_key,
        )
        report["checks"]["search_tabs_before_clear"] = list_emule_searches(emule_base_url, args.emule_api_key)
        report["checks"]["clear_existing_search_tabs"] = delete_all_emule_searches(emule_base_url, args.emule_api_key)
        report["checks"]["search_tabs_after_clear"] = list_emule_searches(emule_base_url, args.emule_api_key)
        arr_category_path = artifacts_dir / arr_category
        arr_category_summary = ensure_emule_category(
            emule_base_url,
            args.emule_api_key,
            arr_category,
            arr_category_path,
        )
        report["checks"][arr_category_key] = arr_category_summary
        arr_category_save_path = str(arr_category_summary.get("path") or arr_category_path.resolve())
        report["checks"]["shared_hashing_idle_after_category_setup"] = wait_for_shared_hashing_idle(
            emule_base_url,
            args.emule_api_key,
        )
        servers = rest_smoke.http_request(emule_base_url, "/api/v1/servers", api_key=args.emule_api_key)
        server_rows = rest_smoke.require_json_array(servers, 200)
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
        if int(kad_connect["status"]) != 200:
            raise RuntimeError(f"Kad start returned HTTP {kad_connect['status']}")
        record_phase("network_ready")
        report["checks"]["network_ready"] = rest_smoke.wait_for_requested_networks(
            emule_base_url,
            args.emule_api_key,
            args.emule_connection_timeout_seconds,
            require_server_connected=False,
            require_kad_connected=True,
        )
        record_phase("prowlarr_indexer_upsert")
        prowlarr_indexer_sync_tags = resolve_prowlarr_indexer_sync_tags(
            prowlarr_url,
            prowlarr_api_key,
            arr_url,
        )
        saved_indexer = prowlarr_live.upsert_indexer(
            prowlarr_url,
            prowlarr_api_key,
            indexer_name=indexer_name,
            torznab_base_url=torznab_base_url,
            emule_api_key=args.emule_api_key,
            tags=prowlarr_indexer_sync_tags,
        )
        report["checks"]["prowlarr_indexer"] = {
            "id": int(saved_indexer["id"]),
            "name": saved_indexer.get("name"),
            "tags": saved_indexer.get("tags"),
            "sync_tags": prowlarr_indexer_sync_tags,
            "unavailableAtUpsert": bool(saved_indexer.get("_emulebbUnavailableAtUpsert")),
        }
        report["checks"]["prowlarr_indexer_availability"] = prowlarr_live.wait_for_indexer_available(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            args.prowlarr_indexer_availability_timeout_seconds,
        )
        selected_media_terms = media_terms
        report[f"{kind}_acquisition"]["selected_term_index"] = 0
        record_phase("prowlarr_application_sync")
        report["checks"]["prowlarr_sync"] = force_prowlarr_application_sync(
            prowlarr_url,
            prowlarr_api_key,
            args.result_timeout_seconds,
        )

        record_phase(f"{kind}_readiness")
        arr_report, arr_client_id = run_arr_checks(
            kind=kind,
            arr_url=arr_url,
            arr_api_key=arr_api_key,
            prowlarr_url=prowlarr_url,
            prowlarr_api_key=prowlarr_api_key,
            prowlarr_indexer_id=int(saved_indexer["id"]),
            bind_addr=bind_addr,
            port=port,
            emule_api_key=args.emule_api_key,
            indexer_name=indexer_name,
            release_terms=selected_media_terms,
            timeout_seconds=args.result_timeout_seconds,
            category_override=arr_category,
            search_releases=False,
        )
        cleanup_clients.append((arr_url, arr_api_key, arr_client_id))
        report["checks"][kind] = arr_report
        require_arr_check_passed(kind, arr_report)
        record_phase(f"{kind}_indexer_isolation")
        indexer_snapshots, isolation_changes = isolate_arr_indexer_search(
            arr_url,
            arr_api_key,
            int(arr_report["synced_indexer"]["id"]),
        )
        indexer_restore_target = (arr_url, arr_api_key, indexer_snapshots)
        report["checks"][f"{kind}_indexer_isolation"] = {
            "allowed_indexer_id": int(arr_report["synced_indexer"]["id"]),
            "snapshot_count": len(indexer_snapshots),
            "changes": isolation_changes,
        }
        record_phase(f"{kind}_search_and_grab")
        if kind == "radarr":
            acquisition_report, cleanup_media_id = run_radarr_movie_download_e2e(
                radarr_url=arr_url,
                radarr_api_key=arr_api_key,
                emule_base_url=emule_base_url,
                emule_api_key=args.emule_api_key,
                indexer_id=int(arr_report["synced_indexer"]["id"]),
                indexer_name=str(arr_report["synced_indexer"].get("name") or indexer_name),
                prowlarr_url=prowlarr_url,
                prowlarr_api_key=prowlarr_api_key,
                prowlarr_indexer_id=int(saved_indexer["id"]),
                movie_title=selected_media_terms[0],
                movie_root=media_root,
                category_name=arr_category,
                category_save_path=arr_category_save_path,
                movie_root_creates_local_path=media_root_creates_local_path,
                quality_profile_name=quality_profile_name,
                release_search_timeout_seconds=args.radarr_release_timeout_seconds,
                timeout_seconds=acquisition_timeout_seconds,
            )
            if cleanup_media_id is not None:
                cleanup_radarr_movies.append((arr_url, arr_api_key, cleanup_media_id))
        else:
            acquisition_report, cleanup_media_id = run_sonarr_series_download_e2e(
                sonarr_url=arr_url,
                sonarr_api_key=arr_api_key,
                emule_base_url=emule_base_url,
                emule_api_key=args.emule_api_key,
                indexer_id=int(arr_report["synced_indexer"]["id"]),
                indexer_name=str(arr_report["synced_indexer"].get("name") or indexer_name),
                prowlarr_url=prowlarr_url,
                prowlarr_api_key=prowlarr_api_key,
                prowlarr_indexer_id=int(saved_indexer["id"]),
                series_title=selected_media_terms[0],
                series_root=media_root,
                category_name=arr_category,
                category_save_path=arr_category_save_path,
                series_root_creates_local_path=media_root_creates_local_path,
                quality_profile_name=quality_profile_name,
                release_search_timeout_seconds=args.radarr_release_timeout_seconds,
                timeout_seconds=acquisition_timeout_seconds,
            )
            if cleanup_media_id is not None:
                cleanup_sonarr_series.append((arr_url, arr_api_key, cleanup_media_id))
        report["checks"][acquisition_check_key] = acquisition_report

        report["status"] = "passed"
        return 0
    except Exception as exc:
        if isinstance(exc, LiveSearchUnavailableError):
            report["status"] = "inconclusive"
            report["inconclusive_reason"] = {"type": type(exc).__name__, "message": str(exc)}
        else:
            report["status"] = "failed"
            report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        exit_code = LIVE_SOURCE_UNAVAILABLE_EXIT_CODE if isinstance(exc, LiveSearchUnavailableError) else 1
        if app is not None:
            try:
                windows = []
                for window in app.windows():
                    windows.append(
                        {
                            "handle": int(window.handle),
                            "class_name": window.class_name(),
                            "text": window.window_text(),
                            "visible": window.is_visible(),
                        }
                    )
                report["failure_windows"] = windows
            except Exception as window_exc:
                report["failure_windows_error"] = str(window_exc)
        if main_window is not None:
            try:
                live_common.dump_window_tree(main_window.handle, artifacts_dir / "window-tree-failure.json")
                report["failure_window_tree"] = "window-tree-failure.json"
            except Exception as tree_exc:
                report["failure_window_tree_error"] = str(tree_exc)
        append_failure_log_tails(report, profile)
        return exit_code
    finally:
        cleanup_report: list[dict[str, object]] = []
        movie_cleanup_report: list[dict[str, object]] = []
        series_cleanup_report: list[dict[str, object]] = []
        if indexer_restore_target is not None:
            restore_url, restore_api_key, restore_snapshots = indexer_restore_target
            try:
                report[ARR_INDEXER_RESTORE_KEY] = restore_arr_indexers(restore_url, restore_api_key, restore_snapshots)
            except Exception as exc:
                report[ARR_INDEXER_RESTORE_KEY] = {"status": "cleanup_failed", "error": str(exc)}
                if report.get("status") == "passed":
                    report["status"] = "failed"
        for arr_url, arr_api_key, movie_id in cleanup_radarr_movies:
            try:
                movie_cleanup_report.append(delete_radarr_movie(arr_url, arr_api_key, movie_id))
            except Exception as exc:
                movie_cleanup_report.append({"id": movie_id, "status": "cleanup_failed", "error": str(exc)})
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if movie_cleanup_report:
            report["cleanup_radarr_movies"] = movie_cleanup_report
        for arr_url, arr_api_key, series_id in cleanup_sonarr_series:
            try:
                series_cleanup_report.append(delete_sonarr_series(arr_url, arr_api_key, series_id))
            except Exception as exc:
                series_cleanup_report.append({"id": series_id, "status": "cleanup_failed", "error": str(exc)})
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if series_cleanup_report:
            report["cleanup_sonarr_series"] = series_cleanup_report
        for arr_url, arr_api_key, client_id in cleanup_clients:
            try:
                cleanup_report.append(delete_download_client(arr_url, arr_api_key, client_id))
            except Exception as exc:
                cleanup_report.append({"id": client_id, "status": "cleanup_failed", "error": str(exc)})
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if cleanup_report:
            report[ARR_DOWNLOAD_CLIENT_CLEANUP_KEY] = cleanup_report
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
                report["cleanup"] = {"closed_app": True}
            except Exception as exc:
                report["cleanup"] = {"closed_app": False, "error": str(exc)}
                if report.get("status") == "passed":
                    report["status"] = "failed"
        report["live_logs"] = summarize_live_logs(profile)
        live_common.write_json(result_path, report)
        paths.run_report_dir.parent.mkdir(parents=True, exist_ok=True)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
        print(f"{kind.title()} eMule BB live test {report['status']}. Report directory: {paths.run_report_dir}")


if __name__ == "__main__":
    raise SystemExit(main())
