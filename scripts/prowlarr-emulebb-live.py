"""Runs a live Prowlarr check against the eMule BB Torznab bridge."""

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


def build_indexer_payload(
    base_payload: dict[str, Any],
    *,
    name: str,
    torznab_base_url: str,
    emule_api_key: str,
    tags: list[int] | None = None,
) -> dict[str, Any]:
    """Builds the persistent Generic Torznab indexer payload for eMule BB."""

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
    return payload


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
        result = prowlarr_request(prowlarr_url, api_key, path, method="PUT", json_body=payload)
        if should_force_save_indexer_validation(result):
            forced_save = True
            result = prowlarr_request(prowlarr_url, api_key, path + "?forceSave=true", method="PUT", json_body=payload)
    else:
        result = prowlarr_request(prowlarr_url, api_key, "/api/v1/indexer", method="POST", json_body=payload)
        if should_force_save_indexer_validation(result):
            forced_save = True
            disabled_payload = json.loads(json.dumps(payload))
            disabled_payload["enable"] = False
            create_result = prowlarr_request(
                prowlarr_url,
                api_key,
                "/api/v1/indexer?forceSave=true",
                method="POST",
                json_body=disabled_payload,
            )
            created = require_success(create_result, "Prowlarr disabled eMule BB indexer create")
            if not isinstance(created, dict) or not created.get("id"):
                raise RuntimeError("Prowlarr did not return a created indexer id.")
            payload["id"] = int(created["id"])
            result = prowlarr_request(
                prowlarr_url,
                api_key,
                f"/api/v1/indexer/{int(created['id'])}?forceSave=true",
                method="PUT",
                json_body=payload,
            )
    saved = require_success(result, "Prowlarr eMule BB indexer upsert")
    if not isinstance(saved, dict) or not saved.get("id"):
        if payload.get("id"):
            saved = get_indexer_by_id(prowlarr_url, api_key, int(payload["id"]))
        else:
            raise RuntimeError("Prowlarr did not return a saved indexer id.")
    saved["_emulebbForcedSave"] = forced_save
    return saved


def test_indexer(prowlarr_url: str, api_key: str, indexer_payload: dict[str, Any]) -> dict[str, object]:
    """Runs Prowlarr's indexer test endpoint for the eMule BB indexer."""

    result = prowlarr_request(
        prowlarr_url,
        api_key,
        "/api/v1/indexer/test",
        method="POST",
        json_body=indexer_payload,
        timeout_seconds=90.0,
    )
    if is_no_results_validation_error(result):
        return {
            "status": "no_results_validation",
            "http_status": int(result.get("status") or 0),
            "body_preview": compact_body_preview(result),
        }
    require_success(result, "Prowlarr eMule BB indexer test")
    return {"status": "passed", "http_status": int(result.get("status") or 0)}


def check_direct_caps(base_url: str, emule_api_key: str) -> dict[str, object]:
    """Validates the direct eMule BB Torznab caps endpoint."""

    path = "/indexer/emulebb/api?t=caps&apikey=" + urllib.parse.quote(emule_api_key)
    result = rest_smoke.http_request(base_url, path, request_timeout_seconds=20.0)
    if int(result.get("status") or 0) != 200:
        raise RuntimeError(f"Direct Torznab caps returned HTTP {result.get('status')}")
    body_text = str(result.get("body_text") or "")
    root = ET.fromstring(body_text)
    if root.tag != "caps":
        raise RuntimeError(f"Direct Torznab caps returned unexpected root: {root.tag}")
    return {"status": 200, "root": root.tag, "length": len(body_text)}


def build_direct_torznab_search_path(emule_api_key: str, query: str, category_id: int) -> str:
    """Builds one direct eMule BB Torznab search path."""

    return (
        f"/indexer/emulebb/api?t=search&cat={int(category_id)}&q="
        + urllib.parse.quote(query)
        + "&apikey="
        + urllib.parse.quote(emule_api_key)
    )


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
        result = rest_smoke.http_request(base_url, path, request_timeout_seconds=45.0)
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
        results.append(
            {
                "name": scenario["name"],
                "status": status,
                "expected_status": scenario["expected_status"],
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
                result = rest_smoke.http_request(base_url, path, request_timeout_seconds=45.0)
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
    raise RuntimeError(f"Direct eMule BB Torznab search returned no results before timeout. Attempts: {attempts!r}")


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
        result = rest_smoke.http_request(base_url, path, request_timeout_seconds=45.0)
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
            path = build_prowlarr_search_path(query, category_id, indexer_id)
            result = prowlarr_request(prowlarr_url, api_key, path, timeout_seconds=90.0)
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
        time.sleep(5.0)
    raise RuntimeError(f"Prowlarr did not return eMule BB results before timeout. Attempts: {attempts!r}")


def build_parser() -> argparse.ArgumentParser:
    """Builds the Prowlarr eMule BB live test argument parser."""

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
    parser.add_argument("--enable-upnp", action="store_true", default=True)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--result-timeout-seconds", type=float, default=300.0)
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
    """Runs the live Prowlarr eMule BB bridge test."""

    args = build_parser().parse_args()
    if args.cached_search_stress_count <= 0:
        raise ValueError("--cached-search-stress-count must be greater than zero.")
    if args.direct_search_stress_count <= 0:
        raise ValueError("--direct-search-stress-count must be greater than zero.")
    if args.prowlarr_search_stress_count <= 0:
        raise ValueError("--prowlarr-search-stress-count must be greater than zero.")
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    document_terms = inputs.document_terms
    radarr_movie_terms = inputs.radarr_movie_terms
    sonarr_series_terms = inputs.sonarr_series_terms
    env_values = live_env.load_env_values(
        ("PROWLARR_URL", "PROWLARR_API_KEY"),
        env_file=Path(args.env_file).resolve(),
        defaults={"PROWLARR_EMULEBB_INDEXER_NAME": "eMule BB Local"},
    )
    prowlarr_url = env_values["PROWLARR_URL"].rstrip("/")
    prowlarr_api_key = env_values["PROWLARR_API_KEY"]
    indexer_name = env_values["PROWLARR_EMULEBB_INDEXER_NAME"]

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
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    artifacts_dir = paths.source_artifacts_dir
    bind_addr = resolve_bind_addr(prowlarr_url, args.bind_addr)
    port = choose_listen_port(bind_addr)
    emule_base_url = f"http://{bind_addr}:{port}"
    torznab_base_url = f"{emule_base_url}/indexer/emulebb"

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
    report: dict[str, object] = {
        "suite": "prowlarr-emulebb-live",
        "status": "running",
        "prowlarr_url": prowlarr_url,
        "indexer_name": indexer_name,
        "emule_base_url": emule_base_url,
        "torznab_base_url": torznab_base_url,
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
            "documents": live_wire_inputs.summarize_terms(document_terms),
            "radarr_movies": live_wire_inputs.summarize_terms(radarr_movie_terms),
            "sonarr_series": live_wire_inputs.summarize_terms(sonarr_series_terms),
        },
        "torznab_media_categories": {
            "movie": TORZNAB_MOVIE_CATEGORY,
            "tv": TORZNAB_TV_CATEGORY,
            "document": TORZNAB_DOCUMENT_CATEGORY,
        },
        "checks": {},
    }
    result_path = artifacts_dir / "result.json"
    try:
        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]))
        main_window = live_common.wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        ready = rest_smoke.wait_for_rest_ready(emule_base_url, args.emule_api_key, args.rest_ready_timeout_seconds)
        report["checks"]["rest_ready"] = rest_smoke.compact_http_result(ready)
        servers = rest_smoke.http_request(emule_base_url, "/api/v1/servers", api_key=args.emule_api_key)
        server_rows = rest_smoke.require_json_array(servers, 200)
        report["checks"]["servers_list"] = {"count": len(server_rows)}
        report["checks"]["servers_connect"] = rest_smoke.connect_to_live_server(
            emule_base_url,
            args.emule_api_key,
            server_rows,
            args.result_timeout_seconds,
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
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["network_ready"] = rest_smoke.wait_for_requested_networks(
            emule_base_url,
            args.emule_api_key,
            args.result_timeout_seconds,
            require_server_connected=False,
            require_kad_connected=True,
        )
        report["checks"]["direct_auth_rejection"] = check_direct_auth_rejection(emule_base_url)
        report["checks"]["direct_torznab_error_edges"] = check_direct_torznab_error_edges(emule_base_url, args.emule_api_key)
        report["checks"]["direct_caps"] = check_direct_caps(emule_base_url, args.emule_api_key)
        report["checks"]["direct_rss_results"] = check_direct_rss_results(
            emule_base_url,
            args.emule_api_key,
            document_terms,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
            source="documents",
        )
        direct_results = wait_for_direct_torznab_results(
            emule_base_url,
            args.emule_api_key,
            document_terms,
            args.result_timeout_seconds,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )
        report["checks"]["direct_search_results"] = redact_term_result(
            direct_results,
            source="documents",
            term_count=len(document_terms),
        )
        direct_movie_results = wait_for_direct_torznab_results(
            emule_base_url,
            args.emule_api_key,
            radarr_movie_terms,
            args.result_timeout_seconds,
            category_id=TORZNAB_MOVIE_CATEGORY,
        )
        report["checks"]["direct_movie_video_results"] = redact_term_result(
            direct_movie_results,
            source="radarr_movies",
            term_count=len(radarr_movie_terms),
        )
        direct_series_results = wait_for_direct_torznab_results(
            emule_base_url,
            args.emule_api_key,
            sonarr_series_terms,
            args.result_timeout_seconds,
            category_id=TORZNAB_TV_CATEGORY,
        )
        report["checks"]["direct_series_video_results"] = redact_term_result(
            direct_series_results,
            source="sonarr_series",
            term_count=len(sonarr_series_terms),
        )
        report["checks"]["direct_cached_search_stress"] = stress_cached_direct_torznab_search(
            emule_base_url,
            args.emule_api_key,
            str(direct_results["query"]),
            args.cached_search_stress_count,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )
        report["checks"]["direct_search_stress"] = stress_direct_torznab_search_terms(
            emule_base_url,
            args.emule_api_key,
            document_terms,
            args.direct_search_stress_count,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )

        status_payload = require_success(
            prowlarr_request(prowlarr_url, prowlarr_api_key, "/api/v1/system/status"),
            "Prowlarr system status",
        )
        report["checks"]["prowlarr_status"] = {
            "appName": status_payload.get("appName") if isinstance(status_payload, dict) else None,
            "version": status_payload.get("version") if isinstance(status_payload, dict) else None,
        }

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
        }
        indexer_statuses = require_success(
            prowlarr_request(prowlarr_url, prowlarr_api_key, "/api/v1/indexerstatus"),
            "Prowlarr indexer status",
        )
        if isinstance(indexer_statuses, list):
            report["checks"]["indexer_status"] = [
                {
                    "indexerId": status.get("indexerId"),
                    "disabledTill": status.get("disabledTill"),
                    "mostRecentFailure": status.get("mostRecentFailure"),
                }
                for status in indexer_statuses
                if isinstance(status, dict) and status.get("indexerId") == int(saved_indexer["id"])
            ]
        report["checks"]["indexer_test"] = test_indexer(prowlarr_url, prowlarr_api_key, saved_indexer)
        report["checks"]["search_results"] = wait_for_prowlarr_results(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            document_terms,
            args.result_timeout_seconds,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )
        report["checks"]["search_results"] = redact_term_result(
            report["checks"]["search_results"],
            source="documents",
            term_count=len(document_terms),
        )
        prowlarr_movie_results = wait_for_prowlarr_results(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            radarr_movie_terms,
            args.result_timeout_seconds,
            category_id=TORZNAB_MOVIE_CATEGORY,
        )
        report["checks"]["prowlarr_movie_video_results"] = redact_term_result(
            prowlarr_movie_results,
            source="radarr_movies",
            term_count=len(radarr_movie_terms),
        )
        prowlarr_series_results = wait_for_prowlarr_results(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            sonarr_series_terms,
            args.result_timeout_seconds,
            category_id=TORZNAB_TV_CATEGORY,
        )
        report["checks"]["prowlarr_series_video_results"] = redact_term_result(
            prowlarr_series_results,
            source="sonarr_series",
            term_count=len(sonarr_series_terms),
        )
        report["checks"]["prowlarr_search_stress"] = stress_prowlarr_search_terms(
            prowlarr_url,
            prowlarr_api_key,
            int(saved_indexer["id"]),
            document_terms,
            args.prowlarr_search_stress_count,
            category_id=TORZNAB_DOCUMENT_CATEGORY,
        )
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return 1
    finally:
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
        print(f"Prowlarr eMule BB live test {report['status']}. Report directory: {paths.run_report_dir}")


if __name__ == "__main__":
    raise SystemExit(main())
