"""Runs live Radarr and Sonarr checks through Prowlarr and eMule BB qBit APIs."""

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

SYNTHETIC_TRIGGER_MAGNET = (
    "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000"
    "&dn=eMuleBB-Live-Wire-Trigger.bin"
    "&xl=1048576"
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


prowlarr_live = load_local_module("prowlarr_emulebb_live", "prowlarr-emulebb-live.py")
harness_cli_common = prowlarr_live.harness_cli_common
rest_smoke = prowlarr_live.rest_smoke
live_common = prowlarr_live.live_common
live_wire_inputs = prowlarr_live.live_wire_inputs


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
    set_field_value(payload, "initialState", 2)
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
    created = require_success(
        arr_request(arr_url, api_key, "/api/v3/downloadclient?forceSave=true", method="POST", json_body=payload),
        "Arr eMule BB qBittorrent client create",
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError("Arr did not return a created qBittorrent client id.")

    test_payload = json.loads(json.dumps(created))
    test_result = arr_request(arr_url, api_key, "/api/v3/downloadclient/test", method="POST", json_body=test_payload, timeout_seconds=60.0)
    require_success(test_result, "Arr eMule BB qBittorrent client test")
    created["_emulebbSchemaSummary"] = schema_summary
    created["_emulebbTestStatus"] = int(test_result.get("status") or 0)
    return created


def summarize_arr_indexer(indexer: dict[str, Any]) -> dict[str, object]:
    """Builds a compact readiness summary for one synced Arr indexer."""

    return {
        "id": int(indexer.get("id") or 0),
        "name": indexer.get("name"),
        "implementation": indexer.get("implementation"),
        "enable": bool(indexer.get("enable")),
        "protocol": indexer.get("protocol"),
        "priority": indexer.get("priority"),
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


def delete_download_client(arr_url: str, api_key: str, client_id: int) -> dict[str, object]:
    """Deletes one temporary Arr download client."""

    result = arr_request(arr_url, api_key, f"/api/v3/downloadclient/{client_id}", method="DELETE")
    return {"id": client_id, "status": int(result.get("status") or 0)}


def get_first_direct_magnet(base_url: str, emule_api_key: str, query: str) -> dict[str, object]:
    """Returns the first direct Torznab magnet for a safe open-document query."""

    path = (
        "/indexer/emulebb/api?t=search&cat=7000&q="
        + urllib.parse.quote(query)
        + "&apikey="
        + urllib.parse.quote(emule_api_key)
    )
    result = rest_smoke.http_request(base_url, path, request_timeout_seconds=45.0)
    status = int(result.get("status") or 0)
    body_text = str(result.get("body_text") or "")
    if status != 200:
        raise RuntimeError(f"Direct Torznab magnet lookup returned HTTP {status}")
    root = ET.fromstring(body_text)
    item = root.find("./channel/item")
    if item is None:
        raise RuntimeError("Direct Torznab magnet lookup returned no items.")
    title = item.findtext("title") or ""
    link = item.findtext("link") or ""
    if not link.startswith("magnet:?"):
        raise RuntimeError("Direct Torznab first item did not include a magnet link.")
    return {"query": query, "title": title, "magnet": link}


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
) -> dict[str, object]:
    """Collects unique direct Torznab magnets across multiple search terms."""

    magnets: list[dict[str, str]] = []
    attempts: list[dict[str, object]] = []
    seen_hashes: set[str] = set()
    for query_index, query in enumerate(queries):
        path = (
            "/indexer/emulebb/api?t=search&cat=7000&q="
            + urllib.parse.quote(query)
            + "&apikey="
            + urllib.parse.quote(emule_api_key)
        )
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
        form={"urls": magnet, "category": category, "stopped": "true"},
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

    wrong_login_info = qbit_request(base_url, "/api/v2/torrents/info")
    if int(wrong_login_info.get("status") or 0) != 403:
        raise RuntimeError(f"qBit wrong-login session reached protected endpoint: {wrong_login_info!r}")

    cookie, login = qbit_login(base_url, emule_api_key)
    invalid_add = qbit_request(
        base_url,
        "/api/v2/torrents/add",
        cookie=cookie,
        form={"urls": "not-a-download-link", "category": "RADARR_ENG", "stopped": "true"},
        method="POST",
    )
    if int(invalid_add.get("status") or 0) != 400:
        raise RuntimeError(f"qBit invalid add was not rejected: {invalid_add!r}")

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
        "properties_missing_hash": qbit_request(base_url, "/api/v2/torrents/properties", cookie=cookie),
        "files_bad_hash": qbit_request(base_url, "/api/v2/torrents/files?hash=bad", cookie=cookie),
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
        "wrong_login_info": wrong_login_info,
        "valid_login": login,
        "invalid_add": invalid_add,
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
    progress: dict[str, object] | None = None,
) -> dict[str, object]:
    """Exercises qBittorrent-compatible add, mutate, verify, and delete flow."""

    report = progress if progress is not None else {}
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
    report["active_metadata"] = {
        "filtered_info_count": len(filtered_rows),
        "properties_status": int(properties.get("status") or 0),
        "files_count": len(files_body),
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
    report["delete_status"] = int(delete.get("status") or 0)
    deleted_seen = wait_for_transfer_absent(base_url, emule_api_key, transfer_hash, timeout_seconds)
    report["deleted_transfer"] = deleted_seen

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


def qbit_direct_live_wire_stress(
    base_url: str,
    emule_api_key: str,
    magnets: list[dict[str, str]],
    *,
    rounds: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Runs repeated qBittorrent add/mutate/delete live-wire rounds."""

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
            initial_category="RADARR_ENG",
            updated_category="SONARR_ENG",
            timeout_seconds=timeout_seconds,
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
            matches = [
                row
                for row in rows
                if isinstance(row, dict)
                and (int(row.get("indexerId") or 0) == indexer_id or "emule bb" in str(row.get("indexer") or "").lower())
            ]
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
                first = matches[0]
                return {
                    "term_index": term_index,
                    "term_present": bool(term),
                    "count": len(matches),
                    "first_title_present": bool(first.get("title")) if isinstance(first, dict) else False,
                    "indexer": first.get("indexer"),
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
    parser.add_argument("--enable-upnp", action="store_true")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--result-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--qbit-live-wire-rounds", type=int, default=2)
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
    bind_addr: str,
    port: int,
    emule_api_key: str,
    indexer_name: str,
    release_terms: tuple[str, ...],
    timeout_seconds: float,
) -> tuple[dict[str, object], int | None]:
    """Runs one Radarr or Sonarr live integration check."""

    category = "RADARR_ENG" if kind == "radarr" else "SONARR_ENG"
    category_field = "movieCategory" if kind == "radarr" else "tvCategory"
    temp_client_name = f"eMule BB Live {kind} {port}"
    status_payload = require_success(arr_request(arr_url, arr_api_key, "/api/v3/system/status"), f"{kind} status")
    synced_indexer = wait_for_synced_indexer(arr_url, arr_api_key, indexer_name, timeout_seconds)
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
        "synced_indexer": summarize_arr_indexer(synced_indexer),
        "download_client": summarize_arr_download_client(client, category=category),
        "readiness": {
            "indexer_synced": int(synced_indexer.get("id") or 0) > 0 and bool(synced_indexer.get("enable")),
            "download_client_created": int(client["id"]) > 0,
            "download_client_tested": int(client.get("_emulebbTestStatus") or 0) >= 200
            and int(client.get("_emulebbTestStatus") or 0) < 300,
        },
    }
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
    return report, int(client["id"])


def main() -> int:
    """Runs the live Radarr/Sonarr eMule BB bridge test."""

    args = build_parser().parse_args()
    if args.qbit_live_wire_rounds <= 0:
        raise ValueError("--qbit-live-wire-rounds must be greater than zero.")
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
    document_terms = inputs.document_terms
    radarr_movie_terms = inputs.radarr_movie_terms
    qbit_search_terms = tuple(dict.fromkeys(radarr_movie_terms + document_terms))

    prowlarr_url = env_values["PROWLARR_URL"].rstrip("/")
    prowlarr_api_key = env_values["PROWLARR_API_KEY"]
    indexer_name = env_values["PROWLARR_EMULEBB_INDEXER_NAME"]
    bind_addr = prowlarr_live.resolve_bind_addr(prowlarr_url, args.bind_addr)
    port = prowlarr_live.choose_listen_port(bind_addr)
    emule_base_url = f"http://{bind_addr}:{port}"
    torznab_base_url = f"{emule_base_url}/indexer/emulebb"

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="radarr-sonarr-emulebb-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    artifacts_dir = paths.source_artifacts_dir
    result_path = artifacts_dir / "result.json"
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
        args.enable_upnp,
    )

    app = None
    main_window = None
    cleanup_clients: list[tuple[str, str, int]] = []
    forced_trigger_added = False
    report: dict[str, object] = {
        "suite": "radarr-sonarr-emulebb-live",
        "status": "running",
        "emule_base_url": emule_base_url,
        "torznab_base_url": torznab_base_url,
        "indexer_name": indexer_name,
        "seed_refresh": seed_refresh,
        "live_wire_inputs_file": str(inputs.path),
        "live_wire_search_terms": {
            "documents": live_wire_inputs.summarize_terms(document_terms),
            "radarr_movies": live_wire_inputs.summarize_terms(radarr_movie_terms),
        },
        "checks": {},
    }
    try:
        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]))
        main_window = live_common.wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        ready = rest_smoke.wait_for_rest_ready(emule_base_url, args.emule_api_key, args.rest_ready_timeout_seconds)
        report["checks"]["rest_ready"] = rest_smoke.compact_http_result(ready)
        servers = rest_smoke.http_request(emule_base_url, "/api/v1/servers", api_key=args.emule_api_key)
        server_rows = rest_smoke.require_json_array(servers, 200)
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
        if int(kad_connect["status"]) != 200:
            raise RuntimeError(f"Kad start returned HTTP {kad_connect['status']}")
        report["checks"]["network_ready"] = rest_smoke.wait_for_requested_networks(
            emule_base_url,
            args.emule_api_key,
            args.result_timeout_seconds,
            require_server_connected=False,
            require_kad_connected=True,
        )
        direct_results = prowlarr_live.wait_for_direct_torznab_results(
            emule_base_url,
            args.emule_api_key,
            document_terms,
            args.result_timeout_seconds,
        )
        report["checks"]["direct_search_results"] = prowlarr_live.redact_term_result(
            direct_results,
            source="documents",
            term_count=len(document_terms),
        )

        magnet = get_first_direct_magnet(emule_base_url, args.emule_api_key, str(direct_results["query"]))
        report["checks"]["direct_qbit_magnet"] = redact_direct_magnet(magnet)
        report["checks"]["qbit_safety"] = qbit_direct_safety_checks(emule_base_url, args.emule_api_key)
        direct_magnets = collect_direct_magnets(
            emule_base_url,
            args.emule_api_key,
            qbit_search_terms,
            args.qbit_live_wire_rounds,
        )
        report["checks"]["direct_qbit_search_stress"] = redact_collected_direct_magnets(direct_magnets)
        report["checks"]["direct_qbit_trigger"] = {
            "title_present": bool(magnet["title"]),
            "hash_present": bool(ed2k_hash_from_magnet(str(magnet["magnet"]))),
        }
        forced_trigger_added = True
        report["checks"]["direct_qbit_live_wire"] = qbit_direct_live_wire_stress(
            emule_base_url,
            args.emule_api_key,
            direct_magnets["magnets"],
            rounds=args.qbit_live_wire_rounds,
            timeout_seconds=args.result_timeout_seconds,
        )
        forced_trigger_added = False

        eng_tag_id = get_tag_id(prowlarr_url, prowlarr_api_key, "eng")
        saved_indexer = prowlarr_live.upsert_indexer(
            prowlarr_url,
            prowlarr_api_key,
            indexer_name=indexer_name,
            torznab_base_url=torznab_base_url,
            emule_api_key=args.emule_api_key,
            tags=[eng_tag_id] if eng_tag_id is not None else None,
        )
        report["checks"]["prowlarr_indexer"] = {
            "id": int(saved_indexer["id"]),
            "name": saved_indexer.get("name"),
            "tags": saved_indexer.get("tags"),
        }
        report["checks"]["prowlarr_sync"] = force_prowlarr_application_sync(
            prowlarr_url,
            prowlarr_api_key,
            args.result_timeout_seconds,
        )

        radarr_report, radarr_client_id = run_arr_checks(
            kind="radarr",
            arr_url=env_values["RADARR_URL"].rstrip("/"),
            arr_api_key=env_values["RADARR_API_KEY"],
            bind_addr=bind_addr,
            port=port,
            emule_api_key=args.emule_api_key,
            indexer_name=indexer_name,
            release_terms=radarr_movie_terms,
            timeout_seconds=args.result_timeout_seconds,
        )
        cleanup_clients.append((env_values["RADARR_URL"].rstrip("/"), env_values["RADARR_API_KEY"], radarr_client_id))
        report["checks"]["radarr"] = radarr_report

        sonarr_report, sonarr_client_id = run_arr_checks(
            kind="sonarr",
            arr_url=env_values["SONARR_URL"].rstrip("/"),
            arr_api_key=env_values["SONARR_API_KEY"],
            bind_addr=bind_addr,
            port=port,
            emule_api_key=args.emule_api_key,
            indexer_name=indexer_name,
            release_terms=document_terms,
            timeout_seconds=args.result_timeout_seconds,
        )
        cleanup_clients.append((env_values["SONARR_URL"].rstrip("/"), env_values["SONARR_API_KEY"], sonarr_client_id))
        report["checks"]["sonarr"] = sonarr_report

        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
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
        return 1
    finally:
        cleanup_report: list[dict[str, object]] = []
        for arr_url, arr_api_key, client_id in cleanup_clients:
            try:
                cleanup_report.append(delete_download_client(arr_url, arr_api_key, client_id))
            except Exception as exc:
                cleanup_report.append({"id": client_id, "status": "cleanup_failed", "error": str(exc)})
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if cleanup_report:
            report["cleanup_download_clients"] = cleanup_report
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
                report["cleanup"] = {"closed_app": True}
            except Exception as exc:
                if forced_trigger_added:
                    try:
                        app.kill()
                        report["cleanup"] = {"closed_app": False, "forced_kill": True, "clean_error": str(exc)}
                    except Exception as kill_exc:
                        report["cleanup"] = {
                            "closed_app": False,
                            "forced_kill": False,
                            "clean_error": str(exc),
                            "kill_error": str(kill_exc),
                        }
                        if report.get("status") == "passed":
                            report["status"] = "failed"
                else:
                    report["cleanup"] = {"closed_app": False, "error": str(exc)}
                    if report.get("status") == "passed":
                        report["status"] = "failed"
                if report.get("cleanup", {}).get("forced_kill") is False and report.get("status") == "passed":
                    report["status"] = "failed"
        live_common.write_json(result_path, report)
        paths.run_report_dir.parent.mkdir(parents=True, exist_ok=True)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
        print(f"Radarr/Sonarr eMule BB live test {report['status']}. Report directory: {paths.run_report_dir}")


if __name__ == "__main__":
    raise SystemExit(main())
