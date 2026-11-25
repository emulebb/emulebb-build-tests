"""Live emulebb-rust REST OpenAPI conformance runner."""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import jsonschema

from emule_test_harness import rust_openapi_responses
from emule_test_harness.rust_rest_contract import iter_downloads, settings_patch
from emule_test_harness.workspace_layout import resolve_rust_openapi_contract
from emule_test_harness.script_modules import load_script_module
from emule_test_harness.rust_rest_contract import REST_CONTRACT_VERSION, REST_CONTRACT_VERSION_HEADER

REST_COVERAGE_BUDGETS = ("contract", "contract-stress")
EVENT_STREAM_PATH = "/api/v1/events"
EVENT_STREAM_LAST_EVENT_ID = "00000000-0000-4000-8000-000000000001:1"
EVENT_STREAM_READ_LINES = 16
DOWNLOAD_EVENT_SCHEMA_COMPONENT = "DownloadEvent"
OPENAPI_CONTRACT_ENV = "EMULEBB_REST_OPENAPI_CONTRACT_PATH"
RUST_OPENAPI_CONTRACT_PATH = resolve_rust_openapi_contract()
EVENT_STREAM_EXPECTED_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    REST_CONTRACT_VERSION_HEADER: REST_CONTRACT_VERSION,
    "X-Accel-Buffering": "no",
}
RUST_MISSING_CATEGORY_NAME = "MissingCategory"
RUST_MISSING_TAG_NAME = "MissingTag"
RUST_MISSING_DOWNLOAD_ID = "9223372036854775807"


class RestConformanceError(AssertionError):
    """Raised when the live REST response conformance summary fails."""

    def __init__(self, summary: dict[str, object]):
        super().__init__(summary)
        self.summary = summary


def load_rest_smoke_module(openapi_path: Path | None = None) -> Any:
    """Select a contract before script initialization without changing environment."""
    smoke = load_script_module("rest_api_smoke_for_rust_conformance", "rest-api-smoke.py",
                               initial_globals={"SELECTED_OPENAPI_CONTRACT_PATH": openapi_path or RUST_OPENAPI_CONTRACT_PATH})
    if not hasattr(smoke, "build_openapi_contract_routes"):
        return smoke

    concrete_path = smoke.concrete_contract_path
    normalize_path = smoke.normalize_contract_path_for_openapi
    contract_body = smoke.get_contract_route_body

    def rust_concrete_path(path: str, operation_id: str) -> str:
        concrete = concrete_path(path.replace("{serverId}", RUST_MISSING_DOWNLOAD_ID), operation_id).replace("{resultId}", RUST_MISSING_DOWNLOAD_ID).replace("{categoryName}", RUST_MISSING_CATEGORY_NAME).replace("{tagName}", RUST_MISSING_TAG_NAME)
        return concrete.replace("{id}", RUST_MISSING_DOWNLOAD_ID) if path.startswith(("/downloads/", "/library/roots/")) else concrete

    def rust_normalize_path(path: str) -> str:
        path = path.replace(f"/servers/{RUST_MISSING_DOWNLOAD_ID}", "/servers/{serverId}")
        path = path.replace(f"/results/{RUST_MISSING_DOWNLOAD_ID}", "/results/{resultId}")
        path = path.replace(f"/library/roots/{RUST_MISSING_DOWNLOAD_ID}", "/library/roots/{id}")
        path = path.replace(f"/library/tags/{RUST_MISSING_TAG_NAME}", "/library/tags/{tagName}")
        path = path.replace("/operations/browse/123", "/operations/browse/{searchId}")
        path = path.replace(f"/library/ignores/defaults/{smoke.REST_CONTRACT_IGNORE_RULE_KEY}",
                            "/library/ignores/defaults/{ruleKey}")
        return normalize_path(path.replace(f"/categories/{RUST_MISSING_CATEGORY_NAME}",
                                           "/categories/{categoryName}")
                              .replace(f"/downloads/{RUST_MISSING_DOWNLOAD_ID}",
                                       "/downloads/{id}"))

    def rust_contract_body(operation_id: str) -> dict[str, object] | None:
        if operation_id == "patchSettings":
            return {"expectedRevision": "1", "set": {"network": {"servers": {"safeConnect": True}}}}
        if operation_id == "createLibraryRoot":
            return {}
        if operation_id == "updateLibraryRoot":
            return {"watchEnabled": False}
        if operation_id == "setLibrarySharing":
            return {"enabled": False, "hashes": ["ff" * 16]}
        if operation_id == "patchLibraryFile":
            return {"uploadPriority": "normal"}
        if operation_id == "createLibraryTag":
            return {}
        if operation_id in {"addLibraryFileTags", "removeLibraryFileTags"}:
            return {"tag": RUST_MISSING_TAG_NAME, "hashes": ["ff" * 16]}
        if operation_id == "patchCategory":
            return {"comment": "REST contract"}
        if operation_id == "createDownload":
            return {}
        if operation_id == "patchDownload":
            return {"category": None}
        if operation_id in {"startDownloads", "stopDownloads", "verifyDownloads"}:
            return {"ids": [RUST_MISSING_DOWNLOAD_ID]}
        if operation_id == "removeDownloads":
            return {"ids": [RUST_MISSING_DOWNLOAD_ID], "deleteData": False}
        if operation_id == "downloadSearchResult":
            return {"intent": "stopped", "category": None}
        return contract_body(operation_id)

    smoke.concrete_contract_path = rust_concrete_path
    smoke.normalize_contract_path_for_openapi = rust_normalize_path
    smoke.get_contract_route_body = rust_contract_body
    smoke.REST_CONTRACT_EXPECTED_ERROR_STATUSES.update({
        "createDownload": (400,),
        "createLibraryTag": (400,),
        "createLibraryRoot": (400,),
        "getLibraryRoot": (404,),
        "updateLibraryRoot": (404,),
        "deleteLibraryRoot": (404,),
        "getLibraryTag": (404,),
        "getLibraryFile": (404,),
        "patchLibraryFile": (404,),
        "listLibraryFileTags": (404,),
        "listLibraryFileLocations": (404,),
        "listSearchResultObservations": (404,),
        "listSearchResults": (404,),
        "stopSearch": (404,),
        "getSearchResult": (404,),
        **{name: (404,) for name in (
            "getDownload", "patchDownload", "listDownloadParts", "listDownloadComments",
            "listDownloadSources", "getDownloadSource", "browseDownloadSource",
            "getDownloadSourceBrowse",
            "addDownloadSourceFriend", "removeDownloadSourceFriend", "removeDownloadSource",
            "banDownloadSource", "unbanDownloadSource",
        )},
    })
    smoke.REST_CONTRACT_ROUTES = smoke.build_openapi_contract_routes()
    exercise = smoke.exercise_rest_contract_completeness

    def rust_exercise(base_url: str, api_key: str, budget: str) -> dict[str, object]:
        # WHY: settings writes require the observed profile revision. Prepare a
        # live fixture rather than treating a stale or invalid write as success.
        snapshot = smoke.http_request(base_url, "/api/v1/settings", api_key=api_key)
        smoke.require_json_object(snapshot, 200)
        body = settings_patch(snapshot["raw_json"], set_values={"network": {"servers": {"safeConnect": True}}})
        return exercise(base_url, api_key, budget, request_bodies={"patchSettings": body})

    smoke.exercise_rest_contract_completeness = rust_exercise
    return smoke


def _event_stream_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}{EVENT_STREAM_PATH}"


def require_rest_base_url(base_url: str) -> str:
    """Returns the daemon base URL, rejecting API-root URLs that would double-prefix paths."""

    normalized = base_url.rstrip("/")
    parsed = urllib.parse.urlparse(normalized)
    if parsed.path not in ("", "/"):
        raise ValueError(
            "REST conformance --base-url must be the daemon root, without a path such as /api/v1."
        )
    return normalized


def _read_first_sse_frame(response: Any) -> str:
    lines: list[str] = []
    for _ in range(EVENT_STREAM_READ_LINES):
        raw_line = response.readline()
        if raw_line == b"":
            break
        line = raw_line.decode("utf-8", errors="replace")
        lines.append(line)
        if line in ("\n", "\r\n"):
            break
    return "".join(lines)


def _sse_frame_data(frame: str) -> str:
    return "\n".join(
        line.removeprefix("data:").lstrip()
        for line in frame.splitlines()
        if line.startswith("data:")
    )


def run_event_stream_conformance(
    base_url: str,
    api_key: str,
    *,
    timeout_seconds: float = 5.0,
    opener: Callable[..., Any] | None = None,
    openapi_path: Path = RUST_OPENAPI_CONTRACT_PATH,
) -> dict[str, object]:
    """Checks the long-lived SSE route through its immediate resume-reset frame."""

    base_url = require_rest_base_url(base_url)
    url = _event_stream_url(base_url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/event-stream",
            "Last-Event-ID": EVENT_STREAM_LAST_EVENT_ID,
            "X-API-Key": api_key,
        },
    )
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout_seconds) as response:
            status = int(getattr(response, "status", None) or response.getcode())
            content_type = str(response.headers.get("Content-Type", ""))
            response_headers = {
                name: str(response.headers.get(name, ""))
                for name in EVENT_STREAM_EXPECTED_HEADERS
            }
            frame = _read_first_sse_frame(response)
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "operationId": "getEvents",
            "path": EVENT_STREAM_PATH,
            "error": str(exc),
        }

    expected = {
        "event": "event: sync.reset",
        "id": "id: ",
    }
    missing = [name for name, needle in expected.items() if needle not in frame]
    missing_headers = [
        name
        for name, expected_value in EVENT_STREAM_EXPECTED_HEADERS.items()
        if response_headers.get(name) != expected_value
    ]
    payload: object | None = None
    payload_error: str | None = None
    try:
        data = _sse_frame_data(frame)
        payload = json.loads(data)
        rust_openapi_responses.validate_openapi_schema_component_payload(
            DOWNLOAD_EVENT_SCHEMA_COMPONENT,
            payload,
            openapi_path,
        )
    except (json.JSONDecodeError, RuntimeError, jsonschema.ValidationError) as exc:
        payload_error = str(exc)
    if isinstance(payload, dict):
        if payload.get("type") != "sync.reset":
            missing.append("type")
        if payload.get("reason") != "reconnect":
            missing.append("reason")
        cursor = next((line.removeprefix("id:").strip() for line in frame.splitlines()
                       if line.startswith("id:")), None)
        if cursor != f"{payload.get('epoch')}:{payload.get('id')}":
            missing.append("cursor")
    ok = (
        status == 200
        and content_type.startswith("text/event-stream")
        and not missing
        and not missing_headers
        and payload_error is None
    )
    result: dict[str, object] = {
        "ok": ok,
        "operationId": "getEvents",
        "path": EVENT_STREAM_PATH,
        "status": status,
        "contentType": content_type,
        "responseHeaders": response_headers,
    }
    if missing:
        result["missing"] = missing
        result["frameSample"] = frame[:500]
    if missing_headers:
        result["missingResponseHeaders"] = missing_headers
    if payload_error is not None:
        result["payloadSchemaError"] = payload_error
        result["frameSample"] = frame[:500]
    elif payload is not None:
        result["payloadSchema"] = DOWNLOAD_EVENT_SCHEMA_COMPONENT
    return result


def run_response_conformance(
    base_url: str,
    api_key: str,
    *,
    budget: str = "contract",
    rest_smoke_module: Any | None = None,
    event_stream_checker: Callable[[str, str], dict[str, object]] | None = None,
    openapi_path: Path | None = None,
) -> dict[str, object]:
    """Runs live REST contract completeness and fails on OpenAPI response drift."""

    if budget not in REST_COVERAGE_BUDGETS:
        raise ValueError(f"REST conformance budget must be one of {REST_COVERAGE_BUDGETS!r}: {budget!r}")
    base_url = require_rest_base_url(base_url)
    rest_smoke = rest_smoke_module or (load_rest_smoke_module(openapi_path) if openapi_path else load_rest_smoke_module())
    summary = rest_smoke.exercise_rest_contract_completeness(base_url, api_key, budget)
    checker = event_stream_checker or run_event_stream_conformance
    event_stream_summary = (checker(base_url, api_key, openapi_path=openapi_path)
                            if openapi_path and event_stream_checker is None else checker(base_url, api_key))
    summary["event_stream"] = event_stream_summary
    if not bool(event_stream_summary.get("ok")):
        summary["ok"] = False
        failed_routes = list(summary.get("failed_routes", []))
        if "getEvents" not in failed_routes:
            failed_routes.append("getEvents")
        summary["failed_routes"] = failed_routes
    if not bool(summary.get("ok")):
        raise RestConformanceError(summary)
    return summary


def write_report(path: Path, summary: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a running emulebb-rust /api/v1 daemon against OpenAPI.")
    parser.add_argument("--base-url", required=True, help="Running emulebb-rust REST base URL.")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--rest-coverage-budget", choices=REST_COVERAGE_BUDGETS, default="contract")
    parser.add_argument("--json-output", type=Path, help="Optional path for the conformance summary JSON.")
    args = parser.parse_args(argv)

    summary: dict[str, object] = {}
    try:
        summary = run_response_conformance(args.base_url, args.api_key, budget=args.rest_coverage_budget)
    except ValueError as exc:
        print(f"emulebb-rust REST OpenAPI response conformance preflight failed: {exc}")
        return 2
    except RestConformanceError as exc:
        summary = exc.summary
        if args.json_output is not None:
            write_report(args.json_output, summary)
        failed_routes = ", ".join(str(route) for route in summary.get("failed_routes", [])) or "<unknown>"
        print(f"emulebb-rust REST OpenAPI response conformance failed: {failed_routes}")
        return 1

    if args.json_output is not None:
        write_report(args.json_output, summary)
    print("emulebb-rust REST OpenAPI response conformance passed.")
    return 0


def prove_retained_download_pages(
    request: Callable[[str], dict[str, Any]], fixture: dict[str, int], *,
    validate_first_page: Callable[[dict[str, Any]], None] | None = None,
    sample: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Traverse the canonical retained-job fixture with bounded rows and cursors."""
    views = {}
    for view, expected in (("all", fixture["jobs"]), ("completed", fixture["completed"]),
                           ("unfinished", fixture["queued"] + fixture["stopped"])):
        seen, pages = 0, 0
        started = time.monotonic()
        def page(path):
            nonlocal pages
            payload = request(path)
            if sample is not None:
                sample()
            if pages == 0 and validate_first_page is not None:
                validate_first_page(payload)
            rows = payload["data"]
            if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
                raise RuntimeError(f"Retained-scale {view} returned an invalid page length")
            pages += 1
            return payload
        for row in iter_downloads(page, view=view):
            identity = int(row["id"])
            complete = identity % 1000 >= 10
            if (not 0 < identity <= fixture["jobs"] or row.get("hash") != f"{identity:032x}"
                    or (view == "completed" and not complete)
                    or (view == "unfinished" and complete)):
                raise RuntimeError(f"Retained-scale {view} returned another fixture's content or view")
            seen += 1
            if seen > expected:
                raise RuntimeError(f"Retained-scale {view} did not terminate at its fixture bound")
        if seen != expected:
            raise RuntimeError(f"Retained-scale {view} omitted jobs: {seen}/{expected}")
        views[view] = {"rows": seen, "pages": pages, "elapsedSeconds": time.monotonic() - started}
    return views
