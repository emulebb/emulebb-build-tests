"""Live emulebb-rust REST OpenAPI conformance runner."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import jsonschema

from emule_test_harness import rust_openapi_responses
from emule_test_harness.paths import get_emule_workspace_root
from emule_test_harness.script_modules import load_script_module
from emule_test_harness.rust_rest_contract import REST_CONTRACT_VERSION, REST_CONTRACT_VERSION_HEADER

REST_COVERAGE_BUDGETS = ("contract", "contract-stress")
EVENT_STREAM_PATH = "/api/v1/events"
EVENT_STREAM_LAST_EVENT_ID = "1"
EVENT_STREAM_READ_LINES = 16
TRANSFER_EVENT_SCHEMA_COMPONENT = "TransferEvent"
REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_OPENAPI_CONTRACT_PATH = (
    get_emule_workspace_root(REPO_ROOT)
    / "repos"
    / "emulebb-tooling"
    / "docs"
    / "products"
    / "emulebb-rust"
    / "api"
    / "REST-API-OPENAPI.yaml"
)
EVENT_STREAM_EXPECTED_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    REST_CONTRACT_VERSION_HEADER: REST_CONTRACT_VERSION,
    "X-Accel-Buffering": "no",
}


class RestConformanceError(AssertionError):
    """Raised when the live REST response conformance summary fails."""

    def __init__(self, summary: dict[str, object]):
        super().__init__(summary)
        self.summary = summary


def load_rest_smoke_module() -> Any:
    return load_script_module("rest_api_smoke_for_rust_conformance", "rest-api-smoke.py")


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
        "type": '"type":"sync.reset"',
        "reason": '"reason":"last-event-id"',
        "lastEventId": f'"lastEventId":"{EVENT_STREAM_LAST_EVENT_ID}"',
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
            TRANSFER_EVENT_SCHEMA_COMPONENT,
            payload,
            openapi_path,
        )
    except (json.JSONDecodeError, RuntimeError, jsonschema.ValidationError) as exc:
        payload_error = str(exc)
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
        result["payloadSchema"] = TRANSFER_EVENT_SCHEMA_COMPONENT
    return result


def run_response_conformance(
    base_url: str,
    api_key: str,
    *,
    budget: str = "contract",
    rest_smoke_module: Any | None = None,
    event_stream_checker: Callable[[str, str], dict[str, object]] | None = None,
) -> dict[str, object]:
    """Runs live REST contract completeness and fails on OpenAPI response drift."""

    if budget not in REST_COVERAGE_BUDGETS:
        raise ValueError(f"REST conformance budget must be one of {REST_COVERAGE_BUDGETS!r}: {budget!r}")
    base_url = require_rest_base_url(base_url)
    rest_smoke = rest_smoke_module or load_rest_smoke_module()
    summary = rest_smoke.exercise_rest_contract_completeness(base_url, api_key, budget)
    checker = event_stream_checker or run_event_stream_conformance
    event_stream_summary = checker(base_url, api_key)
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
