"""Runs the canonical isolated live E2E suite against the in-process eMule REST API."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL, refresh_seed_files


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
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
close_app_cleanly = live_common.close_app_cleanly
launch_app = live_common.launch_app
patch_ini_value = live_common.patch_ini_value
prepare_profile_base = live_common.prepare_profile_base
upsert_ini_section_value = live_common.upsert_ini_section_value
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
write_json = live_common.write_json

LIVE_WIRE_SEARCH_QUERIES = ("linux", "ubuntu", "fedora", "freebsd", "debian", "emule")
DEFAULT_SERVER_SEARCH_QUERIES = LIVE_WIRE_SEARCH_QUERIES
DEFAULT_KAD_SEARCH_QUERIES = LIVE_WIRE_SEARCH_QUERIES
NAT_BACKEND_ATTEMPT_PREFIX = "Attempting NAT mapping backend "
UPNP_IGD_BACKEND_NAME = "UPnP IGD (MiniUPnP)"
PCP_NATPMP_BACKEND_NAME = "PCP/NAT-PMP"
LIVE_NETWORK_UNAVAILABLE_EXIT_CODE = 2
REST_SURFACE_TEST_SERVER = {
    "addr": "192.0.2.254",
    "port": 4669,
    "name": "REST surface smoke disposable",
}
REST_SURFACE_MISSING_HASH = "0123456789abcdef0123456789abcdef"
REST_PREFERENCE_KEYS = {
    "maxUploadKiB",
    "maxDownloadKiB",
    "maxConnections",
    "maxConPerFive",
    "maxSourcesPerFile",
    "uploadClientDataRate",
    "maxUploadSlots",
    "queueSize",
    "autoConnect",
    "newAutoUp",
    "newAutoDown",
    "creditSystem",
    "safeServerConnect",
    "networkKademlia",
    "networkEd2k",
}
REST_COVERAGE_PROFILES = ("smoke", "contract", "contract-stress")
REST_STRESS_PROFILES = ("off", "smoke", "soak")
REST_CONTRACT_ROUTES: tuple[dict[str, object], ...] = (
    {"name": "app", "family": "app", "method": "GET", "path": "/api/v1/app", "safe": True},
    {"name": "app_preferences_get", "family": "app", "method": "GET", "path": "/api/v1/app/preferences", "safe": True},
    {"name": "app_preferences_patch", "family": "app", "method": "PATCH", "path": "/api/v1/app/preferences", "safe": True},
    {"name": "app_shutdown", "family": "app", "method": "POST", "path": "/api/v1/app/shutdown", "safe": False},
    {"name": "status", "family": "status", "method": "GET", "path": "/api/v1/status", "safe": True},
    {"name": "snapshot", "family": "status", "method": "GET", "path": "/api/v1/snapshot?limit=7", "safe": True},
    {"name": "categories", "family": "categories", "method": "GET", "path": "/api/v1/categories", "safe": True},
    {"name": "categories_create", "family": "categories", "method": "POST", "path": "/api/v1/categories", "safe": True},
    {"name": "categories_get", "family": "categories", "method": "GET", "path": "/api/v1/categories/999999", "safe": True},
    {"name": "categories_patch", "family": "categories", "method": "PATCH", "path": "/api/v1/categories/999999", "safe": True},
    {"name": "categories_delete", "family": "categories", "method": "DELETE", "path": "/api/v1/categories/999999", "safe": True},
    {"name": "transfers_list", "family": "transfers", "method": "GET", "path": "/api/v1/transfers", "safe": True},
    {"name": "transfers_add_link", "family": "transfers", "method": "POST", "path": "/api/v1/transfers", "safe": True},
    {"name": "transfers_add_links", "family": "transfers", "method": "POST", "path": "/api/v1/transfers", "safe": True},
    {"name": "transfers_get", "family": "transfers", "method": "GET", "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "transfers_patch_action", "family": "transfers", "method": "PATCH", "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "transfers_delete", "family": "transfers", "method": "DELETE", "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "transfers_sources", "family": "transfers", "method": "GET", "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources", "safe": True},
    {"name": "transfers_source_browse", "family": "transfers", "method": "POST", "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources/browse", "safe": True},
    {"name": "shared_directories_get", "family": "shared-directories", "method": "GET", "path": "/api/v1/shared-directories", "safe": True},
    {"name": "shared_directories_patch", "family": "shared-directories", "method": "PATCH", "path": "/api/v1/shared-directories", "safe": True},
    {"name": "shared_directories_reload", "family": "shared-directories", "method": "POST", "path": "/api/v1/shared-directories/reload", "safe": True},
    {"name": "shared_files_list", "family": "shared", "method": "GET", "path": "/api/v1/shared-files", "safe": True},
    {"name": "shared_files_add", "family": "shared", "method": "POST", "path": "/api/v1/shared-files", "safe": True},
    {"name": "shared_files_get", "family": "shared", "method": "GET", "path": f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "shared_files_patch", "family": "shared", "method": "PATCH", "path": f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "shared_files_delete_body", "family": "shared", "method": "DELETE", "path": "/api/v1/shared-files", "safe": True},
    {"name": "shared_files_delete_route", "family": "shared", "method": "DELETE", "path": f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "uploads", "family": "uploads", "method": "GET", "path": "/api/v1/uploads", "safe": True},
    {"name": "upload_queue", "family": "uploads", "method": "GET", "path": "/api/v1/upload-queue", "safe": True},
    {"name": "uploads_remove", "family": "uploads", "method": "DELETE", "path": f"/api/v1/uploads/{REST_SURFACE_MISSING_HASH}", "safe": True},
    {"name": "uploads_release_slot", "family": "uploads", "method": "POST", "path": f"/api/v1/uploads/{REST_SURFACE_MISSING_HASH}/release-slot", "safe": True},
    {"name": "servers_list", "family": "servers", "method": "GET", "path": "/api/v1/servers", "safe": True},
    {"name": "servers_add", "family": "servers", "method": "POST", "path": "/api/v1/servers", "safe": True},
    {"name": "servers_patch", "family": "servers", "method": "PATCH", "path": "/api/v1/servers/current:1", "safe": True},
    {"name": "servers_delete", "family": "servers", "method": "DELETE", "path": "/api/v1/servers/192.0.2.254:4669", "safe": True},
    {"name": "kad_status", "family": "kad", "method": "GET", "path": "/api/v1/kad", "safe": True},
    {"name": "kad_patch", "family": "kad", "method": "PATCH", "path": "/api/v1/kad", "safe": True},
    {"name": "searches_start", "family": "searches", "method": "POST", "path": "/api/v1/searches", "safe": True},
    {"name": "searches_get", "family": "searches", "method": "GET", "path": "/api/v1/searches/123", "safe": True},
    {"name": "searches_delete", "family": "searches", "method": "DELETE", "path": "/api/v1/searches/123", "safe": True},
    {"name": "logs", "family": "logs", "method": "GET", "path": "/api/v1/logs?limit=9", "safe": True},
)
REST_STRESS_READ_PATHS = (
    "/api/v1/app",
    "/api/v1/status",
    "/api/v1/snapshot?limit=10",
    "/api/v1/categories",
    "/api/v1/transfers",
    "/api/v1/shared-directories",
    "/api/v1/shared-files",
    "/api/v1/uploads",
    "/api/v1/upload-queue",
    "/api/v1/servers",
    "/api/v1/kad",
    "/api/v1/logs?limit=20",
)
REST_STRESS_SAFE_MUTATION_OPERATIONS: tuple[dict[str, object], ...] = (
    {
        "method": "PATCH",
        "path": "/api/v1/app/preferences",
        "json_body": {"safeServerConnect": True},
        "family": "app",
    },
    {
        "method": "POST",
        "path": "/api/v1/transfers",
        "json_body": {"link": "not-an-ed2k-link"},
        "family": "transfers",
    },
    {
        "method": "PATCH",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        "json_body": {"action": "pause"},
        "family": "transfers",
    },
    {
        "method": "DELETE",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        "json_body": {"delete_files": False},
        "family": "transfers",
    },
    {
        "method": "POST",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources/browse",
        "json_body": {"userHash": REST_SURFACE_MISSING_HASH},
        "family": "transfers",
    },
    {
        "method": "PATCH",
        "path": "/api/v1/kad",
        "json_body": {"action": "recheck_firewall"},
        "family": "kad",
    },
    {
        "method": "POST",
        "path": "/api/v1/searches",
        "json_body": {"query": "", "method": "automatic", "type": "any"},
        "family": "searches",
    },
    {
        "method": "DELETE",
        "path": "/api/v1/searches/123",
        "json_body": {},
        "family": "searches",
    },
)
REST_INTENTIONALLY_UNSUPPORTED = (
    "category_crud",
    "shared_file_rename",
    "completed_transfer_rename",
    "custom_save_path",
    "broad_preferences",
)


class LiveNetworkUnavailableError(RuntimeError):
    """Raised when live seed files load but no external network candidate connects."""


def choose_listen_port() -> int:
    """Returns one ephemeral localhost TCP port for the smoke listener."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def configure_webserver_profile(
    config_dir: Path,
    app_exe: Path,
    api_key: str,
    port: int,
    bind_addr: str,
    enable_upnp: bool,
) -> None:
    """Enables the WebServer listener and REST API key inside the temp profile."""

    preferences_path = config_dir / "preferences.ini"
    text = preferences_path.read_text(encoding="utf-8", errors="ignore")
    text = patch_ini_value(text, "ConfirmExit", "0")
    for key, value in (
        ("Autoconnect", "1"),
        ("Reconnect", "1"),
        ("NetworkED2K", "1"),
        ("NetworkKademlia", "1"),
    ):
        text = patch_ini_value(text, key, value)
    if enable_upnp:
        for key in ("Verbose", "FullVerbose"):
            text = patch_ini_value(text, key, "1")
    template_path = app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"
    text = patch_ini_value(text, "WebTemplateFile", str(template_path))
    for key, value in (
        ("Password", ""),
        ("PasswordLow", ""),
        ("ApiKey", api_key),
        ("BindAddr", bind_addr),
        ("Port", str(port)),
        ("WebUseUPnP", "0"),
        ("Enabled", "1"),
        ("UseGzip", "1"),
        ("PageRefreshTime", "120"),
        ("UseLowRightsUser", "0"),
        ("AllowAdminHiLevelFunc", "1"),
        ("WebTimeoutMins", "5"),
        ("UseHTTPS", "0"),
        ("HTTPSCertificate", ""),
        ("HTTPSKey", ""),
    ):
        text = upsert_ini_section_value(text, "WebServer", key, value)
    text = upsert_ini_section_value(text, "UPnP", "EnableUPnP", "1" if enable_upnp else "0")
    text = patch_ini_value(text, "CloseUPnPOnExit", "0")
    preferences_path.write_text(text, encoding="utf-8", newline="\r\n")


def apply_p2p_bindaddr_override(
    config_dir: Path,
    interface_name: str,
    bind_updater_script: Path,
) -> None:
    """Runs the canonical bind-address updater against the isolated profile."""

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(bind_updater_script),
        "-InterfaceName",
        interface_name,
        "-ConfigDirectory",
        str(config_dir),
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "P2P bind updater failed with exit code "
            f"{completed.returncode}: {completed.stdout}{completed.stderr}"
        )


def http_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    api_key: str | None = None,
    json_body=None,
    request_timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Performs one HTTP request and returns a compact structured result."""

    data = None
    headers: dict[str, str] = {}
    if api_key is not None:
        headers["X-API-Key"] = api_key
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"

    request = urllib.request.Request(base_url + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=request_timeout_seconds) as response:
            body_bytes = response.read()
            body_text = body_bytes.decode("utf-8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            payload = None
            if "application/json" in content_type:
                payload = json.loads(body_text)
            return {
                "status": int(response.status),
                "content_type": content_type,
                "body_text": body_text,
                "json": unwrap_rest_payload(payload),
                "raw_json": payload,
            }
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        content_type = exc.headers.get("Content-Type", "")
        payload = None
        if "application/json" in content_type and body_text:
            payload = json.loads(body_text)
        return {
            "status": int(exc.code),
            "content_type": content_type,
            "body_text": body_text,
            "json": unwrap_rest_payload(payload),
            "raw_json": payload,
        }


def unwrap_rest_payload(payload: object) -> object:
    """Returns the payload body inside the final REST envelope."""

    if not isinstance(payload, dict):
        return payload

    error = payload.get("error")
    if isinstance(error, dict):
        normalized = {
            "error": error.get("code"),
            "message": error.get("message"),
        }
        if "details" in error:
            normalized["details"] = error["details"]
        return normalized

    if "data" in payload and "meta" in payload:
        return payload["data"]

    return payload


def require_json_object(result: dict[str, object], expected_status: int) -> dict[str, Any]:
    """Asserts one REST response is the expected JSON object payload."""

    assert int(result["status"]) == expected_status
    assert isinstance(result["json"], dict)
    return result["json"]


def require_json_array(result: dict[str, object], expected_status: int) -> list[Any]:
    """Asserts one REST response is the expected JSON array payload."""

    assert int(result["status"]) == expected_status, compact_http_result(result)
    payload = result["json"]
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return list(payload["items"])
    assert isinstance(payload, list), compact_http_result(result)
    return list(payload)


def require_error_response(
    result: dict[str, object],
    expected_status: int,
    expected_code: str,
    *,
    message_contains: str | None = None,
) -> dict[str, Any]:
    """Asserts one REST error response carries the stable JSON error envelope."""

    payload = require_json_object(result, expected_status)
    assert payload.get("error") == expected_code, compact_http_result(result)
    message = payload.get("message")
    assert isinstance(message, str), compact_http_result(result)
    if message_contains is not None:
        assert message_contains in message, compact_http_result(result)
    return payload


def require_missing_transfer_bulk_result(result: dict[str, object]) -> dict[str, object]:
    """Asserts one bulk transfer mutation reports a per-item missing-transfer result."""

    payload = require_json_object(result, 200)
    rows = payload.get("results")
    assert isinstance(rows, list) and rows, compact_http_result(result)
    first = rows[0]
    assert isinstance(first, dict), compact_http_result(result)
    assert first.get("ok") is False, compact_http_result(result)
    assert str(first.get("hash") or "").lower() == REST_SURFACE_MISSING_HASH
    assert "transfer not found" in str(first.get("error") or "")
    return first


def get_app_process_id(app: object) -> int | None:
    """Returns the launched process id when pywinauto exposes it."""

    process_id = getattr(app, "process", None)
    if callable(process_id):
        try:
            process_id = process_id()
        except TypeError:
            process_id = None
    if isinstance(process_id, int):
        return process_id
    return None


def compact_server_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Keeps the server-status timeline compact and stable in artifacts."""

    payload = get_server_status_payload(payload)
    current_server = payload.get("currentServer")
    compact_current = None
    if isinstance(current_server, dict):
        compact_current = {
            "name": current_server.get("name"),
            "address": current_server.get("address"),
            "port": current_server.get("port"),
            "current": current_server.get("current"),
            "connected": current_server.get("connected"),
            "connecting": current_server.get("connecting"),
        }

    return {
        "connected": payload.get("connected"),
        "connecting": payload.get("connecting"),
        "lowId": payload.get("lowId"),
        "serverCount": payload.get("serverCount"),
        "currentServer": compact_current,
    }


def get_server_status_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Returns the eD2K server-status object from a status or server payload."""

    nested = payload.get("servers")
    return nested if isinstance(nested, dict) else payload


def compact_kad_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Keeps the Kad-status timeline compact and stable in artifacts."""

    return {
        "running": payload.get("running"),
        "connected": payload.get("connected"),
        "bootstrapping": payload.get("bootstrapping"),
        "firewalled": payload.get("firewalled"),
        "users": payload.get("users"),
        "files": payload.get("files"),
    }


def compact_http_result(result: dict[str, object]) -> dict[str, object]:
    """Strips one HTTP result down to stable artifact fields."""

    compact: dict[str, object] = {
        "status": int(result["status"]),
        "content_type": result.get("content_type"),
    }
    if isinstance(result.get("json"), dict | list):
        compact["json"] = result["json"]
    if isinstance(result.get("raw_json"), dict | list):
        compact["raw_json"] = result["raw_json"]
    elif isinstance(result.get("body_text"), str):
        compact["body_text"] = result["body_text"]
    return compact


def validate_rest_stress_config(
    *,
    profile: str,
    duration_seconds: float,
    concurrency: int,
    max_failures: int,
    request_timeout_seconds: float,
) -> None:
    """Validates REST stress knobs before the live app is launched."""

    if profile not in REST_STRESS_PROFILES:
        raise ValueError(f"Unsupported REST stress profile: {profile}")
    if duration_seconds <= 0:
        raise ValueError("REST stress duration must be greater than zero.")
    if concurrency <= 0:
        raise ValueError("REST stress concurrency must be greater than zero.")
    if max_failures < 0:
        raise ValueError("REST stress max failures must be zero or greater.")
    if request_timeout_seconds <= 0:
        raise ValueError("REST stress request timeout must be greater than zero.")


def build_rest_stress_operations(profile: str) -> list[dict[str, object]]:
    """Builds the REST operation mix used by one bounded stress profile."""

    operations = [
        {
            "method": "GET",
            "path": path,
            "json_body": None,
            "family": path.split("/")[3].split("?")[0] if len(path.split("/")) > 3 else "root",
        }
        for path in REST_STRESS_READ_PATHS
    ]
    if profile in {"smoke", "soak"}:
        operations.extend(dict(operation) for operation in REST_STRESS_SAFE_MUTATION_OPERATIONS)
    return operations


def percentile(values: list[float], percentile_value: float) -> float:
    """Returns a nearest-rank percentile from an already collected sample."""

    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile_value / 100.0) * (len(ordered) - 1))))
    return round(ordered[index], 3)


def summarize_rest_stress_results(
    rows: list[dict[str, object]],
    *,
    profile: str,
    duration_seconds: float,
    concurrency: int,
    max_failures: int,
) -> dict[str, object]:
    """Builds a compact deterministic summary for one REST stress run."""

    status_counts: dict[str, int] = {}
    method_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    error_counts: dict[str, int] = {}
    durations = []
    failures = []
    for row in rows:
        status = str(row.get("status", "exception"))
        status_counts[status] = status_counts.get(status, 0) + 1
        method = str(row.get("method") or "UNKNOWN")
        method_counts[method] = method_counts.get(method, 0) + 1
        family = str(row.get("family") or "unknown")
        family_counts[family] = family_counts.get(family, 0) + 1
        duration_ms = row.get("duration_ms")
        if isinstance(duration_ms, int | float):
            durations.append(float(duration_ms))
        if not row.get("ok"):
            error_key = str(row.get("error") or status)
            error_counts[error_key] = error_counts.get(error_key, 0) + 1
            if len(failures) < 10:
                failures.append(row)
    failure_count = len([row for row in rows if not row.get("ok")])
    return {
        "profile": profile,
        "duration_seconds": duration_seconds,
        "concurrency": concurrency,
        "max_failures": max_failures,
        "requests_started": len(rows),
        "requests_completed": len(rows),
        "failure_count": failure_count,
        "ok": failure_count <= max_failures,
        "status_counts": status_counts,
        "method_counts": method_counts,
        "family_counts": family_counts,
        "error_counts": error_counts,
        "latency_ms": {
            "min": round(min(durations), 3) if durations else 0.0,
            "p50": percentile(durations, 50.0),
            "p95": percentile(durations, 95.0),
            "max": round(max(durations), 3) if durations else 0.0,
        },
        "failures_sample": failures,
    }


def build_contract_coverage_summary(routes: list[dict[str, object]], profile: str) -> dict[str, object]:
    """Summarizes exercised REST route coverage by contract family."""

    coverage_by_family: dict[str, dict[str, int]] = {}
    for route in routes:
        family = str(route["family"])
        family_summary = coverage_by_family.setdefault(family, {"total": 0, "exercised": 0, "skipped": 0, "failed": 0})
        family_summary["total"] += 1
        if route.get("skipped"):
            family_summary["skipped"] += 1
        elif route.get("ok"):
            family_summary["exercised"] += 1
        else:
            family_summary["failed"] += 1
    failed_routes = [route["name"] for route in routes if not route.get("ok") and not route.get("skipped")]
    return {
        "profile": profile,
        "route_count": len(routes),
        "routes": routes,
        "coverage_by_family": coverage_by_family,
        "intentionally_unsupported": list(REST_INTENTIONALLY_UNSUPPORTED),
        "failed_routes": failed_routes,
        "ok": not failed_routes,
    }


def exercise_rest_contract_completeness(base_url: str, api_key: str, profile: str) -> dict[str, object]:
    """Exercises and reports the safe broadband REST contract surface."""

    routes: list[dict[str, object]] = []
    for route in REST_CONTRACT_ROUTES:
        row = {
            "name": route["name"],
            "family": route["family"],
            "method": route["method"],
            "path": route["path"],
            "safe": route["safe"],
            "skipped": False,
            "ok": False,
        }
        if route["safe"] is False:
            row.update({"skipped": True, "ok": True, "reason": "unsafe during smoke run"})
            routes.append(row)
            continue
        start = time.monotonic()
        try:
            result = http_request(
                base_url,
                str(route["path"]),
                method=str(route["method"]),
                api_key=api_key,
                json_body=get_contract_route_body(str(route["name"])),
            )
            status = int(result["status"])
            row.update(
                {
                    "status": status,
                    "ok": 200 <= status < 500,
                    "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
                }
            )
        except Exception as exc:
            row.update(
                {
                    "status": "exception",
                    "ok": False,
                    "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
                    "error": str(exc),
                }
            )
        routes.append(row)
    return build_contract_coverage_summary(routes, profile)


def get_contract_route_body(route_name: str) -> dict[str, object] | None:
    """Returns the safe payload used to exercise one REST contract route."""

    if route_name == "app_preferences_patch":
        return {"safeServerConnect": True}
    if route_name == "categories_create":
        return {}
    if route_name == "categories_patch":
        return {"name": "REST contract"}
    if route_name == "transfers_add_link":
        return {"link": "not-an-ed2k-link"}
    if route_name == "transfers_add_links":
        return {"links": ["not-an-ed2k-link"]}
    if route_name == "transfers_patch_action":
        return {"action": "pause"}
    if route_name == "transfers_delete":
        return {"delete_files": False}
    if route_name == "transfers_source_browse":
        return {"userHash": REST_SURFACE_MISSING_HASH}
    if route_name == "shared_files_add":
        return {}
    if route_name == "shared_files_patch":
        return {"comment": "rest contract", "rating": 4}
    if route_name == "shared_files_delete_body":
        return {}
    if route_name in {"uploads_remove", "uploads_release_slot"}:
        return {}
    if route_name == "servers_add":
        return dict(REST_SURFACE_TEST_SERVER)
    if route_name == "servers_patch":
        return {"action": "disconnect"}
    if route_name == "servers_delete":
        return {}
    if route_name == "kad_patch":
        return {"action": "recheck_firewall"}
    if route_name == "searches_start":
        return {"query": "", "method": "automatic", "type": "any"}
    if route_name == "searches_delete":
        return {}
    return None


def exercise_rest_stress(
    base_url: str,
    api_key: str,
    *,
    profile: str,
    duration_seconds: float,
    concurrency: int,
    max_failures: int,
    request_timeout_seconds: float,
) -> dict[str, object]:
    """Runs a bounded read-heavy REST stress pass against the isolated app."""

    validate_rest_stress_config(
        profile=profile,
        duration_seconds=duration_seconds,
        concurrency=concurrency,
        max_failures=max_failures,
        request_timeout_seconds=request_timeout_seconds,
    )
    if profile == "off":
        return {
            "profile": profile,
            "enabled": False,
            "ok": True,
            "requests_started": 0,
            "requests_completed": 0,
        }

    deadline = time.monotonic() + duration_seconds
    operations = build_rest_stress_operations(profile)
    rows: list[dict[str, object]] = []
    next_index = 0

    def run_one(index: int) -> dict[str, object]:
        operation = operations[index % len(operations)]
        method = str(operation["method"])
        path = str(operation["path"])
        json_body = operation.get("json_body")
        family = str(operation.get("family") or "unknown")
        start = time.monotonic()
        try:
            result = http_request(
                base_url,
                path,
                method=method,
                api_key=api_key,
                json_body=json_body,
                request_timeout_seconds=request_timeout_seconds,
            )
            status = int(result["status"])
            return {
                "method": method,
                "path": path,
                "family": family,
                "status": status,
                "ok": 200 <= status < 500,
                "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
            }
        except Exception as exc:
            return {
                "method": method,
                "path": path,
                "family": family,
                "status": "exception",
                "ok": False,
                "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
                "error": str(exc),
            }

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {}
        while time.monotonic() < deadline and len(futures) < concurrency:
            futures[executor.submit(run_one, next_index)] = next_index
            next_index += 1
        while futures:
            for future in as_completed(list(futures)):
                futures.pop(future)
                rows.append(future.result())
                if time.monotonic() < deadline:
                    futures[executor.submit(run_one, next_index)] = next_index
                    next_index += 1
                break

    summary = summarize_rest_stress_results(
        rows,
        profile=profile,
        duration_seconds=duration_seconds,
        concurrency=concurrency,
        max_failures=max_failures,
    )
    if not summary["ok"]:
        raise AssertionError(f"REST stress failures exceeded budget: {summary}")
    return summary


def extract_log_messages(log_entries: list[object]) -> list[str]:
    """Extracts message strings from one REST log payload."""

    messages: list[str] = []
    for entry in log_entries:
        if not isinstance(entry, dict):
            continue
        message = entry.get("message")
        if isinstance(message, str):
            messages.append(message)
    return messages


def summarize_nat_backend_order(log_entries: list[object]) -> dict[str, object]:
    """Summarizes NAT backend attempt ordering from REST log entries."""

    messages = extract_log_messages(log_entries)
    attempts = [
        message
        for message in messages
        if message.startswith(NAT_BACKEND_ATTEMPT_PREFIX)
    ]
    backend_names = [
        message[len(NAT_BACKEND_ATTEMPT_PREFIX):].strip("'")
        for message in attempts
    ]
    return {
        "attempts": attempts,
        "backend_names": backend_names,
        "message_count": len(messages),
        "upnp_first": bool(backend_names) and backend_names[0] == UPNP_IGD_BACKEND_NAME,
        "pcp_before_upnp": (
            UPNP_IGD_BACKEND_NAME in backend_names
            and PCP_NATPMP_BACKEND_NAME in backend_names
            and backend_names.index(PCP_NATPMP_BACKEND_NAME) < backend_names.index(UPNP_IGD_BACKEND_NAME)
        ),
    }


def assert_upnp_backend_order(log_entries: list[object]) -> dict[str, object]:
    """Requires automatic NAT mapping to attempt MiniUPnP before PCP/NAT-PMP."""

    summary = summarize_nat_backend_order(log_entries)
    backend_names = summary["backend_names"]
    assert isinstance(backend_names, list)
    if not backend_names:
        raise AssertionError("No NAT mapping backend attempts were found in the live log.")
    if backend_names[0] != UPNP_IGD_BACKEND_NAME:
        raise AssertionError(f"Expected first NAT backend to be {UPNP_IGD_BACKEND_NAME!r}, got {backend_names!r}.")
    return summary


def wait_for_upnp_backend_order(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until the live log exposes NAT backend ordering and asserts UPnP is first."""

    def resolve():
        result = http_request(base_url, "/api/v1/logs?limit=400", api_key=api_key)
        if int(result["status"]) != 200:
            return None
        entries = require_json_array(result, 200)
        summary = summarize_nat_backend_order(entries)
        if not summary["backend_names"]:
            return None
        return assert_upnp_backend_order(entries)

    return wait_for(resolve, timeout=timeout_seconds, interval=0.5, description="UPnP NAT backend order")


def exercise_rest_surface_smoke(base_url: str, api_key: str) -> dict[str, object]:
    """Exercises low-risk REST endpoints that do not depend on external live peers."""

    surface: dict[str, object] = {}

    app = http_request(base_url, "/api/v1/app", api_key=api_key)
    app_payload = require_json_object(app, 200)
    capabilities = app_payload.get("capabilities")
    assert isinstance(capabilities, dict), compact_http_result(app)
    for capability in (
        "transfers",
        "searches",
        "sharedDirectories",
        "categoriesRead",
        "categoryAssignment",
        "fileRatingComment",
        "renameFile",
    ):
        assert capabilities.get(capability) is True, compact_http_result(app)
    assert capabilities.get("categoryCrud") is True, compact_http_result(app)
    surface["app"] = {
        "status": app["status"],
        "apiVersion": app_payload.get("apiVersion"),
        "capabilities": capabilities,
    }

    preferences = http_request(base_url, "/api/v1/app/preferences", api_key=api_key)
    preference_payload = require_json_object(preferences, 200)
    missing_preference_keys = sorted(REST_PREFERENCE_KEYS.difference(preference_payload.keys()))
    assert not missing_preference_keys, missing_preference_keys
    surface["app_preferences_get"] = {
        "status": preferences["status"],
        "keys": sorted(preference_payload.keys()),
    }

    invalid_preference = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        json_body={"unsupportedPreference": True},
    )
    surface["app_preferences_invalid"] = {
        "status": invalid_preference["status"],
        "error": require_error_response(
            invalid_preference,
            400,
            "INVALID_ARGUMENT",
            message_contains="unsupported preference key",
        ),
    }

    safe_preference_update = {
        "safeServerConnect": bool(preference_payload["safeServerConnect"]),
    }
    preference_set = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        json_body=safe_preference_update,
    )
    preference_set_payload = require_json_object(preference_set, 200)
    assert preference_set_payload.get("ok") is True
    surface["app_preferences_set_noop"] = {
        "status": preference_set["status"],
        "updated": safe_preference_update,
    }

    transfers = http_request(base_url, "/api/v1/transfers", api_key=api_key)
    transfer_rows = require_json_array(transfers, 200)
    transfers_by_filter = http_request(base_url, "/api/v1/transfers?filter=downloading&category=0", api_key=api_key)
    require_json_array(transfers_by_filter, 200)
    categories = http_request(base_url, "/api/v1/categories", api_key=api_key)
    category_rows = require_json_array(categories, 200)
    assert any(
        isinstance(row, dict) and row.get("id") == 0 and row.get("name") == "Default"
        for row in category_rows
    ), compact_http_result(categories)
    category_create_bad = http_request(
        base_url,
        "/api/v1/categories",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    category_get_missing = http_request(base_url, "/api/v1/categories/999999", api_key=api_key)
    category_patch_default = http_request(
        base_url,
        "/api/v1/categories/0",
        method="PATCH",
        api_key=api_key,
        json_body={"name": "Default"},
    )
    category_delete_default = http_request(
        base_url,
        "/api/v1/categories/0",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    missing_transfer = http_request(base_url, f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}", api_key=api_key)
    missing_transfer_sources = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources",
        api_key=api_key,
    )
    missing_transfer_source_browse = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources/browse",
        method="POST",
        api_key=api_key,
        json_body={"userHash": REST_SURFACE_MISSING_HASH},
    )
    transfer_pause = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"action": "pause"},
    )
    transfer_resume = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"action": "resume"},
    )
    transfer_stop = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"action": "stop"},
    )
    transfer_delete_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"delete_files": True},
    )
    transfer_delete_bad = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"delete_files": False},
    )
    transfer_add_bad = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={"link": "not-an-ed2k-link"},
    )
    transfer_recheck_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"action": "recheck"},
    )
    transfer_priority_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"priority": "high"},
    )
    transfer_category_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"category": 0},
    )
    transfer_rename_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"name": "renamed.bin"},
    )
    surface["transfers"] = {
        "list_count": len(transfer_rows),
        "list_status": transfers["status"],
        "filter_status": transfers_by_filter["status"],
        "category_count": len(category_rows),
        "category_create_bad": require_error_response(category_create_bad, 400, "INVALID_ARGUMENT", message_contains="name must be"),
        "category_get_missing": require_error_response(category_get_missing, 404, "NOT_FOUND", message_contains="category not found"),
        "category_patch_default": require_error_response(category_patch_default, 400, "INVALID_ARGUMENT", message_contains="default category"),
        "category_delete_default": require_error_response(category_delete_default, 400, "INVALID_ARGUMENT", message_contains="default category"),
        "missing_get": require_error_response(missing_transfer, 404, "NOT_FOUND", message_contains="transfer not found"),
        "missing_sources": require_error_response(missing_transfer_sources, 404, "NOT_FOUND", message_contains="transfer not found"),
        "missing_source_browse": require_error_response(missing_transfer_source_browse, 404, "NOT_FOUND", message_contains="transfer not found"),
        "pause_missing_item": require_missing_transfer_bulk_result(transfer_pause),
        "resume_missing_item": require_missing_transfer_bulk_result(transfer_resume),
        "stop_missing_item": require_missing_transfer_bulk_result(transfer_stop),
        "delete_missing_item": require_missing_transfer_bulk_result(transfer_delete_missing),
        "delete_without_files": require_missing_transfer_bulk_result(transfer_delete_bad),
        "add_bad_payload": require_error_response(
            transfer_add_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="Not an eD2K server or file link",
        ),
        "recheck_missing": require_error_response(transfer_recheck_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "priority_missing": require_error_response(transfer_priority_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "category_missing": require_error_response(transfer_category_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "rename_missing": require_error_response(transfer_rename_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
    }

    shared_directories = http_request(base_url, "/api/v1/shared-directories", api_key=api_key)
    shared_directories_payload = require_json_object(shared_directories, 200)
    assert isinstance(shared_directories_payload.get("roots"), list), compact_http_result(shared_directories)
    assert isinstance(shared_directories_payload.get("items"), list), compact_http_result(shared_directories)
    shared_directories_bad_patch = http_request(
        base_url,
        "/api/v1/shared-directories",
        method="PATCH",
        api_key=api_key,
        json_body={},
    )
    shared_directories_reload = http_request(
        base_url,
        "/api/v1/shared-directories/reload",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    surface["shared_directories"] = {
        "root_count": len(shared_directories_payload["roots"]),
        "item_count": len(shared_directories_payload["items"]),
        "bad_patch": require_error_response(
            shared_directories_bad_patch,
            400,
            "INVALID_ARGUMENT",
            message_contains="roots must be an array",
        ),
        "reload": compact_http_result(shared_directories_reload),
    }
    assert shared_directories_reload["status"] == 200, compact_http_result(shared_directories_reload)

    upload_list = http_request(base_url, "/api/v1/uploads", api_key=api_key)
    upload_queue = http_request(base_url, "/api/v1/upload-queue", api_key=api_key)
    upload_remove_bad = http_request(
        base_url,
        "/api/v1/uploads/unknown",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    upload_release_bad = http_request(
        base_url,
        "/api/v1/uploads/unknown/release-slot",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    surface["uploads"] = {
        "list_count": len(require_json_array(upload_list, 200)),
        "queue_count": len(require_json_array(upload_queue, 200)),
        "remove_bad_payload": require_error_response(
            upload_remove_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="userHash or ip and port are required",
        ),
        "release_slot_bad_payload": require_error_response(
            upload_release_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="userHash or ip and port are required",
        ),
    }

    shared = http_request(base_url, "/api/v1/shared-files", api_key=api_key)
    shared_rows = require_json_array(shared, 200)
    for row in shared_rows:
        assert isinstance(row, dict), compact_http_result(shared)
        for field_name in ("comment", "rating", "hasComment", "userRating"):
            assert field_name in row, compact_http_result(shared)
    missing_shared = http_request(base_url, f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}", api_key=api_key)
    shared_rating_missing = http_request(
        base_url,
        f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"comment": "rest smoke", "rating": 4},
    )
    shared_rating_bad_payload = None
    if shared_rows:
        first_hash = str(shared_rows[0].get("hash") or "")
        if first_hash:
            shared_rating_bad_payload = http_request(
                base_url,
                f"/api/v1/shared-files/{first_hash}",
                method="PATCH",
                api_key=api_key,
                json_body={"comment": "rest smoke", "rating": 9},
            )
    shared_add_bad = http_request(
        base_url,
        "/api/v1/shared-files",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    shared_remove_bad = http_request(
        base_url,
        "/api/v1/shared-files",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    surface["shared"] = {
        "list_count": len(shared_rows),
        "missing_get": require_error_response(missing_shared, 404, "NOT_FOUND", message_contains="shared file not found"),
        "rating_missing": require_error_response(shared_rating_missing, 404, "NOT_FOUND", message_contains="shared file not found"),
        "rating_bad_payload": (
            require_error_response(
                shared_rating_bad_payload,
                400,
                "INVALID_ARGUMENT",
                message_contains="rating must be an integer between 0 and 5",
            )
            if shared_rating_bad_payload is not None
            else None
        ),
        "add_bad_payload": require_error_response(
            shared_add_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="path must be a non-empty string path",
        ),
        "remove_bad_payload": require_error_response(
            shared_remove_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="exactly one of hash or path is required",
        ),
    }

    missing_route = http_request(base_url, "/api/v1/not-a-route", api_key=api_key)
    invalid_method = http_request(base_url, "/api/v1/app", method="POST", api_key=api_key, json_body={})
    invalid_json_shape = http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body=[],
    )
    surface["errors"] = {
        "missing_route": require_error_response(missing_route, 404, "NOT_FOUND", message_contains="API route not found"),
        "invalid_method": require_error_response(
            invalid_method,
            404,
            "NOT_FOUND",
            message_contains="API route not found",
        ),
        "invalid_json_shape": require_error_response(
            invalid_json_shape,
            400,
            "INVALID_ARGUMENT",
            message_contains="JSON body must be an object",
        ),
    }

    server_payload = dict(REST_SURFACE_TEST_SERVER)
    server_add = http_request(
        base_url,
        "/api/v1/servers",
        method="POST",
        api_key=api_key,
        json_body=server_payload,
    )
    server_add_payload = require_json_object(server_add, 200)
    servers_after_add = http_request(base_url, "/api/v1/servers", api_key=api_key)
    servers_after_add_rows = require_json_array(servers_after_add, 200)
    added_servers = [
        row
        for row in servers_after_add_rows
        if isinstance(row, dict)
        and str(row.get("address") or "") == REST_SURFACE_TEST_SERVER["addr"]
        and int(row.get("port") or 0) == REST_SURFACE_TEST_SERVER["port"]
    ]
    assert added_servers, compact_http_result(servers_after_add)
    server_remove = http_request(
        base_url,
        f"/api/v1/servers/{REST_SURFACE_TEST_SERVER['addr']}:{REST_SURFACE_TEST_SERVER['port']}",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    server_remove_payload = require_json_object(server_remove, 200)
    surface["servers_mutation"] = {
        "add": compact_http_result(server_add),
        "added_server": server_add_payload,
        "remove": compact_http_result(server_remove),
        "removed_server": server_remove_payload,
    }

    return surface


def wait_for_server_activity(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until the live server flow shows observable progress."""

    observations: list[dict[str, Any]] = []

    def resolve():
        result = http_request(base_url, "/api/v1/status", api_key=api_key)
        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            return None
        payload = get_server_status_payload(require_json_object(result, 200))
        snapshot = compact_server_status(payload)
        snapshot["observed_at"] = round(time.time(), 3)
        observations.append(snapshot)
        if payload.get("connected") or payload.get("connecting") or payload.get("currentServer") is not None:
            return {
                "status": result,
                "observations": observations,
            }
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description="server activity")


def wait_for_server_connected(
    base_url: str,
    api_key: str,
    timeout_seconds: float,
    *,
    expected_server: dict[str, object] | None = None,
) -> dict[str, object]:
    """Waits until eD2K reaches a connected state, optionally for one target server."""

    observations: list[dict[str, Any]] = []
    expected_address = None if expected_server is None else str(expected_server.get("address") or "")
    expected_port = None if expected_server is None else int(expected_server.get("port") or 0)

    def resolve():
        result = http_request(base_url, "/api/v1/status", api_key=api_key)
        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            return None
        payload = get_server_status_payload(require_json_object(result, 200))
        snapshot = compact_server_status(payload)
        snapshot["observed_at"] = round(time.time(), 3)
        observations.append(snapshot)

        current_server = payload.get("currentServer")
        matches_expected = expected_server is None
        if isinstance(current_server, dict) and expected_server is not None:
            matches_expected = (
                str(current_server.get("address") or "") == expected_address
                and int(current_server.get("port") or 0) == expected_port
            )

        if payload.get("connected") and matches_expected:
            return {
                "status": result,
                "observations": observations,
            }
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description="server connected state")


def observe_server_connect_attempt(
    base_url: str,
    api_key: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Watches one accepted server-connect attempt until it connects or clearly aborts."""

    observations: list[dict[str, Any]] = []
    last_result: dict[str, object] | None = None
    saw_progress = False
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        try:
            result = http_request(base_url, "/api/v1/status", api_key=api_key)
        except Exception as exc:
            observations.append(
                {
                    "observed_at": round(time.time(), 3),
                    "transport_error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                }
            )
            time.sleep(2.0)
            continue

        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            observations.append(
                {
                    "observed_at": round(time.time(), 3),
                    "unexpected_status": compact_http_result(result),
                }
            )
            time.sleep(2.0)
            continue

        payload = get_server_status_payload(require_json_object(result, 200))
        last_result = result
        snapshot = compact_server_status(payload)
        snapshot["observed_at"] = round(time.time(), 3)
        observations.append(snapshot)

        if bool(payload.get("connected")):
            return {
                "connected": True,
                "status": result,
                "observations": observations,
            }

        if bool(payload.get("connecting")) or payload.get("currentServer") is not None:
            saw_progress = True
        elif saw_progress:
            return {
                "connected": False,
                "aborted": True,
                "status": result,
                "observations": observations,
            }

        time.sleep(2.0)

    return {
        "connected": False,
        "aborted": False,
        "status": last_result,
        "observations": observations,
    }


def wait_for_kad_running(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until Kad reports a running state after the connect request."""

    observations: list[dict[str, Any]] = []

    def resolve():
        result = http_request(base_url, "/api/v1/kad", api_key=api_key)
        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            return None
        payload = require_json_object(result, 200)
        snapshot = compact_kad_status(payload)
        snapshot["observed_at"] = round(time.time(), 3)
        observations.append(snapshot)
        if payload.get("running"):
            return {
                "status": result,
                "observations": observations,
            }
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description="Kad running state")


def wait_for_network_ready(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until the requested live network modes become usable for searches."""

    return wait_for_requested_networks(
        base_url,
        api_key,
        timeout_seconds,
        require_server_connected=False,
        require_kad_connected=False,
    )


def wait_for_requested_networks(
    base_url: str,
    api_key: str,
    timeout_seconds: float,
    *,
    require_server_connected: bool,
    require_kad_connected: bool,
) -> dict[str, object]:
    """Waits until the requested live server/Kad connectivity requirements are met."""

    observations: list[dict[str, Any]] = []
    last_server_result = None
    last_kad_result = None
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        server_result = http_request(base_url, "/api/v1/status", api_key=api_key)
        kad_result = http_request(base_url, "/api/v1/kad", api_key=api_key)
        if int(server_result["status"]) != 200 or int(kad_result["status"]) != 200:
            time.sleep(2.0)
            continue
        if not isinstance(server_result["json"], dict) or not isinstance(kad_result["json"], dict):
            time.sleep(2.0)
            continue

        server_payload = get_server_status_payload(require_json_object(server_result, 200))
        kad_payload = require_json_object(kad_result, 200)
        last_server_result = server_result
        last_kad_result = kad_result
        snapshot = {
            "observed_at": round(time.time(), 3),
            "server": compact_server_status(server_payload),
            "kad": compact_kad_status(kad_payload),
        }
        observations.append(snapshot)

        server_connected = bool(server_payload.get("connected"))
        kad_connected = bool(kad_payload.get("connected"))

        if require_server_connected or require_kad_connected:
            if (not require_server_connected or server_connected) and (
                not require_kad_connected or kad_connected
            ):
                mode = "both" if server_connected and kad_connected else (
                    "server" if server_connected else "kad"
                )
                return {
                    "ready": True,
                    "mode": mode,
                    "server_ready": server_connected,
                    "kad_ready": kad_connected,
                    "server_status": server_result,
                    "kad_status": kad_result,
                    "observations": observations,
                }
        elif server_connected:
            return {
                "ready": True,
                "mode": "server",
                "server_ready": True,
                "kad_ready": kad_connected,
                "server_status": server_result,
                "kad_status": kad_result,
                "observations": observations,
            }
        elif kad_connected:
            return {
                "ready": True,
                "mode": "kad",
                "server_ready": server_connected,
                "kad_ready": True,
                "server_status": server_result,
                "kad_status": kad_result,
                "observations": observations,
            }
        time.sleep(2.0)

    raise RuntimeError(
        "Timed out waiting for live network readiness. "
        f"Last server status: {compact_http_result(last_server_result) if isinstance(last_server_result, dict) else None!r}; "
        f"last Kad status: {compact_http_result(last_kad_result) if isinstance(last_kad_result, dict) else None!r}"
    )


def build_search_method_candidates(mode: str) -> list[str]:
    """Returns one resilient search-method preference order for live runs."""

    if mode == "server":
        return ["server", "global", "automatic"]
    if mode == "kad":
        return ["kad", "automatic"]
    return ["automatic", "server", "kad"]


def build_search_plan(server_search_count: int, kad_search_count: int) -> list[dict[str, object]]:
    """Builds one deterministic multi-search plan for the requested network counts."""

    plan: list[dict[str, object]] = []
    for index in range(server_search_count):
        plan.append(
            {
                "network": "server",
                "query": DEFAULT_SERVER_SEARCH_QUERIES[index % len(DEFAULT_SERVER_SEARCH_QUERIES)],
                "ordinal": index + 1,
            }
        )
    for index in range(kad_search_count):
        plan.append(
            {
                "network": "kad",
                "query": DEFAULT_KAD_SEARCH_QUERIES[index % len(DEFAULT_KAD_SEARCH_QUERIES)],
                "ordinal": index + 1,
            }
        )
    return plan


def start_live_search(
    base_url: str,
    api_key: str,
    mode: str,
    query: str,
    forced_method: str | None = None,
) -> dict[str, object]:
    """Starts one real live search, retrying through sensible transport methods."""

    attempts: list[dict[str, Any]] = []
    method_candidates = [forced_method] if forced_method else build_search_method_candidates(mode)
    for method_name in method_candidates:
        response = http_request(
            base_url,
            "/api/v1/searches",
            method="POST",
            api_key=api_key,
            json_body={
                "query": query,
                "method": method_name,
                "type": "any",
            },
        )
        attempt = {
            "method": method_name,
            "response": response,
        }
        attempts.append(attempt)
        if int(response["status"]) == 200 and isinstance(response["json"], dict) and response["json"].get("search_id"):
            return {
                "ok": True,
                "attempts": attempts,
                "selected_method": method_name,
                "method_candidates": method_candidates,
                "response": response,
            }
    return {
        "ok": False,
        "attempts": attempts,
        "selected_method": None,
        "method_candidates": method_candidates,
        "response": attempts[-1]["response"] if attempts else None,
    }


def connect_to_live_server(
    base_url: str,
    api_key: str,
    server_rows: list[dict[str, object]],
    timeout_seconds: float,
) -> dict[str, object]:
    """Attempts real server connections until one seeded candidate reaches connected state."""

    candidates = [
        {
            "name": row.get("name"),
            "address": row.get("address"),
            "port": row.get("port"),
            "description": row.get("description"),
        }
        for row in server_rows
        if isinstance(row, dict) and row.get("address") and row.get("port")
    ]
    if not candidates:
        raise LiveNetworkUnavailableError("No server candidates were available for live connect attempts.")

    deadline = time.time() + timeout_seconds
    attempts: list[dict[str, object]] = []

    for index, candidate in enumerate(candidates, start=1):
        remaining_seconds = deadline - time.time()
        if remaining_seconds <= 0:
            break

        attempt: dict[str, object] = {
            "ordinal": index,
            "candidate": candidate,
        }
        try:
            connect_response = http_request(
                base_url,
                f"/api/v1/servers/{candidate['address']}:{candidate['port']}",
                method="PATCH",
                api_key=api_key,
                json_body={"action": "connect"},
                request_timeout_seconds=15.0,
            )
            attempt["connect_response"] = compact_http_result(connect_response)
        except Exception as exc:
            attempt["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            attempts.append(attempt)
            continue

        if int(connect_response["status"]) != 200 or not isinstance(connect_response["json"], dict):
            attempts.append(attempt)
            continue

        settle = observe_server_connect_attempt(
            base_url,
            api_key,
            min(remaining_seconds, 120.0),
        )
        attempt["settle"] = settle
        attempts.append(attempt)
        if bool(settle.get("connected")):
            return {
                "selected_server": candidate,
                "attempts": attempts,
                "final_status": settle["status"],
            }
        if not bool(settle.get("aborted")):
            break

    raise LiveNetworkUnavailableError(f"Failed to connect to any seeded server candidate. Attempts: {attempts!r}")


def wait_for_search_observation(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Polls one live search until results are observable or the search completes."""

    observations: list[dict[str, Any]] = []

    def resolve():
        result = http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            return None
        payload = require_json_object(result, 200)
        results = payload.get("results")
        assert isinstance(results, list)
        snapshot = {
            "observed_at": round(time.time(), 3),
            "status": payload.get("status"),
            "result_count": len(results),
        }
        observations.append(snapshot)
        if len(results) > 0:
            return {
                "result": result,
                "observations": observations,
                "terminal_state": "results",
            }
        if payload.get("status") == "complete":
            return {
                "result": result,
                "observations": observations,
                "terminal_state": "complete",
            }
        if payload.get("status") == "running" and len(observations) >= 2:
            return {
                "result": result,
                "observations": observations,
                "terminal_state": "running",
            }
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="live search activity")


def stop_live_search(base_url: str, api_key: str, search_id: str) -> dict[str, object]:
    """Stops one live search and returns the raw REST response."""

    return http_request(
        base_url,
        f"/api/v1/searches/{search_id}",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )


def execute_search_plan(
    base_url: str,
    api_key: str,
    search_plan: list[dict[str, object]],
    observation_timeout_seconds: float,
    *,
    search_method_override: str | None,
) -> tuple[list[dict[str, object]], str | None]:
    """Runs one deterministic search plan and returns completed cycle artifacts."""

    completed_cycles: list[dict[str, object]] = []
    active_search_id: str | None = None

    for cycle_index, cycle_plan in enumerate(search_plan, start=1):
        network = str(cycle_plan["network"])
        query = str(cycle_plan["query"])
        cycle_report: dict[str, object] = {
            "cycle_index": cycle_index,
            "network": network,
            "query": query,
            "ordinal": int(cycle_plan["ordinal"]),
        }
        try:
            live_search = start_live_search(
                base_url,
                api_key,
                network,
                query,
                forced_method=search_method_override or network,
            )
            cycle_report["start"] = live_search
            if not bool(live_search["ok"]):
                raise AssertionError(
                    "Failed to start a live search via methods "
                    f"{live_search['method_candidates']!r} for network {network!r}."
                )

            assert isinstance(live_search["response"], dict)
            search_payload = require_json_object(live_search["response"], 200)
            active_search_id = str(search_payload["search_id"])
            cycle_report["search_id"] = active_search_id
            cycle_report["selected_method"] = live_search["selected_method"]

            try:
                cycle_report["activity"] = wait_for_search_observation(
                    base_url,
                    api_key,
                    active_search_id,
                    observation_timeout_seconds,
                )
            finally:
                if active_search_id is not None:
                    stop_result = stop_live_search(base_url, api_key, active_search_id)
                    cycle_report["stop"] = compact_http_result(stop_result)
                    assert int(stop_result["status"]) == 200
                    assert isinstance(stop_result["json"], dict)
                    active_search_id = None
        except Exception:
            completed_cycles.append(cycle_report)
            raise

        completed_cycles.append(cycle_report)

    return completed_cycles, active_search_id


def wait_for_rest_ready(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Polls until the live REST listener answers the version route."""

    def resolve():
        try:
            result = http_request(base_url, "/api/v1/app", api_key=api_key)
        except OSError:
            return None
        if int(result["status"]) != 200:
            return None
        return result

    return wait_for(resolve, timeout=timeout_seconds, interval=0.5, description="REST API readiness")


def set_phase(report: dict[str, object], phase: str) -> str:
    """Records the current execution phase in the report and returns it."""

    report["current_phase"] = phase
    phase_history = report.setdefault("phase_history", [])
    assert isinstance(phase_history, list)
    phase_history.append(
        {
            "phase": phase,
            "entered_at": round(time.time(), 3),
        }
    )
    return phase


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--seed-config-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="rest-smoke-test-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--enable-upnp", action="store_true")
    parser.add_argument("--p2p-bind-interface-name")
    parser.add_argument("--bind-updater-script")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--server-activity-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--server-search-count", type=int, default=0)
    parser.add_argument("--kad-search-count", type=int, default=0)
    parser.add_argument("--search-method-override", choices=["automatic", "server", "global", "kad"])
    parser.add_argument("--rest-coverage-profile", choices=REST_COVERAGE_PROFILES, default="contract")
    parser.add_argument("--skip-rest-contract-completeness", action="store_true")
    parser.add_argument("--rest-stress-profile", choices=REST_STRESS_PROFILES, default="off")
    parser.add_argument("--rest-stress-duration-seconds", type=float, default=30.0)
    parser.add_argument("--rest-stress-concurrency", type=int, default=4)
    parser.add_argument("--rest-stress-max-failures", type=int, default=1)
    parser.add_argument("--rest-stress-request-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()
    if args.server_search_count < 0 or args.kad_search_count < 0:
        raise ValueError("Search counts must be zero or greater.")
    effective_stress_profile = (
        "smoke"
        if args.rest_coverage_profile == "contract-stress" and args.rest_stress_profile == "off"
        else args.rest_stress_profile
    )
    validate_rest_stress_config(
        profile=effective_stress_profile,
        duration_seconds=args.rest_stress_duration_seconds,
        concurrency=args.rest_stress_concurrency,
        max_failures=args.rest_stress_max_failures,
        request_timeout_seconds=args.rest_stress_request_timeout_seconds,
    )

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="rest-api-smoke",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts or args.keep_running,
    )
    app_exe = paths.app_exe
    seed_config_dir = Path(args.seed_config_dir).resolve() if args.seed_config_dir else paths.seed_config_dir
    artifacts_dir = paths.source_artifacts_dir

    port = choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"
    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    seed_refresh = None
    if not args.skip_live_seed_refresh:
        seed_refresh = refresh_seed_files(
            Path(profile["config_dir"]),
            timeout_seconds=args.seed_download_timeout_seconds,
        )
    configure_webserver_profile(
        Path(profile["config_dir"]),
        app_exe,
        args.api_key,
        port,
        args.bind_addr,
        args.enable_upnp,
    )
    if args.p2p_bind_interface_name:
        if not args.bind_updater_script:
            raise ValueError("bind updater script path is required when a P2P bind interface name is supplied.")
        apply_p2p_bindaddr_override(
            Path(profile["config_dir"]),
            args.p2p_bind_interface_name,
            Path(args.bind_updater_script).resolve(),
        )

    app = None
    search_id = None
    report: dict[str, object] = {
        "base_url": base_url,
        "port": port,
        "suite": "rest-api-live-e2e",
        "launch_inputs": {
            "app_exe": str(app_exe),
            "seed_config_dir": str(seed_config_dir),
            "live_seed_source_url": EMULE_SECURITY_HOME_URL,
            "live_seed_refresh": seed_refresh,
            "artifacts_dir": str(artifacts_dir),
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "api_key_length": len(args.api_key),
            "bind_addr": args.bind_addr,
            "enable_upnp": bool(args.enable_upnp),
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "bind_updater_script": args.bind_updater_script,
            "keep_running": bool(args.keep_running),
            "server_search_count": args.server_search_count,
            "kad_search_count": args.kad_search_count,
            "live_wire_search_queries": list(LIVE_WIRE_SEARCH_QUERIES),
            "search_method_override": args.search_method_override,
            "rest_coverage_profile": args.rest_coverage_profile,
            "rest_contract_completeness_enabled": not args.skip_rest_contract_completeness,
            "rest_stress_profile": effective_stress_profile,
            "rest_stress_duration_seconds": args.rest_stress_duration_seconds,
            "rest_stress_concurrency": args.rest_stress_concurrency,
            "timeouts": {
                "rest_ready_seconds": args.rest_ready_timeout_seconds,
                "server_activity_seconds": args.server_activity_timeout_seconds,
                "kad_running_seconds": args.kad_running_timeout_seconds,
                "network_ready_seconds": args.network_ready_timeout_seconds,
                "search_observation_seconds": args.search_observation_timeout_seconds,
                "seed_download_seconds": args.seed_download_timeout_seconds,
                "rest_stress_request_seconds": args.rest_stress_request_timeout_seconds,
            },
        },
        "checks": {},
        "cleanup": {},
        "status": "failed",
    }
    current_phase = set_phase(report, "launch")
    pending_error: Exception | None = None

    try:
        app = launch_app(app_exe, Path(profile["profile_base"]))
        report["launched_process_id"] = get_app_process_id(app)
        main_window = wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()

        current_phase = set_phase(report, "rest_ready")
        ready = wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["checks"]["ready"] = compact_http_result(ready)

        if args.enable_upnp:
            current_phase = set_phase(report, "nat_backend_order")
            report["checks"]["nat_backend_order"] = wait_for_upnp_backend_order(
                base_url,
                args.api_key,
                timeout_seconds=20.0,
            )

        current_phase = set_phase(report, "auth_checks")
        no_key = http_request(base_url, "/api/v1/app")
        assert no_key["status"] == 401
        assert isinstance(no_key["json"], dict)
        assert no_key["json"]["error"] == "UNAUTHORIZED"
        report["checks"]["missing_key"] = compact_http_result(no_key)

        wrong_key = http_request(base_url, "/api/v1/app", api_key="wrong-key")
        assert wrong_key["status"] == 401
        assert isinstance(wrong_key["json"], dict)
        assert wrong_key["json"]["error"] == "UNAUTHORIZED"
        report["checks"]["wrong_key"] = compact_http_result(wrong_key)

        current_phase = set_phase(report, "app_version")
        version = http_request(base_url, "/api/v1/app", api_key=args.api_key)
        assert version["status"] == 200
        assert isinstance(version["json"], dict)
        assert version["json"]["appName"] == "eMule"
        assert "version" in version["json"]
        report["checks"]["app_version"] = compact_http_result(version)

        current_phase = set_phase(report, "stats_global")
        stats = http_request(base_url, "/api/v1/status", api_key=args.api_key)
        assert stats["status"] == 200
        assert isinstance(stats["json"], dict)
        assert isinstance(stats["json"].get("stats"), dict)
        assert "connected" in stats["json"]["stats"]
        report["checks"]["stats_global"] = compact_http_result(stats)

        current_phase = set_phase(report, "rest_surface")
        report["checks"]["rest_surface"] = exercise_rest_surface_smoke(base_url, args.api_key)

        if args.rest_coverage_profile != "smoke" and not args.skip_rest_contract_completeness:
            current_phase = set_phase(report, "rest_contract")
            rest_contract = exercise_rest_contract_completeness(
                base_url,
                args.api_key,
                args.rest_coverage_profile,
            )
            assert rest_contract["ok"], rest_contract
            report["checks"]["rest_contract"] = rest_contract

        if effective_stress_profile != "off":
            current_phase = set_phase(report, "rest_stress")
            report["checks"]["rest_stress"] = exercise_rest_stress(
                base_url,
                args.api_key,
                profile=effective_stress_profile,
                duration_seconds=args.rest_stress_duration_seconds,
                concurrency=args.rest_stress_concurrency,
                max_failures=args.rest_stress_max_failures,
                request_timeout_seconds=args.rest_stress_request_timeout_seconds,
            )

        current_phase = set_phase(report, "servers_list")
        servers = http_request(base_url, "/api/v1/servers", api_key=args.api_key)
        assert servers["status"] == 200
        server_rows = require_json_array(servers, 200)
        assert len(server_rows) > 0
        first_server = server_rows[0]
        assert isinstance(first_server, dict)
        assert "address" in first_server and "port" in first_server
        report["checks"]["servers_list"] = {
            "count": len(server_rows),
            "first_server": {
                "name": first_server.get("name"),
                "address": first_server.get("address"),
                "port": first_server.get("port"),
                "description": first_server.get("description"),
            },
        }

        current_phase = set_phase(report, "servers_status_initial")
        initial_server_status = http_request(base_url, "/api/v1/status", api_key=args.api_key)
        assert initial_server_status["status"] == 200
        assert isinstance(initial_server_status["json"], dict)
        report["checks"]["servers_status_initial"] = compact_http_result(initial_server_status)

        current_phase = set_phase(report, "servers_connect")
        server_connect = connect_to_live_server(
            base_url,
            api_key=args.api_key,
            server_rows=server_rows,
            timeout_seconds=args.network_ready_timeout_seconds,
        )
        report["checks"]["servers_connect"] = server_connect
        report["selected_server_target"] = dict(server_connect["selected_server"])

        current_phase = set_phase(report, "kad_status_initial")
        initial_kad_status = http_request(base_url, "/api/v1/kad", api_key=args.api_key)
        assert initial_kad_status["status"] == 200
        assert isinstance(initial_kad_status["json"], dict)
        report["checks"]["kad_status_initial"] = compact_http_result(initial_kad_status)

        current_phase = set_phase(report, "kad_connect")
        kad_connect = http_request(
            base_url,
            "/api/v1/kad",
            method="PATCH",
            api_key=args.api_key,
            json_body={"action": "connect"},
        )
        assert kad_connect["status"] == 200
        assert isinstance(kad_connect["json"], dict)
        report["checks"]["kad_connect"] = compact_http_result(kad_connect)

        current_phase = set_phase(report, "kad_running")
        kad_running = wait_for_kad_running(base_url, args.api_key, args.kad_running_timeout_seconds)
        report["checks"]["kad_running"] = kad_running

        current_phase = set_phase(report, "kad_recheck_firewall")
        kad_recheck = http_request(
            base_url,
            "/api/v1/kad",
            method="PATCH",
            api_key=args.api_key,
            json_body={"action": "recheck_firewall"},
        )
        assert kad_recheck["status"] == 200
        assert isinstance(kad_recheck["json"], dict)
        report["checks"]["kad_recheck_firewall"] = compact_http_result(kad_recheck)

        current_phase = set_phase(report, "network_ready")
        live_network = wait_for_requested_networks(
            base_url,
            args.api_key,
            args.network_ready_timeout_seconds,
            require_server_connected=args.server_search_count > 0,
            require_kad_connected=args.kad_search_count > 0,
        )
        report["checks"]["network_ready"] = live_network
        assert bool(live_network.get("ready"))

        search_plan = build_search_plan(args.server_search_count, args.kad_search_count)
        if not search_plan:
            search_plan = [
                {
                    "network": str(live_network["mode"]),
                    "query": DEFAULT_SERVER_SEARCH_QUERIES[0],
                    "ordinal": 1,
                }
            ]
        report["checks"]["search_plan"] = search_plan

        current_phase = set_phase(report, "search_cycles")
        completed_cycles, search_id = execute_search_plan(
            base_url,
            args.api_key,
            search_plan,
            args.search_observation_timeout_seconds,
            search_method_override=args.search_method_override,
        )
        report["checks"]["search_cycles"] = completed_cycles
        search_id = None

        current_phase = set_phase(report, "log_limit")
        log_entries = http_request(base_url, "/api/v1/logs?limit=1", api_key=args.api_key)
        assert log_entries["status"] == 200
        assert len(require_json_array(log_entries, 200)) <= 1
        report["checks"]["log_limit"] = compact_http_result(log_entries)

        current_phase = set_phase(report, "servers_disconnect")
        server_disconnect = http_request(
            base_url,
            "/api/v1/servers/current:1",
            method="PATCH",
            api_key=args.api_key,
            json_body={"action": "disconnect"},
        )
        assert server_disconnect["status"] == 200
        assert isinstance(server_disconnect["json"], dict)
        report["checks"]["servers_disconnect"] = compact_http_result(server_disconnect)

        current_phase = set_phase(report, "kad_disconnect")
        kad_disconnect = http_request(
            base_url,
            "/api/v1/kad",
            method="PATCH",
            api_key=args.api_key,
            json_body={"action": "disconnect"},
        )
        assert kad_disconnect["status"] == 200
        assert isinstance(kad_disconnect["json"], dict)
        assert "running" in kad_disconnect["json"]
        report["checks"]["kad_disconnect"] = compact_http_result(kad_disconnect)

        current_phase = set_phase(report, "html_root")
        html_root = http_request(base_url, "/")
        assert html_root["status"] == 200
        assert "text/html" in str(html_root["content_type"]).lower()
        assert "<html" in str(html_root["body_text"]).lower()
        report["checks"]["html_root"] = {
            "status": html_root["status"],
            "content_type": html_root["content_type"],
            "body_preview": str(html_root["body_text"])[:200],
        }

        current_phase = set_phase(report, "completed")
        report["status"] = "passed"
    except Exception as exc:
        if isinstance(exc, LiveNetworkUnavailableError):
            report["status"] = "inconclusive"
            report["inconclusive_phase"] = current_phase
            report["inconclusive_reason"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        else:
            pending_error = exc
            report["status"] = "failed"
            report["failed_phase"] = current_phase
            report["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
    finally:
        cleanup = report["cleanup"]
        assert isinstance(cleanup, dict)
        if app is not None and search_id is not None:
            cleanup["search_stop_attempted"] = True
            try:
                stop_response = stop_live_search(base_url, args.api_key, search_id)
                cleanup["search_stop"] = compact_http_result(stop_response)
            except Exception as exc:  # pragma: no cover - best-effort live cleanup
                cleanup["search_stop_error"] = repr(exc)
        if app is not None:
            cleanup["process_id"] = get_app_process_id(app)
            cleanup["profile_base"] = str(profile["profile_base"])
            if args.keep_running and str(report.get("status")) == "passed":
                cleanup["app_closed"] = False
                cleanup["app_left_running"] = True
            else:
                try:
                    close_app_cleanly(app)
                    cleanup["app_closed"] = True
                except Exception as exc:
                    cleanup["app_closed"] = False
                    cleanup["app_close_error"] = repr(exc)
                    if pending_error is None:
                        pending_error = exc
                        report["status"] = "failed"
                        report["failed_phase"] = "cleanup"
                        report["error"] = {
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
        write_json(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)
    if pending_error is not None:
        raise pending_error

    if report["status"] == "inconclusive":
        print(
            "REST API live E2E was inconclusive because no seeded live server candidate connected. "
            f"Report directory: {paths.run_report_dir}"
        )
        return LIVE_NETWORK_UNAVAILABLE_EXIT_CODE

    print(f"REST API live E2E {'passed' if report['status'] == 'passed' else 'failed'}. Report directory: {paths.run_report_dir}")
    if args.keep_running and str(report.get("status")) == "passed":
        cleanup = report.get("cleanup")
        if isinstance(cleanup, dict):
            print(
                "eMule left running. PID: "
                f"{cleanup.get('process_id')} Profile: {cleanup.get('profile_base')}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
