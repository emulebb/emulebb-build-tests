"""Runs the canonical isolated live E2E suite against the in-process eMule REST API."""

from __future__ import annotations

import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_wire_inputs
from emule_test_harness.live_seed_sources import (
    EMULE_SECURITY_HOME_URL,
    EMULE_SECURITY_NODES_DAT_URL,
    EMULE_SECURITY_SERVER_MET_URL,
    refresh_seed_files,
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
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
close_app_cleanly = live_common.close_app_cleanly
launch_app = live_common.launch_app
patch_ini_value = live_common.patch_ini_value
prepare_profile_base = live_common.prepare_profile_base
upsert_ini_section_value = live_common.upsert_ini_section_value
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
WebServerProfileSpec = live_common.WebServerProfileSpec
write_json = live_common.write_json

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
STILL_ACTIVE = 259
GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int
kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
kernel32.GetProcessHandleCount.restype = ctypes.c_int
kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
kernel32.GetExitCodeProcess.restype = ctypes.c_int
psapi = ctypes.WinDLL("psapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetGuiResources.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
user32.GetGuiResources.restype = ctypes.c_uint32


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    """Mirror of PROCESS_MEMORY_COUNTERS_EX for REST/WebSocket leak snapshots."""

    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class THREADENTRY32(ctypes.Structure):
    """Mirror of THREADENTRY32 for process thread-count leak snapshots."""

    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ThreadID", ctypes.c_uint32),
        ("th32OwnerProcessID", ctypes.c_uint32),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
    ]


kernel32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = ctypes.c_int
kernel32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = ctypes.c_int


psapi.GetProcessMemoryInfo.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
    ctypes.c_uint32,
]
psapi.GetProcessMemoryInfo.restype = ctypes.c_int

DEFAULT_LIVE_DOWNLOAD_TRIGGER_COUNT = 1
MAX_SAFE_LIVE_DOWNLOAD_BYTES = 1024 * 1024 * 1024
MIN_SAFE_LIVE_DOWNLOAD_SOURCES = 2
UNSAFE_LIVE_DOWNLOAD_SUFFIXES = (
    ".7z",
    ".ace",
    ".bat",
    ".bz2",
    ".cmd",
    ".com",
    ".exe",
    ".gz",
    ".msi",
    ".ps1",
    ".rar",
    ".scr",
    ".tar",
    ".vbs",
    ".xz",
    ".zip",
)
NAT_BACKEND_ATTEMPT_PREFIX = "Attempting NAT mapping backend "
UPNP_IGD_BACKEND_NAME = "UPnP IGD (MiniUPnP)"
PCP_NATPMP_BACKEND_NAME = "PCP/NAT-PMP"
LIVE_NETWORK_UNAVAILABLE_EXIT_CODE = 2
REST_SURFACE_TEST_SERVER = {
    "address": "192.0.2.254",
    "port": 4669,
    "name": "REST surface smoke disposable",
}
REST_SURFACE_MISSING_HASH = "0123456789abcdef0123456789abcdef"
REST_SURFACE_VALID_DOWNLOAD_HASH = "fedcba98765432100123456789abcdef"
REST_SURFACE_UNICODE_DOWNLOAD_HASH = "abcdef0123456789fedcba9876543210"
REST_SURFACE_RESERVED_DOWNLOAD_HASH = "00112233445566778899aabbccddeeff"
REST_SURFACE_QBIT_DOWNLOAD_HASH = "11223344556677889900aabbccddeeff"
REST_PREFERENCE_KEYS = {
    "uploadLimitKiBps",
    "downloadLimitKiBps",
    "maxConnections",
    "maxConnectionsPerFiveSeconds",
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
REST_COVERAGE_BUDGETS = ("smoke", "contract", "contract-stress")
REST_STRESS_BUDGETS = ("off", "smoke", "soak")
REST_SOCKET_ADVERSITY_BUDGETS = ("off", "smoke")
REST_TLS_HANDSHAKE_ADVERSITY_BUDGETS = ("off", "smoke")
REST_LEAK_CHURN_BUDGETS = ("off", "smoke", "soak")
REST_LEAK_CHURN_DEFAULT_CYCLES = {
    "off": 0,
    "smoke": 100,
    "soak": 1000,
}
REST_STRESS_RETRYABLE_ERROR_FRAGMENTS = (
    "winerror 10053",
    "winerror 10054",
    "unexpected_eof_while_reading",
    "forcibly closed",
    "connection was aborted",
)
REST_LEAK_CHURN_RESOURCE_THRESHOLDS = {
    "handles": {"after_drain_max": 64, "peak_max": 128},
    "thread_count": {"after_drain_max": 4, "peak_max": 32},
    "gdi_objects": {"after_drain_max": 32, "peak_max": 64},
    "user_objects": {"after_drain_max": 32, "peak_max": 64},
    "private_bytes": {"after_drain_max": 256 * 1024 * 1024, "peak_max": 384 * 1024 * 1024},
    "working_set_bytes": {"after_drain_max": 256 * 1024 * 1024, "peak_max": 384 * 1024 * 1024},
}
REST_ERROR_MATRIX_RELEASE_STATUSES = (400, 401, 404, 405, 409, 500, 503)
REST_ERROR_MATRIX_SEAM_BACKED_ROWS = {
    405: {
        "scenario": "native_rest_method_not_allowed_route_rejection",
        "surface": "native-rest",
        "source": "web_api.tests.cpp::Web API rejects malformed native REST routes with stable error codes",
        "expected_error_code": "METHOD_NOT_ALLOWED",
    },
    409: {
        "scenario": "native_rest_invalid_state_envelope",
        "surface": "native-rest",
        "source": "web_api.tests.cpp::Web API envelopes representative runtime REST failures",
        "expected_error_code": "INVALID_STATE",
    },
    500: {
        "scenario": "native_rest_runtime_failure_envelope",
        "surface": "native-rest",
        "source": "web_api.tests.cpp::Web API envelopes representative runtime REST failures",
        "expected_error_code": "EMULE_ERROR",
    },
    503: {
        "scenario": "native_rest_unavailable_envelope",
        "surface": "native-rest",
        "source": "web_api.tests.cpp::Web API classifies native REST API key failures without exposing wrong keys",
        "expected_error_code": "EMULE_UNAVAILABLE",
    },
}
REST_STRESS_LONG_SEARCH_QUERY = "unicode-lambda-" + ("λ" * 161)
REST_STRESS_LONG_UNICODE_PATH = (
    ("deep_unicode_λ_例" * 24)
    + "-linux-iso-library-Ω-例.mkv"
)
OPENAPI_CONTRACT_PATH = REPO_ROOT.parent / "eMule-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
NATIVE_ROUTE_HEADER_PATH = (
    REPO_ROOT.parent.parent
    / "workspaces"
    / "v0.72a"
    / "app"
    / "eMule-main"
    / "srchybrid"
    / "WebServerJsonSeams.h"
)
UNSAFE_OPENAPI_OPERATIONS = {"captureDiagnosticDump", "triggerDiagnosticCrashTest", "shutdownApp"}
UNSAFE_BROAD_MUTATION_PATHS = (
    "/api/v1/app/shutdown",
    "/api/v1/diagnostics/dumps",
    "/api/v1/diagnostics/crash-tests",
)
REST_CONTRACT_EXPECTED_ERROR_STATUSES: dict[str, tuple[int, ...]] = {
    "getCategory": (404,),
    "createCategory": (400,),
    "patchCategory": (404,),
    "deleteCategory": (404,),
    "createTransfers": (400,),
    "getTransfer": (404,),
    "patchTransfer": (404,),
    "getTransferDetails": (404,),
    "listTransferSources": (404,),
    "getTransferSource": (404,),
    "browseTransferSource": (404,),
    "addTransferSourceFriend": (404,),
    "removeTransferSourceFriend": (404,),
    "removeTransferSource": (404,),
    "banTransferSource": (404,),
    "unbanTransferSource": (404,),
    "releaseTransferSourceUploadSlot": (404,),
    "recheckTransfer": (404,),
    "previewTransfer": (404,),
    "createSharedFile": (400,),
    "getSharedFile": (404,),
    "patchSharedFile": (404,),
    "deleteSharedFile": (404,),
    "getSharedFileEd2kLink": (404,),
    "listSharedFileComments": (404,),
    "replaceSharedDirectories": (400,),
    "getUpload": (404,),
    "releaseUploadSlot": (404,),
    "removeUploadClient": (404,),
    "addUploadFriend": (404,),
    "removeUploadFriend": (404,),
    "banUploadClient": (404,),
    "unbanUploadClient": (404,),
    "removeUploadQueueClient": (404,),
    "getUploadQueueClient": (404,),
    "releaseUploadQueueClientSlot": (404,),
    "addUploadQueueFriend": (404,),
    "removeUploadQueueFriend": (404,),
    "banUploadQueueClient": (404,),
    "unbanUploadQueueClient": (404,),
    "createServerMetUrlImport": (400,),
    "getServer": (404,),
    "patchServer": (404,),
    "deleteServer": (404,),
    "connectServer": (404,),
    "createKadNodesUrlImport": (400,),
    "bootstrapKad": (400,),
    "createSearch": (400,),
    "getSearch": (404,),
    "deleteSearch": (404,),
    "downloadSearchResult": (404,),
    "deleteFriend": (404,),
}
OPENAPI_TAG_FAMILIES = {
    "App": "app",
    "Diagnostics": "diagnostics",
    "Stats": "status",
    "Categories": "categories",
    "Transfers": "transfers",
    "SharedFiles": "shared",
    "SharedDirectories": "shared-directories",
    "Uploads": "uploads",
    "Servers": "servers",
    "Kad": "kad",
    "Searches": "searches",
    "Friends": "friends",
    "Logs": "logs",
}


def load_openapi_method_paths(openapi_path: Path = OPENAPI_CONTRACT_PATH) -> set[tuple[str, str]]:
    """Extracts method/path pairs from the source OpenAPI YAML without extra dependencies."""

    method_paths: set[tuple[str, str]] = set()
    current_path: str | None = None
    in_paths = False
    for raw_line in openapi_path.read_text(encoding="utf-8").splitlines():
        if raw_line == "paths:":
            in_paths = True
            continue
        if not in_paths:
            continue
        if raw_line.startswith("components:"):
            break
        if raw_line.startswith("  /") and raw_line.rstrip().endswith(":"):
            current_path = raw_line.strip()[:-1]
            continue
        if current_path is None:
            continue
        stripped = raw_line.strip()
        if stripped in {"get:", "post:", "patch:", "delete:"}:
            method_paths.add((stripped[:-1].upper(), current_path))
    return method_paths


def load_openapi_document(openapi_path: Path = OPENAPI_CONTRACT_PATH) -> dict[str, Any]:
    """Loads the OpenAPI document with the harness-pinned YAML parser."""

    document = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError(f"OpenAPI document is not an object: {openapi_path}")
    return document


def get_openapi_response_schema(response_name: str, openapi_path: Path = OPENAPI_CONTRACT_PATH) -> dict[str, Any]:
    """Returns the JSON schema for one named OpenAPI response component."""

    document = load_openapi_document(openapi_path)
    response = (((document.get("components") or {}).get("responses") or {}).get(response_name) or {})
    content = response.get("content") if isinstance(response, dict) else None
    media_type = (content or {}).get("application/json") if isinstance(content, dict) else None
    schema = (media_type or {}).get("schema") if isinstance(media_type, dict) else None
    if not isinstance(schema, dict):
        raise RuntimeError(f"OpenAPI response does not define an application/json schema: {response_name}")
    return schema


def validate_openapi_response_payload(response_name: str, payload: object, openapi_path: Path = OPENAPI_CONTRACT_PATH) -> None:
    """Validates one REST response payload against its OpenAPI response schema."""

    document = load_openapi_document(openapi_path)
    schema = get_openapi_response_schema(response_name, openapi_path)
    validator = jsonschema.Draft202012Validator(document).evolve(schema=schema)
    validator.validate(payload)


def _commit_openapi_operation(
    operations: list[dict[str, object]],
    *,
    path: str | None,
    method: str | None,
    operation_id: str | None,
    tag: str | None,
    has_request_body: bool,
    request_body_required: bool,
    success_response_statuses: list[str],
    success_response_refs: list[str],
) -> None:
    """Appends one parsed OpenAPI operation when all required fields are present."""

    if path is None or method is None:
        return
    if not operation_id:
        raise RuntimeError(f"OpenAPI operation is missing operationId: {method.upper()} {path}")
    if not tag:
        raise RuntimeError(f"OpenAPI operation is missing tags: {method.upper()} {path}")
    operations.append(
        {
            "operationId": operation_id,
            "method": method.upper(),
            "openapiPath": path,
            "tag": tag,
            "hasRequestBody": has_request_body,
            "requestBodyRequired": request_body_required,
            "successResponseStatuses": list(success_response_statuses),
            "successResponseRefs": list(success_response_refs),
        }
    )


def load_openapi_operations(openapi_path: Path = OPENAPI_CONTRACT_PATH) -> list[dict[str, object]]:
    """Extracts operation metadata from the source OpenAPI YAML without extra dependencies."""

    operations: list[dict[str, object]] = []
    current_path: str | None = None
    current_method: str | None = None
    current_operation_id: str | None = None
    current_tag: str | None = None
    current_has_request_body = False
    current_request_body_required = False
    current_success_response_statuses: list[str] = []
    current_success_response_refs: list[str] = []
    current_response_status: str | None = None
    in_paths = False
    for raw_line in openapi_path.read_text(encoding="utf-8").splitlines():
        if raw_line == "paths:":
            in_paths = True
            continue
        if not in_paths:
            continue
        if raw_line.startswith("components:"):
            break
        if raw_line.startswith("  /") and raw_line.rstrip().endswith(":"):
            _commit_openapi_operation(
                operations,
                path=current_path,
                method=current_method,
                operation_id=current_operation_id,
                tag=current_tag,
                has_request_body=current_has_request_body,
                request_body_required=current_request_body_required,
                success_response_statuses=current_success_response_statuses,
                success_response_refs=current_success_response_refs,
            )
            current_path = raw_line.strip()[:-1]
            current_method = None
            current_operation_id = None
            current_tag = None
            current_has_request_body = False
            current_request_body_required = False
            current_success_response_statuses = []
            current_success_response_refs = []
            current_response_status = None
            continue
        stripped = raw_line.strip()
        if stripped in {"get:", "post:", "patch:", "delete:"}:
            _commit_openapi_operation(
                operations,
                path=current_path,
                method=current_method,
                operation_id=current_operation_id,
                tag=current_tag,
                has_request_body=current_has_request_body,
                request_body_required=current_request_body_required,
                success_response_statuses=current_success_response_statuses,
                success_response_refs=current_success_response_refs,
            )
            current_method = stripped[:-1]
            current_operation_id = None
            current_tag = None
            current_has_request_body = False
            current_request_body_required = False
            current_success_response_statuses = []
            current_success_response_refs = []
            current_response_status = None
            continue
        if current_method is None:
            continue
        if stripped.startswith("operationId:"):
            current_operation_id = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("tags:"):
            tag_text = stripped.split(":", 1)[1].strip()
            if tag_text.startswith("[") and tag_text.endswith("]"):
                current_tag = tag_text[1:-1].split(",", 1)[0].strip()
        elif stripped == "requestBody:":
            current_has_request_body = True
        elif current_has_request_body and stripped.startswith("required:"):
            current_request_body_required = stripped.split(":", 1)[1].strip().lower() == "true"
        elif stripped.startswith('"2') and stripped.endswith('":'):
            current_response_status = stripped.split(":", 1)[0].strip('"')
        elif current_response_status is not None and stripped.startswith("$ref:"):
            response_ref = stripped.rsplit("/", 1)[-1].strip('"')
            current_success_response_statuses.append(current_response_status)
            current_success_response_refs.append(response_ref)
            current_response_status = None
    _commit_openapi_operation(
        operations,
        path=current_path,
        method=current_method,
        operation_id=current_operation_id,
        tag=current_tag,
        has_request_body=current_has_request_body,
        request_body_required=current_request_body_required,
        success_response_statuses=current_success_response_statuses,
        success_response_refs=current_success_response_refs,
    )
    return operations


def load_native_route_execution_models(route_header_path: Path = NATIVE_ROUTE_HEADER_PATH) -> dict[tuple[str, str], str]:
    """Extracts internal route execution ownership from the native REST seam."""

    route_specs = re.findall(
        r'\{\s*"([A-Z]+)"\s*,\s*"([^"]+)"\s*,\s*"[^"]*"\s*,\s*"[^"]*"(?:\s*,\s*([^}]+?))?\s*\}',
        route_header_path.read_text(encoding="utf-8"),
    )
    models: dict[tuple[str, str], str] = {}
    for method, path, model in route_specs:
        if "kRestRouteExecutionDirect" in model:
            models[(method, path)] = "direct"
        else:
            models[(method, path)] = "ui-thread"
    return models


def concrete_contract_path(openapi_path: str, operation_id: str) -> str:
    """Converts one OpenAPI path template to a live-smoke safe concrete path."""

    path = "/api/v1" + openapi_path
    path = path.replace("{hash}", REST_SURFACE_MISSING_HASH)
    path = path.replace("{clientId}", REST_SURFACE_MISSING_HASH)
    path = path.replace("{userHash}", REST_SURFACE_MISSING_HASH)
    path = path.replace("{categoryId}", "999999")
    path = path.replace("{serverId}", "192.0.2.254:4669")
    path = path.replace("{searchId}", "123")
    if operation_id == "getSnapshot":
        path += "?limit=7"
    elif operation_id == "listLogs":
        path += "?limit=9"
    return path


def build_openapi_contract_routes(openapi_path: Path = OPENAPI_CONTRACT_PATH) -> tuple[dict[str, object], ...]:
    """Builds the live REST completeness route list from the OpenAPI contract."""

    routes: list[dict[str, object]] = []
    execution_models = load_native_route_execution_models()
    for operation in load_openapi_operations(openapi_path):
        tag = operation["tag"]
        family = OPENAPI_TAG_FAMILIES.get(tag)
        if family is None:
            raise RuntimeError(f"OpenAPI tag is not mapped to a REST family: {tag}")
        operation_id = operation["operationId"]
        openapi_path_value = operation["openapiPath"]
        safe = operation_id not in UNSAFE_OPENAPI_OPERATIONS
        success_response_refs = list(operation["successResponseRefs"])
        if not success_response_refs:
            raise RuntimeError(f"OpenAPI operation is missing a 2xx response envelope: {operation_id}")
        routes.append(
            {
                "name": operation_id,
                "operationId": operation_id,
                "family": family,
                "method": operation["method"],
                "path": concrete_contract_path(openapi_path_value, operation_id),
                "openapiPath": openapi_path_value,
                "safe": safe,
                "safety": "safe" if safe else "unsafe",
                "hasRequestBody": bool(operation["hasRequestBody"]),
                "requestBodyRequired": bool(operation["requestBodyRequired"]),
                "successResponseStatuses": operation["successResponseStatuses"],
                "successResponseRefs": success_response_refs,
                "responseEnvelope": success_response_refs[0],
                "executionModel": execution_models.get((str(operation["method"]), str(openapi_path_value)), "unknown"),
            }
        )
    return tuple(routes)


def normalize_contract_path_for_openapi(path: str) -> str:
    """Converts one concrete smoke path back to its OpenAPI template form."""

    normalized = path.split("?", 1)[0]
    normalized = normalized.replace(REST_SURFACE_MISSING_HASH, "{hash}")
    normalized = normalized.replace("/api/v1", "", 1) or "/"
    normalized = normalized.replace("/categories/999999", "/categories/{categoryId}")
    normalized = normalized.replace("/servers/192.0.2.254:4669", "/servers/{serverId}")
    normalized = normalized.replace("/searches/123/results/{hash}", "/searches/{searchId}/results/{hash}")
    normalized = normalized.replace("/searches/123", "/searches/{searchId}")
    normalized = normalized.replace("/uploads/{hash}", "/uploads/{clientId}")
    normalized = normalized.replace("/upload-queue/{hash}", "/upload-queue/{clientId}")
    normalized = normalized.replace("/sources/{hash}", "/sources/{clientId}")
    normalized = normalized.replace("/friends/{hash}", "/friends/{userHash}")
    return normalized


REST_CONTRACT_ROUTES: tuple[dict[str, object], ...] = build_openapi_contract_routes()


def assert_contract_routes_match_openapi() -> dict[str, object]:
    """Verifies the smoke route registry and OpenAPI path table stay in lockstep."""

    openapi_routes = load_openapi_method_paths()
    registry_routes = {
        (str(route["method"]), normalize_contract_path_for_openapi(str(route["path"])))
        for route in REST_CONTRACT_ROUTES
    }
    operation_ids = [str(route["operationId"]) for route in REST_CONTRACT_ROUTES]
    duplicate_operation_ids = sorted({operation_id for operation_id in operation_ids if operation_ids.count(operation_id) > 1})
    missing_from_registry = sorted(openapi_routes - registry_routes)
    missing_from_openapi = sorted(registry_routes - openapi_routes)
    missing_required_body_payloads = sorted(
        str(route["operationId"])
        for route in REST_CONTRACT_ROUTES
        if bool(route["requestBodyRequired"]) and get_contract_route_body(str(route["operationId"])) is None
    )
    unknown_execution_models = sorted(
        str(route["operationId"])
        for route in REST_CONTRACT_ROUTES
        if route.get("executionModel") == "unknown"
    )
    return {
        "openapi_route_count": len(openapi_routes),
        "registry_route_count": len(registry_routes),
        "operation_count": len(operation_ids),
        "duplicate_operation_ids": duplicate_operation_ids,
        "missing_from_registry": missing_from_registry,
        "missing_from_openapi": missing_from_openapi,
        "missing_required_body_payloads": missing_required_body_payloads,
        "unknown_execution_models": unknown_execution_models,
        "ok": not missing_from_registry
        and not missing_from_openapi
        and not duplicate_operation_ids
        and not missing_required_body_payloads
        and not unknown_execution_models,
    }
REST_STRESS_READ_PATHS = (
    "/api/v1/app",
    "/api/v1/status",
    "/api/v1/stats",
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
        "scenario": "safe_mutation",
        "expected_statuses": (200,),
    },
    {
        "method": "POST",
        "path": "/api/v1/transfers",
        "json_body": {"link": "not-an-ed2k-link"},
        "family": "transfers",
        "scenario": "safe_mutation",
        "expected_statuses": (400,),
    },
    {
        "method": "POST",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/operations/pause",
        "json_body": {},
        "family": "transfers",
        "scenario": "safe_mutation",
        "expected_statuses": (200,),
    },
    {
        "method": "DELETE",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        "json_body": {"deleteFiles": False},
        "family": "transfers",
        "scenario": "transfer_delete_requires_delete_files",
        "expected_statuses": (400,),
    },
    {
        "method": "POST",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources/{REST_SURFACE_MISSING_HASH}/operations/browse",
        "json_body": {},
        "family": "transfers",
        "scenario": "safe_mutation",
        "expected_statuses": (404,),
    },
    {
        "method": "POST",
        "path": "/api/v1/logs/operations/clear",
        "json_body": {"confirmClearLogs": True},
        "family": "logs",
        "scenario": "safe_mutation",
        "expected_statuses": (200,),
    },
    {
        "method": "PATCH",
        "path": "/api/v1/servers/192.0.2.254:4669",
        "json_body": {"priority": "high"},
        "family": "servers",
        "scenario": "safe_mutation",
    },
    {
        "method": "POST",
        "path": "/api/v1/kad/operations/recheck-firewall",
        "json_body": {},
        "family": "kad",
        "scenario": "safe_mutation",
    },
    {
        "method": "POST",
        "path": "/api/v1/searches",
        "json_body": {"query": "", "method": "automatic", "type": ""},
        "family": "searches",
        "scenario": "safe_mutation",
        "expected_statuses": (400,),
    },
    {
        "method": "DELETE",
        "path": "/api/v1/searches/123",
        "json_body": {},
        "family": "searches",
        "scenario": "safe_mutation",
    },
)
REST_STRESS_EDGE_OPERATIONS: tuple[dict[str, object], ...] = (
    {
        "method": "GET",
        "path": "/api/v1/logs?limit=%2x",
        "json_body": None,
        "family": "logs",
        "scenario": "malformed_percent_escape",
        "expected_statuses": (400,),
    },
    {
        "method": "GET",
        "path": "/api/v1/logs%2x?limit=10",
        "json_body": None,
        "family": "logs",
        "scenario": "malformed_route_escape",
        "expected_statuses": (400,),
    },
	{
		"method": "GET",
		"path": "/api/v1/logs?limit=10&limit=20",
		"json_body": None,
		"family": "logs",
		"scenario": "duplicate_query_parameter",
		"expected_statuses": (400,),
	},
	{
		"method": "get",
		"path": "/api/v1/app",
		"json_body": None,
		"family": "app",
		"scenario": "lowercase_method_rejected",
		"expected_statuses": (400,),
	},
    {
        "method": "GET",
        "path": "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF",
        "json_body": None,
        "family": "transfers",
        "scenario": "uppercase_hash_rejected",
        "expected_statuses": (400,),
    },
    {
        "method": "GET",
        "path": f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/details",
        "json_body": None,
        "family": "transfers",
        "scenario": "missing_transfer_details_rejected",
        "expected_statuses": (404,),
    },
    {
        "method": "POST",
        "path": "/api/v1/transfers",
        "json_body": {
            "link": f"ed2k://|file|rest-stress.bin|1024|{REST_SURFACE_MISSING_HASH}|/",
            "categoryId": 0,
            "categoryName": "Default",
        },
        "family": "transfers",
        "scenario": "conflicting_category_fields",
        "expected_statuses": (400,),
    },
    {
        "method": "POST",
        "path": "/api/v1/searches",
        "json_body": {"query": REST_STRESS_LONG_SEARCH_QUERY, "method": "automatic", "type": ""},
        "family": "searches",
        "scenario": "unicode_query_length_rejected",
        "expected_statuses": (400,),
    },
    {
        "method": "POST",
        "path": "/api/v1/shared-files",
        "json_body": {"path": REST_STRESS_LONG_UNICODE_PATH},
        "family": "shared",
        "scenario": "long_unicode_shared_file_path_rejected",
        "expected_statuses": (400,),
    },
)
REST_STRESS_ADAPTER_OPERATIONS: tuple[dict[str, object], ...] = (
    {
        "method": "GET",
        "path": "/indexer/emulebb/api?t=caps",
        "family": "torznab",
        "scenario": "torznab_caps",
        "expected_statuses": (200,),
        "response_kind": "xml",
        "expected_body_contains": "<caps>",
    },
    {
        "method": "GET",
        "path": "/indexer/emulebb/api?t=caps&t=search",
        "family": "torznab",
        "scenario": "torznab_duplicate_query_rejected",
        "expected_statuses": (400,),
        "response_kind": "xml",
    },
    {
        "method": "GET",
        "path": "/indexer/emulebb/api?t=caps&apikey=wrong-key",
        "family": "torznab",
        "scenario": "torznab_wrong_query_key_rejected",
        "expected_statuses": (401,),
        "response_kind": "xml",
        "api_key": False,
    },
    {
        "method": "GET",
        "path": "/indexer/emulebb/api?t=search&season=abc&q=linux&apikey={api_key}",
        "family": "torznab",
        "scenario": "torznab_search_validation_rejected",
        "expected_statuses": (400,),
        "response_kind": "xml",
        "api_key": False,
    },
    {
        "method": "GET",
        "path": "/indexer/emulebb/api?t=search&cat=abc&q=linux&apikey={api_key}",
        "family": "torznab",
        "scenario": "torznab_bad_category_rejected",
        "expected_statuses": (400,),
        "response_kind": "xml",
        "api_key": False,
    },
    {
        "method": "GET",
        "path": "/api/v2/app/webapiVersion",
        "family": "qbit",
        "scenario": "qbit_public_version",
        "expected_statuses": (200,),
        "response_kind": "text",
        "expected_body_contains": "2.",
        "api_key": False,
    },
    {
        "method": "GET",
        "path": "/api/v2/torrents/categories",
        "family": "qbit",
        "scenario": "qbit_categories",
        "expected_statuses": (200,),
        "response_kind": "json",
        "extra_headers": {"Cookie": "{qbit_session_cookie}"},
        "api_key": False,
    },
    {
        "method": "GET",
        "path": "/api/v2/torrents/categories",
        "family": "qbit",
        "scenario": "qbit_wrong_cookie_rejected",
        "expected_statuses": (403,),
        "response_kind": "text",
        "expected_body_contains": "Forbidden",
        "extra_headers": {"Cookie": "SID=wrong"},
        "api_key": False,
    },
    {
        "method": "POST",
        "path": "/api/v2/auth/login",
        "raw_body": "username=emule&password=wrong-key",
        "content_type": "application/x-www-form-urlencoded",
        "family": "qbit",
        "scenario": "qbit_bad_login_rejected",
        "expected_statuses": (200,),
        "response_kind": "text",
        "expected_body_contains": "Fails.",
        "api_key": False,
    },
    {
        "method": "GET",
        "path": f"/api/v2/torrents/properties?hash={REST_SURFACE_MISSING_HASH}",
        "family": "qbit",
        "scenario": "qbit_missing_hash_read",
        "expected_statuses": (404,),
        "response_kind": "text",
        "extra_headers": {"Cookie": "{qbit_session_cookie}"},
        "api_key": False,
    },
    {
        "method": "POST",
        "path": "/api/v2/torrents/pause",
        "raw_body": f"hashes={REST_SURFACE_MISSING_HASH}",
        "content_type": "application/x-www-form-urlencoded",
        "family": "qbit",
        "scenario": "qbit_missing_hash_mutation",
        "expected_statuses": (200,),
        "response_kind": "text",
        "expected_body_contains": "Ok.",
        "extra_headers": {"Cookie": "{qbit_session_cookie}"},
        "api_key": False,
    },
    {
        "method": "POST",
        "path": "/api/v2/torrents/delete",
        "raw_body": f"hashes={REST_SURFACE_MISSING_HASH}&deleteFiles=false",
        "content_type": "application/x-www-form-urlencoded",
        "family": "qbit",
        "scenario": "qbit_missing_hash_delete",
        "expected_statuses": (200,),
        "response_kind": "text",
        "expected_body_contains": "Ok.",
        "extra_headers": {"Cookie": "{qbit_session_cookie}"},
        "api_key": False,
    },
    {
        "method": "POST",
        "path": "/api/v2/torrents/delete",
        "raw_body": f"hashes={REST_SURFACE_MISSING_HASH}&deleteFiles=wat",
        "content_type": "application/x-www-form-urlencoded",
        "family": "qbit",
        "scenario": "qbit_bad_delete_boolean_rejected",
        "expected_statuses": (400,),
        "response_kind": "text",
        "expected_body_contains": "Fails.",
        "extra_headers": {"Cookie": "{qbit_session_cookie}"},
        "api_key": False,
    },
    {
        "method": "POST",
        "path": "/api/v2/torrents/setForceStart",
        "raw_body": f"hashes={REST_SURFACE_MISSING_HASH}&value=wat",
        "content_type": "application/x-www-form-urlencoded",
        "family": "qbit",
        "scenario": "qbit_bad_force_start_boolean_rejected",
        "expected_statuses": (400,),
        "response_kind": "text",
        "expected_body_contains": "Fails.",
        "extra_headers": {"Cookie": "{qbit_session_cookie}"},
        "api_key": False,
    },
)
REST_STRESS_LEGACY_OPERATIONS: tuple[dict[str, object], ...] = ()
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


def create_https_certificate_pair(artifacts_dir: Path) -> dict[str, str]:
    """Creates a temporary self-signed certificate/key pair for localhost HTTPS tests."""

    cert_dir = artifacts_dir / "https-cert"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "webserver-cert.pem"
    key_path = cert_dir / "webserver-key.pem"
    config_path = cert_dir / "openssl.cnf"
    config_path.write_text(
        "\n".join(
            [
                "[req]",
                "distinguished_name = req_distinguished_name",
                "prompt = no",
                "[req_distinguished_name]",
                "CN = 127.0.0.1",
                "",
            ]
        ),
        encoding="utf-8",
    )
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "1",
        "-config",
        str(config_path),
    ]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {
        "certificate": str(cert_path),
        "key": str(key_path),
    }


def build_urlopen_context(base_url: str):
    """Returns an urllib TLS context for localhost HTTPS smoke requests."""

    if urllib.parse.urlparse(base_url).scheme == "https":
        return ssl._create_unverified_context()
    return None


def configure_webserver_profile(
    config_dir: Path,
    app_exe: Path,
    api_key: str,
    port: int,
    bind_addr: str,
    *,
    use_https: bool = False,
    https_certificate: str = "",
    https_key: str = "",
    enable_crash_test_endpoint: bool = False,
) -> None:
    """Enables the WebServer listener and REST API key inside the temp profile."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("ConfirmExit", "0"),
            ("Autoconnect", "1"),
            ("Reconnect", "1"),
            ("NetworkED2K", "1"),
            ("NetworkKademlia", "1"),
            ("Verbose", "1"),
            ("FullVerbose", "1"),
        ),
    )
    live_common.apply_webserver_profile(
        config_dir,
        WebServerProfileSpec(
            app_exe=app_exe,
            api_key=api_key,
            port=port,
            bind_addr=bind_addr,
            use_gzip=True,
            allow_admin_high_level_func=True,
            use_https=use_https,
            https_certificate=https_certificate,
            https_key=https_key,
            enable_crash_test_endpoint=enable_crash_test_endpoint,
        ),
    )
    live_common.apply_live_network_policy(config_dir)


def apply_p2p_bind_interface_override(
    config_dir: Path,
    interface_name: str,
) -> None:
    """Writes the requested P2P bind interface name into the isolated profile."""

    live_common.apply_live_network_policy(config_dir, p2p_bind_interface_name=interface_name)


def http_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    api_key: str | None = None,
    json_body=None,
    raw_body: bytes | str | None = None,
    content_type: str | None = None,
    extra_headers: dict[str, str] | None = None,
    request_timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Performs one HTTP request and returns a compact structured result."""

    data = None
    headers: dict[str, str] = {}
    if api_key is not None:
        headers["X-API-Key"] = api_key
    if extra_headers:
        headers.update(extra_headers)
    if json_body is not None and raw_body is not None:
        raise ValueError("json_body and raw_body are mutually exclusive")
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = content_type or "application/json; charset=utf-8"
    elif raw_body is not None:
        data = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
        if content_type is not None:
            headers["Content-Type"] = content_type

    request = urllib.request.Request(base_url + path, data=data, method=method, headers=headers)
    urlopen_kwargs = {"timeout": request_timeout_seconds}
    context = build_urlopen_context(base_url)
    if context is not None:
        urlopen_kwargs["context"] = context
    try:
        with urllib.request.urlopen(request, **urlopen_kwargs) as response:
            body_bytes = response.read()
            body_text = body_bytes.decode("utf-8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            payload = None
            if "application/json" in content_type:
                payload = json.loads(body_text)
            return {
                "status": int(response.status),
                "content_type": content_type,
                "headers": dict(response.headers.items()),
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
            "headers": dict(exc.headers.items()),
            "body_text": body_text,
            "json": unwrap_rest_payload(payload),
            "raw_json": payload,
        }


def parse_base_url_endpoint(base_url: str) -> dict[str, object]:
    """Parses a REST base URL into socket connection details."""

    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported REST base URL scheme for socket probes: {parsed.scheme!r}")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": int(port),
    }


def read_raw_http_status(sock: socket.socket, timeout_seconds: float) -> dict[str, object]:
    """Reads one raw HTTP status line, returning a closed/timeout outcome when no status arrives."""

    sock.settimeout(timeout_seconds)
    data = b""
    try:
        while b"\r\n" not in data and len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                return {"outcome": "closed", "status": None, "status_line": ""}
            data += chunk
    except socket.timeout:
        return {"outcome": "timeout", "status": None, "status_line": ""}
    except OSError as exc:
        return {"outcome": "socket_error", "status": None, "error": str(exc), "status_line": ""}

    status_line = data.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    status = None
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return {"outcome": "response", "status": status, "status_line": status_line}


def raw_socket_probe(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout_seconds: float,
    read_response: bool,
    reset_on_close: bool,
) -> dict[str, object]:
    """Sends one raw TCP probe and returns the observed response or close behavior."""

    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        sock.sendall(payload)
        if reset_on_close:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0))
        if not read_response:
            return {
                "outcome": "sent_reset" if reset_on_close else "sent_closed",
                "status": None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            }
        result = read_raw_http_status(sock, timeout_seconds)
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        return result


def raw_socket_chunk_probe(
    host: str,
    port: int,
    chunks: list[bytes],
    *,
    chunk_delay_seconds: float,
    timeout_seconds: float,
    reset_on_close: bool,
) -> dict[str, object]:
    """Sends delayed raw TCP chunks and closes without waiting for HTTP response bytes."""

    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            for chunk in chunks:
                if chunk:
                    sock.sendall(chunk)
                if chunk_delay_seconds > 0:
                    time.sleep(chunk_delay_seconds)
            if reset_on_close:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0))
            return {
                "outcome": "sent_reset" if reset_on_close else "sent_closed",
                "status": None,
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            }
    except socket.timeout:
        return {
            "outcome": "timeout",
            "status": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }
    except OSError as exc:
        return {
            "outcome": "socket_error",
            "status": None,
            "error": str(exc),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }


def require_socket_probe_outcome(
    scenario: str,
    result: dict[str, object],
    *,
    allowed_statuses: set[int],
    allow_close: bool = True,
) -> None:
    """Validates one socket-adversity probe outcome."""

    status = result.get("status")
    outcome = result.get("outcome")
    if isinstance(status, int) and status in allowed_statuses:
        return
    if allow_close and outcome in {"closed", "socket_error", "sent_reset", "sent_closed"}:
        return
    raise AssertionError(f"Unexpected socket adversity outcome for {scenario}: {result!r}")


def exercise_rest_socket_adversity(
    base_url: str,
    api_key: str,
    *,
    budget: str,
    request_timeout_seconds: float,
) -> dict[str, object]:
    """Runs raw socket probes for malformed and reset-prone REST/WebServer paths."""

    if budget not in REST_SOCKET_ADVERSITY_BUDGETS:
        raise ValueError(f"Unsupported REST socket adversity budget: {budget}")
    if budget == "off":
        return {"budget": budget, "probes": [], "probe_count": 0}

    endpoint = parse_base_url_endpoint(base_url)
    if endpoint["scheme"] != "http":
        raise RuntimeError("Raw socket adversity smoke currently requires an HTTP base URL.")

    host = str(endpoint["host"])
    port = int(endpoint["port"])
    quoted_host = host.encode("ascii", errors="ignore") or b"127.0.0.1"
    api_key_bytes = api_key.encode("ascii", errors="ignore")
    probes = [
        {
            "scenario": "partial_header_reset",
            "payload": b"GET /api/v1/app HTTP/1.1\r\nHost: " + quoted_host + b"\r\nX-API-Key: " + api_key_bytes + b"\r\n",
            "read_response": False,
            "reset_on_close": True,
            "allowed_statuses": set(),
        },
        {
            "scenario": "declared_body_reset",
            "payload": (
                b"POST /api/v1/transfers HTTP/1.1\r\nHost: "
                + quoted_host
                + b"\r\nX-API-Key: "
                + api_key_bytes
                + b"\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n{\"ed2kLinks\":["
            ),
            "read_response": False,
            "reset_on_close": True,
            "allowed_statuses": set(),
        },
        {
            "scenario": "conflicting_content_length",
            "payload": (
                b"POST /api/v1/transfers HTTP/1.1\r\nHost: "
                + quoted_host
                + b"\r\nX-API-Key: "
                + api_key_bytes
                + b"\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\n{}"
            ),
            "read_response": True,
            "reset_on_close": False,
            "allowed_statuses": {400, 408, 413, 500},
        },
        {
            "scenario": "overlong_header",
            "payload": (
                b"GET /api/v1/app HTTP/1.1\r\nHost: "
                + quoted_host
                + b"\r\nX-API-Key: "
                + api_key_bytes
                + b"\r\nX-Fill: "
                + (b"a" * 70000)
                + b"\r\n\r\n"
            ),
            "read_response": True,
            "reset_on_close": False,
            "allowed_statuses": {400, 408, 413, 431, 500},
        },
        {
            "scenario": "reset_during_response_send",
            "payload": (
                b"GET /api/v1/logs?limit=400 HTTP/1.1\r\nHost: "
                + quoted_host
                + b"\r\nX-API-Key: "
                + api_key_bytes
                + b"\r\nConnection: close\r\n\r\n"
            ),
            "read_response": False,
            "reset_on_close": True,
            "allowed_statuses": set(),
        },
        {
            "scenario": "reset_during_error_response_send",
            "payload": (
                b"GET /api/v1/r1-missing-error-reset HTTP/1.1\r\nHost: "
                + quoted_host
                + b"\r\nX-API-Key: "
                + api_key_bytes
                + b"\r\nConnection: close\r\n\r\n"
            ),
            "read_response": False,
            "reset_on_close": True,
            "allowed_statuses": set(),
        },
    ]

    rows = []
    for probe in probes:
        result = raw_socket_probe(
            host,
            port,
            probe["payload"],
            timeout_seconds=request_timeout_seconds,
            read_response=bool(probe["read_response"]),
            reset_on_close=bool(probe["reset_on_close"]),
        )
        require_socket_probe_outcome(
            str(probe["scenario"]),
            result,
            allowed_statuses=set(probe["allowed_statuses"]),
        )
        rows.append(
            {
                "scenario": probe["scenario"],
                "outcome": result.get("outcome"),
                "status": result.get("status"),
                "status_line": result.get("status_line", ""),
                "elapsed_ms": result.get("elapsed_ms"),
            }
        )

    invalid_utf8_json = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        raw_body=b"\xff\xfe\xfd",
        content_type="application/json",
        request_timeout_seconds=request_timeout_seconds,
    )
    if int(invalid_utf8_json["status"]) not in {400, 500}:
        raise AssertionError(f"Unexpected invalid UTF-8 JSON status: {compact_http_result(invalid_utf8_json)}")
    rows.append(
        {
            "scenario": "invalid_utf8_json",
            "outcome": "response",
            "status": int(invalid_utf8_json["status"]),
            "content_type": invalid_utf8_json.get("content_type", ""),
        }
    )

    return {
        "budget": budget,
        "scheme": endpoint["scheme"],
        "host": host,
        "port": port,
        "probe_count": len(rows),
        "probes": rows,
    }


def exercise_rest_tls_handshake_adversity(
    base_url: str,
    *,
    budget: str,
    request_timeout_seconds: float,
) -> dict[str, object]:
    """Runs HTTPS-only raw TCP probes for stalled and partial TLS handshakes."""

    if budget not in REST_TLS_HANDSHAKE_ADVERSITY_BUDGETS:
        raise ValueError(f"Unsupported REST TLS handshake adversity budget: {budget}")
    if budget == "off":
        return {"budget": budget, "probes": [], "probe_count": 0}

    endpoint = parse_base_url_endpoint(base_url)
    if endpoint["scheme"] != "https":
        raise RuntimeError("REST TLS handshake adversity requires an HTTPS base URL.")

    host = str(endpoint["host"])
    port = int(endpoint["port"])
    delay_seconds = min(max(request_timeout_seconds / 20.0, 0.05), 0.25)
    probes = [
        {
            "scenario": "stalled_tls_connect_close",
            "chunks": [b""],
            "reset_on_close": False,
        },
        {
            "scenario": "partial_tls_record_reset",
            "chunks": [b"\x16\x03", b"\x01\x02", b"\x00"],
            "reset_on_close": True,
        },
        {
            "scenario": "partial_tls_clienthello_reset",
            "chunks": [b"\x16\x03\x01\x02\x00", b"\x01\x00", b"\x01"],
            "reset_on_close": True,
        },
    ]

    rows = []
    for probe in probes:
        result = raw_socket_chunk_probe(
            host,
            port,
            list(probe["chunks"]),
            chunk_delay_seconds=delay_seconds,
            timeout_seconds=request_timeout_seconds,
            reset_on_close=bool(probe["reset_on_close"]),
        )
        require_socket_probe_outcome(
            str(probe["scenario"]),
            result,
            allowed_statuses=set(),
        )
        rows.append(
            {
                "scenario": probe["scenario"],
                "outcome": result.get("outcome"),
                "status": result.get("status"),
                "elapsed_ms": result.get("elapsed_ms"),
            }
        )

    return {
        "budget": budget,
        "scheme": endpoint["scheme"],
        "host": host,
        "port": port,
        "chunk_delay_seconds": delay_seconds,
        "probe_count": len(rows),
        "probes": rows,
    }


def max_resource_snapshot(
    current: dict[str, int | None] | None,
    candidate: dict[str, int | None],
) -> dict[str, int | None]:
    """Returns the element-wise maximum for numeric resource snapshot values."""

    if current is None:
        return dict(candidate)
    result = dict(current)
    for key, candidate_value in candidate.items():
        if candidate_value is None:
            continue
        current_value = result.get(key)
        if current_value is None or int(candidate_value) > int(current_value):
            result[key] = int(candidate_value)
    return result


def evaluate_rest_leak_churn_resources(
    before_to_after_drain: dict[str, int | None],
    before_to_peak: dict[str, int | None],
) -> dict[str, object]:
    """Evaluates leak-churn resource deltas against the R1 release thresholds."""

    violations = []
    for metric, limits in REST_LEAK_CHURN_RESOURCE_THRESHOLDS.items():
        after_value = before_to_after_drain.get(metric)
        after_limit = int(limits["after_drain_max"])
        if after_value is not None and int(after_value) > after_limit:
            violations.append(
                {
                    "metric": metric,
                    "phase": "after_drain",
                    "value": int(after_value),
                    "limit": after_limit,
                }
            )

        peak_value = before_to_peak.get(metric)
        peak_limit = int(limits["peak_max"])
        if peak_value is not None and int(peak_value) > peak_limit:
            violations.append(
                {
                    "metric": metric,
                    "phase": "peak",
                    "value": int(peak_value),
                    "limit": peak_limit,
                }
            )

    return {
        "ok": not violations,
        "thresholds": REST_LEAK_CHURN_RESOURCE_THRESHOLDS,
        "violations": violations,
    }


def evaluate_rest_leak_churn_resource_observability(
    snapshots: tuple[dict[str, int | None], ...],
) -> dict[str, object]:
    """Requires enabled leak churn to capture each tracked resource metric."""

    metrics = tuple(REST_LEAK_CHURN_RESOURCE_THRESHOLDS.keys())
    available_metrics = [
        metric
        for metric in metrics
        if any(snapshot.get(metric) is not None for snapshot in snapshots)
    ]
    missing_metrics = [metric for metric in metrics if metric not in available_metrics]
    return {
        "ok": not missing_metrics,
        "required_metrics": list(metrics),
        "available_metrics": available_metrics,
        "missing_metrics": missing_metrics,
    }


def exercise_rest_leak_churn(
    base_url: str,
    api_key: str,
    *,
    process_id: int | None,
    budget: str,
    cycles: int | None,
    request_timeout_seconds: float,
) -> dict[str, object]:
    """Runs repeated HTTP or HTTPS connect/reset cycles and reports resource snapshots."""

    if budget not in REST_LEAK_CHURN_BUDGETS:
        raise ValueError(f"Unsupported REST leak churn budget: {budget}")
    if cycles is None:
        cycles = REST_LEAK_CHURN_DEFAULT_CYCLES[budget]
    if cycles < 0:
        raise ValueError("REST leak churn cycles must be zero or greater.")
    if budget == "off" or cycles == 0:
        return {"budget": budget, "cycles_requested": cycles, "cycles_completed": 0, "snapshots": {}}

    endpoint = parse_base_url_endpoint(base_url)
    host = str(endpoint["host"])
    port = int(endpoint["port"])
    quoted_host = host.encode("ascii", errors="ignore") or b"127.0.0.1"
    api_key_bytes = api_key.encode("ascii", errors="ignore")
    http_payloads = (
        {
            "scenario": "partial_header_reset",
            "payload": b"GET /api/v1/app HTTP/1.1\r\nHost: "
            + quoted_host
            + b"\r\nX-API-Key: "
            + api_key_bytes
            + b"\r\n",
        },
        {
            "scenario": "response_send_reset",
            "payload": b"GET /api/v1/logs?limit=400 HTTP/1.1\r\nHost: "
            + quoted_host
            + b"\r\nX-API-Key: "
            + api_key_bytes
            + b"\r\nConnection: close\r\n\r\n",
        },
        {
            "scenario": "declared_body_reset",
            "payload": b"POST /api/v1/transfers HTTP/1.1\r\nHost: "
            + quoted_host
            + b"\r\nX-API-Key: "
            + api_key_bytes
            + b"\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n{\"ed2kLinks\":[",
        },
    )
    tls_chunk_sets = (
        {
            "scenario": "stalled_tls_connect_close",
            "chunks": [b""],
            "reset_on_close": False,
        },
        {
            "scenario": "partial_tls_record_reset",
            "chunks": [b"\x16\x03", b"\x01\x02", b"\x00"],
            "reset_on_close": True,
        },
        {
            "scenario": "partial_tls_clienthello_reset",
            "chunks": [b"\x16\x03\x01\x02\x00", b"\x01\x00", b"\x01"],
            "reset_on_close": True,
        },
    )

    before = get_process_resource_snapshot(process_id)
    peak = dict(before)
    rows: list[dict[str, object]] = []
    started = time.perf_counter()
    sample_every = max(1, cycles // 10)

    for cycle_index in range(cycles):
        if endpoint["scheme"] == "https":
            scenario = tls_chunk_sets[cycle_index % len(tls_chunk_sets)]
            result = raw_socket_chunk_probe(
                host,
                port,
                list(scenario["chunks"]),
                chunk_delay_seconds=0.0,
                timeout_seconds=request_timeout_seconds,
                reset_on_close=bool(scenario["reset_on_close"]),
            )
        else:
            scenario = http_payloads[cycle_index % len(http_payloads)]
            result = raw_socket_probe(
                host,
                port,
                bytes(scenario["payload"]),
                timeout_seconds=request_timeout_seconds,
                read_response=False,
                reset_on_close=True,
            )
        require_socket_probe_outcome(
            f"leak_churn_cycle_{cycle_index}",
            result,
            allowed_statuses=set(),
        )
        if cycle_index < 10 or (cycle_index + 1) % sample_every == 0:
            rows.append(
                {
                    "cycle": cycle_index + 1,
                    "scenario": scenario["scenario"],
                    "outcome": result.get("outcome"),
                    "elapsed_ms": result.get("elapsed_ms"),
                }
            )
        if (cycle_index + 1) % sample_every == 0:
            peak = max_resource_snapshot(peak, get_process_resource_snapshot(process_id))

    time.sleep(0.5)
    after = get_process_resource_snapshot(process_id)
    peak = max_resource_snapshot(peak, after)
    before_to_after_drain = diff_process_resource_snapshots(before, after)
    before_to_peak = diff_process_resource_snapshots(before, peak)
    resource_observability = evaluate_rest_leak_churn_resource_observability((before, peak, after))
    if not resource_observability["ok"]:
        raise AssertionError(f"REST leak churn resource snapshots incomplete: {resource_observability!r}")
    resource_thresholds = evaluate_rest_leak_churn_resources(before_to_after_drain, before_to_peak)
    if not resource_thresholds["ok"]:
        raise AssertionError(f"REST leak churn resource thresholds exceeded: {resource_thresholds!r}")
    return {
        "budget": budget,
        "scheme": endpoint["scheme"],
        "host": host,
        "port": port,
        "cycles_requested": cycles,
        "cycles_completed": cycles,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "sampled_cycles": rows,
        "snapshots": {
            "before": before,
            "peak": peak,
            "after_drain": after,
        },
        "deltas": {
            "before_to_after_drain": before_to_after_drain,
            "before_to_peak": before_to_peak,
        },
        "resource_observability": resource_observability,
        "resource_thresholds": resource_thresholds,
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
    if 200 <= expected_status < 300:
        require_success_envelope(result)
    assert isinstance(result["json"], dict)
    return result["json"]


def require_json_array(result: dict[str, object], expected_status: int) -> list[Any]:
    """Asserts one REST response is the expected JSON array payload."""

    assert int(result["status"]) == expected_status, compact_http_result(result)
    if 200 <= expected_status < 300:
        require_success_envelope(result)
    payload = result["json"]
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return list(payload["items"])
    assert isinstance(payload, list), compact_http_result(result)
    return list(payload)


def require_success_envelope(result: dict[str, object]) -> dict[str, Any]:
    """Asserts one successful REST response uses the strict `{data, meta}` envelope."""

    raw = result.get("raw_json")
    assert isinstance(raw, dict), compact_http_result(result)
    assert "data" in raw and "meta" in raw, compact_http_result(result)
    assert isinstance(raw["meta"], dict), compact_http_result(result)
    assert raw["meta"].get("apiVersion") == "v1", compact_http_result(result)
    return raw


def require_error_response(
    result: dict[str, object],
    expected_status: int,
    expected_code: str,
    *,
    message_contains: str | None = None,
) -> dict[str, Any]:
    """Asserts one REST error response carries the stable JSON error envelope."""

    content_type = str(result.get("content_type") or "").lower()
    body_text = str(result.get("body_text") or "")
    assert "application/json" in content_type, compact_http_result(result)
    assert "text/html" not in content_type, compact_http_result(result)
    assert "<html" not in body_text.lower(), compact_http_result(result)
    payload = require_json_object(result, expected_status)
    assert payload.get("error") == expected_code, compact_http_result(result)
    raw = result.get("raw_json")
    assert isinstance(raw, dict), compact_http_result(result)
    error = raw.get("error")
    assert isinstance(error, dict), compact_http_result(result)
    assert error.get("code") == expected_code, compact_http_result(result)
    assert isinstance(error.get("details"), dict), compact_http_result(result)
    message = payload.get("message")
    assert isinstance(message, str), compact_http_result(result)
    if message_contains is not None:
        assert message_contains in message, compact_http_result(result)
    return payload


def is_native_rest_json_response(result: dict[str, object]) -> bool:
    """Returns whether one native REST response stayed on the JSON envelope path."""

    content_type = str(result.get("content_type") or "").lower()
    body_text = str(result.get("body_text") or "").lower()
    return "application/json" in content_type and "text/html" not in content_type and "<html" not in body_text


def response_matches_kind(result: dict[str, object], response_kind: str) -> bool:
    """Returns whether one stress response matches its expected adapter shape."""

    content_type = str(result.get("content_type") or "").lower()
    if response_kind == "native-json":
        return is_native_rest_json_response(result)
    if response_kind == "json":
        return "application/json" in content_type
    if response_kind == "xml":
        return "application/xml" in content_type
    if response_kind == "text":
        return "application/json" not in content_type and "text/html" not in content_type
    return True


def classify_rest_stress_response_error(
    *,
    expected_match: bool,
    response_kind_match: bool,
    body_match: bool,
    native_rest_json: bool,
) -> str | None:
    """Returns a compact failure reason for one REST stress response."""

    if not expected_match:
        return "status mismatch"
    if not response_kind_match:
        return "response kind mismatch"
    if not body_match:
        return "response body mismatch"
    if not native_rest_json:
        return "native REST JSON mismatch"
    return None


def require_missing_transfer_bulk_result(result: dict[str, object]) -> dict[str, object]:
    """Asserts one bulk transfer mutation reports a per-item missing-transfer result."""

    payload = require_json_object(result, 200)
    rows = payload.get("items") or payload.get("results")
    assert isinstance(rows, list) and rows, compact_http_result(result)
    first = rows[0]
    assert isinstance(first, dict), compact_http_result(result)
    assert first.get("ok") is False, compact_http_result(result)
    assert str(first.get("hash") or "").lower() == REST_SURFACE_MISSING_HASH
    assert "transfer not found" in str(first.get("error") or "")
    return first


def iter_http_status_entries(value: object, path: tuple[str, ...] = ()):
    """Yields compact HTTP result dictionaries found inside nested report data."""

    if isinstance(value, dict):
        status = value.get("status")
        if isinstance(status, int):
            yield {
                "path": ".".join(path) if path else "<root>",
                "status": status,
                "content_type": value.get("content_type", ""),
                "error": value.get("error"),
                "message": value.get("message"),
            }
        for key, child in value.items():
            if key in {"headers", "body_text", "json", "raw_json"}:
                continue
            yield from iter_http_status_entries(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_http_status_entries(child, path + (str(index),))


def build_rest_error_path_matrix(checks: dict[str, object]) -> dict[str, object]:
    """Builds the release error-path coverage matrix from live REST check artifacts."""

    error_rows = [
        row
        for row in iter_http_status_entries(checks)
        if isinstance(row.get("status"), int) and int(row["status"]) >= 400
    ]
    by_status: dict[str, int] = {}
    for row in error_rows:
        key = str(row["status"])
        by_status[key] = by_status.get(key, 0) + 1
    release_status_rows = [
        {
            "status": status,
            "covered": by_status.get(str(status), 0) > 0 or status in REST_ERROR_MATRIX_SEAM_BACKED_ROWS,
            "coverage_source": (
                "live"
                if by_status.get(str(status), 0) > 0
                else "seam-backed"
                if status in REST_ERROR_MATRIX_SEAM_BACKED_ROWS
                else "missing"
            ),
            "live_count": by_status.get(str(status), 0),
            "seam": REST_ERROR_MATRIX_SEAM_BACKED_ROWS.get(status),
        }
        for status in REST_ERROR_MATRIX_RELEASE_STATUSES
    ]
    missing_release_statuses = [row["status"] for row in release_status_rows if not row["covered"]]
    return {
        "ok": not missing_release_statuses,
        "release_statuses": release_status_rows,
        "covered_release_statuses": [row["status"] for row in release_status_rows if row["covered"]],
        "missing_release_statuses": missing_release_statuses,
        "live_missing_release_statuses": [row["status"] for row in release_status_rows if row["live_count"] == 0],
        "seam_backed_release_statuses": [
            row["status"] for row in release_status_rows if row["coverage_source"] == "seam-backed"
        ],
        "error_response_count": len(error_rows),
        "status_counts": by_status,
        "sample_errors": error_rows[:40],
    }


def require_rest_error_path_matrix(matrix: dict[str, object]) -> None:
    """Fails the run when the R1 REST/WebServer error-path matrix has release gaps."""

    if not matrix.get("ok"):
        raise AssertionError(f"REST error-path release coverage gaps: {matrix.get('missing_release_statuses')!r}")


def compact_transfer_details_payload(payload: dict[str, Any], expected_hash: str) -> dict[str, object]:
    """Asserts and compacts one transfer-detail REST payload for smoke artifacts."""

    transfer = payload.get("transfer")
    parts = payload.get("parts")
    sources = payload.get("sources")
    assert isinstance(transfer, dict)
    assert transfer.get("hash") == expected_hash
    assert isinstance(parts, list) and parts
    assert isinstance(sources, list)
    first_part = parts[0]
    assert isinstance(first_part, dict)
    assert isinstance(first_part.get("index"), int)
    assert isinstance(first_part.get("start"), int)
    assert isinstance(first_part.get("end"), int)
    assert isinstance(first_part.get("completedBytes"), int)
    assert isinstance(first_part.get("gapBytes"), int)
    assert isinstance(first_part.get("complete"), bool)
    assert isinstance(first_part.get("requested"), bool)
    assert isinstance(first_part.get("corrupted"), bool)
    assert isinstance(first_part.get("availableSources"), int)
    return {
        "hash": transfer.get("hash"),
        "part_count": len(parts),
        "source_count": len(sources),
        "first_part": {
            "index": first_part.get("index"),
            "start": first_part.get("start"),
            "end": first_part.get("end"),
            "completedBytes": first_part.get("completedBytes"),
            "gapBytes": first_part.get("gapBytes"),
            "complete": first_part.get("complete"),
            "requested": first_part.get("requested"),
            "corrupted": first_part.get("corrupted"),
            "availableSources": first_part.get("availableSources"),
        },
    }


def require_transfer_bulk_result(result: dict[str, object], expected_hash: str, expected_ok: bool) -> dict[str, object]:
    """Asserts one bulk transfer mutation reports the expected per-item outcome."""

    payload = require_json_object(result, 200)
    rows = payload.get("items") or payload.get("results")
    assert isinstance(rows, list) and rows, compact_http_result(result)
    first = rows[0]
    assert isinstance(first, dict), compact_http_result(result)
    assert first.get("ok") is expected_ok, compact_http_result(result)
    assert str(first.get("hash") or "").lower() == expected_hash
    return first


def require_transfer_add_result(result: dict[str, object], expected_hash: str) -> dict[str, object]:
    """Asserts one transfer add response reports the newly queued transfer item."""

    payload = require_json_object(result, 200)
    rows = payload.get("items") or payload.get("results")
    assert isinstance(rows, list) and rows, compact_http_result(result)
    first = rows[0]
    assert isinstance(first, dict), compact_http_result(result)
    assert first.get("ok") is True, compact_http_result(result)
    assert str(first.get("hash") or "").lower() == expected_hash
    return first


def require_transfer_operation_result(result: dict[str, object], expected_hash: str) -> dict[str, object]:
    """Asserts one successful single-transfer operation reports a bulk item outcome."""

    item = require_transfer_bulk_result(result, expected_hash, True)
    return {
        "hash": item.get("hash"),
        "ok": item.get("ok"),
        "state": item.get("state"),
        "stopped": item.get("stopped"),
    }


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


def get_process_resource_snapshot(process_id: int | None) -> dict[str, int | None]:
    """Returns a best-effort resource snapshot for the launched eMule process."""

    if process_id is None:
        return {
            "process_id": None,
            "handles": None,
            "thread_count": None,
            "gdi_objects": None,
            "user_objects": None,
            "private_bytes": None,
            "working_set_bytes": None,
        }

    process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, process_id)
    if not process_handle:
        return {
            "process_id": process_id,
            "handles": None,
            "thread_count": None,
            "gdi_objects": None,
            "user_objects": None,
            "private_bytes": None,
            "working_set_bytes": None,
        }
    try:
        handle_count = ctypes.c_uint32()
        handles = None
        if kernel32.GetProcessHandleCount(process_handle, ctypes.byref(handle_count)):
            handles = int(handle_count.value)
        thread_count = get_process_thread_count(process_id)

        memory = PROCESS_MEMORY_COUNTERS_EX()
        memory.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
        private_bytes = None
        working_set = None
        if psapi.GetProcessMemoryInfo(process_handle, ctypes.byref(memory), memory.cb):
            private_bytes = int(memory.PrivateUsage)
            working_set = int(memory.WorkingSetSize)

        return {
            "process_id": process_id,
            "handles": handles,
            "thread_count": thread_count,
            "gdi_objects": int(user32.GetGuiResources(process_handle, GR_GDIOBJECTS)),
            "user_objects": int(user32.GetGuiResources(process_handle, GR_USEROBJECTS)),
            "private_bytes": private_bytes,
            "working_set_bytes": working_set,
        }
    finally:
        kernel32.CloseHandle(process_handle)


def get_process_exit_state(process_id: int | None) -> dict[str, object]:
    """Returns whether a Windows process id is still active and its exit code when available."""

    state: dict[str, object] = {
        "process_id": process_id,
        "open_process_ok": False,
        "running": None,
        "exit_code": None,
        "last_error": None,
    }
    if process_id is None:
        return state
    process_handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
    if not process_handle:
        state["last_error"] = ctypes.get_last_error()
        state["running"] = False
        return state
    try:
        state["open_process_ok"] = True
        exit_code = ctypes.c_uint32()
        if kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
            state["exit_code"] = int(exit_code.value)
            state["running"] = int(exit_code.value) == STILL_ACTIVE
        else:
            state["last_error"] = ctypes.get_last_error()
    finally:
        kernel32.CloseHandle(process_handle)
    return state


def get_process_thread_count(process_id: int | None) -> int | None:
    """Counts live threads owned by one process through Toolhelp snapshots."""

    if process_id is None:
        return None
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot in (None, INVALID_HANDLE_VALUE):
        return None
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            return None
        count = 0
        while True:
            if int(entry.th32OwnerProcessID) == int(process_id):
                count += 1
            entry.dwSize = ctypes.sizeof(THREADENTRY32)
            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                break
        return count
    finally:
        kernel32.CloseHandle(snapshot)


def diff_process_resource_snapshots(
    before: dict[str, int | None],
    after: dict[str, int | None],
) -> dict[str, int | None]:
    """Computes deltas between two process resource snapshots."""

    deltas: dict[str, int | None] = {}
    for key, before_value in before.items():
        if key == "process_id":
            continue
        after_value = after.get(key)
        deltas[key] = None if before_value is None or after_value is None else int(after_value) - int(before_value)
    return deltas


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
    budget: str,
    duration_seconds: float,
    concurrency: int,
    max_failures: int,
    request_timeout_seconds: float,
) -> None:
    """Validates REST stress knobs before the live app is launched."""

    if budget not in REST_STRESS_BUDGETS:
        raise ValueError(f"Unsupported REST stress budget: {budget}")
    if duration_seconds <= 0:
        raise ValueError("REST stress duration must be greater than zero.")
    if concurrency <= 0:
        raise ValueError("REST stress concurrency must be greater than zero.")
    if max_failures < 0:
        raise ValueError("REST stress max failures must be zero or greater.")
    if request_timeout_seconds <= 0:
        raise ValueError("REST stress request timeout must be greater than zero.")


def build_rest_stress_operations(budget: str) -> list[dict[str, object]]:
    """Builds the REST operation mix used by one bounded stress budget."""

    operations = [
        {
            "method": "GET",
            "path": path,
            "json_body": None,
            "family": path.split("/")[3].split("?")[0] if len(path.split("/")) > 3 else "root",
            "scenario": "read",
            "expected_statuses": (200,),
        }
        for path in REST_STRESS_READ_PATHS
    ]
    if budget in {"smoke", "soak"}:
        operations.extend(dict(operation) for operation in REST_STRESS_SAFE_MUTATION_OPERATIONS)
        operations.extend(dict(operation) for operation in REST_STRESS_EDGE_OPERATIONS)
        operations.extend(dict(operation) for operation in REST_STRESS_ADAPTER_OPERATIONS)
    return operations


def assert_shutdown_excluded_from_broad_mutation_loops() -> dict[str, object]:
    """Asserts app-level unsafe diagnostics are excluded from broad mutation loops."""

    stress_budgets: dict[str, object] = {}
    for budget in REST_STRESS_BUDGETS:
        if budget == "off":
            continue
        operations = build_rest_stress_operations(budget)
        matches = [
            {
                "method": operation.get("method"),
                "path": operation.get("path"),
                "scenario": operation.get("scenario"),
            }
            for operation in operations
            if operation.get("path") in UNSAFE_BROAD_MUTATION_PATHS
        ]
        if matches:
            raise AssertionError(f"Unsafe app-level route present in {budget!r} stress operations: {matches!r}")
        stress_budgets[budget] = {
            "operation_count": len(operations),
            "unsafe_path_match_count": 0,
        }

    unsafe_app_routes = [
        {
            "name": route["name"],
            "operationId": route["operationId"],
            "path": route["path"],
            "safe": route["safe"],
            "safety": route["safety"],
        }
        for route in REST_CONTRACT_ROUTES
        if route["operationId"] == "shutdownApp" or route["path"] in UNSAFE_BROAD_MUTATION_PATHS
    ]
    if not any(route["operationId"] == "shutdownApp" for route in unsafe_app_routes):
        raise AssertionError("OpenAPI-derived REST contract routes do not include shutdownApp.")
    unsafe_routes = [route for route in unsafe_app_routes if route["safe"] is False and route["safety"] == "unsafe"]
    if len(unsafe_routes) != len(unsafe_app_routes):
        raise AssertionError(f"Unsafe app-level routes are not all marked unsafe: {unsafe_app_routes!r}")

    return {
        "ok": True,
        "excluded_paths": list(UNSAFE_BROAD_MUTATION_PATHS),
        "stress_budgets": stress_budgets,
        "contract_routes": unsafe_app_routes,
    }


def percentile(values: list[float], percentile_value: float) -> float:
    """Returns a nearest-rank percentile from an already collected sample."""

    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile_value / 100.0) * (len(ordered) - 1))))
    return round(ordered[index], 3)


def is_retryable_rest_stress_exception(exc: Exception) -> bool:
    """Reports whether a stress request failed with a transient TLS/TCP reset."""

    message = str(exc).lower()
    return any(fragment in message for fragment in REST_STRESS_RETRYABLE_ERROR_FRAGMENTS)


def build_rest_stress_operation_key(method: object, path: object, scenario: object) -> str:
    """Builds a stable operation identity for stress scheduler coverage accounting."""

    return f"{method or 'UNKNOWN'} {path or ''} [{scenario or 'unknown'}]"


def rest_stress_operation_key(operation: dict[str, object]) -> str:
    """Returns the stable coverage key for one configured REST stress operation."""

    return build_rest_stress_operation_key(
        operation.get("method"),
        operation.get("path"),
        operation.get("scenario"),
    )


def rest_stress_row_operation_key(row: dict[str, object]) -> str:
    """Returns the stable coverage key recorded by one completed REST stress request."""

    operation_key = row.get("operation_key")
    if operation_key:
        return str(operation_key)
    return build_rest_stress_operation_key(row.get("method"), row.get("path"), row.get("scenario"))


def summarize_rest_stress_operation_coverage(
    rows: list[dict[str, object]],
    operations: list[dict[str, object]],
) -> dict[str, object]:
    """Summarizes scheduler coverage for a bounded REST stress pass."""

    expected_keys = [rest_stress_operation_key(operation) for operation in operations]
    observed_counts: dict[str, int] = {}
    for row in rows:
        operation_key = rest_stress_row_operation_key(row)
        observed_counts[operation_key] = observed_counts.get(operation_key, 0) + 1

    expected_set = set(expected_keys)
    observed_expected_keys = [key for key in observed_counts if key in expected_set]
    missed_keys = [key for key in expected_keys if observed_counts.get(key, 0) == 0]
    per_operation_counts = [observed_counts.get(key, 0) for key in expected_keys]
    reached_full_cycle = len(rows) >= len(expected_keys)
    coverage_ok = not reached_full_cycle or not missed_keys
    return {
        "expected_operation_count": len(expected_keys),
        "observed_operation_count": len(observed_expected_keys),
        "missed_operation_count": len(missed_keys),
        "missed_operations_sample": missed_keys[:10],
        "unexpected_operation_count": len([key for key in observed_counts if key not in expected_set]),
        "min_observed_per_operation": min(per_operation_counts) if per_operation_counts else 0,
        "max_observed_per_operation": max(per_operation_counts) if per_operation_counts else 0,
        "full_cycle_reached": reached_full_cycle,
        "ok": coverage_ok,
    }


def compact_rest_stress_row(row: dict[str, object]) -> dict[str, object]:
    """Returns a report-safe compact representation of one REST stress request."""

    compact = {
        "operation_key": rest_stress_row_operation_key(row),
        "method": row.get("method"),
        "family": row.get("family"),
        "scenario": row.get("scenario"),
        "status": row.get("status"),
        "ok": bool(row.get("ok")),
        "duration_ms": row.get("duration_ms"),
        "retry_count": int(row.get("retry_count") or 0),
    }
    if row.get("error"):
        compact["error"] = str(row.get("error"))
    return compact


def summarize_rest_stress_results(
    rows: list[dict[str, object]],
    *,
    budget: str,
    duration_seconds: float,
    concurrency: int,
    max_failures: int,
    operations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Builds a compact deterministic summary for one REST stress run."""

    status_counts: dict[str, int] = {}
    method_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    scenario_counts: dict[str, int] = {}
    content_type_counts: dict[str, int] = {}
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
        scenario = str(row.get("scenario") or "unknown")
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
        content_type = str(row.get("content_type") or "unknown")
        content_type_counts[content_type] = content_type_counts.get(content_type, 0) + 1
        duration_ms = row.get("duration_ms")
        if isinstance(duration_ms, int | float):
            durations.append(float(duration_ms))
        if not row.get("ok"):
            error_key = str(row.get("error") or status)
            error_counts[error_key] = error_counts.get(error_key, 0) + 1
            if len(failures) < 10:
                failures.append(compact_rest_stress_row(row))
    failure_count = len([row for row in rows if not row.get("ok")])
    retry_attempt_count = sum(int(row.get("retry_count") or 0) for row in rows)
    operation_coverage = (
        summarize_rest_stress_operation_coverage(rows, operations)
        if operations is not None
        else None
    )
    operation_coverage_ok = operation_coverage is None or bool(operation_coverage["ok"])
    return {
        "budget": budget,
        "duration_seconds": duration_seconds,
        "concurrency": concurrency,
        "max_failures": max_failures,
        "requests_started": len(rows),
        "requests_completed": len(rows),
        "failure_count": failure_count,
        "ok": failure_count <= max_failures and operation_coverage_ok,
        "retry_attempt_count": retry_attempt_count,
        "retried_success_count": len([row for row in rows if row.get("ok") and int(row.get("retry_count") or 0) > 0]),
        "status_counts": status_counts,
        "method_counts": method_counts,
        "family_counts": family_counts,
        "scenario_counts": scenario_counts,
        "content_type_counts": content_type_counts,
        "error_counts": error_counts,
        "timeout_count": len([row for row in rows if row.get("status") == "exception" and "timeout" in str(row.get("error") or "").lower()]),
        "native_rest_non_json_count": len([row for row in rows if not bool(row.get("native_rest_json", True))]),
        "latency_ms": {
            "min": round(min(durations), 3) if durations else 0.0,
            "p50": percentile(durations, 50.0),
            "p95": percentile(durations, 95.0),
            "max": round(max(durations), 3) if durations else 0.0,
        },
        "slowest_requests_sample": [
            compact_rest_stress_row(row)
            for row in sorted(
                [row for row in rows if isinstance(row.get("duration_ms"), int | float)],
                key=lambda row: float(row.get("duration_ms") or 0.0),
                reverse=True,
            )[:10]
        ],
        "failures_sample": failures,
        "operation_coverage": operation_coverage,
    }


def build_contract_coverage_summary(routes: list[dict[str, object]], budget: str) -> dict[str, object]:
    """Summarizes exercised REST route coverage by contract family."""

    openapi_coverage = assert_contract_routes_match_openapi()
    coverage_by_family: dict[str, dict[str, int]] = {}
    method_counts: dict[str, int] = {}
    outcome_counts: dict[str, int] = {}
    response_envelope_counts: dict[str, int] = {}
    safety_counts: dict[str, int] = {}
    execution_model_counts: dict[str, int] = {}
    for route in routes:
        family = str(route["family"])
        family_summary = coverage_by_family.setdefault(family, {"total": 0, "exercised": 0, "skipped": 0, "failed": 0})
        family_summary["total"] += 1
        method = str(route.get("method") or "UNKNOWN")
        method_counts[method] = method_counts.get(method, 0) + 1
        response_envelope = str(route.get("responseEnvelope") or "UNKNOWN")
        response_envelope_counts[response_envelope] = response_envelope_counts.get(response_envelope, 0) + 1
        safety = str(route.get("safety") or ("unsafe" if route.get("safe") is False else "safe"))
        safety_counts[safety] = safety_counts.get(safety, 0) + 1
        execution_model = str(route.get("executionModel") or "unknown")
        execution_model_counts[execution_model] = execution_model_counts.get(execution_model, 0) + 1
        outcome = str(route.get("outcome") or ("skipped" if route.get("skipped") else "unknown"))
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        if route.get("skipped"):
            family_summary["skipped"] += 1
        elif route.get("ok"):
            family_summary["exercised"] += 1
        else:
            family_summary["failed"] += 1
    failed_routes = [route["name"] for route in routes if not route.get("ok") and not route.get("skipped")]
    if not bool(openapi_coverage["ok"]):
        failed_routes.append("openapi_registry_consistency")
    return {
        "budget": budget,
        "route_count": len(routes),
        "safe_route_count": len([route for route in routes if route.get("safe") is not False]),
        "unsafe_route_count": len([route for route in routes if route.get("safe") is False]),
        "exercised_route_count": len([route for route in routes if route.get("ok") and not route.get("skipped")]),
        "expected_error_count": outcome_counts.get("expected_error", 0),
        "success_count": outcome_counts.get("success", 0),
        "method_counts": method_counts,
        "response_envelope_counts": response_envelope_counts,
        "safety_counts": safety_counts,
        "execution_model_counts": execution_model_counts,
        "outcome_counts": outcome_counts,
        "routes": routes,
        "coverage_by_family": coverage_by_family,
        "openapi": openapi_coverage,
        "intentionally_unsupported": list(REST_INTENTIONALLY_UNSUPPORTED),
        "failed_routes": failed_routes,
        "ok": not failed_routes,
    }


def exercise_rest_contract_completeness(base_url: str, api_key: str, budget: str) -> dict[str, object]:
    """Exercises and reports the safe broadband REST contract surface."""

    routes: list[dict[str, object]] = []
    for route in REST_CONTRACT_ROUTES:
        operation_id = str(route["operationId"])
        expected_error_statuses = REST_CONTRACT_EXPECTED_ERROR_STATUSES.get(operation_id, ())
        expected_statuses = tuple(int(value) for value in route["successResponseStatuses"]) + expected_error_statuses
        row = {
            "name": route["name"],
            "operationId": operation_id,
            "family": route["family"],
            "method": route["method"],
            "path": route["path"],
            "safe": route["safe"],
            "safety": route["safety"],
            "hasRequestBody": route["hasRequestBody"],
            "requestBodyRequired": route["requestBodyRequired"],
            "successResponseStatuses": route["successResponseStatuses"],
            "expectedResponseStatuses": list(expected_statuses),
            "successResponseRefs": route["successResponseRefs"],
            "responseEnvelope": route["responseEnvelope"],
            "executionModel": route.get("executionModel", "unknown"),
            "skipped": False,
            "ok": False,
        }
        if route["safe"] is False:
            row.update({"skipped": True, "ok": True, "outcome": "skipped_unsafe", "reason": "unsafe during smoke run"})
            routes.append(row)
            continue
        start = time.monotonic()
        try:
            request_body = get_contract_route_body(str(route["name"])) if bool(route["hasRequestBody"]) else None
            if bool(route["requestBodyRequired"]) and request_body is None:
                raise RuntimeError(f"OpenAPI operation requires a request body but no safe contract payload is registered: {route['name']}")
            result = http_request(
                base_url,
                str(route["path"]),
                method=str(route["method"]),
                api_key=api_key,
                json_body=request_body,
            )
            status = int(result["status"])
            if 200 <= status < 300:
                require_success_envelope(result)
                validate_openapi_response_payload(str(route["responseEnvelope"]), result.get("raw_json"))
                outcome = "success"
            elif status >= 400:
                require_error_response(result, status, str(require_json_object(result, status).get("error") or ""))
                validate_openapi_response_payload("ErrorResponse", result.get("raw_json"))
                outcome = "expected_error" if status in expected_error_statuses else "unexpected_error"
            else:
                outcome = "unexpected_status"
            row.update(
                {
                    "status": status,
                    "ok": status in expected_statuses and outcome in {"success", "expected_error"},
                    "outcome": outcome,
                    "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
                }
            )
        except Exception as exc:
            row.update(
                {
                    "status": "exception",
                    "ok": False,
                    "outcome": "exception",
                    "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
                    "error": str(exc),
                }
            )
        routes.append(row)
    return build_contract_coverage_summary(routes, budget)


def get_contract_route_body(route_name: str) -> dict[str, object] | None:
    """Returns the safe payload used to exercise one REST contract route."""

    if route_name in {"app_shutdown", "shutdownApp"}:
        return {"confirmShutdown": True}
    if route_name == "captureDiagnosticDump":
        return {"confirmDump": True, "fullMemory": False}
    if route_name == "triggerDiagnosticCrashTest":
        return {"confirmCrash": True}
    if route_name in {"app_preferences_patch", "patchPreferences"}:
        return {"safeServerConnect": True}
    if route_name in {"categories_create", "createCategory"}:
        return {}
    if route_name in {"categories_patch", "patchCategory"}:
        return {"name": "REST contract"}
    if route_name in {"transfers_add_link", "createTransfers"}:
        return {"link": "not-an-ed2k-link"}
    if route_name == "transfers_add_links":
        return {"links": ["not-an-ed2k-link"]}
    if route_name in {"transfers_patch", "patchTransfer"}:
        return {"priority": "high"}
    if route_name in {
        "transfers_pause",
        "transfers_resume",
        "transfers_stop",
        "transfers_recheck",
        "transfers_preview",
        "pauseTransfer",
        "resumeTransfer",
        "stopTransfer",
        "recheckTransfer",
        "previewTransfer",
    }:
        return {}
    if route_name in {"transfers_clear_completed", "clearCompletedTransfers"}:
        return {"confirmClearCompleted": True}
    if route_name in {"logs_clear", "clearLogs"}:
        return {"confirmClearLogs": True}
    if route_name in {"transfers_delete", "deleteTransfer"}:
        return {"deleteFiles": True}
    if route_name.startswith("transfers_source_") or route_name in {
        "browseTransferSource",
        "addTransferSourceFriend",
        "removeTransferSourceFriend",
        "removeTransferSource",
        "banTransferSource",
        "unbanTransferSource",
        "releaseTransferSourceUploadSlot",
    }:
        return {}
    if route_name in {"shared_files_add", "createSharedFile"}:
        return {}
    if route_name in {"shared_files_patch", "patchSharedFile"}:
        return {"comment": "rest contract", "rating": 4}
    if route_name in {"shared_files_delete", "deleteSharedFile"}:
        return {"deleteFiles": False}
    if route_name in {"replaceSharedDirectories"}:
        return {"confirmReplaceRoots": True, "roots": []}
    if route_name in {"shared_files_reload", "reloadSharedFiles", "reloadSharedDirectories"}:
        return {}
    if route_name.startswith("uploads_") or route_name.startswith("upload_queue_") or route_name in {
        "releaseUploadSlot",
        "removeUploadClient",
        "addUploadFriend",
        "removeUploadFriend",
        "banUploadClient",
        "unbanUploadClient",
        "removeUploadQueueClient",
        "releaseUploadQueueClientSlot",
        "addUploadQueueFriend",
        "removeUploadQueueFriend",
        "banUploadQueueClient",
        "unbanUploadQueueClient",
    }:
        return {}
    if route_name in {"servers_add", "createServer"}:
        return dict(REST_SURFACE_TEST_SERVER)
    if route_name in {"servers_connect", "servers_patch", "servers_connect_specific", "connectServerAny", "disconnectServers", "connectServer"}:
        return {}
    if route_name in {"servers_patch_properties", "patchServer"}:
        return {"priority": "high"}
    if route_name in {"servers_import_met_url", "createServerMetUrlImport", "kad_import_nodes_url", "createKadNodesUrlImport"}:
        return {}
    if route_name in {"servers_delete", "deleteServer"}:
        return {}
    if route_name in {"kad_start", "kad_patch", "kad_stop", "kad_bootstrap", "startKad", "recheckKadFirewall", "stopKad", "bootstrapKad"}:
        return {}
    if route_name in {"searches_start", "createSearch"}:
        return {"query": "", "method": "automatic", "type": ""}
    if route_name in {"searches_download_result", "downloadSearchResult"}:
        return {"paused": True, "categoryId": 0}
    if route_name in {"searches_delete_all", "deleteSearches"}:
        return {"confirmDeleteAllSearches": True}
    if route_name in {"searches_delete", "deleteSearch"}:
        return {}
    if route_name in {"friends_create", "createFriend"}:
        return {"userHash": REST_SURFACE_MISSING_HASH, "name": "REST contract"}
    if route_name in {"friends_delete", "deleteFriend"}:
        return {}
    return None


def exercise_rest_stress(
    base_url: str,
    api_key: str,
    *,
    budget: str,
    duration_seconds: float,
    concurrency: int,
    max_failures: int,
    request_timeout_seconds: float,
) -> dict[str, object]:
    """Runs a bounded read-heavy REST stress pass against the isolated app."""

    validate_rest_stress_config(
        budget=budget,
        duration_seconds=duration_seconds,
        concurrency=concurrency,
        max_failures=max_failures,
        request_timeout_seconds=request_timeout_seconds,
    )
    if budget == "off":
        return {
            "budget": budget,
            "enabled": False,
            "ok": True,
            "requests_started": 0,
            "requests_completed": 0,
        }

    deadline = time.monotonic() + duration_seconds
    operations = build_rest_stress_operations(budget)
    qbit_session_cookie = ""
    if any(
        "{qbit_session_cookie}" in str(operation.get("extra_headers", {}).get("Cookie", ""))
        for operation in operations
        if isinstance(operation.get("extra_headers"), dict)
    ):
        qbit_session_cookie = create_qbit_session_cookie(base_url, api_key)
    rows: list[dict[str, object]] = []
    next_index = 0

    def run_one(index: int) -> dict[str, object]:
        operation = operations[index % len(operations)]
        operation_key = rest_stress_operation_key(operation)
        method = str(operation["method"])
        path = str(operation["path"]).replace("{api_key}", urllib.parse.quote(api_key, safe=""))
        json_body = operation.get("json_body")
        raw_body = operation.get("raw_body")
        if isinstance(raw_body, str):
            raw_body = raw_body.replace("{api_key}", urllib.parse.quote(api_key, safe=""))
        content_type = operation.get("content_type")
        extra_headers = dict(operation.get("extra_headers") or {})
        if extra_headers.get("Cookie") == "{qbit_session_cookie}":
            extra_headers["Cookie"] = qbit_session_cookie
        family = str(operation.get("family") or "unknown")
        scenario = str(operation.get("scenario") or "unknown")
        response_kind = str(operation.get("response_kind") or "native-json")
        expected_body_contains = operation.get("expected_body_contains")
        expected_statuses = tuple(int(value) for value in operation.get("expected_statuses", ()))
        start = time.monotonic()
        retry_count = 0
        last_exception: Exception | None = None
        for attempt_index in range(3):
            try:
                result = http_request(
                    base_url,
                    path,
                    method=method,
                    api_key=api_key if bool(operation.get("api_key", True)) else None,
                    json_body=json_body,
                    raw_body=raw_body if isinstance(raw_body, bytes | str) else None,
                    content_type=str(content_type) if content_type is not None else None,
                    extra_headers=extra_headers,
                    request_timeout_seconds=request_timeout_seconds,
                )
                status = int(result["status"])
                expected_match = not expected_statuses or status in expected_statuses
                response_kind_match = response_matches_kind(result, response_kind)
                body_match = expected_body_contains is None or str(expected_body_contains).lower() in str(result.get("body_text") or "").lower()
                native_rest_json = response_kind != "native-json" or is_native_rest_json_response(result)
                error = classify_rest_stress_response_error(
                    expected_match=expected_match,
                    response_kind_match=response_kind_match,
                    body_match=body_match,
                    native_rest_json=native_rest_json,
                )
                return {
                    "operation_key": operation_key,
                    "method": method,
                    "path": path,
                    "family": family,
                    "scenario": scenario,
                    "status": status,
                    "ok": (expected_match if expected_statuses else 200 <= status < 500) and response_kind_match and body_match and native_rest_json,
                    "expected_statuses": list(expected_statuses),
                    "content_type": str(result.get("content_type") or ""),
                    "response_kind": response_kind,
                    "native_rest_json": native_rest_json,
                    "retry_count": retry_count,
                    "error": error,
                    "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
                }
            except Exception as exc:
                last_exception = exc
                if attempt_index >= 2 or not is_retryable_rest_stress_exception(exc):
                    break
                retry_count += 1
                time.sleep(0.025 * retry_count)
        return {
            "operation_key": operation_key,
            "method": method,
            "path": path,
            "family": family,
            "scenario": scenario,
            "status": "exception",
            "ok": False,
            "expected_statuses": list(expected_statuses),
            "retry_count": retry_count,
            "duration_ms": round((time.monotonic() - start) * 1000.0, 3),
            "error": str(last_exception),
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
        budget=budget,
        duration_seconds=duration_seconds,
        concurrency=concurrency,
        max_failures=max_failures,
        operations=operations,
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


def wait_for_log_message_containing(
    base_url: str,
    api_key: str,
    fragment: str,
    *,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until REST logs expose one message containing the expected text."""

    def resolve():
        result = http_request(base_url, "/api/v1/logs?limit=400", api_key=api_key)
        if int(result["status"]) != 200:
            return None
        entries = require_json_array(result, 200)
        messages = extract_log_messages(entries)
        matched_message = next((message for message in messages if fragment in message), None)
        if matched_message is None:
            return None
        return {
            "status": int(result["status"]),
            "matched": True,
            "fragment": fragment,
            "message": matched_message,
            "message_count": len(messages),
        }

    return wait_for(
        resolve,
        timeout=timeout_seconds,
        interval=0.5,
        description=f"REST log message containing {fragment!r}",
    )


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
        "transferDetails",
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
    invalid_preference_value = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        json_body={"maxUploadSlots": 0},
    )
    invalid_preference_boolean = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        json_body={"safeServerConnect": "true"},
    )
    invalid_preference_empty = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        json_body={},
    )
    surface["app_preferences_invalid"] = {
        "status": invalid_preference["status"],
        "error": require_error_response(
            invalid_preference,
            400,
            "INVALID_ARGUMENT",
            message_contains="unknown JSON field: unsupportedPreference",
        ),
        "bad_value": require_error_response(
            invalid_preference_value,
            400,
            "INVALID_ARGUMENT",
            message_contains="maxUploadSlots must be an unsigned number in the range 1..32",
        ),
        "bad_boolean": require_error_response(
            invalid_preference_boolean,
            400,
            "INVALID_ARGUMENT",
            message_contains="safeServerConnect must be a boolean",
        ),
        "empty": require_error_response(
            invalid_preference_empty,
            400,
            "INVALID_ARGUMENT",
            message_contains="preferences PATCH requires at least one preference",
        ),
    }

    safe_preference_update = {key: preference_payload[key] for key in REST_PREFERENCE_KEYS}
    preference_set = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        json_body=safe_preference_update,
    )
    preference_set_payload = require_json_object(preference_set, 200)
    for key, expected_value in safe_preference_update.items():
        assert preference_set_payload.get(key) == expected_value, compact_http_result(preference_set)
    surface["app_preferences_set_noop"] = {
        "status": preference_set["status"],
        "updated": safe_preference_update,
    }

    transfers = http_request(base_url, "/api/v1/transfers", api_key=api_key)
    transfer_rows = require_json_array(transfers, 200)
    transfers_by_filter = http_request(base_url, "/api/v1/transfers?state=downloading&categoryId=0", api_key=api_key)
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
    category_patch_empty = http_request(
        base_url,
        "/api/v1/categories/1",
        method="PATCH",
        api_key=api_key,
        json_body={},
    )
    category_patch_bad_color = http_request(
        base_url,
        "/api/v1/categories/1",
        method="PATCH",
        api_key=api_key,
        json_body={"color": 16777216},
    )
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
    missing_transfer_details = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/details",
        api_key=api_key,
    )
    missing_transfer_source_browse = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/sources/{REST_SURFACE_MISSING_HASH}/operations/browse",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    transfer_pause = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/operations/pause",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    transfer_resume = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/operations/resume",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    transfer_stop = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/operations/stop",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    transfer_delete_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": True},
    )
    transfer_delete_bad = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": False},
    )
    transfer_add_bad = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={"link": "not-an-ed2k-link"},
    )
    transfer_add_missing_link = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={"paused": True},
    )
    transfer_add_bad_paused = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": f"ed2k://|file|rest-api-smoke.bin|1024|{REST_SURFACE_VALID_DOWNLOAD_HASH}|/",
            "paused": "true",
        },
    )
    transfer_add_conflicting_link_shapes = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": f"ed2k://|file|rest-api-smoke.bin|1024|{REST_SURFACE_VALID_DOWNLOAD_HASH}|/",
            "links": [f"ed2k://|file|rest-api-smoke.bin|1024|{REST_SURFACE_VALID_DOWNLOAD_HASH}|/"],
        },
    )
    transfer_add_bad_category_id = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": f"ed2k://|file|rest-api-smoke.bin|1024|{REST_SURFACE_VALID_DOWNLOAD_HASH}|/",
            "categoryId": -1,
        },
    )
    transfer_add_valid = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": f"ed2k://|file|rest-api-smoke.bin|1024|{REST_SURFACE_VALID_DOWNLOAD_HASH}|/",
            "paused": True,
            "categoryId": 0,
        },
        request_timeout_seconds=30.0,
    )
    transfer_add_valid_payload = require_transfer_add_result(transfer_add_valid, REST_SURFACE_VALID_DOWNLOAD_HASH)
    transfer_added = http_request(base_url, f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}", api_key=api_key)
    transfer_added_payload = require_json_object(transfer_added, 200)
    transfer_added_details = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}/details",
        api_key=api_key,
    )
    transfer_added_details_payload = require_json_object(transfer_added_details, 200)
    transfer_added_resume = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}/operations/resume",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    transfer_added_pause = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}/operations/pause",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    transfer_added_stop = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}/operations/stop",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    transfer_added_resume_after_stop = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}/operations/resume",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    transfer_added_pause_after_resume = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}/operations/pause",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    unicode_transfer_name = "rest-api-unicode-ß-漢.bin"
    unicode_transfer_link = (
        "ed2k://|file|"
        f"{urllib.parse.quote(unicode_transfer_name, safe='')}"
        f"|2048|{REST_SURFACE_UNICODE_DOWNLOAD_HASH}|/"
    )
    transfer_add_unicode = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": unicode_transfer_link,
            "paused": True,
            "categoryId": 0,
        },
        request_timeout_seconds=30.0,
    )
    transfer_add_unicode_payload = require_transfer_add_result(transfer_add_unicode, REST_SURFACE_UNICODE_DOWNLOAD_HASH)
    transfer_added_unicode = http_request(base_url, f"/api/v1/transfers/{REST_SURFACE_UNICODE_DOWNLOAD_HASH}", api_key=api_key)
    transfer_added_unicode_payload = require_json_object(transfer_added_unicode, 200)
    assert transfer_added_unicode_payload.get("name") == unicode_transfer_name, compact_http_result(transfer_added_unicode)
    unicode_log_message = wait_for_log_message_containing(
        base_url,
        api_key,
        unicode_transfer_name,
        timeout_seconds=10.0,
    )
    reserved_transfer_name = "NUL .txt"
    reserved_transfer_expected_name = "NUL_.txt"
    reserved_transfer_link = (
        "ed2k://|file|"
        f"{urllib.parse.quote(reserved_transfer_name, safe='')}"
        f"|4096|{REST_SURFACE_RESERVED_DOWNLOAD_HASH}|/"
    )
    transfer_add_reserved = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": reserved_transfer_link,
            "paused": True,
            "categoryId": 0,
        },
        request_timeout_seconds=30.0,
    )
    transfer_add_reserved_payload = require_transfer_add_result(transfer_add_reserved, REST_SURFACE_RESERVED_DOWNLOAD_HASH)
    transfer_added_reserved = http_request(base_url, f"/api/v1/transfers/{REST_SURFACE_RESERVED_DOWNLOAD_HASH}", api_key=api_key)
    transfer_added_reserved_payload = require_json_object(transfer_added_reserved, 200)
    assert transfer_added_reserved_payload.get("name") == reserved_transfer_expected_name, compact_http_result(transfer_added_reserved)
    transfer_delete_added = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_VALID_DOWNLOAD_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": True},
        request_timeout_seconds=30.0,
    )
    transfer_delete_reserved = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_RESERVED_DOWNLOAD_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": True},
        request_timeout_seconds=30.0,
    )
    transfer_delete_unicode = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_UNICODE_DOWNLOAD_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": True},
        request_timeout_seconds=30.0,
    )
    transfer_recheck_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}/operations/recheck",
        method="POST",
        api_key=api_key,
        json_body={},
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
        json_body={"categoryId": 0},
    )
    transfer_rename_missing = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"name": "renamed.bin"},
    )
    transfer_patch_conflicting_families = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"priority": "high", "name": "renamed.bin"},
    )
    transfer_patch_bad_priority_type = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"priority": 7},
    )
    surface["transfers"] = {
        "list_count": len(transfer_rows),
        "list_status": transfers["status"],
        "filter_status": transfers_by_filter["status"],
        "category_count": len(category_rows),
        "category_create_bad": require_error_response(category_create_bad, 400, "INVALID_ARGUMENT", message_contains="name must be"),
        "category_get_missing": require_error_response(category_get_missing, 404, "NOT_FOUND", message_contains="category not found"),
        "category_patch_empty": require_error_response(category_patch_empty, 400, "INVALID_ARGUMENT", message_contains="category PATCH requires at least one field"),
        "category_patch_bad_color": require_error_response(category_patch_bad_color, 400, "INVALID_ARGUMENT", message_contains="color must be null or an RGB integer"),
        "category_patch_default": require_error_response(category_patch_default, 400, "INVALID_ARGUMENT", message_contains="default category"),
        "category_delete_default": require_error_response(category_delete_default, 400, "INVALID_ARGUMENT", message_contains="default category"),
        "missing_get": require_error_response(missing_transfer, 404, "NOT_FOUND", message_contains="transfer not found"),
        "missing_sources": require_error_response(missing_transfer_sources, 404, "NOT_FOUND", message_contains="transfer not found"),
        "missing_details": require_error_response(missing_transfer_details, 404, "NOT_FOUND", message_contains="transfer not found"),
        "missing_source_browse": require_error_response(missing_transfer_source_browse, 404, "NOT_FOUND", message_contains="transfer not found"),
        "pause_missing_item": require_missing_transfer_bulk_result(transfer_pause),
        "resume_missing_item": require_missing_transfer_bulk_result(transfer_resume),
        "stop_missing_item": require_missing_transfer_bulk_result(transfer_stop),
        "delete_missing_item": require_missing_transfer_bulk_result(transfer_delete_missing),
        "delete_without_files": require_error_response(
            transfer_delete_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="deleteFiles must be true for transfer deletes",
        ),
        "add_bad_payload": require_error_response(
            transfer_add_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="Not an eD2K server or file link",
        ),
        "add_missing_link": require_error_response(
            transfer_add_missing_link,
            400,
            "INVALID_ARGUMENT",
            message_contains="link or links is required",
        ),
        "add_bad_paused": require_error_response(
            transfer_add_bad_paused,
            400,
            "INVALID_ARGUMENT",
            message_contains="paused must be a boolean",
        ),
        "add_conflicting_link_shapes": require_error_response(
            transfer_add_conflicting_link_shapes,
            400,
            "INVALID_ARGUMENT",
            message_contains="link and links are mutually exclusive",
        ),
        "add_bad_category_id": require_error_response(
            transfer_add_bad_category_id,
            400,
            "INVALID_ARGUMENT",
            message_contains="categoryId must be an unsigned number",
        ),
        "add_valid_paused": {
            "status": transfer_add_valid["status"],
            "hash": transfer_add_valid_payload.get("hash"),
            "state": transfer_added_payload.get("state"),
            "details": compact_transfer_details_payload(transfer_added_details_payload, REST_SURFACE_VALID_DOWNLOAD_HASH),
            "lifecycle": {
                "resume": require_transfer_operation_result(transfer_added_resume, REST_SURFACE_VALID_DOWNLOAD_HASH),
                "pause": require_transfer_operation_result(transfer_added_pause, REST_SURFACE_VALID_DOWNLOAD_HASH),
                "stop": require_transfer_operation_result(transfer_added_stop, REST_SURFACE_VALID_DOWNLOAD_HASH),
                "resume_after_stop": require_transfer_operation_result(transfer_added_resume_after_stop, REST_SURFACE_VALID_DOWNLOAD_HASH),
                "pause_after_resume": require_transfer_operation_result(transfer_added_pause_after_resume, REST_SURFACE_VALID_DOWNLOAD_HASH),
            },
            "delete": require_transfer_bulk_result(transfer_delete_added, REST_SURFACE_VALID_DOWNLOAD_HASH, True),
        },
        "add_unicode_filename": {
            "status": transfer_add_unicode["status"],
            "hash": transfer_add_unicode_payload.get("hash"),
            "name": transfer_added_unicode_payload.get("name"),
            "state": transfer_added_unicode_payload.get("state"),
            "log_message": unicode_log_message,
            "delete": require_transfer_bulk_result(transfer_delete_unicode, REST_SURFACE_UNICODE_DOWNLOAD_HASH, True),
        },
        "add_reserved_filename": {
            "status": transfer_add_reserved["status"],
            "hash": transfer_add_reserved_payload.get("hash"),
            "input_name": reserved_transfer_name,
            "name": transfer_added_reserved_payload.get("name"),
            "state": transfer_added_reserved_payload.get("state"),
            "delete": require_transfer_bulk_result(transfer_delete_reserved, REST_SURFACE_RESERVED_DOWNLOAD_HASH, True),
        },
        "recheck_missing": require_error_response(transfer_recheck_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "priority_missing": require_error_response(transfer_priority_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "category_missing": require_error_response(transfer_category_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "rename_missing": require_error_response(transfer_rename_missing, 404, "NOT_FOUND", message_contains="transfer not found"),
        "patch_conflicting_families": require_error_response(
            transfer_patch_conflicting_families,
            400,
            "INVALID_ARGUMENT",
            message_contains="transfer PATCH accepts only one mutation family",
        ),
        "patch_bad_priority_type": require_error_response(
            transfer_patch_bad_priority_type,
            400,
            "INVALID_ARGUMENT",
            message_contains="priority must be a string",
        ),
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
        json_body={"confirmReplaceRoots": True},
    )
    shared_directories_missing_confirmation = http_request(
        base_url,
        "/api/v1/shared-directories",
        method="PATCH",
        api_key=api_key,
        json_body={"roots": []},
    )
    shared_directories_bad_recursive = http_request(
        base_url,
        "/api/v1/shared-directories",
        method="PATCH",
        api_key=api_key,
        json_body={"confirmReplaceRoots": True, "roots": [{"path": "C:\\not-shared", "recursive": "yes"}]},
    )
    shared_directories_reload = http_request(
        base_url,
        "/api/v1/shared-directories/operations/reload",
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
        "missing_confirmation": require_error_response(
            shared_directories_missing_confirmation,
            400,
            "INVALID_ARGUMENT",
            message_contains="confirmReplaceRoots must be true",
        ),
        "bad_recursive": require_error_response(
            shared_directories_bad_recursive,
            400,
            "INVALID_ARGUMENT",
            message_contains="recursive must be a boolean",
        ),
        "reload": compact_http_result(shared_directories_reload),
    }
    assert shared_directories_reload["status"] == 200, compact_http_result(shared_directories_reload)

    upload_list = http_request(base_url, "/api/v1/uploads", api_key=api_key)
    upload_queue = http_request(base_url, "/api/v1/upload-queue", api_key=api_key)
    upload_remove_bad = http_request(
        base_url,
        "/api/v1/uploads/unknown/operations/remove",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    upload_release_bad = http_request(
        base_url,
        "/api/v1/uploads/unknown/operations/release-slot",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    upload_queue_remove_bad = http_request(
        base_url,
        "/api/v1/upload-queue/unknown/operations/remove",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    upload_unsupported_operation = http_request(
        base_url,
        f"/api/v1/uploads/{REST_SURFACE_MISSING_HASH}/operations/unsupported",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    upload_queue_unsupported_operation = http_request(
        base_url,
        f"/api/v1/upload-queue/{REST_SURFACE_MISSING_HASH}/operations/unsupported",
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
            message_contains="clientId must be a 32-character lowercase hex string or address:port",
        ),
        "release_slot_bad_payload": require_error_response(
            upload_release_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="clientId must be a 32-character lowercase hex string or address:port",
        ),
        "queue_remove_bad_payload": require_error_response(
            upload_queue_remove_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="clientId must be a 32-character lowercase hex string or address:port",
        ),
        "unsupported_operation": require_error_response(
            upload_unsupported_operation,
            404,
            "NOT_FOUND",
            message_contains="API route not found",
        ),
        "queue_unsupported_operation": require_error_response(
            upload_queue_unsupported_operation,
            404,
            "NOT_FOUND",
            message_contains="API route not found",
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
    shared_patch_empty = http_request(
        base_url,
        f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={},
    )
    shared_patch_bad_priority_type = http_request(
        base_url,
        f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"priority": 7},
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
    shared_add_traversal = http_request(
        base_url,
        "/api/v1/shared-files",
        method="POST",
        api_key=api_key,
        json_body={"path": "..\\outside\\traversal.bin"},
    )
    shared_add_long_unicode = http_request(
        base_url,
        "/api/v1/shared-files",
        method="POST",
        api_key=api_key,
        json_body={"path": REST_STRESS_LONG_UNICODE_PATH},
    )
    shared_delete_bad = http_request(
        base_url,
        f"/api/v1/shared-files/{REST_SURFACE_MISSING_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": "yes"},
    )
    shared_reload = http_request(
        base_url,
        "/api/v1/shared-files/operations/reload",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    surface["shared"] = {
        "list_count": len(shared_rows),
        "missing_get": require_error_response(missing_shared, 404, "NOT_FOUND", message_contains="shared file not found"),
        "rating_missing": require_error_response(shared_rating_missing, 404, "NOT_FOUND", message_contains="shared file not found"),
        "patch_empty": require_error_response(
            shared_patch_empty,
            400,
            "INVALID_ARGUMENT",
            message_contains="shared-file PATCH requires priority, comment, or rating",
        ),
        "patch_bad_priority_type": require_error_response(
            shared_patch_bad_priority_type,
            400,
            "INVALID_ARGUMENT",
            message_contains="priority must be a string",
        ),
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
        "add_traversal_path": require_error_response(
            shared_add_traversal,
            400,
            "INVALID_ARGUMENT",
            message_contains="path must point to a file inside a shareable directory",
        ),
        "add_long_unicode_path": require_error_response(
            shared_add_long_unicode,
            400,
            "INVALID_ARGUMENT",
            message_contains="path must point to a file inside a shareable directory",
        ),
        "delete_bad_payload": require_error_response(
            shared_delete_bad,
            400,
            "INVALID_ARGUMENT",
            message_contains="deleteFiles must be an explicit boolean",
        ),
        "reload": compact_http_result(shared_reload),
    }
    assert shared_reload["status"] == 200, compact_http_result(shared_reload)

    missing_route = http_request(base_url, "/api/v1/not-a-route", api_key=api_key)
    invalid_method = http_request(base_url, "/api/v1/app", method="POST", api_key=api_key, json_body={})
    invalid_json_shape = http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body=[],
    )
    unknown_json_field = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="PATCH",
        api_key=api_key,
        json_body={"priority": "high", "legacy": True},
    )
    malformed_query = http_request(
        base_url,
        "/api/v1/transfers?categoryId=abc",
        api_key=api_key,
    )
    duplicate_query = http_request(
        base_url,
        "/api/v1/logs?limit=10&limit=20",
        api_key=api_key,
    )
    out_of_range_limit = http_request(
        base_url,
        "/api/v1/logs?limit=0",
        api_key=api_key,
    )
    unknown_query = http_request(
        base_url,
        "/api/v1/logs?limit=1&legacy=1",
        api_key=api_key,
    )
    ambiguous_category_selector = http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={
            "link": "ed2k://|file|x|1|0123456789abcdef0123456789abcdef|/",
            "categoryId": 0,
            "categoryName": "Default",
        },
    )
    missing_delete_confirmation = http_request(
        base_url,
        f"/api/v1/transfers/{REST_SURFACE_MISSING_HASH}",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    missing_clear_completed_confirmation = http_request(
        base_url,
        "/api/v1/transfers/operations/clear-completed",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    missing_shutdown_confirmation = http_request(
        base_url,
        "/api/v1/app/shutdown",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    missing_delete_all_searches_confirmation = http_request(
        base_url,
        "/api/v1/searches",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    missing_clear_logs_confirmation = http_request(
        base_url,
        "/api/v1/logs/operations/clear",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    bad_json_content_type = http_request(
        base_url,
        "/api/v1/app/preferences",
        method="PATCH",
        api_key=api_key,
        raw_body=json.dumps({"safeServerConnect": True}),
        content_type="text/plain",
    )
    search_bad_method = http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body={"query": "ubuntu", "method": "contentdb", "type": ""},
    )
    search_bad_range = http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body={"query": "ubuntu", "minSizeBytes": 4096, "maxSizeBytes": 700},
    )
    search_bad_clear_existing = http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body={"query": "ubuntu", "clearExisting": 1},
    )
    friend_bad_user_hash = http_request(
        base_url,
        "/api/v1/friends",
        method="POST",
        api_key=api_key,
        json_body={"userHash": REST_SURFACE_MISSING_HASH.upper(), "name": "REST contract"},
    )
    surface["errors"] = {
        "missing_route": require_error_response(missing_route, 404, "NOT_FOUND", message_contains="API route not found"),
        "invalid_method": require_error_response(
            invalid_method,
            405,
            "METHOD_NOT_ALLOWED",
            message_contains="HTTP method is not allowed",
        ),
        "invalid_json_shape": require_error_response(
            invalid_json_shape,
            400,
            "INVALID_ARGUMENT",
            message_contains="JSON body must be an object",
        ),
        "unknown_json_field": require_error_response(
            unknown_json_field,
            400,
            "INVALID_ARGUMENT",
            message_contains="unknown JSON field: legacy",
        ),
        "malformed_query": require_error_response(
            malformed_query,
            400,
            "INVALID_ARGUMENT",
            message_contains="categoryId must be an unsigned number",
        ),
        "duplicate_query": require_error_response(
            duplicate_query,
            400,
            "INVALID_ARGUMENT",
            message_contains="duplicate query parameter: limit",
        ),
        "out_of_range_limit": require_error_response(
            out_of_range_limit,
            400,
            "INVALID_ARGUMENT",
            message_contains="limit is out of range",
        ),
        "unknown_query": require_error_response(
            unknown_query,
            400,
            "INVALID_ARGUMENT",
            message_contains="unknown query parameter: legacy",
        ),
        "ambiguous_category_selector": require_error_response(
            ambiguous_category_selector,
            400,
            "INVALID_ARGUMENT",
            message_contains="categoryId and categoryName are mutually exclusive",
        ),
        "missing_delete_confirmation": require_error_response(
            missing_delete_confirmation,
            400,
            "INVALID_ARGUMENT",
            message_contains="deleteFiles must be an explicit boolean",
        ),
        "missing_clear_completed_confirmation": require_error_response(
            missing_clear_completed_confirmation,
            400,
            "INVALID_ARGUMENT",
            message_contains="confirmClearCompleted must be true",
        ),
        "missing_shutdown_confirmation": require_error_response(
            missing_shutdown_confirmation,
            400,
            "INVALID_ARGUMENT",
            message_contains="confirmShutdown must be true",
        ),
        "missing_delete_all_searches_confirmation": require_error_response(
            missing_delete_all_searches_confirmation,
            400,
            "INVALID_ARGUMENT",
            message_contains="confirmDeleteAllSearches must be true",
        ),
        "missing_clear_logs_confirmation": require_error_response(
            missing_clear_logs_confirmation,
            400,
            "INVALID_ARGUMENT",
            message_contains="confirmClearLogs must be true",
        ),
        "bad_json_content_type": require_error_response(
            bad_json_content_type,
            400,
            "INVALID_ARGUMENT",
            message_contains="Content-Type must be application/json",
        ),
        "search_bad_method": require_error_response(
            search_bad_method,
            400,
            "INVALID_ARGUMENT",
            message_contains="method must be one of automatic, server, global, kad",
        ),
        "search_bad_range": require_error_response(
            search_bad_range,
            400,
            "INVALID_ARGUMENT",
            message_contains="maxSizeBytes must be greater than or equal to minSizeBytes",
        ),
        "search_bad_clear_existing": require_error_response(
            search_bad_clear_existing,
            400,
            "INVALID_ARGUMENT",
            message_contains="unknown JSON field: clearExisting",
        ),
        "friend_bad_user_hash": require_error_response(
            friend_bad_user_hash,
            400,
            "INVALID_ARGUMENT",
            message_contains="userHash must be a 32-character lowercase hex string",
        ),
    }

    server_payload = dict(REST_SURFACE_TEST_SERVER)
    server_add_bad_port = http_request(
        base_url,
        "/api/v1/servers",
        method="POST",
        api_key=api_key,
        json_body={"address": REST_SURFACE_TEST_SERVER["address"], "port": 0},
    )
    server_add_bad_connect = http_request(
        base_url,
        "/api/v1/servers",
        method="POST",
        api_key=api_key,
        json_body={"address": REST_SURFACE_TEST_SERVER["address"], "port": REST_SURFACE_TEST_SERVER["port"], "connect": "yes"},
    )
    server_met_bad_url = http_request(
        base_url,
        "/api/v1/servers/operations/import-met-url",
        method="POST",
        api_key=api_key,
        json_body={"url": "   "},
    )
    kad_bootstrap_bad_port = http_request(
        base_url,
        "/api/v1/kad/operations/bootstrap",
        method="POST",
        api_key=api_key,
        json_body={"address": "bootstrap.example.invalid", "port": 65536},
    )
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
        and str(row.get("address") or "") == REST_SURFACE_TEST_SERVER["address"]
        and int(row.get("port") or 0) == REST_SURFACE_TEST_SERVER["port"]
    ]
    assert added_servers, compact_http_result(servers_after_add)
    server_remove = http_request(
        base_url,
        f"/api/v1/servers/{REST_SURFACE_TEST_SERVER['address']}:{REST_SURFACE_TEST_SERVER['port']}",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )
    server_remove_payload = require_json_object(server_remove, 200)
    surface["servers_mutation"] = {
        "add_bad_port": require_error_response(
            server_add_bad_port,
            400,
            "INVALID_ARGUMENT",
            message_contains="port must be in the range 1..65535",
        ),
        "add_bad_connect": require_error_response(
            server_add_bad_connect,
            400,
            "INVALID_ARGUMENT",
            message_contains="connect must be a boolean",
        ),
        "met_bad_url": require_error_response(
            server_met_bad_url,
            400,
            "INVALID_ARGUMENT",
            message_contains="url must not be empty",
        ),
        "kad_bootstrap_bad_port": require_error_response(
            kad_bootstrap_bad_port,
            400,
            "INVALID_ARGUMENT",
            message_contains="port must be in the range 1..65535",
        ),
        "add": compact_http_result(server_add),
        "added_server": server_add_payload,
        "remove": compact_http_result(server_remove),
        "removed_server": server_remove_payload,
    }

    return surface


def get_response_header(result: dict[str, object], header_name: str) -> str:
    """Returns one response header case-insensitively from an http_request result."""

    headers = result.get("headers")
    if not isinstance(headers, dict):
        return ""
    for name, value in headers.items():
        if str(name).lower() == header_name.lower():
            return str(value)
    return ""


def create_qbit_session_cookie(base_url: str, api_key: str) -> str:
    """Authenticates once against qBit compatibility and returns the SID pair."""

    login_form = urllib.parse.urlencode({"username": "emule", "password": api_key})
    qbit_login = http_request(
        base_url,
        "/api/v2/auth/login",
        method="POST",
        raw_body=login_form,
        content_type="application/x-www-form-urlencoded",
    )
    assert int(qbit_login["status"]) == 200, compact_http_result(qbit_login)
    session_cookie = get_response_header(qbit_login, "Set-Cookie")
    assert "SID=" in session_cookie, compact_http_result(qbit_login)
    return session_cookie.split(";", 1)[0]


def require_qbit_json_array(result: dict[str, object], description: str) -> list[Any]:
    """Asserts one qBittorrent compatibility response is a JSON array."""

    assert int(result["status"]) == 200, compact_http_result(result)
    payload = result.get("json")
    assert isinstance(payload, list), {description: compact_http_result(result)}
    return list(payload)


def require_qbit_json_object(result: dict[str, object], description: str) -> dict[str, Any]:
    """Asserts one qBittorrent compatibility response is a JSON object."""

    assert int(result["status"]) == 200, compact_http_result(result)
    payload = result.get("json")
    assert isinstance(payload, dict), {description: compact_http_result(result)}
    return dict(payload)


def require_qbit_ok_text(result: dict[str, object], description: str) -> None:
    """Asserts one qBittorrent compatibility mutation returned qBit's Ok text."""

    assert int(result["status"]) == 200, compact_http_result(result)
    assert str(result.get("body_text") or "") == "Ok.", {description: compact_http_result(result)}


def find_qbit_info_row(rows: list[Any], transfer_hash: str) -> dict[str, Any] | None:
    """Finds one qBittorrent info row by lowercase eD2K hash."""

    expected_hash = transfer_hash.lower()
    for row in rows:
        if isinstance(row, dict) and str(row.get("hash") or "").lower() == expected_hash:
            return row
    return None


def exercise_live_seed_imports(
    base_url: str,
    api_key: str,
    seed_refresh: dict[str, object] | None,
    *,
    request_timeout_seconds: float = 60.0,
) -> dict[str, object]:
    """Imports refreshed live seed URLs and records source plus REST outcome evidence."""

    if not isinstance(seed_refresh, dict):
        return {"skipped": True, "reason": "live seed refresh disabled"}

    route_by_file = {
        "server.met": {
            "route": "/api/v1/servers/operations/import-met-url",
            "default_url": EMULE_SECURITY_SERVER_MET_URL,
        },
        "nodes.dat": {
            "route": "/api/v1/kad/operations/import-nodes-url",
            "default_url": EMULE_SECURITY_NODES_DAT_URL,
        },
    }
    imports: list[dict[str, object]] = []
    for source in seed_refresh.get("files", []):
        assert isinstance(source, dict), source
        file_name = str(source.get("file_name") or "")
        route = route_by_file.get(file_name)
        if route is None:
            continue

        source_url = str(source.get("url") or route["default_url"])
        result = http_request(
            base_url,
            str(route["route"]),
            method="POST",
            api_key=api_key,
            json_body={"url": source_url},
            request_timeout_seconds=request_timeout_seconds,
        )
        payload = require_json_object(result, 200)
        imported = bool(payload.get("imported", payload.get("ok")))
        evidence = {
            "name": source.get("name"),
            "file_name": file_name,
            "source_url": source_url,
            "source_bytes": source.get("bytes"),
            "source_sha256": source.get("sha256"),
            "route": route["route"],
            "imported": imported,
            "response": compact_http_result(result),
        }
        assert imported, evidence
        imports.append(evidence)

    expected_files = set(route_by_file.keys())
    imported_files = {str(entry["file_name"]) for entry in imports}
    assert imported_files == expected_files, {"expected": sorted(expected_files), "actual": sorted(imported_files)}
    return {
        "source_home_url": seed_refresh.get("source_home_url"),
        "imports": imports,
    }


def exercise_arr_adapter_smoke(base_url: str, api_key: str) -> dict[str, object]:
    """Exercises low-risk qBit/Torznab adapter flows without triggering live downloads."""

    smoke: dict[str, object] = {}

    torznab_unauthorized = http_request(base_url, "/indexer/emulebb/api?t=caps")
    assert int(torznab_unauthorized["status"]) == 401, compact_http_result(torznab_unauthorized)

    torznab_wrong_query_key = http_request(base_url, "/indexer/emulebb/api?t=caps&apikey=wrong-key")
    assert int(torznab_wrong_query_key["status"]) == 401, compact_http_result(torznab_wrong_query_key)

    torznab_caps_header = http_request(base_url, "/indexer/emulebb/api?t=caps", api_key=api_key)
    assert int(torznab_caps_header["status"]) == 200, compact_http_result(torznab_caps_header)
    assert "<caps>" in str(torznab_caps_header.get("body_text") or ""), compact_http_result(torznab_caps_header)

    torznab_caps_query = http_request(
        base_url,
        "/indexer/emulebb/api?t=caps&apikey=" + urllib.parse.quote(api_key, safe=""),
    )
    assert int(torznab_caps_query["status"]) == 200, compact_http_result(torznab_caps_query)

    torznab_duplicate_query = http_request(
        base_url,
        "/indexer/emulebb/api?t=caps&t=search",
        api_key=api_key,
    )
    assert int(torznab_duplicate_query["status"]) == 400, compact_http_result(torznab_duplicate_query)
    torznab_search = http_request(
        base_url,
        "/indexer/emulebb/api?t=search&q=linux",
        api_key=api_key,
        request_timeout_seconds=10.0,
    )
    assert int(torznab_search["status"]) == 200, compact_http_result(torznab_search)
    assert "<rss" in str(torznab_search.get("body_text") or ""), compact_http_result(torznab_search)
    torznab_malformed_search = http_request(
        base_url,
        "/indexer/emulebb/api?t=search&season=abc&q=linux",
        api_key=api_key,
    )
    assert int(torznab_malformed_search["status"]) == 400, compact_http_result(torznab_malformed_search)
    torznab_bad_category = http_request(
        base_url,
        "/indexer/emulebb/api?t=search&cat=abc&q=linux",
        api_key=api_key,
    )
    assert int(torznab_bad_category["status"]) == 400, compact_http_result(torznab_bad_category)
    smoke["torznab"] = {
        "unauthorized": compact_http_result(torznab_unauthorized),
        "wrong_query_key": compact_http_result(torznab_wrong_query_key),
        "caps_header_auth": compact_http_result(torznab_caps_header),
        "caps_query_auth": compact_http_result(torznab_caps_query),
        "duplicate_query": compact_http_result(torznab_duplicate_query),
        "search": compact_http_result(torznab_search),
        "malformed_search": compact_http_result(torznab_malformed_search),
        "bad_category": compact_http_result(torznab_bad_category),
    }

    qbit_public_version = http_request(base_url, "/api/v2/app/webapiVersion")
    assert int(qbit_public_version["status"]) == 200, compact_http_result(qbit_public_version)
    assert str(qbit_public_version.get("body_text") or "").startswith("2."), compact_http_result(qbit_public_version)

    qbit_categories_unauthenticated = http_request(base_url, "/api/v2/torrents/categories")
    assert int(qbit_categories_unauthenticated["status"]) == 403, compact_http_result(qbit_categories_unauthenticated)

    qbit_categories_wrong_cookie = http_request(
        base_url,
        "/api/v2/torrents/categories",
        extra_headers={"Cookie": "SID=wrong"},
    )
    assert int(qbit_categories_wrong_cookie["status"]) == 403, compact_http_result(qbit_categories_wrong_cookie)

    qbit_bad_login = http_request(
        base_url,
        "/api/v2/auth/login",
        method="POST",
        raw_body="username=emule&password=wrong-key",
        content_type="application/x-www-form-urlencoded",
    )
    assert int(qbit_bad_login["status"]) == 200, compact_http_result(qbit_bad_login)
    assert str(qbit_bad_login.get("body_text") or "") == "Fails.", compact_http_result(qbit_bad_login)
    assert "SID=" not in get_response_header(qbit_bad_login, "Set-Cookie"), compact_http_result(qbit_bad_login)

    login_form = urllib.parse.urlencode({"username": "emule", "password": api_key})
    qbit_login = http_request(
        base_url,
        "/api/v2/auth/login",
        method="POST",
        raw_body=login_form,
        content_type="application/x-www-form-urlencoded",
    )
    assert int(qbit_login["status"]) == 200, compact_http_result(qbit_login)
    assert str(qbit_login.get("body_text") or "") == "Ok.", compact_http_result(qbit_login)
    session_cookie = get_response_header(qbit_login, "Set-Cookie")
    assert "SID=" in session_cookie, compact_http_result(qbit_login)
    cookie_pair = session_cookie.split(";", 1)[0]

    qbit_categories = http_request(
        base_url,
        "/api/v2/torrents/categories",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_categories["status"]) == 200, compact_http_result(qbit_categories)
    assert isinstance(qbit_categories.get("json"), dict), compact_http_result(qbit_categories)
    assert "Default" in qbit_categories["json"], compact_http_result(qbit_categories)

    qbit_duplicate_query = http_request(
        base_url,
        "/api/v2/torrents/info?category=Movies&category=TV",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_duplicate_query["status"]) == 400, compact_http_result(qbit_duplicate_query)

    qbit_info = http_request(
        base_url,
        "/api/v2/torrents/info",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_info["status"]) == 200, compact_http_result(qbit_info)
    assert isinstance(qbit_info.get("json"), list), compact_http_result(qbit_info)

    qbit_add_category = "REST-QBIT-SMOKE"
    qbit_add_form = urllib.parse.urlencode(
        {
            "urls": (
                "magnet:?xt=urn:btih:"
                f"{REST_SURFACE_QBIT_DOWNLOAD_HASH}00000000"
                "&dn=qbit-rest-smoke.bin"
                "&xl=1024"
            ),
            "category": qbit_add_category,
            "stopped": "true",
        }
    )
    qbit_add_valid = http_request(
        base_url,
        "/api/v2/torrents/add",
        method="POST",
        raw_body=qbit_add_form,
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    require_qbit_ok_text(qbit_add_valid, "qBit add valid")
    qbit_info_after_add = http_request(
        base_url,
        "/api/v2/torrents/info",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    qbit_info_after_add_rows = require_qbit_json_array(qbit_info_after_add, "qBit info after add")
    qbit_added_row = find_qbit_info_row(qbit_info_after_add_rows, REST_SURFACE_QBIT_DOWNLOAD_HASH)

    qbit_info_added_category = http_request(
        base_url,
        "/api/v2/torrents/info?category=" + urllib.parse.quote(qbit_add_category),
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    qbit_info_added_category_rows = require_qbit_json_array(qbit_info_added_category, "qBit info added category")
    qbit_added_category_row = find_qbit_info_row(qbit_info_added_category_rows, REST_SURFACE_QBIT_DOWNLOAD_HASH)

    qbit_properties_added = http_request(
        base_url,
        f"/api/v2/torrents/properties?hash={REST_SURFACE_QBIT_DOWNLOAD_HASH}",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    qbit_properties_added_payload = require_qbit_json_object(qbit_properties_added, "qBit properties after add")

    qbit_files_added = http_request(
        base_url,
        f"/api/v2/torrents/files?hash={REST_SURFACE_QBIT_DOWNLOAD_HASH}",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    qbit_files_added_payload = require_qbit_json_array(qbit_files_added, "qBit files after add")

    qbit_delete_added = http_request(
        base_url,
        "/api/v2/torrents/delete",
        method="POST",
        raw_body=f"hashes={REST_SURFACE_QBIT_DOWNLOAD_HASH}&deleteFiles=true",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    require_qbit_ok_text(qbit_delete_added, "qBit delete added")

    qbit_info_after_delete = http_request(
        base_url,
        "/api/v2/torrents/info",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    qbit_info_after_delete_rows = require_qbit_json_array(qbit_info_after_delete, "qBit info after delete")
    qbit_properties_after_delete = http_request(
        base_url,
        f"/api/v2/torrents/properties?hash={REST_SURFACE_QBIT_DOWNLOAD_HASH}",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )
    qbit_files_after_delete = http_request(
        base_url,
        f"/api/v2/torrents/files?hash={REST_SURFACE_QBIT_DOWNLOAD_HASH}",
        extra_headers={"Cookie": cookie_pair},
        request_timeout_seconds=30.0,
    )

    assert qbit_added_row is not None, compact_http_result(qbit_info_after_add)
    assert qbit_added_row.get("category") == qbit_add_category, qbit_added_row
    assert qbit_added_row.get("name") == "qbit-rest-smoke.bin", qbit_added_row
    assert qbit_added_category_row is not None, compact_http_result(qbit_info_added_category)
    assert qbit_properties_added_payload.get("hash") == REST_SURFACE_QBIT_DOWNLOAD_HASH, qbit_properties_added_payload
    assert qbit_files_added_payload and isinstance(qbit_files_added_payload[0], dict), qbit_files_added_payload
    assert qbit_files_added_payload[0].get("name") == "qbit-rest-smoke.bin", qbit_files_added_payload
    assert find_qbit_info_row(qbit_info_after_delete_rows, REST_SURFACE_QBIT_DOWNLOAD_HASH) is None, compact_http_result(
        qbit_info_after_delete
    )
    assert int(qbit_properties_after_delete["status"]) == 404, compact_http_result(qbit_properties_after_delete)
    assert int(qbit_files_after_delete["status"]) == 404, compact_http_result(qbit_files_after_delete)

    qbit_bad_category_filter = http_request(
        base_url,
        "/api/v2/torrents/info?category=bad%01name",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_bad_category_filter["status"]) == 400, compact_http_result(qbit_bad_category_filter)

    qbit_properties_missing = http_request(
        base_url,
        f"/api/v2/torrents/properties?hash={REST_SURFACE_MISSING_HASH}",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_properties_missing["status"]) == 404, compact_http_result(qbit_properties_missing)

    qbit_files_missing = http_request(
        base_url,
        f"/api/v2/torrents/files?hash={REST_SURFACE_MISSING_HASH}",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_files_missing["status"]) == 404, compact_http_result(qbit_files_missing)

    qbit_properties_bad_hash = http_request(
        base_url,
        "/api/v2/torrents/properties?hash=bad",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_properties_bad_hash["status"]) == 400, compact_http_result(qbit_properties_bad_hash)

    qbit_files_duplicate_hash = http_request(
        base_url,
        f"/api/v2/torrents/files?hash={REST_SURFACE_MISSING_HASH}&hash={REST_SURFACE_VALID_DOWNLOAD_HASH}",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_files_duplicate_hash["status"]) == 400, compact_http_result(qbit_files_duplicate_hash)

    qbit_bad_form = http_request(
        base_url,
        "/api/v2/torrents/createCategory",
        method="POST",
        raw_body="=bad",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_bad_form["status"]) == 400, compact_http_result(qbit_bad_form)

    qbit_json_content_type = http_request(
        base_url,
        "/api/v2/torrents/add",
        method="POST",
        raw_body='{"urls":"not-a-link"}',
        content_type="application/json",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_json_content_type["status"]) == 400, compact_http_result(qbit_json_content_type)

    qbit_bad_add = http_request(
        base_url,
        "/api/v2/torrents/add",
        method="POST",
        raw_body="urls=not-a-link",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_bad_add["status"]) == 400, compact_http_result(qbit_bad_add)

    qbit_bad_paused_boolean = http_request(
        base_url,
        "/api/v2/torrents/add",
        method="POST",
        raw_body=(
            "paused=maybe&urls=magnet%3A%3Fxt%3Durn%3Abtih%3A"
            f"{REST_SURFACE_MISSING_HASH}00000000%26dn%3Dlinux.iso%26xl%3D42"
        ),
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_bad_paused_boolean["status"]) == 400, compact_http_result(qbit_bad_paused_boolean)

    synthetic_magnet = (
        "urls=magnet%3A%3Fxt%3Durn%3Abtih%3A"
        f"{REST_SURFACE_MISSING_HASH}00000000%26dn%3Dlinux.iso%26xl%3D0"
    )
    qbit_bad_synthetic_magnet = http_request(
        base_url,
        "/api/v2/torrents/add",
        method="POST",
        raw_body=synthetic_magnet,
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_bad_synthetic_magnet["status"]) == 400, compact_http_result(qbit_bad_synthetic_magnet)

    qbit_missing_hash_form = f"hashes={REST_SURFACE_MISSING_HASH}"
    qbit_pause_missing = http_request(
        base_url,
        "/api/v2/torrents/pause",
        method="POST",
        raw_body=qbit_missing_hash_form,
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_pause_missing["status"]) == 200, compact_http_result(qbit_pause_missing)

    qbit_resume_missing = http_request(
        base_url,
        "/api/v2/torrents/resume",
        method="POST",
        raw_body=qbit_missing_hash_form,
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_resume_missing["status"]) == 200, compact_http_result(qbit_resume_missing)

    qbit_stop_missing = http_request(
        base_url,
        "/api/v2/torrents/stop",
        method="POST",
        raw_body=qbit_missing_hash_form,
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_stop_missing["status"]) == 200, compact_http_result(qbit_stop_missing)

    qbit_start_missing = http_request(
        base_url,
        "/api/v2/torrents/start",
        method="POST",
        raw_body=qbit_missing_hash_form,
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_start_missing["status"]) == 200, compact_http_result(qbit_start_missing)

    qbit_delete_missing = http_request(
        base_url,
        "/api/v2/torrents/delete",
        method="POST",
        raw_body=f"{qbit_missing_hash_form}&deleteFiles=false",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_delete_missing["status"]) == 200, compact_http_result(qbit_delete_missing)

    qbit_delete_bad_boolean = http_request(
        base_url,
        "/api/v2/torrents/delete",
        method="POST",
        raw_body=f"{qbit_missing_hash_form}&deleteFiles=wat",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_delete_bad_boolean["status"]) == 400, compact_http_result(qbit_delete_bad_boolean)

    qbit_set_category_missing = http_request(
        base_url,
        "/api/v2/torrents/setCategory",
        method="POST",
        raw_body=f"{qbit_missing_hash_form}&category=Default",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_set_category_missing["status"]) == 400, compact_http_result(qbit_set_category_missing)

    qbit_set_force_start_bad_hash = http_request(
        base_url,
        "/api/v2/torrents/setForceStart",
        method="POST",
        raw_body="hashes=bad&value=true",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_set_force_start_bad_hash["status"]) == 400, compact_http_result(qbit_set_force_start_bad_hash)

    qbit_set_force_start_bad_boolean = http_request(
        base_url,
        "/api/v2/torrents/setForceStart",
        method="POST",
        raw_body=f"{qbit_missing_hash_form}&value=wat",
        content_type="application/x-www-form-urlencoded",
        extra_headers={"Cookie": cookie_pair},
    )
    assert int(qbit_set_force_start_bad_boolean["status"]) == 400, compact_http_result(qbit_set_force_start_bad_boolean)

    smoke["qbit"] = {
        "public_version": compact_http_result(qbit_public_version),
        "categories_unauthenticated": compact_http_result(qbit_categories_unauthenticated),
        "categories_wrong_cookie": compact_http_result(qbit_categories_wrong_cookie),
        "bad_login": compact_http_result(qbit_bad_login),
        "login": {
            "status": qbit_login["status"],
            "content_type": qbit_login.get("content_type"),
            "has_session_cookie": bool(cookie_pair),
        },
        "categories": compact_http_result(qbit_categories),
        "duplicate_query": compact_http_result(qbit_duplicate_query),
        "info": compact_http_result(qbit_info),
        "add_valid": compact_http_result(qbit_add_valid),
        "info_after_add": compact_http_result(qbit_info_after_add),
        "info_added_category": compact_http_result(qbit_info_added_category),
        "properties_added": compact_http_result(qbit_properties_added),
        "files_added": compact_http_result(qbit_files_added),
        "delete_added": compact_http_result(qbit_delete_added),
        "info_after_delete": compact_http_result(qbit_info_after_delete),
        "properties_after_delete": compact_http_result(qbit_properties_after_delete),
        "files_after_delete": compact_http_result(qbit_files_after_delete),
        "bad_category_filter": compact_http_result(qbit_bad_category_filter),
        "properties_missing": compact_http_result(qbit_properties_missing),
        "files_missing": compact_http_result(qbit_files_missing),
        "properties_bad_hash": compact_http_result(qbit_properties_bad_hash),
        "files_duplicate_hash": compact_http_result(qbit_files_duplicate_hash),
        "bad_form": compact_http_result(qbit_bad_form),
        "json_content_type": compact_http_result(qbit_json_content_type),
        "bad_add": compact_http_result(qbit_bad_add),
        "bad_paused_boolean": compact_http_result(qbit_bad_paused_boolean),
        "bad_synthetic_magnet": compact_http_result(qbit_bad_synthetic_magnet),
        "pause_missing": compact_http_result(qbit_pause_missing),
        "resume_missing": compact_http_result(qbit_resume_missing),
        "stop_missing": compact_http_result(qbit_stop_missing),
        "start_missing": compact_http_result(qbit_start_missing),
        "delete_missing": compact_http_result(qbit_delete_missing),
        "delete_bad_boolean": compact_http_result(qbit_delete_bad_boolean),
        "set_category_missing": compact_http_result(qbit_set_category_missing),
        "set_force_start_bad_hash": compact_http_result(qbit_set_force_start_bad_hash),
        "set_force_start_bad_boolean": compact_http_result(qbit_set_force_start_bad_boolean),
    }

    return smoke


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


def did_rest_listener_disappear(observation_rows: object) -> bool:
    """Reports whether server-connect observation rows show REST listener loss."""

    if not isinstance(observation_rows, list):
        return False
    for row in observation_rows:
        if not isinstance(row, dict):
            continue
        transport_error = row.get("transport_error")
        if not isinstance(transport_error, dict):
            continue
        message = str(transport_error.get("message") or "")
        if "actively refused" in message or "forcibly closed" in message:
            return True
    return False


def close_app_cleanly_with_timing(app: object, close_func=close_app_cleanly) -> dict[str, object]:
    """Closes the live app and returns bounded shutdown timing evidence."""

    start = time.monotonic()
    close_func(app)
    return {
        "app_closed": True,
        "shutdown_duration_ms": round((time.monotonic() - start) * 1000.0, 3),
    }


def restart_app_after_churn(
    app: object,
    *,
    app_exe: Path,
    profile_base: Path,
    base_url: str,
    api_key: str,
    rest_ready_timeout_seconds: float,
    close_func=close_app_cleanly,
    launch_func=launch_app,
    wait_main_window_func=wait_for_main_window,
    wait_ready_func=None,
    get_pid_func=get_app_process_id,
    snapshot_func=get_process_resource_snapshot,
) -> tuple[object, dict[str, object]]:
    """Stops and relaunches the same live profile after REST churn."""

    if wait_ready_func is None:
        wait_ready_func = wait_for_rest_ready

    old_process_id = get_pid_func(app)
    before_shutdown = snapshot_func(old_process_id)
    shutdown = close_app_cleanly_with_timing(app, close_func=close_func)
    relaunched_app = launch_func(app_exe, profile_base)
    new_process_id = get_pid_func(relaunched_app)
    after_relaunch = snapshot_func(new_process_id)
    main_window = wait_main_window_func(relaunched_app)
    ready = wait_ready_func(base_url, api_key, rest_ready_timeout_seconds)

    return relaunched_app, {
        "old_process_id": old_process_id,
        "new_process_id": new_process_id,
        "same_process_id_reused": old_process_id is not None
        and new_process_id is not None
        and int(old_process_id) == int(new_process_id),
        "shutdown": shutdown,
        "main_window_title": main_window.window_text(),
        "ready": compact_http_result(ready),
        "snapshots": {
            "before_shutdown": before_shutdown,
            "after_relaunch": after_relaunch,
        },
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


def build_search_plan(
    server_search_count: int,
    kad_search_count: int,
    search_terms: tuple[str, ...],
) -> list[dict[str, object]]:
    """Builds one deterministic multi-search plan for the requested network counts."""

    if not search_terms:
        raise RuntimeError("Live search plan requires at least one configured search term.")
    plan: list[dict[str, object]] = []
    for index in range(server_search_count):
        plan.append(
            {
                "network": "server",
                "query": search_terms[index % len(search_terms)],
                "query_index": index % len(search_terms),
                "ordinal": index + 1,
            }
        )
    for index in range(kad_search_count):
        plan.append(
            {
                "network": "kad",
                "query": search_terms[index % len(search_terms)],
                "query_index": index % len(search_terms),
                "ordinal": index + 1,
            }
        )
    return plan


def summarize_search_plan(search_plan: list[dict[str, object]]) -> list[dict[str, object]]:
    """Returns a report-safe search plan summary without exact runtime terms."""

    return [
        {
            "network": row.get("network"),
            "query_index": row.get("query_index"),
            "ordinal": row.get("ordinal"),
        }
        for row in search_plan
    ]


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
                "type": "",
            },
        )
        attempt = {
            "method": method_name,
            "response": response,
        }
        attempts.append(attempt)
        if int(response["status"]) == 200 and isinstance(response["json"], dict) and response["json"].get("id"):
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
                f"/api/v1/servers/{candidate['address']}:{candidate['port']}/operations/connect",
                method="POST",
                api_key=api_key,
                json_body={},
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
        if did_rest_listener_disappear(settle.get("observations")):
            raise RuntimeError(f"REST listener disappeared during live server connect. Attempts: {attempts!r}")
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


def is_lowercase_md4_hash(value: object) -> bool:
    """Returns true when one public hash token is the strict REST lowercase MD4 shape."""

    if not isinstance(value, str) or len(value) != 32:
        return False
    return all(("0" <= ch <= "9") or ("a" <= ch <= "f") for ch in value)


def is_safe_live_download_result(result_row: object) -> bool:
    """Rejects unsafe or incomplete live search rows before triggering a paused download."""

    if not isinstance(result_row, dict):
        return False
    file_name = str(result_row.get("name") or "").strip().lower()
    file_type = str(result_row.get("fileType") or "").strip().lower()
    size_bytes = result_row.get("sizeBytes", result_row.get("size"))
    sources = result_row.get("sources")
    if not file_name or file_name.endswith(UNSAFE_LIVE_DOWNLOAD_SUFFIXES) or file_type in {"arc", "archive", "program", "pro"}:
        return False
    if not isinstance(sources, int) or isinstance(sources, bool) or sources < MIN_SAFE_LIVE_DOWNLOAD_SOURCES:
        return False
    if not is_lowercase_md4_hash(result_row.get("hash")):
        return False
    return (
        isinstance(size_bytes, int)
        and not isinstance(size_bytes, bool)
        and 0 < size_bytes <= MAX_SAFE_LIVE_DOWNLOAD_BYTES
    )


def find_safe_live_download_result(search_payload: dict[str, Any]) -> dict[str, Any] | None:
    """Selects the first search result safe enough for the paused-download trigger."""

    results = search_payload.get("results")
    if not isinstance(results, list):
        return None
    for result_row in results:
        if is_safe_live_download_result(result_row):
            assert isinstance(result_row, dict)
            return result_row
    return None


def wait_for_triggered_transfer(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Polls until a download trigger is visible through the native transfer API."""

    deadline = time.time() + timeout_seconds
    last_status: int | None = None
    while time.time() < deadline:
        result = http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash}",
            api_key=api_key,
            request_timeout_seconds=timeout_seconds,
        )
        last_status = int(result["status"])
        if last_status != 200:
            time.sleep(1.0)
            continue
        payload = require_json_object(result, 200)
        if payload.get("hash") != transfer_hash:
            raise AssertionError(f"Triggered transfer hash mismatch: expected {transfer_hash!r}, got {payload.get('hash')!r}")
        return compact_http_result(result)

    raise RuntimeError(
        "Timed out waiting for triggered transfer materialization. "
        f"transfer_hash={transfer_hash!r}; last_status={last_status!r}"
    )


def trigger_paused_download_from_search_result(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Polls for one safe live search result and triggers it as a paused download."""

    observations: list[dict[str, object]] = []
    selected_candidate: dict[str, object] | None = None

    def resolve():
        nonlocal selected_candidate
        result = http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            return None
        payload = require_json_object(result, 200)
        candidate = find_safe_live_download_result(payload)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "status": payload.get("status"),
                "result_count": len(payload.get("results") or []),
                "has_candidate": candidate is not None,
            }
        )
        if candidate is None:
            return None
        selected_candidate = {
            "hash_present": bool(candidate.get("hash")),
            "name_present": bool(candidate.get("name")),
            "sizeBytes": candidate.get("sizeBytes", candidate.get("size")),
            "fileType": candidate.get("fileType"),
            "sources": candidate.get("sources"),
            "completeSources": candidate.get("completeSources"),
        }
        download = http_request(
            base_url,
            f"/api/v1/searches/{search_id}/results/{candidate['hash']}/operations/download",
            method="POST",
            api_key=api_key,
            json_body={"paused": True, "categoryId": 0},
            request_timeout_seconds=timeout_seconds,
        )
        require_json_object(download, 200)
        transfer = wait_for_triggered_transfer(
            base_url,
            api_key,
            str(candidate["hash"]),
            timeout_seconds,
        )
        return {
            "ok": int(download["status"]) == 200,
            "searchId": search_id,
            "candidate": selected_candidate,
            "download": {"status": download.get("status")},
            "transfer": transfer,
            "observations": observations,
        }

    try:
        result = wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="safe live download candidate")
    except Exception as exc:
        if selected_candidate is None:
            return {
                "ok": False,
                "reason": "timed out without a safe download candidate",
                "observations": observations,
            }
        raise RuntimeError(
            "Timed out or failed while triggering a safe live download candidate. "
            f"selected_candidate={selected_candidate!r}; observations={observations!r}; cause={type(exc).__name__}: {exc}"
        ) from exc
    assert isinstance(result, dict)
    return result


def stop_live_search(base_url: str, api_key: str, search_id: str) -> dict[str, object]:
    """Stops one live search and returns the raw REST response."""

    return http_request(
        base_url,
        f"/api/v1/searches/{search_id}",
        method="DELETE",
        api_key=api_key,
        json_body={},
    )


def delete_all_searches(base_url: str, api_key: str) -> dict[str, object]:
    """Deletes every live search tab through the explicit destructive REST route."""

    return http_request(
        base_url,
        "/api/v1/searches",
        method="DELETE",
        api_key=api_key,
        json_body={"confirmDeleteAllSearches": True},
    )


def verify_searches_deleted(base_url: str, api_key: str, search_ids: list[str]) -> dict[str, object]:
    """Verifies that all supplied live search ids are gone after delete-all."""

    probes: list[dict[str, object]] = []
    for search_id in search_ids:
        result = http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        probes.append(
            {
                "searchId": search_id,
                "response": compact_http_result(result),
            }
        )
        require_error_response(result, 404, "NOT_FOUND", message_contains="search not found")
    return {
        "checked": len(search_ids),
        "probes": probes,
    }


def clear_completed_transfers(base_url: str, api_key: str) -> dict[str, object]:
    """Clears completed transfers through the explicit native REST confirmation route."""

    return http_request(
        base_url,
        "/api/v1/transfers/operations/clear-completed",
        method="POST",
        api_key=api_key,
        json_body={"confirmClearCompleted": True},
    )


def clear_logs(base_url: str, api_key: str) -> dict[str, object]:
    """Clears retained UI logs through the explicit native REST confirmation route."""

    return http_request(
        base_url,
        "/api/v1/logs/operations/clear",
        method="POST",
        api_key=api_key,
        json_body={"confirmClearLogs": True},
    )


def extract_triggered_transfer_hashes(completed_cycles: list[dict[str, object]]) -> list[str]:
    """Extracts triggered transfer hashes captured during live search cycles."""

    hashes: list[str] = []
    for cycle in completed_cycles:
        trigger = cycle.get("download_trigger")
        if not isinstance(trigger, dict) or not bool(trigger.get("ok")):
            continue
        transfer = trigger.get("transfer")
        if not isinstance(transfer, dict):
            continue
        transfer_json = transfer.get("json")
        if not isinstance(transfer_json, dict):
            continue
        transfer_hash = transfer_json.get("hash")
        if isinstance(transfer_hash, str) and is_lowercase_md4_hash(transfer_hash):
            hashes.append(transfer_hash)
    return hashes


def verify_transfers_still_exist(base_url: str, api_key: str, transfer_hashes: list[str]) -> dict[str, object]:
    """Verifies that named transfers remain visible after a safe no-op mutation."""

    probes: list[dict[str, object]] = []
    for transfer_hash in transfer_hashes:
        result = http_request(base_url, f"/api/v1/transfers/{transfer_hash}", api_key=api_key)
        body = require_json_object(result, 200)
        assert body.get("hash") == transfer_hash, compact_http_result(result)
        probes.append(
            {
                "hash": transfer_hash,
                "response": compact_http_result(result),
            }
        )
    return {
        "checked": len(transfer_hashes),
        "probes": probes,
    }


def execute_search_plan(
    base_url: str,
    api_key: str,
    search_plan: list[dict[str, object]],
    observation_timeout_seconds: float,
    *,
    search_method_override: str | None,
    live_download_trigger_count: int,
) -> tuple[list[dict[str, object]], str | None]:
    """Runs one deterministic search plan and returns completed cycle artifacts."""

    completed_cycles: list[dict[str, object]] = []
    active_search_id: str | None = None
    remaining_download_triggers = live_download_trigger_count

    for cycle_index, cycle_plan in enumerate(search_plan, start=1):
        network = str(cycle_plan["network"])
        query = str(cycle_plan["query"])
        query_index = int(cycle_plan.get("query_index", cycle_index - 1))
        cycle_report: dict[str, object] = {
            "cycle_index": cycle_index,
            "network": network,
            "query_index": query_index,
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
            active_search_id = str(search_payload["id"])
            cycle_report["searchId"] = active_search_id
            cycle_report["selected_method"] = live_search["selected_method"]

            try:
                cycle_report["activity"] = wait_for_search_observation(
                    base_url,
                    api_key,
                    active_search_id,
                    observation_timeout_seconds,
                )
                if remaining_download_triggers > 0:
                    download_trigger = trigger_paused_download_from_search_result(
                        base_url,
                        api_key,
                        active_search_id,
                        observation_timeout_seconds,
                    )
                    cycle_report["download_trigger"] = download_trigger
                    if bool(download_trigger.get("ok")):
                        remaining_download_triggers -= 1
            finally:
                if active_search_id is not None:
                    try:
                        stop_result = stop_live_search(base_url, api_key, active_search_id)
                        cycle_report["stop"] = compact_http_result(stop_result)
                        assert int(stop_result["status"]) == 200
                        assert isinstance(stop_result["json"], dict)
                    except Exception as exc:
                        cycle_report["stop_error"] = {
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
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
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="rest-smoke-test-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--webserver-scheme", choices=["http", "https"], default="http")
    parser.add_argument("--enable-upnp", action="store_true", default=True)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--server-activity-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--server-search-count", type=int, default=0)
    parser.add_argument("--kad-search-count", type=int, default=0)
    parser.add_argument("--search-method-override", choices=["automatic", "server", "global", "kad"])
    parser.add_argument("--live-download-trigger-count", type=int, default=DEFAULT_LIVE_DOWNLOAD_TRIGGER_COUNT)
    parser.add_argument("--rest-coverage-budget", choices=REST_COVERAGE_BUDGETS, default="contract")
    parser.add_argument("--skip-rest-contract-completeness", action="store_true")
    parser.add_argument("--rest-stress-budget", choices=REST_STRESS_BUDGETS, default="off")
    parser.add_argument("--rest-stress-duration-seconds", type=float, default=30.0)
    parser.add_argument("--rest-stress-concurrency", type=int, default=4)
    parser.add_argument("--rest-stress-max-failures", type=int, default=1)
    parser.add_argument("--rest-stress-request-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--rest-socket-adversity-budget", choices=REST_SOCKET_ADVERSITY_BUDGETS, default="off")
    parser.add_argument("--rest-tls-handshake-adversity-budget", choices=REST_TLS_HANDSHAKE_ADVERSITY_BUDGETS, default="off")
    parser.add_argument("--rest-leak-churn-budget", choices=REST_LEAK_CHURN_BUDGETS, default="off")
    parser.add_argument("--rest-leak-churn-cycles", type=int)
    parser.add_argument("--rest-stop-start-after-churn", action="store_true")
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)),
    )
    args = parser.parse_args()
    if args.server_search_count < 0 or args.kad_search_count < 0:
        raise ValueError("Search counts must be zero or greater.")
    if args.live_download_trigger_count < 0:
        raise ValueError("Live download trigger count must be zero or greater.")
    if args.rest_stop_start_after_churn and args.rest_leak_churn_budget == "off":
        raise ValueError("REST stop/start after churn requires --rest-leak-churn-budget.")
    effective_stress_budget = (
        "smoke"
        if args.rest_coverage_budget == "contract-stress" and args.rest_stress_budget == "off"
        else args.rest_stress_budget
    )
    validate_rest_stress_config(
        budget=effective_stress_budget,
        duration_seconds=args.rest_stress_duration_seconds,
        concurrency=args.rest_stress_concurrency,
        max_failures=args.rest_stress_max_failures,
        request_timeout_seconds=args.rest_stress_request_timeout_seconds,
    )
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    search_terms = inputs.generic_open_terms

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
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    artifacts_dir = paths.source_artifacts_dir

    port = choose_listen_port()
    base_url = f"{args.webserver_scheme}://127.0.0.1:{port}"
    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    https_material = (
        create_https_certificate_pair(artifacts_dir)
        if args.webserver_scheme == "https"
        else {"certificate": "", "key": ""}
    )
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
        use_https=(args.webserver_scheme == "https"),
        https_certificate=https_material["certificate"],
        https_key=https_material["key"],
    )
    if args.p2p_bind_interface_name:
        apply_p2p_bind_interface_override(
            Path(profile["config_dir"]),
            args.p2p_bind_interface_name,
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
            "webserver_scheme": args.webserver_scheme,
            "https_certificate": https_material["certificate"],
            "enable_upnp": True,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "keep_running": bool(args.keep_running),
            "server_search_count": args.server_search_count,
            "kad_search_count": args.kad_search_count,
            "live_download_trigger_count": args.live_download_trigger_count,
            "live_wire_inputs_file": str(inputs.path),
            "live_wire_search_terms": live_wire_inputs.summarize_terms(search_terms),
            "search_method_override": args.search_method_override,
            "rest_coverage_budget": args.rest_coverage_budget,
            "rest_contract_completeness_enabled": not args.skip_rest_contract_completeness,
            "rest_stress_budget": effective_stress_budget,
            "rest_stress_duration_seconds": args.rest_stress_duration_seconds,
            "rest_stress_concurrency": args.rest_stress_concurrency,
            "rest_socket_adversity_budget": args.rest_socket_adversity_budget,
            "rest_tls_handshake_adversity_budget": args.rest_tls_handshake_adversity_budget,
            "rest_leak_churn_budget": args.rest_leak_churn_budget,
            "rest_leak_churn_cycles": args.rest_leak_churn_cycles,
            "rest_stop_start_after_churn": bool(args.rest_stop_start_after_churn),
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
        launched_process_id = get_app_process_id(app)
        report["launched_process_id"] = launched_process_id
        report["resource_snapshots"] = {
            "after_launch": get_process_resource_snapshot(launched_process_id),
        }
        main_window = wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()

        current_phase = set_phase(report, "rest_ready")
        ready = wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["checks"]["ready"] = compact_http_result(ready)

        current_phase = set_phase(report, "nat_backend_order")
        report["checks"]["nat_backend_order"] = wait_for_upnp_backend_order(
            base_url,
            args.api_key,
            timeout_seconds=20.0,
        )

        current_phase = set_phase(report, "auth_checks")
        no_key = http_request(base_url, "/api/v1/app")
        require_error_response(no_key, 401, "UNAUTHORIZED")
        report["checks"]["missing_key"] = compact_http_result(no_key)

        wrong_key = http_request(base_url, "/api/v1/app", api_key="wrong-key")
        require_error_response(wrong_key, 401, "UNAUTHORIZED")
        report["checks"]["wrong_key"] = compact_http_result(wrong_key)

        current_phase = set_phase(report, "app_version")
        version = http_request(base_url, "/api/v1/app", api_key=args.api_key)
        assert version["status"] == 200
        assert isinstance(version["json"], dict)
        assert version["json"]["name"] == "eMule"
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

        current_phase = set_phase(report, "live_seed_imports")
        report["checks"]["live_seed_imports"] = exercise_live_seed_imports(
            base_url,
            args.api_key,
            seed_refresh,
            request_timeout_seconds=max(30.0, args.seed_download_timeout_seconds + 10.0),
        )

        current_phase = set_phase(report, "arr_adapters")
        report["checks"]["arr_adapters"] = exercise_arr_adapter_smoke(base_url, args.api_key)

        if args.rest_socket_adversity_budget != "off":
            current_phase = set_phase(report, "rest_socket_adversity")
            report["checks"]["rest_socket_adversity"] = exercise_rest_socket_adversity(
                base_url,
                args.api_key,
                budget=args.rest_socket_adversity_budget,
                request_timeout_seconds=args.rest_stress_request_timeout_seconds,
            )

        if args.rest_tls_handshake_adversity_budget != "off":
            current_phase = set_phase(report, "rest_tls_handshake_adversity")
            report["checks"]["rest_tls_handshake_adversity"] = exercise_rest_tls_handshake_adversity(
                base_url,
                budget=args.rest_tls_handshake_adversity_budget,
                request_timeout_seconds=args.rest_stress_request_timeout_seconds,
            )

        if args.rest_coverage_budget != "smoke" and not args.skip_rest_contract_completeness:
            current_phase = set_phase(report, "rest_contract")
            rest_contract = exercise_rest_contract_completeness(
                base_url,
                args.api_key,
                args.rest_coverage_budget,
            )
            assert rest_contract["ok"], rest_contract
            report["checks"]["rest_contract"] = rest_contract

        current_phase = set_phase(report, "shutdown_exclusion_audit")
        report["checks"]["shutdown_exclusion_audit"] = assert_shutdown_excluded_from_broad_mutation_loops()

        if effective_stress_budget != "off":
            current_phase = set_phase(report, "rest_stress")
            report["checks"]["rest_stress"] = exercise_rest_stress(
                base_url,
                args.api_key,
                budget=effective_stress_budget,
                duration_seconds=args.rest_stress_duration_seconds,
                concurrency=args.rest_stress_concurrency,
                max_failures=args.rest_stress_max_failures,
                request_timeout_seconds=args.rest_stress_request_timeout_seconds,
            )

        if args.rest_leak_churn_budget != "off":
            current_phase = set_phase(report, "rest_leak_churn")
            report["checks"]["rest_leak_churn"] = exercise_rest_leak_churn(
                base_url,
                args.api_key,
                process_id=launched_process_id,
                budget=args.rest_leak_churn_budget,
                cycles=args.rest_leak_churn_cycles,
                request_timeout_seconds=args.rest_stress_request_timeout_seconds,
            )

        if args.rest_stop_start_after_churn:
            current_phase = set_phase(report, "rest_stop_start_after_churn")
            old_app = app
            app = None
            app, report["checks"]["rest_stop_start_after_churn"] = restart_app_after_churn(
                old_app,
                app_exe=app_exe,
                profile_base=Path(profile["profile_base"]),
                base_url=base_url,
                api_key=args.api_key,
                rest_ready_timeout_seconds=args.rest_ready_timeout_seconds,
            )
            launched_process_id = get_app_process_id(app)
            report["relaunched_process_id"] = launched_process_id

        assert isinstance(report.get("resource_snapshots"), dict)
        report["resource_snapshots"]["after_rest_adversity_and_stress"] = get_process_resource_snapshot(
            launched_process_id
        )
        report["resource_deltas"] = {
            "launch_to_after_rest_adversity_and_stress": diff_process_resource_snapshots(
                report["resource_snapshots"]["after_launch"],
                report["resource_snapshots"]["after_rest_adversity_and_stress"],
            )
        }

        current_phase = set_phase(report, "rest_error_path_matrix")
        report["checks"]["rest_error_path_matrix"] = build_rest_error_path_matrix(report["checks"])
        require_rest_error_path_matrix(report["checks"]["rest_error_path_matrix"])

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
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=args.api_key,
            json_body={},
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
            "/api/v1/kad/operations/recheck-firewall",
            method="POST",
            api_key=args.api_key,
            json_body={},
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

        search_plan = build_search_plan(args.server_search_count, args.kad_search_count, search_terms)
        if not search_plan:
            search_plan = [
                {
                    "network": str(live_network["mode"]),
                    "query": search_terms[0],
                    "query_index": 0,
                    "ordinal": 1,
                }
            ]
        report["checks"]["search_plan"] = summarize_search_plan(search_plan)

        current_phase = set_phase(report, "search_cycles")
        completed_cycles, search_id = execute_search_plan(
            base_url,
            args.api_key,
            search_plan,
            args.search_observation_timeout_seconds,
            search_method_override=args.search_method_override,
            live_download_trigger_count=args.live_download_trigger_count,
        )
        report["checks"]["search_cycles"] = completed_cycles
        completed_download_triggers = sum(
            1
            for cycle in completed_cycles
            if isinstance(cycle.get("download_trigger"), dict) and bool(cycle["download_trigger"].get("ok"))
        )
        report["checks"]["live_download_triggers"] = {
            "requested": args.live_download_trigger_count,
            "completed": completed_download_triggers,
            "ok": completed_download_triggers >= args.live_download_trigger_count,
        }
        assert completed_download_triggers >= args.live_download_trigger_count, report["checks"]["live_download_triggers"]

        search_ids = [
            str(cycle["searchId"])
            for cycle in completed_cycles
            if isinstance(cycle.get("searchId"), str) and cycle.get("searchId")
        ]
        current_phase = set_phase(report, "delete_all_searches")
        delete_all_searches_result = delete_all_searches(base_url, args.api_key)
        require_json_object(delete_all_searches_result, 200)
        report["checks"]["delete_all_searches"] = {
            "searchIds": search_ids,
            "response": compact_http_result(delete_all_searches_result),
            "post_delete": verify_searches_deleted(base_url, args.api_key, search_ids),
        }

        triggered_transfer_hashes = extract_triggered_transfer_hashes(completed_cycles)
        current_phase = set_phase(report, "clear_completed_transfers")
        clear_completed_result = clear_completed_transfers(base_url, args.api_key)
        require_json_object(clear_completed_result, 200)
        report["checks"]["clear_completed_transfers"] = {
            "triggeredTransferHashes": triggered_transfer_hashes,
            "response": compact_http_result(clear_completed_result),
            "post_clear": verify_transfers_still_exist(base_url, args.api_key, triggered_transfer_hashes),
        }
        search_id = None

        current_phase = set_phase(report, "log_limit")
        log_entries = http_request(base_url, "/api/v1/logs?limit=1", api_key=args.api_key)
        assert log_entries["status"] == 200
        assert len(require_json_array(log_entries, 200)) <= 1
        report["checks"]["log_limit"] = compact_http_result(log_entries)

        current_phase = set_phase(report, "servers_disconnect")
        server_disconnect = http_request(
            base_url,
            "/api/v1/servers/operations/disconnect",
            method="POST",
            api_key=args.api_key,
            json_body={},
        )
        assert server_disconnect["status"] == 200
        assert isinstance(server_disconnect["json"], dict)
        report["checks"]["servers_disconnect"] = compact_http_result(server_disconnect)

        current_phase = set_phase(report, "kad_disconnect")
        kad_disconnect = http_request(
            base_url,
            "/api/v1/kad/operations/stop",
            method="POST",
            api_key=args.api_key,
            json_body={},
        )
        assert kad_disconnect["status"] == 200
        assert isinstance(kad_disconnect["json"], dict)
        assert "running" in kad_disconnect["json"]
        report["checks"]["kad_disconnect"] = compact_http_result(kad_disconnect)

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
                    cleanup.update(close_app_cleanly_with_timing(app))
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
