from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import urllib.parse

import pytest

from emule_test_harness import rust_rest_conformance
from emule_test_harness.rust_rest_contract import iter_downloads, iter_library_roots
from emule_test_harness.workspace_layout import resolve_selected_workspace_repo


def test_library_roots_follow_short_pages_without_skipping_id_gaps():
    calls = []
    def fetch(path):
        calls.append(path)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        assert query["limit"] == ["100"]
        if len(calls) == 1:
            return {"data": [{"id": "1"}], "meta": {"hasMore": True, "nextCursor": "opaque-next"}}
        assert query["cursor"] == ["opaque-next"]
        return {"data": [{"id": "7"}], "meta": {"hasMore": False, "nextCursor": None}}
    assert [row["id"] for row in iter_library_roots(fetch)] == ["1", "7"]
    assert len(calls) == 2


@pytest.mark.parametrize("document", [
    {"data": [], "meta": {"hasMore": True, "nextCursor": "next"}},
    {"data": [{"id": "01"}], "meta": {"hasMore": False, "nextCursor": None}},
    {"data": [{"id": "2"}, {"id": "1"}], "meta": {"hasMore": False, "nextCursor": None}},
    {"data": [{"id": "1"}] * 101, "meta": {"hasMore": False, "nextCursor": None}},
])
def test_library_roots_require_bounded_advancing_pages(document):
    with pytest.raises(RuntimeError):
        list(iter_library_roots(lambda path: document))


def test_download_pages_keep_full_width_ids_and_follow_short_pages():
    calls = []
    def fetch(path):
        calls.append(path)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        assert query["view"] == ["all"] and query["limit"] == ["200"]
        if len(calls) == 1:
            return {"data": [{"id": "9007199254740993"}, {"id": "7"}],
                    "meta": {"hasMore": True, "nextCursor": "opaque-next"}}
        assert query["cursor"] == ["opaque-next"]
        return {"data": [{"id": "1"}], "meta": {"hasMore": False, "nextCursor": None}}
    assert [row["id"] for row in iter_downloads(fetch)] == ["9007199254740993", "7", "1"]
    assert len(calls) == 2


@pytest.mark.parametrize("document", [
    {"data": [], "meta": {"hasMore": False}},
    {"data": [], "meta": {"hasMore": True, "nextCursor": "next"}},
    {"data": [{"id": "01"}], "meta": {"hasMore": False, "nextCursor": None}},
    {"data": [{"id": "1"}, {"id": "2"}], "meta": {"hasMore": False, "nextCursor": None}},
    {"data": [{"id": "9223372036854775808"}], "meta": {"hasMore": False, "nextCursor": None}},
    {"data": [{"id": "7"}] * 201, "meta": {"hasMore": False, "nextCursor": None}},
])
def test_download_pages_require_bounded_advancing_current_identities(document):
    with pytest.raises(RuntimeError):
        list(iter_downloads(lambda path: document))


def test_explicit_contract_load_does_not_override_operator_environment(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    selected = tmp_path / "selected.yaml"
    monkeypatch.setenv(rust_rest_conformance.OPENAPI_CONTRACT_ENV, "operator-value")
    observed = {}
    def loader(*args, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace()
    monkeypatch.setattr(rust_rest_conformance, "load_script_module", loader)
    rust_rest_conformance.load_rest_smoke_module(selected)
    assert observed["initial_globals"]["SELECTED_OPENAPI_CONTRACT_PATH"] == selected
    assert os.environ[rust_rest_conformance.OPENAPI_CONTRACT_ENV] == "operator-value"


def test_explicit_contract_reaches_response_and_sse_checks(tmp_path, monkeypatch):
    selected = tmp_path / "selected.yaml"
    observed = []
    smoke = SimpleNamespace(exercise_rest_contract_completeness=lambda *args: {"ok": True})
    monkeypatch.setattr(rust_rest_conformance, "load_rest_smoke_module", lambda path: observed.append(path) or smoke)
    def sse(*args, **kwargs):
        observed.append(kwargs["openapi_path"])
        return {"ok": True}
    monkeypatch.setattr(rust_rest_conformance, "run_event_stream_conformance", sse)
    assert rust_rest_conformance.run_response_conformance("http://127.0.0.1:4711", "test-key", openapi_path=selected)["ok"]
    assert observed == [selected, selected]


class FakeEventStreamResponse:
    def __init__(
        self,
        lines: list[bytes],
        *,
        status: int = 200,
        content_type: str = "text/event-stream",
        headers: dict[str, str] | None = None,
    ):
        self._lines = list(lines)
        self.status = status
        self.headers = {
            "Content-Type": content_type,
            "Cache-Control": "no-cache, no-transform",
            "X-Contract-Version": "2.0.0",
            "X-Accel-Buffering": "no",
            **(headers or {}),
        }

    def __enter__(self) -> "FakeEventStreamResponse":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def readline(self) -> bytes:
        if not self._lines:
            return b""
        return self._lines.pop(0)


def test_run_response_conformance_invokes_rest_contract_budget() -> None:
    calls: list[tuple[str, str, str]] = []
    event_calls: list[tuple[str, str]] = []

    def exercise(base_url: str, api_key: str, budget: str) -> dict[str, object]:
        calls.append((base_url, api_key, budget))
        return {"ok": True, "failed_routes": []}

    def event_stream(base_url: str, api_key: str) -> dict[str, object]:
        event_calls.append((base_url, api_key))
        return {"ok": True, "operationId": "getEvents"}

    summary = rust_rest_conformance.run_response_conformance(
        "http://127.0.0.1:4711",
        "test-key",
        budget="contract-stress",
        rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
        event_stream_checker=event_stream,
    )

    assert summary["ok"] is True
    assert calls == [("http://127.0.0.1:4711", "test-key", "contract-stress")]
    assert event_calls == [("http://127.0.0.1:4711", "test-key")]
    assert summary["event_stream"] == {"ok": True, "operationId": "getEvents"}


def test_load_rest_smoke_module_pins_rust_openapi_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, str | None] = {}
    monkeypatch.delenv(rust_rest_conformance.OPENAPI_CONTRACT_ENV, raising=False)

    def load_script_module(_module_name: str, _filename: str, **kwargs) -> object:
        observed["during_load"] = str(kwargs["initial_globals"]["SELECTED_OPENAPI_CONTRACT_PATH"])
        return SimpleNamespace()

    monkeypatch.setattr(rust_rest_conformance, "load_script_module", load_script_module)

    rust_rest_conformance.load_rest_smoke_module()

    assert observed["during_load"] == str(
        rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH
    )
    assert (
        rust_rest_conformance.OPENAPI_CONTRACT_ENV
        not in os.environ
    )


def test_load_rest_smoke_module_restores_existing_openapi_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, str | None] = {}
    monkeypatch.setenv(
        rust_rest_conformance.OPENAPI_CONTRACT_ENV, "operator-contract.yaml"
    )

    def load_script_module(_module_name: str, _filename: str, **kwargs) -> object:
        observed["during_load"] = str(kwargs["initial_globals"]["SELECTED_OPENAPI_CONTRACT_PATH"])
        return SimpleNamespace()

    monkeypatch.setattr(rust_rest_conformance, "load_script_module", load_script_module)

    rust_rest_conformance.load_rest_smoke_module()

    assert observed["during_load"] == str(
        rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH
    )
    assert (
        os.environ[rust_rest_conformance.OPENAPI_CONTRACT_ENV]
        == "operator-contract.yaml"
    )


def test_rust_openapi_network_tags_are_mapped_to_rest_families() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()

    assert module.RUST_CONTRACT_ONLY is True
    assert module.live_common is None
    assert module.kernel32 is None
    assert module.OPENAPI_TAG_FAMILIES["Network"] == "network"
    assert module.OPENAPI_TAG_FAMILIES["Nat"] == "nat"
    assert module.OPENAPI_TAG_FAMILIES["VpnGuard"] == "vpn-guard"
    assert module.OPENAPI_TAG_FAMILIES["IpFilter"] == "ip-filter"


def test_rust_library_routes_use_resource_ids_and_current_body_shapes() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    routes = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}
    assert routes["createLibraryRoot"]["path"] == "/api/v1/library/roots"
    for operation in ("getLibraryRoot", "updateLibraryRoot", "deleteLibraryRoot"):
        assert routes[operation]["path"] == "/api/v1/library/roots/9223372036854775807"
        assert module.normalize_contract_path_for_openapi(routes[operation]["path"]) == "/library/roots/{id}"
    assert module.get_contract_route_body("createLibraryRoot") == {}
    assert module.get_contract_route_body("updateLibraryRoot") == {"watchEnabled": False}
    assert routes["removeSharedFileIgnorePattern"]["path"] == (
        "/api/v1/library/ignores?" + urllib.parse.urlencode({"pattern": "rest-contract-ignored-*.bin"}))
    assert routes["updateSharedFileIgnoreRule"]["path"] == "/api/v1/library/ignores/defaults/noise.desktop-ini"
    assert module.assert_contract_routes_match_openapi()["ok"] is True
    assert module.get_contract_route_body("addSharedFileIgnorePattern") == {"pattern": "rest-contract-ignored-*.bin"}
    assert module.get_contract_route_body("updateSharedFileIgnoreRule") == {"enabled": True}


def test_rust_category_contract_uses_name_paths_and_nullable_download_body() -> None:
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    openapi = tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    module = rust_rest_conformance.load_rest_smoke_module(openapi)
    routes = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}
    for operation_id in ("getCategory", "patchCategory", "deleteCategory"):
        route = routes[operation_id]
        assert route["path"] == "/api/v1/categories/MissingCategory"
        assert route["openapiPath"] == "/categories/{categoryName}"
        assert module.normalize_contract_path_for_openapi(route["path"]) == route["openapiPath"]
    report = module.assert_contract_routes_match_openapi()
    assert report["ok"] is True, json.dumps(report, sort_keys=True)
    assert module.get_contract_route_body("patchCategory") == {"comment": "REST contract"}
    assert module.get_contract_route_body("downloadSearchResult") == {
        "intent": "stopped", "category": None,
    }


def test_rust_download_path_uses_public_job_id() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    path = module.concrete_contract_path("/downloads/{id}/parts", "listDownloadParts")
    assert path == "/api/v1/downloads/9223372036854775807/parts"
    assert module.normalize_contract_path_for_openapi(path) == "/downloads/{id}/parts"


def test_rust_download_contract_uses_explicit_id_action_bodies() -> None:
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    openapi = tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    module = rust_rest_conformance.load_rest_smoke_module(openapi)
    routes = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}
    assert routes["getDownload"]["path"] == "/api/v1/downloads/9223372036854775807"
    assert routes["startDownloads"]["successResponseStatuses"] == ["207"]
    missing = rust_rest_conformance.RUST_MISSING_DOWNLOAD_ID
    assert module.get_contract_route_body("createDownload") == {}
    assert module.get_contract_route_body("patchDownload") == {"category": None}
    for action in ("startDownloads", "stopDownloads", "verifyDownloads"):
        assert module.get_contract_route_body(action) == {"ids": [missing]}
    assert module.get_contract_route_body("removeDownloads") == {
        "ids": [missing], "deleteData": False,
    }
    assert module.REST_CONTRACT_EXPECTED_ERROR_STATUSES["getDownload"] == (404,)


def test_diagnostic_bundle_contract_body_uses_minimum_bounded_capture() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()

    assert module.get_contract_route_body("captureDiagnosticBundle") == {
        "confirmCapture": True,
        "maxBytes": 65_536,
    }


def test_library_point_probes_have_valid_bodies_and_require_missing_hash_response() -> None:
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    module = rust_rest_conformance.load_rest_smoke_module(
        tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    routes = {row["operationId"]: row for row in module.REST_CONTRACT_ROUTES}
    base_path = "/api/v1/library/files/0123456789abcdef0123456789abcdef"
    for operation, suffix, success in (
        ("getLibraryFile", "", "200"),
        ("patchLibraryFile", "", "204"),
        ("listLibraryFileLocations", "/locations", "200"),
    ):
        assert routes[operation]["path"] == base_path + suffix
        assert routes[operation]["successResponseStatuses"] == [success]
        assert module.REST_CONTRACT_EXPECTED_ERROR_STATUSES[operation] == (404,)
    report = module.assert_contract_routes_match_openapi()
    assert report["ok"] is True, json.dumps(report, sort_keys=True)
    assert module.get_contract_route_body("patchLibraryFile") == {"uploadPriority": "normal"}


def test_rust_openapi_live_disruptive_operations_are_unsafe() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    routes_by_operation = {
        route["operationId"]: route for route in module.REST_CONTRACT_ROUTES
    }

    for operation_id in {
        "captureDiagnosticBundle",
        "refreshNat",
        "probeVpnGuard",
        "scanLibrary",
        "connectServerAny",
        "disconnectServers",
        "connectServer",
        "startKad",
        "stopKad",
        "bootstrapKad",
        "recheckKadFirewall",
        "deleteSearches",
        "reloadIpFilter",
        "clearLogs",
    }:
        assert routes_by_operation[operation_id]["safe"] is False
        assert routes_by_operation[operation_id]["safety"] == "unsafe"


def test_rust_openapi_download_schema_separates_job_and_delivery_identity() -> None:
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    openapi = tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    module = rust_rest_conformance.load_rest_smoke_module(openapi)
    schemas = module.load_openapi_document()["components"]["schemas"]
    download = schemas["Download"]
    assert download["properties"]["id"] == {"$ref": "#/components/schemas/DownloadId"}
    assert download["properties"]["hash"]["pattern"] == "^[0-9a-f]{32}$"
    assert download["properties"]["hash"]["minLength"] == 32
    assert download["properties"]["hash"]["maxLength"] == 32
    assert download["properties"]["delivery"]["oneOf"] == [
        {"$ref": "#/components/schemas/DownloadDelivery"}, {"type": "null"},
    ]
    assert "payloadVerified" in download["required"]


def test_rust_openapi_documents_ed2k_identity_and_server_connection_metadata() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    network = schemas["SettingsPartial"]["properties"]["network"]["properties"]
    assert network["nickname"]["type"] == "string"
    assert network["nickname"]["x-maxUtf8Bytes"] == 128
    servers = network["servers"]["properties"]
    assert servers["usePriorities"]["type"] == "boolean"
    assert servers["staticOnly"]["type"] == "boolean"

    server = schemas["Server"]
    assert "auxiliaryPorts" in server["required"]
    assert server["properties"]["auxiliaryPorts"] == {
        "type": "array",
        "items": {"type": "integer", "minimum": 1, "maximum": 65535},
    }


def test_rust_openapi_smoke_uses_canonical_server_controls() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]
    servers = schemas["SettingsPartial"]["properties"]["network"]["properties"]["servers"]["properties"]
    for key in ("autoReconnect", "safeConnect", "acceptServerListUpdates"):
        assert servers[key]["type"] == "boolean"
    assert servers["keepaliveMinutes"] == {"type": "integer", "minimum": 0, "maximum": 1440, "multipleOf": 1}
    assert module.get_contract_route_body("patchSettings") == {
        "expectedRevision": "1", "set": {"network": {"servers": {"safeConnect": True}}},
    }


def test_live_settings_fixture_uses_selected_contract_and_exact_observed_revision(monkeypatch):
    module = rust_rest_conformance.load_rest_smoke_module()
    module.REST_CONTRACT_ROUTES = [route for route in module.REST_CONTRACT_ROUTES
                                   if route["operationId"] == "patchSettings"]
    requests = []
    def request(base, path, *, method="GET", json_body=None, **kwargs):
        requests.append((method, path, json_body))
        document = {"data": {"ok": True},
                    "meta": {"apiVersion": "v1", "settingsRevision": "9007199254740993"}}
        return {"status": 200, "content_type": "application/json", "json": document["data"],
                "raw_json": document, "body_text": json.dumps(document)}
    monkeypatch.setattr(module, "http_request", request)
    monkeypatch.setattr(module, "validate_openapi_operation_response_payload", lambda *args: None)
    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:4711", "key", "contract")
    assert summary["routes"][0]["ok"], summary["routes"][0]
    assert requests == [("GET", "/api/v1/settings", None), ("PATCH", "/api/v1/settings", {
        "expectedRevision": "9007199254740993", "set": {"network": {"servers": {"safeConnect": True}}}})]
    assert module.OPENAPI_CONTRACT_PATH == resolve_selected_workspace_repo(
        Path(__file__).resolve().parents[2], "emulebb-tooling") / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"


def test_rust_openapi_documents_nat_backend_choices() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]
    order = schemas["SettingsPartial"]["properties"]["network"]["properties"]["nat"]["properties"]["backendOrder"]
    assert order["items"]["enum"] == ["pcp-natpmp", "upnp"]
    assert order["minItems"] == 1 and order["maxItems"] == 2 and order["uniqueItems"] is True


def test_rust_openapi_diagnostics_documents_download_event_runtime_metrics() -> None:
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    openapi = tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    module = rust_rest_conformance.load_rest_smoke_module(openapi)
    schemas = module.load_openapi_document()["components"]["schemas"]

    assert "downloadEvents" in schemas["RuntimeDiagnostics"]["required"]
    assert schemas["RuntimeDiagnostics"]["properties"]["downloadEvents"] == {
        "$ref": "#/components/schemas/DownloadEventRuntimeDiagnostics"
    }
    assert schemas["DownloadEventRuntimeDiagnostics"]["required"] == [
        "enabled",
        "stream",
        "epoch",
        "channelCapacity",
        "queuedEventCount",
        "subscriberCount",
        "latestEventId",
        "nextEventId",
        "resumeBehavior",
    ]
    assert schemas["DownloadEventRuntimeDiagnostics"]["properties"]["stream"][
        "enum"
    ] == ["sse"]
    assert schemas["DownloadEventRuntimeDiagnostics"]["properties"]["resumeBehavior"][
        "enum"
    ] == ["reset"]
    for field_name in (
        "channelCapacity",
        "queuedEventCount",
        "subscriberCount",
        "latestEventId",
    ):
        assert (
            schemas["DownloadEventRuntimeDiagnostics"]["properties"][field_name][
                "minimum"
            ]
            == 0
        )
    assert (
        schemas["DownloadEventRuntimeDiagnostics"]["properties"]["nextEventId"][
            "minimum"
        ]
        == 1
    )


def test_rust_openapi_stages_diagnostic_writer_health_as_optional() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    runtime = schemas["RuntimeDiagnostics"]
    assert "diagnosticWriter" not in runtime["required"]
    assert runtime["properties"]["diagnosticWriter"] == {
        "$ref": "#/components/schemas/DiagnosticWriterHealth"
    }
    writer = schemas["DiagnosticWriterHealth"]
    assert writer["additionalProperties"] is False
    assert writer["properties"]["schema"]["enum"] == ["diag_event_v2"]
    assert writer["required"] == list(writer["properties"])
    assert len(writer["required"]) == 41
    assert {
        "retentionScanErrors",
        "freeSpaceProbeErrors",
        "storagePolicyDrops",
        "storageAuthorityFaulted",
        "writerIoFaulted",
        "storageBlockReason",
        "storagePolicySatisfied",
        "maximumGrowthBytes",
        "maxTotalBytes",
        "maxRetainedSeconds",
        "minimumFreeBytes",
    } <= set(writer["required"])
    assert writer["properties"]["storageBlockReason"]["enum"] == [
        "retentionScanFailure",
        "retentionDeleteFailure",
        "freeSpaceProbeFailure",
        "retainedSegmentLimit",
        "aggregateByteLimit",
        "minimumFreeSpace",
        "pendingRetentionDeletions",
        None,
    ]


def test_run_response_conformance_rejects_api_root_base_url() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        raise AssertionError("exercise should not run after base-url preflight failure")

    with pytest.raises(ValueError, match="without a path"):
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711/api/v1",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=exercise
            ),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )


def test_run_response_conformance_rejects_non_root_base_url() -> None:
    with pytest.raises(ValueError, match="without a path"):
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711/rest",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=lambda *_args: {"ok": True}
            ),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )


def test_run_response_conformance_raises_on_contract_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=exercise
            ),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )

    assert raised.value.summary["failed_routes"] == ["getApp"]


def test_run_response_conformance_reports_event_stream_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": True, "failed_routes": []}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=exercise
            ),
            event_stream_checker=lambda _base_url, _api_key: {
                "ok": False,
                "reason": "missing reset",
            },
        )

    assert raised.value.summary["ok"] is False
    assert raised.value.summary["failed_routes"] == ["getEvents"]
    assert raised.value.summary["event_stream"] == {
        "ok": False,
        "reason": "missing reset",
    }


def write_download_event_openapi(path: Path) -> Path:
    path.write_text(
        """
openapi: 3.1.0
components:
  schemas:
    DownloadEvent:
      oneOf:
        - $ref: "#/components/schemas/DownloadSyncResetEvent"
    DownloadSyncResetEvent:
      type: object
      additionalProperties: false
      required: [id, epoch, type, reason]
      properties:
        id: { type: integer, minimum: 0 }
        epoch: { type: string, format: uuid }
        type:
          type: string
          enum: [sync.reset]
        reason:
          type: string
          enum: [initial, reconnect, lagged, epoch-changed]
""",
        encoding="utf-8",
    )
    return path


def test_run_event_stream_conformance_reads_resume_reset_frame(tmp_path: Path) -> None:
    requests = []
    openapi_yaml = write_download_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")

    def opener(request, *, timeout: float):
        requests.append((request, timeout))
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 00000000-0000-4000-8000-000000000001:42\n",
                b'data: {"id":42,"epoch":"00000000-0000-4000-8000-000000000001","type":"sync.reset","reason":"reconnect"}\n',
                b"\n",
            ]
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
        openapi_path=openapi_yaml,
    )

    assert summary == {
        "ok": True,
        "operationId": "getEvents",
        "path": "/api/v1/events",
        "status": 200,
        "contentType": "text/event-stream",
        "responseHeaders": {
            "Cache-Control": "no-cache, no-transform",
            "X-Contract-Version": "2.0.0",
            "X-Accel-Buffering": "no",
        },
        "payloadSchema": "DownloadEvent",
    }
    request, timeout = requests[0]
    assert request.full_url == "http://127.0.0.1:4711/api/v1/events"
    assert request.headers["Accept"] == "text/event-stream"
    assert request.headers["Last-event-id"] == "00000000-0000-4000-8000-000000000001:1"
    assert request.headers["X-api-key"] == "test-key"
    assert timeout == 2.0


def test_run_event_stream_conformance_rejects_api_root_base_url() -> None:
    def opener(_request, *, timeout: float):
        raise AssertionError(
            "event stream opener should not run after base-url preflight failure"
        )

    with pytest.raises(ValueError, match="without a path"):
        rust_rest_conformance.run_event_stream_conformance(
            "http://127.0.0.1:4711/api/v1/",
            "test-key",
            timeout_seconds=2.0,
            opener=opener,
        )


def test_run_event_stream_conformance_fails_without_stream_headers(
    tmp_path: Path,
) -> None:
    openapi_yaml = write_download_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")

    def opener(_request, *, timeout: float):
        assert timeout == 2.0
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 00000000-0000-4000-8000-000000000001:42\n",
                b'data: {"id":42,"epoch":"00000000-0000-4000-8000-000000000001","type":"sync.reset","reason":"reconnect"}\n',
                b"\n",
            ],
            headers={
                "Cache-Control": "",
                "X-Contract-Version": "",
                "X-Accel-Buffering": "",
            },
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
        openapi_path=openapi_yaml,
    )

    assert summary["ok"] is False
    assert summary["missingResponseHeaders"] == [
        "Cache-Control",
        "X-Contract-Version",
        "X-Accel-Buffering",
    ]


def test_run_event_stream_conformance_fails_on_schema_invalid_payload(
    tmp_path: Path,
) -> None:
    openapi_yaml = write_download_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")

    def opener(_request, *, timeout: float):
        assert timeout == 2.0
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 00000000-0000-4000-8000-000000000001:42\n",
                b'data: {"id":42,"epoch":"00000000-0000-4000-8000-000000000001","type":"sync.reset"}\n',
                b"\n",
            ]
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
        openapi_path=openapi_yaml,
    )

    assert summary["ok"] is False
    assert "payloadSchemaError" in summary
    assert "not valid under any of the given schemas" in str(
        summary["payloadSchemaError"]
    )


def test_run_cli_writes_failed_conformance_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    monkeypatch.setattr(
        rust_rest_conformance,
        "load_rest_smoke_module",
        lambda: SimpleNamespace(exercise_rest_contract_completeness=exercise),
    )
    monkeypatch.setattr(
        rust_rest_conformance,
        "run_event_stream_conformance",
        lambda _base_url, _api_key: {"ok": True},
    )
    output_path = tmp_path / "conformance.json"

    exit_code = rust_rest_conformance.run_cli(
        [
            "--base-url",
            "http://127.0.0.1:4711",
            "--api-key",
            "test-key",
            "--json-output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "event_stream": {"ok": True},
        "failed_routes": ["getApp"],
        "ok": False,
    }


def test_run_cli_reports_api_root_base_url_as_preflight_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = rust_rest_conformance.run_cli(
        [
            "--base-url",
            "http://127.0.0.1:4711/api/v1",
            "--api-key",
            "test-key",
        ]
    )

    assert exit_code == 2
    assert "preflight failed" in capsys.readouterr().out


@pytest.mark.parametrize("cursor, expected", [
    ("00000000-0000-4000-8000-000000000001:18446744073709551615", True),
    ("00000000-0000-4000-8000-000000000002:18446744073709551615", False),
    ("00000000-0000-4000-8000-000000000001:18446744073709552000", False),
])
def test_event_cursor_matches_payload_epoch_and_exact_revision(tmp_path, cursor, expected):
    openapi = write_download_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")
    def opener(_request, *, timeout):
        return FakeEventStreamResponse([
            b"event: sync.reset\n", f"id: {cursor}\n".encode(),
            b'data: {"id":18446744073709551615,"epoch":"00000000-0000-4000-8000-000000000001","type":"sync.reset","reason":"reconnect"}\n',
            b"\n",
        ])
    result = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711", "test-key", opener=opener, openapi_path=openapi,
    )
    assert result["ok"] is expected
    if not expected:
        assert result["missing"] == ["cursor"]


def test_sharing_mutation_is_explicitly_unsafe_for_generic_profile_probes():
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    module = rust_rest_conformance.load_rest_smoke_module(tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    row = next(route for route in module.REST_CONTRACT_ROUTES if route["operationId"] == "setLibrarySharing")
    assert row["safe"] is False
    assert module.get_contract_route_body("setLibrarySharing") == {"enabled": False, "hashes": ["ff" * 16]}


def test_search_result_resources_keep_their_template_and_expected_missing_lookup():
    tooling = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
    smoke = rust_rest_conformance.load_rest_smoke_module(
        tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    for resource, operation in [("observations", "listSearchResultObservations"), ("download", "downloadSearchResult")]:
        template = "/searches/{searchId}/results/{resultId}/" + resource
        path = smoke.concrete_contract_path(template, operation)
        assert smoke.normalize_contract_path_for_openapi(path) == template
    assert smoke.REST_CONTRACT_EXPECTED_ERROR_STATUSES["listSearchResultObservations"] == (404,)
