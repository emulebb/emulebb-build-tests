from __future__ import annotations

import importlib.util
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

PRIVATE_NATIVE_ONLY_ROUTES: set[tuple[str, str]] = set()


def load_rest_api_smoke_module():
    """Loads the hyphenated REST smoke script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "rest-api-smoke.py"
    spec = importlib.util.spec_from_file_location("rest_api_smoke_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_nat_backend_order_accepts_upnp_first() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_upnp_backend_order(
        [
            {"message": "NAT mapping backend mode: Automatic"},
            {"message": "Attempting NAT mapping backend 'UPnP IGD (MiniUPnP)'"},
            {"message": "Trying fallback NAT mapping backend 'PCP/NAT-PMP'"},
            {"message": "Attempting NAT mapping backend 'PCP/NAT-PMP'"},
        ]
    )

    assert summary["backend_names"] == ["UPnP IGD (MiniUPnP)", "PCP/NAT-PMP"]
    assert summary["upnp_first"] is True
    assert summary["pcp_before_upnp"] is False


def test_nat_backend_order_rejects_pcp_first() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="Expected first NAT backend"):
        module.assert_upnp_backend_order(
            [
                {"message": "Attempting NAT mapping backend 'PCP/NAT-PMP'"},
                {"message": "Attempting NAT mapping backend 'UPnP IGD (MiniUPnP)'"},
            ]
        )


def test_nat_backend_order_requires_attempts() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="No NAT mapping backend attempts"):
        module.assert_upnp_backend_order([{"message": "eMule Version 0.72a x64 ready"}])


def test_p2p_bind_override_writes_interface_name(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text(
        "[eMule]\nBindAddr=127.0.0.1\nBindInterface=\n",
        encoding="utf-16",
    )

    module.apply_p2p_bind_interface_override(config_dir, "hide.me")

    text = module.live_common.read_ini_text(preferences_path)
    assert "BindInterface=hide.me" in text
    assert "BindAddr=hide.me" not in text
    assert "BindAddr=" in text
    assert "BlockNetworkWhenBindUnavailableAtStartup=1" in text
    assert "127.0.0.1" not in text


def test_configure_webserver_profile_keeps_crash_endpoint_disabled_by_default(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text("[eMule]\nConfirmExit=1\n[WebServer]\nEnabled=0\n", encoding="utf-16")
    app_exe = tmp_path / "app" / "eMule-main" / "srchybrid" / "x64" / "Release" / "emule.exe"

    module.configure_webserver_profile(config_dir, app_exe, "api-key", 4711, "127.0.0.1")

    text = module.live_common.read_ini_text(preferences_path)
    assert "Enabled=1" in text
    assert "EnableDiagnosticRestEndpoints=0" in text


def test_configure_webserver_profile_can_enable_crash_endpoint(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text("[eMule]\nConfirmExit=1\n[WebServer]\nEnabled=0\n", encoding="utf-16")
    app_exe = tmp_path / "app" / "eMule-main" / "srchybrid" / "x64" / "Release" / "emule.exe"

    module.configure_webserver_profile(
        config_dir,
        app_exe,
        "api-key",
        4711,
        "127.0.0.1",
        enable_crash_test_endpoint=True,
    )

    text = module.live_common.read_ini_text(preferences_path)
    assert "EnableDiagnosticRestEndpoints=1" in text


def test_live_server_unavailable_is_inconclusive_exit_code() -> None:
    module = load_rest_api_smoke_module()

    assert module.LIVE_NETWORK_UNAVAILABLE_EXIT_CODE == 2
    with pytest.raises(module.LiveNetworkUnavailableError, match="No server candidates"):
        module.connect_to_live_server("http://127.0.0.1:1", "api-key", [], 1.0)


def test_rest_socket_adversity_base_url_parsing() -> None:
    module = load_rest_api_smoke_module()

    assert module.parse_base_url_endpoint("http://127.0.0.1:4711") == {
        "scheme": "http",
        "host": "127.0.0.1",
        "port": 4711,
    }
    assert module.parse_base_url_endpoint("https://localhost") == {
        "scheme": "https",
        "host": "localhost",
        "port": 443,
    }


def test_https_urlopen_context_is_only_used_for_https() -> None:
    module = load_rest_api_smoke_module()

    assert module.build_urlopen_context("http://127.0.0.1:4711") is None
    assert module.build_urlopen_context("https://127.0.0.1:4711") is not None


def test_rest_socket_probe_outcome_rejects_timeouts() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="timeout_probe"):
        module.require_socket_probe_outcome(
            "timeout_probe",
            {"outcome": "timeout", "status": None},
            allowed_statuses={400},
        )


def test_rest_socket_probe_outcome_accepts_declared_status_or_close() -> None:
    module = load_rest_api_smoke_module()

    module.require_socket_probe_outcome(
        "bad_request_probe",
        {"outcome": "response", "status": 400},
        allowed_statuses={400},
    )
    module.require_socket_probe_outcome(
        "closed_probe",
        {"outcome": "closed", "status": None},
        allowed_statuses={400},
    )


def test_rest_socket_adversity_includes_response_send_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    raw_payloads: list[bytes] = []

    def fake_raw_socket_probe(_host: str, _port: int, payload: bytes, **_kwargs: object) -> dict[str, object]:
        raw_payloads.append(payload)
        return {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0}

    def fake_http_request(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "bad request"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "raw_socket_probe", fake_raw_socket_probe)
    monkeypatch.setattr(module, "http_request", fake_http_request)

    summary = module.exercise_rest_socket_adversity(
        "http://127.0.0.1:4711",
        "api-key",
        budget="smoke",
        request_timeout_seconds=1.0,
    )

    assert "reset_during_response_send" in [probe["scenario"] for probe in summary["probes"]]
    assert "reset_during_error_response_send" in [probe["scenario"] for probe in summary["probes"]]
    assert any(b"GET /api/v1/logs?limit=400 HTTP/1.1" in payload for payload in raw_payloads)
    assert any(b"GET /api/v1/r1-missing-error-reset HTTP/1.1" in payload for payload in raw_payloads)


def test_rest_tls_handshake_adversity_requires_https() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(RuntimeError, match="HTTPS base URL"):
        module.exercise_rest_tls_handshake_adversity(
            "http://127.0.0.1:4711",
            budget="smoke",
            request_timeout_seconds=1.0,
        )


def test_rest_tls_handshake_adversity_records_smoke_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    observed: list[dict[str, object]] = []

    def fake_chunk_probe(host: str, port: int, chunks: list[bytes], **kwargs: object) -> dict[str, object]:
        observed.append({"host": host, "port": port, "chunks": chunks, **kwargs})
        return {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0}

    monkeypatch.setattr(module, "raw_socket_chunk_probe", fake_chunk_probe)

    summary = module.exercise_rest_tls_handshake_adversity(
        "https://127.0.0.1:4711",
        budget="smoke",
        request_timeout_seconds=2.0,
    )

    assert summary["scheme"] == "https"
    assert summary["probe_count"] == 3
    assert [probe["scenario"] for probe in summary["probes"]] == [
        "stalled_tls_connect_close",
        "partial_tls_record_reset",
        "partial_tls_clienthello_reset",
    ]
    assert {entry["host"] for entry in observed} == {"127.0.0.1"}
    assert {entry["port"] for entry in observed} == {4711}


def test_rest_error_path_matrix_summarizes_release_statuses() -> None:
    module = load_rest_api_smoke_module()

    matrix = module.build_rest_error_path_matrix(
        {
            "missing_key": {"status": 401, "content_type": "application/json"},
            "rest_surface": {
                "invalid_method": {"status": 405, "content_type": "application/json"},
                "missing_route": {"status": 404, "content_type": "application/json"},
                "bad_payload": {"status": 400, "content_type": "application/json"},
            },
            "conflict": {"response": {"status": 409, "content_type": "application/json"}},
        }
    )

    assert matrix["status_counts"] == {"400": 1, "401": 1, "404": 1, "405": 1, "409": 1}
    assert matrix["ok"] is True
    assert matrix["covered_release_statuses"] == [400, 401, 404, 405, 409, 500, 503]
    assert matrix["missing_release_statuses"] == []
    assert matrix["live_missing_release_statuses"] == [500, 503]
    assert matrix["seam_backed_release_statuses"] == [500, 503]
    assert matrix["release_statuses"][3]["seam"]["expected_error_code"] == "METHOD_NOT_ALLOWED"
    assert matrix["release_statuses"][4]["seam"]["expected_error_code"] == "INVALID_STATE"
    assert matrix["release_statuses"][5]["seam"]["expected_error_code"] == "EMULE_ERROR"
    assert matrix["release_statuses"][6]["seam"]["expected_error_code"] == "EMULE_UNAVAILABLE"
    assert matrix["error_response_count"] == 5


def test_rest_error_path_matrix_hard_gate_rejects_missing_statuses() -> None:
    module = load_rest_api_smoke_module()

    matrix = module.build_rest_error_path_matrix({"missing_key": {"status": 401, "content_type": "application/json"}})

    assert matrix["ok"] is False
    assert matrix["missing_release_statuses"] == [400, 404]
    with pytest.raises(AssertionError, match="release coverage gaps"):
        module.require_rest_error_path_matrix(matrix)


def test_process_resource_snapshot_diff_ignores_missing_values() -> None:
    module = load_rest_api_smoke_module()

    assert module.diff_process_resource_snapshots(
        {
            "process_id": 123,
            "handles": 10,
            "thread_count": 4,
            "gdi_objects": None,
            "private_bytes": 4096,
        },
        {
            "process_id": 123,
            "handles": 14,
            "thread_count": 5,
            "gdi_objects": 2,
            "private_bytes": 6144,
        },
    ) == {
        "handles": 4,
        "thread_count": 1,
        "gdi_objects": None,
        "private_bytes": 2048,
    }


def test_process_exit_state_handles_missing_process_id() -> None:
    module = load_rest_api_smoke_module()

    assert module.get_process_exit_state(None) == {
        "process_id": None,
        "open_process_ok": False,
        "running": None,
        "exit_code": None,
        "last_error": None,
    }


def test_rest_leak_churn_defaults_include_r1_soak_boundary() -> None:
    module = load_rest_api_smoke_module()

    assert module.REST_LEAK_CHURN_DEFAULT_CYCLES["smoke"] > 0
    assert module.REST_LEAK_CHURN_DEFAULT_CYCLES["soak"] >= 1000


def test_rest_leak_churn_supports_https_cycles(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[dict[str, object]] = []

    def fake_chunk_probe(host: str, port: int, chunks: list[bytes], **kwargs: object) -> dict[str, object]:
        calls.append({"host": host, "port": port, "chunks": chunks, **kwargs})
        return {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0}

    monkeypatch.setattr(module, "raw_socket_chunk_probe", fake_chunk_probe)
    monkeypatch.setattr(module, "get_process_resource_snapshot", lambda _pid: {"handles": 10})

    summary = module.exercise_rest_leak_churn(
        "https://127.0.0.1:4711",
        "api-key",
        process_id=123,
        budget="smoke",
        cycles=3,
        request_timeout_seconds=1.0,
    )

    assert summary["scheme"] == "https"
    assert summary["cycles_completed"] == 3
    assert [row["scenario"] for row in summary["sampled_cycles"]] == [
        "stalled_tls_connect_close",
        "partial_tls_record_reset",
        "partial_tls_clienthello_reset",
    ]
    assert len(calls) == 3


def test_rest_leak_churn_resource_thresholds_report_pass_and_failures() -> None:
    module = load_rest_api_smoke_module()

    passing = module.evaluate_rest_leak_churn_resources(
        {"handles": 1, "private_bytes": 1024, "working_set_bytes": None},
        {"handles": 2, "private_bytes": 2048, "working_set_bytes": None},
    )
    assert passing["ok"] is True
    assert passing["violations"] == []

    failing = module.evaluate_rest_leak_churn_resources(
        {"handles": 65, "thread_count": 5, "private_bytes": 1024, "working_set_bytes": None},
        {"handles": 2, "private_bytes": 512 * 1024 * 1024, "working_set_bytes": None},
    )
    assert failing["ok"] is False
    assert {
        (violation["metric"], violation["phase"])
        for violation in failing["violations"]
    } == {
        ("handles", "after_drain"),
        ("thread_count", "after_drain"),
        ("private_bytes", "peak"),
    }


def test_restart_app_after_churn_records_shutdown_relaunch_and_ready_evidence() -> None:
    module = load_rest_api_smoke_module()
    closed_apps: list[object] = []

    def fake_close(app: object) -> None:
        closed_apps.append(app)

    def fake_launch(app_exe: Path, profile_base: Path) -> str:
        assert app_exe == Path("emule.exe")
        assert profile_base == Path("profile")
        return "new-app"

    def fake_pid(app: object) -> int:
        return {"old-app": 111, "new-app": 222}[str(app)]

    def fake_snapshot(process_id: int | None) -> dict[str, int | None]:
        return {
            "process_id": process_id,
            "handles": 20,
            "thread_count": 8,
            "gdi_objects": 1,
            "user_objects": 1,
            "private_bytes": 4096,
            "working_set_bytes": 8192,
        }

    relaunched, summary = module.restart_app_after_churn(
        "old-app",
        app_exe=Path("emule.exe"),
        profile_base=Path("profile"),
        base_url="https://127.0.0.1:4711",
        api_key="api-key",
        rest_ready_timeout_seconds=5.0,
        close_func=fake_close,
        launch_func=fake_launch,
        wait_main_window_func=lambda _app: SimpleNamespace(window_text=lambda: "eMule"),
        wait_ready_func=lambda _base_url, _api_key, _timeout: {
            "status": 200,
            "content_type": "application/json",
            "json": {"name": "eMule"},
        },
        get_pid_func=fake_pid,
        snapshot_func=fake_snapshot,
    )

    assert relaunched == "new-app"
    assert closed_apps == ["old-app"]
    assert summary["old_process_id"] == 111
    assert summary["new_process_id"] == 222
    assert summary["same_process_id_reused"] is False
    assert summary["main_window_title"] == "eMule"
    assert summary["ready"] == {
        "status": 200,
        "content_type": "application/json",
        "json": {"name": "eMule"},
    }
    assert summary["snapshots"]["before_shutdown"]["process_id"] == 111
    assert summary["snapshots"]["after_relaunch"]["process_id"] == 222


def test_max_resource_snapshot_keeps_high_water_marks() -> None:
    module = load_rest_api_smoke_module()

    assert module.max_resource_snapshot(
        {"handles": 10, "private_bytes": None, "working_set_bytes": 500},
        {"handles": 8, "private_bytes": 1000, "working_set_bytes": 700},
    ) == {
        "handles": 10,
        "private_bytes": 1000,
        "working_set_bytes": 700,
    }


def test_live_seed_import_evidence_records_sources_and_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[dict[str, object]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: object) -> dict[str, object]:
        calls.append({"base_url": base_url, "path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json",
            "raw_json": {"data": {"ok": True, "imported": True}, "meta": {"apiVersion": "v1"}},
            "json": {"ok": True, "imported": True},
            "headers": {},
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    summary = module.exercise_live_seed_imports(
        "http://127.0.0.1:1",
        "api-key",
        {
            "source_home_url": module.EMULE_SECURITY_HOME_URL,
            "files": [
                {
                    "name": "server_met",
                    "file_name": "server.met",
                    "url": module.EMULE_SECURITY_SERVER_MET_URL,
                    "bytes": 80,
                    "sha256": "s" * 64,
                },
                {
                    "name": "nodes_dat",
                    "file_name": "nodes.dat",
                    "url": module.EMULE_SECURITY_NODES_DAT_URL,
                    "bytes": 96,
                    "sha256": "n" * 64,
                },
            ],
        },
    )

    assert [call["path"] for call in calls] == [
        "/api/v1/servers/operations/import-met-url",
        "/api/v1/kad/operations/import-nodes-url",
    ]
    assert [call["json_body"] for call in calls] == [
        {"url": module.EMULE_SECURITY_SERVER_MET_URL},
        {"url": module.EMULE_SECURITY_NODES_DAT_URL},
    ]
    assert {entry["file_name"]: entry["imported"] for entry in summary["imports"]} == {
        "server.met": True,
        "nodes.dat": True,
    }
    assert {entry["file_name"]: entry["source_bytes"] for entry in summary["imports"]} == {
        "server.met": 80,
        "nodes.dat": 96,
    }


def test_live_seed_import_evidence_rejects_failed_import(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url: str, _path: str, **_kwargs: object) -> dict[str, object]:
        return {
            "status": 200,
            "content_type": "application/json",
            "raw_json": {"data": {"ok": False, "imported": False}, "meta": {"apiVersion": "v1"}},
            "json": {"ok": False, "imported": False},
            "headers": {},
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    with pytest.raises(AssertionError, match="imported"):
        module.exercise_live_seed_imports(
            "http://127.0.0.1:1",
            "api-key",
            {
                "source_home_url": module.EMULE_SECURITY_HOME_URL,
                "files": [
                    {
                        "name": "server_met",
                        "file_name": "server.met",
                        "url": module.EMULE_SECURITY_SERVER_MET_URL,
                        "bytes": 80,
                        "sha256": "s" * 64,
                    },
                    {
                        "name": "nodes_dat",
                        "file_name": "nodes.dat",
                        "url": module.EMULE_SECURITY_NODES_DAT_URL,
                        "bytes": 96,
                        "sha256": "n" * 64,
                    },
                ],
            },
        )


def test_missing_transfer_bulk_result_requires_per_item_error() -> None:
    module = load_rest_api_smoke_module()

    result = module.require_missing_transfer_bulk_result(
        {
            "status": 200,
            "raw_json": {
                "data": {
                    "items": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": False,
                            "error": "transfer not found",
                        },
                    ],
                },
                "meta": {"apiVersion": "v1"},
            },
            "json": {
                "items": [
                    {
                        "hash": module.REST_SURFACE_MISSING_HASH,
                        "ok": False,
                        "error": "transfer not found",
                    },
                ],
            },
        }
    )

    assert result["hash"] == module.REST_SURFACE_MISSING_HASH


def test_transfer_details_payload_compaction_validates_release_shape() -> None:
    module = load_rest_api_smoke_module()

    compact = module.compact_transfer_details_payload(
        {
            "transfer": {"hash": module.REST_SURFACE_VALID_DOWNLOAD_HASH, "name": "rest-api-smoke.bin"},
            "parts": [
                {
                    "index": 0,
                    "start": 0,
                    "end": 1023,
                    "completedBytes": 0,
                    "gapBytes": 1024,
                    "complete": False,
                    "requested": False,
                    "corrupted": False,
                    "availableSources": 0,
                }
            ],
            "sources": [],
        },
        module.REST_SURFACE_VALID_DOWNLOAD_HASH,
    )

    assert compact["hash"] == module.REST_SURFACE_VALID_DOWNLOAD_HASH
    assert compact["part_count"] == 1
    assert compact["source_count"] == 0
    assert compact["first_part"]["gapBytes"] == 1024


def test_rest_payload_unwraps_success_and_error_envelopes() -> None:
    module = load_rest_api_smoke_module()

    assert module.unwrap_rest_payload(
        {
            "data": {"items": [{"name": "file.bin"}]},
            "meta": {"apiVersion": "v1"},
        }
    ) == {"items": [{"name": "file.bin"}]}
    assert module.unwrap_rest_payload(
        {
            "error": {
                "code": "NOT_FOUND",
                "message": "transfer not found",
            }
        }
    ) == {"error": "NOT_FOUND", "message": "transfer not found"}


def test_openapi_error_envelope_documents_stable_error_codes() -> None:
    openapi_path = Path(__file__).resolve().parents[3] / "eMule-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
    text = openapi_path.read_text(encoding="utf-8")
    error_schema = text[text.index("    ErrorEnvelope:\n") : text.index("    Collection:\n")]

    assert "required: [error]" in error_schema
    assert "required: [code, message]" in error_schema
    for code in (
        "INVALID_ARGUMENT",
        "UNAUTHORIZED",
        "METHOD_NOT_ALLOWED",
        "NOT_FOUND",
        "INVALID_STATE",
        "EMULE_UNAVAILABLE",
        "EMULE_ERROR",
    ):
        assert f"                - {code}" in error_schema
    assert "details:" in error_schema
    assert "additionalProperties: true" in error_schema


def test_openapi_metadata_tracks_beta_release_contract() -> None:
    openapi_path = Path(__file__).resolve().parents[3] / "eMule-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
    text = openapi_path.read_text(encoding="utf-8")

    assert "  version: 0.7.3\n" in text
    assert "Canonical beta 0.7.3 contract" in text
    assert "1.0.0-pre" not in text


def _collect_open_additional_properties(schema: object, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], object]:
    open_nodes: dict[tuple[str, ...], object] = {}
    if isinstance(schema, dict):
        if schema.get("additionalProperties") is not False and "additionalProperties" in schema:
            open_nodes[path] = schema["additionalProperties"]
        for key, value in schema.items():
            if key != "additionalProperties":
                open_nodes.update(_collect_open_additional_properties(value, path + (str(key),)))
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            open_nodes.update(_collect_open_additional_properties(value, path + (str(index),)))
    return open_nodes


def test_openapi_public_response_dtos_are_closed_except_explicit_extension_maps() -> None:
    module = load_rest_api_smoke_module()
    document = module.load_openapi_document()

    open_nodes = _collect_open_additional_properties(document)

    assert open_nodes == {
        (
            "components",
            "schemas",
            "ErrorEnvelope",
            "properties",
            "error",
            "properties",
            "details",
        ): True,
        (
            "components",
            "schemas",
            "App",
            "properties",
            "capabilities",
        ): {"type": "boolean"},
    }


def test_openapi_core_public_dtos_reject_undocumented_fields() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    for schema_name in (
        "EnvelopeMeta",
        "Preferences",
        "Stats",
        "Category",
        "Transfer",
        "TransferPart",
        "TransferSource",
        "SharedFile",
        "SharedDirectory",
        "Upload",
        "SearchResult",
    ):
        assert schemas[schema_name]["additionalProperties"] is False

    assert schemas["SnapshotEnvelope"]["allOf"][1]["properties"]["data"]["additionalProperties"] is False


def test_openapi_search_type_enums_match_rest_tokens() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]
    rest_tokens = ["", "arc", "audio", "iso", "image", "pro", "video", "doc", "emulecollection"]

    for schema_name in ("SearchSession", "Search", "SearchCreateRequest", "SearchResult"):
        assert schemas[schema_name]["properties"]["type"]["enum"] == rest_tokens

    assert "enum" not in schemas["SearchResult"]["properties"]["fileType"]
    assert "not remapped" in schemas["SearchResult"]["properties"]["fileType"]["description"]


def test_openapi_rest_consistency_cleanup_contracts() -> None:
    module = load_rest_api_smoke_module()
    document = module.load_openapi_document()
    schemas = document["components"]["schemas"]

    assert schemas["Category"]["properties"]["priority"] == {"type": "integer", "minimum": 0}
    assert schemas["CategoryCreateRequest"]["properties"]["priority"] == {
        "$ref": "#/components/schemas/CategoryPriorityInput"
    }
    assert schemas["CategoryPatch"]["properties"]["priority"] == {
        "$ref": "#/components/schemas/CategoryPriorityInput"
    }
    assert schemas["CategoryCreateRequest"]["properties"]["path"]["minLength"] == 1
    assert schemas["CategoryPatch"]["properties"]["path"]["minLength"] == 1
    assert schemas["CategoryPriorityInput"]["oneOf"] == [
        {"type": "string", "enum": ["verylow", "low", "normal", "high", "veryhigh"]},
        {"type": "integer", "minimum": 0},
    ]

    assert schemas["TransferPriority"]["enum"] == ["auto", "verylow", "low", "normal", "high", "veryhigh"]
    assert schemas["SharedFilePriority"]["enum"] == ["auto", "verylow", "low", "normal", "high", "release"]
    assert "release" not in schemas["TransferPriority"]["enum"]
    assert "veryhigh" not in schemas["SharedFilePriority"]["enum"]
    assert schemas["Transfer"]["properties"]["priority"] == {"$ref": "#/components/schemas/TransferPriority"}
    assert schemas["TransferPatch"]["properties"]["priority"] == {"$ref": "#/components/schemas/TransferPriority"}
    assert schemas["SharedFile"]["properties"]["priority"] == {"$ref": "#/components/schemas/SharedFilePriority"}
    assert schemas["SharedFilePatch"]["properties"]["priority"] == {"$ref": "#/components/schemas/SharedFilePriority"}

    assert len(schemas["TransferCreateRequest"]["oneOf"]) == 2
    assert schemas["TransferCreateRequest"]["not"] == {"required": ["categoryId", "categoryName"]}
    assert schemas["TransferCreateRequest"]["properties"]["categoryId"]["maximum"] == 4294967295
    assert len(schemas["TransferPatch"]["oneOf"]) == 4
    assert schemas["TransferPatch"]["properties"]["categoryId"]["maximum"] == 4294967295
    assert schemas["SharedFilePatch"]["minProperties"] == 1
    assert schemas["SharedFilePatch"]["dependentRequired"] == {
        "comment": ["rating"],
        "rating": ["comment"],
    }
    assert schemas["SharedFileCreateRequest"]["properties"]["path"]["minLength"] == 1
    assert schemas["SharedDirectoryReplaceRequest"]["properties"]["roots"]["items"] == {
        "$ref": "#/components/schemas/SharedDirectoryRootInput"
    }
    assert schemas["SharedDirectoryRootInput"]["oneOf"] == [
        {"type": "string", "minLength": 1},
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "recursive": {"type": "boolean"},
            },
        },
    ]
    assert schemas["PreferencesPatch"]["minProperties"] == 1
    assert schemas["ServerPatch"]["minProperties"] == 1
    assert schemas["ServerCreateRequest"]["properties"]["address"]["minLength"] == 1
    assert schemas["ServerCreateRequest"]["properties"]["port"]["minimum"] == 1
    assert schemas["ServerCreateRequest"]["properties"]["port"]["maximum"] == 65535
    assert schemas["UrlImportRequest"]["properties"]["url"]["minLength"] == 1
    assert "format" not in schemas["UrlImportRequest"]["properties"]["url"]
    assert schemas["KadBootstrapRequest"]["required"] == ["address", "port"]
    assert schemas["KadBootstrapRequest"]["properties"]["address"]["minLength"] == 1
    assert schemas["KadBootstrapRequest"]["properties"]["port"]["minimum"] == 1
    assert schemas["KadBootstrapRequest"]["properties"]["port"]["maximum"] == 65535
    assert document["paths"]["/kad/operations/bootstrap"]["post"]["requestBody"]["required"] is True
    assert schemas["SearchResultDownloadRequest"]["not"] == {"required": ["categoryId", "categoryName"]}
    assert schemas["SearchResultDownloadRequest"]["properties"]["categoryId"]["maximum"] == 4294967295

    parameters = document["components"]["parameters"]
    assert parameters["CategoryId"]["schema"]["maximum"] == 4294967295
    assert parameters["SearchId"]["schema"] == {"type": "integer", "minimum": 0, "maximum": 4294967295}
    assert parameters["Offset"]["schema"]["maximum"] == 2147483647

    responses = document["components"]["responses"]
    assert document["paths"]["/transfers"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/transfers/{hash}/operations/pause"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/transfers/{hash}/operations/resume"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/transfers/{hash}/operations/stop"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/shared-files"]["post"]["responses"]["200"]["$ref"].endswith("/SharedFileCreateResponse")
    assert document["paths"]["/searches/{searchId}/results/{hash}/operations/download"]["post"]["responses"]["200"]["$ref"].endswith("/SearchResultDownloadResponse")
    assert document["paths"]["/transfers/{hash}/sources/{clientId}/operations/browse"]["post"]["responses"]["200"]["$ref"].endswith("/TransferSourceBrowseResponse")
    assert document["paths"]["/servers/{serverId}/operations/connect"]["post"]["responses"]["200"]["$ref"].endswith("/ServerStatusResponse")
    assert document["paths"]["/servers/operations/import-met-url"]["post"]["responses"]["200"]["$ref"].endswith("/UrlImportResponse")
    assert document["paths"]["/kad/operations/import-nodes-url"]["post"]["responses"]["200"]["$ref"].endswith("/UrlImportResponse")
    assert document["paths"]["/uploads/{clientId}/operations/remove"]["post"]["responses"]["200"]["$ref"].endswith("/UploadRemoveResponse")
    assert document["paths"]["/upload-queue/{clientId}/operations/remove"]["post"]["responses"]["200"]["$ref"].endswith("/UploadRemoveResponse")
    for response_name in (
        "PeerBanResponse",
        "SearchResultDownloadResponse",
        "SharedFileCreateResponse",
        "TransferSourceBrowseResponse",
        "UploadRemoveResponse",
        "UrlImportResponse",
    ):
        assert response_name in responses

    source_properties = schemas["TransferSource"]["properties"]
    assert "state" not in source_properties
    assert source_properties["downloadState"]["enum"] == [
        "downloading",
        "onqueue",
        "connected",
        "connecting",
        "waitcallback",
        "waitcallbackkad",
        "reqhashset",
        "noneededparts",
        "toomanyconns",
        "toomanyconnskad",
        "lowtolowip",
        "banned",
        "error",
        "none",
        "remotequeuefull",
        "unknown",
    ]


def test_native_transfer_operation_responses_use_stable_bulk_items() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "WebServerJson.cpp"
    source = source_path.read_text(encoding="utf-8")

    assert 'return json{{"items", json::array({result})}};' in source
    assert "json singleResource;" not in source
    assert 'return json{{"items", results}};' in source


def test_rest_search_type_docs_reject_alias_and_remap_language() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    rest_docs_dir = workspace_root / "repos" / "eMule-tooling" / "docs" / "rest"
    docs = "\n".join(
        (rest_docs_dir / name).read_text(encoding="utf-8")
        for name in ("REST-API-CONTRACT.md", "REST-API-ADAPTERS.md", "REST-API-PARITY-INVENTORY.md")
    )
    normalized_docs = re.sub(r"\s+", " ", docs)

    assert "No aliases, alternate casing, or request-time type remapping are accepted." in normalized_docs
    assert "`SearchResult.fileType` remains row metadata" in normalized_docs
    assert "adapter-side result filter" in normalized_docs
    assert "family-to-search-type mapping still resolves to REST tokens" in normalized_docs

    for forbidden in ("`Video`", "`cdimage`", "normalized to", "normalizes to"):
        assert forbidden not in docs


def test_rest_contract_docs_define_adapter_subset_and_legacy_compile_only_boundary() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    rest_docs_dir = workspace_root / "repos" / "eMule-tooling" / "docs" / "rest"
    adapter_doc = (rest_docs_dir / "REST-API-ADAPTERS.md").read_text(encoding="utf-8")
    contract_doc = (rest_docs_dir / "REST-API-CONTRACT.md").read_text(encoding="utf-8")
    parity_doc = (rest_docs_dir / "REST-API-PARITY-INVENTORY.md").read_text(encoding="utf-8")
    qbit_seams = (
        workspace_root
        / "workspaces"
        / "v0.72a"
        / "app"
        / "eMule-main"
        / "srchybrid"
        / "WebServerQBitCompatSeams.h"
    ).read_text(encoding="utf-8")

    route_specs = re.findall(r'\{"(GET|POST)", "([^"]+)", (?:true|false)\}', qbit_seams)
    assert len(route_specs) == 19

    adapter_doc_lower = adapter_doc.lower()
    for method, path in route_specs:
        assert f"| `{method.lower()}` | `{path}` |" in adapter_doc_lower

    normalized_adapter_doc = re.sub(r"\s+", " ", adapter_doc_lower)
    assert "not a full qbittorrent web api clone" in normalized_adapter_doc

    for required_text in (
        "/indexer/emulebb/api",
        "https://github.com/qbittorrent/qbittorrent/wiki/webui-api-%28qbittorrent-4.1%29",
        "https://torznab.github.io/spec-1.3-draft/",
        "save_path",
        "content_path",
        "setsharelimits",
        "`t`",
        "`apikey`",
        "`season`",
        "`ep`",
        "`year`",
        "deprecated",
        "compile-only",
    ):
        assert required_text in adapter_doc_lower

    contract_doc_lower = contract_doc.lower()
    assert "rest-api-adapters.md" in contract_doc_lower
    assert "deprecated" in contract_doc_lower
    assert "legacy template-based webserver" in contract_doc_lower
    assert "compile preservation" in contract_doc_lower

    parity_doc_lower = parity_doc.lower()
    assert "migrated action inventory" in parity_doc_lower
    assert "not a functional parity promise" in parity_doc_lower
    assert "compile-only" in parity_doc_lower
    assert "legacy action" not in parity_doc_lower


def test_rest_error_response_requires_json_not_html() -> None:
    module = load_rest_api_smoke_module()
    error_result = {
        "status": 404,
        "content_type": "application/json; charset=utf-8",
        "body_text": '{"error":{"code":"NOT_FOUND","message":"transfer not found","details":{}}}',
        "raw_json": {
            "error": {
                "code": "NOT_FOUND",
                "message": "transfer not found",
                "details": {},
            },
        },
        "json": {
            "error": "NOT_FOUND",
            "message": "transfer not found",
            "details": {},
        },
    }

    assert module.is_native_rest_json_response(error_result) is True
    assert module.response_matches_kind(error_result, "native-json") is True
    assert module.response_matches_kind(error_result, "json") is True
    assert module.require_error_response(error_result, 404, "NOT_FOUND")["error"] == "NOT_FOUND"

    method_not_allowed = {
        **error_result,
        "status": 405,
        "body_text": (
            '{"error":{"code":"METHOD_NOT_ALLOWED",'
            '"message":"HTTP method is not allowed for this API route","details":{}}}'
        ),
        "raw_json": {
            "error": {
                "code": "METHOD_NOT_ALLOWED",
                "message": "HTTP method is not allowed for this API route",
                "details": {},
            },
        },
        "json": {
            "error": "METHOD_NOT_ALLOWED",
            "message": "HTTP method is not allowed for this API route",
            "details": {},
        },
    }
    assert module.require_error_response(method_not_allowed, 405, "METHOD_NOT_ALLOWED")["error"] == "METHOD_NOT_ALLOWED"

    html_content_type = {**error_result, "content_type": "text/html; charset=utf-8"}
    assert module.is_native_rest_json_response(html_content_type) is False
    assert module.response_matches_kind({**html_content_type, "body_text": "<html></html>"}, "native-json") is False
    with pytest.raises(AssertionError):
        module.require_error_response(html_content_type, 404, "NOT_FOUND")

    html_body = {**error_result, "body_text": "<html><body>login</body></html>"}
    with pytest.raises(AssertionError):
        module.require_error_response(html_body, 404, "NOT_FOUND")
def test_missing_transfer_bulk_result_rejects_success_rows() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError):
        module.require_missing_transfer_bulk_result(
            {
                "status": 200,
                "raw_json": {
                    "data": {
                        "items": [
                            {
                                "hash": module.REST_SURFACE_MISSING_HASH,
                                "ok": True,
                            },
                        ],
                    },
                    "meta": {"apiVersion": "v1"},
                },
                "json": {
                    "items": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": True,
                        },
                    ],
                },
            }
        )


def test_rest_contract_registry_matches_openapi() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_contract_routes_match_openapi()

    assert summary["ok"] is True
    assert summary["operation_count"] == summary["openapi_route_count"]
    assert summary["duplicate_operation_ids"] == []
    assert summary["missing_from_registry"] == []
    assert summary["missing_from_openapi"] == []
    assert summary["unknown_execution_models"] == []


def _csv_fields(value: str) -> set[str]:
    return {field for field in value.split(",") if field}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _component_ref_name(line: str, kind: str) -> str | None:
    match = re.search(rf"#/components/{kind}/([A-Za-z0-9_]+)", line)
    return match.group(1) if match else None


def _native_route_contracts() -> dict[tuple[str, str], dict[str, set[str]]]:
    workspace_root = Path(__file__).resolve().parents[4]
    route_header = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "WebServerJsonSeams.h"
    route_specs = re.findall(
        r'\{\s*"([A-Z]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"(?:\s*,\s*([^}]+?))?\s*\}',
        route_header.read_text(encoding="utf-8"),
    )

    return {
        (method, path): {
            "body": _csv_fields(body_fields),
            "query": _csv_fields(query_fields),
            "execution": {"direct"} if "kRestRouteExecutionDirect" in execution_model else {"ui-thread"},
        }
        for method, path, body_fields, query_fields, execution_model in route_specs
    }


def _openapi_component_parameters(lines: list[str]) -> dict[str, dict[str, str | None]]:
    parameters: dict[str, dict[str, str | None]] = {}
    in_components = False
    in_parameters = False
    current_name: str | None = None
    current_block: list[str] = []

    def commit() -> None:
        if current_name is None:
            return
        name = None
        location = None
        for line in current_block:
            stripped = line.strip()
            if stripped.startswith("name:"):
                name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("in:"):
                location = stripped.split(":", 1)[1].strip()
        parameters[current_name] = {"name": name, "in": location}

    for line in lines:
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        if line.startswith("  parameters:"):
            in_parameters = True
            continue
        if in_parameters and line.startswith("  ") and not line.startswith("    ") and not line.startswith("  parameters:"):
            commit()
            break
        if not in_parameters:
            continue
        match = re.match(r"    ([A-Za-z0-9_]+):\s*$", line)
        if match:
            commit()
            current_name = match.group(1)
            current_block = []
        elif current_name is not None:
            current_block.append(line)
    return parameters


def _openapi_schema_properties(lines: list[str]) -> dict[str, set[str]]:
    schemas: dict[str, set[str]] = {}
    in_components = False
    in_schemas = False
    current_name: str | None = None
    in_properties = False
    properties: set[str] = set()

    def commit() -> None:
        if current_name is not None:
            schemas[current_name] = set(properties)

    for line in lines:
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        if line.startswith("  schemas:"):
            in_schemas = True
            continue
        if not in_schemas:
            continue
        schema_match = re.match(r"    ([A-Za-z0-9_]+):\s*$", line)
        if schema_match:
            commit()
            current_name = schema_match.group(1)
            in_properties = False
            properties = set()
            continue
        if current_name is None:
            continue
        if line.startswith("      properties:"):
            in_properties = True
            continue
        if in_properties:
            prop_match = re.match(r"        ([A-Za-z0-9_]+):\s*$", line)
            if prop_match:
                properties.add(prop_match.group(1))
            elif line and _indent(line) <= 6:
                in_properties = False
    commit()
    return schemas


def _openapi_operation_contracts(openapi_path: Path) -> dict[tuple[str, str], dict[str, set[str]]]:
    lines = openapi_path.read_text(encoding="utf-8").splitlines()
    component_parameters = _openapi_component_parameters(lines)
    schema_properties = _openapi_schema_properties(lines)
    operations: dict[tuple[str, str], dict[str, set[str]]] = {}
    current_path: str | None = None
    current_method: str | None = None
    block: list[str] = []

    def parse_operation_block() -> dict[str, set[str]]:
        body_fields: set[str] = set()
        query_fields: set[str] = set()
        in_parameters = False
        in_request_body = False
        for index, line in enumerate(block):
            stripped = line.strip()
            if _indent(line) == 6 and stripped == "parameters:":
                in_parameters = True
                in_request_body = False
                continue
            if _indent(line) == 6 and stripped == "requestBody:":
                in_request_body = True
                in_parameters = False
                continue
            if _indent(line) <= 6 and stripped not in {"parameters:", "requestBody:"}:
                in_parameters = False
                in_request_body = False
            if in_parameters:
                parameter_ref = _component_ref_name(line, "parameters")
                if parameter_ref is not None:
                    parameter = component_parameters[parameter_ref]
                    if parameter["in"] == "query":
                        query_fields.add(str(parameter["name"]))
                direct_name = re.match(r"        - name: (.+)$", line)
                if direct_name:
                    location = None
                    for nested in block[index + 1 :]:
                        if re.match(r"        - ", nested) or _indent(nested) <= 6:
                            break
                        if nested.strip().startswith("in:"):
                            location = nested.strip().split(":", 1)[1].strip()
                    if location == "query":
                        query_fields.add(direct_name.group(1).strip())
            if in_request_body:
                schema_ref = _component_ref_name(line, "schemas")
                if schema_ref is not None:
                    body_fields.update(schema_properties.get(schema_ref, set()))
        return {"body": body_fields, "query": query_fields}

    def commit() -> None:
        if current_path is not None and current_method is not None:
            operations[(current_method, current_path)] = parse_operation_block()

    for line in lines:
        if line.startswith("components:"):
            commit()
            break
        path_match = re.match(r"  (/[^:]+):\s*$", line)
        if path_match:
            commit()
            current_path = path_match.group(1)
            current_method = None
            block = []
            continue
        method_match = re.match(r"    (get|post|patch|delete):\s*$", line)
        if method_match:
            commit()
            current_method = method_match.group(1).upper()
            block = []
            continue
        if current_method is not None:
            block.append(line)
    return operations


def test_native_route_specs_match_openapi_methods_paths_and_fields() -> None:
    module = load_rest_api_smoke_module()
    native_contracts = {
        route_key: {
            "body": contract["body"],
            "query": contract["query"],
        }
        for route_key, contract in _native_route_contracts().items()
        if route_key not in PRIVATE_NATIVE_ONLY_ROUTES
    }
    openapi_contracts = _openapi_operation_contracts(module.OPENAPI_CONTRACT_PATH)

    assert native_contracts == openapi_contracts


def test_rest_v1_paging_surface_is_intentionally_narrow() -> None:
    contracts = _openapi_operation_contracts(load_rest_api_smoke_module().OPENAPI_CONTRACT_PATH)

    assert contracts[("GET", "/shared-files")]["query"] == {"limit", "offset"}
    assert contracts[("GET", "/upload-queue")]["query"] == {"limit", "offset"}
    assert contracts[("GET", "/logs")]["query"] == {"limit"}
    assert contracts[("GET", "/snapshot")]["query"] == {"limit"}

    unpaged_routes = {
        ("GET", "/categories"),
        ("GET", "/transfers"),
        ("GET", "/transfers/{hash}/sources"),
        ("GET", "/transfers/{hash}/sources/{clientId}"),
        ("GET", "/shared-files/{hash}/comments"),
        ("GET", "/uploads"),
        ("GET", "/uploads/{clientId}"),
        ("GET", "/upload-queue/{clientId}"),
        ("GET", "/servers"),
        ("GET", "/friends"),
        ("GET", "/searches"),
        ("GET", "/searches/{searchId}"),
    }
    for route_key in unpaged_routes:
        assert "limit" not in contracts[route_key]["query"]
        assert "offset" not in contracts[route_key]["query"]


def test_native_route_execution_model_inventory_matches_dispatch_boundary() -> None:
    module = load_rest_api_smoke_module()
    native_contracts = _native_route_contracts()
    direct_routes = sorted(
        route_key for route_key, contract in native_contracts.items() if contract["execution"] == {"direct"}
    )
    ui_thread_routes = sorted(
        route_key for route_key, contract in native_contracts.items() if contract["execution"] == {"ui-thread"}
    )
    routes_by_operation = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}

    assert direct_routes == [("GET", "/app")]
    assert len(direct_routes) + len(ui_thread_routes) == len(native_contracts)
    assert routes_by_operation["getApp"]["executionModel"] == "direct"
    assert routes_by_operation["getPreferences"]["executionModel"] == "ui-thread"
    assert routes_by_operation["shutdownApp"]["executionModel"] == "ui-thread"
    assert all(route["executionModel"] in {"direct", "ui-thread"} for route in module.REST_CONTRACT_ROUTES)


def test_destructive_native_routes_require_explicit_confirmation_or_intent() -> None:
    native_contracts = _native_route_contracts()
    required_body_fields = {
        ("POST", "/app/shutdown"): {"confirmShutdown"},
        ("POST", "/diagnostics/dumps"): {"confirmDump"},
        ("POST", "/transfers/operations/clear-completed"): {"confirmClearCompleted"},
        ("DELETE", "/transfers/{hash}"): {"deleteFiles"},
        ("DELETE", "/shared-files/{hash}"): {"deleteFiles"},
        ("PATCH", "/shared-directories"): {"confirmReplaceRoots"},
        ("DELETE", "/searches"): {"confirmDeleteAllSearches"},
        ("POST", "/logs/operations/clear"): {"confirmClearLogs"},
        ("POST", "/diagnostics/crash-tests"): {"confirmCrash"},
    }
    id_targeted_delete_routes = {
        ("DELETE", "/categories/{categoryId}"),
        ("DELETE", "/servers/{serverId}"),
        ("DELETE", "/searches/{searchId}"),
        ("DELETE", "/friends/{userHash}"),
    }

    for route_key, required_fields in required_body_fields.items():
        assert required_fields <= native_contracts[route_key]["body"]

    for route_key in id_targeted_delete_routes:
        assert route_key in native_contracts

    audited_delete_routes = {
        route_key for route_key in required_body_fields if route_key[0] == "DELETE"
    } | id_targeted_delete_routes
    delete_routes = {route_key for route_key in native_contracts if route_key[0] == "DELETE"}
    assert delete_routes == audited_delete_routes


def test_openapi_contract_routes_are_the_live_completeness_source() -> None:
    module = load_rest_api_smoke_module()

    routes_by_operation = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}

    assert routes_by_operation["getApp"]["path"] == "/api/v1/app"
    assert routes_by_operation["getApp"]["safety"] == "safe"
    assert routes_by_operation["getApp"]["successResponseStatuses"] == ["200"]
    assert routes_by_operation["getApp"]["successResponseRefs"] == ["AppResponse"]
    assert routes_by_operation["getApp"]["responseEnvelope"] == "AppResponse"
    assert routes_by_operation["getSnapshot"]["path"] == "/api/v1/snapshot?limit=7"
    assert routes_by_operation["getTransfer"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}"
    assert routes_by_operation["getTransfer"]["responseEnvelope"] == "TransferResponse"
    assert routes_by_operation["getTransferDetails"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details"
    assert routes_by_operation["getTransferDetails"]["responseEnvelope"] == "TransferDetailsResponse"
    assert routes_by_operation["removeUploadClient"]["method"] == "POST"
    assert routes_by_operation["removeUploadClient"]["path"] == (
        f"/api/v1/uploads/{module.REST_SURFACE_MISSING_HASH}/operations/remove"
    )
    assert routes_by_operation["downloadSearchResult"]["path"] == (
        f"/api/v1/searches/123/results/{module.REST_SURFACE_MISSING_HASH}/operations/download"
    )
    assert routes_by_operation["shutdownApp"]["safe"] is False
    assert routes_by_operation["shutdownApp"]["safety"] == "unsafe"
    assert routes_by_operation["shutdownApp"]["successResponseStatuses"] == ["200"]
    assert routes_by_operation["shutdownApp"]["responseEnvelope"] == "OkAcceptedResponse"
    assert routes_by_operation["captureDiagnosticDump"]["safe"] is False
    assert routes_by_operation["captureDiagnosticDump"]["safety"] == "unsafe"
    assert routes_by_operation["captureDiagnosticDump"]["responseEnvelope"] == "DiagnosticDumpResponse"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safe"] is False
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safety"] == "unsafe"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["responseEnvelope"] == "OkAcceptedResponse"
    assert all(len(route["successResponseRefs"]) == 1 for route in module.REST_CONTRACT_ROUTES)
    assert all(route["responseEnvelope"] == route["successResponseRefs"][0] for route in module.REST_CONTRACT_ROUTES)


def test_openapi_response_schema_validation_rejects_extra_fields(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    openapi_path = tmp_path / "openapi.yaml"
    openapi_path.write_text(
        """
openapi: 3.1.0
components:
  responses:
    StrictResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/StrictEnvelope"
  schemas:
    StrictEnvelope:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          type: object
          additionalProperties: false
          required: [ok]
          properties:
            ok:
              type: boolean
""",
        encoding="utf-8",
    )

    module.validate_openapi_response_payload("StrictResponse", {"data": {"ok": True}}, openapi_path)
    with pytest.raises(module.jsonschema.ValidationError):
        module.validate_openapi_response_payload("StrictResponse", {"data": {"ok": True, "extra": 1}}, openapi_path)


def test_qbit_compat_torrent_list_uses_native_transfer_command() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "WebServerQBitCompat.cpp"
    source = source_path.read_text(encoding="utf-8")

    assert 'BuildInternalCommand("transfers/list"' in source
    assert "theApp.downloadqueue" not in source
    assert "CPartFile" not in source


def test_arr_compat_uses_shared_native_validation_and_search_commands() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"
    tooling_docs = workspace_root / "repos" / "eMule-tooling" / "docs" / "rest"
    source = (app_source / "WebServerArrCompat.cpp").read_text(encoding="utf-8")
    seams = (app_source / "WebServerArrCompatSeams.h").read_text(encoding="utf-8")
    adapter_docs = (tooling_docs / "REST-API-ADAPTERS.md").read_text(encoding="utf-8")
    parity_docs = (tooling_docs / "REST-API-PARITY-INVENTORY.md").read_text(encoding="utf-8")

    assert 'BuildInternalCommand("search/start"' in source
    assert 'BuildInternalCommand("search/results"' in source
    assert 'BuildInternalCommand("search/stop"' in source
    assert '"method", rMethod' in source
    assert '"type", rSearchType' in source
    assert 'BuildInternalCommand("status/get"' in source
    assert "BuildAvailableNativeSearchMethods(request.eFamily)" in source
    assert "BuildCacheKey(request, nativeSearchMethods)" in source
    assert "RunNativeSearches(request, nativeSearchMethods)" in source
    assert "BuildNativeSearchMethodNames(eFamily)" in source
    assert "BuildRestSearchTypeNames(rRequest.eFamily)" in source
    assert "WebServerJsonSeams::TryValidateRequestPathEscapes" in seams
    assert "WebServerJsonSeams::TryParseQueryString" in seams
    assert "WebServerJsonSeams::TryNormalizeSearchText" in seams
    assert "WebServerJsonSeams::TryParseUnsignedDecimalValue" in seams
    assert "WebServerJsonSeams::TryValidatePublicFileNameText" in seams
    assert "WebServerJsonSeams::NormalizeAsciiWhitespace" in seams
    assert seams.index('methods.push_back("global")') < seams.index('methods.push_back("kad")')
    assert "BuildAvailableNativeSearchMethodNames" in seams
    assert "BuildNativeSearchMethodsCacheToken" in seams
    assert "IsConnectedNetworkSearchMethod" in seams
    assert 'return "video";' in seams
    assert "REST `video` searches" in adapter_docs
    assert "adapter-side result filter" in adapter_docs
    assert "REST `video` searches" in parity_docs


def test_native_search_resources_echo_selected_type() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "WebServerJson.cpp"
    source = source_path.read_text(encoding="utf-8")

    rest_type_formatter = "WebServerJsonSeams::GetRestSearchFileTypeName(StdUtf8FromCString(rFileType))"
    native_type_assignment = (
        "pSearchParams->strFileType = CStringFromStdUtf8("
        "WebServerJsonSeams::GetNativeSearchFileTypeName(request.strFileType));"
    )
    assert rest_type_formatter in source
    assert native_type_assignment in source

    assert "GetSearchTypeName(pSearchParams->strFileType)" in source
    assert "GetSearchTypeName(rSearchParams.strFileType)" in source


def test_qbit_compat_uses_shared_native_validation_and_bridge_commands() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"
    source = (app_source / "WebServerQBitCompat.cpp").read_text(encoding="utf-8")
    seams = (app_source / "WebServerQBitCompatSeams.h").read_text(encoding="utf-8")

    assert "WebServerJson::BuildInternalCommand" in source
    assert 'BuildInternalCommand("transfers/add"' in source
    assert 'ExecuteHashBulkCommand("transfers/delete"' in source
    assert 'BuildInternalCommand("transfers/set_category"' in source
    assert 'BuildInternalCommand("transfers/get"' in source
    assert "WebServerJsonSeams::TryValidateRequestPathEscapes" in seams
    assert "WebServerJsonSeams::TryParseQueryString" in seams
    assert "WebServerJsonSeams::TryParseUrlEncodedFields" in seams
    assert "WebServerJsonSeams::TryNormalizeCategoryNameText" in seams
    assert "WebServerJsonSeams::TryValidatePublicFileNameText" in seams
    assert "WebServerJsonSeams::TryParseUnsignedDecimalValue" in seams
    assert "WebServerJsonSeams::UrlEncodeUtf8" in seams


def test_rest_contract_registry_covers_release_families() -> None:
    module = load_rest_api_smoke_module()

    families = {route["family"] for route in module.REST_CONTRACT_ROUTES}

    assert families == {
        "app",
        "categories",
        "diagnostics",
        "friends",
        "kad",
        "logs",
        "searches",
        "servers",
        "shared",
        "shared-directories",
        "status",
        "transfers",
        "uploads",
    }
    assert any(route["operationId"] == "shutdownApp" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)
    assert any(route["operationId"] == "captureDiagnosticDump" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)
    assert any(route["operationId"] == "triggerDiagnosticCrashTest" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)


def test_rest_contract_summary_counts_outcomes_and_methods() -> None:
    module = load_rest_api_smoke_module()

    summary = module.build_contract_coverage_summary(
        [
            {
                "name": "getApp",
                "operationId": "getApp",
                "family": "app",
                "method": "GET",
                "path": "/api/v1/app",
                "safe": True,
                "safety": "safe",
                "responseEnvelope": "AppResponse",
                "executionModel": "direct",
                "skipped": False,
                "ok": True,
                "outcome": "success",
            },
            {
                "name": "getTransfer",
                "operationId": "getTransfer",
                "family": "transfers",
                "method": "GET",
                "path": f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}",
                "safe": True,
                "safety": "safe",
                "responseEnvelope": "TransferResponse",
                "executionModel": "ui-thread",
                "skipped": False,
                "ok": True,
                "outcome": "expected_error",
            },
            {
                "name": "shutdownApp",
                "operationId": "shutdownApp",
                "family": "app",
                "method": "POST",
                "path": "/api/v1/app/shutdown",
                "safe": False,
                "safety": "unsafe",
                "responseEnvelope": "OkAcceptedResponse",
                "executionModel": "ui-thread",
                "skipped": True,
                "ok": True,
                "outcome": "skipped_unsafe",
            },
        ],
        "contract",
    )

    assert summary["safe_route_count"] == 2
    assert summary["unsafe_route_count"] == 1
    assert summary["exercised_route_count"] == 2
    assert summary["success_count"] == 1
    assert summary["expected_error_count"] == 1
    assert summary["method_counts"] == {"GET": 2, "POST": 1}
    assert summary["response_envelope_counts"] == {"AppResponse": 1, "TransferResponse": 1, "OkAcceptedResponse": 1}
    assert summary["safety_counts"] == {"safe": 2, "unsafe": 1}
    assert summary["execution_model_counts"] == {"direct": 1, "ui-thread": 2}
    assert summary["outcome_counts"]["skipped_unsafe"] == 1


def test_live_search_plan_covers_release_query_corpus() -> None:
    module = load_rest_api_smoke_module()

    search_terms = ("linux", "ubuntu", "fedora", "freebsd", "debian", "emule")
    server_count = len(search_terms)
    kad_count = len(search_terms)
    plan = module.build_search_plan(server_count, kad_count, search_terms)

    assert [row["query"] for row in plan[:server_count]] == list(search_terms)
    assert [row["query_index"] for row in plan[:server_count]] == list(range(server_count))
    assert [row["network"] for row in plan[:server_count]] == ["server"] * server_count
    assert [row["query"] for row in plan[server_count:]] == list(search_terms)
    assert [row["query_index"] for row in plan[server_count:]] == list(range(kad_count))
    assert [row["network"] for row in plan[server_count:]] == ["kad"] * kad_count
    assert all("query" not in row for row in module.summarize_search_plan(plan))


def test_live_search_start_uses_broad_file_type_for_release_terms(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"id": "42"},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.start_live_search("http://127.0.0.1:1", "key", "server", "fedora", forced_method="server")

    assert result["ok"] is True
    assert requests[0]["path"] == "/api/v1/searches"
    assert requests[0]["json_body"] == {
        "query": "fedora",
        "method": "server",
        "type": "",
    }


def test_delete_all_searches_uses_confirmation_payload(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.delete_all_searches("http://127.0.0.1:1", "key")

    assert result["status"] == 200
    assert requests == [
        {
            "path": "/api/v1/searches",
            "method": "DELETE",
            "api_key": "key",
            "json_body": {"confirmDeleteAllSearches": True},
        }
    ]


def test_verify_searches_deleted_requires_each_search_to_404(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[str] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append(path)
        return {
            "status": 404,
            "content_type": "application/json; charset=utf-8",
            "json": {"error": "NOT_FOUND", "message": "search not found"},
            "raw_json": {
                "error": {
                    "code": "NOT_FOUND",
                    "message": "search not found",
                    "details": {},
                }
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.verify_searches_deleted("http://127.0.0.1:1", "key", ["42", "43"])

    assert result["checked"] == 2
    assert requests == ["/api/v1/searches/42", "/api/v1/searches/43"]


def test_clear_completed_transfers_uses_confirmation_payload(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.clear_completed_transfers("http://127.0.0.1:1", "key")

    assert result["status"] == 200
    assert requests == [
        {
            "path": "/api/v1/transfers/operations/clear-completed",
            "method": "POST",
            "api_key": "key",
            "json_body": {"confirmClearCompleted": True},
        }
    ]


def test_clear_logs_uses_confirmation_payload(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.clear_logs("http://127.0.0.1:1", "key")

    assert result["status"] == 200
    assert requests == [
        {
            "path": "/api/v1/logs/operations/clear",
            "method": "POST",
            "api_key": "key",
            "json_body": {"confirmClearLogs": True},
        }
    ]


def test_extract_triggered_transfer_hashes_uses_live_transfer_response() -> None:
    module = load_rest_api_smoke_module()

    cycles = [
        {
            "download_trigger": {
                "ok": True,
                "transfer": {
                    "json": {
                        "hash": "0123456789abcdef0123456789abcdef",
                    },
                },
            },
        },
        {
            "download_trigger": {
                "ok": True,
                "transfer": {
                    "json": {
                        "hash": "0123456789ABCDEF0123456789ABCDEF",
                    },
                },
            },
        },
        {"download_trigger": {"ok": False}},
    ]

    assert module.extract_triggered_transfer_hashes(cycles) == ["0123456789abcdef0123456789abcdef"]


def test_verify_transfers_still_exist_requires_hash_match(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[str] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append(path)
        transfer_hash = path.rsplit("/", 1)[-1]
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"hash": transfer_hash},
            "raw_json": {
                "data": {"hash": transfer_hash},
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.verify_transfers_still_exist(
        "http://127.0.0.1:1",
        "key",
        ["0123456789abcdef0123456789abcdef"],
    )

    assert result["checked"] == 1
    assert requests == ["/api/v1/transfers/0123456789abcdef0123456789abcdef"]


def test_live_download_candidate_filter_rejects_unsafe_rows() -> None:
    module = load_rest_api_smoke_module()

    safe = {
        "hash": "0123456789abcdef0123456789abcdef",
        "name": "linux.iso",
        "sizeBytes": 1024,
        "fileType": "Iso",
        "sources": module.MIN_SAFE_LIVE_DOWNLOAD_SOURCES,
        "completeSources": 0,
    }

    assert module.is_safe_live_download_result(safe) is True
    assert module.is_safe_live_download_result({**safe, "name": "setup.exe"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "installer.msi"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "bundle.rar", "fileType": "Arc"}) is False
    assert module.is_safe_live_download_result({**safe, "fileType": "Pro"}) is False
    assert module.is_safe_live_download_result({**safe, "hash": "0123456789ABCDEF0123456789ABCDEF"}) is False
    assert module.is_safe_live_download_result({**safe, "sizeBytes": 0}) is False
    assert module.is_safe_live_download_result({**safe, "sizeBytes": module.MAX_SAFE_LIVE_DOWNLOAD_BYTES + 1}) is False
    assert module.is_safe_live_download_result({**safe, "sources": module.MIN_SAFE_LIVE_DOWNLOAD_SOURCES - 1}) is False


def test_live_download_trigger_posts_paused_download(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        if path.endswith("/operations/download"):
            return {
                "status": 200,
                "content_type": "application/json",
                "json": {"ok": True},
                "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
                "body_text": "{}",
            }
        if path == "/api/v1/transfers/0123456789abcdef0123456789abcdef":
            return {
                "status": 200,
                "content_type": "application/json",
                "json": {
                    "hash": "0123456789abcdef0123456789abcdef",
                    "name": "linux.iso",
                    "sizeBytes": 1024,
                    "complete": False,
                },
                "raw_json": {
                    "data": {
                        "hash": "0123456789abcdef0123456789abcdef",
                        "name": "linux.iso",
                        "sizeBytes": 1024,
                        "complete": False,
                    },
                    "meta": {"apiVersion": "v1"},
                },
                "body_text": "{}",
            }
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {
                "id": "42",
                "query": "linux",
                "method": "kad",
                "type": "iso",
                "status": "running",
                "results": [
                    {
                        "method": "kad",
                        "type": "iso",
                        "hash": "0123456789abcdef0123456789abcdef",
                        "name": "linux.iso",
                        "sizeBytes": 1024,
                        "fileType": "Iso",
                        "sources": 2,
                        "completeSources": 0,
                    }
                ],
            },
            "raw_json": {
                "data": {
                    "id": "42",
                    "query": "linux",
                    "method": "kad",
                    "type": "iso",
                    "status": "running",
                    "results": [
                        {
                            "method": "kad",
                            "type": "iso",
                            "hash": "0123456789abcdef0123456789abcdef",
                            "name": "linux.iso",
                            "sizeBytes": 1024,
                            "fileType": "Iso",
                            "sources": 2,
                            "completeSources": 0,
                        }
                    ],
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.trigger_paused_download_from_search_result("http://127.0.0.1:1", "key", "42", 1.0)

    assert result["ok"] is True
    assert requests[-2]["path"] == "/api/v1/searches/42/results/0123456789abcdef0123456789abcdef/operations/download"
    assert requests[-2]["json_body"] == {"paused": True, "categoryId": 0}
    assert requests[-1]["path"] == "/api/v1/transfers/0123456789abcdef0123456789abcdef"
    assert result["transfer"]["status"] == 200


def test_triggered_transfer_wait_rejects_hash_mismatch(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url, _path, **_kwargs):
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "raw_json": {
                "data": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    with pytest.raises(AssertionError, match="hash mismatch"):
        module.wait_for_triggered_transfer(
            "http://127.0.0.1:1",
            "key",
            "0123456789abcdef0123456789abcdef",
            1.0,
        )


def test_live_download_trigger_timeout_without_candidate_is_nonfatal(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url, _path, **_kwargs):
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {
                "id": "42",
                "query": "linux",
                "method": "kad",
                "type": "",
                "status": "running",
                "results": [],
            },
            "raw_json": {
                "data": {
                    "id": "42",
                    "query": "linux",
                    "method": "kad",
                    "type": "",
                    "status": "running",
                    "results": [],
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.trigger_paused_download_from_search_result("http://127.0.0.1:1", "key", "42", 0.01)

    assert result["ok"] is False
    assert result["reason"] == "timed out without a safe download candidate"
    assert result["observations"]


def test_rest_stress_config_rejects_invalid_values() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(ValueError, match="duration"):
        module.validate_rest_stress_config(
            budget="smoke",
            duration_seconds=0,
            concurrency=1,
            max_failures=0,
            request_timeout_seconds=1,
        )
    with pytest.raises(ValueError, match="concurrency"):
        module.validate_rest_stress_config(
            budget="smoke",
            duration_seconds=1,
            concurrency=0,
            max_failures=0,
            request_timeout_seconds=1,
        )


def test_rest_stress_operations_include_safe_mutation_routes() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    method_path_pairs = {(operation["method"], operation["path"]) for operation in operations}
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert ("GET", "/api/v1/status") in method_path_pairs
    assert ("GET", "/api/v1/shared-directories") in method_path_pairs
    assert operations_by_pair[("GET", "/api/v1/status")]["expected_statuses"] == (200,)
    assert ("PATCH", "/api/v1/app/preferences") in method_path_pairs
    assert ("POST", "/api/v1/transfers") in method_path_pairs
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/operations/pause") in method_path_pairs
    assert ("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}") in method_path_pairs
    assert operations_by_pair[("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}")][
        "expected_statuses"
    ] == (400,)
    assert operations_by_pair[("DELETE", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}")][
        "scenario"
    ] == "transfer_delete_requires_delete_files"
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse") in method_path_pairs
    assert operations_by_pair[
        ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse")
    ]["json_body"] == {}
    assert operations_by_pair[("POST", "/api/v1/logs/operations/clear")]["json_body"] == {"confirmClearLogs": True}
    assert ("POST", "/api/v1/kad/operations/recheck-firewall") in method_path_pairs
    assert ("POST", "/api/v1/searches") in method_path_pairs
    assert ("DELETE", "/api/v1/searches/123") in method_path_pairs


def test_shutdown_is_excluded_from_broad_stress_mutation_loops() -> None:
    module = load_rest_api_smoke_module()

    audit = module.assert_shutdown_excluded_from_broad_mutation_loops()

    assert audit["ok"] is True
    assert "/api/v1/app/shutdown" in audit["excluded_paths"]
    assert "/api/v1/diagnostics/dumps" in audit["excluded_paths"]
    assert "/api/v1/diagnostics/crash-tests" in audit["excluded_paths"]
    assert set(audit["stress_budgets"]) == {"smoke", "soak"}
    for budget in ("smoke", "soak"):
        operations = module.build_rest_stress_operations(budget)
        assert all(operation["path"] != "/api/v1/app/shutdown" for operation in operations)
        assert all(operation["path"] != "/api/v1/diagnostics/dumps" for operation in operations)
        assert all(operation["path"] != "/api/v1/diagnostics/crash-tests" for operation in operations)
        assert audit["stress_budgets"][budget]["unsafe_path_match_count"] == 0
        assert audit["stress_budgets"][budget]["operation_count"] == len(operations)
    routes_by_operation = {route["operationId"]: route for route in audit["contract_routes"]}
    assert set(routes_by_operation) == {"captureDiagnosticDump", "shutdownApp", "triggerDiagnosticCrashTest"}
    assert routes_by_operation["shutdownApp"]["path"] == "/api/v1/app/shutdown"
    assert routes_by_operation["shutdownApp"]["safe"] is False
    assert routes_by_operation["shutdownApp"]["safety"] == "unsafe"
    assert routes_by_operation["captureDiagnosticDump"]["path"] == "/api/v1/diagnostics/dumps"
    assert routes_by_operation["captureDiagnosticDump"]["safe"] is False
    assert routes_by_operation["captureDiagnosticDump"]["safety"] == "unsafe"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["path"] == "/api/v1/diagnostics/crash-tests"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safe"] is False
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safety"] == "unsafe"


def test_rest_stress_operations_include_expected_error_edges() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert operations_by_pair[("GET", "/api/v1/logs?limit=%2x")]["scenario"] == "malformed_percent_escape"
    assert operations_by_pair[("GET", "/api/v1/logs?limit=%2x")]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/api/v1/logs%2x?limit=10")]["scenario"] == "malformed_route_escape"
    assert operations_by_pair[("GET", "/api/v1/logs?limit=10&limit=20")]["scenario"] == "duplicate_query_parameter"
    assert operations_by_pair[("get", "/api/v1/app")]["scenario"] == "lowercase_method_rejected"
    assert operations_by_pair[("get", "/api/v1/app")]["expected_statuses"] == (400,)
    assert operations_by_pair[
        ("GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF")
    ]["scenario"] == "uppercase_hash_rejected"
    assert operations_by_pair[
        ("GET", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details")
    ]["scenario"] == "missing_transfer_details_rejected"
    assert operations_by_pair[
        ("GET", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details")
    ]["expected_statuses"] == (404,)
    assert operations_by_pair[("POST", "/api/v1/transfers")]["expected_statuses"] == (400,)
    assert any(
        operation["scenario"] == "conflicting_category_fields"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert any(
        operation["scenario"] == "unicode_query_length_rejected"
        and operation["expected_statuses"] == (400,)
        and "λ" in operation["json_body"]["query"]
        for operation in operations
    )
    assert any(
        operation["scenario"] == "long_unicode_shared_file_path_rejected"
        and operation["expected_statuses"] == (400,)
        and "λ" in operation["json_body"]["path"]
        and "例" in operation["json_body"]["path"]
        and "\\" not in operation["json_body"]["path"]
        for operation in operations
    )


def test_rest_stress_operations_include_adapter_traffic_without_legacy_html() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps")]["response_kind"] == "xml"
    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps&t=search")]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps&apikey=wrong-key")]["expected_statuses"] == (401,)
    assert operations_by_pair[
        ("GET", "/indexer/emulebb/api?t=search&season=abc&q=linux&apikey={api_key}")
    ]["api_key"] is False
    assert operations_by_pair[
        ("GET", "/indexer/emulebb/api?t=search&cat=abc&q=linux&apikey={api_key}")
    ]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/api/v2/app/webapiVersion")]["response_kind"] == "text"
    assert any(
        operation["method"] == "GET"
        and operation["path"] == "/api/v2/torrents/categories"
        and operation["scenario"] == "qbit_categories"
        and operation["extra_headers"] == {"Cookie": "{qbit_session_cookie}"}
        for operation in operations
    )
    assert any(
        operation["method"] == "GET"
        and operation["path"] == "/api/v2/torrents/categories"
        and operation["scenario"] == "qbit_wrong_cookie_rejected"
        and operation["expected_statuses"] == (403,)
        and operation["extra_headers"] == {"Cookie": "SID=wrong"}
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/auth/login"
        and operation["scenario"] == "qbit_bad_login_rejected"
        and operation["raw_body"] == "username=emule&password=wrong-key"
        and operation["expected_statuses"] == (200,)
        and operation["expected_body_contains"] == "Fails."
        for operation in operations
    )
    assert operations_by_pair[
        ("GET", f"/api/v2/torrents/properties?hash={module.REST_SURFACE_MISSING_HASH}")
    ]["expected_statuses"] == (404,)
    assert operations_by_pair[("POST", "/api/v2/torrents/pause")]["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}"
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/delete"
        and operation["scenario"] == "qbit_missing_hash_delete"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&deleteFiles=false"
        and operation["expected_statuses"] == (200,)
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/delete"
        and operation["scenario"] == "qbit_bad_delete_boolean_rejected"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&deleteFiles=wat"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/setForceStart"
        and operation["scenario"] == "qbit_bad_force_start_boolean_rejected"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&value=wat"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert ("GET", "/") not in operations_by_pair
    assert all(operation.get("family") != "legacy-html" for operation in operations)
    assert all(operation.get("response_kind") != "html" for operation in operations)


def test_rest_stress_summary_is_bounded_and_deterministic() -> None:
    module = load_rest_api_smoke_module()

    summary = module.summarize_rest_stress_results(
        [
            {
                "path": "/ok",
                "status": 200,
                "ok": True,
                "duration_ms": 1.0,
                "scenario": "read",
                "content_type": "application/json; charset=utf-8",
                "native_rest_json": True,
            },
            {
                "path": "/missing",
                "status": 404,
                "ok": True,
                "duration_ms": 4.0,
                "scenario": "safe_mutation",
                "content_type": "application/json; charset=utf-8",
                "native_rest_json": True,
            },
            {
                "path": "/boom",
                "status": "exception",
                "ok": False,
                "duration_ms": 9.0,
                "error": "timeout",
                "scenario": "read",
                "content_type": "application/xml",
                "native_rest_json": False,
            },
        ],
        budget="smoke",
        duration_seconds=30.0,
        concurrency=4,
        max_failures=1,
    )

    assert summary["ok"] is True
    assert summary["budget"] == "smoke"
    assert summary["requests_completed"] == 3
    assert summary["status_counts"] == {"200": 1, "404": 1, "exception": 1}
    assert summary["method_counts"] == {"UNKNOWN": 3}
    assert summary["scenario_counts"] == {"read": 2, "safe_mutation": 1}
    assert summary["content_type_counts"] == {"application/json; charset=utf-8": 2, "application/xml": 1}
    assert summary["error_counts"] == {"timeout": 1}
    assert summary["timeout_count"] == 1
    assert summary["native_rest_non_json_count"] == 1
    assert summary["retry_attempt_count"] == 0
    assert summary["retried_success_count"] == 0
    assert summary["latency_ms"]["max"] == 9.0
    assert len(summary["failures_sample"]) == 1


def test_rest_stress_retry_classification_is_limited_to_transient_resets() -> None:
    module = load_rest_api_smoke_module()

    assert module.is_retryable_rest_stress_exception(
        RuntimeError("<urlopen error [WinError 10054] An existing connection was forcibly closed by the remote host>")
    )
    assert module.is_retryable_rest_stress_exception(
        RuntimeError("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol")
    )
    assert not module.is_retryable_rest_stress_exception(
        RuntimeError("<urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>")
    )
    assert not module.is_retryable_rest_stress_exception(TimeoutError("timed out"))


def test_rest_stress_summary_reports_retry_recovery() -> None:
    module = load_rest_api_smoke_module()

    summary = module.summarize_rest_stress_results(
        [
            {"status": 200, "ok": True, "duration_ms": 2.0, "retry_count": 1},
            {"status": "exception", "ok": False, "duration_ms": 3.0, "retry_count": 2, "error": "reset"},
        ],
        budget="soak",
        duration_seconds=30.0,
        concurrency=64,
        max_failures=1,
    )

    assert summary["ok"] is True
    assert summary["retry_attempt_count"] == 3
    assert summary["retried_success_count"] == 1


def test_server_connect_transport_loss_is_runtime_failure_signal() -> None:
    module = load_rest_api_smoke_module()

    assert module.did_rest_listener_disappear(
        [
            {"connected": False},
            {"transport_error": {"message": "<urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>"}},
        ]
    )
    assert not module.did_rest_listener_disappear([{"connected": False, "connecting": False}])


def test_close_app_cleanly_with_timing_records_shutdown_duration() -> None:
    module = load_rest_api_smoke_module()
    closed: list[object] = []

    result = module.close_app_cleanly_with_timing("app", close_func=closed.append)

    assert closed == ["app"]
    assert result["app_closed"] is True
    assert isinstance(result["shutdown_duration_ms"], float)
    assert result["shutdown_duration_ms"] >= 0.0


def test_rest_contract_completeness_skips_shutdown(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    observed_paths: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        observed_paths.append((method, path))
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    monkeypatch.setattr(module, "validate_openapi_response_payload", lambda *_args, **_kwargs: None)

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert ("POST", "/api/v1/app/shutdown") not in observed_paths
    assert ("POST", "/api/v1/diagnostics/dumps") not in observed_paths
    assert ("POST", "/api/v1/diagnostics/crash-tests") not in observed_paths
    assert any(route["operationId"] == "shutdownApp" and route["skipped"] for route in summary["routes"])
    assert any(route["operationId"] == "captureDiagnosticDump" and route["skipped"] for route in summary["routes"])
    assert any(route["operationId"] == "triggerDiagnosticCrashTest" and route["skipped"] for route in summary["routes"])


def test_rest_contract_completeness_rejects_undeclared_4xx(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "getApp",
                "operationId": "getApp",
                "family": "app",
                "method": "GET",
                "path": "/api/v1/app",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": False,
                "requestBodyRequired": False,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["AppResponse"],
                "responseEnvelope": "AppResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "bad request"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "bad request", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is False
    assert summary["failed_routes"] == ["getApp"]
    assert summary["routes"][0]["outcome"] == "unexpected_error"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200]


def test_rest_contract_completeness_accepts_declared_negative_probe(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "createSearch",
                "operationId": "createSearch",
                "family": "searches",
                "method": "POST",
                "path": "/api/v1/searches",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": True,
                "requestBodyRequired": True,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["SearchResponse"],
                "responseEnvelope": "SearchResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "query is required"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "query is required", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert summary["expected_error_count"] == 1
    assert summary["failed_routes"] == []
    assert summary["routes"][0]["outcome"] == "expected_error"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200, 400]


def test_rest_contract_completeness_accepts_category_create_negative_probe(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "createCategory",
                "operationId": "createCategory",
                "family": "categories",
                "method": "POST",
                "path": "/api/v1/categories",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": True,
                "requestBodyRequired": True,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["CategoryResponse"],
                "responseEnvelope": "CategoryResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "name is required"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "name is required", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert summary["expected_error_count"] == 1
    assert summary["routes"][0]["operationId"] == "createCategory"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200, 400]
