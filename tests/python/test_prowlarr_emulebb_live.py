from __future__ import annotations

import importlib.util
import sys
import urllib.error
from types import SimpleNamespace
from pathlib import Path
from typing import Any

import pytest

from emule_test_harness import live_env


def load_prowlarr_module():
    """Loads the hyphenated Prowlarr live script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "prowlarr-emulebb-live.py"
    spec = importlib.util.spec_from_file_location("prowlarr_emulebb_live_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["prowlarr_emulebb_live_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_prowlarr_live_report_records_live_network_launch_inputs() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "prowlarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert '"launch_inputs"' in script_text
    assert '"p2p_bind_interface_name": args.p2p_bind_interface_name' in script_text
    assert '"enable_upnp": True' in script_text
    assert 'BindAddr=hide.me' not in script_text


def test_prowlarr_live_report_contract_requires_download_client_grab_proof() -> None:
    module = load_prowlarr_module()
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "prowlarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert module.PROWLARR_GRAB_CATEGORY == "prowlarr_grabs_cat"
    assert module.PROWLARR_DOWNLOAD_CLIENT_CHECK_KEYS == (
        "download_client",
        "search_results",
        "download_client_grab",
    )
    assert module.PROWLARR_DOWNLOAD_CLIENT_CLEANUP_KEY == "cleanup_download_clients"
    assert "radarr_movie_primary_readiness" not in script_text
    assert "radarr_movie_term_diagnostics" not in script_text
    assert "prowlarr_movie_video_results" not in script_text
    assert "prowlarr_series_video_results" not in script_text


def test_parser_defaults_rest_webserver_to_https() -> None:
    module = load_prowlarr_module()

    args = module.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.rest_webserver_scheme == "https"
    assert args.lan_bind_addr == "192.0.2.10"


def test_upsert_creates_indexer_with_force_save_to_avoid_live_validation(monkeypatch) -> None:
    module = load_prowlarr_module()
    requests: list[dict[str, Any]] = []

    schema = {
        "name": "Generic Torznab",
        "implementation": "Torznab",
        "fields": [
            {"name": "baseUrl", "value": ""},
            {"name": "apiPath", "value": ""},
            {"name": "apiKey", "value": ""},
            {"name": "torrentBaseSettings.preferMagnetUrl", "value": False},
        ],
    }
    saved = {
        "id": 40,
        "name": "eMuleBB Local",
        "implementation": "Torznab",
        "enable": True,
        "fields": schema["fields"],
    }

    def fake_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        requests.append({"path": path, "method": method, "json_body": json_body})
        if path == "/api/v1/indexer" and method == "GET":
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v1/indexer/schema":
            return {"status": 200, "json": [schema], "body_text": "[]"}
        if path == "/api/v1/indexer?forceSave=true" and method == "POST":
            assert isinstance(json_body, dict)
            assert json_body["enable"] is True
            return {"status": 202, "json": saved, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    result = module.upsert_indexer(
        "http://prowlarr.test",
        "secret",
        indexer_name="eMuleBB Local",
        torznab_base_url="http://127.0.0.1:61920/indexer/emulebb",
        emule_api_key="emule-key",
    )

    assert result["id"] == 40
    assert result["enable"] is True
    assert result["_emulebbForcedSave"] is True
    assert [request["path"] for request in requests] == [
        "/api/v1/indexer",
        "/api/v1/indexer/schema",
        "/api/v1/indexer?forceSave=true",
    ]


def test_upsert_preserves_existing_indexer_when_prowlarr_marked_it_unavailable(monkeypatch) -> None:
    module = load_prowlarr_module()
    requests: list[dict[str, Any]] = []

    existing = {
        "id": 40,
        "name": "eMuleBB Local",
        "implementation": "Torznab",
        "fields": [
            {"name": "baseUrl", "value": ""},
            {"name": "apiPath", "value": ""},
            {"name": "apiKey", "value": ""},
            {"name": "torrentBaseSettings.preferMagnetUrl", "value": False},
        ],
    }
    def fake_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        requests.append({"path": path, "method": method, "json_body": json_body})
        if path == "/api/v1/indexer" and method == "GET":
            return {"status": 200, "json": [existing], "body_text": "[]"}
        if path == "/api/v1/indexerstatus":
            return {"status": 200, "json": [{"indexerId": 40, "disabledTill": "2026-05-11T16:08:19Z"}], "body_text": "[]"}
        if path == "/api/v1/indexer/40?forceSave=true" and method == "PUT":
            assert isinstance(json_body, dict)
            assert json_body["enable"] is True
            return {"status": 202, "json": {**json_body, "id": 40}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    result = module.upsert_indexer(
        "http://prowlarr.test",
        "secret",
        indexer_name="eMuleBB Local",
        torznab_base_url="http://127.0.0.1:61920/indexer/emulebb",
        emule_api_key="emule-key",
    )

    assert result["id"] == 40
    assert result["_emulebbRecreatedAfterUnavailable"] is False
    assert result["_emulebbUnavailableAtUpsert"] is True
    assert [request["path"] for request in requests] == [
        "/api/v1/indexer",
        "/api/v1/indexerstatus",
        "/api/v1/indexer/40?forceSave=true",
    ]


def test_wait_for_indexer_available_polls_until_disabled_status_clears(monkeypatch) -> None:
    module = load_prowlarr_module()
    statuses = [
        [{"indexerId": 40, "disabledTill": "2026-05-11T16:08:19Z"}],
        [{"indexerId": 40, "disabledTill": "2026-05-11T16:08:19Z"}],
        [],
    ]

    def fake_get_indexer_statuses(_prowlarr_url: str, _api_key: str) -> list[dict[str, Any]]:
        return statuses.pop(0)

    monkeypatch.setattr(module, "get_indexer_statuses", fake_get_indexer_statuses)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.wait_for_indexer_available("http://prowlarr.test", "secret", 40, 5.0)

    assert result["status"] == "available"
    assert result["indexer_id"] == 40
    assert result["attempt_count"] == 3


def qbit_schema() -> dict[str, Any]:
    """Returns a minimal Prowlarr qBittorrent schema fixture."""

    return {
        "implementation": "QBittorrent",
        "implementationName": "qBittorrent",
        "protocol": "torrent",
        "configContract": "QBittorrentSettings",
        "fields": [
            {"name": "host", "value": ""},
            {"name": "port", "value": 0},
            {"name": "useSsl", "value": True},
            {"name": "urlBase", "value": "/qbittorrent"},
            {"name": "username", "value": ""},
            {"name": "password", "value": ""},
            {"name": "category", "value": ""},
            {"name": "priority", "value": 1},
            {"name": "initialState", "value": 0},
        ],
    }


def schema_with_certificate_validation(schema: dict[str, Any]) -> dict[str, Any]:
    """Adds the Arr/Prowlarr local certificate policy field to a provider fixture."""

    schema = {**schema, "fields": [dict(field) for field in schema["fields"]]}
    schema["fields"].append({"name": "certificateValidation", "value": 0})
    return schema


def field_value(provider: dict[str, Any], name: str) -> object:
    """Returns one provider field value from a fixture payload."""

    for field in provider["fields"]:
        if field["name"] == name:
            return field["value"]
    raise AssertionError(f"Missing field {name}")


def test_qbit_download_client_payload_sets_emule_connection_and_category() -> None:
    module = load_prowlarr_module()

    payload = module.build_qbit_download_client_payload(
        qbit_schema(),
        name="eMuleBB Live Prowlarr 12345",
        host="192.0.2.10",
        port=12345,
        emule_api_key="emule-key",
        category="prowlarr_grabs_cat",
    )

    assert payload["name"] == "eMuleBB Live Prowlarr 12345"
    assert payload["enable"] is True
    assert payload["implementation"] == "QBittorrent"
    assert field_value(payload, "host") == "192.0.2.10"
    assert field_value(payload, "port") == 12345
    assert field_value(payload, "useSsl") is False
    assert field_value(payload, "urlBase") == ""
    assert field_value(payload, "username") == "emule"
    assert field_value(payload, "password") == "emule-key"
    assert field_value(payload, "category") == "prowlarr_grabs_cat"
    assert field_value(payload, "initialState") == 2
    assert payload["_emulebbCertificatePolicy"] == {"certificateValidation": False}


def test_indexer_payload_covers_http_and_https_certificate_policy() -> None:
    module = load_prowlarr_module()
    schema = {
        "name": "Generic Torznab",
        "implementation": "Torznab",
        "fields": [
            {"name": "baseUrl", "value": ""},
            {"name": "apiPath", "value": ""},
            {"name": "apiKey", "value": ""},
            {"name": "torrentBaseSettings.preferMagnetUrl", "value": False},
        ],
    }

    http_payload = module.build_indexer_payload(
        schema_with_certificate_validation(schema),
        name="eMuleBB Local",
        torznab_base_url="http://127.0.0.1:61920/indexer/emulebb",
        emule_api_key="emule-key",
    )
    https_payload = module.build_indexer_payload(
        schema_with_certificate_validation(schema),
        name="eMuleBB Local",
        torznab_base_url="https://127.0.0.1:61920/indexer/emulebb",
        emule_api_key="emule-key",
    )

    assert field_value(http_payload, "baseUrl") == "http://127.0.0.1:61920/indexer/emulebb"
    assert field_value(http_payload, "certificateValidation") == 0
    assert http_payload["_emulebbCertificatePolicy"] == {"certificateValidation": False}
    assert field_value(https_payload, "baseUrl") == "https://127.0.0.1:61920/indexer/emulebb"
    assert field_value(https_payload, "certificateValidation") == 1
    assert https_payload["_emulebbCertificatePolicy"] == {"certificateValidation": True}


def test_indexer_payload_uses_host_config_when_schema_omits_certificate_policy() -> None:
    module = load_prowlarr_module()
    schema = {
        "name": "Generic Torznab",
        "implementation": "Torznab",
        "fields": [
            {"name": "baseUrl", "value": ""},
            {"name": "apiPath", "value": ""},
            {"name": "apiKey", "value": ""},
            {"name": "torrentBaseSettings.preferMagnetUrl", "value": False},
        ],
    }

    payload = module.build_indexer_payload(
        schema,
        name="eMuleBB Local",
        torznab_base_url="https://127.0.0.1:61920/indexer/emulebb",
        emule_api_key="emule-key",
    )

    assert field_value(payload, "baseUrl") == "https://127.0.0.1:61920/indexer/emulebb"
    assert payload["_emulebbCertificatePolicy"] == {
        "certificateValidation": False,
        "prowlarrHostConfig": "disabledForLocalAddresses",
    }


def test_set_prowlarr_local_certificate_validation_updates_host_config(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[dict[str, object]] = []

    def fake_request(prowlarr_url, api_key, path, *, method="GET", json_body=None, timeout_seconds=30.0):
        calls.append({"path": path, "method": method, "json_body": json_body})
        if method == "GET":
            return {"status": 200, "json": {"id": 1, "certificateValidation": "enabled"}, "body_text": "{}"}
        assert method == "PUT"
        assert json_body["certificateValidation"] == "disabledForLocalAddresses"
        return {"status": 200, "json": dict(json_body), "body_text": "{}"}

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    result = module.set_prowlarr_local_certificate_validation("http://prowlarr", "key")

    assert result == {"changed": True, "previous": "enabled", "current": "disabledForLocalAddresses"}
    assert [call["method"] for call in calls] == ["GET", "PUT"]


def test_qbit_download_client_payload_covers_http_and_https_transport() -> None:
    module = load_prowlarr_module()

    http_payload = module.build_qbit_download_client_payload(
        schema_with_certificate_validation(qbit_schema()),
        name="eMuleBB Live Prowlarr HTTP",
        host="127.0.0.1",
        port=61920,
        emule_api_key="emule-key",
        category="prowlarr_grabs_cat",
        use_ssl=False,
    )
    https_payload = module.build_qbit_download_client_payload(
        schema_with_certificate_validation(qbit_schema()),
        name="eMuleBB Live Prowlarr HTTPS",
        host="127.0.0.1",
        port=61921,
        emule_api_key="emule-key",
        category="prowlarr_grabs_cat",
        use_ssl=True,
    )

    assert field_value(http_payload, "useSsl") is False
    assert field_value(http_payload, "certificateValidation") == 0
    assert http_payload["_emulebbCertificatePolicy"] == {"certificateValidation": False}
    assert field_value(https_payload, "useSsl") is True
    assert field_value(https_payload, "certificateValidation") == 1
    assert https_payload["_emulebbCertificatePolicy"] == {"certificateValidation": True}


def test_qbit_download_client_payload_uses_host_config_when_schema_omits_certificate_policy() -> None:
    module = load_prowlarr_module()

    payload = module.build_qbit_download_client_payload(
        qbit_schema(),
        name="eMuleBB Live Prowlarr HTTPS",
        host="127.0.0.1",
        port=61921,
        emule_api_key="emule-key",
        category="prowlarr_grabs_cat",
        use_ssl=True,
    )

    assert field_value(payload, "useSsl") is True
    assert payload["_emulebbCertificatePolicy"] == {
        "certificateValidation": False,
        "prowlarrHostConfig": "disabledForLocalAddresses",
    }


def test_first_live_wire_term_keeps_only_primary_operator_term() -> None:
    module = load_prowlarr_module()

    assert module.first_live_wire_term(("primary", "fallback"), "search_terms.radarr_movies") == ("primary",)


def test_temp_qbit_download_client_creates_and_tests(monkeypatch) -> None:
    module = load_prowlarr_module()
    requests: list[dict[str, Any]] = []
    monkeypatch.setattr(module, "wait_for_qbit_endpoint_ready", lambda *_args, **_kwargs: {"ready": True, "attempt_count": 1})

    def fake_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        requests.append({"path": path, "method": method, "json_body": json_body})
        if path == "/api/v1/downloadclient/schema":
            return {"status": 200, "json": [qbit_schema()], "body_text": "[]"}
        if path == "/api/v1/downloadclient?forceSave=true" and method == "POST":
            assert isinstance(json_body, dict)
            assert json_body["name"] == "eMuleBB Live Prowlarr 8080"
            assert "_emulebbCertificatePolicy" not in json_body
            return {"status": 201, "json": {"id": 41, "name": json_body["name"], "fields": json_body["fields"]}, "body_text": "{}"}
        if path == "/api/v1/downloadclient/test" and method == "POST":
            assert isinstance(json_body, dict)
            assert "_emulebbCertificatePolicy" not in json_body
            return {"status": 200, "json": None, "body_text": ""}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    client = module.create_temp_qbit_download_client(
        "http://prowlarr.test",
        "key",
        name="eMuleBB Live Prowlarr 8080",
        host="127.0.0.1",
        port=8080,
        emule_api_key="emule-key",
        category="prowlarr_grabs_cat",
    )

    assert client["id"] == 41
    assert client["_emulebbTemporary"] is True
    assert client["_emulebbTestStatus"] == 200
    assert [request["path"] for request in requests] == [
        "/api/v1/downloadclient/schema",
        "/api/v1/downloadclient?forceSave=true",
        "/api/v1/downloadclient/test",
    ]


def test_temp_qbit_download_client_cleans_up_when_test_fails(monkeypatch) -> None:
    module = load_prowlarr_module()
    requests: list[dict[str, Any]] = []
    monkeypatch.setattr(module, "wait_for_qbit_endpoint_ready", lambda *_args, **_kwargs: {"ready": True, "attempt_count": 1})

    def fake_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        requests.append({"path": path, "method": method, "json_body": json_body})
        if path == "/api/v1/downloadclient/schema":
            return {"status": 200, "json": [qbit_schema()], "body_text": "[]"}
        if path == "/api/v1/downloadclient?forceSave=true" and method == "POST":
            return {"status": 201, "json": {"id": 41, "fields": qbit_schema()["fields"]}, "body_text": "{}"}
        if path == "/api/v1/downloadclient/test" and method == "POST":
            return {"status": 400, "json": None, "body_text": "cannot connect"}
        if path == "/api/v1/downloadclient/41" and method == "DELETE":
            return {"status": 200, "json": None, "body_text": ""}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    try:
        module.create_temp_qbit_download_client(
            "http://prowlarr.test",
            "key",
            name="client",
            host="127.0.0.1",
            port=8080,
            emule_api_key="emule-key",
            category="prowlarr_grabs_cat",
        )
    except RuntimeError as exc:
        assert "qBittorrent client test" in str(exc)
    else:
        raise AssertionError("Expected client test failure")

    assert [request["path"] for request in requests] == [
        "/api/v1/downloadclient/schema",
        "/api/v1/downloadclient?forceSave=true",
        "/api/v1/downloadclient/test",
        "/api/v1/downloadclient/41",
    ]


def test_temp_qbit_download_client_retries_transient_create_failure(monkeypatch) -> None:
    module = load_prowlarr_module()
    requests: list[dict[str, Any]] = []
    monkeypatch.setattr(module, "wait_for_qbit_endpoint_ready", lambda *_args, **_kwargs: {"ready": True, "attempt_count": 1})
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    def fake_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        requests.append({"path": path, "method": method, "json_body": json_body})
        create_count = sum(1 for request in requests if request["path"] == "/api/v1/downloadclient?forceSave=true")
        if path == "/api/v1/downloadclient/schema":
            return {"status": 200, "json": [qbit_schema()], "body_text": "[]"}
        if path == "/api/v1/downloadclient?forceSave=true" and method == "POST" and create_count == 1:
            return {
                "status": 400,
                "json": None,
                "body_text": "Unable to connect to qBittorrent: The SSL connection could not be established.",
            }
        if path == "/api/v1/downloadclient?forceSave=true" and method == "POST":
            return {"status": 201, "json": {"id": 41, "fields": qbit_schema()["fields"]}, "body_text": "{}"}
        if path == "/api/v1/downloadclient/test" and method == "POST":
            return {"status": 200, "json": None, "body_text": ""}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    client = module.create_temp_qbit_download_client(
        "http://prowlarr.test",
        "key",
        name="client",
        host="127.0.0.1",
        port=8080,
        emule_api_key="emule-key",
        category="prowlarr_grabs_cat",
    )

    assert client["id"] == 41
    assert len(client["_emulebbTransientRetries"]) == 1
    assert [request["path"] for request in requests].count("/api/v1/downloadclient?forceSave=true") == 2


def test_wait_for_qbit_endpoint_ready_retries_busy_web_thread(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls = 0

    def fake_qbit_login(_base_url, _api_key):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("Web Interface rejected connection because 1 accepted-client thread is already active")
        return "SID=ok", {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_login", fake_qbit_login)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.wait_for_qbit_endpoint_ready("https://127.0.0.1:4711", "secret", timeout_seconds=10.0)

    assert result["ready"] is True
    assert result["attempt_count"] == 2
    assert len(result["transient_errors"]) == 1


def test_ensure_emule_category_creates_missing_category(monkeypatch, tmp_path: Path) -> None:
    module = load_prowlarr_module()
    calls: list[dict[str, Any]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"base_url": base_url, "path": path, **kwargs})
        if path == "/api/v1/categories" and kwargs.get("method", "GET") == "GET":
            rows = [{"id": 0, "name": "Default", "path": "C:\\Incoming\\"}]
            return {
                "status": 200,
                "json": rows,
                "raw_json": {"data": rows, "meta": {"apiVersion": "v1"}},
                "body_text": "[]",
            }
        if path == "/api/v1/categories" and kwargs.get("method") == "POST":
            payload = {"id": 8, "name": "prowlarr_grabs_cat", "path": kwargs["json_body"]["path"]}
            return {
                "status": 200,
                "json": payload,
                "raw_json": {"data": payload, "meta": {"apiVersion": "v1"}},
                "body_text": "{}",
            }
        raise AssertionError(f"Unexpected request: {kwargs.get('method', 'GET')} {path}")

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.ensure_emule_category(
        "http://127.0.0.1:4711",
        "key",
        "prowlarr_grabs_cat",
        tmp_path / "incoming",
    )

    assert result["id"] == 8
    assert result["created"] is True
    assert calls[1]["json_body"]["name"] == "prowlarr_grabs_cat"
    assert str(calls[1]["json_body"]["path"]).endswith("\\")


def test_native_rest_transfer_add_retries_transient_socket_abort(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[dict[str, Any]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"base_url": base_url, "path": path, **kwargs})
        if len(calls) == 1:
            raise urllib.error.URLError(10053)
        payload = {
            "items": [
                {
                    "ok": True,
                    "hash": "fedcba9876543210fedcba9876543210",
                    "name": "Linux.iso",
                }
            ]
        }
        return {
            "status": 200,
            "json": payload,
            "raw_json": {"data": payload, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.native_rest_transfer_add(
        "https://127.0.0.1:4711",
        "key",
        "ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/",
        "prowlarr_grabs_cat",
    )

    assert result["add_status"] == 200
    assert result["hash"] == "fedcba9876543210fedcba9876543210"
    assert result["transient_errors"]
    assert len(calls) == 2


def test_transfer_hashes_retries_transient_socket_abort(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls = 0

    def fake_http_request(_base_url: str, path: str, **_kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        assert path == "/api/v1/transfers"
        if calls == 1:
            raise urllib.error.URLError(10053)
        rows = [{"hash": "fedcba9876543210fedcba9876543210"}]
        return {
            "status": 200,
            "json": rows,
            "raw_json": {"data": rows, "meta": {"apiVersion": "v1"}},
            "body_text": "[]",
        }

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    assert module.transfer_hashes("https://127.0.0.1:4711", "key") == {"fedcba9876543210fedcba9876543210"}
    assert calls == 2


def test_prowlarr_download_client_grab_adds_release_through_native_rest_endpoint(monkeypatch) -> None:
    module = load_prowlarr_module()
    prowlarr_requests: list[dict[str, Any]] = []
    transfer_adds: list[dict[str, Any]] = []
    transfer_calls = 0
    release = {
        "title": "Linux ISO",
        "guid": "guid-1",
        "indexerId": 40,
        "downloadUrl": "ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/",
        "magnetUrl": "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000",
    }

    def fake_prowlarr_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        *,
        method: str = "GET",
        json_body: object | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        prowlarr_requests.append({"path": path, "method": method, "json_body": json_body})
        if path == "/api/v1/search?query=linux&categories=7000&indexerIds=40" and method == "GET":
            return {"status": 200, "json": [release], "body_text": "[]"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        nonlocal transfer_calls
        assert path == "/api/v1/transfers"
        method = str(kwargs.get("method", "GET"))
        if method == "POST":
            transfer_adds.append(
                {
                    "base_url": base_url,
                    "emule_api_key": kwargs.get("api_key"),
                    "json_body": kwargs.get("json_body"),
                }
            )
            return {
                "status": 200,
                "json": {
                    "items": [
                        {
                            "ok": True,
                            "hash": "fedcba9876543210fedcba9876543210",
                            "name": "Linux.iso",
                        }
                    ]
                },
                "raw_json": {
                    "data": {
                        "items": [
                            {
                                "ok": True,
                                "hash": "fedcba9876543210fedcba9876543210",
                                "name": "Linux.iso",
                            }
                        ]
                    },
                    "meta": {"apiVersion": "v1"},
                },
                "body_text": "{}",
            }
        transfer_calls += 1
        if transfer_calls == 1:
            return {"status": 200, "json": [], "raw_json": {"data": [], "meta": {"apiVersion": "v1"}}, "body_text": "[]"}
        return {
            "status": 200,
            "json": [
                {
                    "hash": "fedcba9876543210fedcba9876543210",
                    "name": "Linux ISO",
                    "state": "downloading",
                    "categoryName": "prowlarr_grabs_cat",
                }
            ],
            "raw_json": {
                "data": [
                    {
                        "hash": "fedcba9876543210fedcba9876543210",
                        "name": "Linux ISO",
                        "state": "downloading",
                        "categoryName": "prowlarr_grabs_cat",
                    }
                ],
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "[]",
        }

    monkeypatch.setattr(module, "prowlarr_request", fake_prowlarr_request)
    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.prowlarr_download_client_grab_roundtrip(
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="key",
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        indexer_id=40,
        queries=("linux",),
        category_id=module.TORZNAB_DOCUMENT_CATEGORY,
        download_client_id=55,
        download_category="prowlarr_grabs_cat",
        timeout_seconds=10.0,
        transfer_timeout_seconds=300.0,
    )

    assert result["status"] == "passed"
    assert result["release"]["title_present"] is True
    assert result["release"]["hash_present"] is True
    assert result["handoff"] == "prowlarr-search-native-emulebb-rest-add"
    assert result["download_link_hash_present"] is True
    assert result["transfer"]["categoryName"] == "prowlarr_grabs_cat"
    assert [request["path"] for request in prowlarr_requests] == [
        "/api/v1/search?query=linux&categories=7000&indexerIds=40",
    ]
    assert transfer_adds == [
        {
            "base_url": "http://127.0.0.1:1",
            "emule_api_key": "emule-key",
            "json_body": {
                "link": "ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/",
                "categoryName": "prowlarr_grabs_cat",
                "paused": True,
            },
        }
    ]


def test_select_grabbable_release_requires_matching_indexer_and_guid() -> None:
    module = load_prowlarr_module()

    result = module.select_grabbable_release(
        [
            {"indexerId": 39, "guid": "wrong"},
            {"indexerId": 40, "guid": ""},
            {"indexerId": 40, "guid": "right", "title": "Linux ISO"},
        ],
        40,
        "linux iso",
    )

    assert result["guid"] == "right"


def test_select_native_transfer_release_skips_internal_prowlarr_guid() -> None:
    module = load_prowlarr_module()

    result = module.select_native_transfer_release(
        [
            {"indexerId": 40, "guid": "prowlarr://release/1", "title": "Linux ISO"},
            {
                "indexerId": 40,
                "guid": "ed2k:fedcba9876543210fedcba9876543210",
                "downloadUrl": "ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/",
                "title": "Linux ISO",
            },
        ],
        "linux iso",
        indexer_id=40,
    )

    assert result["downloadUrl"].startswith("ed2k://")


def test_parse_torznab_item_releases_extracts_native_download_link() -> None:
    module = load_prowlarr_module()
    body = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Linux ISO</title>
      <guid isPermaLink="false">ed2k:fedcba9876543210fedcba9876543210</guid>
      <link>ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/</link>
      <enclosure url="ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/" length="1024" type="application/x-ed2k-link" />
      <torznab:attr name="size" value="1024" />
    </item>
  </channel>
</rss>
"""

    rows = module.parse_torznab_item_releases(body)

    assert rows == [
        {
            "title": "Linux ISO",
            "guid": "ed2k:fedcba9876543210fedcba9876543210",
            "downloadUrl": "ed2k://|file|Linux.iso|1024|fedcba9876543210fedcba9876543210|/",
            "size": 1024,
        }
    ]


def test_select_grabbable_release_prefers_title_match_then_sources() -> None:
    module = load_prowlarr_module()

    result = module.select_grabbable_release(
        [
            {"indexerId": 40, "guid": "many-sources", "title": "Unrelated.mkv", "sources": 99},
            {"indexerId": 40, "guid": "weak-match", "title": "Linux sample", "sources": 50},
            {"indexerId": 40, "guid": "best", "title": "Linux ISO 1080p", "sources": 7},
            {"indexerId": 40, "guid": "tie-lower-sources", "title": "Linux ISO 720p", "sources": 3},
        ],
        40,
        "linux iso",
    )

    assert result["guid"] == "best"
    assert module.summarize_release_selection(result, "linux iso") == {
        "title_match_score": 200,
        "source_count": 7,
    }


def test_radarr_movie_term_diagnostics_compare_direct_and_prowlarr_paths(monkeypatch) -> None:
    module = load_prowlarr_module()
    rss_empty = """<?xml version="1.0" encoding="UTF-8"?><rss><channel /></rss>"""
    rss_video = """<?xml version="1.0" encoding="UTF-8"?>
<rss><channel><item><title>Fixture.mkv</title><torznab:attr xmlns:torznab="http://torznab.com/schemas/2015/feed" name="size" value="123456789" /></item></channel></rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if "q=second" in path and "cat=2000" in path:
            return {"status": 200, "body_text": rss_video}
        return {"status": 200, "body_text": rss_empty}

    def fake_prowlarr_request(prowlarr_url: str, api_key: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if "query=second" in path:
            return {"status": 200, "json": [{"title": "Fixture.mkv", "size": 123456789}], "body_text": "[]"}
        return {"status": 200, "json": [], "body_text": "[]"}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module, "prowlarr_request", fake_prowlarr_request)

    diagnostic = module.diagnose_radarr_movie_terms(
        base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="key",
        indexer_id=40,
        terms=("first", "second"),
    )

    assert diagnostic["term_count"] == 2
    assert diagnostic["first_term_movie_results_ok"] is False
    assert diagnostic["terms"][0]["prowlarr_movie"]["buckets"]["result_count"] == 0
    assert diagnostic["terms"][1]["direct_movie"]["buckets"]["video_extension_count"] == 1
    assert diagnostic["terms"][1]["prowlarr_movie"]["buckets"]["video_extension_count"] == 1


def test_primary_radarr_movie_term_gate_requires_first_term_results() -> None:
    module = load_prowlarr_module()

    with pytest.raises(RuntimeError, match="Primary Radarr movie"):
        module.require_first_radarr_movie_term_results({"first_term_movie_results_ok": False})
    with pytest.raises(RuntimeError, match="Primary Radarr movie"):
        module.require_first_radarr_movie_term_results({"ok": False})

    module.require_first_radarr_movie_term_results({"first_term_movie_results_ok": True})
    module.require_first_radarr_movie_term_results({"ok": True})


def test_primary_radarr_movie_term_readiness_retries_until_results(monkeypatch) -> None:
    module = load_prowlarr_module()
    now = {"value": 0.0}
    direct_counts = [0, 2]
    prowlarr_counts = [2]

    def fake_direct(*_args: Any, **_kwargs: Any) -> dict[str, object]:
        count = direct_counts.pop(0)
        return {
            "status": 200,
            "category": module.TORZNAB_MOVIE_CATEGORY,
            "query_present": True,
            "buckets": {"result_count": count},
        }

    def fake_prowlarr(*_args: Any, **_kwargs: Any) -> dict[str, object]:
        count = prowlarr_counts.pop(0)
        return {
            "status": 200,
            "category": module.TORZNAB_MOVIE_CATEGORY,
            "query_present": True,
            "buckets": {"result_count": count},
        }

    monkeypatch.setattr(module, "direct_torznab_term_diagnostic", fake_direct)
    monkeypatch.setattr(module, "prowlarr_term_diagnostic", fake_prowlarr)
    monkeypatch.setattr(module, "compact_search_network_snapshot", lambda *_args, **_kwargs: {"server": {"connected": True}})

    result = module.wait_for_primary_radarr_movie_term_results(
        base_url="http://127.0.0.1:1",
        emule_api_key="secret",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="key",
        indexer_id=40,
        terms=("primary", "backup"),
        timeout_seconds=20.0,
        poll_interval_seconds=5.0,
        monotonic_seconds=lambda: now["value"],
        sleep_seconds=lambda seconds: now.__setitem__("value", now["value"] + seconds),
    )

    assert result["ok"] is True
    assert result["term_index"] == 0
    assert result["attempt_count"] == 2
    assert result["result_count"] == 2
    assert result["attempts"][0]["prowlarr_movie"]["status"] == "skipped_until_direct_movie_results"
    assert result["attempts"][1]["prowlarr_movie"]["buckets"]["result_count"] == 2


def test_primary_radarr_movie_term_readiness_fails_fast_when_prowlarr_marks_indexer_unavailable(monkeypatch) -> None:
    module = load_prowlarr_module()

    monkeypatch.setattr(
        module,
        "direct_torznab_term_diagnostic",
        lambda *_args, **_kwargs: {
            "status": 200,
            "category": module.TORZNAB_MOVIE_CATEGORY,
            "query_present": True,
            "buckets": {"result_count": 100},
        },
    )
    monkeypatch.setattr(
        module,
        "prowlarr_term_diagnostic",
        lambda *_args, **_kwargs: {
            "status": 400,
            "category": module.TORZNAB_MOVIE_CATEGORY,
            "query_present": True,
            "body_preview": "Search failed due to all selected indexers being unavailable",
            "buckets": {"result_count": 0},
        },
    )
    monkeypatch.setattr(module, "compact_search_network_snapshot", lambda *_args, **_kwargs: {"server": {"connected": True}})

    result = module.wait_for_primary_radarr_movie_term_results(
        base_url="http://127.0.0.1:1",
        emule_api_key="secret",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="key",
        indexer_id=40,
        terms=("primary",),
        timeout_seconds=180.0,
        monotonic_seconds=lambda: 0.0,
        sleep_seconds=lambda _seconds: (_ for _ in ()).throw(AssertionError("should not sleep")),
    )

    assert result["ok"] is False
    assert result["attempt_count"] == 1
    assert result["prowlarr_indexer_unavailable"] is True


def test_cached_direct_torznab_stress_requires_item_bearing_rss(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[str] = []
    rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss><channel><item><title>Big Buck Bunny</title></item></channel></rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        return {"status": 200, "body_text": rss}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.stress_cached_direct_torznab_search("http://127.0.0.1:1", "secret key", "Big Buck Bunny", 3)

    assert result["requests"] == 3
    assert len(calls) == 3
    assert all("apikey=secret%20key" in call for call in calls)


def test_direct_torznab_search_stress_cycles_terms(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[str] = []
    rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss><channel><item><title>Linux</title></item></channel></rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        return {"status": 200, "body_text": rss}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.stress_direct_torznab_search_terms("http://127.0.0.1:1", "secret", ("alpha", "beta"), 3)

    assert result["requests"] == 3
    assert result["term_count"] == 2
    assert result["item_total"] == 3
    assert "q=alpha" in calls[0]
    assert "q=beta" in calls[1]
    assert "q=alpha" in calls[2]
    assert all("cat=7000" in call for call in calls)


def test_prowlarr_search_stress_requires_result_rows(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[str] = []

    def fake_prowlarr_request(prowlarr_url: str, api_key: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        return {"status": 200, "json": [{"title": "Linux"}], "body_text": "[]"}

    monkeypatch.setattr(module, "prowlarr_request", fake_prowlarr_request)

    result = module.stress_prowlarr_search_terms("http://prowlarr.test", "key", 40, ("alpha", "beta"), 2)

    assert result["requests"] == 2
    assert result["row_total"] == 2
    assert "query=alpha" in calls[0]
    assert "query=beta" in calls[1]
    assert all("categories=7000" in call for call in calls)


def test_direct_media_category_search_stress_covers_radarr_and_sonarr(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[dict[str, object]] = []

    def fake_stress(base_url: str, api_key: str, queries: tuple[str, ...], count: int, *, category_id: int) -> dict[str, object]:
        calls.append(
            {
                "base_url": base_url,
                "api_key": api_key,
                "queries": queries,
                "count": count,
                "category_id": category_id,
            }
        )
        return {"category": category_id, "requests": count, "term_count": len(queries)}

    monkeypatch.setattr(module, "stress_direct_torznab_search_terms", fake_stress)

    result = module.stress_direct_media_category_searches(
        "http://127.0.0.1:1",
        "secret",
        ("movie",),
        ("series", "show"),
        3,
    )

    assert result == {
        "radarr_movies": {"category": module.TORZNAB_MOVIE_CATEGORY, "requests": 3, "term_count": 1},
        "sonarr_series": {"category": module.TORZNAB_TV_CATEGORY, "requests": 3, "term_count": 2},
    }
    assert [call["category_id"] for call in calls] == [module.TORZNAB_MOVIE_CATEGORY, module.TORZNAB_TV_CATEGORY]
    assert [call["queries"] for call in calls] == [("movie",), ("series", "show")]


def test_prowlarr_media_category_search_stress_covers_radarr_and_sonarr(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[dict[str, object]] = []

    def fake_stress(
        prowlarr_url: str,
        api_key: str,
        indexer_id: int,
        queries: tuple[str, ...],
        count: int,
        *,
        category_id: int,
    ) -> dict[str, object]:
        calls.append(
            {
                "prowlarr_url": prowlarr_url,
                "api_key": api_key,
                "indexer_id": indexer_id,
                "queries": queries,
                "count": count,
                "category_id": category_id,
            }
        )
        return {"category": category_id, "requests": count, "term_count": len(queries)}

    monkeypatch.setattr(module, "stress_prowlarr_search_terms", fake_stress)

    result = module.stress_prowlarr_media_category_searches(
        "http://prowlarr.test",
        "key",
        40,
        ("movie", "film"),
        ("series",),
        2,
    )

    assert result == {
        "radarr_movies": {"category": module.TORZNAB_MOVIE_CATEGORY, "requests": 2, "term_count": 2},
        "sonarr_series": {"category": module.TORZNAB_TV_CATEGORY, "requests": 2, "term_count": 1},
    }
    assert [call["category_id"] for call in calls] == [module.TORZNAB_MOVIE_CATEGORY, module.TORZNAB_TV_CATEGORY]
    assert [call["queries"] for call in calls] == [("movie", "film"), ("series",)]


def test_search_path_builders_preserve_explicit_video_categories() -> None:
    module = load_prowlarr_module()

    direct_path = module.build_direct_torznab_search_path("secret key", "movie term", module.TORZNAB_MOVIE_CATEGORY)
    prowlarr_path = module.build_prowlarr_search_path("series term", module.TORZNAB_TV_CATEGORY, 40)

    assert direct_path == "/indexer/emulebb/api?t=search&cat=2000&q=movie%20term&apikey=secret%20key"
    assert prowlarr_path == "/api/v1/search?query=series%20term&categories=5000&indexerIds=40"


def test_secret_ignore_check_uses_secret_file_git_worktree(tmp_path: Path, monkeypatch) -> None:
    secret_root = tmp_path / "bountarr"
    secret_root.mkdir()
    secret_path = secret_root / ".env"
    secret_path.write_text("PROWLARR_URL=http://127.0.0.1\n", encoding="utf-8")
    calls: list[tuple[list[str], Path | None]] = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs.get("cwd")))
        if "rev-parse" in args:
            return SimpleNamespace(returncode=0, stdout=str(secret_root) + "\n")
        if "check-ignore" in args:
            assert kwargs.get("cwd") == secret_root.resolve()
            assert args[-1] == ".env"
            return SimpleNamespace(returncode=0)
        raise AssertionError(f"Unexpected subprocess call: {args}")

    monkeypatch.setattr(live_env.subprocess, "run", fake_run)

    live_env.ensure_secret_file_is_ignored(secret_path)

    assert calls[0][0][:3] == ["git", "-C", str(secret_root)]
    assert calls[1][0][:3] == ["git", "check-ignore", "-q"]


def test_direct_auth_rejection_requires_401(monkeypatch) -> None:
    module = load_prowlarr_module()

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        assert path == "/indexer/emulebb/api?t=caps"
        return {"status": 401, "body_text": ""}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    assert module.check_direct_auth_rejection("http://127.0.0.1:1") == {"status": 401}


def test_direct_unknown_query_tolerance_accepts_extension_parameters(monkeypatch) -> None:
    module = load_prowlarr_module()

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        assert path == "/indexer/emulebb/api?t=caps&unknownProviderField=ignored&apikey=secret%20key"
        return {"status": 200, "body_text": "<caps></caps>"}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    assert module.check_direct_unknown_query_tolerance("http://127.0.0.1:1", "secret key") == {
        "status": 200,
        "root": "caps",
    }


def test_direct_torznab_error_edges_are_expected_400s(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[tuple[str, str]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path))
        status = 404 if method == "POST" else 400
        return {
            "status": status,
            "body_text": f'<error code="{status}" description="fixture" />',
        }

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.check_direct_torznab_error_edges("http://127.0.0.1:1", "secret key")

    assert result["ok"] is True
    assert [scenario["name"] for scenario in result["scenarios"]] == [
        scenario["name"] for scenario in module.TORZNAB_DIRECT_ERROR_SCENARIOS
    ]
    assert [scenario["expected_status"] for scenario in result["scenarios"]] == [
        scenario["expected_status"] for scenario in module.TORZNAB_DIRECT_ERROR_SCENARIOS
    ]
    assert all(scenario["root"] == "error" for scenario in result["scenarios"])
    assert all(scenario["code"] == str(scenario["status"]) for scenario in result["scenarios"])
    assert all(scenario["description_present"] is True for scenario in result["scenarios"])
    assert all("apikey=secret%20key" in path for _method, path in calls)
    assert calls[2][0] == "POST"
    assert "q=bad%2xescape" in calls[0][1]
    assert "/api%2x" in calls[1][1]
    assert "t=search&t=movie" in calls[3][1]
    assert "%CE%BB" in calls[4][1]


def test_direct_rss_validation_requires_results(monkeypatch) -> None:
    module = load_prowlarr_module()
    rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss><channel><item><title>Linux</title></item></channel></rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        assert path == "/indexer/emulebb/api?t=search&cat=2000&q=movie%20term&apikey=secret"
        return {"status": 200, "body_text": rss}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    assert module.check_direct_rss_results(
        "http://127.0.0.1:1",
        "secret",
        ("movie term",),
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        source="radarr_movies",
    ) == {
        "status": 200,
        "count": 1,
        "category": 2000,
        "source": "radarr_movies",
        "term_count": 1,
        "attempts": [{"query_index": 0, "query_present": True, "status": 200, "count": 1}],
    }


def test_cached_direct_torznab_offset_page_requires_cached_rows(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[str] = []
    rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <torznab:response offset="{offset}" total="{total}" />
    <item><title>Linux</title></item>
  </channel>
</rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        if "offset=1" in path:
            return {"status": 200, "body_text": rss.format(offset=1, total=2)}
        return {"status": 200, "body_text": rss.format(offset=0, total=1)}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    assert module.check_cached_direct_torznab_offset_page(
        "http://127.0.0.1:1",
        "secret",
        "movie term",
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    ) == {
        "query_present": True,
        "category": 2000,
        "first_count": 1,
        "offset_count": 1,
        "offset": 1,
        "total": 2,
        "attempts": [
            {
                "first_status": 200,
                "first_count": 1,
                "offset_status": 200,
                "offset_count": 1,
                "offset": 1,
                "total": 2,
            }
        ],
    }
    assert calls == [
        "/indexer/emulebb/api?t=search&cat=2000&limit=1&q=movie%20term&apikey=secret",
        "/indexer/emulebb/api?t=search&cat=2000&offset=1&limit=1&q=movie%20term&apikey=secret",
    ]


def test_cached_direct_torznab_offset_page_for_terms_uses_result_bearing_term(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[str] = []
    empty_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel><torznab:response offset="0" total="0" /></channel>
</rss>"""
    populated_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <torznab:response offset="{offset}" total="2" />
    <item><title>Linux</title></item>
  </channel>
</rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        if "q=empty%20term" in path:
            return {"status": 200, "body_text": empty_rss}
        if "offset=1" in path:
            return {"status": 200, "body_text": populated_rss.format(offset=1)}
        return {"status": 200, "body_text": populated_rss.format(offset=0)}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.check_cached_direct_torznab_offset_page_for_terms(
        "http://127.0.0.1:1",
        "secret",
        ("empty term", "movie term"),
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        timeout_seconds=0.0,
    )

    assert result["status"] == "checked"
    assert result["query_index"] == 1
    assert result["term_count"] == 2
    assert result["first_count"] == 1
    assert result["offset_count"] == 1
    assert [attempt["query_index"] for attempt in result["attempts"]] == [0, 1]
    assert calls == [
        "/indexer/emulebb/api?t=search&cat=2000&limit=1&q=empty%20term&apikey=secret",
        "/indexer/emulebb/api?t=search&cat=2000&offset=1&limit=1&q=empty%20term&apikey=secret",
        "/indexer/emulebb/api?t=search&cat=2000&limit=1&q=movie%20term&apikey=secret",
        "/indexer/emulebb/api?t=search&cat=2000&offset=1&limit=1&q=movie%20term&apikey=secret",
    ]


def test_cached_direct_torznab_offset_page_for_terms_reports_sparse_live_results(monkeypatch) -> None:
    module = load_prowlarr_module()
    rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel><torznab:response offset="{offset}" total="0" /></channel>
</rss>"""

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        offset = 1 if "offset=1" in path else 0
        return {"status": 200, "body_text": rss.format(offset=offset)}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.check_cached_direct_torznab_offset_page_for_terms(
        "http://127.0.0.1:1",
        "secret",
        ("first term", "second term"),
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        timeout_seconds=0.0,
    )

    assert result["status"] == "no_pageable_live_result_set"
    assert result["term_count"] == 2
    assert result["max_first_count"] == 0
    assert result["max_offset_count"] == 0
    assert [attempt["query_index"] for attempt in result["attempts"]] == [0, 1]


def test_prowlarr_search_attempts_capture_error_body(monkeypatch) -> None:
    module = load_prowlarr_module()
    attempts: list[str] = []

    def fake_prowlarr_request(
        prowlarr_url: str,
        api_key: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        attempts.append(path)
        if len(attempts) > 1:
            raise RuntimeError("stop")
        return {"status": 400, "json": {"error": "blocked"}, "body_text": " indexer   unavailable "}

    monkeypatch.setattr(module, "prowlarr_request", fake_prowlarr_request)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(module.time, "monotonic", iter([0.0, 0.1, 0.2, 2.0, 2.0]).__next__)

    try:
        module.wait_for_prowlarr_results("http://prowlarr.test", "key", 40, ("linux",), 1.0)
    except RuntimeError as exc:
        assert "body_preview" in str(exc)
        assert "indexer unavailable" in str(exc)
    else:
        raise AssertionError("Expected wait_for_prowlarr_results to fail")
