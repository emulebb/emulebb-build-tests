from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


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


def test_upsert_creates_disabled_then_force_enables_when_prowlarr_create_test_has_no_results(monkeypatch) -> None:
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
        "name": "eMule BB Local",
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
        if path == "/api/v1/indexer" and method == "POST":
            return {
                "status": 400,
                "json": None,
                "body_text": "Query successful, but no results were returned from your indexer.",
            }
        if path == "/api/v1/indexer?forceSave=true" and method == "POST":
            assert isinstance(json_body, dict)
            assert json_body["enable"] is False
            return {"status": 201, "json": {"id": 40}, "body_text": "{}"}
        if path == "/api/v1/indexer/40?forceSave=true" and method == "PUT":
            assert isinstance(json_body, dict)
            assert json_body["enable"] is True
            assert json_body["id"] == 40
            return {"status": 202, "json": saved, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "prowlarr_request", fake_request)

    result = module.upsert_indexer(
        "http://prowlarr.test",
        "secret",
        indexer_name="eMule BB Local",
        torznab_base_url="http://127.0.0.1:61920/indexer/emulebb",
        emule_api_key="emule-key",
    )

    assert result["id"] == 40
    assert result["enable"] is True
    assert result["_emulebbForcedSave"] is True
    assert [request["path"] for request in requests] == [
        "/api/v1/indexer",
        "/api/v1/indexer/schema",
        "/api/v1/indexer",
        "/api/v1/indexer?forceSave=true",
        "/api/v1/indexer/40?forceSave=true",
    ]
