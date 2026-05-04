from __future__ import annotations

import importlib.util
import sys
from types import SimpleNamespace
from pathlib import Path
from typing import Any

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


def test_secret_ignore_check_uses_secret_file_git_worktree(tmp_path: Path, monkeypatch) -> None:
    secret_root = tmp_path / "bountarr"
    secret_root.mkdir()
    secret_path = secret_root / ".env"
    secret_path.write_text("PROWLARR_URL=http://localhost\n", encoding="utf-8")
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


def test_direct_torznab_error_edges_are_expected_400s(monkeypatch) -> None:
    module = load_prowlarr_module()
    calls: list[tuple[str, str]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: Any) -> dict[str, Any]:
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path))
        return {"status": 404 if method == "POST" else 400, "body_text": ""}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.check_direct_torznab_error_edges("http://127.0.0.1:1", "secret key")

    assert result["ok"] is True
    assert [scenario["name"] for scenario in result["scenarios"]] == [
        "malformed_percent_escape",
        "malformed_path_escape",
        "unsupported_method",
        "duplicate_t_parameter",
        "unicode_query_length_rejected",
    ]
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
        assert path == "/indexer/emulebb/api?t=search&apikey=secret"
        return {"status": 200, "body_text": rss}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    assert module.check_direct_rss_results("http://127.0.0.1:1", "secret") == {"status": 200, "count": 1}


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
    monkeypatch.setattr(module.time, "monotonic", iter([0.0, 0.1, 2.0]).__next__)

    try:
        module.wait_for_prowlarr_results("http://prowlarr.test", "key", 40, ("linux",), 1.0)
    except RuntimeError as exc:
        assert "body_preview" in str(exc)
        assert "indexer unavailable" in str(exc)
    else:
        raise AssertionError("Expected wait_for_prowlarr_results to fail")
