from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def load_radarr_sonarr_module():
    """Loads the hyphenated Radarr/Sonarr live script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "radarr-sonarr-emulebb-live.py"
    spec = importlib.util.spec_from_file_location("radarr_sonarr_emulebb_live_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_qbit_safety_checks_cover_auth_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()

    responses = {
        "/api/v2/app/webapiVersion": {"status": 200, "body_text": "2.11.0"},
        "/api/v2/torrents/info": [
            {"status": 403, "body_text": "Forbidden"},
            {"status": 403, "body_text": "Forbidden"},
        ],
        "/api/v2/auth/login": {"status": 200, "body_text": "Fails."},
        "/api/v2/torrents/add": {"status": 400, "body_text": "Fails."},
    }

    def fake_qbit_request(_base_url, path, **_kwargs):
        value = responses[path]
        if isinstance(value, list):
            return value.pop(0)
        return value

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)
    monkeypatch.setattr(module, "qbit_login", lambda _base_url, _api_key: (object(), {"status": 200, "body_text": "Ok."}))

    result = module.qbit_direct_safety_checks("http://127.0.0.1:4711", "secret")

    assert result["public_webapi_version"]["status"] == 200
    assert result["unauthenticated_info"]["status"] == 403
    assert result["wrong_login"]["body_text"] == "Fails."
    assert result["wrong_login_info"]["status"] == 403
    assert result["invalid_add"]["status"] == 400


def test_qbit_safety_checks_reject_unprotected_info(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()

    def fake_qbit_request(_base_url, path, **_kwargs):
        if path == "/api/v2/app/webapiVersion":
            return {"status": 200, "body_text": "2.11.0"}
        if path == "/api/v2/torrents/info":
            return {"status": 200, "body_text": "[]"}
        return {"status": 200, "body_text": "Fails."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)

    with pytest.raises(RuntimeError, match="unauthenticated protected endpoint"):
        module.qbit_direct_safety_checks("http://127.0.0.1:4711", "secret")


def test_qbit_live_wire_roundtrip_mutates_and_deletes_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[str] = []
    transfer_hash = "0123456789abcdef0123456789abcdef"

    monkeypatch.setattr(module, "qbit_login", lambda _base_url, _api_key: ("opener", {"status": 200, "body_text": "Ok."}))
    monkeypatch.setattr(
        module,
        "qbit_direct_add",
        lambda *_args, **_kwargs: calls.append("add") or {"add_status": 200, "hash": transfer_hash},
    )
    def fake_wait_for_transfer_category(*args, **_kwargs):
        category = args[3]
        calls.append(f"category:{category}")
        return {"hash": transfer_hash, "categoryName": category}

    monkeypatch.setattr(module, "wait_for_transfer_category", fake_wait_for_transfer_category)
    monkeypatch.setattr(
        module,
        "wait_for_transfer",
        lambda *_args, **_kwargs: calls.append("transfer") or {"hash": transfer_hash, "state": "paused"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_transfer_absent",
        lambda *_args, **_kwargs: calls.append("absent") or {"hash": transfer_hash, "absent": True},
    )

    def fake_qbit_request(_base_url, path, **_kwargs):
        calls.append(path.rsplit("/", 1)[-1])
        if path == "/api/v2/torrents/info":
            return {"status": 200, "body_text": f'[{{"hash":"{transfer_hash}"}}]'}
        return {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)

    result = module.qbit_direct_live_wire_roundtrip(
        "http://127.0.0.1:4711",
        "secret",
        module.SYNTHETIC_TRIGGER_MAGNET,
        initial_category="RADARR_ENG",
        updated_category="SONARR_ENG",
        timeout_seconds=30.0,
    )

    assert calls == [
        "add",
        "info",
        "setCategory",
        "resume",
        "pause",
        "delete",
        "absent",
    ]
    assert result["add"]["hash"] == transfer_hash
    assert result["delete_status"] == 200
    assert result["deleted_transfer"]["absent"] is True
