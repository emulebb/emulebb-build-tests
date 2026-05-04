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
        if path in {
            "/api/v2/torrents/delete",
            "/api/v2/torrents/setCategory",
            "/api/v2/torrents/pause",
            "/api/v2/torrents/properties",
            "/api/v2/torrents/files?hash=bad",
        }:
            return {"status": 400, "body_text": "Fails."}
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
    assert all(response["status"] == 400 for response in result["invalid_mutations"].values())


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


def test_qbit_schema_summary_requires_arr_fields() -> None:
    module = load_radarr_sonarr_module()
    schema = {
        "implementation": "QBittorrent",
        "implementationName": "qBittorrent",
        "protocol": "torrent",
        "configContract": "QBittorrentSettings",
        "fields": [
            {"name": "host"},
            {"name": "port"},
            {"name": "username"},
            {"name": "password"},
            {"name": "initialState"},
            {"name": "movieCategory"},
        ],
    }

    summary = module.summarize_qbit_schema(schema, category_field="movieCategory")

    assert summary["ok"] is True
    assert summary["missing_required_fields"] == []
    assert module.summarize_qbit_schema(schema, category_field="tvCategory")["missing_required_fields"] == ["tvCategory"]


def test_arr_readiness_summaries_are_compact() -> None:
    module = load_radarr_sonarr_module()

    indexer = module.summarize_arr_indexer(
        {
            "id": 40,
            "name": "eMule BB Local",
            "implementation": "Torznab",
            "enable": True,
            "protocol": "torrent",
            "priority": 25,
        }
    )
    client = module.summarize_arr_download_client(
        {
            "id": 50,
            "name": "eMule BB Live radarr 4711",
            "implementation": "QBittorrent",
            "protocol": "torrent",
            "enable": True,
            "_emulebbSchemaSummary": {"ok": True},
            "_emulebbTestStatus": 200,
        },
        category="RADARR_ENG",
    )

    assert indexer == {
        "id": 40,
        "name": "eMule BB Local",
        "implementation": "Torznab",
        "enable": True,
        "protocol": "torrent",
        "priority": 25,
    }
    assert client["test_status"] == 200
    assert client["schema"] == {"ok": True}
    assert "fields" not in client


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
        if path.startswith("/api/v2/torrents/info?category="):
            return {"status": 200, "body_text": f'[{{"hash":"{transfer_hash}"}}]'}
        if path.startswith("/api/v2/torrents/properties?hash="):
            return {"status": 200, "body_text": f'{{"hash":"{transfer_hash}","save_path":""}}'}
        if path.startswith("/api/v2/torrents/files?hash="):
            return {"status": 200, "body_text": '[{"name":"test.bin"}]'}
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
        "info?category=RADARR_ENG",
        "properties?hash=0123456789abcdef0123456789abcdef",
        "files?hash=0123456789abcdef0123456789abcdef",
        "setCategory",
        "category:SONARR_ENG",
        "resume",
        "pause",
        "delete",
        "absent",
    ]
    assert result["add"]["hash"] == transfer_hash
    assert result["active_metadata"]["files_count"] == 1
    assert result["delete_status"] == 200
    assert result["deleted_transfer"]["absent"] is True


def test_collect_direct_magnets_deduplicates_search_results(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    magnet_a = (
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef00000000"
        "&dn=La%20Dolce%20Vita.mkv&xl=42"
    )
    magnet_b = (
        "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000"
        "&dn=Roma%20citta%20aperta.mkv&xl=84"
    )
    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss><channel>
<item><title>La Dolce Vita</title><link>{magnet_a.replace("&", "&amp;")}</link></item>
<item><title>Duplicate</title><link>{magnet_a.replace("&", "&amp;")}</link></item>
<item><title>Roma citta aperta</title><link>{magnet_b.replace("&", "&amp;")}</link></item>
</channel></rss>"""

    monkeypatch.setattr(
        module.rest_smoke,
        "http_request",
        lambda *_args, **_kwargs: {"status": 200, "body_text": rss},
    )

    result = module.collect_direct_magnets("http://127.0.0.1:4711", "secret", ("La Dolce Vita",), 2)

    assert result["attempts"][0]["items"] == 3
    assert [row["hash"] for row in result["magnets"]] == [
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
    ]


def test_qbit_live_wire_stress_runs_requested_rounds(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[str] = []
    magnets = [
        {"query": "La Dolce Vita", "title": "A", "magnet": "magnet-a", "hash": "a"},
        {"query": "Roma citta aperta", "title": "B", "magnet": "magnet-b", "hash": "b"},
        {"query": "Ladri di biciclette", "title": "C", "magnet": "magnet-c", "hash": "c"},
    ]

    def fake_roundtrip(_base_url, _api_key, magnet, **kwargs):
        calls.append(magnet)
        kwargs["progress"]["delete_status"] = 200
        return kwargs["progress"]

    monkeypatch.setattr(module, "qbit_direct_live_wire_roundtrip", fake_roundtrip)

    result = module.qbit_direct_live_wire_stress(
        "http://127.0.0.1:4711",
        "secret",
        magnets,
        rounds=2,
        timeout_seconds=30.0,
    )

    assert calls == ["magnet-a", "magnet-b"]
    assert result["rounds"] == 2
    assert result["runs"][1]["expected_hash_present"] is True
    assert "expected_hash" not in result["runs"][1]
    assert "query" not in result["runs"][1]
    assert "title" not in result["runs"][1]
