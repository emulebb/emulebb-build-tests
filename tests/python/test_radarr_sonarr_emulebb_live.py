from __future__ import annotations

import importlib.util
import types
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


def test_radarr_sonarr_live_report_records_live_network_launch_inputs() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "radarr-sonarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert '"launch_inputs"' in script_text
    assert '"p2p_bind_interface_name": args.p2p_bind_interface_name' in script_text
    assert '"enable_upnp": True' in script_text
    assert 'BindAddr=hide.me' not in script_text


def test_radarr_sonarr_direct_search_terms_include_generic_fallback() -> None:
    module = load_radarr_sonarr_module()
    inputs = types.SimpleNamespace(
        document_terms=("linux", "ubuntu"),
        generic_open_terms=("ubuntu", "emule", "fedora"),
        radarr_movie_terms=("operator movie term", "linux"),
        sonarr_series_terms=("operator series term", "linux"),
    )

    assert module.build_direct_search_terms(inputs) == ("linux", "ubuntu", "emule", "fedora")
    assert module.build_qbit_search_terms(inputs) == (
        "operator movie term",
        "linux",
        "operator series term",
        "ubuntu",
        "emule",
        "fedora",
    )
    assert module.build_sonarr_release_terms(inputs) == ("operator series term", "linux", "ubuntu", "emule", "fedora")


def test_radarr_import_movie_title_comes_from_live_wire_inputs() -> None:
    module = load_radarr_sonarr_module()
    inputs = types.SimpleNamespace(radarr_movie_terms=(" operator configured title ", "fallback"))

    assert module.require_radarr_import_movie_terms(inputs) == ("operator configured title",)


def test_radarr_sonarr_live_script_does_not_define_static_movie_title() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "radarr-sonarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "RADARR_IMPORT_MOVIE_TITLE" not in script_text
    assert "movie_title = " not in script_text


def test_radarr_sonarr_direct_magnet_collection_uses_explicit_video_category(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[str] = []
    magnet = (
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef00000000"
        "&dn=Public%20Movie.mkv&xl=42"
    )
    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss><channel><item><title>Public Movie</title><link>{magnet.replace("&", "&amp;")}</link></item></channel></rss>"""

    def fake_http_request(_base_url, path, **_kwargs):
        calls.append(path)
        return {"status": 200, "body_text": rss}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.collect_direct_magnets(
        "http://127.0.0.1:4711",
        "secret key",
        ("Public Movie",),
        1,
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    )

    assert result["magnets"][0]["hash"] == "0123456789abcdef0123456789abcdef"
    assert "cat=2000" in calls[0]
    assert "cat=7000" not in calls[0]


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

    def fake_qbit_request(_base_url, path, **kwargs):
        method = str(kwargs.get("method") or "GET").upper()
        if kwargs.get("cookie") is not None:
            if method == "GET" and path in {
                "/api/v2/app/version",
                "/api/v2/app/preferences",
                "/api/v2/torrents/categories",
                "/api/v2/torrents/info",
            }:
                return {"status": 200, "body_text": "Ok."}
            if (
                path == "/api/v2/torrents/setForceStart"
                and kwargs.get("form", {}).get("hashes") == "bad"
            ):
                return {"status": 400, "body_text": "Fails."}
            if method == "POST" and path in {
                "/api/v2/torrents/setShareLimits",
                "/api/v2/torrents/topPrio",
                "/api/v2/torrents/setForceStart",
            }:
                return {"status": 200, "body_text": "Ok."}
            if path == "/api/v2/torrents/createCategory" and kwargs.get("form", {}).get("category") == "LIVE_WIRE_ROUTE_CHECK":
                return {"status": 200, "body_text": "Ok."}
            if path == "/api/v2/torrents/createCategory" and kwargs.get("form", {}).get("category") == "bad\u0001name":
                return {"status": 400, "body_text": "Fails."}
            if path in {
                f"/api/v2/torrents/properties?hash={module.rest_smoke.REST_SURFACE_MISSING_HASH}",
                f"/api/v2/torrents/files?hash={module.rest_smoke.REST_SURFACE_MISSING_HASH}",
            }:
                return {"status": 404, "body_text": "Not found"}
            if path in {
                "/api/v2/torrents/delete",
                "/api/v2/torrents/pause",
                "/api/v2/torrents/stop",
                "/api/v2/torrents/resume",
                "/api/v2/torrents/start",
            } and kwargs.get("form", {}).get("hashes") == module.rest_smoke.REST_SURFACE_MISSING_HASH:
                return {"status": 200, "body_text": "Ok."}
            if (
                path == "/api/v2/torrents/setCategory"
                and kwargs.get("form", {}).get("hashes") == module.rest_smoke.REST_SURFACE_MISSING_HASH
                and kwargs.get("form", {}).get("category") == "LIVE_WIRE_ROUTE_CHECK"
            ):
                return {"status": 400, "body_text": "Fails."}
        if path == "/api/v2/app/webapiVersion" and method == "POST":
            return {"status": 404, "body_text": "Not found"}
        if path == "/api/v2/app/version" and method == "POST":
            return {"status": 404, "body_text": "Not found"}
        if path in {"/api/v2/torrents/add", "/api/v2/torrents/delete"} and method == "GET":
            return {"status": 404, "body_text": "Not found"}
        if path in {
            "/api/v2/torrents/delete",
            "/api/v2/torrents/setCategory",
            "/api/v2/torrents/createCategory",
            "/api/v2/torrents/pause",
            "/api/v2/torrents/properties",
            "/api/v2/torrents/info?category=%2x",
            "/api/v2/torrents/info?category=Movies&category=TV",
            "/api/v2/torrents/info?category=bad%01name",
            "/api/v2/torrents/files?hash=bad",
            "/api/v2/torrents/files?hash=%2x",
            "/api/v2/torrents/files%2x?hash=0123456789abcdef0123456789abcdef",
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
    assert result["missing_username_login"]["body_text"] == "Fails."
    assert result["wrong_username_login"]["body_text"] == "Fails."
    assert result["wrong_login_info"]["status"] == 403
    assert result["invalid_add"]["status"] == 400
    assert all(response["status"] == 404 for response in result["wrong_methods"].values())
    assert all(response["status"] == 400 for response in result["invalid_mutations"].values())
    assert set(result["route_completeness"]) == {scenario["name"] for scenario in module.QBIT_ROUTE_COMPLETENESS_SCENARIOS}
    assert result["route_completeness"]["set_force_start"]["status"] == 200
    assert result["route_completeness"]["set_force_start"]["expected_status"] == 200
    assert all("expected_statuses" not in response for response in result["route_completeness"].values())
    assert {
        "delete_duplicate_hash",
        "pause_too_many_hashes",
        "set_force_start_bad_hash",
        "add_json_content_type",
        "create_category_empty",
        "create_category_control_character",
        "info_malformed_percent_category",
        "info_duplicate_category",
        "info_control_character_category",
        "files_malformed_percent_hash",
        "files_malformed_percent_path",
    } <= set(result["invalid_mutations"])


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
            {"name": "useSsl"},
            {"name": "urlBase"},
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


def test_temp_qbit_client_is_deleted_when_validation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, str]] = []
    schema = {
        "implementation": "QBittorrent",
        "implementationName": "qBittorrent",
        "protocol": "torrent",
        "configContract": "QBittorrentSettings",
        "fields": [
            {"name": "host"},
            {"name": "port"},
            {"name": "useSsl"},
            {"name": "urlBase"},
            {"name": "username"},
            {"name": "password"},
            {"name": "initialState"},
            {"name": "movieCategory"},
        ],
    }

    monkeypatch.setattr(module, "get_qbit_schema", lambda _arr_url, _api_key: schema)

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path))
        if path == "/api/v3/downloadclient?forceSave=true":
            return {"status": 201, "json": {"id": 77, "fields": []}, "body_text": "{}"}
        if path == "/api/v3/downloadclient/test":
            return {"status": 400, "json": None, "body_text": "cannot connect"}
        if path == "/api/v3/downloadclient/77":
            return {"status": 200, "json": None, "body_text": ""}
        raise AssertionError(f"Unexpected Arr request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    with pytest.raises(RuntimeError, match="qBittorrent client test failed"):
        module.create_temp_qbit_client(
            "http://radarr.test",
            "key",
            name="eMule BB Live radarr 4711",
            host="127.0.0.1",
            port=4711,
            emule_api_key="emule-key",
            category_field="movieCategory",
            category="RADARR_ENG",
        )

    assert calls == [
        ("POST", "/api/v3/downloadclient?forceSave=true"),
        ("POST", "/api/v3/downloadclient/test"),
        ("DELETE", "/api/v3/downloadclient/77"),
    ]


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
        "enableRss": None,
        "enableAutomaticSearch": None,
        "enableInteractiveSearch": None,
        "protocol": "torrent",
        "priority": 25,
    }
    assert client["test_status"] == 200
    assert client["schema"] == {"ok": True}
    assert "fields" not in client


def test_ensure_emule_category_creates_dedicated_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    calls: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        calls.append({"path": path, **kwargs})
        if path == "/api/v1/categories":
            if kwargs.get("method") == "POST":
                return {"status": 200, "json": {"id": 9, "name": module.RADARR_IMPORT_CATEGORY, "path": kwargs["json_body"]["path"]}}
            return {"status": 200, "json": []}
        raise AssertionError(f"Unexpected native request: {path}")

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_array", lambda result, status: result["json"] if result["status"] == status else [])
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, status: result["json"] if result["status"] == status else {})

    summary = module.ensure_emule_category(
        "http://127.0.0.1:4711",
        "secret",
        module.RADARR_IMPORT_CATEGORY,
        tmp_path / module.RADARR_IMPORT_CATEGORY,
    )

    assert summary["created"] is True
    assert summary["name"] == module.RADARR_IMPORT_CATEGORY
    assert Path(str(summary["path"])).name == module.RADARR_IMPORT_CATEGORY
    assert calls[1]["json_body"]["path"] == str((tmp_path / module.RADARR_IMPORT_CATEGORY).resolve())


def test_ensure_radarr_movie_ensures_root_folder_before_create(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    calls: list[str] = []

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        calls.append(path)
        if path == "/api/v3/rootfolder":
            if kwargs.get("method") == "POST":
                return {"status": 201, "json": {"id": 5, "path": kwargs["json_body"]["path"]}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/movie":
            if kwargs.get("method") == "POST":
                payload = kwargs["json_body"]
                assert payload["rootFolderPath"] == str(tmp_path.resolve())
                return {"status": 201, "json": {"id": 17, "title": payload["title"]}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/qualityprofile":
            return {"status": 200, "json": [{"id": 3}], "body_text": "[]"}
        if path.startswith("/api/v3/movie/lookup?term="):
            return {"status": 200, "json": [{"title": "operator configured title", "tmdbId": 123}], "body_text": "[]"}
        raise AssertionError(f"Unexpected Radarr request: {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    summary = module.ensure_radarr_movie("http://radarr.test", "key", "operator configured title", tmp_path)

    assert summary["id"] == 17
    assert summary["created"] is True
    assert summary["root_folder"] == {"id": 5, "path": str(tmp_path.resolve()), "created": True}
    assert calls[:2] == ["/api/v3/rootfolder", "/api/v3/rootfolder"]


def test_ensure_arr_indexer_enabled_reenables_disabled_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    requests: list[dict[str, object]] = []

    def fake_arr_request(arr_url, api_key, path, **kwargs):
        requests.append({"path": path, **kwargs})
        assert path == "/api/v3/indexer/15?forceSave=true"
        assert kwargs["method"] == "PUT"
        payload = kwargs["json_body"]
        assert payload["enable"] is True
        return {"status": 202, "json": {**payload, "id": 15}, "body_text": "{}"}

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    enabled, summary = module.ensure_arr_indexer_enabled(
        "http://sonarr.test",
        "key",
        {"id": 15, "name": "eMule BB Local", "enable": False, "fields": []},
    )

    assert enabled["enable"] is True
    assert summary == {"changed": True, "status": 202}
    assert len(requests) == 1


def test_require_arr_check_passed_accepts_release_search_diagnostics() -> None:
    module = load_radarr_sonarr_module()
    report = {
        "readiness": {
            "indexer_synced": True,
            "indexer_enabled": True,
            "download_client_created": True,
            "download_client_tested": True,
        },
        "release_search": {"status": "inconclusive", "error": "no rows"},
    }

    module.require_arr_check_passed("sonarr", report)


def test_require_arr_check_passed_rejects_disabled_indexer() -> None:
    module = load_radarr_sonarr_module()
    report = {
        "readiness": {
            "indexer_synced": True,
            "indexer_enabled": False,
            "download_client_created": True,
            "download_client_tested": True,
        },
        "release_search": {"count": 1},
    }

    with pytest.raises(RuntimeError, match="readiness"):
        module.require_arr_check_passed("sonarr", report)


def test_is_arr_indexer_enabled_uses_modern_arr_flags() -> None:
    module = load_radarr_sonarr_module()

    assert module.is_arr_indexer_enabled(
        {
            "enableRss": True,
            "enableAutomaticSearch": True,
            "enableInteractiveSearch": True,
        }
    )
    assert not module.is_arr_indexer_enabled(
        {
            "enableRss": True,
            "enableAutomaticSearch": False,
            "enableInteractiveSearch": True,
        }
    )


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


def test_qbit_live_wire_roundtrip_cleans_up_added_transfer_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[str] = []
    transfer_hash = "0123456789abcdef0123456789abcdef"

    monkeypatch.setattr(module, "qbit_login", lambda _base_url, _api_key: ("opener", {"status": 200, "body_text": "Ok."}))
    monkeypatch.setattr(
        module,
        "qbit_direct_add",
        lambda *_args, **_kwargs: {"add_status": 200, "hash": transfer_hash},
    )
    monkeypatch.setattr(
        module,
        "delete_transfer",
        lambda *_args, **_kwargs: calls.append("native_cleanup") or {"status": 200},
    )

    def fake_qbit_request(_base_url, path, **_kwargs):
        if path == "/api/v2/torrents/info":
            return {"status": 200, "body_text": "[]"}
        return {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)

    progress: dict[str, object] = {}
    with pytest.raises(RuntimeError, match="did not include the selected transfer"):
        module.qbit_direct_live_wire_roundtrip(
            "http://127.0.0.1:4711",
            "secret",
            module.SYNTHETIC_TRIGGER_MAGNET,
            initial_category="RADARR_ENG",
            updated_category="SONARR_ENG",
            timeout_seconds=30.0,
            progress=progress,
        )

    assert calls == ["native_cleanup"]
    assert progress["native_cleanup_delete"] == {"status": 200}


def test_collect_direct_magnets_deduplicates_search_results(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    magnet_a = (
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef00000000"
        "&dn=operator-movie-one.mkv&xl=42"
    )
    magnet_b = (
        "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000"
        "&dn=operator-movie-two.mkv&xl=84"
    )
    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss><channel>
<item><title>operator movie one</title><link>{magnet_a.replace("&", "&amp;")}</link></item>
<item><title>Duplicate</title><link>{magnet_a.replace("&", "&amp;")}</link></item>
<item><title>operator movie two</title><link>{magnet_b.replace("&", "&amp;")}</link></item>
</channel></rss>"""

    monkeypatch.setattr(
        module.rest_smoke,
        "http_request",
        lambda *_args, **_kwargs: {"status": 200, "body_text": rss},
    )

    result = module.collect_direct_magnets(
        "http://127.0.0.1:4711",
        "secret",
        ("operator movie one",),
        2,
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    )

    assert result["attempts"][0]["items"] == 3
    assert [row["hash"] for row in result["magnets"]] == [
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
    ]


def test_qbit_live_wire_stress_runs_requested_rounds(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, str, str]] = []
    magnets = [
        {"query": "operator movie one", "title": "A", "magnet": "magnet-a", "hash": "a"},
        {"query": "operator movie two", "title": "B", "magnet": "magnet-b", "hash": "b"},
        {"query": "operator movie three", "title": "C", "magnet": "magnet-c", "hash": "c"},
    ]

    def fake_roundtrip(_base_url, _api_key, magnet, **kwargs):
        calls.append((magnet, kwargs["initial_category"], kwargs["updated_category"]))
        kwargs["progress"]["delete_status"] = 200
        return kwargs["progress"]

    monkeypatch.setattr(module, "qbit_direct_live_wire_roundtrip", fake_roundtrip)

    result = module.qbit_direct_live_wire_stress(
        "http://127.0.0.1:4711",
        "secret",
        magnets,
        rounds=2,
        timeout_seconds=30.0,
        initial_category=module.RADARR_IMPORT_CATEGORY,
        updated_category=module.RADARR_IMPORT_CATEGORY,
    )

    assert calls == [
        ("magnet-a", module.RADARR_IMPORT_CATEGORY, module.RADARR_IMPORT_CATEGORY),
        ("magnet-b", module.RADARR_IMPORT_CATEGORY, module.RADARR_IMPORT_CATEGORY),
    ]
    assert result["rounds"] == 2
    assert result["runs"][1]["expected_hash_present"] is True
    assert "expected_hash" not in result["runs"][1]
    assert "query" not in result["runs"][1]
    assert "title" not in result["runs"][1]


def test_qbit_live_wire_stress_requires_enough_unique_magnets() -> None:
    module = load_radarr_sonarr_module()

    with pytest.raises(RuntimeError, match="needs 2 unique magnet"):
        module.qbit_direct_live_wire_stress(
            "http://127.0.0.1:4711",
            "secret",
            [{"query": "operator movie one", "title": "A", "magnet": "magnet-a", "hash": "a"}],
            rounds=2,
            timeout_seconds=30.0,
        )
