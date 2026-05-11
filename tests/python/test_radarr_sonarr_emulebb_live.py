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


def test_radarr_stage_keeps_movie_and_generic_terms_separate() -> None:
    module = load_radarr_sonarr_module()
    inputs = types.SimpleNamespace(
        generic_open_terms=("linux", "ubuntu"),
        radarr_movie_terms=("operator movie term", "fallback movie"),
        sonarr_series_terms=("operator series term",),
    )
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "radarr-sonarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert not hasattr(module, "build_direct_search_terms")
    assert not hasattr(module, "build_qbit_search_terms")
    assert module.require_radarr_import_movie_terms(inputs) == ("operator movie term", "fallback movie")
    assert "generic_open" not in script_text


def test_radarr_import_movie_title_comes_from_live_wire_inputs() -> None:
    module = load_radarr_sonarr_module()
    inputs = types.SimpleNamespace(radarr_movie_terms=(" operator configured title ", "fallback"))

    assert module.require_radarr_import_movie_terms(inputs) == ("operator configured title", "fallback")


def test_media_acquisition_defaults_to_small_quality_profile() -> None:
    module = load_radarr_sonarr_module()
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "radarr-sonarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert module.DEFAULT_MEDIA_QUALITY_PROFILE_NAME == "AnyAnyLang"
    assert 'env_values.get("RADARR_QUALITY_PROFILE_NAME")' not in script_text
    assert 'env_values.get("SONARR_QUALITY_PROFILE_NAME")' not in script_text


def test_radarr_stage_does_not_duplicate_prowlarr_movie_readiness() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "radarr-sonarr-emulebb-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "selected_media_terms = media_terms" in script_text
    assert "wait_for_primary_radarr_movie_term_results" not in script_text
    assert "diagnose_radarr_movie_terms" not in script_text
    assert "prowlarr_radarr_video_search" not in script_text
    assert "prowlarr_sonarr_video_search" not in script_text


def test_arr_release_selection_prefers_title_match_then_sources() -> None:
    module = load_radarr_sonarr_module()

    result = module.select_best_arr_release(
        [
            {"title": "Other Release", "sources": 100, "guid": "other"},
            {"title": "Operator Movie 720p", "sources": 4, "guid": "lower"},
            {"title": "Operator Movie 1080p", "sources": 12, "guid": "best"},
        ],
        "operator movie",
    )

    assert result["guid"] == "best"


def test_arr_release_search_paths_try_operator_term_before_media_id() -> None:
    module = load_radarr_sonarr_module()

    paths = module.build_arr_release_search_paths("radarr", "operator movie", 14, media_id=77)

    assert paths[:2] == [
        "/api/v3/release?term=operator%20movie&indexerIds=14",
        "/api/v3/release?term=operator%20movie&indexerId=14",
    ]
    assert paths[2:] == [
        "/api/v3/release?movieId=77&indexerIds=14",
        "/api/v3/release?movieId=77&indexerId=14",
    ]


def test_radarr_movie_download_e2e_requires_release_grab_and_category_transfer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        module,
        "ensure_radarr_movie",
        lambda *_args, **_kwargs: calls.append(("movie", None))
        or {"id": 77, "created": True, "root_folder": {"path": str(tmp_path)}},
    )
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: calls.append(("release_grab", _args[3]))
        or {
            "attempt_count": 1,
            "title_present": True,
            "downloadUrl_present": True,
            "guid_present": True,
            "selection": {"title_match_score": 200, "source_count": 12},
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "grab_status": 200,
        },
    )
    monkeypatch.setattr(
        module,
        "wait_for_transfer_category",
        lambda *_args, **_kwargs: calls.append(("category_transfer", _args[2:4]))
        or {"hash": _args[2], "categoryName": _args[3]},
    )
    monkeypatch.setattr(
        module,
        "wait_for_transfer_completion",
        lambda *_args, **_kwargs: calls.append(("transfer_complete", _args[2])) or {"hash": _args[2], "state": "completed"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_radarr_import",
        lambda *_args, **_kwargs: calls.append(("radarr_import", _args[2])) or {"movie_id": _args[2], "hasFile": True},
    )
    monkeypatch.setattr(
        module,
        "resume_transfer_if_paused",
        lambda *_args, **_kwargs: calls.append(("resume_if_paused", _args[2])) or {"resumed": False},
    )
    monkeypatch.setattr(module, "arr_health_rows", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: set())
    report, cleanup_movie_id = module.run_radarr_movie_download_e2e(
        radarr_url="http://radarr.test",
        radarr_api_key="key",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        indexer_id=40,
        indexer_name="eMule BB Local (Prowlarr)",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        movie_root_creates_local_path=True,
        quality_profile_name="AnyAnyLang",
        release_search_timeout_seconds=10.0,
        timeout_seconds=10.0,
    )

    assert cleanup_movie_id == 77
    assert report["release_grab"]["hash_present"] is True
    assert report["release_grab"]["selection"] == {"title_match_score": 200, "source_count": 12}
    assert report["category_transfer"]["categoryName"] == module.RADARR_IMPORT_CATEGORY
    assert calls == [
        ("movie", None),
        ("release_grab", "operator movie"),
        ("category_transfer", ("fedcba9876543210fedcba9876543210", module.RADARR_IMPORT_CATEGORY)),
        ("resume_if_paused", "fedcba9876543210fedcba9876543210"),
        ("transfer_complete", "fedcba9876543210fedcba9876543210"),
        ("radarr_import", 77),
    ]


def test_radarr_movie_download_e2e_uses_prowlarr_source_when_arr_quarantined_indexer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        module,
        "ensure_radarr_movie",
        lambda *_args, **_kwargs: {"id": 77, "created": True, "root_folder": {"path": str(tmp_path)}},
    )
    monkeypatch.setattr(
        module,
        "arr_health_rows",
        lambda *_args, **_kwargs: [
            {
                "source": "IndexerStatusCheck",
                "message": "Indexers unavailable due to failures: eMule BB Local (Prowlarr)",
            }
        ],
    )
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: calls.append(("direct_arr_search", None)) or pytest.fail("direct Arr search should not run"),
    )

    def fake_prowlarr_source_grab(**kwargs):
        calls.append(("prowlarr_source_grab", (kwargs["title"], kwargs["category_id"], kwargs["download_category"])))
        return {
            "source": "prowlarr_eMule_indexer_arr_grab",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "category_transfer": {"hash_present": True, "categoryName": module.RADARR_IMPORT_CATEGORY},
        }

    monkeypatch.setattr(module, "grab_first_arr_release_via_prowlarr", fake_prowlarr_source_grab)
    monkeypatch.setattr(
        module,
        "wait_for_transfer_completion",
        lambda *_args, **_kwargs: calls.append(("transfer_complete", _args[2])) or {"hash": _args[2], "state": "completed"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_radarr_import",
        lambda *_args, **_kwargs: calls.append(("radarr_import", _args[2])) or {"movie_id": _args[2], "hasFile": True},
    )
    monkeypatch.setattr(
        module,
        "resume_transfer_if_paused",
        lambda *_args, **_kwargs: calls.append(("resume_if_paused", _args[2])) or {"resumed": False},
    )

    report, cleanup_movie_id = module.run_radarr_movie_download_e2e(
        radarr_url="http://radarr.test",
        radarr_api_key="key",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        indexer_id=40,
        indexer_name="eMule BB Local (Prowlarr)",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        movie_root_creates_local_path=True,
        quality_profile_name="AnyAnyLang",
        release_search_timeout_seconds=10.0,
        timeout_seconds=10.0,
    )

    assert cleanup_movie_id == 77
    assert report["indexer_health"]["unavailable_due_to_failures"] is True
    assert report["release_grab"]["source"] == "prowlarr_eMule_indexer_arr_grab"
    assert report["category_transfer"]["categoryName"] == module.RADARR_IMPORT_CATEGORY
    assert calls == [
        ("prowlarr_source_grab", ("operator movie", module.TORZNAB_MOVIE_CATEGORY, module.RADARR_IMPORT_CATEGORY)),
        ("resume_if_paused", "fedcba9876543210fedcba9876543210"),
        ("transfer_complete", "fedcba9876543210fedcba9876543210"),
        ("radarr_import", 77),
    ]


def test_arr_release_grab_discovers_new_category_transfer_when_release_hash_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: calls.append(("direct_arr_search", _args[3]))
        or {"source": "arr_release_search", "hash": "", "hash_present": False, "grab_status": 200},
    )
    monkeypatch.setattr(
        module,
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: calls.append(("new_transfer", kwargs["category"]))
        or {"hash": "fedcba9876543210fedcba9876543210", "categoryName": kwargs["category"]},
    )

    result = module.grab_first_arr_release_or_fallback_to_prowlarr(
        kind="radarr",
        arr_url="http://radarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMule BB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator movie",
        media_id=77,
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        download_category=module.RADARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
        health_rows=[],
    )

    assert result["hash"] == "fedcba9876543210fedcba9876543210"
    assert result["hash_present"] is True
    assert result["category_transfer"]["categoryName"] == module.RADARR_IMPORT_CATEGORY
    assert calls == [
        ("direct_arr_search", "operator movie"),
        ("new_transfer", module.RADARR_IMPORT_CATEGORY),
    ]


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
            if (
                path == "/api/v2/torrents/setShareLimits"
                and (
                    kwargs.get("form", {}).get("ratioLimit") == "bad"
                    or kwargs.get("form", {}).get("seedingTimeLimit") == "1.5"
                )
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
        "set_share_limits_bad_ratio",
        "set_share_limits_bad_seed_time",
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


def test_qbit_client_payload_starts_media_downloads() -> None:
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

    payload = module.build_qbit_client_payload(
        schema,
        name="eMule BB Live radarr 4711",
        host="127.0.0.1",
        port=4711,
        api_key="emule-key",
        category_field="movieCategory",
        category="radarr_movies_cat",
    )

    assert next(field["value"] for field in payload["fields"] if field["name"] == "initialState") == 0
    assert next(field["value"] for field in payload["fields"] if field["name"] == "movieCategory") == "radarr_movies_cat"


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
        "tag_count": None,
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


def test_ensure_radarr_movie_accepts_explicit_remote_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    remote_root = "/media/radarr-import-root"

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        if path == "/api/v3/rootfolder":
            if kwargs.get("method") == "POST":
                assert kwargs["json_body"]["path"] == remote_root
                return {"status": 201, "json": {"id": 5, "path": remote_root}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/movie":
            if kwargs.get("method") == "POST":
                assert kwargs["json_body"]["rootFolderPath"] == remote_root
                return {"status": 201, "json": {"id": 17, "title": kwargs["json_body"]["title"]}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/qualityprofile":
            return {"status": 200, "json": [{"id": 3}], "body_text": "[]"}
        if path.startswith("/api/v3/movie/lookup?term="):
            return {"status": 200, "json": [{"title": "operator configured title", "tmdbId": 123}], "body_text": "[]"}
        raise AssertionError(f"Unexpected Radarr request: {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    summary = module.ensure_radarr_movie(
        "http://radarr.test",
        "key",
        "operator configured title",
        remote_root,
        create_local_root_path=False,
    )

    assert summary["id"] == 17
    assert not (tmp_path / "media" / "radarr-import-root").exists()


def test_ensure_radarr_movie_prefers_named_quality_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        if path == "/api/v3/rootfolder":
            if kwargs.get("method") == "POST":
                return {"status": 201, "json": {"id": 5, "path": kwargs["json_body"]["path"]}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/qualityprofile":
            return {
                "status": 200,
                "json": [{"id": 3, "name": "Large"}, {"id": 9, "name": "AnyAnyLang"}],
                "body_text": "[]",
            }
        if path == "/api/v3/movie":
            if kwargs.get("method") == "POST":
                payload = kwargs["json_body"]
                assert payload["qualityProfileId"] == 9
                return {"status": 201, "json": {"id": 17, "title": payload["title"]}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path.startswith("/api/v3/movie/lookup?term="):
            return {"status": 200, "json": [{"title": "operator configured title", "tmdbId": 123}], "body_text": "[]"}
        raise AssertionError(f"Unexpected Radarr request: {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    summary = module.ensure_radarr_movie(
        "http://radarr.test",
        "key",
        "operator configured title",
        tmp_path,
        quality_profile_name="AnyAnyLang",
    )

    assert summary["quality_profile"] == {"id": 9, "name": "AnyAnyLang", "preferred_name": "AnyAnyLang"}


def test_radarr_root_environment_warning_marks_remote_local_roots(tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()

    warning = module.build_radarr_root_environment_warning(
        "http://192.0.2.10:7878",
        tmp_path / "radarr-root",
        create_local_path=True,
    )

    assert warning == {
        "remote_arr_url": True,
        "local_or_windows_root": True,
        "root_path_present": True,
        "message": "Radarr is not local; ensure the configured movie root is visible from the Radarr host/container.",
    }
    assert module.build_radarr_root_environment_warning(
        "http://127.0.0.1:7878",
        tmp_path / "radarr-root",
        create_local_path=True,
    ) is None


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


def test_ensure_arr_emule_indexer_reuses_existing_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    requests: list[tuple[str, str, dict[str, object] | None]] = []

    def fake_arr_request(_arr_url, _api_key, path, *, method="GET", json_body=None, **_kwargs):
        requests.append((method, path, json_body))
        if path == "/api/v3/indexer" and method == "GET":
            return {
                "status": 200,
                "json": [
                    {
                        "id": 14,
                        "name": "eMule BB Local (Prowlarr)",
                        "enableRss": False,
                        "enableAutomaticSearch": False,
                        "enableInteractiveSearch": False,
                        "fields": [{"name": "baseUrl"}, {"name": "apiPath"}, {"name": "apiKey"}, {"name": "categories"}],
                    },
                    {"id": 20, "name": "Other Indexer"},
                ],
                "body_text": "[]",
            }
        if path == "/api/v3/indexer/14?forceSave=true" and method == "PUT":
            assert json_body["name"] == "eMule BB Local"
            assert json_body["enableRss"] is True
            assert json_body["fields"][0]["value"] == "http://prowlarr.test/40/"
            assert json_body["fields"][3]["value"] == [module.TORZNAB_MOVIE_CATEGORY]
            return {"status": 202, "json": {**json_body, "id": 14}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.ensure_arr_emule_indexer(
        arr_url="http://radarr.test",
        api_key="key",
        indexer_name="eMule BB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=40,
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    )

    assert indexer["id"] == 14
    assert summary == {"mode": "updated", "validation_retry": False, "category": module.TORZNAB_MOVIE_CATEGORY, "status": 202}
    assert [request[:2] for request in requests] == [("GET", "/api/v3/indexer"), ("PUT", "/api/v3/indexer/14?forceSave=true")]


def test_ensure_arr_emule_indexer_creates_missing_sonarr_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    requests: list[tuple[str, str]] = []
    schema = {
        "implementation": "Torznab",
        "implementationName": "Torznab",
        "configContract": "TorznabSettings",
        "protocol": "torrent",
        "enableRss": False,
        "enableAutomaticSearch": False,
        "enableInteractiveSearch": False,
        "fields": [{"name": "baseUrl"}, {"name": "apiPath"}, {"name": "apiKey"}, {"name": "categories"}],
    }

    def fake_arr_request(_arr_url, _api_key, path, *, method="GET", json_body=None, **_kwargs):
        requests.append((method, path))
        if path == "/api/v3/indexer" and method == "GET":
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/indexer/schema" and method == "GET":
            return {"status": 200, "json": [schema], "body_text": "[]"}
        if path == "/api/v3/indexer?forceSave=true" and method == "POST":
            assert json_body["fields"][0]["value"] == "http://prowlarr.test/40/"
            assert json_body["fields"][3]["value"] == [module.TORZNAB_TV_CATEGORY]
            return {"status": 201, "json": {**json_body, "id": 16}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.ensure_arr_emule_indexer(
        arr_url="http://sonarr.test",
        api_key="key",
        indexer_name="eMule BB Local",
        prowlarr_url="http://prowlarr.test/",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=40,
        category_id=module.TORZNAB_TV_CATEGORY,
    )

    assert indexer["id"] == 16
    assert summary == {"mode": "created", "validation_retry": False, "category": module.TORZNAB_TV_CATEGORY, "status": 201}
    assert requests == [
        ("GET", "/api/v3/indexer"),
        ("GET", "/api/v3/indexer/schema"),
        ("POST", "/api/v3/indexer?forceSave=true"),
    ]


def test_ensure_arr_emule_indexer_retries_disabled_save_on_validation_blocker(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    requests: list[tuple[str, str, bool]] = []
    schema = {
        "implementation": "Torznab",
        "implementationName": "Torznab",
        "configContract": "TorznabSettings",
        "protocol": "torrent",
        "enableRss": False,
        "enableAutomaticSearch": False,
        "enableInteractiveSearch": False,
        "fields": [{"name": "baseUrl"}, {"name": "apiPath"}, {"name": "apiKey"}, {"name": "categories"}],
    }

    def fake_arr_request(_arr_url, _api_key, path, *, method="GET", json_body=None, **_kwargs):
        enabled = bool(json_body and json_body.get("enableRss"))
        requests.append((method, path, enabled))
        if path == "/api/v3/indexer" and method == "GET":
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/indexer/schema" and method == "GET":
            return {"status": 200, "json": [schema], "body_text": "[]"}
        if path == "/api/v3/indexer?forceSave=true" and method == "POST" and enabled:
            return {"status": 400, "json": None, "body_text": "no results in the configured categories"}
        if path == "/api/v3/indexer?forceSave=true" and method == "POST" and not enabled:
            return {"status": 201, "json": {**json_body, "id": 21}, "body_text": "{}"}
        if path == "/api/v3/indexer/21?forceSave=true" and method == "PUT" and enabled:
            return {"status": 202, "json": {**json_body, "id": 21}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.ensure_arr_emule_indexer(
        arr_url="http://radarr.test",
        api_key="key",
        indexer_name="eMule BB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=40,
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    )

    assert indexer["id"] == 21
    assert summary == {
        "mode": "created",
        "validation_retry": True,
        "category": module.TORZNAB_MOVIE_CATEGORY,
        "initial_status": 400,
        "disabled_id": 21,
    }
    assert requests == [
        ("GET", "/api/v3/indexer", False),
        ("GET", "/api/v3/indexer/schema", False),
        ("POST", "/api/v3/indexer?forceSave=true", True),
        ("POST", "/api/v3/indexer?forceSave=true", False),
        ("PUT", "/api/v3/indexer/21?forceSave=true", True),
    ]


def test_recreate_arr_emule_indexer_if_unavailable_uses_public_arr_apis(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    requests: list[tuple[str, str]] = []
    schema = {
        "implementation": "Torznab",
        "implementationName": "Torznab",
        "configContract": "TorznabSettings",
        "protocol": "torrent",
        "enableRss": False,
        "enableAutomaticSearch": False,
        "enableInteractiveSearch": False,
        "fields": [{"name": "baseUrl"}, {"name": "apiPath"}, {"name": "apiKey"}, {"name": "categories"}],
    }

    def fake_arr_request(_arr_url, _api_key, path, *, method="GET", json_body=None, **_kwargs):
        requests.append((method, path))
        if path == "/api/v3/health" and method == "GET":
            return {
                "status": 200,
                "json": [
                    {
                        "source": "IndexerStatusCheck",
                        "message": "Indexers unavailable due to failures: eMule BB Local",
                    }
                ],
                "body_text": "[]",
            }
        if path == "/api/v3/indexer/15" and method == "DELETE":
            return {"status": 202, "json": None, "body_text": ""}
        if path == "/api/v3/indexer/schema" and method == "GET":
            return {"status": 200, "json": [schema], "body_text": "[]"}
        if path == "/api/v3/indexer?forceSave=true" and method == "POST":
            assert json_body["name"] == "eMule BB Local"
            assert json_body["fields"][0]["value"] == "http://prowlarr.test/40/"
            assert json_body["fields"][3]["value"] == [module.TORZNAB_MOVIE_CATEGORY]
            return {"status": 201, "json": {**json_body, "id": 44}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.recreate_arr_emule_indexer_if_unavailable(
        arr_url="http://radarr.test",
        api_key="key",
        indexer={"id": 15, "name": "eMule BB Local"},
        indexer_name="eMule BB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=40,
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    )

    assert indexer["id"] == 44
    assert summary["mode"] == "recreated"
    assert summary["old_id"] == 15
    assert summary["new_id"] == 44
    assert requests == [
        ("GET", "/api/v3/health"),
        ("DELETE", "/api/v3/indexer/15"),
        ("GET", "/api/v3/indexer/schema"),
        ("POST", "/api/v3/indexer?forceSave=true"),
    ]


def test_arr_validation_blocker_accepts_provider_validation_transport_errors() -> None:
    module = load_radarr_sonarr_module()

    assert module.is_arr_validation_blocker(
        {
            "status": 400,
            "body_text": "Unable to connect to indexer. HTTP request failed: [429:TooManyRequests]",
        }
    )


def test_ensure_arr_indexer_untagged_clears_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        assert path == "/api/v3/indexer/15?forceSave=true"
        assert kwargs["method"] == "PUT"
        payload = kwargs["json_body"]
        assert payload["tags"] == []
        return {"status": 202, "json": {**payload, "id": 15}, "body_text": "{}"}

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.ensure_arr_indexer_untagged(
        "http://radarr.test",
        "key",
        {"id": 15, "name": "eMule BB Local", "tags": [3]},
    )

    assert indexer["tags"] == []
    assert summary == {"changed": True, "previous_tag_count": 1, "status": 202}


def test_resolve_prowlarr_indexer_sync_tags_uses_matching_arr_application(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()

    def fake_prowlarr_request(_prowlarr_url, _api_key, path, **_kwargs):
        assert path == "/api/v1/applications"
        return {
            "status": 200,
            "json": [
                {
                    "enable": True,
                    "name": "RADARR_ENG",
                    "tags": [3],
                    "fields": [{"name": "baseUrl", "value": "http://radarr.test/"}],
                },
                {
                    "enable": True,
                    "name": "SONARR_ENG",
                    "tags": [4],
                    "fields": [{"name": "baseUrl", "value": "http://sonarr.test"}],
                },
            ],
            "body_text": "[]",
        }

    monkeypatch.setattr(module.prowlarr_live, "prowlarr_request", fake_prowlarr_request)

    assert module.resolve_prowlarr_indexer_sync_tags("http://prowlarr.test", "key", "http://radarr.test") == [3]


def test_require_arr_check_passed_accepts_skipped_release_search() -> None:
    module = load_radarr_sonarr_module()
    report = {
        "readiness": {
            "indexer_synced": True,
            "indexer_enabled": True,
            "download_client_created": True,
            "download_client_tested": True,
        },
        "release_search": {"status": "skipped", "reason": "covered by movie download proof"},
    }

    module.require_arr_check_passed("radarr", report)


def test_require_arr_check_passed_rejects_release_search_diagnostics() -> None:
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

    with pytest.raises(RuntimeError, match="release search"):
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
    save_path = r"C:\arr\radarr_movies_cat"
    content_path = save_path + r"\test.bin"
    escaped_save_path = save_path.replace("\\", "\\\\")
    escaped_content_path = content_path.replace("\\", "\\\\")

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
            return {"status": 200, "body_text": f'[{{"hash":"{transfer_hash}","name":"test.bin","save_path":"{escaped_save_path}","content_path":"{escaped_content_path}"}}]'}
        if path.startswith("/api/v2/torrents/info?category="):
            return {"status": 200, "body_text": f'[{{"hash":"{transfer_hash}"}}]'}
        if path.startswith("/api/v2/torrents/properties?hash="):
            return {"status": 200, "body_text": f'{{"hash":"{transfer_hash}","save_path":"{escaped_save_path}","content_path":"{escaped_content_path}"}}'}
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
        expected_save_path=save_path,
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
    assert result["active_metadata"]["path_contract"]["info_save_path_matches_expected"] is True
    assert result["active_metadata"]["path_contract"]["properties_save_path_matches_expected"] is True
    assert result["active_metadata"]["path_contract"]["content_path_matches_name"] is True
    assert result["delete_status"] == 200
    assert result["deleted_transfer"]["absent"] is True


def test_qbit_direct_add_sends_arr_share_limit_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    observed_form: dict[str, object] = {}

    def fake_qbit_request(_base_url, _path, **kwargs):
        observed_form.update(kwargs["form"])
        return {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)
    monkeypatch.setattr(module, "qbit_login", lambda _base_url, _api_key: ("opener", {"status": 200, "body_text": "Ok."}))

    result = module.qbit_direct_add(
        "http://127.0.0.1:4711",
        "secret",
        module.SYNTHETIC_TRIGGER_MAGNET,
        module.RADARR_IMPORT_CATEGORY,
    )

    assert result["hash"] == module.ed2k_hash_from_magnet(module.SYNTHETIC_TRIGGER_MAGNET)
    assert observed_form["category"] == module.RADARR_IMPORT_CATEGORY
    assert observed_form["ratioLimit"] == "-1"
    assert observed_form["seedingTimeLimit"] == "-1"
    assert observed_form["inactiveSeedingTimeLimit"] == "-1"


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
    calls: list[tuple[str, str, str, str | None]] = []
    magnets = [
        {"query": "operator movie one", "title": "A", "magnet": "magnet-a", "hash": "a"},
        {"query": "operator movie two", "title": "B", "magnet": "magnet-b", "hash": "b"},
        {"query": "operator movie three", "title": "C", "magnet": "magnet-c", "hash": "c"},
    ]

    def fake_roundtrip(_base_url, _api_key, magnet, **kwargs):
        calls.append((magnet, kwargs["initial_category"], kwargs["updated_category"], kwargs["expected_save_path"]))
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
        expected_save_path=r"C:\arr\radarr_movies_cat",
    )

    assert calls == [
        ("magnet-a", module.RADARR_IMPORT_CATEGORY, module.RADARR_IMPORT_CATEGORY, r"C:\arr\radarr_movies_cat"),
        ("magnet-b", module.RADARR_IMPORT_CATEGORY, module.RADARR_IMPORT_CATEGORY, r"C:\arr\radarr_movies_cat"),
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
