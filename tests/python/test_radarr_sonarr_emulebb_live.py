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
    assert "run_arr_checks(" in script_text
    assert "lan_bind_addr=bind_addr" in script_text
    assert "\n            bind_addr=bind_addr," not in script_text


def test_local_arr_release_names_are_deterministic_and_searchable() -> None:
    module = load_radarr_sonarr_module()

    assert module.arr_fake_release_name("radarr", "Example Movie: Test!") == (
        "Example Movie Test 2026 1080p WEB-DL eMuleBB.mkv"
    )
    assert module.arr_fake_release_name("sonarr", "Example Series") == (
        "Example Series S01E01 1080p WEB-DL eMuleBB.mkv"
    )
    assert "Example Movie" in module.arr_fake_release_name("radarr", "Example Movie: Test!")


def test_local_ed2k_parser_defaults_keep_fixture_in_workspace_control() -> None:
    module = load_radarr_sonarr_module()

    args = module.build_parser().parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--deterministic-local-ed2k"]
    )

    assert args.deterministic_local_ed2k is True
    assert args.local_ed2k_fixture_size_bytes == 132 * 1024 * 1024
    assert args.rest_webserver_scheme == "https"


def test_local_arr_media_folder_is_created_under_owned_root(tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    movie_path = tmp_path / "Movie Title (2026)"

    result = module.ensure_local_arr_media_folder(
        {"movie": {"path": str(movie_path)}},
        create_local_path=True,
        media_key="movie",
    )

    assert result["created"] is True
    assert result["exists"] is True
    assert movie_path.is_dir()


def test_local_arr_media_folder_skips_remote_or_unowned_roots(tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    movie_path = tmp_path / "Movie Title (2026)"

    result = module.ensure_local_arr_media_folder(
        {"movie": {"path": str(movie_path)}},
        create_local_path=False,
        media_key="movie",
    )

    assert result == {"created": False, "reason": "not_local_test_root"}
    assert not movie_path.exists()


def test_shared_hashing_snapshot_reads_status_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()

    def fake_http_request(_base_url, path, **kwargs):
        assert path == "/api/v1/status"
        assert kwargs["request_timeout_seconds"] == 3.0
        return {
            "status": 200,
            "json": {"stats": {"sharedHashingCount": 2, "sharedHashingActive": True}},
            "raw_json": {"data": {"stats": {"sharedHashingCount": 2, "sharedHashingActive": True}}, "meta": {"apiVersion": "v1"}},
        }

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: result["json"])

    assert module.shared_hashing_snapshot("http://127.0.0.1:1", "key", timeout_seconds=3.0) == {
        "status": 200,
        "hashingCount": 2,
        "hashingActive": True,
    }


def test_wait_for_shared_hashing_idle_polls_until_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    snapshots = [
        {"status": 200, "hashingCount": 3, "hashingActive": True},
        {"status": 200, "hashingCount": 0, "hashingActive": False},
    ]
    sleeps: list[float] = []

    monkeypatch.setattr(module, "shared_hashing_snapshot", lambda *_args, **_kwargs: snapshots.pop(0))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleeps.append(seconds))

    result = module.wait_for_shared_hashing_idle("http://127.0.0.1:1", "key", timeout_seconds=10.0)

    assert result == {"status": 200, "hashingCount": 0, "hashingActive": False, "idle": True}
    assert sleeps == [2.0]


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


def test_arr_release_selection_picks_smallest_release_with_enough_sources() -> None:
    module = load_radarr_sonarr_module()

    result = module.select_best_arr_release(
        [
            {"title": "Operator Movie 1080p", "sources": 40, "size": 4_000_000_000, "guid": "larger"},
            {"title": "Operator Movie 720p", "sources": 9, "size": 700_000_000, "guid": "too-few-sources"},
            {"title": "Operator Movie 1080p", "sources": 12, "size": 1_400_000_000, "guid": "smallest-ok"},
            {"title": "Other Release", "sources": 100, "size": 200_000_000, "guid": "other-smaller"},
        ],
        "operator movie",
    )

    assert result["guid"] == "smallest-ok"


def test_arr_release_selection_requires_minimum_sources_and_positive_size() -> None:
    module = load_radarr_sonarr_module()

    with pytest.raises(RuntimeError, match="at least 10 sources"):
        module.select_best_arr_release(
            [
                {"title": "Operator Movie 720p", "sources": 9, "size": 700_000_000, "guid": "too-few-sources"},
                {"title": "Operator Movie 1080p", "sources": 12, "size": 0, "guid": "missing-size"},
                {"title": "Unrelated 1080p", "sources": 12, "size": 1_000_000_000, "guid": "weak-title-match"},
            ],
            "operator movie",
        )


def test_arr_release_selection_can_use_lower_sonarr_source_floor() -> None:
    module = load_radarr_sonarr_module()

    result = module.select_best_arr_release(
        [
            {"title": "Operator Series 1080p", "sources": 8, "size": 2_000_000_000, "guid": "larger"},
            {"title": "Operator Series 720p", "sources": 2, "size": 700_000_000, "guid": "smallest-positive"},
            {"title": "Operator Series 480p", "sources": 0, "size": 400_000_000, "guid": "no-sources"},
        ],
        "operator series",
        min_sources=1,
    )

    assert result["guid"] == "smallest-positive"


def test_sonarr_release_selection_can_prefer_sources_over_size() -> None:
    module = load_radarr_sonarr_module()

    result = module.select_best_arr_release(
        [
            {"title": "Operator Series S01E01 480p", "sources": 1, "size": 400_000_000, "guid": "smallest-one-source"},
            {"title": "Operator Series S01E01 720p", "sources": 6, "size": 1_400_000_000, "guid": "stronger-sources"},
            {"title": "Operator Series S01E01 1080p", "sources": 6, "size": 2_000_000_000, "guid": "same-sources-larger"},
        ],
        "operator series",
        min_sources=1,
        require_episode_like=True,
        prefer_sources=True,
    )

    assert result["guid"] == "stronger-sources"


def test_sonarr_release_selection_requires_episode_like_title_when_requested() -> None:
    module = load_radarr_sonarr_module()

    result = module.select_best_arr_release(
        [
            {"title": "Operator Series Deleted Scene", "sources": 8, "size": 100_000_000, "guid": "not-episode"},
            {"title": "Operator Series S01E01", "sources": 2, "size": 700_000_000, "guid": "episode"},
        ],
        "operator series",
        min_sources=1,
        require_episode_like=True,
    )

    assert result["guid"] == "episode"


def test_sonarr_release_selection_rejects_spinoff_before_episode_marker() -> None:
    module = load_radarr_sonarr_module()

    result = module.select_best_arr_release(
        [
            {"title": "Star Trek Prodigy 1x08", "sources": 8, "size": 100_000_000, "guid": "spinoff"},
            {"title": "Star Trek S01E08", "sources": 2, "size": 700_000_000, "guid": "series-episode"},
        ],
        "Star Trek",
        min_sources=1,
        require_episode_like=True,
    )

    assert result["guid"] == "series-episode"


def test_arr_release_grab_skips_ranked_rows_rejected_by_arr(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    requests: list[tuple[str, str]] = []
    rejected = {
        "title": "Operator Movie Small",
        "indexerId": 14,
        "indexer": "eMuleBB Local",
        "sources": 20,
        "size": 1_000_000_000,
        "downloadUrl": "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000&dn=Operator.Movie.Small.mkv&xl=1000000000",
    }
    accepted = {
        "title": "Operator Movie Larger",
        "indexerId": 14,
        "indexer": "eMuleBB Local",
        "sources": 20,
        "size": 2_000_000_000,
        "downloadUrl": "magnet:?xt=urn:btih:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000&dn=Operator.Movie.Larger.mkv&xl=2000000000",
    }

    def fake_arr_request(_arr_url, _api_key, path, *, method="GET", json_body=None, **_kwargs):
        requests.append((method, path))
        if method == "GET":
            return {"status": 200, "json": [accepted, rejected], "body_text": "[]"}
        if method == "POST" and json_body == rejected:
            return {"status": 404, "json": None, "body_text": "Unable to find matching movie"}
        if method == "POST" and json_body == accepted:
            return {"status": 200, "json": {"status": 200}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    result = module.grab_first_arr_release(
        "http://radarr.test",
        "key",
        14,
        "operator movie",
        30.0,
        kind="radarr",
        media_id=99,
    )

    assert result["selection"]["source_count"] == 20
    assert result["rejected_candidate_count"] == 1
    assert result["hash"] == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert requests[:3] == [
        ("GET", "/api/v3/release?movieId=99&indexerIds=14"),
        ("POST", "/api/v3/release"),
        ("POST", "/api/v3/release"),
    ]


def test_arr_release_grab_enriches_zero_arr_sources_from_direct_torznab(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    posted: list[dict[str, object]] = []
    larger = {
        "title": "Operator Movie Large",
        "indexerId": 14,
        "indexer": "eMuleBB Local",
        "sources": 0,
        "size": 4_000_000_000,
        "downloadUrl": "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000&dn=Operator.Movie.Large.mkv&xl=4000000000",
    }
    smaller = {
        "title": "Operator Movie Small",
        "indexerId": 14,
        "indexer": "eMuleBB Local",
        "sources": 0,
        "size": 1_400_000_000,
        "downloadUrl": "magnet:?xt=urn:btih:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000&dn=Operator.Movie.Small.mkv&xl=1400000000",
    }

    def fake_arr_request(_arr_url, _api_key, _path, *, method="GET", json_body=None, **_kwargs):
        if method == "GET":
            return {"status": 200, "json": [larger, smaller], "body_text": "[]"}
        posted.append(json_body)
        return {"status": 200, "json": {"status": 200}, "body_text": "{}"}

    def fake_http_request(_base_url, path, **_kwargs):
        assert path.startswith("/indexer/emulebb/api?t=search&cat=2000&q=")
        body = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Operator Movie Large</title>
      <link>magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000</link>
      <enclosure url="magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000" length="4000000000" />
      <torznab:attr name="size" value="4000000000" />
      <torznab:attr name="peers" value="30" />
    </item>
    <item>
      <title>Operator Movie Small</title>
      <link>magnet:?xt=urn:btih:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000</link>
      <enclosure url="magnet:?xt=urn:btih:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000" length="1400000000" />
      <torznab:attr name="size" value="1400000000" />
      <torznab:attr name="peers" value="12" />
    </item>
  </channel>
</rss>"""
        return {"status": 200, "body_text": body}

    monkeypatch.setattr(module, "arr_request", fake_arr_request)
    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.grab_first_arr_release(
        "http://radarr.test",
        "key",
        14,
        "operator movie",
        30.0,
        kind="radarr",
        media_id=99,
        emule_base_url="http://emule.test",
        emule_api_key="emule-key",
        category_id=module.TORZNAB_MOVIE_CATEGORY,
    )

    assert posted == [{**smaller, "sources": 12, "sourceCount": 12, "_emulebbSourceEnriched": True}]
    assert result["selection"]["source_count"] == 12
    assert result["rejected_candidate_count"] == 0


def test_arr_release_search_paths_try_media_cache_before_operator_term() -> None:
    module = load_radarr_sonarr_module()

    paths = module.build_arr_release_search_paths("radarr", "operator movie", 14, media_id=77)

    assert paths[:2] == [
        "/api/v3/release?movieId=77&indexerIds=14",
        "/api/v3/release?movieId=77&indexerId=14",
    ]
    assert paths[2:] == [
        "/api/v3/release?term=operator%20movie&indexerIds=14",
        "/api/v3/release?term=operator%20movie&indexerId=14",
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
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: calls.append(("new_category_transfer", kwargs["category"]))
        or {
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "categoryName": kwargs["category"],
            "state": "downloading",
        },
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
        "trigger_arr_downloaded_scan",
        lambda *_args, **_kwargs: calls.append(("downloaded_scan", (_args[2], str(_args[3]))))
        or {"name": "DownloadedMoviesScan", "path_present": True},
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
        indexer_name="eMuleBB Local (Prowlarr)",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        category_save_path=tmp_path / module.RADARR_IMPORT_CATEGORY,
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
        ("new_category_transfer", module.RADARR_IMPORT_CATEGORY),
        ("resume_if_paused", "fedcba9876543210fedcba9876543210"),
        ("transfer_complete", "fedcba9876543210fedcba9876543210"),
        ("downloaded_scan", ("radarr", str(tmp_path / module.RADARR_IMPORT_CATEGORY))),
        ("radarr_import", 77),
    ]


def test_radarr_movie_download_e2e_handoff_skips_completion_and_import(
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
    monkeypatch.setattr(module, "arr_health_rows", lambda *_args, **_kwargs: [])

    def fake_grab(**kwargs):
        calls.append(("release_grab", (kwargs["title"], kwargs["download_category"])))
        return {
            "source": "arr_release_search",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "category_transfer": {
                "hash": "fedcba9876543210fedcba9876543210",
                "categoryName": kwargs["download_category"],
                "state": "downloading",
            },
        }

    monkeypatch.setattr(module, "grab_first_arr_release_or_fallback_to_prowlarr", fake_grab)
    monkeypatch.setattr(
        module,
        "resume_transfer_if_paused",
        lambda *_args, **_kwargs: calls.append(("resume_if_paused", _args[2])) or {"resumed": False},
    )
    monkeypatch.setattr(
        module,
        "stop_and_cancel_handoff_transfer",
        lambda *_args, **_kwargs: calls.append(("stop_cancel", _args[2])) or {"stop_status": 200, "cancel_status": 200},
    )
    monkeypatch.setattr(module, "wait_for_transfer_completion", lambda *_args, **_kwargs: pytest.fail("completion wait should be skipped"))
    monkeypatch.setattr(module, "trigger_arr_downloaded_scan", lambda *_args, **_kwargs: pytest.fail("downloaded scan should be skipped"))
    monkeypatch.setattr(module, "wait_for_radarr_import", lambda *_args, **_kwargs: pytest.fail("Arr import should be skipped"))

    report, cleanup_movie_id = module.run_radarr_movie_download_e2e(
        radarr_url="http://radarr.test",
        radarr_api_key="key",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        indexer_id=40,
        indexer_name="eMuleBB Local (Prowlarr)",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        category_save_path=tmp_path / module.RADARR_IMPORT_CATEGORY,
        movie_root_creates_local_path=True,
        quality_profile_name="AnyAnyLang",
        release_search_timeout_seconds=10.0,
        timeout_seconds=10.0,
        download_proof_mode="handoff",
    )

    assert cleanup_movie_id == 77
    assert report["completed_transfer"]["skipped"] is True
    assert report["downloaded_scan"]["skipped"] is True
    assert report["arr_import"]["skipped"] is True
    assert report["completed_transfer"]["last_seen"]["categoryName"] == module.RADARR_IMPORT_CATEGORY
    assert calls == [
        ("release_grab", ("operator movie", module.RADARR_IMPORT_CATEGORY)),
        ("resume_if_paused", "fedcba9876543210fedcba9876543210"),
        ("stop_cancel", "fedcba9876543210fedcba9876543210"),
    ]


def test_radarr_movie_download_e2e_local_synthetic_fixture_skips_arr_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_radarr_sonarr_module()

    monkeypatch.setattr(
        module,
        "ensure_radarr_movie",
        lambda *_args, **_kwargs: {
            "id": 77,
            "created": False,
            "updated": True,
            "root_folder": {"path": str(tmp_path)},
            "movie": {"path": str(tmp_path / "Movie Title (2026)")},
        },
    )
    monkeypatch.setattr(module, "arr_health_rows", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        module,
        "grab_first_arr_release_or_fallback_to_prowlarr",
        lambda **kwargs: {
            "source": "arr_release_search",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "category_transfer": {"categoryName": kwargs["download_category"]},
        },
    )
    monkeypatch.setattr(module, "resume_transfer_if_paused", lambda *_args, **_kwargs: {"resumed": False})
    monkeypatch.setattr(
        module,
        "wait_for_transfer_completion",
        lambda *_args, **_kwargs: {"completed": True, "name": "fixture.mkv"},
    )
    monkeypatch.setattr(
        module,
        "trigger_arr_downloaded_scan",
        lambda *_args, **_kwargs: pytest.fail("downloaded scan should be skipped"),
    )
    monkeypatch.setattr(
        module,
        "wait_for_radarr_import",
        lambda *_args, **_kwargs: pytest.fail("Arr import should be skipped"),
    )

    report, cleanup_movie_id = module.run_radarr_movie_download_e2e(
        radarr_url="http://radarr.test",
        radarr_api_key="key",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        indexer_id=40,
        indexer_name="eMuleBB Local",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        category_save_path=tmp_path / module.RADARR_IMPORT_CATEGORY,
        movie_root_creates_local_path=True,
        quality_profile_name="AnyAnyLang",
        release_search_timeout_seconds=10.0,
        timeout_seconds=10.0,
        skip_arr_import=True,
    )

    assert cleanup_movie_id == 77
    assert report["completed_transfer"]["completed"] is True
    assert report["downloaded_scan"] == {"skipped": True, "reason": "synthetic-local-ed2k-fixture"}
    assert report["arr_import"] == {"skipped": True, "reason": "synthetic-local-ed2k-fixture"}


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
                "message": "Indexers unavailable due to failures: eMuleBB Local (Prowlarr)",
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
            "source": "prowlarr_eMule_indexer_qbit_add",
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
        "trigger_arr_downloaded_scan",
        lambda *_args, **_kwargs: calls.append(("downloaded_scan", (_args[2], str(_args[3]))))
        or {"name": "DownloadedMoviesScan", "path_present": True},
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
        indexer_name="eMuleBB Local (Prowlarr)",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        category_save_path=tmp_path / module.RADARR_IMPORT_CATEGORY,
        movie_root_creates_local_path=True,
        quality_profile_name="AnyAnyLang",
        release_search_timeout_seconds=10.0,
        timeout_seconds=10.0,
    )

    assert cleanup_movie_id == 77
    assert report["indexer_health"]["unavailable_due_to_failures"] is True
    assert report["release_grab"]["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert report["category_transfer"]["categoryName"] == module.RADARR_IMPORT_CATEGORY
    assert calls == [
        ("prowlarr_source_grab", ("operator movie", module.TORZNAB_MOVIE_CATEGORY, module.RADARR_IMPORT_CATEGORY)),
        ("resume_if_paused", "fedcba9876543210fedcba9876543210"),
        ("transfer_complete", "fedcba9876543210fedcba9876543210"),
        ("downloaded_scan", ("radarr", str(tmp_path / module.RADARR_IMPORT_CATEGORY))),
        ("radarr_import", 77),
    ]


def test_radarr_movie_download_e2e_uses_manual_import_when_downloaded_scan_stalls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []
    import_attempts = 0
    category_path = tmp_path / module.RADARR_IMPORT_CATEGORY
    category_path.mkdir()
    completed = category_path / "Operator Movie.mkv"
    completed.write_text("video", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "ensure_radarr_movie",
        lambda *_args, **_kwargs: {"id": 77, "created": True, "root_folder": {"path": str(tmp_path)}},
    )
    monkeypatch.setattr(module, "arr_health_rows", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: {
            "source": "arr_release_search",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "grab_status": 200,
        },
    )
    monkeypatch.setattr(
        module,
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: {"hash": "fedcba9876543210fedcba9876543210", "categoryName": kwargs["category"]},
    )
    monkeypatch.setattr(
        module,
        "resume_transfer_if_paused",
        lambda *_args, **_kwargs: calls.append(("resume_if_paused", _args[2])) or {"resumed": False},
    )
    monkeypatch.setattr(
        module,
        "wait_for_transfer_completion",
        lambda *_args, **_kwargs: calls.append(("transfer_complete", _args[2]))
        or {"hash": _args[2], "last_seen": {"name": completed.name}},
    )
    monkeypatch.setattr(
        module,
        "trigger_arr_downloaded_scan",
        lambda *_args, **_kwargs: calls.append(("downloaded_scan", str(_args[3]))) or {"name": "DownloadedMoviesScan"},
    )

    def fake_wait_for_radarr_import(*_args, **_kwargs):
        nonlocal import_attempts
        import_attempts += 1
        calls.append(("radarr_import", import_attempts))
        if import_attempts == 1:
            raise RuntimeError("Radarr did not import movie before timeout. Last hasFile=False.")
        return {"movie_id": _args[2], "hasFile": True}

    monkeypatch.setattr(module, "wait_for_radarr_import", fake_wait_for_radarr_import)
    monkeypatch.setattr(
        module,
        "manual_import_radarr_movie",
        lambda *_args, **_kwargs: calls.append(("manual_import", str(_args[3]))) or {"candidate_count": 1, "status": 202},
    )

    report, cleanup_movie_id = module.run_radarr_movie_download_e2e(
        radarr_url="http://radarr.test",
        radarr_api_key="key",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        indexer_id=40,
        indexer_name="eMuleBB Local (Prowlarr)",
        prowlarr_indexer_id=50,
        movie_title="operator movie",
        movie_root=tmp_path,
        category_name=module.RADARR_IMPORT_CATEGORY,
        category_save_path=category_path,
        movie_root_creates_local_path=True,
        quality_profile_name="AnyAnyLang",
        release_search_timeout_seconds=10.0,
        timeout_seconds=10.0,
    )

    assert cleanup_movie_id == 77
    assert report["manual_import"] == {"candidate_count": 1, "status": 202}
    assert "downloaded_scan_import_error" in report
    assert report["arr_import"]["hasFile"] is True
    assert calls == [
        ("resume_if_paused", "fedcba9876543210fedcba9876543210"),
        ("transfer_complete", "fedcba9876543210fedcba9876543210"),
        ("downloaded_scan", str(completed)),
        ("radarr_import", 1),
        ("manual_import", str(completed)),
        ("radarr_import", 2),
    ]


def test_prowlarr_fallback_adds_selected_magnet_through_qbit_category(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []
    magnet = "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000&dn=Operator.Movie.mkv&xl=42"

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module.prowlarr_live,
        "build_prowlarr_search_path",
        lambda title, category_id, indexer_id: f"/api/v1/search?query={title}&categories={category_id}&indexerIds={indexer_id}",
    )
    monkeypatch.setattr(
        module.prowlarr_live,
        "prowlarr_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "json": [
                {
                    "indexerId": 50,
                    "title": "Operator Movie 1080p",
                    "downloadUrl": magnet,
                    "guid": magnet,
                    "sources": 9,
                }
            ],
        },
    )
    monkeypatch.setattr(
        module.prowlarr_live,
        "select_grabbable_release",
        lambda rows, _indexer_id, _title: rows[0],
    )
    monkeypatch.setattr(
        module,
        "qbit_direct_add",
        lambda _base_url, _api_key, selected_magnet, category: calls.append(("qbit_add", (selected_magnet, category)))
        or {"add_status": 200, "hash": "fedcba9876543210fedcba9876543210"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: calls.append(("new_transfer", kwargs["category"]))
        or {"hash": "fedcba9876543210fedcba9876543210", "categoryName": kwargs["category"]},
    )

    result = module.grab_first_arr_release_via_prowlarr(
        kind="radarr",
        arr_url="http://radarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator movie",
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        download_category=module.RADARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
    )

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert result["grab_status"] == 200
    assert result["hash_present"] is True
    assert result["category_transfer"]["categoryName"] == module.RADARR_IMPORT_CATEGORY
    assert calls == [
        ("qbit_add", (magnet, module.RADARR_IMPORT_CATEGORY)),
        ("new_transfer", module.RADARR_IMPORT_CATEGORY),
    ]


def test_prowlarr_fallback_uses_direct_torznab_when_row_has_no_magnet(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []
    ed2k_link = "ed2k://|file|Operator.Series.S01E01.mkv|1400000000|fedcba9876543210fedcba9876543210|/"

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module.prowlarr_live,
        "build_prowlarr_search_path",
        lambda title, category_id, indexer_id: f"/api/v1/search?query={title}&categories={category_id}&indexerIds={indexer_id}",
    )
    monkeypatch.setattr(
        module.prowlarr_live,
        "prowlarr_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "json": [{"indexerId": 50, "title": "Operator Series S01E01 1080p", "guid": "ed2k:hash", "sources": 20}],
        },
    )
    monkeypatch.setattr(module.prowlarr_live, "select_grabbable_release", lambda rows, _indexer_id, _title: rows[0])

    def fake_http_request(_base_url, path, **_kwargs):
        assert path.startswith("/indexer/emulebb/api?t=search&cat=5000&q=")
        body = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Operator Series S01E01 1080p</title>
      <link>{ed2k_link}</link>
      <enclosure url="{ed2k_link}" length="1400000000" type="application/x-ed2k-link" />
      <torznab:attr name="size" value="1400000000" />
      <torznab:attr name="peers" value="20" />
    </item>
  </channel>
</rss>"""
        return {"status": 200, "body_text": body}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(
        module,
        "qbit_direct_add",
        lambda _base_url, _api_key, selected_magnet, category: calls.append(("qbit_add", (selected_magnet, category)))
        or {"add_status": 200, "hash": "fedcba9876543210fedcba9876543210"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: calls.append(("new_transfer", kwargs["category"]))
        or {"hash": "fedcba9876543210fedcba9876543210", "categoryName": kwargs["category"]},
    )

    result = module.grab_first_arr_release_via_prowlarr(
        kind="sonarr",
        arr_url="http://sonarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator series",
        category_id=module.TORZNAB_TV_CATEGORY,
        download_category=module.SONARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
    )

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert result["hash_present"] is True
    assert calls == [
        ("qbit_add", (ed2k_link, module.SONARR_IMPORT_CATEGORY)),
        ("new_transfer", module.SONARR_IMPORT_CATEGORY),
    ]


def test_prowlarr_fallback_uses_direct_torznab_when_indexer_is_quarantined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []
    ed2k_link = "ed2k://|file|Operator.Movie.mkv|1400000000|fedcba9876543210fedcba9876543210|/"

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module.prowlarr_live,
        "build_prowlarr_search_path",
        lambda title, category_id, indexer_id: f"/api/v1/search?query={title}&categories={category_id}&indexerIds={indexer_id}",
    )
    monkeypatch.setattr(
        module.prowlarr_live,
        "prowlarr_request",
        lambda *_args, **_kwargs: {
            "status": 429,
            "json": {"message": "Indexer is disabled due to recent failures."},
            "body_text": "Indexer is disabled due to recent failures.",
        },
    )

    def fake_http_request(_base_url, path, **_kwargs):
        assert path.startswith("/indexer/emulebb/api?t=search&cat=2000&q=")
        body = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Operator Movie 1080p</title>
      <link>{ed2k_link}</link>
      <enclosure url="{ed2k_link}" length="1400000000" type="application/x-ed2k-link" />
      <torznab:attr name="size" value="1400000000" />
      <torznab:attr name="peers" value="20" />
    </item>
  </channel>
</rss>"""
        return {"status": 200, "body_text": body}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(
        module,
        "qbit_direct_add",
        lambda _base_url, _api_key, selected_link, category: calls.append(("qbit_add", (selected_link, category)))
        or {"add_status": 200, "hash": "fedcba9876543210fedcba9876543210"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: calls.append(("new_transfer", kwargs["category"]))
        or {"hash": "fedcba9876543210fedcba9876543210", "categoryName": kwargs["category"]},
    )

    result = module.grab_first_arr_release_via_prowlarr(
        kind="radarr",
        arr_url="http://radarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator movie",
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        download_category=module.RADARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
    )

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert result["search_source"] == "direct_torznab_after_prowlarr_quarantine"
    assert result["hash_present"] is True
    assert calls == [
        ("qbit_add", (ed2k_link, module.RADARR_IMPORT_CATEGORY)),
        ("new_transfer", module.RADARR_IMPORT_CATEGORY),
    ]


def test_prowlarr_fallback_uses_direct_torznab_after_search_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []
    ed2k_link = "ed2k://|file|Operator.Movie.mkv|1400000000|fedcba9876543210fedcba9876543210|/"

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module.prowlarr_live,
        "build_prowlarr_search_path",
        lambda title, category_id, indexer_id: f"/api/v1/search?query={title}&categories={category_id}&indexerIds={indexer_id}",
    )
    monkeypatch.setattr(
        module.prowlarr_live,
        "prowlarr_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "json": {"message": "search failed"},
            "body_text": "search failed",
        },
    )

    def fake_http_request(_base_url, path, **_kwargs):
        assert path.startswith("/indexer/emulebb/api?t=search&cat=2000&q=")
        body = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Operator Movie 1080p</title>
      <link>{ed2k_link}</link>
      <enclosure url="{ed2k_link}" length="1400000000" type="application/x-ed2k-link" />
      <torznab:attr name="size" value="1400000000" />
      <torznab:attr name="peers" value="20" />
    </item>
  </channel>
</rss>"""
        return {"status": 200, "body_text": body}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(
        module,
        "qbit_direct_add",
        lambda _base_url, _api_key, selected_link, category: calls.append(("qbit_add", (selected_link, category)))
        or {"add_status": 200, "hash": "fedcba9876543210fedcba9876543210"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_new_transfer_category",
        lambda *_args, **kwargs: calls.append(("new_transfer", kwargs["category"]))
        or {"hash": "fedcba9876543210fedcba9876543210", "categoryName": kwargs["category"]},
    )

    result = module.grab_first_arr_release_via_prowlarr(
        kind="radarr",
        arr_url="http://radarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator movie",
        category_id=module.TORZNAB_MOVIE_CATEGORY,
        download_category=module.RADARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
    )

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert result["search_source"] == "direct_torznab_after_prowlarr_search_error"
    assert result["hash_present"] is True
    assert calls == [
        ("qbit_add", (ed2k_link, module.RADARR_IMPORT_CATEGORY)),
        ("new_transfer", module.RADARR_IMPORT_CATEGORY),
    ]


def test_direct_torznab_parser_preserves_namespaced_magnet_attr() -> None:
    module = load_radarr_sonarr_module()
    magnet = "magnet:?xt=urn:btih:fedcba9876543210fedcba987654321000000000&dn=Operator.Movie.mkv&xl=42"
    escaped_magnet = magnet.replace("&", "&amp;")
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Operator Movie 1080p</title>
      <guid>ed2k:opaque</guid>
      <enclosure length="1400000000" />
      <torznab:attr name="size" value="1400000000" />
      <torznab:attr name="sourceCount" value="14" />
      <torznab:attr name="magneturl" value="{escaped_magnet}" />
    </item>
  </channel>
</rss>"""

    rows = module.parse_direct_torznab_release_rows(body)

    assert rows[0]["magnetUrl"] == magnet
    assert rows[0]["sourceCount"] == 14
    assert module.get_release_download_link(rows[0]) == magnet


def test_direct_torznab_parser_preserves_native_ed2k_download_link() -> None:
    module = load_radarr_sonarr_module()
    ed2k_link = "ed2k://|file|Operator.Movie.mkv|1400000000|fedcba9876543210fedcba9876543210|/"
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:torznab="http://torznab.com/schemas/2015/feed">
  <channel>
    <item>
      <title>Operator Movie 1080p</title>
      <guid isPermaLink="false">ed2k:fedcba9876543210fedcba9876543210</guid>
      <link>{ed2k_link}</link>
      <enclosure url="{ed2k_link}" length="1400000000" type="application/x-ed2k-link" />
      <torznab:attr name="size" value="1400000000" />
      <torznab:attr name="peers" value="14" />
    </item>
  </channel>
</rss>"""

    rows = module.parse_direct_torznab_release_rows(body)

    assert rows[0]["downloadUrl"] == ed2k_link
    assert module.get_release_download_link(rows[0]) == ed2k_link
    assert module.hash_from_download_link(ed2k_link) == "fedcba9876543210fedcba9876543210"


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
        arr_indexer_name="eMuleBB Local",
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


def test_sonarr_release_grab_falls_back_to_prowlarr_when_healthy_arr_returns_no_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: calls.append(("direct_arr_search", _args[3]))
        or (_ for _ in ()).throw(RuntimeError("sonarr release search returned no eMuleBB rows before timeout.")),
    )

    def fake_prowlarr_source_grab(**kwargs):
        calls.append(("prowlarr_source_grab", (kwargs["kind"], kwargs["category_id"], kwargs["download_category"])))
        return {
            "source": "prowlarr_eMule_indexer_qbit_add",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "category_transfer": {"hash_present": True, "categoryName": module.SONARR_IMPORT_CATEGORY},
        }

    monkeypatch.setattr(module, "grab_first_arr_release_via_prowlarr", fake_prowlarr_source_grab)

    result = module.grab_first_arr_release_or_fallback_to_prowlarr(
        kind="sonarr",
        arr_url="http://sonarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator series",
        media_id=77,
        category_id=module.TORZNAB_TV_CATEGORY,
        download_category=module.SONARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
        health_rows=[],
    )

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert result["arr_indexer_unavailable_due_to_failures"] is False
    assert calls == [
        ("direct_arr_search", "operator series"),
        ("prowlarr_source_grab", ("sonarr", module.TORZNAB_TV_CATEGORY, module.SONARR_IMPORT_CATEGORY)),
    ]


def test_radarr_release_grab_falls_back_to_prowlarr_when_healthy_arr_returns_no_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: calls.append(("direct_arr_search", _args[3]))
        or (_ for _ in ()).throw(RuntimeError("radarr release search returned no eMuleBB rows before timeout.")),
    )

    def fake_prowlarr_source_grab(**kwargs):
        calls.append(("prowlarr_source_grab", (kwargs["kind"], kwargs["category_id"], kwargs["download_category"])))
        return {
            "source": "prowlarr_eMule_indexer_qbit_add",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "category_transfer": {"hash_present": True, "categoryName": module.RADARR_IMPORT_CATEGORY},
        }

    monkeypatch.setattr(module, "grab_first_arr_release_via_prowlarr", fake_prowlarr_source_grab)

    result = module.grab_first_arr_release_or_fallback_to_prowlarr(
        kind="radarr",
        arr_url="http://radarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
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

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert result["arr_indexer_unavailable_due_to_failures"] is False
    assert "radarr release search returned no eMuleBB rows" in result["arr_direct_search_error"]
    assert calls == [
        ("direct_arr_search", "operator movie"),
        ("prowlarr_source_grab", ("radarr", module.TORZNAB_MOVIE_CATEGORY, module.RADARR_IMPORT_CATEGORY)),
    ]


def test_sonarr_release_grab_falls_back_when_arr_rows_fail_episode_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: {"oldhash"})
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: calls.append(("direct_arr_search", _args[3]))
        or (_ for _ in ()).throw(RuntimeError("Arr release selection found no release with at least 1 sources.")),
    )

    def fake_prowlarr_source_grab(**kwargs):
        calls.append(("prowlarr_source_grab", (kwargs["kind"], kwargs["category_id"], kwargs["download_category"])))
        return {
            "source": "prowlarr_eMule_indexer_qbit_add",
            "hash": "fedcba9876543210fedcba9876543210",
            "hash_present": True,
            "category_transfer": {"hash_present": True, "categoryName": module.SONARR_IMPORT_CATEGORY},
        }

    monkeypatch.setattr(module, "grab_first_arr_release_via_prowlarr", fake_prowlarr_source_grab)

    result = module.grab_first_arr_release_or_fallback_to_prowlarr(
        kind="sonarr",
        arr_url="http://sonarr.test",
        arr_api_key="key",
        arr_indexer_id=40,
        arr_indexer_name="eMuleBB Local",
        prowlarr_url="http://prowlarr.test",
        prowlarr_api_key="prowlarr-key",
        prowlarr_indexer_id=50,
        emule_base_url="http://127.0.0.1:1",
        emule_api_key="emule-key",
        title="operator series",
        media_id=77,
        category_id=module.TORZNAB_TV_CATEGORY,
        download_category=module.SONARR_IMPORT_CATEGORY,
        timeout_seconds=10.0,
        health_rows=[],
    )

    assert result["source"] == "prowlarr_eMule_indexer_qbit_add"
    assert calls == [
        ("direct_arr_search", "operator series"),
        ("prowlarr_source_grab", ("sonarr", module.TORZNAB_TV_CATEGORY, module.SONARR_IMPORT_CATEGORY)),
    ]


def test_transfer_completion_accepts_completed_handoff_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    transfer_hash = "fedcba9876543210fedcba9876543210"
    calls = 0

    def fake_wait_for_transfer(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"hash": transfer_hash, "state": "downloading"}
        raise RuntimeError("Added qBit transfer did not appear before timeout.")

    monkeypatch.setattr(module, "wait_for_transfer", fake_wait_for_transfer)
    monkeypatch.setattr(module.time, "sleep", lambda *_args, **_kwargs: None)

    result = module.wait_for_transfer_completion("http://emule.test", "key", transfer_hash, 30.0)

    assert result["completed"] is True
    assert result["state"] == "absent_after_seen"
    assert result["last_seen"] == {"hash": transfer_hash, "state": "downloading"}
    assert calls == 2


def test_completed_category_import_path_prefers_completed_file(tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    category = tmp_path / "sonarr_series_cat"
    category.mkdir()
    completed = category / "Operator Series S01E01.mkv"
    completed.write_text("video", encoding="utf-8")

    result = module.completed_category_import_path(
        category,
        {"last_seen": {"name": completed.name}},
        {"name": "ignored.mkv"},
    )

    assert result == completed


def test_arr_release_grab_does_not_fallback_when_arr_indexer_is_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_radarr_sonarr_module()
    calls: list[str] = []

    monkeypatch.setattr(module, "transfer_hashes", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(
        module,
        "grab_first_arr_release",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("manual search failed")),
    )
    monkeypatch.setattr(
        module,
        "grab_first_arr_release_via_prowlarr",
        lambda **_kwargs: calls.append("fallback") or {},
    )

    with pytest.raises(RuntimeError, match="manual Arr release acquisition failed"):
        module.grab_first_arr_release_or_fallback_to_prowlarr(
            kind="radarr",
            arr_url="http://radarr.test",
            arr_api_key="key",
            arr_indexer_id=40,
            arr_indexer_name="eMuleBB Local",
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

    assert calls == []


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


def test_handoff_stop_and_cancel_uses_qbit_stop_then_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        module,
        "qbit_login",
        lambda *_args, **_kwargs: ("SID=abc", {"status": 200}),
    )

    def fake_qbit_request(_base_url, path, **kwargs):
        calls.append((path, kwargs.get("form")))
        return {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)
    monkeypatch.setattr(
        module,
        "wait_for_transfer",
        lambda *_args, **_kwargs: {"hash": _args[2], "state": "stopped"},
    )
    monkeypatch.setattr(
        module,
        "wait_for_transfer_absent",
        lambda *_args, **_kwargs: {"hash": _args[2], "absent": True},
    )
    monkeypatch.setattr(module, "delete_transfer", lambda *_args, **_kwargs: pytest.fail("native cleanup should not run"))

    report = module.stop_and_cancel_handoff_transfer(
        "https://127.0.0.1:61921",
        "emule-key",
        "fedcba9876543210fedcba9876543210",
        60.0,
    )

    assert report["login_status"] == 200
    assert report["stop_status"] == 200
    assert report["cancel_status"] == 200
    assert report["deleted_transfer"] == {"hash": "fedcba9876543210fedcba9876543210", "absent": True}
    assert calls == [
        ("/api/v2/torrents/stop", {"hashes": "fedcba9876543210fedcba9876543210"}),
        ("/api/v2/torrents/delete", {"hashes": "fedcba9876543210fedcba9876543210", "deleteFiles": "true"}),
    ]


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


def arr_qbit_schema(category_field: str = "movieCategory", *, certificate_validation: bool = False) -> dict[str, object]:
    fields = [
        {"name": "host"},
        {"name": "port"},
        {"name": "useSsl"},
        {"name": "urlBase"},
        {"name": "username"},
        {"name": "password"},
        {"name": "initialState"},
        {"name": category_field},
    ]
    if certificate_validation:
        fields.append({"name": "certificateValidation", "value": 0})
    return {
        "implementation": "QBittorrent",
        "implementationName": "qBittorrent",
        "protocol": "torrent",
        "configContract": "QBittorrentSettings",
        "fields": fields,
    }


def provider_field_value(provider: dict[str, object], field_name: str) -> object:
    fields = provider.get("fields")
    assert isinstance(fields, list)
    for field in fields:
        assert isinstance(field, dict)
        if field.get("name") == field_name:
            return field.get("value")
    raise AssertionError(f"Missing field {field_name}")


def test_qbit_client_payload_starts_media_downloads() -> None:
    module = load_radarr_sonarr_module()

    payload = module.build_qbit_client_payload(
        arr_qbit_schema(),
        name="eMuleBB Live radarr 4711",
        host="127.0.0.1",
        port=4711,
        api_key="emule-key",
        category_field="movieCategory",
        category="radarr_movies_cat",
    )

    assert provider_field_value(payload, "initialState") == 0
    assert provider_field_value(payload, "movieCategory") == "radarr_movies_cat"
    assert provider_field_value(payload, "useSsl") is False
    assert payload["_emulebbCertificatePolicy"] == {"certificateValidation": False}


def test_qbit_client_payload_covers_http_and_https_transport() -> None:
    module = load_radarr_sonarr_module()

    http_payload = module.build_qbit_client_payload(
        arr_qbit_schema(certificate_validation=True),
        name="eMuleBB Live radarr HTTP",
        host="127.0.0.1",
        port=61920,
        api_key="emule-key",
        category_field="movieCategory",
        category="radarr_movies_cat",
        use_ssl=False,
    )
    https_payload = module.build_qbit_client_payload(
        arr_qbit_schema(certificate_validation=True),
        name="eMuleBB Live radarr HTTPS",
        host="127.0.0.1",
        port=61921,
        api_key="emule-key",
        category_field="movieCategory",
        category="radarr_movies_cat",
        use_ssl=True,
    )

    assert provider_field_value(http_payload, "useSsl") is False
    assert provider_field_value(http_payload, "certificateValidation") == 0
    assert http_payload["_emulebbCertificatePolicy"] == {"certificateValidation": False}
    assert provider_field_value(https_payload, "useSsl") is True
    assert provider_field_value(https_payload, "certificateValidation") == 1
    assert https_payload["_emulebbCertificatePolicy"] == {
        "certificateValidation": True,
        "arrHostConfig": module.ARR_LOCAL_CERTIFICATE_VALIDATION,
    }


def test_qbit_client_payload_uses_host_certificate_policy_when_provider_field_is_missing() -> None:
    module = load_radarr_sonarr_module()

    payload = module.build_qbit_client_payload(
        arr_qbit_schema(),
        name="eMuleBB Live radarr HTTPS",
        host="127.0.0.1",
        port=61921,
        api_key="emule-key",
        category_field="movieCategory",
        category="radarr_movies_cat",
        use_ssl=True,
    )

    assert payload["_emulebbCertificatePolicy"] == {
        "certificateValidation": False,
        "arrHostConfig": module.ARR_LOCAL_CERTIFICATE_VALIDATION,
    }


def test_set_arr_local_certificate_validation_updates_host_config(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, str, object]] = []

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path, kwargs.get("json_body")))
        if path == "/api/v3/config/host" and method == "GET":
            return {"status": 200, "json": {"id": 1, "certificateValidation": "enabled"}, "body_text": "{}"}
        if path == "/api/v3/config/host" and method == "PUT":
            body = dict(kwargs["json_body"])
            return {"status": 202, "json": body, "body_text": "{}"}
        raise AssertionError(f"Unexpected Arr request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    result = module.set_arr_local_certificate_validation("http://radarr.test", "key")

    assert result == {
        "changed": True,
        "previous": "enabled",
        "current": module.ARR_LOCAL_CERTIFICATE_VALIDATION,
    }
    assert calls[1][2]["certificateValidation"] == module.ARR_LOCAL_CERTIFICATE_VALIDATION


def test_temp_qbit_client_is_deleted_when_validation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, str]] = []
    schema = arr_qbit_schema()

    monkeypatch.setattr(module, "get_qbit_schema", lambda _arr_url, _api_key: schema)
    monkeypatch.setattr(module, "wait_for_qbit_endpoint_ready", lambda *_args, **_kwargs: {"ready": True, "attempt_count": 1})

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path))
        if path == "/api/v3/downloadclient?forceSave=true":
            assert "_emulebbCertificatePolicy" not in kwargs["json_body"]
            return {"status": 201, "json": {"id": 77, "fields": []}, "body_text": "{}"}
        if path == "/api/v3/downloadclient/test":
            assert "_emulebbCertificatePolicy" not in kwargs["json_body"]
            return {"status": 400, "json": None, "body_text": "cannot connect"}
        if path == "/api/v3/downloadclient/77":
            return {"status": 200, "json": None, "body_text": ""}
        raise AssertionError(f"Unexpected Arr request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    with pytest.raises(RuntimeError, match="qBittorrent client test failed"):
        module.create_temp_qbit_client(
            "http://radarr.test",
            "key",
            name="eMuleBB Live radarr 4711",
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


def test_temp_qbit_client_retries_transient_https_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls: list[tuple[str, str]] = []
    schema = arr_qbit_schema(certificate_validation=True)

    monkeypatch.setattr(module, "get_qbit_schema", lambda _arr_url, _api_key: schema)
    monkeypatch.setattr(module, "wait_for_qbit_endpoint_ready", lambda *_args, **_kwargs: {"ready": True, "attempt_count": 1})
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path))
        if path == "/api/v3/config/host" and method == "GET":
            return {"status": 200, "json": {"id": 1, "certificateValidation": "enabled"}, "body_text": "{}"}
        if path == "/api/v3/config/host" and method == "PUT":
            return {"status": 202, "json": kwargs["json_body"], "body_text": "{}"}
        if path == "/api/v3/downloadclient?forceSave=true" and calls.count((method, path)) == 1:
            return {
                "status": 400,
                "json": None,
                "body_text": "Unable to connect to qBittorrent: The SSL connection could not be established.",
            }
        if path == "/api/v3/downloadclient?forceSave=true":
            return {"status": 201, "json": {"id": 77, "fields": []}, "body_text": "{}"}
        if path == "/api/v3/downloadclient/test":
            return {"status": 200, "json": {"ok": True}, "body_text": "{}"}
        raise AssertionError(f"Unexpected Arr request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    created = module.create_temp_qbit_client(
        "http://radarr.test",
        "key",
        name="eMuleBB Live radarr 4711",
        host="127.0.0.1",
        port=4711,
        emule_api_key="emule-key",
        category_field="movieCategory",
        category="RADARR_ENG",
        use_ssl=True,
    )

    assert created["id"] == 77
    assert created["_emulebbTestStatus"] == 200
    assert len(created["_emulebbTransientRetries"]) == 1
    assert calls.count(("POST", "/api/v3/downloadclient?forceSave=true")) == 2


def test_wait_for_qbit_endpoint_ready_retries_busy_web_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
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


def test_transfer_hashes_retries_busy_web_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls = 0

    def fake_http_request(_base_url, _path, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise module.urllib.error.URLError("Web Interface rejected connection because 1 accepted-client thread is already active")
        return {"status": 200, "json": [{"hash": "ABCDEF0123456789ABCDEF0123456789"}]}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_array", lambda result, status: result["json"] if result["status"] == status else [])
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    assert module.transfer_hashes("https://127.0.0.1:4711", "secret") == {"abcdef0123456789abcdef0123456789"}
    assert calls == 2


def test_arr_request_retries_transient_local_socket_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls = 0

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(_request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise module.urllib.error.URLError("An established connection was aborted by the software in your host machine")
        assert timeout == 30.0
        return FakeResponse()

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.arr_request("http://radarr.test", "key", "/api/v3/system/status")

    assert result["status"] == 200
    assert result["json"] == {"ok": True}
    assert len(result["_emulebbTransientRetries"]) == 1
    assert calls == 2


def test_arr_readiness_summaries_are_compact() -> None:
    module = load_radarr_sonarr_module()

    indexer = module.summarize_arr_indexer(
        {
            "id": 40,
            "name": "eMuleBB Local",
            "implementation": "Torznab",
            "enable": True,
            "protocol": "torrent",
            "priority": 25,
        }
    )
    client = module.summarize_arr_download_client(
        {
            "id": 50,
            "name": "eMuleBB Live radarr 4711",
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
        "name": "eMuleBB Local",
        "implementation": "Torznab",
        "enable": True,
        "enableRss": None,
        "enableAutomaticSearch": None,
        "enableInteractiveSearch": None,
        "protocol": "torrent",
        "priority": 25,
        "certificate_policy": None,
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


def test_ensure_radarr_movie_falls_back_when_default_quality_profile_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_radarr_sonarr_module()

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        if path == "/api/v3/rootfolder":
            if kwargs.get("method") == "POST":
                return {"status": 201, "json": {"id": 5, "path": kwargs["json_body"]["path"]}, "body_text": "{}"}
            return {"status": 200, "json": [], "body_text": "[]"}
        if path == "/api/v3/qualityprofile":
            return {"status": 200, "json": [{"id": 3, "name": "HD-1080p"}], "body_text": "[]"}
        if path == "/api/v3/movie":
            if kwargs.get("method") == "POST":
                payload = kwargs["json_body"]
                assert payload["qualityProfileId"] == 3
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

    assert summary["quality_profile"] == {
        "id": 3,
        "name": "HD-1080p",
        "preferred_name": "AnyAnyLang",
        "fallback_reason": "preferred profile 'AnyAnyLang' was not found",
    }


def test_ensure_radarr_movie_realigns_existing_movie_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    target_root = str(tmp_path.resolve())

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        if path == "/api/v3/rootfolder":
            return {"status": 200, "json": [{"id": 5, "path": target_root}], "body_text": "[]"}
        if path == "/api/v3/qualityprofile":
            return {"status": 200, "json": [{"id": 9, "name": "AnyAnyLang"}], "body_text": "[]"}
        if path == "/api/v3/movie":
            return {
                "status": 200,
                "json": [
                    {
                        "id": 42,
                        "title": "operator configured title",
                        "qualityProfileId": 3,
                        "rootFolderPath": r"C:\old\root",
                        "path": r"C:\old\root\Movie Folder",
                        "monitored": False,
                        "minimumAvailability": "announced",
                    }
                ],
                "body_text": "[]",
            }
        if path == "/api/v3/movie/42":
            assert kwargs["method"] == "PUT"
            payload = kwargs["json_body"]
            assert payload["qualityProfileId"] == 9
            assert payload["rootFolderPath"] == target_root
            assert Path(payload["path"]) == tmp_path.resolve() / "Movie Folder"
            assert payload["monitored"] is True
            assert payload["minimumAvailability"] == "released"
            return {"status": 202, "json": payload, "body_text": "{}"}
        raise AssertionError(f"Unexpected Radarr request: {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    summary = module.ensure_radarr_movie(
        "http://radarr.test",
        "key",
        "operator configured title",
        tmp_path,
        quality_profile_name="AnyAnyLang",
    )

    assert summary["id"] == 42
    assert summary["created"] is False
    assert summary["updated"] is True
    assert summary["movie"]["rootFolderPath"] == target_root


def test_ensure_sonarr_series_realigns_existing_series_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_radarr_sonarr_module()
    target_root = str(tmp_path.resolve())

    def fake_arr_request(_arr_url, _api_key, path, **kwargs):
        if path == "/api/v3/rootfolder":
            return {"status": 200, "json": [{"id": 6, "path": target_root}], "body_text": "[]"}
        if path == "/api/v3/qualityprofile":
            return {"status": 200, "json": [{"id": 11, "name": "AnyAnyLang"}], "body_text": "[]"}
        if path == "/api/v3/series":
            return {
                "status": 200,
                "json": [
                    {
                        "id": 77,
                        "title": "operator configured series",
                        "qualityProfileId": 2,
                        "rootFolderPath": r"C:\old\series",
                        "path": r"C:\old\series\Series Folder",
                        "monitored": False,
                        "seasonFolder": False,
                    }
                ],
                "body_text": "[]",
            }
        if path == "/api/v3/series/77":
            assert kwargs["method"] == "PUT"
            payload = kwargs["json_body"]
            assert payload["qualityProfileId"] == 11
            assert payload["rootFolderPath"] == target_root
            assert Path(payload["path"]) == tmp_path.resolve() / "Series Folder"
            assert payload["monitored"] is True
            assert payload["seasonFolder"] is True
            return {"status": 202, "json": payload, "body_text": "{}"}
        raise AssertionError(f"Unexpected Sonarr request: {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    summary = module.ensure_sonarr_series(
        "http://sonarr.test",
        "key",
        "operator configured series",
        tmp_path,
        quality_profile_name="AnyAnyLang",
    )

    assert summary["id"] == 77
    assert summary["created"] is False
    assert summary["updated"] is True
    assert summary["series"]["rootFolderPath"] == target_root


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
        {"id": 15, "name": "eMuleBB Local", "enable": False, "fields": []},
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
                        "name": "eMuleBB Local (Prowlarr)",
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
            assert json_body["name"] == "eMuleBB Local"
            assert json_body["enableRss"] is False
            assert json_body["enableAutomaticSearch"] is True
            assert json_body["enableInteractiveSearch"] is True
            assert json_body["fields"][0]["value"] == "http://prowlarr.test/40/"
            assert json_body["fields"][3]["value"] == [module.TORZNAB_MOVIE_CATEGORY]
            return {"status": 202, "json": {**json_body, "id": 14}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.ensure_arr_emule_indexer(
        arr_url="http://radarr.test",
        api_key="key",
        indexer_name="eMuleBB Local",
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
            assert json_body["enableRss"] is False
            assert json_body["enableAutomaticSearch"] is True
            assert json_body["enableInteractiveSearch"] is True
            assert json_body["fields"][0]["value"] == "http://prowlarr.test/40/"
            assert json_body["fields"][3]["value"] == [module.TORZNAB_TV_CATEGORY]
            return {"status": 201, "json": {**json_body, "id": 16}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.ensure_arr_emule_indexer(
        arr_url="http://sonarr.test",
        api_key="key",
        indexer_name="eMuleBB Local",
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
        enabled = bool(json_body and json_body.get("enableAutomaticSearch") and json_body.get("enableInteractiveSearch"))
        if enabled:
            assert json_body["enableRss"] is False
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
        indexer_name="eMuleBB Local",
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
                        "message": "Indexers unavailable due to failures: eMuleBB Local",
                    }
                ],
                "body_text": "[]",
            }
        if path == "/api/v3/indexer/15" and method == "DELETE":
            return {"status": 202, "json": None, "body_text": ""}
        if path == "/api/v3/indexer/schema" and method == "GET":
            return {"status": 200, "json": [schema], "body_text": "[]"}
        if path == "/api/v3/indexer?forceSave=true" and method == "POST":
            assert json_body["name"] == "eMuleBB Local"
            assert json_body["fields"][0]["value"] == "http://prowlarr.test/40/"
            assert json_body["fields"][3]["value"] == [module.TORZNAB_MOVIE_CATEGORY]
            return {"status": 201, "json": {**json_body, "id": 44}, "body_text": "{}"}
        raise AssertionError(f"Unexpected request: {method} {path}")

    monkeypatch.setattr(module, "arr_request", fake_arr_request)

    indexer, summary = module.recreate_arr_emule_indexer_if_unavailable(
        arr_url="http://radarr.test",
        api_key="key",
        indexer={"id": 15, "name": "eMuleBB Local"},
        indexer_name="eMuleBB Local",
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
        {"id": 15, "name": "eMuleBB Local", "tags": [3]},
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
            "enableRss": False,
            "enableAutomaticSearch": True,
            "enableInteractiveSearch": True,
        }
    )
    assert module.is_arr_indexer_enabled(
        {
            "enable": True,
            "enableRss": False,
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


def test_isolate_arr_indexer_search_force_refreshes_allowed_indexer(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    changes: list[tuple[int, bool]] = []

    monkeypatch.setattr(
        module,
        "list_arr_indexers",
        lambda *_args: [
            {"id": 22, "name": "eMuleBB Local", "enableAutomaticSearch": True, "enableInteractiveSearch": True},
            {"id": 30, "name": "Other", "enableAutomaticSearch": True, "enableInteractiveSearch": True},
        ],
    )
    monkeypatch.setattr(
        module,
        "set_arr_indexer_search_state",
        lambda _url, _key, indexer, enabled: changes.append((int(indexer["id"]), enabled))
        or {"id": int(indexer["id"]), "enabled": enabled, "status": 202},
    )

    snapshots, summary = module.isolate_arr_indexer_search("http://radarr.test", "key", 22)

    assert [row["id"] for row in snapshots] == [22, 30]
    assert changes == [(22, True), (30, False)]
    assert summary == [{"id": 22, "enabled": True, "status": 202}, {"id": 30, "enabled": False, "status": 202}]


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


def test_qbit_direct_add_accepts_native_ed2k_links(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    observed_form: dict[str, object] = {}
    ed2k_link = "ed2k://|file|Operator.Movie.mkv|1400000000|fedcba9876543210fedcba9876543210|/"

    def fake_qbit_request(_base_url, _path, **kwargs):
        observed_form.update(kwargs["form"])
        return {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)
    monkeypatch.setattr(module, "qbit_login", lambda _base_url, _api_key: ("opener", {"status": 200, "body_text": "Ok."}))

    result = module.qbit_direct_add(
        "http://127.0.0.1:4711",
        "secret",
        ed2k_link,
        module.RADARR_IMPORT_CATEGORY,
    )

    assert result["hash"] == "fedcba9876543210fedcba9876543210"
    assert observed_form["urls"] == ed2k_link


def test_qbit_direct_add_retries_transient_local_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_radarr_sonarr_module()
    calls = 0

    monkeypatch.setattr(module, "qbit_login", lambda _base_url, _api_key: ("opener", {"status": 200, "body_text": "Ok."}))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    def fake_qbit_request(_base_url, _path, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise module.urllib.error.URLError(
                "[WinError 10053] An established connection was aborted by the software in your host machine"
            )
        return {"status": 200, "body_text": "Ok."}

    monkeypatch.setattr(module, "qbit_request", fake_qbit_request)

    result = module.qbit_direct_add(
        "http://127.0.0.1:4711",
        "secret",
        module.SYNTHETIC_TRIGGER_MAGNET,
        module.RADARR_IMPORT_CATEGORY,
    )

    assert calls == 2
    assert result["hash"] == module.ed2k_hash_from_magnet(module.SYNTHETIC_TRIGGER_MAGNET)
    assert len(result["transient_errors"]) == 1


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
