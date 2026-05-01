from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_auto_browse_module():
    """Loads the hyphenated auto-browse script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "auto-browse-live.py"
    spec = importlib.util.spec_from_file_location("auto_browse_live_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["auto_browse_live_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_transfer_acquisition_plan_covers_bootstrap_and_public_queries() -> None:
    module = load_auto_browse_module()

    plan = module.build_transfer_acquisition_plan()
    direct_plan = module.build_direct_bootstrap_transfer_plan()

    assert module.LIVE_WIRE_SEARCH_QUERIES == ("linux", "ubuntu", "fedora", "freebsd", "debian", "emule")
    assert plan[0] == (module.BOOTSTRAP_TRANSFER_HASH, list(module.BOOTSTRAP_SEARCH_METHODS))
    assert [query for query, _methods in plan[1:]] == list(module.FALLBACK_SEARCH_QUERIES)
    assert all("server" in methods and "kad" in methods for _query, methods in plan)
    assert direct_plan[0]["name"].endswith(".iso")
    assert module.is_safe_download_result(direct_plan[0])
    assert module.LIVE_SOURCE_UNAVAILABLE_EXIT_CODE == 2
    assert module.DEFAULT_NATURAL_AUTO_BROWSE_TIMEOUT_SECONDS < module.DEFAULT_FALLBACK_AUTO_BROWSE_TIMEOUT_SECONDS


def test_transfer_search_uses_file_oriented_iso_filter(monkeypatch) -> None:
    module = load_auto_browse_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"search_id": "123"},
            "body_text": "{}",
        }

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.start_transfer_search("http://127.0.0.1:1", "key", "server", "ubuntu")

    assert result["ok"]
    assert requests[0]["path"] == "/api/v1/searches"
    assert requests[0]["json_body"] == {
        "query": "ubuntu",
        "method": "server",
        "type": "iso",
        "ext": "iso",
    }


def test_transfer_search_result_wait_keeps_polling_running_empty_searches(monkeypatch) -> None:
    module = load_auto_browse_module()
    responses = iter(
        [
            {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": {"status": "running", "results": []},
                "body_text": "{}",
            },
            {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": {"status": "running", "results": []},
                "body_text": "{}",
            },
            {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": {"status": "running", "results": [{"name": "ubuntu.iso"}]},
                "body_text": "{}",
            },
        ]
    )

    monkeypatch.setattr(module.rest_smoke, "http_request", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.wait_for_transfer_search_results("http://127.0.0.1:1", "key", "123", 30.0)

    assert result["terminal_state"] == "running"
    assert [observation["result_count"] for observation in result["observations"]] == [0, 0, 1]


def test_selected_transfer_source_summary_is_compact() -> None:
    module = load_auto_browse_module()
    sources = [
        {"userHash": "a"},
        {"userHash": "b"},
        {"userHash": "c"},
        {"userHash": "d"},
        {"userHash": "e"},
        {"userHash": "f"},
    ]

    summary = module.summarize_selected_transfer_sources(
        [
            {"query": "ubuntu", "error": {"type": "RuntimeError"}},
            {
                "selected": {
                    "query": "linux",
                    "method": "automatic",
                    "search_id": "6",
                    "result": {
                        "hash": "b05c1075089e1de58a13de1b77ba4b2a",
                        "name": "linux.tar.gz",
                        "size": 68082727,
                    },
                    "sources_ready": {
                        "sources": sources
                    },
                }
            },
        ]
    )

    assert summary["query"] == "linux"
    assert summary["method"] == "automatic"
    assert summary["source_count"] == 6
    assert len(summary["sources"]) == 5
    assert summary["hash"] == "b05c1075089e1de58a13de1b77ba4b2a"


def test_selected_transfer_sources_returns_full_source_list() -> None:
    module = load_auto_browse_module()
    sources = [{"userHash": "a"}, {"userHash": "b"}, {"userHash": "c"}, {"userHash": "d"}, {"userHash": "e"}, {"userHash": "f"}]

    selected_sources = module.get_selected_transfer_sources([{"selected": {"sources_ready": {"sources": sources}}}])

    assert selected_sources == sources


def test_source_browse_probe_refreshes_selected_transfer_sources(monkeypatch) -> None:
    module = load_auto_browse_module()
    transfer_hash = "b05c1075089e1de58a13de1b77ba4b2a"
    original_source = {
        "userHash": "a" * 32,
        "ip": "1.2.3.4",
        "port": 4662,
        "viewSharedFiles": True,
    }
    refreshed_source = {
        "userHash": "b" * 32,
        "ip": "5.6.7.8",
        "port": 4662,
        "viewSharedFiles": True,
    }
    observed_sources: list[object] = []

    monkeypatch.setattr(
        module,
        "wait_for_source_browse_candidates",
        lambda *_args, **_kwargs: {"sources": [refreshed_source], "candidate_count": 1, "ready_candidate_count": 1},
    )

    def fake_wait_for_source_browse_success(_base_url, _api_key, _transfer_hash, sources, _timeout_seconds):
        observed_sources.extend(sources)
        return {"ok": True, "attempts": [{"selector": {"ip": "5.6.7.8", "port": 4662}}]}

    monkeypatch.setattr(module, "wait_for_source_browse_success", fake_wait_for_source_browse_success)

    result = module.probe_selected_transfer_source_browse(
        "http://127.0.0.1:1",
        "key",
        [
            {
                "selected": {
                    "query": "linux",
                    "method": "server",
                    "result": {
                        "hash": transfer_hash,
                        "name": "linux.iso",
                        "size": 1024,
                    },
                    "add_response": {"hash": transfer_hash},
                    "sources_ready": {"sources": [original_source]},
                }
            }
        ][0],
        30.0,
    )

    assert result["ok"] is True
    assert result["selected_transfer"]["hash"] == transfer_hash
    assert result["source_refresh"]["sources"] == [refreshed_source]
    assert result["source_refresh"]["ready_candidate_count"] == 1
    assert observed_sources == [refreshed_source, original_source]


def test_source_browse_candidates_prefer_reachable_emule_sources() -> None:
    module = load_auto_browse_module()

    candidates = module.iter_source_browse_candidates(
        [
            {"userHash": "0" * 32, "ip": "", "port": 0},
            {
                "userHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "ip": "",
                "port": 4662,
                "lowId": True,
                "clientSoftware": "",
            },
            {
                "userHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "ip": "1.2.3.4",
                "port": 4662,
                "lowId": False,
                "clientSoftware": "eMule v0.70b",
            },
            {
                "userHash": "cccccccccccccccccccccccccccccccc",
                "ip": "1.2.3.5",
                "port": 4662,
                "viewSharedFiles": False,
            },
        ]
    )

    assert len(candidates) == 2
    assert candidates[0]["selector"]["ip"] == "1.2.3.4"
    assert candidates[0]["selectors"] == [
        {"ip": "1.2.3.4", "port": 4662},
        {"userHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {"userHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ip": "1.2.3.4", "port": 4662},
    ]
    assert candidates[1]["selector"]["userHash"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_source_browse_candidate_wait_prefers_handshaken_sources(monkeypatch) -> None:
    module = load_auto_browse_module()
    responses = iter(
        [
            {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": [
                    {
                        "userHash": "a" * 32,
                        "ip": "1.2.3.4",
                        "port": 4662,
                        "downloadState": "Connecting",
                        "viewSharedFiles": True,
                    }
                ],
                "body_text": "{}",
            },
            {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": [
                    {
                        "userHash": "b" * 32,
                        "ip": "5.6.7.8",
                        "port": 4662,
                        "clientSoftware": "eMule v0.50a",
                        "downloadState": "OnQueue",
                        "viewSharedFiles": True,
                    }
                ],
                "body_text": "{}",
            },
        ]
    )

    monkeypatch.setattr(module.rest_smoke, "http_request", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.wait_for_source_browse_candidates("http://127.0.0.1:1", "key", "c" * 32, 30.0)

    assert result["candidate_count"] == 1
    assert result["ready_candidate_count"] == 1
    assert [observation["ready_candidate_count"] for observation in result["observations"]] == [0, 1]


def test_source_browse_success_tries_selector_variants(monkeypatch) -> None:
    module = load_auto_browse_module()
    attempted_selectors: list[dict[str, object]] = []

    def fake_request(_base_url, _api_key, _transfer_hash, selector):
        attempted_selectors.append(selector)
        if selector == {"userHash": "b" * 32}:
            return {"ok": True, "search_id": "42"}
        raise AssertionError("source not found")

    monkeypatch.setattr(module, "request_source_browse", fake_request)
    monkeypatch.setattr(
        module,
        "wait_for_source_browse_results",
        lambda *_args, **_kwargs: {"result_count": 1, "sample_results": [{"name": "share.bin"}]},
    )

    result = module.wait_for_source_browse_success(
        "http://127.0.0.1:1",
        "key",
        "a" * 32,
        [
            {
                "userHash": "b" * 32,
                "ip": "1.2.3.4",
                "port": 4662,
                "viewSharedFiles": True,
            }
        ],
        30.0,
    )

    assert result["ok"] is True
    assert attempted_selectors == [
        {"ip": "1.2.3.4", "port": 4662},
        {"userHash": "b" * 32},
    ]


def test_record_phase_writes_partial_report(tmp_path: Path, capsys) -> None:
    module = load_auto_browse_module()
    report: dict[str, object] = {"status": "failed"}

    module.record_phase(tmp_path, report, "network_ready")

    assert report["current_phase"] == "network_ready"
    assert report["phase_history"] and report["phase_history"][0]["phase"] == "network_ready"
    assert (tmp_path / "result.partial.json").is_file()
    assert "auto-browse-live phase: network_ready" in capsys.readouterr().out


def test_record_auto_browse_observation_keeps_recent_partial_state(tmp_path: Path) -> None:
    module = load_auto_browse_module()
    report: dict[str, object] = {"checks": {}}

    for index in range(25):
        module.record_auto_browse_observation(
            tmp_path,
            report,
            "natural_auto_browse_progress",
            {
                "observed_at": float(index),
                "auto_count": 0,
                "success_count": 0,
                "cache_files": [],
            },
        )

    progress = report["checks"]["natural_auto_browse_progress"]
    assert len(progress["observations"]) == 20
    assert progress["observations"][0]["observed_at"] == 5.0
    assert progress["last_observation"]["observed_at"] == 24.0
    assert (tmp_path / "result.partial.json").is_file()


def test_cleanup_error_only_promotes_passing_runs_to_failure() -> None:
    module = load_auto_browse_module()

    assert module.should_promote_cleanup_error("passed", None) is True
    assert module.should_promote_cleanup_error("inconclusive", None) is False
    assert module.should_promote_cleanup_error("failed", RuntimeError("primary failure")) is False


def test_wait_for_source_browse_results_tolerates_pending_search_tab(monkeypatch) -> None:
    module = load_auto_browse_module()
    calls = iter(
        [
            {
                "status": 404,
                "content_type": "application/json; charset=utf-8",
                "json": {"error": "NOT_FOUND", "message": "search not found"},
                "body_text": '{"error":"NOT_FOUND","message":"search not found"}',
            },
            {
                "status": 404,
                "content_type": "application/json; charset=utf-8",
                "json": {"error": "NOT_FOUND", "message": "search not found"},
                "body_text": '{"error":"NOT_FOUND","message":"search not found"}',
            },
            {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": {
                    "status": "complete",
                    "results": [{"name": "shared-file.txt", "hash": "a" * 32}],
                },
                "body_text": "{}",
            },
        ]
    )

    monkeypatch.setattr(module.rest_smoke, "http_request", lambda *_args, **_kwargs: next(calls))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.wait_for_source_browse_results(
        "http://127.0.0.1:1",
        "key",
        "2147483657",
        30.0,
    )

    assert result["result_count"] == 1
    assert [observation["state"] for observation in result["observations"]] == [
        "search_tab_pending",
        "search_tab_pending",
        "search_tab_ready",
    ]


def test_direct_bootstrap_transfer_candidate_uses_known_safe_link(monkeypatch) -> None:
    module = load_auto_browse_module()
    added_rows: list[dict[str, object]] = []

    def fake_add_transfer(_base_url, _api_key, result_row):
        added_rows.append(result_row)
        return {
            "hash": result_row["hash"],
            "name": result_row["name"],
        }

    monkeypatch.setattr(module, "add_transfer_from_search_result", fake_add_transfer)
    monkeypatch.setattr(
        module,
        "wait_for_transfer_sources",
        lambda *_args, **_kwargs: {
            "sources": [
                {
                    "userHash": "b" * 32,
                    "ip": "1.2.3.4",
                    "port": 4662,
                    "viewSharedFiles": True,
                }
            ]
        },
    )

    result = module.find_direct_bootstrap_transfer_candidate(
        "http://127.0.0.1:1",
        "key",
        source_discovery_timeout_seconds=1.0,
    )

    assert result["selected"]["method"] == "direct_ed2k"
    assert added_rows[0]["name"] == module.DIRECT_BOOTSTRAP_TRANSFERS[0]["name"]
    assert result["selected"]["sources_ready"]["sources"][0]["userHash"] == "b" * 32
