from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "rest-cold-start-dump-stress.py"
    spec = importlib.util.spec_from_file_location("rest_cold_start_dump_stress_test_module", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_script_help_loads() -> None:
    module = load_script_module()
    parser = module.build_parser()
    help_text = parser.format_help()

    assert "--waves" in help_text
    assert "--enable-umdh" in help_text
    assert "--skip-dumps" in help_text


def test_wave_plan_mixes_methods_when_both_networks_are_ready() -> None:
    module = load_script_module()
    plan = module.build_wave_search_plan(
        wave_index=2,
        searches_per_wave=5,
        search_terms=("alpha", "beta", "gamma"),
        network_mode="both",
    )

    assert [row["method"] for row in plan] == ["server", "global", "kad", "automatic", "server"]
    assert [row["network"] for row in plan] == ["server", "server", "kad", "server", "server"]
    assert [row["query_index"] for row in plan] == [2, 0, 1, 2, 0]
    assert all("stress" not in str(row["query"]).lower() for row in plan)


def test_open_source_stress_terms_extend_operator_terms() -> None:
    module = load_script_module()
    terms = module.build_open_source_stress_terms(("linux", "custom oss term"))

    assert terms[0] == "linux"
    assert "custom oss term" in terms
    assert "libreoffice" in terms
    assert "gnu" in terms
    assert "python" in terms
    assert "rust" in terms
    assert len(terms) == len({term.lower() for term in terms})


def test_active_download_candidates_allow_archives_audio_and_video() -> None:
    module = load_script_module()

    base = {
        "hash": "0123456789abcdef0123456789abcdef",
        "sources": 3,
        "sizeBytes": 1024,
    }
    assert module.is_stress_download_candidate({**base, "name": "debian.zip", "fileType": "archive"}) is True
    assert module.is_stress_download_candidate({**base, "name": "public-domain.mp3", "fileType": "audio"}) is True
    assert module.is_stress_download_candidate({**base, "name": "creative-commons.mkv", "fileType": "video"}) is True
    assert module.is_stress_download_candidate({**base, "name": "installer.exe", "fileType": "program"}) is False


def test_stress_search_observation_waits_past_initial_zero(monkeypatch) -> None:
    module = load_script_module()
    payloads = [
        {"id": "101", "status": "complete", "results": []},
        {"id": "101", "status": "running", "results": []},
        {"id": "101", "status": "running", "results": [{"hash": "0" * 32}]},
    ]

    def fake_http_request(*args, **kwargs):
        return {"status": 200, "json": payloads.pop(0)}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, status: result["json"])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    result = module.wait_for_stress_search_observation(
        "http://127.0.0.1:1",
        "key",
        "101",
        timeout_seconds=10.0,
    )

    assert result["ok"] is True
    assert result["terminal"] == "results"
    assert result["maxResults"] == 1
    assert len(result["observations"]) == 3


def test_common_sentinel_terms_require_nonzero_results() -> None:
    module = load_script_module()

    assert module.search_requires_nonzero_results("linux") is True
    assert module.search_requires_nonzero_results("  Ubuntu  ") is True
    assert module.search_requires_nonzero_results("obscure fixture term") is False
    assert module.fallback_search_methods("server", "server") == ("global", "kad")
    assert module.fallback_search_methods("automatic", "kad") == ("global",)


def test_discover_diagnostic_tools_uses_path_first(monkeypatch) -> None:
    module = load_script_module()

    def fake_which(name: str):
        return rf"C:\tools\{name}" if name == "procdump64.exe" else None

    monkeypatch.setattr(module.shutil, "which", fake_which)
    monkeypatch.setattr(module, "candidate_tool_paths", lambda name: [])

    tools = module.discover_diagnostic_tools()

    assert tools["procdump"] == r"C:\tools\procdump64.exe"
    assert tools["cdb"] is None


def test_search_network_mode_reconnects_when_ready_probe_fails(monkeypatch) -> None:
    module = load_script_module()

    def fail_ready(*args, **kwargs):
        raise RuntimeError("not ready")

    def reconnect(*args, **kwargs):
        return {"selected_server": {"address": "127.0.0.1", "port": 4661}}

    monkeypatch.setattr(module.rest_smoke, "wait_for_requested_networks", fail_ready)
    monkeypatch.setattr(module.rest_smoke, "connect_to_live_server", reconnect)

    result = module.get_search_network_mode(
        base_url="http://127.0.0.1:1",
        api_key="key",
        server_rows=[{"address": "127.0.0.1", "port": 4661}],
        timeout_seconds=1.0,
    )

    assert result["ok"] is True
    assert result["mode"] == "server"
    assert result["source"] == "server_reconnect"


def test_umdh_gflags_commands_are_explicit(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    calls: list[list[str]] = []

    def fake_run(command, output_path, timeout_seconds, *, env=None):
        calls.append(command)
        return {"command": command, "output_path": str(output_path), "return_code": 0, "timed_out": False}

    monkeypatch.setattr(module, "run_tool_to_file", fake_run)

    module.set_umdh_stack_tracing("gflags.exe", tmp_path / "emule.exe", True, tmp_path / "enable.txt", 1.0)
    module.set_umdh_stack_tracing("gflags.exe", tmp_path / "emule.exe", False, tmp_path / "disable.txt", 1.0)

    assert calls == [
        ["gflags.exe", "/i", "emule.exe", "+ust"],
        ["gflags.exe", "/i", "emule.exe", "-ust"],
    ]


def test_diagnostics_completeness_requires_all_default_dumps() -> None:
    module = load_script_module()
    report = {
        "diagnostics": {
            label: {
                "tools": {
                    "dump_analysis": {
                        "dump": {"dump_exists": True},
                    }
                }
            }
            for label in module.DIAGNOSTIC_LABELS
        }
    }

    assert module.diagnostics_are_complete(report, skip_dumps=False) is True
    report["diagnostics"]["peak"]["tools"]["dump_analysis"]["dump"]["dump_exists"] = False
    assert module.diagnostics_are_complete(report, skip_dumps=False) is False
    assert module.diagnostics_are_complete({}, skip_dumps=True) is True


def test_umdh_completeness_requires_snapshots_and_finished_diffs() -> None:
    module = load_script_module()
    report = {
        "diagnostics": {
            label: {
                "tools": {
                    "umdh": {
                        "timed_out": False,
                        "snapshot_exists": True,
                    }
                }
            }
            for label in module.DIAGNOSTIC_LABELS
        }
    }
    report["diagnostics"]["umdh_diffs"] = {
        "baseline_to_peak": {"timed_out": False, "return_code": 0},
        "baseline_to_post_drain": {"timed_out": False, "return_code": 0},
    }

    assert module.umdh_diagnostics_are_complete(report) is True
    report["diagnostics"]["umdh_diffs"]["baseline_to_post_drain"]["timed_out"] = True
    assert module.umdh_diagnostics_are_complete(report) is False


def test_collect_zero_result_searches_flags_observed_empty_results() -> None:
    module = load_script_module()
    stress = {
        "waves": [
            {
                "searches": [
                    {
                        "wave": 1,
                        "ordinal": 1,
                        "searchId": "101",
                        "method": "server",
                        "network": "server",
                        "must_return_results": True,
                        "activity": {"maxResults": 0, "terminal": "timeout_zero_results"},
                    },
                    {
                        "wave": 1,
                        "ordinal": 2,
                        "searchId": "102",
                        "method": "kad",
                        "network": "kad",
                        "must_return_results": False,
                        "activity": {"maxResults": 4, "terminal": "results"},
                    },
                ]
            }
        ]
    }

    assert module.collect_zero_result_searches(stress) == [
        {
            "wave": 1,
            "ordinal": 1,
            "searchId": "101",
            "method": "server",
            "network": "server",
            "terminal": "timeout_zero_results",
            "must_return_results": True,
        }
    ]
    assert module.collect_zero_result_searches(stress, required_only=True)[0]["searchId"] == "101"

    stress["waves"][0]["searches"][0]["fallback"] = {"recovered": True}
    assert module.collect_zero_result_searches(stress) == []

    stress["waves"][0]["searches"][0]["fallback"] = {"recovered": False}
    stress["waves"][0]["searches"][0]["must_return_results"] = False
    assert module.collect_zero_result_searches(stress, required_only=True) == []


def test_validate_rejects_invalid_stress_shape() -> None:
    module = load_script_module()
    args = SimpleNamespace(
        waves=0,
        searches_per_wave=1,
        max_concurrent_searches=1,
        downloads_per_wave=0,
        post_drain_seconds=0,
        tool_timeout_seconds=1,
    )

    try:
        module.validate_args(args)
    except ValueError as exc:
        assert "waves" in str(exc)
    else:
        raise AssertionError("expected invalid waves to be rejected")
