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
    assert "--max-post-drain-umdh-positive-bytes" in help_text
    assert "--cpu-profile" in help_text
    assert "--cpu-profile-max-file-mb" in help_text
    assert "--skip-dumps" in help_text
    assert "--downloads-per-search" in help_text
    assert "--target-completed-downloads" in help_text
    assert "--resource-monitor-interval-seconds" in help_text
    assert parser.get_default("max_post_drain_umdh_positive_bytes") == 16 * 1024 * 1024
    assert parser.get_default("cpu_profile_max_file_mb") == 512
    assert parser.get_default("cpu_profile_symbols_required") is True


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


def test_public_search_term_label_redacts_custom_terms() -> None:
    module = load_script_module()

    assert module.public_search_term_label("  Linux  ") == "linux"
    assert module.public_search_term_label("custom private term") == "<custom>"


def test_active_download_candidates_allow_archives_audio_and_block_video() -> None:
    module = load_script_module()

    base = {
        "hash": "0123456789abcdef0123456789abcdef",
        "sources": 3,
        "sizeBytes": 1024,
    }
    assert module.is_stress_download_candidate({**base, "name": "debian.zip", "fileType": "archive"}) is True
    assert module.is_stress_download_candidate({**base, "name": "public-domain.mp3", "fileType": "audio"}) is True
    assert module.is_stress_download_candidate({**base, "name": "creative-commons.mkv", "fileType": "video"}) is False
    assert module.is_stress_download_candidate({**base, "name": "public-domain.mp4", "fileType": ""}) is False
    assert module.is_stress_download_candidate({**base, "name": "installer.exe", "fileType": "program"}) is False


def test_download_trigger_summary_counts_file_types_and_video() -> None:
    module = load_script_module()
    report = {
        "waves": [
            {
                "searches": [
                    {
                        "download_trigger": {
                            "triggers": [
                                {"candidate": {"extension": ".pdf", "fileType": "Doc"}},
                                {"candidate": {"extension": ".mp3", "fileType": "Audio"}},
                                {"candidate": {"extension": ".mp4", "fileType": ""}},
                                {"candidate": {"extension": ".bin", "fileType": "Video"}},
                            ]
                        }
                    }
                ]
            }
        ]
    }

    summary = module.summarize_download_triggers(report)

    assert summary["total"] == 4
    assert summary["file_type_counts"] == {"audio": 1, "doc": 1, "video": 1}
    assert summary["extension_counts"] == {".bin": 1, ".mp3": 1, ".mp4": 1, ".pdf": 1}
    assert summary["video_download_trigger_count"] == 2


def test_download_candidates_are_ordered_by_size_then_sources() -> None:
    module = load_script_module()
    larger = {
        "hash": "b" * 32,
        "name": "larger.pdf",
        "fileType": "document",
        "sources": 9,
        "completeSources": 9,
        "sizeBytes": 1000,
    }
    smaller_low_sources = {
        "hash": "a" * 32,
        "name": "smaller-a.pdf",
        "fileType": "document",
        "sources": 2,
        "completeSources": 1,
        "sizeBytes": 100,
    }
    smaller_high_sources = {
        "hash": "c" * 32,
        "name": "smaller-c.pdf",
        "fileType": "document",
        "sources": 4,
        "completeSources": 3,
        "sizeBytes": 100,
    }

    ordered = module.find_stress_download_candidates(
        {"results": [larger, smaller_low_sources, smaller_high_sources]}
    )

    assert [row["hash"] for row in ordered] == ["c" * 32, "a" * 32, "b" * 32]


def test_download_trigger_respects_per_search_budget_and_dedupes(monkeypatch) -> None:
    module = load_script_module()
    hash_a = "0123456789abcdef0123456789abcdef"
    hash_b = "abcdef0123456789abcdef0123456789"
    search_payload = {
        "status": "running",
        "results": [
            {"hash": hash_a, "name": "small-a.pdf", "sizeBytes": 100, "sources": 3, "completeSources": 2},
            {"hash": hash_b, "name": "small-b.pdf", "sizeBytes": 200, "sources": 3, "completeSources": 2},
        ],
    }
    downloads: list[str] = []

    def fake_http_request(_base_url, path, **kwargs):
        if path == "/api/v1/searches/101":
            return {"status": 200, "json": search_payload}
        downloads.append(path)
        return {"status": 200, "json": {"ok": True}}

    def fake_wait_for(resolve, **_kwargs):
        return resolve()

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: result["json"])
    monkeypatch.setattr(module.rest_smoke, "wait_for", fake_wait_for)
    monkeypatch.setattr(
        module.rest_smoke,
        "wait_for_triggered_transfer",
        lambda _base_url, _api_key, transfer_hash, _timeout: {"json": {"hash": transfer_hash}},
    )

    coordinator = module.DownloadTriggerCoordinator()
    registry = module.StressTransferRegistry()
    first = module.trigger_active_downloads_from_search_result(
        "http://127.0.0.1:1",
        "key",
        "101",
        5.0,
        1,
        coordinator,
        registry,
        10,
    )
    second = module.trigger_active_downloads_from_search_result(
        "http://127.0.0.1:1",
        "key",
        "101",
        5.0,
        2,
        coordinator,
        registry,
        10,
    )

    assert len(first["triggers"]) == 1
    assert len(second["triggers"]) == 1
    assert downloads == [
        f"/api/v1/searches/101/results/{hash_a}/operations/download",
        f"/api/v1/searches/101/results/{hash_b}/operations/download",
    ]
    assert registry.counts()["triggered_stress_transfer_count"] == 2


def test_compute_cpu_percent_normalizes_by_logical_cpu_count() -> None:
    module = load_script_module()

    assert module.compute_cpu_percent(0, 20_000_000, 2.0, 4) == 25.0
    assert module.compute_cpu_percent(None, 20_000_000, 2.0, 4) is None
    assert module.compute_cpu_percent(0, 20_000_000, 0.0, 4) is None


def test_summarize_resource_monitor_samples_reports_cpu_and_threads() -> None:
    module = load_script_module()

    summary = module.summarize_resource_monitor_samples(
        [
            {"cpu_percent": None, "thread_count": 5, "handles": 10, "private_bytes": 100, "working_set_bytes": 200},
            {"cpu_percent": 10.0, "thread_count": 7, "handles": 15, "private_bytes": 300, "working_set_bytes": 400},
            {"cpu_percent": 30.0, "thread_count": 6, "handles": 12, "private_bytes": 250, "working_set_bytes": 350},
        ]
    )

    assert summary == {
        "sample_count": 3,
        "cpu_percent_avg": 20.0,
        "cpu_percent_p95": 30.0,
        "cpu_percent_max": 30.0,
        "thread_count_max": 7,
        "handles_max": 15,
        "private_bytes_max": 300,
        "working_set_bytes_max": 400,
    }


def test_access_violation_without_emule_dump_is_release_blocking() -> None:
    module = load_script_module()

    assert module.access_violation_without_emule_dump(
        {
            "failure_process_state": {"exit_code": 0xC0000005},
            "local_dump_files": {"files": []},
        }
    )
    assert not module.access_violation_without_emule_dump(
        {
            "failure_process_state": {"exit_code": 0xC0000005},
            "local_dump_files": {"files": [{"name": "emule.exe.1234.dmp"}]},
        }
    )


def test_diagnostic_tool_crashes_detects_umdh_access_violation() -> None:
    module = load_script_module()

    crashes = module.diagnostic_tool_crashes(
        {
            "diagnostics": {
                "post_drain": {
                    "tools": {
                        "umdh": {"return_code": 0xC0000005},
                        "handle": {"return_code": 0},
                    }
                }
            }
        }
    )

    assert crashes == [{"label": "post_drain", "tool": "umdh", "return_code": 0xC0000005}]


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
    assert module.search_requires_nonzero_results("fedora") is True
    assert module.search_requires_nonzero_results("obscure fixture term") is False
    assert module.fallback_search_methods("server", "server") == ("global", "kad", "server")
    assert module.fallback_search_methods("automatic", "kad") == ("server", "global", "kad")


def test_zero_result_search_summary_preserves_safe_diagnostics() -> None:
    module = load_script_module()
    report = {
        "waves": [
            {
                "searches": [
                    {
                        "activity": {
                            "last": {"status": "complete"},
                            "maxResults": 0,
                            "observations": [{}, {}],
                            "terminal": "timeout_zero_results",
                        },
                        "method": "server",
                        "must_return_results": True,
                        "network": "server",
                        "ordinal": 1,
                        "query_index": 0,
                        "query_label": "linux",
                        "searchId": "101",
                        "wave": 1,
                    }
                ]
            }
        ]
    }

    zeros = module.collect_zero_result_searches(report)

    assert zeros == [
        {
            "wave": 1,
            "ordinal": 1,
            "searchId": "101",
            "method": "server",
            "network": "server",
            "query_index": 0,
            "query_label": "linux",
            "terminal": "timeout_zero_results",
            "maxResults": 0,
            "observation_count": 2,
            "last_status": "complete",
            "must_return_results": True,
        }
    ]
    assert module.summarize_zero_result_searches(zeros) == {"linux": 1}


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
    report["diagnostics"]["umdh_diffs"]["baseline_to_peak"]["timed_out"] = True
    assert module.umdh_diagnostics_are_complete(report) is True
    report["diagnostics"]["umdh_diffs"]["baseline_to_post_drain"]["timed_out"] = True
    assert module.umdh_diagnostics_are_complete(report) is False


def test_cpu_profile_completeness_requires_etl_export_and_symbols() -> None:
    module = load_script_module()
    report = {
        "diagnostics": {
            "cpu_profile": {
                "enabled": True,
                "symbols": {"app_pdb_exists": True},
                "stop": {
                    "timed_out": False,
                    "return_code": 0,
                    "etl_exists": True,
                },
                "export": {
                    "timed_out": False,
                    "return_code": 0,
                    "detail_exists": True,
                },
            }
        }
    }

    assert module.cpu_profile_diagnostics_are_complete(report, symbols_required=True) is True
    report["diagnostics"]["cpu_profile"]["symbols"]["app_pdb_exists"] = False
    assert module.cpu_profile_diagnostics_are_complete(report, symbols_required=True) is False
    assert module.cpu_profile_diagnostics_are_complete(report, symbols_required=False) is True
    report["diagnostics"]["cpu_profile"]["stop"]["etl_exists"] = False
    assert module.cpu_profile_diagnostics_are_complete(report, symbols_required=False) is False


def test_initialize_cpu_profile_report_records_tools_paths_and_symbol_status(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    app_exe = tmp_path / "emule.exe"
    app_pdb = tmp_path / "emule.pdb"
    app_exe.write_bytes(b"exe")
    app_pdb.write_bytes(b"pdb")

    monkeypatch.setattr(
        module.cpu_profile,
        "discover_cpu_profile_tools",
        lambda: module.cpu_profile.CpuProfileTools(xperf="xperf.exe", wpaexporter="wpaexporter.exe"),
    )

    tools, paths, report = module.initialize_cpu_profile_report(app_exe=app_exe, artifacts_dir=tmp_path / "artifacts")

    assert tools.xperf == "xperf.exe"
    assert paths.summary_path.name == "cpu-profile-summary.json"
    assert report["enabled"] is True
    assert report["tools"]["xperf"] == "xperf.exe"
    assert report["symbols"]["app_pdb_path"] == str(app_pdb)
    assert report["symbols"]["app_pdb_exists"] is True


def test_parse_umdh_diff_text_extracts_top_positive_deltas() -> None:
    module = load_script_module()
    text = """
command: umdh -d before.txt after.txt
return_code: 0

+ 8,192 ( 12,288 - 4,096) 2 allocs BackTrace00001234
    ntdll!RtlpAllocateHeapInternal+A7D
    emule!operator new+30
    emule!CSearchResultsWnd::AddResult
    emule!CSearchList::AddToList
+ 512 ( 512 - 0) 1 allocs BackTrace00005678
    ntdll!RtlpAllocateHeapInternal+A7D
    emule!operator new+30
    emule!CUpDownClient::Create
- 128 ( 0 - 128) 1 allocs BackTrace00009999
    emule!ReleasedAllocation
"""

    summary = module.parse_umdh_diff_text(text, limit=1)

    assert summary["positive_delta_count"] == 2
    assert summary["positive_delta_bytes"] == 8704
    assert summary["top_positive_deltas"] == [
        {
            "delta_bytes": 8192,
            "after_bytes": 12288,
            "before_bytes": 4096,
            "allocation_count": 2,
            "trace_id": "BackTrace00001234",
            "stack": [
                "ntdll!RtlpAllocateHeapInternal+A7D",
                "emule!operator new+30",
                "emule!CSearchResultsWnd::AddResult",
                "emule!CSearchList::AddToList",
            ],
        }
    ]
    assert summary["top_positive_app_frames"] == [
        {
            "frame": "emule!CSearchResultsWnd::AddResult",
            "delta_bytes": 8192,
            "allocation_count": 2,
            "trace_count": 1,
        }
    ]


def test_summarize_umdh_app_frames_groups_allocator_stacks() -> None:
    module = load_script_module()
    entries = [
        {
            "allocation_count": 2,
            "delta_bytes": 1024,
            "stack": ["ntdll!RtlpAllocateHeapInternal+A7D", "emule!operator new+30", "emule!CPartFile::WriteToBuffer+235"],
        },
        {
            "allocation_count": 3,
            "delta_bytes": 2048,
            "stack": ["ntdll!RtlpAllocateHeapInternal+A7D", "emule!operator new+30", "emule!CPartFile::WriteToBuffer+123"],
        },
    ]

    assert module.summarize_umdh_app_frames(entries) == [
        {
            "frame": "emule!CPartFile::WriteToBuffer",
            "delta_bytes": 3072,
            "allocation_count": 5,
            "trace_count": 2,
        }
    ]


def test_umdh_app_allocation_frame_buckets_allocator_only_stacks() -> None:
    module = load_script_module()

    assert module.umdh_app_allocation_frame(["ntdll!RtlpAllocateHeapInternal+A7D", "emule!operator new+30"]) == "<allocator-only>"


def test_summarize_resource_deltas_reports_peak_and_post_drain() -> None:
    module = load_script_module()
    diagnostics = {
        "baseline": {
            "resources": {
                "private_bytes": 100,
                "working_set_bytes": 200,
                "handles": 10,
                "process_id": 1234,
            }
        },
        "peak": {
            "resources": {
                "private_bytes": 250,
                "working_set_bytes": 500,
                "handles": 15,
                "process_id": 1234,
            }
        },
        "post_drain": {
            "resources": {
                "private_bytes": 175,
                "working_set_bytes": 260,
                "handles": 9,
                "process_id": 1234,
            }
        },
    }

    assert module.summarize_resource_deltas(diagnostics) == {
        "peak_minus_baseline": {
            "private_bytes": 150,
            "working_set_bytes": 300,
            "handles": 5,
        },
        "post_drain_minus_baseline": {
            "private_bytes": 75,
            "working_set_bytes": 60,
            "handles": -1,
        },
        "post_drain_minus_peak": {
            "private_bytes": -75,
            "working_set_bytes": -240,
            "handles": -6,
        },
    }


def test_parse_cdb_summary_text_extracts_heap_and_address_usage() -> None:
    module = load_script_module()
    text = """
          Heap     Flags   Reserv  Commit  Virt   Free  List   UCR  Virt  Lock  Fast
                            (k)     (k)    (k)     (k) length      blocks cont. heap
-------------------------------------------------------------------------------------
0000013844de0000 00000002   81316  61368  81116  39349   713    12    1      1   LFH
0000013844ff0000 00001002    1280    120   1080     43     9     2    0      0   LFH
-------------------------------------------------------------------------------------

--- Usage Summary ---------------- RgnCount ----------- Total Size -------- %ofBusy %ofTotal
Free                                    267     7dfe`e4679000 ( 125.996 TB)           98.43%
<unknown>                               309      201`071c9000 (   2.004 TB)  99.98%    1.57%
Heap                                    988        0`0ceaf000 ( 206.684 MB)   0.01%    0.00%
Image                                   505        0`06d17000 ( 109.090 MB)   0.01%    0.00%
--- Type Summary (for busy) ------ RgnCount ----------- Total Size -------- %ofBusy %ofTotal
"""

    summary = module.parse_cdb_summary_text(text)

    assert summary["heap"] == {
        "heap_count": 2,
        "reserve_bytes": 82596 * 1024,
        "commit_bytes": 61488 * 1024,
        "virtual_bytes": 82196 * 1024,
        "free_bytes": 39392 * 1024,
        "free_block_count": 722,
        "ucr_count": 14,
        "virtual_alloc_count": 1,
    }
    assert summary["address_usage"]["Heap"] == {
        "region_count": 988,
        "total_bytes": int(206.684 * 1024 * 1024),
    }
    assert summary["address_usage"]["Image"]["region_count"] == 505


def test_summarize_cdb_deltas_reports_heap_and_address_changes() -> None:
    module = load_script_module()
    diagnostics = {
        "baseline": {
            "tools": {
                "dump_analysis": {
                    "cdb": {
                        "summary": {
                            "heap": {"reserve_bytes": 100, "commit_bytes": 80, "free_bytes": 10},
                            "address_usage": {"Heap": {"region_count": 2, "total_bytes": 100}},
                        }
                    }
                }
            }
        },
        "peak": {
            "tools": {
                "dump_analysis": {
                    "cdb": {
                        "summary": {
                            "heap": {"reserve_bytes": 400, "commit_bytes": 320, "free_bytes": 50},
                            "address_usage": {"Heap": {"region_count": 7, "total_bytes": 400}},
                        }
                    }
                }
            }
        },
        "post_drain": {
            "tools": {
                "dump_analysis": {
                    "cdb": {
                        "summary": {
                            "heap": {"reserve_bytes": 400, "commit_bytes": 300, "free_bytes": 120},
                            "address_usage": {"Heap": {"region_count": 9, "total_bytes": 400}},
                        }
                    }
                }
            }
        },
    }

    assert module.summarize_cdb_deltas(diagnostics) == {
        "peak_minus_baseline": {
            "heap": {"reserve_bytes": 300, "commit_bytes": 240, "free_bytes": 40},
            "address_usage": {"Heap": {"region_count": 5, "total_bytes": 300}},
        },
        "post_drain_minus_baseline": {
            "heap": {"reserve_bytes": 300, "commit_bytes": 220, "free_bytes": 110},
            "address_usage": {"Heap": {"region_count": 7, "total_bytes": 300}},
        },
        "post_drain_minus_peak": {
            "heap": {"reserve_bytes": 0, "commit_bytes": -20, "free_bytes": 70},
            "address_usage": {"Heap": {"region_count": 2, "total_bytes": 0}},
        },
    }


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
                        "query_index": 0,
                        "query_label": "linux",
                        "must_return_results": True,
                        "activity": {
                            "last": {"status": "complete"},
                            "maxResults": 0,
                            "observations": [{}],
                            "terminal": "timeout_zero_results",
                        },
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
            "query_index": 0,
            "query_label": "linux",
            "terminal": "timeout_zero_results",
            "maxResults": 0,
            "observation_count": 1,
            "last_status": "complete",
            "must_return_results": True,
        }
    ]
    assert module.collect_zero_result_searches(stress, required_only=True)[0]["searchId"] == "101"

    stress["waves"][0]["searches"][0]["fallback"] = {"recovered": True}
    assert module.collect_zero_result_searches(stress) == []

    stress["waves"][0]["searches"][0]["fallback"] = {"recovered": False}
    stress["waves"][0]["searches"][0]["must_return_results"] = False
    assert module.collect_zero_result_searches(stress, required_only=True) == []


def test_extract_stress_transfer_hashes_uses_transfer_payloads() -> None:
    module = load_script_module()
    hash_a = "0123456789abcdef0123456789abcdef"
    hash_b = "abcdef0123456789abcdef0123456789"
    stress = {
        "waves": [
            {
                "searches": [
                    {
                        "download_trigger": {
                            "triggers": [
                                {"transfer": {"json": {"hash": hash_a}}},
                                {"transfer": {"json": {"hash": hash_a.upper()}}},
                                {"transfer": {"json": {"hash": "not-a-hash"}}},
                            ]
                        }
                    },
                    {
                        "download_trigger": {
                            "triggers": [
                                {"transfer": {"json": {"hash": hash_b}}},
                            ]
                        }
                    },
                ]
            }
        ]
    }

    assert module.extract_stress_transfer_hashes(stress) == [hash_a, hash_b]


def test_delete_stress_transfers_uses_explicit_delete_files(monkeypatch) -> None:
    module = load_script_module()
    calls: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        calls.append({"path": path, **kwargs})
        return {"status": 200, "json": {"ok": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    result = module.delete_stress_transfers(
        "http://127.0.0.1:1",
        "key",
        ["0123456789abcdef0123456789abcdef"],
    )

    assert result["requested_count"] == 1
    assert result["deleted_count"] == 1
    assert calls == [
        {
            "path": "/api/v1/transfers/0123456789abcdef0123456789abcdef",
            "method": "DELETE",
            "api_key": "key",
            "json_body": {"deleteFiles": True},
            "request_timeout_seconds": 30.0,
        }
    ]


def test_wait_for_stress_transfers_absent_polls_until_transfer_disappears(monkeypatch) -> None:
    module = load_script_module()
    transfer_hash = "0123456789abcdef0123456789abcdef"
    payloads = [
        [{"hash": transfer_hash}, {"hash": "abcdef0123456789abcdef0123456789"}],
        [{"hash": "abcdef0123456789abcdef0123456789"}],
    ]

    def fake_http_request(_base_url, path, **kwargs):
        assert path == "/api/v1/transfers"
        assert kwargs["api_key"] == "key"
        return {"status": 200, "json": payloads.pop(0)}

    def fake_wait_for(resolve, **_kwargs):
        first = resolve()
        assert first is None
        return resolve()

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_array", lambda result, _status: result["json"])
    monkeypatch.setattr(module.rest_smoke, "wait_for", fake_wait_for)

    result = module.wait_for_stress_transfers_absent(
        "http://127.0.0.1:1",
        "key",
        [transfer_hash],
        30.0,
    )

    assert result["absent"] is True
    assert result["expected_count"] == 1
    assert [row["present_count"] for row in result["observations"]] == [1, 0]


def test_wait_for_completed_stress_downloads_records_completed_hashes(monkeypatch) -> None:
    module = load_script_module()
    transfer_hash = "0123456789abcdef0123456789abcdef"
    registry = module.StressTransferRegistry()
    registry.record_triggered(transfer_hash)

    def fake_http_request(_base_url, path, **kwargs):
        assert path == "/api/v1/transfers"
        return {
            "status": 200,
            "json": [
                {
                    "hash": transfer_hash,
                    "state": "completed",
                    "completedBytes": 1024,
                }
            ],
        }

    def fake_wait_for(resolve, **_kwargs):
        return resolve()

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_array", lambda result, _status: result["json"])
    monkeypatch.setattr(module.rest_smoke, "wait_for", fake_wait_for)

    result = module.wait_for_completed_stress_downloads(
        "http://127.0.0.1:1",
        "key",
        registry,
        1,
        10.0,
    )

    assert result["ok"] is True
    assert result["completed_count"] == 1
    assert registry.counts()["completed_stress_transfer_count"] == 1


def test_delete_non_completed_stress_transfers_avoids_completed_rows(monkeypatch) -> None:
    module = load_script_module()
    active_hash = "0123456789abcdef0123456789abcdef"
    completed_hash = "abcdef0123456789abcdef0123456789"
    registry = module.StressTransferRegistry()
    registry.record_triggered(active_hash)
    registry.record_triggered(completed_hash)
    registry.record_completed(completed_hash)
    deletes: list[str] = []

    def fake_http_request(_base_url, path, **kwargs):
        if path == "/api/v1/transfers":
            return {
                "status": 200,
                "json": [
                    {"hash": active_hash, "state": "downloading", "completedBytes": 500},
                    {"hash": completed_hash, "state": "completed", "completedBytes": 1000},
                ],
            }
        deletes.append(path)
        return {"status": 200, "json": {"ok": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_array", lambda result, _status: result["json"])
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    result = module.delete_non_completed_stress_transfers(
        "http://127.0.0.1:1",
        "key",
        registry,
        5,
    )

    assert result["requested_count"] == 1
    assert result["deleted_count"] == 1
    assert deletes == [f"/api/v1/transfers/{active_hash}"]
    assert registry.counts()["deleted_stress_transfer_count"] == 1


def test_cleanup_clears_logs_after_transfer_cleanup(monkeypatch) -> None:
    module = load_script_module()
    calls: list[str] = []

    def fake_delete_all_searches(*_args, **_kwargs):
        calls.append("delete_all_searches")
        return {"status": 200}

    def fake_verify_searches_deleted(*_args, **_kwargs):
        calls.append("verify_searches_deleted")
        return {"checked": 1}

    def fake_delete_stress_transfers(*_args, **_kwargs):
        calls.append("delete_stress_transfers")
        return {"requested_count": 1, "deleted_count": 1}

    def fake_wait_for_stress_transfers_absent(*_args, **_kwargs):
        calls.append("wait_for_stress_transfers_absent")
        return {"absent": True}

    def fake_clear_completed_transfers(*_args, **_kwargs):
        calls.append("clear_completed_transfers")
        return {"status": 200}

    def fake_clear_logs(*_args, **_kwargs):
        calls.append("clear_logs")
        return {"status": 200}

    monkeypatch.setattr(module.rest_smoke, "delete_all_searches", fake_delete_all_searches)
    monkeypatch.setattr(module.rest_smoke, "verify_searches_deleted", fake_verify_searches_deleted)
    monkeypatch.setattr(module, "delete_stress_transfers", fake_delete_stress_transfers)
    monkeypatch.setattr(module, "wait_for_stress_transfers_absent", fake_wait_for_stress_transfers_absent)
    monkeypatch.setattr(module.rest_smoke, "clear_completed_transfers", fake_clear_completed_transfers)
    monkeypatch.setattr(module.rest_smoke, "clear_logs", fake_clear_logs)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: result)

    result = module.cleanup_searches_and_transfers(
        base_url="http://127.0.0.1:1",
        api_key="key",
        search_ids=["101"],
        transfer_hashes=["0123456789abcdef0123456789abcdef"],
        transfer_cleanup_timeout_seconds=1.0,
    )

    assert calls == [
        "delete_all_searches",
        "verify_searches_deleted",
        "delete_stress_transfers",
        "wait_for_stress_transfers_absent",
        "clear_completed_transfers",
        "clear_logs",
    ]
    assert result["clear_logs"]["status"] == 200


def test_stress_cleanup_completeness_requires_absent_transfers() -> None:
    module = load_script_module()
    report = {
        "cleanup": {
            "searches_and_transfers": {
                "delete_stress_transfers": {"requested_count": 2, "deleted_count": 2},
                "post_transfer_delete": {"absent": True},
            }
        }
    }

    assert module.stress_cleanup_is_complete(report) is True
    report["cleanup"]["searches_and_transfers"]["post_transfer_delete"]["absent"] = False
    assert module.stress_cleanup_is_complete(report) is False


def test_post_drain_umdh_delta_budget_uses_positive_bytes() -> None:
    module = load_script_module()
    report = {
        "diagnostics": {
            "umdh_summary": {
                "baseline_to_post_drain": {
                    "available": True,
                    "positive_delta_bytes": 1024,
                }
            }
        }
    }

    assert module.post_drain_umdh_delta_within_budget(report, 1024) is True
    assert module.post_drain_umdh_delta_within_budget(report, 1023) is False


def test_validate_rejects_invalid_stress_shape() -> None:
    module = load_script_module()
    args = SimpleNamespace(
        waves=0,
        searches_per_wave=1,
        max_concurrent_searches=1,
        downloads_per_wave=0,
        downloads_per_search=None,
        target_completed_downloads=0,
        completion_timeout_seconds=1,
        max_active_downloads=1,
        download_churn_interval_seconds=0,
        download_remove_count_per_churn=0,
        resource_monitor_interval_seconds=0,
        post_drain_seconds=0,
        tool_timeout_seconds=1,
        max_post_drain_umdh_positive_bytes=1,
        cpu_profile_max_file_mb=1,
    )

    try:
        module.validate_args(args)
    except ValueError as exc:
        assert "waves" in str(exc)
    else:
        raise AssertionError("expected invalid waves to be rejected")
