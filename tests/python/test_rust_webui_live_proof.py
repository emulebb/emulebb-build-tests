from __future__ import annotations

from emule_test_harness import rust_webui_live_proof


def test_request_recorder_counts_only_same_origin_api_and_static_assets() -> None:
    recorder = rust_webui_live_proof.RequestRecorder("http://192.0.2.10:4731/")

    recorder.record_url("http://192.0.2.10:4731/api/v1/snapshot?limit=500")
    recorder.record_url("http://192.0.2.10:4731/api/v1/logs?limit=300")
    recorder.record_url("http://192.0.2.10:4731/api/v1/transfers/abcdef0123456789abcdef0123456789/sources")
    recorder.record_url("http://192.0.2.10:4731/assets/index-test.js")
    recorder.record_url("http://example.invalid/api/v1/snapshot?limit=500")

    assert recorder.snapshot()["apiCounts"] == {
        "logs?limit=300": 1,
        "snapshot?limit=500": 1,
        "transfers/{hash}/sources": 1,
    }
    assert recorder.snapshot()["staticAssets"] == {"/assets/index-test.js": 1}


def test_steady_request_load_allows_snapshot_polling_only() -> None:
    check = rust_webui_live_proof.steady_request_load_check(
        {
            "snapshot?limit=500": 6,
            "app": 1,
            "capabilities": 1,
        }
    )

    assert check == {"ok": True, "repeatedSecondaryEndpoints": {}}


def test_steady_request_load_rejects_stale_bundle_secondary_polling() -> None:
    check = rust_webui_live_proof.steady_request_load_check(
        {
            "snapshot?limit=500": 6,
            "logs?limit=300": 6,
            "shared-files?limit=500": 6,
            "uploads": 6,
        }
    )

    assert check == {
        "ok": False,
        "repeatedSecondaryEndpoints": {
            "logs?limit=300": 6,
            "shared-files?limit=500": 6,
            "uploads": 6,
        },
    }


def test_transfer_workflow_check_requires_completed_full_progress_row() -> None:
    check = rust_webui_live_proof.transfer_workflow_check_from_cells(
        [
            {"state": "downloading", "progress": "38.3%"},
            {"state": "completed", "progress": "100.0%"},
        ],
        False,
    )

    assert check == {
        "ok": True,
        "rowCount": 2,
        "activeProgressRowCount": 1,
        "completedRowCount": 1,
        "completedFullProgressRowCount": 1,
        "emptyVisible": False,
    }


def test_transfer_workflow_check_rejects_fraction_rendered_as_percent() -> None:
    check = rust_webui_live_proof.transfer_workflow_check_from_cells(
        [{"state": "completed", "progress": "1.0%"}],
        False,
    )

    assert check == {
        "ok": False,
        "rowCount": 1,
        "activeProgressRowCount": 0,
        "completedRowCount": 1,
        "completedFullProgressRowCount": 0,
        "emptyVisible": False,
    }


def test_transfer_workflow_check_accepts_visible_download_progress() -> None:
    check = rust_webui_live_proof.transfer_workflow_check_from_cells(
        [
            {"state": "downloading", "progress": "0.0%"},
            {"state": "downloading", "progress": "94.9%"},
        ],
        False,
    )

    assert check == {
        "ok": True,
        "rowCount": 2,
        "activeProgressRowCount": 1,
        "completedRowCount": 0,
        "completedFullProgressRowCount": 0,
        "emptyVisible": False,
    }


def test_browser_performance_check_accepts_low_idle_main_thread_work() -> None:
    before = rust_webui_live_proof.performance_metric_map(
        {
            "metrics": [
                {"name": "TaskDuration", "value": 10.0},
                {"name": "ScriptDuration", "value": 2.0},
                {"name": "JSHeapUsedSize", "value": 1000},
            ]
        }
    )
    after = rust_webui_live_proof.performance_metric_map(
        {
            "metrics": [
                {"name": "TaskDuration", "value": 10.5},
                {"name": "ScriptDuration", "value": 2.1},
                {"name": "JSHeapUsedSize", "value": 1200},
            ]
        }
    )

    check = rust_webui_live_proof.browser_performance_check(
        before,
        after,
        elapsed_seconds=10.0,
        max_main_thread_busy_ratio=0.25,
    )

    assert check == {
        "ok": True,
        "missing": [],
        "elapsedSeconds": 10.0,
        "maxMainThreadBusyRatio": 0.25,
        "mainThreadBusyRatio": 0.05,
        "durationDeltas": {
            "TaskDuration": 0.5,
            "ScriptDuration": 0.1,
        },
        "absoluteAfter": {"JSHeapUsedSize": 1200},
    }


def test_browser_performance_check_rejects_busy_idle_main_thread() -> None:
    check = rust_webui_live_proof.browser_performance_check(
        {"TaskDuration": 10.0},
        {"TaskDuration": 14.0},
        elapsed_seconds=10.0,
        max_main_thread_busy_ratio=0.25,
    )

    assert check["ok"] is False
    assert check["mainThreadBusyRatio"] == 0.4


def test_browser_performance_check_requires_task_duration() -> None:
    check = rust_webui_live_proof.browser_performance_check(
        {},
        {},
        elapsed_seconds=10.0,
        max_main_thread_busy_ratio=0.25,
    )

    assert check["ok"] is False
    assert check["missing"] == ["TaskDuration"]


def test_parser_defaults_to_persisted_rust_webui() -> None:
    args = rust_webui_live_proof.build_parser().parse_args([])

    assert args.api_key == "converged-soak"
    assert args.max_main_thread_busy_ratio == 0.25
    assert str(args.report_path).endswith("reports\\rust-webui-live-proof\\rust-webui-live-proof.latest.json")
