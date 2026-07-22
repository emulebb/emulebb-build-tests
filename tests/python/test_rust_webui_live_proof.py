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


def test_parser_defaults_to_persisted_rust_webui() -> None:
    args = rust_webui_live_proof.build_parser().parse_args([])

    assert args.api_key == "converged-soak"
    assert str(args.report_path).endswith("reports\\rust-webui-live-proof\\rust-webui-live-proof.latest.json")
