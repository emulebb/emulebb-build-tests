from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated Rust/eMuleBB cross-client script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "emulebb-rust-emulebb-cross-client.py"
    spec = importlib.util.spec_from_file_location("emulebb_rust_emulebb_cross_client_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_wait_for_rust_ed2k_connected_reads_canonical_status_stats(monkeypatch) -> None:
    module = load_suite_module()

    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {"stats": {"ed2kConnected": True}},
    )
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    status = module.wait_for_rust_ed2k_connected("http://192.0.2.10:4711", "key", 1.0)

    assert status["stats"]["ed2kConnected"] is True


def test_wait_for_rust_search_result_reads_unwrapped_search_payload(monkeypatch) -> None:
    module = load_suite_module()

    expected_hash = "00112233445566778899aabbccddeeff"
    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {
            "id": "search-1",
            "results": [{"hash": expected_hash.upper(), "name": "fixture.bin"}],
        },
    )
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    result = module.wait_for_rust_search_result(
        "http://192.0.2.10:4711",
        "key",
        query="fixture",
        transfer_hash=expected_hash,
        timeout_seconds=1.0,
    )

    assert result["search"]["id"] == "search-1"
    assert result["result"]["name"] == "fixture.bin"
