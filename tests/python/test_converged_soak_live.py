from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from emule_test_harness import soak_launch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SOAK_RUNNER = REPO_ROOT / "scripts" / "converged-soak-live.py"


def _load_soak_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("converged_soak_live_script", SOAK_RUNNER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_soak_launch_requires_same_vpn_bind_ip() -> None:
    assert soak_launch.require_same_vpn_bind_ip({"bindIp": "10.0.0.5"}, {"bindIp": "10.0.0.5"}) == "10.0.0.5"
    with pytest.raises(RuntimeError, match="bind IP mismatch"):
        soak_launch.require_same_vpn_bind_ip({"bindIp": "10.0.0.5"}, {"bindIp": "10.0.0.6"})
    with pytest.raises(RuntimeError, match="bind IP missing"):
        soak_launch.require_same_vpn_bind_ip({"bindIp": ""}, {"bindIp": "10.0.0.5"})


def test_safe_common_download_candidate_requires_hash_on_both_clients() -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(row: dict[str, object]) -> str | None:
            return None if row.get("safe") else "unsafe"

    candidate = runner.safe_common_download_candidate(
        [
            {"hash": "a" * 32, "safe": True, "sources": 2, "sizeBytes": 1024},
            {"hash": "b" * 32, "safe": True, "sources": 9, "sizeBytes": 2048},
            {"hash": "c" * 32, "safe": False, "sources": 99, "sizeBytes": 1},
        ],
        [
            {"hash": "a" * 32},
            {"hash": "b" * 32},
            {"hash": "c" * 32},
        ],
        rust_mod=_RustFilter,
    )

    assert candidate is not None
    assert candidate["hash"] == "b" * 32


def test_safe_common_download_candidate_returns_none_without_common_safe_hash() -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    assert (
        runner.safe_common_download_candidate(
            [{"hash": "a" * 32, "safe": True}],
            [{"hash": "b" * 32}],
            rust_mod=_RustFilter,
        )
        is None
    )


def test_action_tracker_prime_suppresses_existing_rows() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    baseline = tracker.prime(
        rust_searches=[{"id": "old-rs", "key": "linux", "label": "linux"}],
        rust_transfers=[{"id": "old-rt", "key": "a" * 32, "label": "old.iso"}],
        mfc_searches=[{"id": "old-ms", "key": "linux", "label": "linux"}],
        mfc_transfers=[{"id": "old-mt", "key": "a" * 32, "label": "old.iso"}],
    )

    pairs, unpaired = tracker.tick(
        runner.datetime.now(runner.timezone.utc),
        rust_searches=[
            {"id": "old-rs", "key": "linux", "label": "linux"},
            {"id": "new-rs", "key": "python", "label": "python"},
        ],
        rust_transfers=[{"id": "old-rt", "key": "a" * 32, "label": "old.iso"}],
        mfc_searches=[
            {"id": "old-ms", "key": "linux", "label": "linux"},
            {"id": "new-ms", "key": "python", "label": "python"},
        ],
        mfc_transfers=[{"id": "old-mt", "key": "a" * 32, "label": "old.iso"}],
    )

    assert baseline == {
        "rustSearches": 1,
        "rustTransfers": 1,
        "mfcSearches": 1,
        "mfcTransfers": 1,
    }
    assert [(pair.kind, pair.key) for pair in pairs] == []
    assert unpaired == []
    assert [action.key for action in tracker.rust] == ["python"]
    assert [action.key for action in tracker.mfc] == ["python"]
