from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from emule_test_harness import converged_action_driver as driver
from emule_test_harness import soak_action_diff


class AllowSafeDownloads:
    @staticmethod
    def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
        return None


def endpoint(name: str) -> driver.ClientEndpoint:
    return driver.ClientEndpoint(
        name=name,
        base_url=f"http://{name}",
        api_key=f"{name}-key",
    )


def test_common_candidates_enforce_intersection_policy_and_order() -> None:
    mib = 1024 * 1024
    rust_rows = [
        {
            "hash": "a" * 32,
            "name": "small-linux.iso",
            "sources": 99,
            "sizeBytes": 100 * mib,
        },
        {
            "hash": "b" * 32,
            "name": "linux.iso.torrent",
            "sources": 80,
            "sizeBytes": 900 * mib,
        },
        {
            "hash": "c" * 32,
            "name": "ubuntu.iso",
            "sources": 5,
            "sizeBytes": 700 * mib,
        },
        {
            "hash": "d" * 32,
            "name": "debian.iso",
            "sources": 5,
            "sizeBytes": 900 * mib,
        },
        {
            "hash": "e" * 32,
            "name": "fedora.iso",
            "sources": 20,
            "sizeBytes": 800 * mib,
        },
    ]
    mfc_rows = [{"hash": character * 32} for character in "abcde"]

    candidates = driver.top_common_download_candidates(
        rust_rows,
        mfc_rows,
        safety=AllowSafeDownloads,
        required_suffix=".iso",
        min_size_bytes=500 * mib,
    )

    assert [row["hash"] for row in candidates] == [
        "e" * 32,
        "d" * 32,
        "c" * 32,
    ]


def test_automatic_cycle_schedules_without_triggering_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rust = endpoint("rust")
    mfc = endpoint("mfc")
    candidate_hash = "d" * 32
    created: list[tuple[str, str, str]] = []
    triggered: list[str] = []

    def fake_create_search(
        client: driver.ClientEndpoint,
        *,
        query: str,
        method: str,
    ) -> str:
        created.append((client.name, query, method))
        return f"{client.name}-search"

    monkeypatch.setattr(driver, "create_search", fake_create_search)
    monkeypatch.setattr(
        driver,
        "poll_search_results",
        lambda *_args, **_kwargs: [
            {
                "hash": candidate_hash,
                "name": "fixture.iso",
                "sources": 3,
                "sizeBytes": 2048,
            }
        ],
    )
    monkeypatch.setattr(driver, "get_list", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(driver, "transfer_exists", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        driver,
        "trigger_download",
        lambda *_args, **_kwargs: triggered.append("unexpected") or {},
    )

    cycle = driver.drive_automatic_cycle(
        cycle_index=2,
        query="linux",
        method="server",
        rust=rust,
        mfc=mfc,
        safety=AllowSafeDownloads,
        download=True,
        search_timeout_seconds=1.0,
    )

    assert created == [
        ("rust", "linux", "server"),
        ("mfc", "linux", "server"),
    ]
    assert triggered == []
    assert cycle["download"] == {
        "ok": None,
        "scheduled": True,
        "hash": candidate_hash,
        "name": "fixture.iso",
        "sizeBytes": 2048,
        "sources": 3,
        "searchIds": {"rust": "rust-search", "mfc": "mfc-search"},
    }


def test_execute_scheduled_download_targets_both_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, str]] = []

    def fake_trigger(
        client: driver.ClientEndpoint,
        search_id: str,
        file_hash: str,
    ) -> dict[str, str]:
        calls.append((client.name, search_id, file_hash))
        return {"client": client.name}

    monkeypatch.setattr(driver, "trigger_download", fake_trigger)

    result = driver.execute_scheduled_download(
        rust=endpoint("rust"),
        mfc=endpoint("mfc"),
        download={
            "hash": "A" * 32,
            "searchIds": {"rust": "rust-search", "mfc": "mfc-search"},
        },
    )

    assert calls == [
        ("rust", "rust-search", "a" * 32),
        ("mfc", "mfc-search", "a" * 32),
    ]
    assert result == {"rust": {"client": "rust"}, "mfc": {"client": "mfc"}}


def test_action_tracker_primes_and_settles_synchronized_action() -> None:
    tracker = driver.ActionTracker(
        window_seconds=90.0,
        settle_seconds=45.0,
        lead_seconds=8.0,
    )
    now = datetime.now(UTC)
    baseline = tracker.prime(
        rust_searches=[{"id": "old-rs", "key": "linux", "label": "Linux"}],
        rust_transfers=[],
        mfc_searches=[{"id": "old-ms", "key": "linux", "label": "Linux"}],
        mfc_transfers=[],
    )

    pairs, unpaired = tracker.tick(
        now,
        rust_searches=[
            {"id": "old-rs", "key": "linux", "label": "Linux"},
            {"id": "new-rs", "key": "python", "label": "Python"},
        ],
        rust_transfers=[],
        mfc_searches=[
            {"id": "old-ms", "key": "linux", "label": "Linux"},
            {"id": "new-ms", "key": "python", "label": "Python"},
        ],
        mfc_transfers=[],
    )
    settled, still_unpaired = tracker.tick(
        now + timedelta(seconds=46),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )

    assert baseline == {
        "rustSearches": 1,
        "rustTransfers": 0,
        "mfcSearches": 1,
        "mfcTransfers": 0,
    }
    assert pairs == []
    assert unpaired == []
    assert [(pair.kind, pair.key) for pair in settled] == [
        (soak_action_diff.SEARCH, "python")
    ]
    assert still_unpaired == []
