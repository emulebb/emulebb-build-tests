from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from emule_test_harness import converged_action_driver as driver
from emule_test_harness import soak_action_diff
from emule_test_harness import vm_guest_profiles


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


def test_search_create_phase_resumes_persisted_identifier_without_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver,
        "create_search",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("persisted search must not be created again")
        ),
    )

    phase = driver.run_search_create_phase(
        endpoint("rust"),
        query="exact local term",
        method="server",
        existing_search_id="rust-search-17",
    )

    assert phase.search_id == "rust-search-17"
    assert phase.error is None
    assert phase.resumed is True
    assert phase.cycle_record() == {
        "ok": True,
        "searchId": "rust-search-17",
        "resumed": True,
    }


def test_read_search_results_performs_one_bounded_read_without_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    rows = [{"hash": "a" * 32}]

    def fake_retry(*args: object, **kwargs: object) -> dict[str, object]:
        calls.append((*args, kwargs))
        return {"data": {"status": "running", "items": rows}}

    monkeypatch.setattr(driver, "retry_http_json", fake_retry)
    monkeypatch.setattr(
        driver.time,
        "sleep",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("one-shot results read must not sleep")
        ),
    )

    result = driver.read_search_results(endpoint("rust"), "rust-search-17")

    assert list(result) == rows
    assert result.completed is False
    assert calls == [
        (
            "rust soak search poll",
            1,
            "http://rust",
            "/api/v1/searches/rust-search-17",
            {"api_key": "rust-key", "timeout_seconds": 30.0},
        )
    ]


def test_read_search_results_recognizes_completed_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver,
        "retry_http_json",
        lambda *_args, **_kwargs: {
            "data": {"status": "COMPLETED", "items": []}
        },
    )

    result = driver.read_search_results(endpoint("mfc"), "mfc-search-9")

    assert list(result) == []
    assert result.completed is True


def test_read_search_results_passes_custom_request_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[float] = []

    def fake_retry(*_args: object, **kwargs: object) -> dict[str, object]:
        observed.append(float(kwargs["timeout_seconds"]))
        return {"data": {"status": "running", "items": []}}

    monkeypatch.setattr(driver, "retry_http_json", fake_retry)

    driver.read_search_results(
        endpoint("rust"),
        "rust-search-17",
        timeout_seconds=0.25,
    )

    assert observed == [0.25]
    with pytest.raises(ValueError, match="greater than zero"):
        driver.read_search_results(
            endpoint("rust"),
            "rust-search-17",
            timeout_seconds=0,
        )


@pytest.mark.parametrize(
    ("attempts", "expected_sleeps"),
    [(1, []), (2, [1.0])],
)
def test_retry_http_json_never_sleeps_after_final_failure(
    monkeypatch: pytest.MonkeyPatch,
    attempts: int,
    expected_sleeps: list[float],
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(vm_guest_profiles.time, "sleep", sleeps.append)

    def fail_request(*_args: object, **_kwargs: object) -> object:
        raise OSError("exact local failure")

    with pytest.raises(RuntimeError, match=f"failed after {attempts} attempts"):
        vm_guest_profiles.retry_http_json(
            "bounded read",
            attempts,
            "http://rust",
            "/api/v1/searches/rust-search-17",
            request_func=fail_request,
        )

    assert sleeps == expected_sleeps


def test_search_results_poll_phase_preserves_exact_rest_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver,
        "read_search_results",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("raw local REST failure")
        ),
    )

    phase = driver.run_search_results_poll_phase(
        endpoint("rust"),
        "rust-search-17",
    )

    assert phase.rows == ()
    assert phase.completed is False
    assert phase.error == {
        "client": "rust",
        "phase": "search-results",
        "type": "RuntimeError",
        "message": "raw local REST failure",
    }


def test_search_results_poll_phase_preserves_incomplete_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [{"hash": "a" * 32}, {"hash": "b" * 32}]
    monkeypatch.setattr(
        driver,
        "read_search_results",
        lambda *_args, **_kwargs: driver.SearchResults(rows, completed=False),
    )

    phase = driver.run_search_results_poll_phase(
        endpoint("mfc"),
        "mfc-search-9",
    )

    assert list(phase.rows) == rows
    assert phase.completed is False
    assert phase.error is None
    assert phase.cycle_record() == {
        "ok": True,
        "count": 2,
        "completed": False,
    }


def test_blocking_search_results_poll_retains_last_rows_at_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = iter(
        [
            driver.SearchResults([{"hash": "a" * 32}], completed=False),
            driver.SearchResults([], completed=False),
        ]
    )
    monotonic = iter([0.0, 0.0, 1.0, 2.0])
    sleeps: list[float] = []
    monkeypatch.setattr(
        driver,
        "read_search_results",
        lambda *_args, **_kwargs: next(snapshots),
    )
    monkeypatch.setattr(driver.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(driver.time, "sleep", sleeps.append)

    result = driver.poll_search_results(
        endpoint("mfc"),
        "mfc-search-9",
        timeout_seconds=2.0,
    )

    assert list(result) == [{"hash": "a" * 32}]
    assert result.completed is False
    assert sleeps == [2.0, 2.0]


def test_search_results_phase_preserves_incomplete_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [{"hash": "a" * 32}, {"hash": "b" * 32}]
    monkeypatch.setattr(
        driver,
        "poll_search_results",
        lambda *_args, **_kwargs: driver.SearchResults(rows, completed=False),
    )

    phase = driver.run_search_results_phase(
        endpoint("mfc"),
        "mfc-search-9",
        timeout_seconds=30.0,
    )

    assert list(phase.rows) == rows
    assert phase.completed is False
    assert phase.error is None
    assert phase.cycle_record() == {
        "ok": True,
        "count": 2,
        "completed": False,
    }


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


def test_search_only_cycle_does_not_require_download_safety(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver,
        "create_search",
        lambda client, **_kwargs: f"{client.name}-search",
    )
    monkeypatch.setattr(
        driver,
        "poll_search_results",
        lambda *_args, **_kwargs: [{"hash": "a" * 32}],
    )

    cycle = driver.drive_automatic_cycle(
        cycle_index=3,
        query="debian",
        method="kad",
        rust=endpoint("rust"),
        mfc=endpoint("mfc"),
        safety=None,
        download=False,
        search_timeout_seconds=30.0,
    )

    assert cycle == {
        "cycle": 3,
        "queryIndex": 2,
        "method": "kad",
        "query": "debian",
        "downloadRequested": False,
        "ok": True,
        "searches": {
            "rust": {
                "create": {"ok": True, "searchId": "rust-search"},
                "results": {"ok": True, "count": 1, "completed": True},
            },
            "mfc": {
                "create": {"ok": True, "searchId": "mfc-search"},
                "results": {"ok": True, "count": 1, "completed": True},
            },
        },
        "searchIds": {"rust": "rust-search", "mfc": "mfc-search"},
        "resultCounts": {"rust": 1, "mfc": 1},
        "errors": [],
    }


def test_search_cycle_preserves_one_sided_create_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str]] = []

    def fake_create(client: driver.ClientEndpoint, **_kwargs) -> str:
        events.append(("create", client.name))
        if client.name == "mfc":
            raise RuntimeError("MFC create failed exactly")
        return "rust-search"

    def fake_poll(client: driver.ClientEndpoint, *_args, **_kwargs):
        events.append(("poll", client.name))
        return [{"hash": "a" * 32}]

    monkeypatch.setattr(driver, "create_search", fake_create)
    monkeypatch.setattr(driver, "poll_search_results", fake_poll)

    cycle = driver.drive_automatic_cycle(
        cycle_index=4,
        query="Exact Local Term",
        method="server",
        rust=endpoint("rust"),
        mfc=endpoint("mfc"),
        safety=None,
        download=False,
        search_timeout_seconds=30.0,
    )

    assert events == [("create", "rust"), ("create", "mfc"), ("poll", "rust")]
    assert cycle["ok"] is False
    assert cycle["query"] == "Exact Local Term"
    assert cycle["searchIds"] == {"rust": "rust-search"}
    assert cycle["resultCounts"] == {"rust": 1}
    assert cycle["searches"]["mfc"] == {
        "create": {
            "ok": False,
            "error": {
                "client": "mfc",
                "phase": "search-create",
                "type": "RuntimeError",
                "message": "MFC create failed exactly",
            },
        },
        "results": {"ok": False, "skipped": "search-create-failed"},
    }
    assert cycle["errors"] == [cycle["searches"]["mfc"]["create"]["error"]]


def test_search_cycle_preserves_one_sided_result_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str]] = []

    def fake_create(client: driver.ClientEndpoint, **_kwargs) -> str:
        events.append(("create", client.name))
        return f"{client.name}-search"

    def fake_poll(client: driver.ClientEndpoint, *_args, **_kwargs):
        events.append(("poll", client.name))
        if client.name == "rust":
            raise RuntimeError("Rust poll failed exactly")
        return [{"hash": "a" * 32}, {"hash": "b" * 32}]

    monkeypatch.setattr(driver, "create_search", fake_create)
    monkeypatch.setattr(driver, "poll_search_results", fake_poll)

    cycle = driver.drive_automatic_cycle(
        cycle_index=5,
        query="debian",
        method="global",
        rust=endpoint("rust"),
        mfc=endpoint("mfc"),
        safety=None,
        download=False,
        search_timeout_seconds=30.0,
    )

    assert events[:2] == [("create", "rust"), ("create", "mfc")]
    assert cycle["ok"] is False
    assert cycle["searchIds"] == {
        "rust": "rust-search",
        "mfc": "mfc-search",
    }
    assert cycle["resultCounts"] == {"mfc": 2}
    assert cycle["searches"]["rust"]["results"]["error"] == {
        "client": "rust",
        "phase": "search-results",
        "type": "RuntimeError",
        "message": "Rust poll failed exactly",
    }


def test_search_cycle_records_bounded_poll_timeout_without_losing_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver,
        "create_search",
        lambda client, **_kwargs: f"{client.name}-search",
    )
    monkeypatch.setattr(
        driver,
        "poll_search_results",
        lambda *_args, **_kwargs: driver.SearchResults(
            [{"hash": "a" * 32}],
            completed=False,
        ),
    )

    cycle = driver.drive_automatic_cycle(
        cycle_index=6,
        query="linux",
        method="kad",
        rust=endpoint("rust"),
        mfc=endpoint("mfc"),
        safety=None,
        download=False,
        search_timeout_seconds=30.0,
    )

    assert cycle["ok"] is True
    assert cycle["resultCounts"] == {"rust": 1, "mfc": 1}
    assert cycle["searches"]["rust"]["results"] == {
        "ok": True,
        "count": 1,
        "completed": False,
    }
    assert cycle["searches"]["mfc"]["results"]["completed"] is False


def test_download_cycle_rejects_missing_safety_before_public_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver,
        "create_search",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("search must not be created")
        ),
    )

    with pytest.raises(ValueError, match="download safety policy"):
        driver.drive_automatic_cycle(
            cycle_index=7,
            query="linux",
            method="server",
            rust=endpoint("rust"),
            mfc=endpoint("mfc"),
            safety=None,
            download=True,
            search_timeout_seconds=30.0,
        )


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
