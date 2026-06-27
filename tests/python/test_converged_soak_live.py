from __future__ import annotations

import importlib.util
from datetime import timedelta
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


def test_load_shareddir_roots_deduplicates_and_adds_incoming(tmp_path: Path) -> None:
    shareddir = tmp_path / "shareddir.dat"
    shareddir.write_text(
        "C:\\ShareA\\\r\n"
        "c:\\sharea\r\n"
        "D:\\ShareB/\r\n"
        "\r\n",
        encoding="utf-8",
    )

    roots = soak_launch.load_shareddir_roots(shareddir, extra_roots=[Path("E:/Incoming")])

    assert roots == ["C:\\ShareA\\", "D:\\ShareB\\", "E:\\Incoming\\"]


def test_existing_shared_roots_counts_inaccessible_entries(tmp_path: Path) -> None:
    present = tmp_path / "present"
    present.mkdir()

    roots, skipped = soak_launch.existing_shared_roots(
        [str(present) + "\\", str(tmp_path / "missing") + "\\"]
    )

    assert roots == [str(present) + "\\"]
    assert skipped == 1


def test_ensure_operator_server_reuses_existing_row(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_retry(_description: str, _attempts: int, _base_url: str, path: str, **kwargs: object) -> object:
        calls.append((str(kwargs.get("method") or "GET"), path))
        return {
            "data": {
                "items": [
                    {
                        "address": soak_launch.operator_server_parts()[0],
                        "port": soak_launch.operator_server_parts()[1],
                        "name": "preloaded",
                        "static": True,
                    }
                ]
            }
        }

    monkeypatch.setattr(soak_launch, "retry_http_json", fake_retry)

    result = soak_launch.ensure_operator_server("http://client", "key")

    assert result["preloaded"] is True
    assert result["staticUpdated"] is False
    assert calls == [("GET", "/api/v1/servers")]


def test_ensure_operator_server_promotes_preloaded_row_to_static(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_retry(_description: str, _attempts: int, _base_url: str, path: str, **kwargs: object) -> object:
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path, kwargs.get("body")))
        if method == "GET":
            return {
                "data": {
                    "items": [
                        {
                            "address": soak_launch.operator_server_parts()[0],
                            "port": soak_launch.operator_server_parts()[1],
                            "name": "preloaded",
                            "static": False,
                        }
                    ]
                }
            }
        return {"data": {"static": True}}

    monkeypatch.setattr(soak_launch, "retry_http_json", fake_retry)

    result = soak_launch.ensure_operator_server("http://client", "key")

    assert result["preloaded"] is True
    assert result["staticUpdated"] is True
    assert calls == [
        ("GET", "/api/v1/servers", None),
        ("PATCH", f"/api/v1/servers/{soak_launch.OPERATOR_SERVER}", {"static": True}),
    ]


def test_ensure_operator_server_adds_missing_row(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_retry(_description: str, _attempts: int, _base_url: str, path: str, **kwargs: object) -> object:
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path, kwargs.get("body")))
        if method == "GET":
            return {"data": {"items": []}}
        return {"data": {"added": True}}

    monkeypatch.setattr(soak_launch, "retry_http_json", fake_retry)

    result = soak_launch.ensure_operator_server("http://client", "key")

    assert result["preloaded"] is False
    assert calls == [
        ("GET", "/api/v1/servers", None),
        (
            "POST",
            "/api/v1/servers",
            {
                "address": soak_launch.operator_server_parts()[0],
                "port": soak_launch.operator_server_parts()[1],
                "name": soak_launch.OPERATOR_SERVER_NAME,
                "static": True,
            },
        ),
    ]


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


def test_action_tracker_logs_redacted_action_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    messages: list[str] = []
    monkeypatch.setattr(runner, "log", messages.append)
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)

    tracker.tick(
        runner.datetime.now(runner.timezone.utc),
        rust_searches=[{"id": "rs", "key": "private search", "label": "Private Search"}],
        rust_transfers=[
            {"id": "rt", "key": "a" * 32, "label": "Private Download Title.pdf"}
        ],
        mfc_searches=[],
        mfc_transfers=[],
    )
    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key="b" * 32,
        label="Another Private Download Title.pdf",
        observed_at=runner.datetime.now(runner.timezone.utc),
        action_id="auto-download-1",
    )

    joined = "\n".join(messages)
    assert "Private Search" not in joined
    assert "Private Download Title" not in joined
    assert "Another Private" not in joined
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in joined
    assert "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" not in joined
    assert "observed rust search action" in joined
    assert "observed rust download action" in joined
    assert "observed synchronized download action" in joined


def test_automatic_cycle_schedules_download_without_triggering(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    triggered: list[str] = []

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    monkeypatch.setattr(
        runner,
        "create_search",
        lambda base_url, api_key, *, query, method: "rust-search"
        if api_key == runner.RUST_API_KEY
        else "mfc-search",
    )
    monkeypatch.setattr(
        runner,
        "poll_search_results",
        lambda *_args, **_kwargs: [{"hash": "d" * 32, "sources": 3, "sizeBytes": 2048}],
    )
    monkeypatch.setattr(runner, "trigger_download", lambda *_args, **_kwargs: triggered.append("download"))

    cycle = runner.drive_automatic_cycle(
        cycle_index=1,
        query="python",
        method="server",
        rust_base="http://rust",
        mfc_base="http://mfc",
        rust_mod=_RustFilter,
        download=True,
        search_timeout_seconds=1.0,
    )

    assert triggered == []
    assert cycle["download"]["scheduled"] is True
    assert cycle["download"]["ok"] is None
    assert cycle["download"]["searchIds"] == {"rust": "rust-search", "mfc": "mfc-search"}


def test_checkpoint_operator_reconnect_skips_connected_client() -> None:
    runner = _load_soak_runner()

    result = runner.checkpoint_operator_reconnect(
        "http://client",
        "key",
        {"connected": True},
    )

    assert result == {"attempted": False, "reason": "already_connected"}


def test_checkpoint_operator_reconnect_triggers_disconnected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    calls: list[tuple[str, str, str]] = []

    def fake_connect(base_url: str, api_key: str, *, description: str) -> dict[str, object]:
        calls.append((base_url, api_key, description))
        return {"connect": {"data": {"connected": False, "connecting": True, "serverCount": 1}}}

    monkeypatch.setattr(runner.soak_launch, "connect_operator_server", fake_connect)

    result = runner.checkpoint_operator_reconnect(
        "http://client",
        "key",
        {"connected": False},
    )

    assert calls == [("http://client", "key", "checkpoint operator server reconnect")]
    assert result == {
        "attempted": True,
        "ok": True,
        "connected": False,
        "connecting": True,
        "serverCount": 1,
    }


def test_tracker_records_synchronized_download_action() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    now = runner.datetime.now(runner.timezone.utc)

    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key="e" * 32,
        label="e" * 32,
        observed_at=now,
        action_id="auto-download-1",
    )

    assert [(action.client, action.key) for action in tracker.rust] == [("rust", "e" * 32)]
    assert [(action.client, action.key) for action in tracker.mfc] == [("mfc", "e" * 32)]


def test_tracker_uses_download_specific_settle_window() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(
        window_seconds=90.0,
        settle_seconds=45.0,
        lead_seconds=8.0,
        download_settle_seconds=300.0,
    )
    now = runner.datetime.now(runner.timezone.utc)

    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key="e" * 32,
        label="e" * 32,
        observed_at=now,
        action_id="auto-download-1",
    )

    pairs, unpaired = tracker.tick(
        now + timedelta(seconds=100),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )
    assert pairs == []
    assert unpaired == []

    pairs, unpaired = tracker.tick(
        now + timedelta(seconds=301),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )
    assert [(pair.kind, pair.key) for pair in pairs] == [(runner.sad.DOWNLOAD, "e" * 32)]
    assert unpaired == []


def test_tracker_suppresses_rest_echo_of_synchronized_download() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    now = runner.datetime.now(runner.timezone.utc)
    file_hash = "f" * 32

    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key=file_hash,
        label=file_hash,
        observed_at=now,
        action_id="auto-download-1",
    )
    tracker.processed = {action.action_id for action in tracker.rust + tracker.mfc}
    pairs, unpaired = tracker.tick(
        now,
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[{"id": "mfc-transfer", "key": file_hash, "label": "Private Title.pdf"}],
    )

    assert pairs == []
    assert unpaired == []
    assert [action.action_id for action in tracker.mfc] == ["mfc:auto-download-1"]
