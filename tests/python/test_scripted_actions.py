"""Unit tests for the scripted-action capture core (no live client)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from emule_test_harness import scripted_actions as sa

pytestmark = pytest.mark.unit


def test_build_ed2k_link_roundtrip() -> None:
    link = sa.build_ed2k_link({"hash": "A" * 32, "name": "sample.bin", "size": 1234})
    assert link == "ed2k://|file|sample.bin|1234|" + "a" * 32 + "|/"


@pytest.mark.parametrize(
    "fixture",
    [
        {"hash": "A" * 31, "name": "x", "size": 1},  # short hash
        {"hash": "A" * 32, "name": "", "size": 1},  # empty name
        {"hash": "A" * 32, "name": "x", "size": 0},  # non-positive size
    ],
)
def test_build_ed2k_link_rejects_bad_fixture(fixture: dict) -> None:
    with pytest.raises(ValueError):
        sa.build_ed2k_link(fixture)


def test_run_download_adds_absent_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, object]] = []
    fixture = {"hash": "a" * 32, "name": "sample.bin", "size": 1234}
    monkeypatch.setattr(sa, "_http_optional", lambda *_args: None)
    monkeypatch.setattr(
        sa,
        "_http",
        lambda _base, _key, path, method="GET", body=None: calls.append(
            (path, method, body)
        ),
    )

    result = sa.run_download("http://127.0.0.1:4711", "secret", fixture)

    assert result == {"added": True, "reused": False, "resumed": False}
    assert calls == [
        (
            "/api/v1/transfers",
            "POST",
            {"link": f"ed2k://|file|sample.bin|1234|{'a' * 32}|/"},
        )
    ]


def test_run_download_reuses_active_persisted_transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = {"hash": "b" * 32, "name": "sample.bin", "size": 1234}
    monkeypatch.setattr(
        sa,
        "_http_optional",
        lambda *_args: {
            "data": {
                "hash": "B" * 32,
                "sizeBytes": 1234,
                "state": "downloading",
                "stopped": False,
            }
        },
    )
    monkeypatch.setattr(
        sa,
        "_http",
        lambda *_args, **_kwargs: pytest.fail("active transfer must not be re-added"),
    )

    result = sa.run_download("http://127.0.0.1:4711", "secret", fixture)

    assert result == {"added": False, "reused": True, "resumed": False}


def test_run_download_resumes_paused_persisted_transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, object]] = []
    fixture = {"hash": "c" * 32, "name": "sample.bin", "size": 1234}
    monkeypatch.setattr(
        sa,
        "_http_optional",
        lambda *_args: {
            "data": {
                "hash": "c" * 32,
                "sizeBytes": 1234,
                "state": "paused",
                "stopped": False,
            }
        },
    )
    monkeypatch.setattr(
        sa,
        "_http",
        lambda _base, _key, path, method="GET", body=None: calls.append(
            (path, method, body)
        ),
    )

    result = sa.run_download("http://127.0.0.1:4711", "secret", fixture)

    assert result == {"added": False, "reused": True, "resumed": True}
    assert calls == [
        (
            f"/api/v1/transfers/{'c' * 32}/operations/resume",
            "POST",
            None,
        )
    ]


@pytest.mark.parametrize(
    ("transfer", "message"),
    [
        (
            {"hash": "d" * 32, "sizeBytes": 1235, "state": "downloading"},
            "size does not match",
        ),
        (
            {
                "hash": "d" * 32,
                "sizeBytes": 1234,
                "state": "paused",
                "stopped": True,
            },
            "is stopped",
        ),
        (
            {"hash": "d" * 32, "sizeBytes": 1234, "state": "completed"},
            "already completed",
        ),
        (
            {"hash": "d" * 32, "sizeBytes": 1234, "state": "hashing"},
            "is not runnable",
        ),
    ],
)
def test_run_download_rejects_unusable_persisted_transfer(
    monkeypatch: pytest.MonkeyPatch,
    transfer: dict[str, object],
    message: str,
) -> None:
    fixture = {"hash": "d" * 32, "name": "sample.bin", "size": 1234}
    monkeypatch.setattr(sa, "_http_optional", lambda *_args: {"data": transfer})

    with pytest.raises(RuntimeError, match=message):
        sa.run_download("http://127.0.0.1:4711", "secret", fixture)


def test_default_action_set_one_search_per_method_plus_downloads() -> None:
    actions = sa.default_action_set(
        ["ubuntu", "debian"],
        [{"hash": "b" * 32, "name": "n", "size": 10}],
        methods=("server", "global", "kad"),
    )
    kinds = [a.kind for a in actions]
    assert kinds == ["search", "search", "search", "download"]
    assert [a.params["method"] for a in actions[:3]] == ["server", "global", "kad"]
    # round-robins the terms across the methods
    assert [a.params["query"] for a in actions[:3]] == ["ubuntu", "debian", "ubuntu"]
    assert [action.id for action in actions] == [
        "action-0001",
        "action-0002",
        "action-0003",
        "action-0004",
    ]


def test_default_action_set_applies_document_filter_to_every_search() -> None:
    actions = sa.default_action_set(
        ["linux"],
        [],
        methods=("server", "global", "kad"),
        search_options={"type": "doc", "extension": "pdf", "minAvailability": 1},
    )

    assert all(action.params["query"] == "linux" for action in actions)
    assert all(action.params["type"] == "doc" for action in actions)
    assert all(action.params["extension"] == "pdf" for action in actions)
    assert all(action.params["minAvailability"] == 1 for action in actions)


def test_execute_action_set_redacts_private_inputs_from_retained_results() -> None:
    private_hash = "0123456789abcdef0123456789abcdef"
    actions = sa.default_action_set(
        ["private linux documents"],
        [{"hash": private_hash, "name": "private-title.pdf", "size": 10}],
        methods=("server",),
    )
    markers: list[dict] = []

    def runner(action: sa.ScriptedAction) -> dict:
        if action.kind == "search":
            return {"query": action.params["query"], "message": r"unrelated X:\secret\response.txt"}
        return {
            "hash": action.params["hash"],
            "message": f"private-title.pdf {private_hash[:8]} added",
        }

    results = sa.execute_action_set(actions, runner, markers.append, sleep=lambda _s: None)
    retained = json.dumps({"markers": markers, "results": results}).casefold()
    assert "private linux documents" not in retained
    assert "private-title.pdf" not in retained
    assert private_hash not in retained
    assert private_hash[:8] not in retained
    assert "secret" not in retained
    assert [result["actionId"] for result in results] == ["action-0001", "action-0002"]


def test_execute_action_set_emits_begin_end_markers_and_spaces() -> None:
    actions = sa.default_action_set(["ubuntu"], [{"hash": "c" * 32, "name": "n", "size": 5}], methods=("server",))
    markers: list[dict] = []
    slept: list[float] = []

    def runner(action: sa.ScriptedAction) -> dict:
        return {"ran": action.id}

    results = sa.execute_action_set(
        actions, runner, markers.append, spacing_seconds=7.0, sleep=slept.append
    )
    # one begin + one end per action, in order, correlatable by actionId
    assert [m["marker"] for m in markers] == ["begin", "end", "begin", "end"]
    assert {m["actionId"] for m in markers} == {a.id for a in actions}
    assert all(m["schema"] == sa.MARKER_SCHEMA and m["ts_utc"].endswith("Z") for m in markers)
    assert [r["status"] for r in results] == ["ok", "ok"]
    # spaces between actions but not after the last one
    assert slept == [7.0]


def test_execute_action_set_markers_carry_search_method() -> None:
    # The offline diff selects the method-aware coverage gate from the marker.
    actions = sa.default_action_set(
        ["ubuntu"], [{"hash": "d" * 32, "name": "n", "size": 5}], methods=("server", "kad")
    )
    markers: list[dict] = []
    sa.execute_action_set(actions, lambda _a: {}, markers.append, sleep=lambda _s: None)
    search_markers = [m for m in markers if m["kind"] == "search"]
    download_markers = [m for m in markers if m["kind"] == "download"]
    assert [m["method"] for m in search_markers] == ["server", "server", "kad", "kad"]
    assert all("method" not in m for m in download_markers)


def test_execute_action_set_isolates_a_failing_action() -> None:
    actions = sa.default_action_set(["ubuntu", "debian"], [], methods=("server", "global"))
    markers: list[dict] = []

    def runner(action: sa.ScriptedAction) -> dict:
        if action.params["method"] == "server":
            raise RuntimeError(r"private fixture at X:\secret\title.pdf")
        return {"ok": True}

    results = sa.execute_action_set(actions, runner, markers.append, sleep=lambda _s: None)
    assert [r["status"] for r in results] == ["error", "ok"]
    end_markers = [m for m in markers if m["marker"] == "end"]
    assert end_markers[0]["status"] == "error"
    assert end_markers[0]["outcome"] == {
        "errorCode": "action-runner-exception",
        "errorType": "RuntimeError",
    }
    retained = json.dumps({"markers": markers, "results": results})
    assert "private fixture" not in retained
    assert "secret" not in retained


def test_verify_completed_file_checks_size_ed2k_and_computes_sha256(tmp_path: Path) -> None:
    payload = tmp_path / "completed.bin"
    payload.write_bytes(b"abc")

    result = sa.verify_completed_file(
        payload,
        expected_size=3,
        expected_ed2k_hash="a448017aaf21d8525fc10ae87aa6729d",
    )

    assert result.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert result.sanitized_result() == {
        "status": "verified",
        "sizeBytes": 3,
        "sizeVerified": True,
        "ed2kVerified": True,
        "sha256Computed": True,
    }


def test_verify_completed_file_rejects_wrong_hash_without_exposing_it(tmp_path: Path) -> None:
    payload = tmp_path / "completed.bin"
    payload.write_bytes(b"abc")

    with pytest.raises(RuntimeError, match="eD2K hash does not match") as error:
        sa.verify_completed_file(payload, expected_size=3, expected_ed2k_hash="0" * 32)

    assert "0" * 8 not in str(error.value)


def test_wait_for_completed_file_accepts_client_specific_locator(tmp_path: Path) -> None:
    payload = tmp_path / "client-incoming" / "completed.bin"
    payload.parent.mkdir()
    payload.write_bytes(b"abc")
    probes = iter([None, None, payload])
    clock_values = iter([0.0, 0.0, 0.5, 1.0])
    slept: list[float] = []

    result = sa.wait_for_completed_file(
        lambda: next(probes),
        expected_size=3,
        expected_ed2k_hash="a448017aaf21d8525fc10ae87aa6729d",
        timeout_seconds=2.0,
        interval_seconds=0.5,
        sleep=slept.append,
        monotonic=lambda: next(clock_values),
    )

    assert result.path == payload.resolve()
    assert slept == [0.5, 0.5]


def test_verify_matching_sha256_returns_only_sanitized_parity_proof(tmp_path: Path) -> None:
    digest = "a" * 64
    first = sa.CompletedFileVerification(tmp_path / "first", 3, "1" * 32, digest)
    second = sa.CompletedFileVerification(tmp_path / "second", 3, "1" * 32, digest)

    result = sa.verify_matching_sha256([first, second])

    assert result == {"fileCount": 2, "sha256Matched": True}
    assert digest not in json.dumps(result)
