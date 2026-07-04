"""Unit tests for the scripted-action capture core (no live client)."""

from __future__ import annotations

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
    assert actions[3].id == "download-" + ("b" * 32)[:8]


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


def test_execute_action_set_isolates_a_failing_action() -> None:
    actions = sa.default_action_set(["ubuntu", "debian"], [], methods=("server", "global"))
    markers: list[dict] = []

    def runner(action: sa.ScriptedAction) -> dict:
        if action.params["method"] == "server":
            raise RuntimeError("boom")
        return {"ok": True}

    results = sa.execute_action_set(actions, runner, markers.append, sleep=lambda _s: None)
    assert [r["status"] for r in results] == ["error", "ok"]
    end_markers = [m for m in markers if m["marker"] == "end"]
    assert end_markers[0]["status"] == "error" and "boom" in end_markers[0]["outcome"]["error"]
