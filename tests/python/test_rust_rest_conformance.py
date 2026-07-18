from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_rest_conformance


def test_run_response_conformance_invokes_rest_contract_budget() -> None:
    calls: list[tuple[str, str, str]] = []

    def exercise(base_url: str, api_key: str, budget: str) -> dict[str, object]:
        calls.append((base_url, api_key, budget))
        return {"ok": True, "failed_routes": []}

    summary = rust_rest_conformance.run_response_conformance(
        "http://127.0.0.1:4711",
        "test-key",
        budget="contract-stress",
        rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
    )

    assert summary["ok"] is True
    assert calls == [("http://127.0.0.1:4711", "test-key", "contract-stress")]


def test_run_response_conformance_raises_on_contract_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
        )

    assert raised.value.summary["failed_routes"] == ["getApp"]


def test_run_cli_writes_failed_conformance_report(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    monkeypatch.setattr(
        rust_rest_conformance,
        "load_rest_smoke_module",
        lambda: SimpleNamespace(exercise_rest_contract_completeness=exercise),
    )
    output_path = tmp_path / "conformance.json"

    exit_code = rust_rest_conformance.run_cli(
        [
            "--base-url",
            "http://127.0.0.1:4711",
            "--api-key",
            "test-key",
            "--json-output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert json.loads(output_path.read_text(encoding="utf-8")) == {"failed_routes": ["getApp"], "ok": False}
