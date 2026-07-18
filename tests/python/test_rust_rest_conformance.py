from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_rest_conformance


class FakeEventStreamResponse:
    def __init__(
        self,
        lines: list[bytes],
        *,
        status: int = 200,
        content_type: str = "text/event-stream",
    ):
        self._lines = list(lines)
        self.status = status
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> "FakeEventStreamResponse":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def readline(self) -> bytes:
        if not self._lines:
            return b""
        return self._lines.pop(0)


def test_run_response_conformance_invokes_rest_contract_budget() -> None:
    calls: list[tuple[str, str, str]] = []
    event_calls: list[tuple[str, str]] = []

    def exercise(base_url: str, api_key: str, budget: str) -> dict[str, object]:
        calls.append((base_url, api_key, budget))
        return {"ok": True, "failed_routes": []}

    def event_stream(base_url: str, api_key: str) -> dict[str, object]:
        event_calls.append((base_url, api_key))
        return {"ok": True, "operationId": "getEvents"}

    summary = rust_rest_conformance.run_response_conformance(
        "http://127.0.0.1:4711",
        "test-key",
        budget="contract-stress",
        rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
        event_stream_checker=event_stream,
    )

    assert summary["ok"] is True
    assert calls == [("http://127.0.0.1:4711", "test-key", "contract-stress")]
    assert event_calls == [("http://127.0.0.1:4711", "test-key")]
    assert summary["event_stream"] == {"ok": True, "operationId": "getEvents"}


def test_run_response_conformance_raises_on_contract_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )

    assert raised.value.summary["failed_routes"] == ["getApp"]


def test_run_response_conformance_reports_event_stream_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": True, "failed_routes": []}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
            event_stream_checker=lambda _base_url, _api_key: {
                "ok": False,
                "reason": "missing reset",
            },
        )

    assert raised.value.summary["ok"] is False
    assert raised.value.summary["failed_routes"] == ["getEvents"]
    assert raised.value.summary["event_stream"] == {"ok": False, "reason": "missing reset"}


def test_run_event_stream_conformance_reads_resume_reset_frame() -> None:
    requests = []

    def opener(request, *, timeout: float):
        requests.append((request, timeout))
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 42\n",
                b'data: {"id":42,"type":"sync.reset","reason":"last-event-id","lastEventId":"1"}\n',
                b"\n",
            ]
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
    )

    assert summary == {
        "ok": True,
        "operationId": "getEvents",
        "path": "/api/v1/events",
        "status": 200,
        "contentType": "text/event-stream",
    }
    request, timeout = requests[0]
    assert request.full_url == "http://127.0.0.1:4711/api/v1/events"
    assert request.headers["Accept"] == "text/event-stream"
    assert request.headers["Last-event-id"] == "1"
    assert request.headers["X-api-key"] == "test-key"
    assert timeout == 2.0


def test_run_cli_writes_failed_conformance_report(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    monkeypatch.setattr(
        rust_rest_conformance,
        "load_rest_smoke_module",
        lambda: SimpleNamespace(exercise_rest_contract_completeness=exercise),
    )
    monkeypatch.setattr(
        rust_rest_conformance,
        "run_event_stream_conformance",
        lambda _base_url, _api_key: {"ok": True},
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
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "event_stream": {"ok": True},
        "failed_routes": ["getApp"],
        "ok": False,
    }
