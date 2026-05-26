from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_search_ui_module():
    """Loads the hyphenated Search UI live script for pure helper tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "search-ui-live.py"
    spec = importlib.util.spec_from_file_location("search_ui_live_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["search_ui_live_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_get_tab_count_uses_search_tab_control_message(monkeypatch) -> None:
    module = load_search_ui_module()

    class FakeWin32Gui:
        @staticmethod
        def SendMessage(hwnd: int, message: int, wparam: int, lparam: int) -> int:
            assert hwnd == 100
            assert message == module.TCM_GETITEMCOUNT
            return 3

    monkeypatch.setattr(module, "win32gui", FakeWin32Gui)

    assert module.get_tab_count(100) == 3


def test_get_list_count_uses_search_list_message(monkeypatch) -> None:
    module = load_search_ui_module()

    class FakeWin32Gui:
        @staticmethod
        def SendMessage(hwnd: int, message: int, wparam: int, lparam: int) -> int:
            assert hwnd == 200
            assert message == module.LVM_GETITEMCOUNT
            return 42

    monkeypatch.setattr(module, "win32gui", FakeWin32Gui)

    assert module.get_list_count(200) == 42


def test_get_search_status_text_reads_runtime_overlay(monkeypatch) -> None:
    module = load_search_ui_module()

    monkeypatch.setattr(module, "find_control", lambda hwnd, control_id, class_name: 300)

    class FakeWin32Gui:
        @staticmethod
        def IsWindowVisible(hwnd: int) -> bool:
            assert hwnd == 300
            return True

        @staticmethod
        def GetWindowText(hwnd: int) -> str:
            assert hwnd == 300
            return "Searching Kad..."

    monkeypatch.setattr(module, "win32gui", FakeWin32Gui)

    assert module.get_search_status_text(100) == {
        "present": True,
        "visible": True,
        "text": "Searching Kad...",
    }


def test_wait_for_search_progress_accepts_visible_status(monkeypatch) -> None:
    module = load_search_ui_module()

    monkeypatch.setattr(module, "get_search_status_text", lambda hwnd: {"present": True, "visible": True, "text": "Queued..."})
    monkeypatch.setattr(module, "find_control", lambda hwnd, control_id, class_name: 200)
    monkeypatch.setattr(module, "get_list_count", lambda hwnd: 0)

    result = module.wait_for_search_progress_observation(100, timeout_seconds=0.1)

    assert result["seen_status"] is True
    assert result["status_text"] == "Queued..."
    assert result["row_count"] == 0


def test_parse_display_size_bytes_handles_common_units() -> None:
    module = load_search_ui_module()

    assert module.parse_display_size_bytes("1 KB") == 1024
    assert module.parse_display_size_bytes("1.5 MB") == 1572864
    assert module.parse_display_size_bytes("2,0 GB") == 2147483648
    assert module.parse_display_size_bytes("") is None


def test_build_search_plan_rotates_live_wire_terms_without_reporting_text() -> None:
    module = load_search_ui_module()

    plan = module.build_search_plan(("alpha", "beta", "gamma"), 2)

    assert [row["query"] for row in plan] == ["alpha", "beta", "gamma", "alpha"]
    assert [(row["method"], row["round"]) for row in plan] == [
        ("server", 1),
        ("kad", 1),
        ("server", 2),
        ("kad", 2),
    ]
    assert module.summarize_search_plan(plan) == [
        {"scenario": "server-search-round-1", "method": "server", "round": 1, "query_index": 0, "query_count": 3},
        {"scenario": "kad-search-round-1", "method": "kad", "round": 1, "query_index": 1, "query_count": 3},
        {"scenario": "server-search-round-2", "method": "server", "round": 2, "query_index": 2, "query_count": 3},
        {"scenario": "kad-search-round-2", "method": "kad", "round": 2, "query_index": 0, "query_count": 3},
    ]
    assert "alpha" not in repr(module.summarize_search_plan(plan))


def test_build_search_plan_rejects_empty_terms_and_rounds() -> None:
    module = load_search_ui_module()

    for terms, rounds in (((), 1), (("alpha",), 0)):
        try:
            module.build_search_plan(terms, rounds)
        except ValueError:
            continue
        raise AssertionError("invalid Search UI live plan was accepted")


def test_is_safe_ui_download_candidate_rejects_executables_video_and_bad_hash() -> None:
    module = load_search_ui_module()
    base = {
        "name": "ubuntu.iso",
        "size": "4.5 GB",
        "file_type": "CD-Image",
        "hash": "0123456789abcdef0123456789abcdef",
    }

    assert module.is_safe_ui_download_candidate(base)
    assert not module.is_safe_ui_download_candidate({**base, "name": "setup.exe"})
    assert not module.is_safe_ui_download_candidate({**base, "file_type": "Video"})
    assert not module.is_safe_ui_download_candidate({**base, "hash": "not-a-hash"})
    assert not module.is_safe_ui_download_candidate({**base, "size": "40 GB"})


def test_request_transfer_operation_posts_native_lifecycle_route(monkeypatch) -> None:
    module = load_search_ui_module()
    calls = []

    class FakeRestSmoke:
        @staticmethod
        def http_request(base_url: str, path: str, **kwargs):
            calls.append((base_url, path, kwargs))
            return {"status": 200, "content_type": "application/json", "json": {"ok": True}, "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}}}

        @staticmethod
        def require_json_object(result: dict, expected_status: int):
            assert result["status"] == expected_status
            return result["json"]

        @staticmethod
        def compact_http_result(result: dict):
            return {"status": result["status"], "json": result["json"]}

    monkeypatch.setattr(module, "rest_smoke", FakeRestSmoke)

    assert module.request_transfer_operation("http://127.0.0.1:1", "key", "abc", "pause") == {
        "status": 200,
        "json": {"ok": True},
    }
    assert calls == [
        (
            "http://127.0.0.1:1",
            "/api/v1/transfers/abc/operations/pause",
            {
                "method": "POST",
                "api_key": "key",
                "json_body": {},
                "request_timeout_seconds": 30.0,
            },
        )
    ]


def test_delete_transfer_uses_native_partial_file_cleanup(monkeypatch) -> None:
    module = load_search_ui_module()
    calls = []

    class FakeRestSmoke:
        @staticmethod
        def http_request(base_url: str, path: str, **kwargs):
            calls.append((base_url, path, kwargs))
            return {"status": 200, "content_type": "application/json", "json": {"removed": True}, "raw_json": {"data": {"removed": True}, "meta": {"apiVersion": "v1"}}}

        @staticmethod
        def require_json_object(result: dict, expected_status: int):
            assert result["status"] == expected_status
            return result["json"]

        @staticmethod
        def compact_http_result(result: dict):
            return {"status": result["status"], "json": result["json"]}

    monkeypatch.setattr(module, "rest_smoke", FakeRestSmoke)

    assert module.delete_transfer("http://127.0.0.1:1", "key", "abc") == {
        "status": 200,
        "json": {"removed": True},
    }
    assert calls == [
        (
            "http://127.0.0.1:1",
            "/api/v1/transfers/abc/files?confirm=true",
            {
                "method": "DELETE",
                "api_key": "key",
                "request_timeout_seconds": 30.0,
            },
        )
    ]


def test_require_transfer_hash_success_rejects_failed_bulk_item() -> None:
    module = load_search_ui_module()

    module.require_transfer_hash_success({"items": [{"hash": "abc", "ok": True}]}, "abc")
    try:
        module.require_transfer_hash_success({"items": [{"hash": "abc", "ok": False}]}, "abc")
    except AssertionError:
        return
    raise AssertionError("failed transfer lifecycle bulk item was accepted")


def test_capture_network_state_records_status_kad_and_servers(monkeypatch) -> None:
    module = load_search_ui_module()
    requests = []

    class FakeRestSmoke:
        @staticmethod
        def http_request(base_url: str, path: str, **kwargs):
            requests.append((base_url, path, kwargs))
            return {"status": 200, "content_type": "application/json", "json": {"path": path}}

        @staticmethod
        def compact_http_result(result: dict):
            return {"status": result["status"], "json": result["json"]}

    monkeypatch.setattr(module, "rest_smoke", FakeRestSmoke)

    assert module.capture_network_state("http://127.0.0.1:1", "key") == {
        "status": {"status": 200, "json": {"path": "/api/v1/status"}},
        "kad": {"status": 200, "json": {"path": "/api/v1/kad"}},
        "servers": {"status": 200, "json": {"path": "/api/v1/servers"}},
    }
    assert [request[1] for request in requests] == [
        "/api/v1/status",
        "/api/v1/kad",
        "/api/v1/servers",
    ]
    assert all(request[2]["api_key"] == "key" for request in requests)
