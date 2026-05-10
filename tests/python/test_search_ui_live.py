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
