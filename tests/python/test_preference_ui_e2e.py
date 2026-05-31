from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "preference-ui-e2e.py"
    spec = importlib.util.spec_from_file_location("preference_ui_e2e_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("win32"):
            pytest.skip(f"pywin32 live harness dependency is unavailable: {exc.name}")
        raise
    return module


class FakeImage:
    def __init__(self, output: list[Path]) -> None:
        self.output = output

    def save(self, path: Path) -> None:
        self.output.append(path)


class FakeWindow:
    def __init__(self, failures: int, output: list[Path]) -> None:
        self.failures = failures
        self.output = output

    def capture_as_image(self) -> FakeImage:
        if self.failures > 0:
            self.failures -= 1
            raise OSError("screen grab failed")
        return FakeImage(self.output)


class FakeApp:
    def __init__(self, failures: int) -> None:
        self.output: list[Path] = []
        self.fake_window = FakeWindow(failures, self.output)

    def window(self, *, handle: int) -> FakeWindow:
        assert handle == 123
        return self.fake_window


def test_capture_dialog_screenshot_retries_transient_screen_grab_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_script_module()
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    app = FakeApp(failures=1)
    output_path = tmp_path / "web-interface.png"

    result = module.capture_dialog_screenshot(app, 123, output_path)

    assert result == {"status": "captured", "path": str(output_path), "attempt": 2}
    assert app.output == [output_path]


def test_capture_dialog_screenshot_records_persistent_screen_grab_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = load_script_module()
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    output_path = tmp_path / "web-interface.png"

    result = module.capture_dialog_screenshot(FakeApp(failures=3), 123, output_path)

    assert result["status"] == "unavailable"
    assert result["path"] == str(output_path)
    assert result["attempts"] == 3
    assert result["error"] == {"type": "OSError", "message": "screen grab failed"}


def test_wait_for_preferences_dialog_requires_page_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script_module()

    def enum_windows(callback, lparam) -> None:
        callback(100, lparam)
        callback(200, lparam)

    monkeypatch.setattr(module.win32gui, "EnumWindows", enum_windows)
    monkeypatch.setattr(module.win32gui, "IsWindowVisible", lambda hwnd: True)
    monkeypatch.setattr(module.win32gui, "GetClassName", lambda hwnd: "#32770")
    monkeypatch.setattr(module.win32process, "GetWindowThreadProcessId", lambda hwnd: (1, 4321))
    monkeypatch.setattr(module.win32gui, "GetWindowText", lambda hwnd: "Preferences" if hwnd == 100 else "Other dialog")
    monkeypatch.setattr(module, "find_child_control", lambda hwnd, control_id, class_name=None: 300 if hwnd == 200 else None)
    monkeypatch.setattr(module, "wait_for", lambda resolve, **_kwargs: resolve())

    assert module.wait_for_preferences_dialog(4321, 999) == 200
