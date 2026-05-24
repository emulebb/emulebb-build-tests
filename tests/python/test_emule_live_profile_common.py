from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_live_common_module():
    """Loads the hyphenated shared live-profile helper for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "emule-live-profile-common.py"
    spec = importlib.util.spec_from_file_location("emule_live_profile_common_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_close_app_cleanly_kills_test_process_without_top_window(monkeypatch) -> None:
    module = load_live_common_module()
    calls: list[object] = []

    class FakeApp:
        def process(self) -> int:
            return 1234

        def top_window(self):
            raise RuntimeError("No windows for that process could be found")

        def kill(self, *, soft: bool) -> None:
            calls.append(("kill", soft))

    exited_results = iter((False, True))

    def fake_is_process_exited(process_id: int) -> bool:
        calls.append(("exited", process_id))
        return next(exited_results)

    monkeypatch.setattr(module, "_is_process_exited", fake_is_process_exited)
    monkeypatch.setattr(module, "win32api", object())
    monkeypatch.setattr(module, "win32event", object())

    module.close_app_cleanly(FakeApp(), process_timeout=0.1)

    assert calls == [("exited", 1234), ("kill", False), ("exited", 1234)]


def test_launch_app_rejects_interactive_minimized_conflict(tmp_path: Path) -> None:
    module = load_live_common_module()

    try:
        module.launch_app(
            tmp_path / "emulebb.exe",
            tmp_path / "profile-base",
            minimized_to_tray=True,
            requires_interactive_ui=True,
        )
    except ValueError as exc:
        assert "Interactive UI" in str(exc)
    else:
        raise AssertionError("Expected interactive minimized-to-tray launch conflict to fail.")


def test_launch_app_appends_extra_arguments(monkeypatch, tmp_path: Path) -> None:
    module = load_live_common_module()
    commands: list[str] = []

    class FakeApplication:
        def __init__(self, backend: str) -> None:
            assert backend == "win32"

        def start(self, command_line: str, wait_for_idle: bool):
            assert wait_for_idle is False
            commands.append(command_line)
            return self

    monkeypatch.setattr(module, "require_pywinauto", lambda: None)
    monkeypatch.setattr(module, "Application", FakeApplication)

    module.launch_app(
        tmp_path / "emulebb.exe",
        tmp_path / "profile-base",
        minimized_to_tray=False,
        extra_args=["--sharefile", str(tmp_path / "shared.bin")],
    )

    assert "--sharefile" in commands[0]
    assert str(tmp_path / "shared.bin") in commands[0]


def test_main_window_detection_accepts_runtime_speed_prefix(monkeypatch) -> None:
    module = load_live_common_module()

    monkeypatch.setattr(module.win32gui, "GetClassName", lambda hwnd: "#32770")
    monkeypatch.setattr(
        module.win32gui,
        "GetWindowText",
        lambda hwnd: "(U:0.0 D:0.0) eMuleBB 0.7.3 x64",
    )

    assert module.is_main_emule_window(1001)


def test_main_window_detection_accepts_tracing_harness_title(monkeypatch) -> None:
    module = load_live_common_module()

    monkeypatch.setattr(module.win32gui, "GetClassName", lambda hwnd: "#32770")
    monkeypatch.setattr(module.win32gui, "GetWindowText", lambda hwnd: "eMule harness v0.72a x64")

    assert module.is_main_emule_window(1002)


def test_main_window_detection_rejects_generic_startup_dialog(monkeypatch) -> None:
    module = load_live_common_module()

    monkeypatch.setattr(module.win32gui, "GetClassName", lambda hwnd: "#32770")
    monkeypatch.setattr(module.win32gui, "GetWindowText", lambda hwnd: "eMule")

    assert not module.is_main_emule_window(1003)


def test_find_process_main_window_enumerates_hidden_top_level_dialog(monkeypatch) -> None:
    module = load_live_common_module()

    class FakeWindowSpec:
        def __init__(self, handle: int) -> None:
            self.handle = handle

        def wrapper_object(self):
            return self

    class FakeApp:
        def process(self) -> int:
            return 4321

        def window(self, *, handle: int):
            return FakeWindowSpec(handle)

    def fake_enum_windows(callback, lparam) -> None:
        callback(2001, lparam)
        callback(2002, lparam)

    monkeypatch.setattr(module.win32gui, "EnumWindows", fake_enum_windows)
    monkeypatch.setattr(
        module.win32process,
        "GetWindowThreadProcessId",
        lambda hwnd: (99, 4321 if hwnd == 2002 else 1234),
    )
    monkeypatch.setattr(module.win32gui, "GetClassName", lambda hwnd: "#32770")
    monkeypatch.setattr(
        module.win32gui,
        "GetWindowText",
        lambda hwnd: "(U:0.0 D:0.0) eMuleBB 0.7.3 x64",
    )
    monkeypatch.setattr(module.win32gui, "IsWindowVisible", lambda hwnd: False)

    window = module.find_process_main_window(FakeApp())

    assert window.handle == 2002
    assert module.find_process_main_window(FakeApp(), require_visible=True) is None


def test_find_app_main_window_scans_pywinauto_window_list(monkeypatch) -> None:
    module = load_live_common_module()

    class FakeWindow:
        def __init__(self, handle: int, visible: bool) -> None:
            self.handle = handle
            self._visible = visible

        def is_visible(self) -> bool:
            return self._visible

    class FakeApp:
        def windows(self):
            return [FakeWindow(3001, True), FakeWindow(3002, False)]

    def fake_title(hwnd: int) -> str:
        if hwnd == 3002:
            return "(U:0.0 D:0.0) eMuleBB 0.7.3 x64"
        return "Socket Notification Sink"

    monkeypatch.setattr(module.win32gui, "GetClassName", lambda hwnd: "#32770")
    monkeypatch.setattr(module.win32gui, "GetWindowText", fake_title)

    window = module.find_app_main_window(FakeApp())

    assert window.handle == 3002
    assert module.find_app_main_window(FakeApp(), require_visible=True) is None
