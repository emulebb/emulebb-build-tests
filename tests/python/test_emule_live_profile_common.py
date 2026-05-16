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
