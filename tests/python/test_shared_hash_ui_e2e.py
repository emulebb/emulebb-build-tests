from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def load_shared_hash_module():
    """Loads the hyphenated shared-hash script when Win32 UI helpers are available."""

    pytest.importorskip("win32api")
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "shared-hash-ui-e2e.py"
    spec = importlib.util.spec_from_file_location("shared_hash_ui_e2e_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["shared_hash_ui_e2e_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def write_startup_trace(path: Path, events: list[dict[str, object]]) -> None:
    """Writes one compact Chrome Trace payload for startup-profile parser tests."""

    path.write_text(json.dumps({"traceEvents": events}), encoding="utf-8")


def counter_event(timestamp_us: int, counter_id: str, value_key: str, value: int) -> dict[str, object]:
    """Builds one Chrome Trace counter event with the stable counter id shape."""

    return {
        "name": counter_id,
        "ph": "C",
        "ts": timestamp_us,
        "args": {
            "counter_id": counter_id,
            value_key: value,
        },
    }


def phase_event(timestamp_us: int, phase_id: str) -> dict[str, object]:
    """Builds one Chrome Trace instant phase event with a stable phase id."""

    return {
        "name": phase_id,
        "ph": "i",
        "ts": timestamp_us,
        "args": {
            "phase_id": phase_id,
        },
    }


def test_partial_hash_progress_uses_trace_counters(tmp_path: Path) -> None:
    module = load_shared_hash_module()
    trace_path = tmp_path / "startup-profile.trace.json"
    write_startup_trace(
        trace_path,
        [
            counter_event(1000, "shared.hash.completed_files", "files", 1),
            counter_event(1001, "shared.hash.waiting_queue_depth", "files", 2),
            counter_event(1002, "shared.hash.currently_hashing", "files", 1),
        ],
    )

    summary = module.wait_for_partial_hash_progress(trace_path, expected_count=3, timeout=0.1)

    assert summary == {
        "completed_files": 1,
        "expected_count": 3,
        "waiting_queue_depth": 2,
        "currently_hashing": 1,
        "hashing_done_observed": False,
    }


def test_write_json_recreates_parent_directory(tmp_path: Path) -> None:
    module = load_shared_hash_module()
    result_path = tmp_path / "missing-scenario" / "result.json"

    module.write_json(result_path, {"status": "failed"})

    assert result_path.is_file()
    assert json.loads(result_path.read_text(encoding="utf-8")) == {"status": "failed"}


def test_partial_hash_progress_rejects_completed_hashing(tmp_path: Path) -> None:
    module = load_shared_hash_module()
    trace_path = tmp_path / "startup-profile.trace.json"
    write_startup_trace(
        trace_path,
        [
            counter_event(1000, "shared.hash.completed_files", "files", 3),
            phase_event(1001, module.live_common.STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID),
        ],
    )

    with pytest.raises(RuntimeError, match="Hashing completed"):
        module.wait_for_partial_hash_progress(trace_path, expected_count=3, timeout=0.1)


def test_shared_hash_drain_accepts_completed_worker_counters(tmp_path: Path) -> None:
    module = load_shared_hash_module()
    trace_path = tmp_path / "startup-profile.trace.json"
    write_startup_trace(
        trace_path,
        [
            counter_event(1000, "shared.hash.completed_files", "files", 3),
            counter_event(1001, "shared.hash.waiting_queue_depth", "files", 0),
            counter_event(1002, "shared.hash.currently_hashing", "files", 0),
        ],
    )

    summary = module.wait_for_shared_hash_drain(trace_path, expected_count=3, timeout=0.1)

    assert summary["completed_files"] == 3
    assert summary["waiting_queue_depth"] == 0
    assert summary["currently_hashing"] == 0
    assert summary["hashing_done_observed"] is False


def test_shared_hash_drain_rejects_hashing_done_with_short_rows(tmp_path: Path) -> None:
    module = load_shared_hash_module()
    trace_path = tmp_path / "startup-profile.trace.json"
    write_startup_trace(
        trace_path,
        [
            counter_event(1000, "shared.model.hashing_done_shared_files", "files", 2),
            counter_event(1001, "shared.model.hashing_done_visible_rows", "rows", 2),
            phase_event(1002, module.live_common.STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID),
        ],
    )

    with pytest.raises(RuntimeError, match="reported completion before the expected rows"):
        module.wait_for_shared_hash_drain(trace_path, expected_count=3, timeout=0.1)


def test_apply_live_network_policy_sets_bind_interface_and_upnp(tmp_path: Path) -> None:
    module = load_shared_hash_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    module.live_common.write_utf16_ini_text(preferences_path, "[eMule]\r\nNick=CodexE2E\r\n")

    module.live_common.apply_live_network_policy(config_dir)

    assert preferences_path.read_bytes().startswith(b"\xff\xfe")
    text = module.live_common.read_ini_text(preferences_path)
    assert "BindInterface=hide.me" in text
    assert "BindAddr=" in text
    assert "BlockNetworkWhenBindUnavailableAtStartup=1" in text
    assert "[UPnP]" in text
    assert "EnableUPnP=1" in text
    assert "CloseUPnPOnExit=0" in text


def test_launch_app_with_fresh_startup_trace_removes_stale_trace(monkeypatch, tmp_path: Path) -> None:
    module = load_shared_hash_module()
    profile_base = tmp_path / "profile-base"
    config_dir = profile_base / "config"
    config_dir.mkdir(parents=True)
    trace_path = config_dir / "startup-profile.trace.json"
    trace_path.write_text('{"traceEvents":[]}', encoding="utf-8")
    launched: list[Path] = []

    def launch_app(app_exe: Path, launched_profile_base: Path, *, minimized_to_tray: bool = True) -> object:
        launched.append(launched_profile_base)
        assert minimized_to_tray is False
        assert not trace_path.exists()
        return {"app": str(app_exe)}

    monkeypatch.setattr(module.live_common, "launch_app", launch_app)

    app = module.launch_app_with_fresh_startup_trace(
        tmp_path / "emule.exe",
        {
            "profile_base": profile_base,
            "startup_profile_path": trace_path,
        },
    )

    assert app == {"app": str(tmp_path / "emule.exe")}
    assert launched == [profile_base]


def test_deferred_hashing_boundary_allows_startup_complete_jitter() -> None:
    module = load_shared_hash_module()
    live_common = module.live_common
    phases = [
        {
            "phase_id": live_common.STARTUP_PROFILE_DEFERRED_SHARED_HASHING_START_PHASE_ID,
            "absolute_us": 1_000_000,
        },
        {
            "phase_id": live_common.STARTUP_PROFILE_COMPLETE_PHASE_ID,
            "absolute_us": 1_080_000,
        },
    ]

    live_common.enforce_deferred_shared_hashing_boundary(phases, "jitter")


def test_deferred_hashing_boundary_rejects_large_startup_lead() -> None:
    module = load_shared_hash_module()
    live_common = module.live_common
    phases = [
        {
            "phase_id": live_common.STARTUP_PROFILE_DEFERRED_SHARED_HASHING_START_PHASE_ID,
            "absolute_us": 1_000_000,
        },
        {
            "phase_id": live_common.STARTUP_PROFILE_COMPLETE_PHASE_ID,
            "absolute_us": 1_300_000,
        },
    ]

    with pytest.raises(RuntimeError, match="300.000 ms before startup.complete"):
        live_common.enforce_deferred_shared_hashing_boundary(phases, "large-lead")


def test_shared_hash_snapshot_does_not_require_details_static(monkeypatch) -> None:
    module = load_shared_hash_module()
    opened_pages: list[int] = []

    def open_list_page(main_hwnd: int) -> int:
        opened_pages.append(main_hwnd)
        return 1234

    def send_message(hwnd: int, message: int, wparam: int, lparam: int) -> int:
        assert hwnd == 1234
        assert message == module.shared_files_ui.LVM_GETITEMCOUNT
        assert wparam == 0
        assert lparam == 0
        return 7

    monkeypatch.setattr(module.shared_files_ui, "open_shared_files_list_page", open_list_page)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(module.win32gui, "SendMessage", send_message)

    assert module.open_shared_files_page_snapshot(5678) == {"row_count": 7}
    assert opened_pages == [5678]
