"""Shared helpers for deterministic live-profile eMule harness runs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import win32con
import win32api
import win32event
import win32gui
import win32process

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.ini import (
    patch_ini_value,
    read_ini_text,
    upsert_ini_section_value,
    write_utf16_ini_text,
)
from emule_test_harness import windows_processes
from emule_test_harness.live_profiles import (
    DEFAULT_P2P_BIND_INTERFACE_NAME,
    DEFAULT_WINDOW_RECT,
    PREFERENCES_DAT_VERSION,
    PRIVATE_HARNESS_RATE_LIMIT_BITS_PER_SEC,
    PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC,
    STARTUP_PROFILE_TRACE_FILE_NAME,
    WINDOW_PLACEMENT_LENGTH,
    WINDOW_SHOW_MAXIMIZED,
    LiveNetworkProfileSpec,
    PrivateHarnessProfileSpec,
    ProfileBuildSpec,
    WebServerProfileSpec,
    apply_emule_preferences,
    apply_private_harness_obfuscation,
    apply_live_network_policy,
    apply_live_network_profile,
    apply_minimized_to_tray_startup,
    apply_section_preferences,
    apply_webserver_profile,
    build_profile_base,
    materialize_private_harness_profile,
    prepare_profile_base,
    prepare_scenario_profile,
    win_path,
    write_preferences_dat,
    write_shared_directories_file,
)

try:
    from pywinauto import Application
    _PYWINAUTO_IMPORT_ERROR = None
except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
    Application = None  # type: ignore[assignment]
    _PYWINAUTO_IMPORT_ERROR = exc

WINDOWS_DIRECTORY_PATH_LIMIT = 248
WINDOWS_PATH_LIMIT = 260
PATH_SAMPLE_LIMIT = 5
MAIN_WINDOW_TITLE_PREFIXES = ("eMule v", "eMuleBB", "eMule harness v")
MAIN_WINDOW_TITLE_MARKERS = (" eMule v", " eMuleBB", " eMule harness v")
STARTUP_PROFILE_COMPLETE_PHASE_ID = "startup.complete"
STARTUP_PROFILE_COMPLETE_PHASE_NAME = "StartupTimer complete"
STARTUP_PROFILE_SHARED_SCAN_COMPLETE_PHASE_ID = "shared.scan.complete"
STARTUP_PROFILE_SHARED_TREE_POPULATED_PHASE_ID = "shared.tree.populated"
STARTUP_PROFILE_SHARED_MODEL_POPULATED_PHASE_ID = "shared.model.populated"
STARTUP_PROFILE_SHARED_FILES_READY_PHASE_ID = "ui.shared_files_ready"
STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID = "ui.shared_files_hashing_done"
STARTUP_PROFILE_SHARED_LIST_RELOAD_PHASE_NAME = "CSharedFilesCtrl::ReloadFileList total"
STARTUP_PROFILE_DEFERRED_SHARED_HASHING_START_PHASE_ID = "shared.hashing.deferred_start"
STARTUP_PROFILE_DEFERRED_SHARED_HASHING_MAX_LEAD_MS = 250.0
STARTUP_PROFILE_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN = 1

def require_pywinauto() -> None:
    """Raises one actionable error when the live/UI runtime dependency is missing."""

    if _PYWINAUTO_IMPORT_ERROR is not None:
        raise RuntimeError(
            "pywinauto is required for the live/UI harness scripts. "
            "Install it with 'python -m pip install pywinauto'."
        ) from _PYWINAUTO_IMPORT_ERROR


def write_json(path: Path, payload) -> None:
    """Writes a UTF-8 JSON artifact with stable formatting."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def should_exclude_walk_dir(dir_name: str, excluded_dir_prefixes: tuple[str, ...]) -> bool:
    """Reports whether one child directory should be pruned from a harness walk."""

    lowered_name = dir_name.lower()
    return any(lowered_name.startswith(prefix.lower()) for prefix in excluded_dir_prefixes)


def prune_walk_dirs(dir_names: list[str], excluded_dir_prefixes: tuple[str, ...]) -> None:
    """Sorts and prunes os.walk child directories in-place."""

    if excluded_dir_prefixes:
        dir_names[:] = [name for name in dir_names if not should_exclude_walk_dir(name, excluded_dir_prefixes)]
    dir_names.sort(key=str.lower)


def enumerate_recursive_directories(root: Path, excluded_dir_prefixes: tuple[str, ...] = ()) -> list[str]:
    """Returns one deterministic shared-directory list for a recursively shared root."""

    resolved_root = root.resolve()
    directories: list[str] = []
    for current_root, dir_names, _ in os.walk(resolved_root):
        prune_walk_dirs(dir_names, excluded_dir_prefixes)
        directories.append(win_path(Path(current_root), trailing_slash=True))
    return directories


def summarize_shared_directories(shared_dirs: list[str]) -> dict[str, object]:
    """Summarizes the shareddir.dat payload written for one live-profile run."""

    if not shared_dirs:
        return {
            "count": 0,
            "max_path_length": 0,
            "min_path_length": 0,
            "average_path_length": 0.0,
            "entries_over_248_chars": 0,
            "entries_over_260_chars": 0,
            "longest_entries": [],
        }

    lengths = [len(entry) for entry in shared_dirs]
    ranked = sorted(shared_dirs, key=lambda entry: (-len(entry), entry.lower()))
    return {
        "count": len(shared_dirs),
        "max_path_length": max(lengths),
        "min_path_length": min(lengths),
        "average_path_length": round(sum(lengths) / len(lengths), 2),
        "entries_over_248_chars": sum(1 for length in lengths if length > WINDOWS_DIRECTORY_PATH_LIMIT),
        "entries_over_260_chars": sum(1 for length in lengths if length > WINDOWS_PATH_LIMIT),
        "longest_entries": [
            {
                "path": entry,
                "length": len(entry),
            }
            for entry in ranked[:PATH_SAMPLE_LIMIT]
        ],
    }


def summarize_existing_tree(root: Path, excluded_dir_prefixes: tuple[str, ...] = ()) -> dict[str, object]:
    """Summarizes an existing filesystem tree for startup-profile reporting."""

    resolved_root = root.resolve()
    directories = [resolved_root]
    files: list[Path] = []
    for current_root, dir_names, file_names in os.walk(resolved_root):
        prune_walk_dirs(dir_names, excluded_dir_prefixes)
        current_path = Path(current_root)
        directories.extend(current_path / dir_name for dir_name in dir_names)
        files.extend(current_path / file_name for file_name in file_names)

    directory_rows = [
        {
            "path": win_path(path),
            "depth": len(path.relative_to(resolved_root).parts),
        }
        for path in directories
    ]
    file_rows = [{"path": win_path(path)} for path in files]
    directory_lengths = [len(row["path"]) for row in directory_rows]
    file_lengths = [len(row["path"]) for row in file_rows]
    longest_directories = sorted(directory_rows, key=lambda row: (-len(str(row["path"])), str(row["path"]).lower()))
    deepest_directories = sorted(
        directory_rows,
        key=lambda row: (-int(row["depth"]), -len(str(row["path"])), str(row["path"]).lower()),
    )
    longest_files = sorted(file_rows, key=lambda row: (-len(str(row["path"])), str(row["path"]).lower()))
    return {
        "root": win_path(resolved_root, trailing_slash=True),
        "directory_count_including_root": len(directories),
        "file_count": len(files),
        "max_directory_depth": max((int(row["depth"]) for row in directory_rows), default=0),
        "max_directory_path_length": max(directory_lengths, default=0),
        "max_file_path_length": max(file_lengths, default=0),
        "directories_over_248_chars": sum(1 for length in directory_lengths if length > WINDOWS_DIRECTORY_PATH_LIMIT),
        "directories_over_260_chars": sum(1 for length in directory_lengths if length > WINDOWS_PATH_LIMIT),
        "files_over_260_chars": sum(1 for length in file_lengths if length > WINDOWS_PATH_LIMIT),
        "longest_directories": [
            {
                "path": str(row["path"]),
                "length": len(str(row["path"])),
                "depth": int(row["depth"]),
            }
            for row in longest_directories[:PATH_SAMPLE_LIMIT]
        ],
        "deepest_directories": [
            {
                "path": str(row["path"]),
                "length": len(str(row["path"])),
                "depth": int(row["depth"]),
            }
            for row in deepest_directories[:PATH_SAMPLE_LIMIT]
        ],
        "longest_files": [
            {
                "path": str(row["path"]),
                "length": len(str(row["path"])),
            }
            for row in longest_files[:PATH_SAMPLE_LIMIT]
        ],
    }


def wait_for(predicate, timeout: float, interval: float, description: str):
    """Polls until the predicate returns a truthy value or raises on timeout."""

    deadline = time.time() + timeout
    last_value = None
    while time.time() < deadline:
        try:
            last_value = predicate()
        except Exception as exc:
            last_value = f"{type(exc).__name__}: {exc}"
            time.sleep(interval)
            continue
        if last_value:
            return last_value
        time.sleep(interval)
    raise RuntimeError(f"Timed out waiting for {description}. Last value: {last_value!r}")


def launch_app(
    app_exe: Path,
    profile_base: Path,
    *,
    minimized_to_tray: bool = True,
    requires_interactive_ui: bool = False,
    extra_args: list[str] | tuple[str, ...] = (),
) -> Application:
    """Starts the real app with the isolated `-c` override and startup profiling enabled."""

    if minimized_to_tray and requires_interactive_ui:
        raise ValueError("Interactive UI launches must not request minimized-to-tray startup.")
    require_pywinauto()
    if minimized_to_tray:
        apply_minimized_to_tray_startup(profile_base / "config")
    os.environ["EMULE_STARTUP_PROFILE"] = "1"
    command_line = subprocess.list2cmdline(
        [str(app_exe), "-ignoreinstances", "-c", str(profile_base), *extra_args]
    )
    app = Application(backend="win32").start(command_line, wait_for_idle=False)
    setattr(app, "_emulebb_profile_base", str(profile_base))
    setattr(app, "_emulebb_command_line", command_line)
    try:
        process_id = resolve_app_process_id(app)
        creation_date = windows_processes.process_creation_date(process_id) if process_id is not None else ""
        setattr(app, "_emulebb_process_creation_date", creation_date)
    except Exception:
        setattr(app, "_emulebb_process_creation_date", "")
    return app


def is_main_emule_window(hwnd: int) -> bool:
    """Reports whether one visible top-level window is the real main eMule dialog."""

    title = win32gui.GetWindowText(hwnd)
    if win32gui.GetClassName(hwnd) != "#32770":
        return False
    return title.startswith(MAIN_WINDOW_TITLE_PREFIXES) or any(
        marker in title for marker in MAIN_WINDOW_TITLE_MARKERS
    )


def find_process_main_window(app: Application, *, require_visible: bool = False):
    """Finds the launched eMule main window by enumerating process top-level windows."""

    try:
        process_id = int(app.process())
    except Exception:
        return None

    matches: list[int] = []

    def collect(hwnd: int, _lparam: int) -> bool:
        try:
            _, hwnd_process_id = win32process.GetWindowThreadProcessId(hwnd)
            if int(hwnd_process_id) != process_id:
                return True
            if require_visible and not win32gui.IsWindowVisible(hwnd):
                return True
            if is_main_emule_window(hwnd):
                matches.append(hwnd)
        except Exception:
            return True
        return True

    win32gui.EnumWindows(collect, 0)
    if not matches:
        return None
    return app.window(handle=matches[0]).wrapper_object()


def find_app_main_window(app: Application, *, require_visible: bool = False):
    """Finds the eMule main window from pywinauto's process window list."""

    try:
        windows = app.windows()
    except Exception:
        return None
    for window in windows:
        try:
            hwnd = int(window.handle)
            if require_visible and not window.is_visible():
                continue
            if is_main_emule_window(hwnd):
                return window
        except Exception:
            continue
    return None


def describe_startup_dialog(hwnd: int) -> str:
    """Collects one top-level modal dialog description for failure reporting."""

    dialog_texts = []
    child = win32gui.GetWindow(hwnd, win32con.GW_CHILD)
    while child:
        if win32gui.GetClassName(child) == "Static":
            dialog_texts.append(win32gui.GetWindowText(child))
        child = win32gui.GetWindow(child, win32con.GW_HWNDNEXT)
    return "\n".join(filter(None, dialog_texts)).strip()


def is_expected_shutdown_progress_dialog(hwnd: int) -> bool:
    """Reports whether one top-level dialog is the normal eMule shutdown progress window."""

    if win32gui.GetClassName(hwnd) != "#32770":
        return False
    title = win32gui.GetWindowText(hwnd)
    body = describe_startup_dialog(hwnd)
    return title == "Shutting down eMule" or "eMule is shutting down" in body


def wait_for_main_window(app: Application, *, timeout: float = 90.0, require_visible: bool = False):
    """Waits until the started eMule process exposes its main top-level window."""

    def resolve():
        try:
            window = app.top_window()
        except Exception:
            window = None
        if window is not None and window.handle:
            if not (require_visible and not win32gui.IsWindowVisible(window.handle)):
                if is_main_emule_window(window.handle):
                    return window
                if win32gui.GetClassName(window.handle) == "#32770":
                    raise RuntimeError(
                        "Unexpected startup dialog "
                        f"{win32gui.GetWindowText(window.handle)!r}: "
                        f"{describe_startup_dialog(window.handle)!r}"
                    )
        return find_app_main_window(app, require_visible=require_visible) or find_process_main_window(
            app,
            require_visible=require_visible,
        )

    return wait_for(resolve, timeout=timeout, interval=0.5, description="eMule main window")


def get_window_show_cmd(hwnd: int) -> int:
    """Returns the current Win32 show command for one top-level window."""

    return int(win32gui.GetWindowPlacement(hwnd)[1])


def bring_window_to_front(window: object) -> bool:
    """Best-effort foreground preparation for live UI scenarios.

    Windows can reject `SetForegroundWindow` even when the launched eMule window
    is visible and fully usable through direct Win32 messages. This helper keeps
    that focus restriction from masking real scenario assertions while still
    making a normal attempt to restore and foreground the window.
    """

    hwnd = int(getattr(window, "handle", 0) or 0)
    if not hwnd or not win32gui.IsWindow(hwnd):
        return False

    if win32gui.IsIconic(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    else:
        win32gui.ShowWindow(hwnd, win32con.SW_SHOW)

    set_focus = getattr(window, "set_focus", None)
    if callable(set_focus):
        try:
            set_focus()
            return True
        except Exception:
            pass

    try:
        win32gui.BringWindowToTop(hwnd)
    except Exception:
        pass

    try:
        win32gui.SetForegroundWindow(hwnd)
        return True
    except Exception:
        return False


def dump_window_tree(main_hwnd: int, output_path: Path) -> None:
    """Writes a recursive Win32 control dump for failure diagnosis."""

    nodes = []

    def walk(hwnd: int, depth: int) -> None:
        class_name = win32gui.GetClassName(hwnd)
        text = win32gui.GetWindowText(hwnd)
        rect = win32gui.GetWindowRect(hwnd)
        try:
            control_id = win32gui.GetDlgCtrlID(hwnd)
        except win32gui.error:
            control_id = None
        nodes.append(
            {
                "depth": depth,
                "hwnd": hwnd,
                "class_name": class_name,
                "text": text,
                "control_id": control_id,
                "rect": rect,
            }
        )
        child = win32gui.GetWindow(hwnd, win32con.GW_CHILD)
        while child:
            walk(child, depth + 1)
            child = win32gui.GetWindow(child, win32con.GW_HWNDNEXT)

    walk(main_hwnd, 0)
    write_json(output_path, nodes)


def close_app_cleanly(app: Application, window_timeout: float = 30.0, process_timeout: float = 30.0) -> None:
    """Closes the app, rejects blocking shutdown dialogs, and waits for process exit."""

    process_id = resolve_app_process_id(app)
    try:
        main_window = app.top_window()
    except Exception:
        if not process_id or _is_process_exited(int(process_id)):
            return
        _terminate_process_without_window(app, int(process_id), process_timeout)
        return
    win32gui.PostMessage(main_window.handle, win32con.WM_CLOSE, 0, 0)

    def resolve() -> bool:
        try:
            window = app.top_window()
        except Exception:
            return True
        if not window.handle:
            return True
        if is_main_emule_window(window.handle):
            return False
        if is_expected_shutdown_progress_dialog(window.handle):
            return False
        if win32gui.GetClassName(window.handle) == "#32770":
            raise RuntimeError(f"Unexpected shutdown dialog: {describe_startup_dialog(window.handle)!r}")
        return False

    wait_for(resolve, timeout=window_timeout, interval=0.2, description="clean app shutdown")

    if not process_id:
        return

    try:
        process_handle = win32api.OpenProcess(win32con.SYNCHRONIZE, False, int(process_id))
    except Exception:
        return
    try:
        wait_result = win32event.WaitForSingleObject(process_handle, int(process_timeout * 1000))
        if wait_result != win32event.WAIT_OBJECT_0:
            raise RuntimeError(f"Timed out waiting for process {process_id} to exit after window shutdown.")
    finally:
        win32api.CloseHandle(process_handle)


def _is_process_exited(process_id: int) -> bool:
    """Returns whether a process handle is already signaled or inaccessible."""

    try:
        process_handle = win32api.OpenProcess(win32con.SYNCHRONIZE, False, process_id)
    except Exception:
        return True
    try:
        return win32event.WaitForSingleObject(process_handle, 0) == win32event.WAIT_OBJECT_0
    finally:
        win32api.CloseHandle(process_handle)


def resolve_app_process_id(app: Application) -> int | None:
    """Returns the process id tracked by one pywinauto application object."""

    process_id = getattr(app, "process", None)
    if callable(process_id):
        try:
            process_id = process_id()
        except TypeError:
            return None
    if process_id is None:
        return None
    return int(process_id)


def _terminate_process_without_window(app: Application, process_id: int, process_timeout: float) -> None:
    """Stops a test-launched process when no UI window exists to receive WM_CLOSE."""

    profile_base = str(getattr(app, "_emulebb_profile_base", "") or "")
    creation_date = str(getattr(app, "_emulebb_process_creation_date", "") or "")
    if os.name == "nt" and profile_base:
        result = windows_processes.terminate_process_tree(
            process_id,
            timeout_seconds=process_timeout,
            expected_command_line_markers=(profile_base,),
            expected_root_creation_date=creation_date,
        )
        if int(result.get("return_code", 1)) != 0:
            raise RuntimeError(f"Guarded process termination failed for pid {process_id}: {result!r}")
        return

    try:
        app.kill(soft=False)
    except Exception:
        process_handle = win32api.OpenProcess(win32con.SYNCHRONIZE | 0x0001, False, process_id)
        try:
            win32api.TerminateProcess(process_handle, 1)
            wait_result = win32event.WaitForSingleObject(process_handle, int(process_timeout * 1000))
            if wait_result != win32event.WAIT_OBJECT_0:
                raise RuntimeError(f"Timed out waiting for process {process_id} to exit after forced termination.")
        finally:
            win32api.CloseHandle(process_handle)
        return

    if _is_process_exited(process_id):
        return

    try:
        process_handle = win32api.OpenProcess(win32con.SYNCHRONIZE, False, process_id)
    except Exception:
        return
    try:
        wait_result = win32event.WaitForSingleObject(process_handle, int(process_timeout * 1000))
        if wait_result != win32event.WAIT_OBJECT_0:
            raise RuntimeError(f"Timed out waiting for process {process_id} to exit after forced termination.")
    finally:
        win32api.CloseHandle(process_handle)


def load_startup_profile_trace_events(text: str) -> list[dict[str, object]]:
    """Parses one Chrome Trace startup-profile payload and returns its trace-event rows."""

    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError("Startup profile trace payload must be one JSON object.")
    trace_events = payload.get("traceEvents")
    if not isinstance(trace_events, list):
        raise RuntimeError("Startup profile trace payload is missing a traceEvents list.")
    return [event for event in trace_events if isinstance(event, dict)]


def wait_for_startup_profile_complete(startup_profile_path: Path, *, timeout: float = 120.0) -> str:
    """Waits until the finalized Chrome Trace startup profile becomes readable."""

    def resolve():
        if not startup_profile_path.exists():
            return None
        text = startup_profile_path.read_text(encoding="utf-8", errors="ignore")
        trace_events = load_startup_profile_trace_events(text)
        for event in trace_events:
            if str(event.get("name") or "") == STARTUP_PROFILE_COMPLETE_PHASE_NAME:
                return text
            args = event.get("args")
            if isinstance(args, dict) and str(args.get("phase_id") or "") == STARTUP_PROFILE_COMPLETE_PHASE_ID:
                return text
        return None

    return wait_for(resolve, timeout=timeout, interval=0.5, description="startup profile completion")


def startup_profile_has_phase(text: str, phase_id: str) -> bool:
    """Returns whether one startup-profile trace payload contains a stable phase id."""

    for event in load_startup_profile_trace_events(text):
        args = event.get("args")
        if isinstance(args, dict) and str(args.get("phase_id") or "") == phase_id:
            return True
    return False


def wait_for_startup_profile_phase(startup_profile_path: Path, phase_id: str, *, timeout: float = 120.0) -> str:
    """Waits until the startup profile contains one stable phase id and returns the trace text."""

    def resolve():
        if not startup_profile_path.exists():
            return None
        text = startup_profile_path.read_text(encoding="utf-8", errors="ignore")
        return text if startup_profile_has_phase(text, phase_id) else None

    return wait_for(resolve, timeout=timeout, interval=0.5, description=f"startup profile phase {phase_id}")


def parse_startup_profile(text: str) -> list[dict[str, object]]:
    """Parses one Chrome Trace startup-profile payload into structured phase rows."""

    phases: list[dict[str, object]] = []
    for event in load_startup_profile_trace_events(text):
        phase_type = str(event.get("ph") or "")
        if phase_type not in {"X", "i"}:
            continue
        args = event.get("args")
        if not isinstance(args, dict):
            args = {}
        absolute_us = int(event.get("ts", 0) or 0)
        duration_us = int(event.get("dur", 0) or 0)
        phases.append(
            {
                "name": str(event.get("name") or ""),
                "phase_id": str(args.get("phase_id") or ""),
                "category": str(event.get("cat") or ""),
                "event_type": "complete" if phase_type == "X" else "instant",
                "absolute_us": absolute_us,
                "duration_us": duration_us,
                "absolute_ms": round(absolute_us / 1000.0, 3),
                "duration_ms": round(duration_us / 1000.0, 3),
            }
        )
    phases.sort(key=lambda phase: (int(phase["absolute_us"]), str(phase["name"])))
    return phases


def parse_startup_profile_counters(text: str) -> list[dict[str, object]]:
    """Parses one Chrome Trace startup-profile payload into structured counter rows."""

    counters: list[dict[str, object]] = []
    for event in load_startup_profile_trace_events(text):
        if str(event.get("ph") or "") != "C":
            continue
        args = event.get("args")
        if not isinstance(args, dict):
            continue
        values = {
            str(key): value
            for key, value in args.items()
            if key != "counter_id" and isinstance(value, (int, float))
        }
        if not values:
            continue

        absolute_us = int(event.get("ts", 0) or 0)
        value_key, value = next(iter(values.items()))
        counters.append(
            {
                "name": str(event.get("name") or ""),
                "counter_id": str(args.get("counter_id") or event.get("name") or ""),
                "category": str(event.get("cat") or ""),
                "absolute_us": absolute_us,
                "absolute_ms": round(absolute_us / 1000.0, 3),
                "value_key": value_key,
                "value": value,
                "values": values,
            }
        )
    counters.sort(key=lambda counter: (int(counter["absolute_us"]), str(counter["counter_id"])))
    return counters


def summarize_startup_profile(phases: list[dict[str, object]], interesting_names: list[str]) -> dict[str, object]:
    """Extracts highlighted timings for selected phase names from parsed startup-profile rows."""

    by_name = {str(phase["name"]): phase for phase in phases}
    highlights = {}
    for name in interesting_names:
        phase = by_name.get(name)
        if phase is None:
            continue
        highlights[name] = {
            "phase_id": str(phase["phase_id"]),
            "category": str(phase["category"]),
            "event_type": str(phase["event_type"]),
            "absolute_us": int(phase["absolute_us"]),
            "duration_us": int(phase["duration_us"]),
            "absolute_ms": float(phase["absolute_ms"]),
            "duration_ms": float(phase["duration_ms"]),
        }
    return highlights


def get_top_slowest_phases(phases: list[dict[str, object]], limit: int = 10) -> list[dict[str, object]]:
    """Returns the slowest startup-profile phases ordered by descending duration and absolute time."""

    ranked = sorted(
        phases,
        key=lambda phase: (-int(phase["duration_us"]), -int(phase["absolute_us"]), str(phase["name"])),
    )
    return [
        {
            "name": str(phase["name"]),
            "phase_id": str(phase["phase_id"]),
            "category": str(phase["category"]),
            "event_type": str(phase["event_type"]),
            "absolute_us": int(phase["absolute_us"]),
            "duration_us": int(phase["duration_us"]),
            "absolute_ms": float(phase["absolute_ms"]),
            "duration_ms": float(phase["duration_ms"]),
        }
        for phase in ranked[:limit]
    ]


def summarize_startup_profile_counters(counters: list[dict[str, object]]) -> dict[str, object]:
    """Collapses startup-profile counters to the latest value per stable counter id."""

    summarized: dict[str, object] = {}
    for counter in counters:
        entry = {
            "name": str(counter["name"]),
            "category": str(counter["category"]),
            "absolute_us": int(counter["absolute_us"]),
            "absolute_ms": float(counter["absolute_ms"]),
            "value_key": str(counter["value_key"]),
            "value": counter["value"],
            "values": dict(counter["values"]),
        }
        summarized[str(counter["counter_id"])] = entry
    return summarized


def get_phase_by_id(phases: list[dict[str, object]], phase_id: str) -> dict[str, object] | None:
    """Returns the latest parsed phase row for one stable phase id when present."""

    for phase in reversed(phases):
        if str(phase.get("phase_id") or "") == phase_id:
            return phase
    return None


def get_counter_by_id(counters: list[dict[str, object]], counter_id: str) -> dict[str, object] | None:
    """Returns the latest parsed counter row for one stable counter id when present."""

    for counter in reversed(counters):
        if str(counter.get("counter_id") or "") == counter_id:
            return counter
    return None


def count_phases_between(
    phases: list[dict[str, object]],
    phase_name: str,
    start_absolute_us: int,
    end_absolute_us: int | None,
) -> int:
    """Counts named phases that start after one timestamp and before an optional end timestamp."""

    return sum(
        1
        for phase in phases
        if str(phase.get("name") or "") == phase_name
        and int(phase["absolute_us"]) > start_absolute_us
        and (end_absolute_us is None or int(phase["absolute_us"]) <= end_absolute_us)
    )


def summarize_shared_files_readiness(
    phases: list[dict[str, object]],
    counters: list[dict[str, object]],
) -> dict[str, object]:
    """Validates the Shared Files startup-readiness contract and returns compact derived metrics."""

    startup_complete = get_phase_by_id(phases, STARTUP_PROFILE_COMPLETE_PHASE_ID)
    if startup_complete is None:
        raise RuntimeError("Startup profile is missing the startup.complete milestone.")

    shared_scan_complete = get_phase_by_id(phases, STARTUP_PROFILE_SHARED_SCAN_COMPLETE_PHASE_ID)
    if shared_scan_complete is None:
        raise RuntimeError("Startup profile is missing the shared.scan.complete milestone.")

    shared_tree_populated = get_phase_by_id(phases, STARTUP_PROFILE_SHARED_TREE_POPULATED_PHASE_ID)
    if shared_tree_populated is None:
        raise RuntimeError("Startup profile is missing the shared.tree.populated milestone.")

    shared_model_populated = get_phase_by_id(phases, STARTUP_PROFILE_SHARED_MODEL_POPULATED_PHASE_ID)
    if shared_model_populated is None:
        raise RuntimeError("Startup profile is missing the shared.model.populated milestone.")

    shared_files_ready = get_phase_by_id(phases, STARTUP_PROFILE_SHARED_FILES_READY_PHASE_ID)
    if shared_files_ready is None:
        raise RuntimeError("Startup profile is missing the ui.shared_files_ready milestone.")
    if int(shared_files_ready["absolute_us"]) < int(startup_complete["absolute_us"]):
        raise RuntimeError("Startup profile reached ui.shared_files_ready before startup.complete.")

    for phase_id, phase in (
        (STARTUP_PROFILE_SHARED_SCAN_COMPLETE_PHASE_ID, shared_scan_complete),
        (STARTUP_PROFILE_SHARED_TREE_POPULATED_PHASE_ID, shared_tree_populated),
        (STARTUP_PROFILE_SHARED_MODEL_POPULATED_PHASE_ID, shared_model_populated),
    ):
        if int(phase["absolute_us"]) > int(shared_files_ready["absolute_us"]):
            raise RuntimeError(
                f"Startup profile milestone {phase_id} occurs after ui.shared_files_ready."
            )

    pending_hashes_at_readiness = get_counter_by_id(counters, "shared.model.pending_hashes")
    pending_hash_count = int(pending_hashes_at_readiness["value"]) if pending_hashes_at_readiness is not None else 0
    shared_files_hashing_done = get_phase_by_id(phases, STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID)
    if shared_files_hashing_done is not None and int(shared_files_hashing_done["absolute_us"]) < int(shared_files_ready["absolute_us"]):
        raise RuntimeError("Startup profile reached ui.shared_files_hashing_done before ui.shared_files_ready.")
    shared_list_reloads_during_hash_drain = count_phases_between(
        phases,
        STARTUP_PROFILE_SHARED_LIST_RELOAD_PHASE_NAME,
        int(shared_files_ready["absolute_us"]),
        int(shared_files_hashing_done["absolute_us"]) if shared_files_hashing_done is not None else None,
    )
    if (
        pending_hash_count > 0
        and shared_files_hashing_done is not None
        and shared_list_reloads_during_hash_drain > STARTUP_PROFILE_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN
    ):
        raise RuntimeError(
            "Startup profile reloaded the Shared Files list "
            f"{shared_list_reloads_during_hash_drain} times during shared hash drain."
        )

    visible_rows = get_counter_by_id(counters, "shared.model.visible_rows")
    shared_files = get_counter_by_id(counters, "shared.model.shared_files")
    hidden_files = get_counter_by_id(counters, "shared.model.hidden_shared_files")
    active_filter = get_counter_by_id(counters, "shared.model.active_filter")
    hashing_done_visible_rows = get_counter_by_id(counters, "shared.model.hashing_done_visible_rows")
    hashing_done_shared_files = get_counter_by_id(counters, "shared.model.hashing_done_shared_files")

    metrics: dict[str, object] = {
        "shared_files_ready_absolute_ms": float(shared_files_ready["absolute_ms"]),
        "shared_files_ready_after_startup_complete_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(startup_complete["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_scan_to_ready_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(shared_scan_complete["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_tree_to_ready_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(shared_tree_populated["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_model_to_ready_ms": round(
            (int(shared_files_ready["absolute_us"]) - int(shared_model_populated["absolute_us"])) / 1000.0,
            3,
        ),
        "shared_files_hashing_done_observed": 1 if shared_files_hashing_done is not None else 0,
        "shared_list_reloads_during_hash_drain": shared_list_reloads_during_hash_drain,
    }
    if visible_rows is not None:
        metrics["shared_visible_rows_at_readiness"] = int(visible_rows["value"])
    if shared_files is not None:
        metrics["shared_files_at_readiness"] = int(shared_files["value"])
    if hidden_files is not None:
        metrics["shared_hidden_files_at_readiness"] = int(hidden_files["value"])
    if active_filter is not None:
        metrics["shared_active_filter_at_readiness"] = int(active_filter["value"])
    if pending_hashes_at_readiness is not None:
        metrics["shared_pending_hashes_at_readiness"] = pending_hash_count
    if shared_files_hashing_done is not None:
        metrics["shared_files_hashing_done_absolute_ms"] = float(shared_files_hashing_done["absolute_ms"])
        metrics["shared_files_hashing_done_after_ready_ms"] = round(
            (int(shared_files_hashing_done["absolute_us"]) - int(shared_files_ready["absolute_us"])) / 1000.0,
            3,
        )
    if hashing_done_visible_rows is not None:
        metrics["shared_visible_rows_at_hashing_done"] = int(hashing_done_visible_rows["value"])
    if hashing_done_shared_files is not None:
        metrics["shared_files_at_hashing_done"] = int(hashing_done_shared_files["value"])

    return {
        "phases": {
            "startup.complete": dict(startup_complete),
            STARTUP_PROFILE_SHARED_SCAN_COMPLETE_PHASE_ID: dict(shared_scan_complete),
            STARTUP_PROFILE_SHARED_TREE_POPULATED_PHASE_ID: dict(shared_tree_populated),
            STARTUP_PROFILE_SHARED_MODEL_POPULATED_PHASE_ID: dict(shared_model_populated),
            STARTUP_PROFILE_SHARED_FILES_READY_PHASE_ID: dict(shared_files_ready),
            STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID: dict(shared_files_hashing_done) if shared_files_hashing_done is not None else None,
        },
        "counters": {
            "shared.model.pending_hashes": dict(pending_hashes_at_readiness) if pending_hashes_at_readiness is not None else None,
            "shared.model.visible_rows": dict(visible_rows) if visible_rows is not None else None,
            "shared.model.shared_files": dict(shared_files) if shared_files is not None else None,
            "shared.model.hidden_shared_files": dict(hidden_files) if hidden_files is not None else None,
            "shared.model.active_filter": dict(active_filter) if active_filter is not None else None,
            "shared.model.hashing_done_visible_rows": dict(hashing_done_visible_rows) if hashing_done_visible_rows is not None else None,
            "shared.model.hashing_done_shared_files": dict(hashing_done_shared_files) if hashing_done_shared_files is not None else None,
        },
        "metrics": metrics,
    }


def enforce_deferred_shared_hashing_boundary(
    phases: list[dict[str, object]],
    scenario_name: str,
) -> None:
    """Fails when deferred shared hashing starts well before startup finalization."""

    startup_complete = get_phase_by_id(phases, STARTUP_PROFILE_COMPLETE_PHASE_ID)
    deferred_start = get_phase_by_id(phases, STARTUP_PROFILE_DEFERRED_SHARED_HASHING_START_PHASE_ID)
    if startup_complete is None or deferred_start is None:
        return

    lead_us = int(startup_complete["absolute_us"]) - int(deferred_start["absolute_us"])
    if lead_us < 0:
        raise RuntimeError(
            f"Deferred shared hashing boundary regression in '{scenario_name}': "
            "shared.hashing.deferred_start occurred after startup.complete."
        )

    lead_ms = lead_us / 1000.0
    if lead_ms > STARTUP_PROFILE_DEFERRED_SHARED_HASHING_MAX_LEAD_MS:
        raise RuntimeError(
            f"Deferred shared hashing boundary regression in '{scenario_name}': "
            f"shared.hashing.deferred_start occurred {lead_ms:.3f} ms before startup.complete."
        )
