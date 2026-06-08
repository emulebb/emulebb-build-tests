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
from emule_test_harness import startup_diagnostics
from emule_test_harness import windows_processes
from emule_test_harness.live_profiles import (
    DEFAULT_P2P_BIND_INTERFACE_NAME,
    DEFAULT_WINDOW_RECT,
    PREFERENCES_DAT_VERSION,
    PRIVATE_HARNESS_RATE_LIMIT_BITS_PER_SEC,
    PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC,
    STARTUP_DIAGNOSTICS_TRACE_FILE_NAME,
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
NON_MAIN_WINDOW_TITLE_PREFIXES = ("Starting eMule", "Shutting down eMule")
STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID = startup_diagnostics.STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID
STARTUP_DIAGNOSTICS_COMPLETE_PHASE_NAME = startup_diagnostics.STARTUP_DIAGNOSTICS_COMPLETE_PHASE_NAME
STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID = startup_diagnostics.STARTUP_DIAGNOSTICS_SHARED_SCAN_COMPLETE_PHASE_ID
STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID = startup_diagnostics.STARTUP_DIAGNOSTICS_SHARED_TREE_POPULATED_PHASE_ID
STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID = startup_diagnostics.STARTUP_DIAGNOSTICS_SHARED_MODEL_POPULATED_PHASE_ID
STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID = startup_diagnostics.STARTUP_DIAGNOSTICS_SHARED_FILES_READY_PHASE_ID
STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID = startup_diagnostics.STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID
STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME = startup_diagnostics.STARTUP_DIAGNOSTICS_SHARED_LIST_RELOAD_PHASE_NAME
STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID = (
    startup_diagnostics.STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_START_PHASE_ID
)
STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_MAX_LEAD_MS = (
    startup_diagnostics.STARTUP_DIAGNOSTICS_DEFERRED_SHARED_HASHING_MAX_LEAD_MS
)
STARTUP_DIAGNOSTICS_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN = (
    startup_diagnostics.STARTUP_DIAGNOSTICS_MAX_SHARED_LIST_RELOADS_DURING_HASH_DRAIN
)
load_startup_diagnostics_trace_events = startup_diagnostics.load_startup_diagnostics_trace_events
parse_startup_diagnostics = startup_diagnostics.parse_startup_diagnostics
parse_startup_diagnostics_counters = startup_diagnostics.parse_startup_diagnostics_counters
summarize_startup_diagnostics = startup_diagnostics.summarize_startup_diagnostics
get_top_slowest_phases = startup_diagnostics.get_top_slowest_phases
summarize_startup_diagnostics_counters = startup_diagnostics.summarize_startup_diagnostics_counters
get_phase_by_id = startup_diagnostics.get_phase_by_id
get_counter_by_id = startup_diagnostics.get_counter_by_id
count_phases_between = startup_diagnostics.count_phases_between
summarize_shared_files_readiness = startup_diagnostics.summarize_shared_files_readiness
enforce_deferred_shared_hashing_boundary = startup_diagnostics.enforce_deferred_shared_hashing_boundary

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
    """Summarizes an existing filesystem tree for startup-diagnostics reporting."""

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
    """Starts the real app with the isolated `-c` override."""

    if minimized_to_tray and requires_interactive_ui:
        raise ValueError("Interactive UI launches must not request minimized-to-tray startup.")
    require_pywinauto()
    if minimized_to_tray:
        apply_minimized_to_tray_startup(profile_base / "config")
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
    if title.startswith(NON_MAIN_WINDOW_TITLE_PREFIXES):
        return False
    return title.startswith(MAIN_WINDOW_TITLE_PREFIXES) or any(
        marker in title for marker in MAIN_WINDOW_TITLE_MARKERS
    )


def find_process_main_window(app: Application, *, require_visible: bool = False):
    """Finds the launched eMule main window by enumerating process top-level windows."""

    process_id = resolve_app_process_id(app)
    if process_id is None:
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
    main_window = find_process_main_window(app)
    if main_window is None:
        if not process_id or _is_process_exited(int(process_id)):
            return
        _terminate_process_without_window(app, int(process_id), process_timeout)
        return
    # WHY: some pywinauto Application instances expose `process` as an integer
    # property rather than a callable. Calling app.top_window() can then fail
    # inside pywinauto with "'int' object is not callable" during cleanup even
    # though the process is healthy. We already know the process id, so close the
    # enumerated eMule main window directly and keep dialog detection handle-based.
    win32gui.PostMessage(int(main_window.handle), win32con.WM_CLOSE, 0, 0)

    def resolve() -> bool:
        window = find_process_main_window(app)
        if window is None:
            return True
        hwnd = int(window.handle)
        if is_main_emule_window(hwnd):
            return False
        if is_expected_shutdown_progress_dialog(hwnd):
            return False
        if win32gui.GetClassName(hwnd) == "#32770":
            raise RuntimeError(f"Unexpected shutdown dialog: {describe_startup_dialog(hwnd)!r}")
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
    object_pid = getattr(process_id, "pid", None)
    if object_pid is not None:
        process_id = object_pid
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


def wait_for_startup_diagnostics_complete(startup_diagnostics_path: Path, *, timeout: float = 120.0) -> str:
    """Waits until the finalized Chrome Trace startup diagnostics becomes readable."""

    def resolve():
        if not startup_diagnostics_path.exists():
            return None
        text = startup_diagnostics_path.read_text(encoding="utf-8", errors="ignore")
        trace_events = load_startup_diagnostics_trace_events(text)
        for event in trace_events:
            if str(event.get("name") or "") == STARTUP_DIAGNOSTICS_COMPLETE_PHASE_NAME:
                return text
            args = event.get("args")
            if isinstance(args, dict) and str(args.get("phase_id") or "") == STARTUP_DIAGNOSTICS_COMPLETE_PHASE_ID:
                return text
        return None

    return wait_for(resolve, timeout=timeout, interval=0.5, description="startup diagnostics completion")


def startup_diagnostics_has_phase(text: str, phase_id: str) -> bool:
    """Returns whether one startup-diagnostics trace payload contains a stable phase id."""

    for event in load_startup_diagnostics_trace_events(text):
        args = event.get("args")
        if isinstance(args, dict) and str(args.get("phase_id") or "") == phase_id:
            return True
    return False


def wait_for_startup_diagnostics_phase(startup_diagnostics_path: Path, phase_id: str, *, timeout: float = 120.0) -> str:
    """Waits until the startup diagnostics contains one stable phase id and returns the trace text."""

    def resolve():
        if not startup_diagnostics_path.exists():
            return None
        text = startup_diagnostics_path.read_text(encoding="utf-8", errors="ignore")
        return text if startup_diagnostics_has_phase(text, phase_id) else None

    return wait_for(resolve, timeout=timeout, interval=0.5, description=f"startup diagnostics phase {phase_id}")
