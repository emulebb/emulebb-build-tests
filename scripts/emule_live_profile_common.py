"""Shared helpers for deterministic live-profile eMule harness runs."""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import time
from pathlib import Path

import win32con
import win32gui
from pywinauto import Application

PREFERENCES_DAT_VERSION = 0x14
WINDOW_PLACEMENT_LENGTH = 44
WINDOW_SHOW_MAXIMIZED = 3
DEFAULT_WINDOW_RECT = (10, 10, 700, 500)
WINDOWS_DIRECTORY_PATH_LIMIT = 248
WINDOWS_PATH_LIMIT = 260
PATH_SAMPLE_LIMIT = 5
STARTUP_PROFILE_TRACE_FILE_NAME = "startup-profile.trace.json"
STARTUP_PROFILE_COMPLETE_PHASE_ID = "startup.complete"
STARTUP_PROFILE_COMPLETE_PHASE_NAME = "StartupTimer complete"
STARTUP_PROFILE_SHARED_SCAN_COMPLETE_PHASE_ID = "shared.scan.complete"
STARTUP_PROFILE_SHARED_TREE_POPULATED_PHASE_ID = "shared.tree.populated"
STARTUP_PROFILE_SHARED_MODEL_POPULATED_PHASE_ID = "shared.model.populated"
STARTUP_PROFILE_SHARED_FILES_READY_PHASE_ID = "ui.shared_files_ready"
STARTUP_PROFILE_DEFERRED_SHARED_HASHING_START_PHASE_ID = "shared.hashing.deferred_start"
STARTUP_PROFILE_DEFERRED_SHARED_HASHING_MAX_LEAD_MS = 10.0

REQUIRED_SEED_KEYS = (
    "AppVersion",
    "Nick",
    "Port",
    "UDPPort",
    "ServerUDPPort",
    "Language",
    "StartupMinimized",
    "BringToFront",
    "ConfirmExit",
    "RestoreLastMainWndDlg",
    "Splashscreen",
    "Autoconnect",
    "Reconnect",
    "NetworkED2K",
    "NetworkKademlia",
    "ShowSharedFilesDetails",
    "IgnoreInstances",
)


def write_json(path: Path, payload) -> None:
    """Writes a UTF-8 JSON artifact with stable formatting."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def patch_ini_value(text: str, key: str, value: str) -> str:
    """Upserts one simple INI key in the eMule seed profile."""

    pattern = re.compile(rf"(?im)^(?P<key>{re.escape(key)})=.*$")
    replacement = f"{key}={value}"
    if pattern.search(text):
        return pattern.sub(replacement, text)
    suffix = "" if text.endswith("\n") else "\r\n"
    return f"{text}{suffix}{replacement}\r\n"


def parse_ini_values(text: str) -> dict[str, str]:
    """Parses one simple INI text blob into key/value pairs for seed validation."""

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith(";"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def ensure_seed_profile_initialized(text: str) -> None:
    """Fails fast when the checked-in test seed stops being a fully initialized profile."""

    values = parse_ini_values(text)
    missing_keys = [key for key in REQUIRED_SEED_KEYS if not values.get(key, "").strip()]
    if missing_keys:
        raise RuntimeError(
            "Seed preferences.ini is missing required initialized keys: "
            + ", ".join(missing_keys)
        )


def win_path(path: Path, trailing_slash: bool = False) -> str:
    """Formats a path as an absolute Windows string, optionally with a trailing separator."""

    resolved = str(path.resolve())
    return resolved + ("\\" if trailing_slash and not resolved.endswith("\\") else "")


def write_preferences_dat(
    path: Path,
    show_cmd: int = WINDOW_SHOW_MAXIMIZED,
    normal_rect: tuple[int, int, int, int] = DEFAULT_WINDOW_RECT,
) -> None:
    """Writes a deterministic preferences.dat carrying the requested main-window placement."""

    data = struct.pack(
        "<B16sIIIiiiiiiii",
        PREFERENCES_DAT_VERSION,
        b"\0" * 16,
        WINDOW_PLACEMENT_LENGTH,
        0,
        show_cmd,
        0,
        0,
        0,
        0,
        normal_rect[0],
        normal_rect[1],
        normal_rect[2],
        normal_rect[3],
    )
    path.write_bytes(data)


def write_shared_directories_file(path: Path, shared_dirs: list[str]) -> None:
    """Writes the eMule shared-directory list as UTF-16 text."""

    contents = "".join(f"{entry}\r\n" for entry in shared_dirs)
    path.write_text(contents, encoding="utf-16")


def prepare_profile_base(
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_dirs: list[str],
    incoming_dir: Path | None = None,
    temp_dir: Path | None = None,
) -> dict[str, object]:
    """Copies the seed profile and patches per-run mutable paths into an isolated base."""

    profile_base = artifacts_dir / "profile-base"
    config_dir = profile_base / "config"
    log_dir = profile_base / "logs"
    incoming_dir = incoming_dir or (artifacts_dir / "incoming")
    temp_dir = temp_dir or (artifacts_dir / "temp")

    shutil.copytree(seed_config_dir, config_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    preferences_path = config_dir / "preferences.ini"
    preferences_text = preferences_path.read_text(encoding="utf-8", errors="ignore")
    ensure_seed_profile_initialized(preferences_text)
    for key, value in (
        ("IncomingDir", win_path(incoming_dir, trailing_slash=True)),
        ("TempDir", win_path(temp_dir, trailing_slash=True)),
        ("TempDirs", win_path(temp_dir, trailing_slash=True)),
    ):
        preferences_text = patch_ini_value(preferences_text, key, value)
    preferences_path.write_text(preferences_text, encoding="utf-8", newline="\r\n")

    write_preferences_dat(config_dir / "preferences.dat")
    write_shared_directories_file(config_dir / "shareddir.dat", shared_dirs)

    return {
        "profile_base": profile_base,
        "config_dir": config_dir,
        "log_dir": log_dir,
        "incoming_dir": incoming_dir,
        "temp_dir": temp_dir,
        "startup_profile_path": config_dir / STARTUP_PROFILE_TRACE_FILE_NAME,
    }


def enumerate_recursive_directories(root: Path) -> list[str]:
    """Returns one deterministic shared-directory list for a recursively shared root."""

    resolved_root = root.resolve()
    directories: list[str] = []
    for current_root, dir_names, _ in os.walk(resolved_root):
        dir_names.sort(key=str.lower)
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


def summarize_existing_tree(root: Path) -> dict[str, object]:
    """Summarizes an existing filesystem tree for startup-profile reporting."""

    resolved_root = root.resolve()
    directories = [resolved_root]
    files: list[Path] = []
    for current_root, dir_names, file_names in os.walk(resolved_root):
        dir_names.sort(key=str.lower)
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


def launch_app(app_exe: Path, profile_base: Path) -> Application:
    """Starts the real app with the isolated `-c` override and startup profiling enabled."""

    os.environ["EMULE_STARTUP_PROFILE"] = "1"
    command_line = subprocess.list2cmdline(
        [str(app_exe), "-ignoreinstances", "-c", str(profile_base)]
    )
    return Application(backend="win32").start(command_line, wait_for_idle=False)


def is_main_emule_window(hwnd: int) -> bool:
    """Reports whether one visible top-level window is the real main eMule dialog."""

    return win32gui.GetClassName(hwnd) == "#32770" and win32gui.GetWindowText(hwnd).startswith("eMule v")


def describe_startup_dialog(hwnd: int) -> str:
    """Collects one top-level modal dialog description for failure reporting."""

    dialog_texts = []
    child = win32gui.GetWindow(hwnd, win32con.GW_CHILD)
    while child:
        if win32gui.GetClassName(child) == "Static":
            dialog_texts.append(win32gui.GetWindowText(child))
        child = win32gui.GetWindow(child, win32con.GW_HWNDNEXT)
    return "\n".join(filter(None, dialog_texts)).strip()


def wait_for_main_window(app: Application):
    """Waits until the started eMule process exposes a visible top-level window."""

    def resolve():
        try:
            window = app.top_window()
        except Exception:
            return None
        if not window.handle or not win32gui.IsWindowVisible(window.handle):
            return None
        if is_main_emule_window(window.handle):
            return window
        if win32gui.GetClassName(window.handle) == "#32770":
            raise RuntimeError(
                "Unexpected startup dialog "
                f"{win32gui.GetWindowText(window.handle)!r}: "
                f"{describe_startup_dialog(window.handle)!r}"
            )
        return window

    return wait_for(resolve, timeout=90.0, interval=0.5, description="eMule main window")


def get_window_show_cmd(hwnd: int) -> int:
    """Returns the current Win32 show command for one top-level window."""

    return int(win32gui.GetWindowPlacement(hwnd)[1])


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


def close_app_cleanly(app: Application) -> None:
    """Closes the app and fails if an exit-confirmation modal blocks shutdown."""

    main_window = app.top_window()
    main_window.close()

    def resolve() -> bool:
        try:
            window = app.top_window()
        except Exception:
            return True
        if not window.handle:
            return True
        if is_main_emule_window(window.handle):
            return False
        if win32gui.GetClassName(window.handle) == "#32770":
            raise RuntimeError(f"Unexpected shutdown dialog: {describe_startup_dialog(window.handle)!r}")
        return False

    wait_for(resolve, timeout=10.0, interval=0.2, description="clean app shutdown")


def load_startup_profile_trace_events(text: str) -> list[dict[str, object]]:
    """Parses one Chrome Trace startup-profile payload and returns its trace-event rows."""

    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError("Startup profile trace payload must be one JSON object.")
    trace_events = payload.get("traceEvents")
    if not isinstance(trace_events, list):
        raise RuntimeError("Startup profile trace payload is missing a traceEvents list.")
    return [event for event in trace_events if isinstance(event, dict)]


def wait_for_startup_profile_complete(startup_profile_path: Path) -> str:
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

    return wait_for(resolve, timeout=120.0, interval=0.5, description="startup profile completion")


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

    pending_hashes = get_counter_by_id(counters, "shared.model.pending_hashes")
    if pending_hashes is not None and int(pending_hashes["value"]) != 0:
        raise RuntimeError(
            "Startup profile reached ui.shared_files_ready before shared.model.pending_hashes drained to zero."
        )

    visible_rows = get_counter_by_id(counters, "shared.model.visible_rows")
    shared_files = get_counter_by_id(counters, "shared.model.shared_files")
    hidden_files = get_counter_by_id(counters, "shared.model.hidden_shared_files")
    active_filter = get_counter_by_id(counters, "shared.model.active_filter")

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
    }
    if visible_rows is not None:
        metrics["shared_visible_rows_at_readiness"] = int(visible_rows["value"])
    if shared_files is not None:
        metrics["shared_files_at_readiness"] = int(shared_files["value"])
    if hidden_files is not None:
        metrics["shared_hidden_files_at_readiness"] = int(hidden_files["value"])
    if active_filter is not None:
        metrics["shared_active_filter_at_readiness"] = int(active_filter["value"])

    return {
        "phases": {
            "startup.complete": dict(startup_complete),
            STARTUP_PROFILE_SHARED_SCAN_COMPLETE_PHASE_ID: dict(shared_scan_complete),
            STARTUP_PROFILE_SHARED_TREE_POPULATED_PHASE_ID: dict(shared_tree_populated),
            STARTUP_PROFILE_SHARED_MODEL_POPULATED_PHASE_ID: dict(shared_model_populated),
            STARTUP_PROFILE_SHARED_FILES_READY_PHASE_ID: dict(shared_files_ready),
        },
        "counters": {
            "shared.model.pending_hashes": dict(pending_hashes) if pending_hashes is not None else None,
            "shared.model.visible_rows": dict(visible_rows) if visible_rows is not None else None,
            "shared.model.shared_files": dict(shared_files) if shared_files is not None else None,
            "shared.model.hidden_shared_files": dict(hidden_files) if hidden_files is not None else None,
            "shared.model.active_filter": dict(active_filter) if active_filter is not None else None,
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
