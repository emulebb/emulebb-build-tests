"""Real Win32 UI regression for the Shared Files owner-data list."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import win32con
import win32gui
import win32process
from pywinauto import Application, findwindows, mouse

import emule_live_profile_common as live_common
import test_create_long_paths_tree as generated_fixture

WM_COMMAND = 0x0111
BM_CLICK = 0x00F5
MP_HM_FILES = 10213
IDC_RELOADSHAREDFILES = 2049
IDC_SFLIST = 2167
IDC_SF_FNAME = 3038

LVM_FIRST = 0x1000
LVM_GETITEMCOUNT = LVM_FIRST + 4
LVM_GETITEMRECT = LVM_FIRST + 14
LVM_ENSUREVISIBLE = LVM_FIRST + 19
LVM_GETHEADER = LVM_FIRST + 31
LVM_SETITEMSTATE = LVM_FIRST + 43
LVM_SETSELECTIONMARK = LVM_FIRST + 67
LVM_GETITEMTEXTW = LVM_FIRST + 115

HDM_FIRST = 0x1200
HDM_GETITEMRECT = HDM_FIRST + 7

LVIF_TEXT = 0x0001
LVIR_BOUNDS = 0
LVIS_FOCUSED = 0x0001
LVIS_SELECTED = 0x0002

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
kernel32.VirtualFreeEx.restype = ctypes.c_int
kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = ctypes.c_int
kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = ctypes.c_int
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int

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


class LVITEMW(ctypes.Structure):
    """Mirror of the Win32 LVITEMW structure for remote list-view text retrieval."""

    _fields_ = [
        ("mask", ctypes.c_uint),
        ("iItem", ctypes.c_int),
        ("iSubItem", ctypes.c_int),
        ("state", ctypes.c_uint),
        ("stateMask", ctypes.c_uint),
        ("pszText", ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32),
        ("cchTextMax", ctypes.c_int),
        ("iImage", ctypes.c_int),
        ("lParam", ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long),
        ("iIndent", ctypes.c_int),
        ("iGroupId", ctypes.c_int),
        ("cColumns", ctypes.c_uint),
        ("puColumns", ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32),
        ("piColFmt", ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32),
        ("iGroup", ctypes.c_int),
    ]


class RECT(ctypes.Structure):
    """Mirror of the Win32 RECT structure used for cross-process item geometry queries."""

    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class RemoteBuffer:
    """Owns one temporary allocation inside the target process for control-message marshalling."""

    def __init__(self, process_handle: int, size: int) -> None:
        self.process_handle = process_handle
        self.size = size
        self.address = kernel32.VirtualAllocEx(
            process_handle,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
        if not self.address:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.address:
            kernel32.VirtualFreeEx(self.process_handle, self.address, 0, MEM_RELEASE)
            self.address = 0

    def __enter__(self) -> "RemoteBuffer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


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


def prepare_fixture(seed_config_dir: Path, artifacts_dir: Path) -> dict:
    """Creates the small deterministic three-file fixture used by the UI smoke coverage."""

    incoming_dir = artifacts_dir / "incoming"
    temp_dir = artifacts_dir / "temp"
    shared_a_dir = artifacts_dir / "shared-a"
    shared_b_dir = artifacts_dir / "shared-b"

    incoming_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    shared_a_dir.mkdir(parents=True, exist_ok=True)
    shared_b_dir.mkdir(parents=True, exist_ok=True)

    files = [
        (shared_a_dir / "middle_small.txt", b"small\n"),
        (shared_a_dir / "zeta_large.bin", b"z" * 4096),
        (shared_b_dir / "alpha_medium.txt", b"a" * 600),
    ]
    for file_path, content in files:
        file_path.write_bytes(content)

    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=artifacts_dir,
        shared_dirs=[
            live_common.win_path(shared_a_dir, trailing_slash=True),
            live_common.win_path(shared_b_dir, trailing_slash=True),
        ],
        incoming_dir=incoming_dir,
        temp_dir=temp_dir,
    )

    fixture.update(
        {
            "shared_a_dir": shared_a_dir,
            "shared_b_dir": shared_b_dir,
            "expected_name_order_by_name": ["alpha_medium.txt", "middle_small.txt", "zeta_large.bin"],
            "expected_name_order_by_name_descending": ["zeta_large.bin", "middle_small.txt", "alpha_medium.txt"],
            "expected_name_order_by_size_ascending": ["middle_small.txt", "alpha_medium.txt", "zeta_large.bin"],
            "expected_name_order_by_size_descending": ["zeta_large.bin", "alpha_medium.txt", "middle_small.txt"],
        }
    )
    return fixture


def prepare_generated_robustness_fixture(seed_config_dir: Path, artifacts_dir: Path, shared_root: Path) -> dict:
    """Creates an isolated profile base that shares the generated robustness subtree recursively."""

    manifest = generated_fixture.ensure_fixture(shared_root)
    subtree = manifest["subtrees"]["shared_files_robustness"]
    subtree_root = Path(str(subtree["root"])).resolve()
    shared_dirs = live_common.enumerate_recursive_directories(subtree_root)
    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=artifacts_dir,
        shared_dirs=shared_dirs,
    )
    fixture.update(
        {
            "manifest_path": str(Path(str(manifest["manifest_path"])).resolve()),
            "shared_root": live_common.win_path(shared_root.resolve(), trailing_slash=True),
            "subtree_root": live_common.win_path(subtree_root, trailing_slash=True),
            "expected_row_count": int(subtree["expected_visible_file_count"]),
            "expected_file_names": [str(name) for name in subtree["expected_visible_file_names"]],
            "expected_excluded_file_names": [str(name) for name in subtree["expected_excluded_file_names"]],
            "expected_size_ascending_prefix": [
                str(entry["name"]) for entry in subtree["expected_visible_smallest_files_by_size"][:6]
            ],
            "expected_size_descending_prefix": [
                str(entry["name"]) for entry in subtree["expected_visible_largest_files_by_size"][:6]
            ],
            "shared_directory_count": len(shared_dirs),
        }
    )
    return fixture


def open_process(process_id: int) -> int:
    """Opens the target process for the remote memory operations needed by Win32 list controls."""

    access = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION
    handle = kernel32.OpenProcess(access, False, process_id)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def close_process(process_handle: int) -> None:
    """Closes a process handle opened for cross-process control access."""

    if process_handle:
        kernel32.CloseHandle(process_handle)


def write_remote(process_handle: int, remote_address: int, data) -> None:
    """Writes one structure or byte buffer into a remote process allocation."""

    if isinstance(data, (bytes, bytearray)):
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        size = len(data)
        source = buffer
    else:
        size = ctypes.sizeof(data)
        source = data
    written = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(process_handle, remote_address, ctypes.byref(source), size, ctypes.byref(written)):
        raise ctypes.WinError(ctypes.get_last_error())


def read_remote(process_handle: int, remote_address: int, size: int) -> bytes:
    """Reads one byte range from a remote process allocation."""

    buffer = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(process_handle, remote_address, ctypes.byref(buffer), size, ctypes.byref(read)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bytes(buffer[: read.value])


def get_list_item_text(process_handle: int, list_hwnd: int, row_index: int, sub_item: int) -> str:
    """Reads one owner-data list-view cell text through `LVM_GETITEMTEXTW`."""

    max_chars = 1024
    text_bytes = max_chars * ctypes.sizeof(ctypes.c_wchar)
    total_size = ctypes.sizeof(LVITEMW) + text_bytes
    with RemoteBuffer(process_handle, total_size) as remote:
        remote_text_address = remote.address + ctypes.sizeof(LVITEMW)
        item = LVITEMW()
        item.mask = LVIF_TEXT
        item.iItem = row_index
        item.iSubItem = sub_item
        item.pszText = remote_text_address
        item.cchTextMax = max_chars
        write_remote(process_handle, remote.address, item)
        win32gui.SendMessage(list_hwnd, LVM_GETITEMTEXTW, row_index, remote.address)
        raw_text = read_remote(process_handle, remote_text_address, text_bytes)
        return raw_text.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]


def get_list_names(process_handle: int, list_hwnd: int, count: int) -> list[str]:
    """Reads the first N Shared Files row names from the owner-data list."""

    return [get_list_item_text(process_handle, list_hwnd, i, 0) for i in range(count)]


def get_remote_rect(process_handle: int, hwnd: int, message: int, index: int, left_seed: int = 0) -> RECT:
    """Queries one control rectangle by marshalling a RECT through remote process memory."""

    with RemoteBuffer(process_handle, ctypes.sizeof(RECT)) as remote:
        rect = RECT(left_seed, 0, 0, 0)
        write_remote(process_handle, remote.address, rect)
        if not win32gui.SendMessage(hwnd, message, index, remote.address):
            raise RuntimeError(f"Control message 0x{message:04X} failed for index {index}.")
        return RECT.from_buffer_copy(read_remote(process_handle, remote.address, ctypes.sizeof(RECT)))


def get_control_handle(main_hwnd: int, control_id: int, class_name: str) -> int:
    """Finds one descendant control by numeric ID and window class."""

    matches = []

    def walk(hwnd: int) -> None:
        child = win32gui.GetWindow(hwnd, win32con.GW_CHILD)
        while child:
            try:
                child_class = win32gui.GetClassName(child)
                child_id = win32gui.GetDlgCtrlID(child)
                if child_class == class_name and child_id == control_id:
                    matches.append(child)
            except win32gui.error:
                pass
            walk(child)
            child = win32gui.GetWindow(child, win32con.GW_HWNDNEXT)

    walk(main_hwnd)
    if not matches:
        raise RuntimeError(f"Unable to find {class_name} with control id {control_id}.")
    return matches[0]


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


def click_client_rect(hwnd: int, rect: RECT) -> None:
    """Clicks the center of a client-rect region on screen."""

    origin = win32gui.ClientToScreen(hwnd, (0, 0))
    x = origin[0] + rect.left + max((rect.right - rect.left) // 2, 1)
    y = origin[1] + rect.top + max((rect.bottom - rect.top) // 2, 1)
    mouse.click(coords=(x, y))


def set_list_row_selected(process_handle: int, list_hwnd: int, row_index: int) -> None:
    """Selects one virtual list row through the real Win32 list-view state messages."""

    win32gui.SendMessage(list_hwnd, LVM_ENSUREVISIBLE, row_index, 0)
    with RemoteBuffer(process_handle, ctypes.sizeof(LVITEMW)) as remote:
        clear_state = LVITEMW()
        clear_state.stateMask = LVIS_SELECTED | LVIS_FOCUSED
        write_remote(process_handle, remote.address, clear_state)
        win32gui.SendMessage(list_hwnd, LVM_SETITEMSTATE, -1, remote.address)

        select_state = LVITEMW()
        select_state.state = LVIS_SELECTED | LVIS_FOCUSED
        select_state.stateMask = LVIS_SELECTED | LVIS_FOCUSED
        write_remote(process_handle, remote.address, select_state)
        win32gui.SendMessage(list_hwnd, LVM_SETITEMSTATE, row_index, remote.address)

    win32gui.SendMessage(list_hwnd, LVM_SETSELECTIONMARK, 0, row_index)


def launch_app(app_exe: Path, profile_base: Path) -> Application:
    """Starts the real app with the isolated `-c` override."""

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


def wait_for_list_count(list_hwnd: int, minimum_count: int) -> int:
    """Waits until the Shared Files list exposes at least the requested item count."""

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        return count if count >= minimum_count else 0

    return wait_for(resolve, timeout=90.0, interval=0.5, description="Shared Files list rows")


def wait_for_exact_list_count(list_hwnd: int, expected_count: int) -> int:
    """Waits until the Shared Files list exposes exactly the requested item count."""

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        return count if count == expected_count else 0

    return wait_for(resolve, timeout=90.0, interval=0.5, description=f"Shared Files row count {expected_count}")


def wait_for_static_text(static_hwnd: int, expected_text: str) -> None:
    """Waits until a static control shows the expected file name."""

    def resolve():
        actual = win32gui.GetWindowText(static_hwnd)
        return actual if expected_text in actual else ""

    actual = wait_for(resolve, timeout=10.0, interval=0.2, description=f"details text '{expected_text}'")


def click_list_column(process_handle: int, list_hwnd: int, column_index: int, description: str) -> None:
    """Clicks one Shared Files header column by zero-based index."""

    header_hwnd = win32gui.SendMessage(list_hwnd, LVM_GETHEADER, 0, 0)
    if not header_hwnd:
        raise RuntimeError("Shared Files list header was not found.")
    rect = get_remote_rect(process_handle, header_hwnd, HDM_GETITEMRECT, column_index)
    click_client_rect(header_hwnd, rect)
    time.sleep(0.5)


def wait_for_list_names(process_handle: int, list_hwnd: int, expected_names: list[str], description: str) -> list[str]:
    """Waits until the visible Shared Files rows match the expected ordered names."""

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        if count < len(expected_names):
            return None
        names = get_list_names(process_handle, list_hwnd, len(expected_names))
        return names if names == expected_names else None

    return wait_for(resolve, timeout=30.0, interval=0.5, description=description)


def wait_for_list_names_one_of(
    process_handle: int,
    list_hwnd: int,
    expected_orders: list[list[str]],
    description: str,
) -> list[str]:
    """Waits until the list matches one of the expected ordered row sets."""

    expected_lookup = {tuple(order): order for order in expected_orders}

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        required_count = max(len(order) for order in expected_orders)
        if count < required_count:
            return None
        names = get_list_names(process_handle, list_hwnd, required_count)
        return names if tuple(names) in expected_lookup else None

    return wait_for(resolve, timeout=30.0, interval=0.5, description=description)


def wait_for_list_prefix(process_handle: int, list_hwnd: int, expected_prefix: list[str], description: str) -> list[str]:
    """Waits until the first visible Shared Files rows match the expected ordered prefix."""

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        if count < len(expected_prefix):
            return None
        names = get_list_names(process_handle, list_hwnd, len(expected_prefix))
        return names if names == expected_prefix else None

    return wait_for(resolve, timeout=30.0, interval=0.5, description=description)


def wait_for_list_prefix_one_of(
    process_handle: int,
    list_hwnd: int,
    expected_prefixes: list[list[str]],
    description: str,
) -> list[str]:
    """Waits until the first visible Shared Files rows match one of the expected ordered prefixes."""

    expected_lookup = {tuple(prefix): prefix for prefix in expected_prefixes}

    def resolve():
        required_count = max(len(prefix) for prefix in expected_prefixes)
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        if count < required_count:
            return None
        names = get_list_names(process_handle, list_hwnd, required_count)
        return names if tuple(names) in expected_lookup else None

    return wait_for(resolve, timeout=30.0, interval=0.5, description=description)


def click_reload_button(main_hwnd: int) -> None:
    """Invokes the real Reload button on the Shared Files page."""

    reload_hwnd = get_control_handle(main_hwnd, IDC_RELOADSHAREDFILES, "Button")
    win32gui.SendMessage(reload_hwnd, BM_CLICK, 0, 0)


def open_shared_files_page(main_hwnd: int) -> tuple[int, int]:
    """Opens the Shared Files page and returns the list and details control handles."""

    win32gui.SendMessage(main_hwnd, WM_COMMAND, MP_HM_FILES, 0)
    list_hwnd = wait_for(
        lambda: get_control_handle(main_hwnd, IDC_SFLIST, "SysListView32"),
        30.0,
        0.5,
        "Shared Files list control",
    )
    static_hwnd = get_control_handle(main_hwnd, IDC_SF_FNAME, "Static")
    return list_hwnd, static_hwnd


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


def run_shared_files_e2e(app_exe: Path, seed_config_dir: Path, artifacts_dir: Path) -> None:
    """Executes the real Shared Files Win32 regression against an isolated fixture profile."""

    fixture = prepare_fixture(seed_config_dir, artifacts_dir)
    summary = {
        "name": "fixture-three-files",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
        "expected_name_order_by_name": fixture["expected_name_order_by_name"],
        "expected_name_order_by_name_descending": fixture["expected_name_order_by_name_descending"],
        "expected_name_order_by_size_ascending": fixture["expected_name_order_by_size_ascending"],
        "expected_name_order_by_size_descending": fixture["expected_name_order_by_size_descending"],
    }

    app = None
    process_handle = 0
    try:
        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        main_window.set_focus()
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
        if not summary["main_window_is_maximized"]:
            raise RuntimeError(f"Expected the seeded profile to start maximized, got showCmd={summary['main_window_show_cmd']}.")

        startup_profile_text = live_common.wait_for_startup_profile_complete(fixture["startup_profile_path"])
        startup_profile_phases = live_common.parse_startup_profile(startup_profile_text)
        startup_profile_counters = live_common.parse_startup_profile_counters(startup_profile_text)
        summary["startup_profile_path"] = str(fixture["startup_profile_path"])
        summary["startup_profile_phase_count"] = len(startup_profile_phases)
        summary["startup_profile_counter_count"] = len(startup_profile_counters)
        summary["startup_profile_counters"] = live_common.summarize_startup_profile_counters(startup_profile_counters)
        summary["startup_profile_readiness"] = live_common.summarize_shared_files_readiness(
            startup_profile_phases,
            startup_profile_counters,
        )
        summary["startup_profile_highlights"] = live_common.summarize_startup_profile(
            startup_profile_phases,
            [
                "Construct CSharedFileList (share cache/scan)",
                "CSharedFilesWnd::OnInitDialog total",
                "shared.scan.complete",
                "shared.tree.populated",
                "shared.model.populated",
                "ui.shared_files_ready",
                "StartupTimer complete",
            ],
        )
        summary["startup_profile_top_slowest_phases"] = live_common.get_top_slowest_phases(startup_profile_phases, limit=8)
        live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, summary["name"])
        process_handle = open_process(process_id)

        dump_window_tree(main_hwnd, artifacts_dir / "window-tree-initial.json")

        win32gui.SendMessage(main_hwnd, WM_COMMAND, MP_HM_FILES, 0)
        list_hwnd = wait_for(lambda: get_control_handle(main_hwnd, IDC_SFLIST, "SysListView32"), 30.0, 0.5, "Shared Files list control")
        static_hwnd = get_control_handle(main_hwnd, IDC_SF_FNAME, "Static")

        count = wait_for_list_count(list_hwnd, minimum_count=3)
        summary["initial_row_count"] = count
        if count != 3:
            raise RuntimeError(f"Expected exactly 3 Shared Files rows, got {count}.")
        names_before = get_list_names(process_handle, list_hwnd, 3)
        summary["names_before_sort"] = names_before
        if names_before != fixture["expected_name_order_by_name"]:
            raise RuntimeError(f"Unexpected default Shared Files order: {names_before!r}")

        set_list_row_selected(process_handle, list_hwnd, 1)
        wait_for_static_text(static_hwnd, fixture["expected_name_order_by_name"][1])
        summary["details_after_initial_selection"] = fixture["expected_name_order_by_name"][1]

        click_list_column(process_handle, list_hwnd, 1, "Size")
        first_size_sort_order = wait_for_list_names_one_of(
            process_handle,
            list_hwnd,
            [
                fixture["expected_name_order_by_size_ascending"],
                fixture["expected_name_order_by_size_descending"],
            ],
            "Shared Files first size sort order",
        )
        summary["first_size_sort_order"] = first_size_sort_order

        if first_size_sort_order == fixture["expected_name_order_by_size_ascending"]:
            names_by_size_ascending = first_size_sort_order
            set_list_row_selected(process_handle, list_hwnd, 0)
            wait_for_static_text(static_hwnd, fixture["expected_name_order_by_size_ascending"][0])
            summary["details_after_ascending_sort_selection"] = fixture["expected_name_order_by_size_ascending"][0]

            click_list_column(process_handle, list_hwnd, 1, "Size")
            names_by_size_descending = wait_for_list_names(
                process_handle,
                list_hwnd,
                fixture["expected_name_order_by_size_descending"],
                "Shared Files size sort descending order",
            )
        else:
            names_by_size_descending = first_size_sort_order
            click_list_column(process_handle, list_hwnd, 1, "Size")
            names_by_size_ascending = wait_for_list_names(
                process_handle,
                list_hwnd,
                fixture["expected_name_order_by_size_ascending"],
                "Shared Files size sort ascending order",
            )
            set_list_row_selected(process_handle, list_hwnd, 0)
            wait_for_static_text(static_hwnd, fixture["expected_name_order_by_size_ascending"][0])
            summary["details_after_ascending_sort_selection"] = fixture["expected_name_order_by_size_ascending"][0]

            click_list_column(process_handle, list_hwnd, 1, "Size")
            names_by_size_descending = wait_for_list_names(
                process_handle,
                list_hwnd,
                fixture["expected_name_order_by_size_descending"],
                "Shared Files size sort descending order",
            )

        summary["names_by_size_ascending"] = names_by_size_ascending
        summary["names_by_size_descending"] = names_by_size_descending

        click_reload_button(main_hwnd)
        count_after_reload = wait_for_list_count(list_hwnd, minimum_count=3)
        summary["row_count_after_reload"] = count_after_reload
        names_after_reload = get_list_names(process_handle, list_hwnd, 3)
        summary["names_after_reload"] = names_after_reload
        if count_after_reload != 3:
            raise RuntimeError(f"Reload changed the Shared Files row count unexpectedly: {count_after_reload}.")
        if names_after_reload != fixture["expected_name_order_by_size_descending"]:
            raise RuntimeError(
                "Reload did not preserve the active descending size sort order: "
                f"{names_after_reload!r}"
            )

        set_list_row_selected(process_handle, list_hwnd, 2)
        wait_for_static_text(static_hwnd, names_after_reload[2])
        summary["details_after_reload_selection"] = names_after_reload[2]

        click_list_column(process_handle, list_hwnd, 0, "Name")
        first_name_sort_order_after_reload = wait_for_list_names_one_of(
            process_handle,
            list_hwnd,
            [
                fixture["expected_name_order_by_name"],
                fixture["expected_name_order_by_name_descending"],
            ],
            "Shared Files first name sort order after reload",
        )
        summary["first_name_sort_order_after_reload"] = first_name_sort_order_after_reload

        if first_name_sort_order_after_reload == fixture["expected_name_order_by_name"]:
            names_by_name_ascending = first_name_sort_order_after_reload
            set_list_row_selected(process_handle, list_hwnd, 0)
            wait_for_static_text(static_hwnd, fixture["expected_name_order_by_name"][0])
            summary["details_after_name_ascending_selection"] = fixture["expected_name_order_by_name"][0]

            click_list_column(process_handle, list_hwnd, 0, "Name")
            names_by_name_descending = wait_for_list_names(
                process_handle,
                list_hwnd,
                fixture["expected_name_order_by_name_descending"],
                "Shared Files name sort descending order",
            )
        else:
            names_by_name_descending = first_name_sort_order_after_reload
            click_list_column(process_handle, list_hwnd, 0, "Name")
            names_by_name_ascending = wait_for_list_names(
                process_handle,
                list_hwnd,
                fixture["expected_name_order_by_name"],
                "Shared Files name sort ascending order",
            )
            set_list_row_selected(process_handle, list_hwnd, 0)
            wait_for_static_text(static_hwnd, fixture["expected_name_order_by_name"][0])
            summary["details_after_name_ascending_selection"] = fixture["expected_name_order_by_name"][0]

            click_list_column(process_handle, list_hwnd, 0, "Name")
            names_by_name_descending = wait_for_list_names(
                process_handle,
                list_hwnd,
                fixture["expected_name_order_by_name_descending"],
                "Shared Files name sort descending order",
            )

        summary["names_by_name_ascending"] = names_by_name_ascending
        summary["names_by_name_descending"] = names_by_name_descending
        summary["status"] = "passed"
        summary["error"] = None

        write_json(artifacts_dir / "result.json", summary)
    except Exception as exc:
        summary["error"] = str(exc)
        if app is not None:
            try:
                main_window = app.top_window()
                dump_window_tree(main_window.handle, artifacts_dir / "window-tree-failure.json")
                try:
                    image = main_window.capture_as_image()
                    image.save(artifacts_dir / "failure.png")
                except Exception:
                    pass
            except Exception:
                pass
        write_json(artifacts_dir / "result.json", summary)
        raise
    finally:
        if process_handle:
            close_process(process_handle)
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:
                try:
                    app.kill()
                except Exception:
                    pass


def run_generated_robustness_e2e(app_exe: Path, seed_config_dir: Path, artifacts_dir: Path, shared_root: Path) -> None:
    """Executes a larger Shared Files regression against the generated robustness subtree."""

    fixture = prepare_generated_robustness_fixture(seed_config_dir, artifacts_dir, shared_root)
    expected_names_sorted = sorted(fixture["expected_file_names"], key=str.lower)
    summary = {
        "name": "generated-robustness-recursive",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "shared_root": fixture["shared_root"],
        "subtree_root": fixture["subtree_root"],
        "generated_fixture_manifest_path": fixture["manifest_path"],
        "shared_directory_count": fixture["shared_directory_count"],
        "expected_row_count": fixture["expected_row_count"],
        "expected_excluded_file_names": fixture["expected_excluded_file_names"],
        "expected_size_ascending_prefix": fixture["expected_size_ascending_prefix"],
        "expected_size_descending_prefix": fixture["expected_size_descending_prefix"],
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
    }

    app = None
    process_handle = 0
    try:
        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        main_window.set_focus()
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
        if not summary["main_window_is_maximized"]:
            raise RuntimeError(f"Expected the seeded profile to start maximized, got showCmd={summary['main_window_show_cmd']}.")

        startup_profile_text = live_common.wait_for_startup_profile_complete(fixture["startup_profile_path"])
        startup_profile_phases = live_common.parse_startup_profile(startup_profile_text)
        startup_profile_counters = live_common.parse_startup_profile_counters(startup_profile_text)
        summary["startup_profile_path"] = str(fixture["startup_profile_path"])
        summary["startup_profile_phase_count"] = len(startup_profile_phases)
        summary["startup_profile_counter_count"] = len(startup_profile_counters)
        summary["startup_profile_counters"] = live_common.summarize_startup_profile_counters(startup_profile_counters)
        summary["startup_profile_readiness"] = live_common.summarize_shared_files_readiness(
            startup_profile_phases,
            startup_profile_counters,
        )
        summary["startup_profile_highlights"] = live_common.summarize_startup_profile(
            startup_profile_phases,
            [
                "Construct CSharedFileList (share cache/scan)",
                "CSharedFilesWnd::OnInitDialog total",
                "shared.scan.complete",
                "shared.tree.populated",
                "shared.model.populated",
                "ui.shared_files_ready",
                "StartupTimer complete",
            ],
        )
        summary["startup_profile_top_slowest_phases"] = live_common.get_top_slowest_phases(startup_profile_phases, limit=8)
        live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, summary["name"])
        process_handle = open_process(process_id)

        dump_window_tree(main_hwnd, artifacts_dir / "window-tree-initial.json")

        list_hwnd, static_hwnd = open_shared_files_page(main_hwnd)
        count = wait_for_exact_list_count(list_hwnd, fixture["expected_row_count"])
        summary["initial_row_count"] = count

        names_before_sort = get_list_names(process_handle, list_hwnd, count)
        summary["names_before_sort_preview"] = names_before_sort[:12]
        summary["names_before_sort_tail"] = names_before_sort[-12:]
        if sorted(names_before_sort, key=str.lower) != expected_names_sorted:
            raise RuntimeError("Shared Files list did not expose the expected generated robustness file set.")

        click_list_column(process_handle, list_hwnd, 1, "Size")
        first_size_sort_prefix = wait_for_list_prefix_one_of(
            process_handle,
            list_hwnd,
            [
                fixture["expected_size_ascending_prefix"],
                fixture["expected_size_descending_prefix"],
            ],
            "Generated robustness first size sort prefix",
        )
        summary["first_size_sort_prefix"] = first_size_sort_prefix

        if first_size_sort_prefix == fixture["expected_size_ascending_prefix"]:
            size_ascending_prefix = first_size_sort_prefix
            set_list_row_selected(process_handle, list_hwnd, 0)
            wait_for_static_text(static_hwnd, fixture["expected_size_ascending_prefix"][0])
            summary["details_after_ascending_sort_selection"] = fixture["expected_size_ascending_prefix"][0]

            click_list_column(process_handle, list_hwnd, 1, "Size")
            size_descending_prefix = wait_for_list_prefix(
                process_handle,
                list_hwnd,
                fixture["expected_size_descending_prefix"],
                "Generated robustness descending size prefix",
            )
        else:
            size_descending_prefix = first_size_sort_prefix
            click_list_column(process_handle, list_hwnd, 1, "Size")
            size_ascending_prefix = wait_for_list_prefix(
                process_handle,
                list_hwnd,
                fixture["expected_size_ascending_prefix"],
                "Generated robustness ascending size prefix",
            )
            set_list_row_selected(process_handle, list_hwnd, 0)
            wait_for_static_text(static_hwnd, fixture["expected_size_ascending_prefix"][0])
            summary["details_after_ascending_sort_selection"] = fixture["expected_size_ascending_prefix"][0]

            click_list_column(process_handle, list_hwnd, 1, "Size")
            size_descending_prefix = wait_for_list_prefix(
                process_handle,
                list_hwnd,
                fixture["expected_size_descending_prefix"],
                "Generated robustness descending size prefix",
            )

        summary["size_ascending_prefix"] = size_ascending_prefix
        summary["size_descending_prefix"] = size_descending_prefix

        set_list_row_selected(process_handle, list_hwnd, 0)
        wait_for_static_text(static_hwnd, fixture["expected_size_descending_prefix"][0])
        summary["details_after_descending_sort_selection"] = fixture["expected_size_descending_prefix"][0]

        click_reload_button(main_hwnd)
        count_after_reload = wait_for_exact_list_count(list_hwnd, fixture["expected_row_count"])
        summary["row_count_after_reload"] = count_after_reload
        names_after_reload_prefix = get_list_names(process_handle, list_hwnd, len(fixture["expected_size_descending_prefix"]))
        summary["names_after_reload_prefix"] = names_after_reload_prefix
        if names_after_reload_prefix != fixture["expected_size_descending_prefix"]:
            raise RuntimeError(
                "Reload did not preserve the generated robustness descending size prefix: "
                f"{names_after_reload_prefix!r}"
            )

        names_after_reload_all = get_list_names(process_handle, list_hwnd, fixture["expected_row_count"])
        summary["names_after_reload_preview"] = names_after_reload_all[:12]
        summary["names_after_reload_tail"] = names_after_reload_all[-12:]
        if sorted(names_after_reload_all, key=str.lower) != expected_names_sorted:
            raise RuntimeError("Reload changed the generated robustness Shared Files set unexpectedly.")

        summary["status"] = "passed"
        summary["error"] = None
        write_json(artifacts_dir / "result.json", summary)
    except Exception as exc:
        summary["error"] = str(exc)
        if app is not None:
            try:
                main_window = app.top_window()
                dump_window_tree(main_window.handle, artifacts_dir / "window-tree-failure.json")
                try:
                    image = main_window.capture_as_image()
                    image.save(artifacts_dir / "failure.png")
                except Exception:
                    pass
            except Exception:
                pass
        write_json(artifacts_dir / "result.json", summary)
        raise
    finally:
        if process_handle:
            close_process(process_handle)
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:
                try:
                    app.kill()
                except Exception:
                    pass


def run_shared_files_ui_suite(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_root: Path,
    scenario_names: list[str],
) -> None:
    """Runs the requested Shared Files UI scenarios and writes one combined result."""

    combined = {
        "status": "passed",
        "app_exe": str(app_exe),
        "shared_root": live_common.win_path(shared_root.resolve(), trailing_slash=True),
        "scenario_names": scenario_names,
        "scenario_count": len(scenario_names),
        "generated_fixture_manifest_path": None,
        "scenarios": [],
    }
    failures = []

    for scenario_name in scenario_names:
        scenario_dir = artifacts_dir / scenario_name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        try:
            if scenario_name == "fixture-three-files":
                run_shared_files_e2e(app_exe, seed_config_dir, scenario_dir)
            elif scenario_name == "generated-robustness-recursive":
                run_generated_robustness_e2e(app_exe, seed_config_dir, scenario_dir, shared_root)
            else:
                raise RuntimeError(f"Unknown Shared Files UI scenario: {scenario_name}")
        except Exception:
            failures.append(scenario_name)

        result_path = scenario_dir / "result.json"
        if not result_path.exists():
            raise RuntimeError(f"Shared Files UI scenario '{scenario_name}' did not produce result.json.")
        scenario_result = json.loads(result_path.read_text(encoding="utf-8"))
        combined["scenarios"].append(scenario_result)
        generated_manifest_path = scenario_result.get("generated_fixture_manifest_path")
        if generated_manifest_path:
            combined["generated_fixture_manifest_path"] = generated_manifest_path

    if failures:
        combined["status"] = "failed"

    write_json(artifacts_dir / "result.json", combined)
    if failures:
        raise RuntimeError("Shared Files UI scenarios failed: " + ", ".join(failures))


def main(argv: list[str]) -> int:
    """Parses arguments, executes the requested UI scenarios, and writes failure artifacts on disk."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--app-exe", required=True)
    parser.add_argument("--seed-config-dir", required=True)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--shared-root", default=r"C:\tmp\00_long_paths")
    parser.add_argument(
        "--scenario",
        dest="scenarios",
        action="append",
        choices=["fixture-three-files", "generated-robustness-recursive"],
    )
    args = parser.parse_args(argv)

    artifacts_dir = Path(args.artifacts_dir).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    scenario_names = args.scenarios or ["fixture-three-files", "generated-robustness-recursive"]

    try:
        run_shared_files_ui_suite(
            app_exe=Path(args.app_exe).resolve(),
            seed_config_dir=Path(args.seed_config_dir).resolve(),
            artifacts_dir=artifacts_dir,
            shared_root=Path(args.shared_root).resolve(),
            scenario_names=scenario_names,
        )
        return 0
    except Exception as exc:
        (artifacts_dir / "error.txt").write_text(f"{exc}\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
