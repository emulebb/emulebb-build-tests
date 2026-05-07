"""Real Win32 UI regression for WebServer and Tweaks preference controls."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import re
import shutil
import sys
import time
from pathlib import Path

import win32con
import win32gui
import win32process

try:
    from pywinauto import Application
    _PYWINAUTO_IMPORT_ERROR = None
except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
    Application = object  # type: ignore[assignment]
    _PYWINAUTO_IMPORT_ERROR = exc


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
rest_smoke = load_local_module("rest_api_smoke", "rest-api-smoke.py")

WM_COMMAND = 0x0111
WM_SETTEXT = 0x000C
WM_CHAR = 0x0102
BM_CLICK = 0x00F5
BM_GETCHECK = 0x00F0
BST_CHECKED = 0x0001
EN_CHANGE = 0x0300

MP_HM_PREFS = 10217
IDOK = 1
IDCANCEL = 2
PAGE_TREE_ID = 0x7EEE
IDC_EXT_OPTS = 2095
TREE_OPTIONS_EDITBOX_ID = 101

IDC_WSPORT = 2545
IDC_WSENABLED = 2671
IDC_TMPLPATH = 2682
IDC_WEBBINDADDR = 3044
IDC_WS_MAXFILEUPLOAD = 3067
IDC_WS_ALLOWEDIPS = 3069
IDC_AUTOUPDATE_IPFILTER = 3070
IDC_IPFILTERPERIOD = 3072
IDC_UPDATEURL = 2797

TV_FIRST = 0x1100
TVM_EXPAND = TV_FIRST + 2
TVM_GETNEXTITEM = TV_FIRST + 10
TVM_SELECTITEM = TV_FIRST + 11
TVM_ENSUREVISIBLE = TV_FIRST + 20
TVM_GETITEMW = TV_FIRST + 62
TVE_EXPAND = 0x0002
TVGN_ROOT = 0
TVGN_NEXT = 1
TVGN_CHILD = 4
TVGN_CARET = 9
TVIF_TEXT = 0x0001
TVIF_IMAGE = 0x0002
TVIF_SELECTEDIMAGE = 0x0020

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

TWEAKS_LOGGING_GROUP_LABEL = "Logging & Diagnostics"

TWEAKS_EXPECTED_LABELS = (
    TWEAKS_LOGGING_GROUP_LABEL,
    "Crash dump creation",
    "Create dump automatically",
    "Maximum log file size [KiB]",
    "Log view buffer [KiB]",
    "Log file format",
    "UTF-8",
    "Performance log format",
    "Performance log file",
    "Performance log interval [minutes]",
    "Text editor command",
    "High-resolution system timer",
    "Intelligent Corruption Handling",
    "Preview incomplete media blocks",
    "Force even with missing first block",
    "Beep on important errors",
    "Show Copy ed2k Link command",
    "Flash tray icon on new message",
    "General date/time format",
    "Log date/time format",
    "Maximum chat history lines",
    "Maximum message sessions",
)

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


class TVITEMW(ctypes.Structure):
    """Mirror of the Win32 TVITEMW structure for cross-process tree queries."""

    _fields_ = [
        ("mask", ctypes.c_uint),
        ("hItem", ctypes.c_void_p),
        ("state", ctypes.c_uint),
        ("stateMask", ctypes.c_uint),
        ("pszText", ctypes.c_void_p),
        ("cchTextMax", ctypes.c_int),
        ("iImage", ctypes.c_int),
        ("iSelectedImage", ctypes.c_int),
        ("cChildren", ctypes.c_int),
        ("lParam", ctypes.c_void_p),
    ]


class RemoteBuffer:
    """Owns one temporary allocation inside the target process."""

    def __init__(self, process_handle: int, size: int) -> None:
        self.process_handle = process_handle
        self.size = size
        self.address = kernel32.VirtualAllocEx(process_handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
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


def require_pywinauto() -> None:
    if _PYWINAUTO_IMPORT_ERROR is not None:
        raise RuntimeError(
            "pywinauto is required for the live/UI harness scripts. "
            "Install it with 'python -m pip install -e .[live]'."
        ) from _PYWINAUTO_IMPORT_ERROR


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def wait_for(predicate, timeout: float, interval: float, description: str):
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


def enum_descendants(root_hwnd: int) -> list[int]:
    results: list[int] = []

    def callback(hwnd: int, _lparam: int) -> bool:
        results.append(hwnd)
        return True

    win32gui.EnumChildWindows(root_hwnd, callback, 0)
    return results


def find_control(root_hwnd: int, control_id: int, class_name: str | None = None) -> int:
    for hwnd in enum_descendants(root_hwnd):
        try:
            if win32gui.GetDlgCtrlID(hwnd) != control_id:
                continue
        except win32gui.error:
            continue
        if class_name and win32gui.GetClassName(hwnd) != class_name:
            continue
        return hwnd
    raise RuntimeError(f"Control id {control_id} was not found under hwnd={root_hwnd}.")


def find_child_control(root_hwnd: int, control_id: int, class_name: str | None = None) -> int | None:
    try:
        return find_control(root_hwnd, control_id, class_name)
    except RuntimeError:
        return None


def wait_for_preferences_dialog(process_id: int, main_hwnd: int) -> int:
    def resolve() -> int | None:
        matches: list[int] = []

        def callback(hwnd: int, _lparam: int) -> bool:
            if hwnd == main_hwnd or not win32gui.IsWindowVisible(hwnd):
                return True
            if win32gui.GetClassName(hwnd) != "#32770":
                return True
            if int(win32process.GetWindowThreadProcessId(hwnd)[1]) == process_id:
                matches.append(hwnd)
            return True

        win32gui.EnumWindows(callback, 0)
        for hwnd in matches:
            if "Preferences" in win32gui.GetWindowText(hwnd):
                return hwnd
        return matches[0] if matches else None

    return wait_for(resolve, timeout=20.0, interval=0.2, description="Preferences dialog")


def open_preferences(main_hwnd: int, process_id: int) -> int:
    win32gui.PostMessage(main_hwnd, WM_COMMAND, MP_HM_PREFS, 0)
    return wait_for_preferences_dialog(process_id, main_hwnd)


def click_button(button_hwnd: int) -> None:
    win32gui.PostMessage(button_hwnd, BM_CLICK, 0, 0)
    time.sleep(0.3)


def ensure_checkbox(checkbox_hwnd: int, desired: bool) -> None:
    current = bool(win32gui.SendMessage(checkbox_hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED)
    if current != desired:
        click_button(checkbox_hwnd)


def set_edit_text(edit_hwnd: int, text: str) -> None:
    parent = win32gui.GetParent(edit_hwnd)
    control_id = win32gui.GetDlgCtrlID(edit_hwnd)
    win32gui.SendMessage(edit_hwnd, WM_SETTEXT, 0, text)
    win32gui.PostMessage(parent, WM_COMMAND, control_id | (EN_CHANGE << 16), edit_hwnd)
    time.sleep(0.1)


def get_process_handle(hwnd: int) -> int:
    process_id = int(win32process.GetWindowThreadProcessId(hwnd)[1])
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, False, process_id)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def read_process_memory(process_handle: int, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(process_handle, address, buffer, size, ctypes.byref(bytes_read)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[: bytes_read.value]


def write_process_memory(process_handle: int, address: int, payload: bytes) -> None:
    written = ctypes.c_size_t()
    buffer = ctypes.create_string_buffer(payload)
    if not kernel32.WriteProcessMemory(process_handle, address, buffer, len(payload), ctypes.byref(written)):
        raise ctypes.WinError(ctypes.get_last_error())
    if written.value != len(payload):
        raise RuntimeError(f"Short WriteProcessMemory: wrote {written.value}, expected {len(payload)}.")


def tree_get_next(tree_hwnd: int, item: int, relation: int) -> int:
    return int(win32gui.SendMessage(tree_hwnd, TVM_GETNEXTITEM, relation, item))


def iter_tree_items(tree_hwnd: int):
    def walk(item: int):
        while item:
            yield item
            child = tree_get_next(tree_hwnd, item, TVGN_CHILD)
            if child:
                yield from walk(child)
            item = tree_get_next(tree_hwnd, item, TVGN_NEXT)

    root = tree_get_next(tree_hwnd, 0, TVGN_ROOT)
    if root:
        yield from walk(root)


def get_tree_item(tree_hwnd: int, item: int) -> dict[str, object]:
    process_handle = get_process_handle(tree_hwnd)
    try:
        text_capacity = 512
        text_bytes = text_capacity * 2
        with RemoteBuffer(process_handle, ctypes.sizeof(TVITEMW)) as item_buffer, RemoteBuffer(process_handle, text_bytes) as text_buffer:
            tv_item = TVITEMW(
                mask=TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE,
                hItem=ctypes.c_void_p(item),
                pszText=ctypes.c_void_p(text_buffer.address),
                cchTextMax=text_capacity,
            )
            write_process_memory(process_handle, item_buffer.address, bytes(tv_item))
            if not win32gui.SendMessage(tree_hwnd, TVM_GETITEMW, 0, item_buffer.address):
                raise RuntimeError(f"TVM_GETITEMW failed for tree item {item}.")
            returned = TVITEMW.from_buffer_copy(read_process_memory(process_handle, item_buffer.address, ctypes.sizeof(TVITEMW)))
            raw_text = read_process_memory(process_handle, text_buffer.address, text_bytes)
            text = raw_text.decode("utf-16-le", errors="ignore").split("\0", 1)[0]
            return {
                "handle": item,
                "text": text,
                "image": int(returned.iImage),
                "selected_image": int(returned.iSelectedImage),
            }
    finally:
        kernel32.CloseHandle(process_handle)


def collect_tree_texts(tree_hwnd: int) -> list[str]:
    texts: list[str] = []
    for item in iter_tree_items(tree_hwnd):
        texts.append(str(get_tree_item(tree_hwnd, item)["text"]))
    return texts


def find_tree_item_by_label(tree_hwnd: int, label: str) -> int:
    for item in iter_tree_items(tree_hwnd):
        text = str(get_tree_item(tree_hwnd, item)["text"])
        if text == label or text.startswith(label + ":"):
            return item
    raise RuntimeError(f"Tree item label was not found: {label!r}.")


def select_tree_item(tree_hwnd: int, item: int) -> None:
    win32gui.SendMessage(tree_hwnd, TVM_EXPAND, TVE_EXPAND, item)
    win32gui.SendMessage(tree_hwnd, TVM_ENSUREVISIBLE, 0, item)
    win32gui.SendMessage(tree_hwnd, TVM_SELECTITEM, TVGN_CARET, item)
    time.sleep(0.3)


def select_page(dialog_hwnd: int, page_text: str) -> None:
    page_tree = find_control(dialog_hwnd, PAGE_TREE_ID, "SysTreeView32")
    try:
        item = find_tree_item_by_label(page_tree, page_text)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc} Available pages: {collect_tree_texts(page_tree)!r}.") from exc
    select_tree_item(page_tree, item)


def set_tree_edit(tree_hwnd: int, label: str, value: str) -> None:
    item = find_tree_item_by_label(tree_hwnd, label)
    select_tree_item(tree_hwnd, item)
    edit_hwnd = wait_for(
        lambda: find_child_control(tree_hwnd, TREE_OPTIONS_EDITBOX_ID, "Edit"),
        timeout=5.0,
        interval=0.1,
        description=f"tree edit for {label}",
    )
    set_edit_text(edit_hwnd, value)


def activate_tree_item(tree_hwnd: int, label: str) -> None:
    item = find_tree_item_by_label(tree_hwnd, label)
    select_tree_item(tree_hwnd, item)
    win32gui.SendMessage(tree_hwnd, WM_CHAR, ord(" "), 0)
    time.sleep(0.3)


def configure_profile(config_dir: Path, app_exe: Path, rest_port: int) -> None:
    preferences_path = config_dir / "preferences.ini"
    text = live_common.read_ini_text(preferences_path)
    template_path = app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"

    for key, value in (
        ("ConfirmExit", "0"),
        ("Autoconnect", "0"),
        ("Reconnect", "0"),
        ("NetworkED2K", "0"),
        ("NetworkKademlia", "0"),
        ("BeepOnError", "0"),
        ("CreateCrashDump", "0"),
        ("MaxLogFileSize", "1048576"),
        ("MaxLogBuff", "64"),
        ("LogFileFormat", "0"),
        ("PreviewSmallBlocks", "0"),
        ("TxtEditor", "notepad.exe"),
        ("MaxChatHistoryLines", "100"),
        ("MaxMessageSessions", "50"),
        ("IPFilterUpdateEnabled", "0"),
        ("IPFilterUpdatePeriodDays", "7"),
        ("IPFilterLastUpdateTime", str(int(time.time()))),
        ("IPFilterUpdateUrl", "http://upd.emule-security.org/ipfilter.zip"),
    ):
        text = live_common.patch_ini_value(text, key, value)

    for key, value in (
        ("Password", ""),
        ("PasswordLow", ""),
        ("ApiKey", "preference-ui-e2e-key"),
        ("BindAddr", "127.0.0.1"),
        ("Port", str(rest_port)),
        ("WebUseUPnP", "0"),
        ("Enabled", "0"),
        ("UseGzip", "1"),
        ("PageRefreshTime", "120"),
        ("UseLowRightsUser", "0"),
        ("AllowAdminHiLevelFunc", "0"),
        ("WebTimeoutMins", "5"),
        ("UseHTTPS", "0"),
        ("HTTPSCertificate", ""),
        ("HTTPSKey", ""),
        ("MaxFileUploadSizeMB", "5"),
        ("AllowedIPs", ""),
    ):
        text = rest_smoke.upsert_ini_section_value(text, "WebServer", key, value)

    for key, value in (
        ("Mode", "0"),
        ("FileFormat", "0"),
        ("File", ""),
        ("Interval", "5"),
    ):
        text = rest_smoke.upsert_ini_section_value(text, "PerfLog", key, value)

    text = live_common.patch_ini_value(text, "WebTemplateFile", str(template_path))
    live_common.write_utf16_ini_text(preferences_path, text)
    live_common.apply_live_network_policy(config_dir)


def parse_ini_sections(path: Path) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current_section = ""
    for raw_line in live_common.read_ini_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            sections.setdefault(current_section, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        sections.setdefault(current_section or "eMule", {})[key.strip()] = value.strip()
    return sections


def assert_ini_values(preferences_path: Path, expected: dict[str, dict[str, str]]) -> None:
    sections = parse_ini_sections(preferences_path)
    mismatches: list[str] = []
    for section, values in expected.items():
        actual_section = sections.get(section, {})
        for key, expected_value in values.items():
            actual_value = actual_section.get(key)
            if actual_value != expected_value:
                mismatches.append(f"[{section}] {key}: expected {expected_value!r}, got {actual_value!r}")
    if mismatches:
        raise AssertionError("Persisted preferences mismatch:\n" + "\n".join(mismatches))


def run_preference_roundtrip(paths: harness_cli_common.HarnessRunPaths, args: argparse.Namespace) -> dict[str, object]:
    require_pywinauto()
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    artifacts_dir = paths.source_artifacts_dir
    profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    rest_port = rest_smoke.choose_listen_port()
    config_dir = Path(profile["config_dir"])
    preferences_path = config_dir / "preferences.ini"
    perf_log_file = artifacts_dir / "perf-ui-e2e.log"
    configure_profile(config_dir, paths.app_exe, rest_port)

    app = None
    dialog_hwnd: int | None = None
    pending_error: Exception | None = None
    report: dict[str, object] = {
        "suite": "preference-ui-e2e",
        "status": "failed",
        "launch_inputs": {
            "app_exe": str(paths.app_exe),
            "seed_config_dir": str(seed_config_dir),
            "artifacts_dir": str(artifacts_dir),
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(config_dir),
            "rest_port": rest_port,
        },
        "checks": {},
        "cleanup": {},
    }

    try:
        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]))
        main_window = live_common.wait_for_main_window(app)
        process_id = int(win32process.GetWindowThreadProcessId(main_window.handle)[1])
        report["launched_process_id"] = process_id

        dialog_hwnd = open_preferences(main_window.handle, process_id)

        select_page(dialog_hwnd, "Security")
        set_edit_text(find_control(dialog_hwnd, IDC_UPDATEURL, "Edit"), "http://upd.emule-security.org/ipfilter.zip")
        ensure_checkbox(find_control(dialog_hwnd, IDC_AUTOUPDATE_IPFILTER, "Button"), True)
        set_edit_text(find_control(dialog_hwnd, IDC_IPFILTERPERIOD, "Edit"), "11")

        select_page(dialog_hwnd, "Web Interface")
        ensure_checkbox(find_control(dialog_hwnd, IDC_WSENABLED, "Button"), True)
        set_edit_text(find_control(dialog_hwnd, IDC_WSPORT, "Edit"), str(rest_port))
        set_edit_text(find_control(dialog_hwnd, IDC_WEBBINDADDR, "Edit"), "127.0.0.1")
        set_edit_text(find_control(dialog_hwnd, IDC_TMPLPATH, "Edit"), str(paths.app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"))
        set_edit_text(find_control(dialog_hwnd, IDC_WS_MAXFILEUPLOAD, "Edit"), "23")
        set_edit_text(find_control(dialog_hwnd, IDC_WS_ALLOWEDIPS, "Edit"), "127.0.0.1;10.1.2.3")

        select_page(dialog_hwnd, "Extended")
        tweaks_tree = find_control(dialog_hwnd, IDC_EXT_OPTS, "SysTreeView32")
        tree_texts = collect_tree_texts(tweaks_tree)
        missing_labels = [label for label in TWEAKS_EXPECTED_LABELS if not any(text == label or text.startswith(label + ":") for text in tree_texts)]
        if missing_labels:
            raise AssertionError(f"Tweaks tree is missing expected labels: {missing_labels!r}")
        report["checks"]["tweaks_labels"] = {"count": len(TWEAKS_EXPECTED_LABELS)}

        activate_tree_item(tweaks_tree, "Beep on important errors")
        activate_tree_item(tweaks_tree, "Create dump automatically")
        set_tree_edit(tweaks_tree, "Maximum log file size [KiB]", "2048")
        set_tree_edit(tweaks_tree, "Log view buffer [KiB]", "128")
        activate_tree_item(tweaks_tree, "UTF-8")
        activate_tree_item(tweaks_tree, "Enable performance bandwidth log")
        activate_tree_item(tweaks_tree, "MRTG")
        set_tree_edit(tweaks_tree, "Performance log file", str(perf_log_file))
        set_tree_edit(tweaks_tree, "Performance log interval [minutes]", "7")
        set_tree_edit(tweaks_tree, "Text editor command", "notepad.exe /A")
        activate_tree_item(tweaks_tree, "Force even with missing first block")
        set_tree_edit(tweaks_tree, "Maximum chat history lines", "321")
        set_tree_edit(tweaks_tree, "Maximum message sessions", "61")

        select_tree_item(tweaks_tree, find_tree_item_by_label(tweaks_tree, TWEAKS_LOGGING_GROUP_LABEL))
        click_button(find_control(dialog_hwnd, IDOK, "Button"))
        wait_for(lambda: not win32gui.IsWindow(dialog_hwnd), timeout=20.0, interval=0.2, description="Preferences dialog close")

        expected = {
            "eMule": {
                "BeepOnError": "1",
                "CreateCrashDump": "2",
                "MaxLogFileSize": "2097152",
                "MaxLogBuff": "128",
                "LogFileFormat": "1",
                "PreviewSmallBlocks": "2",
                "TxtEditor": "notepad.exe /A",
                "MaxChatHistoryLines": "321",
                "MaxMessageSessions": "61",
                "IPFilterUpdateEnabled": "1",
                "IPFilterUpdatePeriodDays": "11",
                "IPFilterUpdateUrl": "http://upd.emule-security.org/ipfilter.zip",
            },
            "WebServer": {
                "Enabled": "1",
                "BindAddr": "127.0.0.1",
                "Port": str(rest_port),
                "MaxFileUploadSizeMB": "23",
                "AllowedIPs": "127.0.0.1;10.1.2.3",
            },
            "PerfLog": {
                "Mode": "2",
                "FileFormat": "1",
                "File": str(perf_log_file),
                "Interval": "7",
            },
        }
        assert_ini_values(preferences_path, expected)
        report["checks"]["persisted_preferences"] = expected
        report["status"] = "passed"
    except Exception as exc:
        pending_error = exc
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        cleanup = report["cleanup"]
        assert isinstance(cleanup, dict)
        if dialog_hwnd is not None and win32gui.IsWindow(dialog_hwnd):
            try:
                click_button(find_control(dialog_hwnd, IDCANCEL, "Button"))
                wait_for(lambda: not win32gui.IsWindow(dialog_hwnd), timeout=10.0, interval=0.2, description="Preferences dialog cancel")
                cleanup["preferences_dialog_closed"] = True
            except Exception as exc:
                cleanup["preferences_dialog_closed"] = False
                cleanup["preferences_dialog_close_error"] = repr(exc)
        if app is not None and not args.keep_running:
            try:
                live_common.close_app_cleanly(app)
                cleanup["app_closed"] = True
            except Exception as exc:
                cleanup["app_closed"] = False
                cleanup["app_close_error"] = repr(exc)
                if pending_error is None:
                    pending_error = exc
                    report["status"] = "failed"
                    report["error"] = {"type": type(exc).__name__, "message": str(exc)}

    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    args = parser.parse_args()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="preference-ui-e2e",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts or args.keep_running,
    )

    report_path = paths.source_artifacts_dir / "ui-summary.json"
    report: dict[str, object] | None = None
    try:
        report = run_preference_roundtrip(paths, args)
        write_json(report_path, report)
        if report.get("status") != "passed":
            raise RuntimeError(f"Preference UI E2E failed: {report!r}")
    except Exception as exc:
        if report is None:
            report = {"suite": "preference-ui-e2e", "status": "failed"}
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        write_json(report_path, report)
        raise
    finally:
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        if not paths.keep_source_artifacts and not args.keep_running:
            shutil.rmtree(paths.source_artifacts_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
