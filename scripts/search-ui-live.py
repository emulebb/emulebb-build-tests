"""Live Win32 UI smoke for starting eD2K and Kad searches from the Search page."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import win32con
import win32gui
import win32process


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
rest_smoke = load_local_module("rest_api_smoke_for_search_ui", "rest-api-smoke.py")

from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL, refresh_seed_files
from emule_test_harness import live_wire_inputs

try:
    from pywinauto import Application
    _PYWINAUTO_IMPORT_ERROR = None
except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
    Application = object  # type: ignore[assignment]
    _PYWINAUTO_IMPORT_ERROR = exc


BM_CLICK = 0x00F5
CB_SETCURSEL = 0x014E
CBN_SELCHANGE = 1
EN_CHANGE = 0x0300
WM_COMMAND = 0x0111
WM_SETTEXT = 0x000C

MP_HM_SEARCH = 10212
IDC_SEARCHNAME = 2183
IDC_STARTS = 2189
IDC_COMBO1 = 2175
IDC_SEARCHLIST = 2172
IDC_TAB1 = 2442
IDC_SEARCH_STATUS = 3106

LVM_FIRST = 0x1000
LVM_GETITEMCOUNT = LVM_FIRST + 4
LVM_ENSUREVISIBLE = LVM_FIRST + 19
LVM_SETITEMSTATE = LVM_FIRST + 43
LVM_SETSELECTIONMARK = LVM_FIRST + 67
LVM_GETITEMTEXTW = LVM_FIRST + 115
TCM_FIRST = 0x1300
TCM_GETITEMCOUNT = TCM_FIRST + 4

LVIF_TEXT = 0x0001
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

MP_RESUMEPAUSED = 10228

SEARCH_TYPE_ED2K_SERVER = 1
SEARCH_TYPE_KADEMLIA = 3
SUITE_INCONCLUSIVE_RETURN_CODE = 2
MAX_UI_DOWNLOAD_CANDIDATE_BYTES = 20 * 1024 * 1024 * 1024
UNSAFE_DOWNLOAD_SUFFIXES = (
    ".ade",
    ".adp",
    ".app",
    ".appx",
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".dll",
    ".exe",
    ".hta",
    ".ins",
    ".iso.exe",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".msp",
    ".pif",
    ".ps1",
    ".scr",
    ".sh",
    ".vb",
    ".vbe",
    ".vbs",
    ".wsf",
)
UNSAFE_FILE_TYPES = {"program", "video"}

DEFAULT_SEARCH_PLAN = (
    {"method": "server", "method_index": SEARCH_TYPE_ED2K_SERVER},
    {"method": "kad", "method_index": SEARCH_TYPE_KADEMLIA},
)
DEFAULT_UI_SEARCH_ROUNDS = 1
DEFAULT_UI_DOWNLOAD_LIFECYCLE_COUNT = 1

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


class LVITEMW(ctypes.Structure):
    """Mirror of Win32 LVITEMW for remote Search result text retrieval."""

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


class RemoteBuffer:
    """Owns one temporary allocation inside the target process."""

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


def choose_rest_listen_port() -> int:
    """Returns one ephemeral localhost TCP port for a live REST verification listener."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_json(path: Path, payload) -> None:
    """Writes a stable UTF-8 JSON artifact."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def build_search_plan(search_terms: tuple[str, ...], search_rounds: int) -> list[dict[str, object]]:
    """Builds a live Search UI plan without exposing operator-owned terms in reports."""

    if search_rounds <= 0:
        raise ValueError("Search UI rounds must be greater than zero.")
    if not search_terms:
        raise ValueError("Search UI live testing requires at least one generic live-wire term.")

    plan: list[dict[str, object]] = []
    for round_index in range(search_rounds):
        for method_index, method in enumerate(DEFAULT_SEARCH_PLAN):
            term_index = (round_index * len(DEFAULT_SEARCH_PLAN) + method_index) % len(search_terms)
            method_name = str(method["method"])
            plan.append(
                {
                    "scenario": f"{method_name}-search-round-{round_index + 1}",
                    "query": search_terms[term_index],
                    "query_index": term_index,
                    "query_count": len(search_terms),
                    "round": round_index + 1,
                    "method": method_name,
                    "method_index": int(method["method_index"]),
                }
            )
    return plan


def summarize_search_plan(search_plan: list[dict[str, object]]) -> list[dict[str, object]]:
    """Returns a redacted summary of the UI search plan."""

    return [
        {
            "scenario": row["scenario"],
            "method": row["method"],
            "round": row["round"],
            "query_index": row["query_index"],
            "query_count": row["query_count"],
        }
        for row in search_plan
    ]


def configure_search_ui_profile(config_dir: Path, app_exe: Path, api_key: str, port: int, bind_interface: str) -> None:
    """Enables live network policy and localhost REST for the Search UI scenario."""

    rest_smoke.configure_webserver_profile(
        config_dir,
        app_exe,
        api_key,
        port,
        "127.0.0.1",
    )
    rest_smoke.apply_p2p_bind_interface_override(config_dir, bind_interface)


def http_request(base_url: str, path: str, *, api_key: str, request_timeout_seconds: float = 5.0) -> dict[str, object]:
    """Performs one JSON REST GET request against the live WebServer API."""

    request = urllib.request.Request(base_url + path, method="GET", headers={"X-API-Key": api_key})
    with urllib.request.urlopen(request, timeout=request_timeout_seconds) as response:
        body_text = response.read().decode("utf-8", errors="replace")
        payload = None
        if "application/json" in response.headers.get("Content-Type", ""):
            payload = json.loads(body_text)
        return {
            "status": int(response.status),
            "body_text": body_text,
            "json": rest_smoke.unwrap_rest_payload(payload),
            "raw_json": payload,
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


def find_control(parent_hwnd: int, control_id: int, class_name: str | None = None) -> int:
    """Finds one descendant control by dialog ID and optional Win32 class name."""

    matches: list[int] = []

    def visit(hwnd: int, _param) -> bool:
        if win32gui.GetDlgCtrlID(hwnd) == control_id:
            if class_name is None or win32gui.GetClassName(hwnd) == class_name:
                matches.append(hwnd)
                return False
        return True

    win32gui.EnumChildWindows(parent_hwnd, visit, None)
    if not matches:
        expected = f" id={control_id}" + (f" class={class_name}" if class_name else "")
        raise RuntimeError(f"Could not find Search UI control{expected}.")
    return matches[0]


def notify_parent_control_change(control_hwnd: int, control_id: int, notification: int) -> None:
    """Sends a standard WM_COMMAND control-notification message to the parent."""

    parent = win32gui.GetParent(control_hwnd)
    win32gui.SendMessage(parent, WM_COMMAND, (notification << 16) | control_id, control_hwnd)


def open_search_page(main_hwnd: int) -> None:
    """Activates the main Search page."""

    win32gui.SendMessage(main_hwnd, WM_COMMAND, MP_HM_SEARCH, 0)


def start_search_from_ui(main_hwnd: int, query: str, method_index: int) -> None:
    """Starts one search through the real Search page controls."""

    open_search_page(main_hwnd)
    edit_hwnd = wait_for(lambda: find_control(main_hwnd, IDC_SEARCHNAME, "Edit"), 10.0, 0.2, "Search text edit")
    method_hwnd = find_control(main_hwnd, IDC_COMBO1, "ComboBox")
    start_hwnd = find_control(main_hwnd, IDC_STARTS, "Button")

    win32gui.SendMessage(method_hwnd, CB_SETCURSEL, method_index, 0)
    notify_parent_control_change(method_hwnd, IDC_COMBO1, CBN_SELCHANGE)
    win32gui.SendMessage(edit_hwnd, WM_SETTEXT, 0, query)
    notify_parent_control_change(edit_hwnd, IDC_SEARCHNAME, EN_CHANGE)
    win32gui.SendMessage(start_hwnd, BM_CLICK, 0, 0)


def get_tab_count(tab_hwnd: int) -> int:
    """Returns the Search results tab count."""

    return int(win32gui.SendMessage(tab_hwnd, TCM_GETITEMCOUNT, 0, 0))


def get_list_count(list_hwnd: int) -> int:
    """Returns the Search results list row count."""

    return int(win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0))


def get_search_status_text(main_hwnd: int) -> dict[str, object]:
    """Returns the live Search activity overlay state."""

    try:
        status_hwnd = find_control(main_hwnd, IDC_SEARCH_STATUS, "Static")
    except RuntimeError:
        return {"present": False, "visible": False, "text": ""}
    return {
        "present": True,
        "visible": bool(win32gui.IsWindowVisible(status_hwnd)),
        "text": win32gui.GetWindowText(status_hwnd),
    }


def open_process(process_id: int) -> int:
    """Opens the target app process for list-view text marshalling."""

    handle = kernel32.OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        False,
        process_id,
    )
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def close_process(handle: int) -> None:
    """Closes a Win32 process handle."""

    if handle:
        kernel32.CloseHandle(handle)


def write_remote(process_handle: int, address: int, data: bytes) -> None:
    """Writes bytes into the target process."""

    written = ctypes.c_size_t()
    buffer = ctypes.create_string_buffer(data)
    if not kernel32.WriteProcessMemory(process_handle, address, buffer, len(data), ctypes.byref(written)):
        raise ctypes.WinError(ctypes.get_last_error())
    if written.value != len(data):
        raise RuntimeError(f"Short WriteProcessMemory: {written.value} of {len(data)} bytes.")


def read_remote(process_handle: int, address: int, size: int) -> bytes:
    """Reads bytes from the target process."""

    read = ctypes.c_size_t()
    buffer = ctypes.create_string_buffer(size)
    if not kernel32.ReadProcessMemory(process_handle, address, buffer, size, ctypes.byref(read)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bytes(buffer.raw[: read.value])


def get_list_item_text(process_handle: int, list_hwnd: int, row_index: int, column_index: int) -> str:
    """Reads one Search result list cell using LVM_GETITEMTEXTW."""

    text_chars = 512
    text_bytes = text_chars * 2
    item_size = ctypes.sizeof(LVITEMW)
    with RemoteBuffer(process_handle, item_size + text_bytes) as remote:
        text_address = remote.address + item_size
        item = LVITEMW()
        item.mask = LVIF_TEXT
        item.iItem = row_index
        item.iSubItem = column_index
        item.pszText = text_address
        item.cchTextMax = text_chars
        write_remote(process_handle, remote.address, bytes(item))
        win32gui.SendMessage(list_hwnd, LVM_GETITEMTEXTW, row_index, remote.address)
        raw = read_remote(process_handle, text_address, text_bytes)
    return raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]


def get_search_result_row(process_handle: int, list_hwnd: int, row_index: int) -> dict[str, object]:
    """Reads the safety-relevant Search result cells from one visible row."""

    return {
        "index": row_index,
        "name": get_list_item_text(process_handle, list_hwnd, row_index, 0),
        "size": get_list_item_text(process_handle, list_hwnd, row_index, 1),
        "availability": get_list_item_text(process_handle, list_hwnd, row_index, 2),
        "file_type": get_list_item_text(process_handle, list_hwnd, row_index, 4),
        "hash": get_list_item_text(process_handle, list_hwnd, row_index, 5).lower(),
    }


def parse_display_size_bytes(value: str) -> int | None:
    """Parses eMule display sizes such as `1.23 MB` into an approximate byte count."""

    parts = value.strip().replace(",", ".").split()
    if len(parts) < 2:
        return None
    try:
        amount = float(parts[0])
    except ValueError:
        return None
    unit = parts[1].lower()
    multipliers = {
        "b": 1,
        "byte": 1,
        "bytes": 1,
        "kb": 1024,
        "kib": 1024,
        "mb": 1024 * 1024,
        "mib": 1024 * 1024,
        "gb": 1024 * 1024 * 1024,
        "gib": 1024 * 1024 * 1024,
    }
    multiplier = multipliers.get(unit)
    if multiplier is None:
        return None
    return int(amount * multiplier)


def is_lowercase_md4_hash(value: object) -> bool:
    """Returns true when one hash token is the strict lowercase MD4 shape."""

    if not isinstance(value, str) or len(value) != 32:
        return False
    return all(("0" <= ch <= "9") or ("a" <= ch <= "f") for ch in value)


def is_safe_ui_download_candidate(row: dict[str, object]) -> bool:
    """Rejects unsafe Search UI rows before invoking the UI download command."""

    name = str(row.get("name") or "").strip().lower()
    file_type = str(row.get("file_type") or "").strip().lower()
    size_bytes = parse_display_size_bytes(str(row.get("size") or ""))
    if not name or name.endswith(UNSAFE_DOWNLOAD_SUFFIXES):
        return False
    if file_type in UNSAFE_FILE_TYPES:
        return False
    if not is_lowercase_md4_hash(row.get("hash")):
        return False
    return size_bytes is not None and 0 < size_bytes <= MAX_UI_DOWNLOAD_CANDIDATE_BYTES


def select_list_row(process_handle: int, list_hwnd: int, row_index: int) -> None:
    """Selects one Search result row."""

    win32gui.SendMessage(list_hwnd, LVM_ENSUREVISIBLE, row_index, 0)
    with RemoteBuffer(process_handle, ctypes.sizeof(LVITEMW)) as remote:
        clear_state = LVITEMW()
        clear_state.stateMask = LVIS_SELECTED | LVIS_FOCUSED
        write_remote(process_handle, remote.address, bytes(clear_state))
        win32gui.SendMessage(list_hwnd, LVM_SETITEMSTATE, -1, remote.address)

        select_state = LVITEMW()
        select_state.stateMask = LVIS_SELECTED | LVIS_FOCUSED
        select_state.state = LVIS_SELECTED | LVIS_FOCUSED
        write_remote(process_handle, remote.address, bytes(select_state))
        win32gui.SendMessage(list_hwnd, LVM_SETITEMSTATE, row_index, remote.address)
    win32gui.SendMessage(list_hwnd, LVM_SETSELECTIONMARK, 0, row_index)


def find_safe_ui_download_candidate(process_handle: int, list_hwnd: int, row_count: int) -> dict[str, object] | None:
    """Returns the first safe Search UI candidate from visible rows."""

    inspected: list[dict[str, object]] = []
    for row_index in range(min(row_count, 100)):
        row = get_search_result_row(process_handle, list_hwnd, row_index)
        row["safe"] = is_safe_ui_download_candidate(row)
        inspected.append(row)
        if row["safe"]:
            row["inspected_count"] = len(inspected)
            return row
    return None


def trigger_paused_download_from_ui(process_handle: int, list_hwnd: int, row_count: int) -> dict[str, object]:
    """Selects one safe row and invokes the Search result `download paused` command."""

    candidate = find_safe_ui_download_candidate(process_handle, list_hwnd, row_count)
    if candidate is None:
        return {
            "ok": False,
            "reason": "no safe visible Search UI download candidate",
            "inspected_row_limit": min(row_count, 100),
        }
    select_list_row(process_handle, list_hwnd, int(candidate["index"]))
    win32gui.SendMessage(list_hwnd, WM_COMMAND, MP_RESUMEPAUSED, 0)
    return {
        "ok": True,
        "candidate": {
            "index": candidate["index"],
            "name_present": bool(candidate["name"]),
            "size": candidate["size"],
            "availability": candidate["availability"],
            "file_type": candidate["file_type"],
            "hash": candidate["hash"],
            "inspected_count": candidate["inspected_count"],
        },
    }


def wait_for_transfer(base_url: str, api_key: str, transfer_hash: str, timeout_seconds: float) -> dict[str, object]:
    """Polls until a UI-triggered transfer appears through native REST."""

    def resolve():
        result = rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash}",
            api_key=api_key,
            request_timeout_seconds=10.0,
        )
        if int(result["status"]) == 200:
            return rest_smoke.compact_http_result(result)
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description="UI-triggered transfer")


def request_transfer_operation(base_url: str, api_key: str, transfer_hash: str, operation: str) -> dict[str, object]:
    """Invokes one native transfer lifecycle operation and verifies the response envelope."""

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash}/operations/{operation}",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    payload = rest_smoke.require_json_object(result, 200)
    require_transfer_hash_success(payload, transfer_hash)
    return rest_smoke.compact_http_result(result)


def require_transfer_hash_success(payload: dict[str, object], transfer_hash: str) -> None:
    """Requires either a transfer payload or a successful bulk item for one hash."""

    if payload.get("hash") == transfer_hash:
        return
    items = payload.get("items")
    if isinstance(items, list):
        matching = [item for item in items if isinstance(item, dict) and item.get("hash") == transfer_hash]
        assert matching, payload
        assert all(item.get("ok") is True for item in matching), payload
        return
    assert payload.get("ok") is not False and "error" not in payload, payload


def wait_for_transfer_condition(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    timeout_seconds: float,
    description: str,
    predicate,
) -> dict[str, object]:
    """Polls one transfer until the supplied state predicate is true."""

    observations: list[dict[str, object]] = []

    def resolve():
        result = rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash}",
            api_key=api_key,
            request_timeout_seconds=10.0,
        )
        status = int(result["status"])
        payload = result.get("json") if isinstance(result.get("json"), dict) else {}
        assert isinstance(payload, dict)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "status": status,
                "state": payload.get("state"),
                "stopped": payload.get("stopped"),
            }
        )
        if status == 200 and predicate(payload):
            compact = rest_smoke.compact_http_result(result)
            compact["observations"] = observations
            return compact
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description=description)


def wait_for_transfer_absent(base_url: str, api_key: str, transfer_hash: str, timeout_seconds: float) -> dict[str, object]:
    """Polls until one removed transfer no longer resolves through REST."""

    observations: list[dict[str, object]] = []

    def resolve():
        result = rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash}",
            api_key=api_key,
            request_timeout_seconds=10.0,
        )
        observations.append({"observed_at": round(time.time(), 3), "status": int(result["status"])})
        if int(result["status"]) == 404:
            compact = rest_smoke.compact_http_result(result)
            compact["observations"] = observations
            return compact
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description="removed transfer absence")


def delete_transfer(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Removes one sandboxed transfer with native partial-file cleanup semantics."""

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": True},
        request_timeout_seconds=30.0,
    )
    payload = rest_smoke.require_json_object(result, 200)
    require_transfer_hash_success(payload, transfer_hash)
    return rest_smoke.compact_http_result(result)


def exercise_transfer_lifecycle(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Covers pause, resume, stop, and remove on the UI-created transfer."""

    lifecycle: dict[str, object] = {}
    lifecycle["resume"] = {
        "operation": request_transfer_operation(base_url, api_key, transfer_hash, "resume"),
        "state": wait_for_transfer_condition(
            base_url,
            api_key,
            transfer_hash,
            timeout_seconds,
            "resumed transfer state",
            lambda payload: payload.get("state") != "paused" and not bool(payload.get("stopped")),
        ),
    }
    lifecycle["pause"] = {
        "operation": request_transfer_operation(base_url, api_key, transfer_hash, "pause"),
        "state": wait_for_transfer_condition(
            base_url,
            api_key,
            transfer_hash,
            timeout_seconds,
            "paused transfer state",
            lambda payload: payload.get("state") == "paused" and not bool(payload.get("stopped")),
        ),
    }
    lifecycle["stop"] = {
        "operation": request_transfer_operation(base_url, api_key, transfer_hash, "stop"),
        "state": wait_for_transfer_condition(
            base_url,
            api_key,
            transfer_hash,
            timeout_seconds,
            "stopped transfer state",
            lambda payload: bool(payload.get("stopped")) or payload.get("state") == "stopped",
        ),
    }
    lifecycle["remove"] = {
        "operation": delete_transfer(base_url, api_key, transfer_hash),
        "state": wait_for_transfer_absent(base_url, api_key, transfer_hash, timeout_seconds),
    }
    return lifecycle


def wait_for_ui_started_search(main_hwnd: int, previous_tab_count: int, scenario: str, method: str) -> dict[str, object]:
    """Waits until the Search tab control records the UI-started search."""

    observations: list[dict[str, object]] = []

    def resolve():
        tab_hwnd = find_control(main_hwnd, IDC_TAB1, "SysTabControl32")
        tab_count = get_tab_count(tab_hwnd)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "tab_count": tab_count,
            }
        )
        if tab_count > previous_tab_count:
            return {"tab_count": tab_count, "observations": observations}
        return None

    return wait_for(resolve, timeout=30.0, interval=1.0, description=f"UI-started {method} search scenario {scenario}")


def wait_for_search_result_rows(main_hwnd: int, timeout_seconds: float) -> dict[str, object]:
    """Waits for the active Search results list to expose at least one row."""

    observations: list[dict[str, object]] = []

    def resolve():
        list_hwnd = find_control(main_hwnd, IDC_SEARCHLIST, "SysListView32")
        row_count = get_list_count(list_hwnd)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "row_count": row_count,
            }
        )
        if row_count > 0:
            return {"row_count": row_count, "observations": observations}
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="Search result rows")


def wait_for_search_progress_observation(main_hwnd: int, timeout_seconds: float = 8.0) -> dict[str, object]:
    """Waits for either the Search progress overlay or fast-arriving rows."""

    observations: list[dict[str, object]] = []

    def resolve():
        status = get_search_status_text(main_hwnd)
        list_hwnd = find_control(main_hwnd, IDC_SEARCHLIST, "SysListView32")
        row_count = get_list_count(list_hwnd)
        observation = {
            "observed_at": round(time.time(), 3),
            "status": status,
            "row_count": row_count,
        }
        observations.append(observation)
        if bool(status.get("visible")) and str(status.get("text") or "").strip():
            return {
                "seen_status": True,
                "status_text": status["text"],
                "row_count": row_count,
                "observations": observations,
            }
        if row_count > 0:
            return {
                "seen_status": False,
                "reason": "results-arrived-before-progress-overlay",
                "row_count": row_count,
                "observations": observations,
            }
        return None

    return wait_for(
        resolve,
        timeout=timeout_seconds,
        interval=0.25,
        description="Search progress overlay or first result rows",
    )


def capture_network_state(base_url: str, api_key: str) -> dict[str, object]:
    """Captures server and Kad state for inconclusive live-network reports."""

    snapshots: dict[str, object] = {}
    for name, path in (
        ("status", "/api/v1/status"),
        ("kad", "/api/v1/kad"),
        ("servers", "/api/v1/servers"),
    ):
        try:
            snapshots[name] = rest_smoke.compact_http_result(
                rest_smoke.http_request(
                    base_url,
                    path,
                    api_key=api_key,
                    request_timeout_seconds=10.0,
                )
            )
        except Exception as exc:
            snapshots[name] = {
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            }
    return snapshots


def run_search_ui_live(
    *,
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    live_wire_inputs_file: Path,
    p2p_bind_interface_name: str,
    skip_live_seed_refresh: bool,
    ui_search_rounds: int,
    ui_download_lifecycle_count: int,
    network_ready_timeout_seconds: float,
    search_observation_timeout_seconds: float,
    transfer_materialization_timeout_seconds: float,
) -> dict[str, object]:
    """Runs the UI-driven search start scenario and returns the result report."""

    if ui_download_lifecycle_count <= 0:
        raise ValueError("Search UI download lifecycle count must be greater than zero.")
    live_inputs = live_wire_inputs.load_live_wire_inputs(live_wire_inputs_file)
    search_plan = build_search_plan(live_inputs.generic_open_terms, ui_search_rounds)
    rest_api_key = "search-ui-live-key"
    rest_port = choose_rest_listen_port()
    profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="search-ui-live")
    configure_search_ui_profile(
        Path(str(profile["config_dir"])),
        app_exe,
        rest_api_key,
        rest_port,
        p2p_bind_interface_name,
    )
    seed_refresh = None
    if not skip_live_seed_refresh:
        seed_refresh = refresh_seed_files(Path(str(profile["config_dir"])))

    base_url = f"http://127.0.0.1:{rest_port}"
    report: dict[str, object] = {
        "suite": "search-ui-live",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(profile["profile_base"]),
        "rest_base_url": base_url,
        "live_seed_source_url": EMULE_SECURITY_HOME_URL,
        "live_seed_refresh": seed_refresh,
        "live_wire_inputs_file": str(live_inputs.path),
        "live_wire_generic_terms": live_wire_inputs.summarize_terms(live_inputs.generic_open_terms),
        "p2p_bind_interface_name": p2p_bind_interface_name,
        "ui_search_rounds": ui_search_rounds,
        "ui_download_lifecycle_count": ui_download_lifecycle_count,
        "search_plan": summarize_search_plan(search_plan),
        "scenarios": [],
        "searches": [],
        "download_lifecycles": [],
    }
    app = None
    process_handle = 0
    try:
        app = live_common.launch_app(
            app_exe,
            Path(str(profile["profile_base"])),
            minimized_to_tray=False,
            requires_interactive_ui=True,
        )
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)
        report["process_id"] = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        process_handle = open_process(int(report["process_id"]))
        report["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        report["main_window_is_maximized"] = report["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED

        rest_smoke.wait_for_rest_ready(base_url, rest_api_key, timeout_seconds=60.0)
        report["live_seed_imports"] = rest_smoke.exercise_live_seed_imports(
            base_url,
            rest_api_key,
            seed_refresh,
            request_timeout_seconds=60.0,
        )
        servers_result = rest_smoke.http_request(base_url, "/api/v1/servers", api_key=rest_api_key)
        server_rows = rest_smoke.require_json_array(servers_result, 200)
        report["servers"] = {"count": len(server_rows)}
        report["server_connect"] = rest_smoke.connect_to_live_server(
            base_url,
            rest_api_key,
            server_rows,
            timeout_seconds=network_ready_timeout_seconds,
        )
        kad_start = rest_smoke.http_request(
            base_url,
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=rest_api_key,
            json_body={},
        )
        report["kad_start"] = rest_smoke.compact_http_result(kad_start)
        if int(kad_start["status"]) != 200:
            raise RuntimeError(f"Kad start failed: {rest_smoke.compact_http_result(kad_start)!r}")

        tab_hwnd = find_control(main_hwnd, IDC_TAB1, "SysTabControl32")
        previous_tab_count = get_tab_count(tab_hwnd)
        for planned in search_plan:
            query = str(planned["query"])
            method = str(planned["method"])
            scenario = str(planned["scenario"])
            start_search_from_ui(main_hwnd, query, int(planned["method_index"]))
            started = wait_for_ui_started_search(main_hwnd, previous_tab_count, scenario, method)
            progress_observation = wait_for_search_progress_observation(main_hwnd)
            previous_tab_count = int(started["tab_count"])
            search_report: dict[str, object] = {
                "scenario": scenario,
                "query_index": planned["query_index"],
                "query_count": planned["query_count"],
                "round": planned["round"],
                "method": method,
                "start_observations": started["observations"],
                "progress_observation": progress_observation,
                "tab_count_after_start": started["tab_count"],
            }
            try:
                result_rows = wait_for_search_result_rows(main_hwnd, search_observation_timeout_seconds)
                search_report["result_row_count"] = result_rows["row_count"]
                search_report["result_observations"] = result_rows["observations"]
            except Exception as exc:
                search_report["result_row_count"] = 0
                search_report["result_error"] = f"{type(exc).__name__}: {exc}"
                report["searches"].append(search_report)
                report["scenarios"].append({**search_report, "status": "inconclusive"})
                continue

            list_hwnd = find_control(main_hwnd, IDC_SEARCHLIST, "SysListView32")
            if len(report["download_lifecycles"]) >= ui_download_lifecycle_count:
                search_report["download_skipped_reason"] = "download lifecycle target reached"
                report["searches"].append(search_report)
                report["scenarios"].append({**search_report, "status": "passed"})
                continue

            ui_download = trigger_paused_download_from_ui(process_handle, list_hwnd, int(result_rows["row_count"]))
            search_report["ui_download"] = ui_download
            if not bool(ui_download.get("ok")):
                report["searches"].append(search_report)
                report["scenarios"].append({**search_report, "status": "inconclusive"})
                continue

            candidate = ui_download["candidate"]
            assert isinstance(candidate, dict)
            transfer_hash = str(candidate["hash"])
            ui_download_transfer = wait_for_transfer(
                base_url,
                rest_api_key,
                transfer_hash,
                transfer_materialization_timeout_seconds,
            )
            transfer_lifecycle = exercise_transfer_lifecycle(
                base_url,
                rest_api_key,
                transfer_hash,
                transfer_materialization_timeout_seconds,
            )
            lifecycle_report = {
                "scenario": scenario,
                "candidate_hash": transfer_hash,
                "ui_download": ui_download,
                "ui_download_transfer": ui_download_transfer,
                "transfer_lifecycle": transfer_lifecycle,
            }
            report["download_lifecycles"].append(lifecycle_report)
            report["ui_download"] = ui_download
            report["ui_download_transfer"] = ui_download_transfer
            report["transfer_lifecycle"] = transfer_lifecycle
            search_report["download_lifecycle_index"] = len(report["download_lifecycles"])
            report["searches"].append(search_report)
            report["scenarios"].append({**search_report, "status": "passed"})

        if len(report["download_lifecycles"]) < ui_download_lifecycle_count:
            report["status"] = "inconclusive"
            report["inconclusive_reason"] = {
                "reason": "too few UI searches yielded safe downloadable candidates",
                "required_download_lifecycles": ui_download_lifecycle_count,
                "actual_download_lifecycles": len(report["download_lifecycles"]),
                "searches": report["searches"],
            }
            return report

        report["status"] = "passed"
        return report
    except rest_smoke.LiveNetworkUnavailableError as exc:
        report["status"] = "inconclusive"
        report["inconclusive_reason"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "network_state": capture_network_state(base_url, rest_api_key),
        }
        return report
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        write_json(artifacts_dir / "search-ui-live-result.json", report)
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


def main(argv: list[str]) -> int:
    """Parses arguments, runs the Search UI live scenario, and publishes artifacts."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(Path(__file__).resolve().parent.parent)),
    )
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--ui-search-rounds", type=int, default=DEFAULT_UI_SEARCH_ROUNDS)
    parser.add_argument("--ui-download-lifecycle-count", type=int, default=DEFAULT_UI_DOWNLOAD_LIFECYCLE_COUNT)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=240.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--transfer-materialization-timeout-seconds", type=float, default=60.0)
    args = parser.parse_args(argv)

    if _PYWINAUTO_IMPORT_ERROR is not None:
        live_common.require_pywinauto()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="search-ui-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)

    try:
        report = run_search_ui_live(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            live_wire_inputs_file=live_wire_inputs.resolve_inputs_path(paths.repo_root, args.live_wire_inputs_file),
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            skip_live_seed_refresh=args.skip_live_seed_refresh,
            ui_search_rounds=args.ui_search_rounds,
            ui_download_lifecycle_count=args.ui_download_lifecycle_count,
            network_ready_timeout_seconds=args.network_ready_timeout_seconds,
            search_observation_timeout_seconds=args.search_observation_timeout_seconds,
            transfer_materialization_timeout_seconds=args.transfer_materialization_timeout_seconds,
        )
        harness_cli_common.publish_run_artifacts(paths)
        status = str(report.get("status") or "failed")
        summary_payload = harness_cli_common.build_live_ui_summary(status=status, paths=paths)
        summary_path = paths.run_report_dir / "search-ui-live-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        if status == "inconclusive":
            return SUITE_INCONCLUSIVE_RETURN_CODE
        return 0 if status == "passed" else 1
    except Exception as exc:
        (artifacts_dir / "error.txt").write_text(f"{exc}\n", encoding="utf-8")
        harness_cli_common.publish_run_artifacts(paths)
        summary_payload = harness_cli_common.build_live_ui_summary(status="failed", paths=paths, error_message=str(exc))
        summary_path = paths.run_report_dir / "search-ui-live-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        raise


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
