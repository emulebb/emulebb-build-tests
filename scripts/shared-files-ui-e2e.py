"""Real Win32 UI regression for the Shared Files owner-data list."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
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
generated_fixture = load_local_module("create_long_paths_tree", "create-long-paths-tree.py")

WM_COMMAND = 0x0111
WM_PAINT = 0x000F
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
BM_CLICK = 0x00F5
MK_LBUTTON = 0x0001
MP_HM_FILES = 10213
MP_SHAREDIR = 10346
MP_UNSHAREDIR = 10348
MP_SHAREDIRMONITOR = 10350
IDC_RELOADSHAREDFILES = 2049
IDC_SFLIST = 2167
IDC_SF_FNAME = 3038
IDC_SHAREDDIRSTREE = 2926

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

TV_FIRST = 0x1100
TVM_EXPAND = TV_FIRST + 2
TVM_GETNEXTITEM = TV_FIRST + 10
TVM_SELECTITEM = TV_FIRST + 11
TVM_GETITEMW = TV_FIRST + 62

TVGN_ROOT = 0x0000
TVGN_NEXT = 0x0001
TVGN_CHILD = 0x0004
TVGN_CARET = 0x0009
TVE_COLLAPSE = 0x0001
TVE_EXPAND = 0x0002
TVIF_TEXT = 0x0001

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
kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
kernel32.GetProcessHandleCount.restype = ctypes.c_int
psapi = ctypes.WinDLL("psapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetGuiResources.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
user32.GetGuiResources.restype = ctypes.c_uint32
user32.UpdateWindow.argtypes = [ctypes.c_void_p]
user32.UpdateWindow.restype = ctypes.c_int

GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1

SHARED_DUPLICATE_PATH_CACHE_MAGIC = 0x50554453
SHARED_DUPLICATE_PATH_CACHE_VERSION = 1


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


class TVITEMW(ctypes.Structure):
    """Mirror of the Win32 TVITEMW structure for remote tree-view text retrieval."""

    _fields_ = [
        ("mask", ctypes.c_uint),
        ("hItem", ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32),
        ("state", ctypes.c_uint),
        ("stateMask", ctypes.c_uint),
        ("pszText", ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32),
        ("cchTextMax", ctypes.c_int),
        ("iImage", ctypes.c_int),
        ("iSelectedImage", ctypes.c_int),
        ("cChildren", ctypes.c_int),
        ("lParam", ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long),
    ]


class RECT(ctypes.Structure):
    """Mirror of the Win32 RECT structure used for cross-process item geometry queries."""

    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    """Mirror of PROCESS_MEMORY_COUNTERS_EX for process resource snapshots."""

    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


psapi.GetProcessMemoryInfo.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
    ctypes.c_uint32,
]
psapi.GetProcessMemoryInfo.restype = ctypes.c_int


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


def prepare_tree_refresh_stress_fixture(seed_config_dir: Path, artifacts_dir: Path, shared_root: Path, app_exe: Path) -> dict:
    """Creates a profile base that shares the 50k-file tree-refresh stress subtree recursively."""

    manifest = generated_fixture.ensure_fixture(shared_root, include_tree_stress=True)
    subtree = manifest["subtrees"]["shared_files_tree_stress"]
    subtree_root = Path(str(subtree["root"])).resolve()
    shared_dirs = live_common.enumerate_recursive_directories(subtree_root)
    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=artifacts_dir,
        shared_dirs=shared_dirs,
    )
    rest_api_key = "shared-files-ui-tree-stress-key"
    rest_port = choose_rest_listen_port()
    configure_rest_profile(Path(str(fixture["config_dir"])), app_exe, rest_api_key, rest_port)
    fixture.update(
        {
            "manifest_path": str(Path(str(manifest["manifest_path"])).resolve()),
            "shared_root": live_common.win_path(shared_root.resolve(), trailing_slash=True),
            "subtree_root": live_common.win_path(subtree_root, trailing_slash=True),
            "subtree_root_path": subtree_root,
            "expected_row_count": int(subtree["expected_visible_file_count"]),
            "observable_node_count": int(subtree["observable_node_count"]),
            "directory_count": int(subtree["directory_count_including_root"]),
            "stress_branch_count": int(subtree["stress_branch_count"]),
            "stress_files_per_branch": int(subtree["stress_files_per_branch"]),
            "stress_empty_children_per_branch": int(subtree["stress_empty_children_per_branch"]),
            "sample_directories": [Path(str(path)).resolve() for path in subtree["sample_directories"]],
            "shared_directory_count": len(shared_dirs),
            "rest_api_key": rest_api_key,
            "rest_port": rest_port,
            "rest_base_url": f"http://127.0.0.1:{rest_port}",
        }
    )
    return fixture


def prepare_duplicate_reuse_fixture(seed_config_dir: Path, artifacts_dir: Path) -> dict:
    """Creates a deterministic duplicate-content fixture used to prove startup hash skipping on relaunch."""

    incoming_dir = artifacts_dir / "incoming"
    temp_dir = artifacts_dir / "temp"
    shared_a_dir = artifacts_dir / "shared-a"
    shared_b_dir = artifacts_dir / "shared-b"

    incoming_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    shared_a_dir.mkdir(parents=True, exist_ok=True)
    shared_b_dir.mkdir(parents=True, exist_ok=True)

    duplicate_payload = (b"duplicate-payload-block-" * 256) + b"\r\n"
    canonical_path = shared_a_dir / "canonical_duplicate_source.bin"
    duplicate_path = shared_b_dir / "duplicate_payload_copy.bin"
    canonical_path.write_bytes(duplicate_payload)
    duplicate_path.write_bytes(duplicate_payload)

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
            "canonical_path": canonical_path,
            "duplicate_path": duplicate_path,
            "expected_visible_names": sorted([canonical_path.name, duplicate_path.name], key=str.lower),
            "duplicate_cache_path": Path(str(fixture["config_dir"])) / "shareddups.dat",
        }
    )
    return fixture


def choose_rest_listen_port() -> int:
    """Returns one ephemeral localhost TCP port for a live REST verification listener."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def configure_rest_profile(config_dir: Path, app_exe: Path, api_key: str, port: int) -> None:
    """Enables the WebServer REST listener inside one isolated Shared Files UI profile."""

    preferences_path = config_dir / "preferences.ini"
    text = live_common.read_ini_text(preferences_path)
    text = live_common.patch_ini_value(text, "ConfirmExit", "0")
    for key, value in (
        ("Autoconnect", "0"),
        ("Reconnect", "0"),
        ("NetworkED2K", "0"),
        ("NetworkKademlia", "0"),
    ):
        text = live_common.patch_ini_value(text, key, value)
    template_path = app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"
    text = live_common.patch_ini_value(text, "WebTemplateFile", str(template_path))
    for key, value in (
        ("Password", ""),
        ("PasswordLow", ""),
        ("ApiKey", api_key),
        ("BindAddr", "127.0.0.1"),
        ("Port", str(port)),
        ("WebUseUPnP", "0"),
        ("Enabled", "1"),
        ("UseGzip", "0"),
        ("PageRefreshTime", "120"),
        ("UseLowRightsUser", "0"),
        ("AllowAdminHiLevelFunc", "1"),
        ("WebTimeoutMins", "5"),
        ("UseHTTPS", "0"),
        ("HTTPSCertificate", ""),
        ("HTTPSKey", ""),
    ):
        text = live_common.upsert_ini_section_value(text, "WebServer", key, value)
    live_common.write_utf16_ini_text(preferences_path, text)
    live_common.apply_live_network_policy(config_dir)


def prepare_dynamic_folder_lifecycle_fixture(seed_config_dir: Path, artifacts_dir: Path, app_exe: Path) -> dict:
    """Creates an initially unshared folder used for live share/unshare UI mutation coverage."""

    incoming_dir = artifacts_dir / "incoming"
    temp_dir = artifacts_dir / "temp"
    candidate_dir = artifacts_dir / "dynamic-share-candidate"

    incoming_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    candidate_dir.mkdir(parents=True, exist_ok=True)

    initial_files = [
        (candidate_dir / "alpha_dynamic.txt", b"alpha dynamic shared file\r\n"),
        (candidate_dir / "beta_dynamic.bin", b"b" * 2048),
    ]
    for file_path, content in initial_files:
        file_path.write_bytes(content)

    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=artifacts_dir,
        shared_dirs=[],
        incoming_dir=incoming_dir,
        temp_dir=temp_dir,
    )
    rest_api_key = "shared-files-ui-lifecycle-key"
    rest_port = choose_rest_listen_port()
    configure_rest_profile(Path(str(fixture["config_dir"])), app_exe, rest_api_key, rest_port)
    fixture.update(
        {
            "candidate_dir": candidate_dir,
            "late_file": candidate_dir / "gamma_late.txt",
            "deleted_file": candidate_dir / "alpha_dynamic.txt",
            "initial_names": ["alpha_dynamic.txt", "beta_dynamic.bin"],
            "after_add_names": ["alpha_dynamic.txt", "beta_dynamic.bin", "gamma_late.txt"],
            "after_delete_names": ["beta_dynamic.bin", "gamma_late.txt"],
            "rest_api_key": rest_api_key,
            "rest_port": rest_port,
            "rest_base_url": f"http://127.0.0.1:{rest_port}",
        }
    )
    return fixture


def prepare_monitored_folder_events_fixture(seed_config_dir: Path, artifacts_dir: Path, app_exe: Path) -> dict:
    """Creates an initially unshared tree used for monitored filesystem event coverage."""

    incoming_dir = artifacts_dir / "incoming"
    temp_dir = artifacts_dir / "temp"
    monitor_root = artifacts_dir / "monitored-share-root"
    existing_child_dir = monitor_root / "existing-child"

    incoming_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    existing_child_dir.mkdir(parents=True, exist_ok=True)

    root_initial_file = monitor_root / "monitor_root_initial.txt"
    child_initial_file = existing_child_dir / "existing_child_initial.txt"
    root_late_file = monitor_root / "monitor_root_late.txt"
    child_late_file = existing_child_dir / "existing_child_late.txt"
    new_child_dir = monitor_root / "new-child"
    new_child_file = new_child_dir / "new_child_discovered.txt"

    root_initial_file.write_bytes(b"monitor root initial\r\n")
    child_initial_file.write_bytes(b"existing child initial\r\n")

    initial_names = [root_initial_file.name, child_initial_file.name]
    after_file_event_names = initial_names + [root_late_file.name, child_late_file.name]
    after_directory_event_names = after_file_event_names + [new_child_file.name]
    after_delete_names = [
        child_initial_file.name,
        root_late_file.name,
        child_late_file.name,
        new_child_file.name,
    ]

    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=artifacts_dir,
        shared_dirs=[],
        incoming_dir=incoming_dir,
        temp_dir=temp_dir,
    )
    rest_api_key = "shared-files-ui-monitor-key"
    rest_port = choose_rest_listen_port()
    configure_rest_profile(Path(str(fixture["config_dir"])), app_exe, rest_api_key, rest_port)
    fixture.update(
        {
            "monitor_root": monitor_root,
            "existing_child_dir": existing_child_dir,
            "root_late_file": root_late_file,
            "child_late_file": child_late_file,
            "new_child_dir": new_child_dir,
            "new_child_file": new_child_file,
            "deleted_file": root_initial_file,
            "initial_names": initial_names,
            "after_file_event_names": after_file_event_names,
            "after_directory_event_names": after_directory_event_names,
            "after_delete_names": after_delete_names,
            "rest_api_key": rest_api_key,
            "rest_port": rest_port,
            "rest_base_url": f"http://127.0.0.1:{rest_port}",
        }
    )
    return fixture


def read_duplicate_cache_header(path: Path) -> dict[str, int]:
    """Reads the duplicate-path sidecar header and returns its magic, version, and record count."""

    payload = path.read_bytes()
    if len(payload) < 10:
        raise RuntimeError(f"Duplicate cache '{path}' is too small to contain a valid header.")
    magic, version, record_count = struct.unpack_from("<IHI", payload, 0)
    return {
        "magic": int(magic),
        "version": int(version),
        "record_count": int(record_count),
    }


def wait_for_duplicate_cache_records(path: Path, *, minimum_records: int, timeout: float = 30.0) -> dict[str, int]:
    """Waits until the duplicate-path sidecar exists and exposes at least the requested record count."""

    last_header: dict[str, int] | None = None

    def probe() -> bool:
        nonlocal last_header
        if not path.exists():
            return False
        try:
            header = read_duplicate_cache_header(path)
        except Exception:
            return False
        last_header = header
        return header.get("record_count", 0) >= minimum_records

    wait_for(probe, timeout=timeout, interval=0.25, description="duplicate cache record persistence")
    if last_header is None:
        raise RuntimeError(f"Duplicate cache '{path}' never became readable.")
    return last_header


def get_profile_counter_value(summary: dict[str, object], counter_name: str, value_key: str) -> int | None:
    """Returns one integer startup-profile counter value from the summarized live result."""

    counters = summary.get("startup_profile_counters")
    if not isinstance(counters, dict):
        return None
    counter = counters.get(counter_name)
    if not isinstance(counter, dict):
        return None
    values = counter.get("values")
    if not isinstance(values, dict):
        return None
    value = values.get(value_key)
    return int(value) if isinstance(value, int) else None


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


def get_all_list_names(process_handle: int, list_hwnd: int) -> list[str]:
    """Reads all currently exposed Shared Files row names from the owner-data list."""

    count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
    return get_list_names(process_handle, list_hwnd, count)


def get_process_resource_snapshot(process_handle: int) -> dict[str, int | None]:
    """Returns a best-effort Win32 resource snapshot for the target process."""

    handle_count = ctypes.c_uint32()
    handle_value = None
    if kernel32.GetProcessHandleCount(process_handle, ctypes.byref(handle_count)):
        handle_value = int(handle_count.value)

    memory = PROCESS_MEMORY_COUNTERS_EX()
    memory.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
    private_usage = None
    working_set = None
    if psapi.GetProcessMemoryInfo(process_handle, ctypes.byref(memory), memory.cb):
        private_usage = int(memory.PrivateUsage)
        working_set = int(memory.WorkingSetSize)

    return {
        "handles": handle_value,
        "gdi_objects": int(user32.GetGuiResources(process_handle, GR_GDIOBJECTS)),
        "user_objects": int(user32.GetGuiResources(process_handle, GR_USEROBJECTS)),
        "private_bytes": private_usage,
        "working_set_bytes": working_set,
    }


def diff_resource_snapshots(before: dict[str, int | None], after: dict[str, int | None]) -> dict[str, int | None]:
    """Computes numeric deltas between two resource snapshots."""

    deltas: dict[str, int | None] = {}
    for key, before_value in before.items():
        after_value = after.get(key)
        deltas[key] = None if before_value is None or after_value is None else int(after_value) - int(before_value)
    return deltas


def get_tree_item_text(process_handle: int, tree_hwnd: int, item_handle: int) -> str:
    """Reads one tree-view item text through `TVM_GETITEMW`."""

    max_chars = 1024
    text_bytes = max_chars * ctypes.sizeof(ctypes.c_wchar)
    total_size = ctypes.sizeof(TVITEMW) + text_bytes
    with RemoteBuffer(process_handle, total_size) as remote:
        remote_text_address = remote.address + ctypes.sizeof(TVITEMW)
        item = TVITEMW()
        item.mask = TVIF_TEXT
        item.hItem = item_handle
        item.pszText = remote_text_address
        item.cchTextMax = max_chars
        write_remote(process_handle, remote.address, item)
        if not win32gui.SendMessage(tree_hwnd, TVM_GETITEMW, 0, remote.address):
            raise RuntimeError(f"Unable to read tree item 0x{item_handle:X}.")
        raw_text = read_remote(process_handle, remote_text_address, text_bytes)
        return raw_text.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]


def iter_tree_siblings(tree_hwnd: int, first_item: int):
    """Yields a tree-view item and each of its following siblings."""

    current = first_item
    while current:
        yield current
        current = win32gui.SendMessage(tree_hwnd, TVM_GETNEXTITEM, TVGN_NEXT, current)


def expand_tree_item(tree_hwnd: int, item_handle: int) -> None:
    """Expands one tree-view item and gives lazy child population a short turn."""

    win32gui.SendMessage(tree_hwnd, TVM_EXPAND, TVE_EXPAND, item_handle)
    time.sleep(0.2)


def collapse_tree_item(tree_hwnd: int, item_handle: int) -> None:
    """Collapses one tree-view item and gives repaint handling a short turn."""

    win32gui.SendMessage(tree_hwnd, TVM_EXPAND, TVE_COLLAPSE, item_handle)
    time.sleep(0.05)


def force_control_paint(*hwnds: int) -> None:
    """Forces pending paint work through the target controls without changing UI state."""

    for hwnd in hwnds:
        win32gui.SendMessage(hwnd, WM_PAINT, 0, 0)
        user32.UpdateWindow(hwnd)


def normalize_tree_label(label: str) -> str:
    """Normalizes one Shared Files tree label for path-component matching."""

    return label.rstrip("\\").lower()


def tree_label_matches_path_component(label: str, component: str) -> bool:
    """Reports whether one tree label represents a path component."""

    target = component.rstrip("\\").lower()
    normalized = normalize_tree_label(label)
    if normalized == target:
        return True
    if target.endswith(":"):
        return normalized.startswith(target)
    return normalized.startswith(target + " ")


def tree_label_matches_drive(label: str, drive_component: str) -> bool:
    """Reports whether one tree label represents a Windows drive root."""

    drive = drive_component.rstrip("\\").lower()
    normalized = normalize_tree_label(label)
    return normalized.startswith(drive) or f"({drive})" in normalized


def find_tree_child_by_component(process_handle: int, tree_hwnd: int, parent_item: int, component: str) -> int:
    """Finds one direct child whose visible label matches a path component."""

    expand_tree_item(tree_hwnd, parent_item)

    def resolve() -> int | None:
        first_child = win32gui.SendMessage(tree_hwnd, TVM_GETNEXTITEM, TVGN_CHILD, parent_item)
        if not first_child:
            return None
        for child in iter_tree_siblings(tree_hwnd, first_child):
            if tree_label_matches_path_component(get_tree_item_text(process_handle, tree_hwnd, child), component):
                return child
        return None

    return wait_for(resolve, 20.0, 0.25, f"tree component '{component}'")


def find_drive_tree_item(process_handle: int, tree_hwnd: int, drive_component: str) -> int:
    """Finds the drive node below the Shared Files tree's virtual roots."""

    def resolve() -> int | None:
        root = win32gui.SendMessage(tree_hwnd, TVM_GETNEXTITEM, TVGN_ROOT, 0)
        for root_item in iter_tree_siblings(tree_hwnd, root):
            expand_tree_item(tree_hwnd, root_item)
            first_child = win32gui.SendMessage(tree_hwnd, TVM_GETNEXTITEM, TVGN_CHILD, root_item)
            if not first_child:
                continue
            for child in iter_tree_siblings(tree_hwnd, first_child):
                if tree_label_matches_drive(get_tree_item_text(process_handle, tree_hwnd, child), drive_component):
                    return child
        return None

    return wait_for(resolve, 30.0, 0.25, f"drive tree node '{drive_component}'")


def select_tree_root_by_label(process_handle: int, tree_hwnd: int, label: str) -> int:
    """Selects one top-level Shared Files tree node by visible label."""

    target = normalize_tree_label(label)

    def resolve() -> int | None:
        root = win32gui.SendMessage(tree_hwnd, TVM_GETNEXTITEM, TVGN_ROOT, 0)
        for root_item in iter_tree_siblings(tree_hwnd, root):
            if normalize_tree_label(get_tree_item_text(process_handle, tree_hwnd, root_item)) == target:
                return root_item
        return None

    item = wait_for(resolve, 10.0, 0.25, f"tree root '{label}'")
    win32gui.SendMessage(tree_hwnd, TVM_SELECTITEM, TVGN_CARET, item)
    time.sleep(0.2)
    return item


def select_directory_tree_item(process_handle: int, tree_hwnd: int, directory_path: Path) -> int:
    """Expands the Shared Files tree by path and selects the target directory item."""

    parts = list(directory_path.resolve().parts)
    if not parts:
        raise RuntimeError(f"Cannot select empty directory path: {directory_path}")
    current_item = find_drive_tree_item(process_handle, tree_hwnd, parts[0])
    for component in parts[1:]:
        current_item = find_tree_child_by_component(process_handle, tree_hwnd, current_item, component)
    win32gui.SendMessage(tree_hwnd, TVM_SELECTITEM, TVGN_CARET, current_item)
    return current_item


def send_shared_dirs_tree_command(tree_hwnd: int, command_id: int) -> None:
    """Sends one menu command directly to the Shared Files directory tree control."""

    win32gui.SendMessage(tree_hwnd, WM_COMMAND, command_id, 0)
    time.sleep(0.5)


def get_remote_rect(process_handle: int, hwnd: int, message: int, index: int, left_seed: int = 0) -> RECT:
    """Queries one control rectangle by marshalling a RECT through remote process memory."""

    with RemoteBuffer(process_handle, ctypes.sizeof(RECT)) as remote:
        rect = RECT(left_seed, 0, 0, 0)
        write_remote(process_handle, remote.address, rect)
        if not win32gui.SendMessage(hwnd, message, index, remote.address):
            raise RuntimeError(f"Control message 0x{message:04X} failed for index {index}.")
        return RECT.from_buffer_copy(read_remote(process_handle, remote.address, ctypes.sizeof(RECT)))


def get_control_handle(main_hwnd: int, control_id: int, class_name: str, *, visible_only: bool = False) -> int:
    """Finds one descendant control by numeric ID and window class."""

    matches = []

    def walk(hwnd: int) -> None:
        child = win32gui.GetWindow(hwnd, win32con.GW_CHILD)
        while child:
            try:
                child_class = win32gui.GetClassName(child)
                child_id = win32gui.GetDlgCtrlID(child)
                if child_class == class_name and child_id == control_id:
                    if visible_only and not win32gui.IsWindowVisible(child):
                        pass
                    else:
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
                "visible": bool(win32gui.IsWindowVisible(hwnd)),
                "enabled": bool(win32gui.IsWindowEnabled(hwnd)),
            }
        )
        child = win32gui.GetWindow(hwnd, win32con.GW_CHILD)
        while child:
            walk(child, depth + 1)
            child = win32gui.GetWindow(child, win32con.GW_HWNDNEXT)

    walk(main_hwnd, 0)
    write_json(output_path, nodes)


def click_client_rect(hwnd: int, rect: RECT) -> None:
    """Clicks the center of a client-rect region without requiring the active desktop."""

    x = rect.left + max((rect.right - rect.left) // 2, 1)
    y = rect.top + max((rect.bottom - rect.top) // 2, 1)
    lparam = (x & 0xFFFF) | ((y & 0xFFFF) << 16)
    win32gui.SendMessage(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lparam)
    win32gui.SendMessage(hwnd, WM_LBUTTONUP, 0, lparam)


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


def collect_startup_profile_bundle(
    startup_profile_path: Path,
    *,
    require_startup_profile: bool,
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    """Collects startup-profile diagnostics or records an expected omission for baseline runs."""

    try:
        startup_profile_text = live_common.wait_for_startup_profile_complete(
            startup_profile_path,
            timeout=120.0 if require_startup_profile else 5.0,
        )
    except Exception as exc:
        if require_startup_profile:
            raise
        return (
            {
                "startup_profile_path": str(startup_profile_path),
                "startup_profile_status": "missing",
                "startup_profile_error": str(exc),
                "startup_profile_phase_count": 0,
                "startup_profile_counter_count": 0,
                "startup_profile_counters": {},
            },
            [],
            [],
        )

    startup_profile_phases = live_common.parse_startup_profile(startup_profile_text)
    startup_profile_counters = live_common.parse_startup_profile_counters(startup_profile_text)
    return (
        {
            "startup_profile_path": str(startup_profile_path),
            "startup_profile_status": "present",
            "startup_profile_phase_count": len(startup_profile_phases),
            "startup_profile_counter_count": len(startup_profile_counters),
            "startup_profile_counters": live_common.summarize_startup_profile_counters(startup_profile_counters),
            "startup_profile_readiness": live_common.summarize_shared_files_readiness(
                startup_profile_phases,
                startup_profile_counters,
            ),
            "startup_profile_highlights": live_common.summarize_startup_profile(
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
            ),
            "startup_profile_top_slowest_phases": live_common.get_top_slowest_phases(startup_profile_phases, limit=8),
        },
        startup_profile_phases,
        startup_profile_counters,
    )


def is_main_emule_window(hwnd: int) -> bool:
    """Reports whether one visible top-level window is the real main eMule dialog."""

    title = win32gui.GetWindowText(hwnd)
    return win32gui.GetClassName(hwnd) == "#32770" and title.startswith(("eMule v", "eMule BB"))


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


def wait_for_exact_list_count(list_hwnd: int, expected_count: int, *, timeout: float = 90.0) -> int:
    """Waits until the Shared Files list exposes exactly the requested item count."""

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        return count if count == expected_count else 0

    return wait_for(resolve, timeout=timeout, interval=0.5, description=f"Shared Files row count {expected_count}")


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


def wait_for_list_name_set(
    process_handle: int,
    list_hwnd: int,
    expected_names: list[str],
    description: str,
    *,
    timeout: float = 45.0,
) -> list[str]:
    """Waits until the visible Shared Files rows match the expected unordered name set."""

    expected = sorted(expected_names, key=str.lower)

    def resolve():
        count = win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)
        if count != len(expected_names):
            return None
        names = get_all_list_names(process_handle, list_hwnd)
        return {"names": names} if sorted(names, key=str.lower) == expected else None

    result = wait_for(resolve, timeout=timeout, interval=0.5, description=description)
    return list(result["names"])


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
            "json": unwrap_rest_payload(payload),
            "raw_json": payload,
        }


def unwrap_rest_payload(payload: object) -> object:
    """Returns the payload body inside the final REST envelope."""

    if isinstance(payload, dict) and "data" in payload and "meta" in payload:
        return payload["data"]
    return payload


def require_json_array(result: dict[str, object], expected_status: int) -> list[object]:
    """Asserts a REST response is the expected JSON array payload."""

    if int(result["status"]) != expected_status:
        raise RuntimeError(f"Unexpected REST status {result['status']}: {result['body_text']!r}")
    payload = result["json"]
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return list(payload["items"])
    if isinstance(payload, list):
        return list(payload)
    raise RuntimeError(f"Expected JSON array REST payload, got {payload!r}.")


def wait_for_rest_ready(base_url: str, api_key: str) -> dict[str, object]:
    """Waits until the live REST API accepts authenticated localhost requests."""

    return wait_for(
        lambda: http_request(base_url, "/api/v1/app", api_key=api_key),
        timeout=30.0,
        interval=0.5,
        description="REST API readiness",
    )


def get_rest_shared_names(base_url: str, api_key: str) -> list[str]:
    """Returns the current shared-file names exposed by the REST read model."""

    rows = require_json_array(http_request(base_url, "/api/v1/shared-files", api_key=api_key), 200)
    names = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError(f"Unexpected shared-files REST row shape: {row!r}")
        name = row.get("name")
        if not isinstance(name, str):
            raise RuntimeError(f"Shared-files REST row has no string name: {row!r}")
        names.append(name)
    return names


def get_rest_shared_file_count(base_url: str, api_key: str) -> int:
    """Returns the number of shared-file rows exposed by the REST read model."""

    rows = require_json_array(http_request(base_url, "/api/v1/shared-files", api_key=api_key), 200)
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise RuntimeError(f"Unexpected shared-files REST row shape: {row!r}")
    return len(rows)


def get_rest_shared_directory_model(base_url: str, api_key: str) -> dict[str, object]:
    """Returns the current shared-directory REST model."""

    result = http_request(base_url, "/api/v1/shared-directories", api_key=api_key)
    if int(result["status"]) != 200:
        raise RuntimeError(f"Unexpected shared-directories REST status {result['status']}: {result['body_text']!r}")
    payload = result["json"]
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected shared-directories JSON object, got {payload!r}.")
    return payload


def get_rest_shared_directory_paths(base_url: str, api_key: str) -> dict[str, list[str]]:
    """Returns normalized path lists from the shared-directory REST model."""

    payload = get_rest_shared_directory_model(base_url, api_key)
    items = payload.get("items")
    monitor_owned = payload.get("monitorOwned")
    roots = payload.get("roots")
    if not isinstance(items, list) or not isinstance(monitor_owned, list) or not isinstance(roots, list):
        raise RuntimeError(f"Unexpected shared-directories REST shape: {payload!r}")

    def row_paths(rows: list[object]) -> list[str]:
        paths = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise RuntimeError(f"Unexpected shared-directory row shape: {row!r}")
            paths.append(row["path"])
        return paths

    return {
        "items": row_paths(items),
        "monitor_owned": [path for path in monitor_owned if isinstance(path, str)],
        "roots": row_paths(roots),
    }


def wait_for_rest_shared_directory_paths(
    base_url: str,
    api_key: str,
    *,
    expected_items: list[str],
    expected_monitor_owned: list[str],
    description: str,
    timeout: float = 45.0,
) -> dict[str, list[str]]:
    """Waits until REST shared-directory paths contain the expected monitored tree state."""

    expected_item_set = {path.lower() for path in expected_items}
    expected_monitor_owned_set = {path.lower() for path in expected_monitor_owned}

    def resolve():
        paths = get_rest_shared_directory_paths(base_url, api_key)
        item_set = {path.lower() for path in paths["items"]}
        monitor_owned_set = {path.lower() for path in paths["monitor_owned"]}
        if expected_item_set.issubset(item_set) and expected_monitor_owned_set.issubset(monitor_owned_set):
            return paths
        return None

    return wait_for(resolve, timeout=timeout, interval=0.5, description=description)


def wait_for_rest_shared_name_set(
    base_url: str,
    api_key: str,
    expected_names: list[str],
    description: str,
    *,
    timeout: float = 45.0,
) -> list[str]:
    """Waits until REST shared-files rows match the expected unordered name set."""

    expected = sorted(expected_names, key=str.lower)

    def resolve():
        names = get_rest_shared_names(base_url, api_key)
        return {"names": names} if sorted(names, key=str.lower) == expected else None

    result = wait_for(resolve, timeout=timeout, interval=0.5, description=description)
    return list(result["names"])


def wait_for_rest_shared_file_count(
    base_url: str,
    api_key: str,
    expected_count: int,
    description: str,
    *,
    timeout: float = 120.0,
) -> int:
    """Waits until REST shared-files exposes the expected row count."""

    def resolve():
        count = get_rest_shared_file_count(base_url, api_key)
        return count if count == expected_count else None

    return int(wait_for(resolve, timeout=timeout, interval=1.0, description=description))


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

    reload_hwnd = get_control_handle(main_hwnd, IDC_RELOADSHAREDFILES, "Button", visible_only=True)
    win32gui.SendMessage(reload_hwnd, BM_CLICK, 0, 0)


def churn_shared_files_tree(
    process_handle: int,
    main_hwnd: int,
    list_hwnd: int,
    tree_hwnd: int,
    sample_directories: list[Path],
    *,
    cycles: int,
) -> dict[str, object]:
    """Rapidly exercises tree selection, collapse/expand, list sorting, reload, and paint paths."""

    if not sample_directories:
        raise RuntimeError("Tree refresh stress requires at least one sample directory.")

    counts: list[int] = []
    selected_paths: list[str] = []
    reloads = 0
    sort_clicks = 0

    for cycle in range(cycles):
        directory_path = sample_directories[cycle % len(sample_directories)]
        selected_paths.append(live_common.win_path(directory_path))
        item = select_directory_tree_item(process_handle, tree_hwnd, directory_path)
        force_control_paint(tree_hwnd, list_hwnd)

        if cycle % 2 == 0:
            collapse_tree_item(tree_hwnd, item)
            expand_tree_item(tree_hwnd, item)
            win32gui.SendMessage(tree_hwnd, TVM_SELECTITEM, TVGN_CARET, item)

        if cycle % 5 == 0:
            click_list_column(process_handle, list_hwnd, 0, "Name")
            sort_clicks += 1

        if cycle % 7 == 0:
            click_reload_button(main_hwnd)
            reloads += 1

        force_control_paint(tree_hwnd, list_hwnd)
        counts.append(int(win32gui.SendMessage(list_hwnd, LVM_GETITEMCOUNT, 0, 0)))

    return {
        "cycles": cycles,
        "reloads": reloads,
        "sort_clicks": sort_clicks,
        "sample_directory_count": len(sample_directories),
        "selected_path_preview": selected_paths[:8],
        "row_count_min": min(counts) if counts else None,
        "row_count_max": max(counts) if counts else None,
        "row_count_tail": counts[-8:],
    }


def open_shared_files_list_page(main_hwnd: int) -> int:
    """Opens the Shared Files page and returns the visible owner-data list handle."""

    win32gui.SendMessage(main_hwnd, WM_COMMAND, MP_HM_FILES, 0)

    def resolve() -> int | None:
        list_hwnd = get_control_handle(main_hwnd, IDC_SFLIST, "SysListView32", visible_only=True)
        get_control_handle(main_hwnd, IDC_RELOADSHAREDFILES, "Button", visible_only=True)
        return list_hwnd

    return wait_for(resolve, 30.0, 0.5, "visible Shared Files list controls")


def open_shared_files_page(main_hwnd: int) -> tuple[int, int]:
    """Opens the Shared Files page and returns the list and details control handles."""

    list_hwnd = open_shared_files_list_page(main_hwnd)

    def resolve() -> tuple[int, int] | None:
        static_hwnd = get_control_handle(main_hwnd, IDC_SF_FNAME, "Static", visible_only=True)
        return (list_hwnd, static_hwnd)

    return wait_for(resolve, 30.0, 0.5, "visible Shared Files details controls")


def open_shared_files_tree_page(main_hwnd: int) -> tuple[int, int]:
    """Opens the Shared Files page and returns the visible list and directory-tree handles."""

    list_hwnd = open_shared_files_list_page(main_hwnd)

    def resolve() -> tuple[int, int] | None:
        tree_hwnd = get_control_handle(main_hwnd, IDC_SHAREDDIRSTREE, "SysTreeView32", visible_only=True)
        return (list_hwnd, tree_hwnd)

    return wait_for(resolve, 30.0, 0.5, "visible Shared Files directory tree controls")


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


def run_shared_files_e2e(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    *,
    require_startup_profile: bool,
) -> None:
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
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
        if not summary["main_window_is_maximized"]:
            raise RuntimeError(f"Expected the seeded profile to start maximized, got showCmd={summary['main_window_show_cmd']}.")

        startup_profile_summary, startup_profile_phases, _startup_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary.update(startup_profile_summary)
        if startup_profile_phases:
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


def run_dynamic_folder_lifecycle_e2e(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    *,
    require_startup_profile: bool,
) -> None:
    """Exercises live share, rescan, file removal, and unshare through the Shared Files UI."""

    fixture = prepare_dynamic_folder_lifecycle_fixture(seed_config_dir, artifacts_dir, app_exe)
    summary = {
        "name": "dynamic-folder-lifecycle",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "candidate_dir": live_common.win_path(Path(str(fixture["candidate_dir"])), trailing_slash=True),
        "rest_base_url": fixture["rest_base_url"],
        "expected_initial_names": fixture["initial_names"],
        "expected_after_add_names": fixture["after_add_names"],
        "expected_after_delete_names": fixture["after_delete_names"],
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
        "steps": [],
    }

    app = None
    process_handle = 0
    try:
        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED

        startup_profile_summary, startup_profile_phases, _startup_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary.update(startup_profile_summary)
        if startup_profile_phases:
            live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, summary["name"])

        process_handle = open_process(process_id)
        dump_window_tree(main_hwnd, artifacts_dir / "window-tree-initial.json")
        list_hwnd, tree_hwnd = open_shared_files_tree_page(main_hwnd)
        wait_for_rest_ready(str(fixture["rest_base_url"]), str(fixture["rest_api_key"]))

        ui_names = wait_for_list_name_set(process_handle, list_hwnd, [], "initial empty Shared Files UI list")
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            [],
            "initial empty REST shared-files list",
        )
        summary["steps"].append({"name": "initial_empty", "ui_names": ui_names, "rest_names": rest_names})

        select_directory_tree_item(process_handle, tree_hwnd, Path(str(fixture["candidate_dir"])))
        send_shared_dirs_tree_command(tree_hwnd, MP_SHAREDIR)
        click_reload_button(main_hwnd)
        select_tree_root_by_label(process_handle, tree_hwnd, "All Shared Files")
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["initial_names"]),
            "Shared Files UI list after UI share",
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["initial_names"]),
            "REST shared-files list after UI share",
        )
        summary["steps"].append({"name": "after_share", "ui_names": ui_names, "rest_names": rest_names})

        Path(str(fixture["late_file"])).write_bytes(b"late dynamic file\r\n")
        click_reload_button(main_hwnd)
        select_tree_root_by_label(process_handle, tree_hwnd, "All Shared Files")
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["after_add_names"]),
            "Shared Files UI list after adding a file",
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["after_add_names"]),
            "REST shared-files list after adding a file",
        )
        summary["steps"].append({"name": "after_add_file", "ui_names": ui_names, "rest_names": rest_names})

        Path(str(fixture["deleted_file"])).unlink()
        click_reload_button(main_hwnd)
        select_tree_root_by_label(process_handle, tree_hwnd, "All Shared Files")
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["after_delete_names"]),
            "Shared Files UI list after deleting a file",
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["after_delete_names"]),
            "REST shared-files list after deleting a file",
        )
        summary["steps"].append({"name": "after_delete_file", "ui_names": ui_names, "rest_names": rest_names})

        select_directory_tree_item(process_handle, tree_hwnd, Path(str(fixture["candidate_dir"])))
        send_shared_dirs_tree_command(tree_hwnd, MP_UNSHAREDIR)
        click_reload_button(main_hwnd)
        select_tree_root_by_label(process_handle, tree_hwnd, "All Shared Files")
        ui_names = wait_for_list_name_set(process_handle, list_hwnd, [], "Shared Files UI list after UI unshare")
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            [],
            "REST shared-files list after UI unshare",
        )
        summary["steps"].append({"name": "after_unshare", "ui_names": ui_names, "rest_names": rest_names})

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


def run_monitored_folder_events_e2e(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    *,
    require_startup_profile: bool,
) -> None:
    """Exercises live monitored-share file and directory events without manual reloads."""

    fixture = prepare_monitored_folder_events_fixture(seed_config_dir, artifacts_dir, app_exe)
    monitor_root = Path(str(fixture["monitor_root"]))
    existing_child_dir = Path(str(fixture["existing_child_dir"]))
    new_child_dir = Path(str(fixture["new_child_dir"]))
    summary = {
        "name": "monitored-folder-events",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "monitor_root": live_common.win_path(monitor_root, trailing_slash=True),
        "existing_child_dir": live_common.win_path(existing_child_dir, trailing_slash=True),
        "new_child_dir": live_common.win_path(new_child_dir, trailing_slash=True),
        "rest_base_url": fixture["rest_base_url"],
        "expected_initial_names": fixture["initial_names"],
        "expected_after_file_event_names": fixture["after_file_event_names"],
        "expected_after_directory_event_names": fixture["after_directory_event_names"],
        "expected_after_delete_names": fixture["after_delete_names"],
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
        "steps": [],
    }

    app = None
    process_handle = 0
    try:
        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED

        startup_profile_summary, startup_profile_phases, _startup_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary.update(startup_profile_summary)
        if startup_profile_phases:
            live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, summary["name"])

        process_handle = open_process(process_id)
        dump_window_tree(main_hwnd, artifacts_dir / "window-tree-initial.json")
        list_hwnd, tree_hwnd = open_shared_files_tree_page(main_hwnd)
        wait_for_rest_ready(str(fixture["rest_base_url"]), str(fixture["rest_api_key"]))

        ui_names = wait_for_list_name_set(process_handle, list_hwnd, [], "initial empty monitored Shared Files UI list")
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            [],
            "initial empty monitored REST shared-files list",
        )
        summary["steps"].append({"name": "initial_empty", "ui_names": ui_names, "rest_names": rest_names})

        select_directory_tree_item(process_handle, tree_hwnd, monitor_root)
        send_shared_dirs_tree_command(tree_hwnd, MP_SHAREDIRMONITOR)
        select_tree_root_by_label(process_handle, tree_hwnd, "All Shared Files")
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["initial_names"]),
            "Shared Files UI list after monitor share",
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["initial_names"]),
            "REST shared-files list after monitor share",
        )
        directory_paths = wait_for_rest_shared_directory_paths(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            expected_items=[
                live_common.win_path(monitor_root, trailing_slash=True),
                live_common.win_path(existing_child_dir, trailing_slash=True),
            ],
            expected_monitor_owned=[live_common.win_path(existing_child_dir, trailing_slash=True)],
            description="REST shared-directory model after monitor share",
        )
        summary["steps"].append(
            {
                "name": "after_monitor_share",
                "ui_names": ui_names,
                "rest_names": rest_names,
                "directory_paths": directory_paths,
            }
        )

        Path(str(fixture["root_late_file"])).write_bytes(b"monitor root late\r\n")
        Path(str(fixture["child_late_file"])).write_bytes(b"existing child late\r\n")
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["after_file_event_names"]),
            "Shared Files UI list after monitored file create events",
            timeout=90.0,
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["after_file_event_names"]),
            "REST shared-files list after monitored file create events",
            timeout=90.0,
        )
        summary["steps"].append({"name": "after_monitored_file_creates", "ui_names": ui_names, "rest_names": rest_names})

        new_child_dir.mkdir(parents=True, exist_ok=True)
        Path(str(fixture["new_child_file"])).write_bytes(b"new monitored child file\r\n")
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["after_directory_event_names"]),
            "Shared Files UI list after monitored directory create event",
            timeout=90.0,
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["after_directory_event_names"]),
            "REST shared-files list after monitored directory create event",
            timeout=90.0,
        )
        directory_paths = wait_for_rest_shared_directory_paths(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            expected_items=[
                live_common.win_path(monitor_root, trailing_slash=True),
                live_common.win_path(existing_child_dir, trailing_slash=True),
                live_common.win_path(new_child_dir, trailing_slash=True),
            ],
            expected_monitor_owned=[
                live_common.win_path(existing_child_dir, trailing_slash=True),
                live_common.win_path(new_child_dir, trailing_slash=True),
            ],
            description="REST shared-directory model after monitored directory create event",
            timeout=90.0,
        )
        summary["steps"].append(
            {
                "name": "after_monitored_directory_create",
                "ui_names": ui_names,
                "rest_names": rest_names,
                "directory_paths": directory_paths,
            }
        )

        Path(str(fixture["deleted_file"])).unlink()
        ui_names = wait_for_list_name_set(
            process_handle,
            list_hwnd,
            list(fixture["after_delete_names"]),
            "Shared Files UI list after monitored file delete event",
            timeout=90.0,
        )
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            list(fixture["after_delete_names"]),
            "REST shared-files list after monitored file delete event",
            timeout=90.0,
        )
        summary["steps"].append({"name": "after_monitored_file_delete", "ui_names": ui_names, "rest_names": rest_names})

        select_directory_tree_item(process_handle, tree_hwnd, monitor_root)
        send_shared_dirs_tree_command(tree_hwnd, MP_UNSHAREDIR)
        select_tree_root_by_label(process_handle, tree_hwnd, "All Shared Files")
        ui_names = wait_for_list_name_set(process_handle, list_hwnd, [], "Shared Files UI list after monitor unshare")
        rest_names = wait_for_rest_shared_name_set(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            [],
            "REST shared-files list after monitor unshare",
        )
        summary["steps"].append({"name": "after_monitor_unshare", "ui_names": ui_names, "rest_names": rest_names})

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


def run_generated_robustness_e2e(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_root: Path,
    *,
    require_startup_profile: bool,
) -> None:
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
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
        if not summary["main_window_is_maximized"]:
            raise RuntimeError(f"Expected the seeded profile to start maximized, got showCmd={summary['main_window_show_cmd']}.")

        startup_profile_summary, startup_profile_phases, _startup_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary.update(startup_profile_summary)
        if startup_profile_phases:
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


def run_tree_refresh_stress_e2e(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_root: Path,
    *,
    require_startup_profile: bool,
    churn_cycles: int,
) -> None:
    """Executes the 50k-file Shared Files tree-refresh stress regression."""

    fixture = prepare_tree_refresh_stress_fixture(seed_config_dir, artifacts_dir, shared_root, app_exe)
    summary = {
        "name": "tree-refresh-stress-10k",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "shared_root": fixture["shared_root"],
        "subtree_root": fixture["subtree_root"],
        "generated_fixture_manifest_path": fixture["manifest_path"],
        "shared_directory_count": fixture["shared_directory_count"],
        "directory_count": fixture["directory_count"],
        "expected_row_count": fixture["expected_row_count"],
        "observable_node_count": fixture["observable_node_count"],
        "stress_branch_count": fixture["stress_branch_count"],
        "stress_files_per_branch": fixture["stress_files_per_branch"],
        "stress_empty_children_per_branch": fixture["stress_empty_children_per_branch"],
        "rest_base_url": fixture["rest_base_url"],
        "churn_cycles": churn_cycles,
        "timeouts": {
            "main_window_seconds": 900.0,
            "row_count_seconds": 1800.0,
        },
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
    }

    app = None
    process_handle = 0
    try:
        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app, timeout=900.0)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["process_id"] = process_id

        startup_profile_summary, startup_profile_phases, _startup_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary.update(startup_profile_summary)
        if startup_profile_phases:
            live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, summary["name"])
        process_handle = open_process(process_id)

        dump_window_tree(main_hwnd, artifacts_dir / "window-tree-initial.json")
        list_hwnd, tree_hwnd = open_shared_files_tree_page(main_hwnd)
        wait_for_rest_ready(str(fixture["rest_base_url"]), str(fixture["rest_api_key"]))
        select_directory_tree_item(process_handle, tree_hwnd, Path(str(fixture["subtree_root_path"])))
        initial_count = wait_for_exact_list_count(list_hwnd, fixture["expected_row_count"], timeout=1800.0)
        summary["initial_row_count"] = initial_count
        summary["initial_rest_row_count"] = wait_for_rest_shared_file_count(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            fixture["expected_row_count"],
            "initial tree stress REST shared-files count",
        )
        summary["resources_before_churn"] = get_process_resource_snapshot(process_handle)

        sample_directories = list(fixture["sample_directories"])
        if Path(str(fixture["subtree_root_path"])) not in sample_directories:
            sample_directories.insert(0, Path(str(fixture["subtree_root_path"])))

        summary["tree_churn"] = churn_shared_files_tree(
            process_handle,
            main_hwnd,
            list_hwnd,
            tree_hwnd,
            sample_directories,
            cycles=churn_cycles,
        )

        select_directory_tree_item(process_handle, tree_hwnd, Path(str(fixture["subtree_root_path"])))
        click_reload_button(main_hwnd)
        final_count = wait_for_exact_list_count(list_hwnd, fixture["expected_row_count"], timeout=1800.0)
        summary["final_row_count"] = final_count
        summary["final_rest_row_count"] = wait_for_rest_shared_file_count(
            str(fixture["rest_base_url"]),
            str(fixture["rest_api_key"]),
            fixture["expected_row_count"],
            "final tree stress REST shared-files count",
        )
        summary["final_name_preview"] = get_list_names(process_handle, list_hwnd, min(20, final_count))
        summary["resources_after_churn"] = get_process_resource_snapshot(process_handle)
        summary["resource_deltas"] = diff_resource_snapshots(
            summary["resources_before_churn"],
            summary["resources_after_churn"],
        )

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


def run_duplicate_startup_reuse_e2e(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    *,
    require_startup_profile: bool,
) -> None:
    """Executes a duplicate-content relaunch regression and proves the second startup skips rehashing."""

    fixture = prepare_duplicate_reuse_fixture(seed_config_dir, artifacts_dir)
    summary = {
        "name": "duplicate-startup-reuse",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "duplicate_cache_path": str(fixture["duplicate_cache_path"]),
        "canonical_path": live_common.win_path(Path(str(fixture["canonical_path"]))),
        "duplicate_path": live_common.win_path(Path(str(fixture["duplicate_path"]))),
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
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["first_launch_process_id"] = process_id
        process_handle = open_process(process_id)

        startup_profile_summary, startup_profile_phases, _startup_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary["first_launch_startup"] = startup_profile_summary
        if startup_profile_phases:
            live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, summary["name"] + ".first_launch")

        list_hwnd, _static_hwnd = open_shared_files_page(main_hwnd)
        first_launch_row_count = wait_for_exact_list_count(list_hwnd, 1)
        summary["first_launch_row_count"] = first_launch_row_count
        first_launch_names = get_list_names(process_handle, list_hwnd, first_launch_row_count)
        summary["first_launch_names"] = first_launch_names
        if len(first_launch_names) != 1 or first_launch_names[0] not in fixture["expected_visible_names"]:
            raise RuntimeError(f"Unexpected duplicate fixture first-launch rows: {first_launch_names!r}")

        close_process(process_handle)
        process_handle = 0
        live_common.close_app_cleanly(app)
        app = None

        duplicate_cache_path = Path(str(fixture["duplicate_cache_path"]))
        duplicate_cache_header = wait_for_duplicate_cache_records(
            duplicate_cache_path,
            minimum_records=1,
            timeout=30.0,
        )
        summary["duplicate_cache_header"] = duplicate_cache_header
        if duplicate_cache_header["magic"] != SHARED_DUPLICATE_PATH_CACHE_MAGIC:
            raise RuntimeError(f"Unexpected duplicate cache magic: {duplicate_cache_header['magic']:#x}")
        if duplicate_cache_header["version"] != SHARED_DUPLICATE_PATH_CACHE_VERSION:
            raise RuntimeError(f"Unexpected duplicate cache version: {duplicate_cache_header['version']}")

        shared_cache_path = Path(str(fixture["config_dir"])) / "sharedcache.dat"
        summary["shared_cache_path"] = str(shared_cache_path)
        if not shared_cache_path.exists():
            raise RuntimeError("Expected sharedcache.dat to exist after the first launch warm-up.")
        shared_cache_path.unlink()
        summary["shared_cache_removed_before_relaunch"] = True

        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)
        process_id = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["relaunch_process_id"] = process_id
        process_handle = open_process(process_id)

        relaunch_profile_summary, relaunch_profile_phases, _relaunch_profile_counters = collect_startup_profile_bundle(
            fixture["startup_profile_path"],
            require_startup_profile=require_startup_profile,
        )
        summary["relaunch_startup"] = relaunch_profile_summary
        if relaunch_profile_phases:
            live_common.enforce_deferred_shared_hashing_boundary(relaunch_profile_phases, summary["name"] + ".relaunch")

        duplicate_paths_reused = get_profile_counter_value(relaunch_profile_summary, "shared.scan.duplicate_paths_reused", "files")
        files_queued_for_hash = get_profile_counter_value(relaunch_profile_summary, "shared.scan.files_queued_for_hash", "files")
        pending_hashes = get_profile_counter_value(relaunch_profile_summary, "shared.scan.pending_hashes", "files")
        shared_files_after_scan = get_profile_counter_value(relaunch_profile_summary, "shared.scan.shared_files_after_scan", "files")
        summary["relaunch_duplicate_paths_reused"] = duplicate_paths_reused
        summary["relaunch_files_queued_for_hash"] = files_queued_for_hash
        summary["relaunch_pending_hashes"] = pending_hashes
        summary["relaunch_shared_files_after_scan"] = shared_files_after_scan

        if require_startup_profile:
            if duplicate_paths_reused != 1:
                raise RuntimeError(f"Expected duplicate_paths_reused=1 on relaunch, got {duplicate_paths_reused!r}.")
            if files_queued_for_hash != 0:
                raise RuntimeError(f"Expected files_queued_for_hash=0 on relaunch, got {files_queued_for_hash!r}.")
            if pending_hashes != 0:
                raise RuntimeError(f"Expected pending_hashes=0 on relaunch, got {pending_hashes!r}.")
            if shared_files_after_scan != 1:
                raise RuntimeError(f"Expected shared_files_after_scan=1 on relaunch, got {shared_files_after_scan!r}.")

        list_hwnd, _static_hwnd = open_shared_files_page(main_hwnd)
        relaunch_row_count = wait_for_exact_list_count(list_hwnd, 1)
        summary["relaunch_row_count"] = relaunch_row_count
        relaunch_names = get_list_names(process_handle, list_hwnd, relaunch_row_count)
        summary["relaunch_names"] = relaunch_names
        if len(relaunch_names) != 1 or relaunch_names[0] not in fixture["expected_visible_names"]:
            raise RuntimeError(f"Unexpected duplicate fixture relaunch rows: {relaunch_names!r}")

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
    *,
    require_startup_profile: bool,
    tree_stress_churn_cycles: int,
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
                run_shared_files_e2e(
                    app_exe,
                    seed_config_dir,
                    scenario_dir,
                    require_startup_profile=require_startup_profile,
                )
            elif scenario_name == "generated-robustness-recursive":
                run_generated_robustness_e2e(
                    app_exe,
                    seed_config_dir,
                    scenario_dir,
                    shared_root,
                    require_startup_profile=require_startup_profile,
                )
            elif scenario_name == "tree-refresh-stress-10k":
                run_tree_refresh_stress_e2e(
                    app_exe,
                    seed_config_dir,
                    scenario_dir,
                    shared_root,
                    require_startup_profile=require_startup_profile,
                    churn_cycles=tree_stress_churn_cycles,
                )
            elif scenario_name == "duplicate-startup-reuse":
                run_duplicate_startup_reuse_e2e(
                    app_exe,
                    seed_config_dir,
                    scenario_dir,
                    require_startup_profile=require_startup_profile,
                )
            elif scenario_name == "dynamic-folder-lifecycle":
                run_dynamic_folder_lifecycle_e2e(
                    app_exe,
                    seed_config_dir,
                    scenario_dir,
                    require_startup_profile=require_startup_profile,
                )
            elif scenario_name == "monitored-folder-events":
                run_monitored_folder_events_e2e(
                    app_exe,
                    seed_config_dir,
                    scenario_dir,
                    require_startup_profile=require_startup_profile,
                )
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
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--startup-trace-mode", choices=["required", "optional"], default="required")
    parser.add_argument("--shared-root", default=r"C:\tmp\00_long_paths")
    parser.add_argument("--tree-stress-churn-cycles", type=int, default=80)
    parser.add_argument(
        "--scenario",
        dest="scenarios",
        action="append",
        choices=[
            "fixture-three-files",
            "generated-robustness-recursive",
            "tree-refresh-stress-10k",
            "duplicate-startup-reuse",
            "dynamic-folder-lifecycle",
            "monitored-folder-events",
        ],
    )
    args = parser.parse_args(argv)

    if _PYWINAUTO_IMPORT_ERROR is not None:
        live_common.require_pywinauto()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="shared-files-ui-e2e",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    scenario_names = args.scenarios or ["fixture-three-files", "generated-robustness-recursive"]

    try:
        run_shared_files_ui_suite(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            shared_root=Path(args.shared_root).resolve(),
            scenario_names=scenario_names,
            require_startup_profile=(args.startup_trace_mode == "required"),
            tree_stress_churn_cycles=args.tree_stress_churn_cycles,
        )
        harness_cli_common.publish_run_artifacts(paths)
        summary_payload = harness_cli_common.build_live_ui_summary(status="passed", paths=paths)
        summary_path = paths.run_report_dir / "ui-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        return 0
    except Exception as exc:
        (artifacts_dir / "error.txt").write_text(f"{exc}\n", encoding="utf-8")
        harness_cli_common.publish_run_artifacts(paths)
        summary_payload = harness_cli_common.build_live_ui_summary(status="failed", paths=paths, error_message=str(exc))
        summary_path = paths.run_report_dir / "ui-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        raise


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
