"""Resolve one or more RVAs in emule.exe to symbols and source lines."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import os
from pathlib import Path


SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004
SYMOPT_LOAD_LINES = 0x00000010
MAX_SYM_NAME = 2000
DEFAULT_IMAGE_BASE = 0x140000000


class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_uint64),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", ctypes.c_char * MAX_SYM_NAME),
    ]


class IMAGEHLP_LINE64(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.DWORD),
        ("Key", ctypes.c_void_p),
        ("LineNumber", wintypes.DWORD),
        ("FileName", ctypes.c_char_p),
        ("Address", ctypes.c_uint64),
    ]


def default_workspace_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    test_repo_root = script_dir.parent
    return Path(os.environ.get("EMULE_WORKSPACE_ROOT", test_repo_root.parent.parent)).resolve()


def default_exe_path(workspace_root: Path) -> Path:
    candidates = (
        workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "x64" / "Debug" / "emule.exe",
        workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-v0.72a-community" / "srchybrid" / "x64" / "Debug" / "emule.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def parse_hex(value: str) -> int:
    return int(value, 0)


def parse_args() -> argparse.Namespace:
    workspace_root = default_workspace_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exe",
        default=str(default_exe_path(workspace_root)),
        help="Path to the emule.exe to resolve against. Defaults to the main Debug build when present.",
    )
    parser.add_argument(
        "--image-base",
        default=hex(DEFAULT_IMAGE_BASE),
        type=parse_hex,
        help="Image base used to translate RVAs into absolute addresses.",
    )
    parser.add_argument(
        "--rva",
        action="append",
        dest="rvas",
        required=True,
        help="RVA value to resolve. Repeat for multiple addresses.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    exe_path = Path(args.exe).resolve()
    if not exe_path.is_file():
        raise SystemExit(f"Executable was not found: {exe_path}")

    dbghelp = ctypes.WinDLL("dbghelp.dll")
    hprocess = ctypes.c_void_p(0xDEADBEEF)
    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES)
    if not dbghelp.SymInitialize(hprocess, None, False):
        raise SystemExit(f"SymInitialize failed: {ctypes.GetLastError()}")

    try:
        pdb_dir = str(exe_path.parent)
        dbghelp.SymSetSearchPath(hprocess, pdb_dir.encode())

        dbghelp.SymLoadModuleEx.restype = ctypes.c_uint64
        dbghelp.SymLoadModuleEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]

        mod_base = dbghelp.SymLoadModuleEx(
            hprocess,
            None,
            str(exe_path).encode(),
            None,
            args.image_base,
            exe_path.stat().st_size,
            None,
            0,
        )
        if mod_base == 0:
            raise SystemExit(f"SymLoadModuleEx failed: {ctypes.GetLastError()}")

        print(f"Executable: {exe_path}")
        print(f"Symbol search path: {pdb_dir}")
        print(f"Module loaded at base {mod_base:#x}")
        print()

        dbghelp.SymFromAddr.restype = wintypes.BOOL
        dbghelp.SymFromAddr.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(SYMBOL_INFO),
        ]
        dbghelp.SymGetLineFromAddr64.restype = wintypes.BOOL
        dbghelp.SymGetLineFromAddr64.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(IMAGEHLP_LINE64),
        ]

        for raw_rva in args.rvas:
            rva = parse_hex(raw_rva)
            address = args.image_base + rva
            symbol = SYMBOL_INFO()
            symbol.SizeOfStruct = ctypes.sizeof(SYMBOL_INFO) - MAX_SYM_NAME
            symbol.MaxNameLen = MAX_SYM_NAME
            displacement = ctypes.c_uint64(0)

            print(f"RVA {rva:#010x}")
            if dbghelp.SymFromAddr(hprocess, address, ctypes.byref(displacement), ctypes.byref(symbol)):
                name = symbol.Name.decode("utf-8", errors="replace")
                print(f"  symbol: {name}+{displacement.value:#x}")
            else:
                print(f"  symbol: lookup failed ({ctypes.GetLastError()})")

            line = IMAGEHLP_LINE64()
            line.SizeOfStruct = ctypes.sizeof(IMAGEHLP_LINE64)
            line_displacement = wintypes.DWORD(0)
            if dbghelp.SymGetLineFromAddr64(hprocess, address, ctypes.byref(line_displacement), ctypes.byref(line)):
                file_name = line.FileName.decode("utf-8", errors="replace") if line.FileName else "(unknown)"
                print(f"  source: {file_name}:{line.LineNumber}")
            else:
                print(f"  source: lookup failed ({ctypes.GetLastError()})")
            print()
    finally:
        dbghelp.SymCleanup(hprocess)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
