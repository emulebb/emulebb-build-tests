"""Parse one minidump and print thread RIPs resolved to loaded modules."""

from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

from minidump.minidumpfile import MinidumpFile


def default_workspace_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    test_repo_root = script_dir.parent
    return Path(os.environ.get("EMULE_WORKSPACE_ROOT", test_repo_root.parent.parent)).resolve()


def default_dump_path(workspace_root: Path) -> Path:
    return workspace_root / "workspaces" / "workspace" / "state" / "test-reports" / "diag-hash-launch" / "latest" / "emule-cpu.dmp"


def parse_args() -> argparse.Namespace:
    workspace_root = default_workspace_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dump_path",
        nargs="?",
        default=str(default_dump_path(workspace_root)),
        help="Minidump path to inspect. Defaults to workspaces/workspace/state/test-reports/diag-hash-launch/latest/emule-cpu.dmp.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dump_path = Path(args.dump_path).resolve()
    if not dump_path.is_file():
        raise SystemExit(f"Dump file was not found: {dump_path}")

    dump_file = MinidumpFile.parse(str(dump_path))
    modules: list[tuple[int, int, str]] = []
    if dump_file.modules:
        for module in dump_file.modules.modules:
            modules.append((module.baseaddress, module.size, module.name))

    def resolve_module(address: int) -> str:
        for base, size, name in modules:
            if base <= address < base + size:
                return f"{name.rsplit(chr(92), 1)[-1]}+{address - base:#x}"
        return f"{address:#018x}"

    raw = dump_path.read_bytes()

    print(f"Dump: {dump_path}")
    print("=== THREADS ===")
    if dump_file.threads:
        for thread in dump_file.threads.threads:
            ctx_rva = thread.ThreadContext.Rva
            ctx_size = thread.ThreadContext.DataSize

            if ctx_size >= 0x100:
                rip = struct.unpack_from("<Q", raw, ctx_rva + 0xF8)[0]
                rsp = struct.unpack_from("<Q", raw, ctx_rva + 0x98)[0]
                print(
                    f"  TID={thread.ThreadId:#06x}  RIP={rip:#018x}  "
                    f"RSP={rsp:#018x}  => {resolve_module(rip)}"
                )
            else:
                print(f"  TID={thread.ThreadId:#06x}  (context too small: {ctx_size})")

    print()
    print("=== KEY MODULES ===")
    for base, size, name in modules:
        short_name = name.rsplit("\\", 1)[-1].lower()
        if any(token in short_name for token in ("emule", "ntdll", "kernel", "mfc", "msvc")):
            print(f"  {base:#018x}  size={size:#010x}  {name.rsplit(chr(92), 1)[-1]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
