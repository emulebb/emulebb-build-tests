"""Parse one minidump and print thread RIPs resolved to loaded modules."""

from __future__ import annotations

import argparse
import os
import struct
from pathlib import Path

from minidump.minidumpfile import MinidumpFile


def default_output_root() -> Path:
    value = os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT", "").strip()
    if not value:
        raise RuntimeError("EMULEBB_WORKSPACE_OUTPUT_ROOT must be set.")
    return Path(value).resolve()


def default_dump_path(output_root: Path) -> Path:
    return output_root / "reports" / "diag-hash-launch" / "latest" / "emule-cpu.dmp"


def parse_args() -> argparse.Namespace:
    output_root = default_output_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dump_path",
        nargs="?",
        default=str(default_dump_path(output_root)),
        help="Minidump path to inspect. Defaults to EMULEBB_WORKSPACE_OUTPUT_ROOT/reports/diag-hash-launch/latest/emule-cpu.dmp.",
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
