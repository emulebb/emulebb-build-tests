"""Write a Linux PID file and replace this helper with one managed process."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    """Writes the current PID, then execs the command after ``--``."""

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 4 or args[0] != "--pid-file" or "--" not in args[2:]:
        raise RuntimeError("usage: wsl_managed_process.py --pid-file PATH -- COMMAND [ARG ...]")
    separator = args.index("--", 2)
    pid_path = Path(args[1])
    command = args[separator + 1 :]
    if not command:
        raise RuntimeError("managed process command is required")
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(f"{os.getpid()}\n", encoding="ascii")
    os.execv(command[0], command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
