"""Fail fast for the retired whole-trace converged soak runner."""

from __future__ import annotations

import sys


MESSAGE = (
    "converged-soak-live.py is retired because it cannot safely process arbitrarily "
    "long traces. Use scripts/persisted-soak-control.py with preflight, start, "
    "gate-status, status, stop, or the blocking run-to-gate command."
)


def main() -> int:
    """Rejects the retired entrypoint with canonical operator guidance."""

    print(MESSAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
