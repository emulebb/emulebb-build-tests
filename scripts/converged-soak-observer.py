#!/usr/bin/env python3
"""Attach-only bounded observer entry point for a persisted diagnostics soak."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.converged_observer import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
