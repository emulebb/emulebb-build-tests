#!/usr/bin/env python3
"""Run the persisted eMuleBB Rust 100k-file shared-library I/O harness."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from emule_test_harness.rust_shared_library_io import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
