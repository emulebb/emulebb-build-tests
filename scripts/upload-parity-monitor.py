"""Runs the aggregate Rust-vs-MFC upload parity monitor."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.upload_parity_monitor import main


if __name__ == "__main__":
    raise SystemExit(main())
