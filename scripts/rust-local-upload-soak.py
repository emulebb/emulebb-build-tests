#!/usr/bin/env python3
"""Run a deterministic local Rust upload soak with diagnostics and native UI."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_upload_soak  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(rust_upload_soak.run())
