#!/usr/bin/env python3
"""Discover one exact sub-5-MiB PDF for the packaged Rust consumer proof."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_consumer_discovery  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(rust_consumer_discovery.run())
