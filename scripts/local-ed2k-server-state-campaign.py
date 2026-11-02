#!/usr/bin/env python3
"""Run the deterministic upstream ED2K server state-machine campaign."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.ed2k_server_state_campaign import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
