"""Validates the tracked eD2K/Kad protocol-parity catalog."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.protocol_parity import run_validate_cli


if __name__ == "__main__":
    raise SystemExit(run_validate_cli(sys.argv[1:]))
