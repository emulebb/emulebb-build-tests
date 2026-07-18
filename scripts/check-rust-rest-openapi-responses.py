"""Checks a running emulebb-rust REST daemon against OpenAPI response schemas."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.rust_rest_conformance import run_cli


if __name__ == "__main__":
    raise SystemExit(run_cli())
