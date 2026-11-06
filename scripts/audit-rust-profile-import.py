"""Audit stock hash reuse offline on native Windows or WSL Docker."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.profile_import_audit import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
