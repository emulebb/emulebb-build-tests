"""Control an until-stopped persisted full-tunnel diagnostics soak."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.persisted_soak_controller import main


if __name__ == "__main__":
    raise SystemExit(main())
