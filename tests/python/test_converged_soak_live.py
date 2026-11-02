from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
RETIRED_RUNNER = REPO_ROOT / "scripts" / "converged-soak-live.py"


def test_retired_runner_fails_fast_with_canonical_guidance() -> None:
    result = subprocess.run(
        [sys.executable, str(RETIRED_RUNNER), "--duration", "4h"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "converged-soak-live.py is retired" in result.stderr
    assert "scripts/persisted-soak-control.py" in result.stderr
    assert "run-to-gate" in result.stderr
