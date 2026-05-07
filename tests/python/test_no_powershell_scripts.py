from __future__ import annotations

import subprocess
from pathlib import Path


def test_repo_does_not_carry_powershell_scripts() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    tracked_scripts = subprocess.run(
        ["git", "ls-files", "*.ps1"],
        cwd=repo_root,
        check=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
    ).stdout.splitlines()
    assert tracked_scripts == []
