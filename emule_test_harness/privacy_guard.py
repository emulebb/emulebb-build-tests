"""Compatibility imports for the tooling-owned tracked-file privacy guard."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def tooling_ci_root() -> Path:
    """Returns the canonical tooling CI module directory."""

    env_root = os.environ.get("EMULE_WORKSPACE_ROOT")
    candidates: list[Path] = []
    if env_root:
        candidates.append(Path(env_root).resolve() / "repos" / "eMule-tooling" / "ci")

    test_repo_root = Path(__file__).resolve().parent.parent
    candidates.append(test_repo_root.parent / "eMule-tooling" / "ci")
    candidates.append(test_repo_root.parent.parent / "repos" / "eMule-tooling" / "ci")

    for candidate in candidates:
        if (candidate / "workspace_ci.py").is_file():
            return candidate
    raise RuntimeError("Unable to locate repos\\eMule-tooling\\ci\\workspace_ci.py.")


TOOLING_CI_ROOT = tooling_ci_root()
if str(TOOLING_CI_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLING_CI_ROOT))

from workspace_ci import PrivacyGuardFailure, run_privacy_guard  # noqa: E402

__all__ = ["PrivacyGuardFailure", "run_privacy_guard"]
