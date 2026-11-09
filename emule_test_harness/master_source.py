"""Shared helpers for eMuleBB master C++ source-parity checks.

These helpers were previously copy-pasted into every ``test_*_source.py``
module (each defining its own ``app_source_root`` / ``read_app_source`` and
path constants). They are factored here so the parity suite can share a single
source-of-truth for locating and reading the master tree.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from emule_test_harness.paths import get_required_emule_workspace_root

# WHY: managed worktrees have a different directory depth; operator state owns
# the canonical source root regardless of where this harness is checked out.
_WORKSPACE_ROOT = get_required_emule_workspace_root()


def workspace_root() -> Path:
    """Returns the workspace root that owns ``repos/`` and ``workspaces/``."""

    return _WORKSPACE_ROOT


def app_root() -> Path:
    """Returns the eMuleBB master application root (``app/emulebb-main``)."""

    return _WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"


def app_source_root() -> Path:
    """Returns the eMuleBB master ``srchybrid`` source directory."""

    return app_root() / "srchybrid"


def build_root() -> Path:
    """Returns the ``emulebb-build`` repo root (build/release tooling)."""

    return _WORKSPACE_ROOT / "repos" / "emulebb-build"


@lru_cache(maxsize=None)
def read_app_source(name: str) -> str:
    """Reads a file from the master ``srchybrid`` directory as text."""

    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


@lru_cache(maxsize=None)
def read_app_path(*parts: str) -> str:
    """Reads a file relative to the master application root as text."""

    return app_root().joinpath(*parts).read_text(encoding="utf-8", errors="ignore")


@lru_cache(maxsize=None)
def read_build_source(*parts: str) -> str:
    """Reads a file relative to the ``emulebb-build`` repo as text."""

    return build_root().joinpath(*parts).read_text(encoding="utf-8")
