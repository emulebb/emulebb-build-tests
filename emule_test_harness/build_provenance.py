"""Causal receipts for canonical builds from clean, unchanged sources."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


BUILD_RECEIPT_SCHEMA = "emulebb-build-tests.canonical-source-build.v1"
GIT_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class GitSourceState:
    """Exact revision and cleanliness of one Git worktree."""

    revision: str
    clean: bool


def git_source_state(repo_root: Path, *, label: str) -> GitSourceState:
    """Read one worktree's exact HEAD and tracked/untracked cleanliness."""

    resolved = repo_root.resolve()
    revision_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=resolved,
        check=False,
        capture_output=True,
        text=True,
    )
    revision = revision_result.stdout.strip().lower()
    if (
        revision_result.returncode != 0
        or GIT_REVISION_PATTERN.fullmatch(revision) is None
    ):
        raise RuntimeError(f"Could not resolve {label} source revision: {resolved}")

    status_result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=resolved,
        check=False,
        capture_output=True,
        text=True,
    )
    if status_result.returncode != 0:
        raise RuntimeError(f"Could not inspect {label} source state: {resolved}")
    return GitSourceState(revision=revision, clean=not status_result.stdout.strip())


def require_clean_git_source(repo_root: Path, *, label: str) -> GitSourceState:
    """Return one exact source state, rejecting a dirty worktree."""

    state = git_source_state(repo_root, label=label)
    if not state.clean:
        raise RuntimeError(f"{label} source worktree must be clean before the build.")
    return state


def _require_unchanged_source(
    repo_root: Path,
    *,
    label: str,
    expected: GitSourceState,
) -> GitSourceState:
    observed = git_source_state(repo_root, label=label)
    if not observed.clean:
        raise RuntimeError(f"{label} source worktree changed during the build.")
    if observed.revision != expected.revision:
        raise RuntimeError(
            f"{label} source revision changed during the build: "
            f"{expected.revision} -> {observed.revision}."
        )
    return observed


def run_canonical_source_build(
    command: Sequence[str],
    *,
    build_repo: Path,
    source_repo: Path,
    label: str,
    timeout_seconds: float | None = None,
) -> dict[str, object]:
    """Run one canonical build and bind success to clean, unchanged revisions."""

    if not command:
        raise ValueError("canonical build command must not be empty")
    source_before = require_clean_git_source(source_repo, label=label)
    orchestrator_before = require_clean_git_source(
        build_repo,
        label="build orchestrator",
    )
    run_arguments: dict[str, object] = {
        "cwd": build_repo.resolve(),
        "check": False,
    }
    if timeout_seconds is not None:
        run_arguments["timeout"] = timeout_seconds
    completed = subprocess.run(list(command), **run_arguments)

    source_after = _require_unchanged_source(
        source_repo,
        label=label,
        expected=source_before,
    )
    orchestrator_after = _require_unchanged_source(
        build_repo,
        label="build orchestrator",
        expected=orchestrator_before,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{label} canonical build failed with exit code {completed.returncode}."
        )

    return {
        "schema": BUILD_RECEIPT_SCHEMA,
        "command": list(command),
        "returnCode": completed.returncode,
        "sourceRevision": source_before.revision,
        "sourceCleanBefore": source_before.clean,
        "sourceCleanAfter": source_after.clean,
        "orchestratorRevision": orchestrator_before.revision,
        "orchestratorCleanBefore": orchestrator_before.clean,
        "orchestratorCleanAfter": orchestrator_after.clean,
    }
