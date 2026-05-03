"""Shared environment loading helpers for live integration harnesses."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

DEFAULT_ENV_FILE_NAME = ".env.local"


def parse_dotenv_text(text: str) -> dict[str, str]:
    """Parses simple dotenv text without expanding or logging secret values."""

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        if name:
            values[name] = value
    return values


def parse_env_file(path: Path) -> dict[str, str]:
    """Parses one dotenv file without exposing values in diagnostics."""

    return parse_dotenv_text(path.read_text(encoding="utf-8", errors="replace"))


def ensure_secret_file_is_ignored(path: Path) -> None:
    """Fails when the selected dotenv file could be tracked by Git."""

    resolved_path = path.resolve()
    root_probe = subprocess.run(
        ["git", "-C", str(resolved_path.parent), "rev-parse", "--show-toplevel"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if root_probe.returncode != 0:
        raise RuntimeError(f"Secret file is not inside a Git worktree: {resolved_path}")

    git_root = Path(root_probe.stdout.strip()).resolve()
    try:
        git_path = resolved_path.relative_to(git_root)
    except ValueError as exc:
        raise RuntimeError(f"Secret file is outside its detected Git worktree: {resolved_path}") from exc

    completed = subprocess.run(
        ["git", "check-ignore", "-q", "--", str(git_path)],
        cwd=git_root,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Secret file is not git-ignored: {resolved_path}")


def load_env_values(
    required_keys: Sequence[str],
    *,
    env_file: Path | None = None,
    defaults: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Loads required live-harness settings from process env with dotenv fallback."""

    values = dict(defaults or {})
    if env_file is not None and env_file.is_file():
        ensure_secret_file_is_ignored(env_file)
        values.update(parse_env_file(env_file))

    for name, value in os.environ.items():
        if value:
            values[name] = value

    missing = [name for name in required_keys if not values.get(name)]
    if missing:
        raise RuntimeError("Environment is missing required key(s): " + ", ".join(missing))
    return values
