from __future__ import annotations

import subprocess
from pathlib import Path


RENAMED_OPERATOR_SCRIPT_NAME_PARTS = (
    ("build", "emule", "tests"),
    ("guard", "tracked", "files"),
    ("diag", "hash", "launch"),
    ("run", "community", "core", "coverage"),
    ("run", "live", "diff"),
    ("run", "live", "e2e", "suite"),
    ("run", "native", "coverage"),
    ("run", "pipe", "live", "matrix"),
)


def get_tracked_files(repo_root: Path) -> list[str]:
    """Returns tracked repo paths using Git's slash-separated path format."""

    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.splitlines()


def test_operator_python_scripts_use_hyphenated_filenames() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    script_names = [
        Path(path).name
        for path in get_tracked_files(repo_root)
        if path.startswith("scripts/") and path.endswith(".py")
    ]

    assert all("_" not in name for name in script_names)


def test_removed_underscore_operator_script_names_are_not_referenced() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    tracked_files = get_tracked_files(repo_root)
    removed_script_names = [("_".join(parts) + ".py") for parts in RENAMED_OPERATOR_SCRIPT_NAME_PARTS]

    assert not any(f"scripts/{name}" in tracked_files for name in removed_script_names)
    for relative_path in tracked_files:
        path = repo_root / relative_path
        if not path.is_file() or path.suffix.lower() in {".dat", ".met", ".h"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for script_name in removed_script_names:
            assert script_name not in text, f"{script_name} is still referenced by {relative_path}"


def test_env_example_is_trackable_but_local_env_files_are_ignored() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    local_env_check = subprocess.run(
        ["git", "check-ignore", "-q", "--", ".env.local"],
        cwd=repo_root,
        check=False,
    )
    example_check = subprocess.run(
        ["git", "check-ignore", "-q", "--", ".env.example"],
        cwd=repo_root,
        check=False,
    )

    assert local_env_check.returncode == 0
    assert example_check.returncode != 0
