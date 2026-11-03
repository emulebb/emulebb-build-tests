"""Unit tests for canonical source-build receipts."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import build_provenance


pytestmark = pytest.mark.unit


def _fake_git_run(
    command: list[str],
    *,
    source_repo: Path,
    build_repo: Path,
    source_revisions: list[str] | None = None,
    source_statuses: list[str] | None = None,
    build_returncode: int = 0,
):
    revisions = source_revisions or ["1" * 40, "1" * 40]
    statuses = source_statuses or ["", ""]
    source_revision_calls = 0
    source_status_calls = 0

    def run(argv, *, cwd, **_kwargs):
        nonlocal source_revision_calls, source_status_calls
        if argv[:2] == ["git", "rev-parse"]:
            if Path(cwd) == source_repo:
                value = revisions[source_revision_calls]
                source_revision_calls += 1
            else:
                assert Path(cwd) == build_repo
                value = "2" * 40
            return SimpleNamespace(returncode=0, stdout=value + "\n", stderr="")
        if argv[:2] == ["git", "status"]:
            if Path(cwd) == source_repo:
                value = statuses[source_status_calls]
                source_status_calls += 1
            else:
                assert Path(cwd) == build_repo
                value = ""
            return SimpleNamespace(returncode=0, stdout=value, stderr="")
        assert argv == command
        assert Path(cwd) == build_repo
        return SimpleNamespace(returncode=build_returncode)

    return run


def test_canonical_source_build_records_clean_unchanged_revisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source"
    build_repo = tmp_path / "build"
    source_repo.mkdir()
    build_repo.mkdir()
    command = ["python", "-m", "builder", "--clean"]
    monkeypatch.setattr(
        build_provenance.subprocess,
        "run",
        _fake_git_run(command, source_repo=source_repo, build_repo=build_repo),
    )

    receipt = build_provenance.run_canonical_source_build(
        command,
        build_repo=build_repo,
        source_repo=source_repo,
        label="Rust diagnostics",
    )

    assert receipt == {
        "schema": build_provenance.BUILD_RECEIPT_SCHEMA,
        "command": command,
        "returnCode": 0,
        "sourceRevision": "1" * 40,
        "sourceCleanBefore": True,
        "sourceCleanAfter": True,
        "orchestratorRevision": "2" * 40,
        "orchestratorCleanBefore": True,
        "orchestratorCleanAfter": True,
    }


def test_canonical_source_build_rejects_dirty_source_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source"
    build_repo = tmp_path / "build"
    source_repo.mkdir()
    build_repo.mkdir()
    command = ["builder", "--clean"]
    monkeypatch.setattr(
        build_provenance.subprocess,
        "run",
        _fake_git_run(
            command,
            source_repo=source_repo,
            build_repo=build_repo,
            source_statuses=[" M changed.rs\n"],
        ),
    )

    with pytest.raises(RuntimeError, match="must be clean before the build"):
        build_provenance.run_canonical_source_build(
            command,
            build_repo=build_repo,
            source_repo=source_repo,
            label="Rust diagnostics",
        )


def test_canonical_source_build_rejects_revision_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source"
    build_repo = tmp_path / "build"
    source_repo.mkdir()
    build_repo.mkdir()
    command = ["builder", "--clean"]
    monkeypatch.setattr(
        build_provenance.subprocess,
        "run",
        _fake_git_run(
            command,
            source_repo=source_repo,
            build_repo=build_repo,
            source_revisions=["1" * 40, "3" * 40],
        ),
    )

    with pytest.raises(RuntimeError, match="source revision changed during the build"):
        build_provenance.run_canonical_source_build(
            command,
            build_repo=build_repo,
            source_repo=source_repo,
            label="Rust diagnostics",
        )


def test_canonical_source_build_rejects_failed_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source"
    build_repo = tmp_path / "build"
    source_repo.mkdir()
    build_repo.mkdir()
    command = ["builder", "--clean"]
    monkeypatch.setattr(
        build_provenance.subprocess,
        "run",
        _fake_git_run(
            command,
            source_repo=source_repo,
            build_repo=build_repo,
            build_returncode=7,
        ),
    )

    with pytest.raises(RuntimeError, match="canonical build failed with exit code 7"):
        build_provenance.run_canonical_source_build(
            command,
            build_repo=build_repo,
            source_repo=source_repo,
            label="Rust diagnostics",
        )


def test_clean_build_commands_are_explicit() -> None:
    from emule_test_harness import rust_ed2k, soak_build_refresh

    assert (
        soak_build_refresh.diagnostics_build_command("rust", clean=True)[-1]
        == "--clean"
    )
    assert (
        soak_build_refresh.diagnostics_build_command("mfc", clean=True)[-1] == "--clean"
    )
    assert rust_ed2k.server_build_command(clean=True)[-1] == "--clean"
