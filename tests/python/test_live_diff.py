from __future__ import annotations

import json
import sys
from pathlib import Path

from emule_test_harness.live_diff import (
    build_doctest_xml_command,
    build_emule_tests_command,
    get_default_workspace_root,
    write_live_diff_summary,
)


def test_get_default_workspace_root_uses_canonical_repo_layout(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    repo_root = tmp_path / "repos" / "emulebb-build-tests"

    assert get_default_workspace_root(repo_root) == tmp_path / "workspaces" / "workspace"


def test_get_default_workspace_root_prefers_environment(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repos" / "emulebb-build-tests"
    workspace_root = tmp_path / "env-root"
    monkeypatch.setenv("EMULE_WORKSPACE_ROOT", str(workspace_root))

    assert get_default_workspace_root(repo_root) == workspace_root / "workspaces" / "workspace"


def test_build_emule_tests_command_uses_python_build_wrapper() -> None:
    command = build_emule_tests_command(
        test_repo_root=Path("C:/repo/tests"),
        workspace_root=Path("C:/repo/workspaces/workspace"),
        app_root=Path("C:/repo/workspaces/workspace/app/eMule-main"),
        configuration="Debug",
        platform="x64",
        build_tag="tag",
    )

    assert command[0] == sys.executable
    assert command[1].endswith("scripts\\build-emule-tests.py")
    assert "--workspace-root" not in command
    assert "--app-root" in command
    assert "tag" in command


def test_build_doctest_xml_command_matches_existing_reporter_contract() -> None:
    command = build_doctest_xml_command(
        binary_path=Path("C:/repo/build/tag/x64/Debug/emule-tests.exe"),
        suite_name="parity",
        xml_path=Path("C:/repo/reports/test-run-parity.xml"),
    )

    assert "--reporters=xml" in command
    assert "--test-suite=parity" in command
    assert any(part.endswith("test-run-parity.xml") and part.startswith("--out=") for part in command)


def test_write_live_diff_summary_matches_publisher_contract(tmp_path: Path) -> None:
    summary_path = tmp_path / "live-diff-summary.json"
    text_path = tmp_path / "live-diff-summary.txt"

    write_live_diff_summary(
        summary_path,
        generated_utc="2026-04-21T00:00:00Z",
        report_root=tmp_path,
        test_run_workspace_root=Path("C:/test-run"),
        baseline_workspace_root=Path("C:/baseline"),
        configuration="Debug",
        platform="x64",
        suite_summaries=[{"suite_name": "parity", "total_cases": 1, "pass_count": 1}],
        failed=False,
        text_summary_path=text_path,
    )

    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    assert payload["failed"] is False
    assert payload["configuration"] == "Debug"
    assert payload["suites"][0]["suite_name"] == "parity"
    assert payload["text_summary_path"] == str(text_path)
