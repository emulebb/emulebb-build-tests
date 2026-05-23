"""Python live-diff orchestration helpers."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from .doctest_results import compare_case_sets, parse_doctest_xml
from .paths import get_build_tag, get_test_binary_path
from .processes import run_captured
from .workspace_layout import get_default_workspace_root

DEFAULT_SUITE_NAMES = ("parity", "protocol-parity", "divergence")


@dataclass(frozen=True)
class LiveDiffConfig:
    """Resolved configuration for one Python live-diff run."""

    test_repo_root: Path
    test_run_workspace_root: Path
    baseline_workspace_root: Path
    test_run_app_root: Path | None
    baseline_app_root: Path | None
    configuration: str
    platform: str
    suite_names: tuple[str, ...]
    report_root: Path
    skip_build: bool = False


def build_emule_tests_command(
    *,
    test_repo_root: Path,
    workspace_root: Path,
    app_root: Path | None,
    configuration: str,
    platform: str,
    build_tag: str,
) -> tuple[str, ...]:
    """Builds the command line for the Python native-test build wrapper."""

    command = [
        sys.executable,
        str((test_repo_root / "scripts" / "build-emule-tests.py").resolve()),
        "--test-repo-root",
        str(test_repo_root.resolve()),
        "--configuration",
        configuration,
        "--platform",
        platform,
        "--build-tag",
        build_tag,
        "--build-output-mode",
        "Full",
    ]
    if app_root is not None:
        command.extend(["--app-root", str(app_root.resolve())])
    return tuple(command)


def build_doctest_xml_command(
    *,
    binary_path: Path,
    suite_name: str,
    xml_path: Path,
) -> tuple[str, ...]:
    """Builds the doctest XML command for one suite."""

    return (
        str(binary_path.resolve()),
        "--reporters=xml",
        "--no-intro",
        "--no-version",
        f"--test-suite={suite_name}",
        f"--out={xml_path.resolve()}",
    )


def run_live_diff(config: LiveDiffConfig) -> int:
    """Runs the Python live-diff flow and returns a process exit code."""

    config.report_root.mkdir(parents=True, exist_ok=True)
    if not config.skip_build:
        _build_workspace(config, config.test_run_workspace_root, config.test_run_app_root)
        _build_workspace(config, config.baseline_workspace_root, config.baseline_app_root)

    summary_lines: list[str] = []
    suite_summaries: list[dict[str, int | str]] = []
    failed = False

    for suite_name in config.suite_names:
        test_run_results = _run_and_parse_suite(
            config,
            workspace_root=config.test_run_workspace_root,
            app_root=config.test_run_app_root,
            workspace_id="test-run",
            suite_name=suite_name,
        )
        baseline_results = _run_and_parse_suite(
            config,
            workspace_root=config.baseline_workspace_root,
            app_root=config.baseline_app_root,
            workspace_id="baseline",
            suite_name=suite_name,
        )
        comparison = compare_case_sets(test_run_results, baseline_results, suite_name=suite_name)
        summary_lines.extend(comparison.lines)
        suite_summaries.append(comparison.summary.to_dict())
        failed = failed or comparison.has_failure

    summary_path = config.report_root / "live-diff-summary.txt"
    summary_path.write_text("\n".join(summary_lines) + ("\n" if summary_lines else ""), encoding="utf-8")
    summary_json_path = config.report_root / "live-diff-summary.json"
    write_live_diff_summary(
        summary_json_path,
        generated_utc=datetime.now(UTC).isoformat(),
        report_root=config.report_root,
        test_run_workspace_root=config.test_run_workspace_root,
        baseline_workspace_root=config.baseline_workspace_root,
        configuration=config.configuration,
        platform=config.platform,
        suite_summaries=suite_summaries,
        failed=failed,
        text_summary_path=summary_path,
    )
    publish_harness_summary(config.test_repo_root, config.test_run_workspace_root, summary_json_path)

    for line in summary_lines:
        print(line)
    print(f"Summary: {summary_path}")
    return 1 if failed else 0


def write_live_diff_summary(
    summary_json_path: Path,
    *,
    generated_utc: str,
    report_root: Path,
    test_run_workspace_root: Path,
    baseline_workspace_root: Path,
    configuration: str,
    platform: str,
    suite_summaries: Iterable[dict[str, int | str]],
    failed: bool,
    text_summary_path: Path,
) -> None:
    """Writes the machine-readable live-diff summary consumed by the publisher."""

    payload = {
        "generated_utc": generated_utc,
        "report_root": str(report_root),
        "test_run_workspace_root": str(test_run_workspace_root),
        "baseline_workspace_root": str(baseline_workspace_root),
        "configuration": configuration,
        "platform": platform,
        "suites": list(suite_summaries),
        "failed": failed,
        "text_summary_path": str(text_summary_path),
    }
    summary_json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def publish_harness_summary(test_repo_root: Path, workspace_root: Path, summary_json_path: Path) -> None:
    """Refreshes the combined harness summary after a live-diff run."""

    run_captured(
        (
            sys.executable,
            str((test_repo_root / "scripts" / "publish-harness-summary.py").resolve()),
            "--test-repo-root",
            str(test_repo_root.resolve()),
            "--workspace-root",
            str(workspace_root.resolve()),
            "--live-diff-summary-path",
            str(summary_json_path.resolve()),
        ),
        check=True,
    )


def _build_workspace(config: LiveDiffConfig, workspace_root: Path, app_root: Path | None) -> None:
    """Invokes the retained native-test build wrapper for one workspace."""

    build_tag = get_build_tag(workspace_root, app_root)
    run_captured(
        build_emule_tests_command(
            test_repo_root=config.test_repo_root,
            workspace_root=workspace_root,
            app_root=app_root,
            configuration=config.configuration,
            platform=config.platform,
            build_tag=build_tag,
        ),
        cwd=config.test_repo_root,
        check=True,
        echo=True,
    )


def _run_and_parse_suite(
    config: LiveDiffConfig,
    *,
    workspace_root: Path,
    app_root: Path | None,
    workspace_id: str,
    suite_name: str,
) -> dict:
    """Runs one doctest suite and parses its XML result."""

    build_tag = get_build_tag(workspace_root, app_root)
    binary_path = get_test_binary_path(
        config.test_repo_root,
        build_tag=build_tag,
        platform=config.platform,
        configuration=config.configuration,
    )
    if not binary_path.is_file():
        raise RuntimeError(f"Built test executable not found: {binary_path}")

    xml_path = config.report_root / f"{workspace_id}-{suite_name}.xml"
    log_path = config.report_root / f"{workspace_id}-{suite_name}.log"
    exit_code_path = config.report_root / f"{workspace_id}-{suite_name}-exit-code.txt"
    completed = run_captured(
        build_doctest_xml_command(
            binary_path=binary_path,
            suite_name=suite_name,
            xml_path=xml_path,
        ),
        cwd=config.test_repo_root,
        log_path=log_path,
        check=False,
    )
    exit_code_path.write_text(f"{completed.returncode}\n", encoding="utf-8")
    return parse_doctest_xml(xml_path, suite_name=suite_name, workspace_id=workspace_id)
