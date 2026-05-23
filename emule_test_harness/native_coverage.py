"""Python native coverage orchestration for the shared test harness."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .artifact_names import utc_run_id
from .live_diff import build_emule_tests_command, get_default_workspace_root
from .paths import get_build_tag, get_test_binary_path, get_test_reports_root
from .processes import run_captured

DEFAULT_COVERAGE_VERSION = "0.9.9.0"


@dataclass(frozen=True)
class NativeCoverageConfig:
    """Resolved configuration for one native coverage run."""

    test_repo_root: Path
    workspace_root: Path
    app_root: Path
    configuration: str
    platform: str
    suite_names: tuple[str, ...]
    preferred_coverage_root: Path | None = None
    skip_build: bool = False


def resolve_app_root(workspace_root: Path, app_root: Path | None = None) -> Path:
    """Resolves the app root used for native coverage."""

    if app_root is not None:
        resolved = app_root.resolve()
        if not resolved.is_dir():
            raise RuntimeError(f"Explicit app root does not exist: {resolved}")
        return resolved
    resolved = (workspace_root.resolve() / "app" / "emulebb-main").resolve()
    if not resolved.is_dir():
        raise RuntimeError(f"Default app root does not exist: {resolved}")
    return resolved


def get_open_cpp_coverage_executable_path(install_root: Path) -> Path | None:
    """Returns OpenCppCoverage.exe under an install root when present."""

    candidate = install_root.resolve() / "OpenCppCoverage.exe"
    return candidate if candidate.is_file() else None


def resolve_open_cpp_coverage(
    test_repo_root: Path,
    *,
    preferred_install_root: Path | None = None,
    version: str = DEFAULT_COVERAGE_VERSION,
) -> Path:
    """Resolves or installs OpenCppCoverage for native coverage runs."""

    if preferred_install_root is not None:
        preferred = get_open_cpp_coverage_executable_path(preferred_install_root)
        if preferred is not None:
            return preferred

    path_executable = shutil.which("OpenCppCoverage.exe")
    if path_executable:
        return Path(path_executable).resolve()

    tools_root = test_repo_root.resolve() / "tools" / "OpenCppCoverage"
    download_root = tools_root / "downloads"
    install_root = tools_root / version
    installer_path = download_root / f"OpenCppCoverageSetup-x64-{version}.exe"
    download_url = f"https://github.com/OpenCppCoverage/OpenCppCoverage/releases/download/release-{version}/OpenCppCoverageSetup-x64-{version}.exe"
    repo_managed = get_open_cpp_coverage_executable_path(install_root)
    if repo_managed is not None:
        return repo_managed

    download_root.mkdir(parents=True, exist_ok=True)
    install_root.mkdir(parents=True, exist_ok=True)
    if not installer_path.is_file():
        urllib.request.urlretrieve(download_url, installer_path)

    installer_arguments = [
        "/SP-",
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        f"/DIR={install_root}",
    ]
    completed = subprocess.run([str(installer_path), *installer_arguments], check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"OpenCppCoverage installer failed with exit code {completed.returncode}.")

    repo_managed = get_open_cpp_coverage_executable_path(install_root)
    if repo_managed is None:
        raise RuntimeError(f"OpenCppCoverage.exe was not installed into '{install_root}'.")
    return repo_managed


def parse_doctest_suite_execution_stats(log_text: str) -> dict[str, int] | None:
    """Parses doctest execution counters from one suite log."""

    matches = re.findall(
        r"^\[doctest\] test cases:\s*(\d+)\s*\|\s*(\d+)\s*passed\s*\|\s*(\d+)\s*failed\s*\|\s*(\d+)\s*skipped",
        log_text,
        flags=re.MULTILINE,
    )
    if not matches:
        return None
    total, passed, failed, skipped = (int(value) for value in matches[-1])
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "executed": passed + failed,
    }


def build_coverage_command(
    *,
    coverage_executable_path: Path,
    binary_path: Path,
    app_root: Path,
    test_repo_root: Path,
    suite_name: str,
    suite_binary_coverage_path: Path,
    cobertura_path: Path | None,
    merged_binary_coverage_path: Path | None = None,
) -> tuple[str, ...]:
    """Builds one OpenCppCoverage suite invocation."""

    arguments: list[str] = [
        str(coverage_executable_path.resolve()),
        "--modules",
        str(binary_path.resolve()),
    ]
    for source_pattern in (
        test_repo_root.resolve() / "src" / "*",
        test_repo_root.resolve() / "include" / "*",
        app_root.resolve() / "*",
    ):
        arguments.extend(["--sources", str(source_pattern)])
    for excluded_source_pattern in (
        test_repo_root.resolve() / "third_party" / "*",
        test_repo_root.resolve() / "build" / "*",
        test_repo_root.resolve() / "reports" / "*",
        app_root.resolve() / "srchybrid" / "x64" / "*",
        app_root.resolve() / "res" / "*",
    ):
        arguments.extend(["--excluded_sources", str(excluded_source_pattern)])
    if merged_binary_coverage_path is not None:
        arguments.extend(["--input_coverage", str(merged_binary_coverage_path.resolve())])
    arguments.extend(
        [
            "--working_dir",
            str(binary_path.resolve().parent),
            "--export_type",
            f"binary:{suite_binary_coverage_path.resolve()}",
        ]
    )
    if cobertura_path is not None:
        arguments.extend(["--export_type", f"cobertura:{cobertura_path.resolve()}"])
    arguments.extend(
        [
            "--",
            str(binary_path.resolve()),
            "--no-intro",
            "--no-version",
            f"--test-suite={suite_name}",
        ]
    )
    return tuple(arguments)


def run_native_coverage(config: NativeCoverageConfig) -> int:
    """Runs native coverage and returns a process exit code."""

    build_tag = get_build_tag(config.workspace_root, config.app_root)
    report_root = get_test_reports_root(config.workspace_root)
    coverage_report_root = report_root / "native-coverage"
    report_stamp = utc_run_id()
    run_report_dir = coverage_report_root / f"{report_stamp}-{build_tag}-{config.platform}-{config.configuration}"
    latest_report_dir = coverage_report_root / "latest"
    coverage_summary_path = run_report_dir / "coverage-summary.json"
    coverage_summary_text_path = run_report_dir / "coverage-summary.txt"
    cobertura_path = run_report_dir / "coverage.cobertura.xml"
    run_report_dir.mkdir(parents=True, exist_ok=True)

    if not config.skip_build:
        run_captured(
            build_emule_tests_command(
                test_repo_root=config.test_repo_root,
                workspace_root=config.workspace_root,
                app_root=config.app_root,
                configuration=config.configuration,
                platform=config.platform,
                build_tag=build_tag,
            ),
            cwd=config.test_repo_root,
            check=True,
            echo=True,
        )

    binary_path = get_test_binary_path(
        config.test_repo_root,
        build_tag=build_tag,
        platform=config.platform,
        configuration=config.configuration,
    )
    if not binary_path.is_file():
        raise RuntimeError(f"Built test executable not found: {binary_path}")

    coverage_executable_path = resolve_open_cpp_coverage(
        config.test_repo_root,
        preferred_install_root=config.preferred_coverage_root,
    )
    suite_run_summaries: list[dict[str, object]] = []
    merged_binary_coverage_path: Path | None = None
    for index, suite_name in enumerate(config.suite_names):
        suite_log_path = run_report_dir / f"suite-{suite_name}.log"
        suite_binary_coverage_path = run_report_dir / f"suite-{suite_name}.cov"
        is_last_suite = index == len(config.suite_names) - 1
        completed = run_captured(
            build_coverage_command(
                coverage_executable_path=coverage_executable_path,
                binary_path=binary_path,
                app_root=config.app_root,
                test_repo_root=config.test_repo_root,
                suite_name=suite_name,
                suite_binary_coverage_path=suite_binary_coverage_path,
                cobertura_path=cobertura_path if is_last_suite else None,
                merged_binary_coverage_path=merged_binary_coverage_path,
            ),
            cwd=config.test_repo_root,
            log_path=suite_log_path,
            check=False,
            echo=True,
        )
        suite_stats = parse_doctest_suite_execution_stats(completed.output)
        suite_run_summaries.append(
            {
                "suite_name": suite_name,
                "exit_code": completed.returncode,
                "log_path": str(suite_log_path),
                "binary_coverage_path": str(suite_binary_coverage_path),
                "execution": suite_stats,
            }
        )
        if completed.returncode != 0:
            raise RuntimeError(f"Coverage run for suite '{suite_name}' failed with exit code {completed.returncode}.")
        if suite_stats is None:
            raise RuntimeError(f"Coverage run for suite '{suite_name}' did not produce a doctest summary line.")
        if int(suite_stats["executed"]) <= 0:
            raise RuntimeError(f"Coverage run for suite '{suite_name}' executed zero test cases.")
        merged_binary_coverage_path = suite_binary_coverage_path

    if not cobertura_path.is_file():
        raise RuntimeError(f"Combined Cobertura coverage report was not generated: {cobertura_path}")

    lines_covered, lines_valid, line_rate_percent = read_cobertura_line_metrics(cobertura_path)
    summary = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test_repo_root": str(config.test_repo_root),
        "workspace_root": str(config.workspace_root),
        "app_root": str(config.app_root),
        "configuration": config.configuration,
        "platform": config.platform,
        "build_tag": build_tag,
        "binary_path": str(binary_path),
        "coverage_tool_path": str(coverage_executable_path),
        "report_dir": str(run_report_dir),
        "latest_report_dir": str(latest_report_dir),
        "cobertura_path": str(cobertura_path),
        "suite_runs": suite_run_summaries,
        "lines_covered": lines_covered,
        "lines_valid": lines_valid,
        "line_rate_percent": line_rate_percent,
    }
    coverage_summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    coverage_summary_text_path.write_text(
        "\n".join(
            [
                "Native seam coverage",
                f"workspace_root: {config.workspace_root}",
                f"binary_path: {binary_path}",
                f"coverage_tool_path: {coverage_executable_path}",
                f"suite_names: {', '.join(config.suite_names)}",
                f"lines_covered: {lines_covered}",
                f"lines_valid: {lines_valid}",
                f"line_rate_percent: {line_rate_percent}",
                f"cobertura_path: {cobertura_path}",
                f"report_dir: {run_report_dir}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    publish_directory_snapshot(run_report_dir, latest_report_dir)
    publish_harness_summary(config.test_repo_root, config.workspace_root, coverage_summary_path)
    print(f"Native coverage report directory: {run_report_dir}")
    return 0


def read_cobertura_line_metrics(cobertura_path: Path) -> tuple[int, int, float]:
    """Reads line coverage metrics from a Cobertura XML report."""

    root = ET.parse(cobertura_path).getroot()
    lines_covered = int(root.get("lines-covered") or 0)
    lines_valid = int(root.get("lines-valid") or 0)
    line_rate_raw = root.get("line-rate")
    if lines_valid > 0:
        line_rate_percent = round((lines_covered / lines_valid) * 100.0, 2)
    elif line_rate_raw:
        line_rate_percent = round(float(line_rate_raw) * 100.0, 2)
    else:
        line_rate_percent = 0.0
    return lines_covered, lines_valid, line_rate_percent


def publish_directory_snapshot(source_directory: Path, destination_directory: Path) -> None:
    """Refreshes one directory snapshot."""

    if destination_directory.exists():
        shutil.rmtree(destination_directory)
    destination_directory.mkdir(parents=True, exist_ok=True)
    for entry in source_directory.iterdir():
        destination = destination_directory / entry.name
        if entry.is_dir():
            shutil.copytree(entry, destination)
        else:
            shutil.copy2(entry, destination)


def publish_harness_summary(test_repo_root: Path, workspace_root: Path, coverage_summary_path: Path) -> None:
    """Refreshes the shared harness summary after a native coverage run."""

    run_captured(
        (
            sys.executable,
            str((test_repo_root / "scripts" / "publish-harness-summary.py").resolve()),
            "--test-repo-root",
            str(test_repo_root.resolve()),
            "--workspace-root",
            str(workspace_root.resolve()),
            "--coverage-summary-path",
            str(coverage_summary_path.resolve()),
        ),
        check=True,
        echo=True,
    )


def build_config(
    *,
    test_repo_root: Path,
    workspace_root: Path | None,
    app_root: Path | None,
    configuration: str,
    platform: str,
    suite_names: tuple[str, ...],
    preferred_coverage_root: Path | None,
    skip_build: bool,
) -> NativeCoverageConfig:
    """Builds a resolved native coverage config from CLI inputs."""

    resolved_test_repo_root = test_repo_root.resolve()
    resolved_workspace_root = (workspace_root or get_default_workspace_root(resolved_test_repo_root)).resolve()
    resolved_app_root = resolve_app_root(resolved_workspace_root, app_root)
    return NativeCoverageConfig(
        test_repo_root=resolved_test_repo_root,
        workspace_root=resolved_workspace_root,
        app_root=resolved_app_root,
        configuration=configuration,
        platform=platform,
        suite_names=suite_names,
        preferred_coverage_root=preferred_coverage_root.resolve() if preferred_coverage_root is not None else None,
        skip_build=skip_build,
    )
