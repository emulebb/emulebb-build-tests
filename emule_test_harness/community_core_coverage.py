"""Canonical main-vs-community coverage orchestration."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .live_diff import LiveDiffConfig, run_live_diff
from .native_coverage import NativeCoverageConfig, run_native_coverage


@dataclass(frozen=True)
class CommunityCoreCoverageConfig:
    """Resolved configuration for one community-core coverage run."""

    test_repo_root: Path
    workspace_root: Path
    main_app_root: Path
    community_app_root: Path
    configuration: str
    platform: str
    preferred_coverage_root: Path | None = None


def get_latest_coverage_summary_path(test_repo_root: Path) -> Path:
    """Returns the most recently written native coverage summary."""

    coverage_root = test_repo_root.resolve() / "reports" / "native-coverage"
    summaries = sorted(
        coverage_root.glob("**/coverage-summary.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not summaries:
        raise RuntimeError(f"Unable to locate a native coverage summary under '{coverage_root}'.")
    return summaries[0]


def run_community_core_coverage(config: CommunityCoreCoverageConfig) -> int:
    """Runs the canonical main-vs-community coverage and live-diff comparison."""

    run_report_dir = config.test_repo_root / "reports" / "community-core-coverage" / time.strftime("%Y%m%d-%H%M%S")
    run_report_dir.mkdir(parents=True, exist_ok=True)

    run_native_coverage(
        NativeCoverageConfig(
            test_repo_root=config.test_repo_root,
            workspace_root=config.workspace_root,
            app_root=config.main_app_root,
            configuration=config.configuration,
            platform=config.platform,
            suite_names=("parity", "community-core-divergence"),
            preferred_coverage_root=config.preferred_coverage_root,
        )
    )
    main_coverage_summary_path = get_latest_coverage_summary_path(config.test_repo_root)

    run_native_coverage(
        NativeCoverageConfig(
            test_repo_root=config.test_repo_root,
            workspace_root=config.workspace_root,
            app_root=config.community_app_root,
            configuration=config.configuration,
            platform=config.platform,
            suite_names=("parity",),
            preferred_coverage_root=config.preferred_coverage_root,
        )
    )
    community_coverage_summary_path = get_latest_coverage_summary_path(config.test_repo_root)

    live_diff_result = run_live_diff(
        LiveDiffConfig(
            test_repo_root=config.test_repo_root,
            test_run_workspace_root=config.workspace_root,
            baseline_workspace_root=config.workspace_root,
            test_run_app_root=config.main_app_root,
            baseline_app_root=config.community_app_root,
            configuration=config.configuration,
            platform=config.platform,
            suite_names=("parity", "community-core-divergence"),
            report_root=config.test_repo_root / "reports",
        )
    )
    if live_diff_result != 0:
        return live_diff_result

    live_diff_summary_path = config.test_repo_root / "reports" / "live-diff-summary.json"
    combined_summary_path = run_report_dir / "community-core-coverage-summary.json"
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "workspace_root": str(config.workspace_root),
        "main_app_root": str(config.main_app_root),
        "community_app_root": str(config.community_app_root),
        "configuration": config.configuration,
        "platform": config.platform,
        "main_coverage_summary": str(main_coverage_summary_path),
        "community_coverage_summary": str(community_coverage_summary_path),
        "live_diff_summary": str(live_diff_summary_path),
    }
    combined_summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Community core coverage summary: {combined_summary_path}")
    return 0


def build_config(
    *,
    test_repo_root: Path,
    workspace_root: Path | None,
    main_app_root: Path | None,
    community_app_root: Path | None,
    configuration: str,
    platform: str,
    preferred_coverage_root: Path | None,
) -> CommunityCoreCoverageConfig:
    """Builds a resolved community-core coverage config from CLI inputs."""

    resolved_test_repo_root = test_repo_root.resolve()
    resolved_workspace_root = (
        workspace_root.resolve()
        if workspace_root is not None
        else (resolved_test_repo_root / ".." / ".." / "workspaces" / "v0.72a").resolve()
    )
    resolved_main_app_root = (
        main_app_root.resolve()
        if main_app_root is not None
        else (resolved_workspace_root / "app" / "eMule-main").resolve()
    )
    resolved_community_app_root = (
        community_app_root.resolve()
        if community_app_root is not None
        else (resolved_workspace_root / "app" / "eMule-v0.72a-community").resolve()
    )
    for label, path in (
        ("workspace root", resolved_workspace_root),
        ("main app root", resolved_main_app_root),
        ("community app root", resolved_community_app_root),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} does not exist: {path}")
    return CommunityCoreCoverageConfig(
        test_repo_root=resolved_test_repo_root,
        workspace_root=resolved_workspace_root,
        main_app_root=resolved_main_app_root,
        community_app_root=resolved_community_app_root,
        configuration=configuration,
        platform=platform,
        preferred_coverage_root=preferred_coverage_root.resolve() if preferred_coverage_root is not None else None,
    )


def invoke_script(argv: list[str]) -> int:
    """Runs the CLI using the shared config builder."""

    from argparse import ArgumentParser

    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--test-repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--main-app-root", type=Path)
    parser.add_argument("--community-app-root", type=Path)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Debug")
    parser.add_argument("--platform", choices=("x64",), default="x64")
    parser.add_argument("--preferred-coverage-root", type=Path)
    args = parser.parse_args(argv)
    return run_community_core_coverage(
        build_config(
            test_repo_root=args.test_repo_root,
            workspace_root=args.workspace_root,
            main_app_root=args.main_app_root,
            community_app_root=args.community_app_root,
            configuration=args.configuration,
            platform=args.platform,
            preferred_coverage_root=args.preferred_coverage_root,
        )
    )


if __name__ == "__main__":
    raise SystemExit(invoke_script(sys.argv[1:]))
