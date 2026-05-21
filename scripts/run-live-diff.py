"""Runs the Python-first test-run-vs-baseline native live-diff comparison."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.live_diff import (
    DEFAULT_SUITE_NAMES,
    LiveDiffConfig,
    get_default_workspace_root,
    run_live_diff,
)
from emule_test_harness.paths import get_test_reports_root, reject_windows_temp_path


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser for the live-diff runner."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--test-run-workspace-root", type=Path)
    parser.add_argument("--baseline-workspace-root", type=Path)
    parser.add_argument("--test-run-app-root", type=Path)
    parser.add_argument("--baseline-app-root", type=Path)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Debug")
    parser.add_argument("--platform", choices=("x64",), default="x64")
    parser.add_argument("--suite-name", dest="suite_names", action="append")
    parser.add_argument("--report-root", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the command-line live-diff flow."""

    args = build_parser().parse_args(argv)
    test_repo_root = args.test_repo_root.resolve()
    test_run_workspace_root = (args.test_run_workspace_root or get_default_workspace_root(test_repo_root)).resolve()
    baseline_workspace_root = (args.baseline_workspace_root or get_default_workspace_root(test_repo_root)).resolve()
    report_root = (args.report_root or get_test_reports_root(test_run_workspace_root)).resolve()
    reject_windows_temp_path(report_root, "report root")
    config = LiveDiffConfig(
        test_repo_root=test_repo_root,
        test_run_workspace_root=test_run_workspace_root,
        baseline_workspace_root=baseline_workspace_root,
        test_run_app_root=args.test_run_app_root.resolve() if args.test_run_app_root else None,
        baseline_app_root=args.baseline_app_root.resolve() if args.baseline_app_root else None,
        configuration=args.configuration,
        platform=args.platform,
        suite_names=tuple(args.suite_names or DEFAULT_SUITE_NAMES),
        report_root=report_root,
        skip_build=args.skip_build,
    )
    return run_live_diff(config)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
