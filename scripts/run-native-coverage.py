"""Runs native doctest suites under OpenCppCoverage."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.native_coverage import build_config, run_native_coverage


def build_parser() -> argparse.ArgumentParser:
    """Builds the native coverage command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--app-root", type=Path)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Debug")
    parser.add_argument("--platform", choices=("x64",), default="x64")
    parser.add_argument("--suite-name", dest="suite_names", action="append", default=[])
    parser.add_argument("--preferred-coverage-root", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the native coverage flow."""

    args = build_parser().parse_args(argv)
    config = build_config(
        test_repo_root=args.test_repo_root,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        configuration=args.configuration,
        platform=args.platform,
        suite_names=tuple(args.suite_names or ["parity"]),
        preferred_coverage_root=args.preferred_coverage_root,
        skip_build=args.skip_build,
    )
    return run_native_coverage(config)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
