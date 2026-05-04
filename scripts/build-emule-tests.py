"""Builds the shared standalone eMule native test executable."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.build_tests import resolve_build_config, run_build_tests


def build_parser() -> argparse.ArgumentParser:
    """Builds the native test build CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--app-root", type=Path)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Debug")
    parser.add_argument("--platform", choices=("x64", "ARM64"), default="x64")
    parser.add_argument("--build-output-mode", choices=("Full", "Warnings", "ErrorsOnly"), default="ErrorsOnly")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--run", dest="run_tests", action="store_true")
    parser.add_argument("--out-file", type=Path)
    parser.add_argument("--allow-test-failure", action="store_true")
    parser.add_argument("--build-tag")
    parser.add_argument("--build-log-session-stamp")
    parser.add_argument("--skip-tracked-file-privacy-guard", action="store_true")
    parser.add_argument("test_arguments", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the native test build CLI."""

    args = build_parser().parse_args(argv)
    test_arguments = list(args.test_arguments)
    if test_arguments and test_arguments[0] == "--":
        test_arguments = test_arguments[1:]
    config = resolve_build_config(
        test_repo_root=args.test_repo_root,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        configuration=args.configuration,
        platform=args.platform,
        build_output_mode=args.build_output_mode,
        clean=args.clean,
        run_tests=args.run_tests,
        out_file=args.out_file,
        allow_test_failure=args.allow_test_failure,
        build_tag=args.build_tag,
        build_log_session_stamp=args.build_log_session_stamp,
        skip_tracked_file_privacy_guard=args.skip_tracked_file_privacy_guard,
        test_arguments=tuple(test_arguments),
    )
    return run_build_tests(config)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
