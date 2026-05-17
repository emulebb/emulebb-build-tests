"""Runs the Kad/eD2K protocol-sensitive source drift checker."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.protocol_surface import (
    check_protocol_surface,
    load_manifest,
    render_report_lines,
    write_report,
)
from emule_test_harness.workspace_layout import get_default_workspace_root


def build_parser() -> argparse.ArgumentParser:
    """Builds the protocol-surface CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--test-run-app-root", type=Path)
    parser.add_argument("--baseline-app-root", type=Path)
    parser.add_argument("--manifest-path", type=Path)
    parser.add_argument("--report-path", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the command-line protocol surface check."""

    args = build_parser().parse_args(argv)
    test_repo_root = args.test_repo_root.resolve()
    workspace_root = (args.workspace_root or get_default_workspace_root(test_repo_root)).resolve()
    test_run_app_root = (args.test_run_app_root or (workspace_root / "app" / "eMule-main")).resolve()
    baseline_app_root = (args.baseline_app_root or (workspace_root / "app" / "eMule-community-baseline")).resolve()
    manifest_path = (args.manifest_path or (test_repo_root / "protocol-parity-surface.json")).resolve()
    report_path = (args.report_path or (test_repo_root / "reports" / "protocol-surface-diff.json")).resolve()

    report = check_protocol_surface(
        manifest=load_manifest(manifest_path),
        test_run_app_root=test_run_app_root,
        baseline_app_root=baseline_app_root,
    )
    write_report(report, report_path)
    for line in render_report_lines(report):
        print(line)
    print(f"Summary: {report_path}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
