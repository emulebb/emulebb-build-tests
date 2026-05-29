"""Operator-facing release campaign matrix reporter."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.release_campaigns import (
    DEFAULT_CAMPAIGN_ID,
    ReleaseCampaignPaths,
    build_release_campaign_report,
    format_release_campaign_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Builds the release campaign reporter CLI parser."""

    parser = argparse.ArgumentParser(description="Show eMuleBB release campaign phases, flows, and evidence status.")
    parser.add_argument("--test-repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--workspace-root", type=Path, default=None)
    parser.add_argument("--workspace-state-root", type=Path, default=None)
    parser.add_argument("--campaign", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--phase", default=None)
    parser.add_argument("--template", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the release campaign reporter."""

    args = build_parser().parse_args(argv)
    workspace_root = args.workspace_root
    if workspace_root is None and os.environ.get("EMULEBB_WORKSPACE_ROOT"):
        workspace_root = Path(os.environ["EMULEBB_WORKSPACE_ROOT"])

    report = build_release_campaign_report(
        ReleaseCampaignPaths(
            tests_repo_root=args.test_repo_root.resolve(),
            emule_workspace_root=workspace_root.resolve() if workspace_root else None,
            workspace_state_root=args.workspace_state_root.resolve() if args.workspace_state_root else None,
        ),
        campaign_id=args.campaign,
        phase_id=args.phase,
        show_template=args.template,
    )
    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_release_campaign_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
