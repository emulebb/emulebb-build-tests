"""Fails when tracked files contain local path or personal-identifier leaks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.privacy_guard import PrivacyGuardFailure, run_privacy_guard


def build_parser() -> argparse.ArgumentParser:
    """Builds the tracked-file privacy guard CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--policy-path", type=Path, default=REPO_ROOT / "manifests" / "privacy-guard" / "policy.v1.json")
    parser.add_argument("--summary-path", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the tracked-file privacy guard CLI."""

    args = build_parser().parse_args(argv)
    try:
        summary = run_privacy_guard(
            repo_root=args.repo_root,
            policy_path=args.policy_path,
            summary_path=args.summary_path,
        )
    except PrivacyGuardFailure as exc:
        print(json.dumps(exc.summary, indent=2))
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
