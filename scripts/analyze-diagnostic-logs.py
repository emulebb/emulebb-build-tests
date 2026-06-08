"""Analyze eMuleBB diagnostics logs from one profile log directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from emule_test_harness.diagnostic_logs import analyze_diagnostic_logs, format_diagnostic_log_analysis  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs-dir", required=True, type=Path, help="Directory containing emulebb-diagnostics-*.log files.")
    parser.add_argument("--window-minutes", type=float, default=15.0, help="Bad-peer analysis window.")
    parser.add_argument("--top", type=int, default=12, help="Maximum rows per top list.")
    parser.add_argument("--json", action="store_true", help="Write machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the diagnostics log analyzer."""

    args = build_parser().parse_args(argv)
    analysis = analyze_diagnostic_logs(args.logs_dir, window_minutes=args.window_minutes, top_count=args.top)
    if args.json:
        print(json.dumps(analysis, indent=2, sort_keys=True))
    else:
        print(format_diagnostic_log_analysis(analysis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
