"""Analyze eMuleBB diagnostics logs from one profile log directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from emule_test_harness.diagnostic_logs import (  # noqa: E402
    analyze_diagnostic_logs,
    analyze_upload_bandwidth,
    format_diagnostic_log_analysis,
    format_upload_bandwidth,
    format_upload_bandwidth_watch,
    summarize_upload_bandwidth_watch,
)


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs-dir", required=True, type=Path, help="Directory containing emulebb-diagnostics-*.log files.")
    parser.add_argument("--window-minutes", type=float, default=15.0, help="Bad-peer analysis window.")
    parser.add_argument("--top", type=int, default=12, help="Maximum rows per top list.")
    parser.add_argument(
        "--upload-bandwidth",
        action="store_true",
        help="Report upload-slot bandwidth utilization vs the configured upload budget (max-upload-BW view).",
    )
    parser.add_argument("--tail", type=int, default=12, help="Upload-bandwidth recent-sample rows to show.")
    parser.add_argument(
        "--budget-bytes-per-sec",
        type=int,
        default=None,
        help="Override the upload budget; defaults to configuredBudgetBytesPerSec from the latest summary.",
    )
    parser.add_argument(
        "--target-utilization",
        type=float,
        default=0.98,
        help="Target utilization fraction for upload-bandwidth analysis.",
    )
    parser.add_argument(
        "--watch-samples",
        type=int,
        default=1,
        help="Run upload-bandwidth analysis repeatedly for this many samples.",
    )
    parser.add_argument(
        "--watch-interval-sec",
        type=float,
        default=15.0,
        help="Seconds between upload-bandwidth watch samples.",
    )
    parser.add_argument("--json", action="store_true", help="Write machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the diagnostics log analyzer."""

    args = build_parser().parse_args(argv)
    if args.upload_bandwidth:
        analyses = []
        watch_samples = max(1, args.watch_samples)
        for sample_index in range(watch_samples):
            analysis = analyze_upload_bandwidth(
                args.logs_dir,
                tail=args.tail,
                budget_bytes_per_sec=args.budget_bytes_per_sec,
                target_utilization=args.target_utilization,
            )
            analysis["sample_index"] = sample_index
            analysis["sample_count"] = watch_samples
            analysis["sample_time"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            analyses.append(analysis)
            if args.json:
                print(json.dumps(analysis, sort_keys=True), flush=True)
            else:
                if watch_samples > 1:
                    print(f"[{sample_index + 1}/{watch_samples}] {analysis['sample_time']}")
                print(format_upload_bandwidth(analysis), flush=True)
            if sample_index + 1 < watch_samples:
                time.sleep(max(0.1, args.watch_interval_sec))
        if watch_samples > 1 and not args.json:
            print(format_upload_bandwidth_watch(summarize_upload_bandwidth_watch(analyses)), flush=True)
        return 0
    analysis = analyze_diagnostic_logs(args.logs_dir, window_minutes=args.window_minutes, top_count=args.top)
    if args.json:
        print(json.dumps(analysis, indent=2, sort_keys=True))
    else:
        print(format_diagnostic_log_analysis(analysis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
