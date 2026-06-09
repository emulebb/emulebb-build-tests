"""Publishes the combined coverage, parity, and optional live-harness summary."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.paths import get_default_workspace_root, get_test_reports_root


def read_json_file(path: Path | None):
    """Reads one JSON file when it exists."""

    if path is None or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def build_combined_summary(
    *,
    coverage_summary,
    live_diff_summary,
    live_session_manifest,
    live_ui_summary,
    startup_diagnostics_summary,
) -> dict[str, object]:
    """Builds the stable combined summary payload under the workspace test report root."""

    live_ui_result = live_ui_summary.get("result") if isinstance(live_ui_summary, dict) else None
    startup_diagnostics_result = startup_diagnostics_summary.get("result") if isinstance(startup_diagnostics_summary, dict) else None
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "coverage": (
            {
                "report_dir": coverage_summary.get("report_dir"),
                "line_rate_percent": coverage_summary.get("line_rate_percent"),
                "lines_covered": coverage_summary.get("lines_covered"),
                "lines_valid": coverage_summary.get("lines_valid"),
                "suite_runs": coverage_summary.get("suite_runs"),
            }
            if isinstance(coverage_summary, dict)
            else None
        ),
        "parity": (
            {
                "report_root": live_diff_summary.get("report_root"),
                "failed": bool(live_diff_summary.get("failed")),
                "suites": live_diff_summary.get("suites"),
            }
            if isinstance(live_diff_summary, dict)
            else None
        ),
        "live_harness": (
            {
                "launch_status": live_session_manifest.get("launch_status"),
                "scenario_profile": live_session_manifest.get("scenario_profile"),
                "cleanup_success": live_session_manifest.get("cleanup_success"),
                "leftover_process_ids": live_session_manifest.get("leftover_process_ids"),
                "artifact_dir": live_session_manifest.get("artifact_dir"),
                "profile_root": live_session_manifest.get("profile_root"),
            }
            if isinstance(live_session_manifest, dict)
            else None
        ),
        "live_ui": (
            {
                "status": live_ui_summary.get("status"),
                "artifact_dir": live_ui_summary.get("artifact_dir"),
                "latest_report_dir": live_ui_summary.get("latest_report_dir"),
                "app_exe": live_ui_summary.get("app_exe"),
                "configuration": live_ui_summary.get("configuration"),
                "shared_root": live_ui_result.get("shared_root") if isinstance(live_ui_result, dict) else None,
                "scenario_count": len(live_ui_result.get("scenarios", [])) if isinstance(live_ui_result, dict) else 0,
                "error": live_ui_summary.get("error"),
            }
            if isinstance(live_ui_summary, dict)
            else None
        ),
        "startup_diagnostics": (
            {
                "status": startup_diagnostics_summary.get("status"),
                "artifact_dir": startup_diagnostics_summary.get("artifact_dir"),
                "latest_report_dir": startup_diagnostics_summary.get("latest_report_dir"),
                "app_exe": startup_diagnostics_summary.get("app_exe"),
                "configuration": startup_diagnostics_summary.get("configuration"),
                "shared_root": startup_diagnostics_summary.get("shared_root"),
                "scenario_count": len(startup_diagnostics_result.get("scenarios", [])) if isinstance(startup_diagnostics_result, dict) else 0,
                "error": startup_diagnostics_summary.get("error"),
            }
            if isinstance(startup_diagnostics_summary, dict)
            else None
        ),
    }


def build_text_summary(combined_summary: dict[str, object]) -> list[str]:
    """Builds the human-readable summary text lines."""

    coverage = combined_summary.get("coverage")
    parity = combined_summary.get("parity")
    live_harness = combined_summary.get("live_harness")
    live_ui = combined_summary.get("live_ui")
    startup_diagnostics = combined_summary.get("startup_diagnostics")
    return [
        "Harness summary",
        f"coverage_available: {coverage is not None}",
        f"parity_available: {parity is not None}",
        f"live_harness_available: {live_harness is not None}",
        f"live_ui_available: {live_ui is not None}",
        f"startup_diagnostics_available: {startup_diagnostics is not None}",
        f"coverage_line_rate_percent: {coverage.get('line_rate_percent', '') if isinstance(coverage, dict) else ''}",
        f"parity_failed: {parity.get('failed', '') if isinstance(parity, dict) else ''}",
        f"live_cleanup_success: {live_harness.get('cleanup_success', '') if isinstance(live_harness, dict) else ''}",
        f"live_ui_status: {live_ui.get('status', '') if isinstance(live_ui, dict) else ''}",
        f"startup_diagnostics_status: {startup_diagnostics.get('status', '') if isinstance(startup_diagnostics, dict) else ''}",
    ]


def main(argv: list[str] | None = None) -> int:
    """Parses arguments, writes the combined summaries, and prints the JSON path."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--test-repo-root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--coverage-summary-path", default="")
    parser.add_argument("--live-diff-summary-path", default="")
    parser.add_argument("--live-session-manifest-path", default="")
    parser.add_argument("--live-ui-summary-path", default="")
    parser.add_argument("--startup-diagnostics-summary-path", default="")
    args = parser.parse_args(argv)

    test_repo_root = Path(args.test_repo_root).resolve()
    workspace_root = get_default_workspace_root(test_repo_root)
    report_root = get_test_reports_root(workspace_root)
    coverage_summary_path = Path(args.coverage_summary_path).resolve() if args.coverage_summary_path else report_root / "native-coverage" / "latest" / "coverage-summary.json"
    live_diff_summary_path = Path(args.live_diff_summary_path).resolve() if args.live_diff_summary_path else report_root / "live-diff-summary.json"
    live_ui_summary_path = Path(args.live_ui_summary_path).resolve() if args.live_ui_summary_path else report_root / "shared-files-ui-e2e" / "latest" / "shared-files-ui-e2e-summary.json"
    startup_diagnostics_summary_path = Path(args.startup_diagnostics_summary_path).resolve() if args.startup_diagnostics_summary_path else report_root / "startup-diagnostics-scenarios" / "latest" / "startup-diagnostics-scenarios-summary.json"
    live_session_manifest_path = Path(args.live_session_manifest_path).resolve() if args.live_session_manifest_path else None

    combined_summary = build_combined_summary(
        coverage_summary=read_json_file(coverage_summary_path),
        live_diff_summary=read_json_file(live_diff_summary_path),
        live_session_manifest=read_json_file(live_session_manifest_path),
        live_ui_summary=read_json_file(live_ui_summary_path),
        startup_diagnostics_summary=read_json_file(startup_diagnostics_summary_path),
    )
    json_path = report_root / "harness-summary-result.json"
    text_path = report_root / "harness-summary.txt"
    json_path.write_text(json.dumps(combined_summary, indent=2, sort_keys=False), encoding="utf-8")
    text_path.write_text("\n".join(build_text_summary(combined_summary)) + "\n", encoding="utf-8")
    print(f"Harness summary JSON: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
