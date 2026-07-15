"""Report the current Rust soak profile status from persisted run artifacts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.paths import get_workspace_output_root


def read_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def rest_status(base_url: str, api_key: str) -> dict[str, object]:
    request = urllib.request.Request(base_url.rstrip("/") + "/api/v1/status")
    request.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"error": {"type": type(exc).__name__, "message": str(exc)}}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-key", default="converged-soak")
    parser.add_argument("--rest-base-url", default="")
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument("--watch-interval-seconds", type=float, default=0.0)
    parser.add_argument("--watch-count", type=int, default=1)
    return parser


def build_report(*, rest_base_url: str, api_key: str) -> dict[str, object]:
    """Builds one status report from persisted artifacts and live REST state."""

    output_root = get_workspace_output_root()
    latest = read_json(output_root / "logs" / "soak-launch" / "rust-regular-1h-soak.latest.json")
    last_run = read_json(output_root / "soak" / "last-run" / "manifest.json")
    report_dir = Path(str(last_run.get("reportDir") or ""))
    metrics = read_json(report_dir / "analysis" / "rust-process-metrics-summary.json") if report_dir else {}
    status = rest_status(rest_base_url, api_key) if rest_base_url else {"error": {"message": "X_LOCAL_IP is not set"}}

    return {
        "schema": "emulebb.rust-soak-profile-report.v1",
        "background": {
            "pid": latest.get("pid"),
            "startedUtc": latest.get("startedUtc"),
            "seconds": latest.get("seconds"),
            "stdout": latest.get("stdout"),
            "stderr": latest.get("stderr"),
        },
        "run": {
            "campaignId": last_run.get("campaignId"),
            "status": last_run.get("status"),
            "reportDir": last_run.get("reportDir"),
            "rustExe": last_run.get("rustExe"),
            "rustProfileDir": last_run.get("rustProfileDir"),
        },
        "processMetrics": metrics.get("summary") if isinstance(metrics.get("summary"), dict) else {},
        "status": status.get("data", status),
    }


def compact_summary(report: dict[str, object]) -> dict[str, object]:
    """Returns the fields needed for regular operator monitoring."""

    metrics = report.get("processMetrics") if isinstance(report.get("processMetrics"), dict) else {}
    last = metrics.get("last") if isinstance(metrics.get("last"), dict) else {}
    status = report.get("status") if isinstance(report.get("status"), dict) else {}
    stats = status.get("stats") if isinstance(status.get("stats"), dict) else {}
    kad = status.get("kad") if isinstance(status.get("kad"), dict) else {}
    servers = status.get("servers") if isinstance(status.get("servers"), dict) else {}
    vpn = status.get("network", {}).get("vpnGuard") if isinstance(status.get("network"), dict) else {}
    if not isinstance(vpn, dict):
        vpn = {}
    run = report.get("run") if isinstance(report.get("run"), dict) else {}
    background = report.get("background") if isinstance(report.get("background"), dict) else {}
    return {
        "campaignId": run.get("campaignId"),
        "runStatus": run.get("status"),
        "backgroundPid": background.get("pid"),
        "elapsedSeconds": last.get("elapsed_seconds"),
        "cpuSeconds": last.get("cpu_seconds"),
        "cpuOneCorePct": last.get("process_pct_one_core"),
        "privateMb": last.get("private_mb"),
        "workingSetMb": last.get("working_set_mb"),
        "handles": last.get("handles"),
        "ed2kConnected": stats.get("ed2kConnected"),
        "ed2kHighId": stats.get("ed2kHighId"),
        "kadConnected": stats.get("kadConnected"),
        "kadContacts": kad.get("contactCount"),
        "serverConnected": servers.get("connected"),
        "currentServer": servers.get("currentServer"),
        "vpnGuardEnabled": vpn.get("enabled"),
        "vpnPublicIp": vpn.get("publicIp"),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.watch_count <= 0:
        raise RuntimeError("--watch-count must be greater than zero.")
    if args.watch_interval_seconds < 0:
        raise RuntimeError("--watch-interval-seconds must not be negative.")

    lan_ip = os.environ.get("X_LOCAL_IP", "").strip()
    rest_base_url = args.rest_base_url.strip() or (f"http://{lan_ip}:4731" if lan_ip else "")
    for index in range(args.watch_count):
        report = build_report(rest_base_url=rest_base_url, api_key=args.api_key)
        payload = compact_summary(report) if args.summary_only else report
        print(json.dumps(payload, indent=2, sort_keys=True), flush=True)
        if index + 1 < args.watch_count and args.watch_interval_seconds > 0:
            time.sleep(args.watch_interval_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
