"""Report the current Rust soak profile status from persisted run artifacts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_root = get_workspace_output_root()
    latest = read_json(output_root / "logs" / "soak-launch" / "rust-regular-1h-soak.latest.json")
    last_run = read_json(output_root / "soak" / "last-run" / "manifest.json")
    report_dir = Path(str(last_run.get("reportDir") or ""))
    metrics = read_json(report_dir / "analysis" / "rust-process-metrics-summary.json") if report_dir else {}
    lan_ip = os.environ.get("X_LOCAL_IP", "").strip()
    rest_base_url = args.rest_base_url.strip() or (f"http://{lan_ip}:4731" if lan_ip else "")
    status = rest_status(rest_base_url, args.api_key) if rest_base_url else {"error": {"message": "X_LOCAL_IP is not set"}}

    payload = {
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
            "rustRuntimeDir": last_run.get("rustRuntimeDir"),
        },
        "processMetrics": metrics.get("summary") if isinstance(metrics.get("summary"), dict) else {},
        "status": status.get("data", status),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
