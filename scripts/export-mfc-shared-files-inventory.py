"""Export MFC shared-file REST rows for exact Rust metadata pre-seeding.

The converged soak runner can consume this JSON via
``--mfc-shared-files-inventory`` before Rust starts. The file is intentionally a
local artifact because it contains private shared-file paths and hashes.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.soak_launch import MFC_API_KEY


def request_json(base_url: str, path: str, api_key: str, *, timeout_seconds: float) -> dict[str, Any]:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = urllib.request.Request(url, headers={"X-API-Key": api_key})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"request failed for {path}: {exc}") from exc
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected response shape for {path}")
    return data


def extract_page(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int | None]:
    data = payload.get("data")
    container = data if isinstance(data, dict) else payload
    items = container.get("items")
    if not isinstance(items, list):
        raise RuntimeError("shared-files response did not contain an items list")
    total = container.get("total")
    return [item for item in items if isinstance(item, dict)], int(total) if total is not None else None


def export_inventory(
    *,
    base_url: str,
    api_key: str,
    output_path: Path,
    page_size: int,
    timeout_seconds: float,
    sleep_seconds: float,
) -> dict[str, Any]:
    if page_size <= 0:
        raise ValueError("--page-size must be greater than zero")
    rows: list[dict[str, Any]] = []
    offset = 0
    total: int | None = None
    while total is None or len(rows) < total:
        path = f"/api/v1/shared-files?offset={offset}&limit={page_size}"
        page, page_total = extract_page(request_json(base_url, path, api_key, timeout_seconds=timeout_seconds))
        if total is None:
            total = page_total
        elif page_total is not None and page_total != total:
            raise RuntimeError(f"shared-files total changed during export: started at {total}, now {page_total}")
        if not page:
            if total is not None and len(rows) < total:
                raise RuntimeError(f"shared-files inventory ended early: got {len(rows)} of {total} row(s)")
            break
        rows.extend(page)
        if total is not None and len(rows) > total:
            raise RuntimeError(f"shared-files inventory exceeded reported total: got {len(rows)} of {total} row(s)")
        offset += len(page)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    if total is not None and len(rows) != total:
        raise RuntimeError(f"shared-files inventory incomplete: got {len(rows)} of {total} row(s)")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "schema": "mfc_shared_files_inventory_v1",
        "capturedAtUtc": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "count": len(rows),
        "items": rows,
    }
    output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"outputPath": str(output_path), "total": total, "count": len(rows)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="MFC REST base URL, e.g. http://192.168.1.210:4732")
    parser.add_argument("--api-key", default=MFC_API_KEY)
    parser.add_argument("--output", required=True, help="Output JSON path.")
    parser.add_argument("--page-size", type=int, default=1000)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--sleep-seconds", type=float, default=0.1)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = export_inventory(
        base_url=args.base_url,
        api_key=args.api_key,
        output_path=Path(args.output),
        page_size=args.page_size,
        timeout_seconds=args.timeout_seconds,
        sleep_seconds=args.sleep_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
