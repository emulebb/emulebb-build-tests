"""Packaged emulebb-rust WebUI live proof against a running persisted daemon."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .paths import get_workspace_output_root

DEFAULT_API_KEY = "converged-soak"
DEFAULT_STEADY_SECONDS = 18.0
DEFAULT_TAB_WAIT_SECONDS = 1.5
DEFAULT_MAX_MAIN_THREAD_BUSY_RATIO = 0.25
TAB_LABELS = (
    "Overview",
    "Transfers",
    "Search",
    "Sharing",
    "Shared Files",
    "Uploads",
    "Network",
    "Servers",
    "Kad",
    "Categories",
    "Friends",
    "Settings",
    "Diagnostics",
    "Logs",
)
ALLOWED_REPEATED_STEADY_PREFIXES = ("snapshot?",)
HASH_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
FULL_PROGRESS_RE = re.compile(r"^100(?:\.0+)?%$")
PERCENT_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)%$")
PERFORMANCE_DURATION_METRICS = (
    "TaskDuration",
    "ScriptDuration",
    "LayoutDuration",
    "RecalcStyleDuration",
)
PERFORMANCE_ABSOLUTE_METRICS = (
    "JSHeapUsedSize",
    "Nodes",
    "JSEventListeners",
)


class RequestRecorder:
    """Collects sanitized same-origin API request counts from a browser page."""

    def __init__(self, base_url: str) -> None:
        parsed = urlparse(base_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.api_counts: Counter[str] = Counter()
        self.static_assets: Counter[str] = Counter()
        self.total_api_requests = 0

    def record_url(self, url: str) -> None:
        parsed = urlparse(url)
        if f"{parsed.scheme}://{parsed.netloc}" != self.origin:
            return
        if parsed.path.startswith("/api/v1/"):
            key = parsed.path.removeprefix("/api/v1/")
            if parsed.query:
                key = f"{key}?{parsed.query}"
            key = sanitize_api_request_key(key)
            self.api_counts[key] += 1
            self.total_api_requests += 1
        elif parsed.path == "/" or parsed.path.startswith("/assets/"):
            self.static_assets[parsed.path] += 1

    def reset_api(self) -> None:
        self.api_counts.clear()
        self.total_api_requests = 0

    def snapshot(self) -> dict[str, Any]:
        return {
            "apiRequests": self.total_api_requests,
            "apiCounts": dict(sorted(self.api_counts.items())),
            "topApiRequests": sorted(self.api_counts.items(), key=lambda item: (-item[1], item[0]))[:20],
            "staticAssets": dict(sorted(self.static_assets.items())),
        }


def sanitize_api_request_key(key: str) -> str:
    """Removes live transfer/file hash material from an API request key."""

    return HASH_TOKEN_RE.sub("{hash}", key)


def default_base_url() -> str:
    """Returns the default persisted Rust WebUI URL for the operator LAN address."""

    host = os.environ.get("X_LOCAL_IP", "").strip() or "127.0.0.1"
    return f"http://{host}:4731"


def default_report_path() -> Path:
    """Returns the canonical latest Rust WebUI live proof report path."""

    return get_workspace_output_root() / "reports" / "rust-webui-live-proof" / "rust-webui-live-proof.latest.json"


def steady_request_load_check(api_counts: dict[str, int]) -> dict[str, Any]:
    """Returns whether default-tab polling is limited to the expected hot endpoints."""

    repeated_secondary = {
        path: count
        for path, count in sorted(api_counts.items())
        if count > 1 and not any(path.startswith(prefix) for prefix in ALLOWED_REPEATED_STEADY_PREFIXES)
    }
    return {
        "ok": not repeated_secondary,
        "repeatedSecondaryEndpoints": repeated_secondary,
    }


def transfer_workflow_check_from_cells(rows: list[dict[str, str]], empty_visible: bool) -> dict[str, Any]:
    """Checks the transfer table exposes public download progress without retaining file identity."""

    completed = [row for row in rows if row.get("state", "").strip().lower() == "completed"]
    completed_full = [
        row
        for row in completed
        if FULL_PROGRESS_RE.match(row.get("progress", "").strip())
    ]
    active_progress = [
        row
        for row in rows
        if row.get("state", "").strip().lower() == "downloading"
        and 0.0 < parse_progress_percent(row.get("progress", "")) < 100.0
    ]
    return {
        "ok": bool(rows) and (bool(completed_full) or bool(active_progress)),
        "rowCount": len(rows),
        "activeProgressRowCount": len(active_progress),
        "completedRowCount": len(completed),
        "completedFullProgressRowCount": len(completed_full),
        "emptyVisible": empty_visible,
    }


def parse_progress_percent(value: str) -> float:
    """Parses a rendered transfer progress percentage, returning -1 on mismatch."""

    match = PERCENT_RE.match(value.strip())
    if not match:
        return -1.0
    return float(match.group("value"))


def performance_metric_map(payload: dict[str, Any]) -> dict[str, float]:
    """Converts a Chrome Performance.getMetrics payload to a name/value map."""

    metrics = payload.get("metrics")
    if not isinstance(metrics, list):
        return {}
    result: dict[str, float] = {}
    for row in metrics:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        value = row.get("value")
        if isinstance(name, str) and isinstance(value, (int, float)):
            result[name] = float(value)
    return result


def browser_performance_check(
    before: dict[str, float],
    after: dict[str, float],
    *,
    elapsed_seconds: float,
    max_main_thread_busy_ratio: float,
) -> dict[str, Any]:
    """Checks idle WebUI main-thread work stays below the beta CPU budget."""

    missing = [name for name in ("TaskDuration",) if name not in before or name not in after]
    duration_deltas = {
        name: round(max(0.0, after.get(name, 0.0) - before.get(name, 0.0)), 6)
        for name in PERFORMANCE_DURATION_METRICS
        if name in before and name in after
    }
    absolute_after = {
        name: int(after[name])
        for name in PERFORMANCE_ABSOLUTE_METRICS
        if name in after
    }
    task_duration = duration_deltas.get("TaskDuration")
    busy_ratio = None if task_duration is None or elapsed_seconds <= 0 else task_duration / elapsed_seconds
    return {
        "ok": not missing and busy_ratio is not None and busy_ratio <= max_main_thread_busy_ratio,
        "missing": missing,
        "elapsedSeconds": round(elapsed_seconds, 3),
        "maxMainThreadBusyRatio": max_main_thread_busy_ratio,
        "mainThreadBusyRatio": None if busy_ratio is None else round(busy_ratio, 4),
        "durationDeltas": duration_deltas,
        "absoluteAfter": absolute_after,
    }


def install_browser_diagnostics(page, diagnostics: dict[str, list[dict[str, Any]]]) -> None:
    """Installs compact browser diagnostics collectors on a Playwright page."""

    page.on(
        "console",
        lambda message: diagnostics["console_errors"].append(
            {"type": message.type, "text": message.text, "location": message.location}
        )
        if message.type == "error"
        else None,
    )
    page.on("pageerror", lambda error: diagnostics["page_errors"].append({"text": str(error)}))
    page.on(
        "requestfailed",
        lambda request: diagnostics["request_failures"].append(
            {
                "failure": str(request.failure),
                "method": request.method,
                "resourceType": request.resource_type,
                "urlPath": urlparse(request.url).path,
            }
        ),
    )


def assert_no_browser_diagnostics(diagnostics: dict[str, list[dict[str, Any]]]) -> None:
    """Fails when the browser recorded console, page, or request failures."""

    failures = {key: value for key, value in diagnostics.items() if value}
    if failures:
        raise RuntimeError(f"Rust WebUI browser diagnostics were not clean: {failures!r}")


def run_webui_live_proof(
    *,
    base_url: str,
    api_key: str,
    report_path: Path,
    steady_seconds: float,
    tab_wait_seconds: float,
    timeout_seconds: float,
    max_main_thread_busy_ratio: float,
) -> dict[str, Any]:
    """Exercises the packaged WebUI and writes a sanitized proof report."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the Rust WebUI live proof.") from exc

    report: dict[str, Any] = {
        "schema": "emulebb-rust.webui-live-proof.v1",
        "status": "running",
        "startedUtc": datetime.now(UTC).isoformat(),
        "baseUrl": base_url,
        "steadySeconds": steady_seconds,
        "tabWaitSeconds": tab_wait_seconds,
        "maxMainThreadBusyRatio": max_main_thread_busy_ratio,
        "tabsExpected": list(TAB_LABELS),
        "checks": {},
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    diagnostics: dict[str, list[dict[str, Any]]] = {
        "console_errors": [],
        "page_errors": [],
        "request_failures": [],
    }
    recorder = RequestRecorder(base_url)
    start = time.monotonic()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1366, "height": 900})
            install_browser_diagnostics(page, diagnostics)
            page.on("request", lambda request: recorder.record_url(request.url))
            try:
                page.add_init_script(
                    f"localStorage.setItem('emulebb.webui.apiKey', {json.dumps(api_key)});"
                )
                page.goto(base_url, wait_until="domcontentloaded", timeout=int(timeout_seconds * 1000))
                page.get_by_role("navigation", name="Primary views").wait_for(timeout=int(timeout_seconds * 1000))
                page.wait_for_timeout(1000)

                recorder.reset_api()
                cdp = page.context.new_cdp_session(page)
                cdp.send("Performance.enable")
                performance_before = performance_metric_map(cdp.send("Performance.getMetrics"))
                performance_start = time.monotonic()
                page.wait_for_timeout(int(steady_seconds * 1000))
                performance_elapsed = time.monotonic() - performance_start
                performance_after = performance_metric_map(cdp.send("Performance.getMetrics"))
                cdp.detach()
                performance_check = browser_performance_check(
                    performance_before,
                    performance_after,
                    elapsed_seconds=performance_elapsed,
                    max_main_thread_busy_ratio=max_main_thread_busy_ratio,
                )
                if not performance_check["ok"]:
                    raise RuntimeError(f"Rust WebUI steady main-thread work is too high: {performance_check!r}")
                report["checks"]["steadyBrowserPerformance"] = performance_check

                steady_snapshot = recorder.snapshot()
                steady_check = steady_request_load_check(steady_snapshot["apiCounts"])
                if not steady_check["ok"]:
                    raise RuntimeError(f"Rust WebUI default-tab polling is too broad: {steady_check!r}")
                report["checks"]["steadyRequestLoad"] = {**steady_snapshot, **steady_check}

                visited_tabs: list[dict[str, Any]] = []
                recorder.reset_api()
                for label in TAB_LABELS:
                    before = recorder.total_api_requests
                    page.get_by_role("button", name=label, exact=True).click(timeout=int(timeout_seconds * 1000))
                    page.wait_for_timeout(int(tab_wait_seconds * 1000))
                    visited_tabs.append(
                        {
                            "label": label,
                            "apiRequestsDuringVisit": recorder.total_api_requests - before,
                        }
                    )
                report["checks"]["tabs"] = {
                    "visited": visited_tabs,
                    "api": recorder.snapshot(),
                    "ok": [row["label"] for row in visited_tabs] == list(TAB_LABELS),
                }

                page.get_by_role("button", name="Transfers", exact=True).click(timeout=int(timeout_seconds * 1000))
                page.wait_for_timeout(int(tab_wait_seconds * 1000))
                transfer_dom = page.evaluate(
                    """() => {
                        const panels = Array.from(document.querySelectorAll('section.panel'));
                        const panel = panels.find((candidate) =>
                            candidate.querySelector('h2')?.textContent?.trim() === 'Transfers'
                        );
                        if (!panel) {
                            return { rows: [], emptyVisible: false };
                        }
                        const rows = Array.from(panel.querySelectorAll('tbody tr'))
                            .map((row) => {
                                const cells = Array.from(row.querySelectorAll('td'));
                                return {
                                    state: cells[1]?.textContent?.trim() || '',
                                    progress: cells[2]?.textContent?.trim() || ''
                                };
                            })
                            .filter((row) => row.state || row.progress);
                        return {
                            rows,
                            emptyVisible: panel.textContent?.includes('No transfers.') || false
                        };
                    }"""
                )
                transfer_workflow = transfer_workflow_check_from_cells(
                    transfer_dom.get("rows", []),
                    bool(transfer_dom.get("emptyVisible")),
                )
                if not transfer_workflow["ok"]:
                    raise RuntimeError(
                        "Rust WebUI transfer workflow did not show completed delivery or active download "
                        f"progress: {transfer_workflow!r}"
                    )
                report["checks"]["transferWorkflow"] = transfer_workflow

                metrics = page.evaluate(
                    """() => ({
                        title: document.title,
                        visibility: document.visibilityState,
                        nodeCount: document.getElementsByTagName('*').length,
                        heapBytes: performance.memory ? performance.memory.usedJSHeapSize : null,
                        activeTab: document.querySelector('button.tab.active')?.textContent?.trim() || null
                    })"""
                )
                report["checks"]["pageMetrics"] = metrics
                assert_no_browser_diagnostics(diagnostics)
                report["checks"]["browserDiagnostics"] = diagnostics
                report["status"] = "passed"
                return report
            finally:
                browser.close()
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        report["checks"]["browserDiagnostics"] = diagnostics
        return report
    finally:
        report["durationSeconds"] = round(time.monotonic() - start, 3)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """Builds the Rust WebUI live proof CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=default_base_url())
    parser.add_argument("--api-key", default=DEFAULT_API_KEY)
    parser.add_argument("--report-path", type=Path, default=default_report_path())
    parser.add_argument("--steady-seconds", type=float, default=DEFAULT_STEADY_SECONDS)
    parser.add_argument("--tab-wait-seconds", type=float, default=DEFAULT_TAB_WAIT_SECONDS)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--max-main-thread-busy-ratio", type=float, default=DEFAULT_MAX_MAIN_THREAD_BUSY_RATIO)
    return parser


def run(argv: list[str] | None = None) -> int:
    """Runs the Rust WebUI live proof command."""

    args = build_parser().parse_args(argv)
    report = run_webui_live_proof(
        base_url=str(args.base_url).rstrip("/"),
        api_key=str(args.api_key),
        report_path=args.report_path,
        steady_seconds=float(args.steady_seconds),
        tab_wait_seconds=float(args.tab_wait_seconds),
        timeout_seconds=float(args.timeout_seconds),
        max_main_thread_busy_ratio=float(args.max_main_thread_busy_ratio),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "passed" else 1
