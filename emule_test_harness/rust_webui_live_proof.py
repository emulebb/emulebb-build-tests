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
                page.wait_for_timeout(int(steady_seconds * 1000))
                steady_snapshot = recorder.snapshot()
                steady_check = steady_request_load_check(steady_snapshot["apiCounts"])
                if not steady_check["ok"]:
                    raise RuntimeError(f"Rust WebUI default-tab polling is too broad: {steady_check!r}")
                report["checks"]["steadyRequestLoad"] = {**steady_snapshot, **steady_check}

                visited_tabs: list[dict[str, Any]] = []
                recorder.reset_api()
                for label in TAB_LABELS:
                    before = recorder.total_api_requests
                    page.get_by_role("button", name=label).click(timeout=int(timeout_seconds * 1000))
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
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "passed" else 1
