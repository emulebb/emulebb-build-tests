"""Packaged emulebb-rust WebUI live proof against a running persisted daemon."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

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


@dataclass(frozen=True)
class ConsumerNetworkWorkflow:
    """Operator-approved public-network actions exercised through the WebUI."""

    search_term: str
    transfer_name: str
    transfer_hash: str
    transfer_size: int
    network_timeout_seconds: float
    transfer_timeout_seconds: float
    complete_transfer: bool = False


def profile_settings_api_key(settings_path: Path) -> str:
    """Read the bootstrap API key without exposing it on the process command line."""

    import tomllib

    payload = tomllib.loads(settings_path.read_text(encoding="utf-8"))
    api_key = payload.get("rest", {}).get("apiKey")
    if not isinstance(api_key, str) or not api_key.strip():
        raise RuntimeError(f"REST API key is missing from {settings_path}")
    return api_key.strip()


def api_data(base_url: str, path: str, api_key: str) -> Any:
    """Fetch one authenticated REST resource and unwrap the API envelope."""

    request = Request(
        f"{base_url.rstrip('/')}/api/v1/{path.lstrip('/')}",
        headers={"X-API-Key": api_key},
    )
    with urlopen(request, timeout=5.0) as response:
        payload = json.loads(response.read())
    return payload.get("data", payload) if isinstance(payload, dict) else payload


def _wait_for_api(description: str, timeout_seconds: float, probe) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
        except Exception as exc:  # noqa: BLE001 - retain the final live observation
            last_error = exc
        time.sleep(min(1.0, max(0.1, deadline - time.monotonic())))
    suffix = f": {last_error}" if last_error is not None else ""
    raise RuntimeError(f"timed out waiting for {description}{suffix}")


def _consumer_network_actions(page, *, base_url: str, api_key: str, options: ConsumerNetworkWorkflow) -> dict[str, Any]:
    """Drive server, Kad, search, and allowlisted transfer actions in the rendered UI."""

    page.get_by_role("button", name="Servers", exact=True).click()
    servers_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Servers", exact=True)
    )
    def disconnected_server() -> dict[str, Any] | None:
        status = api_data(base_url, "status", api_key)
        stats = status.get("stats", {}) if isinstance(status, dict) else {}
        return status if not stats.get("ed2kConnected") else None

    if servers_panel.locator(".section-title").get_by_role(
        "button", name="Disconnect", exact=True
    ).is_enabled():
        servers_panel.locator(".section-title").get_by_role(
            "button", name="Disconnect", exact=True
        ).click()
        page.get_by_text("Server disconnected; Kad remains available", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )
        _wait_for_api(
            "rendered WebUI eD2K baseline disconnect",
            options.network_timeout_seconds,
            disconnected_server,
        )
    servers_panel.get_by_placeholder("server.met URL").locator("xpath=..").get_by_role(
        "button", name="Import", exact=True
    ).click()
    page.get_by_text("server.met imported; the server list is ready", exact=True).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )

    def imported_servers() -> dict[str, Any] | None:
        value = api_data(base_url, "servers", api_key)
        if not isinstance(value, dict):
            return None
        return value if len(value.get("items", [])) > 0 else None

    server_list = _wait_for_api(
        "rendered WebUI server.met import",
        options.network_timeout_seconds,
        imported_servers,
    )
    servers_panel.locator(".section-title").get_by_role(
        "button", name="Connect", exact=True
    ).click()

    def connected_server() -> dict[str, Any] | None:
        status = api_data(base_url, "status", api_key)
        stats = status.get("stats", {}) if isinstance(status, dict) else {}
        return status if stats.get("ed2kConnected") else None

    server_status = _wait_for_api(
        "rendered WebUI eD2K server connection",
        options.network_timeout_seconds,
        connected_server,
    )
    initial_server_stats = server_status.get("stats", {})

    page.get_by_role("button", name="Kad", exact=True).click()
    kad_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Kad", exact=True)
    )
    baseline_kad_stop = _wait_for_api(
        "rendered WebUI Kad baseline stop",
        min(15.0, options.network_timeout_seconds),
        lambda: (lambda value: value if isinstance(value, dict) and not value.get("running") else None)(
            api_data(base_url, "kad", api_key)
        ),
    )
    kad_panel.get_by_role("button", name="Import", exact=True).click()
    page.get_by_text("nodes.dat imported, validated, and saved", exact=True).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )
    kad_panel.get_by_role("button", name="Start", exact=True).click()

    def connected_kad() -> dict[str, Any] | None:
        kad = api_data(base_url, "kad", api_key)
        if not isinstance(kad, dict):
            return None
        return kad if kad.get("connected") and int(kad.get("contactCount") or 0) > 0 else None

    kad_status = _wait_for_api(
        "rendered WebUI Kad connection",
        options.network_timeout_seconds,
        connected_kad,
    )

    page.get_by_role("button", name="Servers", exact=True).click()
    servers_panel.locator(".section-title").get_by_role(
        "button", name="Disconnect", exact=True
    ).click()
    page.get_by_text("Server disconnected; Kad remains available", exact=True).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )
    _wait_for_api(
        "rendered WebUI eD2K disconnect",
        options.network_timeout_seconds,
        disconnected_server,
    )
    kad_after_server_disconnect = api_data(base_url, "kad", api_key)
    server_disconnect_preserved_kad = bool(
        isinstance(kad_after_server_disconnect, dict)
        and kad_after_server_disconnect.get("running")
        and kad_after_server_disconnect.get("connected")
    )
    servers_panel.locator(".section-title").get_by_role(
        "button", name="Connect", exact=True
    ).click()
    reconnected_server_status = _wait_for_api(
        "rendered WebUI eD2K reconnect",
        options.network_timeout_seconds,
        connected_server,
    )
    reconnected_server_stats = reconnected_server_status.get("stats", {})

    page.get_by_role("button", name="Kad", exact=True).click()
    kad_panel.get_by_role("button", name="Stop", exact=True).click()
    page.get_by_text("Kad stopped; the server connection remains available", exact=True).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )
    try:
        kad_stop = _wait_for_api(
            "rendered WebUI Kad stop",
            min(15.0, options.network_timeout_seconds),
            lambda: (lambda value: value if isinstance(value, dict) and not value.get("running") else None)(
                api_data(base_url, "kad", api_key)
            ),
        )
    except RuntimeError:
        kad_stop = None
    server_after_kad_stop = connected_server()
    kad_stop_preserved_server = server_after_kad_stop is not None
    kad_panel.get_by_role("button", name="Start", exact=True).click()
    reconnected_kad_status = _wait_for_api(
        "rendered WebUI Kad reconnect",
        options.network_timeout_seconds,
        connected_kad,
    )

    search_results: list[dict[str, Any]] = []
    transfer_triggered = False
    for method in ("automatic", "server", "kad"):
        page.get_by_role("button", name="Search", exact=True).click()
        search_panel = page.locator("section.panel").filter(
            has=page.get_by_role("heading", name="Search", exact=True)
        )
        before = api_data(base_url, "searches", api_key)
        before_ids = {
            int(row.get("id"))
            for row in (before.get("items", []) if isinstance(before, dict) else [])
            if isinstance(row, dict) and row.get("id") is not None
        }
        search_panel.get_by_placeholder("Search query").fill(options.search_term)
        search_panel.locator("select").nth(0).select_option(method)
        if search_panel.get_by_text("Advanced search filters", exact=True).count():
            details = search_panel.locator("details.search-filters")
            if not details.evaluate("element => element.open"):
                search_panel.get_by_text("Advanced search filters", exact=True).click()
        search_panel.get_by_placeholder("Extension").fill("pdf")
        search_panel.get_by_placeholder("Maximum bytes").fill(str(options.transfer_size))
        search_panel.get_by_role("button", name="Start", exact=True).click()
        page.get_by_text("Search started", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )

        def new_search() -> dict[str, Any] | None:
            collection = api_data(base_url, "searches", api_key)
            rows = collection.get("items", []) if isinstance(collection, dict) else []
            candidates = [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("id") is not None
                and int(row["id"]) not in before_ids
            ]
            return max(candidates, key=lambda row: int(row["id"])) if candidates else None

        created = _wait_for_api(
            f"rendered WebUI {method} search creation",
            options.network_timeout_seconds,
            new_search,
        )
        search_id = int(created["id"])

        def completed_search() -> dict[str, Any] | None:
            value = api_data(base_url, f"searches/{search_id}?limit=200", api_key)
            if not isinstance(value, dict) or value.get("status") != "complete":
                return None
            # A live backend can validly complete with no matches. The workflow
            # still requires the exact allowlisted PDF from at least one method
            # before it can trigger a download from the rendered result table.
            return value

        completed = _wait_for_api(
            f"rendered WebUI {method} search results",
            options.network_timeout_seconds,
            completed_search,
        )
        rows = completed.get("items", completed.get("results", []))
        if not isinstance(rows, list):
            rows = []
        exact_result = next(
            (
                row
                for row in rows
                if isinstance(row, dict)
                and str(row.get("hash") or "").lower() == options.transfer_hash.lower()
                and str(row.get("name") or "") == options.transfer_name
                and row.get("sizeBytes") == options.transfer_size
            ),
            None,
        )
        exact_allowlisted_result = exact_result is not None
        if exact_allowlisted_result and not transfer_triggered:
            # The REST poll above observes completion before the SPA's periodic
            # snapshot refresh necessarily does. Trigger the rendered refresh
            # control so the SPA selects and fetches the newest search session.
            page.get_by_title("Refresh", exact=True).click(
                timeout=int(options.network_timeout_seconds * 1000)
            )
            result_row = search_panel.locator("tbody tr").filter(has_text=options.transfer_name).first
            result_row.wait_for(timeout=int(options.network_timeout_seconds * 1000))
            result_row.get_by_role("button", name="Download", exact=True).click()
            page.get_by_text("Download queued", exact=True).wait_for(
                timeout=int(options.network_timeout_seconds * 1000)
            )
            transfer_triggered = True
        search_results.append(
            {
                "method": method,
                "status": completed.get("status"),
                "resultCount": int(completed.get("total") or 0),
                "pdfFilter": True,
                "maxBytesFilter": options.transfer_size,
                "exactAllowlistedResult": exact_allowlisted_result,
            }
        )

    if not transfer_triggered:
        raise RuntimeError("the exact allowlisted PDF was not found in rendered search results")
    page.get_by_role("button", name="Transfers", exact=True).click()
    transfer_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Transfers", exact=True)
    )

    def active_transfer() -> dict[str, Any] | None:
        value = api_data(
            base_url,
            f"transfers/{options.transfer_hash.lower()}",
            api_key,
        )
        if not isinstance(value, dict):
            return None
        completed_bytes = int(value.get("completedBytes") or 0)
        transferring = int(value.get("sourcesTransferring") or 0)
        return value if completed_bytes > 0 or transferring > 0 else None

    transfer_activity_observed = True
    try:
        transfer = _wait_for_api(
            "rendered WebUI allowlisted transfer network activity",
            options.transfer_timeout_seconds,
            active_transfer,
        )
    except RuntimeError:
        transfer_activity_observed = False
        transfer = api_data(
            base_url,
            f"transfers/{options.transfer_hash.lower()}",
            api_key,
        )
        if not isinstance(transfer, dict):
            transfer = {}
    stopped_after_observation = False
    transfer_stop_state = str(transfer.get("state") or "unknown")
    if options.complete_transfer:
        transfer = _wait_for_api(
            "rendered WebUI allowlisted transfer completion",
            options.transfer_timeout_seconds,
            lambda: (lambda value: value if int(value.get("completedBytes") or 0) == options.transfer_size else None)(
                api_data(base_url, f"transfers/{options.transfer_hash.lower()}", api_key)
            ),
        )
    else:
        transfer_row = transfer_panel.locator("tbody tr").filter(has_text=options.transfer_name).first
        transfer_row.get_by_role("button", name="Stop", exact=True).click()
        page.get_by_text("Transfer stopped", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )
        transfer = _wait_for_api(
            "rendered WebUI transfer quiescence after Stop",
            min(15.0, options.network_timeout_seconds),
            lambda: (lambda value: value if isinstance(value, dict) and value.get("stopped") is True else None)(
                api_data(base_url, f"transfers/{options.transfer_hash.lower()}", api_key)
            ),
        )
        transfer_stop_state = str(transfer.get("state") or "unknown")
        stopped_after_observation = transfer.get("stopped") is True
    kad_disconnect_verified = kad_stop is not None
    transfer_identity_verified = (
        str(transfer.get("hash") or "").lower() == options.transfer_hash.lower()
        and str(transfer.get("name") or "") == options.transfer_name
        and int(transfer.get("sizeBytes") or 0) == options.transfer_size
    )
    failures = []
    if baseline_kad_stop is None:
        failures.append("kad-baseline-stop")
    if not kad_disconnect_verified:
        failures.append("kad-disconnect")
    if not server_disconnect_preserved_kad:
        failures.append("server-disconnect-preserved-kad")
    if not kad_stop_preserved_server:
        failures.append("kad-stop-preserved-server")
    if options.complete_transfer and not transfer_activity_observed:
        failures.append("transfer-network-activity")
    if not transfer_identity_verified:
        failures.append("transfer-identity")
    if not options.complete_transfer and not stopped_after_observation:
        failures.append("transfer-stop-state")
    return {
        "ok": not failures,
        "failures": failures,
        "server": {
            "connected": True,
            "disconnectVerified": True,
            "reconnectVerified": True,
            "importSucceeded": True,
            "serverCount": len(server_list.get("items", [])),
            "initialHighId": bool(initial_server_stats.get("ed2kHighId")),
            "reconnectedHighId": bool(reconnected_server_stats.get("ed2kHighId")),
            "disconnectPreservedKad": server_disconnect_preserved_kad,
        },
        "kad": {
            "running": bool(reconnected_kad_status.get("running")),
            "connected": bool(reconnected_kad_status.get("connected")),
            "baselineStopVerified": baseline_kad_stop is not None,
            "disconnectVerified": kad_disconnect_verified,
            "reconnectVerified": kad_disconnect_verified
            and bool(reconnected_kad_status.get("connected")),
            "stopPreservedServer": kad_stop_preserved_server,
            "initialContactCount": int(kad_status.get("contactCount") or 0),
            "reconnectedContactCount": int(reconnected_kad_status.get("contactCount") or 0),
            "importSucceeded": True,
        },
        "searches": search_results,
        "transfer": {
            "triggered": True,
            "triggeredFromRenderedSearchResult": transfer_triggered,
            "identityVerified": transfer_identity_verified,
            "networkActivityRequired": options.complete_transfer,
            "networkActivityObserved": transfer_activity_observed,
            "sourceCount": int(transfer.get("sources") or 0),
            "sourcesTransferring": int(transfer.get("sourcesTransferring") or 0),
            "completed": int(transfer.get("completedBytes") or 0) == options.transfer_size,
            "completedBytes": int(transfer.get("completedBytes") or 0),
            "sizeBytes": int(transfer.get("sizeBytes") or options.transfer_size),
            "stopRequested": not options.complete_transfer,
            "finalState": transfer_stop_state,
            "stoppedAfterObservation": stopped_after_observation,
            "stoppedFlag": bool(transfer.get("stopped")),
        },
        "nat": _consumer_nat_status(base_url, api_key),
    }


def _consumer_nat_status(base_url: str, api_key: str) -> dict[str, Any]:
    value = api_data(base_url, "nat", api_key)
    if not isinstance(value, dict):
        return {"enabled": False, "gatewayDiscovered": False, "mappingCount": 0}
    mappings = value.get("mappings", [])
    return {
        "enabled": bool(value.get("enabled")),
        "gatewayDiscovered": bool(value.get("gatewayDiscovered")),
        "mappingCount": len(mappings) if isinstance(mappings, list) else 0,
        "backendPresent": bool(value.get("backend")),
        "lastErrorPresent": bool(value.get("lastError")),
    }


def _configure_best_effort_upnp(page, *, timeout_seconds: float) -> dict[str, Any]:
    """Enable best-effort NAT mapping through the rendered Settings form."""

    page.get_by_role("button", name="Settings", exact=True).click(
        timeout=int(timeout_seconds * 1000)
    )
    panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Settings", exact=True)
    )
    advanced = panel.get_by_label(re.compile("Advanced"))
    if not advanced.is_checked():
        advanced.check()
    nat_section = panel.locator('[data-settings-section="nat"]')
    nat_enabled = nat_section.get_by_role("checkbox", name=re.compile(r"^NAT(?:\s|$)"))
    if not nat_enabled.is_checked():
        nat_enabled.check()
    require_initial = nat_section.get_by_role(
        "checkbox",
        name=re.compile(r"^Require initial NAT mapping(?:\s|$)"),
    )
    if require_initial.is_checked():
        require_initial.uncheck()
    panel.get_by_role("button", name="Save", exact=True).click()
    page.get_by_text(
        "Settings saved; restart daemon for bind, port, NAT, VPN, and filter changes",
        exact=True,
    ).wait_for(timeout=int(timeout_seconds * 1000))
    return {
        "enabled": True,
        "requireInitialMapping": False,
        "restartRequired": True,
        "configuredThroughRenderedWebui": True,
    }


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


def sanitize_report_text(value: str, redactions: tuple[str, ...] = ()) -> str:
    """Remove live hashes and machine-local Windows paths from retained text."""

    value = HASH_TOKEN_RE.sub("{hash}", value)
    value = re.sub(r"[A-Za-z]:\\[^\s,;]+", "{path}", value)
    for secret in redactions:
        if secret:
            value = value.replace(secret, "{redacted}")
    return value


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
                "urlPath": sanitize_api_request_key(urlparse(request.url).path),
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
    navigation_only: bool = False,
    verify_stale_key_recovery: bool = False,
    consumer_workflow: ConsumerNetworkWorkflow | None = None,
    configure_best_effort_upnp: bool = False,
    shutdown_after_proof: bool = False,
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
        "navigationOnly": navigation_only,
        "verifyStaleKeyRecovery": verify_stale_key_recovery,
        "consumerWorkflow": consumer_workflow is not None,
        "configureBestEffortUpnp": configure_best_effort_upnp,
        "shutdownAfterProof": shutdown_after_proof,
        "tabsExpected": list(TAB_LABELS),
        "checks": {},
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    diagnostics: dict[str, list[dict[str, Any]]] = {
        "console_errors": [],
        "page_errors": [],
        "request_failures": [],
    }
    consumer_workflow_failed = False
    recorder = RequestRecorder(base_url)
    start = time.monotonic()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1366, "height": 900})
            install_browser_diagnostics(page, diagnostics)
            page.on("request", lambda request: recorder.record_url(request.url))
            try:
                initial_api_key = "stale-package-proof-key" if verify_stale_key_recovery else api_key
                page.add_init_script(
                    f"localStorage.setItem('emulebb.webui.apiKey', {json.dumps(initial_api_key)});"
                )
                page.goto(base_url, wait_until="domcontentloaded", timeout=int(timeout_seconds * 1000))
                if verify_stale_key_recovery:
                    page.get_by_role("heading", name="Connect to the local daemon").wait_for(
                        timeout=int(timeout_seconds * 1000)
                    )
                    if page.get_by_role("button", name="Overview", exact=True).count() != 0:
                        raise RuntimeError("Rust WebUI exposed protected navigation for a stale API key")
                    page.get_by_placeholder("X-API-Key").fill(api_key)
                    page.get_by_role("button", name="Connect", exact=True).click(
                        timeout=int(timeout_seconds * 1000)
                    )
                    page.get_by_text("API key verified", exact=True).wait_for(
                        timeout=int(timeout_seconds * 1000)
                    )
                    stored_api_key = page.evaluate(
                        "() => localStorage.getItem('emulebb.webui.apiKey')"
                    )
                    if stored_api_key != api_key:
                        raise RuntimeError("Rust WebUI did not persist the verified API key")
                    expected_auth_paths = {"/api/v1/app", "/api/v1/capabilities"}
                    auth_console_errors = list(diagnostics["console_errors"])
                    unexpected_auth_errors = [
                        error
                        for error in auth_console_errors
                        if "401 (Unauthorized)" not in str(error.get("text", ""))
                        or urlparse(str(error.get("location", {}).get("url", ""))).path
                        not in expected_auth_paths
                    ]
                    if (
                        not auth_console_errors
                        or unexpected_auth_errors
                        or diagnostics["page_errors"]
                        or diagnostics["request_failures"]
                    ):
                        raise RuntimeError(
                            "Rust WebUI stale-key gate produced unexpected browser diagnostics: "
                            f"{diagnostics!r}"
                        )
                    report["checks"]["staleApiKeyRecovery"] = {
                        "ok": True,
                        "protectedNavigationHidden": True,
                        "verifiedKeyPersisted": True,
                        "expectedUnauthorizedResponses": len(auth_console_errors),
                    }
                    for entries in diagnostics.values():
                        entries.clear()
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

                if configure_best_effort_upnp:
                    report["checks"]["upnpConfiguration"] = _configure_best_effort_upnp(
                        page,
                        timeout_seconds=timeout_seconds,
                    )

                if consumer_workflow is not None:
                    workflow_result = _consumer_network_actions(
                        page,
                        base_url=base_url,
                        api_key=api_key,
                        options=consumer_workflow,
                    )
                    report["checks"]["consumerNetworkWorkflow"] = workflow_result
                    consumer_workflow_failed = not bool(workflow_result.get("ok"))

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
                transfer_workflow["required"] = not navigation_only and consumer_workflow is None
                transfer_workflow["consumerTriggerCovered"] = consumer_workflow is not None
                if not transfer_workflow["ok"] and transfer_workflow["required"]:
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
                if shutdown_after_proof:
                    page.get_by_role("button", name="Diagnostics", exact=True).click(
                        timeout=int(timeout_seconds * 1000)
                    )
                    page.get_by_placeholder("Type SHUTDOWN").fill("SHUTDOWN")
                    with page.expect_response(
                        lambda response: urlparse(response.url).path == "/api/v1/app/shutdown",
                        timeout=int(timeout_seconds * 1000),
                    ) as shutdown_response:
                        page.get_by_role("button", name="Shutdown", exact=True).click(
                            timeout=int(timeout_seconds * 1000)
                        )
                    report["checks"]["shutdown"] = {
                        "requested": True,
                        "httpStatus": shutdown_response.value.status,
                        "ok": shutdown_response.value.ok,
                    }
                    if not shutdown_response.value.ok:
                        raise RuntimeError(
                            "Rust WebUI shutdown request failed with "
                            f"HTTP {shutdown_response.value.status}"
                        )
                if consumer_workflow_failed:
                    raise RuntimeError("consumer network workflow completed with failed checks")
                report["status"] = "passed"
                return report
            finally:
                browser.close()
    except Exception as exc:
        report["status"] = "failed"
        redactions = () if consumer_workflow is None else (
            consumer_workflow.search_term,
            consumer_workflow.transfer_name,
            consumer_workflow.transfer_hash,
        )
        report["error"] = {
            "type": type(exc).__name__,
            "message": sanitize_report_text(str(exc) or repr(exc), redactions),
        }
        report["checks"]["browserDiagnostics"] = diagnostics
        return report
    finally:
        report["durationSeconds"] = round(time.monotonic() - start, 3)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """Builds the Rust WebUI live proof CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=default_base_url())
    key_source = parser.add_mutually_exclusive_group()
    key_source.add_argument("--api-key", default=DEFAULT_API_KEY)
    key_source.add_argument(
        "--profile-settings",
        type=Path,
        help="Read the API key from an emulebb-rust-settings.toml file.",
    )
    parser.add_argument("--report-path", type=Path, default=default_report_path())
    parser.add_argument("--steady-seconds", type=float, default=DEFAULT_STEADY_SECONDS)
    parser.add_argument("--tab-wait-seconds", type=float, default=DEFAULT_TAB_WAIT_SECONDS)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--max-main-thread-busy-ratio", type=float, default=DEFAULT_MAX_MAIN_THREAD_BUSY_RATIO)
    parser.add_argument("--navigation-only", action="store_true",
                        help="Visit every panel and check browser health without requiring active transfer progress.")
    parser.add_argument(
        "--verify-stale-key-recovery",
        action="store_true",
        help="Start with an invalid stored key and prove the authentication gate recovers without a reload.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    """Runs the Rust WebUI live proof command."""

    args = build_parser().parse_args(argv)
    api_key = (
        profile_settings_api_key(args.profile_settings)
        if args.profile_settings is not None
        else str(args.api_key or DEFAULT_API_KEY)
    )
    report = run_webui_live_proof(
        base_url=str(args.base_url).rstrip("/"),
        api_key=api_key,
        report_path=args.report_path,
        steady_seconds=float(args.steady_seconds),
        tab_wait_seconds=float(args.tab_wait_seconds),
        timeout_seconds=float(args.timeout_seconds),
        max_main_thread_busy_ratio=float(args.max_main_thread_busy_ratio),
        navigation_only=bool(args.navigation_only),
        verify_stale_key_recovery=bool(args.verify_stale_key_recovery),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "passed" else 1
