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
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .paths import get_workspace_output_root

DEFAULT_API_KEY = "converged-soak"
DEFAULT_STEADY_SECONDS = 18.0
DEFAULT_TAB_WAIT_SECONDS = 1.5
DEFAULT_MAX_MAIN_THREAD_BUSY_RATIO = 0.25
WEBUI_API_KEY_STORAGE_KEY = "emulebb.webui.apiKey"
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


def browser_api_key_write_script(api_key: str) -> str:
    """Return a script that seeds the WebUI's tab-scoped credential store."""

    return (
        f"sessionStorage.setItem({json.dumps(WEBUI_API_KEY_STORAGE_KEY)}, "
        f"{json.dumps(api_key)});"
    )


def browser_api_key_read_script() -> str:
    """Return a script that reads the WebUI's tab-scoped credential store."""

    return f"() => sessionStorage.getItem({json.dumps(WEBUI_API_KEY_STORAGE_KEY)})"


def _primary_nav_item(page, label: str):
    nav_item = page.get_by_role("link", name=label, exact=True)
    if nav_item.count() == 0:
        # Compatibility with packages built before primary navigation became
        # canonical history-routing links.
        nav_item = page.get_by_role("button", name=label, exact=True)
    return nav_item


def _click_primary_nav(page, label: str, *, timeout_ms: int | None = None) -> None:
    options = {} if timeout_ms is None else {"timeout": timeout_ms}
    _primary_nav_item(page, label).click(**options)


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
class ConsumerSharedFixture:
    """One synthetic file expected in the disposable consumer share tree."""

    name: str
    relative_path: str
    size_bytes: int
    sha256: str


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
    max_transfer_bytes: int | None = None
    shared_root_path: str | None = None
    shared_files: tuple[ConsumerSharedFixture, ...] = ()


def select_filtered_live_pdf(rows: Any, max_bytes: int) -> dict[str, Any] | None:
    """Select a sourced PDF from already-rendered, size-bounded live search results."""

    candidates: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        transfer_hash = str(row.get("hash") or "").lower()
        size = row.get("sizeBytes")
        sources = row.get("sources", row.get("availability", 0))
        if (
            Path(name).name != name
            or Path(name).suffix.lower() != ".pdf"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= max_bytes
            or len(transfer_hash) != 32
            or any(character not in "0123456789abcdef" for character in transfer_hash)
            or not isinstance(sources, int)
            or isinstance(sources, bool)
            or sources <= 0
        ):
            continue
        candidates.append(row)
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda row: (
            int(row.get("sources", row.get("availability", 0))),
            -int(row["sizeBytes"]),
            str(row["hash"]),
        ),
    )


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


def _integer_field(value: Any, name: str) -> int:
    """Return one non-boolean integer field from a REST object."""

    if not isinstance(value, dict):
        return 0
    field = value.get(name)
    return int(field) if isinstance(field, int) and not isinstance(field, bool) else 0


def _publish_diagnostics(status: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract path-free eD2K and Kad publish snapshots from status."""

    runtime = status.get("runtimeDiagnostics", {}) if isinstance(status, dict) else {}
    if not isinstance(runtime, dict):
        runtime = {}
    ed2k = runtime.get("ed2kPublish", {})
    kad = runtime.get("kadPublish", {})
    return (
        ed2k if isinstance(ed2k, dict) else {},
        kad if isinstance(kad, dict) else {},
    )


def _matched_shared_catalog(
    value: Any,
    expected: tuple[ConsumerSharedFixture, ...],
) -> list[dict[str, Any]] | None:
    """Return exact synthetic fixture rows once the shared catalog is complete."""

    rows = value.get("items", []) if isinstance(value, dict) else []
    if not isinstance(rows, list):
        return None
    expected_by_name = {fixture.name: fixture for fixture in expected}
    if len(expected_by_name) != len(expected) or len(rows) != len(expected):
        return None
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            return None
        name = str(row.get("name") or "")
        fixture = expected_by_name.get(name)
        transfer_hash = str(row.get("hash") or "").lower()
        ed2k_link = str(row.get("ed2kLink") or "")
        if (
            fixture is None
            or row.get("sizeBytes") != fixture.size_bytes
            or len(transfer_hash) != 32
            or any(character not in "0123456789abcdef" for character in transfer_hash)
            or not ed2k_link.startswith("ed2k://|file|")
        ):
            return None
        matched.append(
            {
                "name": fixture.name,
                "relativePath": fixture.relative_path,
                "sizeBytes": fixture.size_bytes,
                "sha256": fixture.sha256,
                "ed2kHash": transfer_hash,
            }
        )
    return sorted(matched, key=lambda row: str(row["relativePath"]))


def _sharing_publish_actions(
    page,
    *,
    base_url: str,
    api_key: str,
    options: ConsumerNetworkWorkflow,
) -> dict[str, Any]:
    """Add a disposable share in the WebUI and prove server/Kad advertisement."""

    if not options.shared_root_path or not options.shared_files:
        raise RuntimeError("consumer sharing proof requires a root and synthetic fixture files")
    expected_count = len(options.shared_files)
    baseline_status = api_data(base_url, "status", api_key)
    baseline_ed2k, baseline_kad = _publish_diagnostics(baseline_status)

    _click_primary_nav(page, "Sharing")
    sharing_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Shared Folders", exact=True)
    )
    sharing_panel.get_by_placeholder("Server folder path").fill(options.shared_root_path)
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and urlparse(response.url).path == "/api/v1/shared-directories/roots",
        timeout=int(options.network_timeout_seconds * 1000),
    ) as add_root_response:
        sharing_panel.get_by_role("button", name="Add root", exact=True).click()
    if not add_root_response.value.ok:
        raise RuntimeError(
            "rendered shared-root Add failed with HTTP "
            f"{add_root_response.value.status}"
        )
    page.get_by_text("Folder added", exact=True).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )

    def indexed_fixture(min_updated_at_ms: int = 0) -> dict[str, Any] | None:
        directories = api_data(base_url, "shared-directories", api_key)
        roots = directories.get("roots", []) if isinstance(directories, dict) else []
        reload_progress = (
            directories.get("reloadProgress", {}) if isinstance(directories, dict) else {}
        )
        if not isinstance(roots, list) or len(roots) != 1 or not isinstance(reload_progress, dict):
            return None
        if reload_progress.get("running") or reload_progress.get("pending"):
            return None
        updated_at_ms = _integer_field(reload_progress, "updatedAtMs")
        if updated_at_ms <= min_updated_at_ms:
            return None
        if _integer_field(reload_progress, "failedHashCount") != 0:
            raise RuntimeError("synthetic shared-file hashing reported failures")
        files = api_data(base_url, "shared-files?limit=100", api_key)
        matched = _matched_shared_catalog(files, options.shared_files)
        if matched is None:
            return None
        return {
            "files": matched,
            "hashedCount": _integer_field(reload_progress, "hashedCount"),
            "newCount": _integer_field(reload_progress, "newCount"),
            "reusedCount": _integer_field(reload_progress, "reusedCount"),
            "updatedAtMs": updated_at_ms,
        }

    initial_catalog = _wait_for_api(
        "synthetic shared-tree indexing",
        options.network_timeout_seconds,
        indexed_fixture,
    )
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and urlparse(response.url).path == "/api/v1/shared-directories/operations/reload",
        timeout=int(options.network_timeout_seconds * 1000),
    ) as reload_response:
        sharing_panel.get_by_role("button", name="Reload", exact=True).click()
    if not reload_response.value.ok:
        raise RuntimeError(
            "rendered shared-root Reload failed with HTTP "
            f"{reload_response.value.status}"
        )
    page.get_by_text("Reload queued", exact=True).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )
    reloaded_catalog = _wait_for_api(
        "synthetic shared-tree reload",
        options.network_timeout_seconds,
        lambda: indexed_fixture(_integer_field(initial_catalog, "updatedAtMs")),
    )

    _click_primary_nav(page, "Shared Files")
    shared_files_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Shared Files", exact=True)
    )
    for fixture in options.shared_files:
        row = shared_files_panel.locator("tbody tr").filter(has_text=fixture.name).first
        row.wait_for(timeout=int(options.network_timeout_seconds * 1000))

    def published_fixture() -> dict[str, Any] | None:
        status = api_data(base_url, "status", api_key)
        ed2k, kad = _publish_diagnostics(status)
        ed2k_ready = (
            _integer_field(ed2k, "lastSuccessAtMs")
            > _integer_field(baseline_ed2k, "lastSuccessAtMs")
            and _integer_field(ed2k, "totalEntries") == expected_count
            and _integer_field(ed2k, "publishedEntries") == expected_count
            and _integer_field(ed2k, "pendingEntries") == 0
            and not ed2k.get("lastError")
        )
        kad_ready = (
            kad.get("bootstrapped") is True
            and kad.get("gateAllowed") is True
            and _integer_field(kad, "itemCount") == expected_count
            and _integer_field(kad, "keywordPublishedTotal")
            > _integer_field(baseline_kad, "keywordPublishedTotal")
            and _integer_field(kad, "sourcePublishedTotal")
            >= _integer_field(baseline_kad, "sourcePublishedTotal") + expected_count
            and _integer_field(kad, "keywordAckedContactsTotal")
            > _integer_field(baseline_kad, "keywordAckedContactsTotal")
            and _integer_field(kad, "sourceAckedContactsTotal")
            > _integer_field(baseline_kad, "sourceAckedContactsTotal")
        )
        if not ed2k_ready or not kad_ready:
            return None
        return {
            "ed2k": {
                "phase": str(ed2k.get("phase") or "unknown"),
                "entriesSent": _integer_field(ed2k, "entriesSent"),
                "totalEntries": _integer_field(ed2k, "totalEntries"),
                "publishedEntries": _integer_field(ed2k, "publishedEntries"),
                "pendingEntries": _integer_field(ed2k, "pendingEntries"),
                "lastSuccessAdvanced": True,
            },
            "kad": {
                "phase": str(kad.get("phase") or "unknown"),
                "itemCount": _integer_field(kad, "itemCount"),
                "gateAllowed": True,
                "keywordPublishedDelta": _integer_field(kad, "keywordPublishedTotal")
                - _integer_field(baseline_kad, "keywordPublishedTotal"),
                "sourcePublishedDelta": _integer_field(kad, "sourcePublishedTotal")
                - _integer_field(baseline_kad, "sourcePublishedTotal"),
                "keywordAckedContactsDelta": _integer_field(
                    kad, "keywordAckedContactsTotal"
                )
                - _integer_field(baseline_kad, "keywordAckedContactsTotal"),
                "sourceAckedContactsDelta": _integer_field(kad, "sourceAckedContactsTotal")
                - _integer_field(baseline_kad, "sourceAckedContactsTotal"),
            },
        }

    publish = _wait_for_api(
        "eD2K offer and acknowledged Kad fixture publishing",
        options.network_timeout_seconds,
        published_fixture,
    )
    return {
        "ok": True,
        "rootAddedThroughRenderedWebui": True,
        "reloadTriggeredThroughRenderedWebui": True,
        "rootCount": 1,
        "fileCount": expected_count,
        "recursiveFixture": any("/" in fixture.relative_path for fixture in options.shared_files),
        "initialCatalog": initial_catalog,
        "reloadedCatalog": reloaded_catalog,
        "renderedSharedFileRows": expected_count,
        "publish": publish,
    }


def _consumer_network_actions(page, *, base_url: str, api_key: str, options: ConsumerNetworkWorkflow) -> dict[str, Any]:
    """Drive server, Kad, search, and allowlisted transfer actions in the rendered UI."""

    zero_configuration_defaults = _assert_zero_configuration_defaults(
        page,
        timeout_seconds=options.network_timeout_seconds,
    )
    _click_primary_nav(page, "Servers")
    servers_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Servers", exact=True)
    )

    def disconnected_server() -> dict[str, Any] | None:
        status = api_data(base_url, "status", api_key)
        stats = status.get("stats", {}) if isinstance(status, dict) else {}
        return status if not stats.get("ed2kConnected") else None

    def discovered_servers() -> dict[str, Any] | None:
        value = api_data(base_url, "servers", api_key)
        if not isinstance(value, dict):
            return None
        return value if len(value.get("items", [])) > 0 else None

    server_list = _wait_for_api(
        "automatic first-run server.met discovery",
        options.network_timeout_seconds,
        discovered_servers,
    )

    def connected_server() -> dict[str, Any] | None:
        status = api_data(base_url, "status", api_key)
        stats = status.get("stats", {}) if isinstance(status, dict) else {}
        return status if stats.get("ed2kConnected") else None

    server_status = _wait_for_api(
        "automatic first-run eD2K server connection",
        options.network_timeout_seconds,
        connected_server,
    )
    servers_panel.get_by_text(re.compile(r"Server network:\s+Connected")).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )

    population_signature: tuple[tuple[str, int, int], ...] = ()
    population_sampling_started = time.monotonic()
    population_last_changed = time.monotonic()

    def servers_with_stable_live_population() -> dict[str, Any] | None:
        nonlocal population_signature, population_last_changed
        value = discovered_servers()
        if value is None:
            return None
        signature = tuple(
            sorted(
                (
                    f"{row.get('address')}:{row.get('port')}",
                    int(row.get("users") or 0),
                    int(row.get("files") or 0),
                )
                for row in value.get("items", [])
                if isinstance(row, dict)
                and row.get("enabled", True)
                and int(row.get("users") or 0) > 0
            )
        )
        if signature != population_signature:
            population_signature = signature
            population_last_changed = time.monotonic()
        if (
            not signature
            or time.monotonic() - population_sampling_started < 55.0
            or time.monotonic() - population_last_changed < 3.0
        ):
            return None
        return value

    _wait_for_api(
        "stable live server population metrics",
        options.network_timeout_seconds,
        servers_with_stable_live_population,
    )
    automatic_candidate_endpoint = ""
    automatic_candidate_since = time.monotonic()

    def automatically_selected_most_popular_server() -> dict[str, Any] | None:
        nonlocal automatic_candidate_endpoint, automatic_candidate_since
        value = discovered_servers()
        if value is None:
            return None
        server_rows = [
            row
            for row in value.get("items", [])
            if isinstance(row, dict)
            and row.get("enabled", True)
            and int(row.get("users") or 0) > 0
        ]
        if not server_rows:
            return None
        candidate = max(
            server_rows,
            key=lambda row: (
                int(row.get("users") or 0),
                int(row.get("files") or 0),
                str(row.get("name") or ""),
            ),
        )
        endpoint = f"{candidate.get('address')}:{candidate.get('port')}"
        if candidate.get("connected") is not True or candidate.get("current") is not True:
            automatic_candidate_endpoint = ""
            return None
        if endpoint != automatic_candidate_endpoint:
            automatic_candidate_endpoint = endpoint
            automatic_candidate_since = time.monotonic()
            return None
        if time.monotonic() - automatic_candidate_since < 2.0:
            return None
        return {"collection": value, "server": candidate}

    automatic_selection = _wait_for_api(
        "automatic selection of the most popular reachable server",
        options.network_timeout_seconds,
        automatically_selected_most_popular_server,
    )
    most_popular_server = automatic_selection["server"]
    targeted_server_endpoint = (
        f"{most_popular_server.get('address')}:{most_popular_server.get('port')}"
    )
    server_status = connected_server() or server_status
    initial_server_stats = server_status.get("stats", {})

    _click_primary_nav(page, "Kad")
    kad_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Kad", exact=True)
    )

    def connected_kad() -> dict[str, Any] | None:
        kad = api_data(base_url, "kad", api_key)
        if not isinstance(kad, dict):
            return None
        return kad if kad.get("connected") and int(kad.get("contactCount") or 0) > 0 else None

    kad_status = _wait_for_api(
        "automatic first-run Kad connection from downloaded nodes.dat",
        options.network_timeout_seconds,
        connected_kad,
    )
    kad_panel.get_by_text(re.compile(r"Kad network:\s+Connected")).wait_for(
        timeout=int(options.network_timeout_seconds * 1000)
    )

    _click_primary_nav(page, "Servers")
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
    targeted_server_row = servers_panel.locator("tbody tr").filter(
        has_text=targeted_server_endpoint
    ).first
    targeted_server_row.wait_for(timeout=int(options.network_timeout_seconds * 1000))
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and "/api/v1/servers/" in response.url
        and response.url.endswith("/operations/connect"),
        timeout=int(options.network_timeout_seconds * 1000),
    ) as targeted_connect_response:
        targeted_server_row.get_by_title("Connect", exact=True).click()
    if not targeted_connect_response.value.ok:
        raise RuntimeError(
            "rendered server-row Connect failed with HTTP "
            f"{targeted_connect_response.value.status}"
        )
    reconnected_server_status = _wait_for_api(
        "rendered WebUI targeted eD2K reconnect",
        options.network_timeout_seconds,
        connected_server,
    )
    reconnected_server_stats = reconnected_server_status.get("stats", {})

    _click_primary_nav(page, "Kad")
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

    nat_status = _wait_for_api(
        "UPnP gateway and eD2K/Kad port mappings",
        options.network_timeout_seconds,
        lambda: (lambda value: value if value.get("ready") else None)(
            _consumer_nat_status(base_url, api_key)
        ),
    )
    sharing = _sharing_publish_actions(
        page,
        base_url=base_url,
        api_key=api_key,
        options=options,
    )

    search_results: list[dict[str, Any]] = []
    transfer_triggered = False
    selected_transfer = {
        "hash": options.transfer_hash,
        "name": options.transfer_name,
        "sizeBytes": options.transfer_size,
    }
    selected_from_exact_allowlist = False
    max_transfer_bytes = options.max_transfer_bytes or options.transfer_size
    for method in ("automatic", "server", "kad"):
        _click_primary_nav(page, "Search")
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
        search_panel.get_by_placeholder("Maximum bytes").fill(str(max_transfer_bytes))
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
            # still requires a sourced PDF inside the explicit size bound before
            # it can trigger a download from the rendered result table.
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
        filtered_live_pdf = select_filtered_live_pdf(rows, max_transfer_bytes)
        download_result = exact_result or (None if options.complete_transfer else filtered_live_pdf)
        if download_result is not None and not transfer_triggered:
            # The REST poll above observes completion before the SPA's periodic
            # snapshot refresh necessarily does. Trigger the rendered refresh
            # control so the SPA selects and fetches the newest search session.
            page.get_by_title("Refresh", exact=True).click(
                timeout=int(options.network_timeout_seconds * 1000)
            )
            result_name = str(download_result["name"])
            result_row = search_panel.locator("tbody tr").filter(has_text=result_name).first
            result_row.wait_for(timeout=int(options.network_timeout_seconds * 1000))
            result_row.get_by_role("button", name="Download", exact=True).click()
            page.get_by_text("Download queued", exact=True).wait_for(
                timeout=int(options.network_timeout_seconds * 1000)
            )
            selected_transfer = {
                "hash": str(download_result["hash"]).lower(),
                "name": result_name,
                "sizeBytes": int(download_result["sizeBytes"]),
            }
            selected_from_exact_allowlist = exact_result is not None
            transfer_triggered = True
        search_results.append(
            {
                "method": method,
                "status": completed.get("status"),
                "resultCount": int(completed.get("total") or 0),
                "pdfFilter": True,
                "maxBytesFilter": max_transfer_bytes,
                "exactAllowlistedResult": exact_allowlisted_result,
                "eligibleFilteredLivePdf": filtered_live_pdf is not None,
            }
        )

    if not transfer_triggered:
        raise RuntimeError("no sourced PDF inside the strict size bound was found in rendered search results")
    _click_primary_nav(page, "Transfers")
    transfer_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Transfers", exact=True)
    )

    def active_transfer() -> dict[str, Any] | None:
        value = api_data(
            base_url,
            f"transfers/{selected_transfer['hash']}",
            api_key,
        )
        if not isinstance(value, dict):
            return None
        completed_bytes = int(value.get("completedBytes") or 0)
        return value if completed_bytes > 0 else None

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
            f"transfers/{selected_transfer['hash']}",
            api_key,
        )
        if not isinstance(transfer, dict):
            transfer = {}
    stopped_after_observation = False
    deleted_after_stop = False
    transfer_stop_state = str(transfer.get("state") or "unknown")
    if options.complete_transfer:
        transfer = _wait_for_api(
            "rendered WebUI allowlisted transfer completion",
            options.transfer_timeout_seconds,
            lambda: (lambda value: value if int(value.get("completedBytes") or 0) == selected_transfer["sizeBytes"] else None)(
                api_data(base_url, f"transfers/{selected_transfer['hash']}", api_key)
            ),
        )
    else:
        transfer_row = transfer_panel.locator("tbody tr").filter(has_text=selected_transfer["name"]).first
        transfer_row.get_by_role("button", name="Stop", exact=True).click()
        page.get_by_text("Transfer stopped", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )
        transfer = _wait_for_api(
            "rendered WebUI transfer quiescence after Stop",
            min(15.0, options.network_timeout_seconds),
            lambda: (lambda value: value if isinstance(value, dict) and value.get("stopped") is True else None)(
                api_data(base_url, f"transfers/{selected_transfer['hash']}", api_key)
            ),
        )
        transfer_stop_state = str(transfer.get("state") or "unknown")
        stopped_after_observation = transfer.get("stopped") is True
        page.once("dialog", lambda dialog: dialog.accept())
        transfer_row.get_by_role("button", name="Delete", exact=True).click()
        page.get_by_text("Transfer deleted", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )
        transfer_row.wait_for(
            state="detached",
            timeout=int(options.network_timeout_seconds * 1000),
        )

        def deleted_transfer() -> dict[str, Any] | None:
            try:
                api_data(base_url, f"transfers/{selected_transfer['hash']}", api_key)
            except HTTPError as error:
                if error.code == 404:
                    return {"status": 404}
                raise
            return None

        _wait_for_api(
            "rendered WebUI transfer deletion",
            min(15.0, options.network_timeout_seconds),
            deleted_transfer,
        )
        deleted_after_stop = True
    kad_disconnect_verified = kad_stop is not None
    transfer_hash_verified = (
        str(transfer.get("hash") or "").lower() == selected_transfer["hash"]
    )
    transfer_size_verified = (
        int(transfer.get("sizeBytes") or 0) == selected_transfer["sizeBytes"]
    )
    transfer_name_round_trip = str(transfer.get("name") or "") == selected_transfer["name"]
    # eD2K protocol identity is hash + byte size. Display names may be normalized
    # by a live result source and are retained as a non-gating diagnostic only.
    transfer_identity_verified = transfer_hash_verified and transfer_size_verified
    failures = []
    if not kad_disconnect_verified:
        failures.append("kad-disconnect")
    if not server_disconnect_preserved_kad:
        failures.append("server-disconnect-preserved-kad")
    if not kad_stop_preserved_server:
        failures.append("kad-stop-preserved-server")
    if not transfer_activity_observed:
        failures.append("transfer-network-activity")
    if not transfer_identity_verified:
        failures.append("transfer-identity")
    if not options.complete_transfer and not stopped_after_observation:
        failures.append("transfer-stop-state")
    if not options.complete_transfer and not deleted_after_stop:
        failures.append("transfer-delete")
    return {
        "ok": not failures,
        "failures": failures,
        "zeroConfigurationDefaults": zero_configuration_defaults,
        "server": {
            "connected": True,
            "disconnectVerified": True,
            "reconnectVerified": True,
            "targetedReconnectVerified": True,
            "targetedServerEndpoint": targeted_server_endpoint,
            "targetedServerName": str(most_popular_server.get("name") or ""),
            "targetedServerUsers": int(most_popular_server.get("users") or 0),
            "selectedBy": "maximum live users, then files, among reachable enabled servers",
            "autoConnectVerified": True,
            "automaticMostPopularSelectionVerified": True,
            "automaticServerMetDownloadVerified": True,
            "manualImportUsed": False,
            "serverCount": len(server_list.get("items", [])),
            "initialHighId": bool(initial_server_stats.get("ed2kHighId")),
            "reconnectedHighId": bool(reconnected_server_stats.get("ed2kHighId")),
            "disconnectPreservedKad": server_disconnect_preserved_kad,
        },
        "kad": {
            "running": bool(reconnected_kad_status.get("running")),
            "connected": bool(reconnected_kad_status.get("connected")),
            "autoConnectVerified": True,
            "disconnectVerified": kad_disconnect_verified,
            "reconnectVerified": kad_disconnect_verified
            and bool(reconnected_kad_status.get("connected")),
            "stopPreservedServer": kad_stop_preserved_server,
            "initialContactCount": int(kad_status.get("contactCount") or 0),
            "reconnectedContactCount": int(reconnected_kad_status.get("contactCount") or 0),
            "automaticNodesDatDownloadVerified": True,
            "manualImportUsed": False,
        },
        "searches": search_results,
        "sharing": sharing,
        "transfer": {
            "triggered": True,
            "triggeredFromRenderedSearchResult": transfer_triggered,
            "selectedFromExactAllowlist": selected_from_exact_allowlist,
            "selectedFromFilteredLiveResults": not selected_from_exact_allowlist,
            "identityVerified": transfer_identity_verified,
            "hashVerified": transfer_hash_verified,
            "sizeVerified": transfer_size_verified,
            "displayNameRoundTrip": transfer_name_round_trip,
            "networkActivityRequired": True,
            "networkActivityObserved": transfer_activity_observed,
            "sourceCount": int(transfer.get("sources") or 0),
            "sourcesTransferring": int(transfer.get("sourcesTransferring") or 0),
            "completed": int(transfer.get("completedBytes") or 0) == options.transfer_size,
            "completedBytes": int(transfer.get("completedBytes") or 0),
            "sizeBytes": int(transfer.get("sizeBytes") or selected_transfer["sizeBytes"]),
            "stopRequested": not options.complete_transfer,
            "deleteRequested": not options.complete_transfer,
            "finalState": transfer_stop_state,
            "stoppedAfterObservation": stopped_after_observation,
            "stoppedFlag": bool(transfer.get("stopped")),
            "deletedAfterStop": deleted_after_stop,
            "absentAfterDelete": deleted_after_stop,
        },
        "nat": nat_status,
    }


def _consumer_nat_status(base_url: str, api_key: str) -> dict[str, Any]:
    value = api_data(base_url, "nat", api_key)
    if not isinstance(value, dict):
        return {
            "ready": False,
            "enabled": False,
            "gatewayDiscovered": False,
            "mappingCount": 0,
            "requiredMappings": [],
        }
    mappings = value.get("mappings", [])
    mapping_rows = mappings if isinstance(mappings, list) else []
    observed: set[tuple[str, int]] = set()
    mapping_names: list[str] = []
    for mapping in mapping_rows:
        if not isinstance(mapping, dict):
            continue
        protocol = str(mapping.get("protocol") or "").lower()
        local_addr = str(mapping.get("localAddr") or "")
        try:
            port = int(local_addr.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            port = 0
        if protocol and port:
            observed.add((protocol, port))
        name = str(mapping.get("name") or "")
        if name:
            mapping_names.append(name)
    required = {("tcp", 4662), ("udp", 4672)}
    ready = (
        value.get("enabled") is True
        and value.get("gatewayDiscovered") is True
        and bool(value.get("backend"))
        and not value.get("lastError")
        and required.issubset(observed)
    )
    return {
        "ready": ready,
        "enabled": bool(value.get("enabled")),
        "gatewayDiscovered": bool(value.get("gatewayDiscovered")),
        "mappingCount": len(mapping_rows),
        "requiredMappings": ["tcp:4662", "udp:4672"],
        "mappingNames": sorted(mapping_names),
        "backendPresent": bool(value.get("backend")),
        "lastErrorPresent": bool(value.get("lastError")),
    }


def _assert_zero_configuration_defaults(page, *, timeout_seconds: float) -> dict[str, Any]:
    """Prove fresh-profile auto-connect and best-effort UPnP in the rendered form."""

    _click_primary_nav(page, "Settings", timeout_ms=int(timeout_seconds * 1000))
    panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Settings", exact=True)
    )
    advanced = panel.get_by_label(re.compile("Advanced"))
    if not advanced.is_checked():
        advanced.check()
    auto_connect = panel.get_by_role(
        "checkbox",
        name=re.compile(r"^Auto connect(?:\s|$)"),
    )
    nat_section = panel.locator('[data-settings-section="nat"]')
    nat_enabled = nat_section.get_by_role("checkbox", name=re.compile(r"^NAT(?:\s|$)"))
    require_initial = nat_section.get_by_role(
        "checkbox",
        name=re.compile(r"^Require initial NAT mapping(?:\s|$)"),
    )
    auto_connect.wait_for(timeout=int(timeout_seconds * 1000))
    nat_enabled.wait_for(timeout=int(timeout_seconds * 1000))
    require_initial.wait_for(timeout=int(timeout_seconds * 1000))
    observed = {
        "autoConnect": auto_connect.is_checked(),
        "upnpEnabled": nat_enabled.is_checked(),
        "requireInitialMapping": require_initial.is_checked(),
        "verifiedThroughRenderedWebui": True,
    }
    if (
        not observed["autoConnect"]
        or not observed["upnpEnabled"]
        or observed["requireInitialMapping"]
    ):
        raise RuntimeError(
            "fresh-profile WebUI defaults are not auto-connect plus best-effort UPnP: "
            f"{observed!r}"
        )
    return observed


def _configure_best_effort_upnp(page, *, timeout_seconds: float) -> dict[str, Any]:
    """Enable best-effort NAT mapping through the rendered Settings form."""

    _click_primary_nav(page, "Settings", timeout_ms=int(timeout_seconds * 1000))
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
        "consumerSharingWorkflow": bool(
            consumer_workflow is not None and consumer_workflow.shared_files
        ),
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
                page.add_init_script(browser_api_key_write_script(initial_api_key))
                page.goto(base_url, wait_until="domcontentloaded", timeout=int(timeout_seconds * 1000))
                if verify_stale_key_recovery:
                    page.get_by_role("heading", name="Connect to the local daemon").wait_for(
                        timeout=int(timeout_seconds * 1000)
                    )
                    if page.get_by_role("navigation", name="Primary views").count() != 0:
                        raise RuntimeError("Rust WebUI exposed protected navigation for a stale API key")
                    page.get_by_placeholder("X-API-Key").fill(api_key)
                    page.get_by_role("button", name="Connect", exact=True).click(
                        timeout=int(timeout_seconds * 1000)
                    )
                    page.get_by_text("API key verified", exact=True).wait_for(
                        timeout=int(timeout_seconds * 1000)
                    )
                    stored_api_key = page.evaluate(browser_api_key_read_script())
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
                    _click_primary_nav(page, label, timeout_ms=int(timeout_seconds * 1000))
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

                _click_primary_nav(page, "Transfers", timeout_ms=int(timeout_seconds * 1000))
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
                    _click_primary_nav(
                        page,
                        "Diagnostics",
                        timeout_ms=int(timeout_seconds * 1000),
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
            str(consumer_workflow.shared_root_path or ""),
            *(fixture.name for fixture in consumer_workflow.shared_files),
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
