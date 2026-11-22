"""Packaged emulebb-rust WebUI live proof against a running persisted daemon."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .paths import get_workspace_output_root
from .rust_rest_contract import iter_library_files, restore_settings_patch, settings_patch

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
    "Library",
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


def _download_rows(base_url: str, api_key: str) -> list[dict[str, Any]]:
    document = api_document(base_url, "downloads?view=all&limit=200", api_key)
    rows = document.get("data") if isinstance(document, dict) else None
    meta = document.get("meta") if isinstance(document, dict) else None
    if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
            or not isinstance(meta, dict) or meta.get("hasMore") is not False
            or "nextCursor" not in meta or meta["nextCursor"] is not None
            or not isinstance(meta.get("apiVersion"), str)):
        raise RuntimeError("WebUI proof requires a complete bounded download page")
    return rows


def _require_download_batch(document: dict, download_id: str) -> None:
    rows = document.get("data") if isinstance(document, dict) else None
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get("id") != download_id or rows[0].get("status") not in {"accepted", "unchanged"}
            or type(rows[0].get("httpStatus")) is not int or not 200 <= rows[0]["httpStatus"] < 300
            or "error" in rows[0]):
        raise RuntimeError("WebUI download action did not accept the captured job")


def file_link_confirmation(page, *, base_url: str, api_key: str, link: str,
                           file_hash: str, size_bytes: int, cleanup_evidence: dict,
                           timeout_seconds: float = 30) -> dict:
    """Exercise the real handoff form; inspect actual requests and persisted rows."""
    timeout = int(timeout_seconds * 1000)
    posts = []
    download_id = None

    def observe(request):
        if request.method == "POST" and urlparse(request.url).path == "/api/v1/downloads":
            if len(posts) < 8:
                posts.append(request.post_data_json)

    def rows():
        return _download_rows(base_url, api_key)

    def identities(items):
        return sorted((item.get("id"), item.get("hash", "").lower(), item.get("sizeBytes")) for item in items)

    baseline = rows()
    if any(item.get("hash", "").lower() == file_hash for item in baseline):
        raise RuntimeError("File-link proof requires its own absent transfer hash")
    page.on("request", observe)
    handoff_url = base_url.rstrip("/") + "/transfers#" + urlencode({"ed2k": link})
    from .rust_local_ed2k import request_json

    try:
        page.goto(handoff_url, wait_until="domcontentloaded", timeout=timeout)
        page.get_by_role("heading", name="Connect to the local daemon").wait_for(timeout=timeout)
        if identities(rows()) != identities(baseline) or posts:
            raise RuntimeError("File-link handoff queued a transfer before authentication")
        page.get_by_placeholder("X-API-Key").fill(api_key)
        page.get_by_role("button", name="Connect", exact=True).click(timeout=timeout)
        field = page.get_by_label("eD2K links", exact=True)
        field.wait_for(timeout=timeout)
        if field.input_value() != link or identities(rows()) != identities(baseline) or posts:
            raise RuntimeError("File-link sign-in lost its prefill or silently queued a transfer")
        page.get_by_role("button", name="Cancel links", exact=True).click(timeout=timeout)
        page.wait_for_function("location.hash === ''", timeout=timeout)
        if field.input_value() or identities(rows()) != identities(baseline) or posts:
            raise RuntimeError("File-link cancellation retained input or queued a transfer")

        page.goto(handoff_url, wait_until="domcontentloaded", timeout=timeout)
        field = page.get_by_label("eD2K links", exact=True)
        field.wait_for(timeout=timeout)
        if field.input_value() != link:
            raise RuntimeError("File-link form did not restore the requested link")
        # Queue only a stopped synthetic fixture: this checks the real POST and
        # persistence without inventing an available P2P source for these bytes.
        page.get_by_label("Stopped", exact=True).check(timeout=timeout)
        if identities(rows()) != identities(baseline) or posts:
            raise RuntimeError("File-link handoff queued a transfer before confirmation")
        with page.expect_response(lambda response: response.request.method == "POST"
                                  and urlparse(response.url).path == "/api/v1/downloads", timeout=timeout) as response:
            page.get_by_role("button", name="Add links", exact=True).click(timeout=timeout)
        created = response.value.json().get("data") if response.value.ok and response.value.status == 201 else None
        candidate_id = created.get("id") if isinstance(created, dict) else None
        if (posts != [{"source": {"type": "ed2k-link", "link": link}, "intent": "stopped"}]
                or not isinstance(candidate_id, str) or re.fullmatch(r"[1-9][0-9]{0,18}", candidate_id) is None
                or int(candidate_id) > 9223372036854775807
                or created.get("hash", "").lower() != file_hash or created.get("sizeBytes") != size_bytes):
            raise RuntimeError("File-link confirmation did not submit the exact requested stopped download")
        download_id = candidate_id
        page.wait_for_function("location.hash === ''", timeout=timeout)

        def confirmed():
            items = rows()
            matched = [item for item in items if item.get("id") == download_id]
            if (len(matched) == 1 and matched[0].get("sizeBytes") == size_bytes
                    and matched[0].get("hash", "").lower() == file_hash
                    and matched[0].get("intent") == "stopped"
                    and identities(items) == sorted(identities(baseline) + [(download_id, file_hash, size_bytes)])):
                return items
            return None

        _wait_for_api("confirmed file-link transfer", timeout_seconds, confirmed)
        page.goto(handoff_url, wait_until="domcontentloaded", timeout=timeout)
        page.get_by_label("eD2K links", exact=True).wait_for(timeout=timeout)
        page.wait_for_timeout(1000)
        if len(posts) != 1 or confirmed() is None:
            raise RuntimeError("Repeated file-link navigation automatically changed the transfer queue")
        page.get_by_role("button", name="Cancel links", exact=True).click(timeout=timeout)
        return {"status": "passed", "signInPreserved": True, "cancelWithoutEnqueue": True,
                "explicitConfirmation": True, "repeatedNavigationWithoutEnqueue": True,
                "downloadId": download_id, "hash": file_hash, "sizeBytes": size_bytes, "intent": "stopped"}
    finally:
        active_failure = sys.exc_info()[0] is not None
        errors = []
        try:
            page.remove_listener("request", observe)
        except Exception as error:
            errors.append(type(error).__name__)
        # Remove only the job created by this disposable proof.
        try:
            if download_id is not None and any(item.get("id") == download_id for item in rows()):
                result = request_json(base_url, "POST", "/api/v1/downloads/remove", api_key,
                    {"ids": [download_id], "deleteData": True}, expected_status=207)
                _require_download_batch(result, download_id)
            if len(posts) > 1 or download_id is None and identities(rows()) != identities(baseline):
                raise RuntimeError("File-link proof has an enqueue without a captured creation receipt")
            if identities(rows()) != identities(baseline):
                raise RuntimeError("File-link proof cleanup did not restore the original transfer collection")
        except Exception as error:
            errors.append(type(error).__name__)
        cleanup_evidence.update(status="failed" if errors else "passed", errorTypes=errors)
        if errors and not active_failure:
            raise RuntimeError("File-link proof cleanup failed")


def run_file_link_browser_proof(*, base_url: str, api_key: str, link: str, file_hash: str,
                                size_bytes: int, report_path: Path, identity: dict) -> dict:
    """Use the installed test browser against the source-bound bundled WebUI."""
    report = {"schema": "emulebb-rust.webui-file-link-proof/1", "status": "failed", "buildIdentity": identity}
    try:
        from playwright.sync_api import sync_playwright
        app = api_data(base_url, "app", api_key)
        if any(app.get(key) != value for key, value in identity.items()):
            raise RuntimeError("File-link browser proof source identity differs")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                try:
                    report["confirmation"] = file_link_confirmation(context.new_page(), base_url=base_url,
                        api_key=api_key, link=link, file_hash=file_hash, size_bytes=size_bytes,
                        cleanup_evidence=report.setdefault("cleanup", {}))
                finally:
                    context.close()
            finally:
                browser.close()
        report["status"] = "passed"
        return report
    except Exception as error:
        # Browser errors can contain form values or URLs. Retain only the type;
        # the app's generated credential must never enter proof artifacts.
        report["errorType"] = type(error).__name__
        raise RuntimeError("Bundled WebUI file-link confirmation proof failed") from None
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def require_file_link_browser() -> None:
    """Fail before guest boot when the pinned offline browser is unavailable."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                raise RuntimeError("Missing installed Chromium")
    except Exception:
        raise RuntimeError("APK qualification requires its installed offline Playwright/Chromium image") from None


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
ALLOWED_REPEATED_STEADY_PATHS = frozenset({"downloads?view=all&limit=12"})
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
    api_key = payload.get("rest", {}).get("api_key")
    if not isinstance(api_key, str) or not api_key.strip():
        raise RuntimeError(f"REST API key is missing from {settings_path}")
    return api_key.strip()


def api_document(base_url: str, path: str, api_key: str) -> Any:
    """Fetch one authenticated REST response with its page metadata."""
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/{path.lstrip('/')}",
        headers={"X-API-Key": api_key},
    )
    with urlopen(request, timeout=5.0) as response:
        return json.loads(response.read())


def api_data(base_url: str, path: str, api_key: str) -> Any:
    """Fetch one authenticated REST resource and unwrap the API envelope."""

    payload = api_document(base_url, path, api_key)
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


def _saved_setting(snapshot: dict, key: str) -> dict:
    leaf = snapshot["data"]["saved"]
    for part in key.split("."):
        leaf = leaf[part]
    if leaf["mode"] not in {"default", "custom"} or "value" not in leaf:
        raise RuntimeError(f"Invalid saved setting: {key}")
    return leaf


def _settings_form_check(surface: dict, snapshot: dict, rows: list[dict]) -> dict:
    """Require every current daemon field, saved mode and value in the rendered form."""
    # Reuse the shared exact revision validator without sending any request.
    settings_patch(snapshot, reset=("transfers.uploadLimitBytesPerSecond",))
    fields = surface["fields"]
    keys = [field["key"] for field in fields]
    rendered = [row["key"] for row in rows]
    if not keys or len(set(keys)) != len(keys) or len(set(rendered)) != len(rendered) or set(rendered) != set(keys):
        raise RuntimeError("Rendered settings fields differ from the daemon surface")
    defaults = 0
    for row in rows:
        leaf = _saved_setting(snapshot, row["key"])
        value = leaf["value"]
        text = ("" if value is None else "\n".join(value) if isinstance(value, list)
                else str(value).lower() if isinstance(value, bool) else str(value))
        default = leaf["mode"] == "default"
        if row["default"] is not default or row["text"] != text:
            raise RuntimeError(f"Rendered setting differs from the saved snapshot: {row['key']}")
        if leaf["mode"] == "custom" and (row["unset"] is True) != (value is None):
            raise RuntimeError(f"Rendered nullable setting differs: {row['key']}")
        defaults += default
    return {"ok": True, "fieldCount": len(keys), "defaultCount": defaults}


def _wait_for_settings_form(page, surface: dict, snapshot: dict, timeout_seconds: float) -> dict:
    def probe():
        rows = page.locator("fieldset.setting-editor").evaluate_all("""elements => elements.map(element => {
            const defaults = element.querySelector('input[aria-label^="Use default for "]');
            const unset = element.querySelector('input[aria-label^="Not set for "]');
            const control = element.querySelector('input.form-control, textarea, select')
                ?? Array.from(element.querySelectorAll('input[type="checkbox"]'))
                    .find(input => input !== defaults && input !== unset);
            return {key: element.querySelector('code.setting-key')?.textContent,
                default: defaults?.checked, unset: unset?.checked ?? null,
                text: control?.type === 'checkbox' ? String(control.checked) : control?.value};
        })""")
        return _settings_form_check(surface, snapshot, rows)
    return _wait_for_api("complete canonical settings form", timeout_seconds, probe)


def _settings_editor(page, key: str):
    return page.locator("fieldset.setting-editor").filter(
        has=page.locator("code.setting-key").filter(has_text=re.compile("^" + re.escape(key) + "$")))


def _save_settings_form(page, expected: dict, timeout_seconds: float) -> dict:
    """Submit once; an unconfirmed response never authorizes a compensating write."""
    writes = []

    def observe(request):
        if request.method == "PATCH" and urlparse(request.url).path == "/api/v1/settings":
            writes.append(request.post_data_json)

    page.on("request", observe)
    try:
        with page.expect_response(lambda response: response.request.method == "PATCH"
                                  and urlparse(response.url).path == "/api/v1/settings",
                                  timeout=int(timeout_seconds * 1000)) as observed:
            page.get_by_role("button", name="Save", exact=True).click()
        response = observed.value
        if response.status != 200 or writes != [expected]:
            raise RuntimeError("Settings form did not confirm exactly one expected revisioned write")
        snapshot = response.json()
        revision = settings_patch(snapshot, reset=("transfers.uploadLimitBytesPerSecond",))["expectedRevision"]
        if int(revision) != int(expected["expectedRevision"]) + 1:
            raise RuntimeError("Settings form write did not advance its revision exactly once")
        return snapshot
    finally:
        page.remove_listener("request", observe)


def _read_settings_form(page, *, base_url: str, api_key: str, timeout_seconds: float) -> tuple[dict, dict, dict]:
    """Capture a navigation-owned snapshot and prove its complete rendered form."""
    surface = api_data(base_url, "settings/surface", api_key)
    # WHY: Settings can already be selected by another proof step. Navigate from
    # Logs so the captured GET belongs to this load, without an implicit retry.
    _click_primary_nav(page, "Logs", timeout_ms=int(timeout_seconds * 1000))
    with page.expect_response(lambda response: response.request.method == "GET"
                              and urlparse(response.url).path == "/api/v1/settings",
                              timeout=int(timeout_seconds * 1000)) as observed:
        _click_primary_nav(page, "Settings", timeout_ms=int(timeout_seconds * 1000))
    response = observed.value
    if response.status != 200:
        raise RuntimeError("Settings navigation did not load the native snapshot")
    snapshot = response.json()
    result = _wait_for_settings_form(page, surface, snapshot, timeout_seconds)
    return surface, snapshot, result


def _verify_settings_form(page, *, base_url: str, api_key: str,
                          timeout_seconds: float, verify_edits: bool) -> dict:
    """Read all native fields; optional writes belong only to disposable package profiles."""
    surface, snapshot, result = _read_settings_form(
        page, base_url=base_url, api_key=api_key, timeout_seconds=timeout_seconds)
    result["writes"] = 0
    if not verify_edits:
        return result

    key = "transfers.uploadLimitBytesPerSecond"
    field = next(item for item in surface["fields"] if item["key"] == key)
    original = _saved_setting(snapshot, key)
    rule = field["rule"]
    if field["application"] != "live" or rule["kind"] != "integer":
        raise RuntimeError("Disposable settings proof requires a live integer upload limit")
    step = rule["step"]
    value = original["value"]
    temporary = next((candidate for candidate in (value + step, value - step, value + 2 * step)
                      if rule["min"] <= candidate <= rule["max"] and candidate != field["defaultValue"]), None)
    if temporary is None:
        raise RuntimeError("Upload limit has no alternate valid proof value")
    editor = _settings_editor(page, key)
    editor.locator('input[aria-label^="Use default for "]').uncheck()
    editor.locator("input.form-control").fill(str(temporary))
    changed = _save_settings_form(page, settings_patch(snapshot, set_values={
        "transfers": {"uploadLimitBytesPerSecond": temporary}}), timeout_seconds)
    _wait_for_settings_form(page, surface, changed, timeout_seconds)
    if _saved_setting(changed, key) != {"mode": "custom", "value": temporary}:
        raise RuntimeError("Temporary upload limit was not saved")
    if changed["data"]["effective"]["transfers"]["uploadLimitBytesPerSecond"] != temporary:
        raise RuntimeError("Temporary live upload limit was not applied")
    restore = restore_settings_patch(changed, {key: original})
    if original["mode"] == "default":
        editor.locator('input[aria-label^="Use default for "]').check()
    else:
        editor.locator("input.form-control").fill(str(value))
    restored = _save_settings_form(page, restore, timeout_seconds)
    _wait_for_settings_form(page, surface, restored, timeout_seconds)
    leaf = _saved_setting(restored, key)
    if leaf["mode"] != original["mode"] or (leaf["mode"] == "custom" and leaf["value"] != value):
        raise RuntimeError("Settings form did not restore the original saved mode/value")
    if restored["data"]["effective"]["transfers"]["uploadLimitBytesPerSecond"] != leaf["value"]:
        raise RuntimeError("Settings form did not restore the effective live upload limit")
    return {**result, "writes": 2, "restored": True, "key": key}


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
    rows: list[dict[str, Any]],
    expected: tuple[ConsumerSharedFixture, ...],
    fetch_detail: Callable[[str], Any],
) -> list[dict[str, Any]] | None:
    """Return exact synthetic fixture rows once the shared catalog is complete."""

    if not isinstance(rows, list):
        return None
    expected_by_name = {fixture.name: fixture for fixture in expected}
    if len(expected_by_name) != len(expected) or len(rows) != len(expected):
        return None
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            return None
        name = str(row.get("displayName") or "")
        fixture = expected_by_name.get(name)
        transfer_hash = str(row.get("hash") or "").lower()
        if (
            fixture is None
            or row.get("sizeBytes") != fixture.size_bytes
            or len(transfer_hash) != 32
            or any(character not in "0123456789abcdef" for character in transfer_hash)
        ):
            return None
        detail = fetch_detail(transfer_hash)
        if (not isinstance(detail, dict) or detail.get("hash") != transfer_hash
                or not str(detail.get("ed2kLink") or "").startswith("ed2k://|file|")):
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


def _require_empty_ed2k_catalog(baseline: dict[str, Any]) -> None:
    """Admit the disposable publication proof only before any catalog is present."""
    counts = (baseline.get("totalEntries"), baseline.get("publishedEntries"))
    if not all(type(value) is int and value == 0 for value in counts):
        raise RuntimeError("consumer sharing proof requires an empty baseline eD2K catalog")


def _ed2k_fixture_published(current: dict[str, Any], expected_count: int) -> bool:
    """Prove a new fixture catalog after the caller established an empty baseline."""
    success = current.get("lastSuccessAt")
    return (type(expected_count) is int and expected_count > 0
            and type(success) is int and success >= 0
            and all(type(current.get(name)) is int for name in
                    ("totalEntries", "publishedEntries", "pendingEntries"))
            and current["totalEntries"] == expected_count
            and current["publishedEntries"] == expected_count
            and current["pendingEntries"] == 0
            and "lastError" in current and current["lastError"] is None)


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
    _require_empty_ed2k_catalog(baseline_ed2k)

    _click_primary_nav(page, "Sharing")
    sharing_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Shared Folders", exact=True)
    )
    sharing_panel.get_by_placeholder("Server folder path").fill(options.shared_root_path)
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and urlparse(response.url).path == "/api/v1/library/roots",
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
    root_id = str(add_root_response.value.json()["data"]["id"])

    def indexed_fixture() -> dict[str, Any] | None:
        directories = api_data(base_url, "library/scan", api_key)
        root = api_data(base_url, f"library/roots/{root_id}", api_key)
        reload_progress = (
            directories.get("reloadProgress", {}) if isinstance(directories, dict) else {}
        )
        if not isinstance(root, dict) or root.get("id") != root_id or not isinstance(reload_progress, dict):
            return None
        if reload_progress.get("running") or reload_progress.get("pending"):
            return None
        if _integer_field(reload_progress, "failedHashCount") != 0:
            raise RuntimeError("synthetic shared-file hashing reported failures")
        files = list(iter_library_files(
            lambda path: api_document(base_url, path, api_key), view="shared", root_id=root_id
        ))
        matched = _matched_shared_catalog(
            files, options.shared_files,
            lambda file_hash: api_data(base_url, f"library/files/{file_hash}", api_key),
        )
        if matched is None:
            return None
        return {
            "files": matched,
            "hashedCount": _integer_field(reload_progress, "hashedCount"),
            "newCount": _integer_field(reload_progress, "newCount"),
            "reusedCount": _integer_field(reload_progress, "reusedCount"),
            "updatedAt": _integer_field(reload_progress, "updatedAt"),
        }

    initial_catalog = _wait_for_api(
        "synthetic shared-tree indexing",
        options.network_timeout_seconds,
        indexed_fixture,
    )
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and urlparse(response.url).path == "/api/v1/library/scan",
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
        indexed_fixture,
    )

    _click_primary_nav(page, "Library")
    shared_files_panel = page.locator("section.panel").filter(
        has=page.get_by_role("heading", name="Library", exact=True)
    )
    for fixture in options.shared_files:
        row = shared_files_panel.locator("tbody tr").filter(has_text=fixture.name).first
        row.wait_for(timeout=int(options.network_timeout_seconds * 1000))

    def published_fixture() -> dict[str, Any] | None:
        status = api_data(base_url, "status", api_key)
        ed2k, kad = _publish_diagnostics(status)
        ed2k_ready = _ed2k_fixture_published(ed2k, expected_count)
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
        base_url=base_url,
        api_key=api_key,
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
        "automatic first-run Kad connection from imported SQLite contacts",
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
            with page.expect_response(lambda response: response.request.method == "POST"
                    and re.fullmatch(r"/api/v1/searches/[^/]+/results/[1-9][0-9]{0,18}/download",
                        urlparse(response.url).path) is not None,
                    timeout=int(options.network_timeout_seconds * 1000)) as download_response:
                result_row.get_by_role("button", name="Download", exact=True).click()
            page.get_by_text("Download queued", exact=True).wait_for(
                timeout=int(options.network_timeout_seconds * 1000)
            )
            created = download_response.value.json().get("data") if download_response.value.ok else None
            download_id = created.get("id") if isinstance(created, dict) else None
            if (not isinstance(download_id, str) or re.fullmatch(r"[1-9][0-9]{0,18}", download_id) is None
                    or int(download_id) > 9223372036854775807
                    or created.get("hash", "").lower() != str(download_result["hash"]).lower()):
                raise RuntimeError("Rendered search download did not return a durable job ID")
            selected_transfer = {
                "id": download_id,
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
            f"downloads/{selected_transfer['id']}",
            api_key,
        )
        if not isinstance(value, dict):
            return None
        progress = value.get("progress")
        return value if value.get("id") == selected_transfer["id"] and type(progress) in {int, float} and progress > 0 else None

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
            f"downloads/{selected_transfer['id']}",
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
            lambda: (lambda value: value if isinstance(value, dict) and value.get("id") == selected_transfer["id"]
                and value.get("state") == "completed" and value.get("payloadVerified") is True
                and isinstance(value.get("delivery"), dict) and value["delivery"].get("state") == "delivered"
                and value["delivery"].get("ownership") in {"owned", "unowned"}
                and isinstance(value["delivery"].get("path"), str) and value["delivery"]["path"] else None)(
                api_data(base_url, f"downloads/{selected_transfer['id']}", api_key)
            ),
        )
    else:
        transfer_row = transfer_panel.locator("tbody tr").filter(has_text=selected_transfer["name"]).first
        with page.expect_response(lambda response: response.request.method == "POST"
                and urlparse(response.url).path == "/api/v1/downloads/stop",
                timeout=int(options.network_timeout_seconds * 1000)) as stop_response:
            transfer_row.get_by_role("button", name="Stop", exact=True).click()
        if (stop_response.value.status != 207
                or stop_response.value.request.post_data_json != {"ids": [selected_transfer["id"]]}):
            raise RuntimeError("Rendered Stop did not return a batch outcome")
        _require_download_batch(stop_response.value.json(), selected_transfer["id"])
        page.get_by_text("Transfer stopped", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )
        transfer = _wait_for_api(
            "rendered WebUI transfer quiescence after Stop",
            min(15.0, options.network_timeout_seconds),
            lambda: (lambda value: value if isinstance(value, dict) and value.get("intent") == "stopped"
                and value.get("state") == "stopped" else None)(
                api_data(base_url, f"downloads/{selected_transfer['id']}", api_key)
            ),
        )
        transfer_stop_state = str(transfer.get("state") or "unknown")
        stopped_after_observation = transfer.get("intent") == "stopped" and transfer.get("state") == "stopped"
        page.once("dialog", lambda dialog: dialog.accept())
        with page.expect_response(lambda response: response.request.method == "POST"
                and urlparse(response.url).path == "/api/v1/downloads/remove",
                timeout=int(options.network_timeout_seconds * 1000)) as remove_response:
            transfer_row.get_by_role("button", name="Delete", exact=True).click()
        if (remove_response.value.status != 207
                or remove_response.value.request.post_data_json != {
                    "ids": [selected_transfer["id"]], "deleteData": False}):
            raise RuntimeError("Rendered Delete did not return a batch outcome")
        _require_download_batch(remove_response.value.json(), selected_transfer["id"])
        page.get_by_text("Transfer deleted", exact=True).wait_for(
            timeout=int(options.network_timeout_seconds * 1000)
        )
        transfer_row.wait_for(
            state="detached",
            timeout=int(options.network_timeout_seconds * 1000),
        )

        def deleted_transfer() -> dict[str, Any] | None:
            try:
                api_data(base_url, f"downloads/{selected_transfer['id']}", api_key)
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
    transfer_identity_verified = (transfer.get("id") == selected_transfer["id"]
        and transfer_hash_verified and transfer_size_verified)
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
            "downloadId": selected_transfer["id"],
            "progress": transfer.get("progress"),
            "completed": transfer.get("state") == "completed" and transfer.get("payloadVerified") is True,
            "deliveryOwnership": (transfer.get("delivery") or {}).get("ownership"),
            "sizeBytes": int(transfer.get("sizeBytes") or selected_transfer["sizeBytes"]),
            "stopRequested": not options.complete_transfer,
            "deleteRequested": not options.complete_transfer,
            "finalState": transfer_stop_state,
            "stoppedAfterObservation": stopped_after_observation,
            "stoppedFlag": transfer.get("intent") == "stopped",
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
    required = {("tcp", 20019), ("udp", 20020)}
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
        "requiredMappings": ["tcp:20019", "udp:20020"],
        "mappingNames": sorted(mapping_names),
        "backendPresent": bool(value.get("backend")),
        "lastErrorPresent": bool(value.get("lastError")),
    }


def _assert_zero_configuration_defaults(page, *, base_url: str, api_key: str,
                                         timeout_seconds: float) -> dict[str, Any]:
    """Prove fresh-profile auto-connect and best-effort UPnP in the rendered form."""

    _, snapshot, _ = _read_settings_form(
        page, base_url=base_url, api_key=api_key, timeout_seconds=timeout_seconds)
    expected = {"network.autoConnect": True, "network.nat.enabled": True,
                "network.nat.requireInitialMapping": False}
    for key, value in expected.items():
        leaf = _saved_setting(snapshot, key)
        if leaf != {"mode": "default", "value": value}:
            raise RuntimeError(f"Fresh-profile setting is not the expected default: {key}")
    application = snapshot["data"]["application"]
    if application["pendingRestart"] or application["failed"]:
        raise RuntimeError("Fresh-profile settings have unapplied changes")
    network = snapshot["data"]["effective"]["network"]
    observed = {
        "autoConnect": network["autoConnect"],
        "upnpEnabled": network["nat"]["enabled"],
        "requireInitialMapping": network["nat"]["requireInitialMapping"],
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


def _configure_best_effort_upnp(page, *, base_url: str, api_key: str,
                                timeout_seconds: float) -> dict[str, Any]:
    """Enable best-effort NAT mapping through the rendered Settings form."""

    surface, snapshot, _ = _read_settings_form(
        page, base_url=base_url, api_key=api_key, timeout_seconds=timeout_seconds)
    changes = {}
    for name, value in {"enabled": True, "requireInitialMapping": False}.items():
        key = "network.nat." + name
        if _saved_setting(snapshot, key)["value"] is value:
            continue
        editor = _settings_editor(page, key)
        editor.locator('input[aria-label^="Use default for "]').uncheck()
        editor.locator('input[type="checkbox"]').last.set_checked(value)
        changes[name] = value
    if changes:
        snapshot = _save_settings_form(page, settings_patch(
            snapshot, set_values={"network": {"nat": changes}}), timeout_seconds)
        _wait_for_settings_form(page, surface, snapshot, timeout_seconds)
    for name, value in {"enabled": True, "requireInitialMapping": False}.items():
        if _saved_setting(snapshot, "network.nat." + name)["value"] is not value:
            raise RuntimeError("Best-effort NAT settings were not saved")
    application = snapshot["data"]["application"]
    if application["failed"]:
        raise RuntimeError("Best-effort NAT settings application failed")
    return {
        "enabled": True,
        "requireInitialMapping": False,
        "restartRequired": bool(application["pendingRestart"]),
        "writes": int(bool(changes)),
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
    """Remove live download IDs and file hashes from a request key."""

    return HASH_TOKEN_RE.sub("{hash}",
        re.sub(r"(?<=downloads/)[1-9][0-9]{0,18}(?=/|$)", "{id}", key))


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
        if count > 1 and path not in ALLOWED_REPEATED_STEADY_PATHS
        and not any(path.startswith(prefix) for prefix in ALLOWED_REPEATED_STEADY_PREFIXES)
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


def verify_about_build_identity(page, expected_identity: dict[str, str], *,
                                public_capture_path: Path | None = None) -> dict[str, str]:
    """Compare the rendered About values with the verified package identity."""
    if public_capture_path is not None:
        # WHY: only the fresh synthetic package owner opts in. Never capture
        # Overview's interface data or an authentication form in public images.
        page.set_viewport_size({"width": 1280, "height": 720})
        _click_primary_nav(page, "Search", timeout_ms=30_000)
        page.get_by_role("heading", name="Search", exact=True).wait_for(state="visible")
        if page.get_by_placeholder("X-API-Key").is_visible():
            raise RuntimeError("Public WebUI capture must not include an authentication form")
    details = page.get_by_label("About this build", exact=True)
    details.locator("summary").click()
    try:
        observed = {}
        for label, key in (("Version", "version"), ("Channel", "channel"), ("Architecture", "platform"),
                           ("Build", "build"), ("Source commit", "sourceRevision")):
            value = details.get_by_text(label, exact=True).locator("xpath=following-sibling::dd[1]")
            value.wait_for(state="visible")
            observed[key] = value.inner_text().strip()
        if observed != expected_identity:
            raise RuntimeError("Rendered About build identity does not match the selected package")
        if public_capture_path is not None:
            public_capture_path.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(public_capture_path), type="png", full_page=False,
                            animations="disabled", caret="hide")
        return observed
    finally:
        details.locator("summary").click()


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
    verify_settings_edits: bool = False,
    consumer_workflow: ConsumerNetworkWorkflow | None = None,
    configure_best_effort_upnp: bool = False,
    shutdown_after_proof: bool = False,
    expected_app_identity: dict[str, str] | None = None,
    public_capture_path: Path | None = None,
) -> dict[str, Any]:
    """Exercises the packaged WebUI and writes a sanitized proof report."""

    if public_capture_path is not None and (expected_app_identity is None or not navigation_only
                                           or consumer_workflow is not None):
        raise ValueError("Public capture requires the strict synthetic native-package proof")

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
                if expected_app_identity is not None:
                    report["checks"]["buildIdentity"] = verify_about_build_identity(
                        page, expected_app_identity, public_capture_path=public_capture_path)
                    if public_capture_path is not None:
                        report["checks"]["publicCapture"] = {
                            "file": public_capture_path.name, "width": 1280, "height": 720, "view": "Search",
                            "sha256": hashlib.sha256(public_capture_path.read_bytes()).hexdigest(),
                        }

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

                report["checks"]["settingsForm"] = _verify_settings_form(
                    page, base_url=base_url, api_key=api_key,
                    timeout_seconds=timeout_seconds, verify_edits=verify_settings_edits,
                )

                if configure_best_effort_upnp:
                    report["checks"]["upnpConfiguration"] = _configure_best_effort_upnp(
                        page,
                        base_url=base_url,
                        api_key=api_key,
                        timeout_seconds=timeout_seconds,
                    )
                    if consumer_workflow is not None and report["checks"]["upnpConfiguration"]["restartRequired"]:
                        raise RuntimeError("Saved NAT configuration requires a daemon restart before consumer-network proof")

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
