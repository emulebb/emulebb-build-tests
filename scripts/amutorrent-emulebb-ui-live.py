"""Runs full aMuTorrent eMuleBB live UI E2E checks."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_wire_inputs

SYNTHETIC_ED2K_HASH = "0123456789abcdef0123456789abcdef"
REQUIRED_BUNDLE_HOOKS = (
    "view-home",
    "view-downloads",
    "view-servers",
    "view-logs",
    "view-statistics",
    "emulebb-search-submit",
    "emulebb-search-result-checkbox",
    "emulebb-add-download-submit",
    "emulebb-downloads-select-mode",
    "emulebb-downloads-pause-selected",
    "emulebb-downloads-resume-selected",
    "emulebb-downloads-stop-selected",
    "emulebb-downloads-category-selected",
    "emulebb-downloads-delete-selected",
    "file-category-modal",
    "file-info-modal",
    "delete-confirm-modal",
    "shared-dirs-modal",
    "emulebb-servers-refresh",
    "stats-tree-modal",
    "app-logs-section",
    "client-card-",
)


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    existing = sys.modules.get(module_name)
    if existing is not None and Path(getattr(existing, "__file__", "")).resolve() == module_path:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
rest_api_smoke = load_local_module("rest_api_smoke_helpers", "rest-api-smoke.py")
amutorrent_smoke = load_local_module("amutorrent_browser_smoke_helpers", "amutorrent-browser-smoke.py")
amutorrent_session = load_local_module("amutorrent_interactive_session_helpers", "amutorrent-interactive-session.py")
amutorrent_clean = load_local_module("amutorrent_clean_startup_helpers", "amutorrent-clean-startup.py")
amutorrent_resilience = load_local_module("amutorrent_resilience_live_helpers", "amutorrent-resilience-live.py")

choose_listen_port = rest_api_smoke.choose_listen_port
close_app_cleanly = live_common.close_app_cleanly
get_app_process_id = rest_api_smoke.get_app_process_id
launch_app = live_common.launch_app
prepare_profile_base = live_common.prepare_profile_base
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
wait_for_requested_networks = rest_api_smoke.wait_for_requested_networks
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready
write_json = live_common.write_json


def build_parser() -> argparse.ArgumentParser:
    """Builds the aMuTorrent eMuleBB full UI live parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--api-key", default="amutorrent-emulebb-ui-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--rest-webserver-scheme", choices=["http", "https"], default="https")
    parser.add_argument("--p2p-bind-interface-name", default=live_common.DEFAULT_P2P_BIND_INTERFACE_NAME)
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--live-wire-inputs-file", default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)))
    return parser


def fetch_page_json(page: Any, path: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one same-origin browser fetch and returns status plus parsed payload."""

    return amutorrent_clean.fetch_page_json(page, path, method, body)


def require_browser_http_ok(name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Returns a browser fetch payload or raises with diagnostic context."""

    return amutorrent_clean.require_browser_http_ok(name, result)


def resolve_live_wire_inputs_path(repo_root: Path, raw_path: str | None) -> Path:
    """Resolves live-wire inputs from repo-relative or workspace-relative paths."""

    return amutorrent_clean.resolve_clean_live_wire_inputs_path(repo_root, raw_path)


def npm_command_for_node(node_path: Path) -> str:
    """Returns the npm executable paired with the selected Node runtime."""

    npm_path = node_path.with_name("npm.cmd" if os.name == "nt" else "npm")
    if npm_path.exists():
        return str(npm_path)
    return "npm.cmd" if os.name == "nt" else "npm"


def build_and_verify_frontend_bundle(amutorrent_root: Path, node_path: Path) -> dict[str, Any]:
    """Rebuilds the generated aMuTorrent frontend bundle and verifies UI hooks."""

    npm = npm_command_for_node(node_path)
    env = dict(os.environ)
    if node_path.is_absolute():
        env["PATH"] = str(node_path.parent) + os.pathsep + env.get("PATH", "")
    completed = subprocess.run(
        [npm, "run", "build"],
        cwd=str(amutorrent_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    output_tail = (completed.stdout + completed.stderr)[-4000:]
    if completed.returncode != 0:
        raise RuntimeError(f"aMuTorrent frontend bundle build failed with exit code {completed.returncode}: {output_tail}")

    bundle_path = amutorrent_root / "static" / "dist" / "app.bundle.js"
    if not bundle_path.is_file():
        raise RuntimeError(f"aMuTorrent frontend bundle was not created: {bundle_path}")
    bundle_text = bundle_path.read_text(encoding="utf-8", errors="replace")
    missing = [hook for hook in REQUIRED_BUNDLE_HOOKS if hook not in bundle_text]
    if missing:
        raise RuntimeError(f"aMuTorrent frontend bundle is missing required UI hooks: {missing}")
    return {
        "bundle_path": str(bundle_path),
        "bundle_size_bytes": bundle_path.stat().st_size,
        "required_hooks": list(REQUIRED_BUNDLE_HOOKS),
        "build_output_tail": output_tail,
    }


def ed2k_link_from_transfer(row: dict[str, object]) -> str:
    """Builds a direct ED2K link from one validated live-wire transfer row."""

    transfer_hash = str(row["hash"]).strip().lower()
    name = str(row["name"]).strip()
    size = int(row["size"])
    return f"ed2k://|file|{name}|{size}|{transfer_hash}|/"


def first_direct_ed2k_link(inputs: live_wire_inputs.LiveWireInputs) -> tuple[str, str]:
    """Returns the first operator-provided direct ED2K bootstrap link and hash."""

    if inputs.direct_bootstrap_transfers:
        row = dict(inputs.direct_bootstrap_transfers[0])
        return ed2k_link_from_transfer(row), str(row["hash"]).strip().lower()
    return f"ed2k://|file|amutorrent-ui-smoke.bin|1|{SYNTHETIC_ED2K_HASH}|/", SYNTHETIC_ED2K_HASH


def install_browser_diagnostics(page: Any, diagnostics: dict[str, list[dict[str, Any]]]) -> None:
    """Attaches Playwright diagnostics collectors to one page."""

    page.on("console", lambda message: diagnostics["console_errors"].append({"type": message.type, "text": message.text, "location": message.location}) if message.type == "error" else None)
    page.on("pageerror", lambda error: diagnostics["page_errors"].append({"text": str(error)}))
    page.on("requestfailed", lambda request: diagnostics["request_failures"].append({"failure": str(request.failure), "method": request.method, "resource_type": request.resource_type, "url": request.url}))


def assert_no_unexpected_browser_diagnostics(diagnostics: dict[str, list[dict[str, Any]]]) -> None:
    """Fails the UI proof when the browser reports console, page, or request errors."""

    unexpected = {
        "console_errors": list(diagnostics.get("console_errors", [])),
        "page_errors": list(diagnostics.get("page_errors", [])),
        "request_failures": list(diagnostics.get("request_failures", [])),
    }
    if any(unexpected.values()):
        raise RuntimeError(f"aMuTorrent eMuleBB UI browser diagnostics were not clean: {unexpected!r}")


def click_visible_test_id(page: Any, test_id: str) -> None:
    """Clicks the first visible element matching a data-testid hook."""

    clicked = page.evaluate(
        """(testId) => {
            const nodes = Array.from(document.querySelectorAll(`[data-testid="${testId}"]`));
            const node = nodes.find(element => {
                const rect = element.getBoundingClientRect();
                const style = window.getComputedStyle(element);
                return rect.width > 0
                    && rect.height > 0
                    && style.display !== 'none'
                    && style.visibility !== 'hidden'
                    && style.pointerEvents !== 'none';
            });
            if (!node) {
                return false;
            }
            node.click();
            return true;
        }""",
        test_id,
    )
    if not clicked:
        raise RuntimeError(f"Could not find a visible element with data-testid={test_id!r}.")


def click_visible_button_containing_text(page: Any, text: str) -> None:
    """Clicks the first visible button whose text content contains a label."""

    clicked = page.evaluate(
        """(text) => {
            const nodes = Array.from(document.querySelectorAll('button'));
            const node = nodes.find(element => {
                const rect = element.getBoundingClientRect();
                const style = window.getComputedStyle(element);
                return element.textContent.includes(text)
                    && rect.width > 0
                    && rect.height > 0
                    && style.display !== 'none'
                    && style.visibility !== 'hidden'
                    && style.pointerEvents !== 'none';
            });
            if (!node) {
                return false;
            }
            node.click();
            return true;
        }""",
        text,
    )
    if not clicked:
        raise RuntimeError(f"Could not find a visible button containing text {text!r}.")


def dismiss_first_run_version_modal(page: Any) -> bool:
    """Dismisses aMuTorrent's post-setup version modal when it appears."""

    continue_button = page.get_by_role("button", name="Continue")
    try:
        continue_button.wait_for(timeout=5000)
    except Exception:
        return False
    continue_button.click()
    try:
        continue_button.wait_for(state="detached", timeout=15000)
    except Exception:
        continue_button.wait_for(state="hidden", timeout=15000)
    return True


def navigate_and_verify_views(page: Any) -> list[dict[str, str]]:
    """Navigates every major eMuleBB integration view and verifies its root hook."""

    view_names = ("home", "search", "downloads", "shared", "uploads", "servers", "logs", "statistics", "history", "settings")
    visited: list[dict[str, str]] = []
    for view in view_names:
        page.locator(f'[data-testid="nav-{view}"]').first.wait_for(timeout=30000)
        click_visible_test_id(page, f"nav-{view}")
        page.locator(f'[data-testid="view-{view}"]').wait_for(timeout=15000)
        visited.append({"view": view, "hook": f"view-{view}"})
    return visited


def wait_for_snapshot_item(page: Any, transfer_hash: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until a transfer hash appears in aMuTorrent's unified snapshot."""

    expected = transfer_hash.lower()

    def resolve() -> dict[str, Any] | None:
        snapshot = fetch_page_json(page, "/api/v1/data/snapshot")
        payload = require_browser_http_ok("snapshot-item", snapshot)
        data = payload.get("data")
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise RuntimeError(f"aMuTorrent snapshot did not contain an item list: {snapshot!r}")
        for item in items:
            if isinstance(item, dict) and str(item.get("hash") or item.get("fileHash") or "").lower() == expected:
                return item
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description=f"aMuTorrent snapshot item {expected}")


def wait_for_snapshot_category(page: Any, transfer_hash: str, category_name: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits until a transfer has the expected unified category name."""

    expected_hash = transfer_hash.lower()

    def resolve() -> dict[str, Any] | None:
        item = wait_for_snapshot_item(page, expected_hash, timeout_seconds=5.0)
        return item if item.get("category") == category_name else None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description=f"aMuTorrent category {category_name!r}")


def wait_for_emule_category(
    *,
    emule_base_url: str,
    api_key: str,
    category_name: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Waits until eMuleBB REST reports a category created through aMuTorrent."""

    expected = category_name.strip().lower()

    def resolve() -> dict[str, Any] | None:
        result = rest_api_smoke.http_request(emule_base_url, "/api/v1/categories", api_key=api_key)
        payload = result.get("json")
        if payload is None:
            payload = result.get("payload")
        data = payload.get("data") if isinstance(payload, dict) and "data" in payload else payload
        rows = data.get("items") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise RuntimeError(f"eMuleBB category response did not contain a category list: {result!r}")
        matching = [
            row
            for row in rows
            if isinstance(row, dict) and str(row.get("name") or row.get("title") or "").strip().lower() == expected
        ]
        if not matching:
            return None
        return {
            "status": result.get("status"),
            "category_count": len(rows),
            "category": {
                "id": matching[0].get("id"),
                "name": matching[0].get("name") or matching[0].get("title"),
                "path_present": bool(matching[0].get("path")),
            },
        }

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description=f"eMuleBB category {category_name!r}")


def wait_for_enabled_test_id(page: Any, test_id: str, timeout_seconds: float = 15.0) -> None:
    """Waits for a visible, enabled element with a data-testid hook."""

    page.wait_for_function(
        """(testId) => {
            const nodes = Array.from(document.querySelectorAll(`[data-testid="${testId}"]`));
            return nodes.some(element => {
                const rect = element.getBoundingClientRect();
                const style = window.getComputedStyle(element);
                return rect.width > 0
                    && rect.height > 0
                    && style.display !== 'none'
                    && style.visibility !== 'hidden'
                    && !element.disabled;
            });
        }""",
        arg=test_id,
        timeout=timeout_seconds * 1000,
    )


def ensure_downloads_view(page: Any) -> None:
    """Navigates to the visible downloads view."""

    click_visible_test_id(page, "nav-downloads")
    page.locator('[data-testid="view-downloads"]').wait_for(timeout=15000)


def exit_download_selection_mode_if_active(page: Any) -> bool:
    """Exits downloads selection mode when visible checkboxes are present."""

    if page.locator('[data-testid="emulebb-downloads-select-checkbox"]:visible').count() == 0:
        return False
    click_visible_test_id(page, "emulebb-downloads-select-mode")
    page.locator('[data-testid="emulebb-downloads-select-checkbox"]:visible').first.wait_for(state="detached", timeout=15000)
    return True


def select_download_transfer(page: Any, transfer_hash: str) -> dict[str, Any]:
    """Enables selection mode and selects one visible transfer by hash."""

    ensure_downloads_view(page)
    if page.locator('[data-testid="emulebb-downloads-select-checkbox"]:visible').count() == 0:
        click_visible_test_id(page, "emulebb-downloads-select-mode")
    selector = f'[data-testid="emulebb-downloads-select-checkbox"][data-file-hash="{transfer_hash.lower()}"]:visible'
    checkbox = page.locator(selector).first
    checkbox.wait_for(timeout=15000)
    if not checkbox.is_checked():
        checkbox.check()
    return {"selector": selector, "checked": checkbox.is_checked()}


def delete_transfer(page: Any, *, transfer_hash: str, instance_id: str, file_name: str, timeout_seconds: float) -> dict[str, Any]:
    """Deletes one harness-created eMuleBB transfer and verifies it disappears."""

    delete_result = fetch_page_json(
        page,
        "/api/v1/downloads/delete",
        "POST",
        {
            "items": [
                {
                    "fileHash": transfer_hash.lower(),
                    "clientType": "emulebb",
                    "instanceId": instance_id,
                    "fileName": file_name,
                }
            ],
            "deleteFiles": True,
            "source": "downloads",
        },
    )
    require_browser_http_ok("delete-harness-transfer", delete_result)
    cleanup_snapshot = amutorrent_resilience.wait_for_transfer_absent(page, transfer_hash, timeout_seconds)
    return {"delete": delete_result, "cleanup_snapshot_status": cleanup_snapshot.get("status")}


def cleanup_category(page: Any, category_name: str) -> dict[str, Any]:
    """Deletes a temporary category created by the live UI proof."""

    result = fetch_page_json(page, "/api/v1/categories", "DELETE", {"name": category_name})
    try:
        require_browser_http_ok("delete-temporary-category", result)
    except RuntimeError as exc:
        return {"status": result.get("status"), "error": str(exc)}
    return {"status": result.get("status"), "payload": result.get("payload")}


def run_visible_transfer_actions(
    page: Any,
    *,
    emule_base_url: str,
    api_key: str,
    transfer_hash: str,
    instance_id: str,
    file_name: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Exercises visible transfer actions on one live eMuleBB download."""

    batch_state: dict[str, Any] = {}
    select_download_transfer(page, transfer_hash)

    for action_name, test_id in (
        ("pause", "emulebb-downloads-pause-selected"),
        ("resume", "emulebb-downloads-resume-selected"),
        ("stop", "emulebb-downloads-stop-selected"),
        ("resume_after_stop", "emulebb-downloads-resume-selected"),
    ):
        wait_for_enabled_test_id(page, test_id)
        click_visible_test_id(page, test_id)
        item = wait_for_snapshot_item(page, transfer_hash, timeout_seconds)
        batch_state[action_name] = {
            "status": item.get("status"),
            "client": item.get("client"),
            "progress": item.get("progress"),
        }

    category_name = f"E2E Release Proof {transfer_hash[:8]}"
    click_visible_test_id(page, "emulebb-downloads-category-selected")
    page.locator('[data-testid="file-category-modal"]').wait_for(timeout=15000)
    page.locator('[data-testid="file-category-select"]').select_option("__custom__")
    page.locator('[data-testid="file-category-custom-input"]').fill(category_name)
    click_visible_test_id(page, "file-category-submit")
    page.locator('[data-testid="file-category-modal"]').wait_for(state="detached", timeout=15000)
    categorized = wait_for_snapshot_category(page, transfer_hash, category_name, timeout_seconds)
    emule_category = wait_for_emule_category(
        emule_base_url=emule_base_url,
        api_key=api_key,
        category_name=category_name,
        timeout_seconds=timeout_seconds,
    )

    exit_download_selection_mode_if_active(page)
    page.locator(f'[data-testid="item-file-name"][data-file-hash="{transfer_hash.lower()}"]:visible').first.click()
    page.locator('[data-testid="file-info-modal"]').wait_for(timeout=15000)
    file_info_variant = page.locator('[data-testid="file-info-modal"]').get_attribute("data-variant")
    click_visible_test_id(page, "file-info-close")
    page.locator('[data-testid="file-info-modal"]').wait_for(state="detached", timeout=15000)

    select_download_transfer(page, transfer_hash)
    click_visible_test_id(page, "emulebb-downloads-delete-selected")
    page.locator('[data-testid="delete-confirm-modal"]').wait_for(timeout=15000)
    click_visible_test_id(page, "delete-confirm-cancel")
    page.locator('[data-testid="delete-confirm-modal"]').wait_for(state="detached", timeout=15000)
    still_present = wait_for_snapshot_item(page, transfer_hash, timeout_seconds)

    click_visible_test_id(page, "emulebb-downloads-delete-selected")
    page.locator('[data-testid="delete-confirm-modal"]').wait_for(timeout=15000)
    click_visible_test_id(page, "delete-confirm-submit")
    deleted_snapshot = amutorrent_resilience.wait_for_transfer_absent(page, transfer_hash, timeout_seconds)

    history_result = fetch_page_json(page, "/api/history?limit=50")
    history_payload = require_browser_http_ok("history-after-delete", history_result)
    history_rows = history_payload.get("entries") or history_payload.get("data") or history_payload.get("items") or history_payload.get("history") or []
    history_hash_present = any(
        isinstance(row, dict) and str(row.get("hash") or row.get("fileHash") or "").lower() == transfer_hash.lower()
        for row in history_rows
    ) if isinstance(history_rows, list) else False
    click_visible_test_id(page, "nav-history")
    page.locator('[data-testid="view-history"]').wait_for(timeout=15000)

    return {
        "batch_actions": batch_state,
        "category": {
            "name": category_name,
            "snapshot_category": categorized.get("category"),
            "emule_rest_category": emule_category,
            "cleanup": cleanup_category(page, category_name),
        },
        "file_info": {"variant": file_info_variant},
        "delete_cancel_preserved_transfer": str(still_present.get("hash") or "").lower() == transfer_hash.lower(),
        "delete_confirm_removed_transfer": deleted_snapshot.get("status"),
        "history": {
            "status": history_result.get("status"),
            "rows": len(history_rows) if isinstance(history_rows, list) else None,
            "hash_present": history_hash_present,
        },
        "file_name_present": bool(file_name),
        "instance_id": instance_id,
    }


def run_supporting_visible_views(page: Any, *, instance_id: str) -> dict[str, Any]:
    """Exercises supporting visible eMuleBB UI surfaces beyond downloads/search."""

    checks: dict[str, Any] = {}

    click_visible_test_id(page, "nav-shared")
    page.locator('[data-testid="view-shared"]').wait_for(timeout=15000)
    wait_for_enabled_test_id(page, "shared-dirs-open")
    click_visible_test_id(page, "shared-dirs-open")
    page.locator('[data-testid="shared-dirs-modal"]').wait_for(timeout=15000)
    wait_for_enabled_test_id(page, "shared-dirs-rescan")
    click_visible_test_id(page, "shared-dirs-rescan")
    page.locator('[data-testid="shared-dirs-modal"]').wait_for(timeout=15000)
    click_visible_test_id(page, "shared-dirs-close")
    page.locator('[data-testid="shared-dirs-modal"]').wait_for(state="detached", timeout=15000)
    checks["shared_dirs_modal"] = {"opened": True, "rescan_clicked": True}

    click_visible_test_id(page, "nav-servers")
    page.locator('[data-testid="view-servers"]').wait_for(timeout=15000)
    wait_for_enabled_test_id(page, "emulebb-servers-refresh")
    click_visible_test_id(page, "emulebb-servers-refresh")
    servers = require_browser_http_ok("servers-visible-refresh", fetch_page_json(page, f"/api/v1/ed2k/servers?instanceId={instance_id}"))
    server_rows = servers.get("data") or servers.get("items") or []
    checks["servers"] = {"refresh_clicked": True, "rows": len(server_rows) if isinstance(server_rows, list) else None}

    click_visible_test_id(page, "nav-statistics")
    page.locator('[data-testid="view-statistics"]').wait_for(timeout=15000)
    wait_for_enabled_test_id(page, "stats-tree-open")
    click_visible_test_id(page, "stats-tree-open")
    page.locator('[data-testid="stats-tree-modal"]').wait_for(timeout=15000)
    checks["stats_tree"] = {"instance_id": page.locator('[data-testid="stats-tree-modal"]').get_attribute("data-instance-id")}
    page.keyboard.press("Escape")
    page.locator('[data-testid="stats-tree-modal"]').wait_for(state="detached", timeout=15000)

    click_visible_test_id(page, "nav-logs")
    page.locator('[data-testid="view-logs"]').wait_for(timeout=15000)
    page.locator('[data-testid="app-logs-section"]').wait_for(timeout=15000)
    page.locator('[data-testid="app-logs-records"]').wait_for(timeout=15000)
    page.locator('[data-testid="client-log-section-emulebb-logs"]').wait_for(timeout=15000)
    checks["logs"] = {"app_logs_visible": True, "emulebb_logs_visible": True}

    return checks


def run_visible_search_download(
    page: Any,
    *,
    emule_base_url: str,
    api_key: str,
    instance_id: str,
    inputs: live_wire_inputs.LiveWireInputs,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Runs a live eMuleBB search and download through visible aMuTorrent controls."""

    term_index, query = live_wire_inputs.select_daily(inputs.generic_open_terms)
    click_visible_test_id(page, "nav-search")
    page.locator('[data-testid="view-search"]').wait_for(timeout=15000)
    page.locator('[data-testid="emulebb-search-type-server"]').click()
    page.locator('[data-testid="emulebb-search-query"]').fill(query)
    page.locator('[data-testid="emulebb-search-submit"]').click()

    candidate, observations = amutorrent_clean.wait_for_amutorrent_search_candidate(
        page,
        instance_id=instance_id,
        search_type="server",
        timeout_seconds=timeout_seconds,
    )
    transfer_hash = str(candidate.get("fileHash") or candidate.get("hash") or "").strip().lower()
    file_name = str(candidate.get("fileName") or candidate.get("name") or "amutorrent-live-transfer").strip()
    checkbox = page.locator(f'[data-testid="emulebb-search-result-checkbox"][data-file-hash="{transfer_hash}"]:visible').first
    checkbox.wait_for(timeout=15000)
    checkbox.check()
    page.locator('[data-testid="emulebb-search-download-selected"]').click()

    materialized = amutorrent_clean.wait_for_emule_transfer_materialized(
        emule_base_url=emule_base_url,
        api_key=api_key,
        transfer_hash=transfer_hash,
        timeout_seconds=timeout_seconds,
    )
    snapshot_item = wait_for_snapshot_item(page, transfer_hash, timeout_seconds)
    visible_actions = run_visible_transfer_actions(
        page,
        emule_base_url=emule_base_url,
        api_key=api_key,
        transfer_hash=transfer_hash,
        instance_id=instance_id,
        file_name=file_name,
        timeout_seconds=timeout_seconds,
    )
    return {
        "term_selection": live_wire_inputs.redact_term_selection(term_index, inputs.generic_open_terms, source="generic_open"),
        "candidate": amutorrent_clean.summarize_amutorrent_candidate(candidate),
        "search_observations": observations,
        "transfer_materialization": materialized,
        "snapshot_item": {
            "client": snapshot_item.get("client"),
            "status": snapshot_item.get("status"),
            "progress": snapshot_item.get("progress"),
            "has_detail_hydration": isinstance(snapshot_item.get("partStatus"), list) and isinstance(snapshot_item.get("peers"), list),
        },
        "visible_actions": visible_actions,
    }


def run_add_download_modal(
    page: Any,
    *,
    inputs: live_wire_inputs.LiveWireInputs,
    instance_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Adds one direct ED2K link through the visible Add Download modal."""

    link, transfer_hash = first_direct_ed2k_link(inputs)
    click_visible_test_id(page, "nav-downloads")
    page.locator('[data-testid="view-downloads"]').wait_for(timeout=15000)
    click_visible_test_id(page, "emulebb-downloads-add")
    page.locator('[data-testid="emulebb-add-download-modal"]').wait_for(timeout=15000)
    page.locator('[data-testid="emulebb-add-download-links"]').fill(link)
    page.locator('[data-testid="emulebb-add-download-submit"]').click()
    item = wait_for_snapshot_item(page, transfer_hash, timeout_seconds)
    cleanup = delete_transfer(
        page,
        transfer_hash=transfer_hash,
        instance_id=instance_id,
        file_name=str(item.get("name") or "amutorrent-ui-smoke.bin"),
        timeout_seconds=timeout_seconds,
    )
    return {
        "hash_present": bool(transfer_hash),
        "snapshot_item": {"client": item.get("client"), "status": item.get("status"), "progress": item.get("progress")},
        "cleanup": cleanup,
    }


def run_supporting_endpoint_checks(page: Any, *, instance_id: str) -> dict[str, Any]:
    """Checks eMuleBB supporting surfaces used by diagnostics views."""

    checks = {
        "servers": fetch_page_json(page, f"/api/v1/ed2k/servers?instanceId={instance_id}"),
        "server_info": fetch_page_json(page, f"/api/v1/ed2k/server-info?instanceId={instance_id}"),
        "stats_tree": fetch_page_json(page, f"/api/v1/ed2k/stats-tree?instanceId={instance_id}"),
        "app_logs": fetch_page_json(page, "/api/v1/logs/app"),
        "ed2k_logs": fetch_page_json(page, f"/api/v1/logs/ed2k?instanceId={instance_id}"),
        "metrics_dashboard": fetch_page_json(page, "/api/metrics/dashboard?range=24h"),
        "history": fetch_page_json(page, "/api/history?limit=20"),
        "shared_refresh": fetch_page_json(page, "/api/v1/ed2k/refresh-shared", "POST", {"instanceId": instance_id}),
    }
    for name, result in checks.items():
        require_browser_http_ok(name, result)
    return {name: {"status": result.get("status")} for name, result in checks.items()}


def run_mobile_keyboard_pass(page: Any, artifacts_dir: Path) -> dict[str, Any]:
    """Runs a compact mobile viewport and keyboard/modal smoke."""

    page.set_viewport_size({"width": 390, "height": 844})
    page.locator('[data-testid="view-downloads"]').wait_for(timeout=15000)
    page.keyboard.press("Tab")
    focused_tag = page.evaluate("document.activeElement ? document.activeElement.tagName : null")
    click_visible_test_id(page, "emulebb-downloads-add")
    page.locator('[data-testid="emulebb-add-download-modal"]').wait_for(timeout=15000)
    click_visible_test_id(page, "emulebb-add-download-cancel")
    page.locator('[data-testid="emulebb-add-download-modal"]').wait_for(state="detached", timeout=15000)
    screenshot = artifacts_dir / "amutorrent-emulebb-ui-mobile.png"
    page.screenshot(path=str(screenshot), full_page=True)
    page.set_viewport_size({"width": 1366, "height": 900})
    return {"viewport": "390x844", "keyboard_focus_tag": focused_tag, "cancel_closed_modal": True, "screenshot": str(screenshot)}


def run_browser_ui_workflows(
    *,
    base_url: str,
    emule_base_url: str,
    api_key: str,
    instance_id: str,
    inputs: live_wire_inputs.LiveWireInputs,
    artifacts_dir: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Runs full visible aMuTorrent eMuleBB browser workflows."""

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("Playwright is required for the aMuTorrent eMuleBB UI live proof.") from exc

    checks: dict[str, Any] = {
        "screenshots": {},
        "browser_diagnostics": {"console_errors": [], "page_errors": [], "request_failures": []},
    }
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1366, "height": 900})
        install_browser_diagnostics(page, checks["browser_diagnostics"])
        try:
            page.goto(base_url, wait_until="domcontentloaded", timeout=30000)
            checks["dismissed_version_modal"] = dismiss_first_run_version_modal(page)
            page.locator('[data-testid="view-home"]').wait_for(timeout=30000)
            checks["view_navigation"] = navigate_and_verify_views(page)
            checks["settings_emulebb_card_visible"] = page.locator('[data-testid="client-card-emulebb"]').count() > 0
            if not checks["settings_emulebb_card_visible"]:
                click_visible_button_containing_text(page, "Download Clients")
                page.locator('[data-testid="client-card-emulebb"]').wait_for(timeout=15000)
                checks["settings_emulebb_card_visible"] = True
            checks["supporting_endpoints"] = run_supporting_endpoint_checks(page, instance_id=instance_id)
            checks["supporting_visible_views"] = run_supporting_visible_views(page, instance_id=instance_id)
            checks["visible_search_download"] = run_visible_search_download(
                page,
                emule_base_url=emule_base_url,
                api_key=api_key,
                instance_id=instance_id,
                inputs=inputs,
                timeout_seconds=timeout_seconds,
            )
            checks["add_download_modal"] = run_add_download_modal(
                page,
                inputs=inputs,
                instance_id=instance_id,
                timeout_seconds=timeout_seconds,
            )
            checks["mobile_keyboard"] = run_mobile_keyboard_pass(page, artifacts_dir)
            final = artifacts_dir / "amutorrent-emulebb-ui-final.png"
            page.screenshot(path=str(final), full_page=True)
            checks["screenshots"]["final"] = str(final)
            assert_no_unexpected_browser_diagnostics(checks["browser_diagnostics"])
            return checks
        except Exception:
            failure = artifacts_dir / "amutorrent-emulebb-ui-failure.png"
            try:
                page.screenshot(path=str(failure), full_page=True)
                checks["screenshots"]["failure"] = str(failure)
            except Exception:
                pass
            raise
        finally:
            browser.close()


def main() -> int:
    """Runs the full aMuTorrent eMuleBB live UI E2E proof."""

    args = build_parser().parse_args()
    inputs = live_wire_inputs.load_live_wire_inputs(
        resolve_live_wire_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="amutorrent-emulebb-ui-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    workspace_repo_root = amutorrent_smoke.find_workspace_repo_root(paths.workspace_root)
    amutorrent_root = workspace_repo_root / "repos" / "amutorrent"
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    node_info = amutorrent_smoke.resolve_amutorrent_node()

    emule_port = choose_listen_port()
    amutorrent_port = choose_listen_port()
    if emule_port == amutorrent_port:
        amutorrent_port = choose_listen_port()
    rest_scheme = amutorrent_clean.normalize_rest_scheme(args.rest_webserver_scheme)
    emule_base_url = f"{rest_scheme}://127.0.0.1:{emule_port}"
    amutorrent_base_url = f"http://127.0.0.1:{amutorrent_port}"
    instance_id = f"emulebb-127.0.0.1-{emule_port}"
    artifacts_dir = paths.source_artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    amutorrent_data_dir = artifacts_dir / "amutorrent-emulebb-ui-data"
    rest_transport = amutorrent_clean.prepare_rest_transport(
        scheme=rest_scheme,
        app_exe=paths.app_exe,
        artifacts_dir=artifacts_dir,
    )
    rest_api_smoke.configure_https_trust(str(rest_transport["node_extra_ca_cert"]) or None)

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="amutorrent-emulebb-ui-live")
    amutorrent_session.configure_session_profile(
        Path(profile["config_dir"]),
        paths.app_exe,
        args.api_key,
        emule_port,
        args.bind_addr,
        args.p2p_bind_interface_name,
        live_network=True,
        use_https=bool(rest_transport["use_https"]),
        https_certificate=str(rest_transport["https_material"]["certificate"]) if rest_transport["https_material"] else "",
        https_key=str(rest_transport["https_material"]["key"]) if rest_transport["https_material"] else "",
    )

    report: dict[str, Any] = {
        "suite": "amutorrent-emulebb-ui-live",
        "status": "failed",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "configuration": args.configuration,
        "p2p_bind_interface_name": args.p2p_bind_interface_name,
        "enable_upnp": True,
        "rest_webserver_scheme": rest_transport["scheme"],
        "emule_base_url": emule_base_url,
        "amutorrent_base_url": amutorrent_base_url,
        "profile_base": str(profile["profile_base"]),
        "config_dir": str(profile["config_dir"]),
        "amutorrent_root": str(amutorrent_root),
        "amutorrent_data_dir": str(amutorrent_data_dir),
        "https_material": rest_transport["https_material"],
        "live_wire_inputs_file": str(inputs.path),
        "live_wire_inputs": {
            "generic_open": live_wire_inputs.summarize_terms(inputs.generic_open_terms),
            "direct_bootstrap_transfers": live_wire_inputs.summarize_direct_transfers(inputs.direct_bootstrap_transfers),
        },
        "node": node_info,
        "checks": {},
        "cleanup": {},
    }
    app = None
    amutorrent: subprocess.Popen[str] | None = None
    amutorrent_output = None
    amutorrent_log_path = artifacts_dir / "amutorrent-server.log"
    pending_error: Exception | None = None
    try:
        amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
        node_path = Path(str(node_info["path"]))
        report["checks"]["amutorrent_frontend_bundle"] = build_and_verify_frontend_bundle(amutorrent_root, node_path)
        app = launch_app(paths.app_exe, Path(profile["profile_base"]))
        report["emule_process_id"] = get_app_process_id(app)
        main_window = wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        report["checks"]["emule_rest_ready"] = wait_for_rest_ready(emule_base_url, args.api_key, args.ready_timeout_seconds)
        report["checks"]["emule_network_ready"] = wait_for_requested_networks(
            emule_base_url,
            args.api_key,
            args.network_ready_timeout_seconds,
            require_server_connected=True,
            require_kad_connected=False,
        )

        env = amutorrent_clean.build_clean_amutorrent_environment(
            base_env=os.environ,
            amutorrent_port=amutorrent_port,
            node_path=node_path,
            data_dir=amutorrent_data_dir,
            extra_ca_cert=str(rest_transport["node_extra_ca_cert"]),
        )
        amutorrent_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
        amutorrent = subprocess.Popen(
            [str(node_path), "server/server.js"],
            cwd=str(amutorrent_root),
            env=env,
            stdout=amutorrent_output,
            stderr=subprocess.STDOUT,
        )
        amutorrent_smoke.wait_for_http_ok(f"{amutorrent_base_url}/api/config/status", args.ready_timeout_seconds)
        report["amutorrent_process_id"] = amutorrent.pid
        report["checks"]["wizard"] = amutorrent_clean.drive_first_run_wizard(
            base_url=amutorrent_base_url,
            emule_host="127.0.0.1",
            emule_port=emule_port,
            api_key=args.api_key,
            use_ssl=bool(rest_transport["use_https"]),
            artifacts_dir=artifacts_dir,
            timeout_seconds=args.ready_timeout_seconds,
        )
        report["checks"]["browser_ui_workflows"] = run_browser_ui_workflows(
            base_url=amutorrent_base_url,
            emule_base_url=emule_base_url,
            api_key=args.api_key,
            instance_id=instance_id,
            inputs=inputs,
            artifacts_dir=artifacts_dir,
            timeout_seconds=args.search_observation_timeout_seconds,
        )
        report["status"] = "passed"
    except Exception as exc:
        pending_error = exc
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if amutorrent is not None:
            amutorrent.terminate()
            try:
                amutorrent.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                amutorrent.kill()
                amutorrent.communicate(timeout=10)
        if amutorrent_output is not None:
            amutorrent_output.close()
            report["cleanup"]["amutorrent_log"] = str(amutorrent_log_path)
            if amutorrent_log_path.exists():
                report["cleanup"]["amutorrent_output_tail"] = amutorrent_log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        if app is not None:
            try:
                close_app_cleanly(app)
                report["cleanup"]["emule_closed"] = True
            except Exception as exc:
                app.kill()
                report["cleanup"]["emule_closed"] = False
                report["cleanup"]["emule_killed"] = True
                report["cleanup"]["emule_close_error"] = repr(exc)
        write_json(artifacts_dir / "amutorrent-emulebb-ui-live-result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        if not args.keep_artifacts:
            harness_cli_common.cleanup_source_artifacts(paths)
    if pending_error is not None:
        raise pending_error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
