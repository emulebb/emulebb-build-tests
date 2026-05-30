"""Runs the isolated live auto-browse validation against real eD2K/Kad peers."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
rest_smoke = load_local_module("rest_api_smoke", "rest-api-smoke.py")
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")

close_app_cleanly = live_common.close_app_cleanly
launch_app = live_common.launch_app
prepare_profile_base = live_common.prepare_profile_base
wait_for_main_window = live_common.wait_for_main_window
write_json = live_common.write_json
live_wire_inputs = rest_smoke.live_wire_inputs

BOOTSTRAP_SEARCH_METHODS = ("server", "global", "automatic", "kad")
FALLBACK_SEARCH_METHODS = ("server", "global", "kad", "automatic")
LIVE_SOURCE_UNAVAILABLE_EXIT_CODE = 2
PREFERRED_SERVER_ADDRESSES = ("91.148.135.252", "45.82.80.155", "91.148.135.254")
DEFAULT_NATURAL_AUTO_BROWSE_TIMEOUT_SECONDS = 180.0
DEFAULT_FALLBACK_AUTO_BROWSE_TIMEOUT_SECONDS = 300.0
DEFAULT_DIRECT_BOOTSTRAP_SOURCE_TIMEOUT_SECONDS = 180.0
DEFAULT_SOURCE_BROWSE_TRANSFER_TIMEOUT_SECONDS = 120.0
DEFAULT_SOURCE_BROWSE_ATTEMPT_TIMEOUT_SECONDS = 20.0
DEFAULT_SOURCE_BROWSE_READY_SOURCE_TIMEOUT_SECONDS = 60.0
SOURCE_BROWSE_READY_STATES = {
    "connected",
    "downloading",
    "noneededparts",
    "onqueue",
    "remotequeuefull",
    "reqhashset",
}


class LiveSourceUnavailableError(RuntimeError):
    """Raised when live networks are reachable but no sourced transfer can be acquired."""


class TransferCandidateUnavailableError(RuntimeError):
    """Raised when one live transfer-search plan cannot produce a safe result."""

    def __init__(self, message: str, attempts: list[dict[str, object]]) -> None:
        super().__init__(message)
        self.attempts = attempts


def compact_http_result(result: dict[str, object]) -> dict[str, object]:
    """Keeps stored HTTP results small and stable in artifacts."""

    return {
        "status": result.get("status"),
        "content_type": result.get("content_type"),
        "json": result.get("json"),
        "body_text": result.get("body_text"),
    }


def require_json_object(result: dict[str, object], expected_status: int) -> dict[str, Any]:
    """Asserts that one REST response returned the expected JSON object payload."""

    assert int(result["status"]) == expected_status, compact_http_result(result)
    payload = result.get("json")
    assert isinstance(payload, dict), compact_http_result(result)
    return payload


def checkpoint_report(artifacts_dir: Path, report: dict[str, object]) -> None:
    """Persists best-effort live progress so interrupted runs keep diagnostic context."""

    try:
        write_json(artifacts_dir / "auto-browse-live-result.partial.json", report)
    except Exception as exc:  # pragma: no cover - diagnostics must not mask the live failure
        (artifacts_dir / "result.partial.write-error.txt").write_text(repr(exc), encoding="utf-8")


def record_phase(artifacts_dir: Path, report: dict[str, object], phase: str) -> None:
    """Records one auto-browse live phase transition and flushes a partial report."""

    report["current_phase"] = phase
    history = report.setdefault("phase_history", [])
    assert isinstance(history, list)
    history.append({"phase": phase, "entered_at": round(time.time(), 3)})
    print(f"auto-browse-live phase: {phase}", flush=True)
    checkpoint_report(artifacts_dir, report)


def record_auto_browse_observation(
    artifacts_dir: Path,
    report: dict[str, object],
    check_name: str,
    observation: dict[str, object],
) -> None:
    """Stores the newest auto-browse polling state in the partial report."""

    checks = report.setdefault("checks", {})
    assert isinstance(checks, dict)
    check = checks.setdefault(check_name, {"observations": []})
    assert isinstance(check, dict)
    observations = check.setdefault("observations", [])
    assert isinstance(observations, list)
    observations.append(observation)
    del observations[:-20]
    check["last_observation"] = observation
    checkpoint_report(artifacts_dir, report)


def should_promote_cleanup_error(report_status: object, pending_error: Exception | None) -> bool:
    """Reports whether cleanup failure should become the process-level failure."""

    return pending_error is None and report_status == "passed"


def configure_auto_browse_profile(
    config_dir: Path,
    app_exe: Path,
    api_key: str,
    port: int,
    web_bind_addr: str,
) -> None:
    """Enables REST, auto-browse, and visible browse logging inside the isolated profile."""

    rest_smoke.configure_webserver_profile(
        config_dir=config_dir,
        app_exe=app_exe,
        api_key=api_key,
        port=port,
        bind_addr=web_bind_addr,
    )

    preferences_path = config_dir / "preferences.ini"
    text = live_common.read_ini_text(preferences_path)
    for key, value in (
        ("Autoconnect", "1"),
        ("Reconnect", "1"),
        ("NetworkED2K", "1"),
        ("NetworkKademlia", "1"),
        ("AutoBrowseRemoteShares", "1"),
        ("SaveLogToDisk", "1"),
        ("Verbose", "1"),
        ("FullVerbose", "1"),
    ):
        text = rest_smoke.upsert_ini_section_value(text, "eMule", key, value)
    live_common.write_utf16_ini_text(preferences_path, text)


def reorder_server_rows(server_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Moves previously successful live candidates to the front of the candidate list."""

    preferred: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    preferred_set = set(PREFERRED_SERVER_ADDRESSES)
    for row in server_rows:
        if str(row.get("address")) in preferred_set:
            preferred.append(row)
        else:
            remaining.append(row)
    preferred.sort(key=lambda row: PREFERRED_SERVER_ADDRESSES.index(str(row.get("address"))))
    return preferred + remaining


def build_ed2k_link(result_row: dict[str, Any]) -> str:
    """Builds one minimal ED2K file link from a REST search-result row."""

    raw_name = str(result_row.get("name") or "").strip()
    raw_hash = str(result_row.get("hash") or "").strip()
    raw_size = result_row.get("sizeBytes") or result_row.get("size")
    if not raw_name:
        raise ValueError("Search result row is missing a file name.")
    if not raw_hash:
        raise ValueError("Search result row is missing a file hash.")
    try:
        size_bytes = int(raw_size)
    except (TypeError, ValueError) as exc:
        raise ValueError("Search result row is missing a valid file size.") from exc
    if size_bytes <= 0:
        raise ValueError("Search result row must have a positive file size.")
    file_name = urllib.parse.quote(raw_name, safe="")
    return f"ed2k://|file|{file_name}|{size_bytes}|{raw_hash}|/"


def is_safe_download_result(result_row: dict[str, Any]) -> bool:
    """Rejects executable results so the live scenario never downloads `.exe` payloads from eMule."""

    file_name = str(result_row.get("name") or "").strip().lower()
    file_type = str(result_row.get("fileType") or "").strip().lower()
    return not file_name.endswith(".exe") and file_type not in {"program", "pro"}


def fetch_search_results(base_url: str, api_key: str, search_id: str) -> dict[str, Any]:
    """Fetches one search-results payload and validates the response shape."""

    result = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
    return require_json_object(result, 200)


def start_transfer_search(base_url: str, api_key: str, method: str, query: str) -> dict[str, object]:
    """Starts one file-oriented live search suitable for selecting a safe transfer."""

    response = rest_smoke.http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body={
            "query": query,
            "method": method,
            "type": "iso",
            "extension": "iso",
        },
    )
    return {
        "ok": int(response["status"]) == 200 and isinstance(response.get("json"), dict) and response["json"].get("id"),
        "attempts": [
            {
                "method": method,
                "request": {
                    "query": query,
                    "method": method,
                    "type": "iso",
                    "extension": "iso",
                },
                "response": response,
            }
        ],
        "selected_method": method if int(response["status"]) == 200 else None,
        "method_candidates": [method],
        "response": response,
    }


def wait_for_transfer_search_results(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Polls a transfer search until downloadable rows appear or the search completes empty."""

    deadline = time.time() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.time() < deadline:
        result = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        payload = require_json_object(result, 200)
        rows = payload.get("results")
        assert isinstance(rows, list), compact_http_result(result)
        snapshot = {
            "observed_at": round(time.time(), 3),
            "status": payload.get("status"),
            "result_count": len(rows),
        }
        observations.append(snapshot)
        if rows:
            return {
                "result": compact_http_result(result),
                "observations": observations,
                "terminal_state": payload.get("status"),
            }
        if payload.get("status") == "complete":
            return {
                "result": compact_http_result(result),
                "observations": observations,
                "terminal_state": "complete",
            }
        time.sleep(5.0)

    raise RuntimeError(f"Timed out waiting for transfer search results for search '{search_id}'.")


def find_transfer_candidate(
    base_url: str,
    api_key: str,
    *,
    query: str,
    method_candidates: list[str],
    observation_timeout_seconds: float,
) -> dict[str, object]:
    """Starts live searches until one query/method pair yields a downloadable result."""

    attempts: list[dict[str, object]] = []
    for method in method_candidates:
        search = start_transfer_search(base_url, api_key, method, query)
        attempt: dict[str, object] = {
            "query": query,
            "method": method,
            "start": search,
        }
        attempts.append(attempt)
        if not bool(search["ok"]):
            continue

        search_id = str(require_json_object(search["response"], 200)["id"])
        attempt["searchId"] = search_id
        try:
            attempt["activity"] = wait_for_transfer_search_results(
                base_url,
                api_key,
                search_id,
                observation_timeout_seconds,
            )
            payload = fetch_search_results(base_url, api_key, search_id)
            rows = payload.get("results")
            if not isinstance(rows, list) or not rows:
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                if row.get("hash") and row.get("name") and (row.get("sizeBytes") or row.get("size")) and is_safe_download_result(row):
                    attempt["result"] = row
                    return {
                        "selected": attempt,
                        "attempts": attempts,
                    }
        except Exception as exc:
            attempt["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        finally:
            attempt["stop"] = compact_http_result(rest_smoke.stop_live_search(base_url, api_key, search_id))

    raise TransferCandidateUnavailableError(
        f"No downloadable search result found via {method_candidates!r}.",
        attempts,
    )


def build_transfer_acquisition_plan(inputs) -> list[tuple[str, list[str]]]:
    """Returns the live-search plan used to find one safe sourced transfer."""

    plan = [(transfer_hash, list(BOOTSTRAP_SEARCH_METHODS)) for transfer_hash in inputs.bootstrap_transfer_hashes]
    plan.extend((query, list(FALLBACK_SEARCH_METHODS)) for query in inputs.generic_open_terms)
    return plan


def build_direct_bootstrap_transfer_plan(inputs) -> list[dict[str, Any]]:
    """Returns known safe ED2K links used when live keyword search is empty."""

    return [dict(candidate) for candidate in inputs.direct_bootstrap_transfers]


def summarize_selected_transfer_sources(acquisition_attempts: list[dict[str, object]]) -> dict[str, object]:
    """Extracts a compact source summary from the selected fallback transfer."""

    for item in acquisition_attempts:
        selected = item.get("selected")
        if not isinstance(selected, dict):
            continue
        result_row = selected.get("result")
        sources_ready = selected.get("sources_ready")
        sources: list[object] = []
        if isinstance(sources_ready, dict) and isinstance(sources_ready.get("sources"), list):
            sources = list(sources_ready["sources"])
        summary: dict[str, object] = {
            "query_present": bool(selected.get("query")),
            "method": selected.get("method"),
            "searchId": selected.get("searchId"),
            "source_count": len(sources),
            "sources": sources[:5],
        }
        if isinstance(result_row, dict):
            summary["hash_present"] = bool(result_row.get("hash"))
            summary["name_present"] = bool(result_row.get("name"))
            summary["size"] = result_row.get("sizeBytes") or result_row.get("size")
        return summary
    return {
        "source_count": 0,
        "sources": [],
    }


def get_selected_transfer_sources(acquisition_attempts: list[dict[str, object]]) -> list[object]:
    """Returns the full source list for the selected fallback transfer."""

    for item in acquisition_attempts:
        selected = item.get("selected")
        if not isinstance(selected, dict):
            continue
        sources_ready = selected.get("sources_ready")
        if isinstance(sources_ready, dict) and isinstance(sources_ready.get("sources"), list):
            return list(sources_ready["sources"])
    return []


def get_selected_transfer_hash(acquisition_attempt: dict[str, object]) -> str | None:
    """Returns the selected transfer hash from one acquisition record."""

    selected = acquisition_attempt.get("selected")
    if not isinstance(selected, dict):
        return None

    for payload_name in ("add_response", "result"):
        payload = selected.get(payload_name)
        if not isinstance(payload, dict):
            continue
        transfer_hash = payload.get("hash")
        if isinstance(transfer_hash, str) and transfer_hash.strip():
            return transfer_hash.strip().lower()
    return None


def summarize_transfer_acquisition_plan(inputs) -> dict[str, object]:
    """Returns a report-safe summary for configured transfer acquisition inputs."""

    return {
        "bootstrap_hash_count": len(inputs.bootstrap_transfer_hashes),
        "fallback_search_terms": live_wire_inputs.summarize_terms(inputs.generic_open_terms),
        "direct_bootstrap_transfers": live_wire_inputs.summarize_direct_transfers(inputs.direct_bootstrap_transfers),
    }


def update_live_wire_inputs_from_result(inputs, result_row: dict[str, Any]) -> dict[str, object]:
    """Refreshes operator live-wire bootstrap inputs from one selected result."""

    summary = live_wire_inputs.update_live_wire_bootstrap_inputs(inputs.path, result_row)
    return {
        "enabled": True,
        **summary,
    }


def redact_acquisition_attempts(attempts: list[dict[str, object]]) -> list[dict[str, object]]:
    """Redacts exact runtime terms and hashes from transfer acquisition attempts."""

    redacted: list[dict[str, object]] = []
    for item in attempts:
        row: dict[str, object] = {
            "method": item.get("method"),
            "methods": item.get("methods"),
            "query_present": bool(item.get("query")),
        }
        if isinstance(item.get("error"), dict):
            error = item["error"]
            row["error"] = {
                "type": error.get("type"),
                "message_present": bool(error.get("message")),
            }
        if isinstance(item.get("selected"), dict):
            row["selected_transfer"] = summarize_selected_transfer_sources([item])
        if isinstance(item.get("attempts"), list):
            row["attempt_count"] = len(item["attempts"])  # type: ignore[arg-type]
        if isinstance(item.get("candidates"), list):
            row["candidate_count"] = len(item["candidates"])  # type: ignore[arg-type]
        redacted.append(row)
    return redacted


def positive_source_counter(value: object) -> bool:
    """Reports whether one source counter contains a positive numeric value."""

    return isinstance(value, int | float) and value > 0


def is_source_browse_connection_ready(source: dict[str, Any]) -> bool:
    """Reports whether one source looks handshaken enough for a browse request."""

    if source.get("viewSharedFiles") is False:
        return False
    if str(source.get("clientSoftware") or "").strip():
        return True
    if positive_source_counter(source.get("availableParts")) or positive_source_counter(source.get("partCount")):
        return True
    return str(source.get("downloadState") or "") in SOURCE_BROWSE_READY_STATES


def probe_selected_transfer_source_browse(
    base_url: str,
    api_key: str,
    acquisition_attempt: dict[str, object],
    timeout_seconds: float,
) -> dict[str, object]:
    """Attempts source-browse against one acquired transfer and returns a compact probe result."""

    selected_transfer = summarize_selected_transfer_sources([acquisition_attempt])
    transfer_hash = get_selected_transfer_hash(acquisition_attempt)
    if transfer_hash is None:
        raise RuntimeError(f"Selected transfer has no hash: {selected_transfer!r}")

    source_browse_sources = get_selected_transfer_sources([acquisition_attempt])
    result: dict[str, object] = {
        "ok": False,
        "timeout_seconds": timeout_seconds,
        "selected_transfer": selected_transfer,
    }
    try:
        refreshed_sources = wait_for_source_browse_candidates(
            base_url,
            api_key,
            transfer_hash,
            min(DEFAULT_SOURCE_BROWSE_READY_SOURCE_TIMEOUT_SECONDS, max(1.0, timeout_seconds)),
        )
        result["source_refresh"] = refreshed_sources
        refreshed_rows = refreshed_sources.get("sources")
        if isinstance(refreshed_rows, list):
            source_browse_sources = refreshed_rows + source_browse_sources
    except Exception as exc:
        result["source_refresh"] = {
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        }

    try:
        source_browse = wait_for_source_browse_success(
            base_url,
            api_key,
            transfer_hash,
            source_browse_sources,
            timeout_seconds,
        )
        result["source_browse"] = source_browse
        result["ok"] = bool(source_browse.get("ok"))
    except Exception as exc:
        result["source_browse"] = {
            "ok": False,
            "timeout_seconds": timeout_seconds,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }
    return result


def is_valid_source_user_hash(value: object) -> bool:
    """Reports whether one source user hash is useful as a stable selector."""

    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return len(text) == 32 and text != "0" * 32 and all(ch in "0123456789abcdef" for ch in text)


def build_source_browse_selectors(source: dict[str, Any]) -> list[dict[str, object]]:
    """Builds resilient REST source-browse selectors for one transfer source."""

    selectors: list[dict[str, object]] = []
    user_hash_selector: dict[str, object] = {}
    if is_valid_source_user_hash(source.get("userHash")):
        user_hash_selector["userHash"] = str(source["userHash"]).strip().lower()

    ip = str(source.get("ip") or "").strip()
    port = source.get("port")
    endpoint_selector: dict[str, object] = {}
    if ip and isinstance(port, int) and 0 < port <= 65535:
        endpoint_selector = {
            "ip": ip,
            "port": port,
        }

    if endpoint_selector:
        selectors.append(endpoint_selector)
    if user_hash_selector:
        selectors.append(user_hash_selector)
    if user_hash_selector and endpoint_selector:
        selectors.append({**user_hash_selector, **endpoint_selector})

    unique_selectors: list[dict[str, object]] = []
    seen: set[str] = set()
    for selector in selectors:
        selector_key = json.dumps(selector, sort_keys=True)
        if selector_key in seen:
            continue
        seen.add(selector_key)
        unique_selectors.append(selector)
    return unique_selectors


def build_source_browse_selector(source: dict[str, Any]) -> dict[str, object] | None:
    """Builds the preferred selector accepted by the REST source-browse endpoint."""

    selectors = build_source_browse_selectors(source)
    return selectors[0] if selectors else None


def iter_source_browse_candidates(sources: list[object]) -> list[dict[str, object]]:
    """Returns stable unique source-browse candidates, preferring reachable eMule peers."""

    candidates: list[tuple[tuple[object, ...], dict[str, object]]] = []
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            continue
        if source.get("viewSharedFiles") is False:
            continue
        selectors = build_source_browse_selectors(source)
        if not selectors:
            continue
        selector_key = json.dumps(selectors, sort_keys=True)
        if selector_key in seen:
            continue
        seen.add(selector_key)
        candidates.append(
            (
                (
                    not bool(source.get("ip")),
                    bool(source.get("lowId")),
                    not is_source_browse_connection_ready(source),
                    "emule" not in str(source.get("clientSoftware") or "").lower(),
                ),
                {
                    "selector": selectors[0],
                    "selectors": selectors,
                    "source": source,
                },
            )
        )

    candidates.sort(key=lambda item: item[0])
    return [candidate for _key, candidate in candidates]


def request_source_browse(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    selector: dict[str, object],
) -> dict[str, Any]:
    """Requests one manual shared-file browse against a selected transfer source."""

    client_id = str(selector.get("userHash") or "").strip()
    if not client_id:
        address = str(selector.get("address") or selector.get("ip") or "").strip()
        port = selector.get("port")
        if address and port:
            client_id = f"{address}:{port}"
    if not client_id:
        raise ValueError("source selector must include userHash or address/ip and port")

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash}/sources/{client_id}/operations/browse",
        method="POST",
        api_key=api_key,
        json_body={},
    )
    return require_json_object(result, 200)


def wait_for_source_browse_results(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for one manual shared-file browse search tab to receive rows."""

    deadline = time.time() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.time() < deadline:
        result = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        if int(result["status"]) == 404:
            payload = result.get("json")
            if isinstance(payload, dict) and payload.get("error") == "NOT_FOUND":
                observation = {
                    "observed_at": round(time.time(), 3),
                    "state": "search_tab_pending",
                    "result_count": 0,
                }
                observations.append(observation)
                time.sleep(5.0)
                continue
        payload = require_json_object(result, 200)
        rows = payload.get("results")
        assert isinstance(rows, list), payload
        observation = {
            "observed_at": round(time.time(), 3),
            "state": "search_tab_ready",
            "result_count": len(rows),
        }
        observations.append(observation)
        if rows:
            return {
                "observations": observations,
                "searchId": search_id,
                "result_count": len(rows),
                "sample_results": rows[:5],
            }
        time.sleep(5.0)

    raise RuntimeError(
        "Timed out waiting for manual source-browse results. "
        f"Last observations: {observations[-10:]!r}"
    )


def wait_for_source_browse_success(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    sources: list[object],
    timeout_seconds: float,
) -> dict[str, object]:
    """Requests shared files from live transfer sources until one returns rows."""

    deadline = time.time() + timeout_seconds
    attempts: list[dict[str, object]] = []
    candidates = iter_source_browse_candidates(sources)
    for candidate in candidates[:12]:
        remaining = deadline - time.time()
        if remaining <= 1.0:
            break
        selectors = candidate.get("selectors")
        if not isinstance(selectors, list):
            selectors = [candidate.get("selector")]
        for selector in selectors:
            if not isinstance(selector, dict):
                continue
            remaining = deadline - time.time()
            if remaining <= 1.0:
                break
            attempt: dict[str, object] = {
                "selector": selector,
                "source": candidate["source"],
            }
            attempts.append(attempt)
            try:
                response = request_source_browse(base_url, api_key, transfer_hash, selector)
                attempt["response"] = response
                search_id = str(response["searchId"])
                attempt["results"] = wait_for_source_browse_results(
                    base_url,
                    api_key,
                    search_id,
                    min(DEFAULT_SOURCE_BROWSE_ATTEMPT_TIMEOUT_SECONDS, max(1.0, deadline - time.time())),
                )
                return {
                    "ok": True,
                    "attempts": attempts,
                    "selected": attempt,
                }
            except Exception as exc:
                attempt["error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }

    return {
        "ok": False,
        "attempts": attempts,
        "candidate_count": len(candidates),
        "error": {
            "type": "RuntimeError",
            "message": "No browse-capable transfer source returned shared-file rows.",
        },
    }


def add_transfer_from_search_result(base_url: str, api_key: str, result_row: dict[str, Any]) -> dict[str, Any]:
    """Adds one transfer from a REST search-result row and returns the created transfer payload."""

    add_result = rest_smoke.http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={"link": build_ed2k_link(result_row)},
    )
    return require_json_object(add_result, 200)


def observe_transfer_materialization(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Returns a compact native transfer snapshot after a live bootstrap add."""

    result = rest_smoke.http_request(base_url, f"/api/v1/transfers/{transfer_hash}", api_key=api_key)
    payload = require_json_object(result, 200)
    if payload.get("hash") != transfer_hash:
        raise RuntimeError(f"Transfer materialization hash mismatch: expected {transfer_hash!r}, got {payload.get('hash')!r}")
    return {
        "status": result.get("status"),
        "hash_present": bool(payload.get("hash")),
        "name_present": bool(payload.get("name")),
        "state": payload.get("state"),
        "progress": payload.get("progress"),
        "sizeBytes": payload.get("sizeBytes"),
        "completedBytes": payload.get("completedBytes"),
        "sources": payload.get("sources"),
        "sourcesTransferring": payload.get("sourcesTransferring"),
    }


def wait_for_transfer_sources(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until one transfer reports live remote sources."""

    deadline = time.time() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.time() < deadline:
        result = rest_smoke.http_request(base_url, f"/api/v1/transfers/{transfer_hash}/sources", api_key=api_key)
        assert int(result["status"]) == 200, compact_http_result(result)
        payload = rest_smoke.require_json_array(result, 200)
        snapshot = {
            "observed_at": round(time.time(), 3),
            "source_count": len(payload),
        }
        observations.append(snapshot)
        if payload:
            return {
                "observations": observations,
                "sources": payload,
            }
        time.sleep(5.0)

    raise RuntimeError("Timed out waiting for sources on selected transfer.")


def wait_for_source_browse_candidates(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for browse candidates, preferring sources with completed handshakes."""

    deadline = time.time() + timeout_seconds
    observations: list[dict[str, object]] = []
    best_candidate_result: dict[str, object] | None = None
    while time.time() < deadline:
        result = rest_smoke.http_request(base_url, f"/api/v1/transfers/{transfer_hash}/sources", api_key=api_key)
        assert int(result["status"]) == 200, compact_http_result(result)
        payload = rest_smoke.require_json_array(result, 200)
        candidates = iter_source_browse_candidates(payload)
        ready_candidates = [
            candidate
            for candidate in candidates
            if isinstance(candidate.get("source"), dict) and is_source_browse_connection_ready(candidate["source"])
        ]
        snapshot = {
            "observed_at": round(time.time(), 3),
            "source_count": len(payload),
            "candidate_count": len(candidates),
            "ready_candidate_count": len(ready_candidates),
        }
        observations.append(snapshot)
        if candidates:
            best_candidate_result = {
                "observations": list(observations),
                "sources": payload,
                "candidate_count": len(candidates),
                "ready_candidate_count": len(ready_candidates),
            }
        if ready_candidates:
            return best_candidate_result if best_candidate_result is not None else {
                "observations": observations,
                "sources": payload,
                "candidate_count": len(candidates),
                "ready_candidate_count": len(ready_candidates),
            }
        time.sleep(5.0)

    if best_candidate_result is not None:
        best_candidate_result["fallback_unready_candidates"] = True
        return best_candidate_result
    raise RuntimeError("Timed out waiting for browse-capable sources on selected transfer.")


def find_direct_bootstrap_transfer_candidate(
    base_url: str,
    api_key: str,
    inputs,
    *,
    source_discovery_timeout_seconds: float,
) -> dict[str, object]:
    """Adds known safe ED2K transfers until one yields browse-capable live sources."""

    attempts: list[dict[str, object]] = []
    for result_row in build_direct_bootstrap_transfer_plan(inputs):
        attempt: dict[str, object] = {
            "query_present": bool(result_row.get("name")),
            "method": result_row.get("method", "direct_ed2k"),
            "result": {
                "hash_present": bool(result_row.get("hash")),
                "name_present": bool(result_row.get("name")),
                "size": result_row.get("size"),
                "method": result_row.get("method"),
            },
        }
        attempts.append(attempt)
        try:
            if not is_safe_download_result(result_row):
                raise RuntimeError("Direct bootstrap transfer is not safe to download.")
            add_payload = add_transfer_from_search_result(base_url, api_key, result_row)
            attempt["add_response"] = add_payload
            attempt["transfer_materialization"] = observe_transfer_materialization(
                base_url,
                api_key,
                str(add_payload["hash"]),
            )
            attempt["sources_ready"] = wait_for_transfer_sources(
                base_url,
                api_key,
                str(add_payload["hash"]),
                source_discovery_timeout_seconds,
            )
            source_rows = attempt["sources_ready"].get("sources")
            if not isinstance(source_rows, list) or not iter_source_browse_candidates(source_rows):
                raise RuntimeError("Direct bootstrap transfer had no source candidates with shared-file browsing enabled.")
            return {
                "selected": attempt,
                "attempts": attempts,
            }
        except Exception as exc:
            attempt["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }

    raise RuntimeError(f"No direct ED2K bootstrap transfer yielded browse-capable live sources. Attempts: {attempts!r}")


def wait_for_auto_browse_success(
    base_url: str,
    api_key: str,
    cache_dir: Path,
    timeout_seconds: float,
    progress_callback: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    """Waits for one real auto-browse session to log success and persist cache files."""

    deadline = time.time() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.time() < deadline:
        result = rest_smoke.http_request(base_url, "/api/v1/logs?limit=400", api_key=api_key)
        assert int(result["status"]) == 200, compact_http_result(result)
        payload = rest_smoke.require_json_array(result, 200)

        messages = [
            entry.get("message")
            for entry in payload
            if isinstance(entry, dict) and isinstance(entry.get("message"), str)
        ]
        auto_lines = [message for message in messages if message.startswith("Auto-browsing shared files from ")]
        success_lines = [message for message in messages if message.startswith("Cached ") and " shared files from " in message]
        cache_files = sorted(path.name for path in cache_dir.glob("*.browsecache"))

        observation = {
            "observed_at": round(time.time(), 3),
            "auto_count": len(auto_lines),
            "success_count": len(success_lines),
            "cache_files": cache_files,
        }
        observations.append(observation)
        print(
            "auto-browse-live observation: "
            f"auto={len(auto_lines)} success={len(success_lines)} cache_files={len(cache_files)}",
            flush=True,
        )
        if progress_callback is not None:
            progress_callback(observation)

        if auto_lines and success_lines and cache_files:
            return {
                "observations": observations,
                "auto_lines": auto_lines[-10:],
                "success_lines": success_lines[-10:],
                "cache_files": cache_files,
            }

        time.sleep(10.0)

    raise RuntimeError(
        "Timed out waiting for a successful auto-browse session. "
        f"Last observations: {observations[-10:]!r}"
    )


def try_wait_for_auto_browse_success(
    base_url: str,
    api_key: str,
    cache_dir: Path,
    timeout_seconds: float,
    progress_callback: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    """Attempts to wait for one automatic browse success and reports timeout state without raising."""

    try:
        success = wait_for_auto_browse_success(
            base_url,
            api_key,
            cache_dir,
            timeout_seconds,
            progress_callback,
        )
        return {
            "ok": True,
            "success": success,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }


def wait_for_process_id(app: object) -> int | None:
    """Returns the launched process id when pywinauto exposes it for the live app."""

    process_id = getattr(app, "process", None)
    if callable(process_id):
        try:
            process_id = process_id()
        except TypeError:
            process_id = None
    return process_id if isinstance(process_id, int) else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default="auto-browse-live-key")
    parser.add_argument("--web-bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=540.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--source-discovery-timeout-seconds", type=float, default=600.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--auto-browse-timeout-seconds", type=float, default=1800.0)
    parser.add_argument(
        "--natural-auto-browse-timeout-seconds",
        type=float,
        default=DEFAULT_NATURAL_AUTO_BROWSE_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--fallback-auto-browse-timeout-seconds",
        type=float,
        default=DEFAULT_FALLBACK_AUTO_BROWSE_TIMEOUT_SECONDS,
    )
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(rest_smoke.REPO_ROOT)),
    )
    args = parser.parse_args()
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(rest_smoke.REPO_ROOT, args.live_wire_inputs_file)
    )

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="auto-browse-live",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=(args.keep_artifacts or args.keep_running),
    )

    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    artifacts_dir = paths.source_artifacts_dir
    port = rest_smoke.choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"

    profile = prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="auto-browse-live")
    seed_refresh = None
    if not args.skip_live_seed_refresh:
        seed_refresh = rest_smoke.refresh_seed_files(
            Path(profile["config_dir"]),
            timeout_seconds=args.seed_download_timeout_seconds,
        )
    configure_auto_browse_profile(
        config_dir=Path(profile["config_dir"]),
        app_exe=paths.app_exe,
        api_key=args.api_key,
        port=port,
        web_bind_addr=args.web_bind_addr,
    )
    rest_smoke.apply_p2p_bind_interface_override(
        config_dir=Path(profile["config_dir"]),
        interface_name=args.p2p_bind_interface_name,
    )

    app = None
    pending_error: Exception | None = None
    report: dict[str, object] = {
        "suite": "auto-browse-live",
        "status": "failed",
        "base_url": base_url,
        "port": port,
        "launch_inputs": {
            "app_exe": str(paths.app_exe),
            "seed_config_dir": str(seed_config_dir),
            "live_seed_source_url": rest_smoke.EMULE_SECURITY_HOME_URL,
            "live_seed_refresh": seed_refresh,
            "artifacts_dir": str(artifacts_dir),
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "api_key_length": len(args.api_key),
            "web_bind_addr": args.web_bind_addr,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "enable_upnp": True,
            "autoconnect_via_preferences": True,
            "live_wire_inputs_file": str(inputs.path),
            "transfer_acquisition_inputs": summarize_transfer_acquisition_plan(inputs),
            "reject_exe_results": True,
            "keep_running": bool(args.keep_running),
            "live_wire_inputs_update": {
                "enabled": True,
                "target": str(inputs.path),
            },
            "timeouts": {
                "rest_ready_seconds": args.rest_ready_timeout_seconds,
                "server_connect_seconds": args.server_connect_timeout_seconds,
                "kad_running_seconds": args.kad_running_timeout_seconds,
                "search_observation_seconds": args.search_observation_timeout_seconds,
                "source_discovery_seconds": args.source_discovery_timeout_seconds,
                "natural_auto_browse_seconds": args.natural_auto_browse_timeout_seconds,
                "auto_browse_seconds": args.auto_browse_timeout_seconds,
                "fallback_auto_browse_seconds": args.fallback_auto_browse_timeout_seconds,
                "source_browse_transfer_seconds": DEFAULT_SOURCE_BROWSE_TRANSFER_TIMEOUT_SECONDS,
                "source_browse_attempt_seconds": DEFAULT_SOURCE_BROWSE_ATTEMPT_TIMEOUT_SECONDS,
                "source_browse_ready_source_seconds": DEFAULT_SOURCE_BROWSE_READY_SOURCE_TIMEOUT_SECONDS,
                "direct_bootstrap_source_seconds": min(
                    DEFAULT_DIRECT_BOOTSTRAP_SOURCE_TIMEOUT_SECONDS,
                    args.source_discovery_timeout_seconds,
                ),
                "seed_download_seconds": args.seed_download_timeout_seconds,
            },
        },
        "checks": {},
        "cleanup": {},
    }
    record_phase(artifacts_dir, report, "prepared")

    try:
        record_phase(artifacts_dir, report, "launch")
        app = launch_app(paths.app_exe, Path(profile["profile_base"]))
        report["launched_process_id"] = wait_for_process_id(app)
        report["main_window_title"] = wait_for_main_window(app).window_text()

        record_phase(artifacts_dir, report, "rest_ready")
        ready = rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["checks"]["ready"] = compact_http_result(ready)

        record_phase(artifacts_dir, report, "auth")
        no_key = rest_smoke.http_request(base_url, "/api/v1/app")
        wrong_key = rest_smoke.http_request(base_url, "/api/v1/app", api_key="wrong-key")
        assert int(no_key["status"]) == 401
        assert int(wrong_key["status"]) == 401
        report["checks"]["auth"] = {
            "missing": compact_http_result(no_key),
            "wrong": compact_http_result(wrong_key),
        }

        record_phase(artifacts_dir, report, "servers_list")
        servers = rest_smoke.http_request(base_url, "/api/v1/servers", api_key=args.api_key)
        assert int(servers["status"]) == 200, compact_http_result(servers)
        server_rows = rest_smoke.require_json_array(servers, 200)
        assert server_rows, compact_http_result(servers)
        ordered_server_rows = reorder_server_rows(list(server_rows))
        report["checks"]["servers_list"] = {
            "count": len(ordered_server_rows),
            "preferred_candidates": ordered_server_rows[:5],
        }

        record_phase(artifacts_dir, report, "network_ready")
        network_ready = rest_smoke.wait_for_requested_networks(
            base_url,
            args.api_key,
            args.server_connect_timeout_seconds,
            require_server_connected=True,
            require_kad_connected=True,
        )
        report["checks"]["autoconnect_mode"] = {
            "source": "preferences",
            "server_candidates": ordered_server_rows[:5],
        }
        report["checks"]["network_ready"] = network_ready

        cache_dir = Path(profile["config_dir"]) / "RemoteBrowseCache"
        record_phase(artifacts_dir, report, "natural_auto_browse")
        natural_auto_browse = try_wait_for_auto_browse_success(
            base_url,
            args.api_key,
            cache_dir,
            args.natural_auto_browse_timeout_seconds,
            lambda observation: record_auto_browse_observation(
                artifacts_dir,
                report,
                "natural_auto_browse_progress",
                observation,
            ),
        )
        report["checks"]["natural_auto_browse"] = natural_auto_browse

        if bool(natural_auto_browse.get("ok")):
            report["checks"]["auto_browse"] = natural_auto_browse["success"]
            report["checks"]["bootstrap_strategy"] = {
                "mode": "natural-clients-only",
            }
        else:
            record_phase(artifacts_dir, report, "transfer_acquisition")
            acquisition_attempts: list[dict[str, object]] = []
            source_browse_attempts: list[dict[str, object]] = []
            selected_source_browse: dict[str, object] | None = None
            browsed_transfer_hashes: set[str] = set()
            remaining_timeout = max(1.0, args.auto_browse_timeout_seconds - args.natural_auto_browse_timeout_seconds)
            fallback_timeout = max(1.0, min(args.fallback_auto_browse_timeout_seconds, remaining_timeout))
            source_browse_timeout = max(
                1.0,
                min(DEFAULT_SOURCE_BROWSE_TRANSFER_TIMEOUT_SECONDS, fallback_timeout),
            )
            report["checks"]["bootstrap_strategy"] = {
                "mode": "fallback-transfer-bootstrap",
            }
            direct_source_timeout = min(
                DEFAULT_DIRECT_BOOTSTRAP_SOURCE_TIMEOUT_SECONDS,
                args.source_discovery_timeout_seconds,
            )
            try:
                direct_selection = find_direct_bootstrap_transfer_candidate(
                    base_url,
                    args.api_key,
                    inputs,
                    source_discovery_timeout_seconds=direct_source_timeout,
                )
                acquisition_attempts.append(direct_selection)
                transfer_hash = get_selected_transfer_hash(direct_selection)
                if transfer_hash is not None:
                    browsed_transfer_hashes.add(transfer_hash)
                    record_phase(artifacts_dir, report, "source_browse")
                    source_browse_attempt = probe_selected_transfer_source_browse(
                        base_url,
                        args.api_key,
                        direct_selection,
                        source_browse_timeout,
                    )
                    source_browse_attempts.append(source_browse_attempt)
                    report["checks"]["source_browse_attempts"] = source_browse_attempts
                    report["checks"]["source_browse"] = source_browse_attempt.get("source_browse")
                    report["checks"]["source_browse_source_refresh"] = source_browse_attempt.get("source_refresh")
                    checkpoint_report(artifacts_dir, report)
                    if bool(source_browse_attempt.get("ok")):
                        selected_source_browse = source_browse_attempt
            except Exception as exc:
                acquisition_attempts.append(
                    {
                        "query": "direct_ed2k_bootstrap",
                        "methods": ["direct_ed2k"],
                        "candidate_count": len(build_direct_bootstrap_transfer_plan(inputs)),
                        "source_discovery_timeout_seconds": direct_source_timeout,
                        "error": {
                            "type": type(exc).__name__,
                            "message": str(exc),
                        },
                    }
                )
            for query, methods in build_transfer_acquisition_plan(inputs):
                if selected_source_browse is not None:
                    break
                try:
                    selection = find_transfer_candidate(
                        base_url,
                        args.api_key,
                        query=query,
                        method_candidates=methods,
                        observation_timeout_seconds=args.search_observation_timeout_seconds,
                    )
                    selected_attempt = selection["selected"]
                    assert isinstance(selected_attempt, dict)
                    result_row = selected_attempt["result"]
                    assert isinstance(result_row, dict)
                    add_payload = add_transfer_from_search_result(base_url, args.api_key, result_row)
                    selected_attempt["add_response"] = add_payload
                    selected_attempt["transfer_materialization"] = observe_transfer_materialization(
                        base_url,
                        args.api_key,
                        str(add_payload["hash"]),
                    )
                    selected_attempt["sources_ready"] = wait_for_transfer_sources(
                        base_url,
                        args.api_key,
                        str(add_payload["hash"]),
                        args.source_discovery_timeout_seconds,
                    )
                    source_rows = selected_attempt["sources_ready"].get("sources")
                    if not isinstance(source_rows, list) or not iter_source_browse_candidates(source_rows):
                        raise RuntimeError("Sourced transfer had no source candidates with shared-file browsing enabled.")
                    acquisition_attempts.append(selection)
                    transfer_hash = get_selected_transfer_hash(selection)
                    if transfer_hash is None:
                        raise RuntimeError("Selected sourced transfer had no transfer hash.")
                    if transfer_hash in browsed_transfer_hashes:
                        continue
                    browsed_transfer_hashes.add(transfer_hash)
                    report["checks"]["live_wire_inputs_update"] = update_live_wire_inputs_from_result(inputs, result_row)
                    checkpoint_report(artifacts_dir, report)
                    record_phase(artifacts_dir, report, "source_browse")
                    source_browse_attempt = probe_selected_transfer_source_browse(
                        base_url,
                        args.api_key,
                        selection,
                        source_browse_timeout,
                    )
                    source_browse_attempts.append(source_browse_attempt)
                    report["checks"]["source_browse_attempts"] = source_browse_attempts
                    report["checks"]["source_browse"] = source_browse_attempt.get("source_browse")
                    report["checks"]["source_browse_source_refresh"] = source_browse_attempt.get("source_refresh")
                    checkpoint_report(artifacts_dir, report)
                    if bool(source_browse_attempt.get("ok")):
                        selected_source_browse = source_browse_attempt
                        break
                except Exception as exc:
                    failed_attempt: dict[str, object] = {
                        "query": query,
                        "methods": methods,
                        "error": {
                            "type": type(exc).__name__,
                            "message": str(exc),
                        },
                    }
                    if isinstance(exc, TransferCandidateUnavailableError):
                        failed_attempt["attempts"] = exc.attempts
                    acquisition_attempts.append(failed_attempt)
            report["checks"]["transfer_acquisition"] = redact_acquisition_attempts(acquisition_attempts)
            selected_acquisition_count = sum(1 for item in acquisition_attempts if isinstance(item, dict) and item.get("selected"))
            if selected_acquisition_count == 0:
                report["checks"]["live_source_availability"] = {
                    "status": "unavailable",
                    "transfer_acquisition_inputs": summarize_transfer_acquisition_plan(inputs),
                    "blocking": False,
                }
                raise LiveSourceUnavailableError(
                    "Live networks connected, but no safe downloadable sourced transfer was available "
                    "from the configured live-search plan."
                )

            if selected_source_browse is not None:
                selected_transfer = selected_source_browse.get("selected_transfer", {})
                report["checks"]["live_source_availability"] = {
                    "status": "available",
                    "transfer_acquisition_inputs": summarize_transfer_acquisition_plan(inputs),
                    "blocking": False,
                    "selected_transfer": selected_transfer,
                }
                report["checks"]["source_browse"] = selected_source_browse.get("source_browse")
                report["checks"]["source_browse_source_refresh"] = selected_source_browse.get("source_refresh")
            else:
                last_source_browse_attempt = source_browse_attempts[-1] if source_browse_attempts else {}
                if isinstance(last_source_browse_attempt, dict):
                    report["checks"]["source_browse"] = last_source_browse_attempt.get(
                        "source_browse",
                        report["checks"].get("source_browse"),
                    )
                    report["checks"]["source_browse_source_refresh"] = last_source_browse_attempt.get(
                        "source_refresh",
                        report["checks"].get("source_browse_source_refresh"),
                    )
                    selected_transfer = last_source_browse_attempt.get("selected_transfer", summarize_selected_transfer_sources(acquisition_attempts))
                else:
                    selected_transfer = summarize_selected_transfer_sources(acquisition_attempts)
                report["checks"]["live_source_availability"] = {
                    "status": "shared_file_response_unavailable",
                    "transfer_acquisition_inputs": summarize_transfer_acquisition_plan(inputs),
                    "blocking": False,
                    "selected_transfer": selected_transfer,
                    "selected_transfer_count": selected_acquisition_count,
                }
                raise LiveSourceUnavailableError(
                    "Safe live transfers were acquired, but no selected source returned shared-file "
                    "rows during the source-browse observation windows."
                )
        report["status"] = "passed"
        record_phase(artifacts_dir, report, "passed")
    except Exception as exc:
        record_phase(artifacts_dir, report, "exception")
        if isinstance(exc, LiveSourceUnavailableError):
            report["status"] = "inconclusive"
            report["inconclusive_reason"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        else:
            pending_error = exc
            report["status"] = "failed"
            report["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
    finally:
        record_phase(artifacts_dir, report, "cleanup_start")
        cleanup = report["cleanup"]
        assert isinstance(cleanup, dict)
        if app is not None:
            cleanup["process_id"] = wait_for_process_id(app)
            cleanup["profile_base"] = str(profile["profile_base"])
            if args.keep_running and report["status"] == "passed":
                cleanup["app_closed"] = False
                cleanup["app_left_running"] = True
            else:
                try:
                    close_app_cleanly(app)
                    cleanup["app_closed"] = True
                    cleanup["app_left_running"] = False
                except Exception as exc:
                    cleanup["app_closed"] = False
                    cleanup["app_close_error"] = repr(exc)
                    if should_promote_cleanup_error(report.get("status"), pending_error):
                        pending_error = exc
                        report["status"] = "failed"
                        report["error"] = {
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }

        record_phase(artifacts_dir, report, "cleanup_done")
        write_json(artifacts_dir / "auto-browse-live-result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    if pending_error is not None:
        raise pending_error

    if report["status"] == "inconclusive":
        print(
            "Auto-browse live validation was inconclusive because no browse-capable live source was available. "
            f"Report directory: {paths.run_report_dir}"
        )
        return LIVE_SOURCE_UNAVAILABLE_EXIT_CODE

    if args.keep_running:
        print(
            "Auto-browse live validation passed and left the app running. "
            f"Report directory: {paths.run_report_dir} "
            f"(PID: {report.get('launched_process_id')}, profile: {profile['profile_base']})"
        )
    else:
        print(f"Auto-browse live validation passed. Report directory: {paths.run_report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
