"""Shared helpers for LAN-bound eMuleBB Rust local ED2K harness clients."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import ed2k_wire, rust_client


class ServerSearchFailure(RuntimeError):
    """Carries the terminal REST snapshot for a failed deterministic search."""

    def __init__(self, message: str, evidence: dict[str, object]) -> None:
        super().__init__(message)
        self.evidence = evidence


class RustRestFailure(RuntimeError):
    """Keep the existing error text plus a closed projection for public receipts."""
    def __init__(self, message: str, *, status: int, detail: str):
        super().__init__(message)
        self.status = status
        try:
            value = json.loads(detail).get("error", {})
        except (ValueError, AttributeError):
            value = {}
        # Structured response stays in memory for callers that verify canonical
        # conflict evidence. Public receipts must use only safe_failure.
        self.response_error = value if isinstance(value, dict) else {}
        code = value.get("code") if isinstance(value, dict) else None
        allowed = {"INVALID_ARGUMENT", "NOT_FOUND", "EMULE_ERROR", "INTERNAL_SERVER_ERROR", "UNAUTHORIZED", "FORBIDDEN", "DOWNLOAD_CONFLICT"}
        text = str(value.get("message", "")).lower() if isinstance(value, dict) else ""
        contexts = (("ed2k network is not configured", "ed2k-not-configured"),
            ("ed2k network is disabled in settings.core", "ed2k-disabled"),
            ("ed2k connect requires at least one configured server", "ed2k-no-server"),
            ("blocked by vpn guard", "vpn-guard-blocked"),
            ("failed to configure the local ed2k client-udp version", "client-udp-version"),
            ("failed to initialize kad runtime for ed2k listener", "kad-listener-initialization"),
            ("failed to bind ed2k tcp listener", "ed2k-listener-bind"),
            ("nat initial reconcile failed", "nat-initial-reconcile"),
            ("nat initial reconcile timed out", "nat-initial-timeout"),
            ("is not assigned to a local interface", "local-bind-interface-missing"),
            ("server not found", "server-not-found"))
        self.safe_failure = {"httpStatus": status, "apiCode": code if isinstance(code, str) and code in allowed else "unrecognized",
                             "coreContext": next((name for marker, name in contexts if marker in text), "unrecognized")}


def request_json(
    base_url: str,
    method: str,
    path: str,
    api_key: str,
    body: dict[str, object] | None = None,
    *,
    timeout_seconds: float = 10.0,
    expected_status: int | None = None,
) -> dict[str, object]:
    """Run one authenticated JSON request with an explicit, normally ten-second deadline."""

    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=payload,
        method=method,
        headers={"X-API-Key": api_key, "Accept": "application/json"},
    )
    if payload is not None:
        request.add_header("Content-Type", "application/json; charset=utf-8")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if expected_status is not None and response.status != expected_status:
                raise RuntimeError(f"Rust REST {method} {path} returned HTTP {response.status}; expected {expected_status}")
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise RustRestFailure(f"Rust REST {method} {path} returned HTTP {exc.code}: {detail or exc.reason}",
                              status=exc.code, detail=detail) from exc
    data = json.loads(text) if text else {}
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    if isinstance(data, dict):
        return data
    raise RuntimeError(f"Rust REST returned a non-object payload for {method} {path}: {data!r}")


def canonical_download_id(job_id: object) -> str:
    """Validate the public positive decimal i64 job identity."""
    if (not isinstance(job_id, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", job_id)
            or int(job_id) > 9223372036854775807):
        raise RuntimeError("Rust download admission returned an invalid job identity")
    return job_id


def require_download_id(admission: dict[str, object], *, expected_hash: str) -> str:
    """Retain the exact allocated job identity alongside its protocol hash."""
    job_id = canonical_download_id(admission.get("id"))
    if admission.get("hash") != expected_hash.lower():
        raise RuntimeError("Rust download admission returned an invalid job identity")
    return job_id


def download_detail(base_url: str, api_key: str, download_id: str, *, expected_hash: str) -> dict[str, object]:
    """Read and verify the captured job; a same-hash replacement is not interchangeable."""
    row = request_json(base_url, "GET", f"/api/v1/downloads/{download_id}", api_key)
    if require_download_id(row, expected_hash=expected_hash) != download_id:
        raise RuntimeError("Rust download detail substituted another job")
    return row


def require_download_batch(document: dict[str, object], download_id: str) -> dict[str, object]:
    """A successful HTTP batch still needs a successful item for the captured job."""
    rows = document.get("data")
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get("id") != download_id or rows[0].get("status") not in {"accepted", "unchanged"}
            or rows[0].get("httpStatus") not in {200, 202} or "error" in rows[0]
            or (rows[0]["status"] == "unchanged" and rows[0]["httpStatus"] != 200)):
        raise RuntimeError(f"Rust download action did not accept captured job {download_id}")
    return rows[0]


def download_part_totals(base_url: str, api_key: str, download_id: str) -> dict[str, int]:
    """Stream part pages with constant retained memory; count presence and verification separately."""
    cursor = None
    previous_index = -1
    totals = {"partCount": 0, "presentBytes": 0, "verifiedBytes": 0}
    while True:
        query = {"limit": 200}
        if cursor is not None:
            query["cursor"] = cursor
        page = request_json(base_url, "GET", f"/api/v1/downloads/{download_id}/parts?{urllib.parse.urlencode(query)}", api_key)
        rows, meta = page.get("data"), page.get("meta")
        if (not isinstance(rows, list) or len(rows) > 200 or not isinstance(meta, dict)
                or type(meta.get("hasMore")) is not bool or "nextCursor" not in meta):
            raise RuntimeError("Rust download parts returned an invalid bounded page")
        for row in rows:
            if (not isinstance(row, dict) or type(row.get("index")) is not int or row["index"] <= previous_index
                    or type(row.get("sizeBytes")) is not int or row["sizeBytes"] < 0
                    or type(row.get("presentBytes")) is not int or not 0 <= row["presentBytes"] <= row["sizeBytes"]
                    or type(row.get("complete")) is not bool):
                raise RuntimeError("Rust download parts lost ordering or byte invariants")
            previous_index = row["index"]
            totals["partCount"] += 1
            totals["presentBytes"] += row["presentBytes"]
            if row["complete"]:
                totals["verifiedBytes"] += row["sizeBytes"]
        next_cursor = meta["nextCursor"]
        if not meta["hasMore"]:
            if next_cursor is not None:
                raise RuntimeError("Rust terminal part page retained a cursor")
            return totals
        if not rows or not isinstance(next_cursor, str) or not 0 < len(next_cursor) <= 512 or next_cursor == cursor:
            raise RuntimeError("Rust download part cursor did not advance")
        cursor = next_cursor


def wait_for(
    probe,
    *,
    timeout_seconds: float,
    interval_seconds: float,
    description: str,
):
    """Polls until a probe returns a non-None value."""

    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() <= deadline:
        try:
            result = probe()
            if result is not None:
                return result
        except Exception as exc:  # noqa: BLE001 - diagnostics preserve the last probe failure
            last_error = exc
        time.sleep(interval_seconds)
    if last_error is not None:
        raise RuntimeError(f"Timed out waiting for {description}: {last_error}")
    raise RuntimeError(f"Timed out waiting for {description}.")


def wait_for_rest_ready(
    base_url: str,
    process: subprocess.Popen[str],
    log_path: Path,
    api_key: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until the Rust REST API is reachable and the process is still alive."""

    def probe() -> dict[str, object] | None:
        if process.poll() is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-2000:] if log_path.exists() else ""
            raise RuntimeError(f"emulebb-rust exited early with code {process.returncode}: {tail}")
        try:
            return request_json(base_url, "GET", "/api/v1/app", api_key)
        except (OSError, urllib.error.URLError, RuntimeError):
            return None

    return wait_for(
        probe,
        timeout_seconds=timeout_seconds,
        interval_seconds=0.5,
        description="emulebb-rust REST ready",
    )


def wait_for_ed2k_connected(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until the Rust client reports an ED2K server connection."""

    def probe() -> dict[str, object] | None:
        data = request_json(base_url, "GET", "/api/v1/status", api_key)
        stats = data.get("stats") if isinstance(data, dict) else None
        if isinstance(stats, dict) and stats.get("ed2kConnected") is True:
            return data
        return None

    return wait_for(
        probe,
        timeout_seconds=timeout_seconds,
        interval_seconds=0.5,
        description="emulebb-rust ED2K connected",
    )


def wait_for_server_list_metadata(
    base_url: str,
    api_key: str,
    *,
    current_server_address: str,
    current_server_port: int,
    metadata_server_address: str,
    metadata_server_port: int,
    expected_name: str,
    expected_description: str,
    expected_users: int | None = None,
    expected_files: int | None = None,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for one server-list entity while independently proving the active server."""

    last_status: dict[str, object] = {}

    def probe() -> dict[str, object] | None:
        status = request_json(base_url, "GET", "/api/v1/status", api_key)
        nested = status.get("servers")
        connection_status = nested if isinstance(nested, dict) else status
        server_entity = request_json(
            base_url,
            "GET",
            f"/api/v1/servers/{metadata_server_address}:{metadata_server_port}",
            api_key,
        )
        last_status.clear()
        last_status.update(
            {
                "connectionStatus": connection_status,
                "serverEntity": server_entity,
            }
        )
        current = (
            connection_status.get("currentServer")
            if isinstance(connection_status.get("currentServer"), dict)
            else {}
        )
        users = server_entity.get("users")
        files = server_entity.get("files")
        counters_valid = all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (users, files)
        )
        counters_match = bool(
            counters_valid
            and (expected_users is None or users == expected_users)
            and (expected_files is None or files == expected_files)
        )
        if (
            connection_status.get("connected") is True
            and current.get("current") is True
            and str(current.get("address") or "").casefold()
            == current_server_address.casefold()
            and current.get("port") == current_server_port
            and str(server_entity.get("address") or "").casefold()
            == metadata_server_address.casefold()
            and server_entity.get("port") == metadata_server_port
            and server_entity.get("name") == expected_name
            and server_entity.get("description") == expected_description
            and counters_match
        ):
            return {
                "connectionStatus": connection_status,
                "serverEntity": server_entity,
            }
        return None

    try:
        return wait_for(
            probe,
            timeout_seconds=timeout_seconds,
            interval_seconds=0.25,
            description="applied ED2K server-list metadata",
        )
    except RuntimeError as exc:
        detail = json.dumps(last_status, sort_keys=True, separators=(",", ":"))
        raise RuntimeError(f"{exc} Last normalized server state: {detail}") from exc


def wait_for_server_search_result(
    base_url: str,
    api_key: str,
    *,
    query: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until a fresh Rust server search returns the exact file hash."""

    observations: list[dict[str, object]] = []
    normalized_hash = transfer_hash.lower()

    def probe() -> dict[str, object] | None:
        created = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            api_key,
            {"query": query, "method": "server", "type": ""},
        )
        search_id = str(created.get("id") or "")
        if not search_id:
            return None
        search = created
        result_count = 0
        deadline = time.time() + 35.0
        while True:
            search = request_json(
                base_url,
                "GET",
                f"/api/v1/searches/{search_id}?limit=200&offset=0",
                api_key,
            )
            items = search.get("items")
            result_count = len(items) if isinstance(items, list) else 0
            if isinstance(items, list):
                for result in items:
                    if (
                        isinstance(result, dict)
                        and str(result.get("hash") or "").lower() == normalized_hash
                    ):
                        observations.append(
                            {
                                "result_count": result_count,
                                "observed_at": round(time.time(), 3),
                            }
                        )
                        return {
                            "search": search,
                            "result": result,
                            "observations": observations[-20:],
                        }
            status = str(search.get("status") or "")
            if status in {"complete", "completed", "error"} or time.time() >= deadline:
                break
            time.sleep(0.5)
        observations.append(
            {
                "result_count": result_count,
                "observed_at": round(time.time(), 3),
            }
        )
        return None

    return wait_for(
        probe,
        timeout_seconds=timeout_seconds,
        interval_seconds=1.0,
        description=f"emulebb-rust server search result {normalized_hash}",
    )


def run_single_server_search(
    base_url: str,
    api_key: str,
    *,
    query: str,
    criteria: ed2k_wire.ServerSearchCriteria,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Runs exactly one server search and requires one exact result row."""

    search_request: dict[str, object] = {
        "query": query,
        "method": "server",
        "type": "",
    }
    if criteria.min_size_bytes is not None:
        search_request["minSizeBytes"] = criteria.min_size_bytes
    if criteria.max_size_bytes is not None:
        search_request["maxSizeBytes"] = criteria.max_size_bytes
    try:
        created = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            api_key,
            search_request,
        )
    except Exception as exc:  # noqa: BLE001 - preserve the failed REST stimulus
        raise ServerSearchFailure(
            f"Deterministic server search creation failed: {exc}",
            {
                "request": search_request,
                "searchId": None,
                "created": {},
                "search": {},
                "result": None,
                "observations": [],
            },
        ) from exc
    search_id = str(created.get("id") or "")
    if not search_id:
        raise ServerSearchFailure(
            "Deterministic server search creation returned no search ID.",
            {
                "request": search_request,
                "searchId": None,
                "created": created,
                "search": {},
                "result": None,
                "observations": [],
            },
        )
    normalized_hash = expected_hash.casefold()
    deadline = time.time() + timeout_seconds
    observations: list[dict[str, object]] = []

    def failure(
        message: str,
        search: dict[str, object],
        matches: list[dict[str, object]],
    ) -> ServerSearchFailure:
        return ServerSearchFailure(
            message,
            {
                "request": search_request,
                "searchId": search_id,
                "created": created,
                "search": search,
                "result": matches[0] if len(matches) == 1 else None,
                "observations": observations[-20:],
            },
        )

    while True:
        try:
            search = request_json(
                base_url,
                "GET",
                f"/api/v1/searches/{search_id}?limit=200&offset=0",
                api_key,
            )
        except Exception as exc:  # noqa: BLE001 - preserve the created search identity
            raise failure(
                f"Deterministic server search result request failed: {exc}",
                {},
                [],
            ) from exc
        items = search.get("items")
        rows = items if isinstance(items, list) else []
        observations.append(
            {
                "status": str(search.get("status") or ""),
                "resultCount": len(rows),
                "observedAt": round(time.time(), 3),
            }
        )
        matches = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("hash") or "").casefold() == normalized_hash
            and row.get("displayName", row.get("name")) == expected_name
            and row.get("sizeBytes", row.get("size")) == expected_size
        ]
        if len(matches) > 1:
            raise failure(
                "Deterministic server search returned duplicate exact result rows.",
                search,
                matches,
            )
        status = str(search.get("status") or "").casefold()
        if len(matches) == 1 and status in {"complete", "completed"}:
            return {
                "request": search_request,
                "searchId": search_id,
                "created": created,
                "search": search,
                "result": matches[0],
                "observations": observations[-20:],
            }
        if status in {"complete", "completed", "error"}:
            raise failure(
                "Deterministic server search completed without the exact published file.",
                search,
                matches,
            )
        if time.time() >= deadline:
            raise failure(
                "Deterministic server search timed out before an exact result.",
                search,
                matches,
            )
        time.sleep(0.25)


def file_sha256(path: Path) -> str:
    """Returns the SHA-256 digest of one file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ed2k_link_with_source(
    link: str,
    source_ip: str,
    source_port: int,
    user_hash: str | None = None,
    connect_options: int | None = None,
) -> str:
    """Appends one stock-compatible direct source hint to an ED2K file link."""

    if not link.startswith("ed2k://|file|") or not link.endswith("|/"):
        raise RuntimeError(f"Cannot append source hint to malformed ED2K link: {link!r}")
    if connect_options is not None and user_hash is None:
        raise RuntimeError("ED2K source connect options require a peer user hash.")
    if connect_options is not None and not 0 <= connect_options <= 0xFF:
        raise RuntimeError(f"ED2K source connect options must fit in one byte, got {connect_options}.")
    source = f"{source_ip}:{source_port}"
    if user_hash:
        source = f"{source}:{user_hash}"
    if connect_options is not None:
        source = f"{source}:{connect_options}"
    return f"{link[:-2]}|sources,{source}|/"


def wait_for_download_completed(
    base_url: str,
    api_key: str,
    download_id: str,
    *,
    expected_hash: str,
    expected_size: int,
    expected_sha256: str,
    expected_delivery_path: Path,
    timeout_seconds: float,
) -> dict[str, object]:
    """Require retained terminal completion and exact delivered bytes for one job."""

    observations: list[dict[str, object]] = []

    def probe() -> dict[str, object] | None:
        data = request_json(base_url, "GET", f"/api/v1/downloads/{download_id}", api_key)
        row = dict(data)
        row["observed_at"] = round(time.time(), 3)
        delivery = data.get("delivery")
        delivered_path = (Path(delivery["path"]) if isinstance(delivery, dict)
                          and isinstance(delivery.get("path"), str) else None)
        row["delivered_file_exists"] = delivered_path.is_file() if delivered_path else False
        row["delivered_file_size"] = delivered_path.stat().st_size if delivered_path and delivered_path.is_file() else 0
        observations.append(row)
        if (
            data.get("id") == download_id
            and data.get("hash") == expected_hash.lower()
            and data.get("state") == "completed"
            and type(data.get("completedAt")) is int
            and data["completedAt"] >= 0
            and data.get("payloadVerified") is True
            and data.get("sizeBytes") == expected_size
            and isinstance(delivery, dict)
            and delivery.get("state") == "delivered"
            and delivery.get("ownership") in ("owned", "unowned")
            and delivered_path is not None
            and delivered_path.resolve() == expected_delivery_path.resolve()
            and delivered_path.is_file()
            and delivered_path.stat().st_size == expected_size
            and file_sha256(delivered_path) == expected_sha256
        ):
            return {**row, "deliveryOwnership": delivery["ownership"], "observations": observations[-20:]}
        return None

    return wait_for(
        probe,
        timeout_seconds=timeout_seconds,
        interval_seconds=1.0,
        description=f"emulebb-rust download {download_id} completion",
    )


def require_shared_file_item(shared_files: dict[str, object], file_name: str) -> dict[str, object]:
    """Returns one Rust shared-file row from a paged shared-files payload."""

    items = shared_files.get("items")
    if not isinstance(items, list):
        raise RuntimeError("Rust shared-files response did not expose an items list.")
    for item in items:
        if isinstance(item, dict) and item.get("name") == file_name:
            link = str(item.get("ed2kLink") or "")
            if not link.startswith("ed2k://|file|"):
                raise RuntimeError(f"Rust shared-file row for {file_name} did not expose an ED2K link.")
            return item
    raise RuntimeError(f"Rust shared-files response did not include {file_name}.")


def publish_shared_tree(
    base_url: str,
    api_key: str,
    *,
    root: Path | str,
    file_name: str,
    timeout_seconds: float = 60.0,
) -> dict[str, object]:
    """Configures one current Rust shared-directory root and returns the matched file row."""

    directories = request_json(
        base_url,
        "PATCH",
        "/api/v1/shared-directories",
        api_key,
        {
            "roots": [{"path": str(root)}],
            "confirmReplaceRoots": True,
        },
    )
    reload_result = request_json(
        base_url,
        "POST",
        "/api/v1/shared-directories/operations/reload",
        api_key,
    )
    observations: list[dict[str, object]] = []

    def resolve_shared_file() -> tuple[dict[str, object], dict[str, object]] | None:
        shared_files = request_json(base_url, "GET", "/api/v1/shared-files", api_key)
        items = shared_files.get("items")
        observations.append(
            {
                "count": len(items) if isinstance(items, list) else None,
                "total": shared_files.get("total"),
                "observedAt": round(time.time(), 3),
            }
        )
        try:
            return shared_files, require_shared_file_item(shared_files, file_name)
        except RuntimeError:
            return None

    shared_files, shared_file = wait_for(
        resolve_shared_file,
        timeout_seconds=timeout_seconds,
        interval_seconds=1.0,
        description=f"Rust shared file {file_name}",
    )
    return {
        "directories": directories,
        "reload": reload_result,
        "sharedFiles": {
            "count": len(shared_files.get("items", [])) if isinstance(shared_files.get("items"), list) else 0,
            "matched": shared_file,
            "observations": observations[-20:],
        },
    }


def start_client(
    *,
    repo: Path,
    executable: Path | None,
    profile_dir: Path,
    log_path: Path,
) -> tuple[subprocess.Popen[str], str, Path]:
    """Starts Rust from a staged executable when present, otherwise through Cargo."""

    if executable is not None and executable.is_file():
        return rust_client.start_rust_client_executable(executable, profile_dir, log_path), "executable", executable
    return rust_client.start_rust_client(repo, profile_dir, log_path), "cargo", repo
