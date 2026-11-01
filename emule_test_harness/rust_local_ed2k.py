"""Shared helpers for LAN-bound eMuleBB Rust local ED2K harness clients."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import rust_client


class ServerSearchFailure(RuntimeError):
    """Carries the terminal REST snapshot for a failed deterministic search."""

    def __init__(self, message: str, evidence: dict[str, object]) -> None:
        super().__init__(message)
        self.evidence = evidence


def request_json(
    base_url: str,
    method: str,
    path: str,
    api_key: str,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    """Runs one authenticated Rust REST request and returns the JSON object payload."""

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
        with urllib.request.urlopen(request, timeout=10.0) as response:
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"Rust REST {method} {path} returned HTTP {exc.code}: {detail or exc.reason}"
        ) from exc
    data = json.loads(text) if text else {}
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    if isinstance(data, dict):
        return data
    raise RuntimeError(f"Rust REST returned a non-object payload for {method} {path}: {data!r}")


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


def wait_for_applied_server_metadata(
    base_url: str,
    api_key: str,
    *,
    expected_address: str,
    expected_port: int,
    expected_name: str,
    expected_description: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for the active endpoint and its exact applied server-list metadata."""

    last_status: dict[str, object] = {}

    def probe() -> dict[str, object] | None:
        status = request_json(base_url, "GET", "/api/v1/status", api_key)
        nested = status.get("servers")
        connection_status = nested if isinstance(nested, dict) else status
        server_entity = request_json(
            base_url,
            "GET",
            f"/api/v1/servers/{expected_address}:{expected_port}",
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
        if (
            connection_status.get("connected") is True
            and current.get("current") is True
            and str(current.get("address") or "").casefold() == expected_address.casefold()
            and current.get("port") == expected_port
            and str(server_entity.get("address") or "").casefold()
            == expected_address.casefold()
            and server_entity.get("port") == expected_port
            and server_entity.get("name") == expected_name
            and server_entity.get("description") == expected_description
            and counters_valid
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
            description="applied current ED2K server metadata",
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
    expected_hash: str,
    expected_name: str,
    expected_size: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Runs exactly one server search and requires one exact result row."""

    try:
        created = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            api_key,
            {"query": query, "method": "server", "type": ""},
        )
    except Exception as exc:  # noqa: BLE001 - preserve the failed REST stimulus
        raise ServerSearchFailure(
            f"Deterministic server search creation failed: {exc}",
            {
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


def wait_for_transfer_completed(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    profile_dir: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until Rust completes a transfer and verifies the stored bytes."""

    observations: list[dict[str, object]] = []
    pieces_path = profile_dir / "transfers" / transfer_hash.lower() / "pieces.bin"

    def probe() -> dict[str, object] | None:
        data = request_json(base_url, "GET", f"/api/v1/transfers/{transfer_hash}", api_key)
        row = dict(data)
        row["observed_at"] = round(time.time(), 3)
        row["pieces_file_exists"] = pieces_path.is_file()
        row["pieces_file_size"] = pieces_path.stat().st_size if pieces_path.is_file() else 0
        observations.append(row)
        if (
            data.get("state") == "completed"
            and int(data.get("completedBytes") or 0) == expected_size
            and pieces_path.is_file()
            and pieces_path.stat().st_size == expected_size
            and file_sha256(pieces_path) == expected_sha256
        ):
            return {**row, "observations": observations[-20:]}
        return None

    return wait_for(
        probe,
        timeout_seconds=timeout_seconds,
        interval_seconds=1.0,
        description=f"emulebb-rust transfer {transfer_hash} completion",
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
    root: Path,
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
