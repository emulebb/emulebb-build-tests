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
    with urllib.request.urlopen(request, timeout=10.0) as response:
        text = response.read().decode("utf-8")
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


def file_sha256(path: Path) -> str:
    """Returns the SHA-256 digest of one file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
) -> dict[str, object]:
    """Configures one recursive Rust shared-directory root and returns the matched file row."""

    directories = request_json(
        base_url,
        "PATCH",
        "/api/v1/shared-directories",
        api_key,
        {
            "roots": [{"path": str(root), "recursive": True}],
            "confirmReplaceRoots": True,
        },
    )
    reload_result = request_json(
        base_url,
        "POST",
        "/api/v1/shared-directories/operations/reload",
        api_key,
    )
    shared_files = request_json(base_url, "GET", "/api/v1/shared-files", api_key)
    shared_file = require_shared_file_item(shared_files, file_name)
    return {
        "directories": directories,
        "reload": reload_result,
        "sharedFiles": {
            "count": len(shared_files.get("items", [])) if isinstance(shared_files.get("items"), list) else 0,
            "matched": shared_file,
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
