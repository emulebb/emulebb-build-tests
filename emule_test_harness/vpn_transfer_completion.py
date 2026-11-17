"""Exact allowlisted transfer completion checks for isolated VPN containers."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .rust_local_ed2k import require_download_id


def load_exact_transfer(inputs_path: Path) -> dict[str, object]:
    payload = json.loads(inputs_path.read_text(encoding="utf-8-sig"))
    rows = payload.get("auto_browse", {}).get("direct_bootstrap_transfers", [])
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("VPN completion proof requires exactly one allowlisted transfer")
    row = rows[0]
    file_hash = str(row.get("hash") or "").lower()
    sha256 = str(row.get("sha256") or "").lower()
    name = str(row.get("name") or "")
    size = row.get("size")
    if (
        not re.fullmatch(r"[0-9a-f]{32}", file_hash)
        or not re.fullmatch(r"[0-9a-f]{64}", sha256)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or Path(name).name != name
    ):
        raise RuntimeError("VPN completion allowlist entry is incomplete or invalid")
    return {"hash": file_hash, "sha256": sha256, "name": name, "size": size}


def ed2k_link(row: dict[str, object]) -> str:
    encoded_name = urllib.parse.quote(str(row["name"]), safe="")
    return (
        f"ed2k://|file|{encoded_name}|{row['size']}|"
        f"{str(row['hash']).upper()}|/"
    )


def container_delivery_matches(run_docker: Callable[..., Any], container: str, delivered_path: str,
                               expected_size: int, expected_sha256: str) -> bool:
    """Verify the exact job output; another matching copy cannot satisfy this proof."""
    stat = run_docker("exec", container, "stat", "-c", "%s", "--", delivered_path, check=False)
    if stat.returncode != 0 or stat.stdout.strip() != str(expected_size):
        return False
    digest = run_docker("exec", container, "sha256sum", "--", delivered_path, check=False)
    fields = digest.stdout.split(maxsplit=1)
    return (digest.returncode == 0 and bool(fields)
            and fields[0].removeprefix("\\").lower() == expected_sha256)


def wait_for_completion(
    *,
    row: dict[str, object],
    create_download: Callable[[dict[str, object]], dict[str, Any]],
    read_download: Callable[[str], dict[str, Any]],
    verify_delivered_sha256: Callable[[str, int, str], bool],
    read_daemon_logs: Callable[[], str],
    timeout_seconds: float,
) -> dict[str, object]:
    admission = create_download({"source": {"type": "ed2k-link", "link": ed2k_link(row)}, "intent": "started"})
    download_id = require_download_id(admission, expected_hash=str(row["hash"]))
    deadline = time.monotonic() + timeout_seconds
    snapshot: dict[str, Any] = {}
    while time.monotonic() < deadline:
        snapshot = read_download(download_id)
        if require_download_id(snapshot, expected_hash=str(row["hash"])) != download_id:
            raise RuntimeError("VPN completion reader substituted a different download job")
        if snapshot.get("state") == "failed":
            raise RuntimeError("VPN download failed before completion; explicit operator action is required")
        delivery = snapshot.get("delivery")
        if (snapshot.get("state") == "completed" and snapshot.get("payloadVerified") is True
                and type(snapshot.get("sizeBytes")) is int and snapshot["sizeBytes"] == row["size"]
                and type(snapshot.get("completedAt")) is int and snapshot["completedAt"] >= 0
                and isinstance(delivery, dict) and delivery.get("state") == "delivered"
                and isinstance(delivery.get("path"), str) and delivery["path"]):
            break
        time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
    else:
        raise RuntimeError("timed out waiting for the exact VPN download to complete")

    if not verify_delivered_sha256(delivery["path"], int(row["size"]), str(row["sha256"])):
        raise RuntimeError("completed VPN download failed delivered SHA-256 verification")
    logs = read_daemon_logs()
    started = "final_completion_rehash_started" in logs
    succeeded = "final_completion_rehash_succeeded" in logs
    if not started or not succeeded:
        raise RuntimeError("completion did not retain final ED2K rehash start/success evidence")
    return {"status": "passed", "downloadId": download_id, "sizeBytes": row["size"],
            "verifiedBytes": snapshot["sizeBytes"], "state": snapshot["state"],
            "sha256Verified": True, "finalRehashStarted": started, "finalRehashSucceeded": succeeded}
