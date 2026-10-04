"""Exact allowlisted transfer completion checks for isolated VPN containers."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any


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


def wait_for_completion(
    *,
    row: dict[str, object],
    create_transfer: Callable[[dict[str, object]], None],
    read_transfer: Callable[[str], dict[str, Any]],
    verify_delivered_sha256: Callable[[int, str], bool],
    read_daemon_logs: Callable[[], str],
    timeout_seconds: float,
) -> dict[str, object]:
    create_transfer({"link": ed2k_link(row), "paused": False})
    deadline = time.monotonic() + timeout_seconds
    snapshot: dict[str, Any] = {}
    while time.monotonic() < deadline:
        snapshot = read_transfer(str(row["hash"]))
        if (
            snapshot.get("state") == "completed"
            and int(snapshot.get("completedBytes") or 0) == int(row["size"])
        ):
            break
        time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
    else:
        raise RuntimeError("timed out waiting for the exact VPN transfer to complete")

    if not verify_delivered_sha256(int(row["size"]), str(row["sha256"])):
        raise RuntimeError("completed VPN transfer failed delivered SHA-256 verification")
    logs = read_daemon_logs()
    started = "final_completion_rehash_started" in logs
    succeeded = "final_completion_rehash_succeeded" in logs
    if not started or not succeeded:
        raise RuntimeError("completion did not retain final ED2K rehash start/success evidence")
    return {
        "status": "passed",
        "size": row["size"],
        "completedBytes": snapshot.get("completedBytes"),
        "state": snapshot.get("state"),
        "sha256Verified": True,
        "finalRehashStarted": started,
        "finalRehashSucceeded": succeeded,
    }
