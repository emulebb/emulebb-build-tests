"""Long-soak rust<->MFC converged parity campaign.

Unlike ``converged-live-wire-diff.py`` (which *issues* one gentle automated pass
to both clients and diffs the whole capture), this orchestrator brings both
diagnostics builds up on **persistent, isolated** profiles under
``$EMULEBB_WORKSPACE_OUTPUT_ROOT/soak/`` and leaves them running for a long soak.
Both connect to the SAME operator eD2K server, bootstrap Kad from the SAME
nodes.dat, and share the SAME library roots from the gitignored live-wire inputs.

A human can drive interactive searches/downloads through each client's own UI
(the MFC native GUI window this script opens, and TrackMuleBB pointed at the rust
REST), or ``--auto-drive`` can issue sparse synchronized REST searches/downloads
for an unattended overnight run. In both modes the harness OBSERVES the clients:
it polls both ``/api/v1/searches`` and ``/api/v1/transfers``, correlates the same
search term / ed2k hash across the two clients within a window, and runs the
converged ``ed2k_packet_v1`` / ``diag_event_v1`` diff over each action's time
window (see ``emule_test_harness.soak_action_diff``). A manual ``begin``/``end``
marker brackets actions the auto-correlator can't pair.

REST control plane binds ``X_LOCAL_IP``; the P2P data plane binds the hide.me
tunnel; build artifacts and the soak profiles live under
``EMULEBB_WORKSPACE_OUTPUT_ROOT``. Nothing machine-specific is baked in.

GENTLE LIVE DISCIPLINE: keep searches few and widely spaced. The unattended driver
enforces a minimum five-minute search interval and defaults to a much slower
half-hour cadence.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import diag_event_diff, live_process_monitor, mfc_known_met, packet_trace_diff
from emule_test_harness import converged_live_wire as clw
from emule_test_harness import soak_action_diff as sad
from emule_test_harness import soak_launch
from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints, load_bootstrap_endpoints
from emule_test_harness.live_wire_inputs import load_live_wire_inputs
from emule_test_harness.paths import get_workspace_output_root, reject_windows_temp_path
from emule_test_harness.rust_client import stop_process_tree
from emule_test_harness.soak_launch import (
    DEFAULT_LOG_TRIM_BYTES,
    DEFAULT_MFC_SEED_CONFIG_DIR,
    DEFAULT_SERVER_MET_URL,
    DEFAULT_UPLOAD_LIMIT_KIBPS,
    MFC_API_KEY,
    MFC_ED2K_PORT,
    MFC_KAD_PORT,
    MFC_SERVER_UDP_PORT,
    OPERATOR_SERVER,
    RUST_API_KEY,
    RUST_ED2K_PORT,
    RUST_KAD_PORT,
    bring_up_mfc,
    bring_up_rust,
    log,
)
from emule_test_harness.vm_guest_profiles import retry_http_json
from emule_test_harness.workspace_layout import get_default_workspace_root, resolve_workspace_repo

SCENARIO = "emulebb.flow.converged.soak.hideme.v1"


def parse_duration(text: str) -> float:
    """Parses ``2h`` / ``90m`` / ``3600s`` / ``0`` (run until quit) into seconds."""

    text = text.strip().lower()
    if text in ("", "0", "forever", "inf"):
        return 0.0
    unit = text[-1]
    factor = {"s": 1.0, "m": 60.0, "h": 3600.0}.get(unit)
    if factor is None:
        return float(text)  # bare seconds
    return float(text[:-1]) * factor


# --------------------------------------------------------------------------- #
# REST list extraction (both clients share the /api/v1 envelope shape).
# --------------------------------------------------------------------------- #


def _extract_items(payload: Any, *keys: str) -> list[dict[str, Any]]:
    """Extracts dict rows from an eMuleBB REST list response, tolerating shapes.

    Thin wrapper over the shared soak_launch.api_items envelope logic (dict rows only):
    accepts a bare list, ``{"items": [...]}``, ``{"data": {"items": [...]}}``, or a named
    collection key (``searches`` / ``transfers``) at either level.
    """

    return soak_launch.api_items(payload, *keys, require_dict=True)


def _get_list(
    base_url: str,
    path: str,
    api_key: str,
    *keys: str,
    timeout_seconds: float = 10.0,
) -> list[dict[str, Any]]:
    try:
        payload = retry_http_json(
            f"poll {path}", 1, base_url, path, api_key=api_key, timeout_seconds=timeout_seconds
        )
    except RuntimeError:
        return []
    return _extract_items(payload, *keys)


def _api_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    return data if isinstance(data, dict) else payload


def _row_hash(row: dict[str, Any]) -> str:
    return str(row.get("hash") or row.get("fileHash") or "").strip().lower()


def transfer_hashes(rows: list[dict[str, Any]]) -> set[str]:
    """Returns all transfer hashes visible in a raw REST transfer list."""

    return {file_hash for row in rows if (file_hash := _row_hash(row))}


def transfer_exists(
    base_url: str,
    api_key: str,
    file_hash: str,
    *,
    timeout_seconds: float = 5.0,
) -> bool:
    """Returns whether a client already exposes a transfer/known-file hash."""

    try:
        payload = retry_http_json(
            "probe transfer",
            1,
            base_url,
            f"/api/v1/transfers/{file_hash}",
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
    except RuntimeError:
        return False
    return bool(_api_data(payload))


def safe_common_download_candidate(
    rust_rows: list[dict[str, Any]],
    mfc_rows: list[dict[str, Any]],
    *,
    rust_mod: Any,
    existing_hashes: set[str] | None = None,
    existing_probe: Callable[[str], bool] | None = None,
) -> dict[str, Any] | None:
    """Selects one safe, not-yet-present result hash from both search pages."""

    mfc_hashes = {_row_hash(row) for row in mfc_rows if _row_hash(row)}
    existing_hashes = {item.strip().lower() for item in (existing_hashes or set()) if item}
    candidates: list[dict[str, Any]] = []
    for row in rust_rows:
        file_hash = _row_hash(row)
        if not file_hash or file_hash not in mfc_hashes:
            continue
        if file_hash in existing_hashes:
            continue
        if existing_probe is not None and existing_probe(file_hash):
            continue
        if rust_mod.safe_download_rejection_reason(row) is None:
            candidates.append(row)
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda row: (
            int(row.get("sources") or row.get("completeSources") or 0),
            -int(row.get("sizeBytes") or row.get("size") or 0),
        ),
    )


def create_search(base_url: str, api_key: str, *, query: str, method: str) -> str:
    created = retry_http_json(
        "soak search create",
        2,
        base_url,
        "/api/v1/searches",
        api_key=api_key,
        method="POST",
        body={"query": query, "method": method, "type": ""},
        timeout_seconds=45.0,
    )
    return str(_api_data(created).get("id") or "")


def poll_search_results(base_url: str, api_key: str, search_id: str, *, timeout_seconds: float) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    last_rows: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        page = retry_http_json(
            "soak search poll",
            2,
            base_url,
            f"/api/v1/searches/{search_id}",
            api_key=api_key,
            timeout_seconds=30.0,
        )
        data = _api_data(page)
        rows = _extract_items(data, "items")
        if rows:
            last_rows = rows
        if str(data.get("status") or "").casefold() in {"complete", "completed"}:
            return rows
        time.sleep(2.0)
    return last_rows


def trigger_download(base_url: str, api_key: str, search_id: str, file_hash: str) -> dict[str, Any]:
    download = retry_http_json(
        "soak download",
        2,
        base_url,
        f"/api/v1/searches/{search_id}/results/{file_hash}/operations/download",
        api_key=api_key,
        method="POST",
        body={"paused": False, "categoryId": 0},
        timeout_seconds=30.0,
    )
    try:
        retry_http_json(
            "soak download resume",
            1,
            base_url,
            f"/api/v1/transfers/{file_hash}/operations/resume",
            api_key=api_key,
            method="POST",
            body={},
            timeout_seconds=15.0,
        )
    except RuntimeError:
        pass
    return download


def drive_automatic_cycle(
    *,
    cycle_index: int,
    query: str,
    method: str,
    rust_base: str,
    mfc_base: str,
    rust_mod: Any,
    download: bool,
    search_timeout_seconds: float,
) -> dict[str, Any]:
    """Runs one gentle synchronized search and records one candidate for later download."""

    cycle: dict[str, Any] = {
        "cycle": cycle_index,
        "queryIndex": cycle_index - 1,
        "method": method,
        "query": query,
        "downloadRequested": download,
    }
    rust_search_id = create_search(rust_base, RUST_API_KEY, query=query, method=method)
    mfc_search_id = create_search(mfc_base, MFC_API_KEY, query=query, method=method)
    cycle["searchIds"] = {"rust": rust_search_id, "mfc": mfc_search_id}
    rust_rows = poll_search_results(rust_base, RUST_API_KEY, rust_search_id, timeout_seconds=search_timeout_seconds)
    mfc_rows = poll_search_results(mfc_base, MFC_API_KEY, mfc_search_id, timeout_seconds=search_timeout_seconds)
    cycle["resultCounts"] = {"rust": len(rust_rows), "mfc": len(mfc_rows)}
    if download:
        rust_transfer_hashes = transfer_hashes(
            _get_list(rust_base, "/api/v1/transfers", RUST_API_KEY, "transfers", timeout_seconds=30.0)
        )
        mfc_transfer_hashes = transfer_hashes(
            _get_list(mfc_base, "/api/v1/transfers", MFC_API_KEY, "transfers", timeout_seconds=30.0)
        )
        existing_hashes = rust_transfer_hashes | mfc_transfer_hashes
        cycle["downloadExistingHashCounts"] = {
            "rust": len(rust_transfer_hashes),
            "mfc": len(mfc_transfer_hashes),
            "combined": len(existing_hashes),
        }

        probe_skips = {"rust": 0, "mfc": 0, "combined": 0}

        def existing_hash_probe(file_hash: str) -> bool:
            rust_known = transfer_exists(rust_base, RUST_API_KEY, file_hash)
            mfc_known = transfer_exists(mfc_base, MFC_API_KEY, file_hash)
            if rust_known:
                probe_skips["rust"] += 1
            if mfc_known:
                probe_skips["mfc"] += 1
            if rust_known or mfc_known:
                probe_skips["combined"] += 1
                return True
            return False

        candidate = safe_common_download_candidate(
            rust_rows,
            mfc_rows,
            rust_mod=rust_mod,
            existing_hashes=existing_hashes,
            existing_probe=existing_hash_probe,
        )
        cycle["downloadExistingHashProbeSkips"] = probe_skips
        if candidate is None:
            cycle["download"] = {"ok": False, "reason": "no common safe candidate"}
        else:
            file_hash = _row_hash(candidate)
            cycle["download"] = {
                "ok": None,
                "scheduled": True,
                "hash": file_hash,
                "sizeBytes": candidate.get("sizeBytes") or candidate.get("size"),
                "sources": candidate.get("sources"),
                "searchIds": {"rust": rust_search_id, "mfc": mfc_search_id},
            }
    return cycle


def execute_scheduled_download(
    *,
    rust_base: str,
    mfc_base: str,
    download: dict[str, Any],
) -> dict[str, Any]:
    """Triggers a previously selected common download on both clients."""

    file_hash = str(download.get("hash") or "").strip().lower()
    search_ids = download.get("searchIds") if isinstance(download.get("searchIds"), dict) else {}
    rust_search_id = str(search_ids.get("rust") or "")
    mfc_search_id = str(search_ids.get("mfc") or "")
    if not file_hash or not rust_search_id or not mfc_search_id:
        raise RuntimeError("scheduled download is missing hash or search ids")
    return {
        "rust": trigger_download(rust_base, RUST_API_KEY, rust_search_id, file_hash),
        "mfc": trigger_download(mfc_base, MFC_API_KEY, mfc_search_id, file_hash),
    }


def status_snapshot(base_url: str, api_key: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
    try:
        status = retry_http_json(
            "soak status",
            1,
            base_url,
            "/api/v1/status",
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
    except RuntimeError as exc:
        return {"error": str(exc)}
    data = _api_data(status)
    runtime = data.get("runtimeDiagnostics") if isinstance(data.get("runtimeDiagnostics"), dict) else {}
    servers = data.get("servers") if isinstance(data.get("servers"), dict) else {}
    current_server = servers.get("currentServer") if isinstance(servers.get("currentServer"), dict) else {}
    return {
        "connected": bool(servers.get("connected")),
        "lowId": servers.get("lowId"),
        "serverAddress": current_server.get("address"),
        "serverPort": current_server.get("port"),
        "activeUploads": runtime.get("activeUploads"),
        "waitingUploads": runtime.get("waitingUploads"),
        "sharedFileCount": runtime.get("sharedFileCount"),
        "sharedHashingCount": runtime.get("sharedHashingCount"),
    }


def operator_connected(status: dict[str, Any], *, endpoint: str = OPERATOR_SERVER) -> bool:
    """Returns true when a redacted status snapshot is on the required server."""

    if not status.get("connected"):
        return False
    address, port_text = endpoint.rsplit(":", 1)
    return str(status.get("serverAddress") or "") == address and int(status.get("serverPort") or 0) == int(port_text)


def connectivity_gate(
    rust_status: dict[str, Any],
    mfc_status: dict[str, Any],
    *,
    rust_endpoint: str = OPERATOR_SERVER,
    mfc_endpoint: str = OPERATOR_SERVER,
) -> dict[str, Any]:
    """Summarizes whether an action can be compared under configured-server parity."""

    rust_ok = operator_connected(rust_status, endpoint=rust_endpoint)
    mfc_ok = operator_connected(mfc_status, endpoint=mfc_endpoint)
    return {
        "ok": rust_ok and mfc_ok,
        "rustConnected": bool(rust_status.get("connected")),
        "mfcConnected": bool(mfc_status.get("connected")),
        "rustOnOperator": rust_ok,
        "mfcOnOperator": mfc_ok,
    }


def checkpoint_operator_reconnect(
    base_url: str,
    api_key: str,
    status: dict[str, Any],
    *,
    endpoint: str = OPERATOR_SERVER,
) -> dict[str, Any]:
    """Attempts a live operator-server reconnect when a checkpoint sees disconnect."""

    if status.get("error"):
        return {"attempted": False, "reason": "status_error"}
    if operator_connected(status, endpoint=endpoint):
        return {"attempted": False, "reason": "already_connected"}
    try:
        result = soak_launch.connect_operator_server(
            base_url,
            api_key,
            description="checkpoint operator server reconnect",
            endpoint=endpoint,
        )
    except RuntimeError as exc:
        return {"attempted": True, "ok": False, "error": str(exc)}
    connect_data = _api_data(result.get("connect") if isinstance(result, dict) else result)
    return {
        "attempted": True,
        "ok": True,
        "connected": bool(connect_data.get("connected")),
        "connecting": bool(connect_data.get("connecting")),
        "serverCount": connect_data.get("serverCount"),
    }


# --------------------------------------------------------------------------- #
# Trace loading (dumps grow during the soak; load + concat current contents).
# --------------------------------------------------------------------------- #


def _glob_all(dump_dir: Path, globs: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for pattern in globs:
        for path in sorted(dump_dir.glob(pattern)):
            if path not in seen:
                seen.add(path)
                found.append(path)
    return found


def load_packets(dump_dir: Path, *, side: str) -> list[dict[str, Any]]:
    globs = clw.RUST_PACKET_DUMP_GLOBS if side == "rust" else clw.EMULE_PACKET_DUMP_GLOBS
    records: list[dict[str, Any]] = []
    for path in _glob_all(dump_dir, globs):
        records.extend(packet_trace_diff.load_trace(path))
    return records


def load_diag(dump_dir: Path, *, side: str) -> list[dict[str, Any]]:
    globs = clw.RUST_DIAG_DUMP_GLOBS if side == "rust" else clw.EMULE_DIAG_DUMP_GLOBS
    records: list[dict[str, Any]] = []
    for path in _glob_all(dump_dir, globs):
        records.extend(diag_event_diff.load_trace(path))
    return records


def public_action_label(kind: str) -> str:
    """Returns a privacy-safe label for retained soak logs."""

    return f"{kind} action"


# --------------------------------------------------------------------------- #
# Action tracker: detect new actions per poll, correlate across clients.
# --------------------------------------------------------------------------- #


class ActionTracker:
    """Accumulates observed actions and yields settled, correlated pairs.

    ``tick`` is fed each poll's normalized REST snapshots; it returns the action
    pairs whose capture window has elapsed (ready to diff) and the actions that
    have aged out of the correlation window with no counterpart (manual-marker
    candidates), each at most once.
    """

    def __init__(
        self,
        *,
        window_seconds: float,
        settle_seconds: float,
        lead_seconds: float,
        download_settle_seconds: float | None = None,
    ) -> None:
        self.window = window_seconds
        self.settle = settle_seconds
        self.download_settle = (
            download_settle_seconds if download_settle_seconds is not None else settle_seconds
        )
        self.lead = lead_seconds
        self.seen: dict[tuple[str, str], set[str]] = {}
        self.rust: list[sad.Action] = []
        self.mfc: list[sad.Action] = []
        self.processed: set[str] = set()
        self.synchronized_keys: set[tuple[str, str]] = set()

    def settle_seconds_for(self, kind: str) -> float:
        """Returns the post-action capture padding for one action kind."""

        return self.download_settle if kind == sad.DOWNLOAD else self.settle

    def _ingest(self, client: str, kind: str, items: list[dict[str, str]], now: datetime) -> None:
        key = (client, kind)
        fresh, self.seen[key] = sad.detect_actions(
            self.seen.get(key), items, client=client, kind=kind, observed_at=now
        )
        fresh = [action for action in fresh if (action.kind, action.key) not in self.synchronized_keys]
        bucket = self.rust if client == "rust" else self.mfc
        bucket.extend(fresh)
        for action in fresh:
            log(f"observed {client} {public_action_label(kind)}")

    def prime(
        self,
        *,
        rust_searches: list[dict[str, str]],
        rust_transfers: list[dict[str, str]],
        mfc_searches: list[dict[str, str]],
        mfc_transfers: list[dict[str, str]],
    ) -> dict[str, int]:
        """Seeds the seen-id sets from existing REST rows without recording actions."""

        snapshots = {
            ("rust", sad.SEARCH): rust_searches,
            ("rust", sad.DOWNLOAD): rust_transfers,
            ("mfc", sad.SEARCH): mfc_searches,
            ("mfc", sad.DOWNLOAD): mfc_transfers,
        }
        for key, items in snapshots.items():
            self.seen[key] = {item["id"] for item in items}
        return {
            "rustSearches": len(rust_searches),
            "rustTransfers": len(rust_transfers),
            "mfcSearches": len(mfc_searches),
            "mfcTransfers": len(mfc_transfers),
        }

    def record_synchronized_action(
        self,
        *,
        kind: str,
        key: str,
        label: str,
        observed_at: datetime,
        action_id: str,
    ) -> None:
        """Records an action the auto-driver successfully issued to both clients."""

        self.synchronized_keys.add((kind, key))
        self.rust.append(
            sad.Action(
                client="rust",
                kind=kind,
                action_id=f"rust:{action_id}",
                key=key,
                label=label,
                observed_at=observed_at,
            )
        )
        self.mfc.append(
            sad.Action(
                client="mfc",
                kind=kind,
                action_id=f"mfc:{action_id}",
                key=key,
                label=label,
                observed_at=observed_at,
            )
        )
        log(f"observed synchronized {public_action_label(kind)}")

    def tick(
        self,
        now: datetime,
        *,
        rust_searches: list[dict[str, str]],
        rust_transfers: list[dict[str, str]],
        mfc_searches: list[dict[str, str]],
        mfc_transfers: list[dict[str, str]],
    ) -> tuple[list[sad.ActionPair], list[sad.Action]]:
        self._ingest("rust", sad.SEARCH, rust_searches, now)
        self._ingest("rust", sad.DOWNLOAD, rust_transfers, now)
        self._ingest("mfc", sad.SEARCH, mfc_searches, now)
        self._ingest("mfc", sad.DOWNLOAD, mfc_transfers, now)

        active_rust = [a for a in self.rust if a.action_id not in self.processed]
        active_mfc = [a for a in self.mfc if a.action_id not in self.processed]
        pairs, unpaired_rust, unpaired_mfc = sad.correlate_actions(
            active_rust, active_mfc, window_seconds=self.window
        )

        ready_pairs: list[sad.ActionPair] = []
        for pair in pairs:
            _, t1 = pair.window(
                lead_seconds=self.lead,
                settle_seconds=self.settle_seconds_for(pair.kind),
            )
            if now >= t1:
                self.processed.add(pair.rust.action_id)
                self.processed.add(pair.mfc.action_id)
                ready_pairs.append(pair)

        aged_unpaired: list[sad.Action] = []
        for action in (*unpaired_rust, *unpaired_mfc):
            age = (now - action.observed_at).total_seconds()
            if age > self.window + self.settle_seconds_for(action.kind):
                self.processed.add(action.action_id)
                aged_unpaired.append(action)
        return ready_pairs, aged_unpaired


# --------------------------------------------------------------------------- #
# Stdin marker thread.
# --------------------------------------------------------------------------- #


def _stdin_reader(commands: "queue.Queue[str]") -> None:
    for line in sys.stdin:
        commands.put(line.strip())


# --------------------------------------------------------------------------- #
# Process monitoring (best-effort; Windows handle-based sampler).
# --------------------------------------------------------------------------- #


class ProcMonitor:
    """Wraps live_process_monitor sampling for one process (no-op off Windows)."""

    def __init__(self, name: str, pid: int) -> None:
        self.name = name
        self.pid = pid
        self.started = time.monotonic()
        self.last_mono: float | None = None
        self.last_cpu: float | None = None
        self.rows: list[dict[str, Any]] = []
        self.handle: int | None = None
        try:
            self.handle = live_process_monitor.open_process(pid)
        except Exception:  # noqa: BLE001 - monitoring is best-effort
            self.handle = None

    def sample(self) -> dict[str, Any] | None:
        if self.handle is None:
            return None
        try:
            row = live_process_monitor.sample_process_metrics(
                handle=self.handle,
                started_monotonic=self.started,
                last_sample_monotonic=self.last_mono,
                last_cpu_seconds=self.last_cpu,
            )
        except OSError:
            return None
        self.last_mono = time.monotonic()
        cpu = row.get("cpu_seconds")
        self.last_cpu = float(cpu) if isinstance(cpu, (int, float)) else 0.0
        self.rows.append(row)
        return row

    def summary(self) -> dict[str, Any]:
        return live_process_monitor.summarize_metric_rows(self.rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inputs", required=True, help="Path to live-wire-inputs.local.json (shared roots).")
    parser.add_argument("--shared-dir-file", help="Optional MFC shareddir.dat to use as the parity share source.")
    parser.add_argument("--rust-incoming-dir", help="Optional Rust incomingDir; also added to the parity share set.")
    parser.add_argument(
        "--fresh-rust-runtime",
        action="store_true",
        help=(
            "Use a campaign-scoped Rust runtime instead of the persistent "
            "soak/rust-runtime profile. This intentionally discards the Rust "
            "shared-file hash cache for the run."
        ),
    )
    parser.add_argument("--duration", default="0", help="Soak length: 2h / 90m / 3600s / 0 (until quit).")
    parser.add_argument("--poll-interval", type=float, default=5.0, help="REST poll cadence (s).")
    parser.add_argument(
        "--poll-rest-timeout",
        type=float,
        default=90.0,
        help="Per-request timeout for steady-state REST polls (s).",
    )
    parser.add_argument("--checkpoint-interval", type=float, default=300.0, help="Stability/coverage checkpoint cadence (s).")
    parser.add_argument("--rest-timeout", type=float, default=60.0, help="Seconds to wait for each client's REST startup.")
    parser.add_argument("--connect-timeout", type=float, default=240.0, help="Seconds to wait for eD2K connection evidence.")
    parser.add_argument("--correlation-window", type=float, default=sad.DEFAULT_CORRELATION_WINDOW_SECONDS, help="Max gap to pair the same action across clients (s).")
    parser.add_argument("--settle-seconds", type=float, default=sad.DEFAULT_SETTLE_SECONDS, help="Window padding after an action before diffing (s).")
    parser.add_argument("--download-settle-seconds", type=float, default=600.0, help="Window padding after a download action before diffing (s).")
    parser.add_argument("--lead-seconds", type=float, default=sad.DEFAULT_LEAD_SECONDS, help="Window padding before an action (s).")
    parser.add_argument("--rust-rest-port", type=int, default=4731)
    parser.add_argument("--mfc-rest-port", type=int, default=4732)
    parser.add_argument("--rust-ed2k-port", type=int, default=RUST_ED2K_PORT)
    parser.add_argument("--rust-kad-port", type=int, default=RUST_KAD_PORT)
    parser.add_argument("--mfc-ed2k-port", type=int, default=MFC_ED2K_PORT)
    parser.add_argument("--mfc-kad-port", type=int, default=MFC_KAD_PORT)
    parser.add_argument("--mfc-server-udp-port", type=int, default=MFC_SERVER_UDP_PORT)
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL fallback when no local nodes.dat is selected.")
    parser.add_argument("--nodes-file", help="Optional local nodes.dat to seed Rust Kad bootstrap; defaults to the MFC profile file when available.")
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL, help="server.met URL for rust import (empty to skip).")
    parser.add_argument("--rust-server", default=OPERATOR_SERVER, help="eD2K server endpoint for Rust, host:port.")
    parser.add_argument("--mfc-server", default=OPERATOR_SERVER, help="eD2K server endpoint for MFC, host:port.")
    parser.add_argument("--bootstrap-limit", type=int, default=40)
    parser.add_argument("--profile-seed-dir", help="MFC profile seed config directory.")
    parser.add_argument("--mfc-profile-dir", help="Launch MFC directly with this profile directory instead of a copied seed profile.")
    parser.add_argument(
        "--skip-mfc-known-met-import",
        action="store_true",
        help="Skip pre-seeding Rust metadata from the MFC profile's config/known.met before launch.",
    )
    parser.add_argument(
        "--mfc-shared-files-inventory",
        help=(
            "Optional JSON captured from MFC /api/v1/shared-files. When present, "
            "pre-seed Rust metadata by exact shared-file path/hash before launch."
        ),
    )
    parser.add_argument("--upload-limit-kibps", type=int, default=DEFAULT_UPLOAD_LIMIT_KIBPS, help="Upload cap to apply to both clients.")
    parser.add_argument("--log-trim-bytes", type=int, default=DEFAULT_LOG_TRIM_BYTES, help="Best-effort log tail-trim threshold; 0 disables.")
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    parser.add_argument("--no-obfuscation", action="store_true", help="Disable protocol obfuscation on both clients.")
    parser.add_argument("--trackmulebb-cmd", help="Optional command to launch TrackMuleBB pointed at the rust REST.")
    parser.add_argument("--auto-drive", action="store_true", help="Unattended gentle driver: issue synchronized searches/downloads over REST.")
    parser.add_argument("--search-profile", default="generic_open", help="live-wire search_terms profile for --auto-drive.")
    parser.add_argument("--auto-method", choices=("server", "kad", "automatic"), default="server", help="Search method for --auto-drive.")
    parser.add_argument("--auto-start-delay", type=float, default=60.0, help="Seconds to wait before the first automated action.")
    parser.add_argument("--auto-search-interval", type=float, default=1800.0, help="Gentle interval between automated search cycles.")
    parser.add_argument("--auto-search-timeout", type=float, default=90.0, help="Seconds to wait for each client's search page.")
    parser.add_argument("--auto-download-every", type=int, default=2, help="Start one common safe download every N automated search cycles; 0 disables.")
    parser.add_argument("--auto-download-delay", type=float, default=90.0, help="Seconds to wait after selecting a download candidate before starting it.")
    parser.add_argument("--auto-max-cycles", type=int, default=0, help="Maximum automated cycles; 0 means bounded only by --duration/quit.")
    return parser


def write_summary(summary: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def trim_oversized_file(path: Path, *, max_bytes: int) -> dict[str, Any] | None:
    """Best-effort tail trim for long-running diagnostic output files."""

    if max_bytes <= 0 or not path.is_file():
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= max_bytes:
        return None
    keep = max(max_bytes // 2, 1024 * 1024)
    try:
        with path.open("rb+") as handle:
            handle.seek(max(0, size - keep))
            data = handle.read()
            newline = data.find(b"\n")
            if newline > 0:
                data = data[newline + 1:]
            handle.seek(0)
            handle.truncate()
            handle.write(data)
    except OSError as exc:
        return {"path": str(path), "beforeBytes": size, "error": f"{type(exc).__name__}: {exc}"}
    try:
        after = path.stat().st_size
    except OSError:
        after = None
    return {"path": str(path), "beforeBytes": size, "afterBytes": after}


def trim_log_tree(paths: list[Path], *, max_bytes: int) -> list[dict[str, Any]]:
    """Trims known soak output logs and returns compact evidence rows."""

    if max_bytes <= 0:
        return []
    candidates: list[Path] = []
    for path in paths:
        if path.is_file():
            candidates.append(path)
        elif path.is_dir():
            for pattern in ("*.log", "*.jsonl", "daemon.out"):
                candidates.extend(path.glob(pattern))
    results: list[dict[str, Any]] = []
    for candidate in sorted(set(candidates)):
        result = trim_oversized_file(candidate, max_bytes=max_bytes)
        if result is not None:
            results.append(result)
    return results


def resolve_rust_runtime_paths(soak_root: Path, campaign_id: str, *, fresh: bool) -> dict[str, Path | str | bool]:
    """Returns the Rust runtime/cache path selection for a converged soak run."""

    runtime_dir = soak_root / (f"rust-runtime-{campaign_id}" if fresh else "rust-runtime")
    return {
        "runtimeDir": runtime_dir,
        "packetDumpDir": runtime_dir / "packet-dump",
        "mode": "fresh-campaign" if fresh else "persistent",
        "fresh": fresh,
    }


def resolve_rust_repo() -> Path:
    """Resolves the active emulebb-rust repo from the generated workspace manifest."""

    return resolve_workspace_repo(get_default_workspace_root(REPO_ROOT), "emulebb_rust")


def import_mfc_known_met_for_rust_profile(
    *,
    mfc_profile_dir: Path | None,
    rust_runtime_dir: Path,
    shared_roots: list[object],
    enabled: bool,
) -> dict[str, Any]:
    """Pre-seed Rust metadata from MFC known.met without leaking file names/paths."""

    if not enabled:
        return {"enabled": False, "status": "skipped", "reason": "disabled"}
    if mfc_profile_dir is None:
        return {"enabled": True, "status": "skipped", "reason": "no-mfc-profile-dir"}

    known_met = mfc_profile_dir / "config" / "known.met"
    if not known_met.is_file():
        return {"enabled": True, "status": "skipped", "reason": "known-met-missing"}

    raw = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=resolve_rust_repo(),
        metadata_db=rust_runtime_dir / "metadata.sqlite",
        known_met=known_met,
        shared_roots=[Path(root) for root in soak_launch.shared_root_paths(shared_roots)],
    )
    return {
        "enabled": True,
        "status": "imported",
        "knownMetRecords": raw["knownMetRecords"],
        "sharedFilesScanned": raw["sharedFilesScanned"],
        "matchedRecords": raw["matchedRecords"],
        "importedRecords": raw["importedRecords"],
        "dryRun": raw["dryRun"],
        "skipped": raw["skipped"],
    }


def import_mfc_shared_files_inventory_for_rust_profile(
    *,
    mfc_profile_dir: Path | None,
    rust_runtime_dir: Path,
    shared_roots: list[object],
    inventory_path: Path | None,
) -> dict[str, Any]:
    """Pre-seed Rust metadata from an exact MFC REST shared-files inventory."""

    if inventory_path is None:
        return {"enabled": False, "status": "skipped", "reason": "no-inventory"}
    if mfc_profile_dir is None:
        return {"enabled": True, "status": "skipped", "reason": "no-mfc-profile-dir"}
    if not inventory_path.is_file():
        return {"enabled": True, "status": "skipped", "reason": "inventory-missing"}

    known_met = mfc_profile_dir / "config" / "known.met"
    if not known_met.is_file():
        return {"enabled": True, "status": "skipped", "reason": "known-met-missing"}

    rows = mfc_known_met.load_shared_file_rows_json(inventory_path)
    raw = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=resolve_rust_repo(),
        metadata_db=rust_runtime_dir / "metadata.sqlite",
        known_met=known_met,
        shared_file_rows=rows,
        shared_roots=[Path(root) for root in soak_launch.shared_root_paths(shared_roots)],
    )
    return {
        "enabled": True,
        "status": "imported",
        "knownMetRecords": raw["knownMetRecords"],
        "sharedFileRows": raw["sharedFileRows"],
        "matchedRows": raw["matchedRows"],
        "importedRows": raw["importedRows"],
        "dryRun": raw["dryRun"],
        "skipped": raw["skipped"],
    }


def resolve_kad_bootstrap_endpoints(
    *,
    mfc_profile_dir: Path | None,
    nodes_file: Path | None,
    nodes_url: str,
    limit: int,
) -> dict[str, Any]:
    """Resolve Rust Kad bootstrap from the exact MFC nodes.dat when available."""

    selected_nodes_file = nodes_file
    source = "explicit-file" if selected_nodes_file is not None else "url"
    if selected_nodes_file is None and mfc_profile_dir is not None:
        profile_nodes_file = mfc_profile_dir / "config" / "nodes.dat"
        if profile_nodes_file.is_file():
            selected_nodes_file = profile_nodes_file
            source = "mfc-profile"

    if selected_nodes_file is not None:
        if not selected_nodes_file.is_file():
            raise RuntimeError("--nodes-file does not exist.")
        endpoints = load_bootstrap_endpoints(selected_nodes_file, limit=limit)
        return {
            "source": source,
            "sourceKind": "file",
            "endpoints": endpoints,
            "nodesDatUrl": None,
            "nodesDatFileSelected": True,
        }

    endpoints = fetch_bootstrap_endpoints(nodes_url, limit=limit)
    return {
        "source": "url",
        "sourceKind": "url",
        "endpoints": endpoints,
        "nodesDatUrl": nodes_url,
        "nodesDatFileSelected": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    duration = parse_duration(args.duration)
    obfuscation = not args.no_obfuscation
    if args.poll_interval <= 0.0:
        raise ValueError("--poll-interval must be greater than zero.")
    if args.poll_rest_timeout <= 0.0:
        raise ValueError("--poll-rest-timeout must be greater than zero.")
    if args.lead_seconds < 0.0:
        raise ValueError("--lead-seconds must be zero or greater.")
    if args.settle_seconds < 0.0:
        raise ValueError("--settle-seconds must be zero or greater.")
    if args.download_settle_seconds < 0.0:
        raise ValueError("--download-settle-seconds must be zero or greater.")
    if args.upload_limit_kibps < 0:
        raise ValueError("--upload-limit-kibps must be zero or greater.")
    if args.log_trim_bytes < 0:
        raise ValueError("--log-trim-bytes must be zero or greater.")
    if args.rest_timeout <= 0.0:
        raise ValueError("--rest-timeout must be greater than zero.")
    if args.connect_timeout <= 0.0:
        raise ValueError("--connect-timeout must be greater than zero.")
    endpoint_ports = soak_launch.require_distinct_endpoint_ports(
        rust_ed2k_port=args.rust_ed2k_port,
        rust_kad_port=args.rust_kad_port,
        mfc_ed2k_port=args.mfc_ed2k_port,
        mfc_kad_port=args.mfc_kad_port,
        mfc_server_udp_port=args.mfc_server_udp_port,
    )

    rest_addr = os.environ.get("X_LOCAL_IP", "").strip()
    if not rest_addr:
        raise RuntimeError("X_LOCAL_IP must be set (REST control plane binds the LAN IP).")
    output_root = get_workspace_output_root()

    rust_exe = clw.resolve_rust_diagnostics_exe(output_root)
    mfc_exe = clw.resolve_mfc_diagnostics_exe(
        output_root, variant=args.mfc_variant, arch=args.mfc_arch, configuration=args.mfc_configuration
    )

    mods = soak_launch.load_helper_modules("observer")
    rust_mod = mods["rust"]
    live_common = mods["live_common"]
    rest_smoke = mods["rest_smoke"]
    shared_dirs_mod = mods["shared_dirs"]

    inputs_path = Path(args.inputs).resolve()
    mfc_profile_dir = Path(args.mfc_profile_dir).resolve() if args.mfc_profile_dir else None
    if mfc_profile_dir is None:
        # Fall back to the operator-configured persisted MFC profile from live-wire
        # inputs (mfc_profile.profile_dir) when no explicit --mfc-profile-dir is given.
        inputs_profile = load_live_wire_inputs(inputs_path).mfc_profile_dir
        if inputs_profile is not None:
            mfc_profile_dir = inputs_profile.resolve()
    rust_incoming_dir = Path(args.rust_incoming_dir).resolve() if args.rust_incoming_dir else None
    shared_dir_file = Path(args.shared_dir_file).resolve() if args.shared_dir_file else None
    nodes_file = Path(args.nodes_file).resolve() if args.nodes_file else None
    mfc_shared_files_inventory = (
        Path(args.mfc_shared_files_inventory).resolve() if args.mfc_shared_files_inventory else None
    )
    if shared_dir_file is None and mfc_profile_dir is not None:
        shared_dir_file = mfc_profile_dir / "config" / "shareddir.dat"
    if shared_dir_file is not None:
        if not shared_dir_file.is_file():
            raise RuntimeError(f"--shared-dir-file does not exist: {shared_dir_file}")
        shared_roots = soak_launch.load_shareddir_root_entries(
            shared_dir_file,
            extra_roots=[rust_incoming_dir] if rust_incoming_dir is not None else None,
        )
        shared_roots, skipped_inaccessible_shared_roots = soak_launch.existing_shared_roots(shared_roots)
        shared_root_source = "shareddir.dat"
    else:
        shared_roots = rust_mod.load_shared_roots(inputs_path)
        skipped_inaccessible_shared_roots = 0
        shared_root_source = "live-wire inputs"
    if not shared_roots:
        raise RuntimeError("No shared roots resolved for the soak run.")
    auto_terms: list[str] = []
    if args.auto_drive:
        if args.auto_download_every < 0:
            raise ValueError("--auto-download-every must be zero or greater.")
        if args.auto_max_cycles < 0:
            raise ValueError("--auto-max-cycles must be zero or greater.")
        if args.auto_search_interval < 300.0:
            raise ValueError("--auto-search-interval must be at least 300 seconds to keep public live traffic gentle.")
        if args.auto_download_delay < 0.0:
            raise ValueError("--auto-download-delay must be zero or greater.")
        auto_terms = clw.select_search_terms(
            rust_mod.load_search_terms(inputs_path, args.search_profile),
            max_terms=1000,
        )
    auto_download_delay = max(
        float(args.auto_download_delay),
        float(args.lead_seconds + args.settle_seconds + args.poll_interval),
    )

    campaign_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    soak_root = output_root / "soak"
    rust_runtime_selection = resolve_rust_runtime_paths(
        soak_root,
        campaign_id,
        fresh=bool(args.fresh_rust_runtime),
    )
    rust_runtime = Path(rust_runtime_selection["runtimeDir"])
    rust_packet_dump = Path(rust_runtime_selection["packetDumpDir"])
    mfc_artifacts = soak_root / "mfc-profile"
    report_dir = soak_root / "reports" / campaign_id
    actions_dir = report_dir / "actions"
    reject_windows_temp_path(report_dir, "soak report directory")
    report_dir.mkdir(parents=True, exist_ok=True)
    summary_path = report_dir / "summary.json"
    summary = sad.empty_summary(campaign_id)
    summary["driver"] = {
        "autoDrive": bool(args.auto_drive),
        "searchProfile": args.search_profile if args.auto_drive else None,
        "method": args.auto_method if args.auto_drive else None,
        "searchIntervalSeconds": args.auto_search_interval if args.auto_drive else None,
        "downloadEvery": args.auto_download_every if args.auto_drive else None,
        "downloadDelaySeconds": auto_download_delay if args.auto_drive else None,
        "maxCycles": args.auto_max_cycles if args.auto_drive else None,
        "cycles": [],
        "connectivitySkips": [],
    }

    log(f"campaign {campaign_id} - sharing {len(shared_roots)} library root(s) on both clients")
    log(f"rust runtime mode: {rust_runtime_selection['mode']} ({rust_runtime.name})")
    log(
        "P2P endpoint ports: "
        f"rust TCP {args.rust_ed2k_port}/UDP {args.rust_kad_port}; "
        f"MFC TCP {args.mfc_ed2k_port}/UDP {args.mfc_kad_port}"
    )
    log(f"reports under {report_dir}")

    log("ensuring hide.me split tunnel for both clients...")
    rust_vpn = ensure_vpn_ready(rust_exe, name="eMuleBB Rust")
    mfc_vpn = ensure_vpn_ready(mfc_exe, name="eMuleBB MFC")
    bind_ip = soak_launch.require_same_vpn_bind_ip(rust_vpn, mfc_vpn)
    log(f"hide.me bind IP: {bind_ip}")

    bootstrap_selection = resolve_kad_bootstrap_endpoints(
        mfc_profile_dir=mfc_profile_dir,
        nodes_file=nodes_file,
        nodes_url=args.nodes_url,
        limit=args.bootstrap_limit,
    )
    bootstrap_nodes = list(bootstrap_selection["endpoints"])
    log(
        "Kad bootstrap from "
        f"{bootstrap_selection['sourceKind']} source ({bootstrap_selection['source']}): "
        f"{len(bootstrap_nodes)} contacts"
    )
    summary["vpn"] = {
        "rust": {
            "exe": rust_exe.name,
            "whitelistAdded": bool(rust_vpn.get("whitelistAdded")),
            "bindIp": rust_vpn.get("bindIp"),
        },
        "mfc": {
            "exe": mfc_exe.name,
            "whitelistAdded": bool(mfc_vpn.get("whitelistAdded")),
            "bindIp": mfc_vpn.get("bindIp"),
        },
        "sameBindIp": True,
    }
    summary["environmentParity"] = {
        "server": OPERATOR_SERVER,
        "rustServer": args.rust_server,
        "mfcServer": args.mfc_server,
        "sameServer": args.rust_server == args.mfc_server,
        "serverMetUrl": args.server_met_url,
        "nodesDatUrl": bootstrap_selection["nodesDatUrl"],
        "nodesDatSource": bootstrap_selection["source"],
        "nodesDatSourceKind": bootstrap_selection["sourceKind"],
        "nodesDatFileSelected": bootstrap_selection["nodesDatFileSelected"],
        "sameKadBootstrap": True,
        "bootstrapLimit": args.bootstrap_limit,
        "bootstrapContactCount": len(bootstrap_nodes),
        "sameShareSet": True,
        "sharedRootCount": len(shared_roots),
        "sharedRootSource": shared_root_source,
        "skippedInaccessibleSharedRootCount": skipped_inaccessible_shared_roots,
        "rustIncomingDirConfigured": rust_incoming_dir is not None,
        "directMfcProfile": mfc_profile_dir is not None,
        "freshRustRuntime": bool(args.fresh_rust_runtime),
        "rustRuntimeMode": rust_runtime_selection["mode"],
        "rustRuntimeDirName": rust_runtime.name,
        "uploadLimitKiBps": args.upload_limit_kibps,
        "logTrimBytes": args.log_trim_bytes,
        "pollRestTimeoutSeconds": args.poll_rest_timeout,
        "restLanAddress": rest_addr,
        "rustRestPort": args.rust_rest_port,
        "mfcRestPort": args.mfc_rest_port,
        "endpointPorts": endpoint_ports,
    }
    known_met_import = import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=mfc_profile_dir,
        rust_runtime_dir=rust_runtime,
        shared_roots=shared_roots,
        enabled=not bool(args.skip_mfc_known_met_import),
    )
    summary["mfcKnownMetImport"] = known_met_import
    if known_met_import["status"] == "imported":
        log(
            "imported MFC known.met into Rust metadata: "
            f"{known_met_import['importedRecords']} safe record(s), "
            f"{known_met_import['sharedFilesScanned']} shared file(s) scanned"
        )
    else:
        log(f"MFC known.met import skipped: {known_met_import['reason']}")
    shared_files_inventory_import = import_mfc_shared_files_inventory_for_rust_profile(
        mfc_profile_dir=mfc_profile_dir,
        rust_runtime_dir=rust_runtime,
        shared_roots=shared_roots,
        inventory_path=mfc_shared_files_inventory,
    )
    summary["mfcSharedFilesInventoryImport"] = shared_files_inventory_import
    if shared_files_inventory_import["status"] == "imported":
        log(
            "imported MFC shared-files inventory into Rust metadata: "
            f"{shared_files_inventory_import['importedRows']} exact row(s), "
            f"{shared_files_inventory_import['sharedFileRows']} row(s) loaded"
        )
    elif shared_files_inventory_import.get("enabled"):
        log(f"MFC shared-files inventory import skipped: {shared_files_inventory_import['reason']}")
    write_summary(summary, summary_path)

    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else DEFAULT_MFC_SEED_CONFIG_DIR
    timeouts = {"rest": args.rest_timeout, "connect": args.connect_timeout}

    rust_handles: dict[str, Any] | None = None
    mfc_handles: dict[str, Any] | None = None
    trackmulebb_proc: subprocess.Popen | None = None
    try:
        rust_handles = bring_up_rust(
            rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
            rest_port=args.rust_rest_port, runtime_dir=rust_runtime, packet_dump_dir=rust_packet_dump,
            incoming_dir=rust_incoming_dir, bootstrap_nodes=bootstrap_nodes, shared_roots=shared_roots,
            server_met_url=args.server_met_url, server_endpoint=args.rust_server, obfuscation=obfuscation,
            upload_limit_kibps=args.upload_limit_kibps, timeouts=timeouts,
            ed2k_port=args.rust_ed2k_port, kad_port=args.rust_kad_port,
        )
        mfc_handles = bring_up_mfc(
            live_common=live_common, rest_smoke=rest_smoke, shared_dirs_mod=shared_dirs_mod,
            exe_path=mfc_exe, seed_config_dir=seed_config_dir, artifacts_dir=mfc_artifacts,
            direct_profile_dir=mfc_profile_dir,
            rest_host=rest_addr, rest_port=args.mfc_rest_port, shared_roots=shared_roots,
            server_endpoint=args.mfc_server, obfuscation=obfuscation, upload_limit_kibps=args.upload_limit_kibps,
            log_trim_bytes=args.log_trim_bytes, timeouts=timeouts,
            ed2k_port=args.mfc_ed2k_port, kad_port=args.mfc_kad_port,
            server_udp_port=args.mfc_server_udp_port,
        )

        rust_proc = rust_handles["process"]
        mfc_app = mfc_handles["app"]
        rust_base = rust_handles["baseUrl"]
        mfc_base = mfc_handles["baseUrl"]
        rust_dump_dir = Path(rust_handles["packetDumpDir"])
        mfc_dump_dir = Path(mfc_handles["packetDumpDir"])

        if args.trackmulebb_cmd:
            log(f"launching TrackMuleBB: {args.trackmulebb_cmd}")
            trackmulebb_proc = subprocess.Popen(args.trackmulebb_cmd, shell=True)
        log("=" * 70)
        log("SOAK LIVE. Drive searches/downloads via the MFC GUI and via TrackMuleBB:")
        log(f"  rust REST : {rust_base}   (X-API-Key: {RUST_API_KEY})")
        log(f"  MFC  REST : {mfc_base}   (X-API-Key: {MFC_API_KEY})")
        log("Console commands: 'begin [label]' / 'end' to bracket a manual action, "
            "'status', 'quit'.")
        log("=" * 70)

        tracker = ActionTracker(
            window_seconds=args.correlation_window,
            settle_seconds=args.settle_seconds,
            lead_seconds=args.lead_seconds,
            download_settle_seconds=args.download_settle_seconds,
        )
        baseline = tracker.prime(
            rust_searches=sad.normalize_search_items(
                _get_list(
                    rust_base,
                    "/api/v1/searches",
                    RUST_API_KEY,
                    "searches",
                    timeout_seconds=args.poll_rest_timeout,
                )
            ),
            rust_transfers=sad.normalize_transfer_items(
                _get_list(
                    rust_base,
                    "/api/v1/transfers",
                    RUST_API_KEY,
                    "transfers",
                    timeout_seconds=args.poll_rest_timeout,
                )
            ),
            mfc_searches=sad.normalize_search_items(
                _get_list(
                    mfc_base,
                    "/api/v1/searches",
                    MFC_API_KEY,
                    "searches",
                    timeout_seconds=args.poll_rest_timeout,
                )
            ),
            mfc_transfers=sad.normalize_transfer_items(
                _get_list(
                    mfc_base,
                    "/api/v1/transfers",
                    MFC_API_KEY,
                    "transfers",
                    timeout_seconds=args.poll_rest_timeout,
                )
            ),
        )
        summary["baseline"] = baseline
        write_summary(summary, summary_path)
        log(
            "baseline: "
            f"rust searches={baseline['rustSearches']} transfers={baseline['rustTransfers']}; "
            f"mfc searches={baseline['mfcSearches']} transfers={baseline['mfcTransfers']}"
        )
        rust_mon = ProcMonitor("rust", rust_proc.pid)
        mfc_pid = getattr(mfc_app, "pid", None)
        mfc_mon = ProcMonitor("mfc", mfc_pid) if isinstance(mfc_pid, int) else None
        log_offsets: dict[str, int] = {}
        error_patterns = [re.compile(p, re.I) for p in ("panic", "assert", "fatal", "exception")]

        commands: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=_stdin_reader, args=(commands,), daemon=True).start()

        seq = 0
        marker_t0: datetime | None = None
        marker_label = ""
        started = time.monotonic()
        last_checkpoint = started
        auto_cycle = 0
        next_auto = started + args.auto_start_delay if args.auto_drive else float("inf")
        pending_downloads: list[dict[str, Any]] = []
        last_connectivity_reconnect = 0.0

        def process_report(report: dict[str, Any]) -> None:
            nonlocal seq
            seq += 1
            full = sad.build_action_report(report, campaign_id=campaign_id, seq=seq)
            path = sad.write_action_report(full, actions_dir)
            sad.append_to_summary(summary, full)
            write_summary(summary, summary_path)
            action_label = public_action_label(str(full.get("kind") or "action"))
            log(f"action #{seq} [{full.get('verdict')}] {action_label} -> {path.name}")

        def maybe_reconnect_rust(status: dict[str, Any]) -> None:
            nonlocal last_connectivity_reconnect
            if time.monotonic() - last_connectivity_reconnect < min(60.0, args.checkpoint_interval):
                return
            checkpoint_operator_reconnect(rust_base, RUST_API_KEY, status, endpoint=args.rust_server)
            last_connectivity_reconnect = time.monotonic()

        while True:
            now = datetime.now(timezone.utc)
            rust_loop_status = status_snapshot(rust_base, RUST_API_KEY, timeout_seconds=args.poll_rest_timeout)
            mfc_loop_status = status_snapshot(mfc_base, MFC_API_KEY, timeout_seconds=args.poll_rest_timeout)
            gate = connectivity_gate(
                rust_loop_status,
                mfc_loop_status,
                rust_endpoint=args.rust_server,
                mfc_endpoint=args.mfc_server,
            )
            for pending in list(pending_downloads):
                if time.monotonic() < float(pending["dueAtMono"]):
                    continue
                download = pending["download"]
                if not gate["ok"]:
                    pending["dueAtMono"] = time.monotonic() + min(60.0, args.auto_search_interval)
                    download["connectivityDelayed"] = int(download.get("connectivityDelayed") or 0) + 1
                    summary["driver"]["connectivitySkips"].append(
                        {"ts": now.isoformat(), "cycle": pending["cycle"], "kind": "download", **gate}
                    )
                    maybe_reconnect_rust(rust_loop_status)
                    write_summary(summary, summary_path)
                    continue
                file_hash = str(download.get("hash") or "").strip().lower()
                log(f"auto cycle {pending['cycle']}: starting delayed download action")
                try:
                    result = execute_scheduled_download(
                        rust_base=rust_base,
                        mfc_base=mfc_base,
                        download=download,
                    )
                    download.update(result)
                    download["ok"] = True
                    download["triggeredAt"] = now.isoformat()
                    tracker.record_synchronized_action(
                        kind=sad.DOWNLOAD,
                        key=file_hash,
                        label=file_hash,
                        observed_at=now,
                        action_id=f"auto-download-{pending['cycle']}-{file_hash}",
                    )
                except Exception as exc:  # noqa: BLE001 - keep the overnight soak alive
                    download["ok"] = False
                    download["error"] = f"{type(exc).__name__}: {exc}"
                    log(f"auto cycle {pending['cycle']}: delayed download failed: {download['error']}")
                pending_downloads.remove(pending)
                write_summary(summary, summary_path)

            if (
                args.auto_drive
                and time.monotonic() >= next_auto
                and (args.auto_max_cycles == 0 or auto_cycle < args.auto_max_cycles)
            ):
                if not gate["ok"]:
                    summary["driver"]["connectivitySkips"].append(
                        {"ts": now.isoformat(), "kind": "search", **gate}
                    )
                    maybe_reconnect_rust(rust_loop_status)
                    write_summary(summary, summary_path)
                    next_auto = time.monotonic() + min(60.0, args.auto_search_interval)
                    log("auto cycle delayed: both clients are not connected to the operator server")
                else:
                    auto_cycle += 1
                    query = auto_terms[(auto_cycle - 1) % len(auto_terms)]
                    should_download = args.auto_download_every > 0 and auto_cycle % args.auto_download_every == 0
                    log(
                        f"auto cycle {auto_cycle}: synchronized {args.auto_method} search "
                        f"(download={str(should_download).lower()})"
                    )
                    try:
                        cycle = drive_automatic_cycle(
                            cycle_index=auto_cycle,
                            query=query,
                            method=args.auto_method,
                            rust_base=rust_base,
                            mfc_base=mfc_base,
                            rust_mod=rust_mod,
                            download=should_download,
                            search_timeout_seconds=args.auto_search_timeout,
                        )
                    except Exception as exc:  # noqa: BLE001 - keep the overnight soak alive
                        cycle = {
                            "cycle": auto_cycle,
                            "queryIndex": auto_cycle - 1,
                            "method": args.auto_method,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                        log(f"auto cycle {auto_cycle}: {cycle['error']}")
                    summary["driver"]["cycles"].append(cycle)
                    download = cycle.get("download")
                    if isinstance(download, dict) and download.get("scheduled"):
                        pending_downloads.append(
                            {
                                "cycle": auto_cycle,
                                "download": download,
                                "dueAtMono": time.monotonic() + auto_download_delay,
                            }
                        )
                        download["delaySeconds"] = auto_download_delay
                    write_summary(summary, summary_path)
                    next_auto = time.monotonic() + args.auto_search_interval

            if gate["ok"]:
                pairs, aged_unpaired = tracker.tick(
                    now,
                    rust_searches=sad.normalize_search_items(
                        _get_list(
                            rust_base,
                            "/api/v1/searches",
                            RUST_API_KEY,
                            "searches",
                            timeout_seconds=args.poll_rest_timeout,
                        )
                    ),
                    rust_transfers=sad.normalize_transfer_items(
                        _get_list(
                            rust_base,
                            "/api/v1/transfers",
                            RUST_API_KEY,
                            "transfers",
                            timeout_seconds=args.poll_rest_timeout,
                        )
                    ),
                    mfc_searches=sad.normalize_search_items(
                        _get_list(
                            mfc_base,
                            "/api/v1/searches",
                            MFC_API_KEY,
                            "searches",
                            timeout_seconds=args.poll_rest_timeout,
                        )
                    ),
                    mfc_transfers=sad.normalize_transfer_items(
                        _get_list(
                            mfc_base,
                            "/api/v1/transfers",
                            MFC_API_KEY,
                            "transfers",
                            timeout_seconds=args.poll_rest_timeout,
                        )
                    ),
                )
            else:
                maybe_reconnect_rust(rust_loop_status)
                pairs, aged_unpaired = [], []
            if pairs:
                rust_pkts = load_packets(rust_dump_dir, side="rust")
                mfc_pkts = load_packets(mfc_dump_dir, side="emule")
                rust_dg = load_diag(rust_dump_dir, side="rust")
                mfc_dg = load_diag(mfc_dump_dir, side="emule")
                for pair in pairs:
                    process_report(
                        sad.diff_action(
                            pair, rust_packets=rust_pkts, mfc_packets=mfc_pkts,
                            rust_diag=rust_dg, mfc_diag=mfc_dg,
                            lead_seconds=args.lead_seconds,
                            settle_seconds=tracker.settle_seconds_for(pair.kind),
                        )
                    )
            for action in aged_unpaired:
                process_report(sad.unpaired_record(action))

            # Drain console commands (manual marker + control).
            try:
                while True:
                    cmd = commands.get_nowait()
                    if cmd.startswith("begin"):
                        marker_t0 = now
                        marker_label = cmd[len("begin"):].strip() or "marker"
                        log(f"manual marker started at {now.isoformat()}")
                    elif cmd == "end" and marker_t0 is not None:
                        pair = sad.ActionPair(
                            kind="marker",
                            key=marker_label,
                            rust=sad.Action(
                                client="rust", kind="marker", action_id="marker",
                                key=marker_label, label=marker_label, observed_at=marker_t0,
                            ),
                            mfc=sad.Action(
                                client="mfc", kind="marker", action_id="marker",
                                key=marker_label, label=marker_label, observed_at=now,
                            ),
                        )
                        process_report(
                            sad.diff_action(
                                pair,
                                rust_packets=load_packets(rust_dump_dir, side="rust"),
                                mfc_packets=load_packets(mfc_dump_dir, side="emule"),
                                rust_diag=load_diag(rust_dump_dir, side="rust"),
                                mfc_diag=load_diag(mfc_dump_dir, side="emule"),
                                lead_seconds=0.0, settle_seconds=0.0,
                            )
                        )
                        marker_t0 = None
                    elif cmd == "status":
                        log(f"status: {json.dumps(summary['totals'])}")
                    elif cmd == "quit":
                        raise KeyboardInterrupt
            except queue.Empty:
                pass

            # Periodic stability + coverage checkpoint.
            if time.monotonic() - last_checkpoint >= args.checkpoint_interval:
                last_checkpoint = time.monotonic()
                rust_status = status_snapshot(rust_base, RUST_API_KEY, timeout_seconds=args.poll_rest_timeout)
                mfc_status = status_snapshot(mfc_base, MFC_API_KEY, timeout_seconds=args.poll_rest_timeout)
                checkpoint = {
                    "schema": "soak_checkpoint_v1",
                    "ts_utc": now.isoformat(),
                    "rustAlive": rust_proc.poll() is None,
                    "rust": rust_mon.sample(),
                    "mfc": mfc_mon.sample() if mfc_mon else None,
                    "packetRecords": {
                        "rust": len(load_packets(rust_dump_dir, side="rust")),
                        "mfc": len(load_packets(mfc_dump_dir, side="emule")),
                    },
                    "restStatus": {
                        "rust": rust_status,
                        "mfc": mfc_status,
                    },
                    "reconnect": {
                        "rust": checkpoint_operator_reconnect(
                            rust_base,
                            RUST_API_KEY,
                            rust_status,
                            endpoint=args.rust_server,
                        ),
                    },
                    "errorLogHits": live_process_monitor.scan_log_markers(
                        [rust_runtime / "daemon.out"], log_offsets, error_patterns
                    ),
                    "logTrim": trim_log_tree(
                        [rust_runtime / "daemon.out", rust_dump_dir, mfc_dump_dir],
                        max_bytes=args.log_trim_bytes,
                    ),
                    "totals": summary["totals"],
                }
                (report_dir / "checkpoints").mkdir(exist_ok=True)
                (report_dir / "checkpoints" / f"{now.strftime('%H%M%SZ')}.json").write_text(
                    json.dumps(checkpoint, indent=2, sort_keys=True), encoding="utf-8"
                )
                log(f"checkpoint: packets rust={checkpoint['packetRecords']['rust']} "
                    f"mfc={checkpoint['packetRecords']['mfc']} actions={summary['totals']['actions']}")
                if not checkpoint["rustAlive"]:
                    log("rust daemon exited - ending soak.")
                    break

            if duration and (time.monotonic() - started) >= duration:
                log("soak duration reached - winding down.")
                break
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        log("interrupted - winding down.")
    finally:
        if trackmulebb_proc is not None:
            stop_process_tree(trackmulebb_proc)
        if mfc_handles is not None and mfc_handles.get("app") is not None:
            try:
                live_common.close_app_cleanly(mfc_handles["app"])
            except Exception:  # noqa: BLE001
                try:
                    mfc_handles["app"].kill()
                except Exception:  # noqa: BLE001
                    pass
        if rust_handles is not None:
            stop_process_tree(rust_handles["process"])
            try:
                rust_handles["logHandle"].close()
            except Exception:  # noqa: BLE001
                pass

    summary["server"] = OPERATOR_SERVER
    summary["rustServer"] = args.rust_server
    summary["mfcServer"] = args.mfc_server
    summary["bindIp"] = bind_ip
    write_summary(summary, summary_path)
    log(f"final summary: {summary_path}")
    print(json.dumps({"scenario": SCENARIO, "campaignId": campaign_id, "totals": summary["totals"], "report": str(summary_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
