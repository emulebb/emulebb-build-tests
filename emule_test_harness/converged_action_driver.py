"""Reusable synchronized REST action driving for converged diagnostics soaks."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Protocol

from . import soak_action_diff, soak_launch
from .vm_guest_profiles import api_data, retry_http_json


class DownloadSafety(Protocol):
    """Safety policy used to reject unsuitable live download candidates."""

    @staticmethod
    def safe_download_rejection_reason(row: dict[str, Any]) -> str | None: ...


@dataclass(frozen=True)
class ClientEndpoint:
    """One diagnostics client's immutable REST endpoint authority."""

    name: str
    base_url: str
    api_key: str


def extract_items(payload: Any, *keys: str) -> list[dict[str, Any]]:
    """Extract dict rows from the REST list envelope variants used by both clients."""

    return soak_launch.api_items(payload, *keys, require_dict=True)


def get_list(
    client: ClientEndpoint,
    path: str,
    *keys: str,
    timeout_seconds: float = 10.0,
) -> list[dict[str, Any]]:
    """Read a REST list, treating a transient read failure as an empty snapshot."""

    try:
        payload = retry_http_json(
            f"poll {client.name} {path}",
            1,
            client.base_url,
            path,
            api_key=client.api_key,
            timeout_seconds=timeout_seconds,
        )
    except RuntimeError:
        return []
    return extract_items(payload, *keys)


def row_hash(row: dict[str, Any]) -> str:
    return str(row.get("hash") or row.get("fileHash") or "").strip().lower()


def transfer_hashes(rows: list[dict[str, Any]]) -> set[str]:
    """Return all transfer hashes visible in a raw REST transfer list."""

    return {file_hash for row in rows if (file_hash := row_hash(row))}


def transfer_exists(
    client: ClientEndpoint,
    file_hash: str,
    *,
    timeout_seconds: float = 5.0,
) -> bool:
    """Return whether a client already exposes a transfer or known-file hash."""

    try:
        payload = retry_http_json(
            f"probe {client.name} transfer",
            1,
            client.base_url,
            f"/api/v1/transfers/{file_hash}",
            api_key=client.api_key,
            timeout_seconds=timeout_seconds,
        )
    except RuntimeError:
        return False
    return bool(api_data(payload))


def row_sources(row: dict[str, Any]) -> int:
    return int(row.get("sources") or row.get("completeSources") or 0)


def row_size(row: dict[str, Any]) -> int:
    return int(row.get("sizeBytes") or row.get("size") or 0)


def row_name(row: dict[str, Any]) -> str:
    return str(row.get("name") or row.get("fileName") or "")


def download_name_allowed(name: str, required_suffix: str | None) -> bool:
    """Apply the requested suffix policy while rejecting torrent sidecars."""

    if not required_suffix:
        return True
    lowered = name.strip().lower()
    if lowered.endswith(".torrent"):
        return False
    return lowered.endswith(required_suffix.lower())


def top_common_download_candidates(
    rust_rows: list[dict[str, Any]],
    mfc_rows: list[dict[str, Any]],
    *,
    safety: DownloadSafety,
    limit: int | None = None,
    existing_hashes: set[str] | None = None,
    existing_probe: Callable[[str], bool] | None = None,
    prefer_hashes: set[str] | None = None,
    required_suffix: str | None = None,
    min_size_bytes: int = 0,
    max_size_bytes: int = 0,
) -> list[dict[str, Any]]:
    """Return safe, absent results common to both clients in deterministic order."""

    mfc_hashes = {row_hash(row) for row in mfc_rows if row_hash(row)}
    existing_hashes = {
        item.strip().lower() for item in (existing_hashes or set()) if item
    }
    prefer_hashes = {item.strip().lower() for item in (prefer_hashes or set()) if item}
    candidates: list[dict[str, Any]] = []
    for row in rust_rows:
        file_hash = row_hash(row)
        if not file_hash or file_hash not in mfc_hashes:
            continue
        if file_hash in existing_hashes:
            continue
        if row_size(row) < min_size_bytes:
            continue
        if not download_name_allowed(row_name(row), required_suffix):
            continue
        if existing_probe is not None and existing_probe(file_hash):
            continue
        reason = safety.safe_download_rejection_reason(row)
        if reason is None or (
            reason == "tooLarge"
            and max_size_bytes > 0
            and row_size(row) <= max_size_bytes
        ):
            candidates.append(row)
    candidates.sort(
        key=lambda row: (
            0 if row_hash(row) in prefer_hashes else 1,
            -row_sources(row),
            -row_size(row),
            row_hash(row),
        )
    )
    return candidates if limit is None else candidates[: max(0, limit)]


def safe_common_download_candidate(
    rust_rows: list[dict[str, Any]],
    mfc_rows: list[dict[str, Any]],
    *,
    safety: DownloadSafety,
    existing_hashes: set[str] | None = None,
    existing_probe: Callable[[str], bool] | None = None,
    required_suffix: str | None = None,
    min_size_bytes: int = 0,
    max_size_bytes: int = 0,
) -> dict[str, Any] | None:
    """Select one safe, absent, most-sourced result common to both clients."""

    candidates = top_common_download_candidates(
        rust_rows,
        mfc_rows,
        safety=safety,
        limit=1,
        existing_hashes=existing_hashes,
        existing_probe=existing_probe,
        required_suffix=required_suffix,
        min_size_bytes=min_size_bytes,
        max_size_bytes=max_size_bytes,
    )
    return candidates[0] if candidates else None


def create_search(client: ClientEndpoint, *, query: str, method: str) -> str:
    """Create one client search and return its REST identifier."""

    created = retry_http_json(
        f"{client.name} soak search create",
        2,
        client.base_url,
        "/api/v1/searches",
        api_key=client.api_key,
        method="POST",
        body={"query": query, "method": method, "type": ""},
        timeout_seconds=45.0,
    )
    return str(api_data(created).get("id") or "")


def poll_search_results(
    client: ClientEndpoint,
    search_id: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    """Poll one search until completion or the timeout, retaining the last results."""

    deadline = time.monotonic() + timeout_seconds
    last_rows: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        page = retry_http_json(
            f"{client.name} soak search poll",
            2,
            client.base_url,
            f"/api/v1/searches/{search_id}",
            api_key=client.api_key,
            timeout_seconds=30.0,
        )
        data = api_data(page)
        rows = extract_items(data, "items")
        if rows:
            last_rows = rows
        if str(data.get("status") or "").casefold() in {"complete", "completed"}:
            return rows
        time.sleep(2.0)
    return last_rows


def trigger_download(
    client: ClientEndpoint,
    search_id: str,
    file_hash: str,
) -> dict[str, Any]:
    """Start and best-effort resume one result download."""

    download = retry_http_json(
        f"{client.name} soak download",
        2,
        client.base_url,
        f"/api/v1/searches/{search_id}/results/{file_hash}/operations/download",
        api_key=client.api_key,
        method="POST",
        body={"paused": False, "categoryId": 0},
        timeout_seconds=30.0,
    )
    try:
        retry_http_json(
            f"{client.name} soak download resume",
            1,
            client.base_url,
            f"/api/v1/transfers/{file_hash}/operations/resume",
            api_key=client.api_key,
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
    rust: ClientEndpoint,
    mfc: ClientEndpoint,
    safety: DownloadSafety,
    download: bool,
    search_timeout_seconds: float,
    required_suffix: str | None = None,
    min_size_bytes: int = 0,
    max_size_bytes: int = 0,
    download_hash: str | None = None,
) -> dict[str, Any]:
    """Run one synchronized search and optionally schedule a common download."""

    cycle: dict[str, Any] = {
        "cycle": cycle_index,
        "queryIndex": cycle_index - 1,
        "method": method,
        "query": query,
        "downloadRequested": download,
    }
    rust_search_id = create_search(rust, query=query, method=method)
    mfc_search_id = create_search(mfc, query=query, method=method)
    cycle["searchIds"] = {"rust": rust_search_id, "mfc": mfc_search_id}
    rust_rows = poll_search_results(
        rust, rust_search_id, timeout_seconds=search_timeout_seconds
    )
    mfc_rows = poll_search_results(
        mfc, mfc_search_id, timeout_seconds=search_timeout_seconds
    )
    cycle["resultCounts"] = {"rust": len(rust_rows), "mfc": len(mfc_rows)}
    if not download:
        return cycle

    rust_transfer_hashes = transfer_hashes(
        get_list(rust, "/api/v1/transfers", "transfers", timeout_seconds=30.0)
    )
    mfc_transfer_hashes = transfer_hashes(
        get_list(mfc, "/api/v1/transfers", "transfers", timeout_seconds=30.0)
    )
    existing_hashes = rust_transfer_hashes | mfc_transfer_hashes
    cycle["downloadExistingHashCounts"] = {
        "rust": len(rust_transfer_hashes),
        "mfc": len(mfc_transfer_hashes),
        "combined": len(existing_hashes),
    }

    probe_skips = {"rust": 0, "mfc": 0, "combined": 0}

    def existing_hash_probe(file_hash: str) -> bool:
        rust_known = transfer_exists(rust, file_hash)
        mfc_known = transfer_exists(mfc, file_hash)
        if rust_known:
            probe_skips["rust"] += 1
        if mfc_known:
            probe_skips["mfc"] += 1
        if rust_known or mfc_known:
            probe_skips["combined"] += 1
            return True
        return False

    if download_hash:
        wanted_hash = download_hash.strip().lower()
        rust_row = next(
            (row for row in rust_rows if row_hash(row) == wanted_hash), None
        )
        present_in_mfc = any(row_hash(row) == wanted_hash for row in mfc_rows)
        candidate = rust_row if rust_row is not None and present_in_mfc else None
    else:
        candidate = safe_common_download_candidate(
            rust_rows,
            mfc_rows,
            safety=safety,
            existing_hashes=existing_hashes,
            existing_probe=existing_hash_probe,
            required_suffix=required_suffix,
            min_size_bytes=min_size_bytes,
            max_size_bytes=max_size_bytes,
        )
    cycle["downloadExistingHashProbeSkips"] = probe_skips
    cycle["downloadCandidateConstraints"] = {
        "requiredSuffix": required_suffix,
        "minSizeBytes": min_size_bytes,
        "maxSizeBytes": max_size_bytes,
    }
    if candidate is None:
        cycle["download"] = {
            "ok": False,
            "reason": (
                f"no common safe candidate matching suffix={required_suffix!r} "
                f"size>={min_size_bytes}B on both clients"
            ),
        }
        return cycle

    file_hash = row_hash(candidate)
    cycle["download"] = {
        "ok": None,
        "scheduled": True,
        "hash": file_hash,
        "name": row_name(candidate),
        "sizeBytes": row_size(candidate),
        "sources": row_sources(candidate),
        "searchIds": {"rust": rust_search_id, "mfc": mfc_search_id},
    }
    return cycle


def execute_scheduled_download(
    *,
    rust: ClientEndpoint,
    mfc: ClientEndpoint,
    download: dict[str, Any],
) -> dict[str, Any]:
    """Trigger a previously selected common download on both clients."""

    file_hash = str(download.get("hash") or "").strip().lower()
    search_ids = (
        download.get("searchIds") if isinstance(download.get("searchIds"), dict) else {}
    )
    rust_search_id = str(search_ids.get("rust") or "")
    mfc_search_id = str(search_ids.get("mfc") or "")
    if not file_hash or not rust_search_id or not mfc_search_id:
        raise RuntimeError("scheduled download is missing hash or search ids")
    return {
        "rust": trigger_download(rust, rust_search_id, file_hash),
        "mfc": trigger_download(mfc, mfc_search_id, file_hash),
    }


class ActionTracker:
    """Accumulate observed actions and yield settled correlation outcomes."""

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
            download_settle_seconds
            if download_settle_seconds is not None
            else settle_seconds
        )
        self.lead = lead_seconds
        self.seen: dict[tuple[str, str], set[str]] = {}
        self.baseline_keys: dict[tuple[str, str], set[str]] = {}
        self.rust: list[soak_action_diff.Action] = []
        self.mfc: list[soak_action_diff.Action] = []
        self.processed: set[str] = set()
        self.synchronized_keys: set[tuple[str, str]] = set()

    def settle_seconds_for(self, kind: str) -> float:
        return (
            self.download_settle if kind == soak_action_diff.DOWNLOAD else self.settle
        )

    def _ingest(
        self,
        client: str,
        kind: str,
        items: list[dict[str, str]],
        now: datetime,
    ) -> None:
        key = (client, kind)
        fresh, self.seen[key] = soak_action_diff.detect_actions(
            self.seen.get(key),
            items,
            client=client,
            kind=kind,
            observed_at=now,
        )
        baseline_keys = self.baseline_keys.get(key, set())
        fresh = [
            action
            for action in fresh
            if (action.kind, action.key) not in self.synchronized_keys
            and action.key not in baseline_keys
        ]
        bucket = self.rust if client == "rust" else self.mfc
        bucket.extend(fresh)

    def prime(
        self,
        *,
        rust_searches: list[dict[str, str]],
        rust_transfers: list[dict[str, str]],
        mfc_searches: list[dict[str, str]],
        mfc_transfers: list[dict[str, str]],
    ) -> dict[str, int]:
        """Seed seen IDs from existing REST rows without recording actions."""

        snapshots = {
            ("rust", soak_action_diff.SEARCH): rust_searches,
            ("rust", soak_action_diff.DOWNLOAD): rust_transfers,
            ("mfc", soak_action_diff.SEARCH): mfc_searches,
            ("mfc", soak_action_diff.DOWNLOAD): mfc_transfers,
        }
        for key, items in snapshots.items():
            self.seen[key] = {item["id"] for item in items}
            self.baseline_keys[key] = {item["key"] for item in items}
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
        """Record an action successfully issued to both clients."""

        self.synchronized_keys.add((kind, key))
        self.rust.append(
            soak_action_diff.Action(
                client="rust",
                kind=kind,
                action_id=f"rust:{action_id}",
                key=key,
                label=label,
                observed_at=observed_at,
            )
        )
        self.mfc.append(
            soak_action_diff.Action(
                client="mfc",
                kind=kind,
                action_id=f"mfc:{action_id}",
                key=key,
                label=label,
                observed_at=observed_at,
            )
        )

    def tick(
        self,
        now: datetime,
        *,
        rust_searches: list[dict[str, str]],
        rust_transfers: list[dict[str, str]],
        mfc_searches: list[dict[str, str]],
        mfc_transfers: list[dict[str, str]],
    ) -> tuple[list[soak_action_diff.ActionPair], list[soak_action_diff.Action]]:
        self._ingest("rust", soak_action_diff.SEARCH, rust_searches, now)
        self._ingest("rust", soak_action_diff.DOWNLOAD, rust_transfers, now)
        self._ingest("mfc", soak_action_diff.SEARCH, mfc_searches, now)
        self._ingest("mfc", soak_action_diff.DOWNLOAD, mfc_transfers, now)

        active_rust = [
            action for action in self.rust if action.action_id not in self.processed
        ]
        active_mfc = [
            action for action in self.mfc if action.action_id not in self.processed
        ]
        pairs, unpaired_rust, unpaired_mfc = soak_action_diff.correlate_actions(
            active_rust,
            active_mfc,
            window_seconds=self.window,
        )

        ready_pairs: list[soak_action_diff.ActionPair] = []
        for pair in pairs:
            _, window_end = pair.window(
                lead_seconds=self.lead,
                settle_seconds=self.settle_seconds_for(pair.kind),
            )
            if now >= window_end:
                self.processed.add(pair.rust.action_id)
                self.processed.add(pair.mfc.action_id)
                ready_pairs.append(pair)

        aged_unpaired: list[soak_action_diff.Action] = []
        for action in (*unpaired_rust, *unpaired_mfc):
            age = (now - action.observed_at).total_seconds()
            if age > self.window + self.settle_seconds_for(action.kind):
                self.processed.add(action.action_id)
                aged_unpaired.append(action)
        return ready_pairs, aged_unpaired
