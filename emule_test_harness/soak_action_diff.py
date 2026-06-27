"""Synchronized-action diff engine for the long-soak rust↔MFC parity campaign.

The converged single-pass orchestrator (``scripts/converged-live-wire-diff.py``)
*issues* the same gentle exchange to both clients and diffs the whole capture. The
long soak is different: a human drives interactive searches/downloads through each
client's own UI (MFC native GUI, TrackMuleBB for emulebb-rust), so the harness
cannot issue the synchronized action — it must **observe** it.

This module is the side-effect-free core the soak orchestrator builds on:

* :func:`normalize_search_items` / :func:`normalize_transfer_items` map each
  client's ``/api/v1`` list shape onto a small normalized record (id + match key);
* :func:`detect_actions` turns two successive REST snapshots into the *new*
  actions a client started since the last poll;
* :func:`correlate_actions` pairs the same search term / ed2k hash across the two
  clients within a correlation window (unpaired actions are surfaced so the
  operator can bracket them with a manual marker instead);
* :func:`slice_trace` cuts an ``ed2k_packet_v1`` / ``diag_event_v1`` record list to
  one action's ``[t0, t1]`` window by ``ts_utc``;
* :func:`diff_action` slices both sides and delegates to the existing
  :mod:`packet_trace_diff` and :mod:`diag_event_diff` engines, then classifies the
  per-action verdict;
* :func:`build_action_report` / :func:`append_to_summary` persist the per-action
  report and the rolling campaign summary.

For two *independent* live clients the wire bytes never match (different peers,
payloads, timing), so the live-meaningful parity signal is the opcode/family
**coverage** the underlying engines compute, not the strict byte diff. The verdict
reflects that: ``coverageOk`` + ``diagOk`` is parity; the strict byte ``ok`` is kept
only as an informational ``byteMatch`` flag.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import diag_event_diff, packet_trace_diff

SEARCH = "search"
DOWNLOAD = "download"

# Default window padding around an observed action. ``lead`` backs the window up
# before the harness first *saw* the action (the action started slightly earlier,
# between two polls); ``settle`` extends past it so the request/response packets
# the action triggered land inside the window.
DEFAULT_LEAD_SECONDS = 8.0
DEFAULT_SETTLE_SECONDS = 45.0
DEFAULT_CORRELATION_WINDOW_SECONDS = 90.0
_WINDOWS_RESERVED_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_HEX_REPORT_KEY = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)


def parse_ts(value: Any) -> datetime | None:
    """Parses an ``ts_utc`` RFC3339-millis string (``...Z``) into aware UTC.

    Returns ``None`` for absent/unparseable values so callers can skip records
    without a usable timestamp rather than crash mid-soak.
    """

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first(item: dict[str, Any], *names: str) -> Any:
    """Returns the first present, non-empty value among ``names``."""

    for name in names:
        value = item.get(name)
        if value not in (None, ""):
            return value
    return None


def normalize_search_items(items: Any) -> list[dict[str, str]]:
    """Normalizes a client's ``/api/v1/searches`` list into id + match key.

    Both clients expose the same surface but with small field-name drift, so the
    extraction is defensive (``id``/``searchId``, ``query``/``keyword``/``term``).
    The match ``key`` is the lower-cased query — that is what correlates the same
    human action across the two clients.
    """

    normalized: list[dict[str, str]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        action_id = _first(item, "id", "searchId", "search_id")
        query = _first(item, "query", "keyword", "term", "name")
        if action_id is None or query is None:
            continue
        method = _first(item, "method", "network") or "automatic"
        normalized.append(
            {
                "id": str(action_id),
                "key": str(query).strip().lower(),
                "label": str(query).strip(),
                "method": str(method).lower(),
            }
        )
    return normalized


def normalize_transfer_items(items: Any) -> list[dict[str, str]]:
    """Normalizes a client's ``/api/v1/transfers`` list into id + match key.

    The match ``key`` is the lower-cased ed2k file hash — identical across clients
    for the same file, so it correlates the same download regardless of the local
    transfer id each client assigns.
    """

    normalized: list[dict[str, str]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        file_hash = _first(
            item, "hash", "fileHash", "file_hash", "ed2kHash", "md4", "fileHashHex"
        )
        if file_hash is None:
            continue
        action_id = _first(item, "id", "transferId", "transfer_id") or file_hash
        name = _first(item, "name", "fileName", "file_name", "displayName")
        normalized.append(
            {
                "id": str(action_id),
                "key": str(file_hash).strip().lower(),
                "label": str(name or file_hash),
            }
        )
    return normalized


@dataclass(frozen=True)
class Action:
    """One human-initiated action observed on one client during the soak."""

    client: str  # "rust" | "mfc"
    kind: str  # SEARCH | DOWNLOAD
    action_id: str
    key: str  # lower-cased query or ed2k hash — the cross-client correlation key
    label: str
    observed_at: datetime
    method: str | None = None


@dataclass(frozen=True)
class ActionPair:
    """A correlated rust↔MFC action: the same key seen on both within the window."""

    kind: str
    key: str
    rust: Action
    mfc: Action

    def window(
        self,
        *,
        lead_seconds: float = DEFAULT_LEAD_SECONDS,
        settle_seconds: float = DEFAULT_SETTLE_SECONDS,
    ) -> tuple[datetime, datetime]:
        """The ``[t0, t1]`` capture window spanning both sides of the action."""

        start = min(self.rust.observed_at, self.mfc.observed_at) - timedelta(seconds=lead_seconds)
        end = max(self.rust.observed_at, self.mfc.observed_at) + timedelta(seconds=settle_seconds)
        return start, end


def detect_actions(
    prev_ids: set[str] | None,
    now_items: list[dict[str, str]],
    *,
    client: str,
    kind: str,
    observed_at: datetime,
) -> tuple[list[Action], set[str]]:
    """Returns the actions present in ``now_items`` but not yet seen.

    ``prev_ids`` is the set of action ids observed on prior polls; the returned
    ``seen`` set folds in every current id (so a finished/dropped action is not
    re-detected when it later disappears). ``observed_at`` is the poll time, used
    as the action's anchor for correlation/windowing.
    """

    prev = set(prev_ids or ())
    fresh: list[Action] = []
    for item in now_items:
        if item["id"] in prev:
            continue
        fresh.append(
            Action(
                client=client,
                kind=kind,
                action_id=item["id"],
                key=item["key"],
                label=item["label"],
                observed_at=observed_at,
                method=item.get("method"),
            )
        )
    seen = prev | {item["id"] for item in now_items}
    return fresh, seen


def correlate_actions(
    rust_actions: list[Action],
    mfc_actions: list[Action],
    *,
    window_seconds: float = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> tuple[list[ActionPair], list[Action], list[Action]]:
    """Pairs the same ``(kind, key)`` across clients within ``window_seconds``.

    Greedy nearest-time matching: each rust action takes the closest still-free
    MFC action of the same kind+key inside the window. Actions with no counterpart
    in time are returned as ``unpaired`` so the operator can bracket them with a
    manual marker (e.g. when the same term was searched far apart, or only on one
    client).
    """

    pairs: list[ActionPair] = []
    used: set[int] = set()
    unpaired_rust: list[Action] = []
    for rust in sorted(rust_actions, key=lambda a: a.observed_at):
        best_index: int | None = None
        best_delta: float | None = None
        for index, mfc in enumerate(mfc_actions):
            if index in used or mfc.kind != rust.kind or mfc.key != rust.key:
                continue
            delta = abs((mfc.observed_at - rust.observed_at).total_seconds())
            if delta <= window_seconds and (best_delta is None or delta < best_delta):
                best_index, best_delta = index, delta
        if best_index is None:
            unpaired_rust.append(rust)
        else:
            used.add(best_index)
            pairs.append(
                ActionPair(kind=rust.kind, key=rust.key, rust=rust, mfc=mfc_actions[best_index])
            )
    unpaired_mfc = [mfc for index, mfc in enumerate(mfc_actions) if index not in used]
    return pairs, unpaired_rust, unpaired_mfc


def slice_trace(
    records: list[dict[str, Any]],
    t0: datetime,
    t1: datetime,
) -> list[dict[str, Any]]:
    """Returns the records whose ``ts_utc`` falls within ``[t0, t1]`` (inclusive).

    Works for both ``ed2k_packet_v1`` and ``diag_event_v1`` records — both carry a
    top-level ``ts_utc``. Records without a parseable timestamp are dropped (they
    cannot be placed in an action window).
    """

    sliced: list[dict[str, Any]] = []
    for record in records:
        timestamp = parse_ts(record.get("ts_utc"))
        if timestamp is None:
            continue
        if t0 <= timestamp <= t1:
            sliced.append(record)
    return sliced


def _shared_opcode_present(
    packet_diff: dict[str, Any],
    *,
    channel: str,
    direction: str,
    protocol_marker: int,
    opcode: int,
) -> bool:
    coverage = packet_diff.get("opcodeCoverage")
    channels = coverage.get("channels") if isinstance(coverage, dict) else None
    if not isinstance(channels, list):
        return False
    for item in channels:
        if not isinstance(item, dict):
            continue
        if item.get("channel") != channel or item.get("direction") != direction:
            continue
        shared = item.get("shared")
        if not isinstance(shared, list):
            return False
        for row in shared:
            if not isinstance(row, dict):
                continue
            if int(row.get("protocolMarker") or 0) == protocol_marker and int(row.get("opcode") or 0) == opcode:
                return int(row.get("rustCount") or 0) > 0 and int(row.get("emuleCount") or 0) > 0
    return False


def _shared_any_opcode_present(packet_diff: dict[str, Any], alternatives: list[dict[str, Any]]) -> bool:
    for alternative in alternatives:
        if _shared_opcode_present(
            packet_diff,
            channel=str(alternative["channel"]),
            direction=str(alternative["direction"]),
            protocol_marker=int(alternative["protocolMarker"]),
            opcode=int(alternative["opcode"]),
        ):
            return True
    return False


def build_action_coverage(kind: str, packet_diff: dict[str, Any]) -> dict[str, Any]:
    """Builds the action-specific live coverage gate for one soak action."""

    required: list[dict[str, Any]] = []
    if kind == SEARCH:
        required = [
            {
                "label": "server-search-request",
                "channel": "server",
                "direction": "send",
                "protocolMarker": 0xE3,
                "opcode": 0x16,
                "opcodeName": "OP_SEARCHREQUEST",
            },
            {
                "label": "server-search-result",
                "channel": "server",
                "direction": "recv",
                "protocolMarker": 0xE3,
                "opcode": 0x33,
                "opcodeName": "OP_SEARCHRESULT",
            },
        ]
    elif kind == DOWNLOAD:
        required = [
            {
                "label": "server-found-sources",
                "alternatives": [
                    {
                        "channel": "server",
                        "direction": "recv",
                        "protocolMarker": 0xE3,
                        "opcode": 0x42,
                        "opcodeName": "OP_FOUNDSOURCES",
                    },
                    {
                        "channel": "server",
                        "direction": "recv",
                        "protocolMarker": 0xE3,
                        "opcode": 0x44,
                        "opcodeName": "OP_FOUNDSOURCES_OBFU",
                    },
                ],
            },
            {
                "label": "client-request-parts",
                "alternatives": [
                    {
                        "channel": "client",
                        "direction": "send",
                        "protocolMarker": 0xE3,
                        "opcode": 0x47,
                        "opcodeName": "OP_REQUESTPARTS",
                    },
                    {
                        "channel": "client",
                        "direction": "send",
                        "protocolMarker": 0xC5,
                        "opcode": 0xA3,
                        "opcodeName": "OP_REQUESTPARTS_I64",
                    },
                ],
            },
        ]
        optional = [
            {
                "label": "client-part-payload",
                "alternatives": [
                    {
                        "channel": "client",
                        "direction": "recv",
                        "protocolMarker": 0xE3,
                        "opcode": 0x46,
                        "opcodeName": "OP_SENDINGPART",
                    },
                    {
                        "channel": "client",
                        "direction": "recv",
                        "protocolMarker": 0xC5,
                        "opcode": 0x40,
                        "opcodeName": "OP_COMPRESSEDPART",
                    },
                    {
                        "channel": "client",
                        "direction": "recv",
                        "protocolMarker": 0xC5,
                        "opcode": 0xA1,
                        "opcodeName": "OP_COMPRESSEDPART_I64",
                    },
                    {
                        "channel": "client",
                        "direction": "recv",
                        "protocolMarker": 0xC5,
                        "opcode": 0xA2,
                        "opcodeName": "OP_SENDINGPART_I64",
                    },
                ],
            },
        ]
        checked_required = _check_action_requirements(required, packet_diff)
        checked_optional = _check_action_requirements(optional, packet_diff)
        start_ok = all(row["presentOnBoth"] for row in checked_required)
        payload_ok = all(row["presentOnBoth"] for row in checked_optional)
        return {
            "ok": start_ok,
            "mode": "action-required-opcodes",
            "required": checked_required,
            "optional": checked_optional,
            "downloadStartOk": start_ok,
            "downloadPayloadOk": payload_ok,
            "diagnosticFullOpcodeCoverageOk": bool(packet_diff.get("coverageOk")),
        }

    if not required:
        return {
            "ok": bool(packet_diff.get("coverageOk")),
            "mode": "full-opcode-coverage",
            "required": [],
        }

    checked = _check_action_requirements(required, packet_diff)
    return {
        "ok": all(row["presentOnBoth"] for row in checked),
        "mode": "action-required-opcodes",
        "required": checked,
        "diagnosticFullOpcodeCoverageOk": bool(packet_diff.get("coverageOk")),
    }


def _check_action_requirements(
    requirements: list[dict[str, Any]], packet_diff: dict[str, Any]
) -> list[dict[str, Any]]:
    checked: list[dict[str, Any]] = []
    for row in requirements:
        alternatives = row.get("alternatives")
        if isinstance(alternatives, list):
            present = _shared_any_opcode_present(packet_diff, alternatives)
        else:
            present = _shared_opcode_present(
                packet_diff,
                channel=str(row["channel"]),
                direction=str(row["direction"]),
                protocol_marker=int(row["protocolMarker"]),
                opcode=int(row["opcode"]),
            )
        checked.append({**row, "presentOnBoth": present})
    return checked


def _classify(
    action_coverage: dict[str, Any],
    diag_diff: dict[str, Any] | None,
    rust_count: int,
    mfc_count: int,
) -> str:
    """Maps the two engine outputs onto a per-action verdict.

    ``no-traffic`` when neither side produced packets in the window; ``one-sided``
    when only one did; ``coverage-parity`` when the opcode/family coverage agrees;
    otherwise ``divergence``. The strict byte ``ok`` is informational only.
    """

    if rust_count == 0 and mfc_count == 0:
        return "no-traffic"
    if rust_count == 0 or mfc_count == 0:
        return "one-sided"
    coverage_ok = bool(action_coverage.get("ok"))
    diag_ok = diag_diff is None or bool(diag_diff.get("ok"))
    return "coverage-parity" if coverage_ok and diag_ok else "divergence"


def diff_action(
    pair: ActionPair,
    *,
    rust_packets: list[dict[str, Any]],
    mfc_packets: list[dict[str, Any]],
    rust_diag: list[dict[str, Any]] | None = None,
    mfc_diag: list[dict[str, Any]] | None = None,
    lead_seconds: float = DEFAULT_LEAD_SECONDS,
    settle_seconds: float = DEFAULT_SETTLE_SECONDS,
) -> dict[str, Any]:
    """Diffs one correlated action's window across both clients.

    Slices every trace to the action's ``[t0, t1]`` window, then runs the existing
    :func:`packet_trace_diff.diff_traces` and (when diag traces are present)
    :func:`diag_event_diff.diff_traces`. Returns a per-action report object.
    """

    t0, t1 = pair.window(lead_seconds=lead_seconds, settle_seconds=settle_seconds)
    rust_slice = slice_trace(rust_packets, t0, t1)
    mfc_slice = slice_trace(mfc_packets, t0, t1)
    packet_diff = packet_trace_diff.diff_traces(rust_slice, mfc_slice)

    diag_diff: dict[str, Any] | None = None
    if rust_diag or mfc_diag:
        diag_diff = diag_event_diff.diff_traces(
            slice_trace(rust_diag or [], t0, t1),
            slice_trace(mfc_diag or [], t0, t1),
        )

    action_coverage = build_action_coverage(pair.kind, packet_diff)
    verdict = _classify(action_coverage, diag_diff, len(rust_slice), len(mfc_slice))
    return {
        "kind": pair.kind,
        "key": pair.key,
        "label": pair.rust.label,
        "window": {"t0": t0.isoformat(), "t1": t1.isoformat()},
        "observed": {
            "rust": pair.rust.observed_at.isoformat(),
            "mfc": pair.mfc.observed_at.isoformat(),
        },
        "packets": {"rust": len(rust_slice), "mfc": len(mfc_slice)},
        "verdict": verdict,
        "coverageOk": bool(action_coverage.get("ok")),
        "fullCoverageOk": bool(packet_diff.get("coverageOk")),
        "byteMatch": bool(packet_diff.get("ok")),
        "diagOk": diag_diff is None or bool(diag_diff.get("ok")),
        "actionCoverage": action_coverage,
        "packetDiff": packet_diff,
        "diagDiff": diag_diff,
    }


def unpaired_record(action: Action) -> dict[str, Any]:
    """Compact record for an action that could not be correlated across clients."""

    return {
        "client": action.client,
        "kind": action.kind,
        "key": action.key,
        "label": action.label,
        "observedAt": action.observed_at.isoformat(),
        "verdict": "unpaired",
    }


def build_action_report(action_diff: dict[str, Any], *, campaign_id: str, seq: int) -> dict[str, Any]:
    """Wraps a :func:`diff_action` result with campaign identity for persistence."""

    return {"schema": "soak_action_diff_v1", "campaignId": campaign_id, "seq": seq, **action_diff}


def safe_report_key(value: Any) -> str:
    """Returns a short filename-safe action key for report paths."""

    text = str(value or "action").strip() or "action"
    normalized = text.lower()
    if _HEX_REPORT_KEY.fullmatch(normalized):
        return "hash"
    if "://" in normalized or normalized.startswith("www."):
        return "url"
    text = _WINDOWS_RESERVED_FILENAME_CHARS.sub("_", text)
    text = text.rstrip(" .") or "action"
    return "term" if text != "action" else "action"


def write_action_report(report: dict[str, Any], actions_dir: Path) -> Path:
    """Writes one per-action report to ``actions_dir`` and returns its path."""

    actions_dir.mkdir(parents=True, exist_ok=True)
    seq = report.get("seq", 0)
    key = safe_report_key(report.get("key"))
    path = actions_dir / f"{seq:05d}-{report.get('kind', 'action')}-{key}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def empty_summary(campaign_id: str) -> dict[str, Any]:
    """Returns a fresh rolling-summary object for a campaign."""

    return {
        "schema": "soak_action_summary_v1",
        "campaignId": campaign_id,
        "totals": {
            "actions": 0,
            "coverageParity": 0,
            "divergence": 0,
            "oneSided": 0,
            "noTraffic": 0,
            "unpaired": 0,
        },
        "actions": [],
    }


_VERDICT_TOTAL = {
    "coverage-parity": "coverageParity",
    "divergence": "divergence",
    "one-sided": "oneSided",
    "no-traffic": "noTraffic",
    "unpaired": "unpaired",
}


def append_to_summary(summary: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Folds one per-action report into the rolling campaign summary (in place)."""

    totals = summary["totals"]
    totals["actions"] += 1
    bucket = _VERDICT_TOTAL.get(report.get("verdict", ""))
    if bucket:
        totals[bucket] += 1
    summary["actions"].append(
        {
            "seq": report.get("seq"),
            "kind": report.get("kind"),
            "key": report.get("key"),
            "label": report.get("label"),
            "verdict": report.get("verdict"),
            "coverageOk": report.get("coverageOk"),
            "byteMatch": report.get("byteMatch"),
        }
    )
    return summary
