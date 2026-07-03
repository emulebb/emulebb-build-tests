"""Adapt MFC's standalone diagnostic streams into the converged ``diag_event_v1`` shape.

MFC only partially migrated to the converged ``diag_event_v1`` stream: its richest
bad-peer diagnostics still live in a separate ``bad_peer_event_v1`` log with
*different event names* and a nested ``peer``/``file``/``evidence`` object shape,
so ``diag_event_diff`` (which reads only ``diag_event_v1``) never sees them and the
bad-peer surface is invisible to the cross-client diff.

This adapter maps those records into the ``diag_event_v1`` ``bad_peer`` envelope
(rust event names, flat ``keys``/``body``) so they can be fed straight into
``diag_event_diff`` / ``schema_audit`` alongside rust's converged ``bad_peer``
family. Only MFC event names with a known rust counterpart are remapped; every
other MFC bad-peer event passes through unchanged so the diff surfaces it as an
oracle-only event (a genuine rust coverage gap, not a naming artifact).
"""

from __future__ import annotations

import glob
import json
from pathlib import Path
from typing import Any

# MFC ``bad_peer_event_v1`` event name -> rust ``diag_event_v1`` bad_peer event name.
BAD_PEER_EVENT_NAME_MAP: dict[str, str] = {
    "upload_repeat_block_request_observed": "repeat_block_request",
    "upload_repeat_file_request_observed": "repeat_file_request",
    "download_first_payload_timeout": "download_first_payload_timeout",
}

# MFC ``evidence`` field -> rust bad_peer body field (the diff's comparable-body names).
_EVIDENCE_BODY_MAP: dict[str, str] = {
    "repeat_count": "repeatCount",
    "window_seconds": "windowSeconds",
    "start_offset": "startOffset",
    "end_offset": "endOffset",
    "part_index": "partIndex",
}


def adapt_bad_peer_record(record: dict[str, Any]) -> dict[str, Any]:
    """Maps one MFC ``bad_peer_event_v1`` record to a ``diag_event_v1`` bad_peer event."""

    mfc_event = record.get("event")
    event = (
        BAD_PEER_EVENT_NAME_MAP.get(mfc_event, mfc_event)
        if isinstance(mfc_event, str)
        else mfc_event
    )
    peer = record.get("peer") or {}
    file_obj = record.get("file") or {}
    evidence = record.get("evidence") or {}

    keys: dict[str, Any] = {}
    address = peer.get("address") or peer.get("connect_ip")
    if address and peer.get("user_port"):
        keys["peer"] = f"{address}:{peer['user_port']}"
    if peer.get("user_hash"):
        keys["peerHash"] = str(peer["user_hash"]).lower()
    if file_obj.get("hash"):
        keys["fileHash"] = str(file_obj["hash"]).lower()

    body: dict[str, Any] = {}
    if record.get("action") is not None:
        body["action"] = record["action"]
    # rust carries the observed behavior name in `behavior` for the repeat events.
    if event in ("repeat_block_request", "repeat_file_request"):
        body["behavior"] = event
    for src, dst in _EVIDENCE_BODY_MAP.items():
        if src in evidence:
            body[dst] = evidence[src]

    return {
        "schema": "diag_event_v1",
        "family": "bad_peer",
        "event": event,
        "severity": record.get("severity"),
        "ts": record.get("ts_utc"),
        "keys": keys,
        "body": body,
    }


def bad_peer_events_as_diag_v1(paths: list[Path]) -> list[dict[str, Any]]:
    """Reads MFC ``bad_peer_event_v1`` JSONL files and returns ``diag_event_v1`` events."""

    out: list[dict[str, Any]] = []
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("schema") != "bad_peer_event_v1":
                continue
            out.append(adapt_bad_peer_record(record))
    return out


def find_mfc_bad_peer_logs(logs_dir: Path) -> list[Path]:
    """Returns MFC's active + rotated ``bad_peer`` log files (newest last)."""

    matches = [Path(p) for p in glob.glob(str(Path(logs_dir) / "emulebb-diagnostics-bad-peer*.log"))]
    return sorted(matches, key=lambda p: p.stat().st_mtime)
