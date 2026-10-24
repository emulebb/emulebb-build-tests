"""Explicitly adapt legacy MFC diagnostic streams into ``diag_event_v2`` records.

MFC historically kept its richest
bad-peer diagnostics still live in a separate ``bad_peer_event_v1`` log with
*different event names* and a nested ``peer``/``file``/``evidence`` object shape,
so ``diag_event_diff`` never saw them and the
bad-peer surface is invisible to the cross-client diff.

This legacy adapter maps those records into the current ``diag_event_v2`` ``bad_peer`` envelope
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

from emule_test_harness.diag_event_schema import DIAG_EVENT_SCHEMA

# MFC ``bad_peer_event_v1`` event name -> current bad_peer event name.
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


def adapt_bad_peer_record(
    record: dict[str, Any],
    *,
    run_id: str = "legacy-mfc-bad-peer-adapter",
    segment_id: int = 0,
    sequence: int = 1,
) -> dict[str, Any]:
    """Maps one legacy MFC bad-peer record to a current diagnostic event."""

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
        "schema": DIAG_EVENT_SCHEMA,
        "client": "mfc",
        "runId": run_id,
        "processId": 0,
        "segmentId": segment_id,
        "seq": sequence,
        "streamSeq": sequence,
        "family": "bad_peer",
        "event": event,
        "severity": record.get("severity"),
        "ts": record.get("ts_utc"),
        "keys": keys,
        "body": body,
    }


def bad_peer_events_as_diag_v2(paths: list[Path]) -> list[dict[str, Any]]:
    """Reads legacy MFC bad-peer JSONL files and returns current diagnostic events."""

    out: list[dict[str, Any]] = []
    sequence = 0
    run_id = "legacy-mfc-bad-peer-adapter"
    for segment_id, path in enumerate(paths):
        text = Path(path).read_text(encoding="utf-8-sig")
        for line_number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"malformed legacy MFC diagnostic JSON in {path} at line {line_number}"
                ) from error
            if record.get("schema") != "bad_peer_event_v1":
                continue
            sequence += 1
            out.append(
                adapt_bad_peer_record(
                    record,
                    run_id=run_id,
                    segment_id=segment_id,
                    sequence=sequence,
                )
            )
    return out


def find_mfc_bad_peer_logs(logs_dir: Path) -> list[Path]:
    """Returns MFC's active + rotated ``bad_peer`` log files (newest last)."""

    matches = [Path(p) for p in glob.glob(str(Path(logs_dir) / "emulebb-diagnostics-bad-peer*.log"))]
    return sorted(matches, key=lambda p: p.stat().st_mtime)
