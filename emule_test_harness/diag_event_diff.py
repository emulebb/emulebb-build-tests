"""Semantic diff of two ``diag_event_v1`` diagnostic traces (rust vs MFC).

Both clients emit the single ``diag_event_v1`` envelope (see
``docs/diagnostics/diag-event-v1-schema.md``); this module aligns the two traces
per ``(family, event)`` and compares only the fields marked **comparable** (C)
in the schema §3 tables, ignoring client-specific (S) fields, timestamps, and
sequence counters.

It generalises ``packet_trace_diff.py``:

* the packet families (``ed2k_tcp``, ``kad_udp``) reuse the same wire-identity
  ``SequenceMatcher`` algorithm — the compare key is ``(protocolMarker, opcode,
  payloadHex)`` for eD2k TCP and ``(protocolMarker, opcode, decodedHex)`` for Kad
  UDP (decoded, so an obfuscation-key difference is not a false mismatch);
* the event families (``kad_event``, ``bad_peer``) use a multiset match over the
  comparable ``(event, keys, body)`` canonical tuple;
* ``sched`` uses a structural match — per aligned ``(peer, file)`` the ordered
  sequence of ``(event, outcome)`` transitions must agree, and numeric C fields
  are checked for invariants (queue rank monotonic non-increasing, a connection
  ``deny`` only at/over the cap) rather than for exact equality, since two
  independent live clients will not match numerically. ``sched`` keys present on
  only one side are reported but are NOT a failure (the two clients may engage
  different peers); only diverging shared keys / invariant violations fail.
"""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
from typing import Any

DIAG_SCHEMA = "diag_event_v1"

PACKET_FAMILIES = ("ed2k_tcp", "kad_udp")
EVENT_FAMILIES = ("kad_event", "bad_peer")
SCHED_FAMILY = "sched"

_PACKET_DIRECTIONS = ("send", "recv")

# Comparable (C) body fields per family (schema §3). Anything not listed is
# client-specific (S) and ignored. Optional fields are simply absent when a call
# site does not have them; an absent field on both sides compares equal.
_COMPARABLE_BODY: dict[str, tuple[str, ...]] = {
    "kad_event": (
        "milestone",
        "action",
        "connected",
        "bootstrapping",
        "firewalled",
        "lanMode",
        "contactTotal",
        "contactVerified",
        "contactWithUdpKey",
        "searchType",
        "resultCount",
        "expectedCount",
    ),
    "bad_peer": (
        "behavior",
        "action",
        "repeatCount",
        "windowSeconds",
        "startOffset",
        "endOffset",
        "partIndex",
        "spamRating",
        "consideredSpam",
    ),
    "sched": (
        "outcome",
        "transport",
        "swapReason",
        "swapTargetFileHash",
        "queueRank",
        "slotKind",
        "denyReason",
        "sourceCount",
        "validSourceCount",
        "nnpSourceCount",
        "a4afFileCount",
        "limitBytesPerSec",
        "baseSlots",
        "elasticSlots",
        "effectiveSlotCap",
        "activeGrantedSessions",
        "activeNeverUploadedSessions",
        "activeProductiveSessions",
        "activeSlots",
        "activeUploadingSessions",
        "waitingSessions",
    ),
}

# Comparable (C) key fields per family for event-family alignment/identity.
_COMPARABLE_KEYS: dict[str, tuple[str, ...]] = {
    "kad_event": ("nodeId", "peer", "searchId"),
    "bad_peer": ("peer", "peerHash", "fileHash", "searchId"),
}


def load_trace(path: Path) -> list[dict[str, Any]]:
    """Loads ``diag_event_v1`` records from a JSONL dump (``\\n`` or ``\\r\\n``)."""

    records: list[dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("schema") != DIAG_SCHEMA:
            continue
        records.append(record)
    return records


def _by_family(trace: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    return [r for r in trace if r.get("family") == family]


# --------------------------------------------------------------------------- #
# Packet families (ed2k_tcp / kad_udp): wire-identity SequenceMatcher.
# --------------------------------------------------------------------------- #


def _packet_payload(family: str, body: dict[str, Any]) -> str:
    if family == "kad_udp":
        return body.get("decodedHex") or ""
    return body.get("payloadHex") or ""


def _packet_wire_key(family: str, record: dict[str, Any]) -> str:
    body = record.get("body") or {}
    return "{}:{}:{}".format(
        body.get("protocolMarker"), body.get("opcode"), _packet_payload(family, body)
    )


def _packet_opcode_key(record: dict[str, Any]) -> str:
    body = record.get("body") or {}
    return "{}:{}".format(body.get("protocolMarker"), body.get("opcode"))


def _packet_describe(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("body") or {}
    return {
        "opcode": body.get("opcode"),
        "opcodeName": body.get("opcodeName"),
        "protocolMarker": body.get("protocolMarker"),
        "payloadLen": body.get("payloadLen"),
    }


def _is_wire_packet(record: dict[str, Any]) -> bool:
    body = record.get("body") or {}
    return body.get("direction") in _PACKET_DIRECTIONS and body.get("opcode") is not None


def _diff_packet_family(
    family: str,
    rust_recs: list[dict[str, Any]],
    mfc_recs: list[dict[str, Any]],
) -> dict[str, Any]:
    directions: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for record in rust_recs:
        if not _is_wire_packet(record):
            continue
        direction = (record["body"]).get("direction")
        directions.setdefault(direction, {"rust": [], "mfc": []})["rust"].append(record)
    for record in mfc_recs:
        if not _is_wire_packet(record):
            continue
        direction = (record["body"]).get("direction")
        directions.setdefault(direction, {"rust": [], "mfc": []})["mfc"].append(record)

    groups: list[dict[str, Any]] = []
    matched = payload_mismatches = only_rust = only_mfc = 0
    for direction, members in sorted(directions.items()):
        rust_block = members["rust"]
        mfc_block = members["mfc"]
        rust_keys = [_packet_wire_key(family, r) for r in rust_block]
        mfc_keys = [_packet_wire_key(family, r) for r in mfc_block]
        matcher = difflib.SequenceMatcher(a=rust_keys, b=mfc_keys, autojunk=False)
        g_matched = 0
        g_payload: list[dict[str, Any]] = []
        g_only_rust: list[dict[str, Any]] = []
        g_only_mfc: list[dict[str, Any]] = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                g_matched += i2 - i1
                continue
            r_part = rust_block[i1:i2]
            m_part = mfc_block[j1:j2]
            paired = min(len(r_part), len(m_part))
            for offset in range(paired):
                r_rec = r_part[offset]
                m_rec = m_part[offset]
                if _packet_opcode_key(r_rec) == _packet_opcode_key(m_rec):
                    g_payload.append(
                        {
                            "opcode": (r_rec["body"]).get("opcode"),
                            "opcodeName": (r_rec["body"]).get("opcodeName"),
                            "rustPayloadLen": (r_rec["body"]).get("payloadLen"),
                            "mfcPayloadLen": (m_rec["body"]).get("payloadLen"),
                        }
                    )
                else:
                    g_only_rust.append(_packet_describe(r_rec))
                    g_only_mfc.append(_packet_describe(m_rec))
            g_only_rust.extend(_packet_describe(r) for r in r_part[paired:])
            g_only_mfc.extend(_packet_describe(m) for m in m_part[paired:])
        matched += g_matched
        payload_mismatches += len(g_payload)
        only_rust += len(g_only_rust)
        only_mfc += len(g_only_mfc)
        groups.append(
            {
                "direction": direction,
                "rustCount": len(rust_block),
                "mfcCount": len(mfc_block),
                "matched": g_matched,
                "payloadMismatches": g_payload,
                "onlyRust": g_only_rust,
                "onlyMfc": g_only_mfc,
            }
        )

    return {
        "family": family,
        "strategy": "wire_identity",
        "ok": payload_mismatches == 0 and only_rust == 0 and only_mfc == 0,
        "totals": {
            "matched": matched,
            "payloadMismatches": payload_mismatches,
            "onlyRust": only_rust,
            "onlyMfc": only_mfc,
        },
        "directions": groups,
    }


# --------------------------------------------------------------------------- #
# Event families (kad_event / bad_peer): multiset match over comparable tuple.
# --------------------------------------------------------------------------- #


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((k, _canonical(v)) for k, v in value.items()))
    if isinstance(value, list):
        return tuple(_canonical(v) for v in value)
    return value


def _event_identity(family: str, record: dict[str, Any]) -> tuple[Any, ...]:
    keys = record.get("keys") or {}
    body = record.get("body") or {}
    key_part = tuple(
        (name, keys.get(name)) for name in _COMPARABLE_KEYS.get(family, ()) if name in keys
    )
    body_part = tuple(
        (name, _canonical(body.get(name)))
        for name in _COMPARABLE_BODY.get(family, ())
        if name in body
    )
    return (record.get("event"), record.get("severity"), key_part, body_part)


def _describe_event(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": record.get("event"),
        "keys": record.get("keys"),
        "body": record.get("body"),
    }


def _diff_event_family(
    family: str,
    rust_recs: list[dict[str, Any]],
    mfc_recs: list[dict[str, Any]],
) -> dict[str, Any]:
    rust_pending = list(rust_recs)
    mfc_ids = [_event_identity(family, r) for r in mfc_recs]
    mfc_used = [False] * len(mfc_recs)
    matched = 0
    only_rust: list[dict[str, Any]] = []
    for record in rust_pending:
        identity = _event_identity(family, record)
        for index, mfc_identity in enumerate(mfc_ids):
            if not mfc_used[index] and mfc_identity == identity:
                mfc_used[index] = True
                matched += 1
                break
        else:
            only_rust.append(_describe_event(record))
    only_mfc = [_describe_event(mfc_recs[i]) for i, used in enumerate(mfc_used) if not used]
    return {
        "family": family,
        "strategy": "multiset",
        "ok": not only_rust and not only_mfc,
        "totals": {
            "matched": matched,
            "onlyRust": len(only_rust),
            "onlyMfc": len(only_mfc),
        },
        "onlyRust": only_rust,
        "onlyMfc": only_mfc,
    }


# --------------------------------------------------------------------------- #
# sched: structural (event, outcome) transition match per aligned (peer, file).
# --------------------------------------------------------------------------- #


def _sched_key(record: dict[str, Any]) -> str:
    keys = record.get("keys") or {}
    peer = keys.get("peerHash") or keys.get("peer") or "<global>"
    return "{}|{}".format(peer, keys.get("fileHash") or "")


def _sched_transitions(records: list[dict[str, Any]]) -> list[tuple[Any, Any]]:
    transitions: list[tuple[Any, Any]] = []
    for record in records:
        body = record.get("body") or {}
        transitions.append((record.get("event"), body.get("outcome")))
    return transitions


def _sched_invariants(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    last_rank: int | None = None
    for record in records:
        body = record.get("body") or {}
        if record.get("event") == "queue_rank":
            rank = body.get("queueRank")
            if isinstance(rank, int):
                if last_rank is not None and rank > last_rank:
                    violations.append(
                        {"invariant": "queue_rank_monotonic", "from": last_rank, "to": rank}
                    )
                last_rank = rank
        if record.get("event") == "conn_budget" and body.get("outcome") == "deny":
            active = body.get("activeConnections")
            cap = body.get("connectionCap")
            if isinstance(active, int) and isinstance(cap, int) and active < cap:
                violations.append(
                    {"invariant": "deny_only_at_cap", "active": active, "cap": cap}
                )
    return violations


def _sched_by_key(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(_sched_key(record), []).append(record)
    return grouped


def _diff_sched_family(
    rust_recs: list[dict[str, Any]],
    mfc_recs: list[dict[str, Any]],
) -> dict[str, Any]:
    rust_by_key = _sched_by_key(rust_recs)
    mfc_by_key = _sched_by_key(mfc_recs)
    shared = sorted(set(rust_by_key) & set(mfc_by_key))
    only_rust_keys = sorted(set(rust_by_key) - set(mfc_by_key))
    only_mfc_keys = sorted(set(mfc_by_key) - set(rust_by_key))

    matched_keys = 0
    transition_divergences: list[dict[str, Any]] = []
    for key in shared:
        rust_seq = _sched_transitions(rust_by_key[key])
        mfc_seq = _sched_transitions(mfc_by_key[key])
        if rust_seq == mfc_seq:
            matched_keys += 1
        else:
            transition_divergences.append(
                {"key": key, "rust": rust_seq, "mfc": mfc_seq}
            )

    invariant_violations: list[dict[str, Any]] = []
    for side, by_key in (("rust", rust_by_key), ("mfc", mfc_by_key)):
        for key, records in by_key.items():
            for violation in _sched_invariants(records):
                invariant_violations.append({"side": side, "key": key, **violation})

    return {
        "family": SCHED_FAMILY,
        "strategy": "structural",
        # Keys present on only one side are informational (the two clients may
        # engage different peers), not a failure.
        "ok": not transition_divergences and not invariant_violations,
        "totals": {
            "sharedKeys": len(shared),
            "matchedKeys": matched_keys,
            "transitionDivergences": len(transition_divergences),
            "onlyRustKeys": len(only_rust_keys),
            "onlyMfcKeys": len(only_mfc_keys),
            "invariantViolations": len(invariant_violations),
        },
        "transitionDivergences": transition_divergences,
        "invariantViolations": invariant_violations,
        "onlyRustKeys": only_rust_keys,
        "onlyMfcKeys": only_mfc_keys,
    }


# --------------------------------------------------------------------------- #
# Top-level dispatch.
# --------------------------------------------------------------------------- #


def diff_traces(
    rust_trace: list[dict[str, Any]],
    mfc_trace: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compares two ``diag_event_v1`` traces family-by-family (schema §4 D4)."""

    families: list[dict[str, Any]] = []
    families_present: set[str] = set()
    for record in (*rust_trace, *mfc_trace):
        family = record.get("family")
        if isinstance(family, str):
            families_present.add(family)
    for family in sorted(families_present):
        rust_recs = _by_family(rust_trace, family)
        mfc_recs = _by_family(mfc_trace, family)
        if family in PACKET_FAMILIES:
            families.append(_diff_packet_family(family, rust_recs, mfc_recs))
        elif family in EVENT_FAMILIES:
            families.append(_diff_event_family(family, rust_recs, mfc_recs))
        elif family == SCHED_FAMILY:
            families.append(_diff_sched_family(rust_recs, mfc_recs))
        else:
            # Unknown family: report counts, do not fail (forward-compatible).
            families.append(
                {
                    "family": family,
                    "strategy": "unknown",
                    "ok": True,
                    "totals": {"rustCount": len(rust_recs), "mfcCount": len(mfc_recs)},
                }
            )

    return {
        "schema": DIAG_SCHEMA,
        "ok": all(f["ok"] for f in families),
        "families": families,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diff two diag_event_v1 diagnostic traces.")
    parser.add_argument("--rust", required=True, type=Path, help="emulebb-rust diag_event_v1 JSONL dump.")
    parser.add_argument("--mfc", required=True, type=Path, help="eMuleBB (MFC) diag_event_v1 JSONL dump.")
    args = parser.parse_args(argv)

    report = diff_traces(load_trace(args.rust), load_trace(args.mfc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
