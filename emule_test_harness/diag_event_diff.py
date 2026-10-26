"""Semantic diff of two ``diag_event_v2`` diagnostic traces (rust vs MFC).

Both clients emit the single ``diag_event_v2`` envelope; this module aligns the two traces
per ``(family, event)`` and compares only the fields marked **comparable** (C)
in the schema §3 tables, ignoring client-specific (S) fields, timestamps, and
sequence counters.

It generalises ``packet_trace_diff.py``:

* the packet families (``ed2k_tcp``, ``ed2k_server_udp``, ``kad_udp``) reuse the same wire-identity
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
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from emule_test_harness.diag_event_runs import load_diag_event_segment
from emule_test_harness.diag_event_schema import (
    DIAG_EVENT_DIFF_REPORT_SCHEMA,
    DIAG_EVENT_FAMILY_CONFORMANCE_REPORT_SCHEMA,
    DIAG_EVENT_SCHEMA,
    DIAG_EVENT_SCHEMA_AUDIT_REPORT_SCHEMA,
    ED2K_CLIENT_UDP_FAMILY,
    FULL_RUN_REQUIRED_PARITY_FAMILIES,
)

PACKET_FAMILIES = ("ed2k_tcp", "ed2k_server_udp", "kad_udp")
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

# Oracle body keys BOTH clients emit only CONDITIONALLY — present only when the event
# actually carried that datum. e.g. `firstSkipReason` on sched/upload_request_outcome
# appears only when an upload request skipped a block before serving; MFC omits it the
# same way rust does (OtherFunctions.cpp appends it only when non-empty). So a finite
# window where rust logged none of these while the oracle logged some is a SAMPLING
# artifact, not a rust ⊇ oracle gap — never a conformance violation. Keyed by family.
_CONDITIONAL_ORACLE_BODY_KEYS: dict[str, frozenset[str]] = {
    "sched": frozenset({"firstSkipReason"}),
    # MFC overloads the kad_event "lookup" event across milestones (search lookups,
    # kad_request_flood anti-flood drops, ...) with different bodies; `reason` appears
    # only on the flood/error milestones, which rust emits under a DISTINCT event name
    # (`anti_flood_drop`), not on its search-lookup event. So a window where MFC logged
    # a lookup-with-reason while rust's lookups had none is a schema-overload sampling
    # artifact, not a rust ⊇ oracle gap.
    "kad_event": frozenset({"reason"}),
}


def load_trace(path: Path) -> list[dict[str, Any]]:
    """Loads current diagnostic-event records from one complete JSONL segment."""

    return load_diag_event_segment(Path(path))


def load_traces(paths: list[Path]) -> list[dict[str, Any]]:
    """Loads supported records from ordered diagnostic-event segments."""

    return [record for path in paths for record in load_trace(path)]


def _by_family(trace: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    return [r for r in trace if r.get("family") == family]


def _require_current_trace(trace: list[dict[str, Any]], *, side: str) -> None:
    for index, record in enumerate(trace):
        if record.get("schema") != DIAG_EVENT_SCHEMA:
            raise ValueError(
                f"{side} trace record {index} uses {record.get('schema')!r}; "
                f"expected {DIAG_EVENT_SCHEMA!r}"
            )


# --------------------------------------------------------------------------- #
# Packet families (ed2k_tcp / ed2k_server_udp / kad_udp): wire identity.
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
    return (
        record.get("event") == "packet"
        and body.get("direction") in _PACKET_DIRECTIONS
        and body.get("opcode") is not None
    )


def _is_non_negative_int(value: Any, *, maximum: int | None = None) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        and (maximum is None or value <= maximum)
    )


def _has_exact_hex(body: dict[str, Any], length_key: str, hex_key: str) -> bool:
    declared_length = body.get(length_key)
    encoded = body.get(hex_key)
    if not _is_non_negative_int(declared_length) or not isinstance(encoded, str):
        return False
    if len(encoded) != declared_length * 2:
        return False
    try:
        bytes.fromhex(encoded)
    except ValueError:
        return False
    return True


def _optional_exact_hex(body: dict[str, Any], length_key: str, hex_key: str) -> bool:
    if length_key not in body and hex_key not in body:
        return True
    return _has_exact_hex(body, length_key, hex_key)


def _optional_md4_hex(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or len(value) != 32 or value != value.lower():
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def ed2k_tcp_packet_view(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalizes one complete unified eD2K TCP packet event for harness use."""

    keys = record.get("keys")
    body = record.get("body")
    if (
        record.get("schema") != DIAG_EVENT_SCHEMA
        or record.get("family") != "ed2k_tcp"
        or record.get("event") != "packet"
        or not isinstance(keys, dict)
        or not isinstance(body, dict)
    ):
        return None

    timestamp = record.get("ts")
    peer = keys.get("peer")
    direction = body.get("direction")
    outcome = body.get("outcome")
    flow = body.get("flow")
    transport_mode = body.get("transportMode")
    protocol_marker = body.get("protocolMarker")
    protocol_name = body.get("protocolName")
    opcode = body.get("opcode")
    opcode_name = body.get("opcodeName")
    trace_key = body.get("traceKey")
    state_id = body.get("stateId")
    state_label = body.get("stateLabel")
    obfuscated = body.get("obfuscated")
    required_strings = (
        timestamp,
        peer,
        flow,
        transport_mode,
        protocol_name,
        opcode_name,
    )
    optional_strings = (outcome, body.get("phase"), trace_key, state_id, state_label)
    if (
        not all(isinstance(value, str) and value for value in required_strings)
        or not all(value is None or isinstance(value, str) and value for value in optional_strings)
        or direction not in _PACKET_DIRECTIONS
        or not _is_non_negative_int(protocol_marker, maximum=0xFF)
        or not _is_non_negative_int(opcode, maximum=0xFF)
        or not isinstance(obfuscated, bool)
        or transport_mode not in {"plaintext", "obfuscated"}
        or obfuscated != (transport_mode == "obfuscated")
        or keys.get("protocolMarker") != protocol_marker
        or keys.get("opcode") != opcode
        or not _has_exact_hex(body, "clearFrameLen", "clearFrameHex")
        or not _optional_exact_hex(body, "rawLen", "rawHex")
        or (not obfuscated and not _has_exact_hex(body, "rawLen", "rawHex"))
        or not _has_exact_hex(body, "payloadLen", "payloadHex")
        or body.get("payloadHexTruncated") is not False
        or not _optional_md4_hex(keys.get("peerHash"))
        or not _optional_md4_hex(keys.get("fileHash"))
    ):
        return None

    send_attempt_id = body.get("sendAttemptId", keys.get("sendAttemptId"))
    if send_attempt_id is not None:
        if not _is_non_negative_int(send_attempt_id) or send_attempt_id == 0:
            return None
        if keys.get("sendAttemptId", send_attempt_id) != send_attempt_id:
            return None

    event_sequence = record.get("streamSeq", record.get("seq"))
    if event_sequence is not None and not _is_non_negative_int(event_sequence):
        return None

    packet = {
        "source": record.get("client"),
        "ts_utc": timestamp,
        "event_seq": event_sequence,
        "trace_key": trace_key,
        "state_id": state_id,
        "state_label": state_label,
        "flow": flow,
        "phase": body.get("phase"),
        "direction": direction,
        "outcome": outcome,
        "remote_addr": peer,
        "peer_hash": keys.get("peerHash"),
        "file_hash": keys.get("fileHash"),
        "transport_mode": transport_mode,
        "obfuscated": obfuscated,
        "protocol": protocol_name,
        "protocol_marker": protocol_marker,
        "opcode": opcode,
        "opcode_name": opcode_name,
        "raw_len": body.get("rawLen"),
        "raw_hex": body.get("rawHex"),
        "clear_frame_len": body.get("clearFrameLen"),
        "clear_frame_hex": body.get("clearFrameHex"),
        "attempted_len": body.get("attemptedLen"),
        "written_len": body.get("writtenLen"),
        "payload_len": body["payloadLen"],
        "payload_hex": body["payloadHex"],
        "payload_hex_truncated": body.get("payloadHexTruncated"),
        "note": body.get("note"),
    }
    if send_attempt_id is not None:
        packet["send_attempt_id"] = send_attempt_id
    return packet


def ed2k_tcp_packet_views(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Returns internal packet views for complete unified eD2K TCP events.

    State, send-outcome, obfuscation-handshake, and malformed records are
    intentionally excluded so packet and action coverage consume wire packets
    only.
    """

    packets = []
    for record in records:
        packet = ed2k_tcp_packet_view(record)
        if packet is not None:
            packets.append(packet)
    return packets


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
# eD2K client UDP: exact datagrams plus correlated send lifecycles.
# --------------------------------------------------------------------------- #


_CLIENT_UDP_TERMINAL_OUTCOMES = frozenset(
    {"send_succeeded", "send_failed", "send_cancelled"}
)


def _is_client_udp_packet(record: dict[str, Any]) -> bool:
    body = record.get("body") or {}
    return (
        record.get("event") == "packet"
        and body.get("direction") in _PACKET_DIRECTIONS
        and isinstance(body.get("rawHex"), str)
    )


def _client_udp_packet_description(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("body") or {}
    return {
        "direction": body.get("direction"),
        "outcome": body.get("outcome"),
        "opcode": body.get("opcode"),
        "opcodeName": body.get("opcodeName"),
        "rawLen": body.get("rawLen"),
        "rawHex": body.get("rawHex"),
    }


def _diff_client_udp_packets(
    rust_recs: list[dict[str, Any]],
    mfc_recs: list[dict[str, Any]],
) -> dict[str, Any]:
    groups: list[dict[str, Any]] = []
    matched = wire_mismatches = only_rust = only_mfc = 0
    for direction in _PACKET_DIRECTIONS:
        rust_block = [
            record
            for record in rust_recs
            if _is_client_udp_packet(record)
            and (record.get("body") or {}).get("direction") == direction
        ]
        mfc_block = [
            record
            for record in mfc_recs
            if _is_client_udp_packet(record)
            and (record.get("body") or {}).get("direction") == direction
        ]
        if not rust_block and not mfc_block:
            continue

        rust_keys = [(record.get("body") or {}).get("rawHex") for record in rust_block]
        mfc_keys = [(record.get("body") or {}).get("rawHex") for record in mfc_block]
        matcher = difflib.SequenceMatcher(a=rust_keys, b=mfc_keys, autojunk=False)
        group_matched = 0
        group_mismatches: list[dict[str, Any]] = []
        group_only_rust: list[dict[str, Any]] = []
        group_only_mfc: list[dict[str, Any]] = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                group_matched += i2 - i1
                continue
            rust_part = rust_block[i1:i2]
            mfc_part = mfc_block[j1:j2]
            paired = min(len(rust_part), len(mfc_part))
            for offset in range(paired):
                group_mismatches.append(
                    {
                        "rust": _client_udp_packet_description(rust_part[offset]),
                        "mfc": _client_udp_packet_description(mfc_part[offset]),
                    }
                )
            group_only_rust.extend(
                _client_udp_packet_description(record) for record in rust_part[paired:]
            )
            group_only_mfc.extend(
                _client_udp_packet_description(record) for record in mfc_part[paired:]
            )

        matched += group_matched
        wire_mismatches += len(group_mismatches)
        only_rust += len(group_only_rust)
        only_mfc += len(group_only_mfc)
        groups.append(
            {
                "direction": direction,
                "rustCount": len(rust_block),
                "mfcCount": len(mfc_block),
                "matched": group_matched,
                "wireMismatches": group_mismatches,
                "onlyRust": group_only_rust,
                "onlyMfc": group_only_mfc,
            }
        )

    return {
        "ok": wire_mismatches == 0 and only_rust == 0 and only_mfc == 0,
        "totals": {
            "matched": matched,
            "wireMismatches": wire_mismatches,
            "onlyRust": only_rust,
            "onlyMfc": only_mfc,
        },
        "directions": groups,
    }


def _send_attempt_id(record: dict[str, Any]) -> Any:
    body = record.get("body") or {}
    keys = record.get("keys") or {}
    return body.get("sendAttemptId", keys.get("sendAttemptId"))


def _client_udp_lifecycle_audit(records: list[dict[str, Any]]) -> dict[str, Any]:
    attempts: dict[int, tuple[int, dict[str, Any]]] = {}
    terminals: dict[int, list[tuple[int, dict[str, Any]]]] = {}
    violations: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        event = record.get("event")
        body = record.get("body") or {}
        direction = body.get("direction")
        outcome = body.get("outcome")
        if event == "packet" and direction == "send":
            attempt_id = _send_attempt_id(record)
            if outcome != "attempted":
                violations.append(
                    {"kind": "invalid_attempt_outcome", "index": index, "outcome": outcome}
                )
                continue
            if not isinstance(attempt_id, int) or isinstance(attempt_id, bool) or attempt_id <= 0:
                violations.append(
                    {"kind": "invalid_attempt_id", "index": index, "sendAttemptId": attempt_id}
                )
                continue
            if attempt_id in attempts:
                violations.append(
                    {"kind": "duplicate_attempt", "index": index, "sendAttemptId": attempt_id}
                )
                continue
            attempts[attempt_id] = (index, record)
        elif event == "send_outcome":
            attempt_id = _send_attempt_id(record)
            if not isinstance(attempt_id, int) or isinstance(attempt_id, bool) or attempt_id <= 0:
                violations.append(
                    {"kind": "invalid_terminal_id", "index": index, "sendAttemptId": attempt_id}
                )
                continue
            terminals.setdefault(attempt_id, []).append((index, record))
            if outcome not in _CLIENT_UDP_TERMINAL_OUTCOMES:
                violations.append(
                    {"kind": "invalid_terminal_outcome", "index": index, "outcome": outcome}
                )
            expected_delivery_known = outcome != "send_cancelled"
            if body.get("deliveryKnown") is not expected_delivery_known:
                violations.append(
                    {
                        "kind": "invalid_delivery_known",
                        "index": index,
                        "outcome": outcome,
                        "deliveryKnown": body.get("deliveryKnown"),
                    }
                )

    for attempt_id, (attempt_index, _record) in sorted(attempts.items()):
        matching = terminals.get(attempt_id, [])
        if not matching:
            violations.append({"kind": "missing_terminal", "sendAttemptId": attempt_id})
        elif len(matching) > 1:
            violations.append(
                {
                    "kind": "duplicate_terminal",
                    "sendAttemptId": attempt_id,
                    "count": len(matching),
                }
            )
        elif matching[0][0] < attempt_index:
            violations.append(
                {"kind": "terminal_before_attempt", "sendAttemptId": attempt_id}
            )
    for attempt_id in sorted(set(terminals) - set(attempts)):
        violations.append({"kind": "orphan_terminal", "sendAttemptId": attempt_id})

    coverage = sorted(
        {
            (
                (record.get("body") or {}).get("role"),
                (record.get("body") or {}).get("opcode"),
                (record.get("body") or {}).get("outcome"),
            )
            for matching in terminals.values()
            for _index, record in matching
        },
        key=repr,
    )
    outcome_counts: dict[str, int] = {}
    for matching in terminals.values():
        for _index, record in matching:
            outcome = (record.get("body") or {}).get("outcome")
            if isinstance(outcome, str):
                outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
    return {
        "ok": not violations,
        "attemptCount": len(attempts),
        "terminalCount": sum(len(matching) for matching in terminals.values()),
        "violations": violations,
        "outcomes": dict(sorted(outcome_counts.items())),
        "coverage": [
            {"role": role, "opcode": opcode, "outcome": outcome}
            for role, opcode, outcome in coverage
        ],
        "coverageKeys": coverage,
    }


def audit_client_udp_lifecycle(trace: list[dict[str, Any]]) -> dict[str, Any]:
    """Validates one complete trace's client-UDP send attempt lifecycle."""

    _require_current_trace(trace, side="diagnostic")
    return _client_udp_lifecycle_audit(_by_family(trace, ED2K_CLIENT_UDP_FAMILY))


def _diff_client_udp_family(
    rust_recs: list[dict[str, Any]],
    mfc_recs: list[dict[str, Any]],
) -> dict[str, Any]:
    packet_diff = _diff_client_udp_packets(rust_recs, mfc_recs)
    rust_lifecycle = _client_udp_lifecycle_audit(rust_recs)
    mfc_lifecycle = _client_udp_lifecycle_audit(mfc_recs)
    rust_coverage = set(rust_lifecycle.pop("coverageKeys"))
    mfc_coverage = set(mfc_lifecycle.pop("coverageKeys"))
    only_rust_coverage = sorted(rust_coverage - mfc_coverage, key=repr)
    only_mfc_coverage = sorted(mfc_coverage - rust_coverage, key=repr)

    def describe_coverage(items: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
        return [
            {"role": role, "opcode": opcode, "outcome": outcome}
            for role, opcode, outcome in items
        ]

    coverage = {
        "ok": not only_rust_coverage and not only_mfc_coverage,
        "onlyRust": describe_coverage(only_rust_coverage),
        "onlyMfc": describe_coverage(only_mfc_coverage),
    }
    return {
        "family": ED2K_CLIENT_UDP_FAMILY,
        "strategy": "client_udp_mixed",
        "ok": packet_diff["ok"]
        and rust_lifecycle["ok"]
        and mfc_lifecycle["ok"]
        and coverage["ok"],
        "packets": packet_diff,
        "lifecycle": {"rust": rust_lifecycle, "mfc": mfc_lifecycle},
        "coverage": coverage,
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
        # rust ⊇ oracle parity contract: rust may emit a SUPERSET of events; the
        # only real failure is an oracle event rust LACKS (onlyMfc). onlyRust events
        # are allowed extras, reported for visibility but not a failure. (Matches the
        # rust-superset-of-oracle model already used by schema_audit.)
        "ok": not only_mfc,
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

    # rust ⊇ oracle: rust emits sched event TYPES the MFC oracle never emits at all
    # (e.g. upload_request_outcome, upload_payload_accounting). Drop only those true
    # rust-only supersets from rust's transition sequence — keep EVERY oracle event
    # so a real divergence (rust emitting a *different* event for the same slot, e.g.
    # slot_closed where the oracle recycled) still fails.
    mfc_event_types = {record.get("event") for record in mfc_recs}
    matched_keys = 0
    transition_divergences: list[dict[str, Any]] = []
    for key in shared:
        # The keyless "<global>|" bucket aggregates periodic snapshots (e.g.
        # capacity_snapshot); rust has no fixed upload-queue tick gate so its cadence
        # is far higher (318 vs 1) and the ordering is not a per-peer transition to
        # compare. Validate those via invariants (below), not sequence equality.
        if key == "<global>|":
            matched_keys += 1
            continue
        rust_seq = [t for t in _sched_transitions(rust_by_key[key]) if t[0] in mfc_event_types]
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
    """Compares two ``diag_event_v2`` traces family-by-family."""

    _require_current_trace(rust_trace, side="rust")
    _require_current_trace(mfc_trace, side="mfc")
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
        elif family == ED2K_CLIENT_UDP_FAMILY:
            families.append(_diff_client_udp_family(rust_recs, mfc_recs))
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
        "schema": DIAG_EVENT_DIFF_REPORT_SCHEMA,
        "ok": bool(families) and all(f["ok"] for f in families),
        "families": families,
    }


def schema_audit(
    rust_trace: list[dict[str, Any]],
    mfc_trace: list[dict[str, Any]],
) -> dict[str, Any]:
    """Body-field schema delta per ``(family, event)``, MFC being the oracle.

    Event *names* aligning across rust and the MFC oracle does not mean their
    bodies do. For every event, this reports which body keys are shared,
    rust-only, or oracle(MFC)-only, plus which side emits the event at all — so
    rust emitters can be conformed to the oracle schema. Keys only; value
    semantics are out of scope.
    """

    _require_current_trace(rust_trace, side="rust")
    _require_current_trace(mfc_trace, side="mfc")

    def index(trace: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        acc: dict[tuple[str, str], dict[str, Any]] = {}
        for record in trace:
            family = record.get("family")
            event = record.get("event")
            if not isinstance(family, str) or not isinstance(event, str):
                continue
            if family in PACKET_FAMILIES and not _is_wire_packet(record):
                continue
            slot = acc.setdefault((family, event), {"keys": set(), "count": 0})
            body = record.get("body")
            if isinstance(body, dict):
                slot["keys"].update(body.keys())
            slot["count"] += 1
        return acc

    rust_idx = index(rust_trace)
    mfc_idx = index(mfc_trace)
    events: list[dict[str, Any]] = []
    for family, event in sorted(set(rust_idx) | set(mfc_idx)):
        rust = rust_idx.get((family, event))
        mfc = mfc_idx.get((family, event))
        rkeys = rust["keys"] if rust else set()
        mkeys = mfc["keys"] if mfc else set()
        presence = "both" if rust and mfc else ("rust_only" if rust else "mfc_only")
        events.append(
            {
                "family": family,
                "event": event,
                "presence": presence,
                "rustCount": rust["count"] if rust else 0,
                "mfcCount": mfc["count"] if mfc else 0,
                "bodyOk": presence == "both" and rkeys == mkeys,
                "sharedKeys": sorted(rkeys & mkeys),
                "onlyRustKeys": sorted(rkeys - mkeys),
                "onlyMfcKeys": sorted(mkeys - rkeys),
            }
        )
    ok = all(e["presence"] == "both" and e["bodyOk"] for e in events)
    # Oracle-conformance verdict (MFC = oracle): rust must cover every oracle event
    # and, on shared events, every oracle body key (rust ⊇ oracle). rust-only events
    # and rust-only body keys are allowed extras, not violations. Oracle events rust
    # did not emit in-window are `unverified` (window/state vs a real gap is
    # indistinguishable from a single trace), not a hard fail.
    body_violations = []
    for e in events:
        if e["presence"] != "both" or not e["onlyMfcKeys"]:
            continue
        conditional = _CONDITIONAL_ORACLE_BODY_KEYS.get(e["family"], frozenset())
        missing = [
            key for key in e["onlyMfcKeys"] if key not in conditional
        ]
        if missing:
            body_violations.append(
                {"family": e["family"], "event": e["event"], "missingOracleKeys": missing}
            )
    conformance = {
        "conformant": not body_violations,
        "bodyKeyViolations": body_violations,
        "oracleOnlyUnverified": [
            f"{e['family']}/{e['event']}" for e in events if e["presence"] == "mfc_only"
        ],
        "rustExtraEvents": [
            f"{e['family']}/{e['event']}" for e in events if e["presence"] == "rust_only"
        ],
    }
    return {
        "schema": DIAG_EVENT_SCHEMA_AUDIT_REPORT_SCHEMA,
        "ok": ok,
        "events": events,
        "conformance": conformance,
    }


def family_conformance(
    rust_trace: list[dict[str, Any]],
    mfc_trace: list[dict[str, Any]],
    *,
    required_families: Iterable[str] = (),
) -> dict[str, Any]:
    """Per-family oracle-conformance gate for one shared action window.

    The strict record-identity diff (:func:`diff_traces` ``ok``) can NEVER pass
    across two independent live sessions — different peers, payloads and timing
    make the per-record sequences unmatchable by construction. The per-action
    gate that IS live-meaningful is oracle conformance scoped per family: for
    every diag family present on both sides, rust's event-type/body-key coverage
    must be a superset of the oracle's (MFC's) on the shared events, reusing the
    exact :func:`schema_audit` rules with no privacy-based omissions.
    Conditional keys remain excluded. Oracle events rust did not emit in-window stay
    informational (``oracleOnlyEvents``) — window/state sampling is
    indistinguishable from a real gap in a finite slice — as do families present
    on only one side.
    """

    audit = schema_audit(rust_trace, mfc_trace)
    required = sorted(set(required_families))
    rust_present = {
        record.get("family")
        for record in rust_trace
        if isinstance(record.get("family"), str)
    }
    mfc_present = {
        record.get("family")
        for record in mfc_trace
        if isinstance(record.get("family"), str)
    }
    required_presence = [
        {
            "family": family,
            "rustPresent": family in rust_present,
            "mfcPresent": family in mfc_present,
            "ok": family in rust_present and family in mfc_present,
        }
        for family in required
    ]
    required_ok = all(item["ok"] for item in required_presence)
    per_family: dict[str, dict[str, Any]] = {}
    for event in audit["events"]:
        slot = per_family.setdefault(
            event["family"],
            {
                "family": event["family"],
                "rustEventTypes": 0,
                "mfcEventTypes": 0,
                "bodyKeyViolations": [],
                "oracleOnlyEvents": [],
                "rustOnlyEvents": [],
            },
        )
        if event["rustCount"]:
            slot["rustEventTypes"] += 1
        if event["mfcCount"]:
            slot["mfcEventTypes"] += 1
        if event["presence"] == "mfc_only":
            slot["oracleOnlyEvents"].append(event["event"])
        elif event["presence"] == "rust_only":
            slot["rustOnlyEvents"].append(event["event"])
    for violation in audit["conformance"]["bodyKeyViolations"]:
        slot = per_family.get(violation["family"])
        if slot is not None:
            slot["bodyKeyViolations"].append(violation)
    families: list[dict[str, Any]] = []
    for slot in sorted(per_family.values(), key=lambda f: str(f["family"])):
        slot["presentOnBoth"] = slot["rustEventTypes"] > 0 and slot["mfcEventTypes"] > 0
        # Body-key violations only exist on shared events, so a family present on
        # one side alone is vacuously ok (informational, never a failure).
        slot["ok"] = not slot["bodyKeyViolations"]
        families.append(slot)
    return {
        "schema": DIAG_EVENT_FAMILY_CONFORMANCE_REPORT_SCHEMA,
        "ok": bool(families) and all(f["ok"] for f in families) and required_ok,
        "families": families,
        "requiredFamilies": required_presence,
        "requiredFamiliesOk": required_ok,
    }


def full_run_conformance(
    rust_trace: list[dict[str, Any]],
    mfc_trace: list[dict[str, Any]],
    *,
    required_families: Iterable[str] = FULL_RUN_REQUIRED_PARITY_FAMILIES,
) -> dict[str, Any]:
    """Validates complete-capture family presence, schema, and send lifecycles."""

    family_gate = family_conformance(
        rust_trace,
        mfc_trace,
        required_families=required_families,
    )
    rust_lifecycle = audit_client_udp_lifecycle(rust_trace)
    mfc_lifecycle = audit_client_udp_lifecycle(mfc_trace)
    return {
        "ok": family_gate["ok"] and rust_lifecycle["ok"] and mfc_lifecycle["ok"],
        "familyConformance": family_gate,
        "clientUdpLifecycle": {
            "rust": rust_lifecycle,
            "mfc": mfc_lifecycle,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Diff two {DIAG_EVENT_SCHEMA} diagnostic traces.")
    parser.add_argument("--rust", required=True, type=Path, help="emulebb-rust diag_event_v2 JSONL dump.")
    parser.add_argument("--mfc", required=True, type=Path, help="eMuleBB (MFC) diag_event_v2 JSONL dump.")
    args = parser.parse_args(argv)

    report = diff_traces(load_trace(args.rust), load_trace(args.mfc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
