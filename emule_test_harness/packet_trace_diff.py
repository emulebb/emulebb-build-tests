"""Diff two ``ed2k_packet_v1`` packet traces (emulebb-rust vs eMuleBB).

Both clients emit the converged ``ed2k_packet_v1`` JSONL packet dump
(emulebb-rust via ``EMULEBB_RUST_LOG_DIR``; eMuleBB via the
``EMULEBB_ENABLE_PACKET_DIAGNOSTICS`` build). This module aligns the two traces
per ``(flow, direction)`` and reports where the wire packets match, where the
payload differs for the same opcode, and where a packet is present on only one
side — so a rust↔eMuleBB exchange can be checked for wire-faithfulness.

The comparison key is the wire identity ``(protocol_marker, opcode, payload_hex)``
— deliberately NOT ``opcode_name`` (each client keeps its own name table) nor
``transport_mode`` (vocab differs) nor timestamps/event_seq/trace context.
"""

from __future__ import annotations

import argparse
import difflib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PACKET_SCHEMA = "ed2k_packet_v1"
_PACKET_DIRECTIONS = ("send", "recv")


def canonical_channel(flow: str | None) -> str:
    """Map a per-client flow label onto a shared rust↔eMuleBB channel taxonomy.

    The two clients name flows differently: eMuleBB MFC uses ``server`` and
    ``client`` (all client-to-client traffic), while emulebb-rust splits the C2C
    channel into ``listener`` (inbound peer), ``native_download``, and
    ``native_upload`` plus ``server``. Grouping the byte-level diff by the raw
    flow therefore never aligns peer traffic across the two clients, so the C2C
    parity is invisible. Collapsing every peer flow to ``client`` (and Kad to
    ``kad``) restores a comparable per-channel view.
    """

    normalized = (flow or "unknown").strip().lower()
    if normalized == "server":
        return "server"
    if normalized in {"kad", "kad_udp", "kademlia"}:
        return "kad"
    # Everything else is client-to-client peer traffic on both clients:
    # rust {listener, native_download, native_upload, peer, client}, MFC {client}.
    return "client"


def load_trace(path: Path) -> list[dict[str, Any]]:
    """Loads ed2k_packet_v1 packet records (send/recv) from a JSONL dump."""

    records: list[dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("schema") != PACKET_SCHEMA:
            continue
        if record.get("direction") not in _PACKET_DIRECTIONS:
            continue
        if record.get("opcode") is None:
            continue
        records.append(record)
    return records


def _wire_key(record: dict[str, Any]) -> str:
    """Wire identity of a packet, independent of per-client naming/transport."""

    return "{}:{}:{}".format(
        record.get("protocol_marker"),
        record.get("opcode"),
        record.get("payload_hex") or "",
    )


def _opcode_key(record: dict[str, Any]) -> str:
    """Opcode-only identity (ignores payload) for payload-mismatch detection."""

    return "{}:{}".format(record.get("protocol_marker"), record.get("opcode"))


@dataclass
class FlowDiff:
    flow: str
    direction: str
    rust_count: int
    emule_count: int
    matched: int
    payload_mismatches: list[dict[str, Any]] = field(default_factory=list)
    only_rust: list[dict[str, Any]] = field(default_factory=list)
    only_emule: list[dict[str, Any]] = field(default_factory=list)


def _describe(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "opcode": record.get("opcode"),
        "opcode_name": record.get("opcode_name"),
        "protocol_marker": record.get("protocol_marker"),
        "payload_len": record.get("payload_len"),
    }


def _diff_group(
    flow: str,
    direction: str,
    rust_recs: list[dict[str, Any]],
    emule_recs: list[dict[str, Any]],
) -> FlowDiff:
    rust_keys = [_wire_key(r) for r in rust_recs]
    emule_keys = [_wire_key(r) for r in emule_recs]
    diff = FlowDiff(
        flow=flow,
        direction=direction,
        rust_count=len(rust_recs),
        emule_count=len(emule_recs),
        matched=0,
    )
    matcher = difflib.SequenceMatcher(a=rust_keys, b=emule_keys, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            diff.matched += i2 - i1
            continue
        # A replace block can mix same-opcode payload mismatches with genuine
        # one-sided packets; pair them up by opcode position.
        rust_block = rust_recs[i1:i2]
        emule_block = emule_recs[j1:j2]
        paired = min(len(rust_block), len(emule_block))
        for offset in range(paired):
            rust_rec = rust_block[offset]
            emule_rec = emule_block[offset]
            if _opcode_key(rust_rec) == _opcode_key(emule_rec):
                diff.payload_mismatches.append(
                    {
                        "opcode": rust_rec.get("opcode"),
                        "opcode_name": rust_rec.get("opcode_name"),
                        "rust_payload_len": rust_rec.get("payload_len"),
                        "emule_payload_len": emule_rec.get("payload_len"),
                    }
                )
            else:
                diff.only_rust.append(_describe(rust_rec))
                diff.only_emule.append(_describe(emule_rec))
        diff.only_rust.extend(_describe(r) for r in rust_block[paired:])
        diff.only_emule.extend(_describe(r) for r in emule_block[paired:])
    return diff


def diff_traces(
    rust_trace: list[dict[str, Any]],
    emule_trace: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compares two ed2k_packet_v1 traces grouped by (canonical channel, direction).

    Flows are collapsed to the shared channel taxonomy (see ``canonical_channel``)
    so peer (client-to-client) traffic aligns across rust and eMuleBB. The
    byte-level diff (``flows``/``totals``/``ok``) stays useful for deterministic
    fixtures, but for two *independent* live clients it will always report
    one-sided packets (different peers, payloads, timing). The ``opcodeCoverage``
    section is the live-meaningful parity signal: which protocol opcodes each
    client exercises per channel/direction, and which are present on only one side.
    """

    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
    for record in rust_trace:
        key = (canonical_channel(record.get("flow")), str(record.get("direction")))
        groups.setdefault(key, {"rust": [], "emule": []})["rust"].append(record)
    for record in emule_trace:
        key = (canonical_channel(record.get("flow")), str(record.get("direction")))
        groups.setdefault(key, {"rust": [], "emule": []})["emule"].append(record)

    flow_diffs = [
        _diff_group(flow, direction, members["rust"], members["emule"])
        for (flow, direction), members in sorted(groups.items())
    ]
    total_mismatches = sum(len(d.payload_mismatches) for d in flow_diffs)
    total_only_rust = sum(len(d.only_rust) for d in flow_diffs)
    total_only_emule = sum(len(d.only_emule) for d in flow_diffs)
    coverage = _opcode_coverage(rust_trace, emule_trace)
    return {
        "schema": PACKET_SCHEMA,
        "ok": total_mismatches == 0 and total_only_rust == 0 and total_only_emule == 0,
        "coverageOk": coverage["ok"],
        "oracleCoverageOk": coverage["oracleOk"],
        "totals": {
            "matched": sum(d.matched for d in flow_diffs),
            "payload_mismatches": total_mismatches,
            "only_rust": total_only_rust,
            "only_emule": total_only_emule,
        },
        "opcodeCoverage": coverage,
        "flows": [
            {
                "flow": d.flow,
                "direction": d.direction,
                "rust_count": d.rust_count,
                "emule_count": d.emule_count,
                "matched": d.matched,
                "payload_mismatches": d.payload_mismatches,
                "only_rust": d.only_rust,
                "only_emule": d.only_emule,
            }
            for d in flow_diffs
        ],
    }


def _opcode_identity(record: dict[str, Any]) -> tuple[int, int]:
    """Wire identity of an opcode for coverage: (protocol_marker, opcode).

    Deliberately NOT opcode_name: the eMuleBB MFC diagnostics dump leaves the name
    empty (raw hex) for many opcodes while rust always names them, so keying on the
    name would report identical wire opcodes as divergent. The name is resolved
    separately for display from whichever side carries it.
    """

    return (int(record.get("protocol_marker") or 0), int(record.get("opcode") or 0))


def _opcode_coverage(
    rust_trace: list[dict[str, Any]],
    emule_trace: list[dict[str, Any]],
) -> dict[str, Any]:
    """Per (channel, direction) opcode-set coverage comparison.

    For two independent live clients the wire bytes never match, but the *set* of
    opcodes each client uses on a given channel should. Reports, per channel and
    direction, the opcodes both clients use (``shared``) and those only one side
    used (``onlyRust`` / ``onlyEmule``) — the latter are the real parity leads.
    Identity is the wire ``(protocol_marker, opcode)`` so per-client naming gaps do
    not create phantom divergences.
    """

    by_key: dict[tuple[str, str], dict[str, dict[tuple[int, int], int]]] = {}
    names: dict[tuple[int, int], str] = {}
    for side, trace in (("rust", rust_trace), ("emule", emule_trace)):
        for record in trace:
            key = (canonical_channel(record.get("flow")), str(record.get("direction")))
            slot = by_key.setdefault(key, {"rust": {}, "emule": {}})[side]
            ident = _opcode_identity(record)
            slot[ident] = slot.get(ident, 0) + 1
            name = record.get("opcode_name")
            if name and ident not in names:
                names[ident] = name

    channels: list[dict[str, Any]] = []
    # `ok` is the STRICT verdict (no one-sided opcode either way); kept for the
    # action-scoped `fullCoverageOk` reference. `oracle_ok` is the rust ⊇ oracle
    # verdict: rust exercising opcodes the oracle didn't (onlyRust) is an allowed
    # superset — and between two independent live clients it is dominated by
    # connection churn (rust's fresh peer handshakes HELLO/SECIDENT/HASHSETREQ vs the
    # oracle's established, payload-only connections). The real parity concern is
    # only opcodes the ORACLE used that rust did NOT (onlyEmule). NOTE: onlyEmule can
    # still be state/window-dependent (e.g. OP_QUEUERANKING only fires when a waiter
    # exists), so treat it as a lead to confirm rather than a hard verdict until
    # synchronized-action windowing scopes coverage to a shared action window.
    all_ok = True
    oracle_ok = True
    for (channel, direction), sides in sorted(by_key.items()):
        rust_ops = sides["rust"]
        emule_ops = sides["emule"]
        only_rust = sorted(set(rust_ops) - set(emule_ops))
        only_emule = sorted(set(emule_ops) - set(rust_ops))
        shared = sorted(set(rust_ops) & set(emule_ops))
        if only_rust or only_emule:
            all_ok = False
        if only_emule:
            oracle_ok = False
        channels.append(
            {
                "channel": channel,
                "direction": direction,
                "shared": [_op_entry(op, names, rust_ops[op], emule_ops[op]) for op in shared],
                "onlyRust": [_op_entry(op, names, rust_ops[op], 0) for op in only_rust],
                "onlyEmule": [_op_entry(op, names, 0, emule_ops[op]) for op in only_emule],
            }
        )
    return {"ok": all_ok, "oracleOk": oracle_ok, "channels": channels}


def _op_entry(
    ident: tuple[int, int],
    names: dict[tuple[int, int], str],
    rust_n: int,
    emule_n: int,
) -> dict[str, Any]:
    protocol_marker, opcode = ident
    return {
        "opcodeName": names.get(ident, f"0x{opcode:02X}"),
        "protocolMarker": protocol_marker,
        "opcode": opcode,
        "rustCount": rust_n,
        "emuleCount": emule_n,
    }


# Authoritative Kad UDP opcode names (MFC srchybrid/Opcodes.h, "KADEMLIA
# (opcodes) (udp)" block). Reports must print hex + name, never a bare decimal;
# this static table names opcodes even when neither client's dump carried a name
# (the MFC diag adapter leaves many legacy opcodes unnamed).
KAD_OPCODE_NAMES: dict[int, str] = {
    0x00: "KADEMLIA_BOOTSTRAP_REQ_DEPRECATED",
    0x01: "KADEMLIA2_BOOTSTRAP_REQ",
    0x08: "KADEMLIA_BOOTSTRAP_RES_DEPRECATED",
    0x09: "KADEMLIA2_BOOTSTRAP_RES",
    0x10: "KADEMLIA_HELLO_REQ_DEPRECATED",
    0x11: "KADEMLIA2_HELLO_REQ",
    0x18: "KADEMLIA_HELLO_RES_DEPRECATED",
    0x19: "KADEMLIA2_HELLO_RES",
    0x20: "KADEMLIA_REQ_DEPRECATED",
    0x21: "KADEMLIA2_REQ",
    0x22: "KADEMLIA2_HELLO_RES_ACK",
    0x28: "KADEMLIA_RES_DEPRECATED",
    0x29: "KADEMLIA2_RES",
    0x30: "KADEMLIA_SEARCH_REQ",
    0x32: "KADEMLIA_SEARCH_NOTES_REQ",
    0x33: "KADEMLIA2_SEARCH_KEY_REQ",
    0x34: "KADEMLIA2_SEARCH_SOURCE_REQ",
    0x35: "KADEMLIA2_SEARCH_NOTES_REQ",
    0x38: "KADEMLIA_SEARCH_RES",
    0x3A: "KADEMLIA_SEARCH_NOTES_RES",
    0x3B: "KADEMLIA2_SEARCH_RES",
    0x40: "KADEMLIA_PUBLISH_REQ",
    0x42: "KADEMLIA_PUBLISH_NOTES_REQ_DEPRECATED",
    0x43: "KADEMLIA2_PUBLISH_KEY_REQ",
    0x44: "KADEMLIA2_PUBLISH_SOURCE_REQ",
    0x45: "KADEMLIA2_PUBLISH_NOTES_REQ",
    0x48: "KADEMLIA_PUBLISH_RES",
    0x4A: "KADEMLIA_PUBLISH_NOTES_RES_DEPRECATED",
    0x4B: "KADEMLIA2_PUBLISH_RES",
    0x4C: "KADEMLIA2_PUBLISH_RES_ACK",
    0x50: "KADEMLIA_FIREWALLED_REQ",
    0x51: "KADEMLIA_FINDBUDDY_REQ",
    0x52: "KADEMLIA_CALLBACK_REQ",
    0x53: "KADEMLIA_FIREWALLED2_REQ",
    0x58: "KADEMLIA_FIREWALLED_RES",
    0x59: "KADEMLIA_FIREWALLED_ACK_RES",
    0x5A: "KADEMLIA_FINDBUDDY_RES",
    0x60: "KADEMLIA2_PING",
    0x61: "KADEMLIA2_PONG",
    0x62: "KADEMLIA2_FIREWALLUDP",
}

# Documented INTENTIONAL divergences: opcodes expected on the MFC side only.
# These annotate (never re-flag) in coverage reports and do not fail oracleOk.
KAD_EXPECTED_ONLY_EMULE_OPCODES: dict[int, str] = {
    0x20: "rust never speaks Kad1: KADEMLIA_REQ_DEPRECATED is legacy Kad1 traffic only MFC handles",
    0x30: "rust never speaks Kad1: KADEMLIA_SEARCH_REQ is legacy Kad1 traffic only MFC handles",
    0x40: "rust never speaks Kad1: KADEMLIA_PUBLISH_REQ is legacy Kad1 traffic only MFC handles",
    0x48: "rust never speaks Kad1: KADEMLIA_PUBLISH_RES is legacy Kad1 traffic only MFC handles",
    0x50: "rust never sends legacy KADEMLIA_FIREWALLED_REQ: firewall-helper selection is "
    "modern KADEMLIA_FIREWALLED2_REQ (0x53) only",
}


def kad_records(trace: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filters Kad packet records from a converged diag_event trace (or raw dump).

    Kad packets have no standalone MFC ``udp_packet_v1`` dump — they live only in
    the converged ``diag_event_v1`` stream (``family:"kad_udp"``) on both clients —
    so the Kad opcode coverage is computed off the diag traces, not packet_trace_diff
    input files.
    """

    return [
        record
        for record in trace
        if record.get("family") in ("kad", "kad_udp") or record.get("schema") == "udp_packet_v1"
    ]


def _kad_opcode(record: dict[str, Any]) -> int | str | None:
    keys = record.get("keys") or {}
    body = record.get("body") or {}
    opcode = keys.get("opcode")
    if opcode is None:
        opcode = body.get("opcode")
    if opcode is None:
        opcode = record.get("opcode")
    if isinstance(opcode, str):
        try:
            return int(opcode, 0)
        except ValueError:
            return opcode
    return opcode


def _kad_direction(record: dict[str, Any]) -> str:
    body = record.get("body") or {}
    return str(record.get("direction") or body.get("direction") or "any")


def kad_opcode_hex(opcode: Any) -> str:
    """Hex spelling for report output — Kad opcodes must never print as decimal."""

    return f"0x{opcode:02X}" if isinstance(opcode, int) else str(opcode)


def kad_opcode_coverage(
    rust_records: list[dict[str, Any]],
    emule_records: list[dict[str, Any]],
    *,
    rust_supplementary_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Direction-combined Kad opcode-set coverage — which KADEMLIA2_* opcodes each
    client *exercises*, the live-meaningful Kad parity signal (the byte-level
    ``kad_udp`` diag diff keys on ``decodedHex`` and never aligns for independent
    clients).

    The verdict is computed on the union of both directions per client, NOT
    per-direction. A per-direction comparison of two INDEPENDENT clients is not a
    protocol-parity signal: a request opcode is ``send`` on the initiator but ``recv``
    on the responder, and each client's inbound (``recv``) traffic — and the responses
    it emits — is network-driven (who chose it as a target), not client-driven. So a
    client that publishes a key emits ``PUBLISH_KEY_REQ`` on ``send`` while its peer
    sees the same opcode on ``recv``; splitting by direction reported that as a false
    gap even though both clients exercise the opcode. Opcode-exercise is also a
    cumulative property (low-frequency opcodes — buddy, firewall, search-source — need
    not recur in every narrow window), so feed this the widest trace available rather
    than a short slice.

    ``ok`` stays the strict verdict (no one-sided opcode either way). ``oracleOk``
    keys on the SEND tier only: an opcode MFC actively *sent* that rust never
    exercised is the real parity signal; an opcode MFC merely *received* is
    network noise (whatever legacy peers happen to throw at it) and is reported
    separately (``onlyEmuleReceivedOnly``), never failing the verdict. Documented
    intentional divergences (:data:`KAD_EXPECTED_ONLY_EMULE_OPCODES`) are
    annotated ``expected`` and excluded from the verdict too.

    ``rust_supplementary_records`` (the rust ``udp_packet_v1`` kad dump) credits
    rust receives the diag stream misses: rust diag stamps ``opcode: None`` for
    unknown/legacy inbound opcodes, so without the dump rust is never credited
    for receiving them. Supplementary records only add opcodes the primary rust
    stream did not already carry (no double counting)."""

    by_dir: dict[str, dict[str, dict[Any, int]]] = {}
    rust_all: dict[Any, int] = {}
    emule_all: dict[Any, int] = {}
    emule_sent: set[Any] = set()
    names: dict[Any, str] = {}
    for side, records in (("rust", rust_records), ("emule", emule_records)):
        combined = rust_all if side == "rust" else emule_all
        for record in records:
            opcode = _kad_opcode(record)
            if opcode is None:
                continue
            direction = _kad_direction(record)
            slot = by_dir.setdefault(direction, {"rust": {}, "emule": {}})[side]
            slot[opcode] = slot.get(opcode, 0) + 1
            combined[opcode] = combined.get(opcode, 0) + 1
            if side == "emule" and direction == "send":
                emule_sent.add(opcode)
            name = record.get("opcode_name") or (record.get("body") or {}).get("opcodeName")
            if name and opcode not in names:
                names[opcode] = name

    supplementary_counts: dict[Any, int] = {}
    for record in rust_supplementary_records or []:
        opcode = _kad_opcode(record)
        if opcode is None:
            continue
        supplementary_counts[opcode] = supplementary_counts.get(opcode, 0) + 1
        name = record.get("opcode_name")
        if name and opcode not in names:
            names[opcode] = name
    supplementary_credited = sorted(
        (op for op in supplementary_counts if op not in rust_all), key=str
    )
    for opcode in supplementary_credited:
        rust_all[opcode] = supplementary_counts[opcode]

    def entry(opcode: Any, rust_n: int, emule_n: int) -> dict[str, Any]:
        static_name = KAD_OPCODE_NAMES.get(opcode) if isinstance(opcode, int) else None
        return {
            "opcode": opcode,
            "opcodeHex": kad_opcode_hex(opcode),
            "opcodeName": static_name or names.get(opcode),
            "rustCount": rust_n,
            "emuleCount": emule_n,
        }

    # Informational per-direction breakdown (NOT used for the verdict).
    directions: list[dict[str, Any]] = []
    for direction, sides in sorted(by_dir.items()):
        rust_ops = sides["rust"]
        emule_ops = sides["emule"]
        directions.append(
            {
                "direction": direction,
                "shared": [
                    entry(op, rust_ops[op], emule_ops[op])
                    for op in sorted(set(rust_ops) & set(emule_ops), key=str)
                ],
                "onlyRust": [
                    entry(op, rust_ops[op], 0)
                    for op in sorted(set(rust_ops) - set(emule_ops), key=str)
                ],
                "onlyEmule": [
                    entry(op, 0, emule_ops[op])
                    for op in sorted(set(emule_ops) - set(rust_ops), key=str)
                ],
            }
        )

    # Direction-combined verdict: an opcode is exercised by a client if seen in either
    # direction. This is the actual parity question.
    only_rust = sorted(set(rust_all) - set(emule_all), key=str)
    only_emule = sorted(set(emule_all) - set(rust_all), key=str)
    shared = sorted(set(rust_all) & set(emule_all), key=str)
    only_emule_entries: list[dict[str, Any]] = []
    for opcode in only_emule:
        row = entry(opcode, 0, emule_all[opcode])
        row["emuleSent"] = opcode in emule_sent
        note = (
            KAD_EXPECTED_ONLY_EMULE_OPCODES.get(opcode) if isinstance(opcode, int) else None
        )
        row["expected"] = note is not None
        if note is not None:
            row["note"] = note
        only_emule_entries.append(row)
    sent_gaps = [row for row in only_emule_entries if row["emuleSent"] and not row["expected"]]
    combined = {
        "shared": [entry(op, rust_all[op], emule_all[op]) for op in shared],
        "onlyRust": [entry(op, rust_all[op], 0) for op in only_rust],
        "onlyEmule": only_emule_entries,
    }
    return {
        "ok": not (only_rust or only_emule),
        "oracleOk": not sent_gaps,
        "combined": combined,
        "onlyEmuleSentGaps": sent_gaps,
        "onlyEmuleReceivedOnly": [row for row in only_emule_entries if not row["emuleSent"]],
        "expectedOnlyEmule": [row for row in only_emule_entries if row["expected"]],
        "supplementaryCreditedOpcodes": [kad_opcode_hex(op) for op in supplementary_credited],
        "directions": directions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diff two ed2k_packet_v1 packet traces.")
    parser.add_argument("--rust", required=True, type=Path, help="emulebb-rust ed2k_packet_v1 JSONL dump.")
    parser.add_argument("--emule", required=True, type=Path, help="eMuleBB ed2k_packet_v1 JSONL dump.")
    args = parser.parse_args(argv)

    report = diff_traces(load_trace(args.rust), load_trace(args.emule))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
