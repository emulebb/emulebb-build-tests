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
    all_ok = True
    for (channel, direction), sides in sorted(by_key.items()):
        rust_ops = sides["rust"]
        emule_ops = sides["emule"]
        only_rust = sorted(set(rust_ops) - set(emule_ops))
        only_emule = sorted(set(emule_ops) - set(rust_ops))
        shared = sorted(set(rust_ops) & set(emule_ops))
        # rust ⊇ oracle: rust exercising opcodes the oracle didn't (onlyRust) is an
        # allowed superset, and between two independent live clients it is dominated
        # by connection churn — rust's fresh peer handshakes (HELLO/SECIDENT/
        # HASHSETREQ) vs the oracle's established, payload-only connections. The
        # parity concern is only opcodes the ORACLE used that rust did NOT
        # (onlyEmule). NOTE: onlyEmule can still be state/window-dependent (e.g.
        # OP_QUEUERANKING only fires when a waiter exists), so treat it as a lead to
        # confirm rather than a hard verdict until synchronized-action windowing
        # scopes coverage to a shared action window.
        if only_emule:
            all_ok = False
        channels.append(
            {
                "channel": channel,
                "direction": direction,
                "shared": [_op_entry(op, names, rust_ops[op], emule_ops[op]) for op in shared],
                "onlyRust": [_op_entry(op, names, rust_ops[op], 0) for op in only_rust],
                "onlyEmule": [_op_entry(op, names, 0, emule_ops[op]) for op in only_emule],
            }
        )
    return {"ok": all_ok, "channels": channels}


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
