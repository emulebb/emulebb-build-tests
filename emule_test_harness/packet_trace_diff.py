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
    """Compares two ed2k_packet_v1 traces grouped by (flow, direction)."""

    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
    for record in rust_trace:
        key = (record.get("flow") or "unknown", record.get("direction"))
        groups.setdefault(key, {"rust": [], "emule": []})["rust"].append(record)
    for record in emule_trace:
        key = (record.get("flow") or "unknown", record.get("direction"))
        groups.setdefault(key, {"rust": [], "emule": []})["emule"].append(record)

    flow_diffs = [
        _diff_group(flow, direction, members["rust"], members["emule"])
        for (flow, direction), members in sorted(groups.items())
    ]
    total_mismatches = sum(len(d.payload_mismatches) for d in flow_diffs)
    total_only_rust = sum(len(d.only_rust) for d in flow_diffs)
    total_only_emule = sum(len(d.only_emule) for d in flow_diffs)
    return {
        "schema": PACKET_SCHEMA,
        "ok": total_mismatches == 0 and total_only_rust == 0 and total_only_emule == 0,
        "totals": {
            "matched": sum(d.matched for d in flow_diffs),
            "payload_mismatches": total_mismatches,
            "only_rust": total_only_rust,
            "only_emule": total_only_emule,
        },
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
