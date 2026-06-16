"""Semantic diff of two ``diag_event_v1`` diagnostic traces (rust vs MFC).

Skeleton stub for the converged diagnostic schema v2 contract. Both clients emit
the single ``diag_event_v1`` envelope (see
``docs/diagnostics/diag-event-v1-schema.md``); this module aligns the two traces
per ``(family, event)`` and compares only the fields marked **comparable** in
the schema, ignoring client-specific fields, timestamps, and sequence counters.

It generalises ``packet_trace_diff.py``: the packet families (``ed2k_tcp``,
``kad_udp``) reuse the same wire-identity algorithm, while ``kad_event`` /
``bad_peer`` use set/sequence equality and ``sched`` uses a structural
transition match. The per-family comparators are intentionally left unimplemented
here — D4 fills them; this lane only fixes the envelope contract and CLI shape.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DIAG_SCHEMA = "diag_event_v1"

# Families and their comparison strategy (see docs/diagnostics schema, §3/§4).
PACKET_FAMILIES = ("ed2k_tcp", "kad_udp")
EVENT_FAMILIES = ("kad_event", "bad_peer")
SCHED_FAMILY = "sched"

# Envelope fields never compared (normalised / client-specific).
_IGNORED_ENVELOPE_FIELDS = ("ts", "seq", "client")


def load_trace(path: Path) -> list[dict[str, Any]]:
    """Loads ``diag_event_v1`` records from a JSONL dump (\\n or \\r\\n)."""

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


def diff_traces(
    rust_trace: list[dict[str, Any]],
    mfc_trace: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compares two ``diag_event_v1`` traces grouped by ``(family, event)``.

    TODO(D4): implement the per-family comparators described in the schema doc
    (§4): wire-identity for packet families, set/sequence for event families,
    structural transition match for ``sched``. The stub returns the grouped
    shape so the CLI and callers can be wired ahead of the comparators.
    """

    raise NotImplementedError(
        "diag_event_v1 comparators are defined in "
        "docs/diagnostics/diag-event-v1-schema.md and land in D4."
    )


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
