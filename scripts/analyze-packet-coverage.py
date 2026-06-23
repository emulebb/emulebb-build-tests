"""Summarize protocol coverage from a live-wire / converged run's packet dumps.

Operationalizes the rust-vs-MFC parity analysis: loads the converged
``ed2k_packet_v1`` traces (and the Kad ``udp_packet_v1`` dump) from a run and
prints, per canonical channel (server / client / kad) and direction, the opcode
SET each client exercised — the right parity signal for two independent live
clients (their wire bytes never match, but the opcode sets should). Also flags
the upload-serving opcodes and the Kad opcode histogram so a soak's uploads and
Kad participation are visible at a glance.

Usage:
  uv run python scripts/analyze-packet-coverage.py --run <run_dir>
  uv run python scripts/analyze-packet-coverage.py --rust-dump-dir <dir> [--mfc-log <packet.log>]

No machine paths are baked in; pass the run/dump locations explicitly.
"""

from __future__ import annotations

import argparse
import collections
import glob
import sys
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import packet_trace_diff as ptd

# eD2k opcodes that only appear when WE serve an upload (a peer downloads from
# us). Their presence on the client/listener channel proves the upload path ran.
UPLOAD_SERVING_OPCODES = (
    "OP_STARTUPLOADREQ",
    "OP_ACCEPTUPLOADREQ",
    "OP_QUEUERANKING",
    "OP_SENDINGPART",
    "OP_SENDINGPART_I64",
    "OP_COMPRESSEDPART",
    "OP_COMPRESSEDPART_I64",
    "OP_REQUESTPARTS",
    "OP_REQUESTPARTS_I64",
)


def _load_rust_ed2k(dump_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(glob.glob(str(dump_dir / "*ed2k-*dump-*.jsonl"))):
        records += ptd.load_trace(Path(path))
    return records


def _load_kad(dump_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(glob.glob(str(dump_dir / "*kad-udp-dump-*.jsonl"))):
        for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                import json

                record = json.loads(line)
            except ValueError:
                continue
            if record.get("schema") == "udp_packet_v1":
                records.append(record)
    return records


def _fmt(entries: list[dict[str, Any]]) -> list[str]:
    return [f"{e['opcodeName']}(r{e['rustCount']}/m{e['emuleCount']})" for e in entries]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=Path, help="A live-wire/converged run dir (auto-discovers dumps).")
    parser.add_argument("--rust-dump-dir", type=Path, help="Directory holding emulebb-rust-*dump-*.jsonl.")
    parser.add_argument("--mfc-log", type=Path, help="eMuleBB MFC ed2k_packet_v1 packet log (optional).")
    args = parser.parse_args(argv)

    rust_dump_dir = args.rust_dump_dir
    mfc_log = args.mfc_log
    if args.run:
        candidates = sorted(glob.glob(str(args.run / "**" / "*ed2k-tcp-dump-*.jsonl"), recursive=True))
        if candidates:
            rust_dump_dir = Path(candidates[0]).parent
        mfc_candidates = sorted(glob.glob(str(args.run / "**" / "emulebb-diagnostics-packet.log"), recursive=True))
        if mfc_candidates and mfc_log is None:
            mfc_log = Path(mfc_candidates[0])
    if rust_dump_dir is None:
        parser.error("provide --run or --rust-dump-dir")

    rust = _load_rust_ed2k(rust_dump_dir)
    mfc = ptd.load_trace(mfc_log) if mfc_log and mfc_log.is_file() else []
    kad = _load_kad(rust_dump_dir)

    print(f"rust ed2k records: {len(rust)} | mfc ed2k records: {len(mfc)} | rust kad-udp records: {len(kad)}")

    cov = ptd._opcode_coverage(rust, mfc)
    print(f"\n=== eD2k opcode coverage per channel (coverageOk={cov['ok']}) ===")
    for ch in cov["channels"]:
        print(f"\n  [{ch['channel']}/{ch['direction']}]")
        print("    shared   :", _fmt(ch["shared"]))
        print("    onlyRust :", _fmt(ch["onlyRust"]))
        print("    onlyEmule:", _fmt(ch["onlyEmule"]))

    # Upload-serving evidence (rust side): does the client/listener channel show
    # us serving an upload? Counts by raw flow so listener vs native_upload shows.
    print("\n=== rust upload-serving opcodes (proves the upload path ran) ===")
    serving = collections.Counter()
    for r in rust:
        name = r.get("opcode_name")
        if name in UPLOAD_SERVING_OPCODES:
            serving[(r.get("flow"), r.get("direction"), name)] += 1
    if serving:
        for key, n in sorted(serving.items()):
            print(f"  {n:5d}  {key}")
    else:
        print("  (none observed - no peer downloaded from us in this run)")

    # Kad opcode histogram (participation at a glance).
    print("\n=== Kad UDP opcode histogram ===")
    def _kad_op_name(record: dict[str, Any]) -> str:
        name = record.get("opcode_name")
        if name:
            return str(name)
        # The Kad udp_packet_v1 dump stores opcode as a hex string ("0x89") or int.
        opcode = record.get("opcode")
        return str(opcode) if opcode is not None else "?"

    kad_hist = collections.Counter((r.get("direction"), _kad_op_name(r)) for r in kad)
    for (direction, name), n in sorted(kad_hist.items(), key=lambda kv: -kv[1]):
        print(f"  {n:5d}  {direction:4}  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
