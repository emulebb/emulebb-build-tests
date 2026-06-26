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
import json
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
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("schema") == "udp_packet_v1":
                records.append(record)
    return records


def _fmt(entries: list[dict[str, Any]]) -> list[str]:
    return [f"{e['opcodeName']}(r{e['rustCount']}/m{e['emuleCount']})" for e in entries]


def _kad_op_name(record: dict[str, Any]) -> str:
    name = record.get("opcode_name")
    if name:
        return str(name)
    # The Kad udp_packet_v1 dump stores opcode as a hex string ("0x89") or int.
    opcode = record.get("opcode")
    return str(opcode) if opcode is not None else "?"


def build_summary(
    rust: list[dict[str, Any]], mfc: list[dict[str, Any]], kad: list[dict[str, Any]]
) -> dict[str, Any]:
    """Builds a machine-readable packet-coverage summary."""

    serving = collections.Counter()
    for record in rust:
        name = record.get("opcode_name")
        if name in UPLOAD_SERVING_OPCODES:
            serving[(record.get("flow"), record.get("direction"), name)] += 1

    kad_hist = collections.Counter((record.get("direction"), _kad_op_name(record)) for record in kad)
    return {
        "schema": "packet_coverage_summary_v1",
        "records": {
            "rustEd2k": len(rust),
            "mfcEd2k": len(mfc),
            "rustKadUdp": len(kad),
        },
        "ed2kOpcodeCoverage": ptd._opcode_coverage(rust, mfc),
        "rustUploadServing": [
            {"flow": flow, "direction": direction, "opcodeName": name, "count": count}
            for (flow, direction, name), count in sorted(serving.items())
        ],
        "kadUdpHistogram": [
            {"direction": direction, "opcodeName": name, "count": count}
            for (direction, name), count in sorted(kad_hist.items(), key=lambda item: (-item[1], item[0]))
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=Path, help="A live-wire/converged run dir (auto-discovers dumps).")
    parser.add_argument("--rust-dump-dir", type=Path, help="Directory holding emulebb-rust-*dump-*.jsonl.")
    parser.add_argument("--mfc-log", type=Path, help="eMuleBB MFC ed2k_packet_v1 packet log (optional).")
    parser.add_argument("--json-output", type=Path, help="Optional machine-readable summary output path.")
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
    summary = build_summary(rust, mfc, kad)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    records = summary["records"]
    print(
        "rust ed2k records: "
        f"{records['rustEd2k']} | mfc ed2k records: {records['mfcEd2k']} | "
        f"rust kad-udp records: {records['rustKadUdp']}"
    )

    cov = summary["ed2kOpcodeCoverage"]
    print(f"\n=== eD2k opcode coverage per channel (coverageOk={cov['ok']}) ===")
    for ch in cov["channels"]:
        print(f"\n  [{ch['channel']}/{ch['direction']}]")
        print("    shared   :", _fmt(ch["shared"]))
        print("    onlyRust :", _fmt(ch["onlyRust"]))
        print("    onlyEmule:", _fmt(ch["onlyEmule"]))

    # Upload-serving evidence (rust side): does the client/listener channel show
    # us serving an upload? Counts by raw flow so listener vs native_upload shows.
    print("\n=== rust upload-serving opcodes (proves the upload path ran) ===")
    if summary["rustUploadServing"]:
        for row in summary["rustUploadServing"]:
            key = (row["flow"], row["direction"], row["opcodeName"])
            print(f"  {row['count']:5d}  {key}")
    else:
        print("  (none observed - no peer downloaded from us in this run)")

    # Kad opcode histogram (participation at a glance).
    print("\n=== Kad UDP opcode histogram ===")
    for row in summary["kadUdpHistogram"]:
        print(f"  {row['count']:5d}  {row['direction']:4}  {row['opcodeName']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
