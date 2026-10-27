"""Summarize protocol coverage from a live-wire / converged diagnostic run.

Operationalizes the rust-vs-MFC parity analysis: selects each client's current
``diag_event_v2`` run and prints, per canonical channel (server / client / kad)
and direction, the opcode SET each client exercised — the right parity signal
for two independent live clients (their wire bytes never match, but the opcode
sets should). Also flags the upload-serving opcodes and the Rust Kad opcode
histogram so a soak's uploads and Kad participation are visible at a glance.

Usage:
  uv run python scripts/analyze-packet-coverage.py --run <run_dir>
  uv run python scripts/analyze-packet-coverage.py \
    --rust-diagnostics-dir <dir> --mfc-diagnostics-dir <dir>

No machine paths are baked in; pass the run/diagnostic locations explicitly.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import diag_event_diff, diag_event_runs
from emule_test_harness import packet_trace_diff as ptd
from emule_test_harness.diag_event_schema import (
    ED2K_SERVER_UDP_FAMILY,
    PERSISTED_SOAK_REQUIRED_PARITY_FAMILIES,
)

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

FILE_HASH_OPCODES = frozenset(
    {
        "OP_AICHANSWER",
        "OP_AICHFILEHASHANS",
        "OP_AICHFILEHASHREQ",
        "OP_AICHREQUEST",
        "OP_ANSWERSOURCES",
        "OP_ANSWERSOURCES2",
        "OP_COMPRESSEDPART",
        "OP_COMPRESSEDPART_I64",
        "OP_END_OF_DOWNLOAD",
        "OP_FILEREQANSNOFIL",
        "OP_FILESTATUS",
        "OP_HASHSETANSWER",
        "OP_HASHSETANSWER2",
        "OP_HASHSETREQUEST",
        "OP_HASHSETREQUEST2",
        "OP_MULTIPACKET",
        "OP_MULTIPACKET_EXT",
        "OP_MULTIPACKET_EXT2",
        "OP_MULTIPACKETANSWER",
        "OP_MULTIPACKETANSWER_EXT2",
        "OP_REQFILENAMEANSWER",
        "OP_REQUESTFILENAME",
        "OP_REQUESTPARTS",
        "OP_REQUESTSOURCES",
        "OP_REQUESTSOURCES2",
        "OP_SENDINGPART",
        "OP_SENDINGPART_I64",
        "OP_SETREQFILEID",
        "OP_STARTUPLOADREQ",
    }
)


def _discover_diag_dir(run_dir: Path, *, client: str) -> Path | None:
    candidates = sorted(run_dir.rglob(f"emulebb-{client}-diag-*.jsonl"))
    return candidates[0].parent if candidates else None


def _load_diagnostics(diagnostics_dir: Path, *, client: str) -> list[dict[str, Any]]:
    return diag_event_runs.load_latest_diag_records(
        diagnostics_dir.glob(f"emulebb-{client}-diag-*.jsonl"),
        client=client,
        allow_incomplete_active_tail=True,
    )


def _fmt(entries: list[dict[str, Any]]) -> list[str]:
    return [f"{e['opcodeName']}(r{e['rustCount']}/m{e['emuleCount']})" for e in entries]


def _kad_op_name(record: dict[str, Any]) -> str:
    body = record.get("body") or {}
    keys = record.get("keys") or {}
    name = record.get("opcode_name") or body.get("opcodeName")
    if name:
        return str(name)
    opcode = record.get("opcode", body.get("opcode", keys.get("opcode")))
    return str(opcode) if opcode is not None else "?"


def _kad_direction(record: dict[str, Any]) -> str:
    body = record.get("body") or {}
    return str(record.get("direction") or body.get("direction") or "any")


def _kad_histogram(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    histogram = collections.Counter(
        (_kad_direction(record), _kad_op_name(record)) for record in records
    )
    return [
        {"direction": direction, "opcodeName": name, "count": count}
        for (direction, name), count in sorted(
            histogram.items(), key=lambda item: (-item[1], item[0])
        )
    ]


def _server_udp_views(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    views = []
    for record in records:
        if record.get("family") != ED2K_SERVER_UDP_FAMILY or record.get("event") != "packet":
            continue
        body = record.get("body")
        if not isinstance(body, dict) or body.get("direction") not in {"send", "recv"}:
            continue
        protocol_marker = body.get("protocolMarker")
        opcode = body.get("opcode")
        if not isinstance(protocol_marker, int) or not isinstance(opcode, int):
            continue
        views.append(
            {
                "flow": "server",
                "direction": body["direction"],
                "protocol_marker": protocol_marker,
                "opcode": opcode,
                "opcode_name": body.get("opcodeName") or "UNKNOWN",
            }
        )
    return views


def _join_key_side_coverage(records: list[dict[str, Any]]) -> dict[str, Any]:
    peer_hash_packets = sum(record.get("peer_hash") is not None for record in records)
    file_packets = [
        record for record in records if record.get("opcode_name") in FILE_HASH_OPCODES
    ]
    missing_file_hash = collections.Counter(
        record.get("opcode_name") or "UNKNOWN"
        for record in file_packets
        if record.get("file_hash") is None
    )
    return {
        "ok": bool(records) and peer_hash_packets > 0 and not missing_file_hash,
        "packetCount": len(records),
        "peerHashPackets": peer_hash_packets,
        "filePacketCount": len(file_packets),
        "fileHashPackets": sum(
            record.get("file_hash") is not None for record in file_packets
        ),
        "missingFileHashByOpcode": [
            {"opcodeName": opcode_name, "count": count}
            for opcode_name, count in sorted(missing_file_hash.items())
        ],
    }


def _join_key_coverage(
    rust_records: list[dict[str, Any]], mfc_records: list[dict[str, Any]]
) -> dict[str, Any]:
    rust = _join_key_side_coverage(rust_records)
    mfc = _join_key_side_coverage(mfc_records)
    return {"ok": rust["ok"] and mfc["ok"], "rust": rust, "mfc": mfc}


def build_summary(
    rust_ed2k: list[dict[str, Any]],
    mfc_ed2k: list[dict[str, Any]],
    rust_diagnostics: list[dict[str, Any]],
    mfc_diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    """Builds bilateral eD2K/Kad coverage and persisted-soak conformance."""

    serving = collections.Counter()
    for record in rust_ed2k:
        name = record.get("opcode_name")
        if name in UPLOAD_SERVING_OPCODES:
            serving[(record.get("flow"), record.get("direction"), name)] += 1

    rust_kad = [
        record
        for record in ptd.kad_records(rust_diagnostics)
        if record.get("event") == "packet"
    ]
    mfc_kad = [
        record
        for record in ptd.kad_records(mfc_diagnostics)
        if record.get("event") == "packet"
    ]
    rust_server_udp = _server_udp_views(rust_diagnostics)
    mfc_server_udp = _server_udp_views(mfc_diagnostics)
    return {
        "schema": "packet_coverage_summary_v2",
        "records": {
            "rustDiagnosticEvents": len(rust_diagnostics),
            "mfcDiagnosticEvents": len(mfc_diagnostics),
            "rustEd2k": len(rust_ed2k),
            "mfcEd2k": len(mfc_ed2k),
            "rustKadUdp": len(rust_kad),
            "mfcKadUdp": len(mfc_kad),
            "rustServerUdp": len(rust_server_udp),
            "mfcServerUdp": len(mfc_server_udp),
        },
        "persistedSoakConformance": diag_event_diff.full_run_conformance(
            rust_diagnostics,
            mfc_diagnostics,
            required_families=PERSISTED_SOAK_REQUIRED_PARITY_FAMILIES,
        ),
        "schemaAudit": diag_event_diff.schema_audit(
            rust_diagnostics,
            mfc_diagnostics,
        ),
        "ed2kOpcodeCoverage": ptd._opcode_coverage(rust_ed2k, mfc_ed2k),
        "ed2kJoinKeyCoverage": _join_key_coverage(rust_ed2k, mfc_ed2k),
        "kadOpcodeCoverage": ptd.kad_opcode_coverage(rust_kad, mfc_kad),
        "serverUdpOpcodeCoverage": ptd._opcode_coverage(
            rust_server_udp,
            mfc_server_udp,
        ),
        "rustUploadServing": [
            {"flow": flow, "direction": direction, "opcodeName": name, "count": count}
            for (flow, direction, name), count in sorted(serving.items())
        ],
        "kadUdpHistogram": {
            "rust": _kad_histogram(rust_kad),
            "mfc": _kad_histogram(mfc_kad),
        },
        "serverUdpHistogram": {
            "rust": _kad_histogram(rust_server_udp),
            "mfc": _kad_histogram(mfc_server_udp),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=Path, help="A live-wire/converged run dir (auto-discovers diagnostics).")
    parser.add_argument("--rust-diagnostics-dir", type=Path, help="Directory holding Rust diag_event_v2 segments.")
    parser.add_argument("--mfc-diagnostics-dir", type=Path, help="Directory holding MFC diag_event_v2 segments.")
    parser.add_argument("--json-output", type=Path, help="Optional machine-readable summary output path.")
    args = parser.parse_args(argv)

    rust_diagnostics_dir = args.rust_diagnostics_dir
    mfc_diagnostics_dir = args.mfc_diagnostics_dir
    if args.run:
        rust_diagnostics_dir = rust_diagnostics_dir or _discover_diag_dir(args.run, client="rust")
        mfc_diagnostics_dir = mfc_diagnostics_dir or _discover_diag_dir(args.run, client="mfc")
    if rust_diagnostics_dir is None or mfc_diagnostics_dir is None:
        parser.error(
            "provide --run containing both clients or both "
            "--rust-diagnostics-dir and --mfc-diagnostics-dir"
        )

    rust_diagnostics = _load_diagnostics(rust_diagnostics_dir, client="rust")
    mfc_diagnostics = _load_diagnostics(mfc_diagnostics_dir, client="mfc")
    rust = diag_event_diff.ed2k_tcp_packet_views(rust_diagnostics)
    mfc = diag_event_diff.ed2k_tcp_packet_views(mfc_diagnostics)
    summary = build_summary(rust, mfc, rust_diagnostics, mfc_diagnostics)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    records = summary["records"]
    print(
        "rust ed2k records: "
        f"{records['rustEd2k']} | mfc ed2k records: {records['mfcEd2k']} | "
        f"rust kad-udp records: {records['rustKadUdp']} | "
        f"mfc kad-udp records: {records['mfcKadUdp']} | "
        f"rust server-udp records: {records['rustServerUdp']} | "
        f"mfc server-udp records: {records['mfcServerUdp']}"
    )

    cov = summary["ed2kOpcodeCoverage"]
    print(f"\n=== eD2k opcode coverage per channel (coverageOk={cov['ok']}) ===")
    for ch in cov["channels"]:
        print(f"\n  [{ch['channel']}/{ch['direction']}]")
        print("    shared   :", _fmt(ch["shared"]))
        print("    onlyRust :", _fmt(ch["onlyRust"]))
        print("    onlyEmule:", _fmt(ch["onlyEmule"]))

    join_coverage = summary["ed2kJoinKeyCoverage"]
    print(f"\n=== eD2k join-key coverage: {join_coverage['ok']} ===")
    for side in ("rust", "mfc"):
        row = join_coverage[side]
        print(
            f"  {side}: peerHash={row['peerHashPackets']}/{row['packetCount']} "
            f"fileHash={row['fileHashPackets']}/{row['filePacketCount']} "
            f"missing={row['missingFileHashByOpcode']}"
        )

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
    kad_coverage = summary["kadOpcodeCoverage"]
    print(
        "\n=== Kad UDP opcode coverage "
        f"(strictOk={kad_coverage['ok']}, oracleOk={kad_coverage['oracleOk']}) ==="
    )
    for side in ("rust", "mfc"):
        print(f"\n  [{side}]")
        for row in summary["kadUdpHistogram"][side]:
            print(f"    {row['count']:5d}  {row['direction']:4}  {row['opcodeName']}")

    server_udp_coverage = summary["serverUdpOpcodeCoverage"]
    print(
        "\n=== server UDP opcode coverage "
        f"(coverageOk={server_udp_coverage['ok']}, "
        f"oracleOk={server_udp_coverage['oracleOk']}) ==="
    )
    for side in ("rust", "mfc"):
        print(f"\n  [{side}]")
        for row in summary["serverUdpHistogram"][side]:
            print(f"    {row['count']:5d}  {row['direction']:4}  {row['opcodeName']}")

    conformance = summary["persistedSoakConformance"]
    print(f"\n=== persisted soak evidence complete: {conformance['ok']} ===")
    for row in conformance["familyConformance"]["requiredFamilies"]:
        print(
            f"  {row['family']}: rust={row['rustPresent']} "
            f"mfc={row['mfcPresent']} ok={row['ok']}"
        )
    print("\n=== ED2K server connection lifecycle ===")
    for side in ("rust", "mfc"):
        lifecycle = conformance["serverConnectionLifecycle"][side]
        print(
            f"  {side}: ok={lifecycle['ok']} attempts={lifecycle['attemptCount']} "
            f"events={lifecycle['eventCount']} outcomes={lifecycle['outcomes']} "
            f"violations={lifecycle['violations']}"
        )

    return 0 if conformance["ok"] and join_coverage["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
