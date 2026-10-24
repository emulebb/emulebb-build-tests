"""Live converged-soak checkpoint: REST heartbeat + optional cross-client divergence.

One repo-tracked helper for the running rust<->MFC converged soak. It replaces the
ad-hoc scratchpad snippets that previously lived outside the repo (and vanished
with the session scratchpad, blinding the overnight monitor).

* default: a live REST heartbeat for both clients (upload/session/ratio, HighID +
  Kad, the converged bad-peer/source diagnostics counts, the FEAT-001 UDP
  reask-transport counters, monitor heartbeat, disk).
* ``--diff``: a cross-client divergence report built by *reusing* the shared
  ``emule_test_harness.diag_event_diff`` and ``packet_trace_diff`` modules (the
  same source of truth the converged live-wire diff uses) rather than
  re-implementing trace parsing.

Paths default to the persistent converged-soak layout and are all overridable.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import glob
import json
import os
import shutil
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import (  # noqa: E402
    converged_live_wire,
    diag_event_diff,
    packet_trace_diff,
)

RUST_BASE = "http://192.168.1.210:4731"
RUST_KEY = "converged-soak-rust-api-key-0001"
MFC_BASE = "http://192.168.1.210:4732"
MFC_KEY = "converged-soak-mfc-api-key-00001"
OUTPUT_ROOT = Path(os.environ["EMULEBB_WORKSPACE_OUTPUT_ROOT"]) if os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT") else None
# Sentinel "since" that keeps every record — used to load a full (unwindowed) trace
# for the cumulative Kad opcode-coverage signal.
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

DIAG_EVENTS = ("anti_flood_ban", "repeat_block_request", "repeat_file_request", "source_count", "reask_sent")


def _get(base: str, key: str, path: str, *, timeout: float, tries: int) -> dict | None:
    for _ in range(tries):
        try:
            req = urllib.request.Request(base + path, headers={"X-API-Key": key})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            time.sleep(3)
    return None


def _stats(base: str, key: str) -> dict | None:
    payload = _get(base, key, "/api/v1/stats", timeout=15, tries=5)
    return payload.get("data") if payload else None


def heartbeat(args: argparse.Namespace) -> bool:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"===== {ts} =====")
    rust = _stats(args.rust_base, args.rust_key)
    mfc = _stats(args.mfc_base, args.mfc_key)
    if rust is None and mfc is None:
        print("STATUS=DOWN both REST unreachable")
        return False
    print("STATUS=UP")
    rust = rust or {}
    mfc = mfc or {}
    rb = rust.get("sessionUploadedBytes", 0) or 0
    mb = mfc.get("sessionUploadedBytes", 0) or 0
    print(f"RUST up={rust.get('uploadSpeedKiBps')}KiB/s upl={rust.get('activeUploads')} sUp={rb/1e9:.2f}GB "
          f"high={rust.get('ed2kHighId')} kadfw={rust.get('kadFirewalled')} actDl={rust.get('activeDownloads')} reach={'y' if rust else 'n'}")
    print(f"MFC  up={mfc.get('uploadSpeedKiBps')}KiB/s upl={mfc.get('activeUploads')} sUp={mb/1e9:.2f}GB reach={'y' if mfc else 'n'}")
    print(f"ratio={mb/rb:.2f}" if rb else "ratio=n/a")
    if args.monitor_heartbeat:
        try:
            print("monitor:", args.monitor_heartbeat.read_text().strip())
        except Exception as exc:
            print("monitor: unreadable", exc)
    if args.rust_dump:
        records = converged_live_wire.load_current_diag_records(
            args.rust_dump, side="rust", allow_incomplete_active_tail=True
        )
        counts: collections.Counter[str] = collections.Counter()
        for record in records:
            for event in DIAG_EVENTS:
                if record.get("event") == event:
                    counts[event] += 1
        print("diag:", dict(counts))
    udp = glob.glob(str(args.rust_dump / "*client-udp*")) if args.rust_dump else []
    ping = ack = 0
    for path in udp:
        for line in open(path, encoding="utf-8", errors="ignore"):
            if '"OP_REASKFILEPING"' in line:
                ping += 1
            elif '"OP_REASKACK"' in line:
                ack += 1
    print(f"reask-transport: OP_REASKFILEPING={ping} OP_REASKACK={ack} clientUdpDumps={len(udp)}")
    if args.output_root:
        print("disk: output-root %.0fGB" % (shutil.disk_usage(args.output_root).free / 1e9))
    return True


def _one_sided(entry: dict) -> str:
    """Compact only-rust / only-mfc rendering for a diff sub-result."""

    keep = {k: v for k, v in entry.items() if k not in ("family", "strategy", "ok")}
    return json.dumps(keep, default=str)[:400]


def _rec_ts(record: dict) -> datetime.datetime | None:
    raw = record.get("ts") or record.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _windowed_diag_trace(loader, paths: list[Path], since: datetime.datetime) -> list[dict]:
    """Load+concat diag traces from one or more (possibly rotated) logs, keeping
    only records at/after ``since`` so rust's full-session jsonl and MFC's rapidly
    rotated per-slice logs are compared over the *same* wall-clock window."""

    out: list[dict] = []
    for path in paths:
        try:
            for record in loader(path):
                ts = _rec_ts(record)
                if ts is None or ts >= since:
                    out.append(record)
        except Exception:
            continue
    return out


def divergence(args: argparse.Namespace) -> None:
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=args.window_minutes)
    rust_diag_files = converged_live_wire.find_diag_traces(args.rust_dump, side="rust")
    mfc_diag_files = converged_live_wire.find_diag_traces(args.mfc_logs, side="emule")
    print("\n=== cross-client divergence (via diag_event_diff / packet_trace_diff) ===")
    print(f"window={args.window_minutes}min  rust diag files: {len(rust_diag_files)}\nmfc diag files: {len(mfc_diag_files)}")
    report: dict = {}
    if not rust_diag_files or not mfc_diag_files:
        raise RuntimeError("cross-client divergence requires both current diagnostic runs")
    if rust_diag_files and mfc_diag_files:
        rust_records = converged_live_wire.load_current_diag_records(
            args.rust_dump, side="rust", allow_incomplete_active_tail=True
        )
        mfc_records = converged_live_wire.load_current_diag_records(
            args.mfc_logs, side="emule", allow_incomplete_active_tail=True
        )
        rt = [
            record
            for record in rust_records
            if (_rec_ts(record) is None or _rec_ts(record) >= since)
        ]
        mt = [
            record
            for record in mfc_records
            if (_rec_ts(record) is None or _rec_ts(record) >= since)
        ]
        if not rt or not mt:
            raise RuntimeError(
                "cross-client divergence window contains no current diagnostics on one or both sides"
            )
        res = diag_event_diff.diff_traces(rt, mt)
        report["diag_event"] = res
        print(f"\n-- diag_event families (overall ok={res['ok']}, rustRecs={len(rt)} mfcRecs={len(mt)}) --")
        for fam in res["families"]:
            flag = "ok" if fam.get("ok") else "DIVERGENT"
            print(f"  [{flag}] {fam.get('family')} ({fam.get('strategy')}): {_one_sided(fam)}")
        # Kad opcode coverage: direction-combined + CUMULATIVE (see
        # packet_trace_diff.kad_opcode_coverage). Which KADEMLIA2_* opcodes each client
        # exercises is a cumulative capability, not a per-window one, and recv traffic is
        # network-driven — so feed rust its FULL session jsonl (one cheap file, loaded
        # unwindowed) rather than the narrow slice, so low-frequency opcodes
        # (buddy/firewall/search-source) it does exercise are not falsely flagged. MFC's
        # window sample is the parity reference.
        rust_kad_all = packet_trace_diff.kad_records(
            rust_records
        )
        kad_cov = packet_trace_diff.kad_opcode_coverage(
            rust_kad_all, packet_trace_diff.kad_records(mt)
        )
        report["kad_opcode_coverage"] = kad_cov
        kad_gaps = sorted(
            f"{e['opcodeHex']} {e['opcodeName'] or '?'}" for e in kad_cov["onlyEmuleSentGaps"]
        )
        kad_recv_noise = len(kad_cov["onlyEmuleReceivedOnly"])
        kad_expected = sorted(
            f"{e['opcodeHex']} {e['opcodeName'] or '?'}" for e in kad_cov["expectedOnlyEmule"]
        )
        print(
            f"  [kad opcode coverage] oracleOk={kad_cov['oracleOk']} sentGaps={kad_gaps} "
            f"recvOnlyNoise={kad_recv_noise} expectedDivergences={kad_expected}"
        )
        # Download-parallelism parity (rotation-robust): the latest source_count body from
        # each side's already-windowed trace. The shared loader selects one complete
        # segmented run, so this is not subject to single-file rotation misses.
        # validSourceCount >> transferringSourceCount is the stall signature (many engaged
        # sources, few actually moving bytes).
        def _latest_source_count(trace: list[dict]) -> dict | None:
            for record in reversed(trace):
                if record.get("event") == "source_count":
                    return record.get("body") or {}
            return None

        rust_sc = _latest_source_count(rt)
        mfc_sc = _latest_source_count(mt)
        report["source_count"] = {"rust": rust_sc, "mfc": mfc_sc}
        print("\n-- source_count (download parallelism, latest in window) --")
        for label, sc in (("rust", rust_sc), ("mfc", mfc_sc)):
            if sc is None:
                print(f"  {label}: (none in window)")
            else:
                print(
                    f"  {label}: sourceCount={sc.get('sourceCount')} "
                    f"valid={sc.get('validSourceCount')} "
                    f"transferring={sc.get('transferringSourceCount')} "
                    f"a4afFiles={sc.get('a4afFileCount')}"
                )
        # Defensive-measure runtime usefulness: per bad_peer event type, how many times
        # each side fired it this window. A measure with rust=0 is either not yet ported
        # or catches no abuse in this window; high counts = high live usefulness. This is
        # how we judge whether each ported defence is worth its complexity at runtime.
        rust_bp = collections.Counter(r.get("event") for r in rt if r.get("family") == "bad_peer")
        mfc_bp = collections.Counter(m.get("event") for m in mt if m.get("family") == "bad_peer")
        report["bad_peer_tally"] = {"rust": dict(rust_bp), "mfc": dict(mfc_bp)}
        events = sorted(set(rust_bp) | set(mfc_bp), key=lambda e: -(rust_bp[e] + mfc_bp[e]))
        print("\n-- bad_peer defensive-measure usefulness (firings this window) --")
        for ev in events:
            note = "" if rust_bp[ev] else "   <- rust: not fired/ported"
            print(f"  {ev}: rust={rust_bp[ev]} mfc={mfc_bp[ev]}{note}")
        if args.schema_audit or args.oracle_conformance:
            audit = diag_event_diff.schema_audit(rt, mt)
            report["schema_audit"] = audit
            if args.oracle_conformance:
                conf = audit["conformance"]
                print(f"\n-- oracle conformance (rust superset-of MFC oracle): {'PASS' if conf['conformant'] else 'FAIL'} --")
                for v in conf["bodyKeyViolations"]:
                    print(f"  [VIOLATION] {v['family']}/{v['event']} missing oracle keys: {v['missingOracleKeys']}")
                if conf["oracleOnlyUnverified"]:
                    print(f"  unverified (oracle event, rust silent in-window): {conf['oracleOnlyUnverified']}")
                if conf["rustExtraEvents"]:
                    print(f"  rust-only extras (allowed): {conf['rustExtraEvents']}")
            if args.schema_audit:
                print(f"\n-- body-field schema audit (MFC=oracle, overall ok={audit['ok']}) --")
                clean = 0
                for e in audit["events"]:
                    if e["presence"] == "both" and e["bodyOk"]:
                        clean += 1
                        continue
                    tag = "BODY-DRIFT" if e["presence"] == "both" else e["presence"].upper()
                    print(f"  [{tag}] {e['family']}/{e['event']} r={e['rustCount']} m={e['mfcCount']}"
                          + (f" onlyRust={e['onlyRustKeys']}" if e["onlyRustKeys"] else "")
                          + (f" onlyMfc={e['onlyMfcKeys']}" if e["onlyMfcKeys"] else ""))
                print(f"  ({clean} shared events with identical body schema)")
    # C2 + rotation: rust splits eD2K packets across the tcp (peer) and server
    # dumps, and MFC rotates its packet.log by size. Concat BOTH rust eD2K dumps so
    # server-flow parity is not silently dropped, and the MFC packet.log files
    # touched within the window so MFC is not just its active slice.
    if args.rust_packet:
        rust_pkt_files = [Path(args.rust_packet)]
    else:
        rust_pkt_files = sorted(Path(args.rust_dump).glob("emulebb-rust-ed2k-*-dump-*.jsonl"))
    if args.mfc_packet:
        mfc_pkt_files = [Path(args.mfc_packet)]
    else:
        mfc_pkt_files = [
            Path(p)
            for p in glob.glob(str(args.mfc_logs / "emulebb-diagnostics-packet*.log"))
            if datetime.datetime.fromtimestamp(Path(p).stat().st_mtime, datetime.timezone.utc) >= since
        ]
    if rust_pkt_files and mfc_pkt_files:
        rp = _windowed_diag_trace(packet_trace_diff.load_trace, rust_pkt_files, since)
        mp = _windowed_diag_trace(packet_trace_diff.load_trace, mfc_pkt_files, since)
        res = packet_trace_diff.diff_traces(rp, mp)
        report["packet"] = res
        cov = res.get("opcodeCoverage", {})
        print(
            f"\n-- packet opcodeCoverage (coverageOk={res.get('coverageOk')} "
            f"oracleCoverageOk={res.get('oracleCoverageOk')}, rust={len(rp)} mfc={len(mp)}) --"
        )
        print(f"  {json.dumps(cov, default=str)[:900]}")
    else:
        raise RuntimeError("cross-client divergence requires both current packet traces")
    if args.diff_json:
        Path(args.diff_json).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"\nfull divergence JSON -> {args.diff_json}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-base", default=RUST_BASE)
    parser.add_argument("--rust-key", default=RUST_KEY)
    parser.add_argument("--mfc-base", default=MFC_BASE)
    parser.add_argument("--mfc-key", default=MFC_KEY)
    default_rust_dump = OUTPUT_ROOT / "soak" / "rust-profile" / "packet-dump" if OUTPUT_ROOT else None
    default_monitor = OUTPUT_ROOT / "soak" / "parity-monitor" / "upload-parity-monitor.heartbeat.txt" if OUTPUT_ROOT else None
    parser.add_argument("--rust-dump", type=Path, default=default_rust_dump, help="Rust packet-dump directory.")
    parser.add_argument("--mfc-logs", type=Path, help="Active MFC profile logs directory (required for --diff).")
    parser.add_argument("--monitor-heartbeat", type=Path, default=default_monitor)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT, help="Output root used only for free-space reporting.")
    parser.add_argument("--diff", action="store_true", help="Also run the cross-client divergence report.")
    parser.add_argument("--window-minutes", type=float, default=15.0, help="Wall-clock window for the divergence diff (both traces are filtered to it).")
    parser.add_argument("--schema-audit", action="store_true", help="Per shared event, report body-field key deltas vs the MFC oracle schema.")
    parser.add_argument("--oracle-conformance", action="store_true", help="Verdict only: does rust cover every oracle event + body key (rust superset-of oracle)? rust extras allowed.")
    parser.add_argument("--rust-packet", help="Override rust ed2k_packet_v1 jsonl.")
    parser.add_argument("--mfc-packet", help="Override MFC ed2k_packet_v1 log.")
    parser.add_argument("--diff-json", help="Write the full divergence result JSON here.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.diff and args.rust_dump is None:
        parser.error("--diff requires --rust-dump when EMULEBB_WORKSPACE_OUTPUT_ROOT is unset")
    if args.diff and args.mfc_logs is None:
        parser.error("--diff requires --mfc-logs")
    up = heartbeat(args)
    if args.diff and up:
        divergence(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
