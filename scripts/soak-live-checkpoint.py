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
import shutil
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import diag_event_diff, mfc_diag_adapter, packet_trace_diff  # noqa: E402

RUST_BASE = "http://192.168.1.210:4731"
RUST_KEY = "converged-soak"
MFC_BASE = "http://192.168.1.210:4732"
MFC_KEY = "converged-soak-mfc"
RUNTIME_DUMP = Path(r"C:\var\build\emulebb_out\soak\rust-runtime\packet-dump")
MFC_LOGS = Path(r"F:\M\H06T01\dldz\EMULE_BIN\logs")
# Sentinel "since" that keeps every record — used to load a full (unwindowed) trace
# for the cumulative Kad opcode-coverage signal.
_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
MONITOR_HB = Path(r"C:\var\build\emulebb_out\soak\parity-monitor\upload-parity-monitor.heartbeat.txt")

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


def _newest(dump_dir: Path, pattern: str) -> Path | None:
    files = glob.glob(str(dump_dir / pattern))
    return Path(max(files, key=lambda p: Path(p).stat().st_mtime)) if files else None


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
    try:
        print("monitor:", MONITOR_HB.read_text().strip())
    except Exception as exc:
        print("monitor: unreadable", exc)
    diag = _newest(args.rust_dump, "emulebb-rust-diag-*.jsonl")
    if diag:
        counts: collections.Counter[str] = collections.Counter()
        for line in open(diag, encoding="utf-8", errors="ignore"):
            for event in DIAG_EVENTS:
                if f'"{event}"' in line:
                    counts[event] += 1
        print("diag:", dict(counts))
    udp = glob.glob(str(args.rust_dump / "*client-udp*"))
    ping = ack = 0
    for path in udp:
        for line in open(path, encoding="utf-8", errors="ignore"):
            if '"OP_REASKFILEPING"' in line:
                ping += 1
            elif '"OP_REASKACK"' in line:
                ack += 1
    print(f"reask-transport: OP_REASKFILEPING={ping} OP_REASKACK={ack} clientUdpDumps={len(udp)}")
    print("disk: C %.0fGB F %.0fGB" % (shutil.disk_usage("C:\\").free / 1e9, shutil.disk_usage("F:\\").free / 1e9))
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
    rust_diag = args.rust_diag or _newest(args.rust_dump, "emulebb-rust-diag-*.jsonl")
    # MFC rotates its diag log every few seconds, so a single active file is a
    # tiny slice; gather every rotated diag log touched within the window.
    if args.mfc_diag:
        mfc_diag_files = [Path(args.mfc_diag)]
    else:
        mfc_diag_files = [
            Path(p) for p in glob.glob(str(MFC_LOGS / "emulebb-diagnostics-diag*.log"))
            if datetime.datetime.fromtimestamp(Path(p).stat().st_mtime, datetime.timezone.utc) >= since
        ]
    print("\n=== cross-client divergence (via diag_event_diff / packet_trace_diff) ===")
    print(f"window={args.window_minutes}min  rust diag: {rust_diag}\nmfc diag files in window: {len(mfc_diag_files)}")
    report: dict = {}
    if rust_diag and Path(rust_diag).exists() and mfc_diag_files:
        rt = _windowed_diag_trace(diag_event_diff.load_trace, [Path(rust_diag)], since)
        mt = _windowed_diag_trace(diag_event_diff.load_trace, mfc_diag_files, since)
        # MFC keeps its richest bad-peer diagnostics in a separate bad_peer_event_v1
        # log (different names/shape) that never reaches the converged diag stream.
        # Adapt + window those into the diag_event_v1 bad_peer envelope so the
        # bad_peer surface is actually diffed (otherwise it is invisible on MFC).
        mfc_bad_peer_files = mfc_diag_adapter.find_mfc_bad_peer_logs(MFC_LOGS)
        mt += _windowed_diag_trace(
            lambda path: mfc_diag_adapter.bad_peer_events_as_diag_v1([path]),
            mfc_bad_peer_files,
            since,
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
            _windowed_diag_trace(diag_event_diff.load_trace, [Path(rust_diag)], _EPOCH)
        )
        kad_cov = packet_trace_diff.kad_opcode_coverage(
            rust_kad_all, packet_trace_diff.kad_records(mt)
        )
        report["kad_opcode_coverage"] = kad_cov
        kad_gaps = sorted(
            {str(e["opcodeName"] or e["opcode"]) for e in kad_cov["combined"]["onlyEmule"]}
        )
        print(f"  [kad opcode coverage] oracleOk={kad_cov['oracleOk']} onlyEmule(gap)={kad_gaps}")
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
    else:
        print("  (skipped diag diff: missing one trace)")
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
            for p in glob.glob(str(MFC_LOGS / "emulebb-diagnostics-packet*.log"))
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
        print("  (skipped packet diff: missing one trace)")
    if args.diff_json:
        Path(args.diff_json).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"\nfull divergence JSON -> {args.diff_json}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-base", default=RUST_BASE)
    parser.add_argument("--rust-key", default=RUST_KEY)
    parser.add_argument("--mfc-base", default=MFC_BASE)
    parser.add_argument("--mfc-key", default=MFC_KEY)
    parser.add_argument("--rust-dump", type=Path, default=RUNTIME_DUMP, help="Rust packet-dump directory.")
    parser.add_argument("--diff", action="store_true", help="Also run the cross-client divergence report.")
    parser.add_argument("--window-minutes", type=float, default=15.0, help="Wall-clock window for the divergence diff (both traces are filtered to it).")
    parser.add_argument("--schema-audit", action="store_true", help="Per shared event, report body-field key deltas vs the MFC oracle schema.")
    parser.add_argument("--oracle-conformance", action="store_true", help="Verdict only: does rust cover every oracle event + body key (rust superset-of oracle)? rust extras allowed.")
    parser.add_argument("--rust-diag", help="Override rust diag_event_v1 jsonl (default: newest in --rust-dump).")
    parser.add_argument("--mfc-diag", help="Override MFC diag_event_v1 log.")
    parser.add_argument("--rust-packet", help="Override rust ed2k_packet_v1 jsonl.")
    parser.add_argument("--mfc-packet", help="Override MFC ed2k_packet_v1 log.")
    parser.add_argument("--diff-json", help="Write the full divergence result JSON here.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    up = heartbeat(args)
    if args.diff and up:
        divergence(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
