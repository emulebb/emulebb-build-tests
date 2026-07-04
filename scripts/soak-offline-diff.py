"""Offline rust-vs-MFC parity diff over two SOLO scripted-capture recordings.

Consumes two packed recordings produced by ``soak-scripted-capture.py`` (one rust,
one mfc) for the same campaign — captured SEQUENTIALLY, so each side has its own
action windows. Correlates the two by ``actionId`` (deterministic — the same scripted
set ran on both), slices each side's diag/packet records to that action's
``[begin-lead, end+settle]`` window, and delegates to the existing
``diag_event_diff`` / ``packet_trace_diff`` engines. Emits a per-action verdict plus a
campaign summary (oracle conformance, cumulative Kad opcode coverage, source_count).

This is the offline half of the capture-then-offline-diff model (adopted 2026-07-04):
reproducible, contention-free, apples-to-apples — no simultaneous operator run.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import diag_event_diff, packet_trace_diff, soak_action_diff
from emule_test_harness.paths import get_workspace_output_root

DIAG_SCHEMA = "diag_event_v1"


def _load_recording(zip_path: Path) -> dict[str, Any]:
    """Reads a packed recording: markers + all diag/packet records (split by schema)."""

    markers: list[dict[str, Any]] = []
    diag: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            lower = name.lower()
            if lower.endswith("markers.jsonl"):
                for line in zf.read(name).decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if line:
                        markers.append(json.loads(line))
                continue
            if lower.endswith("results.json"):
                meta = json.loads(zf.read(name).decode("utf-8", "replace"))
                continue
            if not (lower.endswith(".jsonl") or lower.endswith(".log")):
                continue
            for line in zf.read(name).decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:  # noqa: BLE001 - MFC packet logs may carry non-JSON lines
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("schema") == DIAG_SCHEMA:
                    # diag_event_v1 stamps ``ts``; slice_trace keys on ``ts_utc``.
                    record.setdefault("ts_utc", record.get("ts"))
                    diag.append(record)
                else:
                    packets.append(record)
    return {"markers": markers, "diag": diag, "packets": packets, "meta": meta}


def _action_windows(markers: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Maps ``actionId`` → {kind, t0, t1} from the begin/end markers."""

    windows: dict[str, dict[str, Any]] = {}
    for marker in markers:
        action_id = marker.get("actionId")
        if not action_id:
            continue
        slot = windows.setdefault(action_id, {"kind": marker.get("kind")})
        stamp = soak_action_diff.parse_ts(marker.get("ts_utc"))
        if marker.get("marker") == "begin":
            slot["t0"] = stamp
        elif marker.get("marker") == "end":
            slot["t1"] = stamp
    return windows


def _diff_one_action(
    kind: str,
    rust: dict[str, Any],
    mfc: dict[str, Any],
    rust_win: dict[str, Any],
    mfc_win: dict[str, Any],
    *,
    lead: float,
    settle: float,
) -> dict[str, Any]:
    import datetime

    def pad(win: dict[str, Any]) -> tuple[datetime.datetime, datetime.datetime] | None:
        t0 = win.get("t0") or win.get("t1")
        t1 = win.get("t1") or win.get("t0")
        if t0 is None or t1 is None:
            return None
        return (
            t0 - datetime.timedelta(seconds=lead),
            t1 + datetime.timedelta(seconds=settle),
        )

    rust_span = pad(rust_win)
    mfc_span = pad(mfc_win)
    if rust_span is None or mfc_span is None:
        return {"kind": kind, "verdict": "no-window", "diagOk": False, "coverageOk": None,
                "rustRecords": {"packets": 0, "diag": 0}, "mfcRecords": {"packets": 0, "diag": 0}}
    r0, r1 = rust_span
    m0, m1 = mfc_span
    rust_pkt = soak_action_diff.slice_trace(rust["packets"], r0, r1)
    mfc_pkt = soak_action_diff.slice_trace(mfc["packets"], m0, m1)
    rust_diag = soak_action_diff.slice_trace(rust["diag"], r0, r1)
    mfc_diag = soak_action_diff.slice_trace(mfc["diag"], m0, m1)

    diag_diff = diag_event_diff.diff_traces(rust_diag, mfc_diag)
    packet_diff = packet_trace_diff.diff_traces(rust_pkt, mfc_pkt) if (rust_pkt or mfc_pkt) else None
    action_coverage = soak_action_diff.build_action_coverage(kind, packet_diff or {})

    rust_total = len(rust_pkt) + len(rust_diag)
    mfc_total = len(mfc_pkt) + len(mfc_diag)
    if rust_total == 0 and mfc_total == 0:
        verdict = "no-traffic"
    elif rust_total == 0 or mfc_total == 0:
        verdict = "one-sided"
    else:
        # Both clients emit the same diag_event_v1 schema, so diag family/conformance
        # parity is the reliable cross-client signal. The packet-opcode gate
        # (build_action_coverage) is server-channel-specific and does not cover
        # global/kad search opcodes, so it is reported informationally, not gating.
        diag_ok = bool(diag_diff.get("ok"))
        verdict = "coverage-parity" if diag_ok else "divergence"
    return {
        "kind": kind,
        "verdict": verdict,
        "diagOk": bool(diag_diff.get("ok")),
        "coverageOk": action_coverage.get("ok"),
        "rustRecords": {"packets": len(rust_pkt), "diag": len(rust_diag)},
        "mfcRecords": {"packets": len(mfc_pkt), "diag": len(mfc_diag)},
    }


def _find_recordings(campaign_dir: Path) -> tuple[Path | None, Path | None]:
    rust = sorted(campaign_dir.glob("rust-*.zip"), key=lambda p: p.stat().st_mtime)
    mfc = sorted(campaign_dir.glob("mfc-*.zip"), key=lambda p: p.stat().st_mtime)
    return (rust[-1] if rust else None, mfc[-1] if mfc else None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--campaign", help="Campaign folder under soak/reports (finds rust-*.zip + mfc-*.zip).")
    parser.add_argument("--rust", help="Explicit rust recording .zip.")
    parser.add_argument("--mfc", help="Explicit mfc recording .zip.")
    parser.add_argument("--lead-seconds", type=float, default=soak_action_diff.DEFAULT_LEAD_SECONDS)
    parser.add_argument("--settle-seconds", type=float, default=soak_action_diff.DEFAULT_SETTLE_SECONDS)
    args = parser.parse_args(argv)

    if args.rust and args.mfc:
        rust_zip, mfc_zip = Path(args.rust), Path(args.mfc)
    elif args.campaign:
        campaign_dir = get_workspace_output_root() / "soak" / "reports" / args.campaign
        rust_zip, mfc_zip = _find_recordings(campaign_dir)
    else:
        parser.error("pass --campaign or both --rust and --mfc")
        return 2
    if not rust_zip or not rust_zip.exists() or not mfc_zip or not mfc_zip.exists():
        print(f"missing recordings (rust={rust_zip} mfc={mfc_zip})")
        return 1

    rust = _load_recording(rust_zip)
    mfc = _load_recording(mfc_zip)
    print(f"rust recording: {rust_zip.name}  obf={rust['meta'].get('obfuscation')}  diag={len(rust['diag'])} pkt={len(rust['packets'])}")
    print(f"mfc  recording: {mfc_zip.name}  obf={mfc['meta'].get('obfuscation')}  diag={len(mfc['diag'])} pkt={len(mfc['packets'])}")
    if rust["meta"].get("obfuscation") != mfc["meta"].get("obfuscation"):
        print("  !! WARNING: obfuscation scenario differs between the two recordings")

    rust_windows = _action_windows(rust["markers"])
    mfc_windows = _action_windows(mfc["markers"])
    common = [a for a in rust_windows if a in mfc_windows]

    print("\n== per-action parity ==")
    per_action: list[dict[str, Any]] = []
    for action_id in common:
        kind = rust_windows[action_id].get("kind") or "search"
        result = _diff_one_action(
            kind, rust, mfc, rust_windows[action_id], mfc_windows[action_id],
            lead=args.lead_seconds, settle=args.settle_seconds,
        )
        per_action.append({"actionId": action_id, **result})
        print(
            f"  {action_id:<26} {result['verdict']:<16} diagOk={result['diagOk']} "
            f"cov={result['coverageOk']} rust(pkt/diag)={result['rustRecords']['packets']}/{result['rustRecords']['diag']} "
            f"mfc={result['mfcRecords']['packets']}/{result['mfcRecords']['diag']}"
        )

    # Campaign summary over the FULL recordings (conformance + cumulative Kad coverage).
    audit = diag_event_diff.schema_audit(rust["diag"], mfc["diag"])
    conf = audit["conformance"]
    kad_cov = packet_trace_diff.kad_opcode_coverage(
        packet_trace_diff.kad_records(rust["diag"]), packet_trace_diff.kad_records(mfc["diag"])
    )
    kad_gaps = sorted({str(e["opcodeName"] or e["opcode"]) for e in kad_cov["combined"]["onlyEmule"]})
    print("\n== campaign summary ==")
    print(f"  oracle conformance (rust superset-of oracle): {'PASS' if conf['conformant'] else 'FAIL'}")
    print(f"  kad opcode coverage oracleOk={kad_cov['oracleOk']} onlyEmule(gap)={kad_gaps}")
    verdicts = {r["verdict"] for r in per_action}
    all_parity = verdicts <= {"coverage-parity", "no-traffic"}
    print(f"  per-action verdicts: {sorted(verdicts)}  -> {'PARITY' if all_parity else 'REVIEW'}")

    report = {
        "schema": "soak_offline_diff_v1",
        "rustRecording": rust_zip.name,
        "mfcRecording": mfc_zip.name,
        "obfuscation": rust["meta"].get("obfuscation"),
        "perAction": per_action,
        "conformance": conf["conformant"],
        "kadOpcodeCoverageOracleOk": kad_cov["oracleOk"],
        "kadOnlyEmule": kad_gaps,
        "allParity": all_parity,
    }
    out_path = rust_zip.parent / f"offline-diff-{rust_zip.stem}-vs-{mfc_zip.stem}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nreport: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
