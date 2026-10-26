"""Offline rust-vs-MFC parity diff over two SOLO scripted-capture recordings.

Consumes two sanitized recordings and their private-artifact siblings produced by
``soak-scripted-capture.py`` (one rust, one mfc) for the same campaign — captured
SEQUENTIALLY, so each side has its own action windows. Correlates the two by
``actionId`` (deterministic — the same scripted set ran on both), slices each side's
diagnostic records to that action's
``[begin-lead, end+settle]`` window, and delegates to the existing
``diag_event_diff`` / ``packet_trace_diff`` engines. Emits a per-action verdict plus a
campaign summary (oracle conformance, cumulative Kad opcode coverage, source_count).

This is the offline half of the capture-then-offline-diff model (adopted 2026-07-04):
reproducible, contention-free, apples-to-apples — no simultaneous operator run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import (  # noqa: E402
    diag_event_diff,
    diag_event_runs,
    packet_trace_diff,
    secident_audit,
    soak_action_diff,
    soak_report_summary,
)
from emule_test_harness.diag_event_schema import DIAG_EVENT_SCHEMA  # noqa: E402
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402

CAMPAIGN_EXIT_CODES = {
    "parity": 0,
    "divergence": 1,
    "harness-failure": 2,
    "inconclusive-external": 3,
}
def _load_recording(zip_path: Path, *, client: str) -> dict[str, Any]:
    """Read sanitized metadata plus raw diagnostics from its private sibling."""

    if client not in {"rust", "mfc"}:
        raise ValueError(f"client must be 'rust' or 'mfc', got {client!r}")

    markers: list[dict[str, Any]] = []
    diag: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    native_capture_sizes: list[int] = []
    classification: dict[str, Any] | None = None
    private_dir = zip_path.with_name(f"{zip_path.stem}-private-artifacts")
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            lower = name.lower()
            if lower.endswith("native-capture.pcapng"):
                raise ValueError("A sanitized recording contains a private packet capture.")
            if lower.endswith("evidence-classification.json"):
                classification = json.loads(zf.read(name).decode("utf-8", "replace"))
                continue
            if lower.endswith("markers.jsonl"):
                for line in zf.read(name).decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if line:
                        marker = json.loads(line)
                        if not isinstance(marker, dict):
                            raise ValueError("A recording marker is not a JSON object.")
                        markers.append(marker)
                continue
            if lower.endswith("results.json"):
                result = json.loads(zf.read(name).decode("utf-8", "replace"))
                if not isinstance(result, dict):
                    raise ValueError("The recording results document is not a JSON object.")
                meta = result
                continue
            if lower.endswith(".jsonl") or lower.endswith(".log"):
                raise ValueError("A sanitized recording contains private diagnostics.")

    expected_sibling = f"{zip_path.stem}-private-artifacts"
    if (
        not isinstance(classification, dict)
        or classification.get("archiveClassification") != "sanitized-report"
        or classification.get("privateArtifactsSibling") != expected_sibling
    ):
        raise ValueError("The recording evidence classification is missing or invalid.")
    capture_path = private_dir / "native-capture.pcapng"
    if capture_path.is_file():
        native_capture_sizes.append(capture_path.stat().st_size)
    dumps_dir = private_dir / "dumps"
    if dumps_dir.is_dir():
        diag_paths: list[Path] = []
        other_diagnostic_paths: list[Path] = []
        for path in sorted(dumps_dir.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in (".jsonl", ".log"):
                continue
            if diag_event_runs.diag_segment_identity(path, client=client) is not None:
                diag_paths.append(path)
                continue
            other_client = "mfc" if client == "rust" else "rust"
            if diag_event_runs.diag_segment_identity(path, client=other_client) is not None:
                raise ValueError(f"A {client} recording contains {other_client} diagnostics.")
            if path.name.startswith(("emulebb-rust-diag-", "emulebb-mfc-diag-")):
                raise ValueError(f"Unsupported diagnostic segment name: {path.name}")
            other_diagnostic_paths.append(path)

        diag = diag_event_runs.load_latest_diag_records(diag_paths, client=client)

        if client == "mfc" and diag_paths:
            health_paths = sorted(dumps_dir.rglob("emulebb-mfc-diag-health.json"))
            if len(health_paths) != 1:
                raise ValueError(
                    "An MFC recording must contain exactly one diagnostic writer health file."
                )
            selected_segments = diag_event_runs.select_latest_diag_run(
                diag_paths, client="mfc"
            )
            diag_event_runs.load_and_validate_writer_health(
                health_paths[0], client="mfc", selected_segments=selected_segments
            )

        packets = diag_event_diff.ed2k_tcp_packet_views(diag)
        for path in other_diagnostic_paths:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:  # noqa: BLE001 - MFC packet logs may carry non-JSON lines
                    continue
                if not isinstance(record, dict):
                    continue
                schema = record.get("schema")
                if schema == DIAG_EVENT_SCHEMA:
                    raise ValueError(
                        f"Diagnostic events must use segmented current-run names: {path.name}"
                    )
                if schema in {"ed2k_packet_v1", "udp_packet_v1"}:
                    raise ValueError(
                        f"Legacy packet side files are unsupported: {path.name}"
                    )
    private_completion_path = private_dir / "completion-private.json"
    if private_completion_path.is_file():
        private_completion = json.loads(
            private_completion_path.read_text(encoding="utf-8")
        )
        if not isinstance(private_completion, dict):
            raise ValueError("Private completion evidence is not a JSON object.")
        # Private digests stay in memory and are reduced to counts/booleans by
        # _compare_native_completions; they are never copied into the report.
        meta["_privateCompletionEvidence"] = private_completion
    return {
        "markers": markers,
        "diag": diag,
        "packets": packets,
        "meta": meta,
        "nativeCaptureSizes": native_capture_sizes,
    }


def _native_capture_evidence(recording: dict[str, Any]) -> dict[str, Any]:
    """Validate retained frame counts against the packed native capture entry."""

    sizes = recording.get("nativeCaptureSizes")
    section = recording.get("meta", {}).get("nativeCapture")
    findings: list[str] = []
    if not isinstance(sizes, list) or len(sizes) != 1:
        findings.append("native-capture-entry-count")
        packed_size = 0
    else:
        packed_size = sizes[0] if isinstance(sizes[0], int) else 0
    if not isinstance(section, dict):
        findings.append("native-capture-metadata-missing")
        section = {}
    frame_count = section.get("frameCount")
    relevant_frame_count = section.get("relevantFrameCount")
    captured_bytes = section.get("capturedByteCount")
    file_bytes = section.get("fileByteCount")
    if not isinstance(frame_count, int) or frame_count <= 0:
        findings.append("native-capture-no-frames")
    if not isinstance(relevant_frame_count, int) or relevant_frame_count <= 0:
        findings.append("native-capture-no-relevant-frames")
    if not isinstance(captured_bytes, int) or captured_bytes <= 0:
        findings.append("native-capture-no-captured-bytes")
    if section.get("sizeLimitReached") is not False:
        findings.append("native-capture-size-limit")
    if not isinstance(file_bytes, int) or file_bytes < 28 or file_bytes != packed_size:
        findings.append("native-capture-size-mismatch")
    return {
        "ok": not findings,
        "frameCount": frame_count if isinstance(frame_count, int) else 0,
        "relevantFrameCount": (
            relevant_frame_count if isinstance(relevant_frame_count, int) else 0
        ),
        "capturedByteCount": captured_bytes if isinstance(captured_bytes, int) else 0,
        "findings": findings,
    }


_SEARCH_ACTION_ID_METHOD = re.compile(r"^search-(?P<method>[a-z]+)-")


def _action_method(action_id: str, window: dict[str, Any]) -> str | None:
    """Search method for one action: marker field first, actionId fallback.

    Newer recordings stamp ``method`` on the scripted-action markers; older ones
    only encode it in the actionId (``search-<method>-<term>``).
    """

    method = window.get("method")
    if method:
        return str(method)
    match = _SEARCH_ACTION_ID_METHOD.match(str(action_id))
    return match.group("method") if match else None


def _action_windows(markers: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Maps ``actionId`` → {kind, method, t0, t1} from the begin/end markers."""

    windows: dict[str, dict[str, Any]] = {}
    for marker in markers:
        action_id = marker.get("actionId")
        if not action_id:
            continue
        slot = windows.setdefault(action_id, {"kind": marker.get("kind")})
        if marker.get("method") and not slot.get("method"):
            slot["method"] = marker.get("method")
        stamp = soak_action_diff.parse_ts(marker.get("ts_utc"))
        if marker.get("marker") == "begin":
            slot["t0"] = stamp
        elif marker.get("marker") == "end":
            slot["t1"] = stamp
            slot["status"] = marker.get("status")
    return windows


def _native_action_contract(recording: dict[str, Any]) -> dict[str, Any]:
    """Require the complete native action set, including terminal download markers."""

    summary = recording.get("meta", {}).get("nativeInputSummary")
    if not isinstance(summary, dict):
        return {"required": False, "ok": True, "expectedCount": None, "findings": []}
    download_count = summary.get("ed2k_link_count")
    if not isinstance(download_count, int) or isinstance(download_count, bool) or download_count <= 0:
        return {
            "required": True,
            "ok": False,
            "expectedCount": None,
            "findings": ["native-action-count-invalid"],
        }
    expected_count = 3 + download_count
    expected_ids = {f"action-{index:04d}" for index in range(1, expected_count + 1)}
    marker_ids = {
        str(row.get("actionId"))
        for row in recording.get("markers", [])
        if isinstance(row, dict) and row.get("actionId")
    }
    results = recording.get("meta", {}).get("actionResults")
    result_ids = {
        str(row.get("actionId"))
        for row in results
        if isinstance(row, dict) and row.get("actionId")
    } if isinstance(results, list) else set()
    findings: list[str] = []
    if marker_ids != expected_ids:
        findings.append("native-marker-action-set-mismatch")
    if result_ids != expected_ids:
        findings.append("native-result-action-set-mismatch")

    grouped: dict[str, list[dict[str, Any]]] = {}
    for marker in recording.get("markers", []):
        if isinstance(marker, dict) and marker.get("actionId"):
            grouped.setdefault(str(marker["actionId"]), []).append(marker)
    for action_id in expected_ids:
        rows = grouped.get(action_id, [])
        if not any(row.get("marker") == "begin" for row in rows):
            findings.append("native-action-begin-missing")
            break
        if not any(row.get("marker") == "end" for row in rows):
            findings.append("native-action-end-missing")
            break
    search_methods = {
        str(row.get("method"))
        for action_id in ("action-0001", "action-0002", "action-0003")
        for row in grouped.get(action_id, [])
        if row.get("marker") == "begin" and row.get("method")
    }
    if search_methods != {"server", "global", "kad"}:
        findings.append("native-search-method-set-mismatch")
    for index in range(4, expected_count + 1):
        rows = grouped.get(f"action-{index:04d}", [])
        if not any(row.get("marker") == "end" and row.get("terminal") is True for row in rows):
            findings.append("native-download-terminal-marker-missing")
            break
    return {
        "required": True,
        "ok": not findings,
        "expectedCount": expected_count,
        "findings": sorted(set(findings)),
    }


def _diff_one_action(
    kind: str,
    rust: dict[str, Any],
    mfc: dict[str, Any],
    rust_win: dict[str, Any],
    mfc_win: dict[str, Any],
    *,
    lead: float,
    settle: float,
    method: str | None = None,
) -> dict[str, Any]:
    import datetime

    def pad(win: dict[str, Any]) -> tuple[datetime.datetime, datetime.datetime] | None:
        t0 = win.get("t0")
        t1 = win.get("t1")
        if t0 is None or t1 is None:
            return None
        return (
            t0 - datetime.timedelta(seconds=lead),
            t1 + datetime.timedelta(seconds=settle),
        )

    rust_span = pad(rust_win)
    mfc_span = pad(mfc_win)
    if rust_span is None or mfc_span is None:
        return {"kind": kind, "method": method, "verdict": "no-window", "conformant": False,
                "diagFamilyOk": False, "diagStrictMatchOk": False, "coverageOk": None,
                "rustRecords": {"packets": 0, "diag": 0}, "mfcRecords": {"packets": 0, "diag": 0}}
    if rust_win.get("status") == "error" or mfc_win.get("status") == "error":
        return {"kind": kind, "method": method, "verdict": "action-error", "conformant": False,
                "diagFamilyOk": False, "diagStrictMatchOk": False, "coverageOk": None,
                "rustRecords": {"packets": 0, "diag": 0}, "mfcRecords": {"packets": 0, "diag": 0}}
    r0, r1 = rust_span
    m0, m1 = mfc_span
    rust_window = soak_action_diff.ActionWindow(start_utc=r0, end_utc=r1)
    mfc_window = soak_action_diff.ActionWindow(start_utc=m0, end_utc=m1)
    rust_pkt = soak_action_diff.slice_trace(
        rust["packets"], rust_window, trace_name="rust packet trace"
    )
    mfc_pkt = soak_action_diff.slice_trace(
        mfc["packets"], mfc_window, trace_name="mfc packet trace"
    )
    rust_diag = soak_action_diff.slice_trace(
        rust["diag"], rust_window, trace_name="rust diagnostic trace"
    )
    mfc_diag = soak_action_diff.slice_trace(
        mfc["diag"], mfc_window, trace_name="mfc diagnostic trace"
    )

    diag_diff = diag_event_diff.diff_traces(rust_diag, mfc_diag)
    sched_rows = [
        row for row in diag_diff.get("families", []) if row.get("family") == "sched"
    ]
    state_machine_ok = all(row.get("ok") is True for row in sched_rows) if sched_rows else None
    state_machine_totals = {
        key: sum(int(row.get("totals", {}).get(key) or 0) for row in sched_rows)
        for key in ("sharedKeys", "matchedKeys", "transitionDivergences", "invariantViolations")
    }
    packet_diff = packet_trace_diff.diff_traces(rust_pkt, mfc_pkt) if (rust_pkt or mfc_pkt) else None
    action_coverage = soak_action_diff.build_action_coverage(
        kind,
        packet_diff or {},
        method=method,
        rust_kad_records=packet_trace_diff.kad_records(rust_diag),
        mfc_kad_records=packet_trace_diff.kad_records(mfc_diag),
    )
    audit = diag_event_diff.schema_audit(rust_diag, mfc_diag)
    conf = audit["conformance"]
    family_gate = diag_event_diff.family_conformance(rust_diag, mfc_diag)

    rust_total = len(rust_pkt) + len(rust_diag)
    mfc_total = len(mfc_pkt) + len(mfc_diag)
    if rust_total == 0 and mfc_total == 0:
        verdict = "no-traffic"
    elif rust_total == 0 or mfc_total == 0:
        verdict = "one-sided"
    elif not rust_diag or not mfc_diag:
        verdict = "missing-diagnostics"
    else:
        # For two INDEPENDENT clients the strict diag family-match (like byteMatch) is
        # never true - transition sequences differ. The real parity signal is oracle
        # CONFORMANCE (rust's diag is a superset of the oracle's) over the action window.
        # The strict family-match + server-channel opcode gate are informational only.
        verdict = (
            "conformant"
            if conf["conformant"] and state_machine_ok is not False
            else "divergence"
        )
    return {
        "kind": kind,
        "method": method,
        "verdict": verdict,
        "conformant": bool(
            conf["conformant"]
            and rust_total > 0
            and mfc_total > 0
            and rust_diag
            and mfc_diag
        ),
        # Per-family oracle-conformance gate (rust ⊇ oracle on families present on
        # both sides) — the reported per-action diag gate. The old strict
        # record-identity match is retained as `diagStrictMatchOk`, which is
        # INFORMATIONAL ONLY: it can never pass across two independent live
        # sessions and must not be read as a failure signal.
        "diagFamilyOk": bool(family_gate["ok"]),
        "diagFamilyGate": family_gate,
        "diagStrictMatchOk": bool(diag_diff.get("ok")),
        "stateMachineOk": state_machine_ok,
        "stateMachineTotals": state_machine_totals,
        "coverageOk": action_coverage.get("ok"),
        "conformanceViolations": conf.get("bodyKeyViolations") or conf.get("violations") or [],
        "rustRecords": {"packets": len(rust_pkt), "diag": len(rust_diag)},
        "mfcRecords": {"packets": len(mfc_pkt), "diag": len(mfc_diag)},
    }


def _full_run_diagnostic_gate(
    rust_diag: list[dict[str, Any]],
    mfc_diag: list[dict[str, Any]],
) -> dict[str, Any]:
    """Applies requirements that are meaningful only over complete captures."""

    return diag_event_diff.full_run_conformance(rust_diag, mfc_diag)


def _action_error_count(recording: dict[str, Any]) -> int:
    """Count explicitly failed action results while tolerating legacy metadata."""

    rows = recording.get("meta", {}).get("actionResults")
    if not isinstance(rows, list):
        return 0
    return sum(
        1
        for row in rows
        if isinstance(row, dict) and str(row.get("status") or "").casefold() != "ok"
    )


def _completion_rows(
    meta: dict[str, Any],
) -> tuple[bool, int | None, dict[str, tuple[int, str | None]] | None]:
    """Read opt-in native completion evidence without returning digest-bearing output."""

    public_section = meta.get("nativeCompletionEvidence")
    section = meta.get("_privateCompletionEvidence", public_section)
    if not isinstance(public_section, dict) or public_section.get("required") is not True:
        return False, None, None
    if not isinstance(section, dict) or section.get("required") is not True:
        return True, None, None
    expected_count = section.get("expectedCount")
    if (
        not isinstance(expected_count, int)
        or isinstance(expected_count, bool)
        or expected_count <= 0
    ):
        return True, None, None
    files = section.get("files")
    if not isinstance(files, list):
        return True, expected_count, None
    rows: dict[str, tuple[int, str | None]] = {}
    for item in files:
        if not isinstance(item, dict):
            return True, expected_count, None
        action_id = str(item.get("actionId") or "")
        size = item.get("sizeBytes")
        raw_sha256 = item.get("sha256")
        sha256 = str(raw_sha256).casefold() if isinstance(raw_sha256, str) else ""
        if (
            not action_id
            or action_id in rows
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or item.get("sizeVerified") is not True
            or item.get("ed2kVerified") is not True
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            return True, expected_count, None
        rows[action_id] = (size, sha256)
    return True, expected_count, rows


def _completion_statuses(meta: dict[str, Any]) -> dict[str, str] | None:
    rows = meta.get("nativeCompletionSummary")
    if not isinstance(rows, list):
        return None
    statuses: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            return None
        action_id = str(row.get("actionId") or "")
        status = str(row.get("status") or "")
        if not action_id or action_id in statuses or status not in {"verified", "incomplete", "invalid"}:
            return None
        statuses[action_id] = status
    return statuses


def _compare_native_completions(
    rust_meta: dict[str, Any], mfc_meta: dict[str, Any]
) -> dict[str, Any]:
    """Compare opted-in completion proofs and emit counts/booleans, never digests."""

    rust_required, rust_expected, rust_rows = _completion_rows(rust_meta)
    mfc_required, mfc_expected, mfc_rows = _completion_rows(mfc_meta)
    if not rust_required and not mfc_required:
        return {"required": False, "ok": None, "expectedCount": None, "matchedCount": 0, "findings": []}

    findings: list[str] = []
    if not rust_required or not mfc_required:
        findings.append("recording-opt-in-mismatch")
    if rust_expected is None or rust_rows is None:
        findings.append("rust-completion-evidence-invalid")
    if mfc_expected is None or mfc_rows is None:
        findings.append("mfc-completion-evidence-invalid")
    if findings:
        return {"required": True, "ok": False, "expectedCount": None, "matchedCount": 0, "findings": findings}

    assert rust_expected is not None and mfc_expected is not None
    assert rust_rows is not None and mfc_rows is not None
    rust_statuses = _completion_statuses(rust_meta)
    mfc_statuses = _completion_statuses(mfc_meta)
    if rust_statuses is None and len(rust_rows) == rust_expected:
        rust_statuses = dict.fromkeys(rust_rows, "verified")
    if mfc_statuses is None and len(mfc_rows) == mfc_expected:
        mfc_statuses = dict.fromkeys(mfc_rows, "verified")
    if rust_statuses is None:
        findings.append("rust-completion-summary-invalid")
    if mfc_statuses is None:
        findings.append("mfc-completion-summary-invalid")
    for statuses in (rust_statuses or {}, mfc_statuses or {}):
        if "invalid" in statuses.values():
            findings.append("completion-invalid")
        if "incomplete" in statuses.values():
            findings.append("completion-incomplete")
    if rust_expected != mfc_expected:
        findings.append("expected-count-mismatch")
    expected_count = rust_expected if rust_expected == mfc_expected else None
    if len(rust_rows) != rust_expected:
        findings.append("rust-completion-count-mismatch")
    if len(mfc_rows) != mfc_expected:
        findings.append("mfc-completion-count-mismatch")
    if rust_rows.keys() != mfc_rows.keys():
        findings.append("completion-action-set-mismatch")
    common = rust_rows.keys() & mfc_rows.keys()
    if any(rust_rows[action_id][0] != mfc_rows[action_id][0] for action_id in common):
        findings.append("completion-size-mismatch")
    comparable_digests = [
        action_id
        for action_id in common
        if rust_rows[action_id][1] is not None and mfc_rows[action_id][1] is not None
    ]
    if any(rust_rows[action_id][1] != mfc_rows[action_id][1] for action_id in comparable_digests):
        findings.append("completion-sha256-mismatch")
    return {
        "required": True,
        "ok": not findings,
        "expectedCount": expected_count,
        "matchedCount": len(common),
        "digestComparedCount": len(comparable_digests),
        "findings": findings,
    }


def _campaign_verdict(
    *,
    per_action: list[dict[str, Any]],
    missing_action_count: int,
    action_error_count: int,
    completion: dict[str, Any],
    scenario_mismatch: bool,
    conformance_ok: bool,
    kad_coverage_ok: bool,
    secident_dead: bool,
    external_inconclusive: bool,
    capture_evidence_ok: bool = True,
    action_contract_ok: bool = True,
    state_machine_ok: bool = True,
    state_machine_evidence_observed: bool = True,
) -> dict[str, Any]:
    """Adjudicate one campaign with harness failures taking precedence."""

    findings: list[str] = []
    if not per_action:
        findings.append("no-common-actions")
    if missing_action_count:
        findings.append("missing-actions")
    if action_error_count or any(row.get("verdict") == "action-error" for row in per_action):
        findings.append("action-errors")
    if scenario_mismatch:
        findings.append("scenario-mismatch")
    if not capture_evidence_ok:
        findings.append("native-capture-evidence-failed")
    if not action_contract_ok:
        findings.append("native-action-contract-failed")
    if not state_machine_evidence_observed:
        findings.append("state-machine-evidence-missing")
    if any(row.get("verdict") == "no-window" for row in per_action):
        findings.append("missing-action-windows")
    if (
        any(row.get("verdict") in {"no-traffic", "one-sided"} for row in per_action)
        and not external_inconclusive
    ):
        findings.append("missing-action-traffic")
    if any(row.get("verdict") == "missing-diagnostics" for row in per_action):
        findings.append("missing-action-diagnostics")
    completion_findings = set(completion.get("findings") or [])
    completion_content_divergence = bool(
        completion_findings
        & {"completion-size-mismatch", "completion-sha256-mismatch", "completion-invalid"}
    )
    completion_incomplete = bool(
        completion_findings
        and completion_findings
        <= {
            "rust-completion-count-mismatch",
            "mfc-completion-count-mismatch",
            "completion-action-set-mismatch",
            "completion-incomplete",
        }
    )
    if (
        completion.get("required")
        and completion.get("ok") is not True
        and not completion_content_divergence
        and not (external_inconclusive and completion_incomplete)
    ):
        findings.append("completion-evidence-failed")
    if findings:
        verdict = "harness-failure"
    else:
        divergence = (
            not conformance_ok
            or not kad_coverage_ok
            or not state_machine_ok
            or secident_dead
            or completion_content_divergence
            or any(
                row.get("verdict") == "divergence" or row.get("coverageOk") is False
                for row in per_action
            )
        )
        if divergence:
            verdict = "divergence"
        elif external_inconclusive:
            verdict = "inconclusive-external"
        else:
            verdict = "parity"
    return {"verdict": verdict, "exitCode": CAMPAIGN_EXIT_CODES[verdict], "findings": findings}


def _declared_secident(meta: dict[str, Any]) -> bool | None:
    """Reads the recorded SecIdent claim from a recording's results.json meta.

    ``always-on`` (rust: no config key, identity always provisioned) counts as an
    enabled claim; recordings older than the --secident knob return ``None``.
    """

    section = meta.get("secident")
    if isinstance(section, dict):
        applied = section.get("applied") or section.get("requested")
        if applied == "always-on":
            return True
        if applied in ("on", "off"):
            return applied == "on"
    return None


def _audit_secident(rust: dict[str, Any], mfc: dict[str, Any]) -> dict[str, Any]:
    """Runs the SecIdent liveness audit over both full recordings."""

    report: dict[str, Any] = {}
    for name, side in (("rust", rust), ("mfc", mfc)):
        report[name] = secident_audit.audit_client_secident(
            side["packets"], declared_enabled=_declared_secident(side["meta"])
        )
    return report


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
        print(f"harness-failure: missing recordings (rust={rust_zip} mfc={mfc_zip})")
        return CAMPAIGN_EXIT_CODES["harness-failure"]

    try:
        rust = _load_recording(rust_zip, client="rust")
        mfc = _load_recording(mfc_zip, client="mfc")
        if not rust["diag"] or not mfc["diag"]:
            raise ValueError("Both recordings require current diag_event_v2 evidence.")
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"harness-failure: could not load recordings ({type(exc).__name__})")
        return CAMPAIGN_EXIT_CODES["harness-failure"]
    print(f"rust recording: {rust_zip.name}  obf={rust['meta'].get('obfuscation')}  diag={len(rust['diag'])} pkt={len(rust['packets'])}")
    print(f"mfc  recording: {mfc_zip.name}  obf={mfc['meta'].get('obfuscation')}  diag={len(mfc['diag'])} pkt={len(mfc['packets'])}")
    scenario_mismatch = any(
        rust["meta"].get(key) != mfc["meta"].get(key)
        for key in ("obfuscation", "scenario")
    )
    if scenario_mismatch:
        print("  !! WARNING: scenario metadata differs between the two recordings")

    rust_windows = _action_windows(rust["markers"])
    mfc_windows = _action_windows(mfc["markers"])
    common = [a for a in rust_windows if a in mfc_windows]
    missing_action_count = len(set(rust_windows) ^ set(mfc_windows))

    print("\n== per-action parity ==")
    per_action: list[dict[str, Any]] = []
    for action_id in common:
        kind = rust_windows[action_id].get("kind") or "search"
        method = _action_method(action_id, rust_windows[action_id]) if kind == "search" else None
        result = _diff_one_action(
            kind, rust, mfc, rust_windows[action_id], mfc_windows[action_id],
            lead=args.lead_seconds, settle=args.settle_seconds, method=method,
        )
        per_action.append({"actionId": action_id, **result})
        viol = result.get("conformanceViolations") or []
        print(
            f"  {action_id:<26} {result['verdict']:<12} conformant={result['conformant']} "
            f"viol={len(viol)} famOk={result['diagFamilyOk']} "
            f"strict={result['diagStrictMatchOk']}(info) "
            f"rust(pkt/diag)={result['rustRecords']['packets']}/{result['rustRecords']['diag']} "
            f"mfc={result['mfcRecords']['packets']}/{result['mfcRecords']['diag']}"
        )
        if viol:
            print(f"      violations: {viol[:5]}")

    # Campaign summary over the FULL recordings (conformance + cumulative Kad coverage).
    audit = diag_event_diff.schema_audit(rust["diag"], mfc["diag"])
    conf = audit["conformance"]
    full_diag_gate = _full_run_diagnostic_gate(rust["diag"], mfc["diag"])
    kad_cov = packet_trace_diff.kad_opcode_coverage(
        packet_trace_diff.kad_records(rust["diag"]),
        packet_trace_diff.kad_records(mfc["diag"]),
    )

    def _kad_labels(rows: list[dict[str, Any]]) -> list[str]:
        return sorted(f"{row['opcodeHex']} {row['opcodeName'] or '?'}" for row in rows)

    kad_sent_gaps = _kad_labels(kad_cov["onlyEmuleSentGaps"])
    kad_recv_only = _kad_labels(kad_cov["onlyEmuleReceivedOnly"])
    kad_expected = _kad_labels(kad_cov["expectedOnlyEmule"])
    print("\n== campaign summary ==")
    print(f"  oracle conformance (rust superset-of oracle): {'PASS' if conf['conformant'] else 'FAIL'}")
    print(
        "  full-run diagnostics: "
        f"{'PASS' if full_diag_gate['ok'] else 'FAIL'} "
        f"required={full_diag_gate['familyConformance']['requiredFamilies']} "
        f"rustLifecycleViolations={len(full_diag_gate['clientUdpLifecycle']['rust']['violations'])} "
        f"mfcLifecycleViolations={len(full_diag_gate['clientUdpLifecycle']['mfc']['violations'])}"
    )
    print(
        f"  kad opcode coverage oracleOk={kad_cov['oracleOk']} "
        f"sentGaps={kad_sent_gaps} recvOnlyNoise={kad_recv_only} "
        f"expectedDivergences={kad_expected} "
        f"udpDumpCredited={kad_cov['supplementaryCreditedOpcodes']}"
    )
    # SecIdent liveness: a profile claiming SecIdent on while the wire shows
    # zero 0x85/86/87 packets + HELLO secident bits 0 is a silenced parity
    # surface (the 2026-07-04 capture failure mode) and must be loud.
    secident_report = _audit_secident(rust, mfc)
    for name, audit_row in secident_report.items():
        line = (
            f"  secident[{name}]: {audit_row['verdict']}"
            f" helloBits={audit_row['helloSecIdentBits']}"
            f" packets={audit_row['secIdentPackets']['total']}"
            f" declared={audit_row['declaredEnabled']}"
        )
        print(line)
        if audit_row["verdict"] == "secident-dead":
            print(
                f"  !! SECIDENT-DEAD ({name}): {', '.join(audit_row['findings'])} — "
                "the SecIdent parity surface produced NO wire evidence this run; "
                "check the profile SecureIdent pref / cryptkey provisioning."
            )
    verdicts = {r["verdict"] for r in per_action}
    completion = _compare_native_completions(rust["meta"], mfc["meta"])
    capture_evidence = {
        "rust": _native_capture_evidence(rust),
        "mfc": _native_capture_evidence(mfc),
    }
    action_contract = {
        "rust": _native_action_contract(rust),
        "mfc": _native_action_contract(mfc),
    }
    action_error_count = _action_error_count(rust) + _action_error_count(mfc)
    secident_dead = any(
        row["verdict"] == "secident-dead" for row in secident_report.values()
    )
    state_machine_rows = [
        row.get("stateMachineOk")
        for row in per_action
        if row.get("stateMachineOk") is not None
    ]
    state_machine_evidence_observed = bool(state_machine_rows)
    state_machine_ok = state_machine_evidence_observed and all(state_machine_rows)
    external_inconclusive = any(
        side["meta"].get("externalInconclusive") is True for side in (rust, mfc)
    )
    adjudication = _campaign_verdict(
        per_action=per_action,
        missing_action_count=missing_action_count,
        action_error_count=action_error_count,
        completion=completion,
        scenario_mismatch=scenario_mismatch,
        conformance_ok=bool(full_diag_gate["ok"]),
        kad_coverage_ok=bool(kad_cov["oracleOk"]),
        secident_dead=secident_dead,
        external_inconclusive=external_inconclusive,
        capture_evidence_ok=all(row["ok"] for row in capture_evidence.values()),
        action_contract_ok=all(row["ok"] for row in action_contract.values()),
        state_machine_ok=state_machine_ok,
        state_machine_evidence_observed=state_machine_evidence_observed,
    )
    all_parity = adjudication["verdict"] == "parity"
    print(f"  per-action verdicts: {sorted(verdicts)}")
    if completion["required"]:
        print(
            "  native completions: "
            f"ok={completion['ok']} expected={completion['expectedCount']} "
            f"matched={completion['matchedCount']} findings={completion['findings']}"
        )
    print(
        f"  campaign verdict: {adjudication['verdict']} "
        f"exit={adjudication['exitCode']} findings={adjudication['findings']}"
    )

    report = {
        "schema": "soak_offline_diff_v1",
        "rustRecording": rust_zip.name,
        "mfcRecording": mfc_zip.name,
        "obfuscation": rust["meta"].get("obfuscation"),
        "perAction": per_action,
        "conformance": full_diag_gate["ok"],
        "schemaConformance": conf["conformant"],
        "fullRunDiagnostics": full_diag_gate,
        "fullRunDiagnosticSummary": soak_report_summary.summarize_full_run_diagnostics(
            full_diag_gate
        ),
        "kadOpcodeCoverageOracleOk": kad_cov["oracleOk"],
        "kadOnlyEmuleSentGaps": kad_sent_gaps,
        "kadOnlyEmuleReceivedOnly": kad_recv_only,
        "kadExpectedOnlyEmule": kad_expected,
        "kadUdpDumpCreditedOpcodes": kad_cov["supplementaryCreditedOpcodes"],
        "secident": secident_report,
        "secidentDead": [
            name for name, row in secident_report.items() if row["verdict"] == "secident-dead"
        ],
        "nativeCompletionComparison": completion,
        "nativeCaptureEvidence": capture_evidence,
        "nativeActionContract": action_contract,
        "stateMachineValidation": {
            "observedActionCount": len(state_machine_rows),
            "evidenceObserved": state_machine_evidence_observed,
            "ok": state_machine_ok,
        },
        "campaignVerdict": adjudication["verdict"],
        "exitCode": adjudication["exitCode"],
        "campaignFindings": adjudication["findings"],
        "allParity": all_parity,
    }
    out_path = rust_zip.parent / f"offline-diff-{rust_zip.stem}-vs-{mfc_zip.stem}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nreport: {out_path}")
    return int(adjudication["exitCode"])


def _cli_main() -> int:
    """Map unexpected offline failures to a sanitized harness-failure exit."""

    try:
        return main()
    except KeyboardInterrupt:
        raise
    except Exception as error:  # noqa: BLE001 - malformed evidence must never look like divergence
        print(f"harness-failure: {type(error).__name__}", file=sys.stderr)
        return CAMPAIGN_EXIT_CODES["harness-failure"]


if __name__ == "__main__":
    raise SystemExit(_cli_main())
