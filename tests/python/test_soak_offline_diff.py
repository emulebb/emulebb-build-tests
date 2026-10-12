"""Unit tests for the offline recording diff (scripts/soak-offline-diff.py)."""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OFFLINE_DIFF = REPO_ROOT / "scripts" / "soak-offline-diff.py"


def _load_offline_diff() -> ModuleType:
    spec = importlib.util.spec_from_file_location("soak_offline_diff_script", OFFLINE_DIFF)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ts(seconds: float) -> str:
    stamp = datetime(2026, 7, 4, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return stamp.isoformat().replace("+00:00", "Z")


def _pkt(flow: str, direction: str, opcode: int, payload_hex: str, at: float, *, marker: int = 0xE3) -> dict:
    return {
        "schema": "ed2k_packet_v1",
        "ts_utc": _ts(at),
        "flow": flow,
        "direction": direction,
        "protocol_marker": marker,
        "opcode": opcode,
        "opcode_name": f"OP_{opcode:02X}",
        "payload_len": len(payload_hex) // 2,
        "payload_hex": payload_hex,
    }


def _diag(family: str, event: str, at: float, *, body: dict | None = None) -> dict:
    return {
        "schema": "diag_event_v1",
        "ts_utc": _ts(at),
        "family": family,
        "event": event,
        "severity": "info",
        "keys": {},
        "body": body or {},
    }


def _window(at: float = 0.0) -> dict:
    stamp = datetime(2026, 7, 4, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=at)
    return {"kind": "search", "t0": stamp, "t1": stamp + timedelta(seconds=10)}


def _sides(rust_pkt: list, mfc_pkt: list, rust_diag: list | None = None, mfc_diag: list | None = None) -> tuple[dict, dict]:
    rust = {"packets": rust_pkt, "diag": rust_diag or [], "markers": [], "meta": {}}
    mfc = {"packets": mfc_pkt, "diag": mfc_diag or [], "markers": [], "meta": {}}
    return rust, mfc


def test_diag_family_gate_passes_across_independent_sessions() -> None:
    # Same diag schema on both sides but different record identities: the strict
    # match can never pass; the per-family oracle gate is the reported verdict.
    mod = _load_offline_diff()
    rust_pkt = [
        _pkt("server", "send", 0x16, "aa11", 1.0),
        _pkt("server", "recv", 0x33, "bb", 2.0),
    ]
    mfc_pkt = [
        _pkt("server", "send", 0x16, "cc22", 1.5),
        _pkt("server", "recv", 0x33, "dd", 2.5),
    ]
    rust_diag = [_diag("kad_event", "lookup", 1.0, body={"milestone": "lookup_complete", "resultCount": 3})]
    mfc_diag = [_diag("kad_event", "lookup", 1.2, body={"milestone": "lookup_complete", "resultCount": 9})]
    rust, mfc = _sides(rust_pkt, mfc_pkt, rust_diag, mfc_diag)

    result = mod._diff_one_action("search", rust, mfc, _window(), _window(), lead=2.0, settle=5.0)

    assert result["diagFamilyOk"] is True
    assert result["diagStrictMatchOk"] is False  # informational: never true live
    assert result["verdict"] == "conformant"


def test_diag_family_gate_fails_on_missing_oracle_body_key() -> None:
    mod = _load_offline_diff()
    rust_diag = [_diag("kad_event", "lookup", 1.0, body={"milestone": "lookup_complete"})]
    mfc_diag = [
        _diag("kad_event", "lookup", 1.2, body={"milestone": "lookup_complete", "resultCount": 9})
    ]
    rust, mfc = _sides(
        [_pkt("server", "send", 0x16, "aa", 1.0)],
        [_pkt("server", "send", 0x16, "bb", 1.0)],
        rust_diag,
        mfc_diag,
    )

    result = mod._diff_one_action("search", rust, mfc, _window(), _window(), lead=2.0, settle=5.0)

    assert result["diagFamilyOk"] is False
    assert result["verdict"] == "divergence"


def test_action_windows_capture_marker_method() -> None:
    mod = _load_offline_diff()
    markers = [
        {"actionId": "search-kad-ubuntu", "kind": "search", "method": "kad", "marker": "begin", "ts_utc": _ts(0)},
        {"actionId": "search-kad-ubuntu", "kind": "search", "method": "kad", "marker": "end", "ts_utc": _ts(5)},
    ]
    windows = mod._action_windows(markers)
    assert windows["search-kad-ubuntu"]["method"] == "kad"
    assert mod._action_method("search-kad-ubuntu", windows["search-kad-ubuntu"]) == "kad"


def test_action_method_falls_back_to_action_id_for_old_recordings() -> None:
    mod = _load_offline_diff()
    assert mod._action_method("search-global-ubuntu", {}) == "global"
    assert mod._action_method("download-abcd1234", {}) is None


def test_global_search_action_not_failed_by_missing_mfc_udp_hook() -> None:
    # MFC's capture has no server-UDP hook, so a global search must not be
    # structurally impossible: rust's OP_GLOBSEARCHREQ send carries the gate.
    mod = _load_offline_diff()
    rust_pkt = [_pkt("server", "send", 0x98, "aa11", 1.0)]
    mfc_pkt = [_pkt("server", "send", 0x14, "bb", 1.0)]
    rust, mfc = _sides(rust_pkt, mfc_pkt)
    result = mod._diff_one_action(
        "search", rust, mfc, _window(), _window(), lead=2.0, settle=5.0, method="global"
    )
    assert result["method"] == "global"
    assert result["coverageOk"] is True


def test_kad_search_action_assessed_from_kad_stream() -> None:
    mod = _load_offline_diff()

    def _kad(opcode: int, at: float) -> dict:
        return {
            "schema": "diag_event_v1",
            "ts_utc": _ts(at),
            "family": "kad_udp",
            "event": "packet",
            "keys": {"opcode": opcode},
            "body": {"direction": "send", "opcode": opcode},
        }

    rust, mfc = _sides(
        [_pkt("client", "send", 0x99, "aa", 1.0)],
        [_pkt("client", "send", 0x99, "bb", 1.0)],
        [_kad(0x33, 1.0)],
        [_kad(0x33, 1.5)],
    )
    result = mod._diff_one_action(
        "search", rust, mfc, _window(), _window(), lead=2.0, settle=5.0, method="kad"
    )
    assert result["coverageOk"] is True


def test_no_window_result_carries_gate_keys() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides([], [])
    incomplete = {"kind": "search", "t0": _window()["t0"]}
    result = mod._diff_one_action(
        "search", rust, mfc, incomplete, _window(), lead=1.0, settle=1.0
    )
    assert result["verdict"] == "no-window"
    assert result["diagFamilyOk"] is False
    assert result["diagStrictMatchOk"] is False


def test_no_traffic_is_not_conformant() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides([], [])

    result = mod._diff_one_action(
        "search", rust, mfc, _window(), _window(), lead=1.0, settle=1.0
    )

    assert result["verdict"] == "no-traffic"
    assert result["conformant"] is False


def test_end_marker_action_error_fails_action_without_diffing() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides([], [])
    rust_window = {**_window(), "status": "error"}

    result = mod._diff_one_action(
        "search", rust, mfc, rust_window, _window(), lead=1.0, settle=1.0
    )

    assert result["verdict"] == "action-error"
    assert result["conformant"] is False


def _completion_meta(*, digest: str, size: int = 3, expected_count: int = 1) -> dict:
    return {
        "nativeCompletionEvidence": {
            "required": True,
            "expectedCount": expected_count,
            "files": [
                {
                    "actionId": "action-0001",
                    "sizeBytes": size,
                    "sizeVerified": True,
                    "ed2kVerified": True,
                    "sha256": digest,
                }
            ],
        }
    }


def test_native_completion_comparison_is_opt_in_for_old_recordings() -> None:
    mod = _load_offline_diff()
    result = mod._compare_native_completions({}, {})
    assert result == {
        "required": False,
        "ok": None,
        "expectedCount": None,
        "matchedCount": 0,
        "findings": [],
    }


def test_native_completion_comparison_matches_without_emitting_digest() -> None:
    mod = _load_offline_diff()
    digest = "a" * 64

    result = mod._compare_native_completions(
        _completion_meta(digest=digest), _completion_meta(digest=digest)
    )

    assert result["ok"] is True
    assert result["matchedCount"] == 1
    assert digest not in json.dumps(result)


def test_native_completion_comparison_reports_digest_mismatch_without_values() -> None:
    mod = _load_offline_diff()
    rust_digest = "a" * 64
    mfc_digest = "b" * 64

    result = mod._compare_native_completions(
        _completion_meta(digest=rust_digest), _completion_meta(digest=mfc_digest)
    )

    assert result["ok"] is False
    assert result["findings"] == ["completion-sha256-mismatch"]
    emitted = json.dumps(result)
    assert rust_digest not in emitted and mfc_digest not in emitted


def test_native_capture_evidence_requires_frames_and_matching_archive_size() -> None:
    mod = _load_offline_diff()
    recording = {
        "nativeCaptureSizes": [4096],
        "meta": {
            "nativeCapture": {
                "created": True,
                "fileByteCount": 4096,
                "frameCount": 12,
                "relevantFrameCount": 9,
                "capturedByteCount": 2048,
                "sizeLimitReached": False,
            }
        },
    }

    assert mod._native_capture_evidence(recording) == {
        "ok": True,
        "frameCount": 12,
        "relevantFrameCount": 9,
        "capturedByteCount": 2048,
        "findings": [],
    }
    recording["meta"]["nativeCapture"]["frameCount"] = 0
    result = mod._native_capture_evidence(recording)
    assert result["ok"] is False
    assert "native-capture-no-frames" in result["findings"]


@pytest.mark.parametrize(
    ("overrides", "expected_verdict", "expected_exit"),
    [
        ({}, "parity", 0),
        ({"conformance_ok": False}, "divergence", 1),
        ({"state_machine_ok": False}, "divergence", 1),
        ({"missing_action_count": 1}, "harness-failure", 2),
        ({"external_inconclusive": True}, "inconclusive-external", 3),
    ],
)
def test_campaign_verdict_taxonomy_and_exit_codes(
    overrides: dict, expected_verdict: str, expected_exit: int
) -> None:
    mod = _load_offline_diff()
    inputs = {
        "per_action": [{"verdict": "conformant", "coverageOk": True}],
        "missing_action_count": 0,
        "action_error_count": 0,
        "completion": {"required": False, "ok": None},
        "scenario_mismatch": False,
        "conformance_ok": True,
        "kad_coverage_ok": True,
        "secident_dead": False,
        "external_inconclusive": False,
    }
    inputs.update(overrides)

    result = mod._campaign_verdict(**inputs)

    assert result["verdict"] == expected_verdict
    assert result["exitCode"] == expected_exit


def test_action_errors_and_required_completion_failure_are_harness_failures() -> None:
    mod = _load_offline_diff()
    recording = {"meta": {"actionResults": [{"actionId": "action-0001", "status": "error"}]}}
    assert mod._action_error_count(recording) == 1

    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=1,
        completion={"required": True, "ok": False},
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )
    assert result["verdict"] == "harness-failure"
    assert set(result["findings"]) == {"action-errors", "completion-evidence-failed"}


def test_external_completion_shortfall_is_inconclusive_not_pass_or_harness_failure() -> None:
    mod = _load_offline_diff()
    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={
            "required": True,
            "ok": False,
            "findings": [
                "rust-completion-count-mismatch",
                "completion-action-set-mismatch",
                "completion-incomplete",
            ],
        },
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=True,
    )

    assert result["verdict"] == "inconclusive-external"
    assert result["exitCode"] == 3


def test_invalid_completed_payload_is_divergence() -> None:
    mod = _load_offline_diff()
    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={"required": True, "ok": False, "findings": ["completion-invalid"]},
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )

    assert result["verdict"] == "divergence"
    assert result["exitCode"] == 1


def test_native_action_contract_rejects_symmetric_missing_action() -> None:
    mod = _load_offline_diff()
    markers: list[dict] = []
    results: list[dict] = []
    methods = ("server", "global", "kad")
    for index in range(1, 5):
        action_id = f"action-{index:04d}"
        kind = "search" if index <= 3 else "download"
        extra = {"method": methods[index - 1]} if kind == "search" else {}
        markers.append({"actionId": action_id, "kind": kind, "marker": "begin", **extra})
        markers.append(
            {
                "actionId": action_id,
                "kind": kind,
                "marker": "end",
                "terminal": kind == "download",
                **extra,
            }
        )
        results.append({"actionId": action_id, "status": "ok"})
    recording = {
        "markers": markers,
        "meta": {
            "nativeInputSummary": {"ed2k_link_count": 1},
            "actionResults": results,
        },
    }

    assert mod._native_action_contract(recording)["ok"] is True
    recording["markers"] = [row for row in markers if row["actionId"] != "action-0002"]
    recording["meta"]["actionResults"] = results[:1] + results[2:]
    assert mod._native_action_contract(recording)["ok"] is False


def test_completed_payload_digest_mismatch_is_protocol_divergence() -> None:
    mod = _load_offline_diff()
    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={
            "required": True,
            "ok": False,
            "findings": ["completion-sha256-mismatch"],
        },
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )

    assert result["verdict"] == "divergence"
    assert result["exitCode"] == 1


def test_declared_secident_reads_recorded_campaign_state() -> None:
    mod = _load_offline_diff()
    assert mod._declared_secident({"secident": {"requested": "on", "applied": "on"}}) is True
    assert mod._declared_secident({"secident": {"requested": "off", "applied": "off"}}) is False
    assert mod._declared_secident({"secident": {"requested": "on", "applied": "always-on"}}) is True
    assert mod._declared_secident({}) is None  # pre-knob recording


def test_audit_secident_flags_dead_mfc_side() -> None:
    mod = _load_offline_diff()
    # MFC claims secident on but produced steady peer traffic with zero
    # 0x85/86/87 packets -> the offline report must flag secident-dead.
    mfc_packets = [
        {**_pkt("client", "send", 0x58, "aa", float(i)), "protocol_marker": 0xE3}
        for i in range(30)
    ]
    rust, mfc = _sides([], mfc_packets)
    mfc["meta"] = {"secident": {"requested": "on", "applied": "on"}}
    report = mod._audit_secident(rust, mfc)
    assert report["mfc"]["verdict"] == "secident-dead"
    assert report["rust"]["verdict"] == "not-assessable"  # nothing recorded rust-side
