"""Unit tests for the offline recording diff (scripts/soak-offline-diff.py)."""

from __future__ import annotations

import importlib.util
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
    result = mod._diff_one_action("search", rust, mfc, {"kind": "search"}, {"kind": "search"}, lead=1.0, settle=1.0)
    assert result["verdict"] == "no-window"
    assert result["diagFamilyOk"] is False
    assert result["diagStrictMatchOk"] is False


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
