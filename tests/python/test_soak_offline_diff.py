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


def test_no_window_result_carries_gate_keys() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides([], [])
    result = mod._diff_one_action("search", rust, mfc, {"kind": "search"}, {"kind": "search"}, lead=1.0, settle=1.0)
    assert result["verdict"] == "no-window"
    assert result["diagFamilyOk"] is False
    assert result["diagStrictMatchOk"] is False
