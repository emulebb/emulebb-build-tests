"""Tests for the MFC bad_peer_event_v1 -> diag_event_v1 adapter."""

from __future__ import annotations

from emule_test_harness import mfc_diag_adapter as ad


def test_adapt_repeat_block_request_maps_name_keys_body() -> None:
    record = {
        "schema": "bad_peer_event_v1",
        "event": "upload_repeat_block_request_observed",
        "severity": "medium",
        "peer": {"address": "1.2.3.4", "user_port": 4662, "user_hash": "ABCD"},
        "file": {"hash": "E9E1"},
        "action": "observe",
        "evidence": {
            "repeat_count": 2,
            "window_seconds": 3600,
            "start_offset": 10,
            "end_offset": 20,
            "part_index": 1,
        },
    }
    out = ad.adapt_bad_peer_record(record)
    assert out["schema"] == "diag_event_v1"
    assert out["family"] == "bad_peer"
    assert out["event"] == "repeat_block_request"
    assert out["severity"] == "medium"
    # peerHash/fileHash lowered to match rust + the sched-family convention.
    assert out["keys"] == {"peer": "1.2.3.4:4662", "peerHash": "abcd", "fileHash": "e9e1"}
    assert out["body"]["behavior"] == "repeat_block_request"
    assert out["body"]["action"] == "observe"
    assert out["body"]["repeatCount"] == 2
    assert out["body"]["windowSeconds"] == 3600
    assert out["body"]["startOffset"] == 10
    assert out["body"]["endOffset"] == 20
    assert out["body"]["partIndex"] == 1


def test_unmapped_mfc_event_passes_through_as_oracle_gap() -> None:
    # A MFC bad-peer event with no rust counterpart keeps its name so the diff
    # surfaces it as an oracle-only event (a genuine rust coverage gap).
    record = {
        "schema": "bad_peer_event_v1",
        "event": "upload_slow_rate_recycle",
        "severity": "medium",
        "peer": {},
        "file": {},
        "action": "cooldown",
        "evidence": {},
    }
    out = ad.adapt_bad_peer_record(record)
    assert out["event"] == "upload_slow_rate_recycle"
    assert out["body"]["action"] == "cooldown"
    assert "behavior" not in out["body"]


def test_download_first_payload_timeout_name_preserved() -> None:
    record = {
        "schema": "bad_peer_event_v1",
        "event": "download_first_payload_timeout",
        "severity": "medium",
        "peer": {"address": "5.6.7.8", "user_port": 1, "user_hash": "FF"},
        "file": {"hash": "AA"},
        "action": "cancel_transfer",
        "evidence": {"idle_ms": 60000},
    }
    out = ad.adapt_bad_peer_record(record)
    assert out["event"] == "download_first_payload_timeout"
    assert out["body"]["action"] == "cancel_transfer"


def test_bad_peer_events_as_diag_v1_reads_jsonl(tmp_path) -> None:
    import json

    log = tmp_path / "emulebb-diagnostics-bad-peer.log"
    rows = [
        {"schema": "bad_peer_event_v1", "event": "download_idle_timeout", "severity": "medium",
         "peer": {"address": "9.9.9.9", "user_port": 5, "user_hash": "AB"}, "file": {"hash": "CD"},
         "action": "cancel_transfer", "evidence": {}},
        {"schema": "other", "event": "ignored"},  # non-bad_peer lines skipped
    ]
    log.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    out = ad.bad_peer_events_as_diag_v1([log])
    assert len(out) == 1
    assert out[0]["event"] == "download_idle_timeout"
