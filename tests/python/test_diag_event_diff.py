from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness.diag_event_diff import (
    diff_traces,
    ed2k_tcp_packet_view,
    ed2k_tcp_packet_views,
    family_conformance,
    full_run_conformance,
    load_trace,
    load_traces,
)
from emule_test_harness.diag_event_schema import ED2K_TCP_PACKET_VIEW_SCHEMA
from emule_test_harness.diag_event_runs import DiagnosticTraceError


def _env(family, event, *, keys=None, body=None, severity="info"):
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "ts": "2026-06-16T00:00:00.000Z",
        "seq": 1,
        "family": family,
        "event": event,
        "severity": severity,
        "keys": keys or {},
        "body": body or {},
    }


def _pkt(family, direction, opcode, payload, *, marker=227):
    hexfield = "decodedHex" if family == "kad_udp" else "payloadHex"
    return _env(
        family,
        "packet",
        keys={"peer": "10.0.0.1:4661", "opcode": opcode, "protocolMarker": marker},
        body={
            "direction": direction,
            "opcode": opcode,
            "opcodeName": f"OP_{opcode:02X}",
            "protocolMarker": marker,
            hexfield: payload,
            "payloadLen": len(payload) // 2,
        },
    )


def test_server_udp_uses_packet_diff_strategy() -> None:
    rust = [_pkt("ed2k_server_udp", "send", 0xA2, "0011")]
    mfc = [_pkt("ed2k_server_udp", "send", 0xA2, "0011")]

    report = diff_traces(rust, mfc)

    assert report["ok"] is True
    assert report["families"] == [
        {
            "family": "ed2k_server_udp",
            "strategy": "wire_identity",
            "ok": True,
            "totals": {
                "matched": 1,
                "payloadMismatches": 0,
                "onlyRust": 0,
                "onlyMfc": 0,
            },
            "directions": [
                {
                    "direction": "send",
                    "rustCount": 1,
                    "mfcCount": 1,
                    "matched": 1,
                    "payloadMismatchCount": 0,
                    "payloadMismatches": [],
                    "onlyRustCount": 0,
                    "onlyRust": [],
                    "onlyMfcCount": 0,
                    "onlyMfc": [],
                }
            ],
        }
    ]


def _peer_tcp_packet_event(event: str = "packet") -> dict:
    record = _env(
        "ed2k_tcp",
        event,
        keys={
            "peer": "198.51.100.2:4662",
            "protocolMarker": 0xE3,
            "opcode": 0x01,
            "peerHash": "00112233445566778899aabbccddeeff",
            "fileHash": "ffeeddccbbaa99887766554433221100",
            "sendAttemptId": 17,
        },
        body={
            "direction": "send",
            "outcome": "attempted",
            "flow": "native_upload",
            "phase": "hello",
            "transportMode": "obfuscated",
            "obfuscated": True,
            "protocolMarker": 0xE3,
            "protocolName": "ed2k",
            "opcode": 0x01,
            "opcodeName": "OP_HELLO",
            "rawLen": 8,
            "rawHex": "aabbccddeeff0011",
            "clearFrameLen": 8,
            "clearFrameHex": "e30200000001aabb",
            "attemptedLen": 8,
            "writtenLen": 8,
            "payloadLen": 2,
            "payloadHex": "aabb",
            "payloadHexTruncated": False,
            "traceKey": "native_upload:198.51.100.2:4662",
            "stateId": "native_upload.hello",
            "stateLabel": "hello",
            "sendAttemptId": 17,
            "note": "queued",
        },
    )
    record["streamSeq"] = 23
    return record


def _client_udp_packet(
    direction: str,
    raw_hex: str,
    *,
    opcode: int | None = 0x90,
    outcome: str = "accepted",
    attempt_id: int | None = None,
    role: str | None = None,
):
    keys = {"peer": "10.0.0.1:4672"}
    body = {
        "direction": direction,
        "outcome": outcome,
        "rawHex": raw_hex,
        "rawLen": len(raw_hex) // 2,
    }
    if opcode is not None:
        keys.update({"opcode": opcode, "protocolMarker": 0xC5})
        body.update(
            {
                "opcode": opcode,
                "opcodeName": f"OP_{opcode:02X}",
                "protocolMarker": 0xC5,
            }
        )
    if attempt_id is not None:
        keys["sendAttemptId"] = attempt_id
        body["sendAttemptId"] = attempt_id
    if role is not None:
        body["role"] = role
    return _env("ed2k_client_udp", "packet", keys=keys, body=body)


def _client_udp_terminal(
    attempt_id: int,
    outcome: str = "send_succeeded",
    *,
    delivery_known: bool | None = None,
):
    if delivery_known is None:
        delivery_known = outcome != "send_cancelled"
    return _env(
        "ed2k_client_udp",
        "send_outcome",
        keys={
            "peer": "10.0.0.1:4672",
            "opcode": 0x90,
            "protocolMarker": 0xC5,
            "sendAttemptId": attempt_id,
        },
        body={
            "direction": "send",
            "outcome": outcome,
            "deliveryKnown": delivery_known,
            "sendAttemptId": attempt_id,
            "role": "reask_request",
            "opcode": 0x90,
        },
    )


def _family(report, name):
    return next(f for f in report["families"] if f["family"] == name)


# --- packet families (wire identity) --------------------------------------- #


def test_ed2k_tcp_packets_extracts_complete_packet_shape() -> None:
    expected = {
            "schema": ED2K_TCP_PACKET_VIEW_SCHEMA,
            "source": "rust",
            "ts_utc": "2026-06-16T00:00:00.000Z",
            "event_seq": 23,
            "trace_key": "native_upload:198.51.100.2:4662",
            "state_id": "native_upload.hello",
            "state_label": "hello",
            "flow": "native_upload",
            "phase": "hello",
            "direction": "send",
            "outcome": "attempted",
            "remote_addr": "198.51.100.2:4662",
            "peer_hash": "00112233445566778899aabbccddeeff",
            "file_hash": "ffeeddccbbaa99887766554433221100",
            "transport_mode": "obfuscated",
            "obfuscated": True,
            "protocol": "ed2k",
            "protocol_marker": 0xE3,
            "opcode": 0x01,
            "opcode_name": "OP_HELLO",
            "raw_len": 8,
            "raw_hex": "aabbccddeeff0011",
            "clear_frame_len": 8,
            "clear_frame_hex": "e30200000001aabb",
            "attempted_len": 8,
            "written_len": 8,
            "payload_len": 2,
            "payload_hex": "aabb",
            "payload_hex_truncated": False,
            "note": "queued",
            "send_attempt_id": 17,
    }

    record = _peer_tcp_packet_event()
    assert ed2k_tcp_packet_view(record) == expected
    assert ed2k_tcp_packet_views([record]) == [expected]


def test_ed2k_tcp_packets_accepts_mfc_packet_without_rust_only_context() -> None:
    record = _peer_tcp_packet_event()
    record["client"] = "mfc"
    record["keys"].pop("sendAttemptId")
    record["body"].pop("rawLen")
    record["body"].pop("rawHex")
    for key in (
        "attemptedLen",
        "writtenLen",
        "sendAttemptId",
        "note",
    ):
        record["body"].pop(key)

    packet = ed2k_tcp_packet_view(record)

    assert packet is not None
    assert packet["source"] == "mfc"
    assert packet["payload_hex"] == "aabb"
    assert packet["raw_hex"] is None
    assert packet["clear_frame_hex"] == "e30200000001aabb"
    assert packet["peer_hash"] == "00112233445566778899aabbccddeeff"
    assert packet["file_hash"] == "ffeeddccbbaa99887766554433221100"
    assert "send_attempt_id" not in packet


def test_ed2k_tcp_packets_require_wire_bytes_for_plaintext() -> None:
    record = _peer_tcp_packet_event()
    record["body"]["transportMode"] = "plaintext"
    record["body"]["obfuscated"] = False
    record["body"].pop("rawLen")
    record["body"].pop("rawHex")

    assert ed2k_tcp_packet_view(record) is None


def test_ed2k_tcp_packets_reject_invalid_join_hashes() -> None:
    record = _peer_tcp_packet_event()
    record["keys"]["peerHash"] = "NOT-A-HASH"

    assert ed2k_tcp_packet_view(record) is None


@pytest.mark.parametrize("event", ["state", "send_outcome", "obfuscation_handshake"])
def test_ed2k_tcp_packets_rejects_non_packet_events(event: str) -> None:
    record = _peer_tcp_packet_event(event)
    assert ed2k_tcp_packet_view(record) is None
    assert ed2k_tcp_packet_views([record]) == []


def test_ed2k_tcp_packets_rejects_malformed_packet_records() -> None:
    malformed = _peer_tcp_packet_event()
    malformed["body"]["payloadLen"] = 3

    assert ed2k_tcp_packet_view(malformed) is None
    assert ed2k_tcp_packet_views([malformed]) == []


def test_identical_packet_traces_match() -> None:
    rust = [_pkt("ed2k_tcp", "recv", 0x01, "aabb"), _pkt("ed2k_tcp", "send", 0x4c, "ccdd")]
    report = diff_traces(rust, list(rust))
    assert report["ok"] is True
    fam = _family(report, "ed2k_tcp")
    assert fam["totals"]["matched"] == 2
    assert fam["totals"]["payloadMismatches"] == 0
    assert report["schema"] == "diag_event_diff_v2"


def test_packet_difference_details_are_bounded_with_exact_counts() -> None:
    rust = [_pkt("ed2k_tcp", "recv", opcode, "aabb") for opcode in range(64)]

    family = _family(diff_traces(rust, []), "ed2k_tcp")
    direction = family["directions"][0]

    assert family["totals"]["onlyRust"] == 64
    assert direction["onlyRustCount"] == 64
    assert len(direction["onlyRust"]) == 32
    assert diff_traces(rust, [])["detailLimit"] == 32


def test_diff_rejects_legacy_schema() -> None:
    legacy = _pkt("ed2k_tcp", "recv", 0x01, "aabb")
    legacy["schema"] = "diag_event_v1"
    with pytest.raises(ValueError, match="expected 'diag_event_v2'"):
        diff_traces([legacy], [])


def test_empty_diagnostics_are_not_successful_evidence() -> None:
    assert diff_traces([], [])["ok"] is False
    assert family_conformance([], [])["ok"] is False


def test_packet_same_opcode_different_payload_is_mismatch() -> None:
    rust = [_pkt("ed2k_tcp", "send", 0x01, "aabb")]
    mfc = [_pkt("ed2k_tcp", "send", 0x01, "aaff")]
    report = diff_traces(rust, mfc)
    assert report["ok"] is False
    fam = _family(report, "ed2k_tcp")
    assert fam["totals"]["payloadMismatches"] == 1
    assert fam["directions"][0]["payloadMismatches"][0]["opcode"] == 0x01


def test_packet_one_sided_reported() -> None:
    rust = [_pkt("ed2k_tcp", "recv", 0x01, "aabb"), _pkt("ed2k_tcp", "recv", 0x99, "1234")]
    mfc = [_pkt("ed2k_tcp", "recv", 0x01, "aabb")]
    report = diff_traces(rust, mfc)
    assert report["ok"] is False
    fam = _family(report, "ed2k_tcp")
    assert fam["totals"]["matched"] == 1
    assert fam["totals"]["onlyRust"] == 1
    assert fam["totals"]["onlyMfc"] == 0


def test_kad_udp_uses_decoded_hex_identity() -> None:
    # Same decoded bytes but different obfuscated wire bytes still match.
    rust = [{**_pkt("kad_udp", "recv", 0x10, "dead"), "body": {
        "direction": "recv", "opcode": 0x10, "protocolMarker": 227,
        "decodedHex": "dead", "wireHex": "1111", "payloadLen": 2}}]
    mfc = [{**_pkt("kad_udp", "recv", 0x10, "dead"), "body": {
        "direction": "recv", "opcode": 0x10, "protocolMarker": 227,
        "decodedHex": "dead", "wireHex": "2222", "payloadLen": 2}}]
    report = diff_traces(rust, mfc)
    assert report["ok"] is True
    assert _family(report, "kad_udp")["totals"]["matched"] == 1


def test_packet_meta_records_ignored() -> None:
    rust = [_env("ed2k_tcp", "packet", keys={"peer": "10.0.0.1:1"},
                 body={"direction": "meta", "note": "connect"})]
    report = diff_traces(rust, [])
    assert report["ok"] is True
    assert _family(report, "ed2k_tcp")["totals"]["matched"] == 0


# --- eD2K client UDP mixed packet/lifecycle family ------------------------- #


def test_client_udp_uses_dedicated_mixed_strategy() -> None:
    trace = [
        _client_udp_packet(
            "send",
            "c590aabb",
            outcome="attempted",
            attempt_id=7,
            role="reask_request",
        ),
        _client_udp_terminal(7),
        _client_udp_packet("recv", "c5910001", outcome="accepted"),
    ]

    report = diff_traces(trace, list(trace))
    family = _family(report, "ed2k_client_udp")

    assert report["ok"] is True
    assert family["strategy"] == "client_udp_mixed"
    assert family["packets"]["totals"]["matched"] == 2
    assert family["lifecycle"]["rust"]["attemptCount"] == 1
    assert family["lifecycle"]["rust"]["terminalCount"] == 1


def test_client_udp_packet_identity_uses_raw_hex_without_opcode() -> None:
    rust = [_client_udp_packet("recv", "112233", opcode=None, outcome="dropped")]
    mfc = [_client_udp_packet("recv", "112244", opcode=None, outcome="dropped")]

    family = _family(diff_traces(rust, mfc), "ed2k_client_udp")

    assert family["ok"] is False
    assert family["packets"]["totals"]["wireMismatches"] == 1


@pytest.mark.parametrize(
    ("trace", "violation"),
    [
        ([_client_udp_terminal(1)], "orphan_terminal"),
        (
            [
                _client_udp_packet(
                    "send",
                    "c590",
                    outcome="attempted",
                    attempt_id=1,
                    role="reask_request",
                )
            ],
            "missing_terminal",
        ),
        (
            [
                _client_udp_packet(
                    "send",
                    "c590",
                    outcome="attempted",
                    attempt_id=1,
                    role="reask_request",
                ),
                _client_udp_terminal(1),
                _client_udp_terminal(1),
            ],
            "duplicate_terminal",
        ),
        (
            [
                _client_udp_packet(
                    "send",
                    "c590",
                    outcome="attempted",
                    attempt_id=1,
                    role="reask_request",
                ),
                _client_udp_terminal(1, "send_cancelled", delivery_known=True),
            ],
            "invalid_delivery_known",
        ),
    ],
)
def test_client_udp_rejects_broken_send_lifecycles(trace, violation) -> None:
    family = _family(diff_traces(trace, list(trace)), "ed2k_client_udp")

    assert family["ok"] is False
    assert violation in {
        item["kind"] for item in family["lifecycle"]["rust"]["violations"]
    }


# --- event families (multiset) --------------------------------------------- #


def test_kad_event_multiset_match() -> None:
    rust = [_env("kad_event", "bootstrap", keys={"nodeId": "ab"},
                 body={"milestone": "bootstrap_contact_added", "action": "observe"})]
    mfc = [_env("kad_event", "bootstrap", keys={"nodeId": "ab"},
                body={"milestone": "bootstrap_contact_added", "action": "observe",
                      "reason": "client-specific-ignored"})]
    report = diff_traces(rust, mfc)
    assert report["ok"] is True
    assert _family(report, "kad_event")["totals"]["matched"] == 1


def test_bad_peer_difference_reported() -> None:
    rust = [_env("bad_peer", "repeat_block_request", keys={"peer": "10.0.0.2:5"},
                 body={"behavior": "repeat", "repeatCount": 3})]
    mfc = [_env("bad_peer", "repeat_block_request", keys={"peer": "10.0.0.2:5"},
                body={"behavior": "repeat", "repeatCount": 9})]
    report = diff_traces(rust, mfc)
    assert report["ok"] is False
    fam = _family(report, "bad_peer")
    assert fam["totals"]["onlyRust"] == 1
    assert fam["totals"]["onlyMfc"] == 1


# --- sched (structural) ---------------------------------------------------- #


def _sched(event, outcome, *, peer="10.0.0.3:6", file_hash="ff", extra=None):
    body = {"outcome": outcome}
    if extra:
        body.update(extra)
    return _env("sched", event, keys={"peer": peer, "fileHash": file_hash}, body=body)


def test_sched_matching_transition_sequences_ok() -> None:
    seq = [_sched("upload_slot_opened", "opened"), _sched("upload_slot_closed", "closed")]
    report = diff_traces(list(seq), list(seq))
    assert report["ok"] is True
    fam = _family(report, "sched")
    assert fam["totals"]["sharedKeys"] == 1
    assert fam["totals"]["matchedKeys"] == 1


def test_sched_divergent_transitions_fail() -> None:
    rust = [_sched("upload_slot_opened", "opened"), _sched("upload_slot_closed", "closed")]
    mfc = [_sched("upload_slot_opened", "opened"), _sched("upload_slot_recycled", "recycled")]
    report = diff_traces(rust, mfc)
    assert report["ok"] is False
    assert _family(report, "sched")["totals"]["transitionDivergences"] == 1


def test_sched_keys_on_one_side_are_informational_not_failure() -> None:
    rust = [_sched("upload_slot_opened", "opened", peer="10.0.0.3:6")]
    mfc = [_sched("upload_slot_opened", "opened", peer="10.0.0.9:6")]
    report = diff_traces(rust, mfc)
    fam = _family(report, "sched")
    assert fam["totals"]["onlyRustKeys"] == 1
    assert fam["totals"]["onlyMfcKeys"] == 1
    assert fam["ok"] is True  # disjoint peers are not a failure


def test_sched_queue_rank_monotonic_invariant() -> None:
    rust = [
        _sched("queue_rank", "waiting", extra={"queueRank": 5}),
        _sched("queue_rank", "waiting", extra={"queueRank": 7}),  # rank went up
    ]
    report = diff_traces(rust, list(rust))
    fam = _family(report, "sched")
    assert fam["ok"] is False
    assert fam["totals"]["invariantViolations"] >= 1


def test_sched_deny_only_at_cap_invariant() -> None:
    rust = [_sched("conn_budget", "deny", extra={"activeConnections": 2, "connectionCap": 10})]
    report = diff_traces(rust, list(rust))
    fam = _family(report, "sched")
    assert fam["ok"] is False
    assert any(v["invariant"] == "deny_only_at_cap" for v in fam["invariantViolations"])


# --- loader + self-diff smoke --------------------------------------------- #


def test_load_trace_rejects_foreign_schema(tmp_path: Path) -> None:
    path = tmp_path / "dump.jsonl"
    lines = [
        json.dumps(_pkt("ed2k_tcp", "recv", 0x01, "aabb")),
        json.dumps({"schema": "ed2k_packet_v1", "opcode": 1}),
    ]
    path.write_text("\r\n".join(lines), encoding="utf-8")
    with pytest.raises(DiagnosticTraceError, match="unexpected diagnostic schema"):
        load_trace(path)


def test_load_trace_accepts_current_schema(tmp_path: Path) -> None:
    path = tmp_path / "dump.jsonl"
    record = _pkt("ed2k_tcp", "recv", 0x01, "aabb")
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    assert load_trace(path) == [record]


def test_load_traces_preserves_segment_order(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first_record = _pkt("ed2k_tcp", "recv", 0x01, "aabb")
    second_record = _pkt("ed2k_tcp", "recv", 0x02, "ccdd")
    first.write_text(json.dumps(first_record) + "\n", encoding="utf-8")
    second.write_text(json.dumps(second_record) + "\n", encoding="utf-8")

    assert load_traces([first, second]) == [first_record, second_record]


def test_self_diff_of_mixed_trace_is_ok() -> None:
    trace = [
        _pkt("ed2k_tcp", "recv", 0x01, "aabb"),
        _pkt("kad_udp", "send", 0x10, "dead"),
        _env("kad_event", "lookup", keys={"searchId": 7},
             body={"milestone": "lookup_complete", "resultCount": 3}),
        _sched("upload_slot_opened", "opened"),
        _sched("upload_slot_closed", "closed"),
    ]
    report = diff_traces(list(trace), list(trace))
    assert report["ok"] is True


def test_conformance_requires_unredacted_oracle_fields() -> None:
    from emule_test_harness.diag_event_diff import schema_audit

    common = {"schema": "diag_event_v2", "family": "bad_peer", "event": "repeat_block_request",
              "severity": "medium", "keys": {"peer": "1.2.3.4:5"}}
    rust = [{**common, "body": {"action": "observe", "behavior": "repeat_block_request"}}]
    mfc = [{**common, "body": {"action": "observe", "behavior": "repeat_block_request",
                               "fileName": "secret.mkv", "userName": "http://x"}}]
    audit = schema_audit(rust, mfc)
    assert audit["schema"] == "diag_event_schema_audit_v1"
    assert audit["conformance"]["conformant"] is False
    assert audit["conformance"]["bodyKeyViolations"] == [
        {
            "family": "bad_peer",
            "event": "repeat_block_request",
            "missingOracleKeys": ["fileName", "userName"],
        }
    ]


# --- family_conformance (per-action oracle gate) --------------------------- #


def test_family_conformance_passes_where_strict_diff_cannot() -> None:
    # Two independent live sessions: same event schema, totally different record
    # identities. The strict diff fails by construction; the per-family oracle
    # gate (rust event-type/body-key coverage ⊇ oracle) passes.
    from emule_test_harness.diag_event_diff import family_conformance

    rust = [
        _pkt("ed2k_tcp", "send", 0x16, "aa11"),
        _env("kad_event", "lookup", keys={"searchId": 1},
             body={"milestone": "lookup_complete", "resultCount": 5}),
    ]
    mfc = [
        _pkt("ed2k_tcp", "send", 0x16, "bb22"),
        _env("kad_event", "lookup", keys={"searchId": 9},
             body={"milestone": "lookup_complete", "resultCount": 2}),
    ]
    assert diff_traces(rust, mfc)["ok"] is False  # strict identity never matches
    gate = family_conformance(rust, mfc)
    assert gate["ok"] is True
    families = {f["family"]: f for f in gate["families"]}
    assert families["ed2k_tcp"]["presentOnBoth"] is True
    assert families["kad_event"]["ok"] is True


def test_family_conformance_fails_on_missing_oracle_body_key() -> None:
    from emule_test_harness.diag_event_diff import family_conformance

    rust = [_env("kad_event", "lookup", body={"milestone": "lookup_complete"})]
    mfc = [_env("kad_event", "lookup",
                body={"milestone": "lookup_complete", "resultCount": 4})]
    gate = family_conformance(rust, mfc)
    assert gate["ok"] is False
    fam = next(f for f in gate["families"] if f["family"] == "kad_event")
    assert fam["bodyKeyViolations"][0]["missingOracleKeys"] == ["resultCount"]


def test_family_conformance_ignores_packet_meta_body_key_gap() -> None:
    from emule_test_harness.diag_event_diff import family_conformance

    rust = [
        _env(
            "ed2k_tcp",
            "packet",
            keys={"peer": "10.0.0.1:1"},
            body={"direction": "meta", "flow": "listener", "note": "tcp_accept"},
        )
    ]
    mfc = [
        _env(
            "ed2k_tcp",
            "packet",
            keys={"peer": "10.0.0.2:2", "opcode": 1, "protocolMarker": 227},
            body={
                "direction": "recv",
                "opcode": 1,
                "opcodeName": "OP_HELLO",
                "protocolMarker": 227,
                "payloadHex": "aabb",
                "payloadLen": 2,
                "rawHex": "e30200000001aabb",
                "rawLen": 8,
            },
        )
    ]

    gate = family_conformance(rust, mfc)
    assert gate["ok"] is True
    fam = next(f for f in gate["families"] if f["family"] == "ed2k_tcp")
    assert fam["bodyKeyViolations"] == []
    assert fam["presentOnBoth"] is False


def test_family_conformance_fails_on_wire_packet_body_key_gap() -> None:
    from emule_test_harness.diag_event_diff import family_conformance

    rust = [_pkt("ed2k_tcp", "recv", 0x01, "aabb")]
    mfc = [
        _env(
            "ed2k_tcp",
            "packet",
            keys={"peer": "10.0.0.2:2", "opcode": 1, "protocolMarker": 227},
            body={
                "direction": "recv",
                "opcode": 1,
                "opcodeName": "OP_HELLO",
                "protocolMarker": 227,
                "payloadHex": "aabb",
                "payloadLen": 2,
                "rawHex": "e30200000001aabb",
                "rawLen": 8,
            },
        )
    ]

    gate = family_conformance(rust, mfc)
    assert gate["ok"] is False
    fam = next(f for f in gate["families"] if f["family"] == "ed2k_tcp")
    assert fam["bodyKeyViolations"][0]["missingOracleKeys"] == ["rawHex", "rawLen"]


def test_family_conformance_one_sided_families_are_informational() -> None:
    from emule_test_harness.diag_event_diff import family_conformance

    rust = [_env("sched", "upload_request_outcome", body={"outcome": "served"})]
    mfc = [_env("bad_peer", "spam_wave", body={"behavior": "spam"})]
    gate = family_conformance(rust, mfc)
    assert gate["ok"] is True  # neither family is present on both sides
    families = {f["family"]: f for f in gate["families"]}
    assert families["sched"]["presentOnBoth"] is False
    assert families["bad_peer"]["presentOnBoth"] is False


def test_family_conformance_can_require_full_run_family_presence() -> None:
    rust = [_env("sched", "upload_request_outcome", body={"outcome": "served"})]
    mfc = [_env("sched", "upload_request_outcome", body={"outcome": "served"})]

    gate = family_conformance(
        rust,
        mfc,
        required_families={"ed2k_client_udp"},
    )

    assert gate["ok"] is False
    assert gate["requiredFamiliesOk"] is False
    assert gate["requiredFamilies"] == [
        {
            "family": "ed2k_client_udp",
            "rustPresent": False,
            "mfcPresent": False,
            "ok": False,
        }
    ]


def test_full_run_conformance_requires_valid_client_udp_lifecycles() -> None:
    rust = [
        _peer_tcp_packet_event(),
        _client_udp_packet(
            "send",
            "c590",
            outcome="attempted",
            attempt_id=4,
            role="reask_request",
        )
    ]
    mfc = [
        _peer_tcp_packet_event(),
        _client_udp_packet(
            "send",
            "c590",
            outcome="attempted",
            attempt_id=9,
            role="reask_request",
        ),
        _client_udp_terminal(9),
    ]

    gate = full_run_conformance(rust, mfc)

    assert gate["ok"] is False
    assert gate["familyConformance"]["requiredFamiliesOk"] is True
    assert gate["clientUdpLifecycle"]["rust"]["violations"] == [
        {"kind": "missing_terminal", "sendAttemptId": 4}
    ]


def test_family_conformance_oracle_only_event_is_reported_not_failed() -> None:
    from emule_test_harness.diag_event_diff import family_conformance

    rust = [_env("kad_event", "lookup", body={"milestone": "lookup_complete"})]
    mfc = [
        _env("kad_event", "lookup", body={"milestone": "lookup_complete"}),
        _env("kad_event", "publish", body={"milestone": "publish_done"}),
    ]
    gate = family_conformance(rust, mfc)
    assert gate["ok"] is True
    fam = next(f for f in gate["families"] if f["family"] == "kad_event")
    assert fam["oracleOnlyEvents"] == ["publish"]
