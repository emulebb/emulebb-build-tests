from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness.diag_event_diff import (
    diff_traces,
    family_conformance,
    load_trace,
    load_traces,
)
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


def test_identical_packet_traces_match() -> None:
    rust = [_pkt("ed2k_tcp", "recv", 0x01, "aabb"), _pkt("ed2k_tcp", "send", 0x4c, "ccdd")]
    report = diff_traces(rust, list(rust))
    assert report["ok"] is True
    fam = _family(report, "ed2k_tcp")
    assert fam["totals"]["matched"] == 2
    assert fam["totals"]["payloadMismatches"] == 0
    assert report["schema"] == "diag_event_diff_v1"


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
