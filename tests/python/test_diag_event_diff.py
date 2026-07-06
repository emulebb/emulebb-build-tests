from __future__ import annotations

import json
from pathlib import Path

from emule_test_harness.diag_event_diff import diff_traces, load_trace


def _env(family, event, *, keys=None, body=None, severity="info"):
    return {
        "schema": "diag_event_v1",
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


def test_load_trace_filters_foreign_schema(tmp_path: Path) -> None:
    path = tmp_path / "dump.jsonl"
    lines = [
        json.dumps(_pkt("ed2k_tcp", "recv", 0x01, "aabb")),
        json.dumps({"schema": "ed2k_packet_v1", "opcode": 1}),  # old schema, dropped
        "not json",
        "",
    ]
    path.write_text("\r\n".join(lines), encoding="utf-8")
    records = load_trace(path)
    assert len(records) == 1
    assert records[0]["family"] == "ed2k_tcp"


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


def test_conformance_ignores_deliberate_pii_omissions() -> None:
    # rust deliberately omits filenames/usernames for privacy; an oracle-only PII
    # body key must NOT count as a rust-superset-of-oracle conformance violation.
    from emule_test_harness.diag_event_diff import schema_audit

    common = {"schema": "diag_event_v1", "family": "bad_peer", "event": "repeat_block_request",
              "severity": "medium", "keys": {"peer": "1.2.3.4:5"}}
    rust = [{**common, "body": {"action": "observe", "behavior": "repeat_block_request"}}]
    mfc = [{**common, "body": {"action": "observe", "behavior": "repeat_block_request",
                               "fileName": "secret.mkv", "userName": "http://x"}}]
    audit = schema_audit(rust, mfc)
    assert audit["conformance"]["conformant"] is True


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
