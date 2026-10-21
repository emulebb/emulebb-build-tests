from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness.packet_trace_diff import (
    decode_found_sources_record,
    diff_traces,
    load_trace,
    reflected_self_source_evidence,
)


def _pkt(flow, direction, opcode, payload_hex, *, marker=229, name=None):
    return {
        "schema": "ed2k_packet_v1",
        "flow": flow,
        "direction": direction,
        "protocol_marker": marker,
        "opcode": opcode,
        "opcode_name": name or f"OP_{opcode:02X}",
        "payload_len": len(payload_hex) // 2,
        "payload_hex": payload_hex,
    }


def test_identical_traces_match() -> None:
    rust = [
        _pkt("client", "recv", 0x01, "aabb"),
        _pkt("client", "send", 0x4c, "ccdd"),
    ]
    emule = [
        _pkt("client", "recv", 0x01, "aabb"),
        _pkt("client", "send", 0x4c, "ccdd"),
    ]
    report = diff_traces(rust, emule)
    assert report["ok"] is True
    assert report["totals"]["matched"] == 2
    assert report["totals"]["payload_mismatches"] == 0
    assert report["totals"]["only_rust"] == 0
    assert report["totals"]["only_emule"] == 0


def test_same_opcode_different_payload_is_a_mismatch() -> None:
    rust = [_pkt("client", "send", 0x01, "aabb")]
    emule = [_pkt("client", "send", 0x01, "aaff")]
    report = diff_traces(rust, emule)
    assert report["ok"] is False
    assert report["totals"]["payload_mismatches"] == 1
    assert report["totals"]["only_rust"] == 0
    assert report["totals"]["only_emule"] == 0
    mismatch = report["flows"][0]["payload_mismatches"][0]
    assert mismatch["opcode"] == 0x01


def test_one_sided_packets_are_reported() -> None:
    rust = [
        _pkt("client", "recv", 0x01, "aabb"),
        _pkt("client", "recv", 0x99, "1234"),  # only rust
    ]
    emule = [_pkt("client", "recv", 0x01, "aabb")]
    report = diff_traces(rust, emule)
    assert report["ok"] is False
    assert report["totals"]["matched"] == 1
    assert report["totals"]["only_rust"] == 1
    assert report["totals"]["only_emule"] == 0
    assert report["flows"][0]["only_rust"][0]["opcode"] == 0x99


def test_naming_and_transport_vocab_do_not_affect_match() -> None:
    # Same wire bytes but different opcode_name tables / transport vocab still match.
    rust = [{**_pkt("client", "recv", 0x01, "aabb", name="OP_HELLO"), "transport_mode": "obfuscated"}]
    emule = [{**_pkt("client", "recv", 0x01, "aabb", name="OP_Hello"), "transport_mode": "user_hash"}]
    report = diff_traces(rust, emule)
    assert report["ok"] is True
    assert report["totals"]["matched"] == 1


def test_load_trace_filters_non_packet_records(tmp_path: Path) -> None:
    path = tmp_path / "dump.jsonl"
    lines = [
        json.dumps(_pkt("client", "recv", 0x01, "aabb")),
        json.dumps({"schema": "ed2k_packet_v1", "direction": "meta", "note": "x"}),  # meta, dropped
        json.dumps({"schema": "other_v1", "direction": "recv", "opcode": 1}),  # wrong schema
        "not json",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    records = load_trace(path)
    assert len(records) == 1
    assert records[0]["opcode"] == 0x01


def test_decode_found_sources_record_supports_classic_and_obfuscated_replies() -> None:
    file_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    classic_payload = file_hash + b"\x01" + bytes([192, 0, 2, 10]) + (4662).to_bytes(2, "little")
    obfuscated_payload = (
        file_hash
        + b"\x01"
        + bytes([192, 0, 2, 11])
        + (4663).to_bytes(2, "little")
        + b"\x80"
        + bytes([0xAA]) * 16
    )

    classic = decode_found_sources_record(_pkt("server", "recv", 0x42, classic_payload.hex()))
    obfuscated = decode_found_sources_record(_pkt("server", "recv", 0x44, obfuscated_payload.hex()))

    assert classic == {
        "file_hash": file_hash.hex().upper(),
        "source_count": 1,
        "sources": [{"address": "192.0.2.10", "port": 4662}],
    }
    assert obfuscated == {
        "file_hash": file_hash.hex().upper(),
        "source_count": 1,
        "sources": [{"address": "192.0.2.11", "port": 4663}],
    }


def test_decode_found_sources_record_rejects_truncated_records() -> None:
    payload = bytes.fromhex("00112233445566778899AABBCCDDEEFF") + b"\x01\x7f"

    with pytest.raises(ValueError, match="source record is truncated"):
        decode_found_sources_record(_pkt("server", "recv", 0x42, payload.hex()))


def test_reflected_self_source_evidence_requires_request_and_expected_publisher() -> None:
    file_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    request = _pkt("server", "send", 0x19, (file_hash + (123).to_bytes(4, "little")).hex())
    reply_payload = file_hash + b"\x01" + bytes([192, 0, 2, 10]) + (4662).to_bytes(2, "little")
    reply = _pkt("server", "recv", 0x42, reply_payload.hex())

    assert reflected_self_source_evidence(
        [request, reply],
        file_hash=file_hash.hex(),
        requester_port=4663,
        expected_publisher_port=4662,
    ) == {
        "request_seen": True,
        "reply_seen": True,
        "matching_reply_count": 1,
        "returned_source_count": 1,
        "expected_publisher_present": True,
        "requester_present": False,
    }
    assert reflected_self_source_evidence(
        [reply],
        file_hash=file_hash.hex(),
        requester_port=4663,
        expected_publisher_port=4662,
    ) is None


def test_reflected_self_source_evidence_rejects_requester_endpoint() -> None:
    file_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    request = _pkt("server", "send", 0x23, (file_hash + (123).to_bytes(4, "little")).hex())
    reply_payload = (
        file_hash
        + b"\x02"
        + bytes([192, 0, 2, 10])
        + (4662).to_bytes(2, "little")
        + b"\x00"
        + bytes([192, 0, 2, 11])
        + (4663).to_bytes(2, "little")
        + b"\x00"
    )
    reply = _pkt("server", "recv", 0x44, reply_payload.hex())

    with pytest.raises(RuntimeError, match="reflected the requester endpoint"):
        reflected_self_source_evidence(
            [request, reply],
            file_hash=file_hash.hex(),
            requester_port=4663,
            expected_publisher_port=4662,
        )


def _kad(opcode, direction, name=None):
    rec = {"schema": "diag_event_v1", "family": "kad_udp", "keys": {"opcode": opcode}, "body": {"direction": direction}}
    if name:
        rec["opcode_name"] = name
    return rec


def test_kad_opcode_coverage_rust_superset_is_oracle_ok() -> None:
    from emule_test_harness import packet_trace_diff as ptd

    rust = [_kad(67, "send", "KADEMLIA2_REQ"), _kad(99, "send")]  # 99 is rust-only extra
    mfc = [_kad(67, "send")]
    cov = ptd.kad_opcode_coverage(ptd.kad_records(rust), ptd.kad_records(mfc))
    assert cov["oracleOk"] is True  # rust covers MFC's opcode; the extra is allowed
    assert cov["ok"] is False  # strict: a one-sided (onlyRust) opcode is present


def test_kad_opcode_coverage_flags_oracle_sent_gap() -> None:
    from emule_test_harness import packet_trace_diff as ptd

    rust = [_kad(0x21, "send")]
    # 0x43 is an opcode MFC actively SENT that rust never exercised: real signal.
    mfc = [_kad(0x21, "send"), _kad(0x43, "send")]
    cov = ptd.kad_opcode_coverage(ptd.kad_records(rust), ptd.kad_records(mfc))
    assert cov["oracleOk"] is False
    gap = cov["onlyEmuleSentGaps"][0]
    assert gap["opcodeHex"] == "0x43"
    assert gap["opcodeName"] == "KADEMLIA2_PUBLISH_KEY_REQ"  # static table name


def test_kad_opcode_coverage_recv_only_oracle_opcode_is_noise_not_gap() -> None:
    # An opcode MFC merely RECEIVED is network-driven (whatever peers throw at
    # it), not a rust parity gap; it is reported separately, not failed.
    from emule_test_harness import packet_trace_diff as ptd

    rust = [_kad(0x21, "send")]
    mfc = [_kad(0x21, "send"), _kad(0x32, "recv")]
    cov = ptd.kad_opcode_coverage(ptd.kad_records(rust), ptd.kad_records(mfc))
    assert cov["oracleOk"] is True
    assert cov["onlyEmuleSentGaps"] == []
    noise = cov["onlyEmuleReceivedOnly"][0]
    assert noise["opcodeHex"] == "0x32"
    assert noise["opcodeName"] == "KADEMLIA_SEARCH_NOTES_REQ"


def test_kad_opcode_coverage_annotates_documented_intentional_divergences() -> None:
    # Kad1 opcodes (rust never speaks Kad1) and the legacy KADEMLIA_FIREWALLED_REQ
    # 0x50 (rust is 0x53-only) are expected-only-MFC: annotated, never re-flagged.
    from emule_test_harness import packet_trace_diff as ptd

    rust = [_kad(0x21, "send")]
    mfc = [_kad(0x21, "send"), _kad(0x50, "send"), _kad(0x20, "recv")]
    cov = ptd.kad_opcode_coverage(ptd.kad_records(rust), ptd.kad_records(mfc))
    assert cov["oracleOk"] is True  # 0x50 sent-tier but documented as expected
    expected = {row["opcodeHex"]: row for row in cov["expectedOnlyEmule"]}
    assert set(expected) == {"0x50", "0x20"}
    assert "0x53" in expected["0x50"]["note"]
    assert expected["0x20"]["opcodeName"] == "KADEMLIA_REQ_DEPRECATED"


def test_kad_opcode_coverage_credits_rust_udp_dump_supplementary_source() -> None:
    # rust diag emits opcode None for unknown/legacy inbound opcodes; the raw
    # udp_packet_v1 dump credits those receives so rust is not falsely gapped.
    from emule_test_harness import packet_trace_diff as ptd

    rust_diag = [_kad(0x21, "send")]
    rust_udp_dump = [
        {"schema": "udp_packet_v1", "family": "kad", "direction": "recv", "opcode": "0x35"},
    ]
    mfc = [_kad(0x21, "send"), _kad(0x35, "send")]
    without = ptd.kad_opcode_coverage(ptd.kad_records(rust_diag), ptd.kad_records(mfc))
    assert without["oracleOk"] is False
    cov = ptd.kad_opcode_coverage(
        ptd.kad_records(rust_diag),
        ptd.kad_records(mfc),
        rust_supplementary_records=rust_udp_dump,
    )
    assert cov["oracleOk"] is True
    assert cov["supplementaryCreditedOpcodes"] == ["0x35"]


def test_kad_opcode_coverage_entries_carry_hex_and_static_names() -> None:
    from emule_test_harness import packet_trace_diff as ptd

    rust = [_kad(0x33, "send")]
    mfc = [_kad(0x33, "recv")]
    cov = ptd.kad_opcode_coverage(ptd.kad_records(rust), ptd.kad_records(mfc))
    shared = cov["combined"]["shared"][0]
    assert shared["opcodeHex"] == "0x33"
    assert shared["opcodeName"] == "KADEMLIA2_SEARCH_KEY_REQ"


def test_kad_records_filters_non_kad() -> None:
    from emule_test_harness import packet_trace_diff as ptd

    trace = [_kad(67, "send"), {"schema": "diag_event_v1", "family": "sched", "event": "x"}]
    assert len(ptd.kad_records(trace)) == 1
