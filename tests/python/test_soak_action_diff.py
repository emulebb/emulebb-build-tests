from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from emule_test_harness import soak_action_diff as sad

pytestmark = pytest.mark.unit


def _ts(seconds: float) -> datetime:
    return datetime(2026, 6, 24, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)


def _pkt(
    flow: str, direction: str, opcode: int, payload_hex: str, ts: datetime, *, marker: int = 229
) -> dict:
    return {
        "schema": "ed2k_packet_v1",
        "ts_utc": ts.isoformat().replace("+00:00", "Z"),
        "flow": flow,
        "direction": direction,
        "protocol_marker": marker,
        "opcode": opcode,
        "opcode_name": f"OP_{opcode:02X}",
        "payload_len": len(payload_hex) // 2,
        "payload_hex": payload_hex,
    }


# --------------------------------------------------------------------------- #
# parse_ts
# --------------------------------------------------------------------------- #


def test_parse_ts_handles_rfc3339_millis_z() -> None:
    parsed = sad.parse_ts("2026-06-24T12:00:00.500Z")
    assert parsed == datetime(2026, 6, 24, 12, 0, 0, 500_000, tzinfo=timezone.utc)


def test_parse_ts_returns_none_for_garbage() -> None:
    assert sad.parse_ts(None) is None
    assert sad.parse_ts("") is None
    assert sad.parse_ts("not-a-timestamp") is None


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #


def test_normalize_search_items_uses_field_aliases_and_lowercases_key() -> None:
    rust = sad.normalize_search_items([{"id": "r-1", "query": "Ubuntu", "method": "Kad"}])
    mfc = sad.normalize_search_items([{"searchId": "m-9", "keyword": "ubuntu"}])
    assert rust[0]["id"] == "r-1"
    assert rust[0]["key"] == "ubuntu"
    assert rust[0]["label"] == "Ubuntu"
    assert rust[0]["method"] == "kad"
    # Different ids, same correlation key across clients.
    assert mfc[0]["key"] == rust[0]["key"]
    assert mfc[0]["method"] == "automatic"  # defaulted


def test_normalize_transfer_items_keys_on_hash() -> None:
    items = sad.normalize_transfer_items(
        [{"id": "t-1", "fileHash": "ABCDEF", "fileName": "thing.iso"}]
    )
    assert items[0]["key"] == "abcdef"
    assert items[0]["label"] == "thing.iso"


def test_normalize_skips_unusable_rows() -> None:
    assert sad.normalize_search_items([{"id": "x"}]) == []  # no query
    assert sad.normalize_transfer_items([{"id": "x"}]) == []  # no hash
    assert sad.normalize_search_items(["nonsense", None]) == []


# --------------------------------------------------------------------------- #
# detect_actions
# --------------------------------------------------------------------------- #


def test_detect_actions_reports_only_new_ids() -> None:
    items = sad.normalize_search_items(
        [{"id": "s1", "query": "linux"}, {"id": "s2", "query": "debian"}]
    )
    fresh, seen = sad.detect_actions(
        {"s1"}, items, client="rust", kind=sad.SEARCH, observed_at=_ts(0)
    )
    assert [a.action_id for a in fresh] == ["s2"]
    assert seen == {"s1", "s2"}
    assert fresh[0].key == "debian"
    assert fresh[0].observed_at == _ts(0)


def test_detect_actions_remembers_vanished_ids() -> None:
    # An action seen once then gone from the list must not re-fire later.
    first = sad.normalize_search_items([{"id": "s1", "query": "linux"}])
    _, seen = sad.detect_actions(None, first, client="rust", kind=sad.SEARCH, observed_at=_ts(0))
    fresh, seen2 = sad.detect_actions(
        seen, [], client="rust", kind=sad.SEARCH, observed_at=_ts(5)
    )
    assert fresh == []
    assert "s1" in seen2


# --------------------------------------------------------------------------- #
# correlate_actions
# --------------------------------------------------------------------------- #


def _action(client: str, key: str, ts: datetime, kind: str = sad.SEARCH) -> sad.Action:
    return sad.Action(
        client=client, kind=kind, action_id=f"{client}-{key}", key=key, label=key, observed_at=ts
    )


def test_correlate_pairs_same_key_within_window() -> None:
    rust = [_action("rust", "ubuntu", _ts(0))]
    mfc = [_action("mfc", "ubuntu", _ts(10))]
    pairs, unpaired_rust, unpaired_mfc = sad.correlate_actions(rust, mfc, window_seconds=90)
    assert len(pairs) == 1
    assert pairs[0].key == "ubuntu"
    assert not unpaired_rust and not unpaired_mfc


def test_correlate_leaves_out_of_window_unpaired() -> None:
    rust = [_action("rust", "ubuntu", _ts(0))]
    mfc = [_action("mfc", "ubuntu", _ts(500))]
    pairs, unpaired_rust, unpaired_mfc = sad.correlate_actions(rust, mfc, window_seconds=90)
    assert pairs == []
    assert len(unpaired_rust) == 1 and len(unpaired_mfc) == 1


def test_correlate_picks_nearest_in_time() -> None:
    rust = [_action("rust", "k", _ts(0))]
    mfc = [_action("mfc", "k", _ts(80)), _action("mfc", "k", _ts(20))]
    pairs, _, unpaired_mfc = sad.correlate_actions(rust, mfc, window_seconds=90)
    assert len(pairs) == 1
    assert pairs[0].mfc.observed_at == _ts(20)
    assert len(unpaired_mfc) == 1  # the far one is left over


def test_correlate_does_not_cross_kinds() -> None:
    rust = [_action("rust", "k", _ts(0), kind=sad.SEARCH)]
    mfc = [_action("mfc", "k", _ts(1), kind=sad.DOWNLOAD)]
    pairs, unpaired_rust, unpaired_mfc = sad.correlate_actions(rust, mfc, window_seconds=90)
    assert pairs == []
    assert len(unpaired_rust) == 1 and len(unpaired_mfc) == 1


# --------------------------------------------------------------------------- #
# slice_trace
# --------------------------------------------------------------------------- #


def test_slice_trace_keeps_only_in_window_records() -> None:
    records = [
        _pkt("client", "send", 0x01, "aa", _ts(-5)),  # before
        _pkt("client", "send", 0x02, "bb", _ts(10)),  # inside
        _pkt("client", "send", 0x03, "cc", _ts(99)),  # after
    ]
    sliced = sad.slice_trace(records, _ts(0), _ts(30))
    assert [r["opcode"] for r in sliced] == [0x02]


def test_slice_trace_drops_records_without_timestamp() -> None:
    records = [{"schema": "ed2k_packet_v1", "opcode": 1, "direction": "send"}]
    assert sad.slice_trace(records, _ts(0), _ts(30)) == []


# --------------------------------------------------------------------------- #
# diff_action + reporting
# --------------------------------------------------------------------------- #


def test_diff_action_coverage_parity_when_same_opcodes() -> None:
    pair = sad.ActionPair(
        kind=sad.SEARCH,
        key="ubuntu",
        rust=_action("rust", "ubuntu", _ts(0)),
        mfc=_action("mfc", "ubuntu", _ts(2)),
    )
    # Same search action opcodes on both sides (different payloads / counts is fine for live).
    rust_packets = [
        _pkt("server", "send", 0x16, "aabb", _ts(1), marker=0xE3),
        _pkt("server", "recv", 0x33, "ee", _ts(2), marker=0xE3),
    ]
    mfc_packets = [
        _pkt("server", "send", 0x16, "ccdd", _ts(3), marker=0xE3),
        _pkt("server", "recv", 0x33, "ff", _ts(4), marker=0xE3),
    ]
    report = sad.diff_action(pair, rust_packets=rust_packets, mfc_packets=mfc_packets)
    assert report["verdict"] == "coverage-parity"
    assert report["coverageOk"] is True
    assert report["actionCoverage"]["mode"] == "action-required-opcodes"
    assert report["byteMatch"] is False  # payload differs — expected for live clients


def test_diff_action_search_gate_ignores_unrelated_background_opcodes() -> None:
    pair = sad.ActionPair(
        kind=sad.SEARCH,
        key="ubuntu",
        rust=_action("rust", "ubuntu", _ts(0)),
        mfc=_action("mfc", "ubuntu", _ts(2)),
    )
    rust_packets = [
        _pkt("server", "send", 0x16, "aa", _ts(1), marker=0xE3),
        _pkt("server", "recv", 0x33, "bb", _ts(2), marker=0xE3),
        _pkt("client", "recv", 0x47, "cc", _ts(2)),  # unrelated background transfer
    ]
    mfc_packets = [
        _pkt("server", "send", 0x16, "dd", _ts(3), marker=0xE3),
        _pkt("server", "recv", 0x33, "ee", _ts(4), marker=0xE3),
    ]
    report = sad.diff_action(pair, rust_packets=rust_packets, mfc_packets=mfc_packets)
    assert report["verdict"] == "coverage-parity"
    assert report["coverageOk"] is True
    assert report["fullCoverageOk"] is False


def test_diff_action_divergence_when_required_search_result_is_missing() -> None:
    pair = sad.ActionPair(
        kind=sad.SEARCH,
        key="ubuntu",
        rust=_action("rust", "ubuntu", _ts(0)),
        mfc=_action("mfc", "ubuntu", _ts(2)),
    )
    rust_packets = [
        _pkt("server", "send", 0x16, "aa", _ts(1), marker=0xE3),
        _pkt("server", "send", 0x98, "bb", _ts(1), marker=0xE3),  # opcode only rust uses
    ]
    mfc_packets = [_pkt("server", "send", 0x16, "cc", _ts(3), marker=0xE3)]
    report = sad.diff_action(pair, rust_packets=rust_packets, mfc_packets=mfc_packets)
    assert report["verdict"] == "divergence"
    assert report["coverageOk"] is False


def test_diff_action_download_gate_accepts_core_transfer_opcodes() -> None:
    pair = sad.ActionPair(
        kind=sad.DOWNLOAD,
        key="a" * 32,
        rust=_action("rust", "a" * 32, _ts(0), kind=sad.DOWNLOAD),
        mfc=_action("mfc", "a" * 32, _ts(2), kind=sad.DOWNLOAD),
    )
    rust_packets = [
        _pkt("server", "recv", 0x44, "aa", _ts(1), marker=0xE3),
        _pkt("client", "send", 0x47, "bb", _ts(2), marker=0xE3),
        _pkt("client", "recv", 0x40, "cc", _ts(3), marker=0xC5),
        _pkt("client", "send", 0x99, "dd", _ts(3)),  # unrelated full-window drift
    ]
    mfc_packets = [
        _pkt("server", "recv", 0x44, "ee", _ts(3), marker=0xE3),
        _pkt("client", "send", 0x47, "ff", _ts(4), marker=0xE3),
        _pkt("client", "recv", 0x40, "11", _ts(4), marker=0xC5),
    ]

    report = sad.diff_action(pair, rust_packets=rust_packets, mfc_packets=mfc_packets)

    assert report["verdict"] == "coverage-parity"
    assert report["coverageOk"] is True
    assert report["fullCoverageOk"] is False
    assert [row["label"] for row in report["actionCoverage"]["required"]] == [
        "server-found-sources",
        "client-request-parts",
        "client-part-payload",
    ]


def test_diff_action_download_gate_fails_without_part_payload() -> None:
    pair = sad.ActionPair(
        kind=sad.DOWNLOAD,
        key="a" * 32,
        rust=_action("rust", "a" * 32, _ts(0), kind=sad.DOWNLOAD),
        mfc=_action("mfc", "a" * 32, _ts(2), kind=sad.DOWNLOAD),
    )
    rust_packets = [
        _pkt("server", "recv", 0x44, "aa", _ts(1), marker=0xE3),
        _pkt("client", "send", 0x47, "bb", _ts(2), marker=0xE3),
    ]
    mfc_packets = [
        _pkt("server", "recv", 0x44, "ee", _ts(3), marker=0xE3),
        _pkt("client", "send", 0x47, "ff", _ts(4), marker=0xE3),
    ]

    report = sad.diff_action(pair, rust_packets=rust_packets, mfc_packets=mfc_packets)

    assert report["verdict"] == "divergence"
    assert report["coverageOk"] is False
    assert report["actionCoverage"]["required"][2]["presentOnBoth"] is False


def test_diff_action_no_traffic_and_one_sided() -> None:
    pair = sad.ActionPair(
        kind=sad.SEARCH,
        key="ubuntu",
        rust=_action("rust", "ubuntu", _ts(0)),
        mfc=_action("mfc", "ubuntu", _ts(2)),
    )
    assert sad.diff_action(pair, rust_packets=[], mfc_packets=[])["verdict"] == "no-traffic"
    one = sad.diff_action(
        pair, rust_packets=[_pkt("server", "send", 0x16, "aa", _ts(1))], mfc_packets=[]
    )
    assert one["verdict"] == "one-sided"


def test_summary_folds_verdicts() -> None:
    summary = sad.empty_summary("camp-1")
    for verdict in ("coverage-parity", "divergence", "unpaired"):
        report = sad.build_action_report(
            {"kind": "search", "key": "k", "label": "k", "verdict": verdict, "coverageOk": True},
            campaign_id="camp-1",
            seq=1,
        )
        sad.append_to_summary(summary, report)
    assert summary["totals"]["actions"] == 3
    assert summary["totals"]["coverageParity"] == 1
    assert summary["totals"]["divergence"] == 1
    assert summary["totals"]["unpaired"] == 1


def test_write_action_report_persists_json(tmp_path) -> None:
    report = sad.build_action_report(
        {"kind": "search", "key": "ubuntu", "label": "ubuntu", "verdict": "coverage-parity"},
        campaign_id="camp-1",
        seq=7,
    )
    path = sad.write_action_report(report, tmp_path / "actions")
    assert path.exists()
    assert path.name == "00007-search-term.json"
    assert "ubuntu" not in path.name


def test_write_action_report_sanitizes_windows_reserved_filename_chars(tmp_path) -> None:
    report = sad.build_action_report(
        {
            "kind": "search",
            "key": 'http://example.invalid/a:b?c*"',
            "label": "synthetic url",
            "verdict": "unpaired",
        },
        campaign_id="camp-1",
        seq=8,
    )
    path = sad.write_action_report(report, tmp_path / "actions")
    assert path.exists()
    assert path.name == "00008-search-url.json"
    assert path.suffix == ".json"
    assert ":" not in path.name
    assert "?" not in path.name
    assert "*" not in path.name
    assert '"' not in path.name
    assert "example.invalid" not in path.name


def test_write_action_report_redacts_hash_keys_from_filename(tmp_path) -> None:
    report = sad.build_action_report(
        {
            "kind": "download",
            "key": "a" * 32,
            "label": "synthetic transfer",
            "verdict": "coverage-parity",
        },
        campaign_id="camp-1",
        seq=9,
    )
    path = sad.write_action_report(report, tmp_path / "actions")
    assert path.exists()
    assert path.name == "00009-download-hash.json"
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in path.name
