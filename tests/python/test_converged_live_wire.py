"""Unit tests for the converged live-wire packet-diff pure logic."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import live_profile_seed

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MFC_SEED_CONFIG_DIR = REPO_ROOT / "manifests" / "live-profile-seed" / "config"
CONVERGED_RUNNER = REPO_ROOT / "scripts" / "converged-live-wire-diff.py"


def _load_converged_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("converged_live_wire_diff_script", CONVERGED_RUNNER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_mfc_seed_config_dir_passes_allowlist_validation() -> None:
    # The converged orchestrator defaults the MFC profile seed to this
    # canonical config-only directory; it must satisfy the same allowlist the
    # profile builder enforces (regression guard for the diagnostics-bin-dir bug
    # where the default pointed at the exe/.pdb bin directory).
    live_profile_seed.validate_seed_config_dir(DEFAULT_MFC_SEED_CONFIG_DIR)


def test_converged_live_wire_parser_accepts_lan_bind_addr() -> None:
    runner = _load_converged_runner()
    args = runner.build_parser().parse_args(
        [
            "--inputs",
            "live-wire-inputs.local.json",
            "--lan-bind-addr",
            "192.0.2.10",
        ]
    )

    assert args.lan_bind_addr == "192.0.2.10"


def test_mfc_diagnostics_build_dir_uses_canonical_layout(tmp_path: Path) -> None:
    build_dir = clw.mfc_diagnostics_build_dir(tmp_path)
    assert build_dir == (
        tmp_path / "builds" / "app" / "main" / "x64" / "Release" / "diagnostics" / "bin"
    )


def test_resolve_mfc_diagnostics_exe_resolves_when_present(tmp_path: Path) -> None:
    bin_dir = clw.mfc_diagnostics_build_dir(tmp_path)
    bin_dir.mkdir(parents=True)
    exe = bin_dir / clw.MFC_EXE_NAME
    exe.write_bytes(b"MZ")

    resolved = clw.resolve_mfc_diagnostics_exe(tmp_path)
    assert resolved == exe


def test_resolve_mfc_diagnostics_exe_honors_variant_arch_configuration(tmp_path: Path) -> None:
    resolved = clw.resolve_mfc_diagnostics_exe(
        tmp_path,
        variant="main",
        arch="ARM64",
        configuration="Debug",
        require_exists=False,
    )
    assert resolved == (
        tmp_path / "builds" / "app" / "main" / "ARM64" / "Debug" / "diagnostics" / "bin" / clw.MFC_EXE_NAME
    )


def test_resolve_mfc_diagnostics_exe_raises_with_expected_path(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError) as excinfo:
        clw.resolve_mfc_diagnostics_exe(tmp_path)
    message = str(excinfo.value)
    assert "diagnostics" in message
    assert clw.MFC_EXE_NAME in message


def test_resolve_rust_diagnostics_exe_picks_newest_staged_match(tmp_path: Path) -> None:
    older = tmp_path / "builds" / "rust" / "target" / "release" / clw.RUST_DIAGNOSTICS_EXE_NAME
    newer = tmp_path / "tools" / "emulebb-rust" / "bin" / clw.RUST_DIAGNOSTICS_EXE_NAME
    older.parent.mkdir(parents=True)
    newer.parent.mkdir(parents=True)
    older.write_bytes(b"MZ-old")
    newer.write_bytes(b"MZ-new")
    os.utime(older, (1_000_000_000, 1_000_000_000))
    os.utime(newer, (1_000_000_100, 1_000_000_100))

    resolved = clw.resolve_rust_diagnostics_exe(tmp_path)

    assert resolved == newer


def test_resolve_rust_diagnostics_exe_raises_with_build_hint(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError) as excinfo:
        clw.resolve_rust_diagnostics_exe(tmp_path)
    message = str(excinfo.value)
    assert clw.RUST_DIAGNOSTICS_EXE_NAME in message
    assert "--client emulebb-rust --diagnostics" in message


def test_build_search_payload_shape() -> None:
    assert clw.build_search_payload("  hello world  ") == {
        "query": "hello world",
        "method": "automatic",
        "type": "",
    }


def test_build_search_payload_rejects_blank() -> None:
    with pytest.raises(ValueError):
        clw.build_search_payload("   ")


def test_build_shared_directory_patch_payload_appends_trailing_separator(tmp_path: Path) -> None:
    payload = clw.build_shared_directory_patch_payload(tmp_path)
    assert payload["confirmReplaceRoots"] is True
    assert len(payload["roots"]) == 1
    root = payload["roots"][0]
    assert root["path"].endswith(("\\", "/"))
    assert str(tmp_path) in root["path"]


def test_build_shared_directory_patch_payload_does_not_double_separator() -> None:
    # When str(path) already ends in a separator the helper must not duplicate it.
    class _FakeDir:
        def __str__(self) -> str:
            return "C:\\share\\seed\\"

    payload = clw.build_shared_directory_patch_payload(_FakeDir())  # type: ignore[arg-type]
    assert payload["roots"][0] == {"path": "C:\\share\\seed\\"}


def test_converged_runner_requires_same_vpn_bind_ip() -> None:
    runner = _load_converged_runner()
    assert runner.require_same_vpn_bind_ip({"bindIp": "10.8.0.2"}, {"bindIp": "10.8.0.2"}) == "10.8.0.2"
    with pytest.raises(RuntimeError, match="bind IP mismatch"):
        runner.require_same_vpn_bind_ip({"bindIp": "10.8.0.2"}, {"bindIp": "10.8.0.3"})
    with pytest.raises(RuntimeError, match="bind IP missing"):
        runner.require_same_vpn_bind_ip({"bindIp": ""}, {"bindIp": "10.8.0.2"})


def test_converged_runner_environment_parity_profile_counts_shared_inputs() -> None:
    runner = _load_converged_runner()
    args = argparse.Namespace(
        server_met_url="https://upd.emule-security.org/server.met",
        nodes_url="https://nodes.example.test/nodes.dat",
        bootstrap_limit=40,
        profile="generic_open",
        max_terms=2,
        persisted=True,
        rust_rest_port=4731,
        mfc_rest_port=4732,
    )
    profile = runner.build_environment_parity_profile(
        args=args,
        bootstrap_nodes=["1.2.3.4:4662", "5.6.7.8:4662"],
        terms=["ubuntu", "debian"],
        shared_roots=["C:\\share\\a", "D:\\share\\b"],
    )
    assert profile["server"] == runner.OPERATOR_SERVER
    assert profile["sameServer"] is True
    assert profile["serverMetUrl"] == "https://upd.emule-security.org/server.met"
    assert profile["nodesDatUrl"] == "https://nodes.example.test/nodes.dat"
    assert profile["sameKadBootstrap"] is True
    assert profile["bootstrapContactCount"] == 2
    assert profile["searchProfile"] == "generic_open"
    assert profile["sameSearchTerms"] is True
    assert profile["selectedTermCount"] == 2
    assert profile["shareMode"] == "full-shares"
    assert profile["sameShareSet"] is True
    assert profile["sharedRootCount"] == 2
    assert profile["persistedProfiles"] is True


def test_converged_runner_polls_mfc_search_until_complete() -> None:
    runner = _load_converged_runner()

    class _FakeRestSmoke:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def http_request(self, _base_url: str, path: str, **_kwargs: object) -> dict[str, object]:
            self.paths.append(path)
            return {"json": {"status": "complete", "items": [{"name": "one"}, {"name": "two"}]}}

        def compact_http_result(self, result: dict[str, object]) -> dict[str, object]:
            return result

    rest_smoke = _FakeRestSmoke()
    result = runner.poll_mfc_search_page(rest_smoke, "http://127.0.0.1:4732", "42")
    assert result["json"]["status"] == "complete"
    assert rest_smoke.paths == ["/api/v1/searches/42"]


def test_converged_runner_clears_mfc_append_only_diagnostic_logs(tmp_path: Path) -> None:
    runner = _load_converged_runner()
    packet_log = tmp_path / "emulebb-diagnostics-packet.log"
    diag_log = tmp_path / "emulebb-diagnostics-diag.log"
    keep_log = tmp_path / "other.log"
    packet_log.write_text("{}\n", encoding="utf-8")
    diag_log.write_text("{}\n", encoding="utf-8")
    keep_log.write_text("keep\n", encoding="utf-8")

    removed = runner.clear_mfc_diagnostic_logs(tmp_path)

    assert removed == ["emulebb-diagnostics-packet.log"]
    assert not packet_log.exists()
    assert diag_log.exists()
    assert keep_log.exists()


def test_converged_runner_server_search_action_gate_uses_required_shared_opcodes() -> None:
    runner = _load_converged_runner()
    packet_diff = {
        "coverageOk": False,
        "opcodeCoverage": {
            "channels": [
                {
                    "channel": "server",
                    "direction": "send",
                    "shared": [
                        {"protocolMarker": 0xE3, "opcode": 0x16, "rustCount": 1, "emuleCount": 1}
                    ],
                },
                {
                    "channel": "server",
                    "direction": "recv",
                    "shared": [
                        {"protocolMarker": 0xE3, "opcode": 0x33, "rustCount": 2, "emuleCount": 1}
                    ],
                },
            ]
        },
    }
    scenario = runner.cs.ConvergedScenario(name="server", search_method=runner.cs.SEARCH_SERVER)

    gate = runner.build_live_action_coverage(packet_diff, scenario)

    assert gate["ok"] is True
    assert gate["diagnosticFullOpcodeCoverageOk"] is False
    assert [row["label"] for row in gate["required"]] == ["server-search-request", "server-search-result"]


def test_converged_runner_server_search_action_gate_fails_missing_result() -> None:
    runner = _load_converged_runner()
    packet_diff = {
        "coverageOk": True,
        "opcodeCoverage": {
            "channels": [
                {
                    "channel": "server",
                    "direction": "send",
                    "shared": [
                        {"protocolMarker": 0xE3, "opcode": 0x16, "rustCount": 1, "emuleCount": 1}
                    ],
                }
            ]
        },
    }
    scenario = runner.cs.ConvergedScenario(name="server", search_method=runner.cs.SEARCH_SERVER)

    gate = runner.build_live_action_coverage(packet_diff, scenario)

    assert gate["ok"] is False
    assert gate["required"][1]["presentOnBoth"] is False


def test_select_search_terms_is_gentle() -> None:
    terms = ["  a  ", "b", "", "c", "d"]
    assert clw.select_search_terms(terms, max_terms=2) == ["a", "b"]


def test_select_search_terms_rejects_empty_corpus() -> None:
    with pytest.raises(RuntimeError):
        clw.select_search_terms(["   ", ""], max_terms=2)


def test_select_search_terms_rejects_nonpositive_max() -> None:
    with pytest.raises(ValueError):
        clw.select_search_terms(["a"], max_terms=0)


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )


def test_find_diag_traces_selects_one_rust_run_in_segment_order(tmp_path: Path) -> None:
    stale = tmp_path / "emulebb-rust-diag-41-stale-000000.jsonl"
    first = tmp_path / "emulebb-rust-diag-42-active-000000.jsonl"
    second = tmp_path / "emulebb-rust-diag-42-active-000001.jsonl"
    for path in (stale, first, second):
        path.write_text("{}\n", encoding="utf-8")
    os.utime(stale, ns=(1, 1))
    os.utime(first, ns=(2, 2))
    os.utime(second, ns=(3, 3))

    assert clw.find_diag_traces(tmp_path, side="rust") == [
        first.resolve(),
        second.resolve(),
    ]


def test_find_diag_traces_selects_one_mfc_run_in_segment_order(tmp_path: Path) -> None:
    stale = tmp_path / "emulebb-mfc-diag-41-stale-000000.jsonl"
    first = tmp_path / "emulebb-mfc-diag-42-active-000000.jsonl"
    second = tmp_path / "emulebb-mfc-diag-42-active-000001.jsonl"
    for path in (stale, first, second):
        path.write_text("{}\n", encoding="utf-8")
    os.utime(stale, ns=(1, 1))
    os.utime(first, ns=(2, 2))
    os.utime(second, ns=(3, 3))

    assert clw.find_diag_traces(tmp_path, side="emule") == [
        first.resolve(),
        second.resolve(),
    ]


def test_find_mfc_diag_health(tmp_path: Path) -> None:
    assert clw.find_mfc_diag_health(tmp_path) is None
    health = tmp_path / clw.EMULE_DIAG_HEALTH_FILE
    health.write_text("{}", encoding="utf-8")
    assert clw.find_mfc_diag_health(tmp_path) == health


def test_converged_runner_uses_selected_unified_runs_for_packet_diff(
    tmp_path: Path,
) -> None:
    runner = _load_converged_runner()
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    rust_dir.mkdir()
    mfc_dir.mkdir()
    rust_segment = rust_dir / "emulebb-rust-diag-41-rust-run-000000.jsonl"
    mfc_segment = mfc_dir / "emulebb-mfc-diag-42-mfc-run-000000.jsonl"

    def record(client: str, process_id: int, run_id: str) -> dict[str, object]:
        return {
            "schema": "diag_event_v2",
            "client": client,
            "runId": run_id,
            "processId": process_id,
            "segmentId": 0,
            "seq": 1,
            "streamSeq": 1,
            "ts": "2026-10-24T12:00:00.000Z",
            "family": "ed2k_tcp",
            "event": "packet",
            "severity": "info",
            "keys": {
                "peer": "192.0.2.20:4662",
                "protocolMarker": 0xE3,
                "opcode": 0x01,
            },
            "body": {
                "flow": "server",
                "direction": "send",
                "transportMode": "plaintext",
                "obfuscated": False,
                "protocolMarker": 0xE3,
                "protocolName": "ed2k",
                "opcode": 0x01,
                "opcodeName": "OP_LOGINREQUEST",
                "rawLen": 3,
                "rawHex": "e30100",
                "payloadLen": 1,
                "payloadHex": "00",
                "payloadHexTruncated": False,
            },
        }

    _write_jsonl(rust_segment, [record("rust", 41, "rust-run")])
    _write_jsonl(mfc_segment, [record("mfc", 42, "mfc-run")])
    rust_stale = rust_dir / "emulebb-rust-diag-99-other-run-000000.jsonl"
    mfc_stale = mfc_dir / "emulebb-mfc-diag-99-other-run-000000.jsonl"
    _write_jsonl(rust_stale, [record("rust", 99, "other-run")])
    _write_jsonl(mfc_stale, [record("mfc", 99, "other-run")])
    os.utime(rust_segment, ns=(1, 1))
    os.utime(mfc_segment, ns=(1, 1))
    os.utime(rust_stale, ns=(2, 2))
    os.utime(mfc_stale, ns=(2, 2))
    (mfc_dir / clw.EMULE_DIAG_HEALTH_FILE).write_text(
        json.dumps(
            {
                "schema": "diag_event_v2",
                "enabled": True,
                "configured": True,
                "initialized": True,
                "runId": "mfc-run",
                "processId": 42,
                "activeSegmentId": 0,
                "activeFileName": mfc_segment.name,
                "droppedEvents": 0,
                "encodeErrors": 0,
                "writeErrors": 0,
                "retentionDeleteErrors": 0,
                "initializationFailure": None,
            }
        ),
        encoding="utf-8",
    )

    result = runner.diff_scenario_traces(
        {"diagnosticsDir": str(rust_dir), "processId": 41},
        {"diagnosticsDir": str(mfc_dir), "processId": 42},
    )

    assert result.rust_segments == (rust_segment.resolve(),)
    assert result.emule_segments == (mfc_segment.resolve(),)
    assert result.rust_packet_count == 1
    assert result.emule_packet_count == 1
    assert result.packet_diff["totals"]["matched"] == 1
    assert result.packet_diff["ok"] is True
    assert result.diag_diff["schema"] == "diag_event_diff_v1"
    assert result.diag_diff["ok"] is True


def test_load_current_mfc_diag_requires_lossless_writer_health(tmp_path: Path) -> None:
    segment = tmp_path / "emulebb-mfc-diag-42-active-000000.jsonl"
    _write_jsonl(
        segment,
        [
            {
                "schema": "diag_event_v2",
                "client": "mfc",
                "runId": "active",
                "processId": 42,
                "segmentId": 0,
                "seq": 1,
                "streamSeq": 1,
            }
        ],
    )

    with pytest.raises(ValueError, match="missing MFC diagnostic writer health"):
        clw.load_current_diag_records(tmp_path, side="emule")


def test_load_current_diag_rejects_empty_selected_run(tmp_path: Path) -> None:
    (tmp_path / "emulebb-rust-diag-42-active-000000.jsonl").write_text(
        "", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="contains no complete events"):
        clw.load_current_diag_records(tmp_path, side="rust")


def test_build_converged_report_ok_when_both_captured_and_diffs_pass(tmp_path: Path) -> None:
    rust_segments = (tmp_path / "rust-000000.jsonl", tmp_path / "rust-000001.jsonl")
    emule_segments = (tmp_path / "mfc-000000.jsonl",)

    report = clw.build_converged_report(
        run_id="20260622T000000Z",
        rust_diag_segments=rust_segments,
        emule_diag_segments=emule_segments,
        rust_packet_record_count=2,
        emule_packet_record_count=1,
        packet_diff={"ok": True, "totals": {"matched": 1}},
        diag_diff={"ok": True},
    )
    assert report["scenario"] == "emulebb.flow.converged.live-wire.hideme.v1"
    assert report["ok"] is True
    assert report["packetEvidence"]["source"] == "diag_event_v2"
    assert report["packetEvidence"]["bothCaptured"] is True
    assert report["packetEvidence"]["rust"] == {
        "selectedSegments": [str(path) for path in rust_segments],
        "extractedRecords": 2,
        "captured": True,
    }
    assert report["packetEvidence"]["emule"]["selectedSegments"] == [
        str(emule_segments[0])
    ]
    assert "traces" not in report
    assert "packetSummaries" not in report


def test_build_converged_report_not_ok_when_one_side_missing(tmp_path: Path) -> None:
    report = clw.build_converged_report(
        run_id="20260622T000000Z",
        rust_diag_segments=(tmp_path / "rust.jsonl",),
        emule_diag_segments=(tmp_path / "mfc.jsonl",),
        rust_packet_record_count=1,
        emule_packet_record_count=0,
        packet_diff={"ok": False},
        diag_diff={"ok": True},
    )
    assert report["ok"] is False
    assert report["packetEvidence"]["emule"]["captured"] is False


def test_build_converged_report_not_ok_on_payload_mismatch(tmp_path: Path) -> None:
    report = clw.build_converged_report(
        run_id="20260622T000000Z",
        rust_diag_segments=(tmp_path / "rust.jsonl",),
        emule_diag_segments=(tmp_path / "mfc.jsonl",),
        rust_packet_record_count=1,
        emule_packet_record_count=1,
        packet_diff={"ok": False, "totals": {"payload_mismatches": 1}},
        diag_diff={"ok": True},
    )
    assert report["ok"] is False


def test_build_converged_report_merges_extra() -> None:
    report = clw.build_converged_report(
        run_id="r",
        rust_diag_segments=(),
        emule_diag_segments=(),
        rust_packet_record_count=0,
        emule_packet_record_count=0,
        packet_diff={"ok": False},
        diag_diff={"ok": False},
        extra={"server": "1.2.3.4:5687", "bindIp": "10.0.0.2"},
    )
    assert report["server"] == "1.2.3.4:5687"
    assert report["bindIp"] == "10.0.0.2"
