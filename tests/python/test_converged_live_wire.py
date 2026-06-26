"""Unit tests for the converged live-wire packet-diff pure logic."""

from __future__ import annotations

import argparse
import importlib.util
import json
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
    assert root.endswith(("\\", "/"))
    assert str(tmp_path) in root


def test_build_shared_directory_patch_payload_does_not_double_separator() -> None:
    # When str(path) already ends in a separator the helper must not duplicate it.
    class _FakeDir:
        def __str__(self) -> str:
            return "C:\\share\\seed\\"

    payload = clw.build_shared_directory_patch_payload(_FakeDir())  # type: ignore[arg-type]
    assert payload["roots"][0] == "C:\\share\\seed\\"


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


def test_find_packet_trace_discovers_each_side(tmp_path: Path) -> None:
    rust_dir = tmp_path / "rust"
    emule_dir = tmp_path / "emule"
    rust_dir.mkdir()
    emule_dir.mkdir()
    rust_trace = rust_dir / "emulebb-rust-ed2k-tcp-dump-001.jsonl"
    emule_trace = emule_dir / "emulebb-diagnostics-packet.log"
    rust_trace.write_text("{}\n", encoding="utf-8")
    emule_trace.write_text("{}\n", encoding="utf-8")

    assert clw.find_packet_trace(rust_dir, side="rust") == rust_trace
    assert clw.find_packet_trace(emule_dir, side="emule") == emule_trace


def test_find_packet_trace_returns_none_when_absent(tmp_path: Path) -> None:
    assert clw.find_packet_trace(tmp_path, side="rust") is None


def test_find_packet_trace_rejects_unknown_side(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        clw.find_packet_trace(tmp_path, side="bogus")


def test_count_jsonl_records_ignores_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "dump.jsonl"
    path.write_text('{"a":1}\n\n{"b":2}\n', encoding="utf-8")
    assert clw.count_jsonl_records(path) == 2
    assert clw.count_jsonl_records(None) == 0
    assert clw.count_jsonl_records(tmp_path / "missing.jsonl") == 0


def test_build_converged_report_ok_when_both_captured_and_diffs_pass(tmp_path: Path) -> None:
    rust_trace = tmp_path / "rust.jsonl"
    emule_trace = tmp_path / "emule.jsonl"
    _write_jsonl(rust_trace, [{"schema": "ed2k_packet_v1"}])
    _write_jsonl(emule_trace, [{"schema": "ed2k_packet_v1"}])

    report = clw.build_converged_report(
        run_id="20260622T000000Z",
        rust_packet_trace=rust_trace,
        emule_packet_trace=emule_trace,
        packet_diff={"ok": True, "totals": {"matched": 1}},
        diag_diff={"ok": True},
        rust_packet_summary={"requestSources2Sent": 0},
        emule_packet_summary=None,
    )
    assert report["scenario"] == "emulebb.flow.converged.live-wire.hideme.v1"
    assert report["ok"] is True
    assert report["traces"]["bothCaptured"] is True
    assert report["traces"]["rust"]["records"] == 1


def test_build_converged_report_not_ok_when_one_side_missing(tmp_path: Path) -> None:
    rust_trace = tmp_path / "rust.jsonl"
    _write_jsonl(rust_trace, [{"schema": "ed2k_packet_v1"}])

    report = clw.build_converged_report(
        run_id="20260622T000000Z",
        rust_packet_trace=rust_trace,
        emule_packet_trace=None,
        packet_diff=None,
        diag_diff=None,
        rust_packet_summary=None,
        emule_packet_summary=None,
    )
    assert report["ok"] is False
    assert report["traces"]["emule"]["captured"] is False


def test_build_converged_report_not_ok_on_payload_mismatch(tmp_path: Path) -> None:
    rust_trace = tmp_path / "rust.jsonl"
    emule_trace = tmp_path / "emule.jsonl"
    _write_jsonl(rust_trace, [{"schema": "ed2k_packet_v1"}])
    _write_jsonl(emule_trace, [{"schema": "ed2k_packet_v1"}])

    report = clw.build_converged_report(
        run_id="20260622T000000Z",
        rust_packet_trace=rust_trace,
        emule_packet_trace=emule_trace,
        packet_diff={"ok": False, "totals": {"payload_mismatches": 1}},
        diag_diff={"ok": True},
        rust_packet_summary=None,
        emule_packet_summary=None,
    )
    assert report["ok"] is False


def test_build_converged_report_merges_extra() -> None:
    report = clw.build_converged_report(
        run_id="r",
        rust_packet_trace=None,
        emule_packet_trace=None,
        packet_diff=None,
        diag_diff=None,
        rust_packet_summary=None,
        emule_packet_summary=None,
        extra={"server": "1.2.3.4:5687", "bindIp": "10.0.0.2"},
    )
    assert report["server"] == "1.2.3.4:5687"
    assert report["bindIp"] == "10.0.0.2"
