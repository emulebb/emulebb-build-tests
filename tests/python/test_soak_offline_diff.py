"""Unit tests for the offline recording diff (scripts/soak-offline-diff.py)."""

from __future__ import annotations

import importlib.util
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest

from tests.python.diagnostic_fixtures import ed2k_tcp_clear_frame

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
        "schema": "diag_event_v2",
        "ts": _ts(at),
        "family": family,
        "event": event,
        "severity": "info",
        "keys": {},
        "body": body or {},
    }


def _segmented_diag(
    client: str,
    process_id: int,
    run_id: str,
    segment_id: int,
    seq: int,
    at: float,
) -> dict:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "segmentId": segment_id,
        "seq": seq,
        "streamSeq": seq,
        "ts": _ts(at),
        "family": "sched",
        "event": "tick",
        "severity": "info",
        "keys": {},
        "body": {},
    }


def _segmented_peer_packet(
    client: str,
    process_id: int,
    run_id: str,
    segment_id: int,
    seq: int,
    at: float,
) -> dict:
    record = _segmented_diag(client, process_id, run_id, segment_id, seq, at)
    payload = bytes.fromhex("aabb")
    clear_frame = ed2k_tcp_clear_frame(0xE3, 0x01, payload)
    record.update(
        {
            "family": "ed2k_tcp",
            "event": "packet",
            "keys": {
                "peer": "198.51.100.1:4662",
                "protocolMarker": 0xE3,
                "opcode": 0x01,
            },
            "body": {
                "direction": "send",
                "flow": "client",
                "transportMode": "plaintext",
                "obfuscated": False,
                "protocolMarker": 0xE3,
                "protocolName": "ed2k",
                "opcode": 0x01,
                "opcodeName": "OP_HELLO",
                "rawLen": len(clear_frame),
                "rawHex": clear_frame.hex(),
                "clearFrameLen": len(clear_frame),
                "clearFrameHex": clear_frame.hex(),
                "payloadLen": len(payload),
                "payloadHex": payload.hex(),
                "payloadHexTruncated": False,
            },
        }
    )
    return record


def test_full_run_diagnostics_require_client_udp_without_narrow_window_penalty() -> None:
    mod = _load_offline_diff()
    rust = [_diag("sched", "source_count", 0.0, body={"sourceCount": 1})]
    mfc = [_diag("sched", "source_count", 0.0, body={"sourceCount": 1})]

    assert mod.diag_event_diff.family_conformance(rust, mfc)["ok"] is True
    gate = mod._full_run_diagnostic_gate(rust, mfc)

    assert gate["ok"] is False
    assert gate["familyConformance"]["requiredFamilies"] == [
        {
            "family": "ed2k_client_udp",
            "rustPresent": False,
            "mfcPresent": False,
            "ok": False,
        },
        {
            "family": "ed2k_tcp",
            "rustPresent": False,
            "mfcPresent": False,
            "ok": False,
        },
    ]


def _window(at: float = 0.0) -> dict:
    stamp = datetime(2026, 7, 4, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=at)
    return {"kind": "search", "t0": stamp, "t1": stamp + timedelta(seconds=10)}


def _sides(rust_pkt: list, mfc_pkt: list, rust_diag: list | None = None, mfc_diag: list | None = None) -> tuple[dict, dict]:
    rust = {"packets": rust_pkt, "diag": rust_diag or [], "markers": [], "meta": {}}
    mfc = {"packets": mfc_pkt, "diag": mfc_diag or [], "markers": [], "meta": {}}
    return rust, mfc


def _write_recording_shell(tmp_path: Path, stem: str) -> tuple[Path, Path]:
    recording = tmp_path / f"{stem}.zip"
    private_dir = tmp_path / f"{stem}-private-artifacts"
    (private_dir / "dumps").mkdir(parents=True)
    with zipfile.ZipFile(recording, "w") as archive:
        archive.writestr(f"{stem}/results.json", "{}")
        archive.writestr(f"{stem}/markers.jsonl", "")
        archive.writestr(
            f"{stem}/evidence-classification.json",
            json.dumps(
                {
                    "archiveClassification": "sanitized-report",
                    "privateArtifactsSibling": f"{stem}-private-artifacts",
                }
            ),
        )
    return recording, private_dir


def test_load_recording_uses_sanitized_archive_and_private_raw_sibling(
    tmp_path: Path,
) -> None:
    mod = _load_offline_diff()
    recording = tmp_path / "rust-recording.zip"
    private_dir = tmp_path / "rust-recording-private-artifacts"
    dumps = private_dir / "dumps" / "nested"
    dumps.mkdir(parents=True)
    (private_dir / "native-capture.pcapng").write_bytes(b"x" * 4096)
    (dumps / "emulebb-rust-diag-42-active-000000.jsonl").write_text(
        "\n".join(
            json.dumps(record)
            for record in (
                _segmented_diag("rust", 42, "active", 0, 1, 1),
                _segmented_peer_packet("rust", 42, "active", 0, 2, 2),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    with zipfile.ZipFile(recording, "w") as archive:
        archive.writestr("rust-recording/results.json", json.dumps({"nativeCapture": {}}))
        archive.writestr("rust-recording/markers.jsonl", "")
        archive.writestr(
            "rust-recording/evidence-classification.json",
            json.dumps(
                {
                    "archiveClassification": "sanitized-report",
                    "privateArtifactsSibling": "rust-recording-private-artifacts",
                }
            ),
        )

    loaded = mod._load_recording(recording, client="rust")

    assert loaded["nativeCaptureSizes"] == [4096]
    assert len(loaded["diag"]) == 2
    assert loaded["diag"][0]["ts"] == _ts(1)
    assert loaded["diag"][1]["ts"] == _ts(2)
    assert len(loaded["packets"]) == 1


def test_load_recording_rejects_legacy_packet_side_file(tmp_path: Path) -> None:
    mod = _load_offline_diff()
    recording, private_dir = _write_recording_shell(tmp_path, "rust-recording")
    (private_dir / "dumps" / "packet.log").write_text(
        json.dumps({"schema": "ed2k_packet_v1", "ts_utc": _ts(2)}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Legacy packet side files are unsupported"):
        mod._load_recording(recording, client="rust")


def test_load_recording_rejects_malformed_current_diag_segment(tmp_path: Path) -> None:
    mod = _load_offline_diff()
    recording, private_dir = _write_recording_shell(tmp_path, "rust-recording")
    (private_dir / "dumps" / "emulebb-rust-diag-42-active-000000.jsonl").write_text(
        '{"schema":"diag_event_v2"', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="malformed JSON"):
        mod._load_recording(recording, client="rust")


def test_load_recording_rejects_unsegmented_current_diag_event(tmp_path: Path) -> None:
    mod = _load_offline_diff()
    recording, private_dir = _write_recording_shell(tmp_path, "rust-recording")
    (private_dir / "dumps" / "events.jsonl").write_text(
        json.dumps(_segmented_diag("rust", 42, "active", 0, 1, 1)) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="segmented current-run names"):
        mod._load_recording(recording, client="rust")


def test_load_recording_requires_mfc_writer_health(tmp_path: Path) -> None:
    mod = _load_offline_diff()
    recording, private_dir = _write_recording_shell(tmp_path, "mfc-recording")
    segment = private_dir / "dumps" / "emulebb-mfc-diag-42-active-000000.jsonl"
    segment.write_text(
        json.dumps(_segmented_diag("mfc", 42, "active", 0, 1, 1)) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exactly one diagnostic writer health"):
        mod._load_recording(recording, client="mfc")


def test_load_recording_rejects_private_diagnostics_in_sanitized_archive(
    tmp_path: Path,
) -> None:
    mod = _load_offline_diff()
    recording = tmp_path / "rust-recording.zip"
    with zipfile.ZipFile(recording, "w") as archive:
        archive.writestr("rust-recording/results.json", "{}")
        archive.writestr("rust-recording/markers.jsonl", "")
        archive.writestr("rust-recording/dumps/private.log", "sensitive")

    with pytest.raises(ValueError, match="private diagnostics"):
        mod._load_recording(recording, client="rust")


def test_load_recording_uses_private_completion_digest_for_pair_proof(
    tmp_path: Path,
) -> None:
    mod = _load_offline_diff()
    digest = "a" * 64

    def make_recording(stem: str) -> dict:
        recording = tmp_path / f"{stem}.zip"
        private_dir = tmp_path / f"{stem}-private-artifacts"
        private_dir.mkdir()
        public_meta = _completion_meta(digest=digest)
        del public_meta["nativeCompletionEvidence"]["files"][0]["sha256"]
        with zipfile.ZipFile(recording, "w") as archive:
            archive.writestr(f"{stem}/results.json", json.dumps(public_meta))
            archive.writestr(f"{stem}/markers.jsonl", "")
            archive.writestr(
                f"{stem}/evidence-classification.json",
                json.dumps(
                    {
                        "archiveClassification": "sanitized-report",
                        "privateArtifactsSibling": f"{stem}-private-artifacts",
                    }
                ),
            )
        (private_dir / "completion-private.json").write_text(
            json.dumps(_completion_meta(digest=digest)["nativeCompletionEvidence"]),
            encoding="utf-8",
        )
        client = "rust" if stem.startswith("rust") else "mfc"
        return mod._load_recording(recording, client=client)

    rust = make_recording("rust-recording")
    mfc = make_recording("mfc-recording")
    result = mod._compare_native_completions(rust["meta"], mfc["meta"])

    assert result["ok"] is True
    assert result["digestComparedCount"] == 1
    assert digest not in json.dumps(result)


@pytest.mark.parametrize(
    ("member", "payload", "message"),
    [
        ("results.json", "[]", "results document"),
        ("markers.jsonl", '"not-an-object"\n', "marker"),
    ],
)
def test_load_recording_rejects_valid_json_non_objects(
    tmp_path: Path,
    member: str,
    payload: str,
    message: str,
) -> None:
    mod = _load_offline_diff()
    recording = tmp_path / "rust-recording.zip"
    with zipfile.ZipFile(recording, "w") as archive:
        archive.writestr(
            "rust-recording/results.json",
            payload if member == "results.json" else "{}",
        )
        archive.writestr(
            "rust-recording/markers.jsonl",
            payload if member == "markers.jsonl" else "",
        )

    with pytest.raises(ValueError, match=message):
        mod._load_recording(recording, client="rust")


def test_cli_maps_unexpected_failure_to_sanitized_harness_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mod = _load_offline_diff()
    monkeypatch.setattr(
        mod,
        "main",
        lambda: (_ for _ in ()).throw(RuntimeError("private recording path")),
    )

    assert mod._cli_main() == 2
    stderr = capsys.readouterr().err
    assert stderr == "harness-failure: RuntimeError\n"
    assert "private recording path" not in stderr


def test_cli_preserves_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load_offline_diff()
    monkeypatch.setattr(
        mod,
        "main",
        lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        mod._cli_main()


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


def test_packet_only_action_window_fails_for_missing_diagnostics() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides(
        [_pkt("server", "send", 0x16, "aa", 1.0)],
        [_pkt("server", "send", 0x16, "bb", 1.0)],
        [],
        [],
    )

    result = mod._diff_one_action("search", rust, mfc, _window(), _window(), lead=2.0, settle=5.0)

    assert result["verdict"] == "missing-diagnostics"
    assert result["conformant"] is False
    assert result["diagFamilyOk"] is False


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


def test_global_search_action_is_not_assessable_without_mfc_udp_evidence() -> None:
    # MFC's capture has no aligned server-UDP evidence, so Rust's
    # OP_GLOBSEARCHREQ send cannot establish parity by itself.
    mod = _load_offline_diff()
    rust_pkt = [_pkt("server", "send", 0x98, "aa11", 1.0)]
    mfc_pkt = [_pkt("server", "send", 0x14, "bb", 1.0)]
    rust, mfc = _sides(rust_pkt, mfc_pkt)
    result = mod._diff_one_action(
        "search", rust, mfc, _window(), _window(), lead=2.0, settle=5.0, method="global"
    )
    assert result["method"] == "global"
    assert result["coverageOk"] is False
    assert result["verdict"] == "not-assessable"


def test_kad_search_action_assessed_from_kad_stream() -> None:
    mod = _load_offline_diff()

    def _kad(opcode: int, at: float) -> dict:
        return {
            "schema": "diag_event_v2",
            "ts": _ts(at),
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
    incomplete = {"kind": "search", "t0": _window()["t0"]}
    result = mod._diff_one_action(
        "search", rust, mfc, incomplete, _window(), lead=1.0, settle=1.0
    )
    assert result["verdict"] == "no-window"
    assert result["diagFamilyOk"] is False
    assert result["diagStrictMatchOk"] is False


def test_no_traffic_is_not_conformant() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides([], [])

    result = mod._diff_one_action(
        "search", rust, mfc, _window(), _window(), lead=1.0, settle=1.0
    )

    assert result["verdict"] == "no-traffic"
    assert result["conformant"] is False


def test_end_marker_action_error_fails_action_without_diffing() -> None:
    mod = _load_offline_diff()
    rust, mfc = _sides([], [])
    rust_window = {**_window(), "status": "error"}

    result = mod._diff_one_action(
        "search", rust, mfc, rust_window, _window(), lead=1.0, settle=1.0
    )

    assert result["verdict"] == "action-error"
    assert result["conformant"] is False


def _completion_meta(*, digest: str, size: int = 3, expected_count: int = 1) -> dict:
    return {
        "nativeCompletionEvidence": {
            "required": True,
            "expectedCount": expected_count,
            "files": [
                {
                    "actionId": "action-0001",
                    "sizeBytes": size,
                    "sizeVerified": True,
                    "ed2kVerified": True,
                    "sha256": digest,
                }
            ],
        }
    }


def test_native_completion_comparison_is_opt_in_for_old_recordings() -> None:
    mod = _load_offline_diff()
    result = mod._compare_native_completions({}, {})
    assert result == {
        "required": False,
        "ok": None,
        "expectedCount": None,
        "matchedCount": 0,
        "findings": [],
    }


def test_native_completion_comparison_matches_without_emitting_digest() -> None:
    mod = _load_offline_diff()
    digest = "a" * 64

    result = mod._compare_native_completions(
        _completion_meta(digest=digest), _completion_meta(digest=digest)
    )

    assert result["ok"] is True
    assert result["matchedCount"] == 1
    assert digest not in json.dumps(result)


def test_native_completion_comparison_reports_digest_mismatch_without_values() -> None:
    mod = _load_offline_diff()
    rust_digest = "a" * 64
    mfc_digest = "b" * 64

    result = mod._compare_native_completions(
        _completion_meta(digest=rust_digest), _completion_meta(digest=mfc_digest)
    )

    assert result["ok"] is False
    assert result["findings"] == ["completion-sha256-mismatch"]
    emitted = json.dumps(result)
    assert rust_digest not in emitted and mfc_digest not in emitted


def test_native_completion_comparison_rejects_missing_private_digest() -> None:
    mod = _load_offline_diff()
    rust = _completion_meta(digest="a" * 64)
    mfc = _completion_meta(digest="a" * 64)
    del rust["nativeCompletionEvidence"]["files"][0]["sha256"]
    del mfc["nativeCompletionEvidence"]["files"][0]["sha256"]

    result = mod._compare_native_completions(rust, mfc)

    assert result["ok"] is False
    assert result["matchedCount"] == 0
    assert set(result["findings"]) == {
        "rust-completion-evidence-invalid",
        "mfc-completion-evidence-invalid",
    }


def test_native_capture_evidence_requires_frames_and_matching_archive_size() -> None:
    mod = _load_offline_diff()
    recording = {
        "nativeCaptureSizes": [4096],
        "meta": {
            "nativeCapture": {
                "created": True,
                "fileByteCount": 4096,
                "frameCount": 12,
                "relevantFrameCount": 9,
                "capturedByteCount": 2048,
                "sizeLimitReached": False,
            }
        },
    }

    assert mod._native_capture_evidence(recording) == {
        "ok": True,
        "frameCount": 12,
        "relevantFrameCount": 9,
        "capturedByteCount": 2048,
        "findings": [],
    }
    recording["meta"]["nativeCapture"]["frameCount"] = 0
    result = mod._native_capture_evidence(recording)
    assert result["ok"] is False
    assert "native-capture-no-frames" in result["findings"]


@pytest.mark.parametrize(
    ("overrides", "expected_verdict", "expected_exit"),
    [
        ({}, "parity", 0),
        ({"conformance_ok": False}, "divergence", 1),
        ({"state_machine_ok": False}, "divergence", 1),
        (
            {
                "state_machine_ok": False,
                "state_machine_evidence_observed": False,
            },
            "harness-failure",
            2,
        ),
        ({"missing_action_count": 1}, "harness-failure", 2),
        ({"external_inconclusive": True}, "inconclusive-external", 3),
        (
            {
                "per_action": [
                    {"verdict": "not-assessable", "coverageOk": False}
                ]
            },
            "inconclusive-external",
            3,
        ),
        (
            {
                "per_action": [
                    {"verdict": "evidence-incomplete", "coverageOk": False}
                ]
            },
            "inconclusive-external",
            3,
        ),
    ],
)
def test_campaign_verdict_taxonomy_and_exit_codes(
    overrides: dict, expected_verdict: str, expected_exit: int
) -> None:
    mod = _load_offline_diff()
    inputs = {
        "per_action": [{"verdict": "conformant", "coverageOk": True}],
        "missing_action_count": 0,
        "action_error_count": 0,
        "completion": {"required": False, "ok": None},
        "scenario_mismatch": False,
        "conformance_ok": True,
        "kad_coverage_ok": True,
        "secident_dead": False,
        "external_inconclusive": False,
    }
    inputs.update(overrides)

    result = mod._campaign_verdict(**inputs)

    assert result["verdict"] == expected_verdict
    assert result["exitCode"] == expected_exit


def test_missing_state_machine_evidence_is_not_a_protocol_divergence() -> None:
    mod = _load_offline_diff()
    inputs = {
        "per_action": [{"verdict": "conformant", "coverageOk": True}],
        "missing_action_count": 0,
        "action_error_count": 0,
        "completion": {"required": False, "ok": None},
        "scenario_mismatch": False,
        "conformance_ok": True,
        "kad_coverage_ok": True,
        "secident_dead": False,
        "external_inconclusive": False,
        "state_machine_ok": False,
        "state_machine_evidence_observed": False,
    }

    missing = mod._campaign_verdict(**inputs)
    observed_mismatch = mod._campaign_verdict(
        **{**inputs, "state_machine_evidence_observed": True}
    )

    assert missing == {
        "verdict": "harness-failure",
        "exitCode": 2,
        "findings": ["state-machine-evidence-missing"],
    }
    assert observed_mismatch["verdict"] == "divergence"
    assert observed_mismatch["exitCode"] == 1


def test_missing_action_diagnostics_is_a_harness_failure() -> None:
    mod = _load_offline_diff()

    result = mod._campaign_verdict(
        per_action=[{"verdict": "missing-diagnostics", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={"required": False, "ok": None},
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )

    assert result == {
        "verdict": "harness-failure",
        "exitCode": 2,
        "findings": ["missing-action-diagnostics"],
    }


def test_action_errors_and_required_completion_failure_are_harness_failures() -> None:
    mod = _load_offline_diff()
    recording = {"meta": {"actionResults": [{"actionId": "action-0001", "status": "error"}]}}
    assert mod._action_error_count(recording) == 1

    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=1,
        completion={"required": True, "ok": False},
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )
    assert result["verdict"] == "harness-failure"
    assert set(result["findings"]) == {"action-errors", "completion-evidence-failed"}


def test_external_completion_shortfall_is_inconclusive_not_pass_or_harness_failure() -> None:
    mod = _load_offline_diff()
    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={
            "required": True,
            "ok": False,
            "findings": [
                "rust-completion-count-mismatch",
                "completion-action-set-mismatch",
                "completion-incomplete",
            ],
        },
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=True,
    )

    assert result["verdict"] == "inconclusive-external"
    assert result["exitCode"] == 3


def test_invalid_completed_payload_is_divergence() -> None:
    mod = _load_offline_diff()
    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={"required": True, "ok": False, "findings": ["completion-invalid"]},
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )

    assert result["verdict"] == "divergence"
    assert result["exitCode"] == 1


def test_native_action_contract_rejects_symmetric_missing_action() -> None:
    mod = _load_offline_diff()
    markers: list[dict] = []
    results: list[dict] = []
    methods = ("server", "global", "kad")
    for index in range(1, 5):
        action_id = f"action-{index:04d}"
        kind = "search" if index <= 3 else "download"
        extra = {"method": methods[index - 1]} if kind == "search" else {}
        markers.append({"actionId": action_id, "kind": kind, "marker": "begin", **extra})
        markers.append(
            {
                "actionId": action_id,
                "kind": kind,
                "marker": "end",
                "terminal": kind == "download",
                **extra,
            }
        )
        results.append({"actionId": action_id, "status": "ok"})
    recording = {
        "markers": markers,
        "meta": {
            "nativeInputSummary": {"ed2k_link_count": 1},
            "actionResults": results,
        },
    }

    assert mod._native_action_contract(recording)["ok"] is True
    recording["markers"] = [row for row in markers if row["actionId"] != "action-0002"]
    recording["meta"]["actionResults"] = results[:1] + results[2:]
    assert mod._native_action_contract(recording)["ok"] is False


def test_completed_payload_digest_mismatch_is_protocol_divergence() -> None:
    mod = _load_offline_diff()
    result = mod._campaign_verdict(
        per_action=[{"verdict": "conformant", "coverageOk": True}],
        missing_action_count=0,
        action_error_count=0,
        completion={
            "required": True,
            "ok": False,
            "findings": ["completion-sha256-mismatch"],
        },
        scenario_mismatch=False,
        conformance_ok=True,
        kad_coverage_ok=True,
        secident_dead=False,
        external_inconclusive=False,
    )

    assert result["verdict"] == "divergence"
    assert result["exitCode"] == 1


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
