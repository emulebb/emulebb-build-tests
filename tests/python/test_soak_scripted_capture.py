"""Unit tests for the solo scripted-capture launcher (scripts/soak-scripted-capture.py)."""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from emule_test_harness.scripted_actions import ScriptedAction

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CAPTURE_SCRIPT = REPO_ROOT / "scripts" / "soak-scripted-capture.py"


def _load_capture() -> ModuleType:
    spec = importlib.util.spec_from_file_location("soak_scripted_capture_script", CAPTURE_SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_capture_secident_knob_defaults_on() -> None:
    module = _load_capture()

    args = module.build_parser().parse_args(["--client", "mfc"])
    assert args.secident == "on"

    off_args = module.build_parser().parse_args(["--client", "mfc", "--secident", "off"])
    assert off_args.secident == "off"


def test_direct_capture_parser_exposes_connectivity_and_total_download_deadline() -> None:
    module = _load_capture()

    args = module.build_parser().parse_args(
        ["--client", "rust", "--route", "direct", "--connectivity", "firewalled"]
    )

    assert args.route == "direct"
    assert args.connectivity == "firewalled"
    assert args.download_timeout_seconds > 0


def test_native_completion_verifies_fixture_without_retaining_name_or_hash(tmp_path: Path) -> None:
    module = _load_capture()
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "private.pdf").write_bytes(b"abc")
    action = ScriptedAction("action-0004", "download", {})

    markers: list[dict[str, object]] = []
    private, summary = module._verify_native_downloads(
        actions=[action],
        fixtures=[
            {
                "name": "private.pdf",
                "size": 3,
                "hash": "a448017aaf21d8525fc10ae87aa6729d",
            }
        ],
        incoming_dir=incoming,
        timeout_seconds=1.0,
        marker_writer=markers.append,
    )

    assert private[0]["status"] == "verified"
    assert private[0]["sizeVerified"] is True
    assert summary == [
        {
            "actionId": "action-0004",
            "status": "verified",
            "sizeBytes": 3,
            "sizeVerified": True,
            "ed2kVerified": True,
            "sha256Computed": True,
        }
    ]
    assert "private.pdf" not in str(summary)
    assert markers == [
        {
            "schema": "scripted_action_marker_v1",
            "marker": "end",
            "actionId": "action-0004",
            "kind": "download",
            "terminal": True,
            "status": "verified",
            "ts_utc": markers[0]["ts_utc"],
        }
    ]


def test_recording_archive_excludes_fresh_profiles_and_includes_capture(tmp_path: Path) -> None:
    module = _load_capture()
    report = tmp_path / "rust-case"
    (report / "rust-profile" / "incoming").mkdir(parents=True)
    (report / "rust-profile" / "incoming" / "private.pdf").write_bytes(b"payload")
    (report / "dumps").mkdir()
    (report / "dumps" / "diag.jsonl").write_text("{}\n", encoding="utf-8")
    (report / "native-capture.pcapng").write_bytes(b"capture")

    private_evidence = report / "completion-private.json"
    private_evidence.write_text('{"private": true}', encoding="utf-8")
    archive = module.pack_recording(
        report,
        incoming_dir=report / "rust-profile" / "incoming",
        private_evidence_path=private_evidence,
    )

    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
    assert any(name.endswith("native-capture.pcapng") for name in names)
    assert any(name.endswith("dumps/diag.jsonl") for name in names)
    assert not any("rust-profile" in name for name in names)
    assert not any("completion-private" in name for name in names)
    retained = tmp_path / "rust-case-downloaded-payloads" / "private.pdf"
    assert retained.read_bytes() == b"payload"
    assert (retained.parent / "completion-private.json").is_file()


def test_recording_retains_nested_mfc_incoming_payloads(tmp_path: Path) -> None:
    module = _load_capture()
    report = tmp_path / "mfc-case"
    incoming = report / "mfc-profile" / "profiles" / "converged-soak" / "incoming"
    incoming.mkdir(parents=True)
    (incoming / "private.pdf").write_bytes(b"payload")
    (report / "results.json").write_text("{}", encoding="utf-8")

    module.pack_recording(report, incoming_dir=incoming)

    retained = tmp_path / "mfc-case-downloaded-payloads" / "private.pdf"
    assert retained.read_bytes() == b"payload"


def test_shared_inventory_wait_requires_all_files_and_idle_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_capture()
    shared = tmp_path / "shared"
    (shared / "nested").mkdir(parents=True)
    (shared / "one.bin").write_bytes(b"1")
    (shared / "nested" / "two.bin").write_bytes(b"2")
    assert module._approved_shared_file_count(
        [{"path": str(shared), "recursive": True}]
    ) == 2

    replies = iter(
        [
            {"data": {"runtimeDiagnostics": {"sharedFileCount": 1, "sharedHashingCount": 1}}},
            {"data": {"items": [{}], "total": 1, "offset": 0, "limit": 1}},
            {"data": {"runtimeDiagnostics": {"sharedFileCount": 2, "sharedHashingCount": 0}}},
            {"data": {"items": [{}], "total": 2, "offset": 0, "limit": 1}},
        ]
    )
    monkeypatch.setattr(module, "_http", lambda *_args, **_kwargs: next(replies))
    ticks = iter((0.0, 0.0, 1.0))
    result = module._wait_for_shared_inventory(
        client="mfc",
        base_url="http://127.0.0.1:1",
        api_key="test",
        expected_count=2,
        timeout_seconds=5.0,
        sleep=lambda _seconds: None,
        monotonic=lambda: next(ticks),
    )
    assert result == {
        "ready": True,
        "expectedFileCount": 2,
        "advertisedFileCount": 2,
        "hashingFileCount": 0,
    }


def test_rust_shared_state_uses_paged_inventory_total() -> None:
    module = _load_capture()

    advertised, hashing = module._shared_runtime_state(
        "rust",
        {
            "data": {
                "sharedFilesReady": True,
                "sharedFilesComplete": False,
                "sharedHashingCount": 4,
            }
        },
        {"data": {"items": [{}], "total": 46, "offset": 0, "limit": 1}},
    )

    assert advertised == 46
    assert hashing == 4


def test_mapping_state_wait_retains_only_sanitized_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_capture()

    class Audit:
        @staticmethod
        def sanitized_counts() -> dict[str, object]:
            return {
                "expectedMapped": True,
                "expectedCount": 2,
                "presentCount": 2,
                "matchingLocalCount": 2,
                "foreignTargetCount": 0,
                "missingCount": 0,
                "observedStatus": "mapped",
                "passed": True,
            }

    monkeypatch.setattr(module, "verify_upnp_port_mappings", lambda *_args, **_kwargs: Audit())
    result = module._wait_for_mapping_state(
        local_address="192.0.2.10",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        expected_mapped=True,
        timeout_seconds=1.0,
    )

    assert result["available"] is True
    assert result["passed"] is True
    assert "192.0.2.10" not in str(result)


def test_connectivity_state_normalizes_rust_and_mfc_firewall_signals() -> None:
    module = _load_capture()

    rust = module._connectivity_state(
        "rust",
        {"data": {"ed2kConnected": True, "ed2kHighId": True, "kadFirewalled": False}},
        "upnp",
    )
    mfc = module._connectivity_state(
        "mfc",
        {
            "data": {
                "servers": {"connected": True, "lowId": True},
                "kad": {"firewalled": True},
            }
        },
        "firewalled",
    )

    assert rust["matchesExpectedCase"] is True
    assert mfc["matchesExpectedCase"] is True


def test_linux_document_term_selection_accepts_operator_phrase() -> None:
    module = _load_capture()
    assert module._select_linux_document_term(("public linux documents", "other")) == (
        "public linux documents"
    )
