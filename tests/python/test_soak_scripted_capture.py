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


def test_recording_archive_excludes_fresh_profiles_and_includes_capture(tmp_path: Path) -> None:
    module = _load_capture()
    report = tmp_path / "rust-case"
    (report / "rust-profile" / "incoming").mkdir(parents=True)
    (report / "rust-profile" / "incoming" / "private.pdf").write_bytes(b"payload")
    (report / "dumps").mkdir()
    (report / "dumps" / "diag.jsonl").write_text("{}\n", encoding="utf-8")
    (report / "native-capture.pcapng").write_bytes(b"capture")

    archive = module.pack_recording(report)

    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
    assert any(name.endswith("native-capture.pcapng") for name in names)
    assert any(name.endswith("dumps/diag.jsonl") for name in names)
    assert not any("rust-profile" in name for name in names)


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
