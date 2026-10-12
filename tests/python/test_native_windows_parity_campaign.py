"""Pure orchestration checks for the CI-054 campaign wrapper."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "native-windows-parity-campaign.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("native_windows_parity_campaign", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_fresh_build_order_retains_regular_rust_before_diagnostics() -> None:
    module = _load()
    commands = module.build_commands("python")

    assert "--clean" in commands[0]
    assert "--diagnostics" not in commands[0]
    assert "--diagnostics" in commands[1]
    assert "--clean" not in commands[1]
    assert commands[2][4:6] == ("app", "--variant")
    assert ("--config", "Debug") == commands[2][7:9]
    assert "--diagnostics" in commands[4]


def test_native_cases_are_direct_and_share_one_case_campaign() -> None:
    module = _load()
    inputs = Path("ignored-inputs.json")

    rust = module._capture_command(
        client="rust", case="firewalled", campaign="campaign-firewalled", inputs=inputs
    )
    mfc = module._capture_command(
        client="mfc", case="firewalled", campaign="campaign-firewalled", inputs=inputs
    )

    assert rust[rust.index("--route") + 1] == "direct"
    assert rust[rust.index("--connectivity") + 1] == "firewalled"
    assert rust[rust.index("--campaign") + 1] == "campaign-firewalled"
    assert mfc[mfc.index("--campaign") + 1] == "campaign-firewalled"
    assert "--fresh-profile" in rust and "--fresh-profile" in mfc


def test_deterministic_stage_runs_oracle_and_both_full_protocol_matrices() -> None:
    module = _load()
    commands = module.deterministic_commands("192.0.2.10", Path("mfc-diag.exe"))
    rendered = [" ".join(command) for command in commands]

    assert any("validate-protocol-goldens.py" in command for command in rendered)
    assert any("stock-protocol-oracle-proof.py" in command for command in rendered)
    assert any("local-ed2k-protocol-combinations.py" in command for command in rendered)
    assert any("local-ed2k-rust-protocol-combinations.py" in command for command in rendered)
    assert all("--case" not in command for command in rendered)
    assert all(
        "--client2-app-exe mfc-diag.exe" in command
        for command in rendered
        if "protocol-combinations.py" in command
    )
    assert all(
        "--app-exe mfc-diag.exe" in command
        for command in rendered
        if "protocol-combinations.py" in command
    )


def test_fixture_pin_records_count_and_exact_content_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    fixture = tmp_path / "fixture.txt"
    fixture.write_bytes(b"synthetic fixture bytes\n")
    monkeypatch.setattr(
        module,
        "load_native_parity_config",
        lambda _inputs: SimpleNamespace(ed2k_links_file=fixture),
    )
    monkeypatch.setattr(module, "load_ed2k_link_fixture", lambda _path: (object(), object()))

    pin = module.pin_download_fixture(tmp_path / "inputs.json")

    assert pin.count == 2
    assert pin.content_digest == hashlib.sha256(fixture.read_bytes()).hexdigest()


def test_binary_provenance_summary_uses_output_relative_paths(tmp_path: Path) -> None:
    module = _load()
    binary = tmp_path / "builds" / "rust" / "client.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"binary")
    raw = {
        "rust": {
            "path": str(binary),
            "sizeBytes": 6,
            "sha256": "a" * 64,
        }
    }

    result = module.sanitized_binary_provenance(raw, tmp_path)

    assert result["rust"]["stagedPath"] == str(Path("builds/rust/client.exe"))
    assert str(tmp_path) not in json.dumps(result)


def _completion_set(module: ModuleType, digest: str, *, size: int = 10):
    return module.CompletionSet(
        expected_count=1,
        files=(("action-0004", size, digest),),
    )


def test_load_completion_set_accepts_private_verified_evidence(tmp_path: Path) -> None:
    module = _load()
    archive_path = tmp_path / "rust-recording.zip"
    payload = {
        "required": True,
        "expectedCount": 1,
        "files": [
            {
                "actionId": "action-0004",
                "status": "verified",
                "sizeBytes": 10,
                "sizeVerified": True,
                "ed2kVerified": True,
                "ed2kHash": "1" * 32,
                "sha256": "a" * 64,
            }
        ],
    }
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("rust-run/results.json", "{}")
    private_dir = tmp_path / "rust-recording-downloaded-payloads"
    private_dir.mkdir()
    (private_dir / "completion-private.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )

    completion = module.load_completion_set(archive_path, 1)

    assert completion.expected_count == 1
    assert completion.files == (("action-0004", 10, "a" * 64),)


def test_cross_case_acceptance_requires_all_four_equivalent_without_emitting_hashes() -> None:
    module = _load()
    digest = "a" * 64
    sets = {
        key: _completion_set(module, digest)
        for key in module.REQUIRED_COMPLETION_RECORDINGS
    }

    acceptance = module.compare_cross_case_completions(sets, 1)

    assert acceptance == {
        "complete": True,
        "equivalent": True,
        "expectedFileCount": 1,
        "recordingCount": 4,
        "findings": [],
    }
    assert digest not in json.dumps(acceptance)


def test_cross_case_acceptance_detects_private_digest_difference_without_emitting_it() -> None:
    module = _load()
    sets = {
        key: _completion_set(module, "a" * 64)
        for key in module.REQUIRED_COMPLETION_RECORDINGS
    }
    sets["firewalled-mfc"] = _completion_set(module, "b" * 64)

    acceptance = module.compare_cross_case_completions(sets, 1)

    assert acceptance["complete"] is True
    assert acceptance["equivalent"] is False
    assert acceptance["findings"] == ["completion-set-mismatch"]
    rendered = json.dumps(acceptance)
    assert "a" * 64 not in rendered and "b" * 64 not in rendered


def test_aggregate_parity_is_blocked_by_missing_or_different_completion_sets() -> None:
    module = _load()

    assert module.adjudicate_campaign(
        [],
        {"complete": False, "equivalent": False},
        fixture_unchanged=True,
    ) == ("harness-failure", 2)
    assert module.adjudicate_campaign(
        [],
        {"complete": True, "equivalent": False},
        fixture_unchanged=True,
    ) == ("divergence", 1)
    assert module.adjudicate_campaign(
        [module.StepResult("deterministic-2", 1)],
        {"complete": False, "equivalent": False},
        fixture_unchanged=True,
    ) == ("divergence", 1)
    assert module.adjudicate_campaign(
        [],
        {"complete": True, "equivalent": True},
        fixture_unchanged=False,
    ) == ("harness-failure", 2)
    assert module.adjudicate_campaign(
        [],
        {"complete": True, "equivalent": True},
        fixture_unchanged=True,
    ) == ("parity", 0)


def test_capture_exit_taxonomy_preserves_divergence_and_external_cases() -> None:
    module = _load()
    assert module.CAPTURE_CONTINUE_CODES == {0, 1, 3}

    assert module.adjudicate_campaign(
        [module.StepResult("capture-upnp-rust", 1)],
        {"complete": False, "equivalent": False},
        fixture_unchanged=True,
    ) == ("divergence", 1)
    assert module.adjudicate_campaign(
        [module.StepResult("capture-upnp-rust", 2)],
        {"complete": True, "equivalent": True},
        fixture_unchanged=True,
    ) == ("harness-failure", 2)
    assert module.adjudicate_campaign(
        [module.StepResult("capture-upnp-rust", 3)],
        {"complete": True, "equivalent": True},
        fixture_unchanged=True,
    ) == ("inconclusive-external", 3)
