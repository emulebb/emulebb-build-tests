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


@pytest.mark.parametrize(
    "value",
    (
        "..",
        ".",
        "../escape",
        "nested/case",
        "nested\\case",
        "C:\\escape",
        "bad value",
        "case..escape",
        "case.",
        "CON",
    ),
)
def test_campaign_name_rejects_path_escape_and_non_leaf_values(value: str) -> None:
    module = _load()

    with pytest.raises(RuntimeError, match="Campaign must be one short ASCII leaf"):
        module._validated_campaign_name(value)


def test_campaign_name_accepts_sanitized_leaf() -> None:
    module = _load()

    assert module._validated_campaign_name("ci-054-native_20261012.upnp") == (
        "ci-054-native_20261012.upnp"
    )


def test_offline_harness_failure_aborts_later_public_cases() -> None:
    module = _load()

    assert module._offline_result_requires_abort(2) is True
    assert module._offline_result_requires_abort(4) is True
    assert module._offline_result_requires_abort(0) is False
    assert module._offline_result_requires_abort(1) is False
    assert module._offline_result_requires_abort(3) is False


def test_offline_command_binds_exact_new_recordings() -> None:
    module = _load()
    rust = Path("reports/case/rust-new.zip")
    mfc = Path("reports/case/mfc-new.zip")

    command = module._offline_command(rust, mfc)

    assert "--campaign" not in command
    assert command[command.index("--rust") + 1] == str(rust)
    assert command[command.index("--mfc") + 1] == str(mfc)


def test_cli_maps_unexpected_failures_to_sanitized_harness_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load()
    monkeypatch.setattr(
        module,
        "main",
        lambda: (_ for _ in ()).throw(RuntimeError("private campaign path")),
    )

    assert module._cli_main() == 2
    stderr = capsys.readouterr().err
    assert stderr == "harness-failure: RuntimeError\n"
    assert "private campaign path" not in stderr


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


def test_native_input_pin_covers_config_and_both_fixture_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    config = tmp_path / "inputs.json"
    config.write_bytes(b'{"native_windows_parity": {}}\n')
    downloads = tmp_path / "downloads.txt"
    downloads.write_bytes(b"synthetic download fixture bytes\n")
    shared_paths = tmp_path / "shared-paths.txt"
    shared_paths.write_bytes(b"synthetic shared-path fixture bytes\n")
    monkeypatch.setattr(
        module,
        "load_native_parity_config",
        lambda _inputs: SimpleNamespace(
            ed2k_links_file=downloads,
            shared_paths_file=shared_paths,
        ),
    )
    monkeypatch.setattr(
        module, "load_ed2k_link_fixture", lambda _path: (object(), object())
    )
    monkeypatch.setattr(
        module, "load_shared_path_fixture", lambda _path: ("C:\\Share",)
    )

    pin = module.pin_native_inputs(config)

    assert pin.download_count == 2
    assert pin.shared_path_count == 1
    assert pin.config_content_digest == hashlib.sha256(config.read_bytes()).hexdigest()
    assert (
        pin.download_content_digest
        == hashlib.sha256(downloads.read_bytes()).hexdigest()
    )
    assert (
        pin.shared_paths_content_digest
        == hashlib.sha256(shared_paths.read_bytes()).hexdigest()
    )


def test_native_input_pin_changes_when_config_or_shared_fixture_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load()
    config = tmp_path / "inputs.json"
    config.write_text("first config\n", encoding="utf-8")
    downloads = tmp_path / "downloads.txt"
    downloads.write_text("download fixture\n", encoding="utf-8")
    shared_paths = tmp_path / "shared-paths.txt"
    shared_paths.write_text("shared fixture\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_native_parity_config",
        lambda _inputs: SimpleNamespace(
            ed2k_links_file=downloads,
            shared_paths_file=shared_paths,
        ),
    )
    monkeypatch.setattr(module, "load_ed2k_link_fixture", lambda _path: (object(),))
    monkeypatch.setattr(
        module, "load_shared_path_fixture", lambda _path: ("C:\\Share",)
    )

    original = module.pin_native_inputs(config)
    shared_paths.write_text("changed shared fixture\n", encoding="utf-8")
    assert module.pin_native_inputs(config) != original
    shared_paths.write_text("shared fixture\n", encoding="utf-8")
    config.write_text("changed config\n", encoding="utf-8")
    assert module.pin_native_inputs(config) != original


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


def _prior_summary(
    *,
    revisions: dict[str, str],
    binaries: dict[str, dict[str, object]],
) -> dict[str, object]:
    return {
        "schema": "native_windows_parity_campaign_v1",
        "sourceRevisions": revisions,
        "binaryProvenance": binaries,
        "steps": [
            *(
                {"name": f"fresh-build-{index}", "return_code": 0}
                for index in range(1, 6)
            ),
            *(
                {"name": f"deterministic-{index}", "return_code": 0}
                for index in range(1, 5)
            ),
        ],
    }


def test_skip_stage_provenance_requires_exact_revisions_binaries_and_steps(
    tmp_path: Path,
) -> None:
    module = _load()
    revisions = {"rust": "1" * 40, "mfc": "2" * 40}
    binaries = {
        "rust": {
            "stagedPath": "builds/rust/client.exe",
            "sizeBytes": 6,
            "sha256": "a" * 64,
        }
    }
    report = tmp_path / "native-parity-summary.json"
    report.write_text(
        json.dumps(_prior_summary(revisions=revisions, binaries=binaries)),
        encoding="utf-8",
    )

    proof = module.validate_prior_stage_provenance(
        report,
        current_revisions=revisions,
        current_binary_provenance=binaries,
        require_build=True,
        require_deterministic=True,
    )

    assert [step.name for step in proof.build_steps] == list(
        module.FRESH_BUILD_STEP_NAMES
    )
    assert [step.name for step in proof.deterministic_steps] == list(
        module.DETERMINISTIC_STEP_NAMES
    )
    assert proof.report_digest == hashlib.sha256(report.read_bytes()).hexdigest()


@pytest.mark.parametrize("mismatch", ["revision", "binary", "step"])
def test_skip_stage_provenance_rejects_mismatched_or_incomplete_proof(
    tmp_path: Path,
    mismatch: str,
) -> None:
    module = _load()
    revisions = {"rust": "1" * 40}
    binaries = {
        "rust": {
            "stagedPath": "builds/rust/client.exe",
            "sizeBytes": 6,
            "sha256": "a" * 64,
        }
    }
    payload = _prior_summary(revisions=revisions, binaries=binaries)
    if mismatch == "revision":
        payload["sourceRevisions"] = {"rust": "2" * 40}
    elif mismatch == "binary":
        payload["binaryProvenance"] = {}
    else:
        payload["steps"] = list(payload["steps"])[:-1]  # type: ignore[arg-type]
    report = tmp_path / "native-parity-summary.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="provenance"):
        module.validate_prior_stage_provenance(
            report,
            current_revisions=revisions,
            current_binary_provenance=binaries,
            require_build=True,
            require_deterministic=True,
        )


def test_reused_stage_provenance_is_self_contained_and_path_free() -> None:
    module = _load()
    digest = "a" * 64
    steps = tuple(module.StepResult(name, 0) for name in module.FRESH_BUILD_STEP_NAMES)

    section = module.stage_provenance_section(
        reused=True,
        steps=steps,
        expected_names=module.FRESH_BUILD_STEP_NAMES,
        source_report_digest=digest,
    )

    assert section == {
        "mode": "reused",
        "validated": True,
        "steps": [
            {"name": name, "returnCode": 0} for name in module.FRESH_BUILD_STEP_NAMES
        ],
        "sourceReportSha256": digest,
    }


def test_v2_reused_stage_provenance_can_be_validated_again(tmp_path: Path) -> None:
    module = _load()
    revisions = {"rust": "1" * 40}
    binaries = {
        "rust": {
            "stagedPath": "builds/rust/client.exe",
            "sizeBytes": 6,
            "sha256": "a" * 64,
        }
    }
    payload = {
        "schema": "native_windows_parity_campaign_v2",
        "sourceRevisions": revisions,
        "binaryProvenance": binaries,
        "stageProvenance": {
            "build": {
                "mode": "reused",
                "validated": True,
                "steps": [
                    {"name": name, "returnCode": 0}
                    for name in module.FRESH_BUILD_STEP_NAMES
                ],
            },
            "deterministic": {
                "mode": "reused",
                "validated": True,
                "steps": [
                    {"name": name, "returnCode": 0}
                    for name in module.DETERMINISTIC_STEP_NAMES
                ],
            },
        },
        "steps": [],
    }
    report = tmp_path / "native-parity-summary-v2.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    proof = module.validate_prior_stage_provenance(
        report,
        current_revisions=revisions,
        current_binary_provenance=binaries,
        require_build=True,
        require_deterministic=True,
    )

    assert len(proof.build_steps) == 5
    assert len(proof.deterministic_steps) == 4

    payload["stageProvenance"]["deterministic"]["validated"] = False  # type: ignore[index]
    report.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="does not validate"):
        module.validate_prior_stage_provenance(
            report,
            current_revisions=revisions,
            current_binary_provenance=binaries,
            require_build=True,
            require_deterministic=True,
        )


def test_stage_provenance_does_not_validate_a_partial_successful_stage() -> None:
    module = _load()
    section = module.stage_provenance_section(
        reused=False,
        steps=(module.StepResult("fresh-build-1", 0),),
        expected_names=module.FRESH_BUILD_STEP_NAMES,
    )

    assert section["validated"] is False


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
    private_dir = tmp_path / "rust-recording-private-artifacts"
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
        "scope": "all-four-recordings-private-sha256",
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
