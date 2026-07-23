from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_start_soak_module():
    script_path = REPO_ROOT / "scripts" / "start-rust-soak-profile.py"
    spec = importlib.util.spec_from_file_location("start_rust_soak_profile_under_test", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_background_starter_builds_python_launch_soak_command() -> None:
    module = load_start_soak_module()
    args = module.build_parser().parse_args(["--seconds", "3600", "--lan-bind-addr", "192.0.2.10"])

    command = module.build_launch_command(args)

    assert command[0] == sys.executable
    assert command[1].endswith("scripts\\launch-soak.py") or command[1].endswith("scripts/launch-soak.py")
    assert "--rust-regular" in command
    assert "--no-mfc" in command
    assert command[command.index("--lan-bind-addr") + 1] == "192.0.2.10"
    assert command[command.index("--cpu-profile-seconds") + 1] == "3600"
    assert command[command.index("--rest-timeout-seconds") + 1] == "60.0"
    assert "--cpu-profile-stack" in command
    assert "--process-metrics" in command
    assert "vpn-guard-live.local.json" in command[command.index("--vpn-guard-live-config") + 1]


def test_background_starter_can_request_diagnostics_with_fallback_server() -> None:
    module = load_start_soak_module()
    args = module.build_parser().parse_args(
        [
            "--seconds",
            "3600",
            "--lan-bind-addr",
            "192.0.2.10",
            "--diagnostics",
            "--rust-fallback-server",
            "176.123.5.89:4725",
        ]
    )

    command = module.build_launch_command(args)

    assert "--rust-regular" not in command
    assert command[command.index("--rust-fallback-server") + 1] == "176.123.5.89:4725"
    assert "--no-mfc" in command


def test_background_starter_rejects_short_operator_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_start_soak_module()

    with pytest.raises(RuntimeError, match="at least 3600"):
        module.main(["--seconds", "300", "--lan-bind-addr", "192.0.2.10"])


def write_minimal_live_inputs(repo_root: Path, rust_profile: Path) -> None:
    payload = {
        "schema": "emulebb-build-tests.live-wire-inputs.v1",
        "rust_profile": {"profile_dir": str(rust_profile)},
        "search_terms": {
            "generic_open": ["linux iso"],
            "documents": ["linux pdf"],
            "radarr_movies": ["public domain"],
        },
        "auto_browse": {
            "bootstrap_transfer_hashes": ["0123456789abcdef0123456789abcdef"],
            "direct_bootstrap_transfers": [
                {
                    "hash": "0123456789abcdef0123456789abcdef",
                    "name": "fixture.iso",
                    "size": 123,
                    "method": "direct_ed2k",
                }
            ],
        },
    }
    (repo_root / "live-wire-inputs.local.json").write_text(json.dumps(payload), encoding="utf-8")
    (repo_root / "vpn-guard-live.local.json").write_text(
        json.dumps(
            {
                "schema": "emulebb.vpnGuardLiveConfig.v1",
                "p2pBindInterfaceName": "hide.me",
                "allowedPublicIpCidrs": "192.0.2.0/24",
            }
        ),
        encoding="utf-8",
    )


def set_operator_env(monkeypatch: pytest.MonkeyPatch, workspace_root: Path, output_root: Path) -> Path:
    cargo_target_dir = output_root / "builds" / "rust" / "target"
    workspace_root.mkdir(parents=True)
    cargo_target_dir.mkdir(parents=True)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(cargo_target_dir))
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")
    return cargo_target_dir


def test_background_starter_describe_reports_effective_operator_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_start_soak_module()
    repo_root = tmp_path / "repo"
    output_root = tmp_path / "out"
    rust_profile = output_root / "soak" / "rust-runtime"
    repo_root.mkdir()
    rust_profile.mkdir(parents=True)
    write_minimal_live_inputs(repo_root, rust_profile)
    monkeypatch.setattr(module, "REPO_ROOT", repo_root)
    set_operator_env(monkeypatch, tmp_path / "workspace", output_root)

    assert module.main(["--seconds", "3600", "--lan-bind-addr", "192.0.2.10", "--describe"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "rust-regular-live-profile"
    assert result["lanBindAddr"] == "192.0.2.10"
    assert result["rustProfileDir"] == str(rust_profile)
    assert result["rustExe"] == str(output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe")
    assert result["rustRest"] == "http://192.0.2.10:4731/api/v1"
    assert result["rustRestBaseUrl"] == "http://192.0.2.10:4731"
    assert result["p2pBindInterface"] == "hide.me"
    assert result["restTimeoutSeconds"] == 60.0
    assert result["bootstrapHashCount"] == 1
    assert result["directBootstrapTransferCount"] == 1
    assert "launch-soak.py" in result["launchCommand"][1]
    conformance_command = result["restOpenApiConformanceCommand"]
    assert "check-rust-rest-openapi-responses.py" in conformance_command[1]
    assert conformance_command[conformance_command.index("--base-url") + 1] == "http://192.0.2.10:4731"
    assert conformance_command[conformance_command.index("--api-key") + 1] == "converged-soak"
    assert conformance_command[conformance_command.index("--rest-coverage-budget") + 1] == "contract"
    assert conformance_command[conformance_command.index("--json-output") + 1] == str(
        output_root / "reports" / "rust-rest-openapi-conformance" / "rust-rest-openapi-conformance.latest.json"
    )
    assert "stop-profile-launch" in result["stopCommand"]


def test_profile_launcher_install_writes_regular_client_and_disabled_ui(tmp_path: Path) -> None:
    module = load_start_soak_module()
    profile_dir = tmp_path / "rust-runtime"

    result = module.install_profile_launchers(profile_dir)

    launch_client = profile_dir / "launch-client-here.py"
    launch_ui = profile_dir / "launch-UI-here.py"
    assert result == {"launchClient": str(launch_client), "launchUi": str(launch_ui)}
    client_text = launch_client.read_text(encoding="utf-8")
    ui_text = launch_ui.read_text(encoding="utf-8")
    assert "rust_profile_client_launcher.run" in client_text
    assert "--profile-dir" in client_text
    assert "emulebb-rust-ui" not in client_text
    assert "emulebb-rust-diagnostics" not in client_text
    assert "native Rust UI launcher is disabled" in ui_text
    assert "emulebb-rust-ui" not in ui_text


def test_background_starter_install_launchers_uses_persisted_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_start_soak_module()
    repo_root = tmp_path / "repo"
    output_root = tmp_path / "out"
    rust_profile = output_root / "soak" / "rust-runtime"
    repo_root.mkdir()
    rust_profile.mkdir(parents=True)
    write_minimal_live_inputs(repo_root, rust_profile)
    monkeypatch.setattr(module, "REPO_ROOT", repo_root)
    set_operator_env(monkeypatch, tmp_path / "workspace", output_root)

    assert module.main(["--seconds", "3600", "--lan-bind-addr", "192.0.2.10", "--install-launchers"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "emulebb.rust-soak-profile.launchers.v1"
    assert result["profileDir"] == str(rust_profile)
    assert Path(result["launchers"]["launchClient"]).is_file()
    assert Path(result["launchers"]["launchUi"]).is_file()
    assert "rust_profile_client_launcher.run" in Path(result["launchers"]["launchClient"]).read_text(
        encoding="utf-8"
    )


def test_background_starter_describe_reports_diagnostics_and_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_start_soak_module()
    repo_root = tmp_path / "repo"
    output_root = tmp_path / "out"
    rust_profile = output_root / "soak" / "rust-runtime"
    repo_root.mkdir()
    rust_profile.mkdir(parents=True)
    write_minimal_live_inputs(repo_root, rust_profile)
    monkeypatch.setattr(module, "REPO_ROOT", repo_root)
    set_operator_env(monkeypatch, tmp_path / "workspace", output_root)

    assert module.main(
        [
            "--seconds",
            "3600",
            "--lan-bind-addr",
            "192.0.2.10",
            "--describe",
            "--diagnostics",
            "--rust-fallback-server",
            "176.123.5.89:4725",
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "rust-diagnostics-live-profile"
    assert result["diagnostics"] is True
    assert result["rustFallbackServers"] == ["176.123.5.89:4725"]
    assert result["rustExe"] == str(output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust-diagnostics.exe")
    assert "--rust-regular" not in result["launchCommand"]


def test_background_starter_describe_reports_custom_rest_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_start_soak_module()
    repo_root = tmp_path / "repo"
    output_root = tmp_path / "out"
    rust_profile = output_root / "soak" / "rust-runtime"
    repo_root.mkdir()
    rust_profile.mkdir(parents=True)
    write_minimal_live_inputs(repo_root, rust_profile)
    monkeypatch.setattr(module, "REPO_ROOT", repo_root)
    set_operator_env(monkeypatch, tmp_path / "workspace", output_root)

    assert module.main(
        ["--seconds", "3600", "--lan-bind-addr", "192.0.2.10", "--describe", "--rest-timeout-seconds", "300"]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["restTimeoutSeconds"] == 300.0
    assert result["launchCommand"][result["launchCommand"].index("--rest-timeout-seconds") + 1] == "300.0"


def test_background_starter_requires_inherited_cargo_target_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_start_soak_module()
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "out"
    wrong_cargo_target = tmp_path / "wrong-target"
    workspace_root.mkdir()
    output_root.mkdir()
    wrong_cargo_target.mkdir()
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(wrong_cargo_target))
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    with pytest.raises(RuntimeError, match="CARGO_TARGET_DIR must already point"):
        module.main(["--seconds", "3600", "--lan-bind-addr", "192.0.2.10", "--describe"])
