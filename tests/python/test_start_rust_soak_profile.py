from __future__ import annotations

import importlib.util
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
    assert "--cpu-profile-stack" in command
    assert "--process-metrics" in command
    assert "vpn-guard-live.local.json" in command[command.index("--vpn-guard-live-config") + 1]


def test_background_starter_rejects_short_operator_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_start_soak_module()

    with pytest.raises(RuntimeError, match="at least 3600"):
        module.main(["--seconds", "300", "--lan-bind-addr", "192.0.2.10"])
