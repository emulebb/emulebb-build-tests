"""Pure orchestration checks for the CI-054 campaign wrapper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

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
