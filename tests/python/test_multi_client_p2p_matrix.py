from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from emule_test_harness import multi_client


def load_suite_module():
    """Loads the hyphenated multi-client matrix script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "multi-client-p2p-matrix.py"
    spec = importlib.util.spec_from_file_location("multi_client_p2p_matrix_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_optional_scenarios_are_skipped_when_optional_clients_missing() -> None:
    module = load_suite_module()
    inventory = {
        "emuleai": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emuleai"],
            available=False,
            executable=None,
            reason="missing",
        ),
        "amule": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["amule"],
            available=False,
            executable=None,
            reason="missing",
        ),
    }

    rows = module.build_optional_scenario_rows(inventory, require_optional_clients=False)

    assert {row["status"] for row in rows} == {"skipped"}
    assert rows[0]["missing_clients"] == ["client03-emuleai"]
    assert rows[1]["missing_clients"] == ["client04-amule"]


def test_optional_scenarios_fail_when_required_and_adapter_not_enabled(tmp_path: Path) -> None:
    module = load_suite_module()
    emuleai_exe = tmp_path / "eMuleAI.exe"
    amule_daemon = tmp_path / "amuled.exe"
    amule_control = tmp_path / "amulecmd.exe"
    for executable in (emuleai_exe, amule_daemon, amule_control):
        executable.write_bytes(b"")
    inventory = {
        "emuleai": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emuleai"],
            available=True,
            executable=emuleai_exe,
            reason="available",
        ),
        "amule": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["amule"],
            available=True,
            executable=amule_daemon,
            control_executable=amule_control,
            reason="available",
        ),
    }

    rows = module.build_optional_scenario_rows(inventory, require_optional_clients=True)

    assert {row["status"] for row in rows} == {"failed"}
    assert all("adapter" in str(row["reason"]) for row in rows)


def test_deterministic_transfer_scenario_uses_stable_client_ids(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    captured: dict[str, object] = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "matrix")
    args = module.parse_args(
        [
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--app-exe",
            str(tmp_path / "emule.exe"),
            "--client2-app-exe",
            str(tmp_path / "harness.exe"),
            "--profile-seed-dir",
            str(tmp_path / "seed"),
            "--p2p-bind-interface-address",
            "10.1.2.3",
        ]
    )

    result = module.run_deterministic_transfer_scenario(paths, args)

    assert result["status"] == "passed"
    assert result["clients"] == ["client01-emulebb", "client02-harness"]
    command = captured["command"]
    assert "--p2p-bind-interface-name" in command
    assert "--client2-app-exe" in command
