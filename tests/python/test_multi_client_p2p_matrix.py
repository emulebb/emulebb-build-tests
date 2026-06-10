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


def option_value(command: list[str], option: str) -> str | None:
    if option not in command:
        return None
    index = command.index(option)
    return command[index + 1] if index + 1 < len(command) else None


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
        "emulebb_rust": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust"],
            available=False,
            executable=None,
            reason="missing",
        ),
        "emulebb_rust_peer": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust_peer"],
            available=False,
            executable=None,
            reason="missing",
        ),
    }

    rows = module.build_optional_scenario_rows(inventory, require_optional_clients=False)
    rows_by_id = {row["id"]: row for row in rows}

    assert {row["status"] for row in rows} == {"skipped"}
    assert rows_by_id["cl-emulebb-001-downloads-from-cl-emuleai-003"]["missing_clients"] == ["cl-emuleai-003"]
    assert rows_by_id[module.AMULE_TRANSFER_SCENARIO_ID]["missing_clients"] == ["cl-amule-004"]
    assert rows_by_id[module.RUST_BIDIRECTIONAL_SCENARIO_ID]["missing_clients"] == [
        "cl-emulebb-rust-005",
        "cl-emulebb-rust-006",
    ]
    assert rows_by_id[module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID]["missing_clients"] == ["cl-emulebb-rust-005"]


def test_required_scenario_fails_only_targeted_optional_row_when_missing() -> None:
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
        "emulebb_rust": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust"],
            available=False,
            executable=None,
            reason="missing",
        ),
        "emulebb_rust_peer": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust_peer"],
            available=False,
            executable=None,
            reason="missing",
        ),
    }

    rows = module.build_optional_scenario_rows(
        inventory,
        require_optional_clients=False,
        required_scenario_ids={module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID},
    )
    rows_by_id = {row["id"]: row for row in rows}

    assert rows_by_id[module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID]["status"] == "failed"
    assert rows_by_id[module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID]["missing_clients"] == ["cl-emulebb-rust-005"]
    assert rows_by_id[module.RUST_BIDIRECTIONAL_SCENARIO_ID]["status"] == "skipped"
    assert rows_by_id[module.AMULE_TRANSFER_SCENARIO_ID]["status"] == "skipped"


def test_matrix_defaults_to_132_mib_fixture() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.fixture_size_bytes == 132 * 1024 * 1024
    assert args.transfer_completion_timeout_seconds == 1800.0
    assert args.p2p_bind_interface_name == ""
    assert args.require_scenario == []


def test_matrix_accepts_targeted_required_scenario() -> None:
    module = load_suite_module()
    args = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--require-scenario",
            module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID,
        ]
    )

    assert args.require_scenario == [module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID]


def test_optional_scenarios_fail_when_required_and_adapter_not_enabled(tmp_path: Path) -> None:
    module = load_suite_module()
    emuleai_exe = tmp_path / "eMuleAI.exe"
    amule_daemon = tmp_path / "amuled.exe"
    amule_control = tmp_path / "amulecmd.exe"
    rust_manifest = tmp_path / "emulebb-rust" / "Cargo.toml"
    rust_manifest.parent.mkdir()
    for executable in (emuleai_exe, amule_daemon, amule_control, rust_manifest):
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
        "emulebb_rust": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust"],
            available=True,
            executable=rust_manifest,
            reason="available",
        ),
        "emulebb_rust_peer": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust_peer"],
            available=True,
            executable=rust_manifest,
            reason="available",
        ),
    }

    rows = module.build_optional_scenario_rows(inventory, require_optional_clients=True)

    assert {row["status"] for row in rows} == {"failed"}
    assert all("adapter" in str(row["reason"]) for row in rows)
    assert rows[0]["adapter_blocked_clients"] == ["cl-emuleai-003"]
    assert rows[1]["adapter_blocked_clients"] == ["cl-amule-004"]


def test_optional_rows_omit_completed_amule_scenario(tmp_path: Path) -> None:
    module = load_suite_module()
    amule_daemon = tmp_path / "amuled.exe"
    amule_control = tmp_path / "amulecmd.exe"
    for executable in (amule_daemon, amule_control):
        executable.write_bytes(b"")
    inventory = {
        "emuleai": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emuleai"],
            available=False,
            executable=None,
            reason="missing",
        ),
        "amule": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["amule"],
            available=True,
            executable=amule_daemon,
            control_executable=amule_control,
            reason="available",
            deterministic_transfer_adapter=True,
        ),
        "emulebb_rust": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust"],
            available=False,
            executable=None,
            reason="missing",
        ),
        "emulebb_rust_peer": multi_client.ClientAvailability(
            identity=multi_client.CLIENT_IDENTITIES["emulebb_rust_peer"],
            available=False,
            executable=None,
            reason="missing",
        ),
    }

    rows = module.build_optional_scenario_rows(
        inventory,
        require_optional_clients=False,
        completed_scenario_ids={module.AMULE_TRANSFER_SCENARIO_ID},
    )

    assert module.AMULE_TRANSFER_SCENARIO_ID not in {row["id"] for row in rows}
    assert {row["id"] for row in rows} == {
        "cl-emulebb-001-downloads-from-cl-emuleai-003",
        module.THREE_CLIENT_SWARM_SCENARIO_ID,
        module.RUST_BIDIRECTIONAL_SCENARIO_ID,
        module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID,
        "cl-emuleai-003-and-cl-amule-004-discovery",
    }


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
            "--app-exe",
            str(tmp_path / "emulebb.exe"),
            "--client2-app-exe",
            str(tmp_path / "harness.exe"),
            "--profile-seed-dir",
            str(tmp_path / "seed"),
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "10.1.2.3",
            "--link-export-timeout-seconds",
            "45",
        ]
    )

    result = module.run_deterministic_transfer_scenario(paths, args)

    assert result["status"] == "passed"
    assert result["id"] == "cl-emulebb-001-downloads-from-cl-harness-002"
    assert result["clients"] == ["cl-emulebb-001", "cl-harness-002"]
    command = captured["command"]
    assert command[command.index("--artifacts-dir") + 1].endswith("\\h2") or command[command.index("--artifacts-dir") + 1].endswith("/h2")
    assert "--p2p-bind-interface-name" not in command
    assert "--client2-app-exe" in command


def test_common_child_args_forward_explicit_p2p_interface(tmp_path: Path) -> None:
    module = load_suite_module()
    command: list[str] = []
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10", "--p2p-bind-interface-name", "Ethernet"])

    module.add_common_child_args(command, args)

    assert option_value(command, "--p2p-bind-interface-name") == "Ethernet"


def test_matrix_prepares_one_shared_goed2k_binary_for_child_scenarios(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    server_exe = tmp_path / "tools" / "goed2k-server.exe"
    calls: dict[str, object] = {}

    def fake_prepare_ed2k_server_binary(workspace_root: Path, **kwargs):
        calls["workspace_root"] = workspace_root
        calls["kwargs"] = kwargs
        return SimpleNamespace(server_exe=server_exe, build={"server_exe": str(server_exe), "return_code": 0})

    monkeypatch.setattr(module.goed2k, "prepare_ed2k_server_binary", fake_prepare_ed2k_server_binary)
    paths = SimpleNamespace(workspace_root=workspace)
    args = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--ed2k-server-repo",
            str(tmp_path / "goed2k-server"),
        ]
    )

    build = module.prepare_shared_ed2k_server_binary(paths, args)

    assert build == {"server_exe": str(server_exe), "return_code": 0}
    assert args.ed2k_server_exe == str(server_exe)
    assert args.ed2k_server_repo is None
    assert calls == {
        "workspace_root": workspace,
        "kwargs": {
            "repo_override": str(tmp_path / "goed2k-server"),
            "exe_override": None,
        },
    }


def test_child_scenario_runner_normalizes_subprocess_and_report(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    report_path = tmp_path / "child-report.json"
    report_path.write_text('{"status":"passed","detail":"child"}', encoding="utf-8")
    command = [sys.executable, "child.py"]
    calls: dict[str, object] = {}

    def fake_run(run_command, **kwargs):
        calls["command"] = run_command
        calls["kwargs"] = kwargs
        return subprocess.CompletedProcess(run_command, 0, stdout="stdout", stderr="stderr")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    row = module.run_child_scenario(
        scenario_id="scenario-1",
        clients=["cl-emulebb-001", "cl-emulebb-rust-005"],
        command=command,
        cwd=tmp_path,
        env={"X_LOCAL_IP": "192.0.2.10"},
        report_path=report_path,
        artifacts_dir=tmp_path / "artifacts",
    )

    assert row["id"] == "scenario-1"
    assert row["status"] == "passed"
    assert row["clients"] == ["cl-emulebb-001", "cl-emulebb-rust-005"]
    assert row["command"] == command
    assert row["report"] == {"status": "passed", "detail": "child"}
    assert row["artifacts_dir"] == str(tmp_path / "artifacts")
    assert calls["kwargs"]["cwd"] == tmp_path
    assert calls["kwargs"]["env"] == {"X_LOCAL_IP": "192.0.2.10"}


def test_amule_transfer_scenario_uses_stable_client_ids(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    captured: dict[str, object] = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "matrix")
    args = module.parse_args(
        [
            "--app-exe",
            str(tmp_path / "emulebb.exe"),
            "--profile-seed-dir",
            str(tmp_path / "seed"),
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "10.1.2.3",
            "--amule-daemon-exe",
            str(tmp_path / "amuled.exe"),
            "--amule-control-exe",
            str(tmp_path / "amulecmd.exe"),
        ]
    )

    result = module.run_amule_transfer_scenario(paths, args)

    assert result["status"] == "passed"
    assert result["id"] == "cl-emulebb-001-downloads-from-cl-amule-004"
    assert result["clients"] == ["cl-emulebb-001", "cl-amule-004"]
    command = captured["command"]
    assert "deterministic-amule-transfer.py" in str(command[1])
    assert command[command.index("--artifacts-dir") + 1].endswith("\\a4") or command[command.index("--artifacts-dir") + 1].endswith("/a4")
    assert "--amule-daemon-exe" in command
    assert "--amule-control-exe" in command


def test_three_client_swarm_scenario_forwards_harness_and_amule(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    captured: dict[str, object] = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "matrix")
    args = module.parse_args(
        [
            "--app-exe",
            str(tmp_path / "emulebb.exe"),
            "--client2-app-exe",
            str(tmp_path / "harness.exe"),
            "--profile-seed-dir",
            str(tmp_path / "seed"),
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "10.1.2.3",
            "--amule-daemon-exe",
            str(tmp_path / "amuled.exe"),
            "--amule-control-exe",
            str(tmp_path / "amulecmd.exe"),
        ]
    )

    result = module.run_three_client_swarm_scenario(paths, args)

    assert result["status"] == "passed"
    assert result["id"] == module.THREE_CLIENT_SWARM_SCENARIO_ID
    assert result["clients"] == ["cl-emulebb-001", "cl-harness-002", "cl-amule-004"]
    command = captured["command"]
    assert "three-client-swarm-transfer.py" in str(command[1])
    assert command[command.index("--artifacts-dir") + 1].endswith("\\sw3") or command[command.index("--artifacts-dir") + 1].endswith("/sw3")
    assert "--client2-app-exe" in command
    assert "--amule-daemon-exe" in command
    assert "--amule-control-exe" in command


def test_emulebb_rust_exchange_scenario_uses_existing_local_client_campaign(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        captured["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path))
    workspace_root = tmp_path / "workspaces" / "workspace"
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "matrix", workspace_root=workspace_root)
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])
    args.ed2k_server_exe = str(tmp_path / "tools" / "goed2k-server.exe")

    result = module.run_emulebb_rust_exchange_scenario(paths, args)

    assert result["status"] == "passed"
    assert result["id"] == module.RUST_BIDIRECTIONAL_SCENARIO_ID
    assert result["clients"] == ["cl-emulebb-rust-005", "cl-emulebb-rust-006"]
    assert captured["command"] == [
        sys.executable,
        "-m",
        "emule_workspace",
        "test",
        "python",
        "--path",
        "tests/python/test_emulebb_rust_local_client.py",
        "--quiet",
        "-k",
        "peers_exchange",
    ]
    assert captured["env"]["X_LOCAL_IP"] == "192.0.2.10"
    assert captured["env"][module.goed2k.ED2K_SERVER_EXE_ENV] == str(
        (tmp_path / "tools" / "goed2k-server.exe").resolve()
    )
    assert captured["cwd"] == tmp_path / "repos" / "emulebb-build"


def test_emulebb_rust_emulebb_bidirectional_scenario_uses_cross_client_script(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    captured: dict[str, object] = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "matrix")
    args = module.parse_args(
        [
            "--app-exe",
            str(tmp_path / "emulebb.exe"),
            "--profile-seed-dir",
            str(tmp_path / "seed"),
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "10.1.2.3",
            "--ed2k-server-repo",
            str(tmp_path / "goed2k-server"),
            "--ed2k-server-exe",
            str(tmp_path / "goed2k-server.exe"),
            "--link-export-timeout-seconds",
            "45",
        ]
    )

    result = module.run_emulebb_rust_emulebb_bidirectional_scenario(paths, args)

    assert result["status"] == "passed"
    assert result["id"] == module.RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID
    assert result["clients"] == ["cl-emulebb-001", "cl-emulebb-rust-005"]
    command = captured["command"]
    assert "emulebb-rust-emulebb-cross-client.py" in str(command[1])
    assert command[command.index("--artifacts-dir") + 1].endswith("\\r5-e1") or command[command.index("--artifacts-dir") + 1].endswith("/r5-e1")
    assert option_value(command, "--lan-bind-addr") == "192.0.2.10"
    assert option_value(command, "--p2p-bind-interface-address") == "10.1.2.3"
    assert option_value(command, "--ed2k-server-repo") == str((tmp_path / "goed2k-server").resolve())
    assert option_value(command, "--ed2k-server-exe") == str((tmp_path / "goed2k-server.exe").resolve())
    assert option_value(command, "--link-export-timeout-seconds") == "45.0"


def test_emulebb_rust_emulebb_bidirectional_scenario_uses_prepared_goed2k_exe_only(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    captured: dict[str, object] = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "matrix")
    args = module.parse_args(
        [
            "--app-exe",
            str(tmp_path / "emulebb.exe"),
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "10.1.2.3",
            "--ed2k-server-repo",
            str(tmp_path / "goed2k-server"),
        ]
    )
    args.ed2k_server_exe = str(tmp_path / "tools" / "goed2k-server.exe")
    args.ed2k_server_repo = None

    result = module.run_emulebb_rust_emulebb_bidirectional_scenario(paths, args)

    assert result["status"] == "passed"
    command = captured["command"]
    assert option_value(command, "--ed2k-server-exe") == str((tmp_path / "tools" / "goed2k-server.exe").resolve())
    assert "--ed2k-server-repo" not in command


def test_matrix_main_stops_stray_goed2k_processes_after_child_failure(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[str] = []
    workspace_root = tmp_path / "workspaces" / "workspace"
    app_exe = tmp_path / "emulebb.exe"
    harness_exe = tmp_path / "harness.exe"
    app_exe.write_text("", encoding="utf-8")
    harness_exe.write_text("", encoding="utf-8")
    paths = SimpleNamespace(
        workspace_root=workspace_root,
        app_exe=app_exe,
        source_artifacts_dir=tmp_path / "artifacts",
    )
    paths.source_artifacts_dir.mkdir()

    def available_client(key: str):
        identity = multi_client.CLIENT_IDENTITIES[key]
        return multi_client.ClientAvailability(
            identity=identity,
            available=True,
            executable=tmp_path / f"{identity.profile_id}.exe",
            reason="available",
            deterministic_transfer_adapter=True,
        )

    inventory = {
        "emulebb": available_client("emulebb"),
        "harness": available_client("harness"),
        "emuleai": multi_client.ClientAvailability(multi_client.CLIENT_IDENTITIES["emuleai"], False, None, "missing"),
        "amule": multi_client.ClientAvailability(multi_client.CLIENT_IDENTITIES["amule"], False, None, "missing"),
        "emulebb_rust": multi_client.ClientAvailability(multi_client.CLIENT_IDENTITIES["emulebb_rust"], False, None, "missing"),
        "emulebb_rust_peer": multi_client.ClientAvailability(
            multi_client.CLIENT_IDENTITIES["emulebb_rust_peer"],
            False,
            None,
            "missing",
        ),
    }

    monkeypatch.setattr(module.harness_cli_common, "prepare_run_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(module, "resolve_windows_client_inventory", lambda **_kwargs: inventory)
    monkeypatch.setattr(module, "prepare_shared_ed2k_server_binary", lambda _paths, _args: {"skipped": True})
    monkeypatch.setattr(
        module,
        "run_deterministic_transfer_scenario",
        lambda _paths, _args: {"id": module.HARNESS_TRANSFER_SCENARIO_ID, "status": "failed"},
    )
    monkeypatch.setattr(module.goed2k, "stop_server_processes", lambda: calls.append("stop_goed2k"))
    monkeypatch.setattr(module.harness_cli_common, "write_json_file", lambda _path, _report: calls.append("write_report"))
    monkeypatch.setattr(module.harness_cli_common, "publish_run_artifacts", lambda _paths: calls.append("publish_run"))
    monkeypatch.setattr(module.harness_cli_common, "publish_latest_report", lambda _paths: calls.append("publish_latest"))
    monkeypatch.setattr(module.harness_cli_common, "cleanup_source_artifacts", lambda _paths: calls.append("cleanup_artifacts"))

    exit_code = module.main(
        [
            "--app-exe",
            str(app_exe),
            "--client2-app-exe",
            str(harness_exe),
            "--lan-bind-addr",
            "192.0.2.10",
        ]
    )

    assert exit_code == 1
    assert calls == ["write_report", "stop_goed2k", "publish_run", "publish_latest", "cleanup_artifacts"]
