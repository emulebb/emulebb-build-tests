from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
from pathlib import Path

import pytest

from emule_test_harness import rust_client


def load_rust_live_wire_module():
    script_path = Path(__file__).parents[2] / "scripts" / "rust-live-wire-hideme.py"
    spec = importlib.util.spec_from_file_location("rust_live_wire_hideme", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def rust_repo() -> Path:
    return Path(__file__).parents[3] / "emulebb-rust"


def metadata_path(profile_dir: Path) -> Path:
    return profile_dir / rust_client.RUST_PROFILE_METADATA_FILE


def setting_value(profile_dir: Path, section: str, key: str) -> object:
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        row = conn.execute(
            "SELECT value_json FROM settings WHERE section = ? AND key = ?",
            (section, key),
        ).fetchone()
    assert row is not None
    return json.loads(row[0])


def test_write_rust_profile_supports_rest_only_profile(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
    )

    text = (profile_dir / rust_client.RUST_PROFILE_SETTINGS_FILE).read_text(encoding="utf-8")
    assert 'bindAddr = "192.0.2.10:4711"' in text
    assert 'apiKey = "key"' in text
    assert "[ed2k]" not in text
    assert "runtimeDir" not in text
    assert metadata_path(profile_dir).is_file()


def test_write_rust_profile_supports_incoming_dir(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        incoming_dir=tmp_path / "incoming",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
    )

    assert setting_value(profile_dir, "daemon", "incomingDir") == (tmp_path / "incoming").as_posix()


def test_live_wire_report_separates_completed_and_partial_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rust_live_wire_module()

    candidates = [
        {"hash": "aa", "_searchId": "1", "sizeBytes": 1000, "sources": 3},
        {"hash": "bb", "_searchId": "1", "sizeBytes": 2000, "sources": 4},
    ]

    def fake_retry_http_json(label, attempts, base_url, path, **kwargs):
        _ = (attempts, base_url, kwargs)
        if label in {"download", "resume"}:
            return {"ok": True}
        assert path == "/api/v1/transfers"
        return {
            "transfers": [
                {"hash": "aa", "completedBytes": 1000, "sources": 3, "state": "completed"},
                {"hash": "bb", "completedBytes": 600, "sources": 4, "state": "downloading"},
            ]
        }

    monkeypatch.setattr(module, "retry_http_json", fake_retry_http_json)
    monkeypatch.setattr(module, "api_rows", lambda payload, key: payload[key])
    monkeypatch.setattr(module, "log", lambda message: None)

    result = module.run_downloads("http://192.0.2.10:4711", candidates, 1, max_concurrent=2)

    assert result["completedFiles"] == [{"candidateIndex": 1, "sizeBytes": 1000}]
    assert result["completedFilesTotalBytes"] == 1000
    assert result["aggregateVerifiedBytes"] == 1600
    assert result["totalCompletedBytes"] == 1000


def test_write_rust_profile_requires_complete_ed2k_settings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ED2K Rust profiles"):
        rust_client.write_rust_profile(
            tmp_path / "profile",
            rust_repo=rust_repo(),
            rest_addr="192.0.2.10",
            rest_port=4711,
            api_key="key",
            server_endpoint="192.0.2.10:4661",
        )


def test_write_rust_profile_uses_configurable_ed2k_connect_timeout(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.10:4661",
        connect_timeout_secs=15,
    )

    assert setting_value(profile_dir, "daemon", "p2pBindIp") == "192.0.2.10"
    assert setting_value(profile_dir, "ed2k", "connectTimeoutSecs") == 15
    assert setting_value(profile_dir, "ed2k", "reconnectIntervalSecs") == 60
    assert setting_value(profile_dir, "ed2k", "obfuscationEnabled") is True


def test_write_rust_profile_uses_configurable_reconnect_interval(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.10:4661",
        reconnect_interval_secs=300,
    )

    assert setting_value(profile_dir, "ed2k", "reconnectIntervalSecs") == 300


def test_write_rust_profile_supports_best_effort_initial_nat_mapping(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_interface="hide.me",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
        nat_enabled=True,
        nat_require_initial_mapping=False,
    )

    assert setting_value(profile_dir, "nat", "enabled") is True
    assert setting_value(profile_dir, "nat", "requireInitialMapping") is False


def test_write_rust_profile_supports_interface_and_ip_binding(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        p2p_bind_interface="hide.me",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
    )

    assert setting_value(profile_dir, "daemon", "p2pBindIp") == "192.0.2.10"
    assert setting_value(profile_dir, "daemon", "p2pBindInterface") == "hide.me"


def test_write_rust_profile_supports_interface_only_binding(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_interface="hide.me",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
    )

    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        p2p_bind_ip = conn.execute(
            "SELECT value_json FROM settings WHERE section = 'daemon' AND key = 'p2pBindIp'"
        ).fetchone()
    assert p2p_bind_ip is None
    assert setting_value(profile_dir, "daemon", "p2pBindInterface") == "hide.me"


def test_write_rust_profile_can_disable_obfuscation_and_write_server_entry(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
        server_entry={
            "host": "192.0.2.20",
            "port": 4661,
            "name": "emulebb-local-e2e",
            "udpFlags": 0x78,
            "udpKey": 0x11223344,
            "udpKeyIp": 0,
            "obfuscationPortTcp": 4661,
            "obfuscationPortUdp": 4665,
        },
        obfuscation_enabled=False,
    )

    assert setting_value(profile_dir, "daemon", "p2pBindIp") == "192.0.2.10"
    assert setting_value(profile_dir, "ed2k", "obfuscationEnabled") is False
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        row = conn.execute(
            """
            SELECT address, port, name, enabled, udp_flags, obfuscation_tcp_port
            FROM servers
            """
        ).fetchone()
    assert row == ("192.0.2.20", 4661, "emulebb-local-e2e", 1, 120, 4661)


def test_write_rust_profile_can_replace_server_list(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
    )
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.30:4661",
        replace_servers=True,
    )

    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        rows = conn.execute("SELECT address, port FROM servers ORDER BY address, port").fetchall()
    assert rows == [("192.0.2.30", 4661)]


def test_write_rust_profile_uses_configured_kad_bootstrap_nodes(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.10:4661",
        kad_bootstrap_nodes=["192.0.2.11:4672"],
        kad_bootstrap_min_routing_contacts=1,
    )

    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        endpoints = [
            row[0]
            for row in conn.execute(
                "SELECT endpoint FROM kad_bootstrap_endpoints ORDER BY position"
            )
        ]
    assert endpoints == ["192.0.2.11:4672"]
    assert setting_value(profile_dir, "kad", "bootstrapMinRoutingContacts") == 1


def test_rust_cargo_env_requires_existing_workspace_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_root = tmp_path / "workspace-root"
    output_root = tmp_path / "output-root"
    target_dir = output_root / "builds" / "rust" / "target"
    target_dir.mkdir(parents=True)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    env = rust_client.rust_cargo_env()

    assert Path(env["CARGO_TARGET_DIR"]) == target_dir


def test_rust_cargo_env_rejects_missing_target_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_root = tmp_path / "output-root"
    (output_root / "builds" / "rust" / "target").mkdir(parents=True)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)

    with pytest.raises(RuntimeError, match="CARGO_TARGET_DIR must be set"):
        rust_client.rust_cargo_env()


def test_rust_cargo_env_rejects_wrong_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_root = tmp_path / "output-root"
    expected = output_root / "builds" / "rust" / "target"
    wrong = tmp_path / "wrong-target"
    expected.mkdir(parents=True)
    wrong.mkdir()
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(wrong))

    with pytest.raises(RuntimeError, match="CARGO_TARGET_DIR must be"):
        rust_client.rust_cargo_env()


def test_rust_cargo_env_rejects_nonexistent_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_root = tmp_path / "output-root"
    target_dir = output_root / "builds" / "rust" / "target"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    with pytest.raises(RuntimeError, match="existing directory"):
        rust_client.rust_cargo_env()


def test_start_rust_client_uses_shared_cargo_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    monkeypatch.setattr(rust_client, "rust_cargo_env", lambda: {"CARGO_TARGET_DIR": "target-dir"})
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    process = rust_client.start_rust_client(tmp_path / "repo", tmp_path / "profile", tmp_path / "rust.out")

    assert isinstance(process, FakeProcess)
    assert calls[0]["command"] == [
        "cargo",
        "run",
        "-p",
        "emulebb-daemon",
        "--bin",
        "emulebb-rust",
        "--",
        "--profile",
        str(tmp_path / "profile"),
    ]
    assert calls[0]["cwd"] == tmp_path / "repo"
    assert calls[0]["env"] == {"CARGO_TARGET_DIR": "target-dir"}
    assert calls[0]["stdout"].mode == "w"
    calls[0]["stdout"].close()


def test_start_rust_client_append_keeps_restart_log(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    output_path = tmp_path / "rust.out"
    output_path.write_text("first run\n", encoding="utf-8")
    monkeypatch.setattr(rust_client, "rust_cargo_env", lambda: {"CARGO_TARGET_DIR": "target-dir"})
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    rust_client.start_rust_client_append(tmp_path / "repo", tmp_path / "profile", output_path)

    assert calls[0]["stdout"].mode == "a"
    calls[0]["stdout"].write("second run\n")
    calls[0]["stdout"].close()
    assert output_path.read_text(encoding="utf-8") == "first run\nsecond run\n"


def test_start_rust_client_executable_uses_staged_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    executable = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"exe")
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    process = rust_client.start_rust_client_executable(executable, tmp_path / "profile", tmp_path / "rust.out")

    assert isinstance(process, FakeProcess)
    assert calls[0]["command"] == [str(executable), "--profile", str(tmp_path / "profile")]
    assert calls[0]["cwd"] == executable.parent
    assert calls[0]["stdout"].mode == "w"
    calls[0]["stdout"].close()
