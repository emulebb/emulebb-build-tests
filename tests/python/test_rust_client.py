from __future__ import annotations

import importlib.util
import os
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


def test_write_rust_config_supports_rest_only_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
    )

    text = config_path.read_text(encoding="utf-8")
    assert 'runtimeDir = "' in text
    assert 'bindAddr = "192.0.2.10:4711"' in text
    assert 'apiKey = "key"' in text
    assert "[ed2k]" not in text


def test_write_rust_config_supports_incoming_dir(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        incoming_dir=tmp_path / "incoming",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
    )

    text = config_path.read_text(encoding="utf-8")
    assert f'incomingDir = "{(tmp_path / "incoming").as_posix()}"' in text


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


def test_write_rust_config_requires_complete_ed2k_settings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ED2K Rust configs"):
        rust_client.write_rust_config(
            tmp_path / "emulebb-rust.toml",
            runtime_dir=tmp_path / "runtime",
            rest_addr="192.0.2.10",
            rest_port=4711,
            api_key="key",
            server_endpoint="192.0.2.10:4661",
        )


def test_write_rust_config_uses_configurable_ed2k_connect_timeout(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.10:4661",
        connect_timeout_secs=15,
    )

    text = config_path.read_text(encoding="utf-8")
    assert 'p2pBindIp = "192.0.2.10"' in text
    assert "connectTimeoutSecs = 15" in text
    assert "reconnectIntervalSecs = 60" in text
    assert "obfuscationEnabled = true" in text


def test_write_rust_config_uses_configurable_reconnect_interval(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.10:4661",
        reconnect_interval_secs=300,
    )

    text = config_path.read_text(encoding="utf-8")
    assert "reconnectIntervalSecs = 300" in text


def test_write_rust_config_supports_interface_and_ip_binding(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        p2p_bind_interface="hide.me",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
    )

    text = config_path.read_text(encoding="utf-8")
    assert 'p2pBindIp = "192.0.2.10"' in text
    assert 'p2pBindInterface = "hide.me"' in text


def test_write_rust_config_supports_interface_only_binding(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_interface="hide.me",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.20:4661",
    )

    text = config_path.read_text(encoding="utf-8")
    assert "p2pBindIp" not in text
    assert 'p2pBindInterface = "hide.me"' in text


def test_write_rust_config_can_disable_obfuscation_and_write_server_entry(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
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

    text = config_path.read_text(encoding="utf-8")
    assert 'p2pBindIp = "192.0.2.10"' in text
    assert "obfuscationEnabled = false" in text
    assert "serverEndpoints" not in text
    assert "[[ed2k.serverEntries]]" in text
    assert 'host = "192.0.2.20"' in text
    assert "port = 4661" in text
    assert "udpFlags = 120" in text
    assert "udpKey = 287454020" in text
    assert "obfuscationPortUdp = 4665" in text


def test_write_rust_config_uses_configured_kad_bootstrap_nodes(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
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

    text = config_path.read_text(encoding="utf-8")
    assert 'bootstrapNodes = ["192.0.2.11:4672"]' in text
    assert "bootstrapMinRoutingContacts = 1" in text


def test_write_rust_config_enables_fast_harness_kad_hello_intro(tmp_path: Path) -> None:
    config_path = tmp_path / "emulebb-rust.toml"

    rust_client.write_rust_config(
        config_path,
        runtime_dir=tmp_path / "runtime",
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
        p2p_bind_ip="192.0.2.10",
        ed2k_port=4662,
        kad_port=4672,
        server_endpoint="192.0.2.10:4661",
    )

    text = config_path.read_text(encoding="utf-8")
    assert "helloIntroIntervalSecs = 1" in text
    assert "helloIntroFanout = 4" in text


def test_rust_cargo_env_uses_workspace_output_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_root = tmp_path / "workspace-root"
    output_root = tmp_path / "output-root"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)

    env = rust_client.rust_cargo_env()

    assert Path(env["CARGO_TARGET_DIR"]) == output_root / "builds" / "rust" / "target"
    assert Path(env["CARGO_TARGET_DIR"]).is_dir()
    assert os.environ.get("CARGO_TARGET_DIR") is None


def test_start_rust_client_uses_shared_cargo_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    monkeypatch.setattr(rust_client, "rust_cargo_env", lambda: {"CARGO_TARGET_DIR": "target-dir"})
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    process = rust_client.start_rust_client(tmp_path / "repo", tmp_path / "config.toml", tmp_path / "rust.out")

    assert isinstance(process, FakeProcess)
    assert calls[0]["command"] == [
        "cargo",
        "run",
        "-p",
        "emulebb-daemon",
        "--bin",
        "emulebb-rust",
        "--",
        "--config",
        str(tmp_path / "config.toml"),
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

    rust_client.start_rust_client_append(tmp_path / "repo", tmp_path / "config.toml", output_path)

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

    process = rust_client.start_rust_client_executable(executable, tmp_path / "config.toml", tmp_path / "rust.out")

    assert isinstance(process, FakeProcess)
    assert calls[0]["command"] == [str(executable), "--config", str(tmp_path / "config.toml")]
    assert calls[0]["cwd"] == executable.parent
    assert calls[0]["stdout"].mode == "w"
    calls[0]["stdout"].close()
