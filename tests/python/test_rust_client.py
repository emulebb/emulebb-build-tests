from __future__ import annotations

import os
from pathlib import Path

import pytest

from emule_test_harness import rust_client


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
    assert "connectTimeoutSecs = 15" in text


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
