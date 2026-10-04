from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "smoke-rust-gluetun.py"
    spec = importlib.util.spec_from_file_location("rust_gluetun_smoke_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_zero_packets_are_not_inferred_from_timeout_exit_code() -> None:
    module = load_module()
    result = subprocess.CompletedProcess(
        args=["tcpdump"], returncode=0, stdout="",
        stderr="0 packets captured\n0 packets received by filter\n",
    )
    assert module.captured_packet_count(result) == 0


def test_positive_packet_is_counted_from_capture_output() -> None:
    module = load_module()
    result = subprocess.CompletedProcess(
        args=["tcpdump"], returncode=0,
        stdout="16:24:20 veth0 P 192.0.2.2 > 198.51.100.1: UDP, length 58\n",
        stderr="1 packet captured\n",
    )
    assert module.captured_packet_count(result) == 1


def test_empty_capture_without_summary_is_not_a_pass() -> None:
    module = load_module()
    result = subprocess.CompletedProcess(
        args=["tcpdump"], returncode=0, stdout="", stderr="",
    )
    with pytest.raises(RuntimeError, match="no capture summary"):
        module.captured_packet_count(result)


def test_public_network_ready_requires_ed2k_and_kad_contacts() -> None:
    module = load_module()
    assert module.public_network_ready({
        "data": {"stats": {"ed2kConnected": True}, "kad": {"contactCount": 12}}
    })
    assert not module.public_network_ready({
        "data": {"stats": {"ed2kConnected": False}, "kad": {"contactCount": 12}}
    })
    assert not module.public_network_ready({
        "data": {"stats": {"ed2kConnected": True}, "kad": {"contactCount": 0}}
    })


def test_sha256_file(tmp_path: Path) -> None:
    module = load_module()
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"same-image-input")

    assert module.sha256_file(payload) == hashlib.sha256(b"same-image-input").hexdigest()


def test_isolated_gluetun_compose_is_pinned_and_secret_safe() -> None:
    compose = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "rust-gluetun"
        / "compose.yaml"
    ).read_text(encoding="utf-8")

    assert "qmcgaw/gluetun:v3.41.3" in compose
    assert "network_mode: service:gluetun" in compose
    assert '"127.0.0.1:14711:4711/tcp"' in compose
    assert "EMULEBB_TEST_VPN_PRIVATE_ROOT" in compose
    assert "openvpn_user" in compose and "openvpn_password" in compose
    assert "services:" in compose and compose.count("  emulebb-rust:") == 1


def test_gluetun_smoke_rejoins_recovered_network_namespace() -> None:
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "smoke-rust-gluetun.py"
    ).read_text(encoding="utf-8")

    assert '"start", "gluetun"' in script
    assert '"restart", "emulebb-rust"' in script
    assert "rustRestartedForNamespaceRecovery" in script


def test_reachability_treats_connection_reset_as_not_ready(monkeypatch) -> None:
    module = load_module()

    def reset(*_args, **_kwargs):
        raise ConnectionResetError(104, "reset")

    monkeypatch.setattr(urllib.request, "urlopen", reset)

    assert module.url_is_reachable("http://127.0.0.1:14711/status", "key") is False
