from __future__ import annotations

import pytest

from emule_test_harness import vpn_guard_live


def test_public_ipv4_cidr32_accepts_realistic_public_address() -> None:
    assert vpn_guard_live.public_ipv4_cidr32("8.8.8.8") == "8.8.8.8/32"


def test_public_ipv4_cidr32_rejects_private_address() -> None:
    with pytest.raises(ValueError, match="globally routable"):
        vpn_guard_live.public_ipv4_cidr32("192.168.1.10")


def test_config_roundtrip_and_command_rendering(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    payload = vpn_guard_live.build_config(
        p2p_bind_interface_name="hide.me",
        public_ip="1.1.1.1",
        commands={"connect": ["tool", "--exe", "{app_exe}", "--iface", "{p2p_bind_interface_name}"]},
    )

    vpn_guard_live.write_config(path, payload)
    loaded = vpn_guard_live.load_config(path)

    assert loaded["allowedPublicIpCidrs"] == "1.1.1.1/32"
    assert vpn_guard_live.render_command(
        loaded["commands"]["connect"],
        {"app_exe": "C:\\app\\emulebb.exe", "p2p_bind_interface_name": "hide.me"},
    ) == ["tool", "--exe", "C:\\app\\emulebb.exe", "--iface", "hide.me"]


def test_config_allows_interface_only_guard_without_cidrs(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    path.write_text(
        '{"schema":"emulebb.vpnGuardLiveConfig.v1","p2pBindInterfaceName":"hide.me",'
        '"allowedPublicIpCidrs":"","commands":{}}',
        encoding="utf-8",
    )

    loaded = vpn_guard_live.load_config(path)

    assert loaded["p2pBindInterfaceName"] == "hide.me"
    assert loaded["allowedPublicIpCidrs"] == ""


def test_config_rejects_unknown_hook(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    path.write_text(
        '{"schema":"emulebb.vpnGuardLiveConfig.v1","p2pBindInterfaceName":"hide.me",'
        '"allowedPublicIpCidrs":"8.8.8.8/32","commands":{"bad":["tool"]}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported"):
        vpn_guard_live.load_config(path)
