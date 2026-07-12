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
        p2p_bind_interface_name="test-vpn",
        public_ip="1.1.1.1",
        commands={"connect": ["tool", "--exe", "{app_exe}", "--iface", "{p2p_bind_interface_name}"]},
    )

    vpn_guard_live.write_config(path, payload)
    loaded = vpn_guard_live.load_config(path)

    assert loaded["allowedPublicIpCidrs"] == "1.1.1.1/32"
    assert vpn_guard_live.render_command(
        loaded["commands"]["connect"],
        {"app_exe": "C:\\app\\emulebb.exe", "p2p_bind_interface_name": "test-vpn"},
    ) == ["tool", "--exe", "C:\\app\\emulebb.exe", "--iface", "test-vpn"]


def test_config_allows_non_hideme_interface_only_guard_without_cidrs(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    path.write_text(
        '{"schema":"emulebb.vpnGuardLiveConfig.v1","p2pBindInterfaceName":"test-vpn",'
        '"allowedPublicIpCidrs":"","commands":{}}',
        encoding="utf-8",
    )

    loaded = vpn_guard_live.load_config(path)

    assert loaded["p2pBindInterfaceName"] == "test-vpn"
    assert loaded["allowedPublicIpCidrs"] == ""


def test_hideme_config_requires_approved_public_cidrs(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    path.write_text(
        '{"schema":"emulebb.vpnGuardLiveConfig.v1","p2pBindInterfaceName":"hide.me",'
        '"allowedPublicIpCidrs":"176.10.104.0/22,149.88.27.0/24,98.98.148.0/23,149.50.217.0/24,149.50.216.0/24",'
        '"commands":{}}',
        encoding="utf-8",
    )

    loaded = vpn_guard_live.load_config(path)

    assert loaded["p2pBindInterfaceName"] == "hide.me"


def test_hideme_config_rejects_unapproved_public_cidrs(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    path.write_text(
        '{"schema":"emulebb.vpnGuardLiveConfig.v1","p2pBindInterfaceName":"hide.me",'
        '"allowedPublicIpCidrs":"8.8.8.8/32","commands":{}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="approved hide.me public CIDRs"):
        vpn_guard_live.load_config(path)


def test_config_rejects_unknown_hook(tmp_path) -> None:
    path = tmp_path / "vpn-guard-live.json"
    path.write_text(
        '{"schema":"emulebb.vpnGuardLiveConfig.v1","p2pBindInterfaceName":"hide.me",'
        '"allowedPublicIpCidrs":"176.10.104.0/22,149.88.27.0/24,98.98.148.0/23,149.50.217.0/24,149.50.216.0/24",'
        '"commands":{"bad":["tool"]}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported"):
        vpn_guard_live.load_config(path)
