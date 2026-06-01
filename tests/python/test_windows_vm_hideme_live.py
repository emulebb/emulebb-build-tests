from pathlib import Path

from emule_test_harness import windows_vm_hideme_live as live


def test_preferences_bind_p2p_to_hideme_and_enable_vpn_guard(tmp_path: Path) -> None:
    text = live.preferences_text(
        target="win11",
        incoming_dir=tmp_path / "incoming",
        temp_dir=tmp_path / "temp",
        tcp_port=4662,
        udp_port=4672,
        rest_port=4711,
        lan_bind_addr="192.0.2.50",
        api_key="key",
    )

    assert "BindAddr=\n" in text
    assert "BindInterface=hide.me" in text
    assert "VpnGuardMode=Block" in text
    assert "NetworkED2K=1" in text
    assert "NetworkKademlia=0" in text
    assert "ApiKey=key" in text
    assert "BindAddr=192.0.2.50" in text
    assert "BindAddr=127.0.0.1" not in text


def test_safe_download_candidate_rejects_programs_and_weak_sources() -> None:
    safe = {
        "name": "ubuntu-documentation.iso",
        "hash": "0123456789abcdef0123456789abcdef",
        "sizeBytes": 123456,
        "sources": 3,
    }

    assert live.is_safe_download_candidate(safe)
    assert not live.is_safe_download_candidate({**safe, "name": "setup.exe"})
    assert not live.is_safe_download_candidate({**safe, "sources": 1})
    assert not live.is_safe_download_candidate({**safe, "sizeBytes": live.MAX_SAFE_BYTES + 1})
