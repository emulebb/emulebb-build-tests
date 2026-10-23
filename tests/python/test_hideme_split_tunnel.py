from __future__ import annotations

from pathlib import Path

from emule_test_harness import hideme_split_tunnel


def test_ensure_vpn_ready_restarts_a_disconnected_client(
    tmp_path: Path,
    monkeypatch,
) -> None:
    restarts: list[bool] = []
    executable = tmp_path / "emulebb-rust.exe"

    monkeypatch.setattr(hideme_split_tunnel, "ensure_whitelisted", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(hideme_split_tunnel, "ensure_excluded_ip_ranges", lambda: False)
    monkeypatch.setattr(hideme_split_tunnel, "hideme_adapter_up", lambda: False)
    monkeypatch.setattr(hideme_split_tunnel, "restart_hideme", lambda: restarts.append(True))
    monkeypatch.setattr(hideme_split_tunnel, "hideme_adapter_ipv4", lambda: "10.0.0.2")

    result = hideme_split_tunnel.ensure_vpn_ready(executable)

    assert restarts == [True]
    assert result["bindIp"] == "10.0.0.2"


def test_ensure_vpn_ready_does_not_restart_a_connected_client(
    tmp_path: Path,
    monkeypatch,
) -> None:
    waits: list[bool] = []
    executable = tmp_path / "emulebb-rust.exe"

    monkeypatch.setattr(hideme_split_tunnel, "ensure_whitelisted", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(hideme_split_tunnel, "ensure_excluded_ip_ranges", lambda: False)
    monkeypatch.setattr(hideme_split_tunnel, "hideme_adapter_up", lambda: True)
    monkeypatch.setattr(hideme_split_tunnel, "wait_for_tunnel", lambda: waits.append(True))
    monkeypatch.setattr(hideme_split_tunnel, "restart_hideme", lambda: None)
    monkeypatch.setattr(hideme_split_tunnel, "hideme_adapter_ipv4", lambda: "10.0.0.2")

    result = hideme_split_tunnel.ensure_vpn_ready(executable)

    assert waits == [True]
    assert result["bindIp"] == "10.0.0.2"
