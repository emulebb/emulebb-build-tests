from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import hideme_vpn


def write_settings(path: Path, *, mode: int) -> None:
    path.write_text(json.dumps({"SplitTunneling": {"Mode": mode}}), encoding="utf-8")


def test_full_tunnel_preflight_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings_path = tmp_path / "vpn.settings"
    write_settings(settings_path, mode=hideme_vpn.FULL_TUNNEL_SPLIT_MODE)
    original = settings_path.read_bytes()

    monkeypatch.setattr(hideme_vpn, "hideme_adapter_up", lambda: True)
    monkeypatch.setattr(
        hideme_vpn,
        "hideme_public_route_status",
        lambda: {"adapterCount": 1, "routeProbeCount": 3, "routesThroughHideMe": True},
    )
    monkeypatch.setattr(hideme_vpn, "hideme_adapter_ipv4", lambda: "192.0.2.10")

    status = hideme_vpn.require_full_tunnel_ready(settings_path=settings_path)

    assert status == {
        "schema": "emulebb.hide-me-full-tunnel-status.v1",
        "splitTunnelMode": 0,
        "adapterUp": True,
        "adapterCount": 1,
        "routeProbeCount": 3,
        "routesThroughHideMe": True,
        "bindIp": "192.0.2.10",
    }
    assert settings_path.read_bytes() == original


def test_full_tunnel_preflight_rejects_split_tunneling(tmp_path: Path) -> None:
    settings_path = tmp_path / "vpn.settings"
    write_settings(settings_path, mode=2)

    with pytest.raises(RuntimeError, match="split tunneling must be disabled"):
        hideme_vpn.require_full_tunnel_ready(settings_path=settings_path)


def test_full_tunnel_preflight_rejects_disconnected_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = tmp_path / "vpn.settings"
    write_settings(settings_path, mode=0)
    monkeypatch.setattr(hideme_vpn, "hideme_adapter_up", lambda: False)

    with pytest.raises(RuntimeError, match="must already be connected"):
        hideme_vpn.require_full_tunnel_ready(settings_path=settings_path)


def test_full_tunnel_preflight_rejects_public_routes_outside_vpn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = tmp_path / "vpn.settings"
    write_settings(settings_path, mode=0)
    monkeypatch.setattr(hideme_vpn, "hideme_adapter_up", lambda: True)
    monkeypatch.setattr(
        hideme_vpn,
        "hideme_public_route_status",
        lambda: {"adapterCount": 1, "routeProbeCount": 3, "routesThroughHideMe": False},
    )

    with pytest.raises(RuntimeError, match="do not resolve through"):
        hideme_vpn.require_full_tunnel_ready(settings_path=settings_path)


def test_public_route_status_requires_every_probe_on_hide_me(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hideme_vpn,
        "run_powershell",
        lambda *_args, **_kwargs: json.dumps(
            {
                "adapterInterfaceIndexes": [17],
                "routeInterfaceIndexes": [17, 8, 17],
            }
        ),
    )

    assert hideme_vpn.hideme_public_route_status() == {
        "adapterCount": 1,
        "routeProbeCount": 3,
        "routesThroughHideMe": False,
    }
