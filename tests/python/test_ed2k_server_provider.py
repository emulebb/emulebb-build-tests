from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import ed2k_server, goed2k


@pytest.mark.unit
def test_resolve_provider_keeps_goed2k_as_default() -> None:
    assert ed2k_server.resolve_provider(env={}) is ed2k_server.GOED2K_PROVIDER
    assert ed2k_server.resolve_provider("go") is ed2k_server.GOED2K_PROVIDER
    assert ed2k_server.resolve_provider("goed2k-server") is ed2k_server.GOED2K_PROVIDER


@pytest.mark.unit
def test_resolve_provider_reads_explicit_environment() -> None:
    provider = ed2k_server.resolve_provider(env={ed2k_server.ED2K_SERVER_PROVIDER_ENV: "GOED2K"})

    assert provider.name == "goed2k"


@pytest.mark.unit
def test_resolve_provider_rejects_unavailable_rust_provider() -> None:
    with pytest.raises(RuntimeError, match="provider 'rust' is unavailable"):
        ed2k_server.resolve_provider("rust")


@pytest.mark.unit
def test_goed2k_provider_translates_neutral_launch_arguments(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    launch_result = object()

    def fake_launch(**kwargs):
        calls.append(kwargs)
        return launch_result

    monkeypatch.setattr(goed2k, "launch_ed2k_server", fake_launch)

    result = ed2k_server.GOED2K_PROVIDER.launch(
        workspace_root=tmp_path / "workspace",
        server_dir=tmp_path / "server",
        ed2k_port=4661,
        admin_port=8080,
        admin_secret="secret",
        admin_address="127.0.0.1",
        ed2k_address="192.0.2.10",
        fixture_files=[{"hash": "0011"}],
        repo_override="repo",
        exe_override="server.exe",
        protocol_obfuscation=False,
        server_udp=False,
        packet_trace=True,
        health_timeout_seconds=12.5,
    )

    assert result is launch_result
    assert calls == [
        {
            "workspace_root": tmp_path / "workspace",
            "server_dir": tmp_path / "server",
            "ed2k_port": 4661,
            "admin_port": 8080,
            "token": "secret",
            "admin_address": "127.0.0.1",
            "ed2k_address": "192.0.2.10",
            "catalog_files": [{"hash": "0011"}],
            "repo_override": "repo",
            "exe_override": "server.exe",
            "protocol_obfuscation": False,
            "server_udp": False,
            "packet_trace": True,
            "health_timeout_seconds": 12.5,
        }
    ]


@pytest.mark.unit
def test_goed2k_provider_delegates_normalized_observation_calls(monkeypatch) -> None:
    calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    monkeypatch.setattr(
        goed2k,
        "admin_request",
        lambda *args, **kwargs: calls.append(("admin", args, kwargs)) or {"ok": True},
    )
    monkeypatch.setattr(
        goed2k,
        "wait_for_server_client",
        lambda *args, **kwargs: calls.append(("client", args, kwargs)) or {"client_name": "aMule"},
    )
    monkeypatch.setattr(
        goed2k,
        "wait_for_server_file",
        lambda *args, **kwargs: calls.append(("file", args, kwargs)) or {"hash": "0011"},
    )

    provider = ed2k_server.GOED2K_PROVIDER
    assert provider.admin_request("http://server", "secret", "/api/stats", timeout_seconds=3.0)["ok"] is True
    assert provider.wait_for_client("http://server", "secret", "amule", 4.0)["client_name"] == "aMule"
    assert provider.wait_for_file("http://server", "secret", "0011", 5.0)["hash"] == "0011"
    assert calls == [
        ("admin", ("http://server", "secret", "/api/stats"), {"timeout_seconds": 3.0}),
        ("client", ("http://server", "secret", "amule", 4.0), {}),
        ("file", ("http://server", "secret", "0011", 5.0), {}),
    ]
