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
def test_resolve_provider_loads_rust_provider_lazily() -> None:
    assert ed2k_server.resolve_provider("rust").name == "rust"


@pytest.mark.unit
def test_resolve_provider_rejects_unknown_provider() -> None:
    with pytest.raises(RuntimeError, match="provider 'unknown' is unavailable"):
        ed2k_server.resolve_provider("unknown")


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
    control = ed2k_server.GOED2K_PROVIDER.control("http://server", "secret")
    assert control.stats()["ok"] is True
    assert calls == [
        ("admin", ("http://server", "secret", "/api/stats"), {"timeout_seconds": 10.0}),
    ]


@pytest.mark.unit
def test_goed2k_control_normalizes_clients_and_files(monkeypatch) -> None:
    payloads = {
        "/api/clients": {"ok": True, "data": [{"client_name": "aMule"}, "ignored"]},
        "/api/files/0011": {"ok": True, "data": {"hash": "0011"}},
        "/api/files?search=fixture%20file": {"ok": True, "data": [{"hash": "0011"}]},
    }
    monkeypatch.setattr(
        goed2k,
        "admin_request",
        lambda _base, _secret, path, **_kwargs: payloads[path],
    )
    control = ed2k_server.GOED2K_PROVIDER.control("http://server", "secret")

    assert control.list_clients() == [{"client_name": "aMule"}]
    assert control.get_file("0011") == {"hash": "0011"}
    assert control.list_files("fixture file") == {"ok": True, "data": [{"hash": "0011"}]}
