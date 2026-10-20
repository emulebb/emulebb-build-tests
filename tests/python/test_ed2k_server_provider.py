from __future__ import annotations

import pytest

from emule_test_harness import ed2k_server


@pytest.mark.unit
def test_resolve_provider_uses_rust_by_default() -> None:
    assert ed2k_server.resolve_provider(env={}).name == "rust"


@pytest.mark.unit
def test_resolve_provider_reads_explicit_environment() -> None:
    provider = ed2k_server.resolve_provider(env={ed2k_server.ED2K_SERVER_PROVIDER_ENV: "RUST"})

    assert provider.name == "rust"


@pytest.mark.unit
def test_resolve_provider_loads_rust_provider_lazily() -> None:
    assert ed2k_server.resolve_provider("rust").name == "rust"


@pytest.mark.unit
def test_resolve_provider_rejects_unknown_provider() -> None:
    with pytest.raises(RuntimeError, match="provider 'unknown' is unavailable"):
        ed2k_server.resolve_provider("unknown")


@pytest.mark.parametrize("provider_name", ["go", "goed2k", "goed2k-server", "unknown"])
def test_resolve_provider_rejects_retired_and_unknown_providers(provider_name: str) -> None:
    with pytest.raises(RuntimeError, match="available provider: rust"):
        ed2k_server.resolve_provider(provider_name)


@pytest.mark.unit
def test_require_published_endpoint_uses_server_observed_host() -> None:
    endpoint = ed2k_server.require_published_endpoint(
        {
            "endpoints": [
                {
                    "host": "172.17.128.1",
                    "port": 4662,
                    "user_hash": "AA" * 16,
                }
            ]
        },
        port=4662,
    )

    assert endpoint["host"] == "172.17.128.1"
    assert endpoint["port"] == 4662


@pytest.mark.unit
def test_require_published_endpoint_rejects_missing_or_ambiguous_port() -> None:
    with pytest.raises(RuntimeError, match="found 0"):
        ed2k_server.require_published_endpoint({"endpoints": []}, port=4662)
    with pytest.raises(RuntimeError, match="found 2"):
        ed2k_server.require_published_endpoint(
            {
                "endpoints": [
                    {"host": "192.0.2.10", "port": 4662},
                    {"host": "192.0.2.11", "port": 4662},
                ]
            },
            port=4662,
        )


@pytest.mark.unit
def test_resolve_route_bind_ip_uses_managed_server_route(monkeypatch) -> None:
    calls: list[tuple[str, int]] = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def connect(self, endpoint):
            calls.append(endpoint)

        def getsockname(self):
            return ("172.17.128.1", 50000)

    monkeypatch.setattr(ed2k_server.socket, "socket", lambda *_args: FakeSocket())

    assert ed2k_server.resolve_route_bind_ip("172.17.142.32", 4661) == "172.17.128.1"
    assert calls == [("172.17.142.32", 4661)]
