from __future__ import annotations

import pytest

from emule_test_harness import ed2k_server


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
