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
