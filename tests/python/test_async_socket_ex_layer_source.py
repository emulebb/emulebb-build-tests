from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_layered_sockets_apply_configured_bind_interface_after_bind() -> None:
    source = (app_source_root() / "AsyncSocketExLayer.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "Bind(m_nSocketPort, m_sSocketAddress) || !m_pOwnerSocket->ApplyConfiguredIpv4UnicastInterface()" in source
    assert "Bind(nSocketPort, sSocketAddress) || !m_pOwnerSocket->ApplyConfiguredIpv4UnicastInterface()" in source
    assert "Bind(m_nSocketPort, m_sSocketAddress) && m_pOwnerSocket->ApplyConfiguredIpv4UnicastInterface()" in source
