from __future__ import annotations

from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main"


def test_rest_status_and_snapshot_expose_network_vpn_guard_diagnostics() -> None:
    source = (APP_ROOT / "srchybrid" / "WebServerJson.cpp").read_text(encoding="utf-8")

    assert "json BuildNetworkStatusJson()" in source
    assert '{"vpnGuard", json{' in source
    assert '{"network", BuildNetworkStatusJson()}' in source
    assert 'status["network"]' in source


def test_kad_bootstrap_web_interaction_is_guard_gated() -> None:
    source = (APP_ROOT / "srchybrid" / "EmuleDlg.cpp").read_text(encoding="utf-8")
    case_index = source.index("case WEBGUIIA_KAD_BOOTSTRAP:")
    bootstrap_index = source.index("Kademlia::CKademlia::Bootstrap", case_index)

    guarded_block = source[case_index:bootstrap_index]
    assert "CanUseP2PConnectionCommands()" in guarded_block
    assert "LogP2PConnectionCommandBlocked()" in guarded_block
