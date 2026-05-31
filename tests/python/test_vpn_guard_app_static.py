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


def test_kad_rest_connect_and_bootstrap_report_vpn_guard_refusal() -> None:
    source = (APP_ROOT / "srchybrid" / "WebServerJson.cpp").read_text(encoding="utf-8")

    assert "json BuildP2PConnectionCommandBlockedJson(json result)" in source
    assert 'result["operationQueued"] = false;' in source
    assert 'result["blockedByVpnGuard"] = true;' in source
    assert 'result["network"] = BuildNetworkStatusJson();' in source

    connect_index = source.index('if (strCommand == "kad/connect")')
    connect_dispatch_index = source.index("InvokeWebGuiInteraction(WEBGUIIA_KAD_START)", connect_index)
    connect_block = source[connect_index:connect_dispatch_index]
    assert "IsP2PConnectionCommandBlocked()" in connect_block
    assert "BuildP2PConnectionCommandBlockedJson(BuildKadStatusJson())" in connect_block

    bootstrap_index = source.index('if (strCommand == "kad/bootstrap")')
    bootstrap_dispatch_index = source.index("InvokeWebGuiInteraction", bootstrap_index)
    bootstrap_block = source[bootstrap_index:bootstrap_dispatch_index]
    assert "IsP2PConnectionCommandBlocked()" in bootstrap_block
    assert "BuildP2PConnectionCommandBlockedJson(BuildKadStatusJson())" in bootstrap_block


def test_vpn_guard_release_strings_keep_reviewed_german_and_french_copy() -> None:
    german = (APP_ROOT / "srchybrid" / "lang" / "de_DE.rc").read_text(encoding="utf-8")
    french = (APP_ROOT / "srchybrid" / "lang" / "fr_FR.rc").read_text(encoding="utf-8")

    assert "Abtrennung erforderlich" not in german
    assert "IPv4 CIDRs" not in german
    assert "Trennen angefordert" in german
    assert "IPv4-CIDR-Bereiche" in german

    assert "IPv4 public facultatif CIDRs" not in french
    assert "n'est pas armée" not in french
    assert "CIDR IPv4 publics facultatifs" in french
    assert "déconnexion douce standard" in french
