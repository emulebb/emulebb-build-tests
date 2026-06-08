from __future__ import annotations

from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
APP_ROOT = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"
SRC_ROOT = APP_ROOT / "srchybrid"


def read_app_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def test_kad_contact_quality_score_is_local_and_health_weighted() -> None:
    header = read_app_source("kademlia/routing/Contact.h")
    source = read_app_source("kademlia/routing/Contact.cpp")

    assert "UINT\tGetLocalQualityScore(time_t tNow = 0) const;" in header
    assert "bool\tIsWeakForReplacement(time_t tNow = 0) const;" in header
    assert "UINT CContact::GetLocalQualityScore(time_t tNow) const" in source
    assert "bool CContact::IsWeakForReplacement(time_t tNow) const" in source
    assert ", m_bReceivedHelloPacket()" in source
    assert ", m_bBootstrapContact()" in source
    assert "m_bIPVerified" in source
    assert "m_bReceivedHelloPacket" in source
    assert "!m_cUDPKey.IsEmpty()" in source
    assert "GetKadVersionQuality" in source
    assert "KADEMLIA_VERSION8_49b" in source


def test_kad_routing_uses_quality_for_probe_and_weak_replacement_only() -> None:
    routing_bin_header = read_app_source("kademlia/routing/RoutingBin.h")
    routing_bin_source = read_app_source("kademlia/routing/RoutingBin.cpp")
    routing_zone_source = read_app_source("kademlia/routing/RoutingZone.cpp")

    assert "GetLowestQualityExpiredContact(time_t tNow)" in routing_bin_header
    assert "ReplaceWeakContact(CContact *pContact" in routing_bin_header
    assert "KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN = 120" in routing_bin_source
    assert "GetWeakestReplaceableContact" in routing_bin_source
    assert "CanAcceptContactIPLimits" in routing_bin_source
    assert "m_pBin->ReplaceWeakContact" in routing_zone_source
    assert "replace-weak-contact" in routing_zone_source
    assert "weak-local-quality" in routing_zone_source
    assert "GetLowestQualityExpiredContact(tNow)" in routing_zone_source
    assert "GetRandomContact(uint32 nMaxType, uint32 nMinKadVersion)" in routing_bin_source


def test_kad_diagnostics_exposes_contact_quality_score() -> None:
    diagnostics = read_app_source("KadDiagnosticsSeams.cpp")
    routing_zone = read_app_source("kademlia/routing/RoutingZone.cpp")

    assert "local_quality_score" in diagnostics
    assert "GetLocalQualityScore(tNow)" in diagnostics
    assert "removed_quality_score" in routing_zone
    assert "new_quality_score" in routing_zone
