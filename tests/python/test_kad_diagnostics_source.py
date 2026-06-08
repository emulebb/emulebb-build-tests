from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
APP_ROOT = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"
SRC_ROOT = APP_ROOT / "srchybrid"
BUILD_ROOT = WORKSPACE_ROOT / "repos" / "emulebb-build"


def read_app_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def test_kad_diagnostics_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:KadDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableKadDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_KAD_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(KadDiagnosticsPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(BadPeerDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "$(KadDiagnosticsPreprocessorDefinition)"
        )
        assert config_definitions.index("$(KadDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def test_kad_diagnostics_build_and_release_plumbing() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")
    release_source = (BUILD_ROOT / "emule_workspace" / "release.py").read_text(encoding="utf-8")

    assert '"EMULEBB_ENABLE_KAD_DIAGNOSTICS", "EnableKadDiagnostics"' in build_source
    assert "/p:EnableKadDiagnostics=" in release_source
    assert "KAD_DIAGNOSTICS_BINARY_MARKERS" in release_source
    assert "emulebb-diagnostics-kad.log" in release_source
    assert "enable_kad_diagnostics" in release_source
    assert "kad-diagnostics" in release_source


def test_kad_diagnostics_logger_is_compile_gated() -> None:
    header = read_app_source("KadDiagnosticsSeams.h")
    source = read_app_source("KadDiagnosticsSeams.cpp")
    artifacts = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")

    assert "constexpr LPCTSTR kBinaryMarker = _T(\"KadDiagnostics:\");" in header
    assert "#if EMULEBB_HAS_KAD_DIAGNOSTICS" in header
    assert "inline void LogRoutingSummary" in header
    assert "inline void LogContactEvent" in header
    assert "inline void LogRawContactEvent" in header
    assert "inline void LogPacketEvent" in header
    assert "inline void LogSearchResponseEvent" in header
    assert "CLogFile g_kadDiagnosticsLog;" in source
    assert "kad_event_v1" in source
    assert "kad_routing_summary_v1" in source
    assert "WriteDiagnosticsJsonEvent(" in source
    assert "InitializeDiagnosticsLog(g_kadDiagnosticsLog, pszLogPath, uMaxLogFileSize)" in source
    assert "KadDiagnosticsLogFileName" in artifacts
    assert 'return _T("emulebb-diagnostics-kad.log");' in artifacts
    assert "KadDiagnosticsSeams::InitializeLog" in app_source


def test_kad_diagnostics_covers_health_and_bad_behavior_categories() -> None:
    joined = "\n".join(
        read_app_source(name)
        for name in (
            "kademlia/kademlia/Kademlia.cpp",
            "kademlia/kademlia/Search.cpp",
            "kademlia/net/PacketTracking.cpp",
            "kademlia/routing/RoutingZone.cpp",
            "KadDiagnosticsSeams.cpp",
        )
    )

    for event in (
        "kad_contact_added",
        "kad_contact_updated",
        "kad_contact_update_rejected",
        "kad_contact_rejected",
        "kad_contact_removed",
        "kad_contact_probe",
        "kad_contact_verified",
        "kad_request_flood",
        "kad_request_massive_flood",
        "kad_lookup_response_rejected",
        "kad_lookup_contact_rejected",
        "kad_keyword_result_tag_filtered",
        "kad_keyword_result_tag_rejected",
    ):
        assert event in joined

    assert "EMULEBB_KAD_LOG_ROUTING_SUMMARY" in joined
    assert "legacy_v2_to_v5" in joined
    assert "modern_v8_or_newer" in joined
    assert "version_histogram" in joined
