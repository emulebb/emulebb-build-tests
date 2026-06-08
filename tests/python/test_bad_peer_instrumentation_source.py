from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
APP_ROOT = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"
SRC_ROOT = APP_ROOT / "srchybrid"
BUILD_ROOT = WORKSPACE_ROOT / "repos" / "emulebb-build"


def read_app_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def test_bad_peer_instrumentation_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:BadPeerDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableBadPeerDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_BAD_PEER_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(BadPeerDiagnosticsPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(DownloadSlotDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "$(BadPeerDiagnosticsPreprocessorDefinition)"
        )
        assert config_definitions.index("$(BadPeerDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def test_bad_peer_instrumentation_build_and_release_plumbing() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")
    release_source = (BUILD_ROOT / "emule_workspace" / "release.py").read_text(encoding="utf-8")

    assert '"EMULEBB_ENABLE_BAD_PEER_DIAGNOSTICS", "EnableBadPeerDiagnostics"' in build_source
    assert 'extra_properties.append(f"/p:{property_name}=' in build_source
    assert "BAD_PEER_DIAGNOSTICS_BINARY_MARKERS" in release_source
    assert "emulebb-diagnostics-bad-peer.log" in release_source
    assert "enable_bad_peer_diagnostics" in release_source


def test_bad_peer_instrumentation_logger_is_compile_gated() -> None:
    header = read_app_source("BadPeerInstrumentationSeams.h")
    source = read_app_source("BadPeerInstrumentationSeams.cpp")
    artifact_names = read_app_source("LogArtifactNames.h")
    app_source = read_app_source("Emule.cpp")

    assert "constexpr LPCTSTR kBinaryMarker = _T(\"BadPeerDiagnostics:\");" in header
    assert "#if EMULEBB_HAS_BAD_PEER_DIAGNOSTICS" in header
    assert "inline void LogClientEvent" in header
    assert "inline void LogIpEvent" in header
    assert "inline void LogSearchEvent" in header
    assert "CLogFile g_badPeerInstrumentationLog;" in source
    assert "bad_peer_event_v1" in source
    assert "InitializeDiagnosticsLog(g_badPeerInstrumentationLog, pszLogPath, uMaxLogFileSize)" in source
    assert "WriteDiagnosticsLogLine(g_badPeerInstrumentationLog, g_badPeerInstrumentationLogLock, strJson)" in source
    assert "BadPeerDiagnosticsLogFileName" in artifact_names
    assert 'return _T("emulebb-diagnostics-bad-peer.log");' in artifact_names
    assert "BadPeerInstrumentationSeams::InitializeLog" in app_source


def test_bad_peer_instrumentation_covers_evidence_categories() -> None:
    joined = "\n".join(
        read_app_source(name)
        for name in (
            "BaseClient.cpp",
            "ClientList.cpp",
            "UploadClient.cpp",
            "DownloadClient.cpp",
            "DownloadQueue.cpp",
            "ListenSocket.cpp",
            "UploadQueue.cpp",
            "SearchList.cpp",
            "FakeFileDetector.cpp",
        )
    )

    for event in (
        "identity_userhash_changed",
        "identity_userhash_invalid_collision",
        "tcp_error_flood",
        "file_request_flood",
        "chat_spam_heuristic",
        "client_ban",
        "download_source_file_mismatch",
        "download_first_payload_timeout",
        "download_no_data_slot_cooldown",
        "download_out_of_part_reqs_quarantine",
        "download_queue_rank_flood",
        "download_stale_block_packet_abort",
        "download_accept_suppressed_no_data_cooldown",
        "packet_invalid_multipacket_subopcode",
        "packet_compression_decode_failed",
        "packet_processing_error",
        "packet_unrequested_kad_fw_ack",
        "packet_unknown_edonkey_opcode",
        "packet_unknown_emule_opcode",
        "packet_unknown_client_tcp_packet",
        "upload_queued_request_direct_admit",
        "upload_queued_request_rejected",
        "upload_no_request_recycle",
        "upload_short_failed_slot_cooldown",
        "upload_zero_rate_recycle",
        "search_spam_detected",
        "fake_file_search_detected",
        "fake_file_part_detected",
    ):
        assert event in joined
