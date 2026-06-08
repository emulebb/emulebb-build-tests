from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
APP_ROOT = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"
SRC_ROOT = APP_ROOT / "srchybrid"
BUILD_ROOT = WORKSPACE_ROOT / "repos" / "emulebb-build"


def read_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def read_build_source(name: str) -> str:
    return (BUILD_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def test_packet_diagnostics_compile_flag_is_opt_in() -> None:
    project = read_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:PacketDiagnosticsPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnablePacketDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_PACKET_DIAGNOSTICS;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(PacketDiagnosticsPreprocessorDefinition)" in config_definitions
        assert "MBEDTLS_ALLOW_PRIVATE_ACCESS" in config_definitions
        assert config_definitions.index("$(PacketDiagnosticsPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )
    release_definitions = [
        config_definitions for config_definitions in preprocessor_definitions if "NDEBUG" in config_definitions
    ]
    assert len(release_definitions) == 1
    assert "$(StartupDiagnosticsPreprocessorDefinition)" in release_definitions[0]


def test_packet_diagnostics_build_env_override_is_available() -> None:
    build_source = read_build_source("emule_workspace/build.py")

    assert '"EMULEBB_ENABLE_PACKET_DIAGNOSTICS", "EnablePacketDiagnostics"' in build_source
    assert 'extra_properties.append(f"/p:{property_name}=' in build_source


def test_startup_profiling_compile_flag_is_opt_in() -> None:
    project = read_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:StartupDiagnosticsPreprocessorDefinition", namespace)

    assert "<EnableStartupDiagnostics Condition=\"'$(EnableStartupDiagnostics)'==''\">false</EnableStartupDiagnostics>" in project
    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableStartupDiagnostics)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_STARTUP_DIAGNOSTICS;"


def test_startup_profile_trace_uses_log_artifact_name() -> None:
    emule_source = read_source("Emule.cpp")
    artifacts = read_source("LogArtifactNames.h")

    assert "inline LPCTSTR StartupProfileTraceFileName()" in artifacts
    assert 'return _T("emulebb-diagnostics-startup.trace.json");' in artifacts
    assert (
        "m_strStartupProfilePath = thePrefs.GetMuleDirectory(EMULE_LOGDIR, false) + "
        "LogArtifactNames::StartupProfileTraceFileName();"
    ) in emule_source
    assert '"startup-profile.trace.json"' not in emule_source


def test_retired_diagnostic_flags_are_rejected_at_feature_header_only() -> None:
    feature_header = read_source("BuildFeatures.h")
    combined_sources = "\n".join(
        read_source(name)
        for name in [
            "AsyncSocketEx.cpp",
            "AsyncSocketEx.h",
            "AsyncSocketExLayer.cpp",
            "Emule.cpp",
            "EmuleDlg.cpp",
            "EMSocket.cpp",
            "Preferences.cpp",
            "Preferences.h",
        ]
    )

    for flag in (
        "EMULEBB_DISABLE_SOCKET_STATES",
        "EMULEBB_DEV_BUILD",
        "EMULEBB_ENABLE_DEBUG_DEVICE",
        "EMULEBB_DEBUG_EMSOCKET",
    ):
        assert f"#if defined({flag})" in feature_header
        assert flag not in combined_sources

    assert "EMULEBB_STARTUP_PROFILE" not in combined_sources


def test_packet_diagnostics_logging_api_is_compile_guarded() -> None:
    log_header = read_source("Log.h")
    log_source = read_source("Log.cpp")
    emule_source = read_source("Emule.cpp")
    artifacts = read_source("LogArtifactNames.h")

    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nextern CLogFile thePacketDiagnosticsLog;" in log_header
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\n#include \"Opcodes.h\"\n#endif" in log_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nconstexpr UINT kMaxPacketDiagnosticsPayloadHexBytes = 4 * 1024;" in log_source
    assert "CCriticalSection g_packetDiagnosticsLogLock;" in log_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nvoid PacketDiagnosticsLogInvalidSubOpcode(" in log_source
    assert '\\"schema\\":\\"ed2k_invalid_sub_opcode_v1\\"' in log_source
    assert '\\"context_hex\\":\\"%s\\",\\"payload_hex_truncated\\":%s,\\"payload_hex\\":\\"%s\\"' in log_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nCLogFile thePacketDiagnosticsLog;" in emule_source
    assert "InitializeDiagnosticsLog(thePacketDiagnosticsLog, strDiagnosticsLogDir + LogArtifactNames::PacketDiagnosticsLogFileName(), thePrefs.GetMaxLogFileSize())" in emule_source
    assert "WriteDiagnosticsLogLine(thePacketDiagnosticsLog, g_packetDiagnosticsLogLock, strJson)" in log_source
    assert "bool InitializeDiagnosticsLog(CLogFile &rLog, LPCTSTR pszLogPath, UINT uMaxLogFileSize)" in log_header
    assert "void WriteDiagnosticsLogLine(CLogFile &rLog, CCriticalSection &rLock, const CString &rstrLine)" in log_header
    assert "LogArtifactNames::PacketDiagnosticsLogFileName()" in emule_source
    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\ninline LPCTSTR PacketDiagnosticsLogFileName()" in artifacts
    assert 'return _T("emulebb-diagnostics-packet.log");' in artifacts


def test_rest_recent_log_ring_is_bounded_and_clearable() -> None:
    log_header = read_source("Log.h")
    log_source = read_source("Log.cpp")
    rest_source = read_source("WebServerJson.cpp")

    assert "void ClearRecentLogEntries();" in log_header
    assert "constexpr int kMaxRecentLogEntryChars = 4 * 1024;" in log_source
    assert "TruncateLogLine(CString(pszText != NULL ? pszText : _T(\"\")), kMaxRecentLogEntryChars)" in log_source
    assert "void ClearRecentLogEntries()\n{" in log_source
    assert "ClearRecentLogEntries();" in rest_source


def test_invalid_sub_opcode_diagnostics_call_sites_are_guarded() -> None:
    source = read_source("ListenSocket.cpp")

    assert "#ifdef EMULEBB_ENABLE_PACKET_DIAGNOSTICS\nCString BuildPacketDiagnosticsPeerLabel(" in source
    assert "void LogInvalidMultipacketSubOpcode(" in source
    assert "const ULONGLONG ullInvalidOffset = (ullPosition > 0) ? (ullPosition - 1) : 0;" in source
    assert "const ULONGLONG ullBytesRemaining = (ullLength > ullPosition) ? (ullLength - ullPosition) : 0;" in source

    request_block = source[source.index("case OP_MULTIPACKET_EXT2:") : source.index("case OP_MULTIPACKETANSWER:")]
    answer_block = source[source.index("case OP_MULTIPACKETANSWER:") : source.index("case OP_EMULEINFO:")]

    shared_guard = "#if defined(EMULEBB_ENABLE_PACKET_DIAGNOSTICS) || EMULEBB_HAS_BAD_PEER_DIAGNOSTICS\n\t\t\tint iPreviousSubOpcode = -1;\n#endif"
    assert shared_guard in request_block
    assert shared_guard in answer_block
    assert "LogInvalidMultipacketSubOpcode(_T(\"multipacket_request\"), client, opcode, packet, size, opcode_in, data_in, iPreviousSubOpcode);" in request_block
    assert "LogInvalidMultipacketSubOpcode(_T(\"multipacket_answer\"), client, opcode, packet, size, opcode_in, data_in, iPreviousSubOpcode);" in answer_block
    assert request_block.index("LogInvalidMultipacketSubOpcode(_T(\"multipacket_request\")") < request_block.index("strError.Format(_T(\"Invalid sub opcode 0x%02x received\"), opcode_in);")
    assert answer_block.index("LogInvalidMultipacketSubOpcode(_T(\"multipacket_answer\")") < answer_block.index("strError.Format(_T(\"Invalid sub opcode 0x%02x received\"), opcode_in);")


def test_packet_diagnostics_does_not_port_full_tracing_harness() -> None:
    combined = "\n".join(read_source(name) for name in ["ListenSocket.cpp", "Log.cpp", "Log.h", "Emule.cpp"])

    assert "OracleEd2kTcpDump" not in combined
    assert "OracleUdpDump" not in combined
