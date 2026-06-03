from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
APP_ROOT = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"
SRC_ROOT = APP_ROOT / "srchybrid"
BUILD_ROOT = WORKSPACE_ROOT / "repos" / "emulebb-build"


def read_app_source(name: str) -> str:
    return (SRC_ROOT / name).read_text(encoding="utf-8", errors="ignore")


def test_download_slot_instrumentation_compile_flag_is_opt_in() -> None:
    project = read_app_source("emule.vcxproj")
    root = ET.fromstring(project)
    namespace = {"msb": "http://schemas.microsoft.com/developer/msbuild/2003"}
    definitions = root.findall(".//msb:DownloadSlotInstrumentationPreprocessorDefinition", namespace)
    preprocessor_definitions = [
        element.text or ""
        for element in root.findall(".//msb:PreprocessorDefinitions", namespace)
    ]

    assert len(definitions) == 1
    assert definitions[0].attrib["Condition"] == "'$(EnableDownloadSlotInstrumentation)'=='true'"
    assert definitions[0].text == "EMULEBB_ENABLE_DOWNLOAD_SLOT_INSTRUMENTATION;"
    assert preprocessor_definitions
    for config_definitions in preprocessor_definitions:
        assert "$(UploadSlotInstrumentationPreprocessorDefinition)" in config_definitions
        assert "$(DownloadSlotInstrumentationPreprocessorDefinition)" in config_definitions
        assert config_definitions.index("$(UploadSlotInstrumentationPreprocessorDefinition)") < config_definitions.index(
            "$(DownloadSlotInstrumentationPreprocessorDefinition)"
        )
        assert config_definitions.index("$(DownloadSlotInstrumentationPreprocessorDefinition)") < config_definitions.index(
            "MBEDTLS_ALLOW_PRIVATE_ACCESS"
        )


def test_download_slot_instrumentation_build_env_override_is_plumbed() -> None:
    build_source = (BUILD_ROOT / "emule_workspace" / "build.py").read_text(encoding="utf-8")

    assert 'env_override("EMULEBB_ENABLE_DOWNLOAD_SLOT_INSTRUMENTATION")' in build_source
    assert "/p:EnableDownloadSlotInstrumentation=" in build_source


def test_download_slot_instrumentation_logs_queue_and_client_state() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    queue_source = read_app_source("DownloadQueue.cpp")
    queue_header = read_app_source("DownloadQueue.h")
    client_header = read_app_source("UpDownClient.h")
    base_client_source = read_app_source("BaseClient.cpp")

    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_INSTRUMENTATION\nvoid CUpDownClient::LogDownloadSlotInstrumentation" in client_source
    assert "DownloadSlotInstrumentation: client reason=%s" in client_source
    for anchor in (
        "block-reserved",
        "block-reserve-empty",
        "request-sent",
        "block-complete",
        "request-empty-nnp",
        "out-of-part-reqs",
        "accept-suppressed-out-of-part-cooldown",
        "accept-suppressed-no-data-cooldown",
        "timeout",
        "disconnect-downloading",
    ):
        assert anchor in client_source or anchor in base_client_source

    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_INSTRUMENTATION\nvoid CDownloadQueue::LogDownloadSlotInstrumentation" in queue_source
    assert "DownloadSlotInstrumentation: summary" in queue_source
    assert "LogDownloadSlotInstrumentation(curTick);" in queue_source
    assert "#ifdef EMULEBB_ENABLE_DOWNLOAD_SLOT_INSTRUMENTATION\n\tvoid\tLogDownloadSlotInstrumentation" in queue_header
    assert "m_ullDownloadBlockRequestsReserved" in client_header
    assert "m_uDownloadOutOfPartReqsSuppressions" in client_header
    assert "highVolumeSuppressed=%I64u" in client_source
    assert '_tcscmp(pszReason, _T("block-reserve-empty")) == 0' in client_source
    assert '_tcscmp(pszReason, _T("state-transition")) == 0' in client_source
    assert "noDataSuppressions=%u" in client_source


def test_download_slot_no_data_and_out_of_part_guards_are_conservative() -> None:
    client_source = read_app_source("DownloadClient.cpp")
    client_header = read_app_source("UpDownClient.h")

    timeout_block = client_source[
        client_source.index("void CUpDownClient::CheckDownloadTimeout()") :
        client_source.index("uint16 CUpDownClient::GetAvailablePartCount() const")
    ]

    assert "kDownloadNoDataSlotCooldownThreshold = 2" in client_source
    assert "kDownloadNoDataSlotPayloadThresholdBytes = EMBLOCKSIZE" in client_source
    assert "kDownloadFirstPayloadTimeoutMs = SEC2MS(30)" in client_source
    assert "timeout-first-payload" in timeout_block
    assert "!m_PendingBlocks_list.IsEmpty()" in timeout_block
    assert "GetSessionPayloadDown() == 0" in timeout_block
    assert "GetSessionDown() == 0" in timeout_block
    assert "thePrefs.GetDownloadTimeout() > kDownloadFirstPayloadTimeoutMs" in timeout_block
    assert timeout_block.index("timeout-first-payload") < timeout_block.index('LogDownloadSlotInstrumentation(_T("timeout"))')
    assert "CanAcceptUploadSlotAfterDownloadNoData" in client_header
    assert "NoteDownloadNoDataSlotFailure(pszReason)" in client_source
    assert "Suppressed OP_AcceptUploadReq after repeated no-data download slots" in client_source
    assert "kOutOfPartReqsCooldownThreshold = 2" in client_source
