"""Runs Rust ED2K private parity module tests and publishes campaign evidence."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.artifact_names import utc_run_id  # noqa: E402
from emule_test_harness.paths import get_required_emule_workspace_root, get_workspace_output_root  # noqa: E402

SUITE_NAME = "rust-ed2k-private-parity-modules"


@dataclass(frozen=True)
class RustModuleCase:
    """One Rust module filter promoted to ED2K parity evidence."""

    case_id: str
    title: str
    module_filter: str
    evidence: dict[str, bool]
    package: str = "emulebb-ed2k"


RUST_MODULE_CASES: tuple[RustModuleCase, ...] = (
    RustModuleCase(
        case_id="protocol-codec",
        title="Protocol codec, source exchange, preview, and HASHSET2 shapes",
        module_filter="ed2k_tcp::tests::protocol::codec",
        evidence={
            "protocolCodecCovered": True,
            "sourceExchange2PacketShapeCovered": True,
            "previewPacketDecodeCovered": True,
            "hashset2Md4AichCovered": True,
            "requestFilenameCovered": True,
        },
    ),
    RustModuleCase(
        case_id="ed2k-config-defaults",
        title="ED2K config default download, search, and source fanout",
        module_filter="config::tests",
        evidence={
            "ed2kConfigDefaultsCovered": True,
            "ed2kDownloadFanoutDefaultsCovered": True,
            "ed2kSearchBudgetDefaultsCovered": True,
            "ed2kKadSupplementDefaultsCovered": True,
        },
    ),
    RustModuleCase(
        case_id="protocol-hello",
        title="Hello profile and advertised capability truthfulness",
        module_filter="ed2k_tcp::tests::protocol::hello",
        evidence={
            "helloProfileCovered": True,
            "truthfulCapabilityAdvertCovered": True,
            "sourceExchange2AdvertCovered": True,
            "aichAdvertCovered": True,
            "unsupportedPreviewNotAdvertised": True,
            "unsupportedChatCaptchaNotAdvertised": True,
        },
    ),
    RustModuleCase(
        case_id="protocol-obfuscation",
        title="ED2K TCP obfuscation handshake",
        module_filter="ed2k_tcp::tests::protocol::obfuscation",
        evidence={
            "obfuscationHandshakeCovered": True,
            "encryptedFollowupPacketCovered": True,
        },
    ),
    RustModuleCase(
        case_id="protocol-callback",
        title="Callback, firewall, and Kad TCP ack protocol flows",
        module_filter="ed2k_tcp::tests::protocol::callback",
        evidence={
            "callbackProtocolCovered": True,
            "plaintextCallbackCovered": True,
            "obfuscatedCallbackCovered": True,
            "udpFirewallCheckCovered": True,
            "kadTcpAckCovered": True,
        },
    ),
    RustModuleCase(
        case_id="protocol-identity",
        title="Secure-ident public key, signature, and state wire shapes",
        module_filter="ed2k_tcp::tests::protocol::identity",
        evidence={
            "secureIdentProtocolCovered": True,
            "secureIdentWireShapeCovered": True,
            "secureIdentSignatureCovered": True,
        },
    ),
    RustModuleCase(
        case_id="protocol-dump-labels",
        title="ED2K TCP diagnostic dump phase labels",
        module_filter="ed2k_tcp::tests::protocol::dump_labels",
        evidence={
            "tcpDumpPhaseLabelsCovered": True,
        },
    ),
    RustModuleCase(
        case_id="tcp-dump-inline",
        title="ED2K TCP diagnostic dump naming",
        module_filter="ed2k_tcp::dump::tests",
        evidence={
            "tcpDumpInlineCovered": True,
            "tcpDumpPrefixCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-secure-ident-state",
        title="Downloader secure-ident state gating",
        module_filter="ed2k_tcp::download::session::state::tests",
        evidence={
            "downloaderSecureIdentStateCovered": True,
            "secureIdentPeerSignatureGateCovered": True,
            "secureIdentLocalSignaturePendingCovered": True,
        },
    ),
    RustModuleCase(
        case_id="server-protocol",
        title="ED2K server protocol, decoder, obfuscation, and background search flows",
        module_filter="ed2k_server::tests",
        evidence={
            "serverProtocolCovered": True,
            "serverLoginOracleCovered": True,
            "serverOfferFilesCovered": True,
            "serverLargeFileOfferCovered": True,
            "serverSearchDecodeCovered": True,
            "serverSourceDecodeCovered": True,
            "serverBackgroundSearchCovered": True,
            "serverCallbackDecodeCovered": True,
            "serverObfuscationCovered": True,
            "serverUdpObfuscationCovered": True,
        },
    ),
    RustModuleCase(
        case_id="server-startup-inline",
        title="ED2K server startup offer-file endpoint and Unicode tag handling",
        module_filter="ed2k_server::startup::tests",
        evidence={
            "serverStartupInlineCovered": True,
            "serverOfferFilesLanBindCovered": True,
            "serverOfferFilesUnicodeTagCovered": True,
            "serverOfferFilesCompressionSentinelCovered": True,
        },
    ),
    RustModuleCase(
        case_id="server-diagnostics-inline",
        title="ED2K server diagnostic dump naming",
        module_filter="ed2k_server::diagnostics::tests",
        evidence={
            "serverDiagnosticsInlineCovered": True,
            "serverDiagnosticsDumpNameCovered": True,
        },
    ),
    RustModuleCase(
        case_id="transfer-runtime",
        title="ED2K transfer metadata, hashset, persistence, and upload queue runtime",
        module_filter="ed2k_transfer::tests",
        evidence={
            "transferRuntimeCovered": True,
            "transferMd4PieceVerificationCovered": True,
            "transferAichPersistenceCovered": True,
            "transferRemoteAichPreservedCovered": True,
            "transferStockAichFixtureCovered": True,
            "transferLocalIngestCovered": True,
            "transferLegacyManifestRepairCovered": True,
            "transferInvalidAichRejectedCovered": True,
            "transferMetadataReconcileCovered": True,
            "transferPartialProgressResumeCovered": True,
            "transferCatalogHintMergeCovered": True,
            "transferUploadQueueCovered": True,
            "transferUploadQueueLowIdCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-startup-metadata",
        title="Downloader startup metadata and hash-only recovery",
        module_filter="ed2k_tcp::tests::download::startup_metadata",
        evidence={
            "startupMetadataCovered": True,
            "hashOnlyMetadataRecoveryCovered": True,
            "sourceExchange2ResponseCovered": True,
            "legacyAichDegradeCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-startup-secure-ident",
        title="Downloader startup secure-ident gating",
        module_filter="ed2k_tcp::tests::download::startup_secure_ident",
        evidence={
            "startupSecureIdentCovered": True,
            "metadataWaitsForSecureIdentCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-hashset-startup",
        title="Downloader HASHSET2 startup",
        module_filter="ed2k_tcp::tests::download::hashset_startup",
        evidence={
            "downloadHashsetStartupCovered": True,
            "hashset2RequestCovered": True,
            "aichHashsetAcquisitionCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-hashset-fallback",
        title="Downloader large-file hashset stall fallback",
        module_filter="ed2k_tcp::tests::download::hashset_fallback",
        evidence={
            "downloadHashsetFallbackCovered": True,
            "largeFileFallbackCovered": True,
            "uploadRequestAfterHashsetCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-frame-compressed",
        title="Downloader compressed-part frame handling",
        module_filter="ed2k_tcp::tests::download::frame_compressed",
        evidence={
            "compressedPartFrameCovered": True,
            "splitCompressedFrameCovered": True,
            "obfuscatedPackedCompressedFrameCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-frame-sending-part",
        title="Downloader split sending-part frame handling",
        module_filter="ed2k_tcp::tests::download::frame_sending_part",
        evidence={
            "sendingPartFrameCovered": True,
            "splitSendingPartFrameCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-payload-validation",
        title="Downloader corrupt payload rejection",
        module_filter="ed2k_tcp::tests::download::payload_validation",
        evidence={
            "badPayloadRejectedCovered": True,
            "badPayloadKeepsManifestIncompleteCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-range-malformed",
        title="Downloader malformed range recovery",
        module_filter="ed2k_tcp::tests::download::range_malformed",
        evidence={
            "malformedRangeRecoveryCovered": True,
            "pendingPieceReleaseCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-range-out-of-order-complete",
        title="Downloader out-of-order multi-range completion",
        module_filter="ed2k_tcp::tests::download::range_out_of_order_complete",
        evidence={
            "outOfOrderRangeCompleteCovered": True,
            "multiRangeWindowCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-range-out-of-order-incomplete",
        title="Downloader incomplete out-of-order multi-range recovery",
        module_filter="ed2k_tcp::tests::download::range_out_of_order_incomplete",
        evidence={
            "outOfOrderRangeIncompleteCovered": True,
            "outOfOrderRangePieceReleaseCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-range-out-of-order-compressed",
        title="Downloader compressed out-of-order multi-range completion",
        module_filter="ed2k_tcp::tests::download::range_out_of_order_compressed",
        evidence={
            "outOfOrderCompressedRangeCovered": True,
            "compressedMultiRangeWindowCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-window-policy",
        title="Downloader adaptive read timeout and window policy",
        module_filter="ed2k_tcp::tests::download::window_policy",
        evidence={
            "adaptiveWindowPolicyCovered": True,
            "queueDeadlineTimeoutCovered": True,
            "partDeadlineTimeoutCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-queue",
        title="Downloader queue-only and late accept-upload",
        module_filter="ed2k_tcp::tests::download::queue_only",
        evidence={
            "downloaderQueueCovered": True,
            "queueOnlyAcceptedButIncompleteCovered": True,
            "lateAcceptUploadCovered": True,
            "queueRankingCovered": True,
            "obfuscatedTransportCovered": True,
        },
    ),
    RustModuleCase(
        case_id="listener-queue",
        title="Listener upload queue rank and promotion",
        module_filter="ed2k_tcp::tests::listener::queue",
        evidence={
            "listenerQueueCovered": True,
            "queueRankingCovered": True,
            "acceptUploadCovered": True,
            "duplicateReconnectCovered": True,
            "fileSwitchRankCovered": True,
            "obfuscatedTransportCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-resume",
        title="Downloader partial-piece resume after reconnect",
        module_filter="ed2k_tcp::tests::download::resume_reconnect",
        evidence={
            "downloaderResumeCovered": True,
            "partialPieceResumeCovered": True,
            "resumeManifestCovered": True,
            "obfuscatedTransportCovered": True,
        },
    ),
    RustModuleCase(
        case_id="listener-resume",
        title="Listener upload resume after reconnect",
        module_filter="ed2k_tcp::tests::listener::resume",
        evidence={
            "listenerResumeCovered": True,
            "partialUploadReconnectCovered": True,
            "helloIdentityReconnectCovered": True,
            "obfuscatedTransportCovered": True,
        },
    ),
    RustModuleCase(
        case_id="downloader-callback",
        title="Downloader callback session upload flow",
        module_filter="ed2k_tcp::tests::download::queue_callback",
        evidence={
            "callbackSessionCovered": True,
            "callbackStartsUploadFlowCovered": True,
            "secureIdentHandshakeCovered": True,
        },
    ),
    RustModuleCase(
        case_id="listener-serving",
        title="Listener verified compressed part serving",
        module_filter="ed2k_tcp::tests::listener::serving",
        evidence={
            "listenerServingCovered": True,
            "compressedPartServingCovered": True,
            "obfuscatedTransportCovered": True,
        },
    ),
    RustModuleCase(
        case_id="listener-startup",
        title="Listener startup, shared browse denial, and queue-rank request",
        module_filter="ed2k_tcp::tests::listener::startup",
        evidence={
            "listenerStartupCovered": True,
            "sharedFilesBrowseSurfaceCovered": True,
            "sharedBrowseDeniedCovered": True,
            "queueRankRequestCovered": True,
        },
    ),
    RustModuleCase(
        case_id="listener-hashset",
        title="Listener HASHSET2 AICH answer",
        module_filter="ed2k_tcp::tests::listener::hashset",
        evidence={
            "listenerHashsetCovered": True,
            "listenerHashset2AichAnswerCovered": True,
        },
    ),
    RustModuleCase(
        case_id="kad-firewall-runtime",
        title="Kad-assisted ED2K firewall verification runtime",
        module_filter="kad_firewall::tests",
        evidence={
            "kadFirewallRuntimeCovered": True,
            "udpFirewallRoundCovered": True,
            "tcpFirewallRecheckCovered": True,
        },
    ),
    RustModuleCase(
        case_id="nat-runtime",
        title="NAT runtime provider selection and status reconciliation",
        module_filter="nat::tests",
        evidence={
            "natRuntimeCovered": True,
            "natBackendSelectionCovered": True,
            "natStatusReconcileCovered": True,
        },
    ),
    RustModuleCase(
        case_id="nat-miniupnpc-runtime",
        title="miniupnpc mapping compatibility helpers",
        module_filter="nat::miniupnpc::tests",
        evidence={
            "natMiniupnpcCovered": True,
            "miniupnpcMappingMatchCovered": True,
        },
    ),
    RustModuleCase(
        case_id="nat-rupnp-runtime",
        title="rupnp SSDP discovery and SOAP compatibility helpers",
        module_filter="nat::rupnp::tests",
        evidence={
            "natRupnpCovered": True,
            "rupnpDiscoveryCovered": True,
            "rupnpXmlEscapeCovered": True,
        },
    ),
    RustModuleCase(
        case_id="networking-runtime",
        title="Interface and bind-address selection",
        module_filter="networking::tests",
        evidence={
            "networkingRuntimeCovered": True,
            "networkingBindSelectionCovered": True,
            "vpnPreferenceCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-direct-download-scheduler",
        title="Core direct ED2K download retry and fallback scheduler",
        module_filter="direct_download_scheduler",
        package="emulebb-core",
        evidence={
            "coreDirectDownloadSchedulerCovered": True,
            "coreDirectDownloadRetriesOtherPeerCovered": True,
            "coreDirectDownloadLoopbackRetryCovered": True,
            "coreDirectDownloadAcceptedIncompleteCovered": True,
            "coreDirectDownloadPlaintextFallbackCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-direct-download-candidates",
        title="Core direct ED2K source candidate dedupe and exhaustion policy",
        module_filter="direct_download_candidates",
        package="emulebb-core",
        evidence={
            "coreDirectDownloadCandidatesCovered": True,
            "coreDirectDownloadEndpointFamilyExhaustionCovered": True,
            "coreDirectDownloadEndpointDedupeCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-source-requery-policy",
        title="Core no-progress source requery policy",
        module_filter="source_requery_skip",
        package="emulebb-core",
        evidence={
            "coreSourceRequeryPolicyCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-zero-source-background",
        title="Core zero-source background endpoint reuse policy",
        module_filter="zero_source_background",
        package="emulebb-core",
        evidence={
            "coreZeroSourceBackgroundCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-callback-route",
        title="Core ED2K callback background-session routing",
        module_filter="callback_route_reuses",
        package="emulebb-core",
        evidence={
            "coreCallbackRouteCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-source-merge",
        title="Core ED2K source merge provenance and remembered-source hints",
        module_filter="source",
        package="emulebb-core",
        evidence={
            "coreSourceMergeCovered": True,
            "coreRememberedSourceHintCovered": True,
            "coreKadSourceSupplementCovered": True,
            "coreKadSourceMetadataCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-hash-only-search",
        title="Core exact-hash ED2K search and metadata selection",
        module_filter="ed2k",
        package="emulebb-core",
        evidence={
            "coreHashOnlySearchCovered": True,
            "coreExactHashServerBudgetCovered": True,
            "coreHashOnlyMetadataSelectionCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-keyword-target",
        title="Core ED2K keyword target and significant-word normalization",
        module_filter="keyword",
        package="emulebb-core",
        evidence={
            "coreKeywordTargetCovered": True,
            "coreKeywordSignificantWordsCovered": True,
            "coreKeywordExactHashTargetCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-stock-search-pagination",
        title="Core stock search response pagination",
        module_filter="split_stock_search_responses",
        package="emulebb-core",
        evidence={
            "coreStockSearchPaginationCovered": True,
            "coreStockOversizedSearchResultCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-publish-tags",
        title="Core Kad/ED2K publish tag and source identity parity",
        module_filter="source_publish",
        package="emulebb-core",
        evidence={
            "coreSourcePublishTagsCovered": True,
            "coreSourcePublishObfuscationCovered": True,
            "coreSourcePublishIdentityCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-ed2k-file-type-search",
        title="Core ED2K file-type search term mapping",
        module_filter="ed2k_file_type_search_term",
        package="emulebb-core",
        evidence={
            "coreEd2kFileTypeSearchCovered": True,
        },
    ),
    RustModuleCase(
        case_id="core-transfer-lifecycle",
        title="Core ED2K transfer lifecycle and manifest reload",
        module_filter="transfer",
        package="emulebb-core",
        evidence={
            "coreTransferLifecycleCovered": True,
            "coreTransferManifestReloadCovered": True,
            "coreStoppedTransferPersistenceCovered": True,
        },
    ),
    RustModuleCase(
        case_id="daemon-ed2k-network-config",
        title="Daemon ED2K network config and server metadata parsing",
        module_filter="ed2k",
        package="emulebb-daemon",
        evidence={
            "daemonEd2kNetworkConfigCovered": True,
            "daemonEd2kServerMetadataCovered": True,
            "daemonEd2kNatBindCovered": True,
        },
    ),
    RustModuleCase(
        case_id="daemon-ed2k-user-hash",
        title="Daemon eMule-compatible ED2K user-hash persistence",
        module_filter="user_hash",
        package="emulebb-daemon",
        evidence={
            "daemonEd2kUserHashCovered": True,
            "daemonEd2kUserHashMarkersCovered": True,
            "daemonEd2kUserHashPersistenceCovered": True,
        },
    ),
    RustModuleCase(
        case_id="daemon-p2p-bind-interface",
        title="Daemon P2P bind-interface resolution",
        module_filter="p2p_bind",
        package="emulebb-daemon",
        evidence={
            "daemonP2pBindInterfaceCovered": True,
            "daemonP2pBindOverrideCovered": True,
        },
    ),
    RustModuleCase(
        case_id="daemon-ed2k-config-parse",
        title="Daemon ED2K config parsing and obfuscation metadata",
        module_filter="load_parses",
        package="emulebb-daemon",
        evidence={
            "daemonEd2kConfigParseCovered": True,
            "daemonEd2kObfuscationMetadataCovered": True,
        },
    ),
    RustModuleCase(
        case_id="index-snoop-queue",
        title="Index passive ED2K source, keyword, and notes replay queue",
        module_filter="snoop_queue",
        package="emulebb-index",
        evidence={
            "indexSnoopQueueCovered": True,
            "indexSnoopSourceReplayCovered": True,
            "indexSnoopKeywordNotesCovered": True,
            "indexSnoopMergeRestoreCovered": True,
        },
    ),
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-repo", type=Path)
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--case", choices=[case.case_id for case in RUST_MODULE_CASES], action="append")
    return parser.parse_args(argv)


def selected_cases(case_ids: list[str] | None) -> tuple[RustModuleCase, ...]:
    """Returns the selected Rust parity module cases."""

    if not case_ids:
        return RUST_MODULE_CASES
    selected = set(case_ids)
    return tuple(case for case in RUST_MODULE_CASES if case.case_id in selected)


def resolve_rust_repo(explicit: Path | None, workspace_root: Path) -> Path:
    """Resolves the eMuleBB Rust checkout."""

    rust_repo = explicit.resolve() if explicit else (workspace_root / "repos" / "emulebb-rust").resolve()
    if not (rust_repo / "Cargo.toml").is_file():
        raise RuntimeError(f"Rust checkout was not found at {rust_repo}.")
    return rust_repo


def run_cargo_case(case: RustModuleCase, rust_repo: Path, cargo_target_dir: Path) -> dict[str, Any]:
    """Runs one cargo test module filter and returns summary evidence."""

    command = ["cargo", "test", "-p", case.package, case.module_filter, "--", "--nocapture"]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(cargo_target_dir)
    result = subprocess.run(
        command,
        cwd=rust_repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "id": case.case_id,
        "title": case.title,
        "package": case.package,
        "moduleFilter": case.module_filter,
        "status": "passed" if result.returncode == 0 else "failed",
        "returnCode": result.returncode,
        "command": command,
        "evidence": {**case.evidence, "rustTestsPassed": result.returncode == 0},
        "stdoutTail": tail_lines(result.stdout),
        "stderrTail": tail_lines(result.stderr),
    }


def build_requirement_checks(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregates the private ED2K parity surfaces proven by the Rust modules."""

    passed_ids = {str(case.get("id")) for case in cases if case.get("status") == "passed"}
    evidence_by_id = {
        str(case.get("id")): case.get("evidence")
        for case in cases
        if isinstance(case.get("evidence"), dict)
    }

    return {
        "caseCount": len(cases),
        "allCasesPassed": len(passed_ids) == len(cases),
        "downloaderQueueCovered": bool(evidence_by_id.get("downloader-queue", {}).get("downloaderQueueCovered")),
        "listenerQueueCovered": bool(evidence_by_id.get("listener-queue", {}).get("listenerQueueCovered")),
        "downloaderResumeCovered": bool(evidence_by_id.get("downloader-resume", {}).get("downloaderResumeCovered")),
        "listenerResumeCovered": bool(evidence_by_id.get("listener-resume", {}).get("listenerResumeCovered")),
        "callbackSessionCovered": bool(evidence_by_id.get("downloader-callback", {}).get("callbackSessionCovered")),
        "compressedPartServingCovered": bool(evidence_by_id.get("listener-serving", {}).get("compressedPartServingCovered")),
        "protocolCodecCovered": bool(evidence_by_id.get("protocol-codec", {}).get("protocolCodecCovered")),
        "ed2kConfigDefaultsCovered": bool(
            evidence_by_id.get("ed2k-config-defaults", {}).get("ed2kConfigDefaultsCovered")
            and evidence_by_id.get("ed2k-config-defaults", {}).get("ed2kDownloadFanoutDefaultsCovered")
            and evidence_by_id.get("ed2k-config-defaults", {}).get("ed2kSearchBudgetDefaultsCovered")
            and evidence_by_id.get("ed2k-config-defaults", {}).get("ed2kKadSupplementDefaultsCovered")
        ),
        "helloAdvertTruthfulnessCovered": bool(
            evidence_by_id.get("protocol-hello", {}).get("truthfulCapabilityAdvertCovered")
            and evidence_by_id.get("protocol-hello", {}).get("unsupportedPreviewNotAdvertised")
            and evidence_by_id.get("protocol-hello", {}).get("unsupportedChatCaptchaNotAdvertised")
        ),
        "sourceExchange2Covered": bool(
            evidence_by_id.get("protocol-codec", {}).get("sourceExchange2PacketShapeCovered")
            and evidence_by_id.get("downloader-startup-metadata", {}).get("sourceExchange2ResponseCovered")
            and evidence_by_id.get("server-protocol", {}).get("serverSourceDecodeCovered")
        ),
        "serverProtocolCovered": bool(evidence_by_id.get("server-protocol", {}).get("serverProtocolCovered")),
        "serverLoginOracleCovered": bool(evidence_by_id.get("server-protocol", {}).get("serverLoginOracleCovered")),
        "serverOfferFilesCovered": bool(
            evidence_by_id.get("server-protocol", {}).get("serverOfferFilesCovered")
            and evidence_by_id.get("server-protocol", {}).get("serverLargeFileOfferCovered")
        ),
        "serverSearchDecodeCovered": bool(evidence_by_id.get("server-protocol", {}).get("serverSearchDecodeCovered")),
        "serverSourceDecodeCovered": bool(evidence_by_id.get("server-protocol", {}).get("serverSourceDecodeCovered")),
        "serverBackgroundSearchCovered": bool(
            evidence_by_id.get("server-protocol", {}).get("serverBackgroundSearchCovered")
        ),
        "serverCallbackDecodeCovered": bool(evidence_by_id.get("server-protocol", {}).get("serverCallbackDecodeCovered")),
        "serverObfuscationCovered": bool(
            evidence_by_id.get("server-protocol", {}).get("serverObfuscationCovered")
            and evidence_by_id.get("server-protocol", {}).get("serverUdpObfuscationCovered")
        ),
        "serverStartupInlineCovered": bool(
            evidence_by_id.get("server-startup-inline", {}).get("serverStartupInlineCovered")
        ),
        "serverOfferFilesLanBindCovered": bool(
            evidence_by_id.get("server-startup-inline", {}).get("serverOfferFilesLanBindCovered")
        ),
        "serverOfferFilesUnicodeTagCovered": bool(
            evidence_by_id.get("server-startup-inline", {}).get("serverOfferFilesUnicodeTagCovered")
        ),
        "serverOfferFilesCompressionSentinelCovered": bool(
            evidence_by_id.get("server-startup-inline", {}).get("serverOfferFilesCompressionSentinelCovered")
        ),
        "serverDiagnosticsInlineCovered": bool(
            evidence_by_id.get("server-diagnostics-inline", {}).get("serverDiagnosticsInlineCovered")
        ),
        "serverDiagnosticsDumpNameCovered": bool(
            evidence_by_id.get("server-diagnostics-inline", {}).get("serverDiagnosticsDumpNameCovered")
        ),
        "previewSurfaceCovered": bool(
            evidence_by_id.get("protocol-codec", {}).get("previewPacketDecodeCovered")
            and evidence_by_id.get("protocol-hello", {}).get("unsupportedPreviewNotAdvertised")
        ),
        "startupMetadataCovered": bool(evidence_by_id.get("downloader-startup-metadata", {}).get("startupMetadataCovered")),
        "hashOnlyMetadataRecoveryCovered": bool(
            evidence_by_id.get("downloader-startup-metadata", {}).get("hashOnlyMetadataRecoveryCovered")
        ),
        "transferRuntimeCovered": bool(evidence_by_id.get("transfer-runtime", {}).get("transferRuntimeCovered")),
        "transferMd4PieceVerificationCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferMd4PieceVerificationCovered")
        ),
        "transferAichPersistenceCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferAichPersistenceCovered")
            and evidence_by_id.get("transfer-runtime", {}).get("transferStockAichFixtureCovered")
        ),
        "transferRemoteAichPreservedCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferRemoteAichPreservedCovered")
        ),
        "transferLocalIngestCovered": bool(evidence_by_id.get("transfer-runtime", {}).get("transferLocalIngestCovered")),
        "transferLegacyManifestRepairCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferLegacyManifestRepairCovered")
        ),
        "transferInvalidAichRejectedCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferInvalidAichRejectedCovered")
        ),
        "transferMetadataReconcileCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferMetadataReconcileCovered")
        ),
        "transferPartialProgressResumeCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferPartialProgressResumeCovered")
        ),
        "transferCatalogHintMergeCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferCatalogHintMergeCovered")
        ),
        "transferUploadQueueCovered": bool(
            evidence_by_id.get("transfer-runtime", {}).get("transferUploadQueueCovered")
            and evidence_by_id.get("transfer-runtime", {}).get("transferUploadQueueLowIdCovered")
        ),
        "startupSecureIdentCovered": bool(
            evidence_by_id.get("downloader-startup-secure-ident", {}).get("startupSecureIdentCovered")
        ),
        "downloadHashsetCovered": bool(
            evidence_by_id.get("downloader-hashset-startup", {}).get("downloadHashsetStartupCovered")
            and evidence_by_id.get("downloader-hashset-fallback", {}).get("downloadHashsetFallbackCovered")
        ),
        "compressedFrameDownloadCovered": bool(
            evidence_by_id.get("downloader-frame-compressed", {}).get("compressedPartFrameCovered")
            and evidence_by_id.get("downloader-frame-compressed", {}).get("splitCompressedFrameCovered")
        ),
        "obfuscatedPackedCompressedFrameCovered": bool(
            evidence_by_id.get("downloader-frame-compressed", {}).get("obfuscatedPackedCompressedFrameCovered")
        ),
        "sendingPartFrameCovered": bool(
            evidence_by_id.get("downloader-frame-sending-part", {}).get("sendingPartFrameCovered")
            and evidence_by_id.get("downloader-frame-sending-part", {}).get("splitSendingPartFrameCovered")
        ),
        "badPayloadRejectedCovered": bool(
            evidence_by_id.get("downloader-payload-validation", {}).get("badPayloadRejectedCovered")
            and evidence_by_id.get("downloader-payload-validation", {}).get("badPayloadKeepsManifestIncompleteCovered")
        ),
        "malformedRangeRecoveryCovered": bool(
            evidence_by_id.get("downloader-range-malformed", {}).get("malformedRangeRecoveryCovered")
            and evidence_by_id.get("downloader-range-malformed", {}).get("pendingPieceReleaseCovered")
        ),
        "outOfOrderRangeCompleteCovered": bool(
            evidence_by_id.get("downloader-range-out-of-order-complete", {}).get("outOfOrderRangeCompleteCovered")
            and evidence_by_id.get("downloader-range-out-of-order-complete", {}).get("multiRangeWindowCovered")
        ),
        "outOfOrderRangeIncompleteCovered": bool(
            evidence_by_id.get("downloader-range-out-of-order-incomplete", {}).get("outOfOrderRangeIncompleteCovered")
            and evidence_by_id.get("downloader-range-out-of-order-incomplete", {}).get("outOfOrderRangePieceReleaseCovered")
        ),
        "outOfOrderCompressedRangeCovered": bool(
            evidence_by_id.get("downloader-range-out-of-order-compressed", {}).get("outOfOrderCompressedRangeCovered")
            and evidence_by_id.get("downloader-range-out-of-order-compressed", {}).get("compressedMultiRangeWindowCovered")
        ),
        "adaptiveWindowPolicyCovered": bool(
            evidence_by_id.get("downloader-window-policy", {}).get("adaptiveWindowPolicyCovered")
            and evidence_by_id.get("downloader-window-policy", {}).get("queueDeadlineTimeoutCovered")
            and evidence_by_id.get("downloader-window-policy", {}).get("partDeadlineTimeoutCovered")
        ),
        "hashset2AichCovered": bool(
            evidence_by_id.get("protocol-codec", {}).get("hashset2Md4AichCovered")
            and evidence_by_id.get("downloader-hashset-startup", {}).get("aichHashsetAcquisitionCovered")
            and evidence_by_id.get("listener-hashset", {}).get("listenerHashset2AichAnswerCovered")
        ),
        "listenerStartupCovered": bool(evidence_by_id.get("listener-startup", {}).get("listenerStartupCovered")),
        "sharedBrowseDeniedCovered": bool(evidence_by_id.get("listener-startup", {}).get("sharedBrowseDeniedCovered")),
        "obfuscatedQueueCovered": bool(
            evidence_by_id.get("downloader-queue", {}).get("obfuscatedTransportCovered")
            and evidence_by_id.get("listener-queue", {}).get("obfuscatedTransportCovered")
        ),
        "obfuscatedResumeCovered": bool(
            evidence_by_id.get("downloader-resume", {}).get("obfuscatedTransportCovered")
            and evidence_by_id.get("listener-resume", {}).get("obfuscatedTransportCovered")
        ),
        "obfuscatedServingCovered": bool(evidence_by_id.get("listener-serving", {}).get("obfuscatedTransportCovered")),
        "obfuscatedProtocolCovered": bool(
            evidence_by_id.get("protocol-obfuscation", {}).get("obfuscationHandshakeCovered")
            and evidence_by_id.get("protocol-callback", {}).get("obfuscatedCallbackCovered")
        ),
        "secureIdentProtocolCovered": bool(
            evidence_by_id.get("protocol-identity", {}).get("secureIdentProtocolCovered")
            and evidence_by_id.get("protocol-identity", {}).get("secureIdentWireShapeCovered")
            and evidence_by_id.get("protocol-identity", {}).get("secureIdentSignatureCovered")
        ),
        "tcpDumpPhaseLabelsCovered": bool(
            evidence_by_id.get("protocol-dump-labels", {}).get("tcpDumpPhaseLabelsCovered")
        ),
        "tcpDumpInlineCovered": bool(
            evidence_by_id.get("tcp-dump-inline", {}).get("tcpDumpInlineCovered")
            and evidence_by_id.get("tcp-dump-inline", {}).get("tcpDumpPrefixCovered")
        ),
        "downloaderSecureIdentStateCovered": bool(
            evidence_by_id.get("downloader-secure-ident-state", {}).get("downloaderSecureIdentStateCovered")
            and evidence_by_id.get("downloader-secure-ident-state", {}).get("secureIdentPeerSignatureGateCovered")
            and evidence_by_id.get("downloader-secure-ident-state", {}).get("secureIdentLocalSignaturePendingCovered")
        ),
        "kadFirewallRuntimeCovered": bool(
            evidence_by_id.get("kad-firewall-runtime", {}).get("kadFirewallRuntimeCovered")
            and evidence_by_id.get("kad-firewall-runtime", {}).get("udpFirewallRoundCovered")
            and evidence_by_id.get("kad-firewall-runtime", {}).get("tcpFirewallRecheckCovered")
        ),
        "natRuntimeCovered": bool(
            evidence_by_id.get("nat-runtime", {}).get("natRuntimeCovered")
            and evidence_by_id.get("nat-runtime", {}).get("natBackendSelectionCovered")
            and evidence_by_id.get("nat-runtime", {}).get("natStatusReconcileCovered")
            and evidence_by_id.get("nat-miniupnpc-runtime", {}).get("natMiniupnpcCovered")
            and evidence_by_id.get("nat-rupnp-runtime", {}).get("natRupnpCovered")
        ),
        "networkingRuntimeCovered": bool(
            evidence_by_id.get("networking-runtime", {}).get("networkingRuntimeCovered")
            and evidence_by_id.get("networking-runtime", {}).get("networkingBindSelectionCovered")
            and evidence_by_id.get("networking-runtime", {}).get("vpnPreferenceCovered")
        ),
        "coreDirectDownloadSchedulerCovered": bool(
            evidence_by_id.get("core-direct-download-scheduler", {}).get("coreDirectDownloadSchedulerCovered")
            and evidence_by_id.get("core-direct-download-scheduler", {}).get(
                "coreDirectDownloadRetriesOtherPeerCovered"
            )
            and evidence_by_id.get("core-direct-download-scheduler", {}).get(
                "coreDirectDownloadLoopbackRetryCovered"
            )
            and evidence_by_id.get("core-direct-download-scheduler", {}).get(
                "coreDirectDownloadAcceptedIncompleteCovered"
            )
            and evidence_by_id.get("core-direct-download-scheduler", {}).get(
                "coreDirectDownloadPlaintextFallbackCovered"
            )
        ),
        "coreDirectDownloadCandidatesCovered": bool(
            evidence_by_id.get("core-direct-download-candidates", {}).get("coreDirectDownloadCandidatesCovered")
            and evidence_by_id.get("core-direct-download-candidates", {}).get(
                "coreDirectDownloadEndpointFamilyExhaustionCovered"
            )
            and evidence_by_id.get("core-direct-download-candidates", {}).get(
                "coreDirectDownloadEndpointDedupeCovered"
            )
        ),
        "coreSourceRequeryPolicyCovered": bool(
            evidence_by_id.get("core-source-requery-policy", {}).get("coreSourceRequeryPolicyCovered")
        ),
        "coreZeroSourceBackgroundCovered": bool(
            evidence_by_id.get("core-zero-source-background", {}).get("coreZeroSourceBackgroundCovered")
        ),
        "coreCallbackRouteCovered": bool(
            evidence_by_id.get("core-callback-route", {}).get("coreCallbackRouteCovered")
        ),
        "coreSourceMergeCovered": bool(
            evidence_by_id.get("core-source-merge", {}).get("coreSourceMergeCovered")
            and evidence_by_id.get("core-source-merge", {}).get("coreRememberedSourceHintCovered")
            and evidence_by_id.get("core-source-merge", {}).get("coreKadSourceSupplementCovered")
            and evidence_by_id.get("core-source-merge", {}).get("coreKadSourceMetadataCovered")
        ),
        "coreHashOnlySearchCovered": bool(
            evidence_by_id.get("core-hash-only-search", {}).get("coreHashOnlySearchCovered")
            and evidence_by_id.get("core-hash-only-search", {}).get("coreExactHashServerBudgetCovered")
            and evidence_by_id.get("core-hash-only-search", {}).get("coreHashOnlyMetadataSelectionCovered")
        ),
        "coreKeywordTargetCovered": bool(
            evidence_by_id.get("core-keyword-target", {}).get("coreKeywordTargetCovered")
            and evidence_by_id.get("core-keyword-target", {}).get("coreKeywordSignificantWordsCovered")
            and evidence_by_id.get("core-keyword-target", {}).get("coreKeywordExactHashTargetCovered")
        ),
        "coreStockSearchPaginationCovered": bool(
            evidence_by_id.get("core-stock-search-pagination", {}).get("coreStockSearchPaginationCovered")
            and evidence_by_id.get("core-stock-search-pagination", {}).get("coreStockOversizedSearchResultCovered")
        ),
        "coreSourcePublishCovered": bool(
            evidence_by_id.get("core-publish-tags", {}).get("coreSourcePublishTagsCovered")
            and evidence_by_id.get("core-publish-tags", {}).get("coreSourcePublishObfuscationCovered")
            and evidence_by_id.get("core-publish-tags", {}).get("coreSourcePublishIdentityCovered")
        ),
        "coreEd2kFileTypeSearchCovered": bool(
            evidence_by_id.get("core-ed2k-file-type-search", {}).get("coreEd2kFileTypeSearchCovered")
        ),
        "coreTransferLifecycleCovered": bool(
            evidence_by_id.get("core-transfer-lifecycle", {}).get("coreTransferLifecycleCovered")
            and evidence_by_id.get("core-transfer-lifecycle", {}).get("coreTransferManifestReloadCovered")
            and evidence_by_id.get("core-transfer-lifecycle", {}).get("coreStoppedTransferPersistenceCovered")
        ),
        "daemonEd2kNetworkConfigCovered": bool(
            evidence_by_id.get("daemon-ed2k-network-config", {}).get("daemonEd2kNetworkConfigCovered")
            and evidence_by_id.get("daemon-ed2k-network-config", {}).get("daemonEd2kServerMetadataCovered")
            and evidence_by_id.get("daemon-ed2k-network-config", {}).get("daemonEd2kNatBindCovered")
        ),
        "daemonEd2kUserHashCovered": bool(
            evidence_by_id.get("daemon-ed2k-user-hash", {}).get("daemonEd2kUserHashCovered")
            and evidence_by_id.get("daemon-ed2k-user-hash", {}).get("daemonEd2kUserHashMarkersCovered")
            and evidence_by_id.get("daemon-ed2k-user-hash", {}).get("daemonEd2kUserHashPersistenceCovered")
        ),
        "daemonP2pBindInterfaceCovered": bool(
            evidence_by_id.get("daemon-p2p-bind-interface", {}).get("daemonP2pBindInterfaceCovered")
            and evidence_by_id.get("daemon-p2p-bind-interface", {}).get("daemonP2pBindOverrideCovered")
        ),
        "daemonEd2kConfigParseCovered": bool(
            evidence_by_id.get("daemon-ed2k-config-parse", {}).get("daemonEd2kConfigParseCovered")
            and evidence_by_id.get("daemon-ed2k-config-parse", {}).get("daemonEd2kObfuscationMetadataCovered")
        ),
        "indexSnoopQueueCovered": bool(
            evidence_by_id.get("index-snoop-queue", {}).get("indexSnoopQueueCovered")
            and evidence_by_id.get("index-snoop-queue", {}).get("indexSnoopSourceReplayCovered")
            and evidence_by_id.get("index-snoop-queue", {}).get("indexSnoopKeywordNotesCovered")
            and evidence_by_id.get("index-snoop-queue", {}).get("indexSnoopMergeRestoreCovered")
        ),
    }


def tail_lines(text: str, limit: int = 40) -> list[str]:
    """Returns the last lines of command output for diagnostics."""

    return text.splitlines()[-limit:]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Writes one stable JSON artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def publish_latest(run_dir: Path, latest_dir: Path) -> None:
    """Refreshes the lightweight latest evidence directory for this suite."""

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)


def main(argv: list[str] | None = None) -> int:
    """Runs the selected Rust ED2K parity module cases."""

    args = parse_args(argv)
    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    rust_repo = resolve_rust_repo(args.rust_repo, workspace_root)
    cargo_target_dir = output_root / "builds" / "rust" / "target"
    run_id = utc_run_id()
    run_dir = args.artifacts_dir.resolve() if args.artifacts_dir else output_root / "reports" / SUITE_NAME / run_id
    latest_dir = output_root / "reports" / SUITE_NAME / "latest"
    cases_to_run = selected_cases(args.case)
    report: dict[str, Any] = {
        "suite": SUITE_NAME,
        "status": "running",
        "runId": run_id,
        "startedAtUtc": datetime.now(UTC).isoformat(),
        "rustRepo": str(rust_repo),
        "cargoTargetDir": str(cargo_target_dir),
        "cases": [],
        "checks": {},
    }
    try:
        for case in cases_to_run:
            case_report = run_cargo_case(case, rust_repo, cargo_target_dir)
            report["cases"].append(case_report)
        report["checks"]["rust_private_ed2k_module_requirements"] = build_requirement_checks(report["cases"])
        report["status"] = "passed" if report["checks"]["rust_private_ed2k_module_requirements"]["allCasesPassed"] else "failed"
        return 0 if report["status"] == "passed" else 1
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        report["finishedAtUtc"] = datetime.now(UTC).isoformat()
        write_json(run_dir / f"{SUITE_NAME}-result.json", report)
        publish_latest(run_dir, latest_dir)


if __name__ == "__main__":
    raise SystemExit(main())
