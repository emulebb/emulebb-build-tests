from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace


def load_suite_module():
    """Loads the hyphenated Rust ED2K private parity script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "rust-ed2k-private-parity-modules.py"
    spec = importlib.util.spec_from_file_location("rust_ed2k_private_parity_modules_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_selected_cases_defaults_to_full_private_parity_set() -> None:
    module = load_suite_module()

    cases = module.selected_cases(None)

    assert [case.case_id for case in cases] == [
        "protocol-codec",
        "ed2k-config-defaults",
        "protocol-hello",
        "protocol-obfuscation",
        "protocol-callback",
        "protocol-identity",
        "protocol-dump-labels",
        "tcp-dump-inline",
        "downloader-secure-ident-state",
        "server-protocol",
        "server-startup-inline",
        "server-diagnostics-inline",
        "transfer-runtime",
        "downloader-startup-metadata",
        "downloader-startup-secure-ident",
        "downloader-hashset-startup",
        "downloader-hashset-fallback",
        "downloader-frame-compressed",
        "downloader-frame-sending-part",
        "downloader-payload-validation",
        "downloader-range-malformed",
        "downloader-range-out-of-order-complete",
        "downloader-range-out-of-order-incomplete",
        "downloader-range-out-of-order-compressed",
        "downloader-window-policy",
        "downloader-queue",
        "listener-queue",
        "downloader-resume",
        "listener-resume",
        "downloader-callback",
        "listener-serving",
        "listener-startup",
        "listener-hashset",
        "kad-firewall-runtime",
        "nat-runtime",
        "nat-miniupnpc-runtime",
        "nat-rupnp-runtime",
        "networking-runtime",
        "core-direct-download-scheduler",
        "core-direct-download-candidates",
        "core-source-requery-policy",
        "core-zero-source-background",
        "core-callback-route",
        "core-source-merge",
        "core-hash-only-search",
        "core-keyword-target",
        "core-stock-search-pagination",
        "core-publish-tags",
        "core-ed2k-file-type-search",
        "core-transfer-lifecycle",
        "daemon-ed2k-network-config",
        "daemon-ed2k-user-hash",
        "daemon-p2p-bind-interface",
        "daemon-ed2k-config-parse",
        "index-snoop-queue",
    ]


def test_run_cargo_case_uses_output_root_cargo_target(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[dict[str, object]] = []

    def fake_run(command, *, cwd, env, text, capture_output, check):
        calls.append(
            {
                "command": command,
                "cwd": cwd,
                "cargo_target_dir": env["CARGO_TARGET_DIR"],
                "text": text,
                "capture_output": capture_output,
                "check": check,
            }
        )
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    case = module.selected_cases(["downloader-resume"])[0]
    cargo_target = tmp_path / "output" / "builds" / "rust" / "target"

    report = module.run_cargo_case(case, tmp_path / "rust", cargo_target)

    assert calls == [
        {
            "command": ["cargo", "test", "-p", "emulebb-ed2k", "ed2k_tcp::tests::download::resume_reconnect", "--", "--nocapture"],
            "cwd": tmp_path / "rust",
            "cargo_target_dir": os.fspath(cargo_target),
            "text": True,
            "capture_output": True,
            "check": False,
        }
    ]
    assert report["status"] == "passed"
    assert report["evidence"]["partialPieceResumeCovered"] is True
    assert report["evidence"]["rustTestsPassed"] is True


def test_private_ed2k_requirement_checks_require_every_surface() -> None:
    module = load_suite_module()
    cases = [
        {"id": case.case_id, "status": "passed", "evidence": {**case.evidence, "rustTestsPassed": True}}
        for case in module.RUST_MODULE_CASES
    ]

    checks = module.build_requirement_checks(cases)

    assert checks == {
        "caseCount": 55,
        "allCasesPassed": True,
        "downloaderQueueCovered": True,
        "listenerQueueCovered": True,
        "downloaderResumeCovered": True,
        "listenerResumeCovered": True,
        "callbackSessionCovered": True,
        "compressedPartServingCovered": True,
        "protocolCodecCovered": True,
        "ed2kConfigDefaultsCovered": True,
        "helloAdvertTruthfulnessCovered": True,
        "sourceExchange2Covered": True,
        "serverProtocolCovered": True,
        "serverLoginOracleCovered": True,
        "serverOfferFilesCovered": True,
        "serverSearchDecodeCovered": True,
        "serverSourceDecodeCovered": True,
        "serverBackgroundSearchCovered": True,
        "serverCallbackDecodeCovered": True,
        "serverObfuscationCovered": True,
        "serverStartupInlineCovered": True,
        "serverOfferFilesLanBindCovered": True,
        "serverOfferFilesUnicodeTagCovered": True,
        "serverOfferFilesCompressionSentinelCovered": True,
        "serverDiagnosticsInlineCovered": True,
        "serverDiagnosticsDumpNameCovered": True,
        "previewSurfaceCovered": True,
        "startupMetadataCovered": True,
        "hashOnlyMetadataRecoveryCovered": True,
        "transferRuntimeCovered": True,
        "transferMd4PieceVerificationCovered": True,
        "transferAichPersistenceCovered": True,
        "transferRemoteAichPreservedCovered": True,
        "transferLocalIngestCovered": True,
        "transferLegacyManifestRepairCovered": True,
        "transferInvalidAichRejectedCovered": True,
        "transferMetadataReconcileCovered": True,
        "transferPartialProgressResumeCovered": True,
        "transferCatalogHintMergeCovered": True,
        "transferUploadQueueCovered": True,
        "startupSecureIdentCovered": True,
        "downloadHashsetCovered": True,
        "compressedFrameDownloadCovered": True,
        "obfuscatedPackedCompressedFrameCovered": True,
        "sendingPartFrameCovered": True,
        "badPayloadRejectedCovered": True,
        "malformedRangeRecoveryCovered": True,
        "outOfOrderRangeCompleteCovered": True,
        "outOfOrderRangeIncompleteCovered": True,
        "outOfOrderCompressedRangeCovered": True,
        "adaptiveWindowPolicyCovered": True,
        "hashset2AichCovered": True,
        "listenerStartupCovered": True,
        "sharedBrowseDeniedCovered": True,
        "obfuscatedQueueCovered": True,
        "obfuscatedResumeCovered": True,
        "obfuscatedServingCovered": True,
        "obfuscatedProtocolCovered": True,
        "secureIdentProtocolCovered": True,
        "tcpDumpPhaseLabelsCovered": True,
        "tcpDumpInlineCovered": True,
        "downloaderSecureIdentStateCovered": True,
        "kadFirewallRuntimeCovered": True,
        "natRuntimeCovered": True,
        "networkingRuntimeCovered": True,
        "coreDirectDownloadSchedulerCovered": True,
        "coreDirectDownloadCandidatesCovered": True,
        "coreSourceRequeryPolicyCovered": True,
        "coreZeroSourceBackgroundCovered": True,
        "coreCallbackRouteCovered": True,
        "coreSourceMergeCovered": True,
        "coreHashOnlySearchCovered": True,
        "coreKeywordTargetCovered": True,
        "coreStockSearchPaginationCovered": True,
        "coreSourcePublishCovered": True,
        "coreEd2kFileTypeSearchCovered": True,
        "coreTransferLifecycleCovered": True,
        "daemonEd2kNetworkConfigCovered": True,
        "daemonEd2kUserHashCovered": True,
        "daemonP2pBindInterfaceCovered": True,
        "daemonEd2kConfigParseCovered": True,
        "indexSnoopQueueCovered": True,
    }


def test_private_ed2k_requirement_checks_reject_failed_case() -> None:
    module = load_suite_module()
    cases = [
        {"id": case.case_id, "status": "passed", "evidence": {**case.evidence, "rustTestsPassed": True}}
        for case in module.RUST_MODULE_CASES
    ]
    cases[0]["status"] = "failed"

    checks = module.build_requirement_checks(cases)

    assert checks["allCasesPassed"] is False
