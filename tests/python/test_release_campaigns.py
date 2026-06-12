from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from emule_test_harness import campaign_scenarios, release_campaigns, windows_vm_profiles


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_release_campaign_manifests_match_json_schema() -> None:
    root = repo_root()
    schema = json.loads((root / "manifests" / "release-campaigns" / "v1.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    for path in sorted((root / "manifests" / "release-campaigns").glob("*.json")):
        if path.name.endswith(".schema.json"):
            continue
        validator.validate(json.loads(path.read_text(encoding="utf-8")))


def test_release_campaign_schema_uses_emulebb_namespace() -> None:
    root = repo_root()
    schema = json.loads((root / "manifests" / "release-campaigns" / "v1.schema.json").read_text(encoding="utf-8"))

    assert schema["$id"] == release_campaigns.SCHEMA_VERSION
    assert "emulebb-build-tests" in release_campaigns.SCHEMA_VERSION


def test_default_template_defines_strict_phase_taxonomy() -> None:
    template = release_campaigns.load_release_campaign_template(repo_root())

    assert release_campaigns.validate_release_campaign_template(template) == []
    assert [phase["id"] for phase in template["taxonomy"]["phases"]] == list(release_campaigns.STRICT_PHASE_TAXONOMY)


def test_073_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emulebb-0.7.3")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    scenario_ids = {
        scenario["id"]
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }
    covered_ids = {
        scenario_id
        for gate in campaign["releaseGates"]
        for scenario_id in gate["coveredBy"]
    }
    assert covered_ids <= scenario_ids
    assert {phase["id"] for phase in campaign["phases"]} == set(release_campaigns.STRICT_PHASE_TAXONOMY)
    assert campaign["proofTier"] == "rc-blocking-quick"
    assert set(windows_vm_profiles.WINDOWS_VM_PROFILE_BY_SCENARIO_ID) <= scenario_ids
    installer_scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["id"] == "emulebb.flow.installer.controller-surface.materialized.v1"
    )
    assert installer_scenario["liveE2eProfile"] == "installer-controller-surface"
    assert "emulebb.flow.installer.controller-surface.materialized.v1" in {
        scenario_id
        for gate in campaign["releaseGates"]
        if gate["id"] == "installer-backed-controller-surface"
        for scenario_id in gate["coveredBy"]
    }
    windows_vm_scenarios = {
        scenario
        for scenario in scenario_ids
        if scenario.startswith("emulebb.flow.windows-vm.")
    }
    assert windows_vm_scenarios.isdisjoint(covered_ids)
    for scenario_id in windows_vm_scenarios:
        scenario = next(
            scenario
            for phase in campaign["phases"]
            for scenario in phase["scenarios"]
            if scenario["id"] == scenario_id
        )
        assert scenario["required"] is False
        assert scenario["blocking"] is False


def test_073_campaign_contains_every_reusable_local_vm_swarm_scenario() -> None:
    campaign = release_campaigns.load_release_campaign(repo_root(), "emulebb-0.7.3")
    scenarios = {
        scenario["id"]: scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }

    assert set(campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_SCENARIO_ID) <= set(scenarios)
    for spec in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIOS:
        scenario = scenarios[spec.scenario_id]
        assert scenario["flowCategory"] == "local-vm-swarm"
        assert scenario["executionModes"] == ["local", "vm"]
        assert scenario["localCommand"] == spec.command_for_mode("local")
        assert scenario["vmCommand"] == spec.command_for_mode("vm", release_version=campaign["releaseVersion"])


def test_073_campaign_windows_vm_rows_match_profile_catalog() -> None:
    campaign = release_campaigns.load_release_campaign(repo_root(), "emulebb-0.7.3")
    scenarios = {
        scenario["id"]: scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }

    for spec in windows_vm_profiles.WINDOWS_VM_PROFILE_SPECS:
        scenario = scenarios[spec.scenario_id]
        assert scenario["phase"] == spec.release_phase
        if spec.scenario_id in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_SCENARIO_ID:
            shared = campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_SCENARIO_ID[spec.scenario_id]
            assert scenario["flowCategory"] == "local-vm-swarm"
            assert scenario["command"] == (
                "python -m emule_workspace test campaign-scenario "
                f"--scenario {spec.scenario_id} --mode vm --release-version 0.7.3-rc.2 "
                "--skip-build --swarm-tier 1 --local-swarm-mode plan --dry-run"
            )
            assert scenario["localCommand"] == shared.command_for_mode("local")
            assert scenario["vmCommand"] == shared.command_for_mode("vm", release_version="0.7.3-rc.2")
            assert scenario["command"] == scenario["vmCommand"]
            assert scenario["executionMode"] == "vm"
            assert scenario["executionModes"] == ["local", "vm"]
            assert scenario["localProfile"] == shared.local_profile
            assert scenario["localSuites"] == list(shared.local_suites)
            assert scenario["vmProfile"] == spec.name
            assert scenario["controlBindScope"] == shared.control_bind_scope == "lan"
            assert scenario["amutorrentBindScope"] == shared.amutorrent_bind_scope == "lan"
            assert scenario["p2pMode"] == shared.p2p_mode == "local-swarm"
            assert scenario["p2pBindScope"] == shared.p2p_bind_scope == "lan"
        else:
            assert scenario["flowCategory"] == "windows-vm"
            assert f"test windows-vm --matrix {','.join(spec.required_targets)}" in scenario["command"]
            assert f"--profile {spec.name}" in scenario["command"]
        evidence = scenario["evidence"][0]
        assert evidence["glob"] == "reports/windows-vm/*/windows-vm-result.json"
        assert evidence["matches"] == {"/profile": spec.name}


def test_073_overnight_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emulebb-0.7.3-overnight")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    scenario_ids = {
        scenario["id"]
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }
    covered_ids = {
        scenario_id
        for gate in campaign["releaseGates"]
        for scenario_id in gate["coveredBy"]
    }
    assert covered_ids <= scenario_ids
    assert campaign["proofTier"] == "overnight-full"
    assert {phase["id"] for phase in campaign["phases"]} == set(release_campaigns.STRICT_PHASE_TAXONOMY)


def test_p2p_overlord_campaign_validates_and_covers_all_release_gates() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "p2p-overlord-0.1.1")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    assert campaign["releaseVersion"] == "0.1.1-rc.1"
    scenario_ids = {
        scenario["id"]
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }
    covered_ids = {
        scenario_id
        for gate in campaign["releaseGates"]
        for scenario_id in gate["coveredBy"]
    }
    assert covered_ids <= scenario_ids
    assert "emulebb.flow.p2p-overlord.rest.openapi-subset.v1" in scenario_ids
    assert campaign["proofTier"] == "future"


def test_emulebb_rust_campaign_validates_and_covers_local_proof() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emulebb-rust")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    assert campaign["campaignId"] == "emulebb-rust"
    assert campaign["releaseVersion"] == "0.0.3"
    assert campaign["proofTier"] == "future"
    assert "MVP" not in json.dumps(campaign)
    assert "emulebb-rust-v0.0.3" in json.dumps(campaign)
    scenario_ids = {
        scenario["id"]
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }
    covered_ids = {
        scenario_id
        for gate in campaign["releaseGates"]
        for scenario_id in gate["coveredBy"]
    }
    rust_pytest_command = "python -m emule_workspace test python --path tests/python/test_emulebb_rust_local_client.py --quiet"
    rust_rest_contract_command = (
        "python -m emule_workspace test python "
        "--path tests/python/test_emulebb_rust_rest_contract.py "
        "--path tests/python/test_emulebb_rust_local_client.py --quiet"
    )
    rust_cross_client_command = (
        "python scripts/multi-client-p2p-matrix.py --lan-bind-addr ${X_LOCAL_IP} "
        "--app-exe ${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/main/x64/Release/standard/bin/emulebb.exe "
        "--client2-app-exe ${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/tracing-harness/x64/Release/standard/bin/emule.exe "
        "--require-scenario cl-emulebb-001-cl-emulebb-rust-005-bidirectional-exchange"
    )
    rust_amule_command = (
        "python scripts/multi-client-p2p-matrix.py --lan-bind-addr ${X_LOCAL_IP} "
        "--app-exe ${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/main/x64/Release/standard/bin/emulebb.exe "
        "--client2-app-exe ${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/tracing-harness/x64/Release/standard/bin/emule.exe "
        "--require-scenario cl-emulebb-rust-005-cl-amule-004-bidirectional-exchange"
    )
    rust_protocol_combinations_command = (
        "python scripts/local-ed2k-rust-protocol-combinations.py --lan-bind-addr ${X_LOCAL_IP} "
        "--app-exe ${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/main/x64/Release/standard/bin/emulebb.exe "
        "--client2-app-exe ${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/tracing-harness/x64/Release/standard/bin/emule.exe"
    )

    assert covered_ids <= scenario_ids
    assert {phase["id"] for phase in campaign["phases"]} == set(release_campaigns.STRICT_PHASE_TAXONOMY)
    assert "emulebb.flow.rust.rest.emulebb-contract.v1" in scenario_ids
    assert "emulebb.flow.rust.local-ed2k.protocol-combinations.v1" in scenario_ids
    assert "emulebb.flow.rust.cross-client.emulebb-bidirectional.v1" in scenario_ids
    assert "emulebb.flow.rust.cross-client.amule-bidirectional.v1" in scenario_ids
    assert "emulebb.flow.rust.local-ed2k.protocol-combinations.v1" in covered_ids
    assert "emulebb.flow.rust.cross-client.emulebb-bidirectional.v1" in covered_ids
    assert "emulebb.flow.rust.cross-client.amule-bidirectional.v1" in covered_ids
    assert sum(
        1
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["command"] == rust_pytest_command
    ) == 2
    assert any(
        scenario["command"] == rust_rest_contract_command
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    )
    assert any(
        scenario["command"] == rust_cross_client_command
        and scenario["required"] is True
        and scenario["blocking"] is True
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    )
    assert any(
        scenario["command"] == rust_amule_command
        and scenario["required"] is True
        and scenario["blocking"] is True
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    )
    assert any(
        scenario["command"] == rust_protocol_combinations_command
        and scenario["required"] is True
        and scenario["blocking"] is True
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    )
    rust_scenarios = {
        scenario["id"]: scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["id"].startswith("emulebb.flow.rust.")
    }
    local_description = json.dumps(rust_scenarios["emulebb.flow.rust.local-ed2k.search-download.v1"]["evidence"])
    protocol_description = json.dumps(rust_scenarios["emulebb.flow.rust.local-ed2k.protocol-combinations.v1"]["evidence"])
    cross_client_description = json.dumps(rust_scenarios["emulebb.flow.rust.cross-client.emulebb-bidirectional.v1"]["evidence"])
    amule_description = json.dumps(rust_scenarios["emulebb.flow.rust.cross-client.amule-bidirectional.v1"]["evidence"])
    assert "Unicode filenames" in local_description
    assert "hash-only ED2K metadata recovery" in local_description
    assert "protocol_matrix_coverage" in protocol_description
    assert "all four cases" in protocol_description
    assert "Unicode fixture-name, and hash-only fixture-name surfaces" in protocol_description
    assert "ED2K link name round-trip" in protocol_description
    assert "three Rust transfers in one protocol session" in protocol_description
    assert "hash-only ED2K link metadata recovery in every protocol case" in protocol_description
    assert "source userHash metadata" in protocol_description
    assert "MD4/AICH hashset metadata for both named transfers" in protocol_description
    assert "Rust-persisted source userHash" in cross_client_description
    assert "Unicode filename" in cross_client_description
    assert "AICH hashset metadata" in cross_client_description
    assert "Rust-persisted source userHash" in amule_description
    assert "aMule's missing AICH hashset" in amule_description


def test_emulebb_rust_overnight_campaign_validates_and_covers_ed2k_parity() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = release_campaigns.load_release_campaign(root, "emulebb-rust-overnight")

    assert release_campaigns.validate_release_campaign(campaign, template) == []
    assert campaign["campaignId"] == "emulebb-rust-overnight"
    assert campaign["proofTier"] == "overnight-full"
    assert {phase["id"] for phase in campaign["phases"]} == set(release_campaigns.STRICT_PHASE_TAXONOMY)

    scenarios = {
        scenario["id"]: scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
    }
    covered_ids = {
        scenario_id
        for gate in campaign["releaseGates"]
        for scenario_id in gate["coveredBy"]
    }
    protocol_id = "emulebb.flow.rust.overnight.local-ed2k.protocol-combinations.v1"
    private_modules_id = "emulebb.flow.rust.overnight.private-ed2k.modules.v1"
    emulebb_cross_id = "emulebb.flow.rust.overnight.cross-client.emulebb-bidirectional.v1"
    rust_cross_id = "emulebb.flow.rust.overnight.cross-client.rust-bidirectional.v1"
    amule_cross_id = "emulebb.flow.rust.overnight.cross-client.amule-bidirectional.v1"
    total_audit_id = "emulebb.flow.rust.overnight.ed2k-total-parity-audit.v1"
    preflight_id = "emulebb.flow.rust.overnight.local-client.pytest.v1"
    rest_contract_id = "emulebb.flow.rust.overnight.rest.contract.v1"

    assert covered_ids <= set(scenarios)
    assert preflight_id in covered_ids
    assert rest_contract_id in covered_ids
    assert protocol_id in covered_ids
    assert private_modules_id in covered_ids
    assert emulebb_cross_id in covered_ids
    assert rust_cross_id in covered_ids
    assert amule_cross_id in covered_ids
    assert total_audit_id in covered_ids
    preflight_evidence = scenarios[preflight_id]["evidence"][0]
    assert preflight_evidence["kind"] == "json-status"
    assert preflight_evidence["base"] == "workspace-output"
    assert preflight_evidence["matches"]["/checks/rust_overnight_pytest_requirements/caseCount"] == 2
    assert preflight_evidence["matches"]["/checks/rust_overnight_pytest_requirements/localClientPytestPassed"] is True
    assert preflight_evidence["matches"]["/checks/rust_overnight_pytest_requirements/restContractPytestPassed"] is True
    rest_contract_evidence = scenarios[rest_contract_id]["evidence"][0]
    assert rest_contract_evidence["kind"] == "json-status"
    assert rest_contract_evidence["base"] == "workspace-output"
    assert rest_contract_evidence["matches"]["/checks/rust_overnight_pytest_requirements/restContractPytestPassed"] is True
    assert scenarios[protocol_id]["required"] is True
    assert scenarios[protocol_id]["blocking"] is True
    assert "${EMULEBB_WORKSPACE_OUTPUT_ROOT}/builds/app/main/x64/Release/standard/bin/emulebb.exe" in scenarios[protocol_id]["command"]
    assert "${EMULEBB_WORKSPACE_OUTPUT_ROOT}/tools/goed2k-server/goed2k-server.exe" in scenarios[protocol_id]["command"]
    protocol_evidence = scenarios[protocol_id]["evidence"][0]
    assert protocol_evidence["base"] == "workspace-output"
    assert protocol_evidence["matches"]["/checks/protocol_matrix_coverage/caseCount"] == 4
    assert protocol_evidence["matches"]["/checks/rust_protocol_case_requirements/hashOnlyMetadataRecoveryPerCase"] is True
    assert protocol_evidence["matches"]["/checks/rust_protocol_case_requirements/unicodeHashOnlyMetadataPerCase"] is True
    private_modules_evidence = scenarios[private_modules_id]["evidence"][0]
    assert private_modules_evidence["base"] == "workspace-output"
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/caseCount"] == 55
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/protocolCodecCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/ed2kConfigDefaultsCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/helloAdvertTruthfulnessCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/sourceExchange2Covered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverProtocolCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverObfuscationCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverStartupInlineCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverOfferFilesUnicodeTagCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverOfferFilesCompressionSentinelCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverDiagnosticsInlineCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/serverDiagnosticsDumpNameCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/transferRuntimeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/transferAichPersistenceCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/transferUploadQueueCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/hashset2AichCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/compressedFrameDownloadCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/outOfOrderCompressedRangeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/downloaderQueueCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/listenerResumeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/callbackSessionCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/obfuscatedServingCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/secureIdentProtocolCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/downloaderSecureIdentStateCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/kadFirewallRuntimeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/natRuntimeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/networkingRuntimeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/coreDirectDownloadSchedulerCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/coreHashOnlySearchCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/coreKeywordTargetCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/coreStockSearchPaginationCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/coreSourceMergeCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/coreEd2kFileTypeSearchCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/daemonEd2kNetworkConfigCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/daemonEd2kUserHashCovered"] is True
    assert private_modules_evidence["matches"]["/checks/rust_private_ed2k_module_requirements/indexSnoopQueueCovered"] is True
    emulebb_cross_evidence = scenarios[emulebb_cross_id]["evidence"][0]
    assert emulebb_cross_evidence["matches"]["/scenarios/1/report/checks/rust_emulebb_cross_client_requirements/unicodeFixtureNames"] is True
    assert emulebb_cross_evidence["matches"]["/scenarios/1/report/checks/rust_emulebb_cross_client_requirements/rustPersistedAichHashset"] is True
    rust_cross_evidence = scenarios[rust_cross_id]["evidence"][0]
    assert rust_cross_evidence["matches"]["/scenarios/1/report/checks/multiTransferCount"] == 3
    assert rust_cross_evidence["matches"]["/scenarios/1/report/checks/hashOnlyMetadataRecovery"] is True
    assert rust_cross_evidence["matches"]["/scenarios/1/report/checks/bidirectionalRustTransfers"] is True
    total_audit_evidence = scenarios[total_audit_id]["evidence"][0]
    assert total_audit_evidence["base"] == "workspace-output"
    assert total_audit_evidence["path"] == (
        "reports/rust-ed2k-total-parity-audit/latest/rust-ed2k-total-parity-audit-result.json"
    )
    assert total_audit_evidence["matches"]["/checks/rust_ed2k_total_parity_audit/requirementCount"] == 7
    assert total_audit_evidence["matches"]["/checks/rust_ed2k_total_parity_audit/allRequirementsPassed"] is True
    assert total_audit_evidence["matches"]["/checks/rust_ed2k_total_parity_audit/failedRequirementCount"] == 0
    assert total_audit_evidence["matches"]["/checks/rust_ed2k_total_parity_audit/protocolVariantsPassed"] is True
    assert total_audit_evidence["matches"]["/checks/rust_ed2k_total_parity_audit/multiUnicodeMetadataPassed"] is True
    assert total_audit_evidence["matches"]["/checks/rust_ed2k_total_parity_audit/crossClientMatrixPassed"] is True


def test_emulebb_rust_overnight_report_matches_strict_workspace_output_evidence(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    output_root = tmp_path / "output"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    protocol_report = output_root / "reports" / "local-ed2k-rust-protocol-combinations" / "latest"
    protocol_report.mkdir(parents=True)
    (protocol_report / "local-ed2k-rust-protocol-combinations-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "checks": {
                    "protocol_matrix_coverage": {
                        "caseCount": 4,
                        "hashOnlyFixtureNames": True,
                        "multiTransferFixtureNames": True,
                    },
                    "rust_protocol_case_requirements": {
                        "threeTransfersPerCase": True,
                        "hashOnlyMetadataRecoveryPerCase": True,
                        "unicodeHashOnlyMetadataPerCase": True,
                        "namedTransferHashsetsPerCase": True,
                        "obfuscatedSourceUserHashPerCase": True,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    private_modules_report = output_root / "reports" / "rust-ed2k-private-parity-modules" / "latest"
    private_modules_report.mkdir(parents=True)
    (private_modules_report / "rust-ed2k-private-parity-modules-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "checks": {
                    "rust_private_ed2k_module_requirements": {
                        "caseCount": 55,
                        "allCasesPassed": True,
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
                        "previewSurfaceCovered": True,
                        "startupMetadataCovered": True,
                        "hashOnlyMetadataRecoveryCovered": True,
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
                        "downloaderQueueCovered": True,
                        "listenerQueueCovered": True,
                        "downloaderResumeCovered": True,
                        "listenerResumeCovered": True,
                        "callbackSessionCovered": True,
                        "compressedPartServingCovered": True,
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
                },
            }
        ),
        encoding="utf-8",
    )

    pytest_report = output_root / "reports" / "rust-overnight-pytest-proof" / "latest"
    pytest_report.mkdir(parents=True)
    (pytest_report / "rust-overnight-pytest-proof-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "checks": {
                    "rust_overnight_pytest_requirements": {
                        "caseCount": 2,
                        "allCasesPassed": True,
                        "localClientPytestPassed": True,
                        "restContractPytestPassed": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    total_audit_report = output_root / "reports" / "rust-ed2k-total-parity-audit" / "latest"
    total_audit_report.mkdir(parents=True)
    (total_audit_report / "rust-ed2k-total-parity-audit-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "checks": {
                    "rust_ed2k_total_parity_audit": {
                        "requirementCount": 7,
                        "allRequirementsPassed": True,
                        "failedRequirementCount": 0,
                        "failedRequirementIds": [],
                        "protocolVariantsPassed": True,
                        "multiUnicodeMetadataPassed": True,
                        "privateP2pOverlordModulesPassed": True,
                        "preflightAndRestPassed": True,
                        "crossClientMatrixPassed": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    emulebb_report = output_root / "reports" / "multi-client-p2p-matrix" / "20260612T010000Z"
    rust_report = output_root / "reports" / "multi-client-p2p-matrix" / "20260612T015000Z"
    amule_report = output_root / "reports" / "multi-client-p2p-matrix" / "20260612T020000Z"
    emulebb_report.mkdir(parents=True)
    rust_report.mkdir(parents=True)
    amule_report.mkdir(parents=True)
    (emulebb_report / "multi-client-p2p-matrix-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "scenarios": [
                    {"id": "cl-emulebb-001-downloads-from-cl-harness-002", "status": "passed"},
                    {
                        "id": "cl-emulebb-001-cl-emulebb-rust-005-bidirectional-exchange",
                        "status": "passed",
                        "report": {
                            "status": "passed",
                            "checks": {
                                "rust_emulebb_cross_client_requirements": {
                                    "bidirectionalTransfers": True,
                                    "unicodeFixtureNames": True,
                                    "rustPersistedSourceUserHash": True,
                                    "rustPersistedMd4Hashset": True,
                                    "rustPersistedAichHashset": True,
                                }
                            },
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (rust_report / "multi-client-p2p-matrix-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "scenarios": [
                    {"id": "cl-emulebb-001-downloads-from-cl-harness-002", "status": "passed"},
                    {
                        "id": "cl-emulebb-rust-005-cl-emulebb-rust-006-bidirectional-exchange",
                        "status": "passed",
                        "report": {
                            "status": "passed",
                            "checks": {
                                "multiTransferCount": 3,
                                "unicodeFilenameTransfer": True,
                                "hashOnlyMetadataRecovery": True,
                                "bidirectionalRustTransfers": True,
                                "sourcePersistenceAfterRestart": True,
                                "sourceControlOperations": True,
                            },
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (amule_report / "multi-client-p2p-matrix-result.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "scenarios": [
                    {"id": "cl-emulebb-001-downloads-from-cl-harness-002", "status": "passed"},
                    {
                        "id": "cl-emulebb-rust-005-cl-amule-004-bidirectional-exchange",
                        "status": "passed",
                        "report": {
                            "status": "passed",
                            "checks": {
                                "rust_amule_manifest_metadata": {
                                    "md4HashsetAcquired": True,
                                    "sourceUserHashCount": 1,
                                }
                            },
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(
            tests_repo_root=tests_root,
            workspace_output_root=output_root,
        ),
        campaign_id="emulebb-rust-overnight",
        phase_id="protocol-parity",
    )

    statuses = {scenario["id"]: scenario["status"] for scenario in report["scenarios"]}
    assert statuses["emulebb.flow.rust.overnight.local-ed2k.protocol-combinations.v1"] == "passed"
    assert statuses["emulebb.flow.rust.overnight.private-ed2k.modules.v1"] == "passed"
    assert statuses["emulebb.flow.rust.overnight.cross-client.emulebb-bidirectional.v1"] == "passed"
    assert statuses["emulebb.flow.rust.overnight.cross-client.rust-bidirectional.v1"] == "passed"
    assert statuses["emulebb.flow.rust.overnight.cross-client.amule-bidirectional.v1"] == "passed"
    assert statuses["emulebb.flow.rust.overnight.ed2k-total-parity-audit.v1"] == "passed"


def test_campaign_validation_rejects_missing_proof_tier() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign.pop("proofTier")

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="proofTier"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_warns_for_unmapped_gate() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign["releaseGates"].append({"id": "future-gate", "coveredBy": []})

    warnings = release_campaigns.validate_release_campaign(campaign, template)

    assert warnings == ["Release gate future-gate is not mapped to any feature-flow scenario."]


def test_campaign_validation_rejects_duplicate_scenario_ids() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    duplicate = copy.deepcopy(campaign["phases"][0]["scenarios"][0])
    campaign["phases"][0]["scenarios"].append(duplicate)

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="Duplicate release campaign scenario id"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_unknown_live_e2e_profile() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign["phases"][2]["scenarios"][0]["liveE2eProfile"] = "unknown-profile"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="unknown live E2E profile"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_command_mismatch() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["executionMode"] = "local"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="command must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_catalog_command_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["localCommand"] = f"{scenario['localCommand']} --extra"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="localCommand must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_release_version_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    campaign["releaseVersion"] = "0.7.4-rc.2"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="vmCommand must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_catalog_metadata_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["vmProfile"] = "other-vm-profile"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="vmProfile must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_validation_rejects_local_vm_swarm_network_contract_drift() -> None:
    root = repo_root()
    template = release_campaigns.load_release_campaign_template(root)
    campaign = copy.deepcopy(release_campaigns.load_release_campaign(root, "emulebb-0.7.3"))
    scenario = next(
        scenario
        for phase in campaign["phases"]
        for scenario in phase["scenarios"]
        if scenario["flowCategory"] == "local-vm-swarm"
    )
    scenario["p2pMode"] = "live-wire"

    with pytest.raises(release_campaigns.ReleaseCampaignError, match="p2pMode must match"):
        release_campaigns.validate_release_campaign(campaign, template)


def test_campaign_report_reads_latest_json_status(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    output_root = tmp_path / "output"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    latest = output_root / "reports" / "live-e2e-suite" / "latest"
    latest.mkdir(parents=True)
    (latest / "live-e2e-suite-result.json").write_text(
        json.dumps({"status": "passed", "profile": "release-expanded-quick"}),
        encoding="utf-8",
    )
    fast = output_root / "reports" / "certification" / "20260517-010203-fast"
    fast.mkdir(parents=True)
    (fast / "certification-result.json").write_text(json.dumps({"status": "inconclusive"}), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(
            tests_repo_root=tests_root,
            workspace_output_root=output_root,
        ),
        campaign_id="emulebb-0.7.3",
    )

    scenarios = {scenario["id"]: scenario for scenario in report["scenarios"]}
    assert scenarios["emulebb.flow.certification.fast.matrix.v1"]["status"] == "inconclusive"
    assert scenarios["emulebb.flow.livewire.release-expanded.weak-path.v1"]["status"] == "passed"
    assert scenarios["emulebb.flow.package.core.x64.v1"]["status"] == "missing-evidence"


def test_campaign_report_glob_selects_matching_vm_profile(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    output_root = tmp_path / "output"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    matching = output_root / "reports" / "windows-vm" / "20260602T010000Z" / "windows-vm-result.json"
    newer_other = output_root / "reports" / "windows-vm" / "20260602T020000Z" / "windows-vm-result.json"
    matching.parent.mkdir(parents=True)
    newer_other.parent.mkdir(parents=True)
    matching.write_text(json.dumps({"status": "passed", "profile": "package-smoke"}), encoding="utf-8")
    newer_other.write_text(json.dumps({"status": "passed", "profile": "hideme-live-wire"}), encoding="utf-8")
    os.utime(matching, (1000, 1000))
    os.utime(newer_other, (2000, 2000))

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(
            tests_repo_root=tests_root,
            workspace_output_root=output_root,
        ),
        campaign_id="emulebb-0.7.3",
        phase_id="packaging-provenance",
    )

    scenario = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["id"] == "emulebb.flow.windows-vm.package-smoke.release.v1"
    )
    assert scenario["status"] == "passed"
    assert scenario["evidence"][0]["path"] == str(matching.resolve())


def test_terminal_report_contains_phase_status_and_warning(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(tests_repo_root=tests_root, workspace_output_root=tmp_path / "output"),
        campaign_id="emulebb-0.7.3",
        phase_id="packaging-provenance",
    )
    text = release_campaigns.format_release_campaign_report(report)

    assert "packaging-provenance" in text
    assert "Proof tier: rc-blocking-quick" in text
    assert "emulebb.flow.package.core.x64.v1" in text
    assert "missing required evidence" in text


def test_terminal_report_shows_local_vm_swarm_commands(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    manifest_root = tests_root / "manifests" / "release-campaigns"
    manifest_root.mkdir(parents=True)
    for path in (repo_root() / "manifests" / "release-campaigns").glob("*.json"):
        (manifest_root / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    report = release_campaigns.build_release_campaign_report(
        release_campaigns.ReleaseCampaignPaths(tests_repo_root=tests_root, workspace_output_root=tmp_path / "output"),
        campaign_id="emulebb-0.7.3",
        phase_id="controller-surface",
    )
    scenario = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["id"] == "emulebb.flow.controller.installer-swarm.v1"
    )
    text = release_campaigns.format_release_campaign_report(report)

    assert "--local-swarm-mode execute" in scenario["vmExecuteCommand"]
    assert "--local-swarm-mode plan" in scenario["localPlanCommand"]
    assert "--local-swarm-mode execute" in scenario["localExecuteCommand"]
    assert "--local-swarm-mode plan" in scenario["vmPlanCommand"]
    assert "--dry-run" in scenario["localPlanCommand"]
    assert "--dry-run" not in scenario["localExecuteCommand"]
    assert "--dry-run" in scenario["vmPlanCommand"]
    assert scenario["localExecuteCommand"] == scenario["localCommand"]
    assert scenario["vmPlanCommand"] == scenario["vmCommand"]
    assert scenario["controlBindScope"] == "lan"
    assert scenario["amutorrentBindScope"] == "lan"
    assert scenario["p2pMode"] == "local-swarm"
    assert scenario["p2pBindScope"] == "lan"
    assert "emulebb.flow.controller.installer-swarm.v1" in text
    assert "mode: vm (available: local, vm)" in text
    assert "local command: python -m emule_workspace test campaign-scenario" in text
    assert "local plan command: python -m emule_workspace test campaign-scenario" in text
    assert "local execute command: python -m emule_workspace test campaign-scenario" in text
    assert "vm command: python -m emule_workspace test campaign-scenario" in text
    assert "vm plan command: python -m emule_workspace test campaign-scenario" in text
    assert "vm execute command: python -m emule_workspace test campaign-scenario" in text
    assert "--mode local" in text
    assert "--mode vm" in text
    assert "--local-swarm-mode execute" in text


def test_operator_script_help_loads() -> None:
    completed = subprocess.run(
        [sys.executable, str(repo_root() / "scripts" / "show-release-campaigns.py"), "--help"],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--campaign" in completed.stdout
    assert "--json" in completed.stdout
