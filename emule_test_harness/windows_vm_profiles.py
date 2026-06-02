"""Windows VM test profile catalog owned by the harness."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

WINDOWS_VM_SUITE_NAME = "windows-vm"
WINDOWS_VM_RESULT_FILE_NAME = "windows-vm-result.json"
WINDOWS_VM_SUMMARY_FILE_NAME = "windows-vm-summary.json"
SUPPORTED_TARGETS = ("win10", "win11")


@dataclass(frozen=True)
class WindowsVmProfileSpec:
    """One supported Windows VM test profile."""

    name: str
    title: str
    network_scope: str
    release_phase: str
    required_targets: tuple[str, ...]
    result_file_name: str
    scenario_id: str


WINDOWS_VM_PROFILE_SPECS = (
    WindowsVmProfileSpec(
        name="package-smoke",
        title="Windows VM package smoke",
        network_scope="offline",
        release_phase="packaging-provenance",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.package-smoke.release.v1",
    ),
    WindowsVmProfileSpec(
        name="local-ed2k-transfer",
        title="Windows VM local eD2K transfer",
        network_scope="lan",
        release_phase="protocol-parity",
        required_targets=SUPPORTED_TARGETS,
        result_file_name="local-ed2k-transfer-result.json",
        scenario_id="emulebb.flow.windows-vm.local-ed2k.transfer.v1",
    ),
    WindowsVmProfileSpec(
        name="hideme-live-wire",
        title="Windows VM hide.me live-wire",
        network_scope="vpn",
        release_phase="live-wire-release",
        required_targets=SUPPORTED_TARGETS,
        result_file_name="hideme-live-wire-result.json",
        scenario_id="emulebb.flow.windows-vm.hideme.live-wire.v1",
    ),
    WindowsVmProfileSpec(
        name="rest-smoke-stress",
        title="Windows VM REST smoke/stress",
        network_scope="offline",
        release_phase="controller-surface",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.rest.smoke-stress.v1",
    ),
    WindowsVmProfileSpec(
        name="crash-dump-smoke",
        title="Windows VM crash/dump smoke",
        network_scope="offline",
        release_phase="stabilization-stress",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.crash-dump.smoke.v1",
    ),
    WindowsVmProfileSpec(
        name="cpu-heavy-quick",
        title="Windows VM CPU-heavy quick smoke",
        network_scope="offline",
        release_phase="stabilization-stress",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.cpu-heavy.quick.v1",
    ),
    WindowsVmProfileSpec(
        name="resource-ui-smoke",
        title="Windows VM resource UI smoke",
        network_scope="offline",
        release_phase="ui-resource-depth",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.resource-ui.smoke.v1",
    ),
    WindowsVmProfileSpec(
        name="release-expanded-ui",
        title="Windows VM release-expanded UI smoke",
        network_scope="offline",
        release_phase="live-wire-release",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.release-expanded.ui.v1",
    ),
    WindowsVmProfileSpec(
        name="package-helper-install",
        title="Windows VM package helper install smoke",
        network_scope="offline",
        release_phase="packaging-provenance",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.package-helper.install.v1",
    ),
    WindowsVmProfileSpec(
        name="vhd-profile-isolation",
        title="Windows VM VHD profile isolation smoke",
        network_scope="offline",
        release_phase="stabilization-stress",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.vhd-profile.isolation.v1",
    ),
    WindowsVmProfileSpec(
        name="shared-cache-filesystem",
        title="Windows VM shared-cache filesystem smoke",
        network_scope="offline",
        release_phase="ui-resource-depth",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.shared-cache.filesystem.v1",
    ),
    WindowsVmProfileSpec(
        name="diagnostics-local-dumps",
        title="Windows VM diagnostics LocalDumps smoke",
        network_scope="offline",
        release_phase="stabilization-stress",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.diagnostics.local-dumps.v1",
    ),
    WindowsVmProfileSpec(
        name="ui-shared-files-depth",
        title="Windows VM UI/shared-files depth smoke",
        network_scope="offline",
        release_phase="ui-resource-depth",
        required_targets=SUPPORTED_TARGETS,
        result_file_name=WINDOWS_VM_RESULT_FILE_NAME,
        scenario_id="emulebb.flow.windows-vm.ui-shared-files.depth.v1",
    ),
)
WINDOWS_VM_PROFILE_BY_NAME = {spec.name: spec for spec in WINDOWS_VM_PROFILE_SPECS}
WINDOWS_VM_PROFILE_BY_SCENARIO_ID = {spec.scenario_id: spec for spec in WINDOWS_VM_PROFILE_SPECS}
SUPPORTED_TEST_PROFILES = tuple(spec.name for spec in WINDOWS_VM_PROFILE_SPECS)
LOCAL_ED2K_REQUIRED_TARGETS = WINDOWS_VM_PROFILE_BY_NAME["local-ed2k-transfer"].required_targets
HIDEME_LIVE_REQUIRED_TARGETS = WINDOWS_VM_PROFILE_BY_NAME["hideme-live-wire"].required_targets


def build_windows_vm_profile_matrix() -> dict[str, Any]:
    """Returns the supported Windows VM profile registry for audits and docs."""

    return {
        "schema": "emulebb-build-tests.windows-vm-profile-matrix.v1",
        "suite": WINDOWS_VM_SUITE_NAME,
        "profileCount": len(WINDOWS_VM_PROFILE_SPECS),
        "profiles": [
            {
                "name": spec.name,
                "title": spec.title,
                "networkScope": spec.network_scope,
                "releasePhase": spec.release_phase,
                "requiredTargets": list(spec.required_targets),
                "resultFileName": spec.result_file_name,
                "scenarioId": spec.scenario_id,
            }
            for spec in WINDOWS_VM_PROFILE_SPECS
        ],
    }
