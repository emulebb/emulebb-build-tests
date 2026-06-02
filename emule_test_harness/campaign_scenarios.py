"""Shared local/VM campaign scenario contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


EXECUTION_MODES = ("local", "vm")
VM_LOCAL_SWARM_MODES = ("plan", "execute")
LOCAL_CAMPAIGN_TEST_NETWORK = "default"
LOCAL_CAMPAIGN_ALLOWED_NETWORK_SCOPES = ("offline", "lan")
LOCAL_SWARM_CLIENT_PRODUCTS = ("emulebb", "amule", "tracing-harness")
LOCAL_SWARM_TIERS = (1, 2, 3)
DEFAULT_LOCAL_SWARM_TIER = 1
DEFAULT_RELEASE_VERSION = "0.7.3-rc.1"
LOCAL_SWARM_TIER_OPTIONS: dict[int, dict[str, object]] = {
    1: {
        "stage": "launch-scale",
        "total_client_count": 4,
        "peer_transfer_count": 24,
        "harness_transfer_count": 24,
        "emulebb_files": 80,
        "extra_emulebb_files": 8,
        "harness_files": 60,
        "amule_files": 20,
        "adverse_kill_cycles": 0,
        "adverse_kill_warmup_seconds": 0.0,
        "adverse_recovery_timeout_seconds": 180.0,
        "cpu_profile": False,
        "fail_fast": True,
    },
    2: {
        "stage": "launch-scale",
        "total_client_count": 10,
        "peer_transfer_count": 120,
        "harness_transfer_count": 120,
        "emulebb_files": 240,
        "extra_emulebb_files": 24,
        "harness_files": 180,
        "amule_files": 60,
        "adverse_kill_cycles": 0,
        "adverse_kill_warmup_seconds": 0.0,
        "adverse_recovery_timeout_seconds": 180.0,
        "cpu_profile": True,
        "fail_fast": False,
    },
    3: {
        "stage": "full",
        "total_client_count": 18,
        "peer_transfer_count": 360,
        "harness_transfer_count": 360,
        "emulebb_files": 720,
        "extra_emulebb_files": 72,
        "harness_files": 480,
        "amule_files": 120,
        "adverse_kill_cycles": 2,
        "adverse_kill_warmup_seconds": 20.0,
        "adverse_recovery_timeout_seconds": 180.0,
        "cpu_profile": True,
        "fail_fast": False,
    },
}


@dataclass(frozen=True)
class CampaignScenarioSpec:
    """One reusable scenario with local and VM execution surfaces."""

    key: str
    title: str
    release_phase: str
    network_scope: str
    local_profile: str
    local_suites: tuple[str, ...]
    vm_profile: str
    scenario_id: str
    uses_local_swarm: bool = False
    live_wire: bool = False
    local_test_network: str = LOCAL_CAMPAIGN_TEST_NETWORK
    local_allowed_network_scopes: tuple[str, ...] = LOCAL_CAMPAIGN_ALLOWED_NETWORK_SCOPES

    def as_matrix_row(self) -> dict[str, Any]:
        """Returns the JSON shape used by audits and release tooling tests."""

        return {
            "key": self.key,
            "title": self.title,
            "releasePhase": self.release_phase,
            "networkScope": self.network_scope,
            "executionModes": list(EXECUTION_MODES),
            "localTestNetwork": self.local_test_network,
            "localAllowedNetworkScopes": list(self.local_allowed_network_scopes),
            "localProfile": self.local_profile,
            "localSuites": list(self.local_suites),
            "vmProfile": self.vm_profile,
            "scenarioId": self.scenario_id,
            "usesLocalSwarm": self.uses_local_swarm,
            "liveWire": self.live_wire,
            "localCommand": self.command_for_mode("local"),
            "vmCommand": self.command_for_mode("vm"),
            "vmPlanCommand": self.command_for_mode("vm", local_swarm_mode="plan"),
            "vmExecuteCommand": self.command_for_mode("vm", local_swarm_mode="execute"),
        }

    def command_for_mode(
        self,
        mode: str,
        *,
        release_version: str = DEFAULT_RELEASE_VERSION,
        swarm_tier: int = DEFAULT_LOCAL_SWARM_TIER,
        local_swarm_mode: str = "plan",
    ) -> str:
        """Returns the emule_workspace command that runs this scenario in one mode."""

        if mode not in EXECUTION_MODES:
            raise ValueError(f"Unsupported campaign scenario execution mode: {mode!r}.")
        if swarm_tier not in LOCAL_SWARM_TIERS:
            raise ValueError(f"Unsupported campaign scenario swarm tier: {swarm_tier!r}.")
        if local_swarm_mode not in VM_LOCAL_SWARM_MODES:
            raise ValueError(f"Unsupported campaign scenario VM local swarm mode: {local_swarm_mode!r}.")
        command = f"python -m emule_workspace test campaign-scenario --scenario {self.scenario_id} --mode {mode}"
        if mode == "vm":
            command = f"{command} --release-version {release_version} --skip-build --swarm-tier {swarm_tier}"
            if local_swarm_mode == "plan":
                command = f"{command} --dry-run"
            else:
                command = f"{command} --local-swarm-mode {local_swarm_mode}"
            return command
        return f"{command} --swarm-tier {swarm_tier}"


REUSABLE_CAMPAIGN_SCENARIOS = (
    CampaignScenarioSpec(
        key="installer-controller-surface",
        title="Installer-backed controller surface",
        release_phase="controller-surface",
        network_scope="lan",
        local_profile="installer-controller-surface",
        local_suites=(
            "command-line-smoke",
            "amutorrent-browser-smoke",
            "package-helper-integration",
        ),
        vm_profile="installer-controller-surface-vm",
        scenario_id="emulebb.flow.controller.installer-swarm.v1",
        uses_local_swarm=True,
    ),
    CampaignScenarioSpec(
        key="amutorrent-clean-startup",
        title="aMuTorrent clean startup",
        release_phase="stabilization-stress",
        network_scope="lan",
        local_profile="multi-client-p2p",
        local_suites=("amutorrent-local-ed2k-ui-live",),
        vm_profile="amutorrent-clean-startup-vm",
        scenario_id="emulebb.flow.amutorrent.clean-startup.swarm.v1",
        uses_local_swarm=True,
    ),
    CampaignScenarioSpec(
        key="amutorrent-emulebb-ui",
        title="aMuTorrent eMuleBB UI",
        release_phase="stabilization-stress",
        network_scope="lan",
        local_profile="multi-client-p2p",
        local_suites=("amutorrent-local-ed2k-ui-live",),
        vm_profile="amutorrent-emulebb-ui-vm",
        scenario_id="emulebb.flow.amutorrent.emulebb-ui.swarm.v1",
        uses_local_swarm=True,
    ),
    CampaignScenarioSpec(
        key="prowlarr-controller-handoff",
        title="Prowlarr controller handoff",
        release_phase="controller-surface",
        network_scope="lan",
        local_profile="controller-surface",
        local_suites=("package-helper-integration",),
        vm_profile="prowlarr-controller-handoff-vm",
        scenario_id="emulebb.flow.arr.prowlarr-handoff.swarm.v1",
        uses_local_swarm=True,
    ),
    CampaignScenarioSpec(
        key="search-ui-local-swarm",
        title="Search UI local swarm",
        release_phase="ui-resource-depth",
        network_scope="lan",
        local_profile="multi-client-p2p",
        local_suites=("local-ed2k-search-soak", "local-kad-swarm"),
        vm_profile="search-ui-local-swarm-vm",
        scenario_id="emulebb.flow.ui.search.local-swarm.v1",
        uses_local_swarm=True,
    ),
)
REUSABLE_CAMPAIGN_SCENARIO_BY_KEY = {spec.key: spec for spec in REUSABLE_CAMPAIGN_SCENARIOS}
REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE = {spec.vm_profile: spec for spec in REUSABLE_CAMPAIGN_SCENARIOS}
REUSABLE_CAMPAIGN_SCENARIO_BY_SCENARIO_ID = {spec.scenario_id: spec for spec in REUSABLE_CAMPAIGN_SCENARIOS}


def build_campaign_scenario_matrix() -> dict[str, Any]:
    """Returns reusable scenarios that must support both local and VM execution."""

    return {
        "schema": "emulebb-build-tests.campaign-scenario-matrix.v1",
        "executionModes": list(EXECUTION_MODES),
        "vmLocalSwarmModes": list(VM_LOCAL_SWARM_MODES),
        "localSwarm": {
            "clientProducts": list(LOCAL_SWARM_CLIENT_PRODUCTS),
            "tiers": list(LOCAL_SWARM_TIERS),
            "defaultTier": DEFAULT_LOCAL_SWARM_TIER,
            "tierOptions": LOCAL_SWARM_TIER_OPTIONS,
            "ed2kServerTarget": "win10",
            "vmTargets": ["win10", "win11"],
        },
        "scenarioCount": len(REUSABLE_CAMPAIGN_SCENARIOS),
        "scenarios": [spec.as_matrix_row() for spec in REUSABLE_CAMPAIGN_SCENARIOS],
    }
