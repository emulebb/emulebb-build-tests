"""Shared local/VM campaign scenario contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


EXECUTION_MODES = ("local", "vm")
LOCAL_SWARM_CLIENT_PRODUCTS = ("emulebb", "amule", "tracing-harness")
LOCAL_SWARM_TIERS = (1, 2, 3)
DEFAULT_LOCAL_SWARM_TIER = 1
DEFAULT_RELEASE_VERSION = "0.7.3-rc.1"


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

    def as_matrix_row(self) -> dict[str, Any]:
        """Returns the JSON shape used by audits and release tooling tests."""

        return {
            "key": self.key,
            "title": self.title,
            "releasePhase": self.release_phase,
            "networkScope": self.network_scope,
            "executionModes": list(EXECUTION_MODES),
            "localProfile": self.local_profile,
            "localSuites": list(self.local_suites),
            "vmProfile": self.vm_profile,
            "scenarioId": self.scenario_id,
            "usesLocalSwarm": self.uses_local_swarm,
            "liveWire": self.live_wire,
            "localCommand": self.command_for_mode("local"),
            "vmCommand": self.command_for_mode("vm"),
        }

    def command_for_mode(self, mode: str, *, release_version: str = DEFAULT_RELEASE_VERSION) -> str:
        """Returns the emule_workspace command that runs this scenario in one mode."""

        if mode not in EXECUTION_MODES:
            raise ValueError(f"Unsupported campaign scenario execution mode: {mode!r}.")
        command = f"python -m emule_workspace test campaign-scenario --scenario {self.scenario_id} --mode {mode}"
        if mode == "vm":
            return (
                f"{command} --release-version {release_version} "
                f"--skip-build --swarm-tier {DEFAULT_LOCAL_SWARM_TIER}"
            )
        return f"{command} --swarm-tier {DEFAULT_LOCAL_SWARM_TIER}"


REUSABLE_CAMPAIGN_SCENARIOS = (
    CampaignScenarioSpec(
        key="installer-controller-surface",
        title="Installer-backed controller surface",
        release_phase="controller-surface",
        network_scope="lan",
        local_profile="installer-controller-surface",
        local_suites=(
            "command-line-smoke",
            "rest-api",
            "prowlarr-emulebb",
            "amutorrent-browser-smoke",
            "live-process-monitor",
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
        local_suites=("prowlarr-emulebb",),
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
        "localSwarm": {
            "clientProducts": list(LOCAL_SWARM_CLIENT_PRODUCTS),
            "tiers": list(LOCAL_SWARM_TIERS),
            "defaultTier": DEFAULT_LOCAL_SWARM_TIER,
            "ed2kServerTarget": "win10",
            "vmTargets": ["win10", "win11"],
        },
        "scenarioCount": len(REUSABLE_CAMPAIGN_SCENARIOS),
        "scenarios": [spec.as_matrix_row() for spec in REUSABLE_CAMPAIGN_SCENARIOS],
    }
