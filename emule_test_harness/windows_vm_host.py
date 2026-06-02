"""Host-side contracts for Windows VM harness orchestration."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

try:
    from emule_test_harness import live_e2e_suite
    from emule_test_harness.campaign_scenarios import REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE
except ModuleNotFoundError:
    import live_e2e_suite  # type: ignore[no-redef]
    from campaign_scenarios import REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE


LOCAL_SWARM_VM_PROFILES = tuple(REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE)
GUEST_SCRIPT_FACTORIES = {
    "package-smoke": "package_smoke_script",
    "local-ed2k-transfer": "local_ed2k_transfer_script",
    "hideme-live-wire": "hideme_live_wire_script",
    "rest-smoke-stress": "profile_smoke_script",
    "crash-dump-smoke": "profile_smoke_script",
    "cpu-heavy-quick": "profile_smoke_script",
    "resource-ui-smoke": "profile_smoke_script",
    "release-expanded-ui": "profile_smoke_script",
    "package-helper-install": "profile_smoke_script",
    "vhd-profile-isolation": "profile_smoke_script",
    "shared-cache-filesystem": "profile_smoke_script",
    "diagnostics-local-dumps": "profile_smoke_script",
    "ui-shared-files-depth": "profile_smoke_script",
    **{profile: "profile_smoke_script" for profile in LOCAL_SWARM_VM_PROFILES},
}
GUEST_RUNNER_FILES = {
    "local-ed2k-transfer": "windows_vm_local_ed2k.py",
    "hideme-live-wire": "windows_vm_hideme_live.py",
    "rest-smoke-stress": "windows_vm_profile_smoke.py",
    "crash-dump-smoke": "windows_vm_profile_smoke.py",
    "cpu-heavy-quick": "windows_vm_profile_smoke.py",
    "resource-ui-smoke": "windows_vm_profile_smoke.py",
    "release-expanded-ui": "windows_vm_profile_smoke.py",
    "package-helper-install": "windows_vm_profile_smoke.py",
    "vhd-profile-isolation": "windows_vm_profile_smoke.py",
    "shared-cache-filesystem": "windows_vm_profile_smoke.py",
    "diagnostics-local-dumps": "windows_vm_profile_smoke.py",
    "ui-shared-files-depth": "windows_vm_profile_smoke.py",
    **{profile: "windows_vm_profile_smoke.py" for profile in LOCAL_SWARM_VM_PROFILES},
}
PROFILE_HELPER_FILE = "vm_guest_profiles.py"
LIVE_E2E_SCRIPT_BY_SUITE = {spec.name: spec.script_name for spec in live_e2e_suite.SUITE_SPECS}


def _reusable_campaign_suite_names() -> tuple[str, ...]:
    names: list[str] = []
    for spec in REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE.values():
        names.extend(spec.local_suites)
        if spec.uses_local_swarm:
            names.append("godzilla-local-swarm")
    return tuple(dict.fromkeys(names))


LOCAL_SWARM_SCRIPT_FILES = tuple(
    LIVE_E2E_SCRIPT_BY_SUITE[suite_name]
    for suite_name in _reusable_campaign_suite_names()
)
LOCAL_SWARM_SUPPORT_SCRIPT_FILES = (
    "admin-volume-cleanup-audit.py",
    "amutorrent-browser-smoke.py",
    "amutorrent-clean-startup.py",
    "amutorrent-emulebb-ui-live.py",
    "amutorrent-interactive-session.py",
    "amutorrent-resilience-live.py",
    "emule-live-profile-common.py",
    "harness-cli-common.py",
    "rest-api-smoke.py",
)
GODZILLA_LOCAL_SWARM_HELPER_SCRIPT_FILES = (
    "deterministic-two-client-transfer.py",
    "deterministic-amule-transfer.py",
    "local-ed2k-protocol-combinations.py",
)
LOCAL_SWARM_PAYLOAD_SCRIPT_FILES = tuple(
    dict.fromkeys(
        (
            *LOCAL_SWARM_SCRIPT_FILES,
            *LOCAL_SWARM_SUPPORT_SCRIPT_FILES,
            *GODZILLA_LOCAL_SWARM_HELPER_SCRIPT_FILES,
        )
    )
)
LOCAL_ED2K_TARGET_ENDPOINTS = {
    "win10": {"target": "win10", "tcpPort": 4662, "udpPort": 4672, "restPort": 4711},
    "win11": {"target": "win11", "tcpPort": 4762, "udpPort": 4772, "restPort": 4711},
}
HIDEME_LIVE_TARGET_ENDPOINTS = {
    "win10": {"target": "win10", "tcpPort": 4862, "udpPort": 4872, "restPort": 4711},
    "win11": {"target": "win11", "tcpPort": 4962, "udpPort": 4972, "restPort": 4711},
}


def load_guest_script(tests_repo_root: str | Path, profile_name: str) -> str:
    """Returns the PowerShell Direct guest script for a Windows VM profile."""

    factory_name = GUEST_SCRIPT_FACTORIES.get(profile_name)
    if factory_name is None:
        raise RuntimeError(f"Unsupported Windows VM guest script profile: {profile_name!r}.")
    module = _load_windows_vm_guest_module(Path(tests_repo_root))
    script_factory = getattr(module, factory_name, None)
    if not callable(script_factory):
        raise RuntimeError(f"Windows VM guest harness module is missing {factory_name}().")
    script = script_factory()
    if not isinstance(script, str) or not script.strip():
        raise RuntimeError(f"Windows VM guest harness {factory_name}() returned an empty script.")
    return script


def guest_runner_path(tests_repo_root: str | Path, profile_name: str) -> Path:
    """Returns the guest Python runner copied for a Windows VM profile."""

    file_name = GUEST_RUNNER_FILES.get(profile_name)
    if file_name is None:
        raise RuntimeError(f"Windows VM profile has no guest runner: {profile_name!r}.")
    return Path(tests_repo_root) / "emule_test_harness" / file_name


def profile_helper_path(tests_repo_root: str | Path) -> Path:
    """Returns the shared guest profile helper path."""

    return Path(tests_repo_root) / "emule_test_harness" / PROFILE_HELPER_FILE


def local_swarm_payload_paths(tests_repo_root: str | Path) -> dict[str, Any]:
    """Returns host paths copied into guests for reusable local swarm profiles."""

    root = Path(tests_repo_root)
    return {
        "harnessPackage": root / "emule_test_harness",
        "manifests": root / "manifests",
        "scripts": [root / "scripts" / name for name in LOCAL_SWARM_PAYLOAD_SCRIPT_FILES],
    }


def build_local_ed2k_target_payloads(vm_names: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Returns stable per-target ports for the local ED2K VM scenario."""

    return _target_payloads(LOCAL_ED2K_TARGET_ENDPOINTS, vm_names)


def build_hideme_live_target_payloads(vm_names: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Returns stable per-target ports for the hide.me live-wire VM scenario."""

    return _target_payloads(HIDEME_LIVE_TARGET_ENDPOINTS, vm_names)


def _target_payloads(
    endpoints: dict[str, dict[str, int | str]],
    vm_names: dict[str, str],
) -> dict[str, dict[str, Any]]:
    missing = sorted(set(endpoints) - set(vm_names))
    if missing:
        raise RuntimeError(f"Windows VM target payloads are missing VM name(s): {', '.join(missing)}.")
    return {
        key: {**endpoint, "vmName": vm_names[key]}
        for key, endpoint in endpoints.items()
    }


def _load_windows_vm_guest_module(tests_repo_root: Path) -> ModuleType:
    module_path = tests_repo_root / "emule_test_harness" / "windows_vm_guest.py"
    if not module_path.is_file():
        raise RuntimeError(f"Windows VM guest harness module is missing: {module_path}")
    spec = importlib.util.spec_from_file_location("emulebb_windows_vm_guest", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load Windows VM guest harness module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
