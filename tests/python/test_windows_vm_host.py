from __future__ import annotations

from pathlib import Path
import re

import pytest

from emule_test_harness import live_e2e_suite, windows_vm_host
from emule_test_harness.campaign_scenarios import REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE


def test_guest_scripts_are_loaded_from_harness() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    assert "Restore-VMSnapshot" in windows_vm_host.load_guest_script(repo_root, "package-smoke")
    assert "windows_vm_local_ed2k.py" in windows_vm_host.load_guest_script(repo_root, "local-ed2k-transfer")
    assert "windows_vm_hideme_live.py" in windows_vm_host.load_guest_script(repo_root, "hideme-live-wire")


def test_guest_runner_paths_are_harness_owned() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    assert windows_vm_host.guest_runner_path(repo_root, "local-ed2k-transfer") == (
        repo_root / "emule_test_harness" / "windows_vm_local_ed2k.py"
    )
    assert windows_vm_host.guest_runner_path(repo_root, "hideme-live-wire") == (
        repo_root / "emule_test_harness" / "windows_vm_hideme_live.py"
    )
    assert windows_vm_host.profile_helper_path(repo_root) == (
        repo_root / "emule_test_harness" / "vm_guest_profiles.py"
    )


def test_reusable_campaign_vm_profiles_use_shared_contract_smoke_runner() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    for profile in REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE:
        assert "windows_vm_profile_smoke.py" in windows_vm_host.load_guest_script(repo_root, profile)
        assert windows_vm_host.guest_runner_path(repo_root, profile) == (
            repo_root / "emule_test_harness" / "windows_vm_profile_smoke.py"
        )


def test_local_swarm_payload_paths_are_harness_owned() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    payload = windows_vm_host.local_swarm_payload_paths(repo_root)

    assert payload["harnessPackage"] == repo_root / "emule_test_harness"
    script_names = {path.name for path in payload["scripts"]}
    assert {
        "godzilla-local-swarm.py",
        "local-ed2k-search-soak.py",
        "local-kad-swarm.py",
        "amutorrent-local-ed2k-ui-live.py",
        "package-helper-integration.py",
        "rest-api-smoke.py",
        "harness-cli-common.py",
        "deterministic-two-client-transfer.py",
        "deterministic-amule-transfer.py",
        "local-ed2k-protocol-combinations.py",
    } <= script_names


def test_local_swarm_payload_scripts_cover_reusable_campaign_suites() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script_by_suite = {spec.name: spec.script_name for spec in live_e2e_suite.SUITE_SPECS}
    payload_scripts = set(windows_vm_host.LOCAL_SWARM_PAYLOAD_SCRIPT_FILES)

    for scenario in REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE.values():
        suite_names = list(scenario.local_suites)
        if scenario.uses_local_swarm:
            suite_names.append("godzilla-local-swarm")
        for suite_name in suite_names:
            script_name = script_by_suite[suite_name]
            assert script_name in payload_scripts
            assert (repo_root / "scripts" / script_name).is_file()


def test_local_swarm_payload_scripts_include_sibling_helpers() -> None:
    payload_scripts = set(windows_vm_host.LOCAL_SWARM_PAYLOAD_SCRIPT_FILES)

    assert set(windows_vm_host.LOCAL_SWARM_SCRIPT_FILES) <= payload_scripts
    assert set(windows_vm_host.LOCAL_SWARM_SUPPORT_SCRIPT_FILES) <= payload_scripts
    assert set(windows_vm_host.GODZILLA_LOCAL_SWARM_HELPER_SCRIPT_FILES) <= payload_scripts


def test_local_swarm_payload_scripts_cover_recursive_sibling_imports() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    payload_scripts = set(windows_vm_host.LOCAL_SWARM_PAYLOAD_SCRIPT_FILES)
    pending = list(payload_scripts)
    checked: set[str] = set()
    imported: set[str] = set()
    pattern = re.compile(r'load_local_module\([^)]*,\s*"([^"]+\.py)"\)')

    while pending:
        script_name = pending.pop()
        if script_name in checked:
            continue
        checked.add(script_name)
        source_path = repo_root / "scripts" / script_name
        assert source_path.is_file()
        for imported_script in pattern.findall(source_path.read_text(encoding="utf-8")):
            imported.add(imported_script)
            if imported_script not in checked:
                pending.append(imported_script)

    assert imported <= payload_scripts


def test_endpoint_payloads_materialize_vm_names() -> None:
    vm_names = {"win10": "emulebb-win10-test", "win11": "emulebb-win11-test"}

    local_ed2k = windows_vm_host.build_local_ed2k_target_payloads(vm_names)
    hideme_live = windows_vm_host.build_hideme_live_target_payloads(vm_names)

    assert local_ed2k["win10"] == {
        "target": "win10",
        "vmName": "emulebb-win10-test",
        "tcpPort": 4662,
        "udpPort": 4672,
        "restPort": 4711,
    }
    assert local_ed2k["win11"]["tcpPort"] == 4762
    assert hideme_live["win10"]["tcpPort"] == 4862
    assert hideme_live["win11"]["tcpPort"] == 4962


def test_endpoint_payloads_require_all_vm_names() -> None:
    with pytest.raises(RuntimeError, match="win11"):
        windows_vm_host.build_local_ed2k_target_payloads({"win10": "emulebb-win10-test"})
