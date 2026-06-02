from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import windows_vm_host
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
    } <= script_names


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
