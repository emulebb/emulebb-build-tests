from __future__ import annotations

from emule_test_harness import windows_vm_guest


def test_package_smoke_script_contains_guest_checks() -> None:
    script = windows_vm_guest.package_smoke_script()

    assert "Expand-Archive" in script
    assert "emulebb.exe" in script
    assert "--generate-webserver-cert" in script
    assert "first-run-rest-status" in script
    assert "Restore-VMSnapshot" in script
    assert "[System.Diagnostics.Process]::Start" in script
    assert "UseShellExecute = $false" in script


def test_local_ed2k_transfer_script_is_minimal_transport_shim() -> None:
    script = windows_vm_guest.local_ed2k_transfer_script()

    assert "windows_vm_local_ed2k.py" in script
    assert "vm_guest_profiles.py" in script
    assert "Invoke-GuestPython" in script
    assert "guest python failed with exit code" in script
    assert "2>&1" in script
    assert "Copy-Item -ToSession" in script
    assert "Restore-VMSnapshot" in script
    assert "pythonRoot" not in script
    assert "Re-run vm-lab prepare" in script
    assert "/api/v1/shared-files" not in script
    assert "Get-FileHash" not in script
    assert "New-NetFirewallRule" not in script


def test_hideme_live_wire_script_uses_python_guest_runner_and_visible_vpn() -> None:
    script = windows_vm_guest.hideme_live_wire_script()

    assert "windows_vm_hideme_live.py" in script
    assert "vm_guest_profiles.py" in script
    assert "Start-HideMe" in script
    assert "New-ScheduledTaskAction" in script
    assert "assert-vpn-binding" in script
    assert "import-server-met" in script
    assert "connect-live-server" in script
    assert "--trigger-download" in script
    assert "Invoke-GuestPython" in script


def test_profile_smoke_script_uses_shared_python_runner() -> None:
    script = windows_vm_guest.profile_smoke_script()

    assert "windows_vm_profile_smoke.py" in script
    assert "vm_guest_profiles.py" in script
    assert "campaign_scenarios.py" in script
    assert "localSwarmHarnessPackagePath" in script
    assert "localSwarmScriptPaths" in script
    assert "--harness-root" in script
    assert "godzilla-local-swarm.py" not in script
    assert "--profile" in script
    assert "--swarm-tier" in script
    assert "fixtureSizeBytes" in script
    assert "Invoke-GuestPython" in script
    assert "PYTHONPATH" in script
    assert "@($guestHarnessRoot, $guestRoot)" in script
    assert "guest python produced invalid JSON" in script
    assert "Restore-VMSnapshot" in script
