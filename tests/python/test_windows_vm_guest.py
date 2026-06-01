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
