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
