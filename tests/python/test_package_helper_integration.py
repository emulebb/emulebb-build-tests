from __future__ import annotations

from pathlib import Path


def test_package_helper_uses_packaged_powershell_script_names() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "package-helper-integration.py"
    text = script.read_text(encoding="utf-8")

    assert '"Register-aMuTorrent.ps1"' in text
    assert '"Register-Prowlarr.ps1"' in text
    assert '"Register-ArrStack.ps1"' in text
    assert '"register-amutorrent.ps1"' not in text
    assert '"register-prowlarr.ps1"' not in text
    assert '"register-arr-stack.ps1"' not in text


def test_package_helper_uses_local_rest_only_profile() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "package-helper-integration.py"
    text = script.read_text(encoding="utf-8")

    assert "rest_smoke.configure_webserver_profile(" in text
    assert "live_network=False" in text
