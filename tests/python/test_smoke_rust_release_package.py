from __future__ import annotations

import os
import stat

from emule_test_harness.script_modules import load_script_module


smoke = load_script_module("smoke_rust_release_package", "smoke-rust-release-package.py")


def test_api_key_meets_daemon_production_validation() -> None:
    assert len(smoke.API_KEY.encode("utf-8")) >= 32
    assert smoke.API_KEY.isascii()
    assert smoke.API_KEY.isprintable()
    assert not any(character.isspace() for character in smoke.API_KEY)


def test_write_profile_uses_api_key_and_private_permissions(tmp_path) -> None:
    smoke._write_profile(tmp_path, 4711)

    settings = tmp_path / "emulebb-rust-settings.toml"
    assert settings.read_text(encoding="utf-8") == (
        '[rest]\nbindAddr = "127.0.0.1:4711"\napiKey = "native-package-smoke-secret-0001"\n'
    )
    if os.name == "posix":
        assert stat.S_IMODE(settings.stat().st_mode) == 0o600


def test_webui_asset_paths_accepts_rooted_history_routing_assets() -> None:
    html = '<script src="/assets/app.js"></script><link href="/assets/app.css">'

    assert smoke._webui_asset_paths(html) == ["/assets/app.js", "/assets/app.css"]


def test_webui_asset_paths_accepts_relative_assets() -> None:
    html = '<script src="./assets/app.js"></script>'

    assert smoke._webui_asset_paths(html) == ["/assets/app.js"]
