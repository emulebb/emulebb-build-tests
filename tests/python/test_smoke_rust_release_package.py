from __future__ import annotations

from emule_test_harness.script_modules import load_script_module


smoke = load_script_module("smoke_rust_release_package", "smoke-rust-release-package.py")


def test_webui_asset_paths_accepts_rooted_history_routing_assets() -> None:
    html = '<script src="/assets/app.js"></script><link href="/assets/app.css">'

    assert smoke._webui_asset_paths(html) == ["/assets/app.js", "/assets/app.css"]


def test_webui_asset_paths_accepts_relative_assets() -> None:
    html = '<script src="./assets/app.js"></script>'

    assert smoke._webui_asset_paths(html) == ["/assets/app.js"]
