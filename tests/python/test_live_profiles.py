from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import live_profile_seed, live_profiles
from emule_test_harness.ini import UTF16_LE_BOM, write_utf16_ini_text


def write_valid_seed(root: Path) -> Path:
    """Writes the minimal live-profile seed expected by the profile builder."""

    config_dir = root / "seed" / "config"
    config_dir.mkdir(parents=True)
    preferences_text = "[eMule]\n" + "\n".join(f"{key}=1" for key in live_profile_seed.REQUIRED_SEED_KEYS) + "\n"
    write_utf16_ini_text(config_dir / "preferences.ini", preferences_text)
    (config_dir / "preferences.dat").write_bytes(b"prefs")
    (config_dir / "server.met").write_bytes(b"servers")
    (config_dir / "nodes.dat").write_bytes(b"nodes")
    return config_dir


def test_build_profile_base_creates_fresh_isolated_profile(tmp_path: Path) -> None:
    seed_config_dir = write_valid_seed(tmp_path)
    artifacts_dir = tmp_path / "artifacts"
    shared_dir = live_profiles.win_path(tmp_path / "shared", trailing_slash=True)

    profile = live_profiles.build_profile_base(
        live_profiles.ProfileBuildSpec(
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            shared_dirs=[shared_dir],
            scenario_id="fixture-three-files",
        )
    )

    config_dir = Path(profile["config_dir"])
    preferences_path = config_dir / "preferences.ini"
    assert preferences_path.read_bytes().startswith(UTF16_LE_BOM)
    text = live_profiles.read_ini_text(preferences_path)
    scenario_dir = artifacts_dir / "profiles" / "fixture-three-files"
    assert profile["scenario_id"] == "fixture-three-files"
    assert profile["scenario_artifacts_dir"] == scenario_dir
    assert profile["profile_base"] == scenario_dir / "profile-base"
    assert f"IncomingDir={live_profiles.win_path(scenario_dir / 'incoming', trailing_slash=True)}" in text
    assert f"TempDir={live_profiles.win_path(scenario_dir / 'temp', trailing_slash=True)}" in text
    assert f"TempDirs={live_profiles.win_path(scenario_dir / 'temp', trailing_slash=True)}" in text
    assert "BindInterface=hide.me" in text
    assert "BindAddr=" in text
    assert "EnableUPnP=1" in text
    assert (config_dir / "preferences.dat").read_bytes() != b"prefs"
    assert live_profiles.read_ini_text(config_dir / "shareddir.dat") == shared_dir + "\r\n"
    assert profile["startup_profile_path"] == config_dir / live_profiles.STARTUP_PROFILE_TRACE_FILE_NAME


def test_scenario_id_is_sanitized_for_profile_paths(tmp_path: Path) -> None:
    seed_config_dir = write_valid_seed(tmp_path)

    profile = live_profiles.prepare_scenario_profile(
        seed_config_dir=seed_config_dir,
        artifacts_dir=tmp_path / "artifacts",
        shared_dirs=[],
        scenario_id=" ar AE / modal ",
    )

    assert profile["scenario_id"] == "ar-AE-modal"
    assert Path(profile["profile_base"]).parts[-3:] == ("profiles", "ar-AE-modal", "profile-base")


def test_empty_scenario_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="scenario id"):
        live_profiles.sanitize_profile_scenario_id(" /// ")


def test_apply_live_network_profile_sets_bind_interface_and_upnp(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(preferences_path, "[eMule]\nBindAddr=127.0.0.1\n[UPnP]\nEnableUPnP=0\n")

    live_profiles.apply_live_network_profile(config_dir, live_profiles.LiveNetworkProfileSpec())

    text = live_profiles.read_ini_text(preferences_path)
    assert "BindInterface=hide.me" in text
    assert "BindAddr=hide.me" not in text
    assert "BindAddr=" in text
    assert "BlockNetworkWhenBindUnavailableAtStartup=1" in text
    assert "EnableUPnP=1" in text
    assert "CloseUPnPOnExit=0" in text
    assert "127.0.0.1" not in text


def test_apply_live_network_profile_rejects_empty_interface(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\nNick=CodexE2E\n")

    with pytest.raises(ValueError, match="must not be empty"):
        live_profiles.apply_live_network_profile(config_dir, live_profiles.LiveNetworkProfileSpec(" "))


def test_apply_minimized_to_tray_startup_sets_tray_preferences(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(
        preferences_path,
        "[eMule]\nStartupMinimized=0\nMinToTray=0\nMinToTray_Aero=0\nAlwaysShowTrayIcon=0\n",
    )

    live_profiles.apply_minimized_to_tray_startup(config_dir)

    text = live_profiles.read_ini_text(preferences_path)
    assert "StartupMinimized=1" in text
    assert "MinToTray=1" in text
    assert "MinToTray_Aero=1" in text
    assert "AlwaysShowTrayIcon=1" in text


def test_apply_webserver_profile_writes_typed_rest_overlay(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(preferences_path, "[eMule]\nConfirmExit=1\n[WebServer]\nEnabled=0\n")
    app_exe = tmp_path / "app" / "eMule-main" / "srchybrid" / "x64" / "Release" / "emule.exe"

    live_profiles.apply_webserver_profile(
        config_dir,
        live_profiles.WebServerProfileSpec(
            app_exe=app_exe,
            api_key="api-key",
            port=4711,
            use_gzip=False,
            allow_admin_high_level_func=False,
            max_file_upload_size_mb=5,
            allowed_ips="127.0.0.1",
        ),
    )

    text = live_profiles.read_ini_text(preferences_path)
    expected_template = str(app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl")
    emule_section = text.split("[WebServer]", 1)[0]
    assert emule_section.count("WebTemplateFile=") == 1
    assert f"WebTemplateFile={expected_template}" in emule_section
    assert "ApiKey=api-key" in text
    assert "BindAddr=127.0.0.1" in text
    assert "Port=4711" in text
    assert "Enabled=1" in text
    assert "UseGzip=0" in text
    assert "AllowAdminHiLevelFunc=0" in text
    assert "EnableDiagnosticRestEndpoints=0" in text
    assert "MaxFileUploadSizeMB=5" in text
    assert "AllowedIPs=127.0.0.1" in text
