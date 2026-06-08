from __future__ import annotations

import struct
from pathlib import Path

import pytest

from emule_test_harness import live_profile_seed, live_profiles
from emule_test_harness.ini import UTF16_LE_BOM, write_utf16_ini_text


def section_text(text: str, section: str) -> str:
    """Returns the body for one simple INI section."""

    marker = f"[{section}]"
    tail = text.split(marker, 1)[1]
    return tail.split("\n[", 1)[0]


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


def read_preferences_dat_user_hash(path: Path) -> bytes:
    """Returns the stored eMule userhash from a harness preferences.dat file."""

    return struct.unpack("<B16s", path.read_bytes()[:17])[1]


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
    emule_section = section_text(text, "eMule")
    upnp_section = section_text(text, "UPnP")
    assert profile["scenario_id"] == "fixture-three-files"
    assert profile["scenario_artifacts_dir"] == scenario_dir
    assert profile["profile_base"] == scenario_dir / "profile-base"
    assert f"IncomingDir={live_profiles.win_path(scenario_dir / 'incoming', trailing_slash=True)}" in text
    assert f"TempDir={live_profiles.win_path(scenario_dir / 'temp', trailing_slash=True)}" in text
    assert f"TempDirs={live_profiles.win_path(scenario_dir / 'temp', trailing_slash=True)}" in text
    assert "BindInterface=hide.me" in emule_section
    assert "BindAddr=" in emule_section
    assert "BindAddr=hide.me" not in emule_section
    assert "BlockNetworkWhenBindUnavailableAtStartup" not in emule_section
    assert "VpnGuardMode=Off" in emule_section
    assert "VpnGuardAllowedPublicIpCidrs=" in emule_section
    assert "EnableUPnP=1" in upnp_section
    assert (config_dir / "preferences.dat").read_bytes() != b"prefs"
    user_hash = read_preferences_dat_user_hash(config_dir / "preferences.dat")
    assert user_hash == live_profiles.deterministic_user_hash("fixture-three-files")
    assert user_hash[5] == 14
    assert user_hash[14] == 111
    assert live_profiles.read_ini_text(config_dir / "shareddir.dat") == shared_dir + "\r\n"
    assert profile["startup_diagnostics_path"] == scenario_dir / "profile-base" / "logs" / live_profiles.STARTUP_DIAGNOSTICS_TRACE_FILE_NAME


def test_build_profile_base_uses_distinct_stable_client_hashes(tmp_path: Path) -> None:
    seed_config_dir = write_valid_seed(tmp_path)

    first = live_profiles.build_profile_base(
        live_profiles.ProfileBuildSpec(
            seed_config_dir=seed_config_dir,
            artifacts_dir=tmp_path / "artifacts",
            shared_dirs=[],
            scenario_id="cl-emulebb-001",
        )
    )
    second = live_profiles.build_profile_base(
        live_profiles.ProfileBuildSpec(
            seed_config_dir=seed_config_dir,
            artifacts_dir=tmp_path / "artifacts",
            shared_dirs=[],
            scenario_id="cl-emulebb-extra-001",
        )
    )

    first_hash = read_preferences_dat_user_hash(Path(first["config_dir"]) / "preferences.dat")
    second_hash = read_preferences_dat_user_hash(Path(second["config_dir"]) / "preferences.dat")
    assert first_hash == live_profiles.deterministic_user_hash("cl-emulebb-001")
    assert second_hash == live_profiles.deterministic_user_hash("cl-emulebb-extra-001")
    assert first_hash != second_hash


def test_write_preferences_dat_rejects_wrong_sized_user_hash(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        live_profiles.write_preferences_dat(tmp_path / "preferences.dat", user_hash=b"short")


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
    write_utf16_ini_text(
        preferences_path,
        "[eMule]\nBindAddr=127.0.0.1\n[WebServer]\nBindAddr=127.0.0.1\n[UPnP]\nEnableUPnP=0\n",
    )

    live_profiles.apply_live_network_profile(
        config_dir,
        live_profiles.LiveNetworkProfileSpec(vpn_guard_allowed_public_ip_cidrs="8.8.8.8/32"),
    )

    text = live_profiles.read_ini_text(preferences_path)
    emule_section = section_text(text, "eMule")
    webserver_section = section_text(text, "WebServer")
    upnp_section = section_text(text, "UPnP")
    assert "BindInterface=hide.me" in emule_section
    assert "BindAddr=hide.me" not in emule_section
    assert "BindAddr=" in emule_section
    assert "BlockNetworkWhenBindUnavailableAtStartup" not in emule_section
    assert "VpnGuardMode=Block" in emule_section
    assert "VpnGuardAllowedPublicIpCidrs=8.8.8.8/32" in emule_section
    assert "EnableUPnP=1" in upnp_section
    assert "CloseUPnPOnExit=0" in text
    assert "127.0.0.1" not in emule_section
    assert "BindAddr=127.0.0.1" in webserver_section


def test_apply_live_network_profile_can_enable_vpn_guard_without_cidrs(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(preferences_path, "[eMule]\nBindAddr=127.0.0.1\n[UPnP]\nEnableUPnP=0\n")

    live_profiles.apply_live_network_profile(
        config_dir,
        live_profiles.LiveNetworkProfileSpec(vpn_guard_enabled=True),
    )

    emule_section = section_text(live_profiles.read_ini_text(preferences_path), "eMule")
    assert "BindInterface=hide.me" in emule_section
    assert "BindAddr=" in emule_section
    assert "VpnGuardMode=Block" in emule_section
    assert "VpnGuardAllowedPublicIpCidrs=" in emule_section


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


def test_apply_emule_preferences_updates_only_emule_section_duplicates(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(
        preferences_path,
        (
            "[eMule]\n"
            "FilterBadIPs=1\n"
            "Nick=old\n"
            "FilterBadIPs=1\n"
            "[WebServer]\n"
            "Nick=web\n"
        ),
    )

    live_profiles.apply_emule_preferences(config_dir, (("FilterBadIPs", "0"), ("Nick", "client1")))

    text = live_profiles.read_ini_text(preferences_path)
    emule_section = text.split("[WebServer]", 1)[0]
    webserver_section = text.split("[WebServer]", 1)[1]
    assert emule_section.count("FilterBadIPs=0") == 2
    assert "Nick=client1" in emule_section
    assert "FilterBadIPs=1" not in emule_section
    assert "Nick=web" in webserver_section


def test_materialize_private_harness_profile_writes_local_preferences(tmp_path: Path) -> None:
    seed_config_dir = write_valid_seed(tmp_path)
    profile_root = tmp_path / "private-profile"

    profile = live_profiles.materialize_private_harness_profile(
        live_profiles.PrivateHarnessProfileSpec(
            seed_config_dir=seed_config_dir,
            profile_root=profile_root,
            lan_bind_addr="127.0.0.1",
            tcp_port=33111,
            udp_port=33112,
            server_udp_port=33113,
            web_port=33114,
            enable_kademlia=True,
            enable_ed2k=False,
            shared_dirs=("C:\\share\\",),
        )
    )

    config_dir = Path(profile["config_dir"])
    preferences_path = config_dir / "preferences.ini"
    assert preferences_path.read_bytes().startswith(UTF16_LE_BOM)
    text = live_profiles.read_ini_text(preferences_path)
    emule_section = section_text(text, "eMule")
    webserver_section = section_text(text, "WebServer")
    upnp_section = section_text(text, "UPnP")
    assert profile["profile_root"] == profile_root
    assert profile["preferences_path"] == preferences_path
    assert "BindAddr=127.0.0.1" in emule_section
    assert "BindInterface=" not in emule_section
    assert "Port=33111" in emule_section
    assert "UDPPort=33112" in emule_section
    assert "ServerUDPPort=33113" in emule_section
    assert "NetworkKademlia=1" in emule_section
    assert "NetworkED2K=0" in emule_section
    assert f"MaxDownload={live_profiles.PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC}" in emule_section
    assert f"MaxUpload={live_profiles.PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC}" in emule_section
    assert "Port=33114" in webserver_section
    assert "Enabled=0" in webserver_section
    assert "EnableUPnP=0" in upnp_section
    assert not (config_dir / "server.met").exists()
    assert not (config_dir / "nodes.dat").exists()
    assert live_profiles.read_ini_text(config_dir / "shareddir.dat") == "C:\\share\\\r\n"


def test_materialize_private_harness_profile_preserves_identity_files_on_reset(tmp_path: Path) -> None:
    seed_config_dir = write_valid_seed(tmp_path)
    profile_root = tmp_path / "private-profile"
    config_dir = profile_root / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.dat").write_bytes(b"existing-preferences")
    (config_dir / "preferencesKad.dat").write_bytes(b"existing-kad")
    (config_dir / "cryptkey.dat").write_bytes(b"existing-crypt")
    (config_dir / "collectioncryptkey.dat").write_bytes(b"existing-collection")
    (config_dir / "server.met").write_bytes(b"stale-server")
    (config_dir / "nodes.dat").write_bytes(b"stale-nodes")
    (config_dir / "transient.tmp").write_bytes(b"stale")
    for transient_dir_name in ("logs", "Incoming", "Temp"):
        transient_dir = profile_root / transient_dir_name
        transient_dir.mkdir(parents=True)
        (transient_dir / "stale.txt").write_text("stale", encoding="utf-8")
    for marker_name in ("harness.ready", "status.log", "seed.ed2k"):
        (profile_root / marker_name).write_text("stale", encoding="utf-8")

    live_profiles.materialize_private_harness_profile(
        live_profiles.PrivateHarnessProfileSpec(
            seed_config_dir=seed_config_dir,
            profile_root=profile_root,
            lan_bind_addr="127.0.0.1",
            tcp_port=33111,
            udp_port=33112,
        )
    )

    assert (config_dir / "preferences.dat").read_bytes() == b"existing-preferences"
    assert (config_dir / "preferencesKad.dat").read_bytes() == b"existing-kad"
    assert (config_dir / "cryptkey.dat").read_bytes() == b"existing-crypt"
    assert (config_dir / "collectioncryptkey.dat").read_bytes() == b"existing-collection"
    assert not (config_dir / "server.met").exists()
    assert not (config_dir / "nodes.dat").exists()
    assert not (config_dir / "transient.tmp").exists()
    for transient_dir_name in ("logs", "Incoming", "Temp"):
        assert list((profile_root / transient_dir_name).iterdir()) == []
    for marker_name in ("harness.ready", "status.log", "seed.ed2k"):
        assert not (profile_root / marker_name).exists()


def test_apply_private_harness_obfuscation_updates_crypto_flags(tmp_path: Path) -> None:
    seed_config_dir = write_valid_seed(tmp_path)
    profile = live_profiles.materialize_private_harness_profile(
        live_profiles.PrivateHarnessProfileSpec(
            seed_config_dir=seed_config_dir,
            profile_root=tmp_path / "private-profile",
            lan_bind_addr="127.0.0.1",
            tcp_port=33111,
            udp_port=33112,
        )
    )
    config_dir = Path(profile["config_dir"])

    live_profiles.apply_private_harness_obfuscation(config_dir, obfuscated_preferred=True)
    text = live_profiles.read_ini_text(config_dir / "preferences.ini")
    emule_section = section_text(text, "eMule")
    assert emule_section.count("CryptLayerRequested=1") == 1
    assert emule_section.count("CryptLayerRequired=0") == 1
    assert emule_section.count("CryptLayerSupported=1") == 1

    live_profiles.apply_private_harness_obfuscation(config_dir, obfuscated_preferred=False)
    text = live_profiles.read_ini_text(config_dir / "preferences.ini")
    emule_section = section_text(text, "eMule")
    assert emule_section.count("CryptLayerRequested=0") == 1
    assert emule_section.count("CryptLayerRequired=0") == 1
    assert emule_section.count("CryptLayerSupported=0") == 1


def test_apply_webserver_profile_writes_typed_rest_overlay(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(preferences_path, "[eMule]\nConfirmExit=1\n[WebServer]\nEnabled=0\n")
    app_exe = tmp_path / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"

    live_profiles.apply_webserver_profile(
        config_dir,
        live_profiles.WebServerProfileSpec(
            app_exe=app_exe,
            api_key="api-key",
            port=4711,
            lan_bind_addr="192.0.2.10",
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
    assert "BindAddr=192.0.2.10" in text
    assert "Port=4711" in text
    assert "Enabled=1" in text
    assert "UseGzip=0" in text
    assert "AllowAdminHiLevelFunc=0" in text
    assert "EnableDiagnosticRestEndpoints=0" in text
    assert "MaxFileUploadSizeMB=5" in text
    assert "AllowedIPs=127.0.0.1" in text
