"""Reusable live-profile generation helpers for eMule harness scenarios."""

from __future__ import annotations

import hashlib
import re
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .ini import (
    patch_ini_value,
    read_ini_text,
    remove_ini_section_value,
    upsert_ini_section_value,
    write_utf16_ini_text,
)
from .live_profile_seed import ensure_seed_profile_initialized, validate_seed_config_dir
from .vm_guest_profiles import (
    DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS,
    DEFAULT_HIDEME_VPN_GUARD_PUBLIC_IP_CIDRS,
)

PREFERENCES_DAT_VERSION = 0x14
WINDOW_PLACEMENT_LENGTH = 44
WINDOW_SHOW_MAXIMIZED = 3
DEFAULT_WINDOW_RECT = (10, 10, 700, 500)
STARTUP_DIAGNOSTICS_TRACE_FILE_NAME = "emulebb-diagnostics-startup.trace.json"
DEFAULT_P2P_BIND_INTERFACE_NAME = "hide.me"
DEFAULT_PROFILE_SCENARIO_ID = "default"
PROFILE_ARTIFACTS_DIR_NAME = "profiles"
SCENARIO_ID_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")
PRIVATE_HARNESS_RATE_LIMIT_BITS_PER_SEC = 10_000_000_000
PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC = PRIVATE_HARNESS_RATE_LIMIT_BITS_PER_SEC // 8 // 1024
PRIVATE_HARNESS_PROTECTED_CONFIG_FILES = frozenset(
    {
        "preferences.dat",
        "preferenceskad.dat",
        "cryptkey.dat",
        "collectioncryptkey.dat",
    }
)


def deterministic_user_hash(identity: str) -> bytes:
    """Returns one stable eMule client hash for a deterministic live profile identity."""

    digest = bytearray(hashlib.sha256(f"emulebb-live-profile:{identity}".encode("utf-8")).digest()[:16])
    digest[5] = 14
    digest[14] = 111
    return bytes(digest)


@dataclass(frozen=True)
class LiveNetworkProfileSpec:
    """Live P2P network settings required by the workspace harness policy."""

    p2p_bind_interface_name: str = DEFAULT_P2P_BIND_INTERFACE_NAME
    close_upnp_on_exit: bool = False
    vpn_guard_enabled: bool = False
    vpn_guard_allowed_public_ip_cidrs: str = ""


@dataclass(frozen=True)
class WebServerProfileSpec:
    """REST/WebServer preference overlay for one isolated harness profile."""

    app_exe: Path
    api_key: str
    port: int
    lan_bind_addr: str
    enabled: bool = True
    use_gzip: bool = True
    allow_admin_high_level_func: bool = True
    use_https: bool = False
    https_certificate: str = ""
    https_key: str = ""
    enable_crash_test_endpoint: bool = False
    max_file_upload_size_mb: int | None = None
    allowed_ips: str | None = None
    extra_values: tuple[tuple[str, str], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ProfileBuildSpec:
    """Inputs for generating one fresh deterministic live test profile."""

    seed_config_dir: Path
    artifacts_dir: Path
    shared_dirs: list[str]
    scenario_id: str = DEFAULT_PROFILE_SCENARIO_ID
    incoming_dir: Path | None = None
    temp_dir: Path | None = None
    # Persisted-profile mode: when the target profile-base already exists, reuse it
    # instead of rebuilding from seed, so MFC's known.met/known2_64.met hash cache
    # (and shareddir.dat) survive across runs and the shared library is not
    # re-hashed every launch. First build still seeds normally.
    reuse_existing: bool = False


@dataclass(frozen=True)
class PrivateHarnessProfileSpec:
    """Inputs for one deterministic private/local eMule test profile."""

    seed_config_dir: Path
    profile_root: Path
    lan_bind_addr: str
    tcp_port: int
    udp_port: int
    server_udp_port: int = 0
    web_port: int = 47101
    kad_udp_key: int = 4_206_201
    enable_kademlia: bool = False
    enable_ed2k: bool = True
    enable_upnp: bool = False
    reset_transient_state: bool = True
    max_download_kib_per_sec: int = PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC
    max_upload_kib_per_sec: int = PRIVATE_HARNESS_RATE_LIMIT_KIB_PER_SEC
    nick: str = "eMule harness"
    shared_dirs: tuple[str, ...] = field(default_factory=tuple)


def win_path(path: Path, trailing_slash: bool = False) -> str:
    """Formats a path as an absolute Windows string, optionally with a trailing separator."""

    resolved = str(path.resolve())
    return resolved + ("\\" if trailing_slash and not resolved.endswith("\\") else "")


def apply_emule_preferences(config_dir: Path, values: tuple[tuple[str, str], ...]) -> None:
    """Applies simple eMule section preference values to one profile INI."""

    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    for key, value in values:
        text = upsert_ini_section_value(text, "eMule", key, value)
    write_utf16_ini_text(preferences_path, text)


def apply_section_preferences(config_dir: Path, section: str, values: tuple[tuple[str, str], ...]) -> None:
    """Applies section-scoped preference values to one profile INI."""

    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    for key, value in values:
        text = upsert_ini_section_value(text, section, key, value)
    write_utf16_ini_text(preferences_path, text)


def apply_live_network_policy(
    config_dir: Path,
    *,
    p2p_bind_interface_name: str = DEFAULT_P2P_BIND_INTERFACE_NAME,
    close_upnp_on_exit: bool = False,
    vpn_guard_enabled: bool = False,
    vpn_guard_allowed_public_ip_cidrs: str = "",
) -> None:
    """Persists the workspace live-test P2P bind and UPnP policy."""

    spec = LiveNetworkProfileSpec(
        p2p_bind_interface_name=p2p_bind_interface_name,
        close_upnp_on_exit=close_upnp_on_exit,
        vpn_guard_enabled=vpn_guard_enabled,
        vpn_guard_allowed_public_ip_cidrs=vpn_guard_allowed_public_ip_cidrs,
    )
    apply_live_network_profile(config_dir, spec)


def apply_live_network_profile(config_dir: Path, spec: LiveNetworkProfileSpec) -> None:
    """Applies the live network policy from a typed profile spec."""

    interface_name = spec.p2p_bind_interface_name.strip()
    if not interface_name:
        raise ValueError("P2P bind interface name must not be empty.")

    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    text = upsert_ini_section_value(text, "eMule", "BindInterface", interface_name)
    text = upsert_ini_section_value(text, "eMule", "BindAddr", "")
    text = remove_ini_section_value(text, "eMule", "BlockNetworkWhenBindUnavailableAtStartup")
    text = remove_ini_section_value(text, "eMule", "ExitOnBindInterfaceLoss")
    guard_cidrs = spec.vpn_guard_allowed_public_ip_cidrs.strip()
    guard_enabled = spec.vpn_guard_enabled or bool(guard_cidrs)
    text = upsert_ini_section_value(text, "eMule", "VpnGuardMode", "Block" if guard_enabled else "Off")
    text = upsert_ini_section_value(text, "eMule", "VpnGuardAllowedPublicIpCidrs", guard_cidrs)
    text = upsert_ini_section_value(text, "UPnP", "EnableUPnP", "1")
    text = patch_ini_value(text, "CloseUPnPOnExit", "1" if spec.close_upnp_on_exit else "0")
    write_utf16_ini_text(preferences_path, text)


def apply_minimized_to_tray_startup(config_dir: Path) -> None:
    """Persists startup preferences for non-UI live tests to stay in the tray."""

    apply_emule_preferences(
        config_dir,
        (
            ("StartupMinimized", "1"),
            ("MinToTray", "1"),
            ("MinToTray_Aero", "1"),
            ("AlwaysShowTrayIcon", "1"),
        ),
    )


def apply_webserver_profile(config_dir: Path, spec: WebServerProfileSpec) -> None:
    """Applies a WebServer/REST overlay to one generated profile."""

    template_path = spec.app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"
    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    text = upsert_ini_section_value(text, "eMule", "WebTemplateFile", str(template_path))

    values = [
        ("Password", ""),
        ("PasswordLow", ""),
        ("ApiKey", spec.api_key),
        ("BindAddr", spec.lan_bind_addr),
        ("Port", str(spec.port)),
        ("WebUseUPnP", "0"),
        ("Enabled", "1" if spec.enabled else "0"),
        ("UseGzip", "1" if spec.use_gzip else "0"),
        ("PageRefreshTime", "120"),
        ("UseLowRightsUser", "0"),
        ("AllowAdminHiLevelFunc", "1" if spec.allow_admin_high_level_func else "0"),
        ("WebTimeoutMins", "5"),
        ("UseHTTPS", "1" if spec.use_https else "0"),
        ("HTTPSCertificate", spec.https_certificate),
        ("HTTPSKey", spec.https_key),
    ]
    if spec.enable_crash_test_endpoint:
        values.append(("EnableDiagnosticRestEndpoints", "1"))
    else:
        values.append(("EnableDiagnosticRestEndpoints", "0"))
    if spec.max_file_upload_size_mb is not None:
        values.append(("MaxFileUploadSizeMB", str(spec.max_file_upload_size_mb)))
    if spec.allowed_ips is not None:
        values.append(("AllowedIPs", spec.allowed_ips))
    values.extend(spec.extra_values)

    for key, value in values:
        text = upsert_ini_section_value(text, "WebServer", key, value)
    write_utf16_ini_text(preferences_path, text)


def write_preferences_dat(
    path: Path,
    show_cmd: int = WINDOW_SHOW_MAXIMIZED,
    normal_rect: tuple[int, int, int, int] = DEFAULT_WINDOW_RECT,
    user_hash: bytes | None = None,
) -> None:
    """Writes a deterministic preferences.dat carrying client identity and window placement."""

    if user_hash is None:
        user_hash = deterministic_user_hash("default")
    if len(user_hash) != 16:
        raise ValueError("preferences.dat user hash must be exactly 16 bytes")

    data = struct.pack(
        "<B16sIIIiiiiiiii",
        PREFERENCES_DAT_VERSION,
        user_hash,
        WINDOW_PLACEMENT_LENGTH,
        0,
        show_cmd,
        0,
        0,
        0,
        0,
        normal_rect[0],
        normal_rect[1],
        normal_rect[2],
        normal_rect[3],
    )
    path.write_bytes(data)


def write_shared_directories_file(path: Path, shared_dirs: list[str]) -> None:
    """Writes the eMule shared-directory list as UTF-16 text."""

    contents = "".join(f"{entry}\r\n" for entry in shared_dirs)
    path.write_text(contents, encoding="utf-16", newline="")


def _remove_path(path: Path) -> None:
    """Removes one file or directory without following directory symlinks."""

    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def _copy_seed_config_files(seed_config_dir: Path, config_dir: Path) -> None:
    """Copies deterministic seed files into a profile config directory when missing."""

    for seed_file in seed_config_dir.iterdir():
        target = config_dir / seed_file.name
        if seed_file.is_file() and not target.exists():
            shutil.copy2(seed_file, target)


def _reset_private_harness_config(config_dir: Path) -> None:
    """Drops transient network config while preserving long-lived client identity files."""

    for entry in config_dir.iterdir():
        if entry.name.lower() in PRIVATE_HARNESS_PROTECTED_CONFIG_FILES:
            continue
        _remove_path(entry)


def _private_harness_preferences_text(spec: PrivateHarnessProfileSpec) -> str:
    """Builds the deterministic preferences.ini payload for private/local harness runs."""

    enabled_kad = "1" if spec.enable_kademlia else "0"
    enabled_ed2k = "1" if spec.enable_ed2k else "0"
    enabled_upnp = "1" if spec.enable_upnp else "0"
    return (
        "[eMule]\n"
        "AppVersion=0.72a\n"
        f"Port={spec.tcp_port}\n"
        f"UDPPort={spec.udp_port}\n"
        f"ServerUDPPort={spec.server_udp_port}\n"
        f"BindAddr={spec.lan_bind_addr}\n"
        "AllowLocalHostIP=1\n"
        "FilterBadIPs=0\n"
        "Autoconnect=1\n"
        "StartupMinimized=1\n"
        "MinToTray=1\n"
        "BringToFront=0\n"
        "Splashscreen=0\n"
        "SaveLogToDisk=1\n"
        "SaveDebugToDisk=1\n"
        "Verbose=1\n"
        "OnlineSignature=0\n"
        "AutoTakeED2KLinks=0\n"
        "AutoConnectStaticOnly=0\n"
        "Serverlist=0\n"
        "AddServersFromServer=0\n"
        "AddServersFromClient=0\n"
        f"NetworkKademlia={enabled_kad}\n"
        f"NetworkED2K={enabled_ed2k}\n"
        f"OpenPortsOnStartUp={enabled_upnp}\n"
        "EnableScheduler=0\n"
        f"KadUDPKey={spec.kad_udp_key}\n"
        f"MaxDownload={spec.max_download_kib_per_sec}\n"
        f"MaxUpload={spec.max_upload_kib_per_sec}\n"
        "CreateCrashDump=0\n"
        f"Nick={spec.nick}\n"
        "CryptLayerRequested=0\n"
        "CryptLayerRequired=0\n"
        "CryptLayerSupported=0\n"
        "\n"
        "[WebServer]\n"
        "Enabled=0\n"
        f"Port={spec.web_port}\n"
        f"WebUseUPnP={enabled_upnp}\n"
        "\n"
        "[UPnP]\n"
        f"EnableUPnP={enabled_upnp}\n"
        f"CloseUPnPOnExit={enabled_upnp}\n"
    )


def materialize_private_harness_profile(spec: PrivateHarnessProfileSpec) -> dict[str, object]:
    """Builds or refreshes a deterministic private/local profile for p2p harness tests."""

    validate_seed_config_dir(spec.seed_config_dir)
    profile_root = spec.profile_root
    config_dir = profile_root / "config"
    log_dir = profile_root / "logs"
    incoming_dir = profile_root / "Incoming"
    temp_dir = profile_root / "Temp"

    profile_root.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    _copy_seed_config_files(spec.seed_config_dir, config_dir)

    if spec.reset_transient_state:
        _reset_private_harness_config(config_dir)
        for transient_dir in (log_dir, incoming_dir, temp_dir):
            if transient_dir.exists():
                _remove_path(transient_dir)
        for marker_name in ("harness.ready", "status.log", "seed.ed2k"):
            marker_path = profile_root / marker_name
            if marker_path.exists() or marker_path.is_symlink():
                marker_path.unlink()

    for required_dir in (log_dir, incoming_dir, temp_dir):
        required_dir.mkdir(parents=True, exist_ok=True)

    preferences_path = config_dir / "preferences.ini"
    write_utf16_ini_text(preferences_path, _private_harness_preferences_text(spec))
    if not (config_dir / "preferences.dat").exists():
        write_preferences_dat(config_dir / "preferences.dat", user_hash=deterministic_user_hash(spec.profile_root.name))
    write_shared_directories_file(config_dir / "shareddir.dat", list(spec.shared_dirs))

    return {
        "profile_root": profile_root,
        "config_dir": config_dir,
        "preferences_path": preferences_path,
        "log_dir": log_dir,
        "logs_root": log_dir,
        "incoming_dir": incoming_dir,
        "incoming_root": incoming_dir,
        "temp_dir": temp_dir,
        "temp_root": temp_dir,
    }


def apply_private_harness_obfuscation(config_dir: Path, obfuscated_preferred: bool) -> None:
    """Updates private harness crypto preference flags through the shared INI helper."""

    enabled = "1" if obfuscated_preferred else "0"
    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    for key, value in (
        ("CryptLayerRequested", enabled),
        ("CryptLayerRequired", "0"),
        ("CryptLayerSupported", enabled),
    ):
        text = upsert_ini_section_value(text, "eMule", key, value)
    write_utf16_ini_text(preferences_path, text)


def sanitize_profile_scenario_id(scenario_id: str) -> str:
    """Returns one filesystem-safe scenario id for profile artifact paths."""

    normalized = SCENARIO_ID_PATTERN.sub("-", scenario_id.strip()).strip(".-_")
    if not normalized:
        raise ValueError("Profile scenario id must not be empty.")
    return normalized


def prepare_scenario_profile(
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_dirs: list[str],
    scenario_id: str,
    incoming_dir: Path | None = None,
    temp_dir: Path | None = None,
    reuse_existing: bool = False,
) -> dict[str, object]:
    """Builds one scenario-scoped profile under `<artifacts>/profiles/<scenario>`.

    With `reuse_existing`, an already-built profile-base is reused (persisted
    profile) so the MFC hash cache survives across runs."""

    return build_profile_base(
        ProfileBuildSpec(
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            shared_dirs=shared_dirs,
            scenario_id=scenario_id,
            incoming_dir=incoming_dir,
            temp_dir=temp_dir,
            reuse_existing=reuse_existing,
        )
    )


def prepare_profile_base(
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_dirs: list[str],
    incoming_dir: Path | None = None,
    temp_dir: Path | None = None,
    scenario_id: str = DEFAULT_PROFILE_SCENARIO_ID,
    reuse_existing: bool = False,
) -> dict[str, object]:
    """Builds one scenario-scoped profile using the default scenario id."""

    return prepare_scenario_profile(
        seed_config_dir=seed_config_dir,
        artifacts_dir=artifacts_dir,
        shared_dirs=shared_dirs,
        scenario_id=scenario_id,
        incoming_dir=incoming_dir,
        temp_dir=temp_dir,
        reuse_existing=reuse_existing,
    )


def build_profile_base(spec: ProfileBuildSpec) -> dict[str, object]:
    """Builds one fresh profile base from the checked-in deterministic seed."""

    scenario_id = sanitize_profile_scenario_id(spec.scenario_id)
    scenario_artifacts_dir = spec.artifacts_dir / PROFILE_ARTIFACTS_DIR_NAME / scenario_id
    profile_base = scenario_artifacts_dir / "profile-base"
    config_dir = profile_base / "config"
    log_dir = profile_base / "logs"
    incoming_dir = spec.incoming_dir or (scenario_artifacts_dir / "incoming")
    temp_dir = spec.temp_dir or (scenario_artifacts_dir / "temp")

    if spec.reuse_existing and config_dir.exists():
        # Persisted profile: reuse the existing profile-base so MFC's known.met /
        # known2_64.met hash cache and shareddir.dat survive across runs (no
        # re-hash of the shared library). Only ensure the transient dirs exist.
        log_dir.mkdir(parents=True, exist_ok=True)
        incoming_dir.mkdir(parents=True, exist_ok=True)
        temp_dir.mkdir(parents=True, exist_ok=True)
        return {
            "scenario_id": scenario_id,
            "scenario_artifacts_dir": scenario_artifacts_dir,
            "profile_base": profile_base,
            "config_dir": config_dir,
            "log_dir": log_dir,
            "incoming_dir": incoming_dir,
            "temp_dir": temp_dir,
            "startup_diagnostics_path": log_dir / STARTUP_DIAGNOSTICS_TRACE_FILE_NAME,
        }

    validate_seed_config_dir(spec.seed_config_dir)
    shutil.copytree(spec.seed_config_dir, config_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    incoming_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    preferences_path = config_dir / "preferences.ini"
    preferences_text = read_ini_text(preferences_path)
    ensure_seed_profile_initialized(preferences_text)
    for key, value in (
        ("IncomingDir", win_path(incoming_dir, trailing_slash=True)),
        ("TempDir", win_path(temp_dir, trailing_slash=True)),
        ("TempDirs", win_path(temp_dir, trailing_slash=True)),
        ("SaveLogToDisk", "1"),
        ("SaveDebugToDisk", "1"),
        ("VerboseOptions", "1"),
        ("Verbose", "1"),
        ("FullVerbose", "1"),
        ("MaxLogFileSize", "10485760"),
        ("MaxLogBuff", "256"),
        ("LogFileFormat", "0"),
    ):
        preferences_text = patch_ini_value(preferences_text, key, value)
    write_utf16_ini_text(preferences_path, preferences_text)

    write_preferences_dat(config_dir / "preferences.dat", user_hash=deterministic_user_hash(scenario_id))
    write_shared_directories_file(config_dir / "shareddir.dat", spec.shared_dirs)
    apply_live_network_profile(config_dir, LiveNetworkProfileSpec())

    return {
        "scenario_id": scenario_id,
        "scenario_artifacts_dir": scenario_artifacts_dir,
        "profile_base": profile_base,
        "config_dir": config_dir,
        "log_dir": log_dir,
        "incoming_dir": incoming_dir,
        "temp_dir": temp_dir,
        "startup_diagnostics_path": log_dir / STARTUP_DIAGNOSTICS_TRACE_FILE_NAME,
    }
