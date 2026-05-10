"""Reusable live-profile generation helpers for eMule harness scenarios."""

from __future__ import annotations

import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .ini import (
    patch_ini_value,
    read_ini_text,
    upsert_ini_section_value,
    write_utf16_ini_text,
)
from .live_profile_seed import ensure_seed_profile_initialized, validate_seed_config_dir

PREFERENCES_DAT_VERSION = 0x14
WINDOW_PLACEMENT_LENGTH = 44
WINDOW_SHOW_MAXIMIZED = 3
DEFAULT_WINDOW_RECT = (10, 10, 700, 500)
STARTUP_PROFILE_TRACE_FILE_NAME = "startup-profile.trace.json"
DEFAULT_P2P_BIND_INTERFACE_NAME = "hide.me"


@dataclass(frozen=True)
class LiveNetworkProfileSpec:
    """Live P2P network settings required by the workspace harness policy."""

    p2p_bind_interface_name: str = DEFAULT_P2P_BIND_INTERFACE_NAME
    close_upnp_on_exit: bool = False


@dataclass(frozen=True)
class WebServerProfileSpec:
    """REST/WebServer preference overlay for one isolated harness profile."""

    app_exe: Path
    api_key: str
    port: int
    bind_addr: str = "127.0.0.1"
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
    incoming_dir: Path | None = None
    temp_dir: Path | None = None


def win_path(path: Path, trailing_slash: bool = False) -> str:
    """Formats a path as an absolute Windows string, optionally with a trailing separator."""

    resolved = str(path.resolve())
    return resolved + ("\\" if trailing_slash and not resolved.endswith("\\") else "")


def apply_emule_preferences(config_dir: Path, values: tuple[tuple[str, str], ...]) -> None:
    """Applies simple eMule section preference values to one profile INI."""

    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    for key, value in values:
        text = patch_ini_value(text, key, value)
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
) -> None:
    """Persists the workspace live-test P2P bind and UPnP policy."""

    spec = LiveNetworkProfileSpec(
        p2p_bind_interface_name=p2p_bind_interface_name,
        close_upnp_on_exit=close_upnp_on_exit,
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
    text = upsert_ini_section_value(text, "eMule", "BlockNetworkWhenBindUnavailableAtStartup", "1")
    text = upsert_ini_section_value(text, "UPnP", "EnableUPnP", "1")
    text = patch_ini_value(text, "CloseUPnPOnExit", "1" if spec.close_upnp_on_exit else "0")
    write_utf16_ini_text(preferences_path, text)


def apply_webserver_profile(config_dir: Path, spec: WebServerProfileSpec) -> None:
    """Applies a WebServer/REST overlay to one generated profile."""

    template_path = spec.app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"
    preferences_path = config_dir / "preferences.ini"
    text = read_ini_text(preferences_path)
    text = patch_ini_value(text, "WebTemplateFile", str(template_path))

    values = [
        ("Password", ""),
        ("PasswordLow", ""),
        ("ApiKey", spec.api_key),
        ("BindAddr", spec.bind_addr),
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
) -> None:
    """Writes a deterministic preferences.dat carrying the requested main-window placement."""

    data = struct.pack(
        "<B16sIIIiiiiiiii",
        PREFERENCES_DAT_VERSION,
        b"\0" * 16,
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


def prepare_profile_base(
    seed_config_dir: Path,
    artifacts_dir: Path,
    shared_dirs: list[str],
    incoming_dir: Path | None = None,
    temp_dir: Path | None = None,
) -> dict[str, object]:
    """Copies the seed profile and patches per-run mutable paths into an isolated base."""

    return build_profile_base(
        ProfileBuildSpec(
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            shared_dirs=shared_dirs,
            incoming_dir=incoming_dir,
            temp_dir=temp_dir,
        )
    )


def build_profile_base(spec: ProfileBuildSpec) -> dict[str, object]:
    """Builds one fresh profile base from the checked-in deterministic seed."""

    profile_base = spec.artifacts_dir / "profile-base"
    config_dir = profile_base / "config"
    log_dir = profile_base / "logs"
    incoming_dir = spec.incoming_dir or (spec.artifacts_dir / "incoming")
    temp_dir = spec.temp_dir or (spec.artifacts_dir / "temp")

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
    ):
        preferences_text = patch_ini_value(preferences_text, key, value)
    write_utf16_ini_text(preferences_path, preferences_text)

    write_preferences_dat(config_dir / "preferences.dat")
    write_shared_directories_file(config_dir / "shareddir.dat", spec.shared_dirs)

    return {
        "profile_base": profile_base,
        "config_dir": config_dir,
        "log_dir": log_dir,
        "incoming_dir": incoming_dir,
        "temp_dir": temp_dir,
        "startup_profile_path": config_dir / STARTUP_PROFILE_TRACE_FILE_NAME,
    }
