"""Validation helpers for the deterministic live-profile seed."""

from __future__ import annotations

from pathlib import Path

from .ini import parse_ini_values, read_ini_text

ALLOWED_SEED_FILES = frozenset({"preferences.ini", "preferences.dat", "server.met", "nodes.dat"})
REQUIRED_SEED_KEYS = (
    "AppVersion",
    "Nick",
    "Port",
    "UDPPort",
    "ServerUDPPort",
    "Language",
    "StartupMinimized",
    "BringToFront",
    "ConfirmExit",
    "RestoreLastMainWndDlg",
    "Splashscreen",
    "Autoconnect",
    "Reconnect",
    "NetworkED2K",
    "NetworkKademlia",
    "ShowSharedFilesDetails",
)

def ensure_seed_profile_initialized(text: str) -> None:
    """Fails fast when the checked-in seed no longer contains required settings."""

    values = parse_ini_values(text)
    missing_keys = [key for key in REQUIRED_SEED_KEYS if not values.get(key, "").strip()]
    if missing_keys:
        raise RuntimeError(
            "Seed preferences.ini is missing required initialized keys: "
            + ", ".join(missing_keys)
        )


def validate_seed_config_dir(seed_config_dir: Path) -> None:
    """Validates the live profile seed allowlist and initialized preferences."""

    resolved_dir = seed_config_dir.resolve()
    if not resolved_dir.is_dir():
        raise RuntimeError(f"Seed config directory was not found at '{resolved_dir}'.")

    entries = list(resolved_dir.iterdir())
    unexpected = sorted(entry.name for entry in entries if not entry.is_file() or entry.name not in ALLOWED_SEED_FILES)
    if unexpected:
        raise RuntimeError(
            "Seed config directory contains unsupported file(s): "
            + ", ".join(unexpected)
        )

    existing = {entry.name for entry in entries if entry.is_file()}
    missing = sorted(ALLOWED_SEED_FILES - existing)
    if missing:
        raise RuntimeError(
            "Seed config directory is missing required file(s): "
            + ", ".join(missing)
        )

    preferences_path = resolved_dir / "preferences.ini"
    ensure_seed_profile_initialized(read_ini_text(preferences_path))
