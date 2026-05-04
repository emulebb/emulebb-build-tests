from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness.ini import UTF16_LE_BOM, write_utf16_ini_text
from emule_test_harness import live_profile_seed


def write_valid_seed(root: Path) -> Path:
    config_dir = root / "config"
    config_dir.mkdir()
    preferences_text = "[eMule]\n" + "\n".join(f"{key}=1" for key in live_profile_seed.REQUIRED_SEED_KEYS) + "\n"
    write_utf16_ini_text(config_dir / "preferences.ini", preferences_text)
    (config_dir / "preferences.dat").write_bytes(b"prefs")
    (config_dir / "server.met").write_bytes(b"servers")
    (config_dir / "nodes.dat").write_bytes(b"nodes")
    return config_dir


def test_validate_seed_config_dir_accepts_curated_file_set(tmp_path: Path) -> None:
    config_dir = write_valid_seed(tmp_path)

    live_profile_seed.validate_seed_config_dir(config_dir)


def test_checked_in_preferences_seed_is_utf16le() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    preferences_path = repo_root / "manifests" / "live-profile-seed" / "config" / "preferences.ini"

    assert preferences_path.read_bytes().startswith(UTF16_LE_BOM)
    live_profile_seed.validate_seed_config_dir(preferences_path.parent)


def test_validate_seed_config_dir_rejects_dangling_file(tmp_path: Path) -> None:
    config_dir = write_valid_seed(tmp_path)
    (config_dir / "debug.log").write_text("runtime noise\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unsupported file"):
        live_profile_seed.validate_seed_config_dir(config_dir)


def test_validate_seed_config_dir_requires_initialized_preferences(tmp_path: Path) -> None:
    config_dir = write_valid_seed(tmp_path)
    write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\nNick=1\n")

    with pytest.raises(RuntimeError, match="AppVersion"):
        live_profile_seed.validate_seed_config_dir(config_dir)
