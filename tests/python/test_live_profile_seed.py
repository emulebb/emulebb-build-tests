from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import live_profile_seed


def write_valid_seed(root: Path) -> Path:
    config_dir = root / "config"
    config_dir.mkdir()
    preferences_text = "[eMule]\n" + "\n".join(f"{key}=1" for key in live_profile_seed.REQUIRED_SEED_KEYS) + "\n"
    (config_dir / "preferences.ini").write_text(preferences_text, encoding="utf-8")
    (config_dir / "preferences.dat").write_bytes(b"prefs")
    (config_dir / "server.met").write_bytes(b"servers")
    (config_dir / "nodes.dat").write_bytes(b"nodes")
    return config_dir


def test_validate_seed_config_dir_accepts_curated_file_set(tmp_path: Path) -> None:
    config_dir = write_valid_seed(tmp_path)

    live_profile_seed.validate_seed_config_dir(config_dir)


def test_validate_seed_config_dir_rejects_dangling_file(tmp_path: Path) -> None:
    config_dir = write_valid_seed(tmp_path)
    (config_dir / "debug.log").write_text("runtime noise\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unsupported file"):
        live_profile_seed.validate_seed_config_dir(config_dir)


def test_validate_seed_config_dir_requires_initialized_preferences(tmp_path: Path) -> None:
    config_dir = write_valid_seed(tmp_path)
    (config_dir / "preferences.ini").write_text("[eMule]\nNick=1\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="AppVersion"):
        live_profile_seed.validate_seed_config_dir(config_dir)
