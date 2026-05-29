from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import live_env


def clear_live_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Removes live integration variables that may exist on an operator machine."""

    for name in (
        "PROWLARR_URL",
        "PROWLARR_API_KEY",
        "EMULEBB_TEST_PROWLARR_INDEXER_NAME",
        "RADARR_URL",
        "RADARR_API_KEY",
        "SONARR_URL",
        "SONARR_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_load_env_values_uses_process_env_before_dotenv_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_live_env(monkeypatch)
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "\n".join(
            [
                "PROWLARR_URL=http://from-file",
                "PROWLARR_API_KEY=file-secret",
                "EMULEBB_TEST_PROWLARR_INDEXER_NAME=File Name",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PROWLARR_API_KEY", "process-secret")
    monkeypatch.setattr(live_env, "ensure_secret_file_is_ignored", lambda _path: None)

    values = live_env.load_env_values(
        ("PROWLARR_URL", "PROWLARR_API_KEY"),
        env_file=env_file,
        defaults={"EMULEBB_TEST_PROWLARR_INDEXER_NAME": "Default Name"},
    )

    assert values["PROWLARR_URL"] == "http://from-file"
    assert values["PROWLARR_API_KEY"] == "process-secret"
    assert values["EMULEBB_TEST_PROWLARR_INDEXER_NAME"] == "File Name"


def test_load_env_values_allows_process_only_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    clear_live_env(monkeypatch)
    monkeypatch.setenv("PROWLARR_URL", "http://from-process")
    monkeypatch.setenv("PROWLARR_API_KEY", "process-secret")

    values = live_env.load_env_values(("PROWLARR_URL", "PROWLARR_API_KEY"), env_file=Path("missing.env"))

    assert values["PROWLARR_URL"] == "http://from-process"
    assert values["PROWLARR_API_KEY"] == "process-secret"


def test_missing_required_env_message_names_keys_without_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_live_env(monkeypatch)
    env_file = tmp_path / ".env.local"
    env_file.write_text("PROWLARR_URL=http://from-file\nPROWLARR_API_KEY=secret-value\n", encoding="utf-8")
    monkeypatch.setattr(live_env, "ensure_secret_file_is_ignored", lambda _path: None)

    with pytest.raises(RuntimeError) as excinfo:
        live_env.load_env_values(("RADARR_API_KEY",), env_file=env_file)

    message = str(excinfo.value)
    assert "RADARR_API_KEY" in message
    assert "secret-value" not in message
