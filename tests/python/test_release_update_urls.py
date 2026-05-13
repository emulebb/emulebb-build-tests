from __future__ import annotations

from pathlib import Path


def test_release_update_and_help_urls_use_emulebb_owned_repositories() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"

    emule_cpp = (app_source / "Emule.cpp").read_text(encoding="utf-8", errors="ignore")
    preferences_cpp = (app_source / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")
    release_tests_cpp = (
        workspace_root
        / "repos"
        / "eMule-build-tests"
        / "src"
        / "release_update_check.tests.cpp"
    ).read_text(encoding="utf-8", errors="ignore")

    assert "https://github.com/eMulebb/eMule-tooling/blob/main/docs/HELP.md" in emule_cpp
    assert "https://github.com/eMulebb/eMule/releases" in preferences_cpp
    assert "https://api.github.com/repos/eMulebb/eMule/releases/latest" in preferences_cpp
    assert "https://github.com/eMulebb/eMule/releases/tag/" in release_tests_cpp

    combined = "\n".join([emule_cpp, preferences_cpp, release_tests_cpp])
    assert "github.com/itlezy" not in combined
    assert "api.github.com/repos/itlezy" not in combined
