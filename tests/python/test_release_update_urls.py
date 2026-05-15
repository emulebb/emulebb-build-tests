from __future__ import annotations

import re
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


def test_bootstrap_and_ip_filter_defaults_are_https_only() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"

    preferences_h = (app_source / "Preferences.h").read_text(encoding="utf-8", errors="ignore")
    preferences_cpp = (app_source / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore")
    ppg_security_cpp = (app_source / "PPgSecurity.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "https://upd.emule-security.org/server.met" in preferences_h
    assert "https://upd.emule-security.org/nodes.dat" in preferences_h
    assert "https://upd.emule-security.org/ipfilter.zip" in ppg_security_cpp
    assert "https://emuling.gitlab.io/server.met" in preferences_cpp

    combined = "\n".join([preferences_h, preferences_cpp, ppg_security_cpp])
    assert "http://upd.emule-security.org/server.met" not in combined
    assert "http://upd.emule-security.org/nodes.dat" not in combined
    assert "http://upd.emule-security.org/ipfilter.zip" not in combined


def test_server_met_dropdown_preserves_current_text() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"

    server_wnd_cpp = (app_source / "ServerWnd.cpp").read_text(encoding="utf-8", errors="ignore")
    server_wnd_h = (app_source / "ServerWnd.h").read_text(encoding="utf-8", errors="ignore")
    on_dropdown = re.search(
        r"void CServerWnd::OnDDClicked\(\)\s*\{(?P<body>.*?)\n\}",
        server_wnd_cpp,
        re.DOTALL,
    )

    assert on_dropdown is not None
    assert "m_strServerMetUrlText" in server_wnd_h
    assert "ON_MESSAGE(UM_RESTORE_SERVERMETURL, OnRestoreServerMetUrl)" in server_wnd_cpp
    assert "PostMessage(UM_RESTORE_SERVERMETURL)" in on_dropdown.group("body")
    assert 'SetWindowText(_T(""))' not in on_dropdown.group("body")
