from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_set_linked_client_skips_refresh_after_friendlist_teardown() -> None:
    source = (app_source_root() / "Friend.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "if (theApp.friendlist != NULL)\n\t\ttheApp.friendlist->RefreshFriend(this);" in source


def test_try_to_connect_rejects_null_listener_before_queue_or_callback() -> None:
    source = (app_source_root() / "Friend.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pConnectionReport != NULL);\n\tif (pConnectionReport == NULL)\n\t\treturn false;\n\n\tif (m_FriendConnectState != FCS_NONE)" in source
