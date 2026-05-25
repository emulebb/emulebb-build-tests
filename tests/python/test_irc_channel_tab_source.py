from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_remove_channel_checks_list_position_before_remove_at() -> None:
    source = (app_source_root() / "IrcChannelTabCtrl.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "m_lstChannels.RemoveAt(m_lstChannels.Find(pChannel));" not in source
    assert "POSITION posChannel = m_lstChannels.Find(pChannel);" in source
    assert "ASSERT(posChannel != NULL);" in source
    assert "if (posChannel != NULL)\n\t\tm_lstChannels.RemoveAt(posChannel);" in source
