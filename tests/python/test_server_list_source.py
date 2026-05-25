from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_get_server_at_rejects_invalid_indices_before_position_access() -> None:
    header = (app_source_root() / "ServerList.h").read_text(encoding="utf-8", errors="ignore")

    assert "if (pos < 0 || pos >= list.GetCount())\n\t\t\treturn NULL;" in header
    assert "POSITION serverPos = list.FindIndex(pos);" in header
    assert "return serverPos != NULL ? list.GetAt(serverPos) : NULL;" in header
    assert "return list.GetAt(list.FindIndex(pos));" not in header
