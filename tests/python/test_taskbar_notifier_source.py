from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_taskbar_notifier_create_rejects_null_parent() -> None:
    source = (app_source_root() / "TaskbarNotifier.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pWndParent != NULL);\n\tif (pWndParent == NULL)\n\t\treturn FALSE;\n\tm_pWndParent = pWndParent;" in source
    assert "SetTimer(IDT_APPEARING, m_dwShowEvents, NULL);\n\t\t[[fallthrough]];\n\tcase IDT_APPEARING:" in source
