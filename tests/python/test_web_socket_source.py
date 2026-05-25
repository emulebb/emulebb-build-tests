from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_web_bind_addr_resolution_rejects_null_output_pointer() -> None:
    source = (app_source_root() / "WebSocket.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool TryResolveWebBindAddr(in_addr *pAddr)\n\t{\n\t\tASSERT(pAddr != NULL);\n\t\tif (pAddr == NULL)\n\t\t\treturn false;\n\t\tpAddr->s_addr = INADDR_ANY;" in source
