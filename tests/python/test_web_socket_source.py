from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_web_bind_addr_resolution_rejects_null_output_pointer() -> None:
    source = (app_source_root() / "WebSocket.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool TryResolveWebBindAddr(in_addr *pAddr)\n\t{\n\t\tASSERT(pAddr != NULL);\n\t\tif (pAddr == NULL)\n\t\t\treturn false;\n\t\tpAddr->s_addr = INADDR_ANY;" in source


def test_web_socket_shutdown_waits_without_timeout_before_teardown() -> None:
    source = (app_source_root() / "WebSocket.cpp").read_text(encoding="utf-8", errors="ignore")
    seams = (app_source_root() / "WebSocketHttpSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "enum class ESocketThreadShutdownFollowUp" in seams
    assert "GetSocketThreadShutdownFollowUp(const bool bBoundedWaitSucceeded)" in seams
    assert "DebugLogError(_T(\"Web Interface listener thread is still using WebServer state; waiting without a timeout before teardown.\"));" in source
    assert "(void)::WaitForSingleObject(s_pSocketThread->m_hThread, INFINITE);" in source
    assert "DebugLogError(_T(\"Web Interface accepted-client thread(s) are still using WebServer state; waiting without a timeout before teardown.\"));" in source
    assert "(void)WaitForAcceptedThreadHandles(INFINITE);" in source
    assert "Web Interface termination handle kept open because socket threads are still running" not in source
