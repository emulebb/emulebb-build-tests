from __future__ import annotations

from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main"


def test_connect_completion_revalidates_socket_after_on_connect_callback() -> None:
    source = (APP_ROOT / "srchybrid" / "AsyncSocketEx.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool IsCurrentSocket(const CAsyncSocketEx *pSocket, int nSocketIndex, SOCKET hSocket) const" in source
    assert "pSocket->OnConnect(nErrorCode);\n\t\t\t\t\t\t\t// WHY: server connect failures can synchronously" in source
    assert "if (!pWnd->IsCurrentSocket(pSocket, nSocketIndex, hSocket))\n\t\t\t\t\t\t\t\tbreak;" in source
    assert "if (pWnd->IsCurrentSocket(pSocket, nSocketIndex, hSocket))\n\t\t\t\t\t\t\tpSocket->m_nPendingEvents = 0;" in source
    assert "pSocket->OnConnect(nErrorCode);\n\t\t\t\t\t\t\t// WHY: OnConnect handlers may close and delete" in source
    assert "if (!pWnd->IsCurrentSocket(pSocket, nSocketIndex, pMsg->hSocket))\n\t\t\t\t\t\t\t\tbreak;" in source
    assert "if (pWnd->IsCurrentSocket(pSocket, nSocketIndex, pMsg->hSocket))\n\t\t\t\t\t\t\tpSocket->m_nPendingEvents = 0;" in source
