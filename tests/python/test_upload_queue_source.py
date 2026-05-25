from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_upload_queue_position_helpers_reject_null_positions() -> None:
    source = (app_source_root() / "UploadQueue.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pos != NULL);\n\tif (pUploadClientStruct == NULL || pos == NULL)\n\t\treturn {NULL};" in source
    assert "ASSERT(pos != NULL);\n\tif (pUploadClientStruct == NULL || pClient == NULL || pos == NULL)\n\t\treturn;" in source
    assert "ASSERT(pos != NULL);\n\tif (pUploadClientStruct == NULL || pos == NULL)\n\t\treturn;" in source
    assert "void CUploadQueue::RemoveFromWaitingQueue(POSITION pos, bool updatewindow)\n{\n\tASSERT(pos != NULL);\n\tif (pos == NULL)\n\t\treturn;" in source
    assert "void CUploadQueue::RemoveStaleWaitingClient(POSITION pos)\n{\n\tASSERT(pos != NULL);\n\tif (pos == NULL)\n\t\treturn;" in source
    assert "CUpDownClient* CUploadQueue::GetQueueClientAt(POSITION &curpos) const\n{\n\tif (curpos == NULL)\n\t\treturn NULL;" in source
    assert "CUpDownClient* CUploadQueue::GetWaitClientAt(POSITION &curpos) const\n{\n\tif (curpos == NULL)\n\t\treturn NULL;" in source
