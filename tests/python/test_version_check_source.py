from __future__ import annotations

from pathlib import Path


def _app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_version_check_worker_does_not_keep_raw_dialog_queue_pointer() -> None:
    source_root = _app_source_root()
    emule_dlg_cpp = (source_root / "EmuleDlg.cpp").read_text(encoding="utf-8", errors="ignore")
    emule_dlg_h = (source_root / "EmuleDlg.h").read_text(encoding="utf-8", errors="ignore")
    seams = (source_root / "VersionCheckLaunchSeams.h").read_text(encoding="utf-8", errors="ignore")

    assert "std::shared_ptr<VersionCheckLaunchSeams::SQueuedState> m_pVersionCheckState" in emule_dlg_h
    assert "std::shared_ptr<VersionCheckLaunchSeams::SQueuedState> pQueuedState" in emule_dlg_cpp
    assert "volatile LONG\tm_lVersionCheckQueued" not in emule_dlg_h
    assert "plQueued" not in emule_dlg_cpp
    assert "ClearQueuedOnOwnerTeardown(m_pVersionCheckState)" in emule_dlg_cpp
    assert "struct SQueuedState" in seams
    assert "PostCompletion(HWND hNotifyWnd, UINT uMessage, LPARAM lParam, const std::shared_ptr<SQueuedState>& pState)" in seams
    assert "volatile LONG *" not in seams
