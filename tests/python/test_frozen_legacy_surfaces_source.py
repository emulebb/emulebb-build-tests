from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_legacy_frozen_surfaces_are_called_out_at_class_boundary() -> None:
    app_root = app_source_root()

    web_server = (app_root / "WebServer.h").read_text(encoding="utf-8", errors="ignore")
    archive_recovery = (app_root / "ArchiveRecovery.h").read_text(encoding="utf-8", errors="ignore")
    archive_preview = (app_root / "ArchivePreviewDlg.h").read_text(encoding="utf-8", errors="ignore")

    assert "FROZEN DEPRECATED SURFACE: this is the legacy HTML/template Web Interface." in web_server
    assert web_server.index("FROZEN DEPRECATED SURFACE") < web_server.index("class CWebServer")
    assert "FROZEN DEPRECATED SURFACE: archive recovery is retained only for legacy" in archive_recovery
    assert archive_recovery.index("FROZEN DEPRECATED SURFACE") < archive_recovery.index("class CArchiveRecovery")
    assert "FROZEN DEPRECATED SURFACE: archive preview UI remains for legacy" in archive_preview
    assert archive_preview.index("FROZEN DEPRECATED SURFACE") < archive_preview.index("class CArchivePreviewDlg")
