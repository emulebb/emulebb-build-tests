from pathlib import Path


def test_supported_process_launch_paths_use_shared_seam() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_root = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"

    for source_name in ("PartFile.cpp", "Preview.cpp"):
        source_text = (app_root / source_name).read_text(encoding="utf-8")
        assert '#include "ProcessLaunchSeams.h"' in source_text
        assert "::CreateProcess" not in source_text
