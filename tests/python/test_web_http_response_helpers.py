from pathlib import Path
from emule_test_harness.paths import get_required_emule_workspace_root as _workspace_root_from_environment


def test_web_compat_responses_use_shared_http_writer() -> None:
    workspace_root = _workspace_root_from_environment()
    app_root = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    helper_text = (app_root / "WebServerHttpResponse.h").read_text(encoding="utf-8")

    assert "SendBody" in helper_text
    assert "Content-Length: %Iu" in helper_text

    for source_name in ("WebServerJson.cpp", "WebServerQBitCompat.cpp", "WebServerArrCompat.cpp"):
        source_text = (app_root / source_name).read_text(encoding="utf-8")
        assert '#include "WebServerHttpResponse.h"' in source_text
        assert "WebServerHttpResponse::Send" in source_text
        assert '"HTTP/1.1 %d %s\\r\\n"' not in source_text
