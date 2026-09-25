"""Windows-native direct/UPnP entrypoint for the shared Rust direct smoke runner."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.script_modules import load_script_module  # noqa: E402

direct_smoke = load_script_module("rust_direct_smoke_for_windows", "rust-linux-direct-smoke.py")


if __name__ == "__main__":
    raise SystemExit(direct_smoke.main(["--native-windows", "--enable-upnp", *sys.argv[1:]]))
