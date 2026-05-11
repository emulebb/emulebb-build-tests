"""Runs the live Radarr acquisition check through Prowlarr and eMule BB."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_combined_module():
    """Loads the shared Arr live implementation from the legacy script filename."""

    script_path = Path(__file__).resolve().with_name("radarr-sonarr-emulebb-live.py")
    spec = importlib.util.spec_from_file_location("arr_emulebb_live_shared", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load shared Arr live implementation from '{script_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules["arr_emulebb_live_shared"] = module
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    if "--arr-kind" not in sys.argv:
        sys.argv.extend(["--arr-kind", "radarr"])
    raise SystemExit(load_combined_module().main())
