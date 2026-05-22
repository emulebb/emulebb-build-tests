"""Runs the deterministic local-ED2K Radarr acquisition check."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def load_shared_runner():
    """Loads the shared Radarr/Sonarr runner from its hyphenated filename."""

    script_path = Path(__file__).resolve().with_name("radarr-sonarr-emulebb-live.py")
    spec = importlib.util.spec_from_file_location("arr_emulebb_local_shared", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load shared Arr runner from '{script_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules["arr_emulebb_local_shared"] = module
    spec.loader.exec_module(module)
    return module


if "--arr-kind" not in sys.argv:
    sys.argv.extend(["--arr-kind", "radarr"])
if "--deterministic-local-ed2k" not in sys.argv:
    sys.argv.append("--deterministic-local-ed2k")
if "--skip-live-seed-refresh" not in sys.argv:
    sys.argv.append("--skip-live-seed-refresh")
if "--p2p-bind-interface-name" not in sys.argv:
    sys.argv.extend(["--p2p-bind-interface-name", ""])

shared = load_shared_runner()

if __name__ == "__main__":
    raise SystemExit(shared.main())
