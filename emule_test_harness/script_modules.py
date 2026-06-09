"""Helpers for loading operator-facing harness scripts as Python modules."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_script_module(module_name: str, filename: str, *, scripts_dir: Path | None = None):
    """Loads one script from a hyphenated filename under the harness `scripts` directory."""

    root = Path(__file__).resolve().parent.parent
    module_path = (scripts_dir or root / "scripts") / filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
