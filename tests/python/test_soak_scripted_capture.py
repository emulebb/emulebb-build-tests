"""Unit tests for the solo scripted-capture launcher (scripts/soak-scripted-capture.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CAPTURE_SCRIPT = REPO_ROOT / "scripts" / "soak-scripted-capture.py"


def _load_capture() -> ModuleType:
    spec = importlib.util.spec_from_file_location("soak_scripted_capture_script", CAPTURE_SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_capture_secident_knob_defaults_on() -> None:
    module = _load_capture()

    args = module.build_parser().parse_args(["--client", "mfc"])
    assert args.secident == "on"

    off_args = module.build_parser().parse_args(["--client", "mfc", "--secident", "off"])
    assert off_args.secident == "off"
