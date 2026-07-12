from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_report_module():
    script_path = REPO_ROOT / "scripts" / "report-rust-soak-profile.py"
    spec = importlib.util.spec_from_file_location("report_rust_soak_profile_under_test", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_reporter_reads_missing_json_as_empty(tmp_path: Path) -> None:
    module = load_report_module()

    assert module.read_json(tmp_path / "missing.json") == {}


def test_reporter_parser_defaults_to_soak_api_key() -> None:
    module = load_report_module()
    args = module.build_parser().parse_args([])

    assert args.api_key == "converged-soak"
    assert args.rest_base_url == ""
