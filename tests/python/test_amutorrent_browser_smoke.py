from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_smoke_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "amutorrent-browser-smoke.py"
    spec = importlib.util.spec_from_file_location("amutorrent_browser_smoke_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_node_major_accepts_node_version() -> None:
    smoke = load_smoke_module()

    assert smoke.parse_node_major("v22.14.0") == 22
    assert smoke.parse_node_major("20.11.1") == 20


def test_require_server_dependencies_reports_install_command(tmp_path: Path) -> None:
    smoke = load_smoke_module()
    root = tmp_path / "amutorrent"
    (root / "server" / "node_modules" / "express").mkdir(parents=True)
    node_info = {"install_command": r'"C:\bin\nodejs-v22-old\npm.cmd" ci --prefix server --omit=dev'}

    with pytest.raises(RuntimeError, match="better-sqlite3"):
        smoke.require_amutorrent_server_dependencies(root, node_info)


def test_require_server_dependencies_passes_when_runtime_modules_exist(tmp_path: Path) -> None:
    smoke = load_smoke_module()
    root = tmp_path / "amutorrent"
    (root / "server" / "node_modules" / "express").mkdir(parents=True)
    (root / "server" / "node_modules" / "better-sqlite3").mkdir(parents=True)

    smoke.require_amutorrent_server_dependencies(root, {"install_command": "npm ci --prefix server --omit=dev"})


def test_browser_workflow_validation_walks_nested_results() -> None:
    smoke = load_smoke_module()
    checks = {
        "search_modes": [
            {
                "start": {"status": 200, "payload": {"type": "search-started"}},
                "results": {"status": 200, "payload": {"type": "previous-search-results", "data": []}},
            },
            {
                "start": {"status": 404, "payload": {"error": "not present"}},
                "results": {"status": 200, "payload": {"type": "previous-search-results", "data": []}},
            },
        ]
    }

    smoke.assert_browser_workflow_results(checks, {"console_errors": [], "page_errors": [], "request_failures": []})


def test_browser_workflow_validation_rejects_nested_server_errors() -> None:
    smoke = load_smoke_module()
    checks = {"search_modes": [{"start": {"status": 503, "payload": {"error": "offline"}}}]}

    with pytest.raises(RuntimeError, match=r"search_modes\[0\]\.start"):
        smoke.assert_browser_workflow_results(checks, {"console_errors": [], "page_errors": [], "request_failures": []})


def test_browser_workflow_validation_rejects_nested_error_payloads() -> None:
    smoke = load_smoke_module()
    checks = {"search_modes": [{"start": {"status": 200, "payload": {"type": "error", "message": "bad"}}}]}

    with pytest.raises(RuntimeError, match=r"search_modes\[0\]\.start"):
        smoke.assert_browser_workflow_results(checks, {"console_errors": [], "page_errors": [], "request_failures": []})
