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


def test_build_search_mode_specs_repeats_all_modes_with_unicode() -> None:
    smoke = load_smoke_module()

    specs = smoke.build_search_mode_specs(2)

    assert [spec["type"] for spec in specs] == ["automatic", "server", "kad", "automatic", "server", "kad"]
    assert [spec["round"] for spec in specs] == ["1", "1", "1", "2", "2", "2"]
    assert any("café" in spec["query"] for spec in specs)


def test_build_search_mode_specs_rejects_zero_rounds() -> None:
    smoke = load_smoke_module()

    with pytest.raises(ValueError, match="greater than zero"):
        smoke.build_search_mode_specs(0)


def test_browser_smoke_stays_on_native_v1_surface() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "amutorrent-browser-smoke.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "/api/v2/" not in script_text
    assert "/api/amule/" not in script_text
    assert "/api/v1/amule/" not in script_text


def test_amutorrent_ed2k_browser_routes_do_not_use_legacy_amule_paths() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    amutorrent_root = workspace_root / "repos" / "amutorrent"
    source_roots = [
        amutorrent_root / "server" / "modules",
        amutorrent_root / "static" / "components",
    ]

    matches: list[str] = []
    for source_root in source_roots:
        for path in source_root.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            if "/api/amule/" in text or "/api/v1/amule/" in text:
                matches.append(str(path.relative_to(amutorrent_root)))

    assert matches == []


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


def test_browser_workflow_validation_ignores_expected_search_conflict_console_noise() -> None:
    smoke = load_smoke_module()
    checks = {"search_modes": [{"start": {"status": 202, "payload": {"type": "search-started"}}}]}
    diagnostics = {
        "console_errors": [
            {
                "text": "Failed to load resource: the server responded with a status of 409 (Conflict)",
                "location": {"url": "http://127.0.0.1:4000/api/v1/search?wait=false"},
            }
        ],
        "page_errors": [],
        "request_failures": [],
    }

    smoke.assert_browser_workflow_results(checks, diagnostics)


def test_browser_workflow_validation_rejects_unexpected_console_errors() -> None:
    smoke = load_smoke_module()
    checks = {"snapshot": {"status": 200, "payload": {"type": "empty"}}}
    diagnostics = {
        "console_errors": [{"text": "ReferenceError: bad", "location": {"url": "http://127.0.0.1:4000/"}}],
        "page_errors": [],
        "request_failures": [],
    }

    with pytest.raises(RuntimeError, match="browser diagnostics"):
        smoke.assert_browser_workflow_results(checks, diagnostics)
