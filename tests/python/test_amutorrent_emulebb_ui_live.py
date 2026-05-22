from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_ui_live_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "amutorrent-emulebb-ui-live.py"
    spec = importlib.util.spec_from_file_location("amutorrent_emulebb_ui_live_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parser_defaults_to_emulebb_ui_live_options() -> None:
    ui_live = load_ui_live_module()

    args = ui_live.build_parser().parse_args([])

    assert args.configuration == "Debug"
    assert args.api_key == "amutorrent-emulebb-ui-key"
    assert args.p2p_bind_interface_name == "hide.me"
    assert args.rest_webserver_scheme == "https"
    assert args.search_observation_timeout_seconds == 120.0
    assert args.live_wire_inputs_file.endswith("live-wire-inputs.local.json")


def test_composed_helpers_share_rest_smoke_state() -> None:
    ui_live = load_ui_live_module()

    assert ui_live.amutorrent_clean.rest_api_smoke is ui_live.rest_api_smoke
    assert ui_live.amutorrent_resilience.rest_api_smoke is ui_live.rest_api_smoke


def test_emule_category_wait_accepts_unwrapped_items_payload() -> None:
    ui_live = load_ui_live_module()
    original_request = ui_live.rest_api_smoke.http_request
    original_wait_for = ui_live.wait_for
    try:
        ui_live.rest_api_smoke.http_request = lambda *_args, **_kwargs: {
            "status": 200,
            "json": {"items": [{"id": 3, "name": "E2E Release Proof", "path": "incoming"}]},
        }
        ui_live.wait_for = lambda resolve, **_kwargs: resolve()

        result = ui_live.wait_for_emule_category(
            emule_base_url="https://127.0.0.1:4711",
            api_key="key",
            category_name="E2E Release Proof",
            timeout_seconds=1.0,
        )

        assert result["category"]["id"] == 3
        assert result["category"]["path_present"] is True
    finally:
        ui_live.rest_api_smoke.http_request = original_request
        ui_live.wait_for = original_wait_for


def test_ed2k_link_from_transfer_uses_operator_transfer_row() -> None:
    ui_live = load_ui_live_module()

    link = ui_live.ed2k_link_from_transfer(
        {
            "name": "operator-smoke.bin",
            "size": 42,
            "hash": "0123456789ABCDEF0123456789ABCDEF",
        }
    )

    assert link == "ed2k://|file|operator-smoke.bin|42|0123456789abcdef0123456789abcdef|/"


def test_diagnostics_guard_accepts_empty_browser_diagnostics() -> None:
    ui_live = load_ui_live_module()

    ui_live.assert_no_unexpected_browser_diagnostics(
        {"console_errors": [], "page_errors": [], "request_failures": []}
    )


def test_diagnostics_guard_rejects_browser_errors() -> None:
    ui_live = load_ui_live_module()

    try:
        ui_live.assert_no_unexpected_browser_diagnostics(
            {"console_errors": [{"text": "boom"}], "page_errors": [], "request_failures": []}
        )
    except RuntimeError as exc:
        assert "browser diagnostics" in str(exc)
        assert "boom" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("Expected RuntimeError for browser diagnostic errors")


def test_npm_command_prefers_node_sibling_npm(tmp_path: Path) -> None:
    ui_live = load_ui_live_module()
    node_path = tmp_path / "node.exe"
    npm_path = tmp_path / "npm.cmd"
    node_path.write_text("", encoding="utf-8")
    npm_path.write_text("", encoding="utf-8")

    assert ui_live.npm_command_for_node(node_path) == str(npm_path)


def test_ui_live_script_uses_runtime_live_inputs_and_stable_ui_hooks() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "amutorrent-emulebb-ui-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "live_wire_inputs.load_live_wire_inputs" in script_text
    assert "require_kad_connected=False" in script_text
    assert '"linux"' not in script_text
    assert '"ubuntu"' not in script_text
    assert '"debian"' not in script_text
    assert "emulebb-search-submit" in script_text
    assert "emulebb-add-download-submit" in script_text
    assert "client-card-emulebb" in script_text
    assert "dismiss_first_run_version_modal" in script_text
    assert "build_and_verify_frontend_bundle" in script_text
    assert "wait_for_emule_category" in script_text
    assert "emule_rest_category" in script_text
    assert "rest_webserver_scheme" in script_text
    assert "extra_ca_cert" in script_text
    assert "/api/metrics/dashboard?range=24h" in script_text
    assert "/api/metrics/dashboard?range=hour" not in script_text
    assert ".first()" not in script_text
    assert "emulebb-search-result-checkbox" in script_text
    assert ":visible" in script_text
