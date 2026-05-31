from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_resilience_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "amutorrent-resilience-live.py"
    spec = importlib.util.spec_from_file_location("amutorrent_resilience_live_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parser_defaults_to_resilience_live_options() -> None:
    resilience = load_resilience_module()

    args = resilience.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.configuration == "Debug"
    assert args.lan_bind_addr == "192.0.2.10"
    assert args.api_key == "amutorrent-resilience-key"
    assert args.p2p_bind_interface_name == "hide.me"
    assert args.rest_webserver_scheme == "https"
    assert args.reconnect_timeout_seconds == 120.0
    assert args.live_wire_inputs_file.endswith("live-wire-inputs.local.json")


def test_config_test_failure_requires_clean_emulebb_failure_payload() -> None:
    resilience = load_resilience_module()

    assert resilience.is_config_test_failure(
        {
            "status": 200,
            "payload": {
                "success": False,
                "results": {"emulebb": {"success": False, "error": "Unauthorized"}},
            },
        }
    )
    assert not resilience.is_config_test_failure(
        {
            "status": 200,
            "payload": {
                "success": True,
                "results": {"emulebb": {"success": True}},
            },
        }
    )
    assert not resilience.is_config_test_failure({"status": 500, "payload": {"success": False}})


def test_build_saved_config_with_key_updates_only_expected_client() -> None:
    resilience = load_resilience_module()
    current = {
        "server": {"auth": {"enabled": False}},
        "clients": [
            {"id": "emulebb-127.0.0.1-4711", "type": "emulebb", "host": "127.0.0.1", "port": 4711, "apiKey": "old"},
            {"id": "qbittorrent-main", "type": "qbittorrent", "host": "127.0.0.1", "port": 8080},
        ],
    }

    updated = resilience.build_saved_config_with_key(
        current,
        instance_id="emulebb-127.0.0.1-4711",
        host="127.0.0.1",
        port=4777,
        api_key="new-key",
        use_ssl=True,
    )

    assert updated["clients"][0]["apiKey"] == "new-key"
    assert updated["clients"][0]["port"] == 4777
    assert updated["clients"][0]["useSsl"] is True
    assert updated["clients"][0]["type"] == "emulebb"
    assert updated["clients"][1] == current["clients"][1]
    assert current["clients"][0]["apiKey"] == "old"


def test_find_client_config_reports_missing_instance() -> None:
    resilience = load_resilience_module()

    try:
        resilience.find_client_config({"clients": []}, instance_id="missing")
    except RuntimeError as exc:
        assert "missing" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("Expected RuntimeError for missing client")


def test_resilience_script_does_not_hardcode_runtime_live_terms() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "amutorrent-resilience-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "live_wire_inputs.load_live_wire_inputs" in script_text
    assert script_text.count("require_kad_connected=False") == 2
    assert '"linux"' not in script_text
    assert '"ubuntu"' not in script_text
    assert '"debian"' not in script_text


def test_resilience_uses_lan_bind_for_runtime_urls() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "amutorrent-resilience-live.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "lan_host = rest_api_smoke.rest_base_host_for_lan_bind_addr(args.lan_bind_addr)" in script_text
    assert 'emule_base_url = f"{rest_scheme}://{lan_host}:{emule_port}"' in script_text
    assert 'amutorrent_base_url = f"http://{lan_host}:{amutorrent_port}"' in script_text
    assert "emule_host=lan_host" in script_text
