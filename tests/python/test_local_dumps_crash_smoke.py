from __future__ import annotations

import importlib.util
from pathlib import Path


def load_script_module():
    """Loads the hyphenated LocalDumps crash smoke script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "local-dumps-crash-smoke.py"
    spec = importlib.util.spec_from_file_location("local_dumps_crash_smoke_test_module", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_script_help_loads() -> None:
    module = load_script_module()
    help_text = module.build_parser().format_help()

    assert "--dump-timeout-seconds" in help_text
    assert "--p2p-bind-interface-name" in help_text


def test_trigger_crash_records_expected_disconnect(monkeypatch) -> None:
    module = load_script_module()

    def fake_http_request(*_args, **_kwargs):
        raise ConnectionResetError(10054, "connection reset")

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    result = module.trigger_crash("http://127.0.0.1:1", "api-key", 1.0)

    assert result["request_completed"] is False
    assert result["exception"]["type"] == "ConnectionResetError"


def test_wait_for_emule_local_dump_accepts_non_empty_dump(monkeypatch) -> None:
    module = load_script_module()

    monkeypatch.setattr(
        module.harness_cli_common,
        "collect_local_dump_files",
        lambda _local_dumps: {"files": [{"name": "emule.exe.1234.dmp", "size_bytes": 4096}]},
    )

    result = module.wait_for_emule_local_dump({"dump_folder": "unused"}, 1.0)

    assert result["ok"] is True
    assert result["emule_dumps"][0]["name"] == "emule.exe.1234.dmp"
