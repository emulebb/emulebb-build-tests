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


def test_configure_emule_crash_dump_mode_forces_automatic_dump(tmp_path: Path) -> None:
    module = load_script_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text("[eMule]\nCreateCrashDump=0\n", encoding="utf-16")

    result = module.configure_emule_crash_dump_mode(config_dir, 2)

    text = module.rest_smoke.live_common.read_ini_text(preferences_path)
    assert result["create_crash_dump"] == 2
    assert "CreateCrashDump=2" in text


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


def test_collect_dumps_in_directory_reports_non_empty_dumps(tmp_path: Path) -> None:
    module = load_script_module()
    (tmp_path / "emulebb-crash.dmp").write_bytes(b"dump")

    result = module.collect_dumps_in_directory(tmp_path)

    assert result["count"] == 1
    assert result["files"][0]["name"] == "emulebb-crash.dmp"
    assert result["files"][0]["size_bytes"] == 4


def test_dump_channel_summary_does_not_count_manual_dump_as_crash_dump(tmp_path: Path) -> None:
    module = load_script_module()
    manual_dump = tmp_path / "manual.dmp"
    manual_dump.write_bytes(b"manual")

    summary = module.build_dump_channel_summary(
        {
            "manual_dump": {"ok": True, "dump_path": str(manual_dump)},
            "process_exit": {"ok": True},
            "process_stopped": {"ok": True},
            "local_dump": {"emule_dumps": []},
            "procdump_dump_files": {"files": []},
            "app_crash_dump_files": {
                "files": [
                    {
                        "name": manual_dump.name,
                        "path": str(manual_dump),
                        "size_bytes": manual_dump.stat().st_size,
                    }
                ]
            },
        }
    )

    assert summary["manual_dump_ok"] is True
    assert summary["manual_dump_excluded_from_app_crash_count"] == 1
    assert summary["app_crash_dump_count"] == 0
    assert summary["crash_dump_count"] == 0


def test_dump_channel_summary_counts_independent_crash_channels(tmp_path: Path) -> None:
    module = load_script_module()
    manual_dump = tmp_path / "manual.dmp"
    app_crash_dump = tmp_path / "emule-crash.dmp"
    procdump_crash_dump = tmp_path / "emule-procdump.dmp"
    for path in (manual_dump, app_crash_dump, procdump_crash_dump):
        path.write_bytes(b"dump")

    summary = module.build_dump_channel_summary(
        {
            "manual_dump": {"ok": True, "dump_path": str(manual_dump)},
            "process_exit": {"ok": True},
            "process_stopped": {"ok": True},
            "local_dump": {"emule_dumps": [{"name": "emule.exe.1234.dmp", "size_bytes": 4096}]},
            "procdump_dump_files": {
                "files": [{"name": procdump_crash_dump.name, "path": str(procdump_crash_dump), "size_bytes": 4}]
            },
            "app_crash_dump_files": {
                "files": [
                    {"name": manual_dump.name, "path": str(manual_dump), "size_bytes": 4},
                    {"name": app_crash_dump.name, "path": str(app_crash_dump), "size_bytes": 4},
                ]
            },
        }
    )

    assert summary["wer_emule_dump_count"] == 1
    assert summary["procdump_dump_count"] == 1
    assert summary["app_crash_dump_count"] == 1
    assert summary["crash_dump_count"] == 3
