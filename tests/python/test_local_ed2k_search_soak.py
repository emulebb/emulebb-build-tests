from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_suite_module():
    """Loads the hyphenated local ED2K soak script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-ed2k-search-soak.py"
    spec = importlib.util.spec_from_file_location("local_ed2k_search_soak_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_local_soak_defaults_are_bounded_and_local() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.p2p_bind_interface_name == ""
    assert args.search_waves == 3
    assert args.searches_per_wave == 12
    assert args.max_concurrent_searches == 6
    assert args.synthetic_catalog_files == 240
    assert args.fixture_size_bytes == 132 * 1024 * 1024


def test_main_uses_lan_bind_and_staged_server_helper(tmp_path: Path, monkeypatch) -> None:
    module = load_suite_module()
    calls: dict[str, object] = {}
    source_artifacts_dir = tmp_path / "artifacts"
    server_exe = tmp_path / "harness" / "tools" / "goed2k-server.exe"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"")

    def fake_prepare_run_paths(**_kwargs):
        source_artifacts_dir.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            workspace_root=tmp_path / "workspace",
            seed_config_dir=tmp_path / "seed",
            source_artifacts_dir=source_artifacts_dir,
            app_exe=tmp_path / "emulebb.exe",
        )

    def fake_choose_distinct_ports(host: str | None = None) -> dict[str, int]:
        calls["port_host"] = host
        return {
            "ed2k_tcp": 4661,
            "ed2k_admin": 8080,
            "ed2k_udp": 4665,
            "client1_tcp": 4662,
            "client1_udp": 4672,
            "client1_rest": 4711,
            "client2_tcp": 4663,
            "client2_udp": 4673,
        }

    def fake_launch_ed2k_server(**kwargs):
        calls["ed2k_launch"] = kwargs
        raise RuntimeError("stop after staged server helper")

    monkeypatch.setattr(module.harness_cli_common, "prepare_run_paths", fake_prepare_run_paths)
    monkeypatch.setattr(module.harness_cli_common, "publish_run_artifacts", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "publish_latest_report", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "cleanup_source_artifacts", lambda _paths: None)
    monkeypatch.setattr(module.dtt, "discover_interface_ipv4", lambda _name: "192.0.2.77")
    monkeypatch.setattr(module.dtt, "choose_distinct_ports", fake_choose_distinct_ports)
    monkeypatch.setattr(module.goed2k, "launch_ed2k_server", fake_launch_ed2k_server)

    exit_code = module.main(["--lan-bind-addr", "192.0.2.77", "--ed2k-server-exe", str(server_exe)])

    assert exit_code == 1
    assert calls["port_host"] == "192.0.2.77"
    assert calls["ed2k_launch"]["workspace_root"] == tmp_path / "workspace"
    assert calls["ed2k_launch"]["server_dir"] == source_artifacts_dir / "ed2k-server"
    assert calls["ed2k_launch"]["ed2k_port"] == 4661
    assert calls["ed2k_launch"]["admin_port"] == 8080
    assert calls["ed2k_launch"]["token"] == module.API_KEY
    assert calls["ed2k_launch"]["admin_address"] == "192.0.2.77"
    assert calls["ed2k_launch"]["repo_override"] is None
    assert calls["ed2k_launch"]["exe_override"] == str(server_exe)
    assert len(calls["ed2k_launch"]["catalog_files"]) == module.DEFAULT_SYNTHETIC_CATALOG_FILES
    assert calls["ed2k_launch"]["catalog_files"][0]["endpoints"] == [{"host": "192.0.2.77", "port": 4663}]


def test_local_soak_reuses_shared_goed2k_launcher() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "goed2k.launch_ed2k_server(" in script_text
    assert "goed2k.start_ed2k_server(" not in script_text
    assert "goed2k.build_or_skip_ed2k_server_binary(" not in script_text


def test_synthetic_catalog_records_are_deterministic_and_searchable() -> None:
    module = load_suite_module()

    records = module.build_synthetic_catalog_records(10, source_host="10.1.2.3", source_port=4662)

    assert len(records) == 10
    assert records[0]["name"].startswith("local-soak-linux-")
    assert records[0]["hash"] == module.synthetic_hash("local-soak-linux:0")
    assert records[0]["endpoints"] == [{"host": "10.1.2.3", "port": 4662}]
    assert {row["complete_sources"] for row in records} == {1}
    assert len({row["hash"] for row in records}) == 10


def test_run_one_search_retries_transient_url_error(monkeypatch) -> None:
    module = load_suite_module()
    attempts = []

    def fake_start_server_search(_base_url: str, _api_key: str, query: str) -> dict[str, object]:
        attempts.append(query)
        if len(attempts) == 1:
            raise module.urllib.error.URLError("connection reset")
        return {"id": "search-1", "response": {"status": 200}}

    monkeypatch.setattr(module, "start_server_search", fake_start_server_search)
    monkeypatch.setattr(
        module,
        "wait_for_search_results",
        lambda *_args, **_kwargs: {"search": {"results": [{"hash": "A"}]}, "observations": [{"result_count": 1}]},
    )
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.run_one_search("http://192.0.2.10:4711", "key", "local-soak-linux", 1.0)

    assert result["search_id"] == "search-1"
    assert result["result_count"] == 1
    assert result["attempts"] == 2
    assert len(result["retry_failures"]) == 1


def test_run_one_search_retries_direct_connection_reset(monkeypatch) -> None:
    module = load_suite_module()
    attempts = []

    def fake_start_server_search(_base_url: str, _api_key: str, query: str) -> dict[str, object]:
        attempts.append(query)
        if len(attempts) == 1:
            raise ConnectionResetError("reset")
        return {"id": "search-1", "response": {"status": 200}}

    monkeypatch.setattr(module, "start_server_search", fake_start_server_search)
    monkeypatch.setattr(
        module,
        "wait_for_search_results",
        lambda *_args, **_kwargs: {"search": {"results": [{"hash": "A"}]}, "observations": [{"result_count": 1}]},
    )
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.run_one_search("http://192.0.2.10:4711", "key", "local-soak-linux", 1.0)

    assert result["search_id"] == "search-1"
    assert result["attempts"] == 2
    assert result["retry_failures"][0]["type"] == "ConnectionResetError"


def test_write_catalog_uses_server_schema(tmp_path: Path) -> None:
    module = load_suite_module()
    path = tmp_path / "catalog.json"
    records = module.build_synthetic_catalog_records(2, source_host="10.1.2.3", source_port=4662)

    summary = module.write_catalog(path, records)

    assert summary == {"path": str(path), "file_count": 2}
    assert '"files"' in path.read_text(encoding="utf-8")


def test_search_wave_validation_rejects_zero_counts() -> None:
    module = load_suite_module()

    with pytest.raises(ValueError, match="greater than zero"):
        module.run_search_waves(
            base_url="http://127.0.0.1:1",
            api_key="key",
            waves=0,
            searches_per_wave=1,
            max_concurrent_searches=1,
            timeout_seconds=1.0,
        )
