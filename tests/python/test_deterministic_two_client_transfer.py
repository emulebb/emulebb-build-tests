from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated deterministic transfer script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "deterministic-two-client-transfer.py"
    spec = importlib.util.spec_from_file_location("deterministic_two_client_transfer_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_resolve_manifest_repo_uses_workspace_deps(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    repo = tmp_path / "repos" / "emulebb-ed2k-server"
    workspace.mkdir(parents=True)
    repo.mkdir(parents=True)
    (repo / "go.mod").write_text("module example\n", encoding="utf-8")
    (workspace / "deps.json").write_text(
        json.dumps({"workspace": {"repos": {"ed2k_server": "..\\..\\repos\\emulebb-ed2k-server"}}}),
        encoding="utf-8",
    )

    assert module.resolve_manifest_repo(workspace, "ed2k_server") == repo.resolve()
    assert module.resolve_ed2k_server_repo(workspace, None) == repo.resolve()


def test_resolve_ed2k_server_exe_defaults_to_workspace_state(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"

    resolved = module.resolve_ed2k_server_exe(workspace, None)

    assert resolved == (workspace / "state" / "tools" / "emulebb-ed2k-server" / "overlord-ed2k-server.exe").resolve()


def test_write_server_met_creates_dynamic_ip_single_server(tmp_path: Path) -> None:
    module = load_suite_module()
    server_met = tmp_path / "profile" / "config" / "server.met"

    module.write_server_met(server_met, address="10.44.55.66", port=4711, name="local-ed2k")

    data = server_met.read_bytes()
    assert data[:5] == struct.pack("<BI", module.SERVER_MET_HEADER, 1)
    ip, port, tag_count = struct.unpack("<IHI", data[5:15])
    assert ip == 0
    assert port == 4711
    assert tag_count == 3
    assert b"local-ed2k" in data
    assert b"10.44.55.66" in data


def test_build_server_config_uses_workspace_artifact_paths(tmp_path: Path) -> None:
    module = load_suite_module()
    config_path = tmp_path / "state" / "artifacts" / "server" / "config.json"
    catalog_path = tmp_path / "state" / "artifacts" / "server" / "catalog.json"

    config = module.build_server_config(
        config_path,
        ed2k_port=4661,
        admin_port=8080,
        catalog_path=catalog_path,
        token="secret",
    )

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload == config
    assert payload["listen_address"] == "0.0.0.0:4661"
    assert payload["admin_listen_address"] == "127.0.0.1:8080"
    assert payload["catalog_path"] == str(catalog_path)


def test_parse_exported_ed2k_file_link() -> None:
    module = load_suite_module()

    parsed = module.parse_ed2k_file_link(
        "ed2k://|file|fixture.bin|123|0123456789ABCDEF0123456789ABCDEF|/|sources,10.1.2.3:4662|/"
    )

    assert parsed == {
        "name": "fixture.bin",
        "size": 123,
        "hash": "0123456789abcdef0123456789abcdef",
    }


def test_write_fixture_file_is_deterministic(tmp_path: Path) -> None:
    module = load_suite_module()
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = module.write_fixture_file(first, 4097)
    second_hash = module.write_fixture_file(second, 4097)

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == module.file_sha256(first)


def test_build_client2_harness_args_uses_single_dash_parser_form(tmp_path: Path) -> None:
    module = load_suite_module()

    args = module.build_client2_harness_args(
        ready_path=tmp_path / "ready.txt",
        fixture_file=tmp_path / "shared.bin",
        export_link_path=tmp_path / "link.txt",
        source_ip="10.1.2.3",
    )

    assert args[0::2] == ["-readyfile", "-sharefile", "-exportlinkfile", "-exportsourceip"]
    assert "--sharefile" not in args


def test_configure_client_profile_disables_private_server_filter(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(
        config_dir / "preferences.ini",
        "[eMule]\nFilterBadIPs=1\nIPFilterEnabled=1\n[WebServer]\nEnabled=0\n",
    )

    module.configure_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emule.exe",
        nick="client1",
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=False,
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "FilterBadIPs=0" in emule_section
    assert "IPFilterEnabled=0" in emule_section
    assert "CommitFiles=2" in emule_section
    assert "FileBufferSize=16384" in emule_section
    assert "FileBufferTimeLimit=1" in emule_section
    assert "AllocateFullFile=0" in emule_section
    assert "SparsePartFiles=0" in emule_section
    assert "Nick=client1" in emule_section


def test_add_and_connect_server_reuses_preloaded_server(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        if path == "/api/v1/servers":
            return {"status": 200, "json": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}
        return {"status": 200, "json": {"connected": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(
        module.rest_smoke,
        "require_json_array",
        lambda result, _status: list(result["json"]),
    )
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: dict(result["json"]))
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(
        module.rest_smoke,
        "wait_for_server_connected",
        lambda *_args, **_kwargs: {"connected": True},
    )

    result = module.add_and_connect_server(
        "http://127.0.0.1:4711",
        "key",
        address="10.1.2.3",
        port=4661,
        timeout_seconds=1.0,
    )

    assert result["add"]["preloaded"] is True
    assert ("POST", "/api/v1/servers") not in calls
    assert ("POST", "/api/v1/servers/10.1.2.3:4661/operations/connect") in calls


def test_wait_for_completed_file_timeout_carries_diagnostic_observations(tmp_path: Path) -> None:
    module = load_suite_module()
    snapshots = [{"transfer": {"status": 200, "json": {"state": "downloading"}}}]

    try:
        module.wait_for_completed_file(
            tmp_path / "incoming" / "fixture.bin",
            expected_size=10,
            expected_sha256="0" * 64,
            timeout_seconds=0.0,
            snapshot_callback=lambda: snapshots[0],
        )
    except module.TransferCompletionTimeout as exc:
        assert exc.observations[-1]["snapshot"] == snapshots[0]
    else:
        raise AssertionError("Expected TransferCompletionTimeout")


def test_collect_client1_transfer_snapshot_records_rest_and_workspace_files(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    incoming_dir = tmp_path / "incoming"
    temp_dir = tmp_path / "temp"
    incoming_dir.mkdir()
    temp_dir.mkdir()
    part_file = temp_dir / "001.part"
    part_file.write_bytes(b"abc")
    requested_paths: list[str] = []

    def fake_http_request(_base_url, path, **_kwargs):
        requested_paths.append(path)
        return {"status": 200, "content_type": "application/json", "json": {"path": path}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    snapshot = module.collect_client1_transfer_snapshot(
        base_url="http://127.0.0.1:4711",
        api_key="key",
        transfer_hash="a" * 32,
        incoming_path=incoming_dir / "fixture.bin",
        temp_dir=temp_dir,
        hash_limit_bytes=10,
    )

    assert requested_paths == [
        "/api/v1/transfers/" + "a" * 32,
        "/api/v1/transfers/" + "a" * 32 + "/details",
        "/api/v1/transfers/" + "a" * 32 + "/sources",
    ]
    assert snapshot["incoming_file"]["exists"] is False
    assert snapshot["temp_dir"][0]["sha256"] == module.file_sha256(part_file)
