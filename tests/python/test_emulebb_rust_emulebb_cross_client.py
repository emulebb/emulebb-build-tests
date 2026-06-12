from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_suite_module():
    """Loads the hyphenated Rust/eMuleBB cross-client script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "emulebb-rust-emulebb-cross-client.py"
    spec = importlib.util.spec_from_file_location("emulebb_rust_emulebb_cross_client_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_wait_for_rust_ed2k_connected_reads_canonical_status_stats(monkeypatch) -> None:
    module = load_suite_module()

    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {"stats": {"ed2kConnected": True}},
    )
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    status = module.wait_for_rust_ed2k_connected("http://192.0.2.10:4711", "key", 1.0)

    assert status["stats"]["ed2kConnected"] is True


def test_wait_for_rust_search_result_reads_unwrapped_search_payload(monkeypatch) -> None:
    module = load_suite_module()

    expected_hash = "00112233445566778899aabbccddeeff"
    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {
            "id": "search-1",
            "results": [{"hash": expected_hash.upper(), "name": "fixture.bin"}],
        },
    )
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    result = module.wait_for_rust_search_result(
        "http://192.0.2.10:4711",
        "key",
        query="fixture",
        transfer_hash=expected_hash,
        timeout_seconds=1.0,
    )

    assert result["search"]["id"] == "search-1"
    assert result["result"]["name"] == "fixture.bin"


def test_cross_client_script_uses_shared_goed2k_launcher_boundary() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "goed2k.launch_ed2k_server(" in script_text
    assert "goed2k.resolve_ed2k_server_exe(" not in script_text
    assert "goed2k.build_or_skip_ed2k_server_binary(" not in script_text
    assert "goed2k.build_server_config(" not in script_text
    assert "goed2k.start_ed2k_server(" not in script_text


def test_cross_client_fixture_names_are_unicode() -> None:
    module = load_suite_module()

    assert "Unicode-\u00e9-\u6f22" in module.rust_to_emulebb_fixture_name()
    assert "Unicode-\u00e9-\u6f22" in module.emulebb_to_rust_fixture_name()
    assert not module.rust_to_emulebb_fixture_name().isascii()
    assert not module.emulebb_to_rust_fixture_name().isascii()


def test_decoded_ed2k_link_name_handles_url_escaped_unicode() -> None:
    module = load_suite_module()

    name = module.decoded_ed2k_link_name({"name": "emulebb-to-emulebb-rust-Unicode-%C3%A9-%E6%BC%A2.bin"})

    assert name == "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"


def test_cross_client_requirements_accept_unicode_and_manifest_metadata() -> None:
    module = load_suite_module()

    requirements = module.require_cross_client_requirements(
        {
            "fixture": {"name": "emulebb-rust-to-emulebb-Unicode-\u00e9-\u6f22.bin"},
            "emulebb_fixture": {"name": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"},
            "checks": {
                "rust_emulebb_manifest_metadata": {
                    "canonicalName": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin",
                    "sourceUserHashCount": 1,
                    "md4HashsetCount": 2,
                    "aichHashsetCount": 2,
                }
            },
        }
    )

    assert requirements["bidirectionalTransfers"] is True
    assert requirements["unicodeFixtureNames"] is True
    assert requirements["rustPersistedSourceUserHash"] is True
    assert requirements["rustPersistedMd4Hashset"] is True
    assert requirements["rustPersistedAichHashset"] is True


def test_cross_client_requirements_reject_ascii_fixture_names() -> None:
    module = load_suite_module()

    try:
        module.require_cross_client_requirements(
            {
                "fixture": {"name": "emulebb-rust-to-emulebb.bin"},
                "emulebb_fixture": {"name": "emulebb-to-emulebb-rust.bin"},
                "checks": {
                    "rust_emulebb_manifest_metadata": {
                        "canonicalName": "emulebb-to-emulebb-rust.bin",
                        "sourceUserHashCount": 1,
                        "md4HashsetCount": 2,
                        "aichHashsetCount": 2,
                    }
                },
            }
        )
    except RuntimeError as exc:
        assert "Unicode" in str(exc)
    else:
        raise AssertionError("ASCII cross-client fixture names were accepted")


def test_rust_emulebb_manifest_metadata_requires_md4_aich_and_source_identity(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    manifest_dir = tmp_path / "transfers" / transfer_hash
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "resume-manifest.json").write_text(
        json.dumps(
            {
                "file_hash": transfer_hash,
                "canonical_name": "emulebb-to-emulebb-rust.bin",
                "file_size": module.ED2K_PART_SIZE_BYTES + 1,
                "md4_hashset_acquired": True,
                "md4_hashset": [
                    "0123456789abcdef0123456789abcdef",
                    "fedcba9876543210fedcba9876543210",
                ],
                "aich_hashset_acquired": True,
                "aich_root": "59ba286e4c4b8f0019c9fd89806d7212b37c82d6",
                "aich_hashset": [
                    "044c4a5f2af419cc2b6b06f69f5e3bd655ec6edb",
                    "06fd075b8705ae9189470c69a70e2d5d5593ca09",
                ],
                "sources": [
                    {
                        "ip": "192.0.2.44",
                        "tcp_port": 4662,
                        "user_hash": "31719b50f40e503c1d533d9af3ef6fb8",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    metadata = module.require_rust_download_manifest_metadata(
        tmp_path,
        transfer_hash=transfer_hash,
        expected_name="emulebb-to-emulebb-rust.bin",
        expected_size=module.ED2K_PART_SIZE_BYTES + 1,
        require_aich_hashset=True,
    )

    assert metadata["expectedPartCount"] == 2
    assert metadata["md4HashsetCount"] == 2
    assert metadata["aichHashsetAcquired"] is True
    assert metadata["aichHashsetCount"] == 2
    assert metadata["sourceUserHashCount"] == 1


def test_rust_emulebb_manifest_metadata_rejects_missing_required_aich(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    manifest_dir = tmp_path / "transfers" / transfer_hash
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "resume-manifest.json").write_text(
        json.dumps(
            {
                "file_hash": transfer_hash,
                "canonical_name": "emulebb-to-emulebb-rust.bin",
                "file_size": module.ED2K_PART_SIZE_BYTES,
                "md4_hashset_acquired": True,
                "md4_hashset": ["0123456789abcdef0123456789abcdef"],
                "aich_hashset_acquired": False,
                "aich_hashset": [],
                "sources": [{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="AICH hashset"):
        module.require_rust_download_manifest_metadata(
            tmp_path,
            transfer_hash=transfer_hash,
            expected_name="emulebb-to-emulebb-rust.bin",
            expected_size=module.ED2K_PART_SIZE_BYTES,
            require_aich_hashset=True,
        )


def test_cross_client_uses_shared_goed2k_launcher_and_stops_it_on_failure(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rust_repo = tmp_path / "emulebb-rust"
    rust_repo.mkdir()
    (rust_repo / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    server_process = object()
    calls: dict[str, object] = {"stopped": []}

    paths = SimpleNamespace(
        workspace_root=workspace,
        source_artifacts_dir=tmp_path / "artifacts",
        seed_config_dir=tmp_path / "seed",
        app_exe=tmp_path / "emulebb.exe",
    )
    paths.source_artifacts_dir.mkdir()
    monkeypatch.setattr(module.harness_cli_common, "prepare_run_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(module.harness_cli_common, "write_json_file", lambda path, payload: calls.setdefault("report", payload))
    monkeypatch.setattr(module.harness_cli_common, "publish_run_artifacts", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "publish_latest_report", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "cleanup_source_artifacts", lambda _paths: None)
    monkeypatch.setattr(module, "resolve_manifest_repo", lambda _workspace, key: rust_repo if key == "emulebb_rust" else tmp_path / key)
    monkeypatch.setattr(
        module.dtt,
        "choose_distinct_ports",
        lambda lan_bind_addr: {
            "ed2k_tcp": 4661,
            "ed2k_udp": 4665,
            "ed2k_admin": 8080,
            "client1_rest": 4711,
            "client1_tcp": 4662,
            "client1_udp": 4672,
            "client2_tcp": 5662,
            "client2_udp": 5672,
        },
    )
    monkeypatch.setattr(module, "choose_extra_port", lambda _lan_bind_addr, used_ports, *, udp=False: max(used_ports) + 1)

    def fake_launch_ed2k_server(**kwargs):
        calls["ed2k_launch"] = kwargs
        return SimpleNamespace(
            process=server_process,
            admin_base_url="http://192.0.2.10:8080",
            build={"skipped": True},
            health={"ok": True},
            config={"listen_address": f"{kwargs['ed2k_address']}:{kwargs['ed2k_port']}"},
        )

    monkeypatch.setattr(module.goed2k, "launch_ed2k_server", fake_launch_ed2k_server)
    monkeypatch.setattr(module.goed2k, "stop_process", lambda process: calls["stopped"].append(process))
    monkeypatch.setattr(module.rust_client, "stop_process_tree", lambda process: calls.setdefault("rust_stop", process))
    monkeypatch.setattr(module.dtt, "discover_interface_ipv4", lambda _name: "192.0.2.10")

    def fail_after_goed2k_started(*_args, **_kwargs):
        raise RuntimeError("stop after shared goed2k launch")

    monkeypatch.setattr(module.rust_client, "write_rust_config", fail_after_goed2k_started)

    exit_code = module.main(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "198.51.100.20",
        ]
    )

    assert exit_code == 1
    assert calls["ed2k_launch"]["admin_address"] == "192.0.2.10"
    assert calls["ed2k_launch"]["ed2k_address"] == "198.51.100.20"
    assert calls["stopped"] == [server_process]
    assert calls["report"]["current_phase"] == "start_ed2k_server"
    assert calls["report"]["network"]["lan_bind_addr"] == "192.0.2.10"
    assert calls["report"]["network"]["p2p_bind_interface_address"] == "198.51.100.20"
    assert calls["report"]["network"]["server_endpoint"] == "198.51.100.20:4661"
