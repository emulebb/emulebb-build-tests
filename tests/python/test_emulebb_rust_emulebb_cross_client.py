from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[3] / "emulebb-rust"


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
            "status": "complete",
            "items": [{"hash": expected_hash.upper(), "name": "fixture.bin"}],
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


def test_cross_client_disables_rust_kad_by_default() -> None:
    module = load_suite_module()

    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.rust_kad_enabled is False


def test_local_kad_diagnostics_audit_rejects_nonlocal_contacts(tmp_path: Path) -> None:
    module = load_suite_module()
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    rust_dir.mkdir()
    mfc_dir.mkdir()
    packet = rust_dir / "emulebb-rust-kad-udp-dump-test.jsonl"
    contact = mfc_dir / "emulebb-diagnostics-kad.log"
    packet.write_text(json.dumps({"schema": "udp_packet_v1", "peer": "10.1.2.3:4000"}) + "\n", encoding="utf-8")
    contact.write_text(json.dumps({"contact": {"address": "10.1.2.3"}}) + "\n", encoding="utf-8")
    assert module.audit_local_kad_diagnostics(rust_dir, mfc_dir, expected_ip="10.1.2.3") == {
        "rustPackets": 1, "mfcContacts": 1,
    }

    packet.write_text(json.dumps({"schema": "udp_packet_v1", "peer": "8.8.8.8:4000"}) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="nonlocal peer"):
        module.audit_local_kad_diagnostics(rust_dir, mfc_dir, expected_ip="10.1.2.3")
    packet.write_text(json.dumps({"schema": "udp_packet_v1", "peer": "10.1.2.3:4000"}) + "\n", encoding="utf-8")
    contact.write_text(json.dumps({"contact": {"address": "8.8.8.8"}}) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="nonlocal contact"):
        module.audit_local_kad_diagnostics(rust_dir, mfc_dir, expected_ip="10.1.2.3")


def test_local_kad_exchange_requires_decoded_two_way_bootstrap(tmp_path: Path) -> None:
    module = load_suite_module()
    dump = tmp_path / "emulebb-rust-kad-udp-dump-test.jsonl"
    pairs = [
        ("send", "KADEMLIA2_BOOTSTRAP_REQ"),
        ("recv", "KADEMLIA2_BOOTSTRAP_REQ"),
        ("send", "KADEMLIA2_BOOTSTRAP_RES"),
    ]
    dump.write_text("".join(json.dumps({"schema": "udp_packet_v1", "direction": direction,
                                        "opcode_name": opcode}) + "\n" for direction, opcode in pairs), encoding="utf-8")
    assert module.local_kad_exchange_evidence(tmp_path) is None
    with dump.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"schema": "udp_packet_v1", "direction": "recv",
                                 "opcode_name": "KADEMLIA2_BOOTSTRAP_RES"}) + "\n")
    assert module.local_kad_exchange_evidence(tmp_path) == {
        f"{direction}:{opcode}": 1 for direction, opcode in pairs + [("recv", "KADEMLIA2_BOOTSTRAP_RES")]
    }


def test_cross_client_shared_root_uses_current_object_contract(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls = []
    monkeypatch.setattr(module, "request_json", lambda *args, **kwargs: calls.append((args, kwargs)) or {})
    monkeypatch.setattr(module, "wait_for_rust_shared_file", lambda *_args, **_kwargs: {"name": "fixture.bin"})

    module.publish_rust_shared_tree(
        "http://192.0.2.10:4711", "key", root=tmp_path, file_name="fixture.bin", timeout_seconds=1.0,
    )

    assert calls[0][0][4]["roots"] == [{"path": str(tmp_path)}]


def test_cross_client_diagnostics_require_both_peer_dumps(tmp_path: Path) -> None:
    module = load_suite_module()
    rust = tmp_path / "rust"
    mfc = tmp_path / "mfc"
    rust.mkdir()
    mfc.mkdir()

    with pytest.raises(RuntimeError, match="rust diagnostics"):
        module.require_diagnostics(rust, mfc, kad_required=False)


def test_cross_client_rejects_mfc_secure_ident_failure(tmp_path: Path) -> None:
    module = load_suite_module()
    log = tmp_path / "emulebb-verbose.log"
    log.write_text("Connected to local peer\n", encoding="utf-8")
    assert module.require_mfc_secure_ident_clean(log) == {"failureLines": 0}
    log.write_text("Error: Unknown exception in CClientCreditsList::VerifyIdent\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="rejected Rust secure identification"):
        module.require_mfc_secure_ident_clean(log)


def test_cross_client_fixture_names_are_unicode() -> None:
    module = load_suite_module()

    assert "Unicode-\u00e9-\u6f22" in module.rust_to_emulebb_fixture_name()
    assert "Unicode-\u00e9-\u6f22" in module.rust_shared_tree_fixture_name()
    assert "Unicode-\u00e9-\u6f22" in module.emulebb_to_rust_fixture_name()
    assert not module.rust_to_emulebb_fixture_name().isascii()
    assert not module.rust_shared_tree_fixture_name().isascii()
    assert not module.emulebb_to_rust_fixture_name().isascii()


def test_cross_client_validate_optional_soak_args_accepts_upload_limits() -> None:
    module = load_suite_module()
    args = SimpleNamespace(
        rust_upload_limit_kibps=64,
        emulebb_upload_limit_kibps=64,
    )

    module.validate_optional_soak_args(args)


def test_cross_client_validate_optional_soak_args_rejects_bad_upload_limit() -> None:
    module = load_suite_module()
    args = SimpleNamespace(
        rust_upload_limit_kibps=0,
        emulebb_upload_limit_kibps=None,
    )

    with pytest.raises(ValueError, match="rust-upload-limit-kibps"):
        module.validate_optional_soak_args(args)


def test_decoded_ed2k_link_name_handles_url_escaped_unicode() -> None:
    module = load_suite_module()

    name = module.decoded_ed2k_link_name({"name": "emulebb-to-emulebb-rust-Unicode-%C3%A9-%E6%BC%A2.bin"})

    assert name == "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"


def test_completed_incoming_path_uses_decoded_unicode_name(tmp_path: Path) -> None:
    module = load_suite_module()

    path = module.completed_incoming_path(
        tmp_path, {"name": "emulebb-rust-shared-tree-Unicode-%C3%A9-%E6%BC%A2.bin"}
    )

    assert path == tmp_path / "emulebb-rust-shared-tree-Unicode-\u00e9-\u6f22.bin"
    with pytest.raises(ValueError, match="safe local filename"):
        module.completed_incoming_path(tmp_path, {"name": "..%2Fescape.bin"})


def test_cross_client_requirements_accept_unicode_and_manifest_metadata() -> None:
    module = load_suite_module()
    shared_tree_name = "emulebb-rust-shared-tree-Unicode-\u00e9-\u6f22.bin"

    requirements = module.require_cross_client_requirements(
        {
            "fixture": {"name": "emulebb-rust-to-emulebb-Unicode-\u00e9-\u6f22.bin"},
            "emulebb_fixture": {"name": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"},
            "rust_shared_tree": {"name": shared_tree_name, "recursive": True},
            "checks": {
                "rust_shared_tree_publish": {
                    "sharedFiles": {
                        "matched": {
                            "name": shared_tree_name,
                            "ed2kLink": "ed2k://|file|fixture.bin|1|00112233445566778899aabbccddeeff|/",
                        }
                    }
                },
                "rust_emulebb_manifest_metadata": {
                    "canonicalName": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin",
                    "sourceUserHashCount": 1,
                    "expectedHashsetCount": 2,
                    "md4HashsetAcquired": True,
                    "md4HashsetCount": 2,
                    "aichHashsetAcquired": True,
                    "aichHashsetCount": 2,
                }
            },
        }
    )

    assert requirements["bidirectionalTransfers"] is True
    assert requirements["unicodeFixtureNames"] is True
    assert requirements["recursiveSharedTreeUpload"] is True
    assert requirements["rustPersistedSourceUserHash"] is True
    assert requirements["rustPersistedMd4Hashset"] is True
    assert requirements["rustPersistedAichHashset"] is True


def test_cross_client_requirements_accept_single_part_empty_hashsets() -> None:
    module = load_suite_module()
    shared_tree_name = "emulebb-rust-shared-tree-Unicode-\u00e9-\u6f22.bin"

    requirements = module.require_cross_client_requirements(
        {
            "fixture": {"name": "emulebb-rust-to-emulebb-Unicode-\u00e9-\u6f22.bin"},
            "emulebb_fixture": {"name": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"},
            "rust_shared_tree": {"name": shared_tree_name, "recursive": True},
            "checks": {
                "rust_shared_tree_publish": {"sharedFiles": {"matched": {"name": shared_tree_name}}},
                "rust_emulebb_manifest_metadata": {
                    "canonicalName": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin",
                    "sourceUserHashCount": 1,
                    "expectedHashsetCount": 0,
                    "md4HashsetAcquired": True,
                    "md4HashsetCount": 0,
                    "aichHashsetAcquired": True,
                    "aichHashsetCount": 0,
                },
            },
        }
    )

    assert requirements["rustPersistedMd4Hashset"] is True
    assert requirements["rustPersistedAichHashset"] is True


def test_cross_client_requirements_reject_ascii_fixture_names() -> None:
    module = load_suite_module()

    try:
        module.require_cross_client_requirements(
            {
                "fixture": {"name": "emulebb-rust-to-emulebb.bin"},
                "emulebb_fixture": {"name": "emulebb-to-emulebb-rust.bin"},
                "rust_shared_tree": {"name": "emulebb-rust-shared-tree.bin", "recursive": True},
                "checks": {
                    "rust_shared_tree_publish": {
                        "sharedFiles": {
                            "matched": {
                                "name": "emulebb-rust-shared-tree.bin",
                                "ed2kLink": "ed2k://|file|fixture.bin|1|00112233445566778899aabbccddeeff|/",
                            }
                        }
                    },
                    "rust_emulebb_manifest_metadata": {
                        "canonicalName": "emulebb-to-emulebb-rust.bin",
                        "sourceUserHashCount": 1,
                        "expectedHashsetCount": 2,
                        "md4HashsetAcquired": True,
                        "md4HashsetCount": 2,
                        "aichHashsetAcquired": True,
                        "aichHashsetCount": 2,
                    }
                },
            }
        )
    except RuntimeError as exc:
        assert "Unicode" in str(exc)
    else:
        raise AssertionError("ASCII cross-client fixture names were accepted")


def test_write_rust_shared_tree_fixture_uses_nested_recursive_fixture(tmp_path: Path) -> None:
    module = load_suite_module()

    fixture = module.write_rust_shared_tree_fixture(tmp_path / "shared-tree", 4097)

    assert fixture["recursive"] is True
    assert fixture["unicode_name"] is True
    assert Path(fixture["path"]).is_file()
    assert Path(fixture["path"]).parent == tmp_path / "shared-tree" / "alpha" / "beta"
    assert fixture["name"] == module.rust_shared_tree_fixture_name()
    assert fixture["size"] == 4097
    assert len(str(fixture["sha256"])) == 64


def test_materialize_local_profile_seed_adds_run_server_met(tmp_path: Path) -> None:
    module = load_suite_module()
    seed = tmp_path / "seed"
    seed.mkdir()
    for name in module.MFC_PROFILE_SEED_FILES:
        (seed / name).write_bytes(name.encode("ascii"))

    output = module.materialize_local_profile_seed(
        seed,
        tmp_path / "generated-seed",
        server_address="192.0.2.44",
        server_port=4711,
        server_name="local-cross-client",
    )

    for name in module.MFC_PROFILE_SEED_FILES:
        assert (output / name).read_bytes() == name.encode("ascii")
    server_met = output / "server.met"
    assert server_met.is_file()
    assert b"local-cross-client" in server_met.read_bytes()


def test_publish_rust_shared_tree_configures_current_root_and_returns_link(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str, object]] = []

    def fake_request_json(_base_url, method, path, _api_key, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/shared-directories":
                return {"roots": body["roots"], "items": []}
        if path == "/api/v1/shared-directories/operations/reload":
            return {"ok": True}
        if path == "/api/v1/shared-files":
            return {
                "items": [
                    {
                        "name": "Nested.bin",
                        "ed2kLink": "ed2k://|file|Nested.bin|1|00112233445566778899aabbccddeeff|/",
                    }
                ]
            }
        if path == "/api/v1/status":
            return {"stats": {"sharedHashingCount": 0}}
        raise AssertionError(path)

    monkeypatch.setattr(module, "request_json", fake_request_json)

    result = module.publish_rust_shared_tree(
        "http://192.0.2.10:4711",
        "key",
        root=tmp_path / "shared-tree",
        file_name="Nested.bin",
        timeout_seconds=1.0,
    )

    assert calls[0] == (
        "PATCH",
        "/api/v1/shared-directories",
        {"roots": [{"path": str(tmp_path / "shared-tree")}], "confirmReplaceRoots": True},
    )
    assert calls[1] == ("POST", "/api/v1/shared-directories/operations/reload", None)
    assert calls[2] == ("GET", "/api/v1/shared-files", None)
    assert calls[3] == ("GET", "/api/v1/status", None)
    assert result["sharedFiles"]["matched"]["name"] == "Nested.bin"


def test_rust_emulebb_manifest_metadata_requires_md4_aich_and_source_identity(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    metadata_db = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash=transfer_hash,
        name="emulebb-to-emulebb-rust.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES + 1,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        ],
        aich_hashset_acquired=True,
        aich_root="59ba286e4c4b8f0019c9fd89806d7212b37c82d6",
        aich_hashset=[
            "044c4a5f2af419cc2b6b06f69f5e3bd655ec6edb",
            "06fd075b8705ae9189470c69a70e2d5d5593ca09",
        ],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
    )

    metadata = module.require_rust_download_manifest_metadata(
        tmp_path,
        transfer_hash=transfer_hash,
        expected_name="emulebb-to-emulebb-rust.bin",
        expected_size=module.ED2K_PART_SIZE_BYTES + 1,
        require_aich_hashset=True,
    )

    assert metadata["expectedPartCount"] == 2
    assert metadata["expectedHashsetCount"] == 2
    assert metadata["md4HashsetCount"] == 2
    assert metadata["aichHashsetAcquired"] is True
    assert metadata["aichHashsetCount"] == 2
    assert metadata["sourceUserHashCount"] == 1


def test_rust_emulebb_manifest_metadata_rejects_missing_required_aich(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    metadata_db = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash=transfer_hash,
        name="emulebb-to-emulebb-rust.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[],
        aich_hashset_acquired=False,
        aich_hashset=[],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
    )

    with pytest.raises(RuntimeError, match="AICH hashset"):
        module.require_rust_download_manifest_metadata(
            tmp_path,
            transfer_hash=transfer_hash,
            expected_name="emulebb-to-emulebb-rust.bin",
            expected_size=module.ED2K_PART_SIZE_BYTES,
            require_aich_hashset=True,
        )


def test_rust_emulebb_manifest_metadata_accepts_empty_single_part_hashsets(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    metadata_db = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash=transfer_hash,
        name="emulebb-to-emulebb-rust.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[],
        aich_hashset_acquired=True,
        aich_root="59ba286e4c4b8f0019c9fd89806d7212b37c82d6",
        aich_hashset=[],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
    )

    metadata = module.require_rust_download_manifest_metadata(
        tmp_path,
        transfer_hash=transfer_hash,
        expected_name="emulebb-to-emulebb-rust.bin",
        expected_size=module.ED2K_PART_SIZE_BYTES,
        require_aich_hashset=True,
    )

    assert metadata["expectedPartCount"] == 1
    assert metadata["expectedHashsetCount"] == 0
    assert metadata["md4HashsetAcquired"] is True
    assert metadata["md4HashsetCount"] == 0
    assert metadata["aichHashsetAcquired"] is True
    assert metadata["aichHashsetCount"] == 0


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

    monkeypatch.setattr(module.rust_client, "write_rust_profile", fail_after_goed2k_started)

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
