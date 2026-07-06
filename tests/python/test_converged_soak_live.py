from __future__ import annotations

import importlib.util
import struct
from datetime import timedelta
from pathlib import Path
from types import ModuleType

import pytest

from emule_test_harness import soak_launch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SOAK_RUNNER = REPO_ROOT / "scripts" / "converged-soak-live.py"


def _load_soak_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("converged_soak_live_script", SOAK_RUNNER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_soak_launch_requires_same_vpn_bind_ip() -> None:
    assert soak_launch.require_same_vpn_bind_ip({"bindIp": "10.0.0.5"}, {"bindIp": "10.0.0.5"}) == "10.0.0.5"
    with pytest.raises(RuntimeError, match="bind IP mismatch"):
        soak_launch.require_same_vpn_bind_ip({"bindIp": "10.0.0.5"}, {"bindIp": "10.0.0.6"})
    with pytest.raises(RuntimeError, match="bind IP missing"):
        soak_launch.require_same_vpn_bind_ip({"bindIp": ""}, {"bindIp": "10.0.0.5"})


def test_soak_endpoint_ports_are_distinct_by_default() -> None:
    ports = soak_launch.require_distinct_endpoint_ports(
        rust_ed2k_port=soak_launch.RUST_ED2K_PORT,
        rust_kad_port=soak_launch.RUST_KAD_PORT,
        mfc_ed2k_port=soak_launch.MFC_ED2K_PORT,
        mfc_kad_port=soak_launch.MFC_KAD_PORT,
        mfc_server_udp_port=soak_launch.MFC_SERVER_UDP_PORT,
    )

    assert ports == {
        "rust": {"ed2kTcpPort": 42662, "kadUdpPort": 42672},
        "mfc": {"ed2kTcpPort": 43662, "kadUdpPort": 43672, "serverUdpPort": 43673},
    }


def test_soak_endpoint_ports_reject_duplicates() -> None:
    with pytest.raises(ValueError, match="must be distinct"):
        soak_launch.require_distinct_endpoint_ports(
            rust_ed2k_port=42662,
            rust_kad_port=42672,
            mfc_ed2k_port=42662,
            mfc_kad_port=43672,
            mfc_server_udp_port=43673,
        )


def test_apply_mfc_endpoint_ports_persists_emule_preferences(tmp_path: Path) -> None:
    calls: list[tuple[Path, tuple[tuple[str, str], ...]]] = []

    class _LiveCommon:
        @staticmethod
        def apply_emule_preferences(config_dir: Path, values: tuple[tuple[str, str], ...]) -> None:
            calls.append((config_dir, values))

    soak_launch.apply_mfc_endpoint_ports(
        live_common=_LiveCommon,
        config_dir=tmp_path,
        ed2k_port=43662,
        kad_port=43672,
        server_udp_port=43673,
    )

    assert calls == [
        (
            tmp_path,
            (
                ("Port", "43662"),
                ("UDPPort", "43672"),
                ("ServerUDPPort", "43673"),
            ),
        )
    ]


def test_bring_up_mfc_enables_diagnostic_rest_for_direct_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile_dir = tmp_path / "profile"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.ini").write_text("[eMule]\n[WebServer]\n", encoding="utf-16")
    exe_path = tmp_path / "app" / "bin" / "emulebb-diagnostics.exe"

    configure_calls: list[dict[str, object]] = []

    class _LiveCommon:
        @staticmethod
        def apply_emule_preferences(_config_dir: Path, _values: tuple[tuple[str, str], ...]) -> None:
            return None

        @staticmethod
        def apply_p2p_bind_interface_override(_config_dir: Path, _interface_name: str) -> None:
            return None

        @staticmethod
        def apply_private_harness_obfuscation(_config_dir: Path, _enabled: bool) -> None:
            return None

        @staticmethod
        def launch_app(_exe_path: Path, _profile_base: Path) -> object:
            return object()

    class _RestSmoke:
        @staticmethod
        def configure_webserver_profile(
            config_dir_arg: Path,
            app_exe_arg: Path,
            api_key_arg: str,
            port_arg: int,
            bind_addr_arg: str,
            **kwargs: object,
        ) -> None:
            configure_calls.append(
                {
                    "config_dir": config_dir_arg,
                    "app_exe": app_exe_arg,
                    "api_key": api_key_arg,
                    "port": port_arg,
                    "bind_addr": bind_addr_arg,
                    **kwargs,
                }
            )

        @staticmethod
        def apply_p2p_bind_interface_override(_config_dir: Path, _interface_name: str) -> None:
            return None

        @staticmethod
        def wait_for_rest_ready(_base_url: str, _api_key: str, _timeout_seconds: float) -> None:
            return None

        @staticmethod
        def observe_server_connect_attempt(_base_url: str, _api_key: str, _timeout_seconds: float) -> None:
            return None

        @staticmethod
        def http_request(
            _base_url: str,
            _path: str,
            *,
            method: str,
            api_key: str,
            json_body: dict[str, object],
        ) -> dict[str, object]:
            return {"method": method, "api_key": api_key, "json_body": json_body}

    monkeypatch.setattr(soak_launch, "wait_for_mfc_core_rest_ready", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(soak_launch, "patch_upload_limit", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(soak_launch, "connect_operator_server", lambda *_args, **_kwargs: {})

    result = soak_launch.bring_up_mfc(
        live_common=_LiveCommon,
        rest_smoke=_RestSmoke,
        shared_dirs_mod=object(),
        exe_path=exe_path,
        artifacts_dir=tmp_path / "artifacts",
        seed_config_dir=tmp_path / "seed",
        direct_profile_dir=profile_dir,
        rest_host="192.0.2.10",
        rest_port=4732,
        shared_roots=[],
        server_endpoint="192.0.2.20:4661",
        obfuscation=True,
        timeouts={"rest": 0.1, "connect": 0.1},
    )

    assert result["packetDumpDir"] == profile_dir / "logs"
    assert configure_calls == [
        {
            "config_dir": config_dir,
            "app_exe": exe_path,
            "api_key": soak_launch.MFC_API_KEY,
            "port": 4732,
            "bind_addr": "192.0.2.10",
            "enable_crash_test_endpoint": True,
        }
    ]


def test_load_shareddir_roots_deduplicates_and_adds_incoming(tmp_path: Path) -> None:
    shareddir = tmp_path / "shareddir.dat"
    shareddir.write_text(
        "C:\\ShareA\\\r\n"
        "c:\\sharea\r\n"
        "D:\\ShareB/\r\n"
        "\r\n",
        encoding="utf-8",
    )

    roots = soak_launch.load_shareddir_roots(shareddir, extra_roots=[Path("E:/Incoming")])

    assert roots == ["C:\\ShareA\\", "D:\\ShareB\\", "E:\\Incoming\\"]


def test_load_shareddir_root_entries_preserves_recursive_mfc_roots(tmp_path: Path) -> None:
    shareddir = tmp_path / "shareddir.dat"
    shareddir.write_text(
        "C:\\Flat\\\r\n"
        "C:\\Tree\\\r\n"
        "C:\\Tree\\Child\\\r\n",
        encoding="utf-8",
    )
    (tmp_path / "shareddir.monitored.dat").write_text("C:\\Tree\\\r\n", encoding="utf-8")
    (tmp_path / "shareddir.monitor-owned.dat").write_text("C:\\Tree\\Child\\\r\n", encoding="utf-8")

    roots = soak_launch.load_shareddir_root_entries(shareddir, extra_roots=[Path("E:/Incoming")])

    assert roots == [
        "C:\\Flat\\",
        {"path": "C:\\Tree\\", "recursive": True},
        "E:\\Incoming\\",
    ]


def test_existing_shared_roots_counts_inaccessible_entries(tmp_path: Path) -> None:
    present = tmp_path / "present"
    present.mkdir()

    roots, skipped = soak_launch.existing_shared_roots(
        [str(present) + "\\", str(tmp_path / "missing") + "\\"]
    )

    assert roots == [str(present) + "\\"]
    assert skipped == 1


def test_converged_soak_defaults_to_persistent_rust_runtime(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    selection = runner.resolve_rust_runtime_paths(tmp_path / "soak", "20260627T120000Z", fresh=False)

    assert selection == {
        "runtimeDir": tmp_path / "soak" / "rust-runtime",
        "packetDumpDir": tmp_path / "soak" / "rust-runtime" / "packet-dump",
        "mode": "persistent",
        "fresh": False,
    }


def test_converged_soak_fresh_rust_runtime_is_campaign_scoped(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    selection = runner.resolve_rust_runtime_paths(tmp_path / "soak", "20260627T120000Z", fresh=True)

    assert selection == {
        "runtimeDir": tmp_path / "soak" / "rust-runtime-20260627T120000Z",
        "packetDumpDir": tmp_path / "soak" / "rust-runtime-20260627T120000Z" / "packet-dump",
        "mode": "fresh-campaign",
        "fresh": True,
    }


def test_converged_soak_poll_rest_timeout_default_covers_hashing_load() -> None:
    runner = _load_soak_runner()

    args = runner.build_parser().parse_args(["--inputs", "live-wire-inputs.local.json"])

    assert args.poll_rest_timeout == 90.0


def _nodes_dat_with_one_contact() -> bytes:
    entry = (
        b"\x11" * 16
        + bytes([4, 3, 2, 1])
        + struct.pack("<HHB", 4662, 4661, 8)
    )
    return struct.pack("<I", 1) + entry


def test_converged_soak_prefers_mfc_profile_nodes_dat(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    mfc_profile = tmp_path / "mfc"
    nodes_dat = mfc_profile / "config" / "nodes.dat"
    nodes_dat.parent.mkdir(parents=True)
    nodes_dat.write_bytes(_nodes_dat_with_one_contact())

    selection = runner.resolve_kad_bootstrap_endpoints(
        mfc_profile_dir=mfc_profile,
        nodes_file=None,
        nodes_url="https://nodes.example.test/nodes.dat",
        limit=40,
    )

    assert selection == {
        "source": "mfc-profile",
        "sourceKind": "file",
        "endpoints": ["1.2.3.4:4662"],
        "nodesDatUrl": None,
        "nodesDatFileSelected": True,
    }


def test_converged_soak_falls_back_to_nodes_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    calls: list[tuple[str, int]] = []

    def fake_fetch(url: str, *, limit: int) -> list[str]:
        calls.append((url, limit))
        return ["1.2.3.4:4662"]

    monkeypatch.setattr(runner, "fetch_bootstrap_endpoints", fake_fetch)

    selection = runner.resolve_kad_bootstrap_endpoints(
        mfc_profile_dir=tmp_path / "missing-profile",
        nodes_file=None,
        nodes_url="https://nodes.example.test/nodes.dat",
        limit=12,
    )

    assert calls == [("https://nodes.example.test/nodes.dat", 12)]
    assert selection == {
        "source": "url",
        "sourceKind": "url",
        "endpoints": ["1.2.3.4:4662"],
        "nodesDatUrl": "https://nodes.example.test/nodes.dat",
        "nodesDatFileSelected": False,
    }


def test_converged_soak_poll_list_uses_configured_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    calls: list[dict[str, object]] = []

    def fake_retry(description: str, attempts: int, base_url: str, path: str, **kwargs: object) -> object:
        calls.append(
            {
                "description": description,
                "attempts": attempts,
                "base_url": base_url,
                "path": path,
                "timeout_seconds": kwargs.get("timeout_seconds"),
            }
        )
        return {"data": {"items": [{"id": "one"}]}}

    monkeypatch.setattr(runner, "retry_http_json", fake_retry)

    rows = runner._get_list("http://client", "/api/v1/searches", "key", "searches", timeout_seconds=42.5)

    assert rows == [{"id": "one"}]
    assert calls == [
        {
            "description": "poll /api/v1/searches",
            "attempts": 1,
            "base_url": "http://client",
            "path": "/api/v1/searches",
            "timeout_seconds": 42.5,
        }
    ]


def test_converged_soak_status_snapshot_uses_configured_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    calls: list[dict[str, object]] = []

    def fake_retry(description: str, attempts: int, base_url: str, path: str, **kwargs: object) -> object:
        calls.append(
            {
                "description": description,
                "attempts": attempts,
                "base_url": base_url,
                "path": path,
                "timeout_seconds": kwargs.get("timeout_seconds"),
            }
        )
        return {
            "data": {
                "servers": {
                    "connected": True,
                    "lowId": False,
                    "currentServer": {"address": "45.87.41.16", "port": 6262},
                },
                "runtimeDiagnostics": {
                    "activeUploads": 1,
                    "waitingUploads": 2,
                    "sharedFileCount": 3,
                    "sharedHashingCount": 4,
                },
            }
        }

    monkeypatch.setattr(runner, "retry_http_json", fake_retry)

    status = runner.status_snapshot("http://client", "key", timeout_seconds=37.0)

    assert status == {
        "connected": True,
        "lowId": False,
        "serverAddress": "45.87.41.16",
        "serverPort": 6262,
        "activeUploads": 1,
        "waitingUploads": 2,
        "sharedFileCount": 3,
        "sharedHashingCount": 4,
    }
    assert calls == [
        {
            "description": "soak status",
            "attempts": 1,
            "base_url": "http://client",
            "path": "/api/v1/status",
            "timeout_seconds": 37.0,
        }
    ]


def test_mfc_known_met_import_skips_without_direct_mfc_profile(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=None,
        rust_runtime_dir=tmp_path / "rust-runtime",
        shared_roots=[],
        enabled=True,
    )

    assert result == {"enabled": True, "status": "skipped", "reason": "no-mfc-profile-dir"}


def test_mfc_known_met_import_skips_when_disabled(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=tmp_path / "mfc",
        rust_runtime_dir=tmp_path / "rust-runtime",
        shared_roots=[],
        enabled=False,
    )

    assert result == {"enabled": False, "status": "skipped", "reason": "disabled"}


def test_mfc_known_met_import_records_redacted_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    mfc_profile = tmp_path / "mfc"
    known_met = mfc_profile / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"placeholder")
    rust_repo = tmp_path / "emulebb-rust"
    monkeypatch.setattr(runner, "resolve_rust_repo", lambda: rust_repo)
    calls: list[dict[str, object]] = []

    def fake_import(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "knownMetRecords": 3,
            "sharedFilesScanned": 7,
            "matchedRecords": 2,
            "importedRecords": 2,
            "dryRun": False,
            "metadataDb": str(tmp_path / "private" / "metadata.sqlite"),
            "skipped": {
                "missing_identity": 0,
                "md4_count_mismatch": 0,
                "no_unique_path_match": 1,
                "no_path_match": 1,
                "ambiguous_path_match": 0,
                "aich_count_mismatch": 0,
            },
        }

    monkeypatch.setattr(runner.mfc_known_met, "import_mfc_known_met_hashes", fake_import)

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_runtime_dir=tmp_path / "rust-runtime",
        shared_roots=[str(tmp_path / "share")],
        enabled=True,
    )

    assert calls == [
        {
            "rust_repo": rust_repo,
            "metadata_db": tmp_path / "rust-runtime" / "metadata.sqlite",
            "known_met": known_met,
            "shared_roots": [tmp_path / "share"],
        }
    ]
    assert result == {
        "enabled": True,
        "status": "imported",
        "knownMetRecords": 3,
        "sharedFilesScanned": 7,
        "matchedRecords": 2,
        "importedRecords": 2,
        "dryRun": False,
        "skipped": {
            "missing_identity": 0,
            "md4_count_mismatch": 0,
            "no_unique_path_match": 1,
            "no_path_match": 1,
            "ambiguous_path_match": 0,
            "aich_count_mismatch": 0,
        },
    }


def test_mfc_shared_files_inventory_import_skips_without_inventory(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    result = runner.import_mfc_shared_files_inventory_for_rust_profile(
        mfc_profile_dir=tmp_path / "mfc",
        rust_runtime_dir=tmp_path / "rust-runtime",
        shared_roots=[],
        inventory_path=None,
    )

    assert result == {"enabled": False, "status": "skipped", "reason": "no-inventory"}


def test_mfc_shared_files_inventory_import_records_redacted_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    mfc_profile = tmp_path / "mfc"
    known_met = mfc_profile / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"placeholder")
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"data":{"items":[]}}', encoding="utf-8")
    rust_repo = tmp_path / "emulebb-rust"
    monkeypatch.setattr(runner, "resolve_rust_repo", lambda: rust_repo)
    calls: list[dict[str, object]] = []

    def fake_load(path: Path) -> list[dict[str, object]]:
        calls.append({"load": path})
        return [{"hash": "a" * 32, "path": str(tmp_path / "share" / "file.bin"), "sizeBytes": 4}]

    def fake_import(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "knownMetRecords": 5,
            "sharedFileRows": 4,
            "matchedRows": 3,
            "importedRows": 3,
            "dryRun": False,
            "metadataDb": str(tmp_path / "private" / "metadata.sqlite"),
            "skipped": {
                "invalid_row": 0,
                "path_outside_shared_roots": 0,
                "path_missing": 1,
                "size_mismatch": 0,
                "missing_known_met_entry": 0,
                "md4_count_mismatch": 0,
                "aich_count_mismatch": 0,
            },
        }

    monkeypatch.setattr(runner.mfc_known_met, "load_shared_file_rows_json", fake_load)
    monkeypatch.setattr(runner.mfc_known_met, "import_mfc_shared_file_rows_hashes", fake_import)

    result = runner.import_mfc_shared_files_inventory_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_runtime_dir=tmp_path / "rust-runtime",
        shared_roots=[str(tmp_path / "share")],
        inventory_path=inventory,
    )

    assert calls == [
        {"load": inventory},
        {
            "rust_repo": rust_repo,
            "metadata_db": tmp_path / "rust-runtime" / "metadata.sqlite",
            "known_met": known_met,
            "shared_file_rows": [
                {"hash": "a" * 32, "path": str(tmp_path / "share" / "file.bin"), "sizeBytes": 4}
            ],
            "shared_roots": [tmp_path / "share"],
        },
    ]
    assert result == {
        "enabled": True,
        "status": "imported",
        "knownMetRecords": 5,
        "sharedFileRows": 4,
        "matchedRows": 3,
        "importedRows": 3,
        "dryRun": False,
        "skipped": {
            "invalid_row": 0,
            "path_outside_shared_roots": 0,
            "path_missing": 1,
            "size_mismatch": 0,
            "missing_known_met_entry": 0,
            "md4_count_mismatch": 0,
            "aich_count_mismatch": 0,
        },
    }


def test_converged_soak_accepts_mfc_shared_files_inventory_arg() -> None:
    runner = _load_soak_runner()

    args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--mfc-shared-files-inventory", "inventory.json"]
    )

    assert args.mfc_shared_files_inventory == "inventory.json"


def test_converged_soak_secident_knob_defaults_on() -> None:
    runner = _load_soak_runner()

    default_args = runner.build_parser().parse_args(["--inputs", "live-wire-inputs.local.json"])
    assert default_args.secident == "on"

    off_args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--secident", "off"]
    )
    assert off_args.secident == "off"


def _bring_up_mfc_pref_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: object
) -> list[tuple[Path, tuple[tuple[str, str], ...]]]:
    """Runs bring_up_mfc on a direct profile with stub modules; returns pref writes."""

    profile_dir = tmp_path / "profile"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.ini").write_text("[eMule]\n[WebServer]\n", encoding="utf-16")
    pref_calls: list[tuple[Path, tuple[tuple[str, str], ...]]] = []

    class _LiveCommon:
        @staticmethod
        def apply_emule_preferences(config_dir_arg: Path, values: tuple[tuple[str, str], ...]) -> None:
            pref_calls.append((config_dir_arg, values))

        @staticmethod
        def apply_private_harness_obfuscation(_config_dir: Path, _enabled: bool) -> None:
            return None

        @staticmethod
        def launch_app(_exe_path: Path, _profile_base: Path) -> object:
            return object()

    class _RestSmoke:
        @staticmethod
        def configure_webserver_profile(*_args: object, **_kwargs: object) -> None:
            return None

        @staticmethod
        def apply_p2p_bind_interface_override(_config_dir: Path, _interface_name: str) -> None:
            return None

        @staticmethod
        def wait_for_rest_ready(_base_url: str, _api_key: str, _timeout_seconds: float) -> None:
            return None

        @staticmethod
        def observe_server_connect_attempt(_base_url: str, _api_key: str, _timeout_seconds: float) -> None:
            return None

        @staticmethod
        def http_request(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {}

    monkeypatch.setattr(soak_launch, "wait_for_mfc_core_rest_ready", lambda *_a, **_k: {})
    monkeypatch.setattr(soak_launch, "patch_upload_limit", lambda *_a, **_k: {})
    monkeypatch.setattr(soak_launch, "connect_operator_server", lambda *_a, **_k: {})

    soak_launch.bring_up_mfc(
        live_common=_LiveCommon,
        rest_smoke=_RestSmoke,
        shared_dirs_mod=object(),
        exe_path=tmp_path / "app" / "emulebb-diagnostics.exe",
        artifacts_dir=tmp_path / "artifacts",
        seed_config_dir=tmp_path / "seed",
        direct_profile_dir=profile_dir,
        rest_host="192.0.2.10",
        rest_port=4732,
        shared_roots=[],
        server_endpoint="192.0.2.20:4661",
        obfuscation=True,
        timeouts={"rest": 0.1, "connect": 0.1},
        **overrides,
    )
    return pref_calls


def test_bring_up_mfc_pins_secure_ident_on_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SecIdent must be EXPLICIT, never inherited by accident: a direct operator
    # profile with SecureIdent=0 silently killed the whole SecIdent parity
    # surface in the 2026-07-04 capture.
    pref_calls = _bring_up_mfc_pref_calls(tmp_path, monkeypatch)
    flattened = [pair for _dir, values in pref_calls for pair in values]
    assert ("SecureIdent", "1") in flattened


def test_bring_up_mfc_secure_ident_off_writes_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pref_calls = _bring_up_mfc_pref_calls(tmp_path, monkeypatch, secure_ident=False)
    flattened = [pair for _dir, values in pref_calls for pair in values]
    assert ("SecureIdent", "0") in flattened
    assert ("SecureIdent", "1") not in flattened


def test_ensure_operator_server_reuses_existing_row(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_retry(_description: str, _attempts: int, _base_url: str, path: str, **kwargs: object) -> object:
        calls.append((str(kwargs.get("method") or "GET"), path))
        return {
            "data": {
                "items": [
                    {
                        "address": soak_launch.operator_server_parts()[0],
                        "port": soak_launch.operator_server_parts()[1],
                        "name": "preloaded",
                        "static": True,
                    }
                ]
            }
        }

    monkeypatch.setattr(soak_launch, "retry_http_json", fake_retry)

    result = soak_launch.ensure_operator_server("http://client", "key")

    assert result["preloaded"] is True
    assert result["staticUpdated"] is False
    assert calls == [("GET", "/api/v1/servers")]


def test_ensure_operator_server_promotes_preloaded_row_to_static(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_retry(_description: str, _attempts: int, _base_url: str, path: str, **kwargs: object) -> object:
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path, kwargs.get("body")))
        if method == "GET":
            return {
                "data": {
                    "items": [
                        {
                            "address": soak_launch.operator_server_parts()[0],
                            "port": soak_launch.operator_server_parts()[1],
                            "name": "preloaded",
                            "static": False,
                        }
                    ]
                }
            }
        return {"data": {"static": True}}

    monkeypatch.setattr(soak_launch, "retry_http_json", fake_retry)

    result = soak_launch.ensure_operator_server("http://client", "key")

    assert result["preloaded"] is True
    assert result["staticUpdated"] is True
    assert calls == [
        ("GET", "/api/v1/servers", None),
        ("PATCH", f"/api/v1/servers/{soak_launch.OPERATOR_SERVER}", {"static": True}),
    ]


def test_ensure_operator_server_adds_missing_row(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, object | None]] = []

    def fake_retry(_description: str, _attempts: int, _base_url: str, path: str, **kwargs: object) -> object:
        method = str(kwargs.get("method") or "GET")
        calls.append((method, path, kwargs.get("body")))
        if method == "GET":
            return {"data": {"items": []}}
        return {"data": {"added": True}}

    monkeypatch.setattr(soak_launch, "retry_http_json", fake_retry)

    result = soak_launch.ensure_operator_server("http://client", "key")

    assert result["preloaded"] is False
    assert calls == [
        ("GET", "/api/v1/servers", None),
        (
            "POST",
            "/api/v1/servers",
            {
                "address": soak_launch.operator_server_parts()[0],
                "port": soak_launch.operator_server_parts()[1],
                "name": soak_launch.OPERATOR_SERVER_NAME,
                "static": True,
            },
        ),
    ]


def test_safe_common_download_candidate_requires_hash_on_both_clients() -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(row: dict[str, object]) -> str | None:
            return None if row.get("safe") else "unsafe"

    candidate = runner.safe_common_download_candidate(
        [
            {"hash": "a" * 32, "safe": True, "sources": 2, "sizeBytes": 1024},
            {"hash": "b" * 32, "safe": True, "sources": 9, "sizeBytes": 2048},
            {"hash": "c" * 32, "safe": False, "sources": 99, "sizeBytes": 1},
        ],
        [
            {"hash": "a" * 32},
            {"hash": "b" * 32},
            {"hash": "c" * 32},
        ],
        rust_mod=_RustFilter,
    )

    assert candidate is not None
    assert candidate["hash"] == "b" * 32


def test_safe_common_download_candidate_skips_existing_hashes() -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    candidate = runner.safe_common_download_candidate(
        [
            {"hash": "a" * 32, "safe": True, "sources": 10, "sizeBytes": 1024},
            {"hash": "b" * 32, "safe": True, "sources": 4, "sizeBytes": 2048},
        ],
        [
            {"hash": "a" * 32},
            {"hash": "b" * 32},
        ],
        rust_mod=_RustFilter,
        existing_hashes={"a" * 32},
    )

    assert candidate is not None
    assert candidate["hash"] == "b" * 32


def test_safe_common_download_candidate_skips_probe_existing_hashes() -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    candidate = runner.safe_common_download_candidate(
        [
            {"hash": "a" * 32, "safe": True, "sources": 10, "sizeBytes": 1024},
            {"hash": "b" * 32, "safe": True, "sources": 4, "sizeBytes": 2048},
        ],
        [
            {"hash": "a" * 32},
            {"hash": "b" * 32},
        ],
        rust_mod=_RustFilter,
        existing_probe=lambda file_hash: file_hash == "a" * 32,
    )

    assert candidate is not None
    assert candidate["hash"] == "b" * 32


def test_safe_common_download_candidate_returns_none_without_common_safe_hash() -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    assert (
        runner.safe_common_download_candidate(
            [{"hash": "a" * 32, "safe": True}],
            [{"hash": "b" * 32}],
            rust_mod=_RustFilter,
        )
        is None
    )


def test_action_tracker_prime_suppresses_existing_rows() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    baseline = tracker.prime(
        rust_searches=[{"id": "old-rs", "key": "linux", "label": "linux"}],
        rust_transfers=[{"id": "old-rt", "key": "a" * 32, "label": "old.iso"}],
        mfc_searches=[{"id": "old-ms", "key": "linux", "label": "linux"}],
        mfc_transfers=[{"id": "old-mt", "key": "a" * 32, "label": "old.iso"}],
    )

    pairs, unpaired = tracker.tick(
        runner.datetime.now(runner.timezone.utc),
        rust_searches=[
            {"id": "old-rs", "key": "linux", "label": "linux"},
            {"id": "new-rs", "key": "python", "label": "python"},
        ],
        rust_transfers=[{"id": "old-rt", "key": "a" * 32, "label": "old.iso"}],
        mfc_searches=[
            {"id": "old-ms", "key": "linux", "label": "linux"},
            {"id": "new-ms", "key": "python", "label": "python"},
        ],
        mfc_transfers=[{"id": "old-mt", "key": "a" * 32, "label": "old.iso"}],
    )

    assert baseline == {
        "rustSearches": 1,
        "rustTransfers": 1,
        "mfcSearches": 1,
        "mfcTransfers": 1,
    }
    assert [(pair.kind, pair.key) for pair in pairs] == []
    assert unpaired == []
    assert [action.key for action in tracker.rust] == ["python"]
    assert [action.key for action in tracker.mfc] == ["python"]


def test_action_tracker_logs_redacted_action_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    messages: list[str] = []
    monkeypatch.setattr(runner, "log", messages.append)
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)

    tracker.tick(
        runner.datetime.now(runner.timezone.utc),
        rust_searches=[{"id": "rs", "key": "private search", "label": "Private Search"}],
        rust_transfers=[
            {"id": "rt", "key": "a" * 32, "label": "Private Download Title.pdf"}
        ],
        mfc_searches=[],
        mfc_transfers=[],
    )
    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key="b" * 32,
        label="Another Private Download Title.pdf",
        observed_at=runner.datetime.now(runner.timezone.utc),
        action_id="auto-download-1",
    )

    joined = "\n".join(messages)
    assert "Private Search" not in joined
    assert "Private Download Title" not in joined
    assert "Another Private" not in joined
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in joined
    assert "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" not in joined
    assert "observed rust search action" in joined
    assert "observed rust download action" in joined
    assert "observed synchronized download action" in joined


def test_automatic_cycle_schedules_download_without_triggering(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    triggered: list[str] = []

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    monkeypatch.setattr(
        runner,
        "create_search",
        lambda base_url, api_key, *, query, method: "rust-search"
        if api_key == runner.RUST_API_KEY
        else "mfc-search",
    )
    monkeypatch.setattr(
        runner,
        "poll_search_results",
        lambda *_args, **_kwargs: [{"hash": "d" * 32, "sources": 3, "sizeBytes": 2048}],
    )
    monkeypatch.setattr(runner, "_get_list", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner, "transfer_exists", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(runner, "trigger_download", lambda *_args, **_kwargs: triggered.append("download"))

    cycle = runner.drive_automatic_cycle(
        cycle_index=1,
        query="python",
        method="server",
        rust_base="http://rust",
        mfc_base="http://mfc",
        rust_mod=_RustFilter,
        download=True,
        search_timeout_seconds=1.0,
    )

    assert triggered == []
    assert cycle["download"]["scheduled"] is True
    assert cycle["download"]["ok"] is None
    assert cycle["download"]["searchIds"] == {"rust": "rust-search", "mfc": "mfc-search"}
    assert cycle["downloadExistingHashCounts"] == {"rust": 0, "mfc": 0, "combined": 0}
    assert cycle["downloadExistingHashProbeSkips"] == {"rust": 0, "mfc": 0, "combined": 0}


def test_automatic_cycle_does_not_schedule_existing_transfer_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    monkeypatch.setattr(
        runner,
        "create_search",
        lambda base_url, api_key, *, query, method: "rust-search"
        if api_key == runner.RUST_API_KEY
        else "mfc-search",
    )
    monkeypatch.setattr(
        runner,
        "poll_search_results",
        lambda *_args, **_kwargs: [{"hash": "d" * 32, "sources": 3, "sizeBytes": 2048}],
    )

    def fake_get_list(
        _base_url: str,
        _path: str,
        api_key: str,
        *_keys: str,
        timeout_seconds: float = 10.0,
    ) -> list[dict[str, object]]:
        del timeout_seconds
        if api_key == runner.RUST_API_KEY:
            return [{"hash": "d" * 32, "state": "completed"}]
        return []

    monkeypatch.setattr(runner, "_get_list", fake_get_list)
    monkeypatch.setattr(runner, "transfer_exists", lambda *_args, **_kwargs: False)

    cycle = runner.drive_automatic_cycle(
        cycle_index=1,
        query="python",
        method="server",
        rust_base="http://rust",
        mfc_base="http://mfc",
        rust_mod=_RustFilter,
        download=True,
        search_timeout_seconds=1.0,
    )

    assert cycle["download"] == {"ok": False, "reason": "no common safe candidate"}
    assert cycle["downloadExistingHashCounts"] == {"rust": 1, "mfc": 0, "combined": 1}
    assert cycle["downloadExistingHashProbeSkips"] == {"rust": 0, "mfc": 0, "combined": 0}


def test_automatic_cycle_does_not_schedule_probe_existing_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    monkeypatch.setattr(
        runner,
        "create_search",
        lambda base_url, api_key, *, query, method: "rust-search"
        if api_key == runner.RUST_API_KEY
        else "mfc-search",
    )
    monkeypatch.setattr(
        runner,
        "poll_search_results",
        lambda *_args, **_kwargs: [{"hash": "d" * 32, "sources": 3, "sizeBytes": 2048}],
    )
    monkeypatch.setattr(runner, "_get_list", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        runner,
        "transfer_exists",
        lambda _base_url, api_key, _file_hash, **_kwargs: api_key == runner.RUST_API_KEY,
    )

    cycle = runner.drive_automatic_cycle(
        cycle_index=1,
        query="python",
        method="server",
        rust_base="http://rust",
        mfc_base="http://mfc",
        rust_mod=_RustFilter,
        download=True,
        search_timeout_seconds=1.0,
    )

    assert cycle["download"] == {"ok": False, "reason": "no common safe candidate"}
    assert cycle["downloadExistingHashCounts"] == {"rust": 0, "mfc": 0, "combined": 0}
    assert cycle["downloadExistingHashProbeSkips"] == {"rust": 1, "mfc": 0, "combined": 1}


def test_checkpoint_operator_reconnect_skips_connected_client() -> None:
    runner = _load_soak_runner()

    result = runner.checkpoint_operator_reconnect(
        "http://client",
        "key",
        {"connected": True, "serverAddress": "45.82.80.155", "serverPort": 5687},
    )

    assert result == {"attempted": False, "reason": "already_connected"}


def test_operator_connected_requires_configured_server() -> None:
    runner = _load_soak_runner()

    assert runner.operator_connected(
        {"connected": True, "serverAddress": "45.82.80.155", "serverPort": 5687}
    )
    assert not runner.operator_connected(
        {"connected": True, "serverAddress": "198.51.100.2", "serverPort": 5687}
    )
    assert not runner.operator_connected(
        {"connected": False, "serverAddress": "45.82.80.155", "serverPort": 5687}
    )
    assert runner.operator_connected(
        {"connected": True, "serverAddress": "198.51.100.2", "serverPort": 4661},
        endpoint="198.51.100.2:4661",
    )


def test_connectivity_gate_requires_both_clients_on_operator() -> None:
    runner = _load_soak_runner()
    connected = {"connected": True, "serverAddress": "45.82.80.155", "serverPort": 5687}
    disconnected = {"connected": False}

    assert runner.connectivity_gate(connected, connected)["ok"] is True

    gate = runner.connectivity_gate(disconnected, connected)
    assert gate == {
        "ok": False,
        "rustConnected": False,
        "mfcConnected": True,
        "rustOnOperator": False,
        "mfcOnOperator": True,
    }


def test_connectivity_gate_supports_split_servers() -> None:
    runner = _load_soak_runner()
    rust_status = {"connected": True, "serverAddress": "198.51.100.2", "serverPort": 4661}
    mfc_status = {"connected": True, "serverAddress": "45.82.80.155", "serverPort": 5687}

    gate = runner.connectivity_gate(
        rust_status,
        mfc_status,
        rust_endpoint="198.51.100.2:4661",
        mfc_endpoint="45.82.80.155:5687",
    )

    assert gate["ok"] is True
    assert gate["rustOnOperator"] is True
    assert gate["mfcOnOperator"] is True


def test_checkpoint_operator_reconnect_triggers_disconnected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_soak_runner()
    calls: list[tuple[str, str, str, str]] = []

    def fake_connect(
        base_url: str,
        api_key: str,
        *,
        description: str,
        endpoint: str,
    ) -> dict[str, object]:
        calls.append((base_url, api_key, description, endpoint))
        return {"connect": {"data": {"connected": False, "connecting": True, "serverCount": 1}}}

    monkeypatch.setattr(runner.soak_launch, "connect_operator_server", fake_connect)

    result = runner.checkpoint_operator_reconnect(
        "http://client",
        "key",
        {"connected": False},
        endpoint="198.51.100.2:4661",
    )

    assert calls == [("http://client", "key", "checkpoint operator server reconnect", "198.51.100.2:4661")]
    assert result == {
        "attempted": True,
        "ok": True,
        "connected": False,
        "connecting": True,
        "serverCount": 1,
    }


def test_tracker_records_synchronized_download_action() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    now = runner.datetime.now(runner.timezone.utc)

    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key="e" * 32,
        label="e" * 32,
        observed_at=now,
        action_id="auto-download-1",
    )

    assert [(action.client, action.key) for action in tracker.rust] == [("rust", "e" * 32)]
    assert [(action.client, action.key) for action in tracker.mfc] == [("mfc", "e" * 32)]


def test_tracker_uses_download_specific_settle_window() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(
        window_seconds=90.0,
        settle_seconds=45.0,
        lead_seconds=8.0,
        download_settle_seconds=300.0,
    )
    now = runner.datetime.now(runner.timezone.utc)

    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key="e" * 32,
        label="e" * 32,
        observed_at=now,
        action_id="auto-download-1",
    )

    pairs, unpaired = tracker.tick(
        now + timedelta(seconds=100),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )
    assert pairs == []
    assert unpaired == []

    pairs, unpaired = tracker.tick(
        now + timedelta(seconds=301),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )
    assert [(pair.kind, pair.key) for pair in pairs] == [(runner.sad.DOWNLOAD, "e" * 32)]
    assert unpaired == []


def test_tracker_uses_download_specific_settle_window_for_unpaired_actions() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(
        window_seconds=90.0,
        settle_seconds=45.0,
        lead_seconds=8.0,
        download_settle_seconds=300.0,
    )
    now = runner.datetime.now(runner.timezone.utc)
    tracker.rust.append(
        runner.sad.Action(
            client="rust",
            kind=runner.sad.DOWNLOAD,
            action_id="rust-transfer",
            key="e" * 32,
            label="e" * 32,
            observed_at=now,
        )
    )

    pairs, unpaired = tracker.tick(
        now + timedelta(seconds=200),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )
    assert pairs == []
    assert unpaired == []

    pairs, unpaired = tracker.tick(
        now + timedelta(seconds=391),
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )
    assert pairs == []
    assert [(action.kind, action.key) for action in unpaired] == [(runner.sad.DOWNLOAD, "e" * 32)]


def test_tracker_suppresses_rest_echo_of_synchronized_download() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    now = runner.datetime.now(runner.timezone.utc)
    file_hash = "f" * 32

    tracker.record_synchronized_action(
        kind=runner.sad.DOWNLOAD,
        key=file_hash,
        label=file_hash,
        observed_at=now,
        action_id="auto-download-1",
    )
    tracker.processed = {action.action_id for action in tracker.rust + tracker.mfc}
    pairs, unpaired = tracker.tick(
        now,
        rust_searches=[],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[{"id": "mfc-transfer", "key": file_hash, "label": "Private Title.pdf"}],
    )

    assert pairs == []
    assert unpaired == []
    assert [action.action_id for action in tracker.mfc] == ["mfc:auto-download-1"]
