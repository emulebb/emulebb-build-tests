from __future__ import annotations

import importlib.util
import json
import os
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


def test_resolve_lan_rest_bind_addr_requires_explicit_cli_value_to_match_x_local_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    assert soak_launch.resolve_lan_rest_bind_addr("192.0.2.10") == "192.0.2.10"
    with pytest.raises(ValueError, match="X_LOCAL_IP"):
        soak_launch.resolve_lan_rest_bind_addr("192.0.2.44")


def test_resolve_lan_rest_bind_addr_uses_x_local_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    assert soak_launch.resolve_lan_rest_bind_addr() == "192.0.2.10"


@pytest.mark.parametrize("candidate", ["", "127.0.0.1", "0.0.0.0", "localhost"])
def test_resolve_lan_rest_bind_addr_rejects_missing_loopback_wildcard_or_host(
    candidate: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("X_LOCAL_IP", raising=False)

    with pytest.raises((RuntimeError, ValueError)):
        soak_launch.resolve_lan_rest_bind_addr(candidate)


def test_converged_soak_parser_accepts_lan_bind_addr() -> None:
    runner = _load_soak_runner()
    args = runner.build_parser().parse_args(
        [
            "--inputs",
            "live-wire-inputs.local.json",
            "--lan-bind-addr",
            "192.0.2.10",
        ]
    )

    assert args.lan_bind_addr == "192.0.2.10"


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


def test_soak_endpoint_ports_reject_excluded_windows_ranges() -> None:
    ports = soak_launch.require_distinct_endpoint_ports(
        rust_ed2k_port=42662,
        rust_kad_port=42672,
        mfc_ed2k_port=43662,
        mfc_kad_port=43672,
        mfc_server_udp_port=43673,
    )
    tcp_ranges = soak_launch.parse_windows_excluded_port_ranges("  42660    42665     *\n")
    udp_ranges = soak_launch.parse_windows_excluded_port_ranges("  50000    50059     *\n")

    with pytest.raises(ValueError, match="excluded Windows port ranges"):
        soak_launch.require_ports_not_excluded(ports, tcp_excluded=tcp_ranges, udp_excluded=udp_ranges)


def test_live_wire_operator_server_endpoint_is_fixed() -> None:
    assert soak_launch.require_operator_server_endpoint(soak_launch.OPERATOR_SERVER) == soak_launch.OPERATOR_SERVER

    with pytest.raises(ValueError, match="fixed live-wire ED2K server"):
        soak_launch.require_operator_server_endpoint("192.0.2.1:4661", label="--rust-server")


def test_build_upload_evidence_classifies_passive_serving(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    rust_dump_dir = tmp_path / "rust" / "packet-dump"
    mfc_dump_dir = tmp_path / "mfc" / "logs"
    rust_dump_dir.mkdir(parents=True)
    mfc_dump_dir.mkdir(parents=True)
    (rust_dump_dir / "emulebb-rust-diag-123.jsonl").write_text(
        json.dumps(
            {
                "family": "sched",
                "event": "upload_request_outcome",
                "body": {
                    "outcome": "partial",
                    "firstSkipReason": "duplicateDone",
                    "requestedBytes": 300,
                    "servedBytes": 100,
                    "throttleDelayMs": 4,
                    "verifiedReaderOpenMs": 1,
                    "payloadReadMs": 2,
                },
            }
        )
        + "\n"
        + json.dumps(
            {
                "family": "sched",
                "event": "upload_payload_accounting",
                "body": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (mfc_dump_dir / "emulebb-diagnostics-upload-slot.log").write_text(
        "2026-01-01 00:00:00 UploadSlotDiagnostics: summary "
        "waiting=2 activeSlots=12 effectiveSlotCap=16 datarateBytesPerSec=3145728\n"
        "2026-01-01 00:00:01 UploadSlotDiagnostics: slot=1 live=1 "
        "state=Uploading rateBytesPerSec=1048576 pendingIO=0 reqRejected=0\n",
        encoding="utf-8",
    )

    evidence = runner.build_upload_evidence(
        rust_packets=[
            {"opcode_name": "OP_REQUESTPARTS"},
            {"opcode_name": "OP_SENDINGPART"},
        ],
        mfc_packets=[
            {"opcode_name": "OP_REQUESTPARTS"},
            {"opcode_name": "OP_COMPRESSEDPART"},
            {"opcode_name": "OP_QUEUERANKING"},
        ],
        rust_status={"activeUploads": 1, "waitingUploads": 0},
        mfc_status={"activeUploads": 12, "waitingUploads": 2},
        rust_stats={"uploadSpeedKiBps": 900.0, "activeUploads": 1, "waitingUploads": 0},
        mfc_stats={"uploadSpeedKiBps": 3072.0, "activeUploads": 12, "waitingUploads": 2},
        rust_dump_dir=rust_dump_dir,
        mfc_dump_dir=mfc_dump_dir,
        upload_limit_kibps=3072,
    )

    assert evidence["classification"]["uploadDemandPresent"] is True
    assert evidence["classification"]["rustServingProven"] is True
    assert evidence["classification"]["mfcServingProven"] is True
    assert evidence["classification"]["mfcCapSaturated"] is True
    assert evidence["classification"]["rustThroughputGap"] is True
    assert evidence["classification"]["visibilityGap"] is True
    assert evidence["packetOpcodes"]["rust"]["OP_SENDINGPART"] == 1
    assert evidence["packetOpcodes"]["mfc"]["OP_COMPRESSEDPART"] == 1
    assert evidence["diagnostics"]["rustSched"]["requestedBytes"] == 300
    assert evidence["diagnostics"]["rustSched"]["servedBytes"] == 100
    assert evidence["diagnostics"]["rustSched"]["servedOrDuplicateDoneToRequestedRatio"] == 1.0
    assert evidence["diagnostics"]["mfcUpload"]["summaryRateKiBps"] == 3072.0


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


def test_live_wire_shared_roots_can_point_to_mfc_shareddir(tmp_path: Path) -> None:
    shareddir = tmp_path / "shareddir.dat"
    shareddir.write_text(
        "C:\\Flat\\\r\n"
        "C:\\Tree\\\r\n"
        "C:\\Tree\\Child\\\r\n",
        encoding="utf-8",
    )
    (tmp_path / "shareddir.monitored.dat").write_text("C:\\Tree\\\r\n", encoding="utf-8")
    (tmp_path / "shareddir.monitor-owned.dat").write_text("C:\\Tree\\Child\\\r\n", encoding="utf-8")
    inputs = tmp_path / "live-wire-inputs.local.json"
    inputs.write_text(
        json.dumps(
            {
                "schema": "emulebb-build-tests.live-wire-inputs.v1",
                "shared_directories": {
                    "shareddir_file": str(shareddir),
                    "roots": [{"path": "D:\\Fallback\\", "recursive": True}],
                },
            }
        ),
        encoding="utf-8",
    )

    roots = soak_launch.load_live_wire_shared_root_entries(inputs)

    assert roots == [
        "C:\\Flat\\",
        {"path": "C:\\Tree\\", "recursive": True},
    ]


def test_live_wire_shared_roots_keep_explicit_roots_as_fallback(tmp_path: Path) -> None:
    inputs = tmp_path / "live-wire-inputs.local.json"
    inputs.write_text(
        json.dumps(
            {
                "schema": "emulebb-build-tests.live-wire-inputs.v1",
                "shared_directories": {
                    "roots": [
                        {"path": "C:\\Flat\\", "recursive": False},
                        {"path": "C:\\Tree\\", "recursive": True},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    roots = soak_launch.load_live_wire_shared_root_entries(inputs)

    assert roots == [
        "C:\\Flat\\",
        {"path": "C:\\Tree\\", "recursive": True},
    ]


def test_existing_shared_roots_counts_inaccessible_entries(tmp_path: Path) -> None:
    present = tmp_path / "present"
    present.mkdir()

    roots, skipped = soak_launch.existing_shared_roots(
        [str(present) + "\\", str(tmp_path / "missing") + "\\"]
    )

    assert roots == [str(present) + "\\"]
    assert skipped == 1


def test_converged_soak_defaults_to_persistent_rust_profile(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    persisted_profile = tmp_path / "profiles" / "rust"

    selection = runner.resolve_rust_profile_paths(
        tmp_path / "soak",
        "20260627T120000Z",
        fresh=False,
        persisted_profile_dir=persisted_profile,
    )

    assert selection == {
        "profileDir": persisted_profile.resolve(),
        "packetDumpDir": persisted_profile.resolve() / "packet-dump",
        "mode": "persistent-input",
        "fresh": False,
    }


def test_converged_soak_requires_persisted_rust_profile_for_persistent_runs(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    with pytest.raises(RuntimeError, match="rust_profile.profile_dir"):
        runner.resolve_rust_profile_paths(tmp_path / "soak", "20260627T120000Z", fresh=False)


def test_converged_soak_fresh_rust_profile_is_campaign_scoped(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    selection = runner.resolve_rust_profile_paths(tmp_path / "soak", "20260627T120000Z", fresh=True)

    assert selection == {
        "profileDir": tmp_path / "soak" / "rust-profile-20260627T120000Z",
        "packetDumpDir": tmp_path / "soak" / "rust-profile-20260627T120000Z" / "packet-dump",
        "mode": "fresh-campaign",
        "fresh": True,
    }


def test_converged_soak_poll_rest_timeout_default_covers_hashing_load() -> None:
    runner = _load_soak_runner()

    args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--lan-bind-addr", "192.0.2.10"]
    )

    assert args.poll_rest_timeout == 90.0


def test_converged_soak_downloads_are_opt_in_by_default() -> None:
    runner = _load_soak_runner()

    default_args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--lan-bind-addr", "192.0.2.10"]
    )
    auto_args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--lan-bind-addr", "192.0.2.10", "--auto-drive"]
    )
    enabled_args = runner.build_parser().parse_args(
        [
            "--inputs",
            "live-wire-inputs.local.json",
            "--lan-bind-addr",
            "192.0.2.10",
            "--seed-downloads",
            "3",
            "--auto-download-every",
            "2",
        ]
    )

    assert default_args.seed_downloads == 0
    assert default_args.auto_download_every == 0
    assert auto_args.seed_downloads == 0
    assert auto_args.auto_download_every == 0
    assert auto_args.search_profile == runner.PASSIVE_UPLOAD_SEARCH_PROFILE
    assert enabled_args.seed_downloads == 3
    assert enabled_args.auto_download_every == 2


def test_converged_soak_seed_search_interval_is_separate_from_auto_drive_interval() -> None:
    runner = _load_soak_runner()

    args = runner.build_parser().parse_args(
        [
            "--inputs",
            "live-wire-inputs.local.json",
            "--lan-bind-addr",
            "192.0.2.10",
            "--auto-search-interval",
            "1800",
            "--seed-search-interval",
            "5",
        ]
    )

    assert args.auto_search_interval == 1800.0
    assert args.seed_search_interval == 5.0


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
        rust_profile_dir=tmp_path / "rust-profile",
        shared_roots=[],
        enabled=True,
    )

    assert result == {"enabled": True, "status": "skipped", "reason": "no-mfc-profile-dir"}


def test_mfc_known_met_import_skips_when_rust_db_already_seeded(tmp_path: Path) -> None:
    import sqlite3

    runner = _load_soak_runner()

    # Missing DB reads as empty.
    assert runner.rust_share_in_place_row_count(tmp_path / "nope.sqlite") == 0

    # A persistent runtime already carrying share-in-place rows does not need
    # the expensive MFC import preseed; that path is only for empty profiles.
    mfc_profile = tmp_path / "mfc"
    known_met = mfc_profile / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"placeholder")
    db = tmp_path / "rust-profile" / "emulebb-rust-metadata.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE shared_file_sources (source_path TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO shared_file_sources VALUES ('C:/x/a.iso')")
    conn.commit()
    conn.close()
    assert runner.rust_share_in_place_row_count(db) == 1
    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=tmp_path / "rust-profile",
        shared_roots=[str(tmp_path / "share")],
        enabled=True,
    )
    assert result["status"] == "skipped"
    assert result["reason"] == "rust-db-already-seeded"
    assert result["existingSourcePaths"] == 1
    assert result["freshness"] == "not-required"


def test_mfc_known_met_import_uses_marker_freshness_when_already_seeded(
    tmp_path: Path,
) -> None:
    import sqlite3

    runner = _load_soak_runner()
    mfc_profile = tmp_path / "mfc"
    known_met = mfc_profile / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"placeholder")
    runtime = tmp_path / "rust-profile"
    db = runtime / "emulebb-rust-metadata.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE shared_file_sources (source_path TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO shared_file_sources VALUES ('C:/x/a.iso')")
    conn.commit()
    conn.close()
    signature = runner.known_met_import_signature(known_met, [str(tmp_path / "share")])
    runner.write_known_met_import_marker(runtime, signature, imported_records=1, imported_source_paths=1)

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=runtime,
        shared_roots=[str(tmp_path / "share")],
        enabled=True,
    )

    assert result["status"] == "skipped"
    assert result["reason"] == "rust-db-already-seeded"
    assert result["freshness"] == "matched"


def test_mfc_known_met_import_runs_for_empty_rust_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    mfc_profile = tmp_path / "mfc"
    known_met = mfc_profile / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"placeholder")
    runtime = tmp_path / "rust-profile"
    calls: list[dict[str, object]] = []

    def fake_import(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "knownMetRecords": 1,
            "sharedFilesScanned": 1,
            "matchedRecords": 1,
            "duplicateRecords": 0,
            "importedRecords": 1,
            "importedSourcePaths": 1,
            "dryRun": False,
            "skipped": {
                "missing_identity": 0,
                "md4_count_mismatch": 0,
                "no_path_match": 0,
                "aich_count_mismatch": 0,
            },
        }

    monkeypatch.setattr(runner, "resolve_rust_repo", lambda: tmp_path / "emulebb-rust")
    monkeypatch.setattr(runner.mfc_known_met, "import_mfc_known_met_hashes", fake_import)

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=runtime,
        shared_roots=[str(tmp_path / "share")],
        enabled=True,
    )

    assert result["status"] == "imported"
    assert len(calls) == 1
    marker = runner.load_known_met_import_marker(runtime)
    assert marker is not None
    assert marker["sharedRootCount"] == 1
    assert str(tmp_path / "share") not in json.dumps(marker)


def test_mfc_known_met_import_skips_when_disabled(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=tmp_path / "mfc",
        rust_profile_dir=tmp_path / "rust-profile",
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
            "duplicateRecords": 1,
            "importedRecords": 2,
            "importedSourcePaths": 3,
            "dryRun": False,
            "metadataDb": str(tmp_path / "private" / "emulebb-rust-metadata.db"),
            "skipped": {
                "missing_identity": 0,
                "md4_count_mismatch": 0,
                "no_path_match": 1,
                "aich_count_mismatch": 0,
            },
        }

    monkeypatch.setattr(runner.mfc_known_met, "import_mfc_known_met_hashes", fake_import)

    result = runner.import_mfc_known_met_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=tmp_path / "rust-profile",
        shared_roots=[str(tmp_path / "share")],
        enabled=True,
    )

    assert calls == [
        {
            "rust_repo": rust_repo,
            "metadata_db": tmp_path / "rust-profile" / "emulebb-rust-metadata.db",
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
        "duplicateRecords": 1,
        "importedRecords": 2,
        "importedSourcePaths": 3,
        "dryRun": False,
        "skipped": {
            "missing_identity": 0,
            "md4_count_mismatch": 0,
            "no_path_match": 1,
            "aich_count_mismatch": 0,
        },
    }


def test_mfc_shared_files_inventory_import_skips_without_inventory(tmp_path: Path) -> None:
    runner = _load_soak_runner()

    result = runner.import_mfc_shared_files_inventory_for_rust_profile(
        mfc_profile_dir=tmp_path / "mfc",
        rust_profile_dir=tmp_path / "rust-profile",
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
            "metadataDb": str(tmp_path / "private" / "emulebb-rust-metadata.db"),
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
        rust_profile_dir=tmp_path / "rust-profile",
        shared_roots=[str(tmp_path / "share")],
        inventory_path=inventory,
    )

    assert calls == [
        {"load": inventory},
        {
            "rust_repo": rust_repo,
            "metadata_db": tmp_path / "rust-profile" / "emulebb-rust-metadata.db",
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


def test_mfc_shared_files_inventory_import_skips_when_rust_db_already_seeded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    runner = _load_soak_runner()
    mfc_profile = tmp_path / "mfc"
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"data":{"items":[]}}', encoding="utf-8")
    runtime = tmp_path / "rust-profile"
    db = runtime / "emulebb-rust-metadata.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE shared_file_sources (source_path TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO shared_file_sources VALUES ('C:/x/a.iso')")
    conn.commit()
    conn.close()
    monkeypatch.setattr(
        runner.mfc_known_met,
        "load_shared_file_rows_json",
        lambda _path: pytest.fail("inventory import should not load rows for a seeded Rust profile"),
    )

    result = runner.import_mfc_shared_files_inventory_for_rust_profile(
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=runtime,
        shared_roots=[str(tmp_path / "share")],
        inventory_path=inventory,
    )

    assert result == {
        "enabled": True,
        "status": "skipped",
        "reason": "rust-db-already-seeded",
        "existingSourcePaths": 1,
    }


def test_preseed_rust_shared_roots_writes_before_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    rust_repo = tmp_path / "emulebb-rust"
    runtime = tmp_path / "runtime"
    db_path = runtime / "emulebb-rust-metadata.db"
    shared_root = soak_launch.normalize_shared_root(str(tmp_path / "share"))
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(runner, "resolve_rust_repo", lambda: rust_repo)

    def fake_create(repo: Path, db: Path) -> None:
        calls.append(("create", (repo, db)))
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_bytes(b"sqlite")

    def fake_seed(db: Path, roots: list[dict[str, object]]) -> None:
        calls.append(("seed", (db, roots)))

    monkeypatch.setattr(runner.rust_metadata, "create_metadata_db", fake_create)
    monkeypatch.setattr(runner.rust_metadata, "seed_shared_directory_roots", fake_seed)

    result = runner.preseed_rust_shared_roots_for_startup(
        rust_profile_dir=runtime,
        shared_roots=[
            {"path": str(tmp_path / "share"), "recursive": True},
            str(tmp_path / "share"),
        ],
    )

    assert calls == [
        ("create", (rust_repo, db_path)),
        (
            "seed",
            (
                db_path,
                [
                    {
                        "path": shared_root,
                        "recursive": True,
                        "monitorOwned": False,
                        "shareable": True,
                        "accessible": False,
                    }
                ],
            ),
        ),
    ]
    assert result == {
        "enabled": True,
        "status": "seeded",
        "rootCount": 1,
        "accessibleRootCount": 0,
    }


def test_converged_soak_accepts_mfc_shared_files_inventory_arg() -> None:
    runner = _load_soak_runner()

    args = runner.build_parser().parse_args(
        [
            "--inputs",
            "live-wire-inputs.local.json",
            "--lan-bind-addr",
            "192.0.2.10",
            "--mfc-shared-files-inventory",
            "inventory.json",
        ]
    )

    assert args.mfc_shared_files_inventory == "inventory.json"


def test_converged_soak_secident_knob_defaults_on() -> None:
    runner = _load_soak_runner()

    default_args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--lan-bind-addr", "192.0.2.10"]
    )
    assert default_args.secident == "on"

    off_args = runner.build_parser().parse_args(
        ["--inputs", "live-wire-inputs.local.json", "--lan-bind-addr", "192.0.2.10", "--secident", "off"]
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


def test_common_candidate_enforces_min_size_iso_and_picks_best() -> None:
    runner = _load_soak_runner()
    mib = 1024 * 1024

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return None

    rust_rows = [
        {"hash": "a" * 32, "name": "small-linux.iso", "sources": 99, "sizeBytes": 100 * mib},  # < 500 MiB
        {"hash": "b" * 32, "name": "linux-mint.zip", "sources": 80, "sizeBytes": 900 * mib},   # not .iso
        {"hash": "c" * 32, "name": "ubuntu.iso", "sources": 5, "sizeBytes": 700 * mib},
        {"hash": "d" * 32, "name": "debian.iso", "sources": 5, "sizeBytes": 900 * mib},
        {"hash": "e" * 32, "name": "fedora.iso", "sources": 20, "sizeBytes": 800 * mib},
    ]
    mfc_rows = [{"hash": h * 32} for h in "abcde"]

    # Rejects the sub-500 MiB ISO (a) and the non-ISO (b); among valid .iso >= 500 MiB
    # picks the most-sourced (fedora, e). Same file on both clients (intersection).
    candidate = runner.safe_common_download_candidate(
        rust_rows,
        mfc_rows,
        rust_mod=_RustFilter,
        required_suffix=".iso",
        min_size_bytes=500 * mib,
    )
    assert candidate is not None
    assert candidate["hash"] == "e" * 32

    # Deterministic ordering: most-sourced first, then larger ISO at equal sources.
    top = runner.top_common_download_candidates(
        rust_rows,
        mfc_rows,
        rust_mod=_RustFilter,
        required_suffix=".iso",
        min_size_bytes=500 * mib,
    )
    assert [row["hash"] for row in top] == ["e" * 32, "d" * 32, "c" * 32]


def test_common_candidate_overrides_toolarge_within_max_ceiling() -> None:
    runner = _load_soak_runner()
    mib = 1024 * 1024

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(row: dict[str, object]) -> str | None:
            # Mirrors the shared safe filter's tiny 8 MiB gentle download cap.
            return "tooLarge" if int(row.get("sizeBytes") or 0) > 8 * mib else None

    rows = [
        {"hash": "a" * 32, "name": "ubuntu.iso", "sources": 30, "sizeBytes": 629 * mib},
        {"hash": "b" * 32, "name": "huge.iso", "sources": 99, "sizeBytes": 9000 * mib},
    ]
    mfc = [{"hash": "a" * 32}, {"hash": "b" * 32}]

    # Within [500 MiB, 5 GiB] the 629 MiB ISO is accepted despite the safe filter's
    # "tooLarge" verdict; the 9000 MiB one exceeds the ceiling and stays rejected.
    top = runner.top_common_download_candidates(
        rows,
        mfc,
        rust_mod=_RustFilter,
        required_suffix=".iso",
        min_size_bytes=500 * mib,
        max_size_bytes=5 * 1024 * mib,
    )
    assert [row["hash"] for row in top] == ["a" * 32]


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


def test_automatic_cycle_download_hash_forces_repeatable_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    want = "0123456789abcdef0123456789abcdef"

    class _RustFilter:
        @staticmethod
        def safe_download_rejection_reason(_row: dict[str, object]) -> str | None:
            return "tooLarge"  # the normal picker would reject; download_hash bypasses it

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
        lambda *_a, **_k: [
            {"hash": want, "name": "synthetic-test-file.iso", "sources": 30, "sizeBytes": 629 * 1024 * 1024}
        ],
    )
    # Both clients ALREADY hold the file: download_hash must ignore the existing skip.
    monkeypatch.setattr(runner, "_get_list", lambda *_a, **_k: [{"hash": want}])
    monkeypatch.setattr(runner, "transfer_exists", lambda *_a, **_k: True)

    cycle = runner.drive_automatic_cycle(
        cycle_index=1,
        query="linux iso",
        method="server",
        rust_base="http://rust",
        mfc_base="http://mfc",
        rust_mod=_RustFilter,
        download=True,
        search_timeout_seconds=1.0,
        download_hash=want,
    )

    assert cycle["download"]["scheduled"] is True
    assert cycle["download"]["hash"] == want
    assert cycle["download"]["name"] == "synthetic-test-file.iso"


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

    assert cycle["download"]["ok"] is False
    assert cycle["download"]["reason"].startswith("no common safe candidate")
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

    assert cycle["download"]["ok"] is False
    assert cycle["download"]["reason"].startswith("no common safe candidate")
    assert cycle["downloadExistingHashCounts"] == {"rust": 0, "mfc": 0, "combined": 0}
    assert cycle["downloadExistingHashProbeSkips"] == {"rust": 1, "mfc": 0, "combined": 1}


def test_checkpoint_operator_reconnect_skips_connected_client() -> None:
    runner = _load_soak_runner()
    address, port = runner.OPERATOR_SERVER.rsplit(":", 1)

    result = runner.checkpoint_operator_reconnect(
        "http://client",
        "key",
        {"connected": True, "serverAddress": address, "serverPort": int(port)},
    )

    assert result == {"attempted": False, "reason": "already_connected"}


def test_operator_connected_requires_configured_server() -> None:
    runner = _load_soak_runner()
    address, port = runner.OPERATOR_SERVER.rsplit(":", 1)

    assert runner.operator_connected(
        {"connected": True, "serverAddress": address, "serverPort": int(port)}
    )
    assert not runner.operator_connected(
        {"connected": True, "serverAddress": "198.51.100.2", "serverPort": 5687}
    )
    assert not runner.operator_connected(
        {"connected": False, "serverAddress": address, "serverPort": int(port)}
    )
    assert runner.operator_connected(
        {"connected": True, "serverAddress": "198.51.100.2", "serverPort": 4661},
        endpoint="198.51.100.2:4661",
    )


def test_connectivity_gate_requires_both_clients_on_operator() -> None:
    runner = _load_soak_runner()
    address, port = runner.OPERATOR_SERVER.rsplit(":", 1)
    connected = {"connected": True, "serverAddress": address, "serverPort": int(port)}
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


def test_configured_server_connectivity_uses_configured_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()
    calls: list[tuple[str, str, str, str]] = []

    def fake_ensure(base_url: str, api_key: str, label: str, *, endpoint: str, **_kwargs: object) -> bool:
        calls.append((base_url, api_key, label, endpoint))
        return True

    monkeypatch.setattr(runner, "ensure_operator_and_kad", fake_ensure)

    result = runner.ensure_configured_server_connectivity(
        rust_base="http://rust",
        mfc_base="http://mfc",
        rust_endpoint="198.51.100.2:4661",
        mfc_endpoint="203.0.113.3:5687",
    )

    assert calls == [
        ("http://rust", runner.RUST_API_KEY, "rust", "198.51.100.2:4661"),
        ("http://mfc", runner.MFC_API_KEY, "mfc", "203.0.113.3:5687"),
    ]
    assert result == {
        "rust": {"ok": True, "endpoint": "198.51.100.2:4661"},
        "mfc": {"ok": True, "endpoint": "203.0.113.3:5687"},
    }


def test_configured_server_connectivity_fails_when_client_not_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_soak_runner()

    def fake_ensure(_base_url: str, _api_key: str, label: str, *, endpoint: str, **_kwargs: object) -> bool:
        del endpoint
        return label == "rust"

    monkeypatch.setattr(runner, "ensure_operator_and_kad", fake_ensure)

    with pytest.raises(RuntimeError, match="mfc"):
        runner.ensure_configured_server_connectivity(
            rust_base="http://rust",
            mfc_base="http://mfc",
            rust_endpoint="198.51.100.2:4661",
            mfc_endpoint="203.0.113.3:5687",
        )


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


def test_tracker_suppresses_baseline_transfer_even_when_rest_id_changes() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    now = runner.datetime.now(runner.timezone.utc)
    file_hash = "a" * 32

    baseline = [{"id": "old-transfer-id", "key": file_hash, "label": "Private Title.pdf"}]
    counts = tracker.prime(
        rust_searches=[],
        rust_transfers=baseline,
        mfc_searches=[],
        mfc_transfers=[],
    )

    pairs, unpaired = tracker.tick(
        now,
        rust_searches=[],
        rust_transfers=[{"id": "new-transfer-id", "key": file_hash, "label": "Private Title.pdf"}],
        mfc_searches=[],
        mfc_transfers=[],
    )

    assert counts["rustTransfers"] == 1
    assert pairs == []
    assert unpaired == []
    assert tracker.rust == []


def test_tracker_suppresses_baseline_search_even_when_rest_id_changes() -> None:
    runner = _load_soak_runner()
    tracker = runner.ActionTracker(window_seconds=90.0, settle_seconds=45.0, lead_seconds=8.0)
    now = runner.datetime.now(runner.timezone.utc)

    tracker.prime(
        rust_searches=[{"id": "old-search-id", "key": "ubuntu", "label": "Ubuntu"}],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )

    pairs, unpaired = tracker.tick(
        now,
        rust_searches=[{"id": "new-search-id", "key": "ubuntu", "label": "Ubuntu"}],
        rust_transfers=[],
        mfc_searches=[],
        mfc_transfers=[],
    )

    assert pairs == []
    assert unpaired == []
    assert tracker.rust == []


def test_trim_log_tree_preserves_diagnostic_evidence_by_default(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    dump_dir = tmp_path / "packet-dump"
    dump_dir.mkdir()
    diag = dump_dir / "emulebb-rust-diag-1.jsonl"
    packet = dump_dir / "emulebb-diagnostics-packet.log"
    daemon = tmp_path / "daemon.out"
    large_payload = (b"first\n" + (b"x" * (2 * 1024 * 1024)) + b"\n")

    diag.write_bytes(large_payload)
    packet.write_bytes(large_payload)
    daemon.write_bytes(large_payload)

    results = runner.trim_log_tree([dump_dir, daemon], max_bytes=1024)

    assert [Path(row["path"]).name for row in results] == ["daemon.out"]
    assert diag.stat().st_size == len(large_payload)
    assert packet.stat().st_size == len(large_payload)
    assert daemon.stat().st_size < len(large_payload)


def test_trim_log_tree_can_trim_diagnostic_evidence_when_requested(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    dump_dir = tmp_path / "packet-dump"
    dump_dir.mkdir()
    diag = dump_dir / "emulebb-rust-diag-1.jsonl"
    large_payload = (b"first\n" + (b"x" * (2 * 1024 * 1024)) + b"\n")
    diag.write_bytes(large_payload)

    results = runner.trim_log_tree(
        [dump_dir],
        max_bytes=1024,
        preserve_diagnostic_evidence=False,
    )

    assert [Path(row["path"]).name for row in results] == ["emulebb-rust-diag-1.jsonl"]
    assert diag.stat().st_size < len(large_payload)


def test_load_diag_includes_mfc_bad_peer_adapter(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    diag = tmp_path / "emulebb-diagnostics-diag.log"
    bad_peer = tmp_path / "emulebb-diagnostics-bad-peer.log"
    diag.write_text(
        '{"schema":"diag_event_v1","family":"sched","event":"tick","ts":"2026-07-06T12:00:00.000Z","body":{}}\n',
        encoding="utf-8",
    )
    bad_peer.write_text(
        '{"schema":"bad_peer_event_v1","event":"upload_repeat_block_request_observed",'
        '"severity":"medium","ts_utc":"2026-07-06T12:00:01.000Z",'
        '"peer":{"address":"192.0.2.10","user_port":4662},'
        '"file":{"hash":"ABCDEF"},"evidence":{"repeat_count":3}}\n',
        encoding="utf-8",
    )

    records = runner.load_diag(tmp_path, side="emule")

    assert [(record["family"], record["event"]) for record in records] == [
        ("sched", "tick"),
        ("bad_peer", "repeat_block_request"),
    ]
    assert records[1]["keys"]["fileHash"] == "abcdef"
    assert records[1]["body"]["repeatCount"] == 3


def test_load_diag_mtime_filter_applies_to_mfc_bad_peer_adapter(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    stale = tmp_path / "emulebb-diagnostics-bad-peer-20260706-120000.log"
    fresh = tmp_path / "emulebb-diagnostics-bad-peer.log"
    stale.write_text(
        '{"schema":"bad_peer_event_v1","event":"upload_repeat_block_request_observed","ts_utc":"2026-07-06T12:00:00.000Z"}\n',
        encoding="utf-8",
    )
    fresh.write_text(
        '{"schema":"bad_peer_event_v1","event":"upload_repeat_file_request_observed","ts_utc":"2026-07-06T12:00:10.000Z"}\n',
        encoding="utf-8",
    )
    os.utime(stale, (100.0, 100.0))
    os.utime(fresh, (200.0, 200.0))

    records = runner.load_diag(tmp_path, side="emule", min_mtime=150.0)

    assert [(record["family"], record["event"]) for record in records] == [
        ("bad_peer", "repeat_file_request")
    ]


def test_share_warmup_parity_risk_reports_cold_fresh_rust_profile(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    checkpoints = tmp_path / "checkpoints"
    checkpoints.mkdir()
    (checkpoints / "000001Z.json").write_text(
        json.dumps(
            {
                "restStatus": {
                    "rust": {"sharedFileCount": 1200, "sharedHashingCount": 50000},
                    "mfc": {"sharedFileCount": 60000, "sharedHashingCount": 0},
                }
            }
        ),
        encoding="utf-8",
    )
    summary = {
        "environmentParity": {"freshRustProfile": True},
        "mfcKnownMetImport": {"knownMetRecords": 100000, "importedRecords": 3000},
        "mfcSharedFilesInventoryImport": {"status": "skipped", "reason": "no-inventory"},
    }

    risks = runner.build_share_warmup_parity_risk(summary, checkpoints)

    assert len(risks) == 1
    risk = risks[0]
    assert risk["kind"] == "rust-share-cache-cold"
    assert risk["scope"] == "upload-peer-protocol"
    assert risk["rustSharedHashingCount"] == 50000
    assert risk["mfcKnownMetImportRatio"] == 0.03
    assert risk["mfcSharedFilesInventoryReason"] == "no-inventory"


def test_share_warmup_parity_risk_ignores_persistent_or_warm_runs(tmp_path: Path) -> None:
    runner = _load_soak_runner()
    checkpoints = tmp_path / "checkpoints"
    checkpoints.mkdir()
    (checkpoints / "000001Z.json").write_text(
        json.dumps(
            {
                "restStatus": {
                    "rust": {"sharedFileCount": 60000, "sharedHashingCount": 0},
                    "mfc": {"sharedFileCount": 60000, "sharedHashingCount": 0},
                }
            }
        ),
        encoding="utf-8",
    )

    assert runner.build_share_warmup_parity_risk(
        {"environmentParity": {"freshRustProfile": False}},
        checkpoints,
    ) == []
    assert runner.build_share_warmup_parity_risk(
        {"environmentParity": {"freshRustProfile": True}},
        checkpoints,
    ) == []
