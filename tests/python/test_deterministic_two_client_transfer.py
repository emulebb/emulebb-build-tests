from __future__ import annotations

import importlib.util
import json
import re
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import ed2k_server as ed2k_harness
from emule_test_harness import rust_ed2k


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


def load_script_module(filename: str, module_name: str):
    """Loads one hyphenated script by filename for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_resolve_manifest_repo_uses_workspace_deps(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    repo = tmp_path / "repos" / "ed2k-server"
    workspace.mkdir(parents=True)
    repo.mkdir(parents=True)
    (repo / "Cargo.toml").write_text("[package]\nname = 'ed2k-server'\n", encoding="utf-8")
    (workspace / "deps.json").write_text(
        json.dumps({"workspace": {"repos": {"ed2k_server": "..\\..\\repos\\ed2k-server"}}}),
        encoding="utf-8",
    )

    assert module.resolve_manifest_repo(workspace, "ed2k_server") == repo.resolve()


def test_source_lifecycle_arguments_are_opt_in() -> None:
    module = load_suite_module()

    defaults = module.parse_args(["--lan-bind-addr", "192.0.2.10"])
    enabled = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--verify-source-lifecycle",
            "--source-withdraw-timeout-seconds",
            "45",
        ]
    )

    assert defaults.verify_source_lifecycle is False
    assert defaults.verify_offerfiles_v1_stock_fallback is False
    assert defaults.source_withdraw_timeout_seconds == 30.0
    assert enabled.verify_source_lifecycle is True
    assert enabled.source_withdraw_timeout_seconds == 45.0


def test_offerfiles_v1_fallback_requires_stock_family_lifecycle() -> None:
    module = load_suite_module()
    wrong_client = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--verify-source-lifecycle",
            "--verify-offerfiles-v1-stock-fallback",
        ]
    )
    missing_lifecycle = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--client2-identity",
            "stock_emule",
            "--verify-offerfiles-v1-stock-fallback",
        ]
    )

    with pytest.raises(ValueError, match="stock_emule or amule"):
        module.validate_args(wrong_client)
    with pytest.raises(ValueError, match="requires --verify-source-lifecycle"):
        module.validate_args(missing_lifecycle)


def test_offerfiles_v1_fallback_accepts_zero_negotiation_counters() -> None:
    module = load_suite_module()
    stats = {
        "ok": True,
        "data": {
            "offerfiles_v1": True,
            "offerfiles_v1_error": None,
            "offerfiles_v1_policy": "max 200 records every 500 ms",
            "offer_v1": {
                "requested": 0,
                "sessions": 0,
                "batches": 0,
                "records": 0,
                "oversized": 0,
            },
        },
    }

    evidence = module.require_offerfiles_v1_stock_fallback(
        stats,
        client_identity="stock_emule",
    )

    assert evidence["serverExtensionEnabled"] is True
    assert evidence["customCapabilityRequested"] is False
    assert evidence["customAdvertisementSent"] is False


def test_offerfiles_v1_fallback_rejects_negotiated_session() -> None:
    module = load_suite_module()
    stats = {
        "data": {
            "offerfiles_v1": True,
            "offerfiles_v1_error": None,
            "offerfiles_v1_policy": "valid",
            "offer_v1": {"requested": 1, "sessions": 1},
        }
    }

    with pytest.raises(RuntimeError, match="leaked into OFFERFILES v1 negotiation"):
        module.require_offerfiles_v1_stock_fallback(stats, client_identity="amule")


def test_known_met_fixture_builds_stock_ed2k_link(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    known_met = tmp_path / "known.met"
    expected = SimpleNamespace(
        name="fixture with spaces.bin",
        size_bytes=123,
        ed2k_hash="ab" * 16,
    )
    monkeypatch.setattr(
        module.mfc_known_met,
        "parse_known_met",
        lambda path: [SimpleNamespace(name="other.bin", size_bytes=1), expected] if path == known_met else [],
    )

    entry = module.require_known_met_fixture(
        known_met,
        file_name="fixture with spaces.bin",
        file_size=123,
    )

    assert entry is expected
    assert module.known_met_entry_link(entry) == (
        "ed2k://|file|fixture%20with%20spaces.bin|123|ABABABABABABABABABABABABABABABAB|/"
    )


def test_require_known_met_fixture_rejects_missing_row(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module.mfc_known_met, "parse_known_met", lambda _path: [])

    with pytest.raises(RuntimeError, match="found 0"):
        module.require_known_met_fixture(
            tmp_path / "known.met",
            file_name="fixture.bin",
            file_size=123,
        )


def test_env_ed2k_server_exe_override_uses_shared_harness_env() -> None:
    assert ed2k_harness.env_ed2k_server_exe_override({}) is None
    assert ed2k_harness.env_ed2k_server_exe_override({ed2k_harness.ED2K_SERVER_EXE_ENV: "  "}) is None
    assert (
        ed2k_harness.env_ed2k_server_exe_override(
            {ed2k_harness.ED2K_SERVER_EXE_ENV: "C:/tools/ed2k-server"}
        )
        == "C:/tools/ed2k-server"
    )


def test_with_ed2k_server_exe_env_returns_child_env_copy(tmp_path: Path) -> None:
    base_env = {"KEEP": "1"}
    server_exe = tmp_path / "tools" / "ed2k-server"

    child_env = ed2k_harness.with_ed2k_server_exe_env(base_env, server_exe)

    assert child_env["KEEP"] == "1"
    assert child_env[ed2k_harness.ED2K_SERVER_EXE_ENV] == str(server_exe.resolve())
    assert ed2k_harness.ED2K_SERVER_EXE_ENV not in base_env


def test_stop_server_processes_delegates_to_rust_runtime(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(rust_ed2k, "stop_server_processes", lambda: calls.append("stop"))

    ed2k_harness.stop_server_processes()

    assert calls == ["stop"]


def test_prepare_ed2k_server_binary_centralizes_resolution_and_build(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    server_exe = tmp_path / "tools" / "ed2k-server"
    calls: dict[str, object] = {}

    def prepare_binary(workspace_root: Path, **kwargs: object) -> SimpleNamespace:
        calls["workspace_root"] = workspace_root
        calls.update(kwargs)
        return SimpleNamespace(server_exe=server_exe.resolve(), build={"implementation": "rust"})

    monkeypatch.setattr(rust_ed2k, "prepare_server_binary", prepare_binary)

    prepared = ed2k_harness.prepare_ed2k_server_binary(
        workspace,
        repo_override="repo-override",
        exe_override=str(server_exe),
    )

    assert prepared.server_exe == server_exe.resolve()
    assert prepared.build == {"implementation": "rust"}
    assert calls == {
        "workspace_root": workspace,
        "repo_override": "repo-override",
        "exe_override": str(server_exe),
    }


def test_resolve_client2_app_exe_uses_emulebb_main_executable(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    client2_exe = workspace / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"
    client2_exe.parent.mkdir(parents=True)
    client2_exe.write_bytes(b"")

    assert module.resolve_client2_app_exe(workspace, "Release", None) == client2_exe.resolve()


def test_resolve_client2_app_exe_honors_override(tmp_path: Path) -> None:
    module = load_suite_module()
    override = tmp_path / "custom" / "harness.exe"
    override.parent.mkdir()
    override.write_bytes(b"")

    assert module.resolve_client2_app_exe(tmp_path / "workspace", "Release", str(override)) == override.resolve()


def test_resolve_client2_app_exe_uses_stock_baseline_identity(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    stock_exe = workspace / "app" / "emulebb-community-baseline" / "srchybrid" / "x64" / "Release" / "emule.exe"
    stock_exe.parent.mkdir(parents=True)
    stock_exe.write_bytes(b"")

    assert module.resolve_client2_app_exe(workspace, "Release", None, "stock_emule") == stock_exe.resolve()


def test_is_port_available_accepts_explicit_loopback() -> None:
    module = load_suite_module()

    assert module.is_port_available(0, host="127.0.0.1")


def test_is_port_available_rejects_wildcard_bind() -> None:
    module = load_suite_module()

    with pytest.raises(ValueError, match="all network interfaces"):
        module.is_port_available(0, host="0.0.0.0")


@pytest.mark.parametrize("host", ["", "localhost", "::1"])
def test_is_port_available_rejects_non_ipv4_address(host: str) -> None:
    module = load_suite_module()

    with pytest.raises(ValueError, match="explicit IPv4"):
        module.is_port_available(0, host=host)


def test_choose_distinct_ports_probes_explicit_lan_bind_addr(monkeypatch) -> None:
    module = load_suite_module()
    availability_checks: list[tuple[int, str | None, bool]] = []

    def fake_is_port_available(
        port: int,
        *,
        host: str,
        udp: bool = False,
    ) -> bool:
        availability_checks.append((port, host, udp))
        return True

    monkeypatch.setattr(module, "is_port_available", fake_is_port_available)
    monkeypatch.setattr(module, "ED2K_LOCAL_PORT_MIN", 6200)
    monkeypatch.setattr(module, "ED2K_LOCAL_PORT_MAX", 6209)
    monkeypatch.setattr(module.random, "randrange", lambda _start, _stop: 6200)

    ports = module.choose_distinct_ports("172.24.112.1")

    assert ports["ed2k_tcp"] == 6200
    assert ports["ed2k_udp"] == 6204
    assert ports["ed2k_admin"] == 6201
    assert ports["client1_rest"] == 6202
    assert ports["client2_rest"] == 6203
    assert ports["client1_tcp"] == 6205
    assert ports["client1_udp"] == 6206
    assert ports["client2_tcp"] == 6207
    assert ports["client2_udp"] == 6208
    assert ports["client2_ec"] == 6209
    assert all(
        host == ("127.0.0.1" if port == ports["client2_ec"] else "172.24.112.1")
        for port, host, _udp in availability_checks
    )
    assert availability_checks[:2] == [
        (6200, "172.24.112.1", False),
        (6204, "172.24.112.1", True),
    ]
    assert (6206, "172.24.112.1", True) in availability_checks
    assert (6208, "172.24.112.1", True) in availability_checks
    assert (6209, "127.0.0.1", False) in availability_checks


def test_godzilla_choose_ports_probes_explicit_lan_bind_addr(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_port_bind_test")
    observed: dict[str, str | None] = {}
    availability_checks: list[tuple[int, str | None, bool]] = []
    next_port = iter(range(6300, 6310))

    def fake_choose_distinct_ports(host: str | None = None) -> dict[str, int]:
        observed["dtt_host"] = host
        return {"ed2k_tcp": 4662, "ed2k_udp": 4672, "client1_tcp": 4663, "client1_udp": 4673, "client1_rest": 4711}

    def fake_choose_listen_port(host: str | None = None) -> int:
        observed["extra_host"] = host
        return next(next_port)

    def fake_is_port_available(port: int, *, host: str | None = None, udp: bool = False) -> bool:
        availability_checks.append((port, host, udp))
        return True

    monkeypatch.setattr(godzilla.dtt, "choose_distinct_ports", fake_choose_distinct_ports)
    monkeypatch.setattr(godzilla.rest_smoke, "choose_listen_port", fake_choose_listen_port)
    monkeypatch.setattr(godzilla.dtt, "is_port_available", fake_is_port_available)

    ports = godzilla.choose_ports(extra_emulebb_clients=1, lan_bind_addr="172.24.112.3")

    assert ports["extra_emulebb_0_rest"] == 6302
    assert observed == {"dtt_host": "172.24.112.3", "extra_host": "172.24.112.3"}
    assert all(host == "172.24.112.3" for _port, host, _udp in availability_checks)


def test_discover_interface_ipv4_falls_back_to_hostname_when_windows_adapter_query_fails(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(
        module.windows_processes,
        "collect_adapter_ipv4_addresses",
        lambda _interface_name="": (_ for _ in ()).throw(RuntimeError("wmi unavailable")),
    )
    monkeypatch.setattr(module.socket, "gethostname", lambda: "host")
    monkeypatch.setattr(module.socket, "getfqdn", lambda: "host.local")
    monkeypatch.setattr(
        module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(module.socket.AF_INET, None, None, None, ("192.0.2.10", 0))],
    )

    assert module.discover_interface_ipv4("") == "192.0.2.10"


def test_discover_interface_ipv4_reports_named_interface_adapter_query_failure(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(
        module.windows_processes,
        "collect_adapter_ipv4_addresses",
        lambda _interface_name="": (_ for _ in ()).throw(RuntimeError("wmi unavailable")),
    )

    with pytest.raises(RuntimeError, match="Ethernet"):
        module.discover_interface_ipv4("Ethernet")


def test_resolve_lan_p2p_bind_address_defaults_to_lan_bind(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "discover_interface_ipv4", lambda _name: "192.0.2.99")

    assert module.resolve_lan_p2p_bind_address(lan_bind_addr="192.0.2.10") == "192.0.2.10"


def test_resolve_lan_p2p_bind_address_honors_explicit_interface(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "discover_interface_ipv4", lambda name: f"192.0.2.{len(name)}")

    assert module.resolve_lan_p2p_bind_address(
        lan_bind_addr="192.0.2.10",
        p2p_bind_interface_name="Ethernet",
    ) == "192.0.2.8"


def test_resolve_lan_p2p_bind_address_honors_explicit_address(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "discover_interface_ipv4", lambda _name: "192.0.2.99")

    assert module.resolve_lan_p2p_bind_address(
        lan_bind_addr="192.0.2.10",
        p2p_bind_interface_name="Ethernet",
        p2p_bind_interface_address="192.0.2.44",
    ) == "192.0.2.44"


def test_write_server_met_creates_single_server_with_numeric_and_dynamic_ip(tmp_path: Path) -> None:
    module = load_suite_module()
    server_met = tmp_path / "profile" / "config" / "server.met"

    module.write_server_met(server_met, address="10.44.55.66", port=4711, name="local-ed2k")

    data = server_met.read_bytes()
    assert data[:5] == struct.pack("<BI", module.SERVER_MET_HEADER, 1)
    assert data[5:9] == bytes([10, 44, 55, 66])
    port, tag_count = struct.unpack("<HI", data[9:15])
    assert port == 4711
    assert tag_count == 3
    assert b"local-ed2k" in data
    assert b"10.44.55.66" in data


def test_deterministic_transfer_uses_canonical_server_facade() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "ed2k_server.launch_ed2k_server(" in script_text
    assert "ed2k_server.ed2k_server_control(" in script_text
    assert "ed2k_server.stop_process(server_process)" in script_text
    assert "server_provider" not in script_text
    assert "admin_secret=args.api_key" in script_text
    assert "ed2k_address=p2p_address" in script_text
    assert "address=server_address" in script_text


def test_wait_for_server_file_endpoint_reuses_shared_admin_polling(monkeypatch) -> None:
    expected = {
        "hash": "00112233445566778899AABBCCDDEEFF",
        "name": "fixture.bin",
        "endpoints": [{"host": "192.0.2.10", "port": 4662}],
    }
    calls: list[tuple[object, ...]] = []

    class FakeControl:
        @staticmethod
        def wait_for_file_endpoint(*args: object) -> dict[str, object]:
            calls.append(args)
            return expected

    monkeypatch.setattr(ed2k_harness, "ed2k_server_control", lambda *_args: FakeControl())

    row = ed2k_harness.wait_for_server_file_endpoint(
        "http://192.0.2.10:8080",
        "secret",
        "00112233445566778899aabbccddeeff",
        "192.0.2.10",
        4662,
        1.0,
    )

    assert row["name"] == "fixture.bin"
    assert calls == [
        (
            "00112233445566778899aabbccddeeff",
            "192.0.2.10",
            4662,
            1.0,
            "ED2K server file endpoint publication",
        )
    ]


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


def test_wait_for_emule_shared_file_link_uses_explicit_pagination(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[str] = []
    fixture_hash = "0123456789abcdef0123456789abcdef"

    def fake_http_request(_base_url, path, **_kwargs):
        calls.append(path)
        if path == "/api/v1/shared-files?offset=0&limit=100":
            return {"status": 200, "json": {"items": [{"name": "fixture.bin", "hash": fixture_hash.upper()}]}}
        return {"status": 200, "json": {"link": f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.wait_for_emule_shared_file_link(
        "http://127.0.0.1:4711",
        "secret",
        file_name="fixture.bin",
        timeout_seconds=1.0,
    )

    assert calls[0] == "/api/v1/shared-files?offset=0&limit=100"
    assert calls[1] == f"/api/v1/shared-files/{fixture_hash}/ed2k-link"
    assert result["hash"] == fixture_hash


def test_wait_for_emule_shared_file_link_accepts_link_variants(monkeypatch) -> None:
    module = load_suite_module()
    fixture_hash = "0123456789abcdef0123456789abcdef"

    def fake_http_request(_base_url, path, **_kwargs):
        if path == "/api/v1/shared-files?offset=0&limit=100":
            return {"status": 200, "json": [{"name": "fixture.bin", "hash": fixture_hash}]}
        return {"status": 200, "json": {"ed2kLinks": [f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"]}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.wait_for_emule_shared_file_link(
        "http://127.0.0.1:4711",
        "secret",
        file_name="fixture.bin",
        timeout_seconds=1.0,
    )

    assert result["link"] == f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"


def test_wait_for_emule_shared_file_link_falls_back_to_published_row(monkeypatch) -> None:
    module = load_suite_module()
    fixture_hash = "0123456789abcdef0123456789abcdef"

    def fake_http_request(_base_url, path, **_kwargs):
        if path == "/api/v1/shared-files?offset=0&limit=100":
            return {
                "status": 200,
                "raw_json": {
                    "data": {
                        "items": [
                            {
                                "name": "fixture.bin",
                                "hash": fixture_hash.upper(),
                                "publishedEd2k": True,
                                "sizeBytes": 123,
                            }
                        ]
                    },
                    "meta": {"apiVersion": "v1"},
                },
            }
        return {"status": 404, "body_text": "missing"}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    result = module.wait_for_emule_shared_file_link(
        "http://127.0.0.1:4711",
        "secret",
        file_name="fixture.bin",
        timeout_seconds=1.0,
    )

    assert result["link"] == f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"
    assert result["observations"][-1]["link_source"] == "shared_file_row"


def test_wait_for_emule_shared_file_link_reports_list_failures(monkeypatch) -> None:
    module = load_suite_module()

    monkeypatch.setattr(
        module.rest_smoke,
        "http_request",
        lambda *_args, **_kwargs: {"status": 503, "body_text": "not ready"},
    )
    monkeypatch.setattr(
        module.rest_smoke,
        "require_json_array",
        lambda _result, _status: (_ for _ in ()).throw(AssertionError("not an array")),
    )
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    with pytest.raises(RuntimeError) as exc_info:
        module.wait_for_emule_shared_file_link(
            "http://127.0.0.1:4711",
            "secret",
            file_name="fixture.bin",
            timeout_seconds=1.0,
        )

    message = str(exc_info.value)
    assert "Timed out waiting for eMuleBB shared link" in message
    assert "'status': 503" in message


def test_write_fixture_file_is_deterministic(tmp_path: Path) -> None:
    module = load_suite_module()
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = module.write_fixture_file(first, 4097)
    second_hash = module.write_fixture_file(second, 4097)

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == module.file_sha256(first)


def test_write_fixture_file_seed_changes_bytes(tmp_path: Path) -> None:
    module = load_suite_module()
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = module.write_fixture_file(first, 4097)
    second_hash = module.write_fixture_file(second, 4097, seed=0xE1BB2026)

    assert first.read_bytes() != second.read_bytes()
    assert first_hash != second_hash
    assert second_hash == module.file_sha256(second)


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
        app_exe=tmp_path / "app" / "emulebb.exe",
        nick=module.CLIENT01.nick,
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=False,
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "FilterBadIPs=0" in emule_section
    assert "IPFilterEnabled=0" in emule_section
    assert f"DownloadCapacity={module.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB}" in emule_section
    assert f"UploadCapacity={module.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB}" in emule_section
    assert f"UploadCapacityNew={module.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB}" in emule_section
    assert f"MaxUpload={module.DETERMINISTIC_BANDWIDTH_LIMIT_KIB}" in emule_section
    assert f"MaxDownload={module.DETERMINISTIC_BANDWIDTH_LIMIT_KIB}" in emule_section
    assert "MaxUploadClientsAllowed=32" in text
    assert module.read_preferences_snapshot(config_dir)["CryptLayerSupported"] is None
    assert "SaveLogToDisk=1" in emule_section
    assert "SaveDebugToDisk=1" in emule_section
    assert "VerboseOptions=1" in emule_section
    assert "Verbose=1" in emule_section
    assert "FullVerbose=1" in emule_section
    assert "MaxLogFileSize=10485760" in emule_section
    assert "MaxLogBuff=256" in emule_section
    assert "CommitFiles=2" in emule_section
    assert "FileBufferSize=16384" in emule_section
    assert "FileBufferTimeLimit=1" in emule_section
    assert "AllocateFullFile=0" in emule_section
    assert "SparsePartFiles=0" in emule_section
    assert f"Nick={module.CLIENT01.nick}" in emule_section
    assert "EnableUPnP=0" in text


def test_configure_client_profile_can_apply_protocol_obfuscation_preferences(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\n[WebServer]\n")

    module.configure_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emulebb.exe",
        nick=module.CLIENT01.nick,
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=True,
        p2p_bind_addr="192.0.2.10",
        crypt_layer_supported=True,
        crypt_layer_requested=True,
        crypt_layer_required=True,
        crypt_tcp_padding_length=128,
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "BindAddr=192.0.2.10" in emule_section
    assert "CryptLayerSupported=1" in emule_section
    assert "CryptLayerRequested=1" in emule_section
    assert "CryptLayerRequired=1" in emule_section
    assert "CryptTCPPaddingLength=128" in emule_section


def test_configure_client_profile_prefers_p2p_interface_over_bind_address(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\n[WebServer]\n")

    module.configure_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emulebb.exe",
        nick=module.CLIENT01.nick,
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=True,
        p2p_bind_interface_name="hide.me",
        p2p_bind_addr="10.54.210.222",
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "BindInterface=hide.me" in emule_section
    assert re.search(r"BindAddr=\r?\n", emule_section)
    assert "BindAddr=10.54.210.222" not in emule_section
    assert "BlockNetworkWhenBindUnavailableAtStartup=1" in emule_section


def test_configure_client_profile_preserves_recursive_shared_directory_contract(tmp_path: Path) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_recursive_share_test")
    root = tmp_path / "library"
    (root / "000").mkdir(parents=True)
    (root / "001").mkdir()
    (root / "000" / "a.bin").write_bytes(b"a")
    (root / "001" / "b.bin").write_bytes(b"b")

    shared_dirs = godzilla.generated_library_shared_dirs(root)

    assert shared_dirs == [
        godzilla.live_common.win_path(root, trailing_slash=True),
        godzilla.live_common.win_path(root / "000", trailing_slash=True),
        godzilla.live_common.win_path(root / "001", trailing_slash=True),
    ]


def test_godzilla_runtime_root_is_drive_letter_only() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_runtime_root_test")

    assert godzilla.parse_args(["--lan-bind-addr", "192.0.2.10"]).vhd_runtime_root == "drive-letter"
    with pytest.raises(SystemExit):
        godzilla.parse_args(["--lan-bind-addr", "192.0.2.10", "--vhd-runtime-root", "folder-mount"])


def test_godzilla_stage_defaults_to_full_and_accepts_launch_scale() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_stage_test")

    assert godzilla.parse_args(["--lan-bind-addr", "192.0.2.10"]).stage == "full"
    assert godzilla.parse_args(["--lan-bind-addr", "192.0.2.10", "--stage", "launch-scale"]).stage == "launch-scale"
    with pytest.raises(SystemExit):
        godzilla.parse_args(["--lan-bind-addr", "192.0.2.10", "--stage", "unknown"])


def test_godzilla_lan_mode_uses_x_local_ip(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_lan_env_test")
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    args = godzilla.parse_args(["--lan-bind-addr", "192.0.2.10"])
    godzilla.validate_args(args)

    assert args.total_client_count == 30
    assert args.extra_emulebb_clients == 27
    assert godzilla.resolve_local_p2p_address(args) == "192.0.2.10"
    assert godzilla.resolve_lan_bind_addr(args, "192.0.2.10") == "192.0.2.10"


def test_godzilla_generate_library_reports_failed_path(monkeypatch, tmp_path: Path) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_generate_library_error_test")
    args = godzilla.parse_args(
        [
            "--total-client-count",
            "3",
            "--lan-bind-addr",
            "192.0.2.10",
            "--emulebb-files",
            "1",
            "--harness-files",
            "1",
            "--vhd-size-mb",
            "4103",
        ]
    )
    godzilla.validate_args(args)

    def fail_write(_path: Path, *, size_bytes: int, seed: int) -> str:
        raise PermissionError("denied")

    monkeypatch.setattr(godzilla, "write_generated_file", fail_write)

    with pytest.raises(RuntimeError) as exc_info:
        godzilla.generate_library(tmp_path / "library", owner_key="emulebb", count=1, args=args)

    message = str(exc_info.value)
    assert "owner='emulebb'" in message
    assert "index=0" in message
    assert "emulebb-godzilla-00000" in message


def test_godzilla_spiral_hammer_runs_rest_actions_without_optional_clients(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_rest_spiral_test")

    monkeypatch.setattr(godzilla, "server_telemetry_snapshot", lambda *_args: {"stats": {"clients": 2}})
    monkeypatch.setattr(godzilla.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(godzilla.rest_smoke, "http_request", lambda *_args, **_kwargs: {"status": 200, "json": []})
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    report = godzilla.run_spiral_hammer(
        base_url="http://127.0.0.1:1",
        api_key="secret",
        admin_base_url="http://127.0.0.1:2",
        links=["ed2k://|file|a.bin|1|0123456789ABCDEF0123456789ABCDEF|/"],
        queries=["emulebb-godzilla-"],
        waves=1,
        sleep_seconds=0.0,
    )

    assert {action["kind"] for action in report["waves"][0]["actions"]} == {"rest-search", "rest-add", "rest-churn"}


def test_godzilla_mixed_client_evidence_reports_mfc_peer_swarm() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_mfc_peer_evidence_test")

    evidence = godzilla.classify_godzilla_mixed_client_evidence(queued_transfer_counts={"harness": 7})

    assert evidence["classification"] == "emulebb-mfc-peer-swarm"
    assert evidence["evidence_strength"] == "full"
    assert evidence["optional_clients"] == []
    assert evidence["mfc_peer"]["queued_transfer_count"] == 7


def test_godzilla_transfer_row_hashes_use_live_rest_identifiers() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_transfer_row_hash_test")

    rows = [
        {"hash": "aaa"},
        {"fileHash": "bbb"},
        {"id": 123},
        {"name": "missing-hash"},
    ]

    assert godzilla.transfer_row_hashes(rows) == ["aaa", "bbb", "123"]


def test_godzilla_app_process_id_uses_live_common_resolver(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_app_process_id_test")

    class AppWithBrokenProcessMethod:
        def process(self):
            raise TypeError("'int' object is not callable")

    monkeypatch.setattr(godzilla.live_common, "resolve_app_process_id", lambda _app: 4242)

    assert godzilla.app_process_id(AppWithBrokenProcessMethod()) == 4242


def test_godzilla_queue_downloads_uses_retry_rest_request(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_retry_queue_test")
    calls: list[tuple[str, str]] = []

    def fake_retry(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        return {"status": 200, "json": {"queued": True}, "transient_errors": [{"type": "ConnectionResetError"}]}

    monkeypatch.setattr(godzilla.dtt, "retry_rest_request", fake_retry)
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    rows = godzilla.queue_emulebb_downloads("http://127.0.0.1:4711", "key", ["ed2k://|file|a|1|0|/"])

    assert rows == [{"status": 200}]
    assert calls == [("POST", "/api/v1/transfers")]


def test_godzilla_spiral_hammer_searches_use_retry_rest_request(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_retry_spiral_test")
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_retry(_base_url, path, *, method="GET", json_body=None, **_kwargs):
        calls.append((method, path, dict(json_body or {})))
        return {"status": 200, "json": {"id": "search-1"}, "transient_errors": [{"type": "ConnectionAbortedError"}]}

    monkeypatch.setattr(godzilla.dtt, "retry_rest_request", fake_retry)
    monkeypatch.setattr(godzilla, "server_telemetry_snapshot", lambda *_args, **_kwargs: {"ok": True})
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    result = godzilla.run_spiral_hammer(
        base_url="http://127.0.0.1:4711",
        api_key="key",
        admin_base_url="http://127.0.0.1:8080",
        links=[],
        queries=["alpha", "beta", "gamma"],
        waves=1,
        sleep_seconds=0.0,
    )

    assert result["waves"][0]["actions"][:3] == [
        {"kind": "rest-search", "query": "beta", "response": {"status": 200}},
        {"kind": "rest-search", "query": "gamma", "response": {"status": 200}},
        {"kind": "rest-search", "query": "alpha", "response": {"status": 200}},
    ]
    assert calls == [
        ("POST", "/api/v1/searches", {"query": "beta", "method": "server", "type": ""}),
        ("POST", "/api/v1/searches", {"query": "gamma", "method": "server", "type": ""}),
        ("POST", "/api/v1/searches", {"query": "alpha", "method": "server", "type": ""}),
    ]


def test_godzilla_control_plane_search_hammer_uses_retry_rest_request(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_retry_control_search_test")
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_retry(_base_url, path, *, method="GET", json_body=None, **_kwargs):
        calls.append((method, path, dict(json_body or {})))
        return {"status": 200, "json": {"id": "search-1"}, "transient_errors": [{"type": "ConnectionAbortedError"}]}

    monkeypatch.setattr(godzilla.dtt, "retry_rest_request", fake_retry)
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(godzilla.rest_smoke, "wait_for_search_observation", lambda *_args, **_kwargs: {"observed": True})
    monkeypatch.setattr(godzilla.rest_smoke, "delete_all_searches", lambda *_args, **_kwargs: {"status": 200})

    result = godzilla.run_emulebb_search_hammer(
        "http://127.0.0.1:4711",
        "key",
        queries=["alpha", "beta"],
        rounds=2,
    )

    assert [row["start"] for row in result["rounds"]] == [{"status": 200}, {"status": 200}]
    assert [row["observation"] for row in result["rounds"]] == [{"observed": True}, {"observed": True}]
    assert result["cleanup"] == {"status": 200}
    assert calls == [
        ("POST", "/api/v1/searches", {"query": "alpha", "method": "server", "type": ""}),
        ("POST", "/api/v1/searches", {"query": "beta", "method": "server", "type": ""}),
    ]


def test_godzilla_log_marker_scan_counts_and_samples(tmp_path: Path) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_log_marker_scan_test")
    log_path = tmp_path / "emulebb-verbose.log"
    log_path.write_text(
        "\n".join(
            [
                "normal line",
                "Banned: Aggressive behaviour",
                "Clients: peer, Ban reason: Userhash changed (Found in TrackedClientsList)",
                "Removing client from upload list: Remote client cancelled transfer. In buffer: 16777216.00 TB",
            ]
        ),
        encoding="utf-8",
    )

    report = godzilla.scan_log_markers(
        {"primary": log_path},
        ["Banned:", "Ban reason:", "Userhash changed", "Remote client cancelled transfer", "In buffer: 16777216.00 TB"],
    )

    assert report["primary"]["counts"] == {
        "Banned:": 1,
        "Ban reason:": 1,
        "Userhash changed": 1,
        "Remote client cancelled transfer": 1,
        "In buffer: 16777216.00 TB": 1,
    }
    assert len(report["primary"]["samples"]) == 5


def test_godzilla_rejects_loopback_lan_bind(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_lan_loopback_test")
    args = godzilla.parse_args(
        [
            "--total-client-count",
            "3",
            "--lan-bind-addr",
            "127.0.0.1",
            "--emulebb-files",
            "1",
            "--harness-files",
            "1",
            "--vhd-size-mb",
            "4103",
        ]
    )
    godzilla.validate_args(args)

    with pytest.raises(RuntimeError):
        godzilla.resolve_local_p2p_address(args)


def test_godzilla_local_swarm_reuses_shared_ed2k_harness_launcher() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_ed2k_harness_launcher_test")
    script_text = Path(godzilla.__file__).read_text(encoding="utf-8")

    assert "ed2k_harness.launch_ed2k_server(" in script_text
    assert "ed2k_harness.start_ed2k_server(" not in script_text
    assert "ed2k_harness.build_server_config(" not in script_text


def test_default_fixture_size_is_132_mib() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert module.DEFAULT_FIXTURE_SIZE_BYTES == 132 * 1024 * 1024
    assert args.fixture_size_bytes == module.DEFAULT_FIXTURE_SIZE_BYTES
    assert args.transfer_completion_timeout_seconds == 900.0
    assert args.client2_identity == "harness"


def test_client2_identity_accepts_stock_baseline() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10", "--client2-identity", "stock_emule"])

    assert args.client2_identity == "stock_emule"


def test_client2_identity_accepts_amule_control() -> None:
    module = load_suite_module()
    args = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--client2-identity",
            "amule",
            "--client2-control-exe",
            "amulecmd.exe",
        ]
    )

    assert args.client2_identity == "amule"
    assert args.client2_control_exe == "amulecmd.exe"


def test_observe_amule_publisher_uses_ec_and_server_observations(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"fixture")
    calls: list[tuple[object, ...]] = []

    class FakeControl:
        def wait_for_client_shared_files(self, nick, minimum, timeout):
            calls.append(("shared_files", nick, minimum, timeout))
            return {"client_name": nick, "ip": "172.17.128.1", "shared_files": 1}

        def wait_for_file(self, file_hash, timeout):
            calls.append(("file", file_hash, timeout))
            return {"hash": file_hash, "sources": 1}

        def wait_for_file_endpoint(self, file_hash, host, port, timeout, description):
            calls.append(("endpoint", file_hash, host, port, timeout, description))
            return {"hash": file_hash, "endpoints": [{"host": host, "port": port}]}

    monkeypatch.setattr(
        module.amule_client,
        "wait_for_control",
        lambda control, **kwargs: calls.append(("control", control, kwargs)) or {"ready": True},
    )
    monkeypatch.setattr(
        module.amule_client,
        "wait_for_shared_file_hash",
        lambda control, **kwargs: calls.append(("shared", control, kwargs)) or {"hash": "ab" * 16},
    )

    link, observation = module.observe_amule_publisher(
        control_exe=tmp_path / "amulecmd.exe",
        ec_port=4712,
        ec_password="secret",
        client_nick="cl-amule-007",
        fixture_file=fixture,
        endpoint_port=4662,
        server_control=FakeControl(),
        publish_timeout_seconds=30.0,
    )

    assert link == "ed2k://|file|fixture.bin|7|ABABABABABABABABABABABABABABABAB|/"
    assert observation["observed_host"] == "172.17.128.1"
    assert observation["published"]["sources"] == 1
    assert [call[0] for call in calls] == ["control", "shared", "shared_files", "file", "endpoint"]


def test_recycle_amule_publisher_proves_withdrawal_and_republication(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    old_app = object()
    new_app = object()
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"fixture")
    calls: list[tuple[object, ...]] = []
    file_hash = "ab" * 16
    initial = {"shared": {"hash": file_hash}, "observed_host": "172.17.128.1"}

    class FakeControl:
        def wait_for_client_absent(self, nick, timeout):
            calls.append(("client_absent", nick, timeout))
            return {"absent": True}

        def wait_for_file_endpoint_absent(self, hash_value, host, port, timeout):
            calls.append(("endpoint_absent", hash_value, host, port, timeout))
            return {"absent": True}

        def wait_for_client_shared_files(self, nick, minimum, timeout):
            calls.append(("shared_files", nick, minimum, timeout))
            return {"client_name": nick, "shared_files": 1}

        def wait_for_file(self, hash_value, timeout):
            calls.append(("file", hash_value, timeout))
            return {"hash": hash_value, "sources": 1}

        def wait_for_file_endpoint(self, hash_value, host, port, timeout, description):
            calls.append(("endpoint", hash_value, host, port, timeout, description))
            return {"hash": hash_value, "endpoints": [{"host": host, "port": port}]}

    monkeypatch.setattr(
        module,
        "observe_amule_publisher",
        lambda **kwargs: calls.append(("observe", kwargs))
        or ("ed2k://|file|fixture.bin|7|ABABABABABABABABABABABABABABABAB|/", initial),
    )
    monkeypatch.setattr(
        module.amule_client,
        "shutdown_daemon",
        lambda app, control, **kwargs: calls.append(("shutdown", app, control, kwargs)) or {"return_code": 0},
    )
    monkeypatch.setattr(
        module.amule_client,
        "launch_daemon",
        lambda daemon, config: calls.append(("launch", daemon, config)) or new_app,
    )
    monkeypatch.setattr(
        module.amule_client,
        "wait_for_control",
        lambda control, **kwargs: calls.append(("control", control, kwargs)) or {"ready": True},
    )

    relaunched, link, report = module.recycle_amule_publisher(
        app=old_app,
        daemon_exe=tmp_path / "amuled.exe",
        control_exe=tmp_path / "amulecmd.exe",
        config_dir=tmp_path / "config",
        ec_port=4712,
        ec_password="secret",
        client_nick="cl-amule-007",
        fixture_file=fixture,
        endpoint_port=4662,
        server_control=FakeControl(),
        withdraw_timeout_seconds=20.0,
        publish_timeout_seconds=30.0,
    )

    assert relaunched is new_app
    assert link.endswith("|ABABABABABABABABABABABABABABABAB|/")
    assert report["required_by_adapter"] is False
    assert report["withdrawn"]["client"]["absent"] is True
    assert report["republished"]["file"]["sources"] == 1
    assert [call[0] for call in calls] == [
        "observe",
        "shutdown",
        "client_absent",
        "endpoint_absent",
        "launch",
        "control",
        "shared_files",
        "file",
        "endpoint",
    ]


def test_recycle_publisher_proves_withdrawal_and_republication(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    old_app = object()
    new_app = object()
    calls: list[tuple[object, ...]] = []

    class FakeControl:
        def wait_for_client_absent(self, nick, timeout):
            calls.append(("client_absent", nick, timeout))
            return {"absent": True}

        def wait_for_file_endpoint_absent(self, file_hash, host, port, timeout):
            calls.append(("endpoint_absent", file_hash, host, port, timeout))
            return {"absent": True}

        def wait_for_client(self, nick, timeout):
            calls.append(("client_present", nick, timeout))
            return {"client_name": nick}

        def wait_for_file_endpoint(self, file_hash, host, port, timeout, description):
            calls.append(("endpoint_present", file_hash, host, port, timeout, description))
            return {"hash": file_hash, "endpoints": [{"host": host, "port": port}]}

    monkeypatch.setattr(module.live_common, "close_app_cleanly", lambda app: calls.append(("close", app)))
    monkeypatch.setattr(
        module.live_common,
        "launch_app",
        lambda exe, profile, **kwargs: calls.append(("launch", exe, profile, kwargs)) or new_app,
    )
    monkeypatch.setattr(
        module.rest_smoke,
        "wait_for_rest_ready",
        lambda base_url, api_key, timeout: {
            "status": 200,
            "base_url": base_url,
            "api_key": api_key,
            "timeout": timeout,
        },
    )
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: result)
    monkeypatch.setattr(
        module,
        "reload_emule_shared_files",
        lambda base_url, api_key: {"base_url": base_url, "api_key": api_key},
    )

    relaunched, report = module.recycle_publisher(
        app=old_app,
        app_exe=tmp_path / "emule.exe",
        profile_base=tmp_path / "profile",
        base_url="http://192.0.2.10:4711",
        api_key="key",
        client_nick="publisher",
        transfer_hash="aa" * 16,
        endpoint_host="192.0.2.10",
        endpoint_port=4662,
        server_control=FakeControl(),
        rest_ready_timeout_seconds=10.0,
        withdraw_timeout_seconds=20.0,
        publish_timeout_seconds=30.0,
    )

    assert relaunched is new_app
    assert report["withdrawn"]["client"]["absent"] is True
    assert report["republished"]["endpoint"]["hash"] == "aa" * 16
    assert calls == [
        ("close", old_app),
        ("client_absent", "publisher", 20.0),
        ("endpoint_absent", "aa" * 16, "192.0.2.10", 4662, 20.0),
        ("launch", tmp_path / "emule.exe", tmp_path / "profile", {"minimized_to_tray": True}),
        ("client_present", "publisher", 30.0),
        (
            "endpoint_present",
            "aa" * 16,
            "192.0.2.10",
            4662,
            30.0,
            "ED2K publisher endpoint republication",
        ),
    ]


def test_recycle_stock_publisher_uses_known_met_without_rest(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    old_app = object()
    new_app = object()
    fixture = tmp_path / "fixture.bin"
    fixture.write_bytes(b"fixture")
    known_entry = SimpleNamespace(
        name=fixture.name,
        size_bytes=fixture.stat().st_size,
        ed2k_hash="cd" * 16,
    )
    calls: list[tuple[object, ...]] = []

    class FakeControl:
        def wait_for_client_shared_files(self, nick, minimum, timeout):
            calls.append(("shared_files", nick, minimum, timeout))
            return {"client_name": nick, "ip": "172.17.128.1", "shared_files": 1}

        def wait_for_client_absent(self, nick, timeout):
            calls.append(("client_absent", nick, timeout))
            return {"absent": True}

        def wait_for_file_endpoint_absent(self, file_hash, host, port, timeout):
            calls.append(("endpoint_absent", file_hash, host, port, timeout))
            return {"absent": True}

        def wait_for_file(self, file_hash, timeout):
            calls.append(("file", file_hash, timeout))
            return {"hash": file_hash, "sources": 1}

        def wait_for_file_endpoint(self, file_hash, host, port, timeout, description):
            calls.append(("endpoint_present", file_hash, host, port, timeout, description))
            return {"hash": file_hash, "endpoints": [{"host": host, "port": port}]}

    monkeypatch.setattr(module.live_common, "close_app_cleanly", lambda app: calls.append(("close", app)))
    monkeypatch.setattr(
        module.live_common,
        "launch_app",
        lambda exe, profile, **kwargs: calls.append(("launch", exe, profile, kwargs)) or new_app,
    )
    monkeypatch.setattr(module, "require_known_met_fixture", lambda *_args, **_kwargs: known_entry)

    relaunched, link, report = module.recycle_stock_publisher(
        app=old_app,
        app_exe=tmp_path / "emule.exe",
        profile_base=tmp_path / "profile",
        config_dir=tmp_path / "profile" / "config",
        client_nick="stock publisher",
        fixture_file=fixture,
        endpoint_port=4662,
        server_control=FakeControl(),
        withdraw_timeout_seconds=20.0,
        publish_timeout_seconds=30.0,
    )

    assert relaunched is new_app
    assert link == "ed2k://|file|fixture.bin|7|CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD|/"
    assert report["required_by_adapter"] is True
    assert report["known_met"]["hash"] == "cd" * 16
    assert calls == [
        ("shared_files", "stock publisher", 1, 30.0),
        ("close", old_app),
        ("client_absent", "stock publisher", 20.0),
        ("endpoint_absent", "cd" * 16, "172.17.128.1", 4662, 20.0),
        ("launch", tmp_path / "emule.exe", tmp_path / "profile", {"minimized_to_tray": True}),
        ("shared_files", "stock publisher", 1, 30.0),
        ("file", "cd" * 16, 30.0),
        (
            "endpoint_present",
            "cd" * 16,
            "172.17.128.1",
            4662,
            30.0,
            "stock ED2K publisher endpoint republication",
        ),
    ]


def test_add_and_connect_server_reuses_preloaded_server(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        if path == "/api/v1/servers":
            return {"status": 200, "json": {"items": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}}
        if path == "/api/v1/status":
            return {
                "status": 200,
                "json": {
                    "connected": True,
                    "currentServer": {"address": "10.1.2.3", "port": 4661, "name": "local"},
                },
            }
        return {"status": 200, "json": {"connected": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: dict(result["json"]))
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

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


def test_add_and_connect_server_retries_transient_rest_socket_abort(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []
    first_call = True

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        nonlocal first_call
        calls.append((method, path))
        if first_call:
            first_call = False
            raise ConnectionAbortedError(10053, "socket aborted")
        if path == "/api/v1/servers":
            return {"status": 200, "json": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}
        if path == "/api/v1/status":
            return {
                "status": 200,
                "json": {
                    "connected": True,
                    "currentServer": {"address": "10.1.2.3", "port": 4661, "name": "local"},
                },
            }
        return {"status": 200, "json": {"connected": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: dict(result["json"]))
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.add_and_connect_server(
        "http://127.0.0.1:4711",
        "key",
        address="10.1.2.3",
        port=4661,
        timeout_seconds=2.0,
    )

    assert result["add"]["preloaded"] is True
    assert calls.count(("GET", "/api/v1/servers")) == 2
    assert ("POST", "/api/v1/servers/10.1.2.3:4661/operations/connect") in calls


def test_add_and_connect_server_waits_past_transitional_connect_response(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []
    status_payloads = [
        {
            "connected": False,
            "connecting": True,
            "currentServer": None,
            "serverCount": 1,
        },
        {
            "connected": True,
            "connecting": False,
            "currentServer": {"address": "10.1.2.3", "port": 4661, "name": "local"},
            "serverCount": 1,
        },
    ]

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        if path == "/api/v1/servers":
            return {"status": 200, "json": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}
        if path == "/api/v1/servers/10.1.2.3:4661/operations/connect":
            payload = {
                "connected": False,
                "connecting": True,
                "currentServer": None,
                "serverCount": 1,
            }
            return {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": payload,
                "raw_json": {"data": payload, "meta": {"apiVersion": "v1"}},
            }
        if path == "/api/v1/status":
            payload = status_payloads.pop(0)
            return {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": payload,
                "raw_json": {"data": payload, "meta": {"apiVersion": "v1"}},
            }
        raise AssertionError(path)

    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"], "json": result["json"]})
    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.add_and_connect_server(
        "http://127.0.0.1:4711",
        "key",
        address="10.1.2.3",
        port=4661,
        timeout_seconds=2.0,
    )

    assert result["connect"]["json"]["connecting"] is True
    assert result["connected"]["observations"][-1]["connected"] is True
    assert calls.count(("GET", "/api/v1/status")) == 2


def test_add_transfer_accepts_bulk_items_response_without_contract_gate(monkeypatch) -> None:
    module = load_suite_module()
    expected_hash = "9eced47df2edfbd72f29f93447d60b7b"
    item = {"hash": expected_hash.upper(), "name": "deterministic-two-client-transfer.bin", "ok": True}
    response = {
        "status": 200,
        "content_type": "application/json; charset=utf-8",
        "json": {"items": [item]},
        "raw_json": {"data": {"items": [item]}, "meta": {"apiVersion": "v1"}},
    }
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_http_request(_base_url, path, *, method="GET", json_body=None, **_kwargs):
        calls.append((method, path, dict(json_body or {})))
        return response

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"], "json": result["json"]})

    result = module.add_transfer("http://127.0.0.1:4711", "key", "ed2k://|file|a|1|9ECED47DF2EDFBD72F29F93447D60B7B|/", expected_hash)

    assert result["item"] == item
    assert calls == [
        (
            "POST",
            "/api/v1/transfers",
            {"link": "ed2k://|file|a|1|9ECED47DF2EDFBD72F29F93447D60B7B|/", "paused": False, "categoryId": 0},
        )
    ]


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
