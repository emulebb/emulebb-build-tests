from __future__ import annotations

import random
import shutil
import socket
import uuid
from types import SimpleNamespace
from pathlib import Path

import pytest

from emule_test_harness import rust_ed2k
from emule_test_harness.ed2k_server import UnsupportedEd2kServerCapability
from emule_test_harness.paths import get_workspace_output_root


class FakeProcess:
    def __init__(self) -> None:
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        del timeout
        return self.returncode


def available_local_port(*, udp_offsets: tuple[int, ...] = ()) -> int:
    """Chooses a non-ephemeral port whose requested TCP/UDP companions are free."""

    for _ in range(200):
        port = random.randrange(20000, 45000)
        sockets: list[socket.socket] = []
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind(("127.0.0.1", port))
            sockets.append(tcp)
            for offset in udp_offsets:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind(("127.0.0.1", port + offset))
                sockets.append(udp)
            return port
        except OSError:
            pass
        finally:
            for probe in sockets:
                probe.close()
    raise RuntimeError("Could not choose a free local Rust ED2K smoke port.")


@pytest.mark.unit
def test_build_server_config_writes_private_minimal_toml(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"

    config = rust_ed2k.build_server_config(
        path,
        ed2k_port=4661,
        admin_port=8080,
        listen_address="0.0.0.0",
        advertised_address="172.20.0.2",
        protocol_obfuscation=False,
        offerfiles_v1=True,
        soft_limit_files=100_000,
        hard_limit_files=200_001,
    )

    text = path.read_text(encoding="utf-8")
    assert config["server"]["public"] is False
    assert config["admin"] == {"enabled": True, "port": 8080, "bind": "127.0.0.1", "tls": "off"}
    assert 'this_ip = "172.20.0.2"' in text
    assert 'listen_ip = "0.0.0.0"' in text
    assert "support_crypt = false" in text
    assert config["limits"]["offerfiles_v1"] is True
    assert "offerfiles_v1 = true" in text
    assert config["limits"]["soft_limit_files"] == 100_000
    assert config["limits"]["hard_limit_files"] == 200_001
    assert "soft_limit_files = 100000" in text
    assert "hard_limit_files = 200001" in text
    assert config["network"]["private_highid_probe"] is True
    assert "private_highid_probe = true" in text
    assert "password" not in text
    assert text.endswith("\n")


@pytest.mark.unit
def test_build_server_config_requires_explicit_addresses(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="listen_address"):
        rust_ed2k.build_server_config(
            tmp_path / "config.toml",
            ed2k_port=4661,
            admin_port=8080,
            listen_address="",
            advertised_address="172.20.0.2",
        )


@pytest.mark.unit
def test_build_server_config_rejects_negative_file_limits(tmp_path: Path) -> None:
    common = {
        "ed2k_port": 4661,
        "admin_port": 8080,
        "listen_address": "127.0.0.1",
        "advertised_address": "127.0.0.1",
    }

    with pytest.raises(ValueError, match="soft_limit_files"):
        rust_ed2k.build_server_config(tmp_path / "soft.toml", **common, soft_limit_files=-1)
    with pytest.raises(ValueError, match="hard_limit_files"):
        rust_ed2k.build_server_config(tmp_path / "hard.toml", **common, hard_limit_files=-1)


@pytest.mark.unit
def test_rust_control_normalizes_stats_and_clients(monkeypatch) -> None:
    payloads = {
        "/api/stats": {"bytes_in": 12},
        "/api/clients": [{"nick": "aMule", "ip": "192.0.2.10"}, "ignored"],
    }
    monkeypatch.setattr(
        rust_ed2k,
        "admin_request",
        lambda _base, path, **_kwargs: payloads[path],
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    assert control.stats() == {"ok": True, "data": {"bytes_in": 12}}
    assert control.list_clients() == [
        {"nick": "aMule", "ip": "192.0.2.10", "client_name": "aMule"}
    ]


@pytest.mark.unit
def test_rust_control_normalizes_exact_file_and_missing_response(monkeypatch) -> None:
    file_hash = "00112233445566778899aabbccddeeff"
    payload = {
        "hash": file_hash,
        "name": "fixture.bin",
        "size": 123,
        "source_count": 2,
        "complete_source_count": 1,
        "sources_truncated": False,
        "sources": [
            {
                "user_hash": "aabbccddeeff00112233445566778899",
                "ip": "192.0.2.10",
                "port": 4662,
                "complete": True,
            },
            "ignored",
        ],
    }

    def fake_request(_base, path, **_kwargs):
        if path.endswith("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"):
            raise rust_ed2k.RustEd2kAdminError(path, 404, b'{"error":"file is not indexed"}')
        return payload

    monkeypatch.setattr(rust_ed2k, "admin_request", fake_request)
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    assert control.get_file(file_hash) == {
        "hash": file_hash.upper(),
        "name": "fixture.bin",
        "size": 123,
        "sources": 2,
        "complete_sources": 1,
        "endpoints": [
            {
                "host": "192.0.2.10",
                "port": 4662,
                "complete": True,
                "user_hash": "AABBCCDDEEFF00112233445566778899",
            }
        ],
        "sources_truncated": False,
    }
    assert control.get_file("ff" * 16) is None


@pytest.mark.unit
def test_rust_control_waits_for_file_and_exact_endpoint(monkeypatch) -> None:
    file_hash = "00112233445566778899aabbccddeeff"
    responses = [
        None,
        {
            "hash": file_hash.upper(),
            "endpoints": [{"host": "192.0.2.10", "port": 4662}],
        },
    ]
    monkeypatch.setattr(
        rust_ed2k.RustEd2kServerControl,
        "get_file",
        lambda *_args: responses.pop(0),
    )
    monkeypatch.setattr(
        rust_ed2k.live_common,
        "wait_for",
        lambda resolve, *_args: resolve() or resolve(),
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    row = control.wait_for_file(file_hash, 1.0)
    assert row["observations"][0]["indexed"] is False

    responses.append(
        {
            "hash": file_hash.upper(),
            "endpoints": [{"host": "192.0.2.10", "port": 4662}],
        }
    )
    endpoint_row = control.wait_for_file_endpoint(file_hash, "192.0.2.10", 4662, 1.0)
    assert endpoint_row["hash"] == file_hash.upper()


@pytest.mark.unit
def test_rust_control_waits_for_client_withdrawal(monkeypatch) -> None:
    responses = [
        [{"client_name": "eMuleBB Lifecycle Publisher"}],
        [{"client_name": "another client"}],
    ]
    monkeypatch.setattr(
        rust_ed2k.RustEd2kServerControl,
        "list_clients",
        lambda *_args: responses.pop(0),
    )
    monkeypatch.setattr(
        rust_ed2k.live_common,
        "wait_for",
        lambda resolve, *_args: resolve() or resolve(),
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    result = control.wait_for_client_absent("lifecycle publisher", 1.0)

    assert result["absent"] is True
    assert [row["matching_count"] for row in result["observations"]] == [1, 0]


@pytest.mark.unit
def test_rust_control_waits_for_client_shared_files(monkeypatch) -> None:
    responses = [
        [{"client_name": "stock publisher", "shared_files": 0}],
        [{"client_name": "stock publisher", "shared_files": 1}],
    ]
    monkeypatch.setattr(
        rust_ed2k.RustEd2kServerControl,
        "list_clients",
        lambda *_args: responses.pop(0),
    )
    monkeypatch.setattr(
        rust_ed2k.live_common,
        "wait_for",
        lambda resolve, *_args: resolve() or resolve(),
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    result = control.wait_for_client_shared_files("stock", 1, 1.0)

    assert result["shared_files"] == 1
    assert [row["shared_files"] for row in result["observations"]] == [0, 1]


@pytest.mark.unit
def test_rust_control_waits_for_exact_endpoint_withdrawal(monkeypatch) -> None:
    file_hash = "00112233445566778899aabbccddeeff"
    responses = [
        {
            "hash": file_hash.upper(),
            "endpoints": [{"host": "192.0.2.10", "port": 4662}],
        },
        {
            "hash": file_hash.upper(),
            "endpoints": [{"host": "192.0.2.11", "port": 4662}],
        },
    ]
    monkeypatch.setattr(
        rust_ed2k.RustEd2kServerControl,
        "get_file",
        lambda *_args: responses.pop(0),
    )
    monkeypatch.setattr(
        rust_ed2k.live_common,
        "wait_for",
        lambda resolve, *_args: resolve() or resolve(),
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    result = control.wait_for_file_endpoint_absent(file_hash, "192.0.2.10", 4662, 1.0)

    assert result["absent"] is True
    assert result["file"]["endpoints"] == [{"host": "192.0.2.11", "port": 4662}]
    assert [row["endpoint_present"] for row in result["observations"]] == [True, False]


@pytest.mark.unit
def test_rust_control_treats_unindexed_file_as_withdrawn_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(
        rust_ed2k.RustEd2kServerControl,
        "get_file",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        rust_ed2k.live_common,
        "wait_for",
        lambda resolve, *_args: resolve(),
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    result = control.wait_for_file_endpoint_absent(
        file_hash="ff" * 16,
        host="192.0.2.10",
        port=4662,
        timeout_seconds=1.0,
    )

    assert result["absent"] is True
    assert result["file"] is None
    assert result["observations"][0]["indexed"] is False
    assert result["observations"][0]["endpoint_present"] is False


@pytest.mark.unit
def test_prepare_server_binary_accepts_explicit_staged_binary(monkeypatch, tmp_path: Path) -> None:
    server_exe = tmp_path / "tools" / "ed2k-server"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"linux")
    monkeypatch.setattr(rust_ed2k, "reject_windows_temp_path", lambda *_args: None)

    prepared = rust_ed2k.prepare_server_binary(
        tmp_path / "workspace",
        exe_override=str(server_exe),
    )

    assert prepared.server_exe == server_exe.resolve()
    assert prepared.build["skipped"] is True


@pytest.mark.unit
def test_build_server_binary_uses_workspace_orchestrator(monkeypatch, tmp_path: Path) -> None:
    server_repo = tmp_path / "repos" / "ed2k-server"
    build_repo = tmp_path / "repos" / "emulebb-build"
    server_repo.mkdir(parents=True)
    build_repo.mkdir(parents=True)
    (server_repo / "Cargo.toml").write_text("[package]\nname='server'\nversion='0.0.0'\n", encoding="utf-8")
    server_exe = tmp_path / "output" / "tools" / "ed2k-server" / "bin" / "ed2k-server"
    calls: list[dict[str, object]] = []

    def fake_resolve(_workspace, key):
        return {"ed2k_server": server_repo, "build": build_repo}[key]

    def fake_run(command, **kwargs):
        calls.append({"command": command, **kwargs})
        server_exe.parent.mkdir(parents=True)
        server_exe.write_bytes(b"linux")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(rust_ed2k, "resolve_manifest_repo", fake_resolve)
    monkeypatch.setattr(rust_ed2k, "reject_windows_temp_path", lambda *_args: None)
    monkeypatch.setattr(rust_ed2k.subprocess, "run", fake_run)

    result = rust_ed2k.build_or_skip_server_binary(tmp_path / "workspace", server_exe)

    assert result["return_code"] == 0
    assert calls[0]["cwd"] == build_repo
    assert calls[0]["command"][-6:] == [
        "build",
        "ed2k-server",
        "--config",
        "Release",
        "--platform",
        "x64",
    ]


@pytest.mark.unit
def test_start_server_uses_pid_backed_wsl_process(monkeypatch, tmp_path: Path) -> None:
    server_exe = tmp_path / "ed2k-server"
    config_path = tmp_path / "config.toml"
    log_path = tmp_path / "server.log"
    pid_path = tmp_path / "server.pid"
    server_exe.write_bytes(b"linux")
    config_path.write_text("", encoding="utf-8")
    proxy = FakeProcess()
    calls: list[dict[str, object]] = []

    monkeypatch.setattr(rust_ed2k, "_is_windows_host", lambda: True)
    monkeypatch.setattr(rust_ed2k, "wsl_path", lambda path, _distribution=None: f"/mnt/c/{path.name}")

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return proxy

    monkeypatch.setattr(rust_ed2k.subprocess, "Popen", fake_popen)

    process = rust_ed2k.start_server(
        server_exe,
        config_path,
        log_path,
        pid_path,
        distribution="Ubuntu",
    )

    assert isinstance(process, rust_ed2k.RustWslProcess)
    assert calls[0]["command"][:5] == ["wsl.exe", "--distribution", "Ubuntu", "--", "setsid"]
    assert "--wait" in calls[0]["command"]
    assert "python3" in calls[0]["command"]
    assert "/mnt/c/wsl_managed_process.py" in calls[0]["command"]
    assert "/mnt/c/server.pid" in calls[0]["command"]
    assert calls[0]["command"][-3:] == ["/mnt/c/ed2k-server", "--config", "/mnt/c/config.toml"]


@pytest.mark.unit
def test_wsl_process_signals_linux_process_group(monkeypatch, tmp_path: Path) -> None:
    proxy = FakeProcess()
    calls: list[list[str]] = []
    pid_path = tmp_path / "server.pid"
    pid_path.write_text("1234\n", encoding="ascii")

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(rust_ed2k.subprocess, "run", fake_run)
    process = rust_ed2k.RustWslProcess(proxy, pid_path, "Ubuntu")

    process.terminate()

    assert calls[0][:5] == ["wsl.exe", "--distribution", "Ubuntu", "--", "kill"]
    assert calls[0][-3:] == ["-TERM", "--", "-1234"]


@pytest.mark.unit
def test_stop_process_signals_wsl_pid_even_after_proxy_exit(monkeypatch, tmp_path: Path) -> None:
    proxy = FakeProcess()
    proxy.returncode = 0
    pid_path = tmp_path / "server.pid"
    pid_path.write_text("1234\n", encoding="ascii")
    calls: list[list[str]] = []

    monkeypatch.setattr(
        rust_ed2k.subprocess,
        "run",
        lambda command, **_kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )

    rust_ed2k.stop_process(rust_ed2k.RustWslProcess(proxy, pid_path, "Ubuntu"))

    assert calls[0][-3:] == ["-TERM", "--", "-1234"]


@pytest.mark.unit
def test_rust_server_launches_wsl_with_distinct_connect_address(monkeypatch, tmp_path: Path) -> None:
    server_exe = tmp_path / "tools" / "ed2k-server"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"linux")
    process = FakeProcess()
    binary = rust_ed2k.RustEd2kServerBinary(server_exe, {"return_code": 0})

    monkeypatch.setattr(rust_ed2k, "_is_windows_host", lambda: True)
    monkeypatch.setattr(rust_ed2k, "wsl_ipv4_address", lambda _distribution=None: "172.20.0.2")
    monkeypatch.setattr(rust_ed2k, "prepare_server_binary", lambda *_args, **_kwargs: binary)
    monkeypatch.setattr(rust_ed2k, "start_server", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        rust_ed2k,
        "wait_for_admin_health",
        lambda base_url, _process, timeout: {"ok": True, "data": {"base_url": base_url, "timeout": timeout}},
    )

    launch = rust_ed2k.launch_server(
        workspace_root=tmp_path / "workspace",
        server_dir=tmp_path / "run",
        ed2k_port=4661,
        admin_port=8080,
        admin_secret="unused",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
    )

    assert launch.ed2k_host == "172.20.0.2"
    assert launch.ed2k_port == 4661
    assert launch.admin_base_url == "http://127.0.0.1:8080"
    assert launch.config["network"]["listen_ip"] == "0.0.0.0"
    assert isinstance(rust_ed2k.create_server_control(launch.admin_base_url, "unused"), rust_ed2k.RustEd2kServerControl)


@pytest.mark.unit
def test_rust_server_rejects_unimplemented_fixture_and_trace_capabilities(tmp_path: Path) -> None:
    common = {
        "workspace_root": tmp_path / "workspace",
        "server_dir": tmp_path / "run",
        "ed2k_port": 4661,
        "admin_port": 8080,
        "admin_secret": "unused",
        "admin_address": "127.0.0.1",
        "ed2k_address": "127.0.0.1",
    }

    with pytest.raises(UnsupportedEd2kServerCapability, match="static catalog"):
        rust_ed2k.launch_server(**common, fixture_files=[{"hash": "0011"}])
    with pytest.raises(UnsupportedEd2kServerCapability, match="packet tracing"):
        rust_ed2k.launch_server(**common, packet_trace=True)


@pytest.mark.native
def test_rust_server_live_wsl_smoke() -> None:
    if shutil.which("wsl.exe") is None:
        pytest.skip("WSL is unavailable")
    output_root = get_workspace_output_root()
    server_exe = output_root / "tools" / "ed2k-server" / "bin" / "ed2k-server"
    if not server_exe.is_file():
        pytest.skip(f"staged Rust ED2K server is unavailable: {server_exe}")
    server_dir = output_root / "test-runs" / "rust-ed2k-live-smoke" / uuid.uuid4().hex
    ed2k_port = available_local_port(udp_offsets=(4, 8, 12, 14))
    admin_port = available_local_port()
    launch = None
    try:
        launch = rust_ed2k.launch_server(
            workspace_root=Path("unused-with-explicit-executable"),
            server_dir=server_dir,
            ed2k_port=ed2k_port,
            admin_port=admin_port,
            admin_secret="unused",
            admin_address="127.0.0.1",
            ed2k_address="127.0.0.1",
            exe_override=str(server_exe),
            health_timeout_seconds=30.0,
        )
        control = rust_ed2k.create_server_control(launch.admin_base_url, "unused")
        stats = control.stats()
        assert launch.ed2k_host
        assert launch.health["data"]["ready"] is True
        assert stats["ok"] is True
        assert "bytes_in" in stats["data"]
        assert control.get_file("00" * 16) is None
    finally:
        if launch is not None:
            rust_ed2k.stop_process(launch.process)
            assert launch.process.poll() is not None
