from __future__ import annotations

import importlib.util
import json
import os
import shlex
import sqlite3
import stat
import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_client
from emule_test_harness.kad_nodes import BootstrapContact
from emule_test_harness.workspace_layout import resolve_selected_workspace_repo


def test_container_setup_uses_offline_settings_before_publishing_fixture_ownership() -> None:
    value = "sample name; $(sample) 'quoted'"
    script = rust_client.container_profile_setup_script({"network.nickname": value}, uid=1234, gid=1235)
    lines = script.splitlines()
    assert lines[0] == "test ! -e /config/emulebb-rust"
    assert lines[2] == "/usr/lib/emulebb-rust/emulebb-profile-init"
    assert shlex.split(lines[3]) == [
        "/usr/lib/emulebb-rust/emulebb-rust", "--profile", "/config/emulebb-rust",
        "settings", "set", "network.nickname", value,
    ]
    assert lines[4:] == ["chown -R 1234:1235 /config", "chown 1234:1235 /data/incoming /data/temp"]


@pytest.mark.parametrize("uid,gid", [(-1, 1), (1, "bad"), (True, 1)])
def test_container_setup_requires_numeric_fixture_ownership(uid, gid) -> None:
    with pytest.raises(ValueError, match="numeric IDs"):
        rust_client.container_profile_setup_script({}, uid=uid, gid=gid)


def test_container_profile_preparation_propagates_failure_without_retry() -> None:
    calls = []
    environment = {"SYNTHETIC": "fixture"}
    def run(*args, **kwargs):
        calls.append((args, kwargs))
        raise subprocess.CalledProcessError(1, args)
    with pytest.raises(subprocess.CalledProcessError):
        rust_client.prepare_container_profile(run, ("docker", "compose"), env=environment,
                                              settings={"network.p2p.bindInterface": "tun0"})
    assert len(calls) == 1
    arguments, options = calls[0]
    assert arguments[:9] == ("docker", "compose", "run", "--rm", "--no-deps", "--entrypoint", "/bin/sh", "emulebb-rust", "-ec")
    assert "settings set network.p2p.bindInterface tun0" in arguments[-1]
    assert options == {"env": environment, "timeout": 120}


def test_registered_stage_admission_uses_persisted_source_verifier(monkeypatch, tmp_path):
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    source = workspace / "workspaces/agents/sample/emulebb-rust"
    source.mkdir(parents=True)
    root = output / "tools/workstreams/sample/emulebb-rust/x86_64-pc-windows-msvc"
    name = "emulebb-rust.exe" if os.name == "nt" else "emulebb-rust"
    executable = root / "bin" / name
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"source-bound fixture")
    identity = {"schema": "emulebb.rust-runtime-stage/1", "workstream": "sample",
                "target": root.name, "source": {"path": str(source), "revision": "a" * 40},
                "stageRoot": str(root), "executable": str(executable), "receipt": str(root / "stage.json")}
    calls = []

    def verify(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(identity), stderr="")

    monkeypatch.setattr(rust_client, "get_required_emule_workspace_root", lambda: workspace)
    monkeypatch.setattr(rust_client.subprocess, "run", verify)
    assert rust_client.verified_runtime_stage(source, output) == identity
    command, arguments = calls[0]
    assert command[-2:] == [str(source / "tools/fresh_rust_build.py"), "--verify-stage"]
    assert arguments["cwd"] == source
    for field, value in (("workstream", "other"), ("executable", str(output / "arbitrary.exe")),
                         ("target", "../../operator")):
        original = identity[field]
        identity[field] = value
        with pytest.raises(RuntimeError, match="runtime"):
            rust_client.verified_runtime_stage(source, output)
        identity[field] = original


def test_failed_registered_source_verification_is_an_admission_failure(monkeypatch, tmp_path):
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    source = workspace / "workspaces/agents/sample/emulebb-rust"
    source.mkdir(parents=True)
    monkeypatch.setattr(rust_client, "get_required_emule_workspace_root", lambda: workspace)
    monkeypatch.setattr(rust_client.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 1, stdout="", stderr="source receipt differs"))
    with pytest.raises(RuntimeError, match="source receipt differs"):
        rust_client.verified_runtime_stage(source, output)


def test_registered_diagnostics_requires_the_verified_inventory(tmp_path):
    regular = tmp_path / "emulebb-rust.exe"
    diagnostics = tmp_path / "emulebb-rust-diagnostics.exe"
    diagnostics.touch()
    identity = {"executable": str(regular), "files": []}
    with pytest.raises(RuntimeError, match="verified diagnostics"):
        rust_client.registered_diagnostics_executable(identity)
    identity["files"].append({"path": f"bin/{diagnostics.name}"})
    assert rust_client.registered_diagnostics_executable(identity) == diagnostics
    diagnostics.unlink()
    with pytest.raises(RuntimeError, match="verified diagnostics"):
        rust_client.registered_diagnostics_executable(identity)


def load_rust_live_wire_module():
    script_path = Path(__file__).parents[2] / "scripts" / "rust-live-wire-hideme.py"
    spec = importlib.util.spec_from_file_location("rust_live_wire_hideme", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def rust_repo() -> Path:
    return resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")


def metadata_path(profile_dir: Path) -> Path:
    return profile_dir / rust_client.RUST_PROFILE_METADATA_FILE


def setting_value(profile_dir: Path, key: str) -> object:
    _, document = rust_client.rust_metadata.read_app_settings(metadata_path(profile_dir))
    for segment in key.split("."):
        document = document[segment]
    return document["value"]


def test_request_ctrl_c_sends_sigint_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    signals: list[int] = []

    class FakeProcess:
        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def send_signal(value: int) -> None:
            signals.append(value)

    monkeypatch.setattr(rust_client.os, "name", "posix")

    rust_client.request_ctrl_c(FakeProcess())

    assert signals == [rust_client.signal.SIGINT]


@pytest.mark.parametrize("present", [True, False])
def test_profile_contract_can_be_selected_without_container_workspace(tmp_path, monkeypatch, present):
    from emule_test_harness import workspace_layout

    contract = resolve_selected_workspace_repo(Path(__file__).resolve().parents[2], "emulebb-tooling") / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    selected = tmp_path / "contract.yaml"
    if present:
        selected.write_bytes(contract.read_bytes())
    monkeypatch.setenv("EMULEBB_REST_OPENAPI_CONTRACT_PATH", str(selected))
    def unexpected_resolution(*_args):
        raise AssertionError("Explicit contract must not resolve workspace topology")
    monkeypatch.setattr(workspace_layout, "resolve_selected_workspace_repo", unexpected_resolution)
    profile = tmp_path / "profile"
    arguments = dict(rust_repo=rust_repo(), rest_addr="127.0.0.1", rest_port=4711, api_key="key")
    if not present:
        with pytest.raises(FileNotFoundError):
            rust_client.write_rust_profile(profile, **arguments)
        assert not profile.exists()
        return
    rust_client.write_rust_profile(profile, **arguments)
    assert setting_value(profile, "network.autoConnect") is False
    assert metadata_path(profile).is_file()


def test_write_rust_profile_supports_rest_only_profile(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr="192.0.2.10",
        rest_port=4711,
        api_key="key",
    )

    text = (profile_dir / rust_client.RUST_PROFILE_SETTINGS_FILE).read_text(encoding="utf-8")
    assert 'bind_addr = "192.0.2.10:4711"' in text
    assert 'api_key = "key"' in text
    assert tomllib.loads(text) == {"rest": {"bind_addr": "192.0.2.10:4711", "api_key": "key"}}
    assert metadata_path(profile_dir).is_file()
    assert setting_value(profile_dir, 'network.autoConnect') is False
    assert setting_value(profile_dir, 'network.nat.enabled') is False
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "pending"), ("servers", "pending")
        ]
    if os.name == "posix":
        mode = stat.S_IMODE((profile_dir / rust_client.RUST_PROFILE_SETTINGS_FILE).stat().st_mode)
        assert mode == 0o600


def test_write_rust_profile_persists_ed2k_nickname(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        settings={
            'network.nickname': 'cl-emulebb-rust-005',
        },
    )

    assert setting_value(profile_dir, 'network.nickname') == "cl-emulebb-rust-005"


def test_write_rust_profile_persists_connection_cap(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        settings={
            'network.connections.maxConnections': 1,
            'network.connections.maxHalfOpenConnections': 1,
            'network.connections.maxNewConnectionsPerFiveSeconds': 1,
            'transfers.upload.baseSlots': 1,
            'network.kadEnabled': False,
        },
    )

    assert setting_value(profile_dir, 'network.connections.maxConnections') == 1
    assert setting_value(profile_dir, 'network.kadEnabled') is False


def test_write_rust_profile_persists_production_upload_policy(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        settings={
            'transfers.uploadLimitBytesPerSecond': (4) * 1024,
            'transfers.upload.baseSlots': 1,
            'transfers.upload.elasticPercent': 0,
        },
    )

    assert setting_value(profile_dir, 'transfers.uploadLimitBytesPerSecond') == 4096
    assert setting_value(profile_dir, 'transfers.upload.baseSlots') == 1
    assert setting_value(profile_dir, 'transfers.upload.elasticPercent') == 0



def test_write_rust_profile_rejects_zero_connection_cap(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid canonical profile setting"):
        rust_client.write_rust_profile(
            tmp_path / 'profile',
            rust_repo=rust_repo(),
            rest_addr='192.0.2.10',
            rest_port=4711,
            api_key='key',
            settings={
                'network.connections.maxConnections': 0,
            },
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_private_profile_settings_restrict_existing_file(tmp_path: Path) -> None:
    settings_path = tmp_path / rust_client.RUST_PROFILE_SETTINGS_FILE
    settings_path.write_text("stale\n", encoding="utf-8")
    settings_path.chmod(0o644)

    rust_client.write_private_text(settings_path, 'api_key = "new-key"\n')

    assert stat.S_IMODE(settings_path.stat().st_mode) == 0o600
    assert settings_path.read_text(encoding="utf-8") == 'api_key = "new-key"\n'


def test_write_rust_profile_can_preserve_consumer_auto_connect_default(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        reset=('network.autoConnect', 'network.nat.enabled'),
    )

    _, document = rust_client.rust_metadata.read_app_settings(metadata_path(profile_dir))
    defaults = rust_client.rust_metadata.saved_settings_defaults(rust_repo())
    assert document["network"]["autoConnect"] == defaults["network"]["autoConnect"]
    assert document["network"]["nat"]["enabled"] == defaults["network"]["nat"]["enabled"]


def test_write_rust_profile_local_discovery_blocks_public_first_run_import(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir, rust_repo=rust_repo(), rest_addr="192.0.2.10", rest_port=4711,
        api_key="key", local_only_discovery=True,
    )

    assert not (profile_dir / "nodes.dat").exists()
    assert setting_value(profile_dir, 'network.kadEnabled') is False
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "initialized"), ("servers", "initialized")
        ]


@pytest.mark.parametrize("explicit", ["endpoint", "entry", "empty"])
def test_explicit_server_fixture_claims_only_server_bootstrap(tmp_path, explicit):
    profile_dir = tmp_path / "profile"
    options = {
        "endpoint": {"server_endpoint": "192.0.2.10:4661"},
        "entry": {
            "server_endpoint": "192.0.2.20:4661",
            "server_entry": {"host": "192.0.2.20", "port": 4661},
        },
        "empty": {"replace_servers": True},
    }[explicit]
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='127.0.0.1',
        rest_port=4711,
        api_key='key',
        local_only_discovery=False,
        **options,
        settings={
            'network.p2p.bindIp': '127.0.0.1',
            'network.p2p.tcpPort': 24662,
            'network.p2p.udpPort': 24672,
        },
    )
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "pending"), ("servers", "initialized")
        ]
        assert conn.execute("SELECT count(*) FROM servers").fetchone() == (0 if explicit == "empty" else 1,)


def test_write_rust_profile_local_seed_allows_isolated_running_kad(tmp_path: Path, monkeypatch) -> None:
    profile_dir = tmp_path / "profile"
    initialize = rust_client.rust_metadata.initialize_local_discovery
    initialized = []

    def initialize_after_local_data(source, database):
        with sqlite3.connect(database) as conn:
            assert conn.execute("SELECT endpoint FROM kad_bootstrap_endpoints").fetchall() == [("127.0.0.1:24672",)]
        initialize(source, database)
        initialized.append(database)

    monkeypatch.setattr(rust_client.rust_metadata, "initialize_local_discovery", initialize_after_local_data)

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='127.0.0.1',
        rest_port=4711,
        api_key='key',
        local_only_discovery=True,
        local_kad_seed=BootstrapContact('127.0.0.1', 24672, 24662),
        settings={
            'network.kadEnabled': True,
        },
    )

    assert not (profile_dir / "nodes.dat").exists()
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        assert conn.execute(
            "SELECT endpoint FROM kad_bootstrap_endpoints ORDER BY position"
        ).fetchall() == [("127.0.0.1:24672",)]
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "initialized"), ("servers", "initialized")
        ]
    assert setting_value(profile_dir, 'network.kadEnabled') is True
    assert initialized == [metadata_path(profile_dir)]


def test_write_rust_profile_rejects_implicit_local_kad_enablement(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="network.kadEnabled=true"):
        rust_client.write_rust_profile(
            tmp_path / "profile",
            rust_repo=rust_repo(),
            rest_addr="127.0.0.1",
            rest_port=4711,
            api_key="key",
            local_only_discovery=True,
            local_kad_seed=BootstrapContact("127.0.0.1", 24672, 24662),
        )


def test_write_rust_profile_supports_incoming_dir(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        settings={
            'storage.incomingDirectory': str(tmp_path / 'incoming'),
        },
    )

    assert setting_value(profile_dir, 'storage.incomingDirectory') == str(tmp_path / "incoming")


def test_live_wire_report_separates_completed_and_partial_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rust_live_wire_module()
    hashes = ["a" * 32, "b" * 32]
    search_id = "00000000-0000-0000-0000-000000000001"
    candidates = [{"id": "101", "hash": hashes[0], "_searchId": search_id, "sizeBytes": 1000},
                  {"id": "102", "hash": hashes[1], "_searchId": search_id, "sizeBytes": 20000000}]
    admissions = {f"/api/v1/searches/{search_id}/results/101/download": ("7", hashes[0]),
                  f"/api/v1/searches/{search_id}/results/102/download": ("8", hashes[1])}
    def create(_label, _attempts, _base, path, **kwargs):
        job_id, file_hash = admissions[path]
        assert kwargs["body"] == {"intent": "started", "category": None}
        return {"data": {"id": job_id, "hash": file_hash}}
    def detail(_base, _key, job_id, *, expected_hash):
        done = job_id == "7"
        return {"id": job_id, "hash": expected_hash, "sizeBytes": 1000 if done else 20000000,
                "progress": 1 if done else 0.5, "state": "completed" if done else "downloading",
                "payloadVerified": done, "delivery": {"state": "delivered" if done else "pending"}}
    monkeypatch.setattr(module, "retry_http_json", create)
    monkeypatch.setattr(module, "download_detail", detail)
    monkeypatch.setattr(module, "download_part_totals", lambda *_args: {"verifiedBytes": 9728000})
    monkeypatch.setattr(module, "_source_count_lower_bound", lambda *_args: 1)
    monkeypatch.setattr(module, "log", lambda message: None)
    ticks = iter((0.0, 0.1, 1.1))
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None))
    result = module.run_downloads("http://192.0.2.10:4711", candidates, 1, max_concurrent=2)
    assert result["completedFiles"] == [{"candidateIndex": 1, "sizeBytes": 1000}]
    assert result["completedFilesTotalBytes"] == 1000
    assert result["aggregateVerifiedBytes"] == 9729000
    assert result["totalCompletedBytes"] == 1000


def test_write_rust_profile_requires_complete_ed2k_settings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ED2K fixture requires explicit binding"):
        rust_client.write_rust_profile(
            tmp_path / "profile",
            rust_repo=rust_repo(),
            rest_addr="192.0.2.10",
            rest_port=4711,
            api_key="key",
            server_endpoint="192.0.2.10:4661",
        )


def test_write_rust_profile_uses_configurable_ed2k_connect_timeout(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.10:4661',
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.connections.connectTimeoutSeconds': 15,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.p2p.bindIp') == "192.0.2.10"
    assert setting_value(profile_dir, 'network.connections.connectTimeoutSeconds') == 15
    assert setting_value(profile_dir, 'network.servers.reconnectIntervalSeconds') == 60
    assert setting_value(profile_dir, 'security.obfuscationEnabled') is True


def test_write_rust_profile_uses_configurable_reconnect_interval(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.10:4661',
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.servers.reconnectIntervalSeconds': 300,
            'network.connections.connectTimeoutSeconds': 10,
        },
    )

    assert setting_value(profile_dir, 'network.servers.reconnectIntervalSeconds') == 300


@pytest.mark.parametrize("minutes", [0, 20, 1_440])
def test_write_rust_profile_uses_explicit_server_keepalive_minutes(
    tmp_path: Path, minutes: int
) -> None:
    profile_dir = tmp_path / f"profile-{minutes}"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        settings={
            'network.servers.keepaliveMinutes': minutes,
        },
    )

    assert setting_value(profile_dir, 'network.servers.keepaliveMinutes') == minutes


@pytest.mark.parametrize("minutes", [-1, 1_441, True, 20.5])
def test_write_rust_profile_rejects_invalid_server_keepalive_minutes(
    tmp_path: Path, minutes: object
) -> None:
    with pytest.raises(ValueError, match="Invalid canonical profile setting"):
        rust_client.write_rust_profile(
            tmp_path / 'profile',
            rust_repo=rust_repo(),
            rest_addr='192.0.2.10',
            rest_port=4711,
            api_key='key',
            settings={
                'network.servers.keepaliveMinutes': minutes,
            },
        )


def test_write_rust_profile_can_request_stock_server_list_on_connect(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.10:4661',
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.servers.acceptServerListUpdates': True,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.servers.acceptServerListUpdates') is True


def test_write_rust_profile_supports_best_effort_initial_nat_mapping(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.20:4661',
        settings={
            'network.p2p.bindInterface': 'hide.me',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.nat.enabled': True,
            'network.nat.requireInitialMapping': False,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.nat.enabled') is True
    assert setting_value(profile_dir, 'network.nat.requireInitialMapping') is False


def test_write_rust_profile_selects_the_upnp_backend(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        settings={
            'network.nat.enabled': True,
            'network.nat.backendOrder': ['upnp'],
        },
    )

    assert setting_value(profile_dir, 'network.nat.backendOrder') == ["upnp"]


def test_write_rust_profile_supports_interface_and_ip_binding(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.20:4661',
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.bindInterface': 'hide.me',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.p2p.bindIp') == "192.0.2.10"
    assert setting_value(profile_dir, 'network.p2p.bindInterface') == "hide.me"


def test_write_rust_profile_supports_interface_only_binding(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.20:4661',
        settings={
            'network.p2p.bindInterface': 'hide.me',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.p2p.bindIp') is None
    assert setting_value(profile_dir, 'network.p2p.bindInterface') == "hide.me"


def test_write_rust_profile_supports_direct_resolved_binding(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='127.0.0.1',
        rest_port=4731,
        api_key='key',
        server_endpoint='192.0.2.20:4661',
        settings={
            'network.p2p.bindIp': '172.30.0.2',
            'network.p2p.tcpPort': 41662,
            'network.p2p.udpPort': 41672,
            'security.vpnGuard.mode': 'off',
            'network.nat.enabled': False,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.p2p.bindIp') == "172.30.0.2"
    assert setting_value(profile_dir, 'network.nat.enabled') is False
    assert setting_value(profile_dir, 'security.vpnGuard.mode') == 'off'


def test_write_rust_profile_can_disable_obfuscation_and_write_server_entry(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.20:4661',
        server_entry={'host': '192.0.2.20', 'port': 4661, 'name': 'emulebb-local-e2e', 'udpFlags': 120, 'udpKey': 287454020, 'udpKeyIp': 0, 'obfuscationPortTcp': 4661, 'obfuscationPortUdp': 4665},
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'security.obfuscationEnabled': False,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    assert setting_value(profile_dir, 'network.p2p.bindIp') == "192.0.2.10"
    assert setting_value(profile_dir, 'security.obfuscationEnabled') is False
    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        row = conn.execute(
            """
            SELECT address, port, name, enabled, udp_flags, obfuscation_tcp_port
            FROM servers
            """
        ).fetchone()
    assert row == ("192.0.2.20", 4661, "emulebb-local-e2e", 1, 120, 4661)


def test_write_rust_profile_can_replace_server_list(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.20:4661',
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.30:4661',
        replace_servers=True,
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        rows = conn.execute("SELECT address, port FROM servers ORDER BY address, port").fetchall()
    assert rows == [("192.0.2.30", 4661)]


def test_write_rust_profile_uses_configured_kad_bootstrap_nodes(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo(),
        rest_addr='192.0.2.10',
        rest_port=4711,
        api_key='key',
        server_endpoint='192.0.2.10:4661',
        kad_bootstrap_nodes=['192.0.2.11:4672'],
        settings={
            'network.p2p.bindIp': '192.0.2.10',
            'network.p2p.tcpPort': 4662,
            'network.p2p.udpPort': 4672,
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )

    with sqlite3.connect(metadata_path(profile_dir)) as conn:
        endpoints = [
            row[0]
            for row in conn.execute(
                "SELECT endpoint FROM kad_bootstrap_endpoints ORDER BY position"
            )
        ]
    assert endpoints == ["192.0.2.11:4672"]


def test_rust_cargo_env_requires_existing_workspace_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_root = tmp_path / "workspace-root"
    output_root = tmp_path / "output-root"
    target_dir = output_root / "builds" / "rust" / "target"
    target_dir.mkdir(parents=True)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    env = rust_client.rust_cargo_env()

    assert Path(env["CARGO_TARGET_DIR"]) == target_dir


def test_rust_cargo_env_rejects_missing_target_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_root = tmp_path / "output-root"
    (output_root / "builds" / "rust" / "target").mkdir(parents=True)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)

    with pytest.raises(RuntimeError, match="CARGO_TARGET_DIR must be set"):
        rust_client.rust_cargo_env()


def test_rust_cargo_env_rejects_wrong_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_root = tmp_path / "output-root"
    expected = output_root / "builds" / "rust" / "target"
    wrong = tmp_path / "wrong-target"
    expected.mkdir(parents=True)
    wrong.mkdir()
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(wrong))

    with pytest.raises(RuntimeError, match="CARGO_TARGET_DIR must be"):
        rust_client.rust_cargo_env()


def test_rust_cargo_env_rejects_nonexistent_target_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_root = tmp_path / "output-root"
    target_dir = output_root / "builds" / "rust" / "target"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    with pytest.raises(RuntimeError, match="existing directory"):
        rust_client.rust_cargo_env()


def test_start_rust_client_uses_shared_cargo_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    monkeypatch.setattr(rust_client, "rust_cargo_env", lambda: {"CARGO_TARGET_DIR": "target-dir"})
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    process = rust_client.start_rust_client(tmp_path / "repo", tmp_path / "profile", tmp_path / "rust.out")

    assert isinstance(process, FakeProcess)
    assert calls[0]["command"] == [
        "cargo",
        "run",
        "-p",
        "emulebb-daemon",
        "--bin",
        "emulebb-rust",
        "--",
        "--profile",
        str(tmp_path / "profile"),
    ]
    assert calls[0]["cwd"] == tmp_path / "repo"
    assert calls[0]["env"] == {"CARGO_TARGET_DIR": "target-dir"}
    assert calls[0]["stdout"].mode == "w"
    calls[0]["stdout"].close()


def test_start_rust_client_append_keeps_restart_log(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    output_path = tmp_path / "rust.out"
    output_path.write_text("first run\n", encoding="utf-8")
    monkeypatch.setattr(rust_client, "rust_cargo_env", lambda: {"CARGO_TARGET_DIR": "target-dir"})
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    rust_client.start_rust_client_append(tmp_path / "repo", tmp_path / "profile", output_path)

    assert calls[0]["stdout"].mode == "a"
    calls[0]["stdout"].write("second run\n")
    calls[0]["stdout"].close()
    assert output_path.read_text(encoding="utf-8") == "first run\nsecond run\n"


def test_start_rust_client_executable_uses_staged_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    executable = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"exe")
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    process = rust_client.start_rust_client_executable(executable, tmp_path / "profile", tmp_path / "rust.out")

    assert isinstance(process, FakeProcess)
    assert calls[0]["command"] == [str(executable), "--profile", str(tmp_path / "profile")]
    assert calls[0]["cwd"] == executable.parent
    assert calls[0]["stdout"].mode == "w"
    calls[0]["stdout"].close()


def test_start_rust_client_executable_passes_child_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return object()

    executable = tmp_path / "emulebb-rust-diagnostics.exe"
    executable.write_bytes(b"exe")
    child_env = {"EMULEBB_RUST_LOG_DIR": str(tmp_path / "diagnostics")}
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    rust_client.start_rust_client_executable(
        executable,
        tmp_path / "profile",
        tmp_path / "rust.out",
        env=child_env,
    )

    assert calls[0]["env"] is child_env
    calls[0]["stdout"].close()


def test_start_rust_client_executable_append_keeps_restart_log(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    executable = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"exe")
    output_path = tmp_path / "rust.out"
    output_path.write_text("first run\n", encoding="utf-8")
    monkeypatch.setattr(rust_client.subprocess, "Popen", fake_popen)

    rust_client.start_rust_client_executable_append(executable, tmp_path / "profile", output_path)

    assert calls[0]["command"] == [str(executable), "--profile", str(tmp_path / "profile")]
    assert calls[0]["stdout"].mode == "a"
    calls[0]["stdout"].write("second run\n")
    calls[0]["stdout"].close()
    assert output_path.read_text(encoding="utf-8") == "first run\nsecond run\n"
