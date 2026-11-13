"""The APK transfer fixture admits exact peer bytes and verifies delivered content."""
from contextlib import contextmanager
import hashlib
import json

import pytest

from emule_test_harness import android_apk_peer as subject

IDENTITY = {"sourceRevision": "a" * 40, "version": "0.1.0-test", "channel": "development"}


def fixture(tmp_path, *, identity=IDENTITY):
    binary = tmp_path / "emulebb-rust"
    binary.write_bytes(b"synthetic source-bound CLI")
    value = {"schema": "emulebb.android.apk-peer/1", "sourceRevision": identity["sourceRevision"],
             "target": "x86_64-linux-android", "abi": "x86_64",
             "buildIdentity": identity, "files": {"emulebb-rust": {
                 "sizeBytes": binary.stat().st_size, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}}}
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_peer_is_bound_to_actual_cli_bytes_and_same_distribution(tmp_path):
    digest = fixture(tmp_path)
    value = subject.admit_peer(tmp_path, manifest_sha256=digest, identity=IDENTITY, expected_abi="x86_64")
    assert value["sourceRevision"] == IDENTITY["sourceRevision"]
    with pytest.raises(RuntimeError, match="distribution identity"):
        subject.admit_peer(tmp_path, manifest_sha256=digest, identity={**IDENTITY, "channel": "nightly"}, expected_abi="x86_64")
    (tmp_path / "emulebb-rust").write_bytes(b"substituted source bytes")
    with pytest.raises(RuntimeError, match="inconsistent|hash differs"):
        subject.admit_peer(tmp_path, manifest_sha256=digest, identity=IDENTITY, expected_abi="x86_64")


def test_peer_requires_the_selected_device_abi_and_matching_rust_target(tmp_path):
    digest = fixture(tmp_path)
    with pytest.raises(RuntimeError, match="distribution identity"):
        subject.admit_peer(tmp_path, manifest_sha256=digest, identity=IDENTITY, expected_abi="arm64-v8a")
    value = json.loads((tmp_path / "manifest.json").read_text())
    value["abi"] = "arm64-v8a"
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(RuntimeError, match="distribution identity"):
        subject.admit_peer(tmp_path, manifest_sha256=digest, identity=IDENTITY, expected_abi="arm64-v8a")
    value["target"] = "aarch64-linux-android"
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    assert subject.admit_peer(tmp_path, manifest_sha256=hashlib.sha256(raw).hexdigest(),
                              identity=IDENTITY, expected_abi="arm64-v8a")["target"] == "aarch64-linux-android"


def test_selected_device_peer_requires_explicit_owned_process_callbacks(tmp_path):
    calls = []
    with pytest.raises(ValueError, match="explicit owned launcher"):
        with subject.production_peer(lambda *args: calls.append(args), {}, adb="adb", child={},
                                     report_dir=tmp_path, rust_source=tmp_path, bind_ip="127.0.0.1",
                                     prefix=("-s", "synthetic-phone")):
            pytest.fail("physical peer must not use the emulator launcher")
    assert not calls and not list(tmp_path.iterdir())


def test_peer_home_creation_failure_retains_durable_nonce_and_safe_native_failure(tmp_path, monkeypatch):
    from emule_test_harness import rust_client
    monkeypatch.setattr(rust_client, "write_rust_profile", lambda *args, **kwargs: None)
    peer = {"sourceRevision": IDENTITY["sourceRevision"], "files": {"emulebb-rust": {"sha256": "a" * 64}}}
    campaign = subject._Campaign(tmp_path / "transfer-campaign.json", peer, ("-s", "synthetic-device"))
    mutations = []

    def command(*args, **kwargs):
        receipt = json.loads((tmp_path / "transfer-campaign.json").read_text())
        assert receipt["phase"] == "peer-home-create" and len(receipt["peerOwnership"]["nonce"]) == 32
        assert receipt["peerOwnership"]["creationVerified"] is False
        mutations.append(args)
        raise subject.AdbOperationFailure(("shell", "mkdir"), exit_code=1,
            stderr="mkdir: /private/operator/path: Permission denied synthetic-private-key")

    with pytest.raises(subject.AdbOperationFailure):
        with subject.production_peer(command, peer, adb="adb", child={}, report_dir=tmp_path,
                                     rust_source=tmp_path, bind_ip="192.0.2.20", campaign=campaign):
            pytest.fail("uncreated home must not launch a process")
    raw = (tmp_path / "transfer-campaign.json").read_text()
    receipt = json.loads(raw)
    assert receipt["failure"] == {"phase": "peer-home-create", "code": "peer-home-create-failed",
        "errorType": "AdbOperationFailure", "adb": {"operation": "shell-mkdir", "reason": "permission-denied", "exitCode": 1}}
    assert len(mutations) == 1 and not any("rm" in args or "kill" in args for args in mutations)
    assert "operator" not in raw and "private-key" not in raw and "192.0.2.20" not in raw


def test_early_peer_exit_is_recorded_even_when_complete_home_cleanup_succeeds(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from emule_test_harness import rust_client
    monkeypatch.setattr(rust_client, "write_rust_profile", lambda *args, **kwargs: None)
    peer = {"sourceRevision": IDENTITY["sourceRevision"], "payloadRoot": str(tmp_path),
            "files": {"emulebb-rust": {"sha256": "a" * 64}}}
    campaign = subject._Campaign(tmp_path / "transfer-campaign.json", peer, ("-s", "synthetic-device"))
    process = SimpleNamespace(poll=lambda: 42, returncode=42)
    capture = SimpleNamespace(close=lambda: None, raise_if_failed=lambda: None,
        summary=lambda: {"contexts": ["dynamic-linker"], "systemConditions": []})
    calls = []

    def command(*args, **kwargs):
        calls.append(args)
        if "sha256sum" in args:
            return "a" * 64 + " " + args[-1]
        if "readlink" in args:
            return args[-1]
        return ""

    with pytest.raises(RuntimeError, match="exited before guest process admission"):
        with subject.production_peer(command, peer, adb="adb", child={}, report_dir=tmp_path, rust_source=tmp_path,
                bind_ip="192.0.2.20", campaign=campaign, spawn_daemon=lambda *args: (process, capture), stop_client=lambda process: None):
            pytest.fail("an already-exited peer cannot be ready")
    receipt = json.loads((tmp_path / "transfer-campaign.json").read_text())
    assert receipt["failure"]["phase"] == "peer-process-admission"
    assert receipt["peerProcess"] == {"returnCode": 42, "startup": {"contexts": ["dynamic-linker"], "systemConditions": []}}
    assert any("rm" in call for call in calls) and not any("kill" in call for call in calls)
    assert not (tmp_path / "peer-cleanup.json").exists()


def test_peer_manifest_cannot_be_substituted_or_include_arbitrary_files(tmp_path):
    digest = fixture(tmp_path)
    with pytest.raises(RuntimeError, match="manifest hash"):
        subject.admit_peer(tmp_path, manifest_sha256="0" * 64, identity=IDENTITY, expected_abi="x86_64")
    value = json.loads((tmp_path / "manifest.json").read_text())
    value["files"]["../outside"] = value["files"]["emulebb-rust"]
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    with pytest.raises(RuntimeError, match="distribution identity"):
        subject.admit_peer(tmp_path, manifest_sha256=hashlib.sha256(raw).hexdigest(), identity=IDENTITY, expected_abi="x86_64")


@pytest.mark.parametrize("admitted", [False, True])
def test_peer_failure_cleanup_never_deletes_unadmitted_running_guest(tmp_path, monkeypatch, admitted):
    from types import SimpleNamespace
    from emule_test_harness import android_emulator, rust_client

    calls = []
    running = [True]
    process = SimpleNamespace(poll=lambda: None if running[0] else 0,
                              wait=lambda **kwargs: running.__setitem__(0, False) or 0)
    capture = SimpleNamespace(raise_if_failed=lambda: None, close=lambda: calls.append("capture-close"))
    monkeypatch.setattr(rust_client, "write_rust_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(android_emulator, "_start_production_daemon", lambda *args: (process, capture))
    monkeypatch.setattr(android_emulator, "_stop_group", lambda value: calls.append("stop-wrapper"))
    monkeypatch.setattr(android_emulator, "_rest_app", lambda *args: (200, {}))
    monkeypatch.setattr(android_emulator, "_daemon_identity", lambda *args, **kwargs: ("start", "hash"))

    def fail_identity(*args):
        raise RuntimeError("source identity differs")

    monkeypatch.setattr(android_emulator, "_app_identity", fail_identity)

    def command(*args, **kwargs):
        calls.append(args)
        if "sha256sum" in args:
            return "a" * 64 + " " + args[-1]
        if "readlink" in args:
            return args[-1]
        if "forward" in args and "--remove" not in args:
            if not admitted:
                raise ValueError("private forward failed")
            return "22222"
        if "cat" in args:
            if not admitted:
                raise ValueError("private admission failed")
            return "1234"
        return ""

    peer = {"files": {"emulebb-rust": {"sha256": "a" * 64}}, "payloadRoot": str(tmp_path),
            "buildIdentity": IDENTITY}
    with pytest.raises(RuntimeError if admitted else ValueError, match="source identity|private admission"):
        with subject.production_peer(command, peer, adb="adb", child={}, report_dir=tmp_path,
                                     rust_source=tmp_path, bind_ip="192.0.2.20"):
            pytest.fail("a failed peer must not yield")
    assert "stop-wrapper" in calls and "capture-close" in calls
    deleted = any(isinstance(call, tuple) and "rm" in call for call in calls)
    terminated = any(isinstance(call, tuple) and "kill" in call for call in calls)
    assert deleted == terminated == admitted
    if not admitted:
        assert json.loads((tmp_path / "peer-cleanup.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("failure", [None, "payload", "occupant", "path", "listener", "restart", "unfinished", "known-hash", "server-owner", "restore"])
def test_real_transfer_verdict_requires_delivered_bytes_and_collision_preservation(tmp_path, monkeypatch, failure):
    from types import SimpleNamespace
    from copy import deepcopy
    monkeypatch.setattr(subject, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    content = subject.deterministic_payload(0, 256 * 1024, generation="android-apk-" + "a" * 32)
    guest_files = {}
    original = {"daemon": {"incomingDir": "/original/Incoming"},
                "core": {"autoConnect": True, "networkKademlia": True, "networkEd2k": True},
                "ed2k": {"enableUdpReask": True, "addServersFromServer": True}, "nat": {"enabled": True}}
    state = {"settings": deepcopy(original), "incoming": original["daemon"]["incomingDir"],
             "created": False, "restarts": 0, "deleted": False}
    servers = {}
    deleted_servers = []
    public_server = {"address": "192.0.2.100", "port": 4661, "name": "Operator server", "enabled": True}

    @contextmanager
    def peer(*args, **kwargs):
        yield "/data/local/tmp/peer-test", 22222

    monkeypatch.setattr(subject, "production_peer", peer)
    monkeypatch.setattr(subject, "publish_shared_tree", lambda *args, **kwargs: {
        "sharedFiles": {"matched": {"hash": "b" * 32,
                                    "ed2kLink": "ed2k://|file|Android Sample.bin|262144|" + "b" * 32 + "|/"}}})

    def request(base, method, route, key, body=None):
        if route == "/api/v1/network":
            return {"binding": {"activeConfiguredAddress": "192.0.2.20"}}
        if route == "/api/v1/app/settings":
            if method == "PATCH":
                state["settings"] = deepcopy(body)
                if failure == "restore" and body == original:
                    state["settings"]["core"]["autoConnect"] = False
            return deepcopy(state["settings"])
        if route == "/api/v1/shared-directories":
            return {"roots": [{"path": "/operator/Shared"}]}
        if route == "/api/v1/servers":
            rows = servers.setdefault(base, [deepcopy(public_server)])
            if method == "POST":
                assert body["address"] == "127.0.0.1" and body["port"] == 20031 and body["connect"] is False
                rows.append(deepcopy(body))
            return {"items": deepcopy(rows)}
        if route.startswith("/api/v1/servers/") and method == "DELETE":
            assert route == "/api/v1/servers/127.0.0.1%3A20031"
            deleted_servers.append(route)
            servers[base] = [row for row in servers[base] if row["address"] != "127.0.0.1"]
        if route.endswith("/operations/connect"):
            assert route == "/api/v1/servers/127.0.0.1%3A20031/operations/connect"
            return {"connected": False, "connecting": True, "operationQueued": failure != "listener"}
        if route == "/api/v1/transfers":
            if method == "GET":
                if failure == "unfinished":
                    return {"items": [{"hash": "c" * 32, "state": "paused"}]}
                if not state["created"] or state["deleted"]:
                    return {"items": []}
                return {"items": [{"hash": "b" * 32, "state": "paused" if failure == "restart" else "completed",
                                   "deliveredPath": state["incoming"] + "/Android Sample (1).bin"}]}
            state["created"] = True
            # TransferCreate in the actual Rust REST model accepts singular link
            # and paused; this is the existing release-smoke owner's exact body.
            assert method == "POST" and set(body) == {"link", "paused"} and body["paused"] is False
            assert "|sources,192.0.2.20:20029|/" in body["link"]
            assert state["incoming"] == state["settings"]["daemon"]["incomingDir"]
            assert state["restarts"] == 1, "the immutable live incoming destination requires a real restart"
            guest_files[state["incoming"] + "/Android Sample (1).bin"] = b"corrupt" if failure == "payload" else content
            if failure == "occupant":
                guest_files[state["incoming"] + "/Android Sample.bin"] = content
            if failure == "server-owner":
                servers[base][-1]["name"] = "operator changed endpoint"
        if route.endswith("/files?confirm=true"):
            assert method == "DELETE" and route == "/api/v1/transfers/" + "b" * 32 + "/files?confirm=true"
            state["deleted"] = True
            guest_files.pop(state["incoming"] + "/Android Sample (1).bin", None)
        if route == "/api/v1/shared-files":
            if not state["created"]:
                return {"items": [{"hash": "b" * 32}] if failure == "known-hash" else []}
            return {"items": [{"hash": "b" * 32, "complete": True, "partFile": False,
                              "sizeBytes": len(content),
                              "path": ("/unexpected" if failure == "path" else state["incoming"]) + "/Android Sample (1).bin"}]}
        return {}

    def command(*args, **kwargs):
        operation = args[2:]
        if operation[:1] == ("push",):
            from pathlib import Path
            guest_files[operation[2]] = Path(operation[1]).read_bytes()
        if operation[:3] == ("shell", "readlink", "-f"):
            return operation[3].replace("/sdcard", "/storage/emulated/0")
        if operation[:2] == ("shell", "sha256sum"):
            import shlex
            path = shlex.split(operation[2])[0]
            return hashlib.sha256(guest_files[path]).hexdigest() + " " + path
        if operation[:2] == ("shell", "rm"):
            import shlex
            del guest_files[shlex.split(operation[-1])[0]]
        if operation[:2] == ("shell", "rmdir"):
            assert not any(path.startswith(operation[2] + "/") for path in guest_files)
        return ""

    def restart():
        state["restarts"] += 1
        state["incoming"] = state["settings"]["daemon"]["incomingDir"]

    monkeypatch.setattr(subject, "request_json", request)
    arguments = dict(apk_port=12345, api_key="synthetic-app-key", adb="adb", child={},
                     report_dir=tmp_path, rust_source=tmp_path, restart_service=restart)
    if failure:
        expected_phase = {"payload": "verify-delivered-bytes", "occupant": "verify-collision-preserved",
                          "path": "verify-delivered-path-and-size", "listener": "directed-local-listener-start",
                          "restart": "verify-completed-delivery-metadata", "unfinished": "admit-prior-downloads-and-roots",
                          "known-hash": "peer-shared-file-hash", "server-owner": "verify-owned-loopback-server-removal",
                          "restore": "cleanup-restore-original-settings"}[failure]
        with pytest.raises(subject.CampaignFailure) as failed:
            subject.transfer_proof(command, {"sourceRevision": IDENTITY["sourceRevision"]}, **arguments)
        assert failed.value.failure["phase"] == expected_phase
        receipt = json.loads((tmp_path / "transfer-campaign.json").read_text())
        assert receipt["status"] == "failed" and receipt["failure"]["code"] == expected_phase + "-failed"
    else:
        result = subject.transfer_proof(command, {"sourceRevision": IDENTITY["sourceRevision"]}, **arguments)
        assert result["status"] == "passed"
        assert result["collisionPreserved"] is True
        assert result["completedDeliverySurvivesRestart"] is True
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert state["settings"] == original and state["incoming"] == original["daemon"]["incomingDir"]
        assert state["restarts"] == 3 and state["deleted"]
        assert not any(path.startswith("/storage/") for path in guest_files)
        assert len(deleted_servers) == 2 and all(rows == [public_server] for rows in servers.values())
    if failure not in {"unfinished", "restore"}:
        assert state["settings"] == original
    if failure == "restore":
        assert json.loads((tmp_path / "transfer-cleanup.json").read_text())["status"] == "failed"
        assert any(path.startswith("/storage/") for path in guest_files), "retain owned files when restoration is unproved"
