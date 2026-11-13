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
             "buildIdentity": identity, "files": {"emulebb-rust": {
                 "sizeBytes": binary.stat().st_size, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}}}
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_peer_is_bound_to_actual_cli_bytes_and_same_distribution(tmp_path):
    digest = fixture(tmp_path)
    value = subject.admit_peer(tmp_path, manifest_sha256=digest, identity=IDENTITY)
    assert value["sourceRevision"] == IDENTITY["sourceRevision"]
    with pytest.raises(RuntimeError, match="distribution identity"):
        subject.admit_peer(tmp_path, manifest_sha256=digest, identity={**IDENTITY, "channel": "nightly"})
    (tmp_path / "emulebb-rust").write_bytes(b"substituted source bytes")
    with pytest.raises(RuntimeError, match="inconsistent|hash differs"):
        subject.admit_peer(tmp_path, manifest_sha256=digest, identity=IDENTITY)


def test_peer_manifest_cannot_be_substituted_or_include_arbitrary_files(tmp_path):
    digest = fixture(tmp_path)
    with pytest.raises(RuntimeError, match="manifest hash"):
        subject.admit_peer(tmp_path, manifest_sha256="0" * 64, identity=IDENTITY)
    value = json.loads((tmp_path / "manifest.json").read_text())
    value["files"]["../outside"] = value["files"]["emulebb-rust"]
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    with pytest.raises(RuntimeError, match="distribution identity"):
        subject.admit_peer(tmp_path, manifest_sha256=hashlib.sha256(raw).hexdigest(), identity=IDENTITY)


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
    monkeypatch.setattr(android_emulator, "_daemon_identity", lambda *args: ("start", "hash"))

    def fail_identity(*args):
        raise RuntimeError("source identity differs")

    monkeypatch.setattr(android_emulator, "_app_identity", fail_identity)

    def command(*args, **kwargs):
        calls.append(args)
        if "sha256sum" in args:
            return "a" * 64 + " " + args[-1]
        if "forward" in args and "--remove" not in args:
            if not admitted:
                raise ValueError("private forward failed")
            return "22222"
        if "cat" in args:
            return "1234"
        return ""

    peer = {"files": {"emulebb-rust": {"sha256": "a" * 64}}, "payloadRoot": str(tmp_path),
            "buildIdentity": IDENTITY}
    with pytest.raises(RuntimeError if admitted else ValueError, match="source identity|private forward"):
        with subject.production_peer(command, peer, adb="adb", child={}, report_dir=tmp_path,
                                     rust_source=tmp_path, bind_ip="192.0.2.20"):
            pytest.fail("a failed peer must not yield")
    assert "stop-wrapper" in calls and "capture-close" in calls
    deleted = any(isinstance(call, tuple) and "rm" in call for call in calls)
    terminated = any(isinstance(call, tuple) and "kill" in call for call in calls)
    assert deleted == terminated == admitted
    if not admitted:
        assert json.loads((tmp_path / "peer-cleanup.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("failure", [None, "payload", "occupant", "path", "listener", "public-server"])
def test_real_transfer_verdict_requires_delivered_bytes_and_collision_preservation(tmp_path, monkeypatch, failure):
    content = subject.deterministic_payload(0, 256 * 1024, generation="android-apk")
    guest_files = {}
    state = {"incoming": None, "created": False}
    servers = {}

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
            state["incoming"] = body["daemon"]["incomingDir"]
            assert body["ed2k"] == {"enableUdpReask": False, "addServersFromServer": False}
        if route == "/api/v1/servers":
            if method == "POST":
                assert body == {"address": "127.0.0.1", "port": 20031,
                                "name": "Local qualification endpoint", "connect": False}
                servers[base] = [body]
            return {"items": servers.setdefault(base, [{"address": "192.0.2.100", "port": 4661}])
                    + ([{"address": "192.0.2.100", "port": 4661}] if failure == "public-server" else [])}
        if route.startswith("/api/v1/servers/") and method == "DELETE":
            assert route == "/api/v1/servers/192.0.2.100%3A4661"
            servers[base] = []
        if route == "/api/v1/servers/operations/connect":
            return {"connected": False, "connecting": True, "operationQueued": failure != "listener"}
        if route == "/api/v1/transfers":
            state["created"] = True
            # TransferCreate in the actual Rust REST model accepts singular link
            # and paused; this is the existing release-smoke owner's exact body.
            assert method == "POST" and set(body) == {"link", "paused"} and body["paused"] is False
            assert "|sources,192.0.2.20:20029|/" in body["link"]
            guest_files[state["incoming"] + "/Android Sample (1).bin"] = b"corrupt" if failure == "payload" else content
            if failure == "occupant":
                guest_files[state["incoming"] + "/Android Sample.bin"] = content
        if route == "/api/v1/shared-files":
            assert state["created"]
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
        return ""

    monkeypatch.setattr(subject, "request_json", request)
    arguments = dict(apk_port=12345, api_key="synthetic-app-key", adb="adb", child={},
                     report_dir=tmp_path, rust_source=tmp_path)
    if failure:
        with pytest.raises(RuntimeError, match={"payload": "delivered bytes", "occupant": "foreign destination",
                                               "path": "invalid size", "listener": "eD2K start operation",
                                               "public-server": "nonlocal server"}[failure]):
            subject.transfer_proof(command, {"sourceRevision": IDENTITY["sourceRevision"]}, **arguments)
    else:
        result = subject.transfer_proof(command, {"sourceRevision": IDENTITY["sourceRevision"]}, **arguments)
        assert result["status"] == "passed"
        assert result["collisionPreserved"] is True
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
