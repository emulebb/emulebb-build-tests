"""The APK transfer fixture admits exact peer bytes and verifies delivered content."""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
from urllib.parse import unquote

import pytest

from emule_test_harness import android_apk_peer as subject

IDENTITY = {"sourceRevision": "a" * 40, "version": "0.1.0-test", "channel": "development"}


@pytest.mark.parametrize("response,presence", [
    ({"id": "12", "hash": "b" * 32, "state": "delivering", "progress": 1.0}, "present"),
    ({"id": "12", "hash": "c" * 32, "state": "delivering", "progress": 1.0}, "ambiguous"),
    ({"id": "13", "hash": "b" * 32}, "ambiguous"),
    ({"id": "12", "hash": "private", "state": "delivering"}, "unavailable"),
    (None, "unavailable"), ({}, "unavailable"),
    (subject.RustRestFailure("private", status=404, detail="{}"), "absent"),
    (RuntimeError("private"), "unavailable"),
])
def test_completion_sample_requires_captured_download_identity(response, presence):
    def request(method, route):
        assert method == "GET" and route == "/api/v1/downloads/12"
        if isinstance(response, Exception):
            raise response
        return response

    sample = subject._completion_sample(request, "12", "b" * 32, "missing")
    assert sample["sharedLookup"] == "missing" and sample["transferPresence"] == presence
    if presence != "present":
        assert set(sample) == {"sharedLookup", "transferPresence"}
    assert "hash" not in sample and "private" not in json.dumps(sample)


@pytest.mark.parametrize("progress", [False, True, -0.1, 1.1, float("nan"), float("inf"), 10**1000, "private", None])
def test_completion_projection_rejects_invalid_progress_and_untrusted_fields(progress):
    sample = {"sharedLookup": "missing", "transferPresence": "present", "state": ["private"], "progress": progress,
        "payloadVerified": "private", "sizeBytes": 2**64, "deliveryState": "private",
        "deliveryPathPresent": "private", "deliveryOwnership": "private", "hash": "private", "path": "private"}
    result = subject.safe_completion_failure({"reason": "deadline-exhausted", "samples": [sample], "private": "private"})
    assert result == {"reason": "deadline-exhausted", "samples": [{"sharedLookup": "missing", "transferPresence": "present"}]}


def test_completion_projection_admits_exact_numeric_boundaries_and_closed_fields():
    sample = {"sharedLookup": "metadata-mismatch", "transferPresence": "present", "state": "delivering", "progress": 1.0,
        "sizeBytes": 2**64 - 1, "payloadVerified": True, "deliveryState": "pending",
        "deliveryPathPresent": False, "deliveryOwnership": "none"}
    assert subject.safe_completion_failure({"reason": "lookup-failed", "samples": [sample]}) == {
        "reason": "lookup-failed", "samples": [sample]}
    assert subject.safe_completion_failure({"reason": "lookup-failed", "samples": [sample] * 3}) is None
    assert subject.safe_completion_failure({"reason": [], "samples": []}) is None
    assert subject.safe_completion_failure({"reason": "lookup-failed", "samples": []}) is None


@pytest.mark.parametrize("invalid", [None, {}, {"sharedLookup": []},
    {"sharedLookup": "missing", "transferPresence": "private"}])
@pytest.mark.parametrize("position", [0, 1])
def test_completion_projection_rejects_entire_observation_when_sample_order_is_unproved(invalid, position):
    samples = [{"sharedLookup": "missing", "transferPresence": "absent"}] * 2
    samples[position] = invalid
    assert subject.safe_completion_failure({"reason": "deadline-exhausted", "samples": samples}) is None


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


@pytest.mark.parametrize("failure", [None, "payload", "occupant", "path", "listener", "restart", "unfinished", "known-hash", "server-owner", "restore",
    "history", "duplicate-accepted", "active-row", "preflight-enqueue", "incomplete-inventory",
    "completion-missing", "completion-mismatch", "completion-lookup", "completion-diagnostics", "transient-completion", "unowned",
    "creation-200", "creation-id", "creation-hash"])
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
    disabled_servers = []
    detail_reads, shared_reads, clock = [], [], [0]
    if failure and (failure.startswith("completion-") or failure == "transient-completion"):
        monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    public_server = {"address": "192.0.2.100", "port": 4661, "name": "Operator server", "enabled": True}

    @contextmanager
    def peer(*args, **kwargs):
        yield "/data/local/tmp/peer-test", 22222

    monkeypatch.setattr(subject, "production_peer", peer)
    monkeypatch.setattr(subject, "publish_shared_tree", lambda *args, **kwargs: {
        "sharedFiles": {"matched": {"hash": "b" * 32,
                                    "ed2kLink": "ed2k://|file|Android Sample.bin|262144|" + "b" * 32 + "|/"}}})
    def page(items, *, shared=False):
        return {"items": items, "total": len(items), "limit": 100, **({"nextCursor": None} if shared else {"offset": 0})}

    def downloads(items, *, more=False):
        return {"data": items, "meta": {"apiVersion": "v1", "hasMore": more,
            "nextCursor": "more" if more else None}}

    def request(base, method, route, key, body=None, *, expected_status=None):
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
                assert ipaddress.ip_address(body["address"]).is_loopback and body["address"] != "127.0.0.1"
                assert body["port"] == 20031 and body["connect"] is False
                rows.append({**deepcopy(body), "priority": "normal", "static": False, "enabled": True})
            return {"items": deepcopy(rows)}
        if route.startswith("/api/v1/servers/") and method == "DELETE":
            address, port = unquote(route.rsplit("/", 1)[1]).rsplit(":", 1)
            assert ipaddress.ip_address(address).is_loopback and port == "20031"
            disabled_servers.append(route)
            next(row for row in servers[base] if row["address"] == address)["enabled"] = False
        if route.endswith("/operations/connect"):
            assert "%3A20031/operations/connect" in route and "/127." in route
            return {"connected": False, "connecting": True, "operationQueued": failure != "listener"}
        if route.startswith("/api/v1/downloads?view="):
            assert method == "GET"
            if route.endswith("view=unfinished&limit=200"):
                if failure == "unfinished":
                    return downloads([{"id": "13", "hash": "c" * 32, "state": "stopped"}])
                if state.get("promoted") and failure == "active-row" or state.get("duplicateQueued"):
                    return downloads([{"id": "13", "hash": "b" * 32, "state": "stopped"}])
            if failure == "incomplete-inventory":
                return downloads([], more=True)
            if route.endswith("view=all&limit=200") and state.get("promoted"):
                return downloads([{"id": "12", "hash": "b" * 32, "state": "completed"}])
            return downloads([])
        if route == "/api/v1/downloads":
            assert method == "POST" and body["source"]["type"] == "ed2k-link"
            assert "|sources,192.0.2.20:20029|/" in body["source"]["link"]
            if state["created"]:
                assert body["intent"] == "stopped" and set(body) == {"source", "intent"}
                if failure == "duplicate-accepted":
                    return {"id": "12", "hash": "b" * 32, "sizeBytes": len(content)}
                state["duplicateQueued"] = failure == "preflight-enqueue"
                conflicts = [{"jobId": "12", "hash": "b" * 32, "kind": "presentLocalFile",
                    "requestedName": "Android Sample.bin", "requestedSizeBytes": len(content),
                    "recordedSizeBytes": len(content), "path": state["incoming"] + "/Android Sample_01.bin",
                    "redownloadAllowed": True, "firstCompletedAt": 1,
                    "lastCompletedAt": 0 if failure == "history" else 2}]
                raise subject.RustRestFailure("private conflict details", status=409,
                    detail=json.dumps({"error": {"code": "DOWNLOAD_CONFLICT", "details": {"conflicts": conflicts}}}))
            assert body["intent"] == "started" and set(body) == {"source", "intent"}
            state["created"] = True
            assert expected_status == 201
            if failure == "creation-200":
                raise RuntimeError("Rust REST POST /api/v1/downloads returned HTTP 200; expected 201")
            assert state["incoming"] == state["settings"]["daemon"]["incomingDir"]
            assert state["restarts"] == 1, "the immutable live incoming destination requires a real restart"
            guest_files[state["incoming"] + "/Android Sample_01.bin"] = b"corrupt" if failure == "payload" else content
            if failure == "occupant":
                guest_files[state["incoming"] + "/Android Sample.bin"] = content
            if failure == "server-owner":
                servers[base][-1]["name"] = "operator changed endpoint"
            return {"id": "0" if failure == "creation-id" else "12",
                "hash": "c" * 32 if failure == "creation-hash" else "b" * 32,
                "sizeBytes": len(content)}
        if route == "/api/v1/downloads/remove":
            assert method == "POST" and expected_status == 207
            assert body == {"ids": ["12"], "deleteData": False}
            state["deleted"] = True
            return {"data": [{"id": "12", "status": "accepted", "httpStatus": 200}]}
        if route == "/api/v1/shared-files":
            if not state["created"]:
                return page([{"hash": "b" * 32}] if failure == "known-hash" else [], shared=True)
            pytest.fail("known delivered hash must use its exact endpoint, not a first page")
        if route == "/api/v1/shared-files/" + "b" * 32:
            shared_reads.append(clock[0])
            if failure == "transient-completion" and len(shared_reads) == 1:
                raise subject.RustRestFailure("synthetic-private-error", status=404, detail="{}")
            if failure in {"completion-missing", "completion-diagnostics"}:
                raise subject.RustRestFailure("synthetic-private-error", status=404, detail="{}")
            if failure == "completion-mismatch":
                return {"hash": "b" * 32, "complete": False, "partFile": True}
            if failure == "completion-lookup":
                raise subject.RustRestFailure("synthetic-private-error", status=503, detail="{}")
            state["promoted"] = True
            return {"hash": "b" * 32, "complete": True, "partFile": False,
                              "sizeBytes": len(content),
                              "path": ("/unexpected" if failure == "path" or failure == "restart" and state["restarts"] >= 2 else state["incoming"]) + "/Android Sample_01.bin"}
        if route == "/api/v1/downloads/12":
            assert not state["deleted"]
            detail_reads.append(clock[0])
            if failure == "completion-diagnostics" and detail_reads.count(120) > 1:
                raise RuntimeError("synthetic-private-diagnostic-error")
            completed = bool(state.get("promoted"))
            return {"id": "12", "hash": "b" * 32, "state": "completed" if completed else "delivering",
                "progress": 1.0, "sizeBytes": len(content), "payloadVerified": completed,
                "completedAt": 2 if completed else None,
                "delivery": {"path": state["incoming"] + "/Android Sample_01.bin" if completed else None,
                    "state": "delivered" if completed else "pending",
                    "ownership": "unowned" if failure == "unowned" else "owned" if completed else "none"}}
        return {}

    def command(*args, **kwargs):
        operation = args[2:]
        if operation[:2] == ("exec-out", "sh"):
            return b"/system/bin/sh: find script: inaccessible or not found\n"
        if operation[:2] == ("shell", "sh"):
            import shlex
            root = shlex.split(operation[-1])[0].split()[1]
            entries = [path for path in guest_files if path.rsplit("/", 1)[0] == root]
            return b"\0".join(path.encode() for path in entries) + (b"\0" if entries else b"")
        if operation[:1] == ("push",):
            from pathlib import Path
            guest_files[operation[2]] = Path(operation[1]).read_bytes()
        if operation[:3] == ("shell", "readlink", "-f"):
            return operation[3].replace("/sdcard", "/storage/emulated/0")
        if operation[:2] == ("shell", "sha256sum"):
            import shlex
            path = shlex.split(operation[2])[0]
            return hashlib.sha256(guest_files[path]).hexdigest() + " " + path
        if operation[:3] == ("shell", "ls", "-A"):
            return "\n".join(path.rsplit("/", 1)[1] for path in guest_files if path.startswith(operation[3] + "/"))
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
    if failure and failure not in {"transient-completion", "unowned"}:
        expected_phase = {"payload": "verify-delivered-bytes", "occupant": "verify-collision-preserved",
                          "path": "verify-delivered-path-and-size", "listener": "peer-listener-connect-acknowledgement",
                          "restart": "verify-completed-delivery-metadata", "unfinished": "admit-prior-downloads-and-roots",
                          "known-hash": "peer-shared-file-hash", "server-owner": "app-listener-owned-server-disable-precondition",
                          "restore": "cleanup-restore-original-settings", "history": "verify-completed-download-evidence",
                          "duplicate-accepted": "verify-completed-download-evidence", "active-row": "verify-completed-delivery-metadata",
                          "preflight-enqueue": "verify-completed-download-evidence", "incomplete-inventory": "admit-prior-downloads-and-roots",
                          **{name: "enqueue-owned-transfer" for name in ("creation-200", "creation-id", "creation-hash")},
                          **{name: "await-completed-delivery" for name in ("completion-missing", "completion-mismatch",
                              "completion-lookup", "completion-diagnostics")}}[failure]
        with pytest.raises(subject.CampaignFailure) as failed:
            subject.transfer_proof(command, {"sourceRevision": IDENTITY["sourceRevision"]}, **arguments)
        assert failed.value.failure["phase"] == expected_phase
        receipt = json.loads((tmp_path / "transfer-campaign.json").read_text())
        assert receipt["status"] == "failed" and receipt["failure"]["code"] == expected_phase + "-failed"
        if failure in {"creation-200", "creation-id", "creation-hash"}:
            assert state["deleted"] is False, "unreceipted creation cannot authorize job removal"
            assert json.loads((tmp_path / "transfer-cleanup.json").read_text())["status"] == "failed"
        if failure.startswith("completion-"):
            completion = failed.value.failure["completion"]
            assert receipt["failure"]["completion"] == completion
            assert completion["reason"] == ("lookup-failed" if failure == "completion-lookup" else "deadline-exhausted")
            assert len(completion["samples"]) == 1
            assert detail_reads and detail_reads[-1] == (0 if failure == "completion-lookup" else 120)
            assert clock[0] == (0 if failure == "completion-lookup" else 120)
            assert all(sample["sharedLookup"] == {"completion-missing": "missing", "completion-diagnostics": "missing",
                "completion-mismatch": "metadata-mismatch", "completion-lookup": "unavailable"}[failure] for sample in completion["samples"])
            assert all(sample["transferPresence"] == ("unavailable" if failure == "completion-diagnostics" else "present")
                       for sample in completion["samples"])
            if failure != "completion-diagnostics":
                assert all(sample["deliveryState"] == "pending" for sample in completion["samples"])
            assert "private" not in json.dumps(completion)
            if failure == "completion-lookup":
                assert receipt["failure"]["rest"]["httpStatus"] == 503
            else:
                assert receipt["failure"]["errorType"] == "RuntimeError" and "rest" not in receipt["failure"]
    else:
        result = subject.transfer_proof(command, {"sourceRevision": IDENTITY["sourceRevision"]}, **arguments)
        assert result["status"] == "passed"
        assert result["downloadId"] == "12"
        assert result["deliveryOwnership"] == ("unowned" if failure == "unowned" else "owned")
        assert result["collisionPreserved"] is True
        assert result["completedDeliverySurvivesRestart"] is True
        assert result["sha256"] == hashlib.sha256(content).hexdigest()
        assert state["settings"] == original and state["incoming"] == original["daemon"]["incomingDir"]
        assert detail_reads, "successful transfer waits must inspect the retained job"
        if failure == "transient-completion":
            assert clock[0] == 1 and shared_reads[:2] == [0, 1]
        assert state["restarts"] == 3 and state["deleted"]
        assert not any(path.startswith("/storage/") for path in guest_files)
        assert len(disabled_servers) == 2
        for rows in servers.values():
            assert rows[0] == public_server and len(rows) == 2 and rows[1]["enabled"] is False
        assert all(item["disposition"] == "owned-endpoint-disabled" for item in result["listenerCleanup"].values())
        assert result["restartEvidence"] == {"sharedCatalog": True, "retainedJob": True,
            "duplicateRejected": True, "unfinishedDownloadAbsent": True}
        assert json.loads((tmp_path / "transfer-campaign.json").read_text())["fixtureCleanup"] == {
            "filesRemoved": 2, "directoriesRemoved": 1}
    if failure not in {"unfinished", "restore"}:
        assert state["settings"] == original
    if failure == "restore":
        assert json.loads((tmp_path / "transfer-cleanup.json").read_text())["status"] == "failed"
        assert any(path.startswith("/storage/") for path in guest_files), "retain owned files when restoration is unproved"


@pytest.mark.parametrize("failure", [None, "peer-connect", "app-create", "app-connect", "existing-app"])
def test_listener_only_probe_distinguishes_rpc_rejection_and_existing_row_without_transfer(tmp_path, monkeypatch, failure):
    from copy import deepcopy
    calls, restarts = [], []
    peer_base, app_base = "http://127.0.0.1:22222", "http://127.0.0.1:12345"
    original = {"daemon": {"incomingDir": "/operator/Incoming"}, "nat": {"enabled": True}}
    servers = {peer_base: [{"address": "127.0.0.1", "port": 20031, "name": "Fresh peer seed",
                           "priority": "normal", "static": False, "enabled": True}],
               app_base: [{"address": "192.0.2.100", "port": 4661, "name": "Operator"}]}
    if failure == "existing-app":
        servers[app_base].append({"address": "127.0.0.1", "port": 20031, "name": "Operator loopback",
                                  "priority": "high", "static": True, "enabled": False})
    before = deepcopy(servers)

    @contextmanager
    def peer(*args, **kwargs):
        yield "/unused/owned-peer", 22222

    def request(base, method, route, key, body=None):
        calls.append((base, method, route))
        assert not route.startswith("/api/v1/downloads") or method == "GET"
        assert method != "PATCH"
        if route == "/api/v1/app/settings":
            return deepcopy(original)
        if route == "/api/v1/shared-directories":
            return {"roots": [{"path": "/operator/Shared"}]}
        if route == "/api/v1/downloads?view=unfinished&limit=200":
            return {"data": [], "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}
        if route == "/api/v1/network":
            return {"binding": {"activeConfiguredAddress": "192.0.2.20"}}
        if ((failure == "app-create" and base == app_base and route == "/api/v1/servers" and method == "POST")
                or (failure == "app-connect" and base == app_base and route.endswith("/operations/connect"))
                or (failure == "peer-connect" and base == peer_base and route.endswith("/operations/connect"))):
            raise subject.RustRestFailure("raw-private-path-key-endpoint", status=400,
                detail=json.dumps({"error": {"code": "INVALID_ARGUMENT", "message": "ED2K network is not configured /private/key"}}))
        if route == "/api/v1/servers":
            if method == "POST":
                servers[base].append({**deepcopy(body), "priority": "normal", "static": False, "enabled": True})
            return {"items": deepcopy(servers[base])}
        if route.endswith("/operations/connect"):
            return {"operationQueued": True}
        if method == "DELETE":
            address, port = unquote(route.rsplit("/", 1)[1]).rsplit(":", 1)
            assert address != "127.0.0.1" and ipaddress.ip_address(address).is_loopback and port == "20031"
            next(row for row in servers[base] if row["address"] == address)["enabled"] = False
        return {}

    monkeypatch.setattr(subject, "production_peer", peer)
    monkeypatch.setattr(subject, "request_json", request)
    args = dict(apk_port=12345, api_key="operator-secret", adb="adb", child={}, report_dir=tmp_path,
                rust_source=tmp_path, restart_service=lambda: restarts.append(True))
    if failure and failure != "existing-app":
        with pytest.raises(subject.CampaignFailure) as error:
            subject.probe_local_listeners(lambda *args: pytest.fail("no transfer fixture IO"),
                                         {"sourceRevision": IDENTITY["sourceRevision"]}, **args)
        expected = {"peer-connect": "peer-listener-directed-connect", "app-create": "app-listener-server-create",
                    "app-connect": "app-listener-directed-connect"}[failure]
        assert error.value.failure["phase"] == expected
        assert error.value.failure["rest"] == {"httpStatus": 400, "apiCode": "INVALID_ARGUMENT", "coreContext": "ed2k-not-configured"}
    else:
        result = subject.probe_local_listeners(lambda *args: pytest.fail("no transfer fixture IO"),
                                              {"sourceRevision": IDENTITY["sourceRevision"]}, **args)
        assert result == {"status": "passed", "scope": "listener-control-only", "transfer": "not-run"}
    assert len(restarts) == (0 if failure == "peer-connect" else 1)
    for base, rows in servers.items():
        assert rows[:len(before[base])] == before[base]
        added = rows[len(before[base]):]
        assert len(added) <= 1 and all(row["enabled"] is False for row in added)
    raw = (tmp_path / "listener-probe.json").read_text()
    assert "operator-secret" not in raw and "/private/key" not in raw and "192.0.2.20" not in raw


@pytest.mark.parametrize("collision", [False, True])
def test_nonce_loopback_endpoint_must_be_absent_from_full_catalog(tmp_path, collision, monkeypatch):
    from copy import deepcopy
    from types import SimpleNamespace
    monkeypatch.setattr(subject, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    rows = [{"address": "127.170.170.171", "port": 20031, "name": "Operator private name",
             "priority": "high", "static": True, "enabled": False}] if collision else [{"address": "127.0.0.1", "port": "20031"}]
    calls = []

    def request(base, method, route, key, body=None):
        calls.append((method, route))
        assert method == "GET", "invalid existing configuration must never be changed or connected"
        return {"items": deepcopy(rows)}

    monkeypatch.setattr(subject, "request_json", request)
    campaign = subject._Campaign(tmp_path / "listener-probe.json", {"sourceRevision": IDENTITY["sourceRevision"]}, subject.PREFIX)
    with pytest.raises(RuntimeError):
        with subject.local_listener("http://127.0.0.1:12345", "synthetic", campaign=campaign):
            pytest.fail("unusable existing endpoint must not connect")
    assert campaign.value["phase"] == "app-listener-" + ("allocate-owned-loopback-endpoint" if collision else "server-inventory")
    assert calls == [("GET", "/api/v1/servers")]
    assert "Operator private name" not in (tmp_path / "listener-probe.json").read_text()


@pytest.mark.parametrize("fault,code", [(None, None), ("enabled", "owned-disabled-row-missing-or-mutated"),
    ("name", "owned-disabled-row-missing-or-mutated"), ("priority", "owned-disabled-row-missing-or-mutated"),
    ("static", "owned-disabled-row-missing-or-mutated"), ("missing", "owned-disabled-row-missing-or-mutated"),
    ("ambiguous", "owned-disabled-row-missing-or-mutated"), ("foreign", "preexisting-configuration-changed"),
    ("added", "preexisting-configuration-changed"), ("before-disable", "owned-configuration-mutated-or-missing")])
def test_listener_delete_is_exact_owned_disabled_tombstone_and_preserves_every_prior_configuration(tmp_path, monkeypatch, fault, code):
    from copy import deepcopy
    foreign = {"address": "127.0.0.1", "port": 20031, "name": "Operator private configuration",
               "priority": "high", "static": True, "enabled": False}
    rows, calls = [deepcopy(foreign)], []

    def request(base, method, route, key, body=None):
        calls.append((method, route))
        if method == "POST" and route == "/api/v1/servers":
            rows.append({**body, "priority": "normal", "static": False, "enabled": True})
        if method == "POST" and route.endswith("/operations/connect"):
            if fault == "before-disable":
                rows[1]["name"] = "Operator changed ownership"
            return {"operationQueued": True}
        if method == "DELETE":
            assert "127.0.0.1%3A" not in route
            rows[1]["enabled"] = fault == "enabled"
            if fault in {"name", "priority", "static"}:
                rows[1][fault] = {"name": "changed", "priority": "high", "static": True}[fault]
            if fault == "missing": rows.pop()
            if fault == "ambiguous": rows.append(deepcopy(rows[1]))
            if fault == "foreign": rows[0]["priority"] = "low"
            if fault == "added": rows.append({**foreign, "address": "192.0.2.200"})
        return {"items": deepcopy(rows)}

    monkeypatch.setattr(subject, "request_json", request)
    campaign = subject._Campaign(tmp_path / "campaign.json", {"sourceRevision": IDENTITY["sourceRevision"]}, subject.PREFIX)
    if fault:
        with pytest.raises(subject.ListenerCleanupFailure) as error:
            with subject.local_listener("http://127.0.0.1:12345", "secret", campaign=campaign):
                pass
        assert error.value.code == code and campaign.value["listenerCleanup"]["app"] == {"status": "failed", "code": code}
    else:
        with subject.local_listener("http://127.0.0.1:12345", "secret", campaign=campaign):
            pass
        assert rows[0] == foreign and len(rows) == 2 and rows[1]["enabled"] is False
        assert campaign.value["listenerCleanup"]["app"] == {"status": "passed", "disposition": "owned-endpoint-disabled",
            "ownedRowRetained": True, "preExistingConfigurationPreserved": True}
    if fault == "before-disable":
        assert not any(method == "DELETE" for method, route in calls)
    assert "Operator private configuration" not in (tmp_path / "campaign.json").read_text()


@pytest.mark.parametrize("kind,document", [
    ("downloads", {"data": [], "meta": {"apiVersion": "v1", "hasMore": True, "nextCursor": "next"}}),
    ("downloads", {"data": [], "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": "next"}}),
    ("downloads", {"data": [], "meta": {"apiVersion": "v1", "hasMore": False}}),
    ("downloads", {"items": []}),
    ("shared-files", {"items": [], "total": 1, "limit": 100, "nextCursor": "private cursor"}),
    ("shared-files", {"items": [], "total": 0, "limit": False, "nextCursor": None}),
])
def test_initial_inventory_never_treats_a_truncated_or_unknown_page_as_exhaustive(kind, document):
    with pytest.raises(RuntimeError, match="complete bounded"):
        subject._complete_items(document, kind=kind)
    assert subject._complete_items({"items": []}, kind="servers") == []
