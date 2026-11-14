"""Public campaign boundaries: private copy, ownership, scope and truthful evidence."""
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from test_profile_import_job import directory_alias as directory_alias

from emule_test_harness import android_public_sharing as subject


@pytest.fixture(autouse=True)
def mock_process_inspection(monkeypatch):
    monkeypatch.setattr(subject.windows_processes, "process_creation_date",
                        lambda pid: "20260101000000.000000+000" if pid == subject.os.getpid() else "")


def receipt():
    nonce = "1" * 32
    tree = {"directories": ["Sample Folder"], "files": [{"path": "Sample Folder/Sample Audio.bin",
            "sizeBytes": 4, "mtimeNs": 10, "sha256": hashlib.sha256(b"data").hexdigest()}]}
    return {"schema": subject.SCHEMA, "status": "prepared", "nonce": nonce, "route": "direct-wifi",
            "destination": subject.SHARED + "/campaign-" + nonce,
            "marker": "/data/local/tmp/emulebb-public-sharing-" + nonce + ".owner",
            "staging": "/data/local/tmp/emulebb-public-sharing-" + nonce + ".stage",
            "deviceSerialSha256": hashlib.sha256(b"synthetic:5555").hexdigest(),
            "inventory": tree, "inventorySha256": subject._digest(tree), "fileCount": 1, "totalBytes": 4,
            "limits": subject.asdict(subject.Limits(duration_seconds=1))}


def save_receipt(root, value):
    root.mkdir(exist_ok=True)
    subject.write_json(root / "campaign.json", value)
    return hashlib.sha256((root / "campaign.json").read_bytes()).hexdigest()


def test_inventory_preserves_real_tree_and_rejects_links(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Empty Folder").mkdir()
    path = source / "Sample Audio.bin"
    path.write_bytes(b"sample")
    before = path.stat()
    result = subject.inventory(source)
    assert result["directories"] == ["Empty Folder"]
    assert result["files"][0]["sha256"] == hashlib.sha256(b"sample").hexdigest()
    assert result == subject.inventory(source)
    assert path.stat().st_mtime_ns == before.st_mtime_ns and path.read_bytes() == b"sample"
    try:
        (source / "link.bin").symlink_to(path)
    except OSError:
        pytest.skip("Host does not permit creating symbolic links")
    with pytest.raises(RuntimeError):
        subject.inventory(source)


def test_inventory_accepts_reparse_ancestor_outside_selected_tree(directory_alias):
    alias, actual = directory_alias
    source = actual / "library"
    source.mkdir()
    (source / "Sample.bin").write_bytes(b"data")
    # Simulate the DOS spelling retained below a mounted-volume junction even
    # after source-anchor canonicalization: the selected leaf itself is regular.
    result = subject.inventory(alias / "library")
    assert result == subject.inventory(source)
    assert result["files"][0]["sha256"] == hashlib.sha256(b"data").hexdigest()


def test_inventory_still_rejects_selected_root_reparse(directory_alias):
    alias, actual = directory_alias
    (actual / "Sample.bin").write_bytes(b"data")
    with pytest.raises(RuntimeError):
        subject.inventory(alias)


@pytest.mark.parametrize("fault", ["device", "hash", "destination", "inventory", "route", "limits"])
def test_campaign_receipt_requires_immutable_exact_scope(tmp_path, fault):
    value = receipt()
    if fault == "destination": value["destination"] = subject.SHARED + "/Other"
    if fault == "inventory": value["inventory"]["files"][0]["path"] = "Other.bin"
    if fault == "route": value["route"] = "vpn"
    if fault == "limits": value["limits"]["duration_seconds"] = 86401
    digest = save_receipt(tmp_path, value)
    with pytest.raises((RuntimeError, ValueError)):
        subject.admit_campaign(tmp_path, "0" * 64 if fault == "hash" else digest,
                               "other:5555" if fault == "device" else "synthetic:5555")


def test_campaign_receipt_admits_only_selected_device(tmp_path):
    value = receipt()
    digest = save_receipt(tmp_path, value)
    assert subject.admit_campaign(tmp_path, digest, "synthetic:5555") == value


def test_device_lease_excludes_live_owner_and_preserves_foreign_stale_owner(tmp_path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    with subject.device_lease(tmp_path, "a" * 64, campaign):
        with pytest.raises(RuntimeError):
            with subject.device_lease(tmp_path, "a" * 64, campaign, recover=True):
                pass
    lock = tmp_path / "tmp/android-public-sharing" / ("a" * 64 + ".lock")
    subject.write_json(lock, {"campaign": "foreign", "pid": 999999999, "created": 1})
    with pytest.raises(RuntimeError):
        with subject.device_lease(tmp_path, "a" * 64, campaign, recover=True):
            pass
    assert lock.exists()


@pytest.mark.parametrize("transport", ["WIFI VPN", "CELLULAR", "VPN"])
def test_direct_wifi_rejects_other_default_routes(transport):
    dump = "Active default network: 7\n  NetworkAgentInfo{network{7} nc{[ Transports: " + transport + " Capabilities: INTERNET ]}}"
    with pytest.raises(RuntimeError):
        subject.wifi_default(dump)


def test_direct_wifi_uses_active_network_instead_of_any_wifi():
    subject.wifi_default("Active default network: 7\nNetworkAgentInfo{network{7} nc{[ Transports: WIFI Capabilities: INTERNET ]}}")
    with pytest.raises(RuntimeError):
        subject.wifi_default("Active default network: 8\nNetworkAgentInfo{network{7} nc{[ Transports: WIFI Capabilities: INTERNET ]}}")


@pytest.mark.parametrize("fault", [None, "extra", "link", "missing", "marker", "hash"])
def test_guest_scope_requires_exact_tree_and_hashes(monkeypatch, fault):
    value = receipt()
    destination = value["destination"]
    dirs = {subject.SHARED, destination, destination + "/Sample Folder"}
    files = {destination + "/Sample Folder/Sample Audio.bin"}
    def entries(phone, root, kind=None):
        if root == subject.INCOMING: return {root}
        selected = dirs if kind == "d" else files if kind == "f" else dirs | files
        if fault == "extra" and kind is None: return selected | {destination + "/Unapproved.bin"}
        if fault == "link" and kind == "f": return set()
        if fault == "missing": return selected - files
        return selected
    phone = SimpleNamespace(device=SimpleNamespace(command=lambda *a, **kw: None), prefix=())
    phone.shell = lambda *args: ("wrong" if fault == "marker" else value["nonce"]) if args[0] == "cat" else args[-1]
    monkeypatch.setattr(subject, "_guest_entries", entries)
    monkeypatch.setattr(subject, "guest_sha256", lambda *a, **kw: "0" * 64 if fault == "hash" else value["inventory"]["files"][0]["sha256"])
    if fault:
        with pytest.raises(RuntimeError): subject.guest_scope(phone, value, hashes=True)
    else:
        subject.guest_scope(phone, value, hashes=True)


def test_public_request_is_distinct_from_increasing_payload_and_local_peer():
    catalog = [{"hash": "a" * 32}]
    row = {"clientId": "peer", "address": "93.184.216.34", "requestedFileHash": "a" * 32, "uploadedBytes": 100}
    first, previous = subject.public_upload_evidence({"items": [row]}, catalog, {})
    assert first["requests"] == "observed" and first["bytesVerdict"] == "not-observed"
    second, _ = subject.public_upload_evidence({"items": [{**row, "uploadedBytes": 150}]}, catalog, previous)
    assert second["bytesVerdict"] == "observed" and second["observedPayloadBytesDelta"] == 50
    reset, _ = subject.public_upload_evidence({"items": [{**row, "uploadedBytes": 1}]}, catalog, previous)
    assert reset["bytesVerdict"] == "not-observed"
    local, _ = subject.public_upload_evidence({"items": [{**row, "address": "127.0.0.1"}]}, catalog, {})
    assert local["requests"] == "not-observed"
    with pytest.raises(RuntimeError):
        subject.public_upload_evidence({"items": [{**row, "requestedFileHash": "b" * 32}]}, catalog, previous)


def test_catalog_paginates_and_rejects_foreign_rows():
    value = receipt()
    row = {"hash": "a" * 32, "path": value["destination"] + "/Sample Folder/Sample Audio.bin",
           "sizeBytes": 4, "complete": True, "partFile": False}
    pages = [{"items": [], "total": 1, "nextCursor": "opaque token"},
             {"items": [row], "total": 1, "nextCursor": None}]
    calls = []
    def request(method, path):
        calls.append(path)
        return pages.pop(0)
    result, _ = subject.shared_catalog(SimpleNamespace(request=request), value)
    assert result["status"] == "observed" and "cursor=opaque+token" in calls[1]
    foreign = {"items": [{**row, "path": subject.INCOMING + "/Other.bin"}], "total": 1, "nextCursor": None}
    with pytest.raises(RuntimeError):
        subject.shared_catalog(SimpleNamespace(request=lambda *a: foreign), value)


def test_history_is_bounded_and_retains_only_one_predecessor(tmp_path):
    for i in range(100):
        subject._append_history(tmp_path, {"i": i, "payload": "x" * 2000}, 65536)
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 2 and sum(path.stat().st_size for path in files) <= 65536
    assert json.loads((tmp_path / "observations.jsonl").read_text().splitlines()[-1])["i"] == 99


class FakePhone:
    def __init__(self, state="Stopped"):
        self.phase, self.calls = state, []
        self.device = SimpleNamespace(serial="synthetic:5555", command=self.command)
        self.prefix = ()
        self.ui = self
        self.payload = {"apk": {"sha256": "a" * 64}, "signerSha256": "b" * 64, "versionCode": 1,
                        "buildIdentity": {"sourceRevision": "c" * 40}}
    def command(self, *args, **kwargs): self.calls.append(args)
    def installed(self): self.calls.append("installed")
    def open(self): pass
    def state(self): return self.phase
    def forward(self): pass
    def identity(self): pass
    def cleanup(self): self.calls.append("cleanup")
    def stop(self): self.calls.append("stop"); self.phase = "Stopped"
    def click(self, value): self.calls.append(value); self.phase = "Running"
    def wait_state(self, value): assert self.phase == value
    def script(self, value, **kwargs): self.calls.append("marker")
    def shell(self, *args):
        if args[:2] == ("readlink", "-f"): return args[-1]
        if args[0] == "cat": return "1" * 32
        return ""
    def request(self, *args): return {"total": 0, "items": []}


def installation_evidence(phone):
    return {"schema": "emulebb.android.physical-device/1", "status": "passed", "ownedInstallation": True,
            "freshInstallation": True, "debugBuild": False,
            "deviceSerialSha256": hashlib.sha256(phone.device.serial.encode()).hexdigest(),
            "apkSha256": "a" * 64, "signerSha256": "b" * 64, "versionCode": 1, "sourceRevision": "c" * 40}


def mock_observer(monkeypatch, *, fail=False):
    monkeypatch.setattr(subject, "guest_scope", lambda *a, **kw: None)
    monkeypatch.setattr(subject, "wifi_default", lambda *a: None)
    monkeypatch.setattr(subject, "_settings", lambda *a, **kw: None)
    monkeypatch.setattr(subject, "configure_public_discovery", lambda *a: {"connectionAndPublication": "require-live-observation"})
    monkeypatch.setattr(subject, "publish_staged_tree", lambda *a: None)
    monkeypatch.setattr(subject, "battery_condition", lambda *a, **kw: {"continuousOperationGuarantee": "not-claimed"})
    monkeypatch.setattr(subject, "_guest_free", lambda *a: 1024**4)
    def sample(*args):
        if fail: raise RuntimeError("private-response-must-not-escape")
        return {"privateCatalog": [], "privateUploads": {}, "claims": {"publicPeerServedBytes": "not-observed"}}
    monkeypatch.setattr(subject, "sample", sample)


def test_normal_observer_expiry_leaves_service_running(tmp_path, monkeypatch):
    mock_observer(monkeypatch)
    value = receipt()
    ticks = iter([0, 2])
    monkeypatch.setattr(subject.time, "monotonic", lambda: next(ticks))
    phone = FakePhone()
    session = subject.observe(phone, value, campaign=tmp_path, output_root=tmp_path, start=True)
    assert session["status"] == "observation-complete" and session["service"] == "left-running"
    assert "stop" not in phone.calls and "start_service" in phone.calls
    assert "privateCatalog" not in subject.safe_status(tmp_path, value)["latest"]


def test_resume_failure_stops_owned_service_and_sanitizes_exception(tmp_path, monkeypatch):
    mock_observer(monkeypatch, fail=True)
    phone = FakePhone("Running")
    session = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert session["status"] == "failed" and session["service"] == "stopped-after-failure"
    assert "stop" in phone.calls and "private-response" not in (tmp_path / "session.json").read_text()


def test_resume_never_restarts_stopped_service(tmp_path, monkeypatch):
    mock_observer(monkeypatch)
    phone = FakePhone()
    session = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert session["status"] == "failed" and "start_service" not in phone.calls


def test_explicit_stop_request_stops_normal_ui_service(tmp_path, monkeypatch):
    mock_observer(monkeypatch)
    value = receipt()
    phone = FakePhone("Running")
    session = subject.stop_campaign(phone, value, campaign=tmp_path, output_root=tmp_path)
    assert session["service"] == "stopped" and "stop" in phone.calls
    assert json.loads((tmp_path / "stop-request.json").read_text())["nonce"] == value["nonce"]


def test_prepare_configures_empty_service_before_copy_and_rechecks_source(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Sample.bin").write_bytes(b"data")
    campaign = tmp_path / "campaign"
    phone = FakePhone()
    mock_observer(monkeypatch)
    monkeypatch.setattr(subject, "_guest_entries", lambda phone, root: {root})
    def settings(*args, **kwargs): phone.calls.append("cap-configured")
    monkeypatch.setattr(subject, "_settings", settings)
    digest = subject.prepare(phone, campaign=campaign, output_root=tmp_path, source=source, expected_file_count=1,
                             expected_total_bytes=4, installation=installation_evidence(phone), admission={}, limits=subject.Limits(), route="direct-wifi")
    push = next(call for call in phone.calls if isinstance(call, tuple) and call[0] == "push")
    assert phone.calls.index("cap-configured") < phone.calls.index("stop") < phone.calls.index(push)
    value = subject.admit_campaign(campaign, digest, phone.device.serial)
    assert value["sourceUnchanged"] and value["guestSha256Verified"] and (source / "Sample.bin").read_bytes() == b"data"


@pytest.mark.parametrize("retarget", [False, True])
def test_prepare_resolves_operator_junction_anchor_once_and_detects_retarget(
        tmp_path, monkeypatch, directory_alias, retarget):
    alias, actual = directory_alias
    source = actual / "library"
    source.mkdir()
    (source / "Sample.bin").write_bytes(b"data")
    selected = alias / "library"
    canonical = source.resolve(strict=True)
    campaign = tmp_path / "campaign"
    phone = FakePhone()
    mock_observer(monkeypatch)
    monkeypatch.setattr(subject, "_guest_entries", lambda phone, root: {root})
    inventories = []
    original_inventory = subject.inventory
    def inventory(path):
        inventories.append(path)
        return original_inventory(path)
    monkeypatch.setattr(subject, "inventory", inventory)
    original_command = phone.command
    def command(*args, **kwargs):
        original_command(*args, **kwargs)
        if args[0] == "push" and retarget:
            replacement = tmp_path / "replacement"
            (replacement / "library").mkdir(parents=True)
            (replacement / "library/Sample.bin").write_bytes(b"data")
            if subject.os.name == "nt":
                alias.rmdir()  # Removes only the junction, preserving its target.
                result = subject.subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(replacement)],
                                                capture_output=True, text=True)
                assert result.returncode == 0
            else:
                alias.unlink()
                alias.symlink_to(replacement, target_is_directory=True)
    phone.device.command = command
    kwargs = dict(phone=phone, campaign=campaign, output_root=tmp_path, source=selected,
                  expected_file_count=1, expected_total_bytes=4, installation=installation_evidence(phone),
                  admission={}, limits=subject.Limits(), route="direct-wifi")
    if retarget:
        with pytest.raises(RuntimeError):
            subject.prepare(**kwargs)
        result = subject._read_json(campaign / "preparation.json")
        assert result["status"] == "failed" and result["stage"] == "source-reverification"
        assert not (campaign / "campaign.json").exists()
    else:
        digest = subject.prepare(**kwargs)
        result = subject.admit_campaign(campaign, digest, phone.device.serial)
        assert result["sourcePath"] == str(canonical) and result["sourceAnchorPath"] == str(selected.absolute())
        assert result["stage"] == "complete" and len(inventories) == 2
    assert inventories and all(path == canonical for path in inventories)
    push = next(call for call in phone.calls if isinstance(call, tuple) and call[0] == "push")
    assert push[1] == str(canonical) + "/."
    assert (canonical / "Sample.bin").read_bytes() == b"data"


def test_prepare_still_rejects_junction_inside_selected_source_tree(tmp_path, monkeypatch, directory_alias):
    alias, actual = directory_alias
    (actual / "Sample.bin").write_bytes(b"data")
    phone = FakePhone()
    mock_observer(monkeypatch)
    with pytest.raises(RuntimeError):
        subject.prepare(phone, campaign=tmp_path / "campaign", output_root=tmp_path, source=tmp_path,
                        expected_file_count=1, expected_total_bytes=4, installation=installation_evidence(phone),
                        admission={}, limits=subject.Limits(), route="direct-wifi")
    assert not phone.calls and alias.samefile(actual)


def test_source_anchor_rejects_replacement_of_canonical_directory(tmp_path):
    source, preserved = tmp_path / "source", tmp_path / "preserved"
    source.mkdir()
    original = source.stat()
    assert source.resolve().is_relative_to(tmp_path.resolve()) and preserved.absolute().is_relative_to(tmp_path.absolute())
    source.rename(preserved)
    source.mkdir()
    with pytest.raises(RuntimeError):
        subject.verify_source_anchor(source, source, (original.st_dev, original.st_ino))
    assert preserved.is_dir()


def test_status_does_not_print_inventory_endpoints_or_source(tmp_path):
    value = receipt()
    value["sourcePath"] = "private operator input"
    status = json.dumps(subject.safe_status(tmp_path, value))
    assert "Sample Audio" not in status and "synthetic" not in status and "private operator" not in status


def test_cli_failure_does_not_print_private_exception(tmp_path, monkeypatch, capsys):
    def fail(): raise RuntimeError("private-operator-path-and-endpoint")
    monkeypatch.setattr(subject, "get_workspace_output_root", fail)
    assert subject.main(["status", "--campaign-dir", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "private-operator" not in output
    assert json.loads(output)["failureStage"] == "output-root"
    assert json.loads(output)["failureReason"] == "unclassified"


@pytest.mark.parametrize("stage,reason", [
    ("output-root", "unclassified"), ("payload-admission", "apk-payload-hash-mismatch"),
    ("installation-receipt", "installation-receipt-bound"), ("adb-owner", "adb-server-unavailable"),
    ("installation-scope", "installation-scope-mismatch"), ("source-resolution", "unclassified"),
    ("source-inventory", "reparse-entry-rejected"), ("campaign-directory", "campaign-outside-output-root"),
    ("campaign-operation", "unclassified"),
])
def test_cli_reports_closed_preflight_stage_and_reason_without_private_text(tmp_path, monkeypatch, capsys, stage, reason):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Sample.bin").write_bytes(b"data")
    phone = FakePhone()
    installation = installation_evidence(phone)
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: tmp_path)
    monkeypatch.setattr(subject, "admit_payload", lambda *a, **kw: phone.payload)
    monkeypatch.setattr(subject, "read_hashed_receipt", lambda *a, **kw: installation)
    monkeypatch.setattr(subject, "AdbDevice", lambda *a, **kw: object())
    monkeypatch.setattr(subject, "Phone", lambda *a, **kw: phone)
    messages = {"output-root": "private-operator-path-and-endpoint", "payload-admission": "APK payload hash differs",
                "installation-receipt": "Phone profile operation requires a bounded receipt and immutable SHA-256",
                "adb-owner": "Physical testing requires the existing local operator ADB server",
                "source-inventory": "Campaign paths cannot contain reparse entries"}
    owners = {"output-root": "get_workspace_output_root", "payload-admission": "admit_payload",
              "installation-receipt": "read_hashed_receipt", "adb-owner": "AdbDevice", "source-inventory": "inventory"}
    if stage in owners:
        def fail(*args, **kwargs): raise RuntimeError(messages[stage])
        monkeypatch.setattr(subject, owners[stage], fail)
    if stage == "installation-scope": installation["freshInstallation"] = False
    if stage == "source-resolution": source = tmp_path / "private-missing-source"
    if stage == "campaign-operation":
        def fail_device(): raise RuntimeError("private-device-operation-detail")
        phone.installed = fail_device
    campaign = tmp_path if stage == "campaign-directory" else tmp_path / "campaign"
    args = ["prepare", "--campaign-dir", str(campaign), "--adb", str(tmp_path / "private-adb"),
            "--serial", "synthetic:5555", "--source-dir", str(source), "--expected-file-count", "1",
            "--expected-total-bytes", "4", "--route", "direct-wifi", "--installation-receipt",
            str(tmp_path / "private-installation.json"), "--installation-receipt-sha256", "a" * 64,
            "--apk-payload", str(tmp_path / "private-apk"), "--apk-manifest-name", "manifest.json",
            "--apk-manifest-sha256", "b" * 64, "--apk-source-sha", "c" * 40,
            "--expected-cert-sha256", "d" * 64]
    assert subject.main(args) == 1
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value["failureStage"] == stage and value["failureReason"] == reason
    assert value["failureStage"] in subject.PREFLIGHT_STAGES
    assert "private-" not in output and "synthetic:5555" not in output and str(tmp_path) not in output


def test_safe_failure_reason_matches_exact_runtime_literals_only():
    assert subject.safe_failure_reason(RuntimeError("APK payload hash differs")) == "apk-payload-hash-mismatch"
    assert subject.safe_failure_reason(RuntimeError("APK payload hash differs: private endpoint")) == "unclassified"
    assert subject.safe_failure_reason(ValueError("APK payload hash differs")) == "unclassified"
    assert subject.safe_failure_reason(RuntimeError({"private": "data"})) == "unclassified"


def test_detached_observer_discards_expired_builder_lock_token(tmp_path, monkeypatch):
    monkeypatch.setenv("EMULEBB_WORKSPACE_LOCK_TOKEN", "delegated-token")
    captured = {}
    def spawn(command, **kwargs):
        captured.update(kwargs)
        subject.write_json(tmp_path / "session.json", {"launchToken": command[-1], "status": "observing"})
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(subject.subprocess, "Popen", spawn)
    subject.spawn_observer(["observe", "--serial", "synthetic:5555"], campaign=tmp_path)
    assert "EMULEBB_WORKSPACE_LOCK_TOKEN" not in captured["env"]
    assert subject.os.environ["EMULEBB_WORKSPACE_LOCK_TOKEN"] == "delegated-token"
    assert captured["stdout"] == subject.subprocess.DEVNULL and captured["stderr"] == subject.subprocess.DEVNULL


@pytest.mark.parametrize("counter,expected", [(None, "evidence-incomplete"), (False, "evidence-incomplete"),
                                             (-1, "evidence-incomplete"), (0, "not-observed"), (1, "observed")])
def test_missing_publication_counter_is_inconclusive(counter, expected):
    assert subject.counter_claim(counter) == expected


def test_public_discovery_uses_existing_approved_seed_owners(monkeypatch):
    calls = []
    server_pages = iter([[], [{"enabled": True}]])
    def request(method, path, body=None):
        calls.append((method, path, body))
        if path == "/servers": return {"items": next(server_pages)}
        if path == "/stats": return {"ed2kConnected": False}
        if path == "/kad": return {"connected": False}
        if path == "/kad/operations/import-nodes-url": return {"imported": True}
        return {}
    value = subject.configure_public_discovery(SimpleNamespace(request=request))
    assert ("POST", "/servers/operations/import-met-url", {"url": subject.DEFAULT_SERVER_MET_URL}) in calls
    assert ("POST", "/kad/operations/import-nodes-url", {"url": subject.DEFAULT_NODES_DAT_URL}) in calls
    assert ("POST", "/servers/operations/connect", {}) in calls
    assert ("POST", "/kad/operations/start", {}) in calls
    assert value["connectionAndPublication"] == "require-live-observation"
    assert not any("transfers" in path or "searches" in path for _, path, _ in calls)


def test_disabled_existing_server_seed_is_preserved():
    calls = []
    def request(method, path, body=None):
        calls.append((method, path))
        return {"items": [{"enabled": False}]}
    with pytest.raises(RuntimeError):
        subject.configure_public_discovery(SimpleNamespace(request=request))
    assert calls == [("GET", "/servers")]


def test_explicit_stop_proceeds_before_recording_scope_drift(tmp_path, monkeypatch):
    value = receipt()
    phone = FakePhone("Running")
    def drift(*args, **kwargs):
        assert phone.phase == "Stopped"
        raise RuntimeError("added-unapproved-file")
    monkeypatch.setattr(subject, "guest_scope", drift)
    result = subject.stop_campaign(phone, value, campaign=tmp_path, output_root=tmp_path)
    assert result["service"] == "stopped" and result["scopeAfterStop"] == "drift-observed"


def test_publication_collision_keeps_existing_target_and_aborts(monkeypatch):
    value = receipt()
    stage = value["staging"]
    files = {stage + "/Sample Folder/Sample Audio.bin"}
    dirs = {stage, stage + "/Sample Folder"}
    monkeypatch.setattr(subject, "_guest_entries", lambda phone, root, kind=None:
                        dirs if kind == "d" else files if kind == "f" else dirs | files)
    monkeypatch.setattr(subject, "guest_sha256", lambda *a, **kw: value["inventory"]["files"][0]["sha256"])
    occupant = bytearray(b"preserve existing target")
    calls = []
    def publish(script, **kwargs):
        calls.append(script)
        assert "set -C; cat " in script
        raise FileExistsError("Synthetic atomic O_EXCL collision")
    phone = SimpleNamespace(shell=lambda *args: stage if args[0] == "readlink" else "", script=publish,
                            device=SimpleNamespace(command=lambda *a, **kw: None), prefix=())
    with pytest.raises(FileExistsError):
        subject.publish_staged_tree(phone, value)
    assert occupant == b"preserve existing target" and len(calls) == 1


def test_resume_wrong_nonce_never_grants_cleanup_stop_authority(tmp_path, monkeypatch):
    mock_observer(monkeypatch)
    phone = FakePhone("Running")
    phone.shell = lambda *args: "foreign-nonce"
    result = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert result["status"] == "failed" and result["service"] == "unconfirmed"
    assert "stop" not in phone.calls and "start_service" not in phone.calls


def test_os_lease_metadata_remains_on_same_file_after_release(tmp_path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    with subject.device_lease(tmp_path, "a" * 64, campaign):
        path = tmp_path / "tmp/android-public-sharing" / ("a" * 64 + ".lock")
        before = path.stat().st_ino
    assert path.stat().st_ino == before and subject._read_json(path)["active"] is False
    with subject.device_lease(tmp_path, "a" * 64, campaign):
        assert path.stat().st_ino == before


def test_content_catalog_collapses_duplicate_instances_without_claiming_all_paths_indexed():
    value = receipt()
    original = value["inventory"]["files"][0]
    duplicate = {**original, "path": "Other Folder/Sample Audio Copy.bin"}
    distinct = {**original, "path": "Other Folder/Sample Text.bin", "sha256": hashlib.sha256(b"more").hexdigest()}
    value["inventory"]["files"] = [original, duplicate, distinct]
    value["fileCount"] = 3
    rows = [{"hash": file_hash, "path": value["destination"] + "/" + item["path"], "sizeBytes": item["sizeBytes"],
             "complete": True, "partFile": False} for file_hash, item in (("a" * 32, duplicate), ("b" * 32, distinct))]
    phone = SimpleNamespace(request=lambda *a: {"items": rows, "total": 2, "nextCursor": None})
    result, _ = subject.shared_catalog(phone, value)
    assert result["status"] == "observed" and result["approvedFileInstances"] == 3
    assert result["expectedDistinctContents"] == result["matchedDistinctContents"] == 2
    assert result["catalogRepresentativePaths"] == 2 and result["duplicateFileInstances"] == 1
    assert result["allFileInstancesIndexed"] == "evidence-incomplete"
    # Two incompatible content IDs for byte-identical approved copies are not
    # proof of complete distinct-content coverage.
    rows.append({**rows[0], "hash": "c" * 32, "path": value["destination"] + "/" + original["path"]})
    ambiguous = SimpleNamespace(request=lambda *a: {"items": rows, "total": 3, "nextCursor": None})
    assert subject.shared_catalog(ambiguous, value)[0]["status"] == "evidence-incomplete"


def test_content_catalog_reads_realistic_cursor_after_first_200_of_221_rows():
    value = receipt()
    value["fileCount"] = 221
    value["inventory"]["files"] = [{"path": f"Sample Folder/Sample-{index:03d}.bin", "sizeBytes": index + 1,
                                     "sha256": hashlib.sha256(f"sample-{index}".encode()).hexdigest()}
                                    for index in range(221)]
    rows = [{"path": value["destination"] + "/" + item["path"], "sizeBytes": item["sizeBytes"],
             "hash": f"{index + 1:032x}", "complete": True, "partFile": False}
            for index, item in enumerate(value["inventory"]["files"])]
    cursor = json.dumps({"sortPath": rows[199]["path"], "hash": rows[199]["hash"]}, separators=(",", ":"))
    calls = []
    def request(method, path):
        query = parse_qs(urlsplit(path).query)
        calls.append(query)
        assert query["limit"] == ["200"]
        if len(calls) == 1:
            assert "cursor" not in query
            return {"items": rows[:200], "total": 221, "nextCursor": cursor}
        assert query["cursor"] == [cursor]
        return {"items": rows[200:], "total": 221, "nextCursor": None}
    result, actual = subject.shared_catalog(SimpleNamespace(request=request), value)
    assert result["status"] == "observed" and result["matchedDistinctContents"] == 221
    assert len(actual) == 221 and len(calls) == 2


def battery_label(*, exempt=False, restricted=False):
    return {"package": subject.APPLICATION_ID, "text": "Files: allowed; local network: allowed; notifications: allowed; "
            + "battery exemption: " + ("allowed" if exempt else "disabled") + "; background restriction: "
            + ("enabled" if restricted else "disabled")}


@pytest.mark.parametrize("exempt,restricted", [(False, False), (True, True), (True, False)])
def test_own_app_battery_facts_record_actual_continuous_operation_constraints(exempt, restricted):
    phone = SimpleNamespace(ui=SimpleNamespace(elements=lambda: [battery_label(exempt=exempt, restricted=restricted)]))
    result = subject.battery_condition(phone)
    assert result["batteryOptimizationExempt"] is exempt and result["backgroundRestricted"] is restricted
    assert (result["continuousOperationPrerequisites"] == "observed") == (exempt and not restricted)
    assert result["continuousOperationGuarantee"] == "not-claimed"


def test_ambiguous_or_foreign_battery_label_never_proves_platform_state():
    for nodes in ([battery_label(), battery_label(exempt=True)], [{**battery_label(exempt=True), "package": "foreign.app"}], []):
        assert subject.native_battery_facts(nodes) == {"batteryOptimizationExempt": None, "backgroundRestricted": None}


@pytest.mark.parametrize("ambiguous", [False, True])
def test_battery_grant_uses_only_own_native_button_and_unambiguous_settings_dialog(monkeypatch, ambiguous):
    state = {"dialog": False, "exempt": False}
    calls = []
    def elements():
        if not state["dialog"]:
            return [battery_label(exempt=state["exempt"])]
        button = {"package": "com.android.settings", "resource-id": "android:id/button1", "enabled": "true",
                  "clickable": "true", "bounds": "[600,900][900,1000]"}
        return [{"package": "com.android.settings", "text": "Allow eMuleBB to always run in background?"},
                button, *([button] if ambiguous else [])]
    def click(name):
        assert name == "allow_continuous_background"
        calls.append(name)
        state["dialog"] = True
    def shell(*args):
        calls.append(args)
        if args[:2] == ("dumpsys", "activity"):
            return "mResumedActivity: com.android.settings/.RequestIgnoreBatteryOptimizations"
        if args == ("wm", "size"): return "Physical size: 1080x1920"
        if args[:2] == ("input", "tap"): state["exempt"] = True
        return ""
    def open_main(): state["dialog"] = False
    monkeypatch.setattr(subject.time, "sleep", lambda *a: None)
    phone = SimpleNamespace(ui=SimpleNamespace(elements=elements, click=click), shell=shell, open=open_main)
    result = subject.battery_condition(phone, request_exemption=True)
    assert result["batteryOptimizationExempt"] is (not ambiguous)
    assert any(isinstance(call, tuple) and call[:2] == ("input", "tap") for call in calls) is (not ambiguous)
    assert not any(isinstance(call, tuple) and call[:2] in {("dumpsys", "battery"), ("dumpsys", "deviceidle")} for call in calls)
    assert result["continuousOperationGuarantee"] == "not-claimed"
