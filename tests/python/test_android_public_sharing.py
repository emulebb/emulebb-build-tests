"""Public campaign boundaries: private copy, ownership, scope and truthful evidence."""
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path
import shlex
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


@pytest.mark.parametrize("raw,expected", [(b"", set()), (b"/owned/Sample.bin\0", {"/owned/Sample.bin"})])
def test_guest_entries_accepts_successful_empty_type_filter(raw, expected):
    calls = []
    def shell(*args, **kwargs):
        calls.append((args, kwargs))
        return raw
    assert subject._guest_entries(SimpleNamespace(shell=shell), "/owned", "f") == expected
    assert calls == [(("find", "/owned", "-type", "f", "-print0"), {"binary": True})]


def test_guest_entries_still_rejects_nonempty_unterminated_output():
    with pytest.raises(RuntimeError):
        subject._guest_entries(SimpleNamespace(shell=lambda *a, **kw: b"/owned/Sample.bin"), "/owned", "f")


def test_public_request_is_distinct_from_increasing_payload_and_local_peer():
    catalog = [{"hash": "a" * 32}]
    row = {"id": "peer", "address": "93.184.216.34", "requestedFileHash": "a" * 32, "uploadedBytes": 100}
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


def catalog_phone(rows, locations):
    def request(method, path):
        assert method == "GET"
        if urlsplit(path).path == "/library/files":
            return {"data": rows, "meta": {"total": len(rows), "hasMore": False, "nextCursor": None}}
        file_hash = urlsplit(path).path.split("/")[3]
        return {"data": locations[file_hash], "meta": {"hasMore": False, "nextCursor": None}}
    return SimpleNamespace(request=request)


def test_catalog_reads_separate_locations_and_rejects_foreign_rows():
    value = receipt()
    row = {"hash": "a" * 32, "displayName": "Sample Audio.bin", "sizeBytes": 4}
    path = value["destination"] + "/Sample Folder/Sample Audio.bin"
    phone = catalog_phone([row], {row["hash"]: [{"path": path, "present": True}]})
    result, rows = subject.shared_catalog(phone, value)
    assert result["status"] == result["allFileInstancesIndexed"] == "observed"
    assert result["catalogFileLocations"] == 1 and rows == [row]
    foreign = catalog_phone([row], {row["hash"]: [{"path": subject.INCOMING + "/Other.bin", "present": True}]})
    with pytest.raises(RuntimeError):
        subject.shared_catalog(foreign, value)


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
    def request(self, *args, **kwargs):
        return {"data": [], "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}


def installation_evidence(phone):
    return {"schema": "emulebb.android.physical-device/1", "status": "passed", "ownedInstallation": True,
            "freshInstallation": True, "debugBuild": False,
            "deviceSerialSha256": hashlib.sha256(phone.device.serial.encode()).hexdigest(),
            "apkSha256": "a" * 64, "signerSha256": "b" * 64, "versionCode": 1, "sourceRevision": "c" * 40}


def mock_observer(monkeypatch, *, fail=False):
    monkeypatch.setattr(subject, "guest_scope", lambda *a, **kw: None)
    monkeypatch.setattr(subject, "wifi_default", lambda *a: None)
    monkeypatch.setattr(subject, "_settings", lambda *a, **kw: {"application": {"pendingRestart": []}})
    monkeypatch.setattr(subject, "configure_public_discovery", lambda *a, **kw: {"connectionAndPublication": "require-live-observation"})
    monkeypatch.setattr(subject, "publish_staged_tree", lambda *a: None)
    monkeypatch.setattr(subject, "battery_condition", lambda *a, **kw: {"continuousOperationGuarantee": "not-claimed"})
    monkeypatch.setattr(subject, "_guest_free", lambda *a: 1024**4)
    def sample(*args, **kwargs):
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
    assert session["failurePhase"] == "sample" and session["failureReason"] == "unclassified"


@pytest.mark.parametrize("message,reason", [
    ("Runtime upload cap differs from the admitted bound", "upload-cap-mismatch"),
    ("Runtime upload cap differs from the admitted bound: private-path", "unclassified"),
    ("synthetic-private-endpoint-and-key", "unclassified"),
])
def test_observer_preserves_primary_closed_failure_through_stop_and_cleanup_errors(
        tmp_path, monkeypatch, message, reason):
    mock_observer(monkeypatch)
    phone = FakePhone("Running")
    def sample(*args, phase):
        phase("sample-runtime-summary")
        raise RuntimeError(message)
    stop_error = subject.AdbOperationFailure(("shell", "input", "tap", "private-coordinate"),
        exit_code=1, stderr="permission denied: synthetic-private-device")
    cleanup_error = subject.RustRestFailure("synthetic-private-response", status=400,
        detail=json.dumps({"error": {"code": "INVALID_ARGUMENT",
            "message": "failed to bind eD2k TCP listener: synthetic-private-address"}}))
    def stop():
        phone.failed_rest_operation = "settings-update"
        raise stop_error
    def cleanup():
        raise cleanup_error
    monkeypatch.setattr(subject, "sample", sample)
    phone.stop, phone.cleanup = stop, cleanup
    result = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert result["errorType"] == "RuntimeError" and result["failurePhase"] == "sample-runtime-summary"
    assert result["failureReason"] == reason and result["service"] == "stop-unconfirmed"
    assert "failedRestOperation" not in result and "failedAdbSafeFailure" not in result
    assert result["stopFailure"]["failurePhase"] == "failure-stop"
    assert result["stopFailure"]["failedAdbSafeFailure"] == stop_error.safe_failure
    assert "failedRestOperation" not in result["stopFailure"]
    assert result["cleanupFailure"]["failurePhase"] == "control-cleanup"
    assert result["cleanupFailure"]["failedRestSafeFailure"] == cleanup_error.safe_failure
    raw = (tmp_path / "session.json").read_text()
    assert "private-" not in raw and "synthetic-private" not in raw


def test_cleanup_only_failure_has_its_own_phase_and_preserves_expiry_service_disposition(tmp_path, monkeypatch):
    mock_observer(monkeypatch)
    phone = FakePhone("Running")
    ticks = iter([0, 2])
    monkeypatch.setattr(subject.time, "monotonic", lambda: next(ticks))
    def cleanup():
        raise RuntimeError("synthetic-private-cleanup-path")
    phone.cleanup = cleanup
    result = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert result["status"] == "failed" and result["service"] == "left-running"
    assert result["errorType"] == "RuntimeError" and result["failurePhase"] == "control-cleanup"
    assert result["failureReason"] == "unclassified" and "stop" not in phone.calls
    assert "synthetic-private" not in (tmp_path / "session.json").read_text()


def test_actual_sampler_queue_guard_retains_its_phase_and_exact_safe_reason(tmp_path, monkeypatch):
    actual_sample = subject.sample
    mock_observer(monkeypatch)
    monkeypatch.setattr(subject, "sample", actual_sample)
    phone = FakePhone("Running")
    calls = []
    def request(method, path):
        calls.append((method, path))
        return {"data": [{"name": "private-foreign-download"}],
                "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}
    phone.request = request
    result = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert result["failurePhase"] == "sample-download-queue"
    assert result["failureReason"] == "download-queue-not-empty" and result["service"] == "stopped-after-failure"
    assert calls == [("GET", "/downloads?view=unfinished&limit=1")]
    assert "private-foreign" not in (tmp_path / "session.json").read_text()


@pytest.mark.parametrize("phase,operation", [("private-phase", "private-route"), ([], {})])
def test_observer_projection_suppresses_unknown_phase_operation_and_exception_text(phase, operation):
    assert subject._observer_failure(RuntimeError("private-response"), phase, operation) == {
        "errorType": "RuntimeError", "failurePhase": "unclassified", "failureReason": "unclassified"}


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


@pytest.mark.parametrize("restart_pending", [False, True])
def test_prepare_configures_empty_service_before_copy_and_rechecks_source(tmp_path, monkeypatch, restart_pending):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Sample.bin").write_bytes(b"data")
    campaign = tmp_path / "campaign"
    phone = FakePhone()
    mock_observer(monkeypatch)
    monkeypatch.setattr(subject, "_guest_entries", lambda phone, root: {root})
    def settings(*args, **kwargs):
        phone.calls.append("cap-configured")
        return {"application": {"pendingRestart": ["network.kadEnabled"] if restart_pending else []}}
    monkeypatch.setattr(subject, "_settings", settings)
    discovery = []
    monkeypatch.setattr(subject, "configure_public_discovery", lambda phone, *, start_networks:
                        discovery.append(start_networks) or {"connectionAndPublication": "require-live-observation"})
    digest = subject.prepare(phone, campaign=campaign, output_root=tmp_path, source=source, expected_file_count=1,
                             expected_total_bytes=4, installation=installation_evidence(phone), admission={}, limits=subject.Limits(), route="direct-wifi")
    push = next(call for call in phone.calls if isinstance(call, tuple) and call[0] == "push")
    assert phone.calls.index("cap-configured") < phone.calls.index("stop") < phone.calls.index(push)
    assert discovery == [not restart_pending] and phone.calls.count("start_service") == 1
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


@pytest.mark.parametrize("method,path,timeout", [
    ("POST", "/servers/operations/import-met-url", 60.0),
    ("POST", "/kad/operations/import-nodes-url", 60.0),
    ("POST", "/servers/operations/connect", 60.0),
    ("PATCH", "/settings", 60.0),
    ("GET", "/settings", 10.0), ("GET", "/stats", 10.0), ("GET", "/nat", 10.0),
    ("GET", "/library/files?limit=200&cursor=opaque", 10.0),
])
def test_phone_request_uses_canonical_http_owner_with_bounded_operation_deadline(monkeypatch, method, path, timeout):
    phone = subject.Phone(SimpleNamespace(serial="synthetic:5555", command=lambda *a: None), {})
    phone.port, phone.key = 12345, "fixture-key"
    calls = []
    def request(*args, **kwargs):
        calls.append((args, kwargs))
        return {"ok": True}
    monkeypatch.setattr(subject, "request_json", request)
    assert phone.request(method, path, {"value": 1}) == {"ok": True}
    assert calls == [(("http://127.0.0.1:12345", method, "/api/v1" + path, "fixture-key", {"value": 1}),
                      {"timeout_seconds": timeout})]
    assert phone.failed_rest_operation is None


@pytest.mark.parametrize("fail", [False, True])
def test_phone_settings_request_keeps_revision_and_bounded_failure_owner(monkeypatch, fail):
    phone = subject.Phone(SimpleNamespace(serial="synthetic:5555", command=lambda *a: None), {})
    phone.port, phone.key = 12345, "fixture-key"
    calls = []
    document = {"data": {}, "meta": {"settingsRevision": "9007199254740993"}}
    def request(*args, **kwargs):
        calls.append((args, kwargs))
        if fail:
            raise TimeoutError("private-response")
        return document
    monkeypatch.setattr(subject, "http_json", request)
    if fail:
        with pytest.raises(TimeoutError):
            phone.request("GET", "/settings", include_meta=True)
        assert phone.failed_rest_operation == "settings-read"
    else:
        assert phone.request("GET", "/settings", include_meta=True) == document
    assert calls == [(("http://127.0.0.1:12345", "/api/v1/settings"), {
        "api_key": "fixture-key", "method": "GET", "body": None, "timeout_seconds": 10.0})]


@pytest.mark.parametrize("configure,fault", [
    (False, None), (True, None), (True, "conflict"), (True, "saved-rate"), (True, "apply-failed"),
    (False, "pending"), (False, "effective-rate"), (False, "binding"), (False, "root"),
])
def test_campaign_settings_require_saved_preparation_and_effective_observation(configure, fault):
    from copy import deepcopy
    limits = subject.Limits()
    effective = {"storage": {"incomingDirectory": subject.INCOMING},
                 "security": {"vpnGuard": {"mode": "off"}},
                 "network": {"p2p": {"bindInterface": "tun0" if fault == "binding" else None, "bindIp": None},
                             "autoConnect": not configure, "ed2kEnabled": not configure,
                             "kadEnabled": not configure, "nat": {"enabled": not configure}},
                 "transfers": {"uploadLimitBytesPerSecond": limits.upload_limit_kibps * 1024
                               * (2 if configure or fault == "effective-rate" else 1)}}
    def saved(values):
        return {key: saved(value) if isinstance(value, dict) else {"mode": "custom", "value": value}
                for key, value in values.items()}
    snapshot = {"data": {"effective": effective, "saved": saved(effective), "application": {
        "pendingRestart": ["network.nat.enabled"] if fault == "pending" else [], "failed": []}},
        "meta": {"apiVersion": "v1", "settingsRevision": "9007199254740993"}}
    calls = []
    def request(method, path, body=None, *, include_meta=False):
        calls.append((method, path, body))
        if path.startswith("/library/roots"):
            roots = [{"id": "1", "path": subject.SHARED, "managed": False},
                     {"id": "2", "path": subject.INCOMING, "managed": True}]
            if fault == "root":
                roots.append({"id": "3", "path": "/other", "managed": False})
            return {"data": roots, "meta": {"hasMore": False, "nextCursor": None}}
        assert path == "/settings" and include_meta is True
        if method == "PATCH":
            assert body == {"expectedRevision": "9007199254740993", "set": {
                "transfers": {"uploadLimitBytesPerSecond": limits.upload_limit_kibps * 1024},
                "network": {"autoConnect": True, "ed2kEnabled": True, "kadEnabled": True, "nat": {"enabled": True}}}}
            if fault == "conflict":
                raise RuntimeError("SETTINGS_CONFLICT")
            result = deepcopy(snapshot)
            selected = body["set"]
            if fault == "saved-rate":
                selected = deepcopy(selected)
                selected["transfers"]["uploadLimitBytesPerSecond"] = 1
            result["data"]["saved"]["network"].update(saved(selected["network"]))
            result["data"]["saved"]["transfers"] = saved(selected["transfers"])
            result["data"]["application"] = {"pendingRestart": ["network.kadEnabled"],
                "failed": [{"key": "network.kadEnabled"}] if fault == "apply-failed" else []}
            result["meta"]["settingsRevision"] = "9007199254740994"
            return result
        return deepcopy(snapshot)
    phone = SimpleNamespace(request=request)
    if fault:
        with pytest.raises(RuntimeError, match="Campaign|SETTINGS_CONFLICT"):
            subject._settings(phone, limits, configure=configure)
    else:
        result = subject._settings(phone, limits, configure=configure)
        assert bool(result["application"]["pendingRestart"]) is configure
    assert len([call for call in calls if call[0] == "PATCH"]) == int(configure)


def test_phone_request_records_only_closed_failed_operation(monkeypatch):
    phone = subject.Phone(SimpleNamespace(serial="synthetic:5555", command=lambda *a: None), {})
    phone.port, phone.key = 12345, "fixture-key"
    def fail(*args, **kwargs): raise TimeoutError("private-response-and-path")
    monkeypatch.setattr(subject, "request_json", fail)
    with pytest.raises(TimeoutError): phone.request("PATCH", "/settings", {"private": "payload"})
    assert phone.failed_rest_operation == "settings-update"
    with pytest.raises(TimeoutError): phone.request("POST", "/private-unknown-route", {})
    assert phone.failed_rest_operation == "unclassified-rest-operation"


def test_prepare_timeout_persists_closed_failed_rest_operation(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Sample.bin").write_bytes(b"data")
    campaign = tmp_path / "campaign"
    phone = FakePhone()
    mock_observer(monkeypatch)
    monkeypatch.setattr(subject, "_guest_entries", lambda phone, root: {root})
    def settings(*args, **kwargs):
        phone.failed_rest_operation = "settings-update"
        raise TimeoutError("private-settings-response")
    monkeypatch.setattr(subject, "_settings", settings)
    with pytest.raises(RuntimeError):
        subject.prepare(phone, campaign=campaign, output_root=tmp_path, source=source, expected_file_count=1,
                        expected_total_bytes=4, installation=installation_evidence(phone), admission={},
                        limits=subject.Limits(), route="direct-wifi")
    value = subject._read_json(campaign / "preparation.json")
    assert value["failedRestOperation"] == "settings-update" and value["errorType"] == "TimeoutError"
    assert "private-settings" not in (campaign / "preparation.json").read_text()


def test_observer_timeout_persists_closed_failed_rest_operation(tmp_path, monkeypatch):
    mock_observer(monkeypatch)
    phone = FakePhone("Running")
    def settings(*args, **kwargs):
        phone.failed_rest_operation = "settings-read"
        raise TimeoutError("private-settings-response")
    monkeypatch.setattr(subject, "_settings", settings)
    value = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
    assert value["failedRestOperation"] == "settings-read" and value["service"] == "stopped-after-failure"
    assert "private-settings" not in (tmp_path / "session.json").read_text()


@pytest.mark.parametrize("status", [400, 599, 99, 600, True, "400"])
@pytest.mark.parametrize("mode", ["prepare", "observe"])
def test_private_failure_receipt_reuses_only_closed_rest_projection(tmp_path, monkeypatch, status, mode):
    mock_observer(monkeypatch)
    phone = FakePhone("Stopped" if mode == "prepare" else "Running")
    def fail_settings(*args, **kwargs):
        phone.failed_rest_operation = "settings-update"
        raise subject.RustRestFailure("private-response-text", status=status,
            detail=json.dumps({"error": {"code": "INVALID_ARGUMENT", "message": "failed to bind eD2k TCP listener: private-response-text"}}))
    monkeypatch.setattr(subject, "_settings", fail_settings)
    if mode == "prepare":
        source = tmp_path / "source"
        source.mkdir()
        (source / "Sample.bin").write_bytes(b"data")
        monkeypatch.setattr(subject, "_guest_entries", lambda phone, root: {root})
        campaign = tmp_path / "campaign"
        with pytest.raises(RuntimeError):
            subject.prepare(phone, campaign=campaign, output_root=tmp_path, source=source, expected_file_count=1,
                            expected_total_bytes=4, installation=installation_evidence(phone), admission={},
                            limits=subject.Limits(), route="direct-wifi")
        path = campaign / "preparation.json"
        value = subject._read_json(path)
    else:
        value = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
        path = tmp_path / "session.json"
    assert value["failedRestOperation"] == "settings-update"
    if type(status) is int and 100 <= status <= 599:
        assert value["failedRestSafeFailure"] == {"httpStatus": status, "apiCode": "INVALID_ARGUMENT", "coreContext": "ed2k-listener-bind"}
    else:
        assert "failedRestSafeFailure" not in value
    assert "private-response" not in path.read_text() and "PRIVATE" not in path.read_text()


@pytest.mark.parametrize("mode", ["prepare", "observe"])
def test_private_failure_receipt_reuses_closed_adb_projection(tmp_path, monkeypatch, mode):
    mock_observer(monkeypatch)
    phone = FakePhone("Stopped" if mode == "prepare" else "Running")
    def fail_settings(*args, **kwargs):
        raise subject.AdbOperationFailure(("shell", "sha256sum", "private-device-secret"),
            error=subject.subprocess.TimeoutExpired(["private-endpoint"], 10), stderr="private-stderr")
    monkeypatch.setattr(subject, "_settings", fail_settings)
    if mode == "prepare":
        source = tmp_path / "source"
        source.mkdir()
        (source / "Sample.bin").write_bytes(b"data")
        campaign = tmp_path / "campaign"
        monkeypatch.setattr(subject, "_guest_entries", lambda phone, root: {root})
        with pytest.raises(RuntimeError):
            subject.prepare(phone, campaign=campaign, output_root=tmp_path, source=source, expected_file_count=1,
                            expected_total_bytes=4, installation=installation_evidence(phone), admission={},
                            limits=subject.Limits(), route="direct-wifi")
        path = campaign / "preparation.json"
        value = subject._read_json(path)
    else:
        value = subject.observe(phone, receipt(), campaign=tmp_path, output_root=tmp_path)
        path = tmp_path / "session.json"
    assert value["failedAdbSafeFailure"] == {"operation": "shell-sha256", "reason": "command-timeout", "exitCode": None}
    assert "private-device-secret" not in path.read_text() and "private-stderr" not in path.read_text()


@pytest.mark.parametrize("fault", [None, "digest", "device", "status", "stage"])
def test_failed_preparation_inspection_requires_hash_bound_copy_scope(tmp_path, fault):
    value = {**receipt(), "status": "failed", "stage": "staged-publication"}
    if fault == "status": value["status"] = "prepared"
    if fault == "stage": value["stage"] = "device-admission"
    subject.write_json(tmp_path / "preparation.json", value)
    digest = hashlib.sha256((tmp_path / "preparation.json").read_bytes()).hexdigest()
    if fault:
        with pytest.raises(RuntimeError):
            subject.admit_campaign(tmp_path, "0" * 64 if fault == "digest" else digest,
                                   "foreign:5555" if fault == "device" else "synthetic:5555", failed_preparation=True)
    else:
        assert subject.admit_campaign(tmp_path, digest, "synthetic:5555", failed_preparation=True) == value
        subject.write_json(tmp_path / "campaign.json", value)
        with pytest.raises(RuntimeError): subject.admit_campaign(tmp_path, digest, "synthetic:5555")


@pytest.mark.parametrize("failure", [None, "checksum", "marker"])
def test_failed_preparation_inspection_is_read_only_and_preserves_partial_payloads(tmp_path, monkeypatch, failure):
    value = {**receipt(), "status": "failed", "stage": "staged-publication"}
    subject.write_json(tmp_path / "preparation.json", value)
    digest = hashlib.sha256((tmp_path / "preparation.json").read_bytes()).hexdigest()
    phone = FakePhone()
    for name in ("open", "forward", "stop", "cleanup", "script"):
        setattr(phone, name, lambda *a, **kw: pytest.fail("inspection attempted a guest mutation"))
    if failure == "marker": phone.shell = lambda *args: "wrong-nonce" if args[0] == "cat" else args[-1]
    monkeypatch.setattr(subject, "_stopped_service_flags", lambda ui: {"foreground": False, "startRequested": False})
    stage, destination = value["staging"], value["destination"]
    def entries(phone, root, kind=None):
        dirs = {root, root + "/Sample Folder"} if root == stage else {root}
        files = {root + "/Sample Folder/Sample Audio.bin"} if root == stage else set()
        return files if kind == "f" else dirs if kind == "d" else dirs | files
    monkeypatch.setattr(subject, "_guest_entries", entries)
    def checksum(*args, **kwargs):
        if failure == "checksum":
            raise subject.AdbOperationFailure(("shell", "sha256sum", "private-device-secret"),
                error=subject.subprocess.TimeoutExpired(["private-endpoint"], 10), stderr="private-stderr")
        return value["inventory"]["files"][0]["sha256"]
    monkeypatch.setattr(subject, "guest_sha256", checksum)
    result = subject.inspect_failed_preparation(phone, value, campaign=tmp_path, output_root=tmp_path, digest=digest)
    assert result["guestMutations"] == 0
    assert hashlib.sha256((tmp_path / "preparation.json").read_bytes()).hexdigest() == digest
    assert "Sample Audio" not in json.dumps(result) and "private-" not in json.dumps(result)
    assert value["nonce"] not in json.dumps(result)
    if failure == "checksum":
        assert result["status"] == "failed" and result["step"] == "staging-checksums"
        assert result["failedAdbSafeFailure"]["operation"] == "shell-sha256"
    elif failure == "marker":
        assert result["status"] == "failed" and result["step"] == "nonce-marker"
        assert "staging" not in result
    else:
        assert result["status"] == "inspected" and result["step"] == "complete"
        assert result["staging"]["sha256VerifiedFiles"] == 1
        assert result["destination"]["missingApprovedFiles"] == 1
    assert len(list(tmp_path.glob("inspection-*.json"))) == 1


@pytest.mark.parametrize("action", ["inspect-failed-prepare", "resume-failed-prepare"])
def test_failed_copy_cli_admits_selected_apk_and_never_launches_observer(tmp_path, monkeypatch, capsys, action):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    value = {**receipt(), "status": "failed", "stage": "staged-publication",
             "admission": {"root": str(tmp_path / "payload"), "manifest_name": "manifest.json",
                           "manifest_sha256": "a" * 64, "source_sha": "b" * 40, "expected_cert_sha256": "c" * 64}}
    subject.write_json(campaign / "preparation.json", value)
    digest = hashlib.sha256((campaign / "preparation.json").read_bytes()).hexdigest()
    calls = []
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: tmp_path)
    def admit(root, **kwargs):
        calls.append((root, kwargs))
        return FakePhone().payload
    monkeypatch.setattr(subject, "admit_payload", admit)
    monkeypatch.setattr(subject, "AdbDevice", lambda *a, **kw: object())
    monkeypatch.setattr(subject, "Phone", lambda *a, **kw: FakePhone())
    monkeypatch.setattr(subject, "observe", lambda *a, **kw: pytest.fail("inspection launched an observer"))
    def inspect(phone, admitted, **kwargs):
        assert admitted == value and kwargs["digest"] == digest
        return {"status": "inspected" if action == "inspect-failed-prepare" else "prepared", "mode": action, "guestMutations": 0}
    monkeypatch.setattr(subject, "inspect_failed_preparation" if action == "inspect-failed-prepare" else "resume_failed_preparation", inspect)
    assert subject.main([action, "--campaign-dir", str(campaign),
                         "--campaign-receipt-sha256", digest, "--adb", str(tmp_path / "adb"), "--serial", "synthetic:5555"]) == 0
    assert calls[0][1]["expected_cert_sha256"] == "c" * 64 and calls[0][1]["source_sha"] == "b" * 40
    output = capsys.readouterr().out
    assert "synthetic:5555" not in output and "Sample Audio" not in output
    assert json.loads(output)["guestMutations"] == 0


def resume_case(tmp_path, monkeypatch, *, existing=0):
    """Use real source snapshots and a guest FS model with exclusive creates."""
    source = tmp_path / "source"
    (source / "Sample Folder").mkdir(parents=True)
    (source / "Sample Folder/First Audio.bin").write_bytes(b"data")
    (source / "Sample Folder/Second Audio.bin").write_bytes(b"more")
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    value = {**receipt(), "status": "failed", "stage": "staged-publication", "errorType": "AdbOperationFailure",
             "sourcePath": str(source.resolve()), "sourceAnchorPath": str(source), "inventory": subject.inventory(source),
             "fileCount": 2, "totalBytes": 8}
    value["inventorySha256"] = subject._digest(value["inventory"])
    subject.write_json(campaign / "preparation.json", value)
    digest = hashlib.sha256((campaign / "preparation.json").read_bytes()).hexdigest()
    stage, destination = value["staging"], value["destination"]
    phone = FakePhone()
    phone.writes, phone.nonregular = [], set()
    phone.dirs = {subject.INCOMING, subject.SHARED, stage, stage + "/Sample Folder", destination}
    phone.files = {stage + "/" + row["path"]: (source / row["path"]).read_bytes() for row in value["inventory"]["files"]}
    if existing:
        phone.dirs.add(destination + "/Sample Folder")
        for row in value["inventory"]["files"][:existing]:
            phone.files[destination + "/" + row["path"]] = phone.files[stage + "/" + row["path"]]
    for name in ("open", "forward", "stop", "cleanup", "request"):
        setattr(phone, name, lambda *a, **kw: pytest.fail("copy resume attempted UI/network/lifecycle action"))
    def shell(*args, **kwargs):
        if args[:2] == ("readlink", "-f"): return args[-1]
        if args[0] == "cat": return value["nonce"]
        if args[0] == "mkdir":
            path = shlex.split(args[-1])[0]
            if path in phone.dirs or path in phone.files:
                raise subject.AdbOperationFailure(("shell", "mkdir"), exit_code=1, stderr="File exists")
            phone.dirs.add(path)
            phone.writes.append(("mkdir", path))
            return ""
        pytest.fail("unexpected resume shell operation")
    def script(text, **kwargs):
        tokens = shlex.split(text)
        assert text.startswith("umask 077; set -C; cat ") and tokens[-2] == ">"
        source_path, target_path = tokens[-3], tokens[-1]
        if target_path in phone.files or target_path in phone.dirs:
            raise subject.AdbOperationFailure(("shell", "sh"), exit_code=1, stderr="File exists")
        phone.files[target_path] = phone.files[source_path]
        phone.writes.append(("exclusive-file", target_path))
    phone.shell, phone.script = shell, script
    def entries(selected, root, kind=None):
        inside = lambda path: path == root or path.startswith(root + "/")
        files = {path for path in phone.files if inside(path)}
        dirs = {path for path in phone.dirs if inside(path)}
        other = {path for path in phone.nonregular if inside(path)}
        return files if kind == "f" else dirs if kind == "d" else files | dirs | other
    monkeypatch.setattr(subject, "_guest_entries", entries)
    monkeypatch.setattr(subject, "guest_sha256", lambda command, path, **kw: hashlib.sha256(phone.files[path]).hexdigest())
    monkeypatch.setattr(subject, "_guest_free", lambda *a: 1024**4)
    def stopped(ui):
        assert phone.phase == "Stopped"
        return {"foreground": False, "startRequested": False}
    monkeypatch.setattr(subject, "_stopped_service_flags", stopped)
    return phone, value, source, campaign, digest


@pytest.mark.parametrize("existing", [0, 1, 2])
def test_resume_creates_only_missing_verified_payload_and_new_receipt(tmp_path, monkeypatch, existing):
    phone, value, source, campaign, digest = resume_case(tmp_path, monkeypatch, existing=existing)
    staged = {key: data for key, data in phone.files.items() if key.startswith(value["staging"] + "/")}
    source_before = subject.inventory(source)
    result = subject.resume_failed_preparation(phone, value, campaign=campaign, output_root=tmp_path, digest=digest)
    assert result["status"] == "prepared" and result["service"] == "stopped"
    assert result["createdFiles"] == 2 - existing and result["skippedVerifiedFiles"] == existing
    assert result["createdDirectories"] == (0 if existing else 1)
    assert result["sourceRecopies"] == result["filesDeletedOrOverwritten"] == 0
    assert hashlib.sha256((campaign / "preparation.json").read_bytes()).hexdigest() == digest
    prepared = subject.admit_campaign(campaign, result["campaignReceiptSha256"], phone.device.serial)
    assert prepared["resumedFromPreparationSha256"] == digest and "errorType" not in prepared
    assert subject.inventory(source) == source_before
    assert all(phone.files[key] == data for key, data in staged.items())


@pytest.mark.parametrize("fault", ["partial", "unknown-shared", "unknown-staging", "nonregular", "source-changed"])
def test_resume_rejects_conflicts_without_writing_or_removing_any_guest_entry(tmp_path, monkeypatch, fault):
    phone, value, source, campaign, digest = resume_case(tmp_path, monkeypatch, existing=1)
    first = value["destination"] + "/" + value["inventory"]["files"][0]["path"]
    if fault == "partial": phone.files[first] = b"partial"
    if fault == "unknown-shared": phone.files[subject.SHARED + "/Unknown.bin"] = b"keep"
    if fault == "unknown-staging": phone.files[value["staging"] + "/Unknown.bin"] = b"keep"
    if fault == "nonregular":
        phone.files.pop(first)
        phone.nonregular.add(first)
    if fault == "source-changed": (source / value["inventory"]["files"][0]["path"]).write_bytes(b"changed")
    before = (dict(phone.files), set(phone.dirs), set(phone.nonregular))
    result = subject.resume_failed_preparation(phone, value, campaign=campaign, output_root=tmp_path, digest=digest)
    assert result["status"] == "failed" and result["service"] == "stopped" and not phone.writes
    assert (phone.files, phone.dirs, phone.nonregular) == before
    assert not (campaign / "campaign.json").exists()
    assert hashlib.sha256((campaign / "preparation.json").read_bytes()).hexdigest() == digest


def test_resume_first_directory_failure_retains_closed_adb_cause_and_stopped_state(tmp_path, monkeypatch):
    phone, value, source, campaign, digest = resume_case(tmp_path, monkeypatch)
    original_shell = phone.shell
    def shell(*args, **kwargs):
        if args[0] == "mkdir":
            raise subject.AdbOperationFailure(("shell", "mkdir", "private-device-secret"), exit_code=1, stderr="permission denied")
        return original_shell(*args, **kwargs)
    phone.shell = shell
    before = dict(phone.files)
    result = subject.resume_failed_preparation(phone, value, campaign=campaign, output_root=tmp_path, digest=digest)
    assert result["status"] == "failed" and result["step"] == "destination-directory-create"
    assert result["failedAdbSafeFailure"] == {"operation": "shell-mkdir", "reason": "permission-denied", "exitCode": 1}
    assert phone.files == before and phone.phase == "Stopped" and not phone.writes
    assert "private-device-secret" not in json.dumps(result)


def test_resume_exclusive_create_preserves_a_racing_foreign_file(tmp_path, monkeypatch):
    phone, value, source, campaign, digest = resume_case(tmp_path, monkeypatch)
    original_script = phone.script
    first = value["destination"] + "/" + value["inventory"]["files"][0]["path"]
    def collision(text, **kwargs):
        phone.files[first] = b"foreign occupant"
        return original_script(text, **kwargs)
    phone.script = collision
    result = subject.resume_failed_preparation(phone, value, campaign=campaign, output_root=tmp_path, digest=digest)
    assert result["status"] == "failed" and phone.files[first] == b"foreign occupant"
    assert result["failedAdbSafeFailure"]["reason"] == "already-exists" and result["createdFiles"] == 0
    assert not (campaign / "campaign.json").exists()


def test_resume_never_overwrites_preexisting_campaign_receipt(tmp_path, monkeypatch):
    phone, value, source, campaign, digest = resume_case(tmp_path, monkeypatch)
    target = campaign / "campaign.json"
    target.write_bytes(b"preserve existing receipt")
    with pytest.raises(RuntimeError):
        subject.resume_failed_preparation(phone, value, campaign=campaign, output_root=tmp_path, digest=digest)
    assert target.read_bytes() == b"preserve existing receipt" and not phone.writes and not phone.calls


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


@pytest.mark.parametrize("document", [None, [], {"enabled": "true", "gatewayDiscovered": 1},
    {"mappings": None}, {"mappings": [{}]}, {"mappings": [{"protocol": "private-protocol"}]},
    {"mappings": [{"protocol": []}]}])
def test_nat_missing_or_invalid_facts_remain_unknown_and_private_fields_are_excluded(document):
    assert subject.nat_summary(document) == {"enabled": None, "gatewayDiscovered": None,
        "mappingCount": None, "tcpMapped": None, "udpMapped": None, "publicReachability": "not-claimed"}


@pytest.mark.parametrize("mappings,tcp,udp", [([], False, False),
    ([{"protocol": "tcp", "externalAddr": "private-address"}], True, False),
    ([{"protocol": "tcp"}, {"protocol": "udp"}], True, True)])
def test_nat_projects_only_typed_runtime_mapping_observations(mappings, tcp, udp):
    result = subject.nat_summary({"enabled": True, "gatewayDiscovered": False, "mappings": mappings,
        "lastError": "private-response", "gateway": {"controlUrl": "private-endpoint"}})
    assert result == {"enabled": True, "gatewayDiscovered": False, "mappingCount": len(mappings),
        "tcpMapped": tcp, "udpMapped": udp, "publicReachability": "not-claimed"}


def test_sample_reads_nat_endpoint_and_keeps_raw_contents_separate_from_intake_counts(monkeypatch):
    value = receipt()
    value.update(fileCount=221, guestSha256Verified=True)
    calls = []
    def request(method, path):
        calls.append((method, path))
        return {"data": [], "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}} if path.startswith("/downloads") else {
            "items": []} if path == "/uploads" else {"enabled": True, "gatewayDiscovered": True, "mappings": []}
    phone = SimpleNamespace(identity=lambda: None, shell=lambda *args: "", request=request,
                            base="http://127.0.0.1:12345", key="private-key")
    for name in ("wifi_default", "guest_scope", "_settings"):
        monkeypatch.setattr(subject, name, lambda *a, **kw: None)
    monkeypatch.setattr(subject, "shared_catalog", lambda *a: ({"status": "not-observed",
        "approvedFileInstances": 221, "expectedDistinctContents": 220, "matchedDistinctContents": 218,
        "eligibilityAccounting": "evidence-incomplete"}, []))
    monkeypatch.setattr(subject, "rust_summary", lambda *a: {"uploadLimitBytesPerSec": value["limits"]["upload_limit_kibps"] * 1024,
        "ed2kPublishedEntries": 218, "ed2kPendingEntries": 0})
    monkeypatch.setattr(subject, "compact_progress", lambda *a: {"hashedCount": 218, "skippedIntakeCount": 3})
    phases = []
    result = subject.sample(phone, value, phase=phases.append)
    assert ("GET", "/nat") in calls and ("GET", "/status") not in calls
    assert result["nat"]["enabled"] is True and result["nat"]["tcpMapped"] is False
    assert result["catalog"]["expectedDistinctContents"] == 220 and result["catalog"]["matchedDistinctContents"] == 218
    assert result["fileInstances"]["copiedAndSha256Verified"] == 221
    assert result["fileInstances"]["runtimeSkippedIntakeCount"] == 3
    assert result["fileInstances"]["eligibilityAccounting"] == "evidence-incomplete"
    assert result["claims"]["ed2kPublication"] == "observed"
    assert result["claims"]["ed2kPublicationScope"] == "current-server-session-offerfiles-sent"
    assert result["claims"]["perFileServedBytes"] == "evidence-incomplete"
    assert "private-key" not in json.dumps(result)
    assert phases == ["sample-app-identity", "sample-direct-route", "sample-guest-scope", "sample-settings",
        "sample-download-queue", "sample-catalog", "sample-runtime-summary", "sample-nat", "sample-hashing", "sample-uploads"]


@pytest.mark.parametrize("start_networks", [True, False])
def test_public_discovery_uses_existing_approved_seed_owners(monkeypatch, start_networks):
    calls = []
    server_pages = iter([[], [{"enabled": True}]])
    def request(method, path, body=None):
        calls.append((method, path, body))
        if path == "/servers": return {"items": next(server_pages)}
        if path == "/stats": return {"ed2kConnected": False}
        if path == "/kad": return {"connected": False}
        if path == "/kad/operations/import-nodes-url": return {"imported": True}
        return {}
    value = subject.configure_public_discovery(SimpleNamespace(request=request), start_networks=start_networks)
    assert ("POST", "/servers/operations/import-met-url", {"url": subject.DEFAULT_SERVER_MET_URL}) in calls
    assert ("POST", "/kad/operations/import-nodes-url", {"url": subject.DEFAULT_NODES_DAT_URL}) in calls
    assert (("POST", "/servers/operations/connect", {}) in calls) is start_networks
    assert (("POST", "/kad/operations/start", {}) in calls) is start_networks
    assert value["networkStartDeferred"] is not start_networks
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


def test_content_catalog_checks_every_duplicate_location_and_distinct_content():
    value = receipt()
    original = value["inventory"]["files"][0]
    duplicate = {**original, "path": "Other Folder/Sample Audio Copy.bin"}
    distinct = {**original, "path": "Other Folder/Sample Text.bin", "sha256": hashlib.sha256(b"more").hexdigest()}
    value["inventory"]["files"] = [original, duplicate, distinct]
    value["fileCount"] = 3
    rows = [{"hash": file_hash, "displayName": Path(item["path"]).name, "sizeBytes": item["sizeBytes"]}
            for file_hash, item in (("a" * 32, duplicate), ("b" * 32, distinct))]
    def location(item):
        return {"path": value["destination"] + "/" + item["path"], "present": True}
    locations = {"a" * 32: [location(original), location(duplicate)], "b" * 32: [location(distinct)]}
    result, _ = subject.shared_catalog(catalog_phone(rows, locations), value)
    assert result["status"] == result["allFileInstancesIndexed"] == "observed"
    assert result["approvedFileInstances"] == result["catalogFileLocations"] == 3
    assert result["expectedDistinctContents"] == result["matchedDistinctContents"] == 2
    assert result["duplicateFileInstances"] == 1
    locations["a" * 32] = [location(duplicate)]
    assert subject.shared_catalog(catalog_phone(rows, locations), value)[0]["allFileInstancesIndexed"] == "not-observed"
    rows.append({**rows[0], "hash": "c" * 32})
    locations["c" * 32] = [location(original)]
    assert subject.shared_catalog(catalog_phone(rows, locations), value)[0]["status"] == "evidence-incomplete"


def test_content_catalog_reads_realistic_cursor_after_first_200_of_221_rows():
    value = receipt()
    value["fileCount"] = 221
    value["inventory"]["files"] = [{"path": f"Sample Folder/Sample-{index:03d}.bin", "sizeBytes": index + 1,
                                     "sha256": hashlib.sha256(f"sample-{index}".encode()).hexdigest()}
                                    for index in range(221)]
    rows = [{"displayName": Path(item["path"]).name, "sizeBytes": item["sizeBytes"], "hash": f"{index + 1:032x}"}
            for index, item in enumerate(value["inventory"]["files"])]
    locations = {row["hash"]: [{"path": value["destination"] + "/" + item["path"], "present": True}]
                 for row, item in zip(rows, value["inventory"]["files"])}
    cursor = "opaque library cursor +/"
    calls = []
    def request(method, path):
        query = parse_qs(urlsplit(path).query)
        assert query["limit"] == ["200"]
        if urlsplit(path).path != "/library/files":
            return {"data": locations[urlsplit(path).path.split("/")[3]],
                    "meta": {"hasMore": False, "nextCursor": None}}
        calls.append(query)
        assert query["view"] == ["shared"] and query["countTotal"] == ["true"]
        if len(calls) == 1:
            assert "cursor" not in query
            return {"data": rows[:200], "meta": {"total": 221, "hasMore": True, "nextCursor": cursor}}
        assert query["cursor"] == [cursor]
        return {"data": rows[200:], "meta": {"total": 221, "hasMore": False, "nextCursor": None}}
    result, actual = subject.shared_catalog(SimpleNamespace(request=request), value)
    assert result["status"] == result["allFileInstancesIndexed"] == "observed"
    assert result["matchedDistinctContents"] == 221
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
