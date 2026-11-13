"""APK admission and production controls reject substituted or ambiguous evidence."""
import hashlib
import json

import pytest

from emule_test_harness import android_apk_lifecycle as subject

SOURCE = "a" * 40


def payload(tmp_path, mutate=lambda value: None):
    apk = tmp_path / "application.apk"
    apk.write_bytes(b"synthetic signed APK")
    value = {"schema": "emulebb.android.apk-package/1", "status": "passed",
             "source": {"emulebbRust": {"commit": SOURCE}}, "applicationId": subject.APPLICATION_ID,
             "minSdk": 34, "targetSdk": 37,
             "buildIdentity": {"sourceRevision": SOURCE, "version": "0.1.0-test", "channel": "development"},
             "signerSha256": "b" * 64,
             "apk": {"path": apk.name, "sizeBytes": apk.stat().st_size,
                     "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()}}
    mutate(value)
    raw = json.dumps(value).encode()
    (tmp_path / "manifest.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_source_and_actual_apk_bytes_are_bound(tmp_path):
    digest = payload(tmp_path)
    admitted = subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest)
    assert admitted["payloadPath"] == str(tmp_path / "application.apk")
    (tmp_path / "application.apk").write_bytes(b"substituted APK bytes")
    with pytest.raises(RuntimeError, match="changed|hash differs"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest)


@pytest.mark.parametrize("field,value", [("status", "failed"), ("applicationId", "org.example.other"),
    ("minSdk", 28), ("targetSdk", 34), ("signerSha256", "unsigned")])
def test_wrong_publication_contract_is_rejected(tmp_path, field, value):
    digest = payload(tmp_path, lambda document: document.update({field: value}))
    with pytest.raises(RuntimeError, match="selected signed"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest)


def test_source_substitution_is_rejected(tmp_path):
    digest = payload(tmp_path)
    with pytest.raises(RuntimeError, match="selected signed"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha="c" * 40, manifest_sha256=digest)
    with pytest.raises(RuntimeError, match="receipt hash"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256="d" * 64)


def test_apk_path_cannot_escape_payload(tmp_path):
    digest = payload(tmp_path, lambda document: document["apk"].update(path="../outside.apk"))
    with pytest.raises(RuntimeError, match="selected signed"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest)


def test_production_ui_has_unambiguous_resource_ids():
    xml = '<hierarchy><node resource-id="org.emulebb.android:id/start_service" text="Start" /></hierarchy>'
    assert subject.ui_nodes(xml)["start_service"]["text"] == "Start"
    with pytest.raises(RuntimeError, match="ambiguous"):
        subject.ui_nodes(xml.replace("</hierarchy>", xml[11:]))
    with pytest.raises(RuntimeError, match="malformed"):
        subject.ui_nodes("<broken")


def test_ui_errors_do_not_echo_credential_text():
    secret = "synthetic-private-key-not-for-receipts"
    with pytest.raises(RuntimeError) as error:
        subject.ui_nodes('<hierarchy text="' + secret + '">')
    assert secret not in str(error.value)


class Guest:
    """Minimal production UI/ADB peer, with independently observed REST state."""

    def __init__(self, admitted):
        self.payload = admitted
        self.running = False
        self.calls = []
        self.key = "synthetic-private-key-not-for-receipts"
        self.allow_unauthenticated = False
        self.files_allowed = True
        self.local_allowed = True
        self.desired = False
        self.boot_enabled = False
        self.boot_id = 0
        self.api = 37
        self.doze_state = "IDLE"

    def command(self, *arguments, **kwargs):
        self.calls.append(arguments)
        args = arguments[2:]
        if args == ("reboot",):
            self.boot_id += 1
            self.running = self.desired and self.boot_enabled
        if args == ("shell", "wm", "size"):
            return "Physical size: 1080x1920"
        if args == ("shell", "getprop", "ro.build.version.sdk"):
            return str(self.api)
        if args == ("shell", "getprop", "sys.boot_completed"):
            return "1"
        if args == ("shell", "cat", "/proc/sys/kernel/random/boot_id"):
            return str(self.boot_id)
        if args == ("shell", "dumpsys", "deviceidle", "get", "deep"):
            return self.doze_state
        if args == ("shell", "dumpsys", "power"):
            return "mWakefulness=Asleep"
        if args[:3] == ("shell", "appops", "set"):
            self.files_allowed = args[-1] == "allow"
            if not self.files_allowed:
                self.running = self.desired = False
        if args[:3] in (("shell", "pm", "grant"), ("shell", "pm", "revoke")) and args[-1] == "android.permission.ACCESS_LOCAL_NETWORK":
            self.local_allowed = args[2] == "grant"
            if not self.local_allowed:
                self.running = self.desired = False
        if args[:1] == ("forward",) and "--remove" not in args:
            return "12345"
        if args[:3] == ("shell", "pm", "path"):
            return "package:/data/app/synthetic/base.apk"
        if args[:2] == ("shell", "sha256sum"):
            return self.payload["apk"]["sha256"] + " /data/app/synthetic/base.apk"
        if args[:2] == ("shell", "cat"):
            state = "Running" if self.running else "Stopped"
            return ('<hierarchy><node resource-id="org.emulebb.android:id/service_status" text="' + state
                    + '"/><node resource-id="org.emulebb.android:id/api_key" enabled="true" text="' + self.key
                    + '"/><node resource-id="org.emulebb.android:id/resume_on_boot" enabled="true" bounds="[400,0][500,100]" checked="'
                    + str(self.boot_enabled).lower() + '"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,0][300,100]"/>'
                    '</hierarchy>')
        if args[:3] == ("shell", "input", "tap"):
            if args[3] == "450":
                self.boot_enabled = not self.boot_enabled
            else:
                self.running = self.desired = args[3] == "50" and self.files_allowed and self.local_allowed
        if args[:3] == ("shell", "am", "force-stop"):
            self.running = self.desired = False
        if args[:4] == ("shell", "cmd", "activity", "stop-app"):
            self.running = self.desired = False
        return ""

    def request(self, port, path, key=None):
        assert port == 12345
        if not self.running:
            raise ConnectionRefusedError()
        if path == "/":
            return 200, b"<html>bundled application</html>"
        if key is None:
            return (200 if self.allow_unauthenticated else 401), b"{}"
        assert key == self.key
        return 200, json.dumps({"meta": {"apiVersion": "v1"},
                                "data": {"name": "eMuleBB", "apiVersion": "v1",
                                         "sourceRevision": SOURCE, "version": "0.1.0-test",
                                         "channel": "development", "lifecycle": {"state": "running"}}}).encode()


def guest(tmp_path, monkeypatch):
    digest = payload(tmp_path)
    admitted = subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest)
    peer = Guest(admitted)
    monkeypatch.setattr(subject, "_request", peer.request)
    clock = [0.0]
    monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    return peer, admitted


@pytest.mark.parametrize("api", [34, 35, 36, 37])
def test_lifecycle_uses_production_controls_and_persists_no_credentials(tmp_path, monkeypatch, api):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.api = api
    result = subject.exercise(peer.command, admitted, report_dir=tmp_path)
    assert result["status"] == "passed"
    expected = [
        "installed-apk-identity", "fresh-setup", "authenticated-source-bound-readiness",
        "bundled-webui", "graceful-stop", "notification-denied-service-start",
        "all-files-denial-and-runtime-revocation"]
    if api == 37:
        expected.append("android17-local-network-denial-and-revocation")
    expected.extend(["enabled-boot-resume", "explicit-stop-prevents-boot-resume",
                     "task-manager-stop-prevents-boot-resume", "force-stop-prevents-boot-resume",
                     "restart", "screen-off-doze-observation"])
    assert [case["name"] for case in result["cases"]] == expected
    assert result["localTransfer"] == "not-run"
    assert result["physicalDevice"] == "not-run"
    assert result["endurance"]["samples"] == 3
    assert result["endurance"]["observedSeconds"] == 60
    assert result["endurance"]["over24Hours"] is False
    assert peer.running is False
    assert any(call[2:4] == ("forward", "--remove") for call in peer.calls)
    for path in (tmp_path / "apk-progress.json", tmp_path / "apk-lifecycle.json"):
        assert peer.key not in path.read_text()


def test_successful_force_idle_command_is_not_enough_to_claim_doze(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.doze_state = "ACTIVE"
    with pytest.raises(RuntimeError, match="actual deep idle"):
        subject.exercise(peer.command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["status"] == "failed"
    assert "screen-off-doze-observation" not in [case["name"] for case in result["cases"]]


def test_scrollable_production_ui_does_not_require_controls_in_one_viewport(tmp_path, monkeypatch):
    import xml.etree.ElementTree as ET
    peer, admitted = guest(tmp_path, monkeypatch)
    viewport = [0]

    def scrolling_command(*args, **kwargs):
        raw = peer.command(*args, **kwargs)
        if args[2:5] == ("shell", "input", "swipe"):
            viewport[0] = 1 if int(args[8]) < int(args[6]) else 0
        if args[2:4] == ("shell", "cat") and args[4] != "/proc/sys/kernel/random/boot_id":
            root = ET.fromstring(raw)
            visible = {"service_status", "api_key"} if viewport[0] == 0 else {"start_service", "stop_service", "resume_on_boot"}
            for node in list(root):
                if node.get("resource-id", "").split("/")[-1] not in visible:
                    root.remove(node)
            return ET.tostring(root, encoding="unicode")
        return raw

    result = subject.exercise(scrolling_command, admitted, report_dir=tmp_path)
    assert result["status"] == "passed"
    assert any(call[2:5] == ("shell", "input", "swipe") for call in peer.calls)


def test_transfer_and_restart_verdicts_use_actual_peer_fixture_result(tmp_path, monkeypatch):
    from emule_test_harness import android_apk_peer
    peer, admitted = guest(tmp_path, monkeypatch)
    calls = []
    digest = "d" * 64
    delivered = "/storage/emulated/0/Download/Android Sample (1).bin"

    def transfer(command, payload, **kwargs):
        assert kwargs["api_key"] == peer.key
        assert kwargs["apk_port"] == 12345
        calls.append(payload)
        return {"status": "passed", "sha256": digest, "deliveredPath": delivered, "collisionPreserved": True}

    monkeypatch.setattr(android_apk_peer, "transfer_proof", transfer)
    monkeypatch.setattr(android_apk_peer, "guest_sha256", lambda command, path: digest if path == delivered else None)
    result = subject.exercise(peer.command, admitted, report_dir=tmp_path, peer_payload={"sourceRevision": SOURCE},
                              rust_source=tmp_path, adb="owned-adb", child={})
    assert calls == [{"sourceRevision": SOURCE}]
    assert result["localTransfer"]["status"] == "passed"
    assert {"local-transfer-and-delivery-collision", "completed-delivery-survives-restart"} <= {case["name"] for case in result["cases"]}
    assert peer.key not in json.dumps(result)


def test_failed_authentication_cleans_up_without_claiming_runtime_success(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.allow_unauthenticated = True
    with pytest.raises(RuntimeError, match="require authentication"):
        subject.exercise(peer.command, admitted, report_dir=tmp_path)
    receipt = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["runtimeExecution"] == "not-run"
    assert "authenticated-source-bound-readiness" not in [case["name"] for case in receipt["cases"]]
    assert peer.key not in json.dumps(receipt)
    assert peer.running is False
    assert any(call[2:4] == ("forward", "--remove") for call in peer.calls)


def test_install_failure_does_not_claim_execution_and_still_writes_receipt(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)

    def broken_install(*args, **kwargs):
        if args[2] == "install":
            raise RuntimeError("installation failed")
        return peer.command(*args, **kwargs)

    with pytest.raises(RuntimeError, match="installation failed"):
        subject.exercise(broken_install, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["runtimeExecution"] == "not-run"
    assert result["status"] == "failed"
    assert not result["cases"]


def test_noncanonical_channel_field_cannot_satisfy_source_identity(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)

    def wrong_shape(port, path, key=None):
        status, raw = peer.request(port, path, key)
        if key is not None and path == "/api/v1/app":
            value = json.loads(raw)
            value["data"]["releaseChannel"] = value["data"].pop("channel")
            raw = json.dumps(value).encode()
        return status, raw

    monkeypatch.setattr(subject, "_request", wrong_shape)
    with pytest.raises(RuntimeError, match="identify the requested"):
        subject.exercise(peer.command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["runtimeExecution"] == "not-run"
    assert result["status"] == "failed"


def test_cleanup_attempts_every_action_and_preserves_original_failure(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.allow_unauthenticated = True

    def broken_stop(*args, **kwargs):
        result = peer.command(*args, **kwargs)
        if args[2:5] == ("shell", "am", "force-stop"):
            raise RuntimeError("cleanup failure")
        return result

    with pytest.raises(RuntimeError, match="require authentication"):
        subject.exercise(broken_stop, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["cleanupErrors"] == [{"action": "force-stop", "errorType": "RuntimeError"}]
    assert any(call[2:5] == ("shell", "dumpsys", "battery") for call in peer.calls)
    assert any(call[2:4] == ("forward", "--remove") for call in peer.calls)
