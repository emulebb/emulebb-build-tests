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

    def command(self, *arguments, **kwargs):
        self.calls.append(arguments)
        args = arguments[2:]
        if args[:1] == ("forward",) and "--remove" not in args:
            return "12345"
        if args[:3] == ("shell", "pm", "path"):
            return "package:/data/app/synthetic/base.apk"
        if args[:2] == ("shell", "sha256sum"):
            return self.payload["apk"]["sha256"] + " /data/app/synthetic/base.apk"
        if args[:2] == ("shell", "cat"):
            state = "Running" if self.running else "Stopped"
            return ('<hierarchy><node resource-id="org.emulebb.android:id/service_status" text="' + state
                    + '"/><node resource-id="org.emulebb.android:id/api_key" text="' + self.key
                    + '"/><node resource-id="org.emulebb.android:id/resume_on_boot" checked="false"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,0][300,100]"/>'
                    '</hierarchy>')
        if args[:3] == ("shell", "input", "tap"):
            self.running = args[3] == "50"
        if args[:3] == ("shell", "am", "force-stop"):
            self.running = False
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


def test_lifecycle_uses_production_controls_and_persists_no_credentials(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    result = subject.exercise(peer.command, admitted, report_dir=tmp_path)
    assert result["status"] == "passed"
    assert [case["name"] for case in result["cases"]] == [
        "installed-apk-identity", "fresh-setup", "authenticated-source-bound-readiness",
        "bundled-webui", "graceful-stop", "restart", "screen-off-doze-observation"]
    assert result["localTransfer"] == "not-run"
    assert result["physicalDevice"] == "not-run"
    assert result["endurance"]["samples"] == 3
    assert result["endurance"]["observedSeconds"] == 60
    assert result["endurance"]["over24Hours"] is False
    assert peer.running is False
    assert any(call[2:4] == ("forward", "--remove") for call in peer.calls)
    for path in (tmp_path / "apk-progress.json", tmp_path / "apk-lifecycle.json"):
        assert peer.key not in path.read_text()


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
