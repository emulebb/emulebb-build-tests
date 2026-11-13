"""APK admission and production controls reject substituted or ambiguous evidence."""
import hashlib
import json

import pytest

from emule_test_harness import android_apk_lifecycle as subject

SOURCE = "a" * 40


@pytest.mark.parametrize("api", [34, 35, 36, 37])
def test_trusted_case_contract_has_an_explicit_per_api_permission_matrix(api):
    cases = subject.required_apk_cases(api)
    assert {"local-transfer-and-delivery-collision", "completed-delivery-survives-restart",
            "file-link-intents-and-webui-confirmation", "screen-off-doze-observation"} <= cases
    assert ("android17-local-network-denial-and-revocation" in cases) == (api == 37)
    cases.clear()
    assert subject.required_apk_cases(api)
    assert subject.SUPPORTED_ANDROID_APIS == frozenset({34, 35, 36, 37})


@pytest.mark.parametrize("api", [False, True, None, "37", 37.0, 28, 33, 38, 100])
def test_trusted_case_contract_rejects_implicit_or_future_api_coverage(api):
    with pytest.raises(ValueError, match="only Android APIs 34, 35, 36 and 37"):
        subject.required_apk_cases(api)


def payload(tmp_path, mutate=lambda value: None):
    apk = tmp_path / "application.apk"
    apk.write_bytes(b"synthetic signed APK")
    value = {"schema": "emulebb.android.apk-package/1", "status": "passed",
             "source": {"emulebbRust": {"commit": SOURCE}}, "applicationId": subject.APPLICATION_ID,
             "minSdk": 34, "targetSdk": 37, "debug": False,
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
    admitted = subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest,
                                     expected_cert_sha256="b" * 64)
    assert admitted["payloadPath"] == str(tmp_path / "application.apk")
    (tmp_path / "application.apk").write_bytes(b"substituted APK bytes")
    with pytest.raises(RuntimeError, match="changed|hash differs"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest,
                              expected_cert_sha256="b" * 64)


@pytest.mark.parametrize("field,value", [("status", "failed"), ("applicationId", "org.example.other"),
    ("minSdk", 28), ("targetSdk", 34), ("signerSha256", "unsigned")])
def test_wrong_publication_contract_is_rejected(tmp_path, field, value):
    digest = payload(tmp_path, lambda document: document.update({field: value}))
    with pytest.raises(RuntimeError, match="selected signed|trusted certificate"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest,
                              expected_cert_sha256="b" * 64)


def test_source_substitution_is_rejected(tmp_path):
    digest = payload(tmp_path)
    with pytest.raises(RuntimeError, match="selected signed"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha="c" * 40, manifest_sha256=digest,
                              expected_cert_sha256="b" * 64)
    with pytest.raises(RuntimeError, match="receipt hash"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256="d" * 64,
                              expected_cert_sha256="b" * 64)


def test_apk_path_cannot_escape_payload(tmp_path):
    digest = payload(tmp_path, lambda document: document["apk"].update(path="../outside.apk"))
    with pytest.raises(RuntimeError, match="selected signed"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest,
                              expected_cert_sha256="b" * 64)


@pytest.mark.parametrize("changes", [{"debug": True}, {"debug": None}, {"debug": 0}, {"signerSha256": "c" * 64}])
def test_qualification_rejects_debug_and_payload_selected_signing_authority(tmp_path, changes):
    digest = payload(tmp_path, lambda document: document.update(changes))
    with pytest.raises(RuntimeError, match="production release signed by the trusted certificate"):
        subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest,
                              expected_cert_sha256="b" * 64)


@pytest.mark.parametrize("authority", [None, "", "b" * 63, "B" * 64, False])
def test_qualification_has_no_missing_or_implicit_expected_certificate(authority):
    with pytest.raises(ValueError, match="explicit trusted production certificate"):
        subject.admit_production_certificate({"debug": False, "signerSha256": "b" * 64},
                                             expected_cert_sha256=authority)


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
        self.pending_link = ""
        self.pending_error = ""
        self.browser = True
        self.intent_autostart = False
        self.accept_invalid = False

    def command(self, *arguments, **kwargs):
        self.calls.append(arguments)
        args = arguments[2:]
        if args[:4] == ("shell", "cmd", "package", "resolve-activity"):
            if "ed2k:" in args[-1]:
                return subject.APPLICATION_ID + "/.MainActivity"
            return "com.android.browser/.MainActivity" if self.browser else "No activity found"
        if args[:4] == ("shell", "dumpsys", "activity", "activities"):
            return "mResumedActivity: com.android.browser/.MainActivity"
        if args[:3] == ("shell", "am", "start") and "-d" in args:
            import shlex
            link = shlex.split(args[args.index("-d") + 1])[0]
            valid = "00112233445566778899aabbccddeeff" in link
            self.pending_link = link if valid or self.accept_invalid else ""
            self.pending_error = "" if self.pending_link else "Unsupported or malformed eD2K file link"
            if self.intent_autostart:
                self.running = True
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
                    '<node resource-id="org.emulebb.android:id/pending_link" text="' + self.pending_link + '"/>'
                    '<node resource-id="org.emulebb.android:id/pending_link_error" text="' + self.pending_error + '"/>'
                    '<node resource-id="org.emulebb.android:id/open_webui" enabled="true" bounds="[600,0][700,100]"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,0][300,100]"/>'
                    '</hierarchy>')
        if args[:3] == ("shell", "input", "tap"):
            if args[3] == "450":
                self.boot_enabled = not self.boot_enabled
            elif args[3] == "650":
                self.pending_link = ""
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
    admitted = subject.admit_payload(tmp_path, "manifest.json", source_sha=SOURCE, manifest_sha256=digest,
                                     expected_cert_sha256="b" * 64)
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
    assert result["androidApiLevel"] == api
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
    assert set(expected) == subject.required_apk_cases(api) - {
        "local-transfer-and-delivery-collision", "completed-delivery-survives-restart",
        "file-link-intents-and-webui-confirmation"}
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


@pytest.mark.parametrize("exit_state", ["awake", "active"])
def test_dwell_does_not_pass_if_guest_leaves_screen_off_deep_doze(tmp_path, monkeypatch, exit_state):
    peer, admitted = guest(tmp_path, monkeypatch)
    polls = [0]

    def command(*arguments, **kwargs):
        args = arguments[2:]
        if args == ("shell", "dumpsys", "deviceidle", "get", "deep"):
            polls[0] += 1
            if polls[0] >= 3 and exit_state == "active":
                return "ACTIVE"
        if args == ("shell", "dumpsys", "power") and polls[0] >= 3 and exit_state == "awake":
            return "mWakefulness=Awake"
        return peer.command(*arguments, **kwargs)

    with pytest.raises(RuntimeError, match="deep idle|sleeping device"):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["status"] == "failed" and result["endurance"]["observedSeconds"] == 0
    assert "screen-off-doze-observation" not in [case["name"] for case in result["cases"]]


@pytest.mark.parametrize("api", [34, 35, 36, 37])
def test_permission_changes_that_close_activity_require_real_launcher_reopen(tmp_path, monkeypatch, api):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.api = api
    visible = [False]
    closures = []

    def command(*arguments, **kwargs):
        args = arguments[2:]
        permission_change = args[:3] in (("shell", "pm", "revoke"), ("shell", "pm", "grant"))
        storage_change = args[:3] == ("shell", "appops", "set")
        if permission_change or storage_change:
            visible[0] = False
            closures.append(args)
        if args[:3] == ("shell", "am", "start"):
            visible[0] = True
        if args[:2] == ("shell", "uiautomator"):
            assert visible[0], "The production activity must be reopened after permission changes"
        return peer.command(*arguments, **kwargs)

    result = subject.exercise(command, admitted, report_dir=tmp_path)
    assert result["status"] == "passed" and len(closures) >= 8


@pytest.mark.parametrize("failure", [None, "autostart", "invalid", "browser", "enqueue", "browser-proof"])
def test_real_intent_dispatch_requires_user_start_and_explicit_browser_confirmation(tmp_path, monkeypatch, failure):
    from emule_test_harness import rust_local_ed2k, rust_webui_live_proof
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.intent_autostart = failure == "autostart"
    peer.accept_invalid = failure == "invalid"
    peer.browser = failure != "browser"
    baseline = [{"hash": "b" * 32, "sizeBytes": 262144}]
    browser_calls = []

    def request(base, method, route, key, body=None):
        assert key == peer.key and method == "GET" and route == "/api/v1/transfers?limit=100"
        return {"items": baseline + ([{"hash": "c" * 32, "sizeBytes": 1}]
                                    if failure == "enqueue" and peer.pending_link else [])}

    def browser(**kwargs):
        assert kwargs["api_key"] == peer.key and kwargs["file_hash"] == "00112233445566778899aabbccddeeff"
        assert kwargs["size_bytes"] == 1 and kwargs["identity"] == admitted["buildIdentity"]
        browser_calls.append(kwargs["link"])
        return {"status": "failed" if failure == "browser-proof" else "passed"}

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)
    monkeypatch.setattr(rust_webui_live_proof, "run_file_link_browser_proof", browser)
    if failure:
        messages = {"autostart": "expected service state", "invalid": "malformed or unsupported",
                    "browser": "installed guest default browser", "enqueue": "silently changed",
                    "browser-proof": "did not finish cleanly"}
        with pytest.raises(RuntimeError, match=messages[failure]):
            subject.exercise(peer.command, admitted, report_dir=tmp_path, qualify_file_links=True)
        result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
        assert result["status"] == result["fileLinks"]["status"] == "failed"
    else:
        result = subject.exercise(peer.command, admitted, report_dir=tmp_path, qualify_file_links=True)
        assert result["status"] == result["fileLinks"]["status"] == "passed"
        assert len(browser_calls) == 1
        assert [case["name"] for case in result["fileLinks"]["cases"]] == [
            "os-file-link-resolution", "cold-file-link-without-autostart", "pending-and-repeated-intents-without-autostart",
            "malformed-and-nonfile-intents-rejected", "start-and-repeated-intents-without-enqueue",
            "native-browser-dispatch-without-enqueue", "bundled-webui-confirmation"]
        assert {case["name"] for case in result["fileLinks"]["cases"]} == subject.APK_FILE_LINK_CASES
    assert peer.key not in (tmp_path / "apk-lifecycle.json").read_text()


@pytest.mark.parametrize("api", [34, 35, 36, 37])
def test_full_official_path_matches_source_owned_case_contract(tmp_path, monkeypatch, api):
    from emule_test_harness import android_apk_peer, rust_local_ed2k, rust_webui_live_proof
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.api = api
    digest = "d" * 64
    monkeypatch.setattr(android_apk_peer, "transfer_proof", lambda *args, **kwargs: {
        "status": "passed", "sha256": digest, "deliveredPath": "/owned/Android Sample.bin"})
    monkeypatch.setattr(android_apk_peer, "guest_sha256", lambda *args: digest)
    monkeypatch.setattr(rust_local_ed2k, "request_json", lambda *args, **kwargs: {"items": []})
    monkeypatch.setattr(rust_webui_live_proof, "run_file_link_browser_proof", lambda **kwargs: {"status": "passed"})
    result = subject.exercise(peer.command, admitted, report_dir=tmp_path, peer_payload={},
                              rust_source=tmp_path, adb="adb", child={}, qualify_file_links=True)
    assert result["status"] == "passed"
    assert {case["name"] for case in result["cases"]} == subject.required_apk_cases(api)
    assert len(result["cases"]) == len(subject.required_apk_cases(api))


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
