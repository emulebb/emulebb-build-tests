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
             "minSdk": 34, "targetSdk": 37, "debug": False, "versionCode": 42,
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
    ("minSdk", 28), ("targetSdk", 34), ("signerSha256", "unsigned"),
    ("versionCode", None), ("versionCode", True), ("versionCode", 0), ("versionCode", 2_100_000_001)])
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
        if args == ("shell", "dumpsys", "package", subject.APPLICATION_ID):
            return "Package [org.emulebb.android]\n  versionCode=" + str(self.payload["versionCode"]) + " minSdk=34 targetSdk=37\n"
        if args[:2] == ("shell", "sha256sum"):
            return self.payload["apk"]["sha256"] + " /data/app/synthetic/base.apk"
        if args[:2] == ("shell", "cat"):
            state = "Running" if self.running else "Stopped"
            return ('<hierarchy><node resource-id="org.emulebb.android:id/service_status" text="' + state
                    + '"/><node resource-id="org.emulebb.android:id/api_key" enabled="true" text="' + self.key
                    + '"/><node resource-id="org.emulebb.android:id/resume_on_boot" enabled="true" bounds="[400,500][500,600]" checked="'
                    + str(self.boot_enabled).lower() + '"/>'
                    '<node resource-id="org.emulebb.android:id/pending_link" text="' + self.pending_link + '"/>'
                    '<node resource-id="org.emulebb.android:id/pending_link_error" text="' + self.pending_error + '"/>'
                    '<node resource-id="org.emulebb.android:id/open_webui" enabled="true" bounds="[600,500][700,600]"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,500][100,600]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,500][300,600]"/>'
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


@pytest.mark.parametrize("secure", [False, True])
def test_initial_owned_guest_wakes_and_dismisses_only_insecure_keyguard_before_ui_read(tmp_path, monkeypatch, secure):
    peer, admitted = guest(tmp_path, monkeypatch)
    display = {"awake": False, "locked": True, "firstUiRead": None}

    def command(*arguments, **kwargs):
        args = arguments[2:]
        result = peer.command(*arguments, **kwargs)
        if args == ("reboot",):
            display.update(awake=False, locked=True)
        if args == ("shell", "input", "keyevent", "KEYCODE_WAKEUP"):
            display["awake"] = True
        if args == ("shell", "wm", "dismiss-keyguard"):
            assert display["awake"], "normal wake must precede keyguard dismissal"
            display["locked"] = secure
        if args[:3] == ("shell", "am", "start"):
            assert display["awake"], "am start alone cannot establish display readiness"
        if args[:2] == ("shell", "cat") and "/emulebb-apk-ui-" in args[-1]:
            if display["firstUiRead"] is None:
                display["firstUiRead"] = (display["awake"], display["locked"])
            if display["locked"]:
                return '<hierarchy><node resource-id="com.android.systemui:id/keyguard_root_view"/></hierarchy>'
        return result

    if secure:
        with pytest.raises(subject.DeviceUiUnavailable, match="locked"):
            subject.exercise(command, admitted, report_dir=tmp_path)
        result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
        assert result["runtimeExecution"] == "not-run"
        assert display["firstUiRead"] == (True, True)
        assert not any(call[2:5] == ("shell", "input", "tap") or call[2:5] == ("shell", "input", "swipe") for call in peer.calls)
    else:
        result = subject.exercise(command, admitted, report_dir=tmp_path)
        assert result["status"] == "passed" and display["firstUiRead"] == (True, False)
    initial_launch = next(index for index, call in enumerate(peer.calls) if call[2:5] == ("shell", "am", "start"))
    assert peer.calls[initial_launch - 2:initial_launch] == [
        (*subject.PREFIX, "shell", "input", "keyevent", "KEYCODE_WAKEUP"),
        (*subject.PREFIX, "shell", "wm", "dismiss-keyguard")]
    assert not any(call[2:5] == ("shell", "input", "text") for call in peer.calls)


@pytest.mark.parametrize("api", [34, 35, 36, 37])
def test_lifecycle_uses_production_controls_and_persists_no_credentials(tmp_path, monkeypatch, api):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.api = api
    result = subject.exercise(peer.command, admitted, report_dir=tmp_path)
    assert result["status"] == "passed"
    assert result["androidApiLevel"] == api
    assert result["versionCode"] == admitted["versionCode"]
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
    assert result["endurance"]["minimumSamples"] == subject.MIN_SCREEN_OFF_SAMPLES == 3
    assert result["endurance"]["minimumDwellSeconds"] == subject.MIN_SCREEN_OFF_DWELL_SECONDS == 60
    assert result["endurance"]["observedSeconds"] == 60
    assert result["endurance"]["over24Hours"] is False
    assert peer.running is False
    assert any(call[2:4] == ("forward", "--remove") for call in peer.calls)
    for path in (tmp_path / "apk-progress.json", tmp_path / "apk-lifecycle.json"):
        assert peer.key not in path.read_text()


@pytest.mark.parametrize("details", ["Unknown command", "versionCode=41", "versionCode=42\nversionCode=43"])
def test_guest_does_not_claim_install_identity_for_missing_wrong_or_ambiguous_version(tmp_path, monkeypatch, details):
    peer, admitted = guest(tmp_path, monkeypatch)

    def command(*arguments, **kwargs):
        if arguments[2:] == ("shell", "dumpsys", "package", subject.APPLICATION_ID):
            return details
        return peer.command(*arguments, **kwargs)

    with pytest.raises(RuntimeError, match="Installed APK versionCode"):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["runtimeExecution"] == "not-run" and result["cases"] == []
    assert not any(call[2:5] == ("shell", "am", "start") for call in peer.calls)


def test_slow_doze_requests_still_require_three_authenticated_samples_without_negative_sleep(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    request, advance = peer.request, subject.time.sleep
    samples, sleeps = [], []

    def slow_request(port, path, key=None):
        result = request(port, path, key)
        if key is not None and any(call[2:] == ("shell", "dumpsys", "deviceidle", "force-idle") for call in peer.calls):
            advance(65)
            samples.append(path)
        return result

    def sleep(seconds):
        assert seconds >= 0
        sleeps.append(seconds)
        advance(seconds)

    monkeypatch.setattr(subject, "_request", slow_request)
    monkeypatch.setattr(subject.time, "sleep", sleep)
    result = subject.exercise(peer.command, admitted, report_dir=tmp_path)
    assert result["status"] == "passed" and result["endurance"]["samples"] == 3
    assert result["endurance"]["observedSeconds"] == 195
    assert samples == ["/api/v1/app"] * 3 and 0 in sleeps


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
        "status": "passed", "sha256": digest, "completedDeliverySurvivesRestart": True})
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
        kwargs["restart_service"]()
        calls.append(payload)
        return {"status": "passed", "sha256": digest, "completedDeliverySurvivesRestart": True, "collisionPreserved": True}

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
    assert result["failure"] == {"stage": "install", "code": "other"}


@pytest.mark.parametrize("arguments,stage", [
    (("appops", "set", subject.APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow"), "all-files-access"),
    (("pm", "grant", subject.APPLICATION_ID, "android.permission.POST_NOTIFICATIONS"), "notification-permission"),
    (("getprop", "ro.build.version.sdk"), "android-api"),
    (("dumpsys", "deviceidle", "whitelist", "+" + subject.APPLICATION_ID), "battery-exemption"),
    (("input", "keyevent", "KEYCODE_WAKEUP"), "wake-display"),
    (("wm", "dismiss-keyguard"), "dismiss-keyguard"),
    (("am", "start", "-W", "-n", subject.APPLICATION_ID + "/.MainActivity"), "launch-main"),
])
def test_fresh_setup_command_failure_records_exact_stage_without_private_text(tmp_path, monkeypatch, arguments, stage):
    peer, admitted = guest(tmp_path, monkeypatch)
    private = "synthetic-private-command-and-key-value"

    def command(*args, **kwargs):
        if args[2:] == ("shell", *arguments):
            raise RuntimeError(private)
        if args[2:5] == ("shell", "am", "force-stop"):
            raise RuntimeError("synthetic-private-cleanup-value")
        return peer.command(*args, **kwargs)

    with pytest.raises(RuntimeError, match=private):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["failure"] == {"stage": stage, "code": "other"}
    assert result["runtimeExecution"] == "not-run"
    assert result["cases"] == [{"name": "installed-apk-identity", "status": "passed"}]
    assert result["cleanupErrors"] == [{"action": "force-stop", "errorType": "RuntimeError"}]
    assert "synthetic-private" not in json.dumps(result) and peer.key not in json.dumps(result)
    assert any(call[2:5] == ("shell", "dumpsys", "battery") for call in peer.calls)


@pytest.mark.parametrize("operation", ["grant", "reopen", "start", "wait-running", "authentication"])
def test_post_revocation_failure_identifies_actual_restoration_operation(tmp_path, monkeypatch, operation):
    peer, admitted = guest(tmp_path, monkeypatch)
    grants = [0]
    private = "synthetic-private-restoration-error"
    click, wait, request = subject.ProductionUi.click, subject.ProductionUi.wait_state, peer.request

    def fail_if(target):
        if grants[0] == 3 and operation == target:
            raise RuntimeError(private)

    def command(*args, **kwargs):
        if args[2:] == ("shell", "appops", "set", subject.APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow"):
            grants[0] += 1
            fail_if("grant")
        if args[2:5] == ("shell", "am", "start"):
            fail_if("reopen")
        return peer.command(*args, **kwargs)

    def clicking(ui, name):
        if name == "start_service":
            fail_if("start")
        return click(ui, name)

    def waiting(ui, expected, **kwargs):
        if expected == "Running":
            fail_if("wait-running")
        return wait(ui, expected, **kwargs)

    def requesting(port, path, key=None):
        if key is not None:
            fail_if("authentication")
        return request(port, path, key)

    monkeypatch.setattr(subject.ProductionUi, "click", clicking)
    monkeypatch.setattr(subject.ProductionUi, "wait_state", waiting)
    monkeypatch.setattr(subject, "_request", requesting)
    with pytest.raises(RuntimeError, match=private):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    failure = result["failure"]
    assert failure["stage"] == "all-files-restoration-" + operation and failure["code"] == "other"
    assert failure["servicePhase"] in subject.SETUP_SERVICE_PHASES
    assert set(failure["controls"]) == subject.SETUP_CONTROL_NAMES
    assert result["runtimeExecution"] == "executed" and len(result["cases"]) == 7
    assert result["cases"][-1]["name"] == "all-files-denial-and-runtime-revocation"
    assert private not in json.dumps(result) and peer.key not in json.dumps(result)


@pytest.mark.parametrize("phase", ["Stopped", "Starting", "Running", "Stopping", "Failed", "synthetic-private-phase"])
def test_ui_observation_retains_only_known_controls_booleans_and_service_phase(phase):
    private = "synthetic-private-key-value"
    xml = ('<hierarchy><node resource-id="org.emulebb.android:id/service_status" text="' + phase + '"/>'
           '<node resource-id="org.emulebb.android:id/api_key" text="' + private + '" enabled="true"/>'
           '<node resource-id="org.emulebb.android:id/unknown_private" text="' + private + '"/></hierarchy>')
    ui = subject.ProductionUi(lambda *args: xml if args[-2:-1] == ("cat",) else "")
    ui.inspect()
    observed = ui.setup_observation
    assert observed["controls"] == {"service_status": {"present": True, "enabled": False},
                                    "api_key": {"present": True, "enabled": True},
                                    "resume_on_boot": {"present": False, "enabled": False}}
    assert observed.get("servicePhase") == (phase if phase in subject.SETUP_SERVICE_PHASES else None)
    assert "synthetic-private" not in json.dumps(observed)


@pytest.mark.parametrize("error,code", [
    (RuntimeError("Owned Android ADB command failed"), "adb-command-failed"),
    (subject.DeviceUiUnavailable("device-locked"), "device-locked"),
    (subject.DeviceUiUnavailable("app-not-visible"), "app-not-visible"),
    (RuntimeError("APK required control remains disabled: api_key"), "control-disabled"),
    (RuntimeError("APK required control is not reachable: resume_on_boot"), "control-unreachable"),
    (RuntimeError("APK did not reach expected service state: Running"), "expected-state-not-reached"),
    (RuntimeError("APK UI must expose a valid generated API key"), "invalid-generated-key"),
    (RuntimeError("synthetic-private-error"), "other"),
])
def test_lifecycle_failure_codes_are_closed_and_never_copy_exception_text(error, code):
    result = subject._lifecycle_failure(error, "read-api-key", {})
    assert result == {"stage": "read-api-key", "code": code}
    assert code in subject.APK_LIFECYCLE_FAILURE_CODES


@pytest.mark.parametrize("fault,stage,code", [
    ("disabled-key", "read-api-key", "control-disabled"),
    ("invalid-key", "validate-api-key", "invalid-generated-key"),
    ("boot-enabled", "validate-boot-resume", "unexpected-boot-default"),
    ("failed-state", "wait-stopped", "expected-state-not-reached"),
])
def test_fresh_ui_admission_failure_keeps_actual_stage_and_safe_observation(tmp_path, monkeypatch, fault, stage, code):
    import xml.etree.ElementTree as ET
    peer, admitted = guest(tmp_path, monkeypatch)

    def command(*args, **kwargs):
        raw = peer.command(*args, **kwargs)
        if args[2:4] == ("shell", "cat") and "/emulebb-apk-ui-" in args[-1]:
            root = ET.fromstring(raw)
            for node in root:
                name = node.get("resource-id", "").split("/")[-1]
                if name == "api_key" and fault == "disabled-key":
                    node.set("enabled", "false")
                elif name == "api_key" and fault == "invalid-key":
                    node.set("text", "bad")
                elif name == "resume_on_boot" and fault == "boot-enabled":
                    node.set("checked", "true")
                elif name == "service_status" and fault == "failed-state":
                    node.set("text", "Failed")
            return ET.tostring(root, encoding="unicode")
        return raw

    with pytest.raises(RuntimeError):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    assert result["failure"]["stage"] == stage and result["failure"]["code"] == code
    assert result["failure"]["servicePhase"] == ("Failed" if fault == "failed-state" else "Stopped")
    assert result["failure"]["controls"]["api_key"] == {"present": True, "enabled": fault != "disabled-key"}
    assert result["runtimeExecution"] == "not-run" and len(result["cases"]) == 1
    assert peer.key not in json.dumps(result)


@pytest.mark.parametrize("ime", ["true", "false", "unknown", "ambiguous", "oversize", "query-failed"])
@pytest.mark.parametrize("moves", [False, True])
def test_failed_navigation_records_numeric_progress_and_only_unambiguous_ime_visibility(ime, moves):
    calls = []
    scrolls = [0]
    private = "synthetic-private-ui-and-ime-text"

    def command(*args):
        call = args[2:]
        calls.append(call)
        if call == ("shell", "wm", "size"):
            return "Physical size: 1080x1920"
        if call[:3] == ("shell", "input", "swipe"):
            scrolls[0] += 1
        if call[:2] == ("shell", "cat"):
            # Moving bounds demonstrate scroll progress without retaining text.
            y = 100 + (scrolls[0] if moves else 0)
            return ('<hierarchy><node class="android.widget.ScrollView" package="org.emulebb.android" bounds="[0,24][1080,1800]">'
                    '<node resource-id="org.emulebb.android:id/service_status" text="Stopped" bounds="[0,' + str(y) + '][500,200]"/>'
                    '<node text="' + private + '"/></node></hierarchy>')
        if call == ("shell", "dumpsys", "input_method"):
            if ime == "query-failed":
                raise RuntimeError(private)
            if ime == "oversize":
                return "mInputShown=true " + "x" * 65536
            if ime == "ambiguous":
                return "mInputShown=true mInputShown=false " + private
            return "mInputShown=" + ime + " " + private
        return ""

    ui = subject.ProductionUi(command)
    with pytest.raises(RuntimeError, match="not reachable"):
        ui.find("start_service", enabled=True)
    facts = ui.failure_navigation()
    assert facts["control"] == "start_service" and facts["control"] in subject.APK_NAVIGATION_CONTROLS
    assert facts["displayBounds"] == [0, 0, 1080, 1920]
    assert facts["scrollBounds"] == [0, 24, 1080, 1800]
    assert facts["lastGesture"] == [540, 480, 540, 1440]
    assert {field: facts[field] for field in ("forwardAttempts", "backwardAttempts", "forwardProgress", "backwardProgress")} == {
        "forwardAttempts": 6, "backwardAttempts": 6,
        "forwardProgress": 6 if moves else 0, "backwardProgress": 6 if moves else 0}
    assert facts.get("imeVisible") == ({"true": True, "false": False}.get(ime))
    assert private not in json.dumps(facts)
    assert not any(call[:3] == ("shell", "input", "tap") for call in calls)


@pytest.mark.parametrize("fault", ["null-root", "idle-timeout", "silent-no-write", "partial-write", "invalidation-failed", None])
def test_each_hierarchy_requires_a_fresh_owned_dump_before_controls_can_authorize_a_tap(fault):
    files, calls = {}, []
    old = ('<hierarchy><node resource-id="org.emulebb.android:id/service_status" text="Stopped"/>'
           '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[50,500][150,600]"/>'
           '<node resource-id="org.emulebb.android:id/api_key" text="synthetic-private-old-key"/></hierarchy>')
    fresh = old.replace("[50,500][150,600]", "[300,500][400,600]").replace("old-key", "fresh-key")

    def command(*args):
        call = args[2:]
        calls.append(call)
        if call == ("shell", "wm", "size"):
            return "Physical size: 1080x1920"
        if call[:3] == ("shell", "rm", "-f"):
            assert call == ("shell", "rm", "-f", ui.path)
            if fault == "invalidation-failed":
                raise RuntimeError("Owned Android ADB command failed")
            files.pop(ui.path, None)
        if call[:3] == ("shell", "uiautomator", "dump"):
            assert ui.path not in files, "each dump must invalidate its previous owned hierarchy"
            if fault == "null-root":
                return "ERROR: null root node returned by UiTestAutomationBridge."
            if fault == "idle-timeout":
                return "ERROR: could not get idle state."
            if fault == "silent-no-write":
                return ""
            files[ui.path] = "<hierarchy>" if fault == "partial-write" else fresh
            return "UI hierchary dumped to: " + ui.path
        if call[:2] == ("shell", "cat"):
            if ui.path not in files:
                raise RuntimeError("Owned Android ADB command failed")
            return files[ui.path]
        return ""

    ui = subject.ProductionUi(command)
    files[ui.path] = old
    if fault is not None:
        with pytest.raises(RuntimeError, match="ADB command failed|dump is malformed"):
            ui.click("start_service")
        assert not any(call[:3] == ("shell", "input", "tap") for call in calls)
        assert ui.setup_observation == {}
        if fault == "invalidation-failed":
            assert files[ui.path] == old
            assert not any(call[:2] in {("shell", "cat"), ("shell", "uiautomator")} for call in calls)
        else:
            assert files.get(ui.path) != old
    else:
        ui.click("start_service")
        assert ("shell", "input", "tap", "350", "550") in calls
        dumps = [index for index, call in enumerate(calls) if call[:3] == ("shell", "uiautomator", "dump")]
        assert len(dumps) == 2 and all(calls[index - 1] == ("shell", "rm", "-f", ui.path) for index in dumps)
    assert "synthetic-private" not in json.dumps(ui.setup_observation)


def boot_dumps():
    """Use AOSP-targeted dump shapes; synthetic private values must stay transient."""
    private = "synthetic-private-diagnostic-text"
    return {
        ("am", "get-started-user-state", "0"): "RUNNING_UNLOCKED",
        ("dumpsys", "package", subject.APPLICATION_ID): (
            "Packages:\n  Package [org.emulebb.android] (owned):\n"
            "    User 0: installed=true hidden=false stopped=false\n"
            "      runtime permissions:\n"
            "        android.permission.POST_NOTIFICATIONS: granted=true, flags=[ USER_SET ]\n"
            "        android.permission.ACCESS_LOCAL_NETWORK: granted=false, flags=[ USER_SET ]\n"),
        ("cmd", "package", "query-receivers", "--brief", "--user", "0", "-a",
         "android.intent.action.BOOT_COMPLETED", "-p", subject.APPLICATION_ID): "1 receivers found:\norg.emulebb.android/.BootReceiver\n",
        ("dumpsys", "activity", "services", subject.APPLICATION_ID): (
            "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n"
            "  * ServiceRecord{123 u0 org.emulebb.android/.DaemonService}\n"
            "    isForeground=false startRequested=true\n    " + private),
        ("appops", "get", "--user", "0", subject.APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE"): "MANAGE_EXTERNAL_STORAGE: allow; " + private,
        ("dumpsys", "deviceidle", "whitelist"): "system,com.android.example,1000\nuser,org.emulebb.android,10123\n",
        ("am", "get-bg-restriction-level", "--user", "0", subject.APPLICATION_ID): "background_restricted",
        ("dumpsys", "activity", "exit-info", subject.APPLICATION_ID): (
            "ACTIVITY MANAGER PROCESS EXIT INFO (dumpsys activity exit-info)\n"
            "  package: org.emulebb.android\n"
            "    ApplicationExitInfo #0:\n"
            "      timestamp=2026-01-02 03:04:05.006 pid=41 realUid=10123 packageUid=10123 definingUid=10123 user=0\n"
            "      process=org.emulebb.android:daemon reason=8 (PERMISSION CHANGE) subreason=0 (UNKNOWN) status=0\n"
            "      description=" + private + " trace=" + private + "\n"
            "    ApplicationExitInfo #1:\n"
            "      timestamp=2026-01-01 03:04:05.006 pid=42 realUid=10123 packageUid=10123 definingUid=10123 user=0\n"
            "      process=org.emulebb.android:daemon reason=10 (USER REQUESTED) subreason=0 (UNKNOWN) status=0\n"
            "    ApplicationExitInfo #2:\n"
            "      timestamp=2026-01-03 03:04:05.006 pid=43 realUid=10123 packageUid=10123 definingUid=10123 user=0\n"
            "      process=org.emulebb.android reason=4 (CRASH) subreason=0 (UNKNOWN) status=0\n"),
    }


def test_boot_timeout_facts_select_exact_owned_process_user_and_only_closed_values():
    documents = boot_dumps()
    facts = subject._boot_timeout_facts(lambda *args: documents[args], api=37)
    assert facts == {"userUnlocked": True, "packageStopped": False, "notificationsGranted": True,
                     "localNetworkGranted": False, "bootReceiverResolved": True, "servicePresent": True,
                     "serviceForeground": False, "serviceStartRequested": True, "allFilesAllowed": True,
                     "dozeWhitelisted": True, "backgroundRestricted": True, "latestDaemonExitReason": 8}
    assert "synthetic-private" not in json.dumps(facts)


@pytest.mark.parametrize("fault", ["unknown", "oversize", "query-failed"])
def test_boot_timeout_unknown_or_unavailable_queries_are_omitted_not_false(fault):
    def read(*args):
        if fault == "query-failed":
            raise RuntimeError("synthetic-private-query-error")
        return "synthetic-private-unknown" if fault == "unknown" else "x" * 65537
    assert subject._boot_timeout_facts(read, api=37) == {}


def test_boot_timeout_foreign_ambiguous_and_unrecognized_facts_cannot_become_owned_false_flags():
    documents = boot_dumps()
    documents[("dumpsys", "package", subject.APPLICATION_ID)] = (
        "  Package [org.emulebb.android] (owned):\n    User 10: installed=true stopped=true\n"
        "  Package [org.emulebb.other] (foreign):\n    User 0: installed=true stopped=false\n")
    documents[("dumpsys", "activity", "services", subject.APPLICATION_ID)] = (
        "ACTIVITY MANAGER SERVICES\n  * ServiceRecord{123 u0 org.emulebb.other/.DaemonService}\n"
        "    isForeground=false startRequested=false\n")
    documents[("dumpsys", "activity", "exit-info", subject.APPLICATION_ID)] = documents[
        ("dumpsys", "activity", "exit-info", subject.APPLICATION_ID)].replace("user=0", "user=10")
    documents[("appops", "get", "--user", "0", subject.APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE")] = (
        "MANAGE_EXTERNAL_STORAGE: allow\nMANAGE_EXTERNAL_STORAGE: deny\n")
    documents[("dumpsys", "deviceidle", "whitelist")] = "unrecognized whitelist format"
    facts = subject._boot_timeout_facts(lambda *args: documents[args], api=37)
    assert not {"packageStopped", "notificationsGranted", "localNetworkGranted", "servicePresent",
                "serviceForeground", "serviceStartRequested", "latestDaemonExitReason", "allFilesAllowed",
                "dozeWhitelisted"} & set(facts)


@pytest.mark.parametrize("collector_fails", [False, True])
def test_boot_timeout_collects_before_cleanup_without_launch_and_cannot_turn_failure_into_pass(tmp_path, monkeypatch, collector_fails):
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.api = 36
    documents = boot_dumps()

    def command(*args, **kwargs):
        raw = peer.command(*args, **kwargs)
        if args[2:] == ("reboot",):
            peer.running = False
        if args[2:5] == ("shell", "am", "force-stop"):
            raise RuntimeError("synthetic-private-cleanup-error")
        if peer.boot_id > 0 and args[2:3] == ("shell",) and args[3:] in documents:
            return documents[args[3:]]
        return raw

    if collector_fails:
        def failed_collector(*args, **kwargs):
            raise RuntimeError("synthetic-private-collector-error")
        monkeypatch.setattr(subject, "_boot_timeout_facts", failed_collector)
    with pytest.raises(RuntimeError, match="did not resume after an enabled reboot"):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    failure = result["failure"]
    assert failure["stage"] == "enabled-reboot-authentication" and failure["code"] == "boot-resume-timeout"
    assert failure["boot"]["restAttempts"] == failure["boot"]["restConnectionFailures"] == 91
    assert failure["boot"]["restHttpResponses"] == 0
    assert "lastHttpStatus" not in failure["boot"]
    if collector_fails:
        assert set(failure["boot"]) == {"restAttempts", "restConnectionFailures", "restHttpResponses"}
    else:
        assert failure["boot"]["userUnlocked"] is True
        query = next(index for index, args in enumerate(peer.calls) if args[2:] == ("shell", "am", "get-started-user-state", "0"))
        cleanup = next(index for index, args in enumerate(peer.calls) if args[2:5] == ("shell", "am", "force-stop"))
        assert query < cleanup
    reboot = next(index for index, args in enumerate(peer.calls) if args[2:] == ("reboot",))
    assert not any(args[2:5] == ("shell", "am", "start") for args in peer.calls[reboot:])
    assert result["status"] == "failed" and result["runtimeExecution"] == "executed"
    assert len(result["cases"]) == 7 and "enabled-boot-resume" not in {case["name"] for case in result["cases"]}
    assert result["cleanupErrors"] == [{"action": "force-stop", "errorType": "RuntimeError"}]
    assert "synthetic-private" not in json.dumps(result) and peer.key not in json.dumps(result)


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
