"""APK admission and production controls reject substituted or ambiguous evidence."""
import hashlib
import json

import pytest

from emule_test_harness import android_apk_lifecycle as subject

SOURCE = "a" * 40


def test_initial_app_not_visible_records_original_launch_and_precleanup_facts(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    def command(*arguments, **kwargs):
        args = arguments[2:]
        result = peer.command(*arguments, **kwargs)
        if args[:3] == ('shell', 'am', 'start'):
            return 'Status: ok\nprivate-launch-data'
        if args[:2] == ('shell', 'cat') and '/emulebb-apk-ui-' in args[-1]:
            return '<hierarchy><node resource-id="com.android.launcher:id/workspace"/></hierarchy>'
        if args == ('shell', 'dumpsys', 'window', 'policy'):
            return 'mKeyguardShowing=false\nprivate-data'
        if args == ('shell', 'dumpsys', 'activity', 'activities'):
            return 'topResumedActivity=ActivityRecord{a u0 other.package/.Home t1}\nprivate-data'
        if args == ('shell', 'dumpsys', 'window', 'windows'):
            return 'Window #0 Window{a u0 other.package/.Home}:\nprivate-data'
        if args == ('shell', 'pidof', subject.APPLICATION_ID):
            return '1234'
        return result
    with pytest.raises(subject.DeviceUiUnavailable):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / 'apk-lifecycle.json').read_text())
    assert result['failure']['code'] == 'app-not-visible'
    assert result['failure']['initialLaunch'] == {'result': 'ok', 'resumed': 'other', 'window': 'absent',
                                                  'process': 'present', 'keyguard': 'hidden'}
    cleanup = next(index for index, call in enumerate(peer.calls) if call[2:5] == ('shell', 'am', 'force-stop'))
    assert all(next(index for index, call in enumerate(peer.calls) if call[2:] == command) < cleanup for command in (
        ('shell', 'dumpsys', 'activity', 'activities'), ('shell', 'dumpsys', 'window', 'windows'),
        ('shell', 'pidof', subject.APPLICATION_ID)))
    assert sum(call[2:5] == ('shell', 'am', 'start') for call in peer.calls) == 1
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize("api", [34, 35, 36, 37])
def test_trusted_case_contract_has_an_explicit_per_api_permission_matrix(api):
    cases = subject.required_apk_cases(api)
    assert {"local-transfer-and-delivery-collision", "completed-delivery-survives-restart",
            "file-link-intents-and-webui-confirmation", "screen-off-doze-observation"} <= cases
    assert {"explicit-stop-remains-stopped", "task-manager-stop-remains-stopped",
            "force-stop-remains-stopped", "restart"} <= cases
    assert not any("boot" in case for case in cases)
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


@pytest.mark.parametrize('label,expected', [
    ('Waiting for a usable default network', 'waiting'), ('', 'not-waiting'),
    ('private-value', 'unavailable'), (None, 'unavailable'), ('duplicate', 'unavailable'),
])
def test_network_wait_and_phase_are_same_snapshot_closed_values(label, expected):
    node = '' if label is None else '<node package="org.emulebb.android" resource-id="org.emulebb.android:id/network_wait_status" text="' + ('private-value' if label == 'duplicate' else label) + '"/>'
    if label == 'duplicate':
        node += node
    xml = '<hierarchy><node package="org.emulebb.android" resource-id="org.emulebb.android:id/service_status" text="Starting"/>' + node + '</hierarchy>'
    ui = subject.ProductionUi(lambda *args: xml if args[-2:-1] == ('cat',) else '')
    if label == 'duplicate':
        with pytest.raises(RuntimeError, match='ambiguous'):
            ui.inspect()
    else:
        ui.inspect()
    assert ui.setup_observation['networkWait'] == {'state': expected, 'phase': 'Starting'}
    assert 'private-value' not in json.dumps(ui.setup_observation)


def test_campaign_failure_carries_only_closed_typed_details():
    from emule_test_harness.android_apk_peer import CampaignFailure
    failure = {'phase': 'await-completed-delivery', 'code': 'await-completed-delivery-failed',
        'errorType': 'private', 'rest': {'httpStatus': 409, 'apiCode': 'DOWNLOAD_CONFLICT',
            'coreContext': 'unrecognized', 'raw': 'private'},
        'adb': {'operation': 'push', 'reason': 'no-space', 'exitCode': 7, 'raw': 'private'},
        'ownedFixture': {'code': 'inventory-invalid', 'filesRemoved': 1, 'raw': 'private'}}
    result = subject._lifecycle_failure(CampaignFailure(failure), 'local-transfer', {})
    assert result['code'] == 'other'
    assert result['transfer'] == {'phase': 'await-completed-delivery', 'code': 'await-completed-delivery-failed',
        'rest': {'httpStatus': 409, 'apiCode': 'DOWNLOAD_CONFLICT', 'coreContext': 'unrecognized'},
        'adb': {'operation': 'push', 'reason': 'no-space', 'exitCategory': 'nonzero'},
        'ownedFixture': {'code': 'inventory-invalid', 'filesRemoved': 1}}
    assert 'private' not in json.dumps(result)
    failure['phase'] = 'private'
    assert 'transfer' not in subject._lifecycle_failure(CampaignFailure(failure), 'local-transfer', {})


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
            return "topResumedActivity=ActivityRecord{abc u0 com.android.browser/.MainActivity t1}"
        if args[:3] == ("shell", "am", "start") and "-d" in args:
            import shlex
            link = shlex.split(args[args.index("-d") + 1])[0]
            valid = "00112233445566778899aabbccddeeff" in link
            self.pending_link = link if valid or self.accept_invalid else ""
            self.pending_error = "" if self.pending_link else "Unsupported or malformed eD2K file link"
            if self.intent_autostart:
                self.running = True
        if args == ("shell", "wm", "size"):
            return "Physical size: 1080x1920"
        if args == ("shell", "getprop", "ro.build.version.sdk"):
            return str(self.api)
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
                    + '"/>'
                    '<node resource-id="org.emulebb.android:id/pending_link" text="' + self.pending_link + '"/>'
                    '<node resource-id="org.emulebb.android:id/pending_link_error" text="' + self.pending_error + '"/>'
                    '<node resource-id="org.emulebb.android:id/open_webui" enabled="true" bounds="[600,500][700,600]"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,500][100,600]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,500][300,600]"/>'
                    '</hierarchy>')
        if args[:3] == ("shell", "input", "tap"):
            if args[3] == "650":
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


def test_transient_delayed_restart_after_task_manager_stop_cannot_pass_stopped_observation(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    clock, state = [0.0], {'taskStopped': False, 'reopened': None, 'responded': False}
    monkeypatch.setattr(subject.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(subject.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    def command(*args, **kwargs):
        result = peer.command(*args, **kwargs)
        if args[2:6] == ('shell', 'cmd', 'activity', 'stop-app'):
            state['taskStopped'] = True
        if state['taskStopped'] and args[2:5] == ('shell', 'am', 'start'):
            state['reopened'] = clock[0]
        return result
    def request(*args, **kwargs):
        if state['reopened'] is not None and clock[0] - state['reopened'] >= 10 and not state['responded']:
            state['responded'] = True
            return 200, b'{}'
        return peer.request(*args, **kwargs)
    monkeypatch.setattr(subject, '_request', request)
    with pytest.raises(RuntimeError, match='listener running'):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / 'apk-lifecycle.json').read_text())
    assert result['failure']['stage'] == 'task-manager-stop'
    assert 'task-manager-stop-remains-stopped' not in {case['name'] for case in result['cases']}


def test_home_must_leave_app_foreground_before_screen_off(tmp_path, monkeypatch):
    peer, admitted = guest(tmp_path, monkeypatch)
    def command(*args, **kwargs):
        result = peer.command(*args, **kwargs)
        if args[2:] == ('shell', 'dumpsys', 'activity', 'activities'):
            return 'topResumedActivity=ActivityRecord{abc u0 org.emulebb.android/.MainActivity t1}'
        return result
    with pytest.raises(RuntimeError, match='activity did not leave'):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / 'apk-lifecycle.json').read_text())
    assert result['failure']['stage'] == 'screen-off-doze' and 'endurance' not in result
    assert not any(call[2:] == ('shell', 'input', 'keyevent', 'KEYCODE_SLEEP') for call in peer.calls)


def test_screen_off_failure_retains_exact_substage_and_closed_adb_category(tmp_path, monkeypatch):
    from emule_test_harness.android_adb_failure import AdbOperationFailure
    peer, admitted = guest(tmp_path, monkeypatch)
    def command(*args, **kwargs):
        if args[2:] == ('shell', 'dumpsys', 'battery', 'unplug'):
            raise AdbOperationFailure(args[2:], exit_code=1, stderr='permission denied private',
                                      message='Owned Android ADB command failed')
        return peer.command(*args, **kwargs)
    with pytest.raises(RuntimeError, match='Owned Android ADB command failed'):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / 'apk-lifecycle.json').read_text())
    assert result['failure']['stage'] == 'screen-off-doze'
    assert result['failure']['code'] == 'adb-command-failed' and result['failure']['substage'] == 'unplug'
    assert result['failure']['adb'] == {'operation': 'shell-dumpsys', 'reason': 'permission-denied', 'exitCategory': 'nonzero'}
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize("secure", [False, True])
def test_initial_owned_guest_wakes_and_dismisses_only_insecure_keyguard_before_ui_read(tmp_path, monkeypatch, secure):
    peer, admitted = guest(tmp_path, monkeypatch)
    display = {"awake": False, "locked": True, "firstUiRead": None}

    def command(*arguments, **kwargs):
        args = arguments[2:]
        result = peer.command(*arguments, **kwargs)
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
    expected.extend(["explicit-stop-remains-stopped",
                     "task-manager-stop-remains-stopped", "force-stop-remains-stopped",
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
    assert result["endurance"]["activityClosed"] is True
    assert not any(call[2:] == ("reboot",) for call in peer.calls)
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


@pytest.mark.parametrize("failure", [None, "autostart", "invalid", "browser", "android-resolver", "modern-resolver", "enqueue", "browser-proof"])
def test_real_intent_dispatch_requires_user_start_and_explicit_browser_confirmation(tmp_path, monkeypatch, failure):
    from emule_test_harness import rust_local_ed2k, rust_webui_live_proof
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.intent_autostart = failure == "autostart"
    peer.accept_invalid = failure == "invalid"
    peer.browser = failure != "browser"
    baseline = [{"hash": "b" * 32, "sizeBytes": 262144}]
    browser_calls = []
    resolver = {"android-resolver": "android/com.android.internal.app.ResolverActivity",
                "modern-resolver": "com.android.intentresolver/.ResolverActivity"}.get(failure)

    def command(*args, **kwargs):
        value = peer.command(*args, **kwargs)
        if resolver:
            if args[2:6] == ("shell", "cmd", "package", "resolve-activity") and "ed2k:" not in args[-1]:
                return resolver
            if args[2:6] == ("shell", "dumpsys", "activity", "activities"):
                # Even a visible resumed resolver must not count as a browser.
                return "mResumedActivity: " + resolver
        return value

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
                    "browser-proof": "did not finish cleanly", "android-resolver": "installed guest default browser",
                    "modern-resolver": "installed guest default browser"}
        with pytest.raises(RuntimeError, match=messages[failure]):
            subject.exercise(command, admitted, report_dir=tmp_path, qualify_file_links=True)
        result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
        assert result["status"] == result["fileLinks"]["status"] == "failed"
        if resolver:
            assert not browser_calls
            assert "native-browser-dispatch-without-enqueue" not in {case["name"] for case in result["fileLinks"]["cases"]}
    else:
        result = subject.exercise(command, admitted, report_dir=tmp_path, qualify_file_links=True)
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
            visible = {"service_status", "api_key"} if viewport[0] == 0 else {"start_service", "stop_service"}
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
                                    "api_key": {"present": True, "enabled": True}}
    assert observed.get("servicePhase") == (phase if phase in subject.SETUP_SERVICE_PHASES else None)
    assert "synthetic-private" not in json.dumps(observed)


@pytest.mark.parametrize("error,code", [
    (RuntimeError("Owned Android ADB command failed"), "adb-command-failed"),
    (subject.DeviceUiUnavailable("device-locked"), "device-locked"),
    (subject.DeviceUiUnavailable("app-not-visible"), "app-not-visible"),
    (RuntimeError("APK required control remains disabled: api_key"), "control-disabled"),
    (RuntimeError("APK required control is not reachable: api_key"), "control-unreachable"),
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
        assert ui.setup_observation == {"networkWait": {"state": "unavailable"}}
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


def test_initial_visibility_facts_do_not_retain_unrelated_values():
    docs = {('dumpsys', 'activity', 'activities'): 'topResumedActivity=ActivityRecord{a u0 org.emulebb.android/.MainActivity t1}\n',
            ('dumpsys', 'window', 'windows'): 'Window #0 Window{a u0 org.emulebb.android/org.emulebb.android.MainActivity}:\n',
            ('pidof', subject.APPLICATION_ID): '1234',
            ('dumpsys', 'window', 'policy'): 'mKeyguardShowing=false\n'}
    facts = subject._initial_visibility_facts(lambda *args: docs.get(args, '') + '\nprivate-value')
    assert facts == {'resumed': 'owned', 'window': 'present', 'process': 'unavailable', 'keyguard': 'hidden'}
    assert 'private' not in json.dumps(facts)
    docs[('dumpsys', 'window', 'windows')] = 'Window #0 Window{a u0 org.emulebb.android/org.emulebb.android.MainActivity.Other}:\n'
    docs[('dumpsys', 'activity', 'activities')] = 'topResumedActivity=ActivityRecord{a u0 org.emulebb.android/.MainActivity.Other t1}\n'
    facts = subject._initial_visibility_facts(lambda *args: docs.get(args, ''))
    assert facts['window'] == 'absent' and facts['resumed'] == 'other'
    docs[('dumpsys', 'window', 'windows')] = 'Window #0 Window{a u0 org.emulebb.android/org.emulebb.android.MainActivity-extra}:\n'
    assert subject._initial_visibility_facts(lambda *args: docs.get(args, ''))['window'] == 'absent'


@pytest.mark.parametrize("message,category", [
    ("Android refused the foreground service: ForegroundServiceStartNotAllowedException", "foreground-promotion-denied"),
    ("All-files access was revoked; stopping the daemon", "required-files-permission"),
    ("Local-network permission is required. Open the app to grant it.", "required-local-network-permission"),
    ("Repeated service termination; open the app and press Start to retry", "recovery-budget-blocked"),
    ("Android refused the foreground service: synthetic-private-error", "unknown"),
    ("synthetic-private-arbitrary-error", "unknown"),
])
def test_post_failure_ui_projects_only_exact_known_errors_from_own_text_labels(message, category):
    from types import SimpleNamespace
    ui = SimpleNamespace(find=lambda name, **kwargs: {"text": "Stopped"},
        elements=lambda: [{"package": subject.APPLICATION_ID, "class": "android.widget.TextView",
                           "resource-id": subject.APPLICATION_ID + ":id/service_status", "text": "Stopped"},
                          {"package": subject.APPLICATION_ID, "class": "android.widget.TextView", "text": message},
                          {"package": subject.APPLICATION_ID, "class": "android.widget.EditText", "text": "synthetic-private-key"},
                          {"package": "com.android.other", "class": "android.widget.TextView",
                           "text": "All-files access was revoked; stopping the daemon"}])
    facts = subject._post_failure_ui(ui)
    assert facts == ({"errorCategory": "unknown"} if category == "unknown" else {"servicePhase": "Stopped", "errorCategory": category})
    assert category in subject.APK_POST_FAILURE_ERROR_CATEGORIES
    assert "synthetic-private" not in json.dumps(facts)


@pytest.mark.parametrize("message,category", [
    ("Cannot load the packaged native daemon", "native-library-unavailable"),
    ("Open eMuleBB and complete setup before starting", "bootstrap-unavailable"),
    ("Payload storage is unavailable", "payload-storage-unavailable"),
    ("Packaged WebUI is incomplete", "webui-assets-invalid"),
    ("Cannot persist service state", "lifecycle-state-write-failed"),
    ("Native runtime failed", "native-runtime-failed"),
    ("Cannot inspect native runtime", "native-status-failed"),
    ("Native Stop failed", "native-stop-failed"),
    ("process logging state unavailable", "native-protocol-invalid"),
    ("previous runtime is still draining", "native-ownership-conflict"),
    ("invalid bootstrap: synthetic-private-context", "bootstrap-invalid"),
    ("rest.api_key must contain at least 32 bytes of secret material", "bootstrap-invalid"),
    ("invalid REST bind address: synthetic-private-context", "bootstrap-invalid"),
    ("failed to read settings synthetic-private-path: Permission denied (os error 13)", "bootstrap-io"),
    ("failed to publish bootstrap settings: synthetic-private-cause", "bootstrap-io"),
    ("profile settings synthetic-private-path have mode 644; rest.api_key requires owner-only permissions (chmod 600)", "bootstrap-invalid"),
    ("profile is already in use: synthetic-private-path; stop its daemon or offline command before retrying", "profile-ownership"),
    ("failed to resolve writable profile synthetic-private-path: synthetic-private-cause", "profile-ownership"),
    ("failed to open metadata store under synthetic-private-path: Permission denied (os error 13)", "metadata-startup"),
    ("failed to load daemon settings: synthetic-private-cause", "metadata-startup"),
    ("invalid NAT config in metadata store", "metadata-startup"),
    ("failed to create incoming dir synthetic-private-path: Permission denied (os error 13)", "incoming-storage"),
    ("rest.web_root_dir must contain index.html: synthetic-private-path", "webui-assets-invalid"),
    ("failed to bind REST/WebUI TCP listener at synthetic-private-address: Address in use (os error 98)", "rest-listen-failed"),
    ("failed to install the process logging subscriber: synthetic-private-cause", "logging-init-failed"),
    ("embedded host readiness receiver closed during startup", "native-host-invalid"),
    ("p2pBindIp or p2pBindInterface is required because no default-route IPv4 interface was detected; start with --p2p-bind-interface <NAME>, then save the P2P bind interface in WebUI Settings > Network", "network-default-route-missing"),
    ("p2pBindIp or p2pBindInterface is required because multiple default-route IPv4 interfaces were detected; start with --p2p-bind-interface <NAME>, then save the P2P bind interface in WebUI Settings > Network", "network-default-route-ambiguous"),
    ("p2pBindIp or p2pBindInterface is required when VPN Guard blocks public P2P", "network-binding-invalid"),
    ("p2pBindInterface synthetic-private-interface did not resolve to an IPv4 address", "network-binding-invalid"),
    ("p2pBindInterface synthetic-private-interface is ambiguous", "network-binding-invalid"),
    ("p2pBindInterface synthetic-private-interface resolved to non-IPv4 address synthetic-private-address", "network-binding-invalid"),
    ("failed to enumerate local interfaces: synthetic-private-cause", "network-interface-inventory-failed"),
    ("kad.listenPort is required when ED2K servers are configured", "network-config-invalid"),
    ("ed2k.listenPort is required when ED2K servers are configured", "network-config-invalid"),
])
def test_post_failure_source_stage_wins_over_dynamic_path_and_lower_level_errno(message, category):
    result = subject._post_failure_error_category(message)
    assert result == category and result in subject.APK_POST_FAILURE_ERROR_CATEGORIES
    assert "synthetic-private" not in result


@pytest.mark.parametrize("number,category", [
    (1, "os-access-denied"), (2, "os-path-missing"), (5, "os-io-failed"), (11, "os-resource-unavailable"),
    (12, "os-resource-unavailable"), (13, "os-access-denied"), (17, "os-operation-failed"), (20, "os-operation-failed"),
    (21, "os-operation-failed"), (22, "os-operation-failed"), (24, "os-resource-unavailable"), (28, "os-storage-full"),
    (30, "os-storage-readonly"), (38, "os-operation-failed"), (95, "os-operation-failed"), (98, "os-address-in-use"),
    (99, "os-address-unavailable"),
])
def test_bare_rust_os_errors_have_only_finite_terminal_categories(number, category):
    assert subject._post_failure_error_category(f"synthetic-private-value (os error {number})") == category
    assert subject._post_failure_error_category(f"synthetic-private-value (os error {number}) trailing text") == "unknown"


@pytest.mark.parametrize("suffix,category", [
    ("No such file or directory", "os-path-missing"), ("Permission denied", "os-access-denied"),
    ("Read-only file system", "os-storage-readonly"), ("No space left on device", "os-storage-full"),
])
def test_bare_jvm_io_errors_discard_path_and_match_only_exact_terminal_signature(suffix, category):
    assert subject._post_failure_error_category("synthetic-private-path (" + suffix + ")") == category
    assert subject._post_failure_error_category("synthetic-private-path (" + suffix + ") trailing text") == "unknown"


@pytest.mark.parametrize("message", [
    "synthetic-private-path: permission socket SQLite failure", "Permission denied", "No such file or directory",
    "synthetic-private-value (os error 100)", "synthetic-private-value (os error 101)",
    "synthetic-private-value (os error 013)", "synthetic-private-value (os error -13)",
    "synthetic text: failed to read settings synthetic-private-path",
    "failed to load daemon settingsX: synthetic-private-cause", "invalid REST bind addressed synthetic-private-value",
    "profile settings synthetic-private-path without exact permission suffix",
])
def test_unmatched_error_text_does_not_become_an_invented_stage_or_errno(message):
    assert subject._post_failure_error_category(message) == "unknown"


@pytest.mark.parametrize("fault", ["missing-error", "credential", "other-window", "named-help", "duplicate-status", "missing-status"])
def test_post_failure_error_context_cannot_come_from_key_help_or_another_window(fault):
    from types import SimpleNamespace
    status = {"resource-id": subject.APPLICATION_ID + ":id/service_status", "package": subject.APPLICATION_ID,
              "class": "android.widget.TextView", "text": "Stopped"}
    error = {"package": subject.APPLICATION_ID, "class": "android.widget.TextView", "text": "Cannot load the packaged native daemon"}
    nodes = [status, error]
    if fault == "missing-error":
        nodes = [status, {**error, "text": "Files: allowed; synthetic-private-key"},
                 {**error, "resource-id": subject.APPLICATION_ID + ":id/api_key", "class": "android.widget.EditText"}]
    elif fault == "credential":
        nodes[1] = {**error, "class": "android.widget.EditText", "text": "failed to read settings synthetic-private-key"}
    elif fault == "other-window":
        nodes[1] = {**error, "package": "com.android.other"}
    elif fault == "named-help":
        nodes[1] = {**error, "resource-id": subject.APPLICATION_ID + ":id/storage_paths"}
    elif fault == "duplicate-status":
        nodes += [status, error]
    elif fault == "missing-status":
        nodes = [error]
    ui = SimpleNamespace(find=lambda name, **kwargs: {"text": "Stopped"},
                         elements=lambda: nodes)
    facts = subject._post_failure_ui(ui)
    assert facts == {"errorCategory": "unknown"}


@pytest.mark.parametrize("observer_fails", [False, True])
def test_initial_failed_service_uses_existing_ui_error_without_relaunch_or_replacing_primary_failure(tmp_path, monkeypatch, observer_fails):
    import xml.etree.ElementTree as ET
    peer, admitted = guest(tmp_path, monkeypatch)
    peer.api = 34
    start_seen = [False]

    def command(*args, **kwargs):
        raw = peer.command(*args, **kwargs)
        if args[2:6] == ("shell", "input", "tap", "50"):
            start_seen[0] = True
        if start_seen[0] and args[2:4] == ("shell", "cat") and "/emulebb-apk-ui-" in args[-1]:
            root = ET.fromstring(raw)
            for index, node in enumerate(root):
                if node.get("resource-id") == subject.APPLICATION_ID + ":id/service_status":
                    node.set("text", "Failed")
                    root.insert(index + 1, ET.Element("node", {
                        "package": subject.APPLICATION_ID, "class": "android.widget.TextView",
                        "text": "failed to create incoming dir synthetic-private-path: Permission denied (os error 13)"}))
                    break
            return ET.tostring(root, encoding="unicode")
        return raw

    if observer_fails:
        def unavailable(*args, **kwargs):
            raise RuntimeError("synthetic-private-observer-error")
        monkeypatch.setattr(subject, "_post_failure_ui", unavailable)
    with pytest.raises(RuntimeError, match="APK did not reach expected service state: Running"):
        subject.exercise(command, admitted, report_dir=tmp_path)
    result = json.loads((tmp_path / "apk-lifecycle.json").read_text())
    failure = result["failure"]
    assert failure["stage"] == "initial-wait-running" and failure["code"] == "expected-state-not-reached"
    assert failure["servicePhase"] == "Failed"
    assert result["status"] == "failed" and result["runtimeExecution"] == "not-run"
    assert [case["name"] for case in result["cases"]] == ["installed-apk-identity", "fresh-setup"]
    if observer_fails:
        assert "postFailureUi" not in failure
    else:
        assert failure["postFailureUi"] == {"servicePhase": "Failed", "errorCategory": "incoming-storage"}
    assert len([args for args in peer.calls if args[2:5] == ("shell", "am", "start")]) == 1
    assert [args[2:] for args in peer.calls if args[2:5] == ("shell", "input", "tap")] == [("shell", "input", "tap", "50", "550")]
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
