"""Physical qualification preserves operator transports, profiles and phone data."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import android_apk_device as subject

SERIAL = "synthetic-phone._adb-tls-connect._tcp"
KEY = "synthetic-private-key-not-for-receipts"


def payload():
    return {"apk": {"sha256": "a" * 64}, "signerSha256": "b" * 64, "versionCode": 42, "debug": False,
            "buildIdentity": {"sourceRevision": "c" * 40, "version": "0.1.0-test", "channel": "development"},
            "payloadPath": "synthetic.apk"}


class Phone:
    def __init__(self):
        self.calls = []
        self.installed = False
        self.retained = False
        self.checksum = "a" * 64
        self.permission = True
        self.notifications = True
        self.lan = True
        self.screen = "app"
        self.ambiguous_settings = False
        self.incoming = ""
        self.running = False
        self.forward = False
        self.foreign_forward = False
        self.start_fails = False
        self.phase = "Stopped"
        self.api = 36
        self.page_size = 16384
        self.unauthenticated = 401

    def command(self, *args, **kwargs):
        assert args[:2] == ("-s", SERIAL)
        self.calls.append(args[2:])
        args = args[2:]
        if args == ("get-state",):
            return "device"
        if args == ("shell", "am", "get-current-user"):
            return "0"
        if args == ("shell", "getconf", "PAGESIZE"):
            return str(self.page_size)
        if args[:2] == ("shell", "getprop"):
            return {"ro.build.version.sdk": str(self.api), "ro.product.cpu.abilist64": "arm64-v8a",
                    "ro.kernel.qemu": "0"}[args[2]]
        if args[:3] == ("shell", "pm", "path"):
            return "package:/data/app/synthetic/base.apk" if self.installed else ""
        if args[:3] == ("shell", "dumpsys", "package"):
            return "Package [org.emulebb.android]\nversionCode=42\nversionName=0.1.0-test" if self.installed or self.retained else "Unable to find package"
        if args[:2] == ("shell", "sha256sum"):
            return self.checksum + " " + args[2]
        if args[:1] == ("install",):
            assert not self.installed and "-r" not in args
            self.installed = True
        if args[:3] == ("shell", "appops", "get"):
            return "MANAGE_EXTERNAL_STORAGE: " + ("allow" if self.permission else "default")
        if args[:4] == ("shell", "cmd", "package", "check-permission"):
            allowed = self.notifications if args[4].endswith("POST_NOTIFICATIONS") else self.lan
            return "granted" if allowed else "denied"
        if args[:4] == ("shell", "dumpsys", "activity", "activities"):
            package = "com.android.settings" if self.screen == "files" else "com.google.android.permissioncontroller"
            return "mResumedActivity: " + package + "/.PermissionActivity"
        if args[:3] == ("shell", "am", "start") or args[:3] == ("shell", "input", "keyevent"):
            self.screen = "app"
        if args[:2] == ("shell", "sh"):
            return self.incoming
        if args == ("shell", "wm", "size"):
            return "Physical size: 1080x1920"
        if args[:2] == ("shell", "cat"):
            if self.screen == "files":
                toggle = '<node package="com.android.settings" checkable="true" enabled="true" checked="false" bounds="[0,0][100,100]"/>'
                return ('<hierarchy><node package="com.android.settings" text="eMuleBB"/>' + toggle
                        + (toggle.replace("[0,0][100,100]", "[200,0][300,100]") if self.ambiguous_settings else "") + '</hierarchy>')
            if self.screen in {"notifications", "lan"}:
                return ('<hierarchy><node package="com.google.android.permissioncontroller" text="Allow eMuleBB?"/>'
                        '<node package="com.google.android.permissioncontroller" clickable="true" enabled="true" '
                        'resource-id="com.google.android.permissioncontroller:id/permission_allow_button" bounds="[0,0][100,100]"/></hierarchy>')
            return ('<hierarchy><node resource-id="org.emulebb.android:id/service_status" text="' + self.phase + '"/>'
                    '<node resource-id="org.emulebb.android:id/api_key" enabled="true" text="' + KEY + '"/>'
                    '<node resource-id="org.emulebb.android:id/bind_addr" enabled="true" text="127.0.0.1:20017"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,0][300,100]"/>'
                    '<node resource-id="org.emulebb.android:id/grant_all_files_access" enabled="true" bounds="[400,0][500,100]"/>'
                    '<node resource-id="org.emulebb.android:id/allow_notifications" enabled="true" bounds="[600,0][700,100]"/>'
                    '<node resource-id="org.emulebb.android:id/allow_local_network" enabled="true" bounds="[800,0][900,100]"/>'
                    '</hierarchy>')
        if args[:3] == ("shell", "input", "tap"):
            if self.screen != "app":
                if self.screen == "files":
                    self.permission = True
                elif self.screen == "notifications":
                    self.notifications = True
                elif self.screen == "lan":
                    self.lan = True
                return ""
            if args[3] in {"450", "650", "850"}:
                self.screen = {"450": "files", "650": "notifications", "850": "lan"}[args[3]]
                return ""
            self.running = args[3] == "50" and not self.start_fails
            self.phase = "Failed" if args[3] == "50" and self.start_fails else "Running" if self.running else "Stopped"
        if args[:1] == ("forward",):
            if "--no-rebind" in args:
                self.forward = True
                return "54321"
            if "--list" in args:
                return (("other-device" if self.foreign_forward else SERIAL) + "  tcp:54321  tcp:20017") if self.forward else ""
            if "--remove" in args:
                assert not self.foreign_forward
                self.forward = False
        return ""

    def request(self, port, route, key=None):
        assert port == 54321
        if not self.running:
            raise ConnectionRefusedError()
        if route == "/":
            return 200, b"<html>synthetic bundle</html>"
        if route == "/api/v1/diagnostics":
            assert key == KEY
            return 200, json.dumps({"data": {"processResources": {
                "sampledAtMs": 1700000000000, "residentMemoryBytes": 67108864,
                "cpuUsagePercent": 125.5, "cpuSampleIntervalMs": 500}, "privateOtherData": KEY}}).encode()
        if key is None:
            return self.unauthenticated, b"{}"
        assert key == KEY
        return 200, json.dumps({"meta": {"apiVersion": "v1"}, "data": {
            **payload()["buildIdentity"], "name": "eMuleBB", "apiVersion": "v1", "lifecycle": {"state": "running"}}}).encode()


def run(tmp_path, monkeypatch, phone, *, execute=False, receipt=None):
    monkeypatch.setattr(subject, "_request", phone.request)
    clock = [0.0]
    monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    report_dir = tmp_path / ("resume" if receipt else "initial")
    return subject.probe_physical_device(phone.command, payload(), serial=SERIAL, output_root=tmp_path,
        expected_cert_sha256="b" * 64,
        report_dir=report_dir, execute=execute, dwell_seconds=15, installation_receipt=receipt,
        installation_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt else None)


@pytest.mark.parametrize("execute", [False, True])
@pytest.mark.parametrize("api,page_size", [(34, 4096), (35, 16384), (36, 4096), (37, 16384)])
def test_absent_install_and_bounded_smoke_preserve_phone_state(tmp_path, monkeypatch, execute, api, page_size):
    phone = Phone()
    phone.api, phone.page_size = api, page_size
    report = run(tmp_path, monkeypatch, phone, execute=execute)
    value = json.loads(report.read_text())
    assert value["status"] == "passed" and value["ownedInstallation"] is True
    assert value["runtimeExecution"] == ("executed" if execute else "not-run")
    assert value["transfer"] == value["endurance"] == "not-run"
    assert value["permissionChanges"] == [] and value["pageSizeBytes"] == page_size and value["abis64"] == ["arm64-v8a"]
    assert value["androidApiLevel"] == api and value["versionName"] == "0.1.0-test"
    assert phone.running is False and phone.forward is False
    assert SERIAL not in report.read_text() and KEY not in report.read_text()
    assert all(call[0] not in {"reboot", "uninstall", "kill-server", "disconnect", "start-server"} for call in phone.calls)
    assert all(call[:3] not in {("shell", "appops", "set"), ("shell", "pm", "clear"), ("shell", "pm", "grant"),
                               ("shell", "pm", "revoke"), ("shell", "am", "force-stop")} for call in phone.calls)
    if execute:
        assert value["networkIsolation"] == "not-claimed" and value["webui"]["rendered"] == "not-run"
        assert value["foregroundObservation"]["seconds"] == 15
        assert value["permissions"]["localNetwork"] == (True if api == 37 else "not-required")


@pytest.mark.parametrize("failure", ["different-apk", "retained", "unknown-profile", "foreign-incoming", "failed-start", "foreign-forward"])
def test_physical_admission_and_cleanup_refuse_foreign_state(tmp_path, monkeypatch, failure):
    phone = Phone()
    phone.installed = failure in {"different-apk", "unknown-profile"}
    phone.checksum = "d" * 64 if failure == "different-apk" else "a" * 64
    phone.retained = failure == "retained"
    phone.incoming = "foreign-user-file.bin" if failure == "foreign-incoming" else ""
    phone.start_fails = failure == "failed-start"
    phone.foreign_forward = failure == "foreign-forward"
    with pytest.raises(RuntimeError):
        run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads((tmp_path / "initial/physical-device.json").read_text())
    assert value["status"] == "failed"
    assert not phone.running
    assert value["runtimeExecution"] == ("executed" if failure == "foreign-forward" else "not-run")
    if failure in {"different-apk", "retained", "unknown-profile"}:
        assert not any(call[0] == "install" or call[:3] == ("shell", "am", "start") for call in phone.calls)
    if failure == "foreign-incoming":
        assert not any(call[:3] == ("shell", "input", "tap") for call in phone.calls)
    if failure == "foreign-forward":
        assert phone.forward and value["cleanupErrors"][0]["action"] == "remove-owned-forward"


def test_permission_setup_can_resume_only_its_hash_bound_installation(tmp_path, monkeypatch):
    phone = Phone()
    phone.permission = False
    phone.ambiguous_settings = True
    receipt = run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads(receipt.read_text())
    assert value["status"] == "setup-required" and value["runtimeExecution"] == "not-run"
    phone.permission = True
    report = run(tmp_path, monkeypatch, phone, execute=True, receipt=receipt)
    assert json.loads(report.read_text())["runtimeExecution"] == "executed"
    assert len([call for call in phone.calls if call[0] == "install"]) == 1


@pytest.mark.parametrize("api", [36, 37])
def test_normal_permission_ui_changes_only_denied_owned_app_grants(tmp_path, monkeypatch, api):
    phone = Phone()
    phone.api = api
    phone.permission = phone.notifications = phone.lan = False
    report = run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads(report.read_text())
    assert value["status"] == "passed"
    assert [change["permission"] for change in value["permissionChanges"]] == [
        "MANAGE_EXTERNAL_STORAGE", "POST_NOTIFICATIONS"] + (["ACCESS_LOCAL_NETWORK"] if api == 37 else [])
    assert all(change["before"] == "denied" and change["after"] == "granted" for change in value["permissionChanges"])
    assert value["processResources"]["residentMemoryBytes"] == 67108864
    assert value["processResources"]["cpuUsagePercent"] == 125.5
    assert not any(call[:3] == ("shell", "appops", "set") for call in phone.calls)
    assert not any(call[:3] == ("shell", "pm", "grant") for call in phone.calls)


def test_ambiguous_settings_never_guess_a_permission_toggle_or_start(tmp_path, monkeypatch):
    phone = Phone()
    phone.permission = False
    phone.ambiguous_settings = True
    report = run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads(report.read_text())
    assert value["status"] == "setup-required" and value["permissionChanges"] == []
    assert value["runtimeExecution"] == "not-run" and not phone.running
    assert [call for call in phone.calls if call[:3] == ("shell", "input", "tap")] == [
        ("shell", "input", "tap", "450", "50")]


@pytest.mark.parametrize("fault", ["foreground", "app-label", "checked", "disabled", "bad-bounds"])
def test_normal_settings_guard_requires_the_app_and_one_valid_off_toggle(tmp_path, monkeypatch, fault):
    phone = Phone()
    phone.permission = False
    command = phone.command

    def guarded(*args, **kwargs):
        result = command(*args, **kwargs)
        if args[2:6] == ("shell", "dumpsys", "activity", "activities") and fault == "foreground":
            return "mResumedActivity: com.android.other/.OtherActivity"
        if args[2:4] == ("shell", "cat") and phone.screen == "files":
            return result.replace({"app-label": "text=\"eMuleBB\"", "checked": "checked=\"false\"",
                                   "disabled": "enabled=\"true\"", "bad-bounds": "[0,0][100,100]"}.get(fault, "no-match"),
                                  {"app-label": "text=\"Other App\"", "checked": "checked=\"true\"",
                                   "disabled": "enabled=\"false\"", "bad-bounds": "[0,0][0,0]"}.get(fault, "no-replacement"))
        return result

    phone.command = guarded
    report = run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads(report.read_text())
    assert value["status"] == "setup-required" and value["permissionChanges"] == []
    assert phone.permission is False and phone.running is False


def test_permission_controller_resource_namespace_can_differ_from_package(tmp_path, monkeypatch):
    phone = Phone()
    phone.notifications = False
    command = phone.command

    def namespace(*args, **kwargs):
        result = command(*args, **kwargs)
        if args[2:4] == ("shell", "cat"):
            return result.replace("com.google.android.permissioncontroller:id/permission_allow_button",
                                  "com.android.permissioncontroller:id/permission_allow_button")
        return result

    phone.command = namespace
    report = run(tmp_path, monkeypatch, phone, execute=True)
    assert json.loads(report.read_text())["status"] == "passed" and phone.notifications is True


@pytest.mark.parametrize("changes", [{"residentMemoryBytes": 0}, {"sampledAtMs": None},
    {"cpuUsagePercent": float("nan")}, {"cpuUsagePercent": float("inf")}, {"cpuUsagePercent": -1},
    {"cpuUsagePercent": True}, {"cpuSampleIntervalMs": -1}])
def test_physical_resource_counters_reject_missing_or_nonfinite_samples(monkeypatch, changes):
    record = {"sampledAtMs": 1700000000000, "residentMemoryBytes": 67108864,
              "cpuUsagePercent": 125.5, "cpuSampleIntervalMs": 500, **changes}
    monkeypatch.setattr(subject, "_request", lambda *args: (200, json.dumps({"data": {"processResources": record}}).encode()))
    with pytest.raises(RuntimeError, match="sample"):
        subject._physical_process_resources(54321, KEY)


def test_physical_resource_counters_allow_warmup_and_multiple_cpu_cores(monkeypatch):
    attempts = [0]
    clock = [0.0]
    monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def request(*args):
        attempts[0] += 1
        return 200, json.dumps({"data": {"processResources": {"sampledAtMs": 1700000000000,
            "residentMemoryBytes": 67108864, "cpuUsagePercent": None if attempts[0] == 1 else 250.0,
            "cpuSampleIntervalMs": None if attempts[0] == 1 else 500}, "operatorData": KEY}}).encode()

    monkeypatch.setattr(subject, "_request", request)
    result = subject._physical_process_resources(54321, KEY)
    assert attempts[0] == 2 and result["cpuUsagePercent"] == 250.0 and KEY not in json.dumps(result)


def test_exact_existing_apk_admission_keeps_unknown_profile_readonly(tmp_path, monkeypatch):
    phone = Phone()
    phone.installed = True
    report = run(tmp_path, monkeypatch, phone)
    value = json.loads(report.read_text())
    assert value["status"] == "passed" and value["ownedInstallation"] is False
    assert value["runtimeExecution"] == "not-run"
    assert not any(call[0] == "install" or call[:3] == ("shell", "am", "start") for call in phone.calls)


@pytest.mark.parametrize("debug,signer,authority,error", [
    (True, "b" * 64, "b" * 64, RuntimeError), (None, "b" * 64, "b" * 64, RuntimeError),
    (False, "c" * 64, "b" * 64, RuntimeError), (False, "b" * 64, None, ValueError),
])
def test_physical_certificate_and_release_context_fail_before_any_device_operation(tmp_path, debug, signer, authority, error):
    phone = Phone()
    report_dir = tmp_path / "not-created"
    with pytest.raises(error, match="trusted"):
        subject.probe_physical_device(phone.command, {**payload(), "debug": debug, "signerSha256": signer},
            expected_cert_sha256=authority, serial=SERIAL, output_root=tmp_path, report_dir=report_dir, execute=True)
    assert phone.calls == [] and not report_dir.exists()


def test_primary_readiness_failure_still_stops_via_ui_and_removes_only_own_artifacts(tmp_path, monkeypatch):
    phone = Phone()
    phone.unauthenticated = 200
    with pytest.raises(RuntimeError, match="enforce authentication"):
        run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads((tmp_path / "initial/physical-device.json").read_text())
    assert value["runtimeExecution"] == "not-run" and value["status"] == "failed"
    assert not phone.running and not phone.forward
    assert any(call[:2] == ("shell", "rm") and call[2] == "-f" for call in phone.calls)


def test_cleanup_fault_does_not_hide_primary_failure_or_skip_other_cleanup(tmp_path, monkeypatch):
    phone = Phone()
    phone.unauthenticated = 200
    command = phone.command

    def fail_stop(*args, **kwargs):
        if args[2:5] == ("shell", "input", "tap") and args[5] == "250":
            raise ValueError(KEY)
        return command(*args, **kwargs)

    phone.command = fail_stop
    with pytest.raises(RuntimeError, match="enforce authentication"):
        run(tmp_path, monkeypatch, phone, execute=True)
    report = (tmp_path / "initial/physical-device.json").read_text()
    value = json.loads(report)
    assert value["cleanupErrors"] == [{"action": "normal-ui-stop", "errorType": "ValueError"}]
    assert not phone.forward and KEY not in report
    assert any(call[:2] == ("shell", "rm") for call in phone.calls)


def test_wrong_receipt_or_other_device_never_admits_existing_profile(tmp_path):
    report = tmp_path / "receipt.json"
    report.write_text(json.dumps({"schema": "emulebb.android.physical-device/1", "status": "passed",
        "ownedInstallation": True, "deviceSerialSha256": "0" * 64, "apkSha256": "a" * 64,
        "signerSha256": "b" * 64, "versionCode": 42}))
    digest = hashlib.sha256(report.read_bytes()).hexdigest()
    assert not subject._owned_installation(report, digest, payload=payload(), device_hash="1" * 64)
    with pytest.raises(RuntimeError, match="hash differs"):
        subject._owned_installation(report, "0" * 64, payload=payload(), device_hash="1" * 64)


@pytest.mark.parametrize("api", [33, 38])
def test_unsupported_physical_api_fails_before_installing(tmp_path, monkeypatch, api):
    phone = Phone()
    phone.api = api
    with pytest.raises(ValueError, match="only Android APIs"):
        run(tmp_path, monkeypatch, phone, execute=True)
    assert not phone.installed and not any(call[0] == "install" for call in phone.calls)


def test_mismatched_or_changed_adb_server_is_never_restarted(tmp_path, monkeypatch):
    executable = tmp_path / "adb.exe"
    executable.write_bytes(b"synthetic tool")
    versions = [41]
    monkeypatch.setattr(subject, "existing_adb_server_version", lambda port: versions[0])
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="Android Debug Bridge version 1.0.41", stderr="")

    monkeypatch.setattr(subject.subprocess, "run", command)
    device = subject.AdbDevice(executable, SERIAL)
    versions[0] = 42
    with pytest.raises(RuntimeError, match="version changed"):
        device.command("-s", SERIAL, "get-state")
    assert calls == [[str(executable), "version"]]
    with pytest.raises(RuntimeError, match="refusing to restart"):
        subject.AdbDevice(executable, SERIAL)


@pytest.mark.parametrize("arguments", [
    ("reboot",), ("kill-server",), ("disconnect",), ("uninstall", "org.emulebb.android"),
    ("install", "-r", "synthetic.apk"), ("shell", "pm", "clear", "org.emulebb.android"),
    ("shell", "pm", "grant", "org.emulebb.android", "synthetic.permission"),
    ("shell", "appops", "set", "org.emulebb.android", "MANAGE_EXTERNAL_STORAGE", "allow"),
    ("shell", "am", "force-stop", "org.emulebb.android"), ("shell", "settings", "put", "global", "synthetic", "1"),
])
def test_physical_adb_rejects_destructive_lifecycle_before_cli_execution(tmp_path, monkeypatch, arguments):
    executable = tmp_path / "adb.exe"
    executable.write_bytes(b"synthetic tool")
    monkeypatch.setattr(subject, "existing_adb_server_version", lambda port: 41)
    calls = []
    monkeypatch.setattr(subject.subprocess, "run", lambda args, **kwargs: calls.append(args)
                        or SimpleNamespace(returncode=0, stdout="Android Debug Bridge version 1.0.41", stderr=""))
    device = subject.AdbDevice(executable, SERIAL)
    with pytest.raises(RuntimeError, match="cannot"):
        device.command("-s", SERIAL, *arguments)
    assert calls == [[str(executable), "version"]]


@pytest.mark.parametrize("response", [b"OKAY00040029", b"OKAYffff", b"FAIL", b"OKAY0004oops"])
def test_readonly_adb_version_protocol_is_bounded(monkeypatch, response):
    remaining = bytearray(response)
    sent = []

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendall(self, value):
            sent.append(value)

        def recv(self, count):
            part = bytes(remaining[:count])
            del remaining[:count]
            return part

    monkeypatch.setattr(subject.socket, "create_connection", lambda *args, **kwargs: Stream())
    if response == b"OKAY00040029":
        assert subject.existing_adb_server_version(5037) == 41
    else:
        with pytest.raises(RuntimeError):
            subject.existing_adb_server_version(5037)
    assert sent == [b"000chost:version"]


def test_ui_failure_metadata_retains_only_resource_ids_flags_and_foreground_package():
    ui = SimpleNamespace(elements=lambda: [{"resource-id": "org.emulebb.android:id/service_status",
        "text": KEY, "content-desc": KEY, "enabled": "true", "clickable": "false"},
        {"resource-id": "malformed:" + KEY, "text": KEY}],
        shell=lambda *args: "topResumedActivity=ActivityRecord{synthetic u0 org.emulebb.android/.MainActivity} " + KEY)
    value = subject._ui_failure_metadata(ui)
    assert value["foregroundPackage"] == "org.emulebb.android"
    assert value["resourceControlCount"] == 1 and value["hierarchyNodeCount"] == 2
    assert value["controls"][0]["resourceId"] == "org.emulebb.android:id/service_status"
    assert value["controls"][0]["enabled"] is True and value["controls"][0]["clickable"] is False
    assert KEY not in json.dumps(value)


def test_ui_failure_metadata_bounds_control_count_and_preserves_other_inspections():
    ui = SimpleNamespace(elements=lambda: [{"resource-id": "org.emulebb.android:id/synthetic"} for _ in range(200)],
                         shell=lambda *args: "mResumedActivity: org.emulebb.android/.MainActivity")
    value = subject._ui_failure_metadata(ui)
    assert len(value["controls"]) == 128 and value["controlsTruncated"] is True

    def fail():
        raise ValueError(KEY)

    ui.elements = fail
    value = subject._ui_failure_metadata(ui)
    assert value["foregroundPackage"] == "org.emulebb.android"
    assert value["inspectionErrors"] == [{"action": "resource-ids", "errorType": "ValueError"}]
    assert KEY not in json.dumps(value)
