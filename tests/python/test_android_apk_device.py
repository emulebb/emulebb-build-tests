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


def selected_adb(monkeypatch):
    device = subject.AdbDevice.__new__(subject.AdbDevice)
    device.adb, device.serial, device.server_port, device.version = Path("synthetic-adb"), SERIAL, 5037, 41
    monkeypatch.setattr(subject, "existing_adb_server_version", lambda port: 41)
    return device


def test_binary_device_reads_preserve_kernel_cmdline_nuls(monkeypatch):
    device = selected_adb(monkeypatch)
    calls = []

    def read(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"/owned/emulebb-rust\0--option\0", stderr=b"")

    monkeypatch.setattr(subject.subprocess, "run", read)
    assert device.command("-s", SERIAL, "exec-out", "cat", "/proc/123/cmdline", binary=True).endswith(b"\0")
    assert calls[0][0] == ["synthetic-adb", "-H", "127.0.0.1", "-P", "5037", "-s", SERIAL,
                           "exec-out", "cat", "/proc/123/cmdline"]
    assert calls[0][1]["text"] is False


@pytest.mark.parametrize("fault,reason,exit_code", [("permission", "permission-denied", 1),
    ("unknown", "unclassified-command-failure", 23), ("timeout", "command-timeout", None),
    ("os", "permission-denied", None)])
def test_adb_failure_projection_never_retains_private_argv_output_or_exception_text(monkeypatch, fault, reason, exit_code):
    import errno
    device = selected_adb(monkeypatch)

    def fail(*args, **kwargs):
        if fault == "timeout":
            raise subject.subprocess.TimeoutExpired([KEY, SERIAL], 10, output=KEY, stderr=SERIAL)
        if fault == "os":
            raise PermissionError(errno.EACCES, KEY, SERIAL)
        return SimpleNamespace(returncode=exit_code, stdout=KEY,
            stderr=("Permission denied " if fault == "permission" else "") + KEY + SERIAL)

    monkeypatch.setattr(subject.subprocess, "run", fail)
    with pytest.raises(subject.AdbOperationFailure) as error:
        device.command("-s", SERIAL, "shell", "mkdir", "/private/" + KEY)
    evidence = error.value.safe_failure
    assert evidence == {"operation": "shell-mkdir", "reason": reason, "exitCode": exit_code}
    assert KEY not in str(error.value) + json.dumps(evidence) and SERIAL not in json.dumps(evidence)


def test_physical_peer_launcher_owns_only_selected_client_and_discards_native_logs(tmp_path, monkeypatch):
    import io
    device = selected_adb(monkeypatch)
    calls = []
    process = SimpleNamespace(stdout=io.BytesIO(b""))
    monkeypatch.setattr(subject.subprocess, "Popen", lambda *args, **kwargs: calls.append((args, kwargs)) or process)
    home = "/data/local/tmp/emulebb-apk-peer-" + "a" * 32
    owned, capture = device.spawn_peer("ignored-other-adb", {}, home + "/emulebb-rust", home, home, tmp_path)
    assert owned is process
    capture.close()
    capture.raise_if_failed()
    arguments, options = calls[0]
    assert arguments[0][:8] == ["synthetic-adb", "-H", "127.0.0.1", "-P", "5037", "-s", SERIAL, "shell"]
    assert "owned-daemon.pid" in arguments[0][-1] and "LD_LIBRARY_PATH" in arguments[0][-1]
    assert options["stdin"] == subject.subprocess.DEVNULL
    assert options["stdout"] == subject.subprocess.PIPE and options["stderr"] == subject.subprocess.STDOUT
    assert options["env"] == dict(subject.os.environ)
    assert not list(tmp_path.iterdir())
    with pytest.raises(RuntimeError, match="fresh owned temporary directory"):
        device.spawn_peer("ignored", {}, "/sdcard/Download/emulebb-rust", "/sdcard/Download", "/sdcard/Download", tmp_path)
    assert len(calls) == 1


def test_native_startup_capture_retains_only_allowlisted_codes_in_memory(tmp_path):
    import io
    capture = subject.StartupSummaryCapture(tmp_path)
    capture.start(io.BytesIO(("Error: failed to create incoming dir /private/" + KEY
        + "\nCaused by: Permission denied (os error 13) " + SERIAL).encode()),
        stop_process=lambda: pytest.fail("readable startup pipe must not require termination"))
    capture.close()
    capture.raise_if_failed()
    assert capture.summary() == {"contexts": ["incoming-directory"], "systemConditions": ["permission-denied"]}
    assert not list(tmp_path.iterdir())
    assert KEY not in json.dumps(capture.summary()) and SERIAL not in json.dumps(capture.summary())


@pytest.mark.parametrize("changes", [{"text": KEY}, {"visible-to-user": "false"}, {"bounds": "[0,0][700,100]"},
    {"bounds": "[0,100][1100,180]"}, {"bounds": "[0,100][700,100]"}, {"bounds": "invalid"}])
def test_public_version_label_must_match_and_have_whole_positive_display_bounds(changes):
    node = {"text": "eMuleBB 0.1.0-test", "bounds": "[0,100][700,180]", **changes}
    ui = SimpleNamespace(find=lambda name: node, shell=lambda *args: "Physical size: 1080x1920")
    with pytest.raises(RuntimeError, match="version label") as error:
        subject._visible_app_version(ui, "0.1.0-test")
    assert KEY not in str(error.value)


@pytest.mark.parametrize("fault", ["foreign-origin", "foreign-activity", "missing-record"])
def test_diagnostics_share_never_dismisses_or_selects_an_unproved_chooser(monkeypatch, fault):
    clock, actions = [0.0], []
    monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    component = "com.android.intentresolver/.ChooserActivity" if fault != "foreign-activity" else "other.application/.MainActivity"
    origin = "other.application" if fault == "foreign-origin" else "org.emulebb.android"
    document = ("* Hist  #0: ActivityRecord{abc123 u0 " + component + " t12}\n launchedFromPackage=" + origin
                + " launchedFromUid=10123\ntopResumedActivity=ActivityRecord{abc123 u0 " + component + " t12}\n")
    if fault == "missing-record":
        document = "topResumedActivity" + document.partition("topResumedActivity")[2]
    def shell(*args):
        actions.append(args)
        if args == ("cmd", "package", "resolve-activity", "--brief", "--user", "0", "-a", "android.intent.action.CHOOSER"):
            return "com.android.intentresolver/.ChooserActivity"
        assert args == ("dumpsys", "activity", "activities"), "never touch an unproved recipient UI"
        return document + " private-recipient@example.invalid " + KEY
    ui = SimpleNamespace(click=lambda name: actions.append(("click", name)), shell=shell)
    with pytest.raises(RuntimeError, match="owned Android system chooser") as error:
        subject._share_diagnostics_without_sending(ui)
    assert ("click", "share_diagnostics") in actions
    assert KEY not in str(error.value) and "recipient@" not in str(error.value)


@pytest.mark.parametrize("prefix", ["* Hist #", "* Hist  #", "    Hist  #", "\t* Hist\t#"])
def test_system_chooser_matches_current_aosp_and_observed_phone_history_whitespace(prefix):
    document = (prefix + "0: ActivityRecord{abc123 u0 com.android.intentresolver/.ChooserActivity t12}\n"
        " launchedFromPackage=org.emulebb.android launchedFromUid=10123\n"
        "topResumedActivity=ActivityRecord{abc123 u0 com.android.intentresolver/.ChooserActivity t12}\n")
    assert subject._owned_system_chooser(document, resolved_component="com.android.intentresolver/.ChooserActivity")


@pytest.mark.parametrize("resumed", ["def456 u0 com.android.intentresolver/.ChooserActivity", "def456 u0 other.application/.Activity"])
def test_chooser_origin_from_a_nonresumed_history_record_is_never_accepted(resumed):
    document = ("* Hist  #0: ActivityRecord{abc123 u0 com.android.intentresolver/.ChooserActivity t12}\n"
        " launchedFromPackage=org.emulebb.android launchedFromUid=10123\n"
        "* Hist  #1: ActivityRecord{" + resumed + " t13}\n launchedFromPackage=other.application\n"
        "topResumedActivity=ActivityRecord{" + resumed + " t13}\n")
    assert not subject._owned_system_chooser(document, resolved_component="com.android.intentresolver/.ChooserActivity")


@pytest.mark.parametrize("component", ["com.android.intentresolver/.ChooserActivityLauncher",
    "com.android.intentresolver/.ChooserActivity", "android/com.android.internal.app.ChooserActivity"])
def test_share_observer_uses_exact_package_manager_chooser_instead_of_class_suffix(component):
    calls = []
    document = ("* Hist  #0: ActivityRecord{abc123 u0 " + component + " t12}\n"
        " launchedFromPackage=org.emulebb.android launchedFromUid=10123\n"
        "topResumedActivity=ActivityRecord{abc123 u0 " + component + " t12}\n")
    def shell(*args):
        calls.append(args)
        if args[:3] == ("cmd", "package", "resolve-activity"):
            assert args[3:] == ("--brief", "--user", "0", "-a", "android.intent.action.CHOOSER")
            return component
        if args == ("dumpsys", "activity", "activities"):
            return document
        assert args == ("input", "keyevent", "KEYCODE_BACK")
        return ""
    ui = SimpleNamespace(shell=shell, click=lambda name: calls.append(("click", name)),
        wait_state=lambda state, **kwargs: calls.append(("state", state)))
    result = subject._share_diagnostics_without_sending(ui)
    assert result["recipientSelected"] is False and result["dismissed"] is True
    assert calls[-2:] == [("input", "keyevent", "KEYCODE_BACK"), ("state", "Stopped")]
    assert not subject._owned_system_chooser(document, resolved_component=component + "Other")
    assert not subject._owned_system_chooser(document.replace("launchedFromPackage=org.emulebb.android",
        "launchedFromPackage=other.application"), resolved_component=component)


@pytest.mark.parametrize("resolved", ["other.application/.ChooserActivityLauncher", "No activity found", "", "android/invalid class"])
def test_untrusted_or_unresolved_platform_chooser_never_opens_share_or_sends_input(resolved):
    ui = SimpleNamespace(shell=lambda *args: resolved,
        click=lambda name: pytest.fail("untrusted chooser must not open"))
    with pytest.raises(RuntimeError, match="trusted platform package"):
        subject._share_diagnostics_without_sending(ui)
    assert not subject._owned_system_chooser("", resolved_component=resolved)


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
        self.version_code = 42
        self.version_name = "0.1.0-test"
        self.build_identity = payload()["buildIdentity"]
        self.update_identity = None
        self.api_key = KEY
        self.reset_key_on_update = False
        self.page_size = 16384
        self.unauthenticated = 401
        self.foreground_lingers = False

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
            return ("  Package [org.emulebb.android] (synthetic):\n"
                    "    versionCode=" + str(self.version_code) + "\n    versionName=" + self.version_name + "\n"
                    "    User 0: installed=true hidden=false stopped=false\n"
                    "      runtime permissions:\n"
                    "        android.permission.POST_NOTIFICATIONS: granted=" + str(self.notifications).lower() + ", flags=[ USER_SET ]\n"
                    "        android.permission.ACCESS_LOCAL_NETWORK: granted=" + str(self.lan).lower() + ", flags=[ USER_SET ]\n"
                    ) if self.installed or self.retained else "Unable to find package"
        if args[:2] == ("shell", "sha256sum"):
            return self.checksum + " " + args[2]
        if args[:1] == ("install",):
            if "-r" in args:
                from emule_test_harness.android_apk_profile import OwnedUpdateApproval
                approval = kwargs.get("owned_update")
                assert self.installed and isinstance(approval, OwnedUpdateApproval)
                self.checksum = approval.target_sha256
                self.version_code += 1
                self.version_name = self.update_identity["version"]
                self.build_identity = self.update_identity
                if self.reset_key_on_update:
                    self.api_key = "substituted-private-bootstrap-key-0000000"
            else:
                assert not self.installed
            self.installed = True
        if args[:3] == ("shell", "appops", "get"):
            return "MANAGE_EXTERNAL_STORAGE: " + ("allow" if self.permission else "default")
        if args[:4] == ("shell", "cmd", "package", "check-permission"):
            raise RuntimeError("Unknown command: check-permission")
        if args[:4] == ("shell", "cmd", "package", "resolve-activity"):
            return "com.android.intentresolver/.ChooserActivityLauncher"
        if args[:4] == ("shell", "dumpsys", "activity", "activities"):
            if self.screen == "chooser":
                return ("* Hist  #0: ActivityRecord{abc123 u0 com.android.intentresolver/.ChooserActivityLauncher t12}\n"
                        "  launchedFromPackage=org.emulebb.android launchedFromUid=10123\n"
                        "topResumedActivity=ActivityRecord{abc123 u0 com.android.intentresolver/.ChooserActivityLauncher t12}\n")
            package = "com.android.settings" if self.screen == "files" else "com.google.android.permissioncontroller"
            return "mResumedActivity: " + package + "/.PermissionActivity"
        if args[:4] == ("shell", "dumpsys", "activity", "services"):
            active = str(self.running or self.foreground_lingers).lower()
            return "ACTIVITY MANAGER SERVICES\nServiceRecord org.emulebb.android/.DaemonService\nisForeground=" + active + " startRequested=" + active
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
                    '<node resource-id="org.emulebb.android:id/app_version" text="eMuleBB ' + self.version_name + '" bounds="[0,100][700,180]"/>'
                    '<node resource-id="org.emulebb.android:id/api_key" enabled="true" text="' + self.api_key + '"/>'
                    '<node resource-id="org.emulebb.android:id/bind_addr" enabled="true" text="127.0.0.1:20017"/>'
                    '<node resource-id="org.emulebb.android:id/resume_on_boot" enabled="true" checked="false"/>'
                    '<node resource-id="org.emulebb.android:id/start_service" enabled="true" bounds="[0,500][100,600]"/>'
                    '<node resource-id="org.emulebb.android:id/stop_service" enabled="true" bounds="[200,500][300,600]"/>'
                    '<node resource-id="org.emulebb.android:id/grant_all_files_access" enabled="true" bounds="[400,500][500,600]"/>'
                    '<node resource-id="org.emulebb.android:id/allow_notifications" enabled="true" bounds="[600,500][700,600]"/>'
                    '<node resource-id="org.emulebb.android:id/allow_local_network" enabled="true" bounds="[800,500][900,600]"/>'
                    '<node resource-id="org.emulebb.android:id/share_diagnostics" enabled="true" bounds="[1000,500][1080,600]"/>'
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
            if args[3] == "1040":
                self.screen = "chooser"
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
        assert key == self.api_key
        return 200, json.dumps({"meta": {"apiVersion": "v1"}, "data": {
            **self.build_identity, "name": "eMuleBB", "apiVersion": "v1", "lifecycle": {"state": "running"}}}).encode()


def run(tmp_path, monkeypatch, phone, *, execute=False, receipt=None, configure=False, **kwargs):
    monkeypatch.setattr(subject, "_request", phone.request)
    clock = [0.0]
    monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    report_dir = tmp_path / ("resume" if receipt else "initial")
    return subject.probe_physical_device(phone.command, payload(), serial=SERIAL, output_root=tmp_path,
        expected_cert_sha256="b" * 64,
        report_dir=report_dir, execute=execute, configure_storage=configure, dwell_seconds=15, installation_receipt=receipt,
        installation_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt else None, **kwargs)


@pytest.mark.parametrize("abi", ["arm64-v8a", "x86_64"])
def test_physical_transfer_uses_only_owned_matching_source_abi_and_restarts_normally(tmp_path, monkeypatch, abi):
    from emule_test_harness import android_apk_peer
    phone = Phone()
    calls = []

    def transfer(command, peer, **kwargs):
        assert phone.running and kwargs["prefix"] == ("-s", SERIAL)
        kwargs["restart_service"]()
        assert phone.running
        assert kwargs["spawn_daemon"] is launcher and kwargs["stop_client"] is cleanup
        calls.append(peer)
        return {"status": "passed", "collisionPreserved": True, "completedDeliverySurvivesRestart": True}

    launcher, cleanup = object(), object()
    monkeypatch.setattr(android_apk_peer, "transfer_proof", transfer)
    peer = {"abi": abi, "buildIdentity": payload()["buildIdentity"]}
    arguments = {"peer_payload": peer, "rust_source": tmp_path, "peer_launcher": launcher, "peer_client_cleanup": cleanup}
    if abi == "arm64-v8a":
        report = run(tmp_path, monkeypatch, phone, execute=True, **arguments)
        result = json.loads(report.read_text())
        assert result["status"] == result["transfer"]["status"] == "passed" and calls == [peer]
        assert phone.running is False and KEY not in report.read_text() and SERIAL not in report.read_text()
    else:
        with pytest.raises(RuntimeError, match="source or ABI"):
            run(tmp_path, monkeypatch, phone, execute=True, **arguments)
        assert not calls and not phone.running


def test_physical_transfer_cannot_run_as_admission_or_without_owned_launcher(tmp_path, monkeypatch):
    phone = Phone()
    with pytest.raises(ValueError, match="explicit owned runtime"):
        run(tmp_path, monkeypatch, phone, peer_payload={})
    assert not phone.calls


def test_transfer_primary_stage_survives_restart_phase_updates_and_normal_stop_cleanup(tmp_path, monkeypatch):
    from emule_test_harness import android_apk_peer
    phone = Phone()
    failure = {"phase": "peer-process-admission", "code": "peer-process-admission-failed", "errorType": "RuntimeError"}

    def transfer(command, peer, **kwargs):
        kwargs["restart_service"]()
        raise android_apk_peer.CampaignFailure(failure)

    monkeypatch.setattr(android_apk_peer, "transfer_proof", transfer)
    with pytest.raises(RuntimeError, match="peer-process-admission-failed"):
        run(tmp_path, monkeypatch, phone, execute=True,
            peer_payload={"abi": "arm64-v8a", "buildIdentity": payload()["buildIdentity"]},
            rust_source=tmp_path, peer_launcher=object(), peer_client_cleanup=object())
    report = (tmp_path / "initial/physical-device.json").read_text()
    value = json.loads(report)
    assert value["phase"] == "controlled-transfer-peer-process-admission"
    assert value["transfer"] == {"status": "failed", "failure": failure}
    assert not phone.running and KEY not in report and SERIAL not in report


def test_listener_probe_flag_routes_only_to_control_owner_and_never_claims_transfer(tmp_path, monkeypatch):
    from emule_test_harness import android_apk_peer
    phone = Phone()
    calls = []
    with pytest.raises(ValueError, match="full admitted peer inputs"):
        run(tmp_path, monkeypatch, phone, execute=True, probe_local_listeners=True)
    assert not phone.calls

    def probe(command, peer, **kwargs):
        assert phone.running
        calls.append(peer)
        kwargs["restart_service"]()
        return {"status": "passed", "scope": "listener-control-only", "transfer": "not-run"}

    monkeypatch.setattr(android_apk_peer, "probe_local_listeners", probe)
    monkeypatch.setattr(android_apk_peer, "transfer_proof", lambda *args, **kwargs: pytest.fail("probe must not enqueue transfer"))
    peer = {"abi": "arm64-v8a", "buildIdentity": payload()["buildIdentity"]}
    report = run(tmp_path, monkeypatch, phone, execute=True, probe_local_listeners=True,
        peer_payload=peer, rust_source=tmp_path, peer_launcher=object(), peer_client_cleanup=object())
    value = json.loads(report.read_text())
    assert value["status"] == value["listenerProbe"]["status"] == "passed" and value["transfer"] == "not-run"
    assert calls == [peer] and not phone.running
    assert "physical-local-listener-control-probe" in {row["name"] for row in value["cases"]}


def test_retained_fixture_cleanup_needs_no_peer_and_has_exclusive_hash_authority(tmp_path, monkeypatch):
    from emule_test_harness import android_apk_cleanup
    phone = Phone()
    with pytest.raises(ValueError, match="all three authorities"):
        run(tmp_path, monkeypatch, phone, execute=True, cleanup_transfer_report=tmp_path)
    assert not phone.calls
    calls = []

    def cleanup(command, **kwargs):
        assert phone.running and kwargs["api_key"] == KEY and kwargs["retained_report"] == tmp_path
        assert kwargs["report_sha256"] == "d" * 64 and kwargs["fixture_sha256"] == "e" * 64
        calls.append(kwargs)
        return {"status": "passed", "settingsChanged": False, "filesRemoved": 1, "directoriesRemoved": 1}

    monkeypatch.setattr(android_apk_cleanup, "cleanup_report_fixture", cleanup)
    report = run(tmp_path, monkeypatch, phone, execute=True, cleanup_transfer_report=tmp_path,
        cleanup_transfer_report_sha256="d" * 64, cleanup_transfer_fixture_sha256="e" * 64)
    value = json.loads(report.read_text())
    assert value["status"] == value["ownedFixtureCleanup"]["status"] == "passed" and value["transfer"] == "not-run"
    assert len(calls) == 1 and not phone.running


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
        assert value["appVersion"] == {"versionName": "0.1.0-test", "bounds": [0, 100, 700, 180],
            "displayBounds": [0, 0, 1080, 1920], "whollyVisible": True}
        assert value["diagnosticsShare"] == {"status": "passed", "chooser": "android-system",
            "launchedFromOwnedApp": True, "recipientSelected": False, "dismissed": True}
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
        ("shell", "input", "tap", "450", "550")]


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


def test_storage_configuration_requires_owned_execution_and_uses_authenticated_context(tmp_path, monkeypatch):
    from emule_test_harness import android_apk_profile
    phone = Phone()
    with pytest.raises(ValueError, match="explicit runtime execution"):
        run(tmp_path, monkeypatch, phone, configure=True)
    assert not phone.calls
    calls = []

    def configure(command, **kwargs):
        assert phone.running and kwargs["api_key"] == KEY and kwargs["payload"] == payload()
        calls.append(kwargs)
        kwargs["restart_service"]()
        assert phone.running
        return {"status": "passed", "application": "service-restarted-before-sharing", "restartVerified": True}

    monkeypatch.setattr(android_apk_profile, "configure_storage", configure)
    report = run(tmp_path, monkeypatch, phone, execute=True, configure=True)
    value = json.loads(report.read_text())
    assert value["status"] == "passed" and len(calls) == 1
    assert value["storageConfiguration"]["application"] == "service-restarted-before-sharing"
    assert KEY not in report.read_text()


@pytest.mark.parametrize("fault", [None, "execute", "wrong-installed-bytes", "absent", "other-user", "disconnected", "config", "schema", "no-opt-in", "already-present", "key-reset"])
def test_owned_compatible_update_requires_bound_receipts_and_preserves_phone_state(tmp_path, monkeypatch, fault):
    from emule_test_harness import android_apk_profile
    phone = Phone()
    installation = run(tmp_path, monkeypatch, phone)
    old = json.loads(installation.read_text())
    target = {**payload(), "apk": {"sha256": "e" * 64}, "versionCode": 43,
              "buildIdentity": {**payload()["buildIdentity"], "sourceRevision": "e" * 40, "version": "0.1.1-test"}}
    phone.update_identity = target["buildIdentity"]
    phone.reset_key_on_update = fault == "key-reset"
    configuration = {**old, "schema": "emulebb.android.storage-configuration/1", "incomingDir": android_apk_profile.INCOMING,
        "sharedRoot": android_apk_profile.SHARED, "priorRootsPreserved": fault != "config", "rootEntriesPreserved": True,
        "restartVerified": True, "filesMovedOrDeleted": 0}
    materials = {path: "f" * 64 for path in android_apk_profile.SCHEMA_MATERIALS}
    compatibility = {"schema": "emulebb.android.profile-compatibility/1", "status": "passed",
        "fromSourceRevision": old["sourceRevision"], "toSourceRevision": target["buildIdentity"]["sourceRevision"],
        "materials": materials, "metadataSchemaSha256": "0" * 64 if fault == "schema" else
        hashlib.sha256(json.dumps(materials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}

    def receipt(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    config_path, config_sha = receipt("configuration.json", configuration)
    compat_path, compat_sha = receipt("compatibility.json", compatibility)
    if fault == "wrong-installed-bytes": phone.checksum = "0" * 64
    if fault == "absent": phone.installed = False
    if fault == "disconnected": phone.phase = "Service connection interrupted"
    if fault == "already-present":
        phone.checksum, phone.version_code, phone.version_name = "e" * 64, 43, "0.1.1-test"
    if fault == "other-user":
        command = phone.command

        def other_user(*args, **kwargs):
            result = command(*args, **kwargs)
            if args[2:5] == ("shell", "dumpsys", "package"):
                return result + "\n    User 10: installed=true\n"
            return result

        phone.command = other_user
    phone.calls.clear()
    if fault == "execute":
        from emule_test_harness import rust_local_ed2k
        monkeypatch.setattr(rust_local_ed2k, "request_json", lambda base, method, route, key: {
            "daemon": {"incomingDir": android_apk_profile.INCOMING}} if route == "/api/v1/app/settings" else {
            "roots": [{"path": android_apk_profile.SHARED}]})
    kwargs = dict(serial=SERIAL, output_root=tmp_path, report_dir=tmp_path / "updated", expected_cert_sha256="b" * 64,
        execute=fault == "execute", dwell_seconds=15,
        installation_receipt=installation, installation_receipt_sha256=hashlib.sha256(installation.read_bytes()).hexdigest(),
        allow_owned_compatible_update=fault != "no-opt-in", configuration_receipt=config_path,
        configuration_receipt_sha256=config_sha, compatibility_receipt=compat_path, compatibility_receipt_sha256=compat_sha)
    if fault not in {None, "execute", "already-present"}:
        with pytest.raises((RuntimeError, ValueError)):
            subject.probe_physical_device(phone.command, target, **kwargs)
        assert len([call for call in phone.calls if call[:1] == ("install",)]) == (1 if fault == "key-reset" else 0)
    else:
        report = subject.probe_physical_device(phone.command, target, **kwargs)
        value = json.loads(report.read_text())
        assert value["status"] == "passed" and value["ownedInstallation"] is True
        assert value["ownedCompatibleUpdate"]["resetOrMigration"] is False
        assert value["ownedCompatibleUpdate"]["installationPerformed"] is (fault != "already-present")
        assert phone.checksum == "e" * 64 and phone.version_code == 43
        if fault != "already-present":
            assert value["ownedCompatibleUpdate"]["bootstrapPreferencesPreserved"] is True
        if fault == "execute":
            assert value["runtimeExecution"] == "executed" and not phone.running
            dumps = {call[3] for call in phone.calls if call[:3] == ("shell", "uiautomator", "dump")}
            removed = {call[3] for call in phone.calls if call[:3] == ("shell", "rm", "-f")}
            assert len(dumps) == 1 and dumps == removed
        assert len([call for call in phone.calls if call[:2] == ("install", "-r")]) == (0 if fault == "already-present" else 1)
        assert not any(call[:3] in {("shell", "pm", "clear"), ("shell", "am", "force-stop")} for call in phone.calls)


def test_update_cli_guard_requires_typed_admission_and_rechecks_target_bytes(tmp_path, monkeypatch):
    from emule_test_harness.android_apk_profile import OwnedUpdateApproval
    executable = tmp_path / "adb.exe"
    executable.write_bytes(b"synthetic tool")
    target = tmp_path / "target.apk"
    target.write_bytes(b"source-bound synthetic APK")
    calls = []
    monkeypatch.setattr(subject, "existing_adb_server_version", lambda port: 41)
    monkeypatch.setattr(subject.subprocess, "run", lambda args, **kwargs: calls.append(args)
        or SimpleNamespace(returncode=0, stdout="Android Debug Bridge version 1.0.41", stderr=""))
    device = subject.AdbDevice(executable, SERIAL)
    approval = OwnedUpdateApproval({}, str(target), hashlib.sha256(target.read_bytes()).hexdigest(), "f" * 64)
    device.command("-s", SERIAL, "install", "-r", str(target), owned_update=approval)
    target.write_bytes(b"substituted bytes")
    with pytest.raises(RuntimeError, match="bytes changed"):
        device.command("-s", SERIAL, "install", "-r", str(target), owned_update=approval)
    assert len(calls) == 2


@pytest.mark.parametrize("phase", ["Starting", "Running"])
def test_known_owned_active_service_is_gracefully_stopped_before_smoke(tmp_path, monkeypatch, phase):
    phone = Phone()
    receipt = run(tmp_path, monkeypatch, phone)
    phone.running, phone.phase = True, phase
    report = run(tmp_path, monkeypatch, phone, execute=True, receipt=receipt)
    value = json.loads(report.read_text())
    assert value["status"] == "passed" and value["initialServicePhase"] == phase
    assert value["initialServiceNormalization"] == {"from": phase, "method": "normal-ui-stop", "status": "passed"}
    assert [call[3] for call in phone.calls if call[:3] == ("shell", "input", "tap")] == ["250", "50", "250", "1040"]
    assert not phone.running and value["runtimeExecution"] == "executed"


def test_clipped_stop_is_scrolled_to_safe_content_before_tapping(tmp_path, monkeypatch):
    phone = Phone()
    command = phone.command
    moved = [False]

    def clipped(*args, **kwargs):
        result = command(*args, **kwargs)
        if args[2:5] == ("shell", "input", "swipe"):
            moved[0] = True
        if args[2:4] == ("shell", "cat") and phone.screen == "app":
            return result.replace("[200,500][300,600]", "[200,800][300,900]" if moved[0] else "[200,1850][300,1920]")
        return result

    phone.command = clipped
    report = run(tmp_path, monkeypatch, phone, execute=True)
    assert json.loads(report.read_text())["status"] == "passed" and moved[0]
    assert all(int(call[4]) < 1680 for call in phone.calls if call[:3] == ("shell", "input", "tap"))
    stop_index = next(index for index, call in enumerate(phone.calls)
                      if call[:3] == ("shell", "input", "tap") and call[3] == "250")
    start_index = max(index for index, call in enumerate(phone.calls[:stop_index])
                      if call[:3] == ("shell", "input", "tap") and call[3] == "50")
    assert any(call[:3] == ("shell", "am", "start") for call in phone.calls[start_index + 1:stop_index])


def test_zero_area_stop_is_never_tapped_or_replaced_with_force_stop(tmp_path, monkeypatch):
    phone = Phone()
    command = phone.command

    def zero(*args, **kwargs):
        return command(*args, **kwargs).replace("[200,500][300,600]", "[200,500][300,500]")

    phone.command = zero
    with pytest.raises(RuntimeError, match="safe visible tap bounds"):
        run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads((tmp_path / "initial/physical-device.json").read_text())
    assert value["phase"] == "normal-ui-stop" and value["uiFailure"]["lastAction"]["bounds"] == [200, 500, 300, 500]
    assert value["uiFailure"]["lastAction"]["tapped"] is False and phone.running
    assert not any(call[:3] == ("shell", "input", "tap") and call[3] == "250" for call in phone.calls)


def test_closed_rest_and_stopped_ui_do_not_hide_a_lingering_foreground_service(tmp_path, monkeypatch):
    phone = Phone()
    phone.foreground_lingers = True
    with pytest.raises(RuntimeError, match="remained foreground"):
        run(tmp_path, monkeypatch, phone, execute=True)
    value = json.loads((tmp_path / "initial/physical-device.json").read_text())
    assert value["status"] == "failed" and value["phase"] == "verify-stopped-service-flags"
    assert not any(case["name"] == "physical-graceful-stop" for case in value["cases"])


def test_stopped_bound_service_dump_omits_inactive_foreground_fields():
    ui = SimpleNamespace(shell=lambda *args: "ACTIVITY MANAGER SERVICES\n"
                         "* ServiceRecord org.emulebb.android/.DaemonService\nstartRequested=false\n")
    assert subject._stopped_service_flags(ui) == {"present": True, "foreground": False, "startRequested": False}


BOUND_NEVER_STARTED = """ACTIVITY MANAGER SERVICES (dumpsys activity services)
  User 0 active services:
  * ServiceRecord{123abc u0 org.emulebb.android/.DaemonService c:org.emulebb.android}
    intent={cmp=org.emulebb.android/.DaemonService}
    packageName=org.emulebb.android
    processName=org.emulebb.android:daemon
    targetSdkVersion=37
    app=ProcessRecord{456def 1234:org.emulebb.android:daemon/u0a123}
    createTime=-2m startingBgTimeout=--
    lastActivity=-1m restartTime=-- createdFromFg=true
    Bindings:
    * IntentBindRecord{789abc CREATE}:
      intent={cmp=org.emulebb.android/.DaemonService}
      binder=android.os.BinderProxy@123abc
      requested=true received=true hasBound=true doRebind=false
      * Client AppBindRecord{456abc ProcessRecord{789def 1235:org.emulebb.android/u0a123}}
        Connections:
          ConnectionRecord{123def u0 CR org.emulebb.android/.DaemonService:@123abc flags=0x1}
    All Connections:
      ConnectionRecord{123def u0 CR org.emulebb.android/.DaemonService:@123abc flags=0x1}
"""


def test_complete_owned_bound_never_started_service_has_implicitly_clear_start_and_foreground_flags():
    # AOSP omits the start group when all three controlling values are clear;
    # this is the actual Android 16 phone's observed structural shape.
    ui = SimpleNamespace(shell=lambda *args: BOUND_NEVER_STARTED)
    assert subject._stopped_service_flags(ui) == {"present": True, "foreground": False, "startRequested": False}


@pytest.mark.parametrize("change", [
    lambda text: text.split("    Bindings:")[0],
    lambda text: text.split("    All Connections:")[0],
    lambda text: text.replace("AppBindRecord{", "UnknownBinding{"),
    lambda text: text.replace("packageName=org.emulebb.android", "packageName=other.app"),
    lambda text: text.replace("* ServiceRecord{123abc u0", "* ServiceRecord{123abc u10"),
    lambda text: text.replace("app=ProcessRecord{456def 1234:org.emulebb.android:daemon/u0a123}", "app=null"),
    lambda text: text + "\n isForeground=true foregroundId=42\n",
    lambda text: text + "\n startRequested=true delayedStop=false lastStartId=1\n",
    lambda text: text + "\n startRequested=false delayedStop=true lastStartId=1\n",
    lambda text: text + "\n isForeground=false foregroundId=42 startRequested=false\n",
    lambda text: text + "\n isForeground=unknown startRequested=false\n",
    lambda text: text + "\n startRequested=unknown\n",
])
def test_absent_start_fields_do_not_admit_truncated_foreign_unknown_or_active_bound_records(monkeypatch, change):
    clock = [0.0]
    monkeypatch.setattr(subject.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    ui = SimpleNamespace(shell=lambda *args: change(BOUND_NEVER_STARTED))
    with pytest.raises(RuntimeError, match="remained foreground|unrecognized"):
        subject._stopped_service_flags(ui)


@pytest.mark.parametrize("locked", [False, True])
def test_missing_app_ui_never_swipes_launcher_or_keyguard(tmp_path, monkeypatch, locked):
    phone = Phone()
    command = phone.command

    def unavailable(*args, **kwargs):
        result = command(*args, **kwargs)
        if args[2:4] == ("shell", "cat"):
            resource = "com.android.systemui:id/keyguard_root_view" if locked else "com.android.launcher:id/workspace"
            return '<hierarchy><node resource-id="' + resource + '"/></hierarchy>'
        if args[2:5] == ("shell", "dumpsys", "window"):
            return "mShowingLockscreen=" + str(locked).lower()
        return result

    phone.command = unavailable
    if locked:
        report = run(tmp_path, monkeypatch, phone, execute=True)
        value = json.loads(report.read_text())
        assert value["status"] == "setup-required" and value["phase"] == "unlock-device-before-ui-interaction"
    else:
        with pytest.raises(subject.DeviceUiUnavailable, match="app UI is not visible"):
            run(tmp_path, monkeypatch, phone, execute=True)
    inputs = [call for call in phone.calls if call[:2] == ("shell", "input")]
    assert all(call == ("shell", "input", "keyevent", "KEYCODE_WAKEUP") for call in inputs)


def test_known_owned_failed_service_can_retry_after_normal_permission_setup(tmp_path, monkeypatch):
    phone = Phone()
    receipt = run(tmp_path, monkeypatch, phone)
    phone.phase, phone.notifications = "Failed", False
    report = run(tmp_path, monkeypatch, phone, execute=True, receipt=receipt)
    value = json.loads(report.read_text())
    assert value["status"] == "passed" and value["initialServicePhase"] == "Failed"
    assert "initialServiceNormalization" not in value
    assert phone.notifications and not phone.running


@pytest.mark.parametrize("phase", ["Service connection interrupted", "Stopping", KEY])
def test_disconnected_or_unknown_initial_status_is_not_guessed_or_mutated(tmp_path, monkeypatch, phase):
    phone = Phone()
    receipt = run(tmp_path, monkeypatch, phone)
    phone.running, phone.phase = True, phase
    with pytest.raises(RuntimeError, match="stable admitted service phase"):
        run(tmp_path, monkeypatch, phone, execute=True, receipt=receipt)
    report = (tmp_path / "resume/physical-device.json").read_text()
    value = json.loads(report)
    expected = "connection-interrupted" if phase == "Service connection interrupted" else "Stopping" if phase == "Stopping" else "unrecognized"
    assert value["initialServicePhase"] == value["uiFailure"]["servicePhase"] == expected
    assert value["phase"] == "inspect-initial-service-phase" and value["runtimeExecution"] == "not-run"
    assert not any(call[:3] == ("shell", "input", "tap") for call in phone.calls)
    assert phone.running and KEY not in report


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


@pytest.mark.parametrize("granted", [True, False])
def test_runtime_permission_dump_is_scoped_to_exact_package_and_primary_user(granted):
    permission = "android.permission.POST_NOTIFICATIONS"
    document = ("Packages:\n  Package [org.emulebb.other] (other):\n"
        "    User 0: installed=true\n      runtime permissions:\n"
        f"        {permission}: granted=true, flags=[ USER_SET ]\n"
        "  Package [org.emulebb.android] (selected):\n"
        "    install permissions:\n"
        f"      {permission}: granted=true\n"
        "    User 0: ceDataInode=123 installed=true hidden=false stopped=false\n"
        "      runtime permissions:\n"
        f"        {permission}: granted={str(granted).lower()}, flags=[ USER_SET|USER_FIXED ]\n"
        "    User 10: installed=true\n      runtime permissions:\n"
        f"        {permission}: granted=true, flags=[ USER_SET ]\n")
    assert subject.runtime_permission_granted(document, permission) is granted
    assert subject.runtime_permission_granted(document, "android.permission.ACCESS_LOCAL_NETWORK") is False


@pytest.mark.parametrize("document", ["Unknown command: check-permission", "",
    "  Package [org.emulebb.other]:\n    User 0: installed=true\n",
    "  Package [org.emulebb.android]:\n    User 10: installed=true\n",
    "  Package [org.emulebb.android]:\n    User 0: installed=false\n"])
def test_unrelated_or_missing_package_user_is_not_a_permission_grant(document):
    with pytest.raises(RuntimeError, match="package"):
        subject.runtime_permission_granted(document, "android.permission.POST_NOTIFICATIONS")


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
