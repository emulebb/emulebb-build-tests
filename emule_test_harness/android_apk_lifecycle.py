"""Exercise production APK controls on the existing owned, isolated Android guest.

This module never starts an ADB server or emulator, reads private application
storage, or installs test-only control receivers. UI credentials stay in memory.
"""
from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
import re
import shlex
import sys
import time
import xml.etree.ElementTree as ET
from uuid import uuid4

APPLICATION_ID = "org.emulebb.android"
PREFIX = ("-s", "emulator-5554")
SUPPORTED_ANDROID_APIS = frozenset({34, 35, 36, 37})
APK_FILE_LINK_CASES = frozenset({
    "os-file-link-resolution", "cold-file-link-without-autostart",
    "pending-and-repeated-intents-without-autostart", "malformed-and-nonfile-intents-rejected",
    "start-and-repeated-intents-without-enqueue", "native-browser-dispatch-without-enqueue",
    "bundled-webui-confirmation",
})
FILE_LINK_BROWSER_REQUIRED_CHECKS = frozenset({
    "signInPreserved", "cancelWithoutEnqueue", "explicitConfirmation", "repeatedNavigationWithoutEnqueue",
})
_APK_BASE_CASES = frozenset({
    "installed-apk-identity", "fresh-setup", "authenticated-source-bound-readiness", "bundled-webui",
    "graceful-stop", "notification-denied-service-start", "all-files-denial-and-runtime-revocation",
    "enabled-boot-resume", "explicit-stop-prevents-boot-resume", "task-manager-stop-prevents-boot-resume",
    "force-stop-prevents-boot-resume", "restart", "local-transfer-and-delivery-collision",
    "completed-delivery-survives-restart", "file-link-intents-and-webui-confirmation", "screen-off-doze-observation",
})


def required_apk_cases(api: int) -> set[str]:
    """Return the exact full qualification contract for one supported guest API.

    Candidate admission imports this stdlib-only owner from a verified harness
    revision. A report cannot select its own required cases or extend this range.
    """
    if type(api) is not int or api not in SUPPORTED_ANDROID_APIS:
        raise ValueError("APK qualification supports only Android APIs 34, 35, 36 and 37")
    cases = set(_APK_BASE_CASES)
    if api == 37:
        cases.add("android17-local-network-denial-and-revocation")
    return cases


def admit_production_certificate(payload: dict, *, expected_cert_sha256: str) -> None:
    """Require independently supplied release-signing authority, never self-expectation."""
    if not isinstance(expected_cert_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_cert_sha256) is None:
        raise ValueError("APK qualification requires an explicit trusted production certificate SHA-256")
    if payload.get("debug") is not False or payload.get("signerSha256") != expected_cert_sha256:
        raise RuntimeError("APK qualification requires a production release signed by the trusted certificate")


def admit_payload(root: Path, manifest_name: str, *, source_sha: str, manifest_sha256: str,
                  expected_cert_sha256: str) -> dict:
    """Bind immutable release identities to one bounded, source-built signed APK."""
    if (re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
            or re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None
            or Path(manifest_name).name != manifest_name or "\\" in manifest_name):
        raise ValueError("APK admission requires immutable source and manifest identities")
    manifest = root / manifest_name
    if (root.is_symlink() or manifest.is_symlink() or not manifest.is_file()
            or manifest.stat().st_size > 65536):
        raise RuntimeError("APK receipt must be a bounded regular file")
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise RuntimeError("APK receipt hash differs")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("APK receipt must contain an object")
    admit_production_certificate(value, expected_cert_sha256=expected_cert_sha256)
    identity = value.get("buildIdentity", {})
    apk = value.get("apk", {})
    if (value.get("schema") != "emulebb.android.apk-package/1" or value.get("status") != "passed"
            or value.get("applicationId") != APPLICATION_ID or value.get("minSdk") != 34
            or value.get("targetSdk") != 37
            or value.get("source", {}).get("emulebbRust", {}).get("commit") != source_sha
            or identity.get("sourceRevision") != source_sha
            or not isinstance(identity.get("version"), str) or not identity["version"]
            or identity.get("channel") not in {"development", "nightly"}
            or re.fullmatch(r"[0-9a-f]{64}", value.get("signerSha256", "")) is None
            or not isinstance(apk.get("path"), str) or Path(apk["path"]).name != apk["path"]
            or "\\" in apk["path"] or not apk["path"].endswith(".apk")
            or type(apk.get("sizeBytes")) is not int or not 0 < apk["sizeBytes"] <= 512 * 1024**2
            or re.fullmatch(r"[0-9a-f]{64}", apk.get("sha256", "")) is None):
        raise RuntimeError("APK receipt does not identify the selected signed Android build")
    path = root / apk["path"]
    if path.is_symlink() or not path.is_file() or path.stat().st_size != apk["sizeBytes"]:
        raise RuntimeError("APK receipt payload is missing, redirected or changed")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != apk["sha256"]:
            raise RuntimeError("APK payload hash differs")
    return {**value, "payloadPath": str(path)}


def ui_elements(xml: str) -> list[dict[str, str]]:
    """Parse a bounded transient hierarchy; callers must not retain its values."""
    if len(xml.encode("utf-8")) > 65536:
        raise RuntimeError("APK UI exceeds its inspection bound")
    try:
        tree = ET.fromstring(xml)
    except ET.ParseError:
        raise RuntimeError("APK UI dump is malformed") from None
    return [dict(node.attrib) for node in tree.iter("node")]


def ui_nodes(xml: str) -> dict[str, dict[str, str]]:
    """Read resource IDs from a bounded production UI dump without retaining it."""
    result = {}
    for node in ui_elements(xml):
        resource = node.get("resource-id", "")
        if resource.startswith(APPLICATION_ID + ":id/"):
            name = resource.split("/", 1)[1]
            if name in result:
                raise RuntimeError("APK UI has ambiguous resource controls")
            result[name] = node
    return result


class ProductionUi:
    """Inspect only the production app UI on one explicitly selected device."""

    def __init__(self, command, *, prefix=PREFIX):
        self.command = command
        self.prefix = tuple(prefix)
        self.path = "/data/local/tmp/emulebb-apk-ui-" + uuid4().hex + ".xml"

    def shell(self, *args):
        return self.command(*self.prefix, "shell", *args)

    def _hierarchy(self):
        self.shell("uiautomator", "dump", self.path)
        # This transient hierarchy contains the visible credential. Never copy
        # it to the host or retain it as a diagnostic artifact.
        return self.shell("cat", self.path)

    def inspect(self):
        return ui_nodes(self._hierarchy())

    def elements(self):
        """Inspect stock permission UI only in memory, with the same size bound."""
        return ui_elements(self._hierarchy())

    def find(self, name, *, enabled=False):
        size = re.findall(r"(\d+)x(\d+)", self.shell("wm", "size"))
        if not size:
            raise RuntimeError("Cannot determine owned Android display dimensions")
        width, height = map(int, size[-1])
        deadline = time.monotonic() + 60
        while True:
            nodes = self.inspect()
            if name in nodes:
                node = nodes[name]
                if not enabled or node.get("enabled") == "true":
                    return node
                if time.monotonic() >= deadline:
                    raise RuntimeError("APK required control remains disabled: " + name)
                time.sleep(1)
                continue
            # Production controls may span several scrollable viewports.
            for direction in (1, -1):
                for _ in range(6):
                    first, last = (height * 3 // 4, height // 4) if direction == 1 else (height // 4, height * 3 // 4)
                    self.shell("input", "swipe", str(width // 2), str(first), str(width // 2), str(last), "250")
                    nodes = self.inspect()
                    if name in nodes:
                        break
                if name in nodes:
                    break
            if name not in nodes:
                raise RuntimeError("APK required control is not reachable: " + name)

    def click(self, name):
        node = self.find(name, enabled=True)
        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if bounds is None or node.get("enabled") != "true":
            raise RuntimeError("APK required control is missing or disabled: " + name)
        x1, y1, x2, y2 = map(int, bounds.groups())
        self.shell("input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))

    def wait_state(self, expected, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            state = self.find("service_status").get("text", "")
            if state == expected:
                return
            if state == "Failed" or time.monotonic() >= deadline:
                raise RuntimeError("APK did not reach expected service state: " + expected)
            time.sleep(1)


def _request(port: int, path: str, key: str | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path, headers={} if key is None else {"X-API-Key": key})
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise RuntimeError("APK REST response exceeds its inspection bound")
        return response.status, body
    finally:
        connection.close()


def exercise(command, payload: dict, *, report_dir: Path, soak_seconds: int = 0,
             peer_payload: dict | None = None, rust_source: Path | None = None,
             adb: str | None = None, child: dict | None = None, qualify_file_links: bool = False) -> dict:
    """Install and exercise the actual APK through its normal UI and loopback REST.

    The caller owns a fresh disposable guest. Long screen-off observation is an
    explicitly selected campaign, never an implicit nightly duration.
    """
    if type(soak_seconds) is not int or not 0 <= soak_seconds <= 7 * 86400:
        raise ValueError("APK observation must be bounded to at most seven days")
    cases = []
    result = {"schema": "emulebb.android.apk-lifecycle/1", "status": "failed",
              "apkSha256": payload["apk"]["sha256"], "sourceRevision": payload["buildIdentity"]["sourceRevision"],
              "signerSha256": payload["signerSha256"], "runtimeExecution": "not-run",
              "deviceQualification": "emulator-only", "cases": cases,
              "localTransfer": "not-run", "fileLinks": "not-run", "physicalDevice": "not-run"}
    port = None
    installed = False
    ui = ProductionUi(command)
    ui_path = ui.path
    inspect, find, click, wait_state = ui.inspect, ui.find, ui.click, ui.wait_state

    def shell(*args):
        return command(*PREFIX, "shell", *args)

    def assert_listener_stopped(quiet_seconds=2):
        deadline = time.monotonic() + 30
        quiet_since = None
        while True:
            try:
                _request(port, "/api/v1/app", key)
            except (OSError, http.client.HTTPException):
                if quiet_since is None:
                    quiet_since = time.monotonic()
                if time.monotonic() - quiet_since >= quiet_seconds:
                    return
            else:
                quiet_since = None
            if time.monotonic() >= deadline:
                raise RuntimeError("APK Stop left the REST listener running")
            time.sleep(1)

    def reopen():
        shell("am", "start", "-W", "-n", APPLICATION_ID + "/.MainActivity")

    def reboot():
        previous = shell("cat", "/proc/sys/kernel/random/boot_id")
        command(*PREFIX, "reboot")
        deadline = time.monotonic() + 180
        while True:
            booted = command(*PREFIX, "shell", "getprop", "sys.boot_completed", check=False)
            boot_id = command(*PREFIX, "shell", "cat", "/proc/sys/kernel/random/boot_id", check=False)
            if booted == "1" and boot_id and boot_id != previous:
                shell("input", "keyevent", "KEYCODE_WAKEUP")
                shell("wm", "dismiss-keyguard")
                # ADB forwards are transport-owned and can disappear on reboot.
                # This private server owns this exact port; never adopt a new one.
                command(*PREFIX, "forward", "--remove", "tcp:" + str(port), check=False)
                command(*PREFIX, "forward", "--no-rebind", "tcp:" + str(port), "tcp:20017")
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("APK reboot proof did not observe a fresh unlocked Android boot")
            time.sleep(2)

    def authenticated():
        from .android_emulator import _app_identity
        status, raw = _request(port, "/api/v1/app", key)
        if status != 200:
            raise RuntimeError("APK authenticated REST failed")
        _app_identity(json.loads(raw), payload["buildIdentity"])

    def passed(name):
        cases.append({"name": name, "status": "passed"})

    def file_link_intents():
        from .rust_local_ed2k import request_json
        from .rust_webui_live_proof import run_file_link_browser_proof

        proof = {"schema": "emulebb.android.apk-file-links/1", "status": "failed", "cases": []}
        result["fileLinks"] = proof
        file_hash = "00112233445566778899aabbccddeeff"
        link = f"ed2k://|file|Android%20Intent%20Sample.bin|1|{file_hash}|/"
        base = f"http://127.0.0.1:{port}"

        def case(name):
            proof["cases"].append({"name": name, "status": "passed"})

        def dispatch(value):
            # ADB shell reparses arguments; raw eD2K pipes must never become a
            # guest shell pipeline. No raw hierarchy or intent dump is retained.
            shell("am", "start", "-W", "-a", "android.intent.action.VIEW",
                  "-c", "android.intent.category.BROWSABLE", "-d", shlex.quote(value))

        def pending():
            if link not in find("pending_link").get("text", ""):
                raise RuntimeError("APK did not preserve the requested pending file link")

        def transfer_rows():
            value = request_json(base, "GET", "/api/v1/transfers?limit=100", key)
            items = value.get("items")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise RuntimeError("APK file-link proof received an invalid transfer collection")
            return sorted((item.get("hash", "").lower(), item.get("sizeBytes")) for item in items)

        baseline = transfer_rows()
        click("stop_service")
        wait_state("Stopped")
        assert_listener_stopped()
        resolved = shell("cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.VIEW",
                         "-c", "android.intent.category.BROWSABLE", "-d", shlex.quote(link))
        if (not resolved.splitlines() or resolved.splitlines()[-1]
                not in {APPLICATION_ID + "/.MainActivity", APPLICATION_ID + "/" + APPLICATION_ID + ".MainActivity"}):
            raise RuntimeError("Android does not resolve eD2K file links to the production app")
        case("os-file-link-resolution")
        shell("am", "force-stop", APPLICATION_ID)
        dispatch(link)
        pending()
        wait_state("Stopped")
        assert_listener_stopped()
        case("cold-file-link-without-autostart")
        reopen()
        pending()
        dispatch(link)
        pending()
        assert_listener_stopped()
        case("pending-and-repeated-intents-without-autostart")
        for invalid in ("ed2k://|file|Invalid.bin|1|invalid|/", "ed2k://|server|127.0.0.1|4661|/"):
            dispatch(invalid)
            if not find("pending_link_error").get("text", ""):
                raise RuntimeError("APK accepted a malformed or unsupported eD2K intent")
            if inspect().get("pending_link", {}).get("text"):
                raise RuntimeError("APK retained an invalid pending file link")
            assert_listener_stopped()
        case("malformed-and-nonfile-intents-rejected")
        dispatch(link)
        pending()
        click("start_service")
        wait_state("Running")
        authenticated()
        pending()
        dispatch(link)
        pending()
        if transfer_rows() != baseline:
            raise RuntimeError("APK intent reception silently changed the transfer queue")
        case("start-and-repeated-intents-without-enqueue")
        browser = shell("cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.VIEW",
                        "-c", "android.intent.category.BROWSABLE", "-d", base + "/transfers")
        component = browser.splitlines()[-1] if browser.splitlines() else ""
        package = component.partition("/")[0]
        if "/" not in component or package in {APPLICATION_ID, "android"}:
            raise RuntimeError("APK file-link proof requires an installed guest default browser")
        click("open_webui")
        deadline = time.monotonic() + 30
        while True:
            activities = shell("dumpsys", "activity", "activities")
            if re.search(r"(?:mResumedActivity|topResumedActivity)[^\n]*\b" + re.escape(package) + r"/", activities):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("APK did not dispatch the WebUI to the actual guest browser")
            time.sleep(1)
        reopen()
        if inspect().get("pending_link", {}).get("text") or transfer_rows() != baseline:
            raise RuntimeError("APK browser dispatch retained its pending link or enqueued it")
        case("native-browser-dispatch-without-enqueue")
        proof["browser"] = run_file_link_browser_proof(base_url=base, api_key=key, link=link,
            file_hash=file_hash, size_bytes=1, report_path=report_dir / "apk-file-link-browser.json",
            identity=payload["buildIdentity"])
        if proof["browser"].get("status") != "passed" or transfer_rows() != baseline:
            raise RuntimeError("APK bundled WebUI file-link confirmation did not finish cleanly")
        authenticated()
        case("bundled-webui-confirmation")
        proof["status"] = "passed"

    try:
        command(*PREFIX, "install", "--no-streaming", payload["payloadPath"], timeout=120)
        installed = True
        package_path = shell("pm", "path", APPLICATION_ID)
        paths = package_path.splitlines()
        if len(paths) != 1 or not paths[0].startswith("package:/data/app/"):
            raise RuntimeError("APK installation must produce exactly one base package")
        if shell("sha256sum", paths[0][8:]).split()[0] != payload["apk"]["sha256"]:
            raise RuntimeError("Installed APK bytes differ from qualified payload")
        passed("installed-apk-identity")
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow")
        shell("pm", "grant", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        api = int(shell("getprop", "ro.build.version.sdk"))
        result["androidApiLevel"] = api
        if api >= 37:
            shell("pm", "grant", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
        shell("dumpsys", "deviceidle", "whitelist", "+" + APPLICATION_ID)
        shell("am", "start", "-W", "-n", APPLICATION_ID + "/.MainActivity")
        wait_state("Stopped")
        key = find("api_key", enabled=True).get("text", "")
        if len(key) < 32 or not all(33 <= ord(c) <= 126 for c in key):
            raise RuntimeError("APK UI must expose a valid generated API key")
        if find("resume_on_boot").get("checked") != "false":
            raise RuntimeError("APK boot resume must initially be disabled")
        passed("fresh-setup")
        forward = command(*PREFIX, "forward", "--no-rebind", "tcp:0", "tcp:20017")
        if re.fullmatch(r"[1-9][0-9]*", forward) is None or int(forward) > 65535:
            raise RuntimeError("APK REST forward must allocate a private local port")
        port = int(forward)
        click("start_service")
        wait_state("Running")
        if _request(port, "/api/v1/app")[0] != 401:
            raise RuntimeError("APK REST must require authentication")
        authenticated()
        result["runtimeExecution"] = "executed"
        passed("authenticated-source-bound-readiness")
        status, body = _request(port, "/")
        if status != 200 or b"<html" not in body.lower():
            raise RuntimeError("APK must serve the bundled WebUI")
        passed("bundled-webui")
        click("stop_service")
        wait_state("Stopped")
        assert_listener_stopped()
        passed("graceful-stop")

        # A denied notification grant must not be mistaken for permission to
        # run a foreground service: Android still permits FGS with its notice.
        shell("pm", "revoke", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        # Permission/app-op changes can terminate the activity's UID. Return via
        # its real launcher before looking for controls, rather than using stale UI.
        reopen()
        click("start_service")
        wait_state("Running")
        authenticated()
        passed("notification-denied-service-start")
        shell("pm", "grant", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        reopen()
        click("stop_service")
        wait_state("Stopped")
        assert_listener_stopped()

        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "deny")
        reopen()
        click("start_service")
        assert_listener_stopped()
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow")
        reopen()
        click("start_service")
        wait_state("Running")
        authenticated()
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "deny")
        reopen()
        assert_listener_stopped()
        passed("all-files-denial-and-runtime-revocation")
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow")
        reopen()
        click("start_service")
        wait_state("Running")
        authenticated()

        if api >= 37:
            shell("pm", "revoke", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
            reopen()
            assert_listener_stopped()
            click("start_service")
            assert_listener_stopped()
            shell("pm", "grant", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
            reopen()
            click("start_service")
            wait_state("Running")
            authenticated()
            passed("android17-local-network-denial-and-revocation")

        # Prove actual reboot handling, not an injected fake boot broadcast.
        click("resume_on_boot")
        if find("resume_on_boot").get("checked") != "true":
            raise RuntimeError("APK boot resume setting was not retained")
        reboot()
        deadline = time.monotonic() + 90
        while True:
            try:
                authenticated()
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() >= deadline:
                    raise RuntimeError("APK did not resume after an enabled reboot") from None
                time.sleep(1)
        passed("enabled-boot-resume")
        reopen()
        wait_state("Running")
        click("stop_service")
        wait_state("Stopped")
        reboot()
        assert_listener_stopped(quiet_seconds=5)
        reopen()
        wait_state("Stopped")
        assert_listener_stopped(quiet_seconds=5)
        passed("explicit-stop-prevents-boot-resume")
        click("start_service")
        wait_state("Running")
        authenticated()
        shell("cmd", "activity", "stop-app", APPLICATION_ID)
        assert_listener_stopped()
        reboot()
        assert_listener_stopped(quiet_seconds=5)
        reopen()
        wait_state("Stopped")
        assert_listener_stopped(quiet_seconds=5)
        passed("task-manager-stop-prevents-boot-resume")
        click("start_service")
        wait_state("Running")
        authenticated()
        shell("am", "force-stop", APPLICATION_ID)
        assert_listener_stopped()
        reboot()
        assert_listener_stopped(quiet_seconds=5)
        reopen()
        wait_state("Stopped")
        assert_listener_stopped(quiet_seconds=5)
        passed("force-stop-prevents-boot-resume")
        click("resume_on_boot")
        click("start_service")
        wait_state("Running")
        authenticated()
        passed("restart")
        if peer_payload is not None:
            from .android_apk_peer import guest_sha256, transfer_proof
            if rust_source is None or adb is None or child is None:
                raise RuntimeError("APK transfer proof requires the owned native peer execution context")
            result["localTransfer"] = transfer_proof(command, peer_payload, apk_port=port, api_key=key,
                                                     adb=adb, child=child, report_dir=report_dir, rust_source=rust_source)
            passed("local-transfer-and-delivery-collision")
            click("stop_service")
            wait_state("Stopped")
            assert_listener_stopped()
            click("start_service")
            wait_state("Running")
            authenticated()
            delivered = result["localTransfer"]
            if guest_sha256(command, delivered["deliveredPath"]) != delivered["sha256"]:
                raise RuntimeError("APK delivered bytes changed across service restart")
            passed("completed-delivery-survives-restart")
        if qualify_file_links:
            file_link_intents()
            passed("file-link-intents-and-webui-confirmation")
        # The foreground service must survive closing its visible shell.
        shell("input", "keyevent", "KEYCODE_HOME")
        shell("input", "keyevent", "KEYCODE_SLEEP")
        shell("dumpsys", "battery", "unplug")
        shell("dumpsys", "deviceidle", "force-idle")
        def assert_idle_screen_off():
            if shell("dumpsys", "deviceidle", "get", "deep") != "IDLE":
                raise RuntimeError("APK Doze proof did not retain actual deep idle")
            if re.search(r"mWakefulness=(Asleep|Dozing)\b", shell("dumpsys", "power")) is None:
                raise RuntimeError("APK screen-off proof did not observe a sleeping device")

        assert_idle_screen_off()
        started = time.monotonic()
        dwell = max(60, soak_seconds)
        samples = 0
        while True:
            assert_idle_screen_off()
            authenticated()
            samples += 1
            elapsed = time.monotonic() - started
            result["endurance"] = {"requestedSeconds": soak_seconds, "minimumDwellSeconds": 60,
                                   "observedSeconds": round(elapsed, 3), "samples": samples,
                                   "over24Hours": elapsed > 86400}
            (report_dir / "apk-progress.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            if elapsed >= dwell:
                break
            time.sleep(min(30, dwell - elapsed))
        passed("screen-off-doze-observation")
        if peer_payload is not None and qualify_file_links:
            required = required_apk_cases(api)
            if len(cases) != len(required) or {case["name"] for case in cases} != required:
                raise RuntimeError("APK qualification case coverage differs from its trusted source contract")
        result["status"] = "passed"
        return result
    finally:
        active_failure = sys.exc_info()[0] is not None
        cleanup_errors = []
        # A force-stop is cleanup only, never evidence of graceful service Stop.
        actions = []
        if installed:
            actions.append(("force-stop", lambda: shell("am", "force-stop", APPLICATION_ID)))
        if port is not None:
            actions.append(("remove-forward", lambda: command(*PREFIX, "forward", "--remove", "tcp:" + str(port))))
        actions.extend([
            ("exit-doze", lambda: shell("dumpsys", "deviceidle", "unforce")),
            ("reset-battery", lambda: shell("dumpsys", "battery", "reset")),
            ("remove-ui-dump", lambda: shell("rm", "-f", ui_path)),
        ])
        for name, action in actions:
            try:
                action()
            except Exception as error:
                cleanup_errors.append({"action": name, "errorType": type(error).__name__})
        if cleanup_errors:
            result.update(status="failed", cleanupErrors=cleanup_errors)
        (report_dir / "apk-lifecycle.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if cleanup_errors and not active_failure:
            raise RuntimeError("APK lifecycle cleanup failed")
