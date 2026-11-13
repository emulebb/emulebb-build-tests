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
import sys
import time
import xml.etree.ElementTree as ET
from uuid import uuid4

APPLICATION_ID = "org.emulebb.android"
PREFIX = ("-s", "emulator-5554")


def admit_payload(root: Path, manifest_name: str, *, source_sha: str, manifest_sha256: str) -> dict:
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


def ui_nodes(xml: str) -> dict[str, dict[str, str]]:
    """Read resource IDs from a bounded production UI dump without retaining it."""
    if len(xml.encode("utf-8")) > 65536:
        raise RuntimeError("APK UI exceeds its inspection bound")
    try:
        tree = ET.fromstring(xml)
    except ET.ParseError:
        raise RuntimeError("APK UI dump is malformed") from None
    result = {}
    for node in tree.iter("node"):
        resource = node.get("resource-id", "")
        if resource.startswith(APPLICATION_ID + ":id/"):
            name = resource.split("/", 1)[1]
            if name in result:
                raise RuntimeError("APK UI has ambiguous resource controls")
            result[name] = dict(node.attrib)
    return result


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


def exercise(command, payload: dict, *, report_dir: Path, soak_seconds: int = 0) -> dict:
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
              "localTransfer": "not-run", "physicalDevice": "not-run"}
    port = None
    installed = False
    ui_path = "/data/local/tmp/emulebb-apk-ui-" + uuid4().hex + ".xml"

    def shell(*args):
        return command(*PREFIX, "shell", *args)

    def inspect():
        shell("uiautomator", "dump", ui_path)
        # Never write the UI hierarchy to the host: it contains the visible key.
        return ui_nodes(shell("cat", ui_path))

    def click(name):
        node = inspect().get(name, {})
        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if bounds is None or node.get("enabled") != "true":
            raise RuntimeError("APK required control is missing or disabled: " + name)
        x1, y1, x2, y2 = map(int, bounds.groups())
        shell("input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))

    def wait_state(expected, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            state = inspect().get("service_status", {}).get("text", "")
            if state == expected:
                return
            if state == "Failed" or time.monotonic() >= deadline:
                raise RuntimeError("APK did not reach expected service state: " + expected)
            time.sleep(1)

    def authenticated():
        status, raw = _request(port, "/api/v1/app", key)
        if status != 200:
            raise RuntimeError("APK authenticated REST failed")
        document = json.loads(raw)
        app = document.get("data", {})
        expected = payload["buildIdentity"]
        if (app.get("sourceRevision") != expected["sourceRevision"]
                or app.get("version") != expected["version"]
                or app.get("releaseChannel") != expected["channel"]
                or app.get("lifecycle", {}).get("state") != "running"):
            raise RuntimeError("APK running daemon identity differs from its selected source")

    def passed(name):
        cases.append({"name": name, "status": "passed"})

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
        shell("dumpsys", "deviceidle", "whitelist", "+" + APPLICATION_ID)
        shell("am", "start", "-W", "-n", APPLICATION_ID + "/.MainActivity")
        wait_state("Stopped")
        nodes = inspect()
        key = nodes.get("api_key", {}).get("text", "")
        if len(key) < 32 or not all(33 <= ord(c) <= 126 for c in key):
            raise RuntimeError("APK UI must expose a valid generated API key")
        if nodes.get("resume_on_boot", {}).get("checked") != "false":
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
        try:
            _request(port, "/api/v1/app", key)
        except (OSError, http.client.HTTPException):
            pass
        else:
            raise RuntimeError("APK Stop left the REST listener running")
        passed("graceful-stop")
        click("start_service")
        wait_state("Running")
        authenticated()
        passed("restart")
        # The foreground service must survive closing its visible shell.
        shell("input", "keyevent", "KEYCODE_HOME")
        shell("input", "keyevent", "KEYCODE_SLEEP")
        shell("dumpsys", "battery", "unplug")
        shell("dumpsys", "deviceidle", "force-idle")
        started = time.monotonic()
        dwell = max(60, soak_seconds)
        samples = 0
        while True:
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
