"""Bounded physical-phone admission and smoke; preserve the operator ADB server.

WHY: the emulator owner owns a disposable guest and intentionally changes boot,
permissions and power state. A real phone needs a separate, narrower owner.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import math
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time

from .android_apk_lifecycle import APPLICATION_ID, ProductionUi, _request, admit_production_certificate, required_apk_cases


def _normal_permission_setup(ui: ProductionUi, *, api: int, changes: list) -> dict:
    """Grant only this owned install through app buttons and unambiguous stock UI."""
    def granted(permission):
        if permission == "MANAGE_EXTERNAL_STORAGE":
            return bool(re.search(r"MANAGE_EXTERNAL_STORAGE:\s*allow\b", ui.shell(
                "appops", "get", "--user", "0", APPLICATION_ID, permission)))
        return ui.shell("cmd", "package", "check-permission", "android.permission." + permission,
                        APPLICATION_ID, "0") == "granted"

    def foreground(package):
        return bool(re.search(r"(?:mResumedActivity|topResumedActivity)[^\n]*\b" + re.escape(package) + r"/",
                              ui.shell("dumpsys", "activity", "activities")))

    def tap(node):
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
        if match is None:
            return False
        x1, y1, x2, y2 = map(int, match.groups())
        if x2 <= x1 or y2 <= y1:
            return False
        ui.shell("input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
        return True

    def allow(permission, button, *, settings=False):
        if granted(permission):
            return True
        ui.click(button)
        try:
            deadline = time.monotonic() + 10
            candidates = []
            while True:
                elements = ui.elements()
                packages = {"com.android.settings"} if settings else {
                    "com.android.permissioncontroller", "com.google.android.permissioncontroller"}
                active = next((package for package in packages if foreground(package)), None)
                app_visible = active is not None and any(node.get("package") == active and
                    (node.get("text", "").strip() == "eMuleBB" if settings else "eMuleBB" in node.get("text", ""))
                    for node in elements)
                if active is not None and app_visible:
                    if settings:
                        candidates = [node for node in elements if node.get("package") == active
                                      and node.get("enabled") == "true" and node.get("checkable") == "true"]
                    else:
                        candidates = [node for node in elements if node.get("package") == active
                                      and node.get("enabled") == "true" and node.get("clickable") == "true"
                                      and node.get("resource-id") in {package + ":id/permission_allow_button" for package in packages}]
                    break
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.5)
            # Never guess between Samsung/stock controls or turn an existing
            # grant off. Ambiguous UI remains an explicit manual setup step.
            if len(candidates) != 1 or settings and candidates[0].get("checked") != "false":
                return False
            if not tap(candidates[0]):
                return False
            change = {"permission": permission, "method": "normal-settings-ui" if settings else "normal-permission-dialog",
                      "before": "denied", "after": "unconfirmed"}
            changes.append(change)
            deadline = time.monotonic() + 10
            while not granted(permission):
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.5)
            change["after"] = "granted"
            return True
        finally:
            ui.shell("input", "keyevent", "KEYCODE_BACK")
            ui.shell("am", "start", "-W", "--user", "0", "-n", APPLICATION_ID + "/.MainActivity")
            ui.wait_state("Stopped")

    complete = allow("MANAGE_EXTERNAL_STORAGE", "grant_all_files_access", settings=True)
    if complete:
        complete = allow("POST_NOTIFICATIONS", "allow_notifications")
    if complete and api >= 37:
        complete = allow("ACCESS_LOCAL_NETWORK", "allow_local_network")
    return {"complete": complete, "allFiles": granted("MANAGE_EXTERNAL_STORAGE"),
            "localNetworkRequired": api >= 37,
            "localNetwork": granted("ACCESS_LOCAL_NETWORK") if api >= 37 else "not-required",
            "notifications": granted("POST_NOTIFICATIONS"), "batteryExemption": "not-inspected"}


def _physical_process_resources(port: int, key: str) -> dict:
    """Require real Android RSS and a settled CPU interval, retaining numeric fields only."""
    deadline = time.monotonic() + 15
    while True:
        status, raw = _request(port, "/api/v1/diagnostics", key)
        document = json.loads(raw)
        resources = document.get("data", {}).get("processResources") if isinstance(document, dict) else None
        if status != 200 or not isinstance(resources, dict):
            raise RuntimeError("Physical diagnostics did not expose process resource counters")
        sampled = resources.get("sampledAtMs")
        memory = resources.get("residentMemoryBytes")
        cpu = resources.get("cpuUsagePercent")
        interval = resources.get("cpuSampleIntervalMs")
        if type(sampled) is not int or sampled <= 0 or type(memory) is not int or memory <= 0:
            raise RuntimeError("Physical process memory sample is missing or invalid")
        if cpu is not None and (type(cpu) not in {int, float} or not math.isfinite(cpu) or cpu < 0):
            raise RuntimeError("Physical process CPU sample is invalid")
        if interval is not None and (type(interval) is not int or interval < 0):
            raise RuntimeError("Physical process CPU sample interval is invalid")
        if cpu is not None and interval is not None and interval > 0:
            return {"sampledAtMs": sampled, "residentMemoryBytes": memory,
                    "cpuUsagePercent": cpu, "cpuSampleIntervalMs": interval}
        if time.monotonic() >= deadline:
            raise RuntimeError("Physical process CPU sample did not settle within its bound")
        time.sleep(0.5)


def existing_adb_server_version(port: int) -> int:
    """Read the documented host:version service without starting/replacing ADB."""
    def receive(stream, count):
        value = b""
        while len(value) < count:
            chunk = stream.recv(count - len(value))
            if not chunk:
                raise RuntimeError("Existing ADB server returned an incomplete version")
            value += chunk
        return value

    # WHY: the adb CLI automatically kills/restarts a mismatched server. Query
    # its bounded, read-only host service before allowing that CLI near it.
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
            stream.sendall(b"000chost:version")
            if receive(stream, 4) != b"OKAY":
                raise RuntimeError("Existing ADB server refused version admission")
            length = int(receive(stream, 4), 16)
            if not 0 < length <= 16:
                raise RuntimeError("Existing ADB server version exceeds its bound")
            raw = receive(stream, length)
            if re.fullmatch(rb"[0-9a-fA-F]{1,8}", raw) is None:
                raise RuntimeError("Existing ADB server returned an invalid version")
            return int(raw, 16)
    except (OSError, ValueError):
        raise RuntimeError("Physical testing requires the existing local operator ADB server") from None


class AdbDevice:
    """Use one exact connected Wi-Fi serial; never manage server or transports."""

    def __init__(self, adb: Path, serial: str, *, server_port: int = 5037):
        if (not adb.is_absolute() or not adb.is_file() or not isinstance(serial, str)
                or not 1 <= len(serial) <= 256 or any(char.isspace() or ord(char) < 33 for char in serial)
                or (":" not in serial and "_adb-tls-connect._tcp" not in serial)
                or type(server_port) is not int or not 1 <= server_port <= 65535):
            raise ValueError("Select an installed ADB tool, exact Wi-Fi serial and existing server port")
        self.adb, self.serial, self.server_port = adb, serial, server_port
        self.version = existing_adb_server_version(server_port)
        try:
            result = subprocess.run([str(adb), "version"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("Selected ADB tool version inspection failed") from None
        match = re.search(r"Android Debug Bridge version 1\.0\.(\d+)\b", result.stdout)
        if result.returncode or match is None or int(match[1]) != self.version:
            raise RuntimeError("Selected ADB tool differs from the operator server; refusing to restart it")

    def command(self, *arguments, check=True, timeout=10):
        if arguments[:2] != ("-s", self.serial):
            raise RuntimeError("Physical ADB operations require the exact admitted device serial")
        if len(arguments) < 3 or arguments[2] in {
            "start-server", "kill-server", "connect", "disconnect", "pair", "root", "unroot",
            "reboot", "remount", "uninstall", "reverse",
        }:
            raise RuntimeError("Physical owner cannot manage ADB transports or destructive device lifecycle")
        if arguments[2] == "install" and any(flag in arguments[3:] for flag in {"-r", "-d", "--enable-rollback"}):
            raise RuntimeError("Physical owner cannot replace or downgrade an installed phone package")
        if arguments[2] == "shell":
            action = arguments[3:]
            if (action[:2] in {("pm", "clear"), ("pm", "uninstall"), ("pm", "grant"), ("pm", "revoke"),
                               ("appops", "set"), ("appops", "reset"), ("am", "force-stop"),
                               ("dumpsys", "deviceidle"), ("dumpsys", "battery")}
                    or action[:1] in {("reboot",), ("settings",), ("svc",)}):
                raise RuntimeError("Physical owner cannot reset app, permissions, power or network state")
        if existing_adb_server_version(self.server_port) != self.version:
            raise RuntimeError("Operator ADB server version changed during physical testing")
        try:
            result = subprocess.run([str(self.adb), "-H", "127.0.0.1", "-P", str(self.server_port), *arguments],
                                    capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("Selected physical-device ADB operation failed") from None
        if len(result.stdout) > 1024**2 or len(result.stderr) > 1024**2 or check and result.returncode:
            # Raw output can contain private endpoints, paths or the visible key.
            raise RuntimeError("Selected physical-device ADB operation failed")
        return result.stdout.strip() if result.returncode == 0 else ""


def _owned_installation(path: Path | None, digest: str | None, *, payload: dict, device_hash: str) -> bool:
    """Resume only a hash-bound receipt for this harness's previously absent install."""
    if path is None and digest is None:
        return False
    if (path is None or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or path.is_symlink() or not path.is_file() or path.stat().st_size > 65536):
        raise RuntimeError("Physical runtime resume requires a bounded installation receipt and exact hash")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("Physical installation receipt hash differs")
    value = json.loads(raw)
    return (isinstance(value, dict) and value.get("schema") == "emulebb.android.physical-device/1"
            and value.get("status") in {"passed", "setup-required"} and value.get("ownedInstallation") is True
            and value.get("deviceSerialSha256") == device_hash and value.get("apkSha256") == payload["apk"]["sha256"]
            and value.get("signerSha256") == payload["signerSha256"] and value.get("versionCode") == payload["versionCode"])


def probe_physical_device(command, payload: dict, *, serial: str, output_root: Path, report_dir: Path,
                          expected_cert_sha256: str,
                          execute: bool = False, installation_receipt: Path | None = None,
                          installation_receipt_sha256: str | None = None, dwell_seconds: int = 30,
                          render_webui: bool = False) -> Path:
    """Admit/install or run a bounded owned-phone smoke without resetting user state.

    Runtime is limited to a package installed here while previously absent, or a
    prior hash-bound receipt for that installation. Unknown existing profiles are
    read-only. Public first-run bootstrap is ordinary app behavior, not isolation.
    """
    admit_production_certificate(payload, expected_cert_sha256=expected_cert_sha256)
    if type(dwell_seconds) is not int or not 15 <= dwell_seconds <= 300:
        raise ValueError("Physical foreground observation must be between 15 and 300 seconds")
    if type(payload.get("versionCode")) is not int or not 1 <= payload["versionCode"] <= 2_100_000_000:
        raise ValueError("Physical admission requires the producer's exact APK versionCode")
    output_root = output_root.resolve()
    if (not output_root.is_dir() or report_dir.exists() or report_dir.is_symlink()
            or not report_dir.resolve().is_relative_to(output_root) or report_dir.resolve() == output_root):
        raise RuntimeError("Physical evidence requires a fresh directory below the configured output root")
    report_dir.mkdir(parents=True, mode=0o700)
    report = report_dir / "physical-device.json"
    device_hash = hashlib.sha256(serial.encode()).hexdigest()
    value = {"schema": "emulebb.android.physical-device/1", "status": "failed", "phase": "device-admission",
             "scope": "physical-foreground-smoke" if execute else "physical-admission",
             "deviceSerialSha256": device_hash, "apkSha256": payload["apk"]["sha256"],
             "sourceRevision": payload["buildIdentity"]["sourceRevision"], "signerSha256": payload["signerSha256"],
             "versionCode": payload["versionCode"], "ownedInstallation": False, "runtimeExecution": "not-run",
             "debugBuild": payload.get("debug"),
             "transfer": "not-run", "endurance": "not-run", "permissionChanges": [], "cases": []}
    prefix = ("-s", serial)
    ui = None
    port = None
    remote_port = None
    attempted_start = False
    key = None

    def shell(*args, **kwargs):
        return command(*prefix, "shell", *args, **kwargs)

    def passed(name):
        value["cases"].append({"name": name, "status": "passed"})

    def app():
        from .android_emulator import _app_identity
        status, raw = _request(port, "/api/v1/app", key)
        if status != 200:
            raise RuntimeError("Physical APK authenticated REST failed")
        _app_identity(json.loads(raw), payload["buildIdentity"])

    def assert_stopped():
        deadline = time.monotonic() + 30
        quiet_since = None
        while True:
            try:
                _request(port, "/api/v1/app", key)
            except (OSError, http.client.HTTPException):
                if quiet_since is None:
                    quiet_since = time.monotonic()
                if time.monotonic() - quiet_since >= 2:
                    return
            else:
                quiet_since = None
            if time.monotonic() >= deadline:
                raise RuntimeError("Physical APK Stop left its REST listener active")
            time.sleep(1)

    try:
        if command(*prefix, "get-state") != "device":
            raise RuntimeError("Selected Wi-Fi device is not connected and authorized")
        if shell("am", "get-current-user") != "0":
            raise RuntimeError("Initial physical qualification supports only the primary Android user")
        api = int(shell("getprop", "ro.build.version.sdk"))
        required_apk_cases(api)
        page_size = int(shell("getconf", "PAGESIZE"))
        abis = shell("getprop", "ro.product.cpu.abilist64").split(",")
        if shell("getprop", "ro.kernel.qemu") not in {"", "0"} or page_size not in {4096, 16384}:
            raise RuntimeError("Selected target is not a supported physical Android device")
        if not {"arm64-v8a", "x86_64"}.intersection(abis):
            raise RuntimeError("Physical device has no supported APK ABI")
        value.update(androidApiLevel=api, pageSizeBytes=page_size, abis64=abis)
        passed("physical-api-page-size-abi")
        package = shell("pm", "path", "--user", "0", APPLICATION_ID, check=False)
        if not package:
            known = shell("dumpsys", "package", APPLICATION_ID)
            if "Package [" + APPLICATION_ID + "]" in known:
                raise RuntimeError("Existing or retained package data prevents a fresh physical installation")
            value["phase"] = "install-absent-package"
            command(*prefix, "install", "--no-streaming", "--user", "0", payload["payloadPath"], timeout=120)
            value["ownedInstallation"] = True
            package = shell("pm", "path", "--user", "0", APPLICATION_ID)
        else:
            value["ownedInstallation"] = _owned_installation(installation_receipt, installation_receipt_sha256,
                                                           payload=payload, device_hash=device_hash)
        paths = package.splitlines()
        if len(paths) != 1 or not paths[0].startswith("package:/data/app/"):
            raise RuntimeError("Physical APK must be one installed base package")
        result = shell("sha256sum", shlex.quote(paths[0][8:])).split()
        if not result or result[0] != payload["apk"]["sha256"]:
            raise RuntimeError("Existing physical APK differs; refusing to update or reset its profile")
        details = shell("dumpsys", "package", APPLICATION_ID)
        version = re.search(r"\bversionCode=(\d+)\b", details)
        name = re.search(r"(?m)^\s*versionName=(\S+)", details)
        if (version is None or int(version[1]) != payload["versionCode"] or name is None
                or name[1] != payload["buildIdentity"]["version"]):
            raise RuntimeError("Physical installed APK version differs from its producer receipt")
        value["versionName"] = name[1]
        value["certificateAdmission"] = "exact-producer-admitted-apk-bytes"
        passed("installed-apk-version-bytes-certificate")
        if not execute:
            value["status"] = "passed"
            return report
        if not value["ownedInstallation"]:
            raise RuntimeError("Unknown installed phone profile is read-only; provide this harness's installation receipt")
        if render_webui:
            from .rust_webui_live_proof import require_file_link_browser
            require_file_link_browser()
        value["phase"] = "normal-app-setup"
        ui = ProductionUi(command, prefix=prefix)
        shell("am", "start", "-W", "--user", "0", "-n", APPLICATION_ID + "/.MainActivity")
        state = ui.find("service_status").get("text")
        if state != "Stopped":
            raise RuntimeError("Physical app must be stopped before the bounded owned smoke")
        value["permissions"] = _normal_permission_setup(ui, api=api, changes=value["permissionChanges"])
        if not value["permissions"]["complete"]:
            value.update(status="setup-required", phase="complete-permissions-in-normal-app-ui")
            return report
        # A fresh Incoming folder is implicitly shared. Never enumerate or
        # publish pre-existing phone files before REST can select a test root.
        incoming = shell("sh", "-c", shlex.quote(
            "if test -L /sdcard/Download/eMuleBB; then echo redirected; "
            "elif test -d /sdcard/Download/eMuleBB; then ls -A /sdcard/Download/eMuleBB; "
            "elif test -e /sdcard/Download/eMuleBB; then echo non-directory; else echo absent; fi"))
        if incoming not in {"", "absent"}:
            raise RuntimeError("Default incoming is not empty; refusing first-start implicit sharing of phone files")
        passed("empty-default-incoming-before-first-start")
        bind = ui.find("bind_addr", enabled=True).get("text", "")
        match = re.fullmatch(r"(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]*)", bind)
        if match is None or int(match[1]) > 65535:
            raise RuntimeError("Physical smoke requires the app's loopback REST binding")
        remote_port = int(match[1])
        key = ui.find("api_key", enabled=True).get("text", "")
        if not 32 <= len(key) <= 512 or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise RuntimeError("Physical app UI did not expose a valid generated API key")
        forwarded = command(*prefix, "forward", "--no-rebind", "tcp:0", f"tcp:{remote_port}")
        if re.fullmatch(r"[1-9][0-9]*", forwarded) is None or int(forwarded) > 65535:
            raise RuntimeError("Physical smoke could not allocate its private REST forward")
        port = int(forwarded)
        value.update(phase="ordinary-default-first-start", networkIsolation="not-claimed",
                     startupNetworkBehavior="production-public-discovery-and-auto-connect-defaults")
        attempted_start = True
        ui.click("start_service")
        ui.wait_state("Running")
        if _request(port, "/api/v1/app")[0] != 401:
            raise RuntimeError("Physical APK REST did not enforce authentication")
        app()
        value["runtimeExecution"] = "executed"
        passed("authenticated-source-bound-physical-readiness")
        status, body = _request(port, "/")
        if status != 200 or b"<html" not in body.lower():
            raise RuntimeError("Physical APK did not serve its bundled WebUI")
        value["webui"] = {"served": True, "rendered": "not-run"}
        passed("physical-bundled-webui-served")
        value["phase"] = "physical-process-resources"
        value["processResources"] = _physical_process_resources(port, key)
        passed("physical-process-resources")
        if render_webui:
            from .rust_webui_live_proof import run_webui_live_proof
            browser = run_webui_live_proof(base_url=f"http://127.0.0.1:{port}", api_key=key,
                report_path=report_dir / "physical-webui.json", steady_seconds=1, tab_wait_seconds=0.1,
                timeout_seconds=15, max_main_thread_busy_ratio=1, navigation_only=True)
            if browser.get("status") != "passed":
                raise RuntimeError("Physical bundled WebUI browser proof failed")
            value["webui"]["rendered"] = "passed"
            passed("physical-bundled-webui-rendered")
        value["phase"] = "bounded-foreground-observation"
        started = time.monotonic()
        samples = 0
        while True:
            app()
            samples += 1
            elapsed = time.monotonic() - started
            if elapsed >= dwell_seconds:
                break
            time.sleep(min(5, dwell_seconds - elapsed))
        value["foregroundObservation"] = {"seconds": round(elapsed, 3), "samples": samples}
        passed("bounded-physical-foreground-observation")
        ui.click("stop_service")
        ui.wait_state("Stopped")
        assert_stopped()
        attempted_start = False
        passed("physical-graceful-stop")
        value.update(status="passed", phase="complete")
        return report
    except Exception as error:
        value["errorType"] = type(error).__name__
        raise
    finally:
        active_failure = sys.exc_info()[0] is not None
        cleanup_errors = []
        if attempted_start and ui is not None:
            try:
                shell("am", "start", "-W", "--user", "0", "-n", APPLICATION_ID + "/.MainActivity")
                state = ui.find("service_status").get("text")
                if state in {"Running", "Starting"}:
                    ui.click("stop_service")
                    ui.wait_state("Stopped")
                elif state not in {"Stopped", "Failed"}:
                    ui.wait_state("Stopped")
                assert_stopped()
            except Exception as error:
                cleanup_errors.append({"action": "normal-ui-stop", "errorType": type(error).__name__})
        if port is not None:
            try:
                rows = [row.split() for row in command(*prefix, "forward", "--list").splitlines()]
                existing = [row for row in rows if len(row) == 3 and row[1] == f"tcp:{port}"]
                if existing and existing != [[serial, f"tcp:{port}", f"tcp:{remote_port}"]]:
                    raise RuntimeError("Physical REST forward ownership changed; refusing removal")
                if existing:
                    command(*prefix, "forward", "--remove", f"tcp:{port}")
            except Exception as error:
                cleanup_errors.append({"action": "remove-owned-forward", "errorType": type(error).__name__})
        if ui is not None:
            try:
                shell("rm", "-f", ui.path)
            except Exception as error:
                cleanup_errors.append({"action": "remove-transient-ui", "errorType": type(error).__name__})
        if cleanup_errors:
            value.update(status="failed", cleanupErrors=cleanup_errors)
        report.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        if cleanup_errors and not active_failure:
            raise RuntimeError("Physical smoke cleanup failed; inspect its sanitized receipt")
