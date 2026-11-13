"""Bounded physical-phone admission and smoke; preserve the operator ADB server.

WHY: the emulator owner owns a disposable guest and intentionally changes boot,
permissions and power state. A real phone needs a separate, narrower owner.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time

from .android_apk_lifecycle import APPLICATION_ID, DeviceUiUnavailable, ProductionUi, _request, admit_production_certificate, required_apk_cases
from .android_apk_profile import OwnedUpdateApproval, admit_owned_update, admit_storage_configuration, read_hashed_receipt


def _safe_service_phase(text: str | None) -> str:
    """Classify only source-owned status values; never retain arbitrary screen text."""
    if text in {"Stopped", "Starting", "Running", "Stopping", "Failed"}:
        return text
    if text == "Service connection interrupted":
        return "connection-interrupted"
    return "unrecognized"


def _ui_failure_metadata(ui: ProductionUi) -> dict:
    """Retain only resource IDs/boolean flags and foreground package, never UI values."""
    result = {"foregroundPackage": None}
    if getattr(ui, "last_action", None) is not None:
        result["lastAction"] = ui.last_action
    errors = []
    try:
        elements = ui.elements()
        status = next((node for node in elements if node.get("resource-id") == APPLICATION_ID + ":id/service_status"), {})
        result["servicePhase"] = _safe_service_phase(status.get("text"))
        controls = []
        for node in elements:
            resource = node.get("resource-id", "")
            if re.fullmatch(r"[A-Za-z0-9_.]+:id/[A-Za-z0-9_]+", resource):
                controls.append({"resourceId": resource, **{flag: node.get(flag) == "true" for flag in (
                    "enabled", "clickable", "checkable", "checked", "focusable", "focused", "scrollable", "password")}})
        result.update(hierarchyNodeCount=len(elements), resourceControlCount=len(controls),
                      controls=controls[:128], controlsTruncated=len(controls) > 128)
    except Exception as error:
        errors.append({"action": "resource-ids", "errorType": type(error).__name__})
    try:
        activities = ui.shell("dumpsys", "activity", "activities")
        match = re.search(r"(?:mResumedActivity|topResumedActivity)[^\n]*?\b([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/", activities)
        if match:
            result["foregroundPackage"] = match[1]
    except Exception as error:
        errors.append({"action": "foreground-package", "errorType": type(error).__name__})
    if errors:
        result["inspectionErrors"] = errors
    return result


def runtime_permission_granted(document: str, permission: str) -> bool:
    """Read only the selected package's User 0 runtime-permission grant record."""
    if len(document.encode("utf-8")) > 1024**2:
        raise RuntimeError("Android package permission dump exceeds its bound")
    lines = document.splitlines()

    def block(start):
        indent = len(lines[start]) - len(lines[start].lstrip())
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line.strip() and (len(line) - len(line.lstrip()) <= indent
                                 or re.match(r"\s*Package \[", line)):
                break
            end += 1
        return range(start + 1, end)

    packages = [index for index, line in enumerate(lines)
                if re.match(r"\s*Package \[" + re.escape(APPLICATION_ID) + r"\](?:\s|$)", line)]
    if len(packages) != 1:
        raise RuntimeError("Android permission dump does not identify one selected package")
    users = [index for index in block(packages[0]) if re.match(r"\s*User 0:(?:\s|$)", lines[index])]
    if len(users) != 1 or re.search(r"\binstalled=true\b", lines[users[0]]) is None:
        raise RuntimeError("Android permission dump does not identify the installed primary-user package")
    sections = [index for index in block(users[0]) if lines[index].strip() == "runtime permissions:"]
    if not sections:
        return False
    if len(sections) != 1:
        raise RuntimeError("Android package has ambiguous runtime permission sections")
    matches = []
    for index in block(sections[0]):
        match = re.match(r"\s*" + re.escape(permission) + r":\s*granted=(true|false)(?:,|\s|$)", lines[index])
        if match:
            matches.append(match[1] == "true")
    if len(matches) > 1:
        raise RuntimeError("Android package has ambiguous runtime permission records")
    return bool(matches and matches[0])


def _normal_permission_setup(ui: ProductionUi, *, api: int, changes: list) -> dict:
    """Grant only this owned install through app buttons and unambiguous stock UI."""
    def granted(permission):
        if permission == "MANAGE_EXTERNAL_STORAGE":
            return bool(re.search(r"MANAGE_EXTERNAL_STORAGE:\s*allow\b", ui.shell(
                "appops", "get", "--user", "0", APPLICATION_ID, permission)))
        return runtime_permission_granted(ui.shell("dumpsys", "package", APPLICATION_ID),
                                          "android.permission." + permission)

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
            if _safe_service_phase(ui.find("service_status").get("text")) not in {"Stopped", "Failed"}:
                raise RuntimeError("Physical app changed service phase during normal permission setup")

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


def _stopped_service_flags(ui: ProductionUi) -> dict:
    """Independently require the owned service's foreground/start flags to clear."""
    deadline = time.monotonic() + 15
    while True:
        document = ui.shell("dumpsys", "activity", "services", APPLICATION_ID)
        if "ACTIVITY MANAGER SERVICES" not in document:
            raise RuntimeError("Physical foreground-service state is unavailable")
        present = "DaemonService" in document
        foreground = re.findall(r"\bisForeground=(true|false)\b", document)
        requested = re.findall(r"\bstartRequested=(true|false)\b", document)
        # ServiceRecord.dump omits its foreground fields once both the flag and
        # foreground notification ID are clear. startRequested is still dumped.
        if not present or (requested and "true" not in foreground and "true" not in requested):
            return {"present": present, "foreground": False, "startRequested": False}
        if time.monotonic() >= deadline:
            raise RuntimeError("Physical service remained foreground or start-requested after Stop")
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

    def command(self, *arguments, check=True, timeout=10, binary=False, owned_update: OwnedUpdateApproval | None = None):
        if arguments[:2] != ("-s", self.serial):
            raise RuntimeError("Physical ADB operations require the exact admitted device serial")
        if len(arguments) < 3 or arguments[2] in {
            "start-server", "kill-server", "connect", "disconnect", "pair", "root", "unroot",
            "reboot", "remount", "uninstall", "reverse",
        }:
            raise RuntimeError("Physical owner cannot manage ADB transports or destructive device lifecycle")
        if arguments[2] == "install":
            if any(flag in arguments[3:] for flag in {"-d", "--enable-rollback"}):
                raise RuntimeError("Physical owner cannot downgrade an installed phone package")
            if "-r" in arguments[3:]:
                if not isinstance(owned_update, OwnedUpdateApproval) or arguments[-1] != owned_update.target_path:
                    raise RuntimeError("Physical owner cannot replace a package without verified owned-update admission")
                with Path(owned_update.target_path).open("rb") as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != owned_update.target_sha256:
                        raise RuntimeError("Admitted phone update APK bytes changed before installation")
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
                                    capture_output=True, text=not binary, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("Selected physical-device ADB operation failed") from None
        if len(result.stdout) > 1024**2 or len(result.stderr) > 1024**2 or check and result.returncode:
            # Raw output can contain private endpoints, paths or the visible key.
            raise RuntimeError("Selected physical-device ADB operation failed")
        return (result.stdout if binary else result.stdout.strip()) if result.returncode == 0 else (b"" if binary else "")

    def spawn_peer(self, adb, child, executable, cwd, library_dir, report_dir):
        """Own one selected-device CLI client; discard potentially private native logs."""
        if (re.fullmatch(r"/data/local/tmp/emulebb-apk-peer-[0-9a-f]{32}", cwd) is None
                or executable != cwd + "/emulebb-rust" or library_dir != cwd):
            raise RuntimeError("Physical peer launcher requires its fresh owned temporary directory")
        if existing_adb_server_version(self.server_port) != self.version:
            raise RuntimeError("Operator ADB server version changed before peer launch")
        script = ("cd " + shlex.quote(cwd) + " && printf '%s\\n' \"$$\" > "
                  + shlex.quote(cwd + "/owned-daemon.pid") + " && exec env LD_LIBRARY_PATH="
                  + shlex.quote(library_dir) + " " + shlex.quote(executable))
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        try:
            process = subprocess.Popen([str(self.adb), "-H", "127.0.0.1", "-P", str(self.server_port),
                "-s", self.serial, "shell", "sh", "-c", shlex.quote(script)], env=os.environ.copy(),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("Owned physical Android peer launch failed") from None
        return process, None

    @staticmethod
    def stop_peer_client(process):
        """Stop only the owned local ADB client after guest identity-aware cleanup."""
        from .rust_client import stop_process_tree
        stop_process_tree(process)


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
                          render_webui: bool = False, configure_storage: bool = False,
                          allow_owned_compatible_update: bool = False,
                          configuration_receipt: Path | None = None, configuration_receipt_sha256: str | None = None,
                          compatibility_receipt: Path | None = None, compatibility_receipt_sha256: str | None = None) -> Path:
    """Admit/install or run a bounded owned-phone smoke without resetting user state.

    Runtime is limited to a package installed here while previously absent, or a
    prior hash-bound receipt for that installation. Unknown existing profiles are
    read-only. Public first-run bootstrap is ordinary app behavior, not isolation.
    """
    admit_production_certificate(payload, expected_cert_sha256=expected_cert_sha256)
    if configure_storage and not execute:
        raise ValueError("Approved phone storage configuration requires explicit runtime execution")
    if not allow_owned_compatible_update and (compatibility_receipt is not None or compatibility_receipt_sha256 is not None):
        raise ValueError("Compatible phone update evidence requires explicit update opt-in")
    if type(dwell_seconds) is not int or not 15 <= dwell_seconds <= 300:
        raise ValueError("Physical foreground observation must be between 15 and 300 seconds")
    if type(payload.get("versionCode")) is not int or not 1 <= payload["versionCode"] <= 2_100_000_000:
        raise ValueError("Physical admission requires the producer's exact APK versionCode")
    device_hash = hashlib.sha256(serial.encode()).hexdigest()
    configured_storage = None
    update_approval = None
    if allow_owned_compatible_update:
        update_approval = admit_owned_update(payload, device_hash=device_hash, expected_cert_sha256=expected_cert_sha256,
            installation=read_hashed_receipt(installation_receipt, installation_receipt_sha256),
            configuration=read_hashed_receipt(configuration_receipt, configuration_receipt_sha256),
            compatibility=read_hashed_receipt(compatibility_receipt, compatibility_receipt_sha256))
        configured_storage = read_hashed_receipt(configuration_receipt, configuration_receipt_sha256)
    elif configuration_receipt is not None or configuration_receipt_sha256 is not None:
        configured_storage = read_hashed_receipt(configuration_receipt, configuration_receipt_sha256)
    output_root = output_root.resolve()
    if (not output_root.is_dir() or report_dir.exists() or report_dir.is_symlink()
            or not report_dir.resolve().is_relative_to(output_root) or report_dir.resolve() == output_root):
        raise RuntimeError("Physical evidence requires a fresh directory below the configured output root")
    report_dir.mkdir(parents=True, mode=0o700)
    report = report_dir / "physical-device.json"
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
    previous_bootstrap = None

    def shell(*args, **kwargs):
        return command(*prefix, "shell", *args, **kwargs)

    def open_main():
        # A normal wake event exposes UI without changing timeouts or bypassing
        # a PIN; ProductionUi still rejects an observed locked device.
        shell("input", "keyevent", "KEYCODE_WAKEUP")
        shell("am", "start", "-W", "--user", "0", "-n", APPLICATION_ID + "/.MainActivity")

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

    def restart_for_storage():
        nonlocal attempted_start
        value["phase"] = "restart-approved-storage-stop"
        open_main()
        ui.click("stop_service")
        ui.wait_state("Stopped", timeout=30)
        assert_stopped()
        _stopped_service_flags(ui)
        attempted_start = False
        value["phase"] = "restart-approved-storage-start"
        attempted_start = True
        ui.click("start_service")
        ui.wait_state("Running")
        app()

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
            if update_approval is not None:
                raise RuntimeError("Compatible update expected its owned installed package to remain present")
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
        installed_sha = result[0] if result else None
        if installed_sha != payload["apk"]["sha256"]:
            if update_approval is None or installed_sha != update_approval.installed["apkSha256"]:
                raise RuntimeError("Existing physical APK differs; refusing to update or reset its profile")
            details = shell("dumpsys", "package", APPLICATION_ID)
            version = re.search(r"\bversionCode=(\d+)\b", details)
            name = re.search(r"(?m)^\s*versionName=(\S+)", details)
            if (version is None or int(version[1]) != update_approval.installed["versionCode"]
                    or name is None or name[1] != update_approval.installed["versionName"]
                    or any(int(user) != 0 for user in re.findall(r"\bUser (\d+):[^\n]*\binstalled=true\b", details))):
                raise RuntimeError("Compatible update installed version or user ownership differs")
            value["phase"] = "stop-owned-service-before-compatible-update"
            ui = ProductionUi(command, prefix=prefix)
            open_main()
            state = _safe_service_phase(ui.find("service_status").get("text"))
            if state in {"Starting", "Running"}:
                ui.click("stop_service")
                ui.wait_state("Stopped", timeout=30)
            elif state not in {"Stopped", "Failed"}:
                raise RuntimeError("Owned compatible update requires a stable quiescent service")
            bind = ui.find("bind_addr", enabled=True).get("text", "")
            match = re.fullmatch(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|\[::1\]):([1-9][0-9]*)", bind)
            if match is None or int(match[1]) > 65535:
                raise RuntimeError("Owned update cannot verify the previous REST listener")
            remote_port = int(match[1])
            previous_bootstrap = {"bind": bind, "key": ui.find("api_key", enabled=True).get("text", ""),
                                  "boot": ui.find("resume_on_boot").get("checked")}
            if len(previous_bootstrap["key"]) < 32 or previous_bootstrap["boot"] not in {"true", "false"}:
                raise RuntimeError("Owned update cannot inspect its existing bootstrap preferences")
            forwarded = command(*prefix, "forward", "--no-rebind", "tcp:0", f"tcp:{remote_port}")
            if re.fullmatch(r"[1-9][0-9]*", forwarded) is None or int(forwarded) > 65535:
                raise RuntimeError("Owned update cannot allocate its previous-listener probe")
            port = int(forwarded)
            assert_stopped()
            _stopped_service_flags(ui)
            value["phase"] = "install-owned-compatible-update"
            command(*prefix, "install", "-r", "--no-streaming", "--user", "0", payload["payloadPath"],
                    timeout=120, owned_update=update_approval)
            package = shell("pm", "path", "--user", "0", APPLICATION_ID)
            paths = package.splitlines()
            if len(paths) != 1 or not paths[0].startswith("package:/data/app/"):
                raise RuntimeError("Compatible update did not produce one base package")
            result = shell("sha256sum", shlex.quote(paths[0][8:])).split()
            if not result or result[0] != payload["apk"]["sha256"]:
                raise RuntimeError("Compatible update installed bytes differ from the admitted APK")
        if update_approval is not None:
            value["ownedInstallation"] = True
            value["ownedCompatibleUpdate"] = {"fromSourceRevision": update_approval.installed["sourceRevision"],
                "fromApkSha256": update_approval.installed["apkSha256"], "metadataSchemaSha256": update_approval.schema_sha256,
                "configurationReceiptSha256": configuration_receipt_sha256,
                "installationPerformed": installed_sha != payload["apk"]["sha256"], "resetOrMigration": False}
        details = shell("dumpsys", "package", APPLICATION_ID)
        version = re.search(r"\bversionCode=(\d+)\b", details)
        name = re.search(r"(?m)^\s*versionName=(\S+)", details)
        if (version is None or int(version[1]) != payload["versionCode"] or name is None
                or name[1] != payload["buildIdentity"]["version"]):
            raise RuntimeError("Physical installed APK version differs from its producer receipt")
        value["versionName"] = name[1]
        value["certificateAdmission"] = "exact-producer-admitted-apk-bytes"
        passed("installed-apk-version-bytes-certificate")
        if previous_bootstrap is not None:
            value["phase"] = "verify-owned-update-bootstrap-preservation"
            open_main()
            if (ui.find("bind_addr", enabled=True).get("text") != previous_bootstrap["bind"]
                    or ui.find("api_key", enabled=True).get("text") != previous_bootstrap["key"]
                    or ui.find("resume_on_boot").get("checked") != previous_bootstrap["boot"]):
                raise RuntimeError("Owned compatible update changed bootstrap or reboot preferences")
            value["ownedCompatibleUpdate"]["bootstrapPreferencesPreserved"] = True
        if configured_storage is not None:
            if update_approval is None:
                admit_storage_configuration(configured_storage, installation=value)
            value["admittedStorageConfiguration"] = {"incomingDir": configured_storage["incomingDir"],
                "sharedRoot": configured_storage["sharedRoot"], "receiptSha256": configuration_receipt_sha256}
        if not execute:
            value["status"] = "passed"
            return report
        if not value["ownedInstallation"]:
            raise RuntimeError("Unknown installed phone profile is read-only; provide this harness's installation receipt")
        if render_webui:
            from .rust_webui_live_proof import require_file_link_browser
            require_file_link_browser()
        value["phase"] = "normal-app-launch"
        if ui is None:
            ui = ProductionUi(command, prefix=prefix)
        open_main()
        value["phase"] = "inspect-initial-service-phase"
        state = _safe_service_phase(ui.find("service_status").get("text"))
        value["initialServicePhase"] = state
        if state in {"Starting", "Running"}:
            value["phase"] = "normalize-owned-service-stop"
            value["initialServiceNormalization"] = {"from": state, "method": "normal-ui-stop", "status": "attempted"}
            # Also attempt a graceful stop on failure: the exact installed APK
            # and prior owned-install receipt already admit this running service.
            attempted_start = True
            ui.click("stop_service")
            ui.wait_state("Stopped", timeout=30)
            attempted_start = False
            value["initialServiceNormalization"]["status"] = "passed"
            passed("owned-existing-service-gracefully-stopped")
        elif state not in {"Stopped", "Failed"}:
            raise RuntimeError("Physical app has no stable admitted service phase")
        value["phase"] = "normal-permission-ui"
        value["permissions"] = _normal_permission_setup(ui, api=api, changes=value["permissionChanges"])
        if not value["permissions"]["complete"]:
            value.update(status="setup-required", phase="complete-permissions-in-normal-app-ui")
            return report
        # A fresh Incoming folder is implicitly shared. Never enumerate or
        # publish pre-existing phone files before REST can select a test root.
        if configured_storage is None:
            value["phase"] = "inspect-empty-default-incoming"
            incoming = shell("sh", "-c", shlex.quote(
                "if test -L /sdcard/Download/eMuleBB; then echo redirected; "
                "elif test -d /sdcard/Download/eMuleBB; then ls -A /sdcard/Download/eMuleBB; "
                "elif test -e /sdcard/Download/eMuleBB; then echo non-directory; else echo absent; fi"))
            if incoming not in {"", "absent"}:
                raise RuntimeError("Default incoming is not empty; refusing first-start implicit sharing of phone files")
            passed("empty-default-incoming-before-first-start")
        value["phase"] = "read-bootstrap-bind-address"
        bind = ui.find("bind_addr", enabled=True).get("text", "")
        match = re.fullmatch(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|\[::1\]):([1-9][0-9]*)", bind)
        if match is None or int(match[1]) > 65535:
            raise RuntimeError("Physical smoke requires wildcard or loopback REST reachable through its owned forward")
        if remote_port is not None and int(match[1]) != remote_port:
            raise RuntimeError("Owned compatible update changed its persisted REST port unexpectedly")
        remote_port = int(match[1])
        value["phase"] = "read-bootstrap-api-key"
        key = ui.find("api_key", enabled=True).get("text", "")
        if not 32 <= len(key) <= 512 or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise RuntimeError("Physical app UI did not expose a valid generated API key")
        if port is None:
            value["phase"] = "allocate-owned-rest-forward"
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
        if configured_storage is not None:
            from .rust_local_ed2k import request_json
            value["phase"] = "verify-prepared-storage-after-start"
            try:
                settings = request_json(f"http://127.0.0.1:{port}", "GET", "/api/v1/app/settings", key)
                roots = request_json(f"http://127.0.0.1:{port}", "GET", "/api/v1/shared-directories", key).get("roots", [])
                if (settings.get("daemon", {}).get("incomingDir") != configured_storage["incomingDir"]
                        or configured_storage["sharedRoot"] not in {root.get("path") for root in roots}):
                    raise RuntimeError("Prepared phone storage settings differ")
            except Exception:
                raise RuntimeError("Phone storage configuration did not survive startup/update") from None
            passed("prepared-storage-configuration-survives-startup")
        if configure_storage:
            from .android_apk_profile import configure_storage as prepare_storage
            value["phase"] = "persist-approved-storage-configuration"
            value["storageConfiguration"] = prepare_storage(command, prefix=prefix,
                base_url=f"http://127.0.0.1:{port}", api_key=key, payload=payload, device_hash=device_hash,
                report_path=report_dir / "storage-configuration.json", restart_service=restart_for_storage)
            passed("approved-storage-configuration-persisted")
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
        value["phase"] = "normal-ui-stop"
        open_main()
        ui.click("stop_service")
        value["phase"] = "wait-normal-ui-stop"
        ui.wait_state("Stopped", timeout=30)
        value["phase"] = "verify-stopped-rest-listener"
        assert_stopped()
        value["phase"] = "verify-stopped-service-flags"
        value["stoppedService"] = _stopped_service_flags(ui)
        attempted_start = False
        passed("physical-graceful-stop")
        value.update(status="passed", phase="complete")
        return report
    except DeviceUiUnavailable as error:
        value["errorType"] = type(error).__name__
        if ui is not None:
            value["uiFailure"] = _ui_failure_metadata(ui)
        if error.reason == "device-locked" and not attempted_start:
            value.update(status="setup-required", phase="unlock-device-before-ui-interaction")
            return report
        raise
    except Exception as error:
        value["errorType"] = type(error).__name__
        if ui is not None:
            value["uiFailure"] = _ui_failure_metadata(ui)
        raise
    finally:
        active_failure = sys.exc_info()[0] is not None
        cleanup_errors = []
        if attempted_start and ui is not None:
            try:
                open_main()
                state = ui.find("service_status").get("text")
                if state in {"Running", "Starting"}:
                    ui.click("stop_service")
                    ui.wait_state("Stopped", timeout=30)
                elif state not in {"Stopped", "Failed"}:
                    ui.wait_state("Stopped", timeout=30)
                assert_stopped()
                _stopped_service_flags(ui)
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
