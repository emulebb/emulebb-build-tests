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
MIN_SCREEN_OFF_DWELL_SECONDS = 60
MIN_SCREEN_OFF_SAMPLES = 3
APK_LIFECYCLE_STAGES = frozenset({
    "install", "installed-identity", "rest-forward", "initial-start", "initial-wait-running",
    "initial-authentication", "bundled-webui", "graceful-stop", "notification-denial",
    "notification-restoration", "all-files-denial", "all-files-revocation",
    "all-files-restoration-grant", "all-files-restoration-reopen", "all-files-restoration-start",
    "all-files-restoration-wait-running", "all-files-restoration-authentication",
    "local-network-revocation", "local-network-restoration", "enable-boot-resume",
    "enabled-reboot", "enabled-reboot-authentication", "explicit-stop-reboot",
    "task-manager-stop-reboot", "force-stop-reboot", "restart", "local-transfer",
    "file-link-intents", "screen-off-doze", "case-coverage",
    "all-files-access", "notification-permission", "android-api", "local-network-permission",
    "battery-exemption", "wake-display", "dismiss-keyguard", "launch-main", "wait-stopped",
    "read-api-key", "validate-api-key", "read-boot-resume", "validate-boot-resume",
})
APK_LIFECYCLE_FAILURE_CODES = frozenset({
    "adb-command-failed", "command-timeout", "device-locked", "app-not-visible",
    "ui-too-large", "ui-malformed", "ui-ambiguous", "display-size-unavailable",
    "control-unreachable", "control-disabled", "control-invalid-bounds", "control-unsafe-bounds",
    "expected-state-not-reached",
    "invalid-generated-key", "unexpected-boot-default", "listener-still-running",
    "rest-authentication-failed", "boot-resume-not-retained", "reboot-incomplete",
    "boot-resume-timeout", "connection-error", "http-error", "other",
})
SETUP_SERVICE_PHASES = frozenset({"Stopped", "Starting", "Running", "Stopping", "Failed"})
SETUP_CONTROL_NAMES = frozenset({"service_status", "api_key", "resume_on_boot"})
APK_NAVIGATION_CONTROLS = frozenset({
    "service_status", "api_key", "resume_on_boot", "start_service", "stop_service", "open_webui",
    "pending_link", "pending_link_error", "app_version", "bind_addr", "save_settings",
    "grant_all_files_access", "allow_notifications", "allow_local_network", "share_diagnostics",
})
APK_POST_FAILURE_ERROR_CATEGORIES = frozenset({
    "boot-start-blocked", "foreground-promotion-denied", "required-files-permission",
    "required-local-network-permission", "recovery-budget-blocked", "unknown",
})
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
            or type(value.get("versionCode")) is not int or not 1 <= value["versionCode"] <= 2_100_000_000
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


class DeviceUiUnavailable(RuntimeError):
    """A fixed, non-sensitive reason why production UI interaction is unsafe."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__("Android device is locked" if reason == "device-locked" else "Production Android app UI is not visible")


def _lifecycle_failure(error: Exception, stage: str, observation: dict) -> dict:
    """Project only fixed lifecycle facts; arbitrary exception/UI text stays in memory."""
    import subprocess
    messages = {
        "Owned Android ADB command failed": "adb-command-failed",
        "APK UI exceeds its inspection bound": "ui-too-large",
        "APK UI dump is malformed": "ui-malformed",
        "APK UI has ambiguous resource controls": "ui-ambiguous",
        "Cannot determine owned Android display dimensions": "display-size-unavailable",
        "APK did not reach expected service state: Stopped": "expected-state-not-reached",
        "APK UI must expose a valid generated API key": "invalid-generated-key",
        "APK boot resume must initially be disabled": "unexpected-boot-default",
        "APK Stop left the REST listener running": "listener-still-running",
        "APK authenticated REST failed": "rest-authentication-failed",
        "APK boot resume setting was not retained": "boot-resume-not-retained",
        "APK reboot proof did not observe a fresh unlocked Android boot": "reboot-incomplete",
        "APK did not resume after an enabled reboot": "boot-resume-timeout",
    }
    code = messages.get(str(error), "other")
    if isinstance(error, DeviceUiUnavailable) and error.reason in {"device-locked", "app-not-visible"}:
        code = error.reason
    elif isinstance(error, subprocess.TimeoutExpired):
        code = "command-timeout"
    elif isinstance(error, ConnectionError):
        code = "connection-error"
    elif isinstance(error, http.client.HTTPException):
        code = "http-error"
    else:
        for state in SETUP_SERVICE_PHASES:
            if str(error) == "APK did not reach expected service state: " + state:
                code = "expected-state-not-reached"
        for name in SETUP_CONTROL_NAMES | {"start_service", "stop_service"}:
            if str(error) == "APK required control is not reachable: " + name:
                code = "control-unreachable"
            elif str(error) == "APK required control remains disabled: " + name:
                code = "control-disabled"
            elif str(error) == "APK required control has invalid bounds: " + name:
                code = "control-invalid-bounds"
            elif str(error) == "APK required control has no safe visible tap bounds: " + name:
                code = "control-unsafe-bounds"
    return {"stage": stage, "code": code, **observation}


def _diagnostic_bounds(value: str) -> list[int] | None:
    """Admit only bounded numeric geometry, never arbitrary UI attribute text."""
    match = re.fullmatch(r"\[(\d{1,5}),(\d{1,5})\]\[(\d{1,5}),(\d{1,5})\]", value)
    if match:
        rectangle = [int(item) for item in match.groups()]
        if max(rectangle) <= 32768:
            return rectangle
    return None


def _post_failure_ui(ui) -> dict:
    """Read bound production UI only after failed automatic boot, never press Start."""
    fixed = {
        "Android blocked automatic service startup. Open the app and check its battery settings.": "boot-start-blocked",
        "All-files access is required. Open the app to grant it.": "required-files-permission",
        "All-files access was revoked; stopping the daemon": "required-files-permission",
        "Grant all-files access before starting": "required-files-permission",
        "Local-network permission is required. Open the app to grant it.": "required-local-network-permission",
        "Local-network permission was revoked; stopping the daemon": "required-local-network-permission",
        "Allow local-network access before starting": "required-local-network-permission",
        "Repeated service termination; open the app and press Start to retry": "recovery-budget-blocked",
    }
    promotion_errors = {"ForegroundServiceStartNotAllowedException", "SecurityException", "MissingForegroundServiceTypeException",
                        "InvalidForegroundServiceTypeException", "ForegroundServiceTypeNotAllowedException",
                        "IllegalArgumentException", "IllegalStateException"}
    promotion_messages = {"Android refused the foreground service: " + error for error in promotion_errors}
    for attempt in range(3):
        boot = ui.find("resume_on_boot", enabled=True).get("checked")
        phase = ui.find("service_status").get("text")
        categories = set()
        for node in ui.elements():
            if node.get("package") != APPLICATION_ID or node.get("class") != "android.widget.TextView":
                continue
            text = node.get("text", "")
            if text in fixed:
                categories.add(fixed[text])
            elif text in promotion_messages:
                categories.add("foreground-promotion-denied")
        category = next(iter(categories)) if len(categories) == 1 else "unknown"
        # WHY: setup can enable controls between Binder connection and STATUS.
        # Initial Stopped/unchecked values alone cannot prove a service reply.
        # Never report those defaults as lost persisted state without a positive
        # reply signature; failed automatic boot remains the original verdict.
        if boot == "true" or phase in SETUP_SERVICE_PHASES - {"Stopped"} or category != "unknown":
            facts = {"errorCategory": category}
            if boot in {"true", "false"}:
                facts["resumeOnBoot"] = boot == "true"
            if phase in SETUP_SERVICE_PHASES:
                facts["servicePhase"] = phase
            return facts
        if attempt < 2:
            time.sleep(1)
    return {"errorCategory": "unknown"}


def _boot_timeout_facts(shell, *, api: int) -> dict:
    """Inspect the owned package after failed automatic resume, without launching it.

    AOSP ActivityManagerShellCommand, ServiceRecord and ApplicationExitInfo own
    these fixed formats. Unsupported, ambiguous or truncated facts are omitted.
    Private system dump values are transient and never copied into the receipt.
    """
    from datetime import datetime
    from .android_apk_device import runtime_permission_granted

    def read(*arguments):
        try:
            value = shell(*arguments)
            return value if isinstance(value, str) and len(value.encode("utf-8")) <= 65536 else None
        except Exception:
            return None

    facts = {}
    state = read("am", "get-started-user-state", "0")
    if state in {"BOOTING", "RUNNING_LOCKED", "RUNNING_UNLOCKING", "RUNNING_UNLOCKED", "STOPPING", "SHUTDOWN"}:
        facts["userUnlocked"] = state == "RUNNING_UNLOCKED"
    package = read("dumpsys", "package", APPLICATION_ID)
    if package is not None:
        try:
            facts["notificationsGranted"] = runtime_permission_granted(package, "android.permission.POST_NOTIFICATIONS")
            if api >= 37:
                facts["localNetworkGranted"] = runtime_permission_granted(package, "android.permission.ACCESS_LOCAL_NETWORK")
        except Exception:
            pass
        lines = package.splitlines()
        headers = [index for index, line in enumerate(lines)
                   if re.match(r"\s*Package \[" + re.escape(APPLICATION_ID) + r"\]", line)]
        if len(headers) == 1:
            start = headers[0]
            indent = len(lines[start]) - len(lines[start].lstrip())
            end = next((index for index in range(start + 1, len(lines)) if lines[index].strip()
                        and len(lines[index]) - len(lines[index].lstrip()) <= indent), len(lines))
            stopped = re.findall(r"(?m)^\s*User 0:[^\n]*\binstalled=true\b[^\n]*\bstopped=(true|false)\b",
                                 "\n".join(lines[start + 1:end]))
            if len(stopped) == 1:
                facts["packageStopped"] = stopped[0] == "true"
    # AOSP --brief indents component lines; --components emits only components.
    receiver = read("cmd", "package", "query-receivers", "--components", "--user", "0", "-a",
                    "android.intent.action.BOOT_COMPLETED", "-p", APPLICATION_ID)
    if receiver is not None:
        components = re.findall(r"(?m)^" + re.escape(APPLICATION_ID) + r"/(?:\.BootReceiver|org\.emulebb\.android\.BootReceiver)\s*$", receiver)
        if len(components) == 1:
            facts["bootReceiverResolved"] = True
        elif receiver.strip() == "No receivers found":
            facts["bootReceiverResolved"] = False
    services = read("dumpsys", "activity", "services", APPLICATION_ID)
    if services is not None and "ACTIVITY MANAGER SERVICES" in services:
        headers = re.findall(r"(?m)^\s*\* ServiceRecord\{[^\n]+", services)
        own = [header for header in headers if re.search(r"\bu0 " + re.escape(APPLICATION_ID) + r"/\.DaemonService(?:\s|\})", header)]
        if len(headers) == len(own) == 1:
            facts["servicePresent"] = True
            for token, field in (("isForeground", "serviceForeground"), ("startRequested", "serviceStartRequested")):
                values = re.findall(r"\b" + token + r"=(true|false)\b", services)
                if len(values) == 1:
                    facts[field] = values[0] == "true"
        elif not headers and re.search(r"(?m)^\s*\(nothing\)\s*$", services):
            facts["servicePresent"] = False
    files = read("appops", "get", "--user", "0", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE")
    if files is not None:
        modes = re.findall(r"(?m)^\s*MANAGE_EXTERNAL_STORAGE:\s*(allow|deny|ignore|default)\b", files)
        if len(modes) == 1:
            facts["allFilesAllowed"] = modes[0] == "allow"
    whitelist = read("dumpsys", "deviceidle", "whitelist")
    if whitelist is not None:
        rows = [line.strip().split(",") for line in whitelist.splitlines() if line.strip()]
        if rows and all(len(row) == 3 and row[0] in {"user", "system", "system-excidle"}
                        and re.fullmatch(r"[A-Za-z0-9_.]+", row[1]) and row[2].isdigit() for row in rows):
            facts["dozeWhitelisted"] = any(row[1] == APPLICATION_ID for row in rows)
    restriction = read("am", "get-bg-restriction-level", "--user", "0", APPLICATION_ID)
    if restriction in {"unrestricted", "exempted", "adaptive_bucket", "restricted_bucket", "background_restricted", "hibernation"}:
        facts["backgroundRestricted"] = restriction in {"background_restricted", "hibernation"}
    exits = read("dumpsys", "activity", "exit-info", APPLICATION_ID)
    if exits is not None and "ACTIVITY MANAGER PROCESS EXIT INFO" in exits:
        records = []
        for block in re.split(r"(?m)^\s*ApplicationExitInfo[^\n]*:\s*$", exits)[1:]:
            match = re.search(r"(?m)^\s*process=" + re.escape(APPLICATION_ID) + r":daemon reason=(\d{1,2})\b", block)
            timestamp = re.search(r"(?m)^\s*timestamp=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})[^\n]*\buser=0\s*$", block)
            if match and timestamp:
                try:
                    records.append((datetime.fromisoformat(timestamp[1]), int(match[1])))
                except ValueError:
                    pass
        if records:
            latest = max(time for time, _ in records)
            reasons = [reason for time, reason in records if time == latest]
            if len(reasons) == 1 and 0 <= reasons[0] <= 16:
                facts["latestDaemonExitReason"] = reasons[0]
    return facts


class ProductionUi:
    """Inspect only the production app UI on one explicitly selected device."""

    def __init__(self, command, *, prefix=PREFIX):
        self.command = command
        self.prefix = tuple(prefix)
        self.path = "/data/local/tmp/emulebb-apk-ui-" + uuid4().hex + ".xml"
        self.last_action = None
        self.setup_observation = {}
        self.navigation = {}
        self.scroll_bounds = None

    def shell(self, *args):
        return self.command(*self.prefix, "shell", *args)

    def _hierarchy(self):
        # WHY: AOSP DumpCommand can return success without writing a hierarchy
        # after null-root/idle failures. Invalidate only this owned UUID file so
        # an earlier screen can never authorize a tap on the current screen.
        self.shell("rm", "-f", self.path)
        self.shell("uiautomator", "dump", self.path)
        # This transient hierarchy contains the visible credential. Never copy
        # it to the host or retain it as a diagnostic artifact.
        return self.shell("cat", self.path)

    def inspect(self):
        hierarchy = self._hierarchy()
        nodes = ui_nodes(hierarchy)
        containers = [_diagnostic_bounds(node.get("bounds", "")) for node in ui_elements(hierarchy)
                      if node.get("package") == APPLICATION_ID and node.get("class") == "android.widget.ScrollView"]
        self.scroll_bounds = containers[0] if len(containers) == 1 and containers[0] is not None else None
        # WHY: setup failures precede daemon diagnostics; retain only closed
        # control flags and service phases, never the visible credential/text.
        self.setup_observation = {"controls": {
            name: {"present": name in nodes, "enabled": nodes.get(name, {}).get("enabled") == "true"}
            for name in sorted(SETUP_CONTROL_NAMES)}}
        phase = nodes.get("service_status", {}).get("text")
        if phase in SETUP_SERVICE_PHASES:
            self.setup_observation["servicePhase"] = phase
        return nodes

    def failure_navigation(self):
        """Add only a recognized IME visibility bit after a failed control search."""
        facts = dict(self.navigation)
        if not facts:
            return facts
        try:
            document = self.shell("dumpsys", "input_method")
            if isinstance(document, str) and len(document.encode("utf-8")) <= 65536:
                shown = re.findall(r"\bmInputShown=(true|false)\b", document)
                if len(shown) == 1:
                    facts["imeVisible"] = shown[0] == "true"
        except Exception:
            pass
        return facts

    def elements(self):
        """Inspect stock permission UI only in memory, with the same size bound."""
        return ui_elements(self._hierarchy())

    def _require_app(self, nodes):
        if nodes:
            return
        elements = self.elements()
        locked = any(node.get("resource-id") in {
            "com.android.systemui:id/keyguard_root_view", "com.android.systemui:id/keyguard_status_view",
        } for node in elements)
        if not locked:
            policy = self.shell("dumpsys", "window", "policy")
            locked = re.search(r"(?m)^\s*(?:mShowingLockscreen|mKeyguardShowing|showingAndNotOccluded)\s*[:=]\s*true\b", policy) is not None
        raise DeviceUiUnavailable("device-locked" if locked else "app-not-visible")

    def find(self, name, *, enabled=False):
        size = re.findall(r"(\d+)x(\d+)", self.shell("wm", "size"))
        if not size:
            raise RuntimeError("Cannot determine owned Android display dimensions")
        width, height = map(int, size[-1])
        self.navigation = ({"control": name, "forwardAttempts": 0, "backwardAttempts": 0,
                            "forwardProgress": 0, "backwardProgress": 0}
                           if name in APK_NAVIGATION_CONTROLS else {})
        if self.navigation and 0 < width <= 32768 and 0 < height <= 32768:
            self.navigation["displayBounds"] = [0, 0, width, height]
        deadline = time.monotonic() + 60
        while True:
            nodes = self.inspect()
            if self.navigation and self.scroll_bounds is not None:
                self.navigation["scrollBounds"] = self.scroll_bounds
            self._require_app(nodes)
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
                    self._require_app(nodes)
                    first, last = (height * 3 // 4, height // 4) if direction == 1 else (height // 4, height * 3 // 4)
                    before = {(key, tuple(_diagnostic_bounds(node.get("bounds", "")) or [])) for key, node in nodes.items()}
                    self.shell("input", "swipe", str(width // 2), str(first), str(width // 2), str(last), "250")
                    nodes = self.inspect()
                    if self.navigation:
                        prefix = "forward" if direction == 1 else "backward"
                        self.navigation[prefix + "Attempts"] = min(6, self.navigation[prefix + "Attempts"] + 1)
                        after = {(key, tuple(_diagnostic_bounds(node.get("bounds", "")) or [])) for key, node in nodes.items()}
                        self.navigation[prefix + "Progress"] = min(6, self.navigation[prefix + "Progress"] + int(before != after))
                        gesture = [width // 2, first, width // 2, last]
                        if max(gesture) <= 32768:
                            self.navigation["lastGesture"] = gesture
                        if self.scroll_bounds is not None:
                            self.navigation["scrollBounds"] = self.scroll_bounds
                    if name in nodes:
                        break
                if name in nodes:
                    break
            if name not in nodes:
                raise RuntimeError("APK required control is not reachable: " + name)

    def click(self, name):
        size = re.findall(r"(\d+)x(\d+)", self.shell("wm", "size"))
        if not size:
            raise RuntimeError("Cannot determine owned Android display dimensions")
        width, height = map(int, size[-1])
        top, bottom = height // 8, height * 7 // 8
        for attempt in range(7):
            node = self.find(name, enabled=True)
            bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
            if bounds is None:
                raise RuntimeError("APK required control has invalid bounds: " + name)
            x1, y1, x2, y2 = map(int, bounds.groups())
            self.last_action = {"resourceId": APPLICATION_ID + ":id/" + name, "bounds": [x1, y1, x2, y2],
                                "viewport": [0, top, width, bottom], "scrollAttempts": attempt, "tapped": False}
            if 0 <= x1 < x2 <= width and top <= y1 < y2 <= bottom:
                current = self.inspect()
                self._require_app(current)
                if (name not in current or current[name].get("bounds") != node.get("bounds")
                        or current[name].get("enabled") != "true"):
                    continue
                self.shell("input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
                self.last_action["tapped"] = True
                return
            if attempt == 6 or x2 <= x1 or y2 <= y1:
                raise RuntimeError("APK required control has no safe visible tap bounds: " + name)
            # Immutable older APKs can draw behind gesture/status bars. Move the
            # whole control into the central content area before any tap.
            first, last = (height * 3 // 4, height // 2) if y2 > bottom else (height // 4, height // 2)
            self._require_app(self.inspect())
            self.shell("input", "swipe", str(width // 2), str(first), str(width // 2), str(last), "250")

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
    setup_stage = "install"
    boot_observation = None
    post_failure_ui = None
    primary_ui_observation = None
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

    def prepare_fresh_guest_ui(*, initial=False):
        nonlocal setup_stage
        # WHY: sys.boot_completed does not imply a visible unlocked display.
        # This owned fresh guest uses normal wake/insecure-keyguard dismissal;
        # secure credential challenges still fail the existing UI admission.
        if initial:
            setup_stage = "wake-display"
        shell("input", "keyevent", "KEYCODE_WAKEUP")
        if initial:
            setup_stage = "dismiss-keyguard"
        shell("wm", "dismiss-keyguard")

    def reboot():
        previous = shell("cat", "/proc/sys/kernel/random/boot_id")
        command(*PREFIX, "reboot")
        deadline = time.monotonic() + 180
        while True:
            booted = command(*PREFIX, "shell", "getprop", "sys.boot_completed", check=False)
            boot_id = command(*PREFIX, "shell", "cat", "/proc/sys/kernel/random/boot_id", check=False)
            if booted == "1" and boot_id and boot_id != previous:
                prepare_fresh_guest_ui()
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
        if boot_observation is not None:
            boot_observation["restAttempts"] = min(1024, boot_observation["restAttempts"] + 1)
        try:
            status, raw = _request(port, "/api/v1/app", key)
        except (OSError, http.client.HTTPException):
            if boot_observation is not None:
                boot_observation["restConnectionFailures"] = min(1024, boot_observation["restConnectionFailures"] + 1)
            raise
        if boot_observation is not None:
            boot_observation["restHttpResponses"] = min(1024, boot_observation["restHttpResponses"] + 1)
            if type(status) is int and 100 <= status <= 599:
                boot_observation["lastHttpStatus"] = status
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
        setup_stage = "installed-identity"
        package_path = shell("pm", "path", APPLICATION_ID)
        paths = package_path.splitlines()
        if len(paths) != 1 or not paths[0].startswith("package:/data/app/"):
            raise RuntimeError("APK installation must produce exactly one base package")
        if shell("sha256sum", paths[0][8:]).split()[0] != payload["apk"]["sha256"]:
            raise RuntimeError("Installed APK bytes differ from qualified payload")
        codes = re.findall(r"\bversionCode=(\d+)\b", shell("dumpsys", "package", APPLICATION_ID))
        if len(codes) != 1 or int(codes[0]) != payload["versionCode"]:
            raise RuntimeError("Installed APK versionCode differs from qualified payload")
        result["versionCode"] = int(codes[0])
        passed("installed-apk-identity")
        setup_stage = "all-files-access"
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow")
        setup_stage = "notification-permission"
        shell("pm", "grant", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        setup_stage = "android-api"
        api = int(shell("getprop", "ro.build.version.sdk"))
        result["androidApiLevel"] = api
        if api >= 37:
            setup_stage = "local-network-permission"
            shell("pm", "grant", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
        setup_stage = "battery-exemption"
        shell("dumpsys", "deviceidle", "whitelist", "+" + APPLICATION_ID)
        prepare_fresh_guest_ui(initial=True)
        setup_stage = "launch-main"
        reopen()
        setup_stage = "wait-stopped"
        wait_state("Stopped")
        setup_stage = "read-api-key"
        key = find("api_key", enabled=True).get("text", "")
        setup_stage = "validate-api-key"
        if len(key) < 32 or not all(33 <= ord(c) <= 126 for c in key):
            raise RuntimeError("APK UI must expose a valid generated API key")
        setup_stage = "read-boot-resume"
        boot_resume = find("resume_on_boot").get("checked")
        setup_stage = "validate-boot-resume"
        if boot_resume != "false":
            raise RuntimeError("APK boot resume must initially be disabled")
        passed("fresh-setup")
        setup_stage = "rest-forward"
        forward = command(*PREFIX, "forward", "--no-rebind", "tcp:0", "tcp:20017")
        if re.fullmatch(r"[1-9][0-9]*", forward) is None or int(forward) > 65535:
            raise RuntimeError("APK REST forward must allocate a private local port")
        port = int(forward)
        setup_stage = "initial-start"
        click("start_service")
        setup_stage = "initial-wait-running"
        wait_state("Running")
        setup_stage = "initial-authentication"
        if _request(port, "/api/v1/app")[0] != 401:
            raise RuntimeError("APK REST must require authentication")
        authenticated()
        result["runtimeExecution"] = "executed"
        passed("authenticated-source-bound-readiness")
        setup_stage = "bundled-webui"
        status, body = _request(port, "/")
        if status != 200 or b"<html" not in body.lower():
            raise RuntimeError("APK must serve the bundled WebUI")
        passed("bundled-webui")
        setup_stage = "graceful-stop"
        click("stop_service")
        wait_state("Stopped")
        assert_listener_stopped()
        passed("graceful-stop")

        # A denied notification grant must not be mistaken for permission to
        # run a foreground service: Android still permits FGS with its notice.
        setup_stage = "notification-denial"
        shell("pm", "revoke", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        # Permission/app-op changes can terminate the activity's UID. Return via
        # its real launcher before looking for controls, rather than using stale UI.
        reopen()
        click("start_service")
        wait_state("Running")
        authenticated()
        passed("notification-denied-service-start")
        setup_stage = "notification-restoration"
        shell("pm", "grant", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        reopen()
        click("stop_service")
        wait_state("Stopped")
        assert_listener_stopped()

        setup_stage = "all-files-denial"
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "deny")
        reopen()
        click("start_service")
        assert_listener_stopped()
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow")
        reopen()
        click("start_service")
        wait_state("Running")
        authenticated()
        setup_stage = "all-files-revocation"
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "deny")
        reopen()
        assert_listener_stopped()
        passed("all-files-denial-and-runtime-revocation")
        setup_stage = "all-files-restoration-grant"
        shell("appops", "set", APPLICATION_ID, "MANAGE_EXTERNAL_STORAGE", "allow")
        setup_stage = "all-files-restoration-reopen"
        reopen()
        setup_stage = "all-files-restoration-start"
        click("start_service")
        setup_stage = "all-files-restoration-wait-running"
        wait_state("Running")
        setup_stage = "all-files-restoration-authentication"
        authenticated()

        if api >= 37:
            setup_stage = "local-network-revocation"
            shell("pm", "revoke", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
            reopen()
            assert_listener_stopped()
            click("start_service")
            assert_listener_stopped()
            setup_stage = "local-network-restoration"
            shell("pm", "grant", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
            reopen()
            click("start_service")
            wait_state("Running")
            authenticated()
            passed("android17-local-network-denial-and-revocation")

        # Prove actual reboot handling, not an injected fake boot broadcast.
        setup_stage = "enable-boot-resume"
        click("resume_on_boot")
        if find("resume_on_boot").get("checked") != "true":
            raise RuntimeError("APK boot resume setting was not retained")
        setup_stage = "enabled-reboot"
        reboot()
        setup_stage = "enabled-reboot-authentication"
        boot_observation = {"restAttempts": 0, "restConnectionFailures": 0, "restHttpResponses": 0}
        deadline = time.monotonic() + 90
        while True:
            try:
                authenticated()
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() >= deadline:
                    # WHY: inspect automatic resume BEFORE cleanup or another
                    # Activity launch can change package/service state. Missing
                    # diagnostics must never replace the failed boot verdict.
                    primary_ui_observation = ui.setup_observation
                    try:
                        boot_observation.update(_boot_timeout_facts(shell, api=api))
                    except Exception:
                        pass
                    # This normal launch is diagnostic AFTER automatic resume
                    # failed. It must never satisfy the boot case or replace its
                    # original pre-launch service/REST observations.
                    try:
                        reopen()
                        post_failure_ui = _post_failure_ui(ui)
                    except Exception:
                        pass
                    raise RuntimeError("APK did not resume after an enabled reboot") from None
                time.sleep(1)
        passed("enabled-boot-resume")
        boot_observation = None
        setup_stage = "explicit-stop-reboot"
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
        setup_stage = "task-manager-stop-reboot"
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
        setup_stage = "force-stop-reboot"
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
        setup_stage = "restart"
        click("resume_on_boot")
        click("start_service")
        wait_state("Running")
        authenticated()
        passed("restart")
        if peer_payload is not None:
            setup_stage = "local-transfer"
            from .android_apk_peer import transfer_proof
            if rust_source is None or adb is None or child is None:
                raise RuntimeError("APK transfer proof requires the owned native peer execution context")
            def restart_transfer_service():
                reopen()
                click("stop_service")
                wait_state("Stopped")
                assert_listener_stopped()
                click("start_service")
                wait_state("Running")
                authenticated()
            result["localTransfer"] = transfer_proof(command, peer_payload, apk_port=port, api_key=key,
                adb=adb, child=child, report_dir=report_dir, rust_source=rust_source,
                restart_service=restart_transfer_service)
            passed("local-transfer-and-delivery-collision")
            if result["localTransfer"].get("completedDeliverySurvivesRestart") is not True:
                raise RuntimeError("APK transfer did not prove completed delivery restart")
            passed("completed-delivery-survives-restart")
        if qualify_file_links:
            setup_stage = "file-link-intents"
            file_link_intents()
            passed("file-link-intents-and-webui-confirmation")
        # The foreground service must survive closing its visible shell.
        setup_stage = "screen-off-doze"
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
        dwell = max(MIN_SCREEN_OFF_DWELL_SECONDS, soak_seconds)
        samples = 0
        while True:
            assert_idle_screen_off()
            authenticated()
            samples += 1
            elapsed = time.monotonic() - started
            result["endurance"] = {"requestedSeconds": soak_seconds,
                                   "minimumDwellSeconds": MIN_SCREEN_OFF_DWELL_SECONDS,
                                   "minimumSamples": MIN_SCREEN_OFF_SAMPLES,
                                   "observedSeconds": round(elapsed, 3), "samples": samples,
                                   "over24Hours": elapsed > 86400}
            (report_dir / "apk-progress.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            if elapsed >= dwell and samples >= MIN_SCREEN_OFF_SAMPLES:
                break
            time.sleep(max(0, min(30, dwell - elapsed)))
        passed("screen-off-doze-observation")
        if peer_payload is not None and qualify_file_links:
            setup_stage = "case-coverage"
            required = required_apk_cases(api)
            if len(cases) != len(required) or {case["name"] for case in cases} != required:
                raise RuntimeError("APK qualification case coverage differs from its trusted source contract")
        result["status"] = "passed"
        return result
    except Exception as error:
        if setup_stage is not None:
            result["failure"] = _lifecycle_failure(error, setup_stage,
                primary_ui_observation if primary_ui_observation is not None else ui.setup_observation)
            if result["failure"]["code"] in {"control-unreachable", "control-disabled", "control-invalid-bounds",
                    "control-unsafe-bounds", "device-locked", "app-not-visible"}:
                try:
                    navigation = ui.failure_navigation()
                    if navigation:
                        result["failure"]["navigation"] = navigation
                except Exception:
                    pass
            if boot_observation is not None:
                result["failure"]["boot"] = boot_observation
            if post_failure_ui is not None:
                result["failure"]["postFailureUi"] = post_failure_ui
        raise
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
