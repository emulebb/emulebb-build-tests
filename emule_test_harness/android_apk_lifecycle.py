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
SUPPORTED_ANDROID_APIS = frozenset({31, 32, 33, 34, 35, 36, 37})
MIN_SCREEN_OFF_DWELL_SECONDS = 60
MIN_SCREEN_OFF_SAMPLES = 3
# WHY: Android's power dump can exceed the ADB output bound. Consume it on
# device and emit only a closed state while pipefail preserves dump errors.
# AOSP's two-space global field is distinct from unindented power-group fields.
POWER_WAKEFULNESS_SCRIPT = (
    "set -o pipefail || exit 1; dumpsys power | awk '"
    "/^  mWakefulness=/ { n++; "
    "if ($0 ~ /^  mWakefulness=(Asleep|Dozing)[[:space:]]*$/) asleep=1; else asleep=0 } "
    "END { if (n != 1) print \"unknown\"; else if (asleep) print \"sleep\"; else print \"other\" }'")
TRANSFER_FAILURE_PHASES = frozenset({
    "admit-original-settings", "admit-prior-downloads-and-roots", "admit-network-binding", "fixture-directory-create",
    "fixture-occupant-push", "persist-fixture-settings", "restart-fixture-destination", "verify-fixture-destination",
    "peer-profile-seed", "peer-home-create", "peer-profile-push", "peer-binary-push-and-hash", "peer-process-spawn",
    "peer-process-admission", "peer-rest-forward", "peer-source-bound-readiness", "peer-ready", "peer-graceful-shutdown",
    "peer-shared-fixture-push", "peer-shared-file-hash", "directed-local-listener-start", "enqueue-owned-transfer",
    "await-completed-delivery", "verify-delivered-path-and-size", "verify-delivered-bytes", "verify-collision-preserved",
    "restart-completed-delivery", "verify-completed-delivery-metadata", "verify-completed-download-evidence",
    "verify-completed-delivery-bytes", "cleanup-remove-owned-transfer", "cleanup-restore-original-settings", "cleanup-remove-owned-fixture",
} | {role + "-listener-" + step for role in ("app", "peer") for step in (
    "server-inventory", "allocate-owned-loopback-endpoint", "server-create", "created-configuration-admission",
    "directed-connect", "connect-acknowledgement", "ready", "owned-server-disable-precondition", "owned-server-disable",
    "owned-disabled-row-verification", "preexisting-server-configuration-preservation")})
ADB_OPERATIONS = frozenset({"shell-mkdir", "shell-chmod", "shell-sha256", "shell-cat", "shell-script", "shell-input", "shell-dumpsys", "binary-read", "push", "forward", "install", "device-command"})
ADB_REASONS = frozenset({"unclassified-command-failure", "output-bound-exceeded", "command-timeout", "permission-denied", "operation-not-permitted", "missing-file", "already-exists", "no-space", "connection-reset", "unclassified-os-error", "unsupported-option", "device-offline", "device-not-found", "transport-closed"})
REST_CODES = frozenset({"BAD_REQUEST", "INVALID_ARGUMENT", "NOT_FOUND", "EMULE_ERROR", "INTERNAL_SERVER_ERROR", "UNAUTHORIZED", "FORBIDDEN", "DOWNLOAD_CONFLICT", "unrecognized"})
REST_CONTEXTS = frozenset({"ed2k-not-configured", "ed2k-disabled", "ed2k-no-server", "vpn-guard-blocked", "client-udp-version", "kad-listener-initialization", "ed2k-listener-bind", "nat-initial-reconcile", "nat-initial-timeout", "local-bind-interface-missing", "server-not-found", "unrecognized"})
FIXTURE_CODES = frozenset({"inventory-invalid", "inventory-limit", "nonce-invalid", "payload-authority-invalid", "protected-root", "unsafe-directory-type", "directory-redirected", "unknown-contents", "unsafe-entry-type", "entry-changed-before-delete", "entry-delete-failed", "directory-remove-failed"})
APK_LIFECYCLE_STAGES = frozenset({
    "install", "installed-identity", "rest-forward", "initial-start", "initial-wait-running",
    "initial-authentication", "bundled-webui", "graceful-stop", "notification-denial",
    "notification-restoration", "all-files-denial", "all-files-revocation",
    "all-files-restoration-grant", "all-files-restoration-reopen", "all-files-restoration-start",
    "all-files-restoration-wait-running", "all-files-restoration-authentication",
    "local-network-revocation", "local-network-restoration", "explicit-stop",
    "task-manager-stop", "force-stop", "restart", "local-transfer",
    "file-link-intents", "screen-off-doze", "case-coverage",
    "all-files-access", "notification-permission", "android-api", "local-network-permission",
    "battery-exemption", "wake-display", "dismiss-keyguard", "launch-main", "wait-stopped",
    "read-api-key", "validate-api-key",
})
APK_LIFECYCLE_FAILURE_CODES = frozenset({
    "adb-command-failed", "command-timeout", "device-locked", "app-not-visible",
    "ui-too-large", "ui-malformed", "ui-ambiguous", "display-size-unavailable",
    "control-unreachable", "control-disabled", "control-invalid-bounds", "control-unsafe-bounds",
    "expected-state-not-reached",
    "invalid-generated-key", "listener-still-running",
    "rest-authentication-failed", "connection-error", "http-error", "other",
})
SETUP_SERVICE_PHASES = frozenset({"Stopped", "Starting", "Running", "Stopping", "Failed"})
SETUP_CONTROL_NAMES = frozenset({"service_status", "api_key"})
APK_NAVIGATION_CONTROLS = frozenset({
    "service_status", "api_key", "start_service", "stop_service", "open_webui",
    "pending_link", "pending_link_error", "app_version", "bind_addr", "save_settings",
    "grant_all_files_access", "allow_notifications", "allow_local_network", "share_diagnostics",
})
APK_POST_FAILURE_ERROR_CATEGORIES = frozenset({
    "foreground-promotion-denied", "required-files-permission",
    "required-local-network-permission", "recovery-budget-blocked", "unknown",
    "native-library-unavailable", "bootstrap-unavailable", "payload-storage-unavailable",
    "webui-assets-invalid", "lifecycle-state-write-failed", "native-runtime-failed",
    "native-status-failed", "native-stop-failed", "native-protocol-invalid", "native-ownership-conflict",
    "bootstrap-invalid", "bootstrap-io", "profile-ownership", "metadata-startup", "incoming-storage",
    "rest-listen-failed", "logging-init-failed", "native-host-invalid", "os-path-missing",
    "os-access-denied", "os-storage-full", "os-storage-readonly", "os-address-in-use",
    "os-address-unavailable", "os-resource-unavailable", "os-io-failed", "os-operation-failed",
    "network-default-route-missing", "network-default-route-ambiguous", "network-binding-invalid",
    "network-interface-inventory-failed", "network-config-invalid",
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
    "graceful-stop", "all-files-denial-and-runtime-revocation",
    "explicit-stop-remains-stopped",
    "force-stop-remains-stopped", "restart", "local-transfer-and-delivery-collision",
    "completed-delivery-survives-restart", "file-link-intents-and-webui-confirmation", "screen-off-doze-observation",
})


def required_apk_cases(api: int) -> set[str]:
    """Return the exact full qualification contract for one supported guest API.

    Candidate admission imports this stdlib-only owner from a verified harness
    revision. A report cannot select its own required cases or extend this range.
    """
    if type(api) is not int or api not in SUPPORTED_ANDROID_APIS:
        raise ValueError("APK qualification supports only Android APIs 31 through 37")
    cases = set(_APK_BASE_CASES)
    if api >= 33:
        cases.add("notification-denied-service-start")
        cases.add("task-manager-stop-remains-stopped")
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
            or value.get("applicationId") != APPLICATION_ID or value.get("minSdk") != 31
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
        "APK Stop left the REST listener running": "listener-still-running",
        "APK authenticated REST failed": "rest-authentication-failed",
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
    failure = {"stage": stage, "code": code, **observation}
    from .android_adb_failure import AdbOperationFailure
    from .android_apk_peer import CampaignFailure, safe_completion_failure
    if isinstance(error, AdbOperationFailure):
        failure["adb"] = _safe_adb_failure(error.safe_failure)
    if isinstance(error, CampaignFailure):
        detail = error.failure
        if (isinstance(detail, dict) and isinstance(detail.get("phase"), str)
                and detail["phase"] in TRANSFER_FAILURE_PHASES and detail.get("code") == detail["phase"] + "-failed"):
            safe = {"phase": detail["phase"], "code": detail["code"]}
            if isinstance(detail.get("adb"), dict):
                safe["adb"] = _safe_adb_failure(detail["adb"])
            rest = detail.get("rest")
            if isinstance(rest, dict):
                safe_rest = {}
                if type(rest.get("httpStatus")) is int and 100 <= rest["httpStatus"] <= 599:
                    safe_rest["httpStatus"] = rest["httpStatus"]
                for name, allowed in (("apiCode", REST_CODES), ("coreContext", REST_CONTEXTS)):
                    if isinstance(rest.get(name), str) and rest[name] in allowed:
                        safe_rest[name] = rest[name]
                if safe_rest:
                    safe["rest"] = safe_rest
            fixture = detail.get("ownedFixture")
            if isinstance(fixture, dict) and isinstance(fixture.get("code"), str) and fixture["code"] in FIXTURE_CODES:
                safe["ownedFixture"] = {"code": fixture["code"]}
                if type(fixture.get("filesRemoved")) is int and 0 <= fixture["filesRemoved"] <= 2:
                    safe["ownedFixture"]["filesRemoved"] = fixture["filesRemoved"]
            if detail["phase"] == "await-completed-delivery":
                completion = safe_completion_failure(detail.get("completion"))
                if completion is not None:
                    safe["completion"] = completion
            failure["transfer"] = safe
    return failure


def _safe_adb_failure(value: dict) -> dict:
    """Project only fixed ADB operation, reason and bounded exit category."""
    result = {}
    for name, allowed in (("operation", ADB_OPERATIONS), ("reason", ADB_REASONS)):
        if isinstance(value.get(name), str) and value[name] in allowed:
            result[name] = value[name]
    exit_code = value.get("exitCode")
    result["exitCategory"] = ("success" if exit_code == 0 else "nonzero" if exit_code > 0 else "signal") if type(exit_code) is int else "unavailable"
    return result


def _diagnostic_bounds(value: str) -> list[int] | None:
    """Admit only bounded numeric geometry, never arbitrary UI attribute text."""
    match = re.fullmatch(r"\[(\d{1,5}),(\d{1,5})\]\[(\d{1,5}),(\d{1,5})\]", value)
    if match:
        rectangle = [int(item) for item in match.groups()]
        if max(rectangle) <= 32768:
            return rectangle
    return None


def _post_failure_error_category(message: str) -> str:
    """Discard dynamic error data after matching source-owned stages or OS tails.

    These messages come from the Kotlin shell, JNI host and daemon error chains.
    A category describes the observed post-failure UI, not when the error arose:
    persisted last-error has no boot/session timestamp.
    """
    exact = {
        "required-files-permission": {"All-files access is required. Open the app to grant it.",
            "All-files access was revoked; stopping the daemon", "Grant all-files access before starting"},
        "required-local-network-permission": {"Local-network permission is required. Open the app to grant it.",
            "Local-network permission was revoked; stopping the daemon", "Allow local-network access before starting"},
        "recovery-budget-blocked": {"Repeated service termination; open the app and press Start to retry"},
        "native-library-unavailable": {"Cannot load the packaged native daemon"},
        "bootstrap-unavailable": {"Open eMuleBB and complete setup before starting"},
        "payload-storage-unavailable": {"Payload storage is unavailable"},
        "webui-assets-invalid": {"Cannot create WebUI directory", "Packaged WebUI is incomplete",
            "Missing packaged WebUI", "Cannot create WebUI assets"},
        "lifecycle-state-write-failed": {"Cannot persist explicit service start", "Cannot persist service state"},
        "native-runtime-failed": {"Service startup failed", "Native runtime failed", "native runtime failed"},
        "native-status-failed": {"Cannot inspect native runtime"},
        "native-stop-failed": {"Native Stop failed", "Native Stop failed. Use Android app settings to force-stop eMuleBB.",
            "Native shutdown could not be confirmed. Use Android app settings to force-stop eMuleBB."},
        "native-protocol-invalid": {"Native operation failed", "invalid host request", "host state unavailable", "process logging state unavailable"},
        "native-ownership-conflict": {"previous runtime is still draining", "one Android service process owns one logging profile"},
        "bootstrap-invalid": {"rest.bind_addr is required", "rest.api_key is required and must not be empty",
            "rest.api_key must not have leading or trailing whitespace",
            "rest.api_key must contain only printable ASCII characters without spaces",
            "rest.api_key is a placeholder and must be replaced", "rest.api_key must contain at least 32 bytes of secret material"},
        "native-host-invalid": {"profile directory must be absolute", "host directories must be absolute", "host folders must be absolute",
            "profile has no parent", "WebUI assets must belong to the application directory", "current WebUI assets are not ready",
            "asset cleanup escaped application directory", "embedded host readiness receiver closed before startup",
            "embedded host readiness receiver closed during startup"},
        "network-binding-invalid": {"p2pBindIp or p2pBindInterface is required when VPN Guard blocks public P2P"},
        "network-config-invalid": {"kad.listenPort is required when ED2K servers are configured",
            "ed2k.listenPort is required when ED2K servers are configured"},
    }
    for category, messages in exact.items():
        if message in messages:
            return category
    promotion_errors = {"ForegroundServiceStartNotAllowedException", "SecurityException", "MissingForegroundServiceTypeException",
                        "InvalidForegroundServiceTypeException", "ForegroundServiceTypeNotAllowedException",
                        "IllegalArgumentException", "IllegalStateException"}
    if message in {"Android refused the foreground service: " + error for error in promotion_errors}:
        return "foreground-promotion-denied"
    prefixes = {
        "bootstrap-invalid": ("invalid bootstrap: ", "failed to parse settings "),
        "bootstrap-io": ("failed to read settings ", "failed to inspect settings "),
        "profile-ownership": ("profile is already in use: ", "failed to resolve writable profile ",
            "failed to open ownership lock for profile ", "failed to acquire exclusive ownership of profile ", "failed to create default profile "),
        "metadata-startup": ("failed to open metadata store under ",),
        "incoming-storage": ("failed to create incoming dir ",),
        "webui-assets-invalid": ("rest.web_root_dir must be an existing directory: ", "rest.web_root_dir must contain index.html: "),
        "rest-listen-failed": ("failed to bind REST/WebUI TCP listener at ",),
        "network-default-route-missing": ("p2pBindIp or p2pBindInterface is required because no default-route IPv4 interface was detected; ",),
        "network-default-route-ambiguous": ("p2pBindIp or p2pBindInterface is required because multiple default-route IPv4 interfaces were detected; ",),
    }
    for category, starts in prefixes.items():
        if message.startswith(starts):
            return category
    contexts = {
        "bootstrap-invalid": ("invalid REST bind address",),
        "bootstrap-io": ("failed to publish bootstrap settings",),
        "metadata-startup": ("failed to load daemon settings", "failed to load kad settings", "failed to load Kad bootstrap endpoints",
            "failed to load ed2k settings", "invalid ed2k settings", "failed to load nat settings", "invalid NAT config in metadata store"),
        "logging-init-failed": ("failed to install the process logging subscriber",),
        "network-interface-inventory-failed": ("failed to enumerate local interfaces",),
    }
    for category, starts in contexts.items():
        if any(message == start or message.startswith(start + ": ") for start in starts):
            return category
    if message.startswith("profile settings ") and message.endswith("; rest.api_key requires owner-only permissions (chmod 600)"):
        return "bootstrap-invalid"
    if message.startswith("p2pBindInterface ") and (message.endswith((" did not resolve to an IPv4 address", " is ambiguous"))
            or " resolved to non-IPv4 address " in message):
        return "network-binding-invalid"
    # WHY: bare Rust/JVM I/O messages can contain only a private path/address.
    # Match terminal platform signatures after stage contexts, then discard all
    # free-form data; words like permission/socket/SQLite alone prove nothing.
    errno_categories = {1: "os-access-denied", 2: "os-path-missing", 5: "os-io-failed", 11: "os-resource-unavailable",
        12: "os-resource-unavailable", 13: "os-access-denied", 17: "os-operation-failed", 20: "os-operation-failed",
        21: "os-operation-failed", 22: "os-operation-failed", 24: "os-resource-unavailable", 28: "os-storage-full",
        30: "os-storage-readonly", 38: "os-operation-failed", 95: "os-operation-failed", 98: "os-address-in-use", 99: "os-address-unavailable"}
    for number, category in errno_categories.items():
        if message.endswith(f" (os error {number})"):
            return category
    for suffix, category in {" (No such file or directory)": "os-path-missing", " (Permission denied)": "os-access-denied",
                            " (Read-only file system)": "os-storage-readonly", " (No space left on device)": "os-storage-full"}.items():
        if message.endswith(suffix):
            return category
    return "unknown"


def _post_failure_ui(ui) -> dict:
    """Read a closed error classification from the existing bound production UI."""
    for attempt in range(3):
        phase = ui.find("service_status").get("text")
        nodes = ui.elements()
        status_indices = [index for index, node in enumerate(nodes) if node.get("resource-id") == APPLICATION_ID + ":id/service_status"]
        category = "unknown"
        # MainActivity places its anonymous error TextView directly after status.
        # Do not classify credentials, help text, or another window's messages.
        if len(status_indices) == 1 and status_indices[0] + 1 < len(nodes):
            error = nodes[status_indices[0] + 1]
            if (error.get("package") == APPLICATION_ID and error.get("class") == "android.widget.TextView"
                    and not error.get("resource-id")):
                category = _post_failure_error_category(error.get("text", ""))
        # WHY: initial Stopped alone cannot prove a Binder STATUS reply.
        if phase in SETUP_SERVICE_PHASES - {"Stopped"} or category != "unknown":
            facts = {"errorCategory": category}
            if phase in SETUP_SERVICE_PHASES:
                facts["servicePhase"] = phase
            return facts
        if attempt < 2:
            time.sleep(1)
    return {"errorCategory": "unknown"}


def _initial_visibility_facts(shell) -> dict:
    """Read only closed owned-window, process and keyguard facts; never launch."""
    facts = {key: "unavailable" for key in ("resumed", "window", "process", "keyguard")}
    def read(*args):
        try:
            value = shell(*args)
            return value if isinstance(value, str) and len(value.encode("utf-8")) <= 1024**2 else ""
        except Exception:
            return ""
    activity = read("dumpsys", "activity", "activities")
    resumed = re.findall(r"(?m)^.*(?:topResumedActivity|mResumedActivity)[^\n]*\bu0\s+([^\s}]+)", activity)
    if resumed and len(set(resumed)) == 1:
        facts["resumed"] = "owned" if resumed[0] in {APPLICATION_ID + "/.MainActivity", APPLICATION_ID + "/" + APPLICATION_ID + ".MainActivity"} else "other"
    windows = read("dumpsys", "window", "windows")
    if re.search(r"(?m)^\s*Window #\d+ ", windows):
        owned = re.findall(r"(?m)^\s*Window #\d+ [^\n]*\bu0 " + re.escape(APPLICATION_ID) + r"/" + re.escape(APPLICATION_ID) + r"\.MainActivity(?=[\s}:])", windows)
        facts["window"] = "present" if len(owned) == 1 else "absent" if not owned else "unavailable"
    pid = read("pidof", APPLICATION_ID).strip()
    if re.fullmatch(r"\d+(?:\s+\d+)*", pid):
        facts["process"] = "present"
    policy = read("dumpsys", "window", "policy")
    values = re.findall(r"(?m)^\s*(?:mShowingLockscreen|mKeyguardShowing|showingAndNotOccluded)\s*[:=]\s*(true|false)\b", policy)
    if values and len(set(values)) == 1:
        facts["keyguard"] = "showing" if values[0] == "true" else "hidden"
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
        self.navigation_snapshot = {}

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
        # WHY: retain phase and network wait only from the same bounded UI
        # snapshot, including an explicit unknown for missing or duplicate IDs.
        self.setup_observation = {"networkWait": {"state": "unavailable"}}
        self.navigation_snapshot = {"focusedControl": "unavailable"}
        hierarchy = self._hierarchy()
        elements = ui_elements(hierarchy)
        owned_nodes = [node for node in elements if node.get("package") == APPLICATION_ID]
        focused = [node for node in owned_nodes if node.get("focused") == "true"]
        if len(focused) == 1:
            resource = focused[0].get("resource-id", "")
            self.navigation_snapshot = {"focusedControl": resource.removeprefix(APPLICATION_ID + ":id/")
                if resource in {APPLICATION_ID + ":id/bind_addr", APPLICATION_ID + ":id/api_key"} else "other-owned"}
        else:
            self.navigation_snapshot = {"focusedControl": "unavailable" if not owned_nodes else "none" if not focused else "ambiguous"}
        wait = [node for node in elements if node.get("resource-id") == APPLICATION_ID + ":id/network_wait_status" and node.get("package") == APPLICATION_ID]
        phases = [node for node in elements if node.get("resource-id") == APPLICATION_ID + ":id/service_status" and node.get("package") == APPLICATION_ID]
        if len(wait) == 1:
            text = wait[0].get("text")
            self.setup_observation["networkWait"]["state"] = {"Waiting for a usable default network": "waiting", "": "not-waiting"}.get(text, "unavailable")
        if len(phases) == 1 and phases[0].get("text") in SETUP_SERVICE_PHASES:
            self.setup_observation["networkWait"]["phase"] = phases[0]["text"]
        nodes = ui_nodes(hierarchy)
        scrolls = [node for node in elements if node.get("package") == APPLICATION_ID and node.get("class") == "android.widget.ScrollView"]
        containers = [_diagnostic_bounds(node.get("bounds", "")) for node in scrolls]
        self.scroll_bounds = containers[0] if len(containers) == 1 and containers[0] is not None else None
        if len(scrolls) == 1 and scrolls[0].get("scrollable") in {"true", "false"}:
            self.navigation_snapshot["scrollable"] = scrolls[0]["scrollable"] == "true"
        # WHY: setup failures precede daemon diagnostics; retain only closed
        # control flags and service phases, never the visible credential/text.
        self.setup_observation["controls"] = {
            name: {"present": name in nodes, "enabled": nodes.get(name, {}).get("enabled") == "true"}
            for name in sorted(SETUP_CONTROL_NAMES)}
        phase = nodes.get("service_status", {}).get("text")
        if phase in SETUP_SERVICE_PHASES:
            self.setup_observation["servicePhase"] = phase
        return nodes

    def failure_navigation(self):
        """Classify owned focus and IME state without retaining UI or dump text."""
        facts = dict(self.navigation)
        if not facts:
            return facts
        facts.update(self.navigation_snapshot)
        facts["imeInputShown"] = "unavailable"
        try:
            document = self.shell("dumpsys", "input_method")
            if isinstance(document, str) and len(document.encode("utf-8")) > 65536:
                facts["imeInputShown"] = "oversize"
            elif isinstance(document, str):
                shown = re.findall(r"\bmInputShown=(true|false)\b", document)
                if len(shown) == 1:
                    facts["imeInputShown"] = "shown" if shown[0] == "true" else "hidden"
                    facts["imeVisible"] = shown[0] == "true"
                elif len(shown) > 1:
                    facts["imeInputShown"] = "ambiguous"
        except Exception as error:
            from .android_adb_failure import AdbOperationFailure
            if isinstance(error, AdbOperationFailure) and error.safe_failure.get("reason") == "output-bound-exceeded":
                facts["imeInputShown"] = "oversize"
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
            try:
                state = self.find("service_status").get("text", "")
            except DeviceUiUnavailable as failure:
                if failure.reason != "app-not-visible":
                    raise
                # WHY: an owned launch can precede its accessible controls.
                # Reinspect within this wait's bound without acting on unknown UI.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(1, remaining))
                if time.monotonic() >= deadline:
                    raise
                continue
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
    initial_launch_result = "unavailable"
    screen_substage = None
    post_failure_ui = None
    primary_ui_observation = None
    ui = ProductionUi(command)
    ui_path = ui.path
    inspect, find, click, wait_state = ui.inspect, ui.find, ui.click, ui.wait_state

    def shell(*args):
        return command(*PREFIX, "shell", *args)

    def assert_listener_stopped(quiet_seconds=2, *, fail_on_response=False):
        deadline = time.monotonic() + max(30, quiet_seconds + 5)
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
                if fail_on_response:
                    raise RuntimeError("APK Stop left the REST listener running")
                quiet_since = None
            if time.monotonic() >= deadline:
                raise RuntimeError("APK Stop left the REST listener running")
            time.sleep(1)

    def reopen():
        return shell("am", "start", "-W", "-n", APPLICATION_ID + "/.MainActivity")

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
        # WHY: resolve-activity can return the platform resolver when no default
        # browser is selected. Its resumed window is not browser-dispatch proof.
        if "/" not in component or package in {APPLICATION_ID, "android", "com.android.intentresolver"}:
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
        setup_stage = "android-api"
        api = int(shell("getprop", "ro.build.version.sdk"))
        required_apk_cases(api)
        result["androidApiLevel"] = api
        if api >= 33:
            setup_stage = "notification-permission"
            shell("pm", "grant", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
        if api >= 37:
            setup_stage = "local-network-permission"
            shell("pm", "grant", APPLICATION_ID, "android.permission.ACCESS_LOCAL_NETWORK")
        setup_stage = "battery-exemption"
        shell("dumpsys", "deviceidle", "whitelist", "+" + APPLICATION_ID)
        prepare_fresh_guest_ui(initial=True)
        setup_stage = "launch-main"
        launch = reopen()
        statuses = re.findall(r"(?m)^Status:\s*(ok|timeout|error)\s*$", launch) if isinstance(launch, str) else []
        initial_launch_result = statuses[0] if len(statuses) == 1 else "unavailable"
        setup_stage = "wait-stopped"
        wait_state("Stopped")
        setup_stage = "read-api-key"
        key = find("api_key", enabled=True).get("text", "")
        setup_stage = "validate-api-key"
        if len(key) < 32 or not all(33 <= ord(c) <= 126 for c in key):
            raise RuntimeError("APK UI must expose a valid generated API key")
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

        if api >= 33:
            # Runtime notification denial exists only from Android 13 onward.
            setup_stage = "notification-denial"
            shell("pm", "revoke", APPLICATION_ID, "android.permission.POST_NOTIFICATIONS")
            # Permission changes may terminate the activity's UID.
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

        # Each intentional stop must remain stopped after Main binds again.
        stops = [("explicit-stop", "ui")]
        if api >= 33:
            stops.append(("task-manager-stop", "task"))
        stops.append(("force-stop", "force"))
        for stage, stop in stops:
            setup_stage = stage
            reopen()
            wait_state("Running")
            authenticated()
            if stop == "ui":
                click("stop_service")
                wait_state("Stopped")
            elif stop == "task":
                shell("cmd", "activity", "stop-app", APPLICATION_ID)
            else:
                shell("am", "force-stop", APPLICATION_ID)
            assert_listener_stopped(quiet_seconds=5)
            reopen()
            wait_state("Stopped")
            assert_listener_stopped(quiet_seconds=30, fail_on_response=True)
            passed(stage + "-remains-stopped")
            click("start_service")
            wait_state("Running")
            authenticated()
        setup_stage = "restart"
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
        screen_substage = "home"
        shell("input", "keyevent", "KEYCODE_HOME")
        screen_substage = "home-check"
        activities = shell("dumpsys", "activity", "activities")
        resumed = re.findall(r"(?m)^.*(?:topResumedActivity|mResumedActivity)[^\n]*\bu0\s+([^\s}]+)", activities)
        if not resumed or len(set(resumed)) != 1 or resumed[0].startswith(APPLICATION_ID + "/"):
            raise RuntimeError("APK activity did not leave the foreground after Home")
        screen_substage = "home-authentication"
        authenticated()
        screen_substage = "sleep"
        shell("input", "keyevent", "KEYCODE_SLEEP")
        screen_substage = "unplug"
        shell("dumpsys", "battery", "unplug")
        screen_substage = "force-idle"
        shell("dumpsys", "deviceidle", "force-idle")
        def assert_idle_screen_off():
            nonlocal screen_substage
            screen_substage = "check-idle"
            if shell("dumpsys", "deviceidle", "get", "deep") != "IDLE":
                raise RuntimeError("APK Doze proof did not retain actual deep idle")
            screen_substage = "check-power"
            if shell("sh", "-c", shlex.quote(POWER_WAKEFULNESS_SCRIPT)) != "sleep":
                raise RuntimeError("APK screen-off proof did not observe a sleeping device")

        assert_idle_screen_off()
        started = time.monotonic()
        dwell = max(MIN_SCREEN_OFF_DWELL_SECONDS, soak_seconds)
        samples = 0
        while True:
            assert_idle_screen_off()
            screen_substage = "sample-authentication"
            authenticated()
            samples += 1
            elapsed = time.monotonic() - started
            result["endurance"] = {"requestedSeconds": soak_seconds,
                                   "activityClosed": True,
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
            if setup_stage == "screen-off-doze" and screen_substage is not None:
                result["failure"]["substage"] = screen_substage
            if setup_stage == "wait-stopped" and result["failure"]["code"] == "app-not-visible":
                result["failure"]["initialLaunch"] = {"result": initial_launch_result,
                    **_initial_visibility_facts(shell)}
            if result["failure"]["code"] in {"control-unreachable", "control-disabled", "control-invalid-bounds",
                    "control-unsafe-bounds", "device-locked", "app-not-visible"}:
                try:
                    navigation = ui.failure_navigation()
                    if navigation:
                        result["failure"]["navigation"] = navigation
                except Exception:
                    pass
            if installed and ui.setup_observation.get("controls"):
                # Other lifecycle failures may already expose the real error.
                # Inspect only an existing app window; never launch or press
                # Start to diagnose it, and never replace the primary failure.
                try:
                    if ui.inspect():
                        post_failure_ui = _post_failure_ui(ui)
                except Exception:
                    pass
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
