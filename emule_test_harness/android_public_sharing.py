"""Owned, upload-only Android direct-Wi-Fi discovery with private local evidence.

The physical APK probe remains the installer and qualification owner. This adapter
copies an explicitly approved tree into a fresh public Shared child, then observes
the production foreground service. Observation expiry leaves that service running;
explicit stop and invariant failures request normal UI Stop. Resume never starts a
stopped service. Neither public observations nor aggregate counters certify parity.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

from . import windows_processes
from .android_apk_device import AdbDevice, _stopped_service_flags
from .android_apk_lifecycle import APPLICATION_ID, ProductionUi, admit_payload, required_apk_cases
from .android_apk_peer import guest_sha256
from .android_apk_profile import INCOMING, SHARED, read_hashed_receipt
from .paths import get_workspace_output_root
from .kad_nodes import DEFAULT_NODES_DAT_URL
from .rust_local_ed2k import request_json
from .rust_shared_library_io import compact_progress, path_fingerprint, utc_now, write_json
from .soak_launch import DEFAULT_SERVER_MET_URL
from .upload_parity_monitor import rust_summary

SCHEMA = "emulebb.android.public-sharing/1"
MAX_RECEIPT_BYTES = 4 * 1024**2


@dataclass(frozen=True)
class Limits:
    """Bounds remain immutable across observer restarts."""
    duration_seconds: int = 86400
    interval_seconds: int = 30
    upload_limit_kibps: int = 128
    history_max_bytes: int = 16 * 1024**2
    minimum_free_bytes: int = 256 * 1024**2

    def validate(self):
        bounds = ((self.duration_seconds, 1, 86400), (self.interval_seconds, 5, 300),
                  (self.upload_limit_kibps, 1, 10240), (self.history_max_bytes, 65536, 64 * 1024**2),
                  (self.minimum_free_bytes, 64 * 1024**2, 1024**4))
        if any(type(value) is not int or not low <= value <= high for value, low, high in bounds):
            raise ValueError("Campaign limits are outside the supported bounds")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _regular(path: Path, *, directory=False):
    value = path.lstat()
    if (value.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT if hasattr(value, "st_file_attributes") else False):
        raise RuntimeError("Campaign paths cannot contain reparse entries")
    if not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        raise RuntimeError("Campaign paths must be regular files or directories")
    return value


def inventory(source: Path) -> dict:
    """Hash a read-only tree without traversing links, checking concurrent changes."""
    source = source.absolute()
    for parent in (source, *source.parents):
        _regular(parent, directory=True)
    directories, files = [], []
    for parent, names, leaves in os.walk(source, followlinks=False):
        for name in sorted(names):
            child = Path(parent) / name
            _regular(child, directory=True)
            directories.append(child.relative_to(source).as_posix())
        for name in sorted(leaves):
            child = Path(parent) / name
            before = _regular(child)
            with child.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            after = _regular(child)
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise RuntimeError("Approved source changed while inventorying")
            files.append({"path": child.relative_to(source).as_posix(), "sizeBytes": after.st_size,
                          "mtimeNs": after.st_mtime_ns, "sha256": checksum})
    return {"directories": sorted(directories), "files": sorted(files, key=lambda row: row["path"])}


def _private_root(campaign: Path, output_root: Path, *, fresh=False):
    output_root = output_root.resolve(strict=True)
    campaign = campaign.absolute()
    if campaign == output_root or not campaign.resolve().is_relative_to(output_root):
        raise RuntimeError("Campaign evidence must stay below the configured output root")
    for parent in (campaign, *campaign.parents):
        if parent.exists():
            _regular(parent, directory=True)
        if parent == output_root:
            break
    if fresh:
        campaign.mkdir(parents=True, exist_ok=False, mode=0o700)
    _regular(campaign, directory=True)
    return campaign


def _read_json(path: Path, *, digest=None):
    size = _regular(path).st_size
    if not 0 < size <= MAX_RECEIPT_BYTES:
        raise RuntimeError("Campaign receipt exceeds its bound")
    raw = path.read_bytes()
    if digest is not None and (not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(raw).hexdigest() != digest):
        raise RuntimeError("Campaign receipt identity differs")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("Campaign receipt must be an object")
    return value


def admit_campaign(campaign: Path, digest: str, serial: str | None = None):
    """Require externally hash-bound immutable scope before any device mutation."""
    value = _read_json(campaign / "campaign.json", digest=digest)
    nonce = value.get("nonce", "")
    if (value.get("schema") != SCHEMA or value.get("status") != "prepared"
            or value.get("route") != "direct-wifi" or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
            or value.get("destination") != SHARED + "/campaign-" + nonce
            or value.get("marker") != "/data/local/tmp/emulebb-public-sharing-" + nonce + ".owner"
            or value.get("staging") != "/data/local/tmp/emulebb-public-sharing-" + nonce + ".stage"
            or serial is not None and value.get("deviceSerialSha256") != hashlib.sha256(serial.encode()).hexdigest()
            or _digest(value.get("inventory")) != value.get("inventorySha256")):
        raise RuntimeError("Campaign ownership or admitted sharing scope differs")
    Limits(**value["limits"]).validate()
    return value


def _process_identity():
    created = windows_processes.process_creation_date(os.getpid())
    if not created:
        raise RuntimeError("Observer process identity is unavailable")
    return {"pid": os.getpid(), "created": created}


def _alive(identity):
    if type(identity.get("pid")) is not int or not isinstance(identity.get("created"), str) or not identity["created"]:
        raise RuntimeError("Observer ownership identity is invalid")
    return windows_processes.process_creation_date(identity["pid"]) == identity["created"]


@contextmanager
def device_lease(output_root: Path, device_hash: str, campaign: Path, *, recover=False):
    """Hold an OS lock across ownership checks, recovery and all device changes."""
    root = output_root / "tmp" / "android-public-sharing"
    root.mkdir(parents=True, exist_ok=True)
    _private_root(root, output_root)
    path = root / (device_hash + ".lock")
    owner = {**_process_identity(), "token": uuid4().hex, "campaign": path_fingerprint(campaign), "active": True}
    if path.exists() or path.is_symlink():
        _regular(path)
    with os.fdopen(os.open(path, os.O_CREAT | os.O_RDWR, 0o600), "r+b") as stream:
        # WHY: PID-file unlink/recreate recovery lets simultaneous recoverers
        # remove a newly acquired lease. The inode and OS lock are never replaced.
        if os.name == "nt":
            import msvcrt
            def lock():
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            def unlock():
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            def lock(): fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            def unlock(): fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        try:
            lock()
        except OSError:
            raise RuntimeError("Device already has an active OS-held campaign lease") from None
        try:
            stream.seek(0)
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
            if len(raw) > MAX_RECEIPT_BYTES:
                raise RuntimeError("Device lease metadata exceeds its bound")
            previous = json.loads(raw) if raw else {}
            if previous and previous.get("active", True):
                if not recover or previous.get("campaign") != owner["campaign"] or _alive(previous):
                    raise RuntimeError("Stale device lease requires exact ownership and proven process death")
            def record(value):
                stream.seek(0)
                stream.write(json.dumps(value).encode())
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
            record(owner)
            try:
                yield owner
            finally:
                record({**owner, "active": False})
        finally:
            unlock()


class Phone:
    """Small production-UI adapter using the existing physical ADB owner."""
    def __init__(self, device: AdbDevice, payload: dict):
        self.device, self.payload = device, payload
        self.prefix = ("-s", device.serial)
        self.ui = ProductionUi(device.command, prefix=self.prefix)
        self.port = None
        self.key = None
        self.remote_port = None

    def shell(self, *args, **kwargs):
        return self.device.command(*self.prefix, "shell", *args, **kwargs)

    def script(self, value, *, timeout=10):
        return self.shell("sh", "-c", shlex.quote(value), timeout=timeout)

    def installed(self):
        if self.device.command(*self.prefix, "get-state") != "device" or self.shell("am", "get-current-user") != "0":
            raise RuntimeError("Selected primary-user device is not available")
        required_apk_cases(int(self.shell("getprop", "ro.build.version.sdk")))
        rows = self.shell("pm", "path", "--user", "0", APPLICATION_ID).splitlines()
        if len(rows) != 1 or not rows[0].startswith("package:/data/app/"):
            raise RuntimeError("Campaign requires one installed owned APK")
        if guest_sha256(self.device.command, rows[0][8:], prefix=self.prefix) != self.payload["apk"]["sha256"]:
            raise RuntimeError("Installed production APK bytes differ")

    def open(self):
        self.shell("input", "keyevent", "KEYCODE_WAKEUP")
        self.shell("am", "start", "-W", "--user", "0", "-n", APPLICATION_ID + "/.MainActivity")

    def state(self):
        return self.ui.find("service_status").get("text")

    def forward(self):
        # Running production services disable editing these controls. Reading
        # their visible values is sufficient and never mutates credentials.
        bind = self.ui.find("bind_addr").get("text", "")
        match = re.fullmatch(r"(?:127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\[::\]):([1-9][0-9]*)", bind)
        self.key = self.ui.find("api_key").get("text", "")
        if (match is None or int(match[1]) > 65535 or not 32 <= len(self.key) <= 512
                or any(not 33 <= ord(char) <= 126 for char in self.key)):
            raise RuntimeError("Production UI control credentials are unavailable")
        self.remote_port = int(match[1])
        result = self.device.command(*self.prefix, "forward", "--no-rebind", "tcp:0", "tcp:" + str(self.remote_port))
        if re.fullmatch(r"[1-9][0-9]*", result) is None or int(result) > 65535:
            raise RuntimeError("Could not allocate an owned loopback REST forward")
        self.port = int(result)

    @property
    def base(self):
        return "http://127.0.0.1:" + str(self.port)

    def request(self, method, path, body=None):
        return request_json(self.base, method, "/api/v1" + path, self.key, body)

    def identity(self):
        app = self.request("GET", "/app")
        if (any(app.get(name) != expected for name, expected in self.payload["buildIdentity"].items())
                or app.get("lifecycle", {}).get("state") != "running"):
            raise RuntimeError("Running daemon identity differs")

    def stop(self):
        self.installed()
        self.open()
        state = self.state()
        if state in {"Running", "Starting"}:
            self.ui.click("stop_service")
            self.ui.wait_state("Stopped", timeout=30)
        elif state != "Stopped":
            raise RuntimeError("Normal Stop has no stable owned service state")
        _stopped_service_flags(self.ui)

    def cleanup(self):
        if self.port is not None:
            rows = [line.split() for line in self.device.command(*self.prefix, "forward", "--list").splitlines()]
            selected = [row for row in rows if len(row) == 3 and row[1] == "tcp:" + str(self.port)]
            if selected and selected != [[self.device.serial, "tcp:" + str(self.port), "tcp:" + str(self.remote_port)]]:
                raise RuntimeError("REST forward ownership changed")
            if selected:
                self.device.command(*self.prefix, "forward", "--remove", "tcp:" + str(self.port))
        self.shell("rm", "-f", self.ui.path)
        self.key = None


def wifi_default(document: str):
    """Accept only the explicit active Wi-Fi network, rejecting VPN/unknown dumps."""
    ids = re.findall(r"(?m)^\s*Active default network:\s*(\d+)\s*$", document)
    if len(ids) != 1:
        raise RuntimeError("Active Android route is unavailable")
    rows = [line for line in document.splitlines()
            if "NetworkAgentInfo{" in line and re.search(r"\bnetwork\{" + ids[0] + r"\}", line)]
    transports = [re.search(r"Transports:\s*([^\]]*?)(?:\s+Capabilities:|\])", line) for line in rows]
    if len(transports) != 1 or transports[0] is None or transports[0][1].strip() != "WIFI":
        raise RuntimeError("Campaign requires the direct Wi-Fi default route")


def native_battery_facts(elements: list):
    """Read only the production label's closed PowerManager/ActivityManager facts."""
    pattern = (r"Files: (?:allowed|required); local network: (?:allowed|required); "
               r"notifications: (?:allowed|disabled); battery exemption: (allowed|disabled); "
               r"background restriction: (enabled|disabled)")
    matches = [match for node in elements if node.get("package") == APPLICATION_ID
               and (match := re.fullmatch(pattern, node.get("text", ""))) is not None]
    if len(matches) != 1:
        return {"batteryOptimizationExempt": None, "backgroundRestricted": None}
    return {"batteryOptimizationExempt": matches[0][1] == "allowed", "backgroundRestricted": matches[0][2] == "enabled"}


def battery_condition(phone: Phone, *, request_exemption=False):
    """Use the own-app native button and unambiguous stock Settings dialog only.

    This deliberately avoids the disposable emulator's deviceidle/battery shell
    controls. Eligibility is a recorded prerequisite, never a 24/7 guarantee.
    """
    facts = {"batteryOptimizationExempt": None, "backgroundRestricted": None}
    grant = "not-requested"
    try:
        facts = native_battery_facts(phone.ui.elements())
        if request_exemption and facts["batteryOptimizationExempt"] is False:
            grant = "unconfirmed"
            try:
                phone.ui.click("allow_continuous_background")
                for _ in range(6):
                    nodes = phone.ui.elements()
                    active = phone.shell("dumpsys", "activity", "activities")
                    settings_foreground = re.search(
                        r"(?:mResumedActivity|topResumedActivity)[^\n]*\bcom\.android\.settings/", active) is not None
                    own_app_visible = any(node.get("package") == "com.android.settings"
                                          and "eMuleBB" in node.get("text", "") for node in nodes)
                    buttons = [node for node in nodes if node.get("package") == "com.android.settings"
                               and node.get("resource-id") == "android:id/button1"
                               and node.get("enabled") == "true" and node.get("clickable") == "true"
                               and node.get("visible-to-user") != "false"]
                    if settings_foreground and own_app_visible and len(buttons) == 1:
                        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", buttons[0].get("bounds", ""))
                        sizes = re.findall(r"(\d+)x(\d+)", phone.shell("wm", "size"))
                        if bounds is None or not sizes:
                            break
                        x1, y1, x2, y2 = map(int, bounds.groups())
                        width, height = map(int, sizes[-1])
                        if not 0 <= x1 < x2 <= width or not 0 <= y1 < y2 <= height:
                            break
                        phone.shell("input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
                        grant = "normal-settings-ui-tapped"
                        break
                    time.sleep(0.5)
            finally:
                phone.shell("input", "keyevent", "KEYCODE_BACK")
                phone.open()
            for _ in range(6):
                facts = native_battery_facts(phone.ui.elements())
                if facts["batteryOptimizationExempt"] is True:
                    grant = "normal-settings-ui-verified"
                    break
                time.sleep(0.5)
    except Exception:
        grant = "unavailable" if grant != "not-requested" else "not-requested"
    constraints = []
    if facts["batteryOptimizationExempt"] is not True:
        constraints.append("battery-optimization-not-exempt" if facts["batteryOptimizationExempt"] is False else "battery-exemption-unavailable")
    if facts["backgroundRestricted"] is not False:
        constraints.append("background-restricted" if facts["backgroundRestricted"] is True else "background-restriction-unavailable")
    return {**facts, "source": "production-platform-facts-ui", "observedAtUtc": utc_now(),
            "exemptionGrant": grant, "constraints": constraints,
            "continuousOperationPrerequisites": "observed" if not constraints else "constrained",
            "continuousOperationGuarantee": "not-claimed"}


def _guest_entries(phone: Phone, root: str, kind: str | None = None):
    args = ["find", shlex.quote(root)]
    if kind:
        args += ["-type", kind]
    raw = phone.shell(*args, "-print0", binary=True)
    if not raw.endswith(b"\0"):
        raise RuntimeError("Guest tree inventory is incomplete")
    return {part.decode("utf-8", errors="strict") for part in raw[:-1].split(b"\0")}


def guest_scope(phone: Phone, receipt: dict, *, hashes=False):
    """Reject any extra shareable entry, missing file, link or redirected root."""
    destination = receipt["destination"]
    for root in (INCOMING, SHARED, destination):
        if phone.shell("readlink", "-f", shlex.quote(root)) != root:
            raise RuntimeError("Public sharing directory was redirected")
    if _guest_entries(phone, INCOMING) != {INCOMING}:
        raise RuntimeError("Incoming must remain empty for an upload-only campaign")
    expected_files = {destination + "/" + row["path"] for row in receipt["inventory"]["files"]}
    expected_dirs = {SHARED, destination} | {destination + "/" + name for name in receipt["inventory"]["directories"]}
    if (_guest_entries(phone, SHARED) != expected_files | expected_dirs
            or _guest_entries(phone, SHARED, "f") != expected_files
            or _guest_entries(phone, SHARED, "d") != expected_dirs):
        raise RuntimeError("Public Shared contents differ from the approved inventory")
    if phone.shell("cat", receipt["marker"]) != receipt["nonce"]:
        raise RuntimeError("Guest campaign ownership marker differs")
    if hashes:
        for row in receipt["inventory"]["files"]:
            if guest_sha256(phone.device.command, destination + "/" + row["path"], prefix=phone.prefix) != row["sha256"]:
                raise RuntimeError("Copied guest bytes differ from the approved source")


def _guest_free(phone):
    rows = phone.shell("df", "-k", shlex.quote(SHARED)).splitlines()
    values = rows[-1].split() if rows else []
    if len(values) < 4 or not values[3].isdigit():
        raise RuntimeError("Guest free-space evidence is unavailable")
    return int(values[3]) * 1024


def publish_staged_tree(phone: Phone, receipt: dict):
    """Verify private staging, then exclusively create each public destination.

    Final files use shell noclobber (O_EXCL), so an inserted occupant cannot be
    truncated. A partial failure leaves the production service stopped and keeps
    owned partials for inspection; retry never overwrites or merges that tree.
    """
    staging, destination = receipt["staging"], receipt["destination"]
    tree = receipt["inventory"]
    directories = {staging} | {staging + "/" + name for name in tree["directories"]}
    files = {staging + "/" + row["path"] for row in tree["files"]}
    if (phone.shell("readlink", "-f", staging) != staging
            or _guest_entries(phone, staging) != directories | files
            or _guest_entries(phone, staging, "d") != directories
            or _guest_entries(phone, staging, "f") != files):
        raise RuntimeError("Private copied staging tree differs")
    for row in tree["files"]:
        if guest_sha256(phone.device.command, staging + "/" + row["path"], prefix=phone.prefix) != row["sha256"]:
            raise RuntimeError("Private staged bytes differ from the approved source")
    for name in tree["directories"]:
        phone.shell("mkdir", shlex.quote(destination + "/" + name))
    for row in tree["files"]:
        phone.script("umask 077; set -C; cat " + shlex.quote(staging + "/" + row["path"])
                     + " > " + shlex.quote(destination + "/" + row["path"]),
                     timeout=min(3600, 60 + (row["sizeBytes"] + 1024**2 - 1) // 1024**2))


def prepare(phone: Phone, *, campaign: Path, output_root: Path, source: Path,
            expected_file_count: int, expected_total_bytes: int, installation: dict,
            admission: dict, limits: Limits, route: str):
    """Copy approved bytes without modifying the source or overwriting guest files."""
    limits.validate()
    if route != "direct-wifi" or type(expected_file_count) is not int or not 1 <= expected_file_count <= 10000:
        raise ValueError("Explicit direct Wi-Fi and a bounded approved file count are required")
    if type(expected_total_bytes) is not int or not 0 < expected_total_bytes <= 1024**4:
        raise ValueError("An exact bounded approved byte total is required")
    device_hash = hashlib.sha256(phone.device.serial.encode()).hexdigest()
    if (installation.get("ownedInstallation") is not True or installation.get("status") != "passed"
            or installation.get("freshInstallation") is not True
            or installation.get("schema") != "emulebb.android.physical-device/1"
            or installation.get("debugBuild") is not False
            or any(installation.get(name) != expected for name, expected in {
                "deviceSerialSha256": device_hash, "apkSha256": phone.payload["apk"]["sha256"],
                "signerSha256": phone.payload["signerSha256"], "versionCode": phone.payload["versionCode"],
                "sourceRevision": phone.payload["buildIdentity"]["sourceRevision"]}.items())):
        raise RuntimeError("Prepare requires the exact verified owned installation receipt")
    tree = inventory(source)
    if len(tree["files"]) != expected_file_count or sum(row["sizeBytes"] for row in tree["files"]) != expected_total_bytes:
        raise RuntimeError("Approved source file count or byte total differs")
    campaign = _private_root(campaign, output_root, fresh=True)
    nonce = uuid4().hex
    receipt = {"schema": SCHEMA, "status": "preparing", "route": route, "nonce": nonce,
               "deviceSerialSha256": device_hash, "destination": SHARED + "/campaign-" + nonce,
               "marker": "/data/local/tmp/emulebb-public-sharing-" + nonce + ".owner",
               "staging": "/data/local/tmp/emulebb-public-sharing-" + nonce + ".stage",
               "sourcePath": str(source.absolute()), "inventory": tree, "inventorySha256": _digest(tree),
               "fileCount": expected_file_count, "totalBytes": expected_total_bytes,
               "admission": admission, "limits": asdict(limits), "createdAtUtc": utc_now()}
    if len(json.dumps(receipt).encode()) > MAX_RECEIPT_BYTES:
        raise RuntimeError("Approved inventory exceeds the private receipt bound")
    with device_lease(output_root, device_hash, campaign):
        attempted_start = False
        try:
            phone.installed()
            phone.open()
            if phone.state() != "Stopped":
                raise RuntimeError("Prepare requires a normally stopped owned service")
            receipt["batteryCondition"] = battery_condition(phone, request_exemption=True)
            if phone.state() != "Stopped":
                raise RuntimeError("Battery permission setup changed the owned service state")
            wifi_default(phone.shell("dumpsys", "connectivity"))
            for root in (INCOMING, SHARED):
                if phone.shell("readlink", "-f", shlex.quote(root)) != root or _guest_entries(phone, root) != {root}:
                    raise RuntimeError("Initial canonical public storage must be empty and unredirected")
            if (_guest_free(phone) < 2 * expected_total_bytes + limits.minimum_free_bytes
                    or shutil.disk_usage(campaign).free < limits.minimum_free_bytes):
                raise RuntimeError("Campaign free-space reserve would be exceeded")
            # WHY: configuring a cap after adding real shared bytes leaves an
            # uncapped startup window. Configure the empty owned service first.
            phone.forward()
            attempted_start = True
            phone.ui.click("start_service")
            phone.ui.wait_state("Running")
            phone.identity()
            transfers = phone.request("GET", "/transfers?limit=1")
            if transfers.get("total") != 0 or transfers.get("items") != []:
                raise RuntimeError("Prepare requires an empty download queue")
            _settings(phone, limits, configure=True)
            receipt["discoveryPreparation"] = configure_public_discovery(phone)
            phone.stop()
            attempted_start = False
            phone.script("umask 077; set -C; printf '%s' " + shlex.quote(nonce) + " > " + shlex.quote(receipt["marker"]))
            phone.shell("mkdir", shlex.quote(receipt["destination"]))
            phone.shell("mkdir", "-m", "700", receipt["staging"])
            write_json(campaign / "preparation.json", receipt)
            phone.device.command(*phone.prefix, "push", str(source.absolute()) + "/.", receipt["staging"], timeout=3600)
            publish_staged_tree(phone, receipt)
            guest_scope(phone, receipt, hashes=True)
            if inventory(source) != tree:
                raise RuntimeError("Approved source changed during the copy")
            receipt.update(status="prepared", preparedAtUtc=utc_now(), sourceUnchanged=True, guestSha256Verified=True)
            write_json(campaign / "campaign.json", receipt)
            return hashlib.sha256((campaign / "campaign.json").read_bytes()).hexdigest()
        except Exception as error:
            receipt.update(status="failed", errorType=type(error).__name__)
            write_json(campaign / "preparation.json", receipt)
            raise RuntimeError("Public sharing preparation failed; inspect local evidence") from None
        finally:
            if attempted_start:
                phone.stop()
            phone.cleanup()


def shared_catalog(phone: Phone, receipt: dict):
    """Join content-level catalog representatives to approved SHA-256/size groups.

    REST returns distinct known contents, choosing one eligible path per hash.
    Duplicate approved instances can therefore collapse to one row. Coverage of
    every content group does not prove that every duplicate path was indexed.
    """
    expected = {receipt["destination"] + "/" + row["path"]: (row["sha256"], row["sizeBytes"])
                for row in receipt["inventory"]["files"]}
    groups = set(expected.values())
    rows, cursors, cursor, total, stable = [], set(), None, None, True
    while True:
        query = {"limit": 200}
        if cursor is not None:
            query["cursor"] = cursor
        page = phone.request("GET", "/shared-files?" + urlencode(query))
        if (not isinstance(page.get("items"), list) or type(page.get("total")) is not int
                or not 0 <= page["total"] <= receipt["fileCount"]):
            raise RuntimeError("Shared catalog collection exceeds its approved scope")
        stable &= total is None or page["total"] == total
        total = page["total"]
        rows.extend(page["items"])
        cursor = page.get("nextCursor")
        if cursor is None:
            break
        if not isinstance(cursor, str) or not cursor or cursor in cursors or len(rows) > receipt["fileCount"]:
            raise RuntimeError("Shared catalog pagination is incomplete")
        cursors.add(cursor)
    stable &= len(rows) == total and len({row.get("path") for row in rows}) == len(rows)
    group_hashes, hash_groups = {}, {}
    for row in rows:
        if (row.get("path") not in expected or row.get("sizeBytes") != expected[row["path"]][1]
                or row.get("complete") is not True or row.get("partFile") is not False
                or re.fullmatch(r"[0-9a-fA-F]{32}", row.get("hash", "")) is None):
            raise RuntimeError("Shared catalog contains an unapproved file")
        group, file_hash = expected[row["path"]], row["hash"].lower()
        stable &= group not in group_hashes and file_hash not in hash_groups
        group_hashes[group] = file_hash
        hash_groups[file_hash] = group
    return {"catalogRepresentativePaths": len({row["path"] for row in rows}),
            "approvedFileInstances": len(expected), "duplicateFileInstances": len(expected) - len(groups),
            "matchedDistinctContents": len(group_hashes), "expectedDistinctContents": len(groups),
            "allFileInstancesIndexed": "evidence-incomplete",
            "status": ("evidence-incomplete" if not stable else
                       "observed" if set(group_hashes) == groups else "not-observed")}, rows


def _settings(phone: Phone, limits: Limits, *, configure=False):
    settings = phone.request("GET", "/app/settings")
    daemon = settings.get("daemon", {})
    if (daemon.get("incomingDir") != INCOMING or daemon.get("p2pBindInterface") not in {None, ""}
            or daemon.get("p2pBindIp") not in {None, "", "0.0.0.0", "::"}
            or settings.get("vpnGuard", {}).get("mode") != "off"):
        raise RuntimeError("Campaign requires canonical storage and explicit direct route settings")
    roots = phone.request("GET", "/shared-directories").get("roots")
    if not isinstance(roots, list) or {root.get("path") for root in roots} != {SHARED}:
        raise RuntimeError("Campaign requires only the canonical approved Shared root")
    if configure:
        phone.request("PATCH", "/app/settings", {"core": {"uploadLimitKiBps": limits.upload_limit_kibps,
                      "autoConnect": True, "networkKademlia": True}, "nat": {"enabled": True}})
        settings = phone.request("GET", "/app/settings")
    if (settings.get("core", {}).get("uploadLimitKiBps") != limits.upload_limit_kibps
            or settings.get("core", {}).get("autoConnect") is not True
            or settings.get("core", {}).get("networkKademlia") is not True
            or settings.get("nat", {}).get("enabled") is not True):
        raise RuntimeError("Campaign upload cap or UPnP preference differs")
    return settings


def configure_public_discovery(phone: Phone):
    """Reuse approved public seed owners without changing another host's profile.

    Imports are discovery metadata only. No search or transfer is created. A
    disabled existing server list remains operator state and is never replaced.
    """
    servers = phone.request("GET", "/servers").get("items")
    if not isinstance(servers, list):
        raise RuntimeError("Public server seed inventory is unavailable")
    imported_servers = False
    if not servers:
        phone.request("POST", "/servers/operations/import-met-url", {"url": DEFAULT_SERVER_MET_URL})
        servers = phone.request("GET", "/servers").get("items")
        imported_servers = True
    if not isinstance(servers, list) or not any(row.get("enabled") is True for row in servers):
        raise RuntimeError("Public discovery requires an approved enabled server seed")
    stats = phone.request("GET", "/stats")
    if stats.get("ed2kConnected") is not True:
        phone.request("POST", "/servers/operations/connect", {})
    kad = phone.request("GET", "/kad")
    imported_nodes = False
    if kad.get("connected") is not True:
        imported = phone.request("POST", "/kad/operations/import-nodes-url", {"url": DEFAULT_NODES_DAT_URL})
        if imported.get("imported") is not True:
            raise RuntimeError("Approved Kad discovery import was not confirmed")
        imported_nodes = True
        phone.request("POST", "/kad/operations/start", {})
    return {"serverSourceOwner": "soak_launch.DEFAULT_SERVER_MET_URL", "serverUrlSha256": _digest(DEFAULT_SERVER_MET_URL),
            "kadSourceOwner": "kad_nodes.DEFAULT_NODES_DAT_URL", "nodesUrlSha256": _digest(DEFAULT_NODES_DAT_URL),
            "serverImportRequested": imported_servers, "kadImportConfirmed": imported_nodes,
            "enabledServerCount": sum(row.get("enabled") is True for row in servers),
            "connectionAndPublication": "require-live-observation"}


def sample(phone: Phone, receipt: dict, previous_uploads=None):
    """Publication, upload activity and verified payload remain separate claims."""
    limits = Limits(**receipt["limits"])
    phone.identity()
    wifi_default(phone.shell("dumpsys", "connectivity"))
    guest_scope(phone, receipt)
    _settings(phone, limits)
    transfers = phone.request("GET", "/transfers?limit=1")
    if transfers.get("total") != 0 or transfers.get("items") != []:
        raise RuntimeError("Upload-only campaign observed a download queue")
    catalog, rows = shared_catalog(phone, receipt)
    summary = rust_summary(SimpleNamespace(rust_base_url=phone.base + "/api/v1", rust_api_key=phone.key))
    if summary.get("uploadLimitBytesPerSec") != limits.upload_limit_kibps * 1024:
        raise RuntimeError("Runtime upload cap differs from the admitted bound")
    status = phone.request("GET", "/status")
    directories = phone.request("GET", "/shared-directories")
    hashing = compact_progress(directories)
    upload_evidence, current_uploads = public_upload_evidence(
        phone.request("GET", "/uploads"), rows, previous_uploads or {})
    return {"observedAtUtc": utc_now(), "catalog": catalog, "hashing": hashing,
            "fileInstances": {"approved": receipt["fileCount"],
                              "copiedAndSha256Verified": receipt["fileCount"] if receipt.get("guestSha256Verified") is True else None,
                              "runtimeHashedCount": hashing.get("hashedCount"),
                              "runtimeReusedCount": hashing.get("reusedCount"),
                              "allPathsIndexed": "evidence-incomplete"},
            "runtime": summary, "nat": {key: status.get("nat", {}).get(key) for key in ("enabled", "tcpMapped", "udpMapped")},
            "claims": {"catalog": catalog["status"],
                       "ed2kConnection": ("observed" if summary.get("ed2kConnected") is True else
                                          "not-observed" if summary.get("ed2kConnected") is False else "evidence-incomplete"),
                       "kadConnection": ("observed" if summary.get("kadConnected") is True
                                         and (summary.get("kadContactCount") or 0) > 0 else "not-observed"),
                       "ed2kPublication": counter_claim(summary.get("ed2kPublishedEntries")),
                       "kadAcknowledgement": counter_claim(summary.get("kadSourceAckedContactsTotal")),
                       "uploadRequests": upload_evidence["requests"],
                       "publicPeerServedBytes": upload_evidence["bytesVerdict"],
                       "perFileServedBytes": "evidence-incomplete"},
            "uploadEvidence": upload_evidence, "privateUploads": current_uploads, "privateCatalog": rows}


def counter_claim(value):
    """Missing counters cannot masquerade as a completed negative observation."""
    if type(value) is not int or value < 0:
        return "evidence-incomplete"
    return "observed" if value > 0 else "not-observed"


def public_upload_evidence(document: dict, catalog: list, previous: dict):
    """Join public-peer payload-counter increases to an approved requested hash.

    A requested hash is request evidence. Increasing payload counters on the
    same public peer and requested hash prove bytes served during this observer;
    polling cannot prove exact per-file byte attribution between observations.
    """
    approved = {row["hash"].lower() for row in catalog}
    rows = document.get("items")
    if not isinstance(rows, list):
        raise RuntimeError("Upload evidence collection is unavailable")
    current, requested, served = {}, 0, 0
    for row in rows:
        file_hash = row.get("requestedFileHash")
        if file_hash is None:
            continue
        if not isinstance(file_hash, str) or file_hash.lower() not in approved:
            raise RuntimeError("Upload requested a hash outside the approved catalog")
        try:
            public = ipaddress.ip_address(row.get("address", "")).is_global
        except ValueError:
            public = False
        if not public:
            continue
        count = row.get("uploadedBytes")
        if type(count) is not int or count < 0 or not isinstance(row.get("clientId"), str):
            raise RuntimeError("Public upload payload counters are unavailable")
        key = _digest([row["clientId"], row["address"], file_hash.lower()])
        current[key] = count
        requested += 1
        if key in previous and count >= previous[key]:
            served += count - previous[key]
    return {"requests": "observed" if requested else "not-observed", "publicRequestRows": requested,
            "bytesVerdict": "observed" if served else "not-observed", "observedPayloadBytesDelta": served,
            "attribution": "same-public-peer-and-approved-requested-hash-counter-delta"}, current


def _append_history(campaign: Path, record: dict, limit: int):
    """Keep one bounded segment plus one retained predecessor."""
    path = campaign / "observations.jsonl"
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    if len(raw) > limit // 2:
        raise RuntimeError("Observation exceeds its evidence storage bound")
    if path.exists() and _regular(path).st_size + len(raw) > limit // 2:
        previous = campaign / "observations.previous.jsonl"
        if previous.exists():
            _regular(previous)
        path.replace(previous)
    with path.open("ab") as stream:
        stream.write(raw)


def observe(phone: Phone, receipt: dict, *, campaign: Path, output_root: Path,
            start=False, recover=False, launch_token=None):
    """Own a bounded observer; graceful expiry preserves the running service."""
    limits = Limits(**receipt["limits"])
    session = {"schema": SCHEMA, "campaignNonce": receipt["nonce"], "status": "starting",
               "launchToken": launch_token, "startedAtUtc": utc_now(), "owner": _process_identity(),
               "service": "unconfirmed", "observations": 0, "stopRequested": False,
               "publicUploadRequestObserved": False, "observedPublicPayloadBytes": 0}
    attempted_start = False
    with device_lease(output_root, receipt["deviceSerialSha256"], campaign, recover=recover):
        write_json(campaign / "session.json", session)
        try:
            phone.installed()
            # A receipt for this APK alone does not own another campaign's
            # running service. Admit the private nonce before cleanup may Stop.
            if phone.shell("cat", receipt["marker"]) != receipt["nonce"]:
                raise RuntimeError("Guest campaign ownership marker differs")
            phone.open()
            state = phone.state()
            if not start and state == "Running":
                session["service"] = "running"
            guest_scope(phone, receipt, hashes=True)
            wifi_default(phone.shell("dumpsys", "connectivity"))
            if start:
                if state != "Stopped":
                    raise RuntimeError("Start requires the prepared owned service to be stopped")
            elif state != "Running":
                raise RuntimeError("Resume never restarts a stopped or failed service")
            session["batteryCondition"] = battery_condition(phone, request_exemption=True)
            if phone.state() != state:
                raise RuntimeError("Battery permission setup changed the owned service state")
            phone.forward()
            if start:
                attempted_start = True
                phone.ui.click("start_service")
                phone.ui.wait_state("Running")
            phone.identity()
            _settings(phone, limits)
            session["discoveryPreparation"] = configure_public_discovery(phone)
            phone.shell("input", "keyevent", "KEYCODE_HOME")
            deadline = time.monotonic() + limits.duration_seconds
            # A previous stop request must be explicitly consumed by a successful
            # new monitor only after exact receipt/build admission above.
            stop = campaign / "stop-request.json"
            if stop.exists():
                raise RuntimeError("Campaign has a stop request; prepare a new campaign to restart")
            previous_uploads = {}
            while True:
                if stop.exists():
                    request = _read_json(stop)
                    if request.get("nonce") != receipt["nonce"]:
                        raise RuntimeError("Stop request ownership differs")
                    phone.stop()
                    session.update(status="stopped", service="stopped", stopRequested=True)
                    break
                if (shutil.disk_usage(campaign).free < limits.minimum_free_bytes
                        or _guest_free(phone) < limits.minimum_free_bytes):
                    raise RuntimeError("Campaign free-space reserve was exceeded")
                record = sample(phone, receipt, previous_uploads)
                previous_uploads = record.pop("privateUploads", {})
                evidence = record.get("uploadEvidence", {})
                session["publicUploadRequestObserved"] |= evidence.get("requests") == "observed"
                session["observedPublicPayloadBytes"] += evidence.get("observedPayloadBytesDelta", 0)
                _append_history(campaign, record, limits.history_max_bytes)
                record.pop("privateCatalog", None)
                session.update(status="observing", service="running", heartbeatAtUtc=utc_now(),
                               observations=session["observations"] + 1, latest=record)
                write_json(campaign / "session.json", session)
                if time.monotonic() >= deadline:
                    session.update(status="observation-complete", service="left-running")
                    break
                time.sleep(min(limits.interval_seconds, max(0, deadline - time.monotonic())))
        except Exception as error:
            session.update(status="failed", errorType=type(error).__name__)
            # WHY: loss of scope/route/cap evidence must not silently leave an
            # owned upload service active. Never stop an unverified installation.
            if attempted_start or session["service"] == "running":
                try:
                    phone.stop()
                    session["service"] = "stopped-after-failure"
                except Exception as stop_error:
                    session.update(service="stop-unconfirmed", stopErrorType=type(stop_error).__name__)
        finally:
            try:
                phone.cleanup()
            except Exception as error:
                session.update(status="failed", cleanupErrorType=type(error).__name__)
            session["finishedAtUtc"] = utc_now()
            write_json(campaign / "session.json", session)
    return session


def stop_campaign(phone: Phone, receipt: dict, *, campaign: Path, output_root: Path):
    """Signal only the exact observer, or stop the verified app after it exited."""
    session_path = campaign / "session.json"
    session = _read_json(session_path) if session_path.exists() else {}
    if session and session.get("campaignNonce") != receipt["nonce"]:
        raise RuntimeError("Session campaign ownership differs")
    write_json(campaign / "stop-request.json", {"nonce": receipt["nonce"], "requestedAtUtc": utc_now()})
    if session.get("owner") and _alive(session["owner"]):
        return {"status": "stop-requested", "service": "stop-pending"}
    with device_lease(output_root, receipt["deviceSerialSha256"], campaign, recover=True):
        try:
            phone.installed()
            if phone.shell("cat", receipt["marker"]) != receipt["nonce"]:
                raise RuntimeError("Guest campaign ownership marker differs")
            phone.stop()
            session.update(schema=SCHEMA, campaignNonce=receipt["nonce"], status="stopped", service="stopped", finishedAtUtc=utc_now())
            try:
                guest_scope(phone, receipt)
                session["scopeAfterStop"] = "unchanged"
            except Exception:
                session["scopeAfterStop"] = "drift-observed"
        except Exception as error:
            session.update(schema=SCHEMA, campaignNonce=receipt["nonce"], status="failed",
                           service="stop-unconfirmed", errorType=type(error).__name__)
        finally:
            try:
                phone.cleanup()
            except Exception as error:
                session.update(status="failed", cleanupErrorType=type(error).__name__)
            write_json(session_path, session)
    return session


def safe_status(campaign: Path, receipt: dict):
    """Print only aggregate findings; private inventory and endpoints stay local."""
    path = campaign / "session.json"
    session = _read_json(path) if path.exists() else {}
    if session and session.get("campaignNonce") != receipt["nonce"]:
        raise RuntimeError("Session campaign ownership differs")
    live = bool(session.get("status") in {"observing", "starting"} and session.get("owner") and _alive(session["owner"]))
    lost = session.get("status") in {"observing", "starting"} and not live
    return {"status": "observer-lost" if lost else session.get("status", "prepared"), "monitorAlive": live,
            "service": "unconfirmed" if lost else session.get("service", "stopped-at-prepare"), "fileCount": receipt["fileCount"],
            "totalBytes": receipt["totalBytes"], "observations": session.get("observations", 0),
            "publicUploadRequestObserved": session.get("publicUploadRequestObserved", False),
            "observedPublicPayloadBytes": session.get("observedPublicPayloadBytes", 0),
            "batteryCondition": session.get("batteryCondition", receipt.get("batteryCondition")),
            "latest": session.get("latest"), "publicParityClaim": "not-claimed"}


def spawn_observer(arguments: list[str], *, campaign: Path):
    """Detach persisted Python, retaining no command line or unbounded stdout log."""
    token = uuid4().hex
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/android-public-sharing.py"),
               *arguments, "--worker-token", token]
    options = ({"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
               if os.name == "nt" else {"start_new_session": True})
    child_environment = os.environ.copy()
    # WHY: Builder's delegation token belongs to the short foreground action;
    # the detached observer must never impersonate that expired workspace lock.
    child_environment.pop("EMULEBB_WORKSPACE_LOCK_TOKEN", None)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=child_environment, **options)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        path = campaign / "session.json"
        if path.exists():
            session = _read_json(path)
            if session.get("launchToken") == token and session.get("status") != "starting":
                if session["status"] == "failed":
                    raise RuntimeError("Detached campaign failed; inspect local session evidence")
                return
        if process.poll() is not None:
            raise RuntimeError("Detached campaign exited before readiness; inspect local evidence")
        time.sleep(0.25)
    # Admission may hash a large approved tree over Wi-Fi. The persisted
    # starting receipt remains authoritative while the child is still alive.
    return


def main(argv=None):
    """Operator CLI; errors never expose private paths, endpoints or response text."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "start", "observe", "status", "stop"))
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--campaign-receipt-sha256")
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--serial")
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--expected-file-count", type=int)
    parser.add_argument("--expected-total-bytes", type=int)
    parser.add_argument("--route", choices=("direct-wifi",))
    parser.add_argument("--installation-receipt", type=Path)
    parser.add_argument("--installation-receipt-sha256")
    parser.add_argument("--apk-payload", type=Path)
    parser.add_argument("--apk-manifest-name")
    parser.add_argument("--apk-manifest-sha256")
    parser.add_argument("--apk-source-sha")
    parser.add_argument("--expected-cert-sha256")
    for key, value in asdict(Limits()).items():
        parser.add_argument("--" + key.replace("_", "-"), type=int, default=value)
    parser.add_argument("--recover-stale-monitor", action="store_true")
    parser.add_argument("--worker-token", help=argparse.SUPPRESS)
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(arguments)
    try:
        output_root = get_workspace_output_root()
        if args.action == "prepare":
            required = (args.adb, args.serial, args.source_dir, args.expected_file_count, args.expected_total_bytes,
                        args.route, args.installation_receipt, args.installation_receipt_sha256, args.apk_payload,
                        args.apk_manifest_name, args.apk_manifest_sha256, args.apk_source_sha, args.expected_cert_sha256)
            if not all(value is not None for value in required):
                raise ValueError("Prepare requires explicit installation, approved source and direct-Wi-Fi inputs")
            admission = {"root": str(args.apk_payload.absolute()), "manifest_name": args.apk_manifest_name,
                         "manifest_sha256": args.apk_manifest_sha256, "source_sha": args.apk_source_sha,
                         "expected_cert_sha256": args.expected_cert_sha256}
            payload = admit_payload(Path(admission["root"]), **{key: value for key, value in admission.items() if key != "root"})
            installation = read_hashed_receipt(args.installation_receipt, args.installation_receipt_sha256)
            phone = Phone(AdbDevice(args.adb, args.serial, server_port=args.server_port), payload)
            digest = prepare(phone, campaign=args.campaign_dir, output_root=output_root, source=args.source_dir,
                             expected_file_count=args.expected_file_count, expected_total_bytes=args.expected_total_bytes,
                             installation=installation, admission=admission, route=args.route,
                             limits=Limits(**{key: getattr(args, key) for key in asdict(Limits())}))
            print(json.dumps({"status": "prepared", "campaignReceiptSha256": digest}))
            return 0
        campaign = _private_root(args.campaign_dir, output_root)
        if not args.campaign_receipt_sha256:
            raise ValueError("Campaign operations require its immutable receipt SHA-256")
        receipt = admit_campaign(campaign, args.campaign_receipt_sha256, args.serial)
        if args.action == "status":
            print(json.dumps(safe_status(campaign, receipt)))
            return 0
        if args.adb is None or not args.serial:
            raise ValueError("Device operations require the exact operator-selected ADB and serial")
        if args.action in {"start", "observe"} and args.worker_token is None:
            spawn_observer(arguments, campaign=campaign)
            print(json.dumps(safe_status(campaign, receipt)))
            return 0
        admission = receipt["admission"]
        payload = admit_payload(Path(admission["root"]), **{key: value for key, value in admission.items() if key != "root"})
        phone = Phone(AdbDevice(args.adb, args.serial, server_port=args.server_port), payload)
        if args.action == "stop":
            result = stop_campaign(phone, receipt, campaign=campaign, output_root=output_root)
        else:
            result = observe(phone, receipt, campaign=campaign, output_root=output_root, start=args.action == "start",
                             recover=args.recover_stale_monitor, launch_token=args.worker_token)
        print(json.dumps({"status": result["status"], "service": result.get("service")}))
        return 1 if result["status"] == "failed" else 0
    except Exception as error:
        print(json.dumps({"status": "failed", "errorType": type(error).__name__,
                          "message": "Campaign operation failed; inspect local evidence and ownership before retrying"}))
        return 1
