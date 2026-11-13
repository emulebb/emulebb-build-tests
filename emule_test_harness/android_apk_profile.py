"""Explicit phone storage configuration and schema-equal owned APK updates."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shlex

from .android_apk_lifecycle import admit_production_certificate

INCOMING = "/storage/emulated/0/Download/eMuleBB/Incoming"
SHARED = "/storage/emulated/0/Download/eMuleBB/Shared"
SCHEMA_MATERIALS = frozenset({"crates/emulebb-metadata/src/schema.sql", "crates/emulebb-metadata/src/schema.rs"})


def read_hashed_receipt(path: Path | None, digest: str | None) -> dict:
    """Read one bounded regular receipt only with an independently supplied hash."""
    if (path is None or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or path.is_symlink() or not path.is_file() or path.stat().st_size > 65536):
        raise RuntimeError("Phone profile operation requires a bounded receipt and immutable SHA-256")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("Phone profile receipt hash differs")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("Phone profile receipt must be an object")
    return value


def configure_storage(command, *, prefix: tuple, base_url: str, api_key: str, payload: dict,
                      device_hash: str, report_path: Path) -> dict:
    """Persist only the operator-approved paths; preserve other roots and root entries."""
    from .rust_local_ed2k import request_json
    receipt = {"schema": "emulebb.android.storage-configuration/1", "status": "failed",
               "deviceSerialSha256": device_hash, "apkSha256": payload["apk"]["sha256"],
               "sourceRevision": payload["buildIdentity"]["sourceRevision"], "signerSha256": payload["signerSha256"],
               "versionCode": payload["versionCode"], "incomingDir": INCOMING, "sharedRoot": SHARED,
               "application": "persisted-requires-service-restart", "filesMovedOrDeleted": 0}

    def shell(*args):
        return command(*prefix, "shell", *args)

    def roots():
        document = request_json(base_url, "GET", "/api/v1/shared-directories", api_key)
        value = document.get("roots")
        if not isinstance(value, list) or any(not isinstance(root, dict) or not isinstance(root.get("path"), str) for root in value):
            raise RuntimeError("Invalid shared-root configuration")
        return {root["path"] for root in value}

    try:
        app = request_json(base_url, "GET", "/api/v1/app", api_key)
        if any(app.get(name) != value for name, value in payload["buildIdentity"].items()):
            raise RuntimeError("Storage configuration source identity differs")
        before_roots = roots()
        before_entries = set(shell("ls", "-A", "/sdcard/Download/eMuleBB").splitlines())
        shell("sh", "-c", shlex.quote("test ! -L /sdcard/Download/eMuleBB && "
              "test ! -L /sdcard/Download/eMuleBB/Incoming && test ! -L /sdcard/Download/eMuleBB/Shared"))
        shell("mkdir", "-p", "/sdcard/Download/eMuleBB/Incoming", "/sdcard/Download/eMuleBB/Shared")
        for alias, expected in (("/sdcard/Download/eMuleBB/Incoming", INCOMING), ("/sdcard/Download/eMuleBB/Shared", SHARED)):
            if shell("readlink", "-f", alias) != expected:
                raise RuntimeError("Approved phone storage path is redirected")
        request_json(base_url, "PATCH", "/api/v1/app/settings", api_key, {"daemon": {"incomingDir": INCOMING}})
        if SHARED not in before_roots:
            request_json(base_url, "POST", "/api/v1/shared-directories/roots", api_key, {"path": SHARED})
        settings = request_json(base_url, "GET", "/api/v1/app/settings", api_key)
        after_roots = roots()
        after_entries = set(shell("ls", "-A", "/sdcard/Download/eMuleBB").splitlines())
        if (settings.get("daemon", {}).get("incomingDir") != INCOMING or SHARED not in after_roots
                or not before_roots <= after_roots or not before_entries <= after_entries):
            raise RuntimeError("Approved storage configuration was not preserved or persisted")
        receipt.update(status="passed", priorRootsPreserved=True, rootEntriesPreserved=True,
                       priorRootCount=len(before_roots), rootEntryCountBefore=len(before_entries), rootEntryCountAfter=len(after_entries))
        return receipt
    except Exception as error:
        receipt["errorType"] = type(error).__name__
        # API failures can contain private paths. Never propagate response text.
        raise RuntimeError("Approved phone storage configuration failed") from None
    finally:
        report_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class OwnedUpdateApproval:
    """Typed result of independent old-install/config/schema admission."""
    installed: dict
    target_path: str
    target_sha256: str
    schema_sha256: str


def admit_owned_update(payload: dict, *, device_hash: str, expected_cert_sha256: str,
                       installation: dict, configuration: dict, compatibility: dict) -> OwnedUpdateApproval:
    """Require exact owned origin, persisted configuration and strict source-schema equality."""
    admit_production_certificate(payload, expected_cert_sha256=expected_cert_sha256)
    old = installation
    if (old.get("schema") != "emulebb.android.physical-device/1" or old.get("status") not in {"passed", "setup-required"}
            or old.get("ownedInstallation") is not True or old.get("debugBuild") is not False
            or old.get("deviceSerialSha256") != device_hash or old.get("signerSha256") != expected_cert_sha256
            or not isinstance(old.get("apkSha256"), str) or re.fullmatch(r"[0-9a-f]{64}", old["apkSha256"]) is None
            or not isinstance(old.get("sourceRevision"), str) or re.fullmatch(r"[0-9a-f]{40}", old["sourceRevision"]) is None
            or type(old.get("versionCode")) is not int or old["versionCode"] >= payload["versionCode"]
            or not isinstance(old.get("versionName"), str) or not old["versionName"]):
        raise RuntimeError("Compatible update requires the exact owned production installation and a higher versionCode")
    if (configuration.get("schema") != "emulebb.android.storage-configuration/1"
            or configuration.get("status") != "passed"
            or any(configuration.get(name) != old.get(name) for name in (
                "deviceSerialSha256", "apkSha256", "sourceRevision", "signerSha256", "versionCode"))
            or configuration.get("incomingDir") != INCOMING or configuration.get("sharedRoot") != SHARED
            or configuration.get("priorRootsPreserved") is not True or configuration.get("rootEntriesPreserved") is not True
            or type(configuration.get("filesMovedOrDeleted")) is not int or configuration["filesMovedOrDeleted"] != 0):
        raise RuntimeError("Compatible update requires verified explicit phone storage configuration")
    materials = compatibility.get("materials")
    if (compatibility.get("schema") != "emulebb.android.profile-compatibility/1" or compatibility.get("status") != "passed"
            or compatibility.get("fromSourceRevision") != old["sourceRevision"]
            or compatibility.get("toSourceRevision") != payload["buildIdentity"]["sourceRevision"]
            or not isinstance(materials, dict) or set(materials) != SCHEMA_MATERIALS
            or any(not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in materials.values())):
        raise RuntimeError("Compatible update requires exact old/new source schema equality evidence")
    schema_sha = hashlib.sha256(json.dumps(materials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if compatibility.get("metadataSchemaSha256") != schema_sha:
        raise RuntimeError("Compatible update schema material digest differs")
    return OwnedUpdateApproval(old, payload["payloadPath"], payload["apk"]["sha256"], schema_sha)
