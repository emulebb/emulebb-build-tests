"""Remove only an independently admitted synthetic Android collision fixture."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex

from .android_apk_profile import read_hashed_receipt
from .rust_local_ed2k import request_json
from .rust_shared_library_fixture import deterministic_payload

FIXTURE_NAME = "Android Sample.bin"
COLLISION_OCCUPANT = b"synthetic foreign occupant"
OCCUPANT_SHA256 = hashlib.sha256(COLLISION_OCCUPANT).hexdigest()


def remove_owned_fixture(command, *, prefix, nonce: str, protected_roots: set[str]) -> None:
    """Check the complete owned directory before one file unlink and empty rmdir."""
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise RuntimeError("Owned fixture requires an exact nonce")
    incoming = "/storage/emulated/0/Download/emulebb-apk-proof-" + nonce
    path = PurePosixPath(incoming)
    normalized = {"/storage/emulated/0/" + root[len("/sdcard/"):] if root.startswith("/sdcard/") else root for root in protected_roots}
    if any(path.is_relative_to(PurePosixPath(root)) or PurePosixPath(root).is_relative_to(path) for root in normalized):
        raise RuntimeError("Owned fixture overlaps current Incoming or sharing configuration")
    shell = lambda *args: command(*prefix, "shell", *args)
    shell("test", "!", "-L", incoming)
    if shell("readlink", "-f", incoming) != incoming:
        raise RuntimeError("Owned fixture directory was redirected")
    if shell("ls", "-A", incoming).splitlines() != [FIXTURE_NAME]:
        raise RuntimeError("Owned fixture contains unknown or missing files")
    occupant = incoming + "/" + FIXTURE_NAME
    shell("test", "!", "-L", shlex.quote(occupant))
    if shell("sha256sum", shlex.quote(occupant)).split()[:1] != [OCCUPANT_SHA256]:
        raise RuntimeError("Owned collision fixture bytes changed")
    shell("rm", "--", shlex.quote(occupant))
    shell("rmdir", incoming)


def cleanup_report_fixture(command, *, prefix, retained_report: Path, report_sha256: str, fixture_sha256: str,
                           output_root: Path, device_hash: str, expected_cert_sha256: str,
                           base_url: str, api_key: str, report_path: Path) -> dict:
    receipt = {"schema": "emulebb.android.owned-fixture-cleanup/1", "status": "failed", "phase": "admit-report",
               "retainedReportSha256": report_sha256, "fixtureSha256": fixture_sha256,
               "deviceSerialSha256": device_hash, "settingsChanged": False, "filesRemoved": 0, "directoriesRemoved": 0}
    def save():
        temporary = report_path.with_name(report_path.name + ".tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(receipt, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(report_path)
    def stage(value):
        receipt["phase"] = value
        save()
    try:
        if retained_report.is_symlink() or not retained_report.resolve().is_relative_to(output_root.resolve()):
            raise RuntimeError("Retained fixture report must belong to the inherited output root")
        proof = read_hashed_receipt(retained_report / "physical-device.json", report_sha256)
        if (proof.get("schema") != "emulebb.android.physical-device/1" or proof.get("status") != "failed"
                or proof.get("ownedInstallation") is not True or proof.get("debugBuild") is not False
                or proof.get("runtimeExecution") != "executed" or proof.get("deviceSerialSha256") != device_hash
                or proof.get("signerSha256") != expected_cert_sha256
                or re.fullmatch(r"[0-9a-f]{40}", proof.get("sourceRevision", "")) is None):
            raise RuntimeError("Retained report does not admit an owned source-bound physical fixture")
        stage("admit-host-fixture")
        fixture = retained_report / FIXTURE_NAME
        if (re.fullmatch(r"[0-9a-f]{64}", fixture_sha256) is None or fixture.is_symlink()
                or not fixture.is_file() or fixture.stat().st_size != 256 * 1024
                or hashlib.sha256(fixture.read_bytes()).hexdigest() != fixture_sha256):
            raise RuntimeError("Retained synthetic payload differs from caller authority")
        stage("admit-current-storage")
        settings = request_json(base_url, "GET", "/api/v1/app/settings", api_key)
        incoming = settings.get("daemon", {}).get("incomingDir")
        roots = request_json(base_url, "GET", "/api/v1/shared-directories", api_key)["roots"]
        protected = {root["path"] for root in roots}
        if not isinstance(incoming, str) or not incoming.startswith("/"):
            raise RuntimeError("Current incoming destination is not explicit")
        protected.add(incoming)
        stage("match-owned-nonce")
        listing = command(*prefix, "shell", "sh", "-c", shlex.quote(
            "find /sdcard/Download -mindepth 1 -maxdepth 1 -name 'emulebb-apk-proof-*' -print | head -n 17")).splitlines()
        if len(listing) > 16:
            raise RuntimeError("Owned fixture namespace exceeds its bounded inventory")
        matches = []
        for candidate in listing:
            match = re.fullmatch(r"/sdcard/Download/emulebb-apk-proof-([0-9a-f]{32})", candidate)
            if match is not None and hashlib.sha256(deterministic_payload(0, 256 * 1024,
                    generation="android-apk-" + match[1])).hexdigest() == fixture_sha256:
                matches.append(match[1])
        if len(matches) != 1:
            raise RuntimeError("Retained payload must identify exactly one owned fixture nonce")
        receipt["nonce"] = matches[0]
        stage("remove-owned-fixture")
        remove_owned_fixture(command, prefix=prefix, nonce=matches[0], protected_roots=protected)
        receipt.update(filesRemoved=1, directoriesRemoved=1)
        stage("verify-settings-preserved")
        if (request_json(base_url, "GET", "/api/v1/app/settings", api_key) != settings
                or {root["path"] for root in request_json(base_url, "GET", "/api/v1/shared-directories", api_key)["roots"]}
                   != {root["path"] for root in roots}):
            raise RuntimeError("Configuration changed during owned fixture cleanup")
        receipt.update(status="passed", phase="complete")
        return receipt
    except Exception as error:
        receipt["errorType"] = type(error).__name__
        raise RuntimeError("Owned fixture cleanup failed at " + receipt["phase"]) from None
    finally:
        save()
