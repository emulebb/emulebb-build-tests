"""Explicit configuration never replaces roots; updates require independently bound evidence."""
import hashlib
import json

import pytest

from emule_test_harness import android_apk_profile as subject


def evidence():
    old = {"schema": "emulebb.android.physical-device/1", "status": "passed", "ownedInstallation": True,
           "debugBuild": False, "deviceSerialSha256": "d" * 64, "apkSha256": "a" * 64,
           "sourceRevision": "1" * 40, "signerSha256": "b" * 64, "versionCode": 1, "versionName": "0.1.0-old"}
    config = {**old, "schema": "emulebb.android.storage-configuration/1", "incomingDir": subject.INCOMING,
              "sharedRoot": subject.SHARED, "priorRootsPreserved": True, "rootEntriesPreserved": True,
              "restartVerified": True, "filesMovedOrDeleted": 0}
    materials = {path: "c" * 64 for path in subject.SCHEMA_MATERIALS}
    compat = {"schema": "emulebb.android.profile-compatibility/1", "status": "passed",
              "fromSourceRevision": "1" * 40, "toSourceRevision": "2" * 40, "materials": materials,
              "metadataSchemaSha256": hashlib.sha256(json.dumps(materials, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    payload = {"debug": False, "apk": {"sha256": "e" * 64}, "signerSha256": "b" * 64,
               "versionCode": 2, "payloadPath": "synthetic.apk", "buildIdentity": {"sourceRevision": "2" * 40}}
    return old, config, compat, payload


@pytest.mark.parametrize("fault", [None, "foreign-install", "wrong-device", "same-version", "signer", "config-source", "config-path", "lost-roots", "schema-source", "schema-map", "schema-hash"])
def test_compatible_update_requires_exact_owned_origin_configuration_and_schema(fault):
    old, config, compat, payload = evidence()
    if fault == "foreign-install": old["ownedInstallation"] = False
    if fault == "wrong-device": old["deviceSerialSha256"] = "0" * 64
    if fault == "same-version": payload["versionCode"] = 1
    if fault == "signer": payload["signerSha256"] = "0" * 64
    if fault == "config-source": config["sourceRevision"] = "3" * 40
    if fault == "config-path": config["incomingDir"] = "/foreign"
    if fault == "lost-roots": config["priorRootsPreserved"] = False
    if fault == "schema-source": compat["fromSourceRevision"] = "3" * 40
    if fault == "schema-map": compat["materials"].pop(next(iter(compat["materials"])))
    if fault == "schema-hash": compat["metadataSchemaSha256"] = "0" * 64
    kwargs = dict(device_hash="d" * 64, expected_cert_sha256="b" * 64,
                  installation=old, configuration=config, compatibility=compat)
    if fault:
        with pytest.raises(RuntimeError):
            subject.admit_owned_update(payload, **kwargs)
    else:
        approval = subject.admit_owned_update(payload, **kwargs)
        assert approval.installed == old and approval.target_sha256 == "e" * 64


@pytest.mark.parametrize("fault", [None, "lost-roots", "lost-files", "redirected", "no-restart"])
def test_normal_configuration_uses_additive_roots_and_preserves_phone_entries(tmp_path, monkeypatch, fault):
    from emule_test_harness import rust_local_ed2k
    old, _, _, payload = evidence()
    payload["buildIdentity"]["sourceRevision"] = old["sourceRevision"]
    roots = {"/storage/emulated/0/Download/Existing Shared"}
    entries = {"Existing User File.bin"}
    settings = {"daemon": {"incomingDir": None}}
    calls = []
    changed = [False]
    live_incoming = ["/storage/emulated/0/Download/eMuleBB"]

    def request(base, method, route, key, body=None):
        calls.append((method, route, body))
        if route == "/api/v1/app": return payload["buildIdentity"]
        if route == "/api/v1/shared-directories": return {"roots": [{"path": root} for root in roots]}
        if route == "/api/v1/app/settings":
            if method == "PATCH": settings.update(body)
            return settings
        if route == "/api/v1/shared-directories/roots":
            assert method == "POST" and body == {"path": subject.SHARED}
            # Canonical Rust behavior: children covered by the live Incoming
            # folder are ignored, even after a persisted-only incoming PATCH.
            if not subject.SHARED.startswith(live_incoming[0] + "/"):
                roots.add(subject.SHARED)
            if fault == "lost-roots": roots.remove("/storage/emulated/0/Download/Existing Shared")
        return {}

    def command(*args):
        assert args[:3] == ("-s", "synthetic-device", "shell")
        operation = args[3:]
        if operation[:1] == ("ls",):
            return "\n".join(entries - ({"Existing User File.bin"} if fault == "lost-files" and changed[0] else set()))
        if operation[:1] == ("mkdir",):
            changed[0] = True
            entries.update({"Incoming", "Shared"})
            return ""
        if operation[:1] == ("readlink",):
            return "/foreign" if fault == "redirected" else operation[-1].replace("/sdcard", "/storage/emulated/0")
        assert operation[:2] == ("sh", "-c")
        return ""

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)
    report = tmp_path / "config.json"
    kwargs = dict(prefix=("-s", "synthetic-device"), base_url="http://127.0.0.1:1234", api_key="synthetic-private-key",
                  payload=payload, device_hash="d" * 64, report_path=report,
                  restart_service=lambda: live_incoming.__setitem__(0, settings["daemon"]["incomingDir"])
                  if fault != "no-restart" else None)
    if fault:
        with pytest.raises(RuntimeError, match="storage configuration failed"):
            subject.configure_storage(command, **kwargs)
        assert json.loads(report.read_text())["status"] == "failed"
    else:
        result = subject.configure_storage(command, **kwargs)
        assert result["status"] == "passed" and result["application"] == "service-restarted-before-sharing"
        assert result["priorRootsPreserved"] and result["rootEntriesPreserved"] and result["filesMovedOrDeleted"] == 0
    assert not any(method == "DELETE" or route == "/api/v1/shared-directories" and method == "PATCH" for method, route, body in calls)
    assert "Existing User File.bin" not in report.read_text() and "synthetic-private-key" not in report.read_text()


def test_profile_receipts_require_an_immutable_hash(tmp_path):
    report = tmp_path / "receipt.json"
    report.write_text('{"status":"passed"}')
    assert subject.read_hashed_receipt(report, hashlib.sha256(report.read_bytes()).hexdigest()) == {"status": "passed"}
    with pytest.raises(RuntimeError, match="hash differs"):
        subject.read_hashed_receipt(report, "0" * 64)
