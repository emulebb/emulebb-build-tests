"""Retained reports authorize only one exact synthetic Android fixture."""
import hashlib
import json
import shlex
from copy import deepcopy

import pytest

from emule_test_harness import android_apk_cleanup as subject

NONCE = "a" * 32
DEVICE = "b" * 64
SIGNER = "c" * 64


@pytest.mark.parametrize("fault", [None, "report-hash", "device", "fixture-hash", "zero", "multiple", "bound",
    "unknown-file", "directory-symlink", "file-symlink", "redirect", "changed-occupant", "current-incoming", "shared-root"])
def test_cleanup_requires_exact_source_report_nonce_content_and_unprotected_directory(tmp_path, monkeypatch, fault):
    retained = tmp_path / "retained"
    retained.mkdir()
    proof = {"schema": "emulebb.android.physical-device/1", "status": "failed", "ownedInstallation": True,
             "debugBuild": False, "runtimeExecution": "executed", "deviceSerialSha256": DEVICE,
             "signerSha256": SIGNER, "sourceRevision": "d" * 40}
    if fault == "device":
        proof["deviceSerialSha256"] = "e" * 64
    raw = json.dumps(proof).encode()
    (retained / "physical-device.json").write_bytes(raw)
    report_sha = hashlib.sha256(raw).hexdigest()
    payload = subject.deterministic_payload(0, 256 * 1024, generation="android-apk-" + NONCE)
    (retained / subject.FIXTURE_NAME).write_bytes(payload)
    payload_sha = hashlib.sha256(payload).hexdigest()
    candidate = "/sdcard/Download/emulebb-apk-proof-" + NONCE
    canonical = candidate.replace("/sdcard", "/storage/emulated/0")
    candidates = [candidate]
    if fault == "zero":
        candidates = [candidate[:-32] + "f" * 32]
    elif fault == "multiple":
        candidates *= 2
    elif fault == "bound":
        candidates *= 17
    settings = {"daemon": {"incomingDir": candidate if fault == "current-incoming" else "/operator/Incoming"}}
    roots = [{"path": canonical if fault == "shared-root" else "/operator/Shared"}]
    operations, requests, removed = [], [], []

    def request(base, method, route, key):
        requests.append((method, route))
        assert method == "GET", "cleanup must not mutate operator configuration"
        return deepcopy(settings if route.endswith("settings") else {"roots": roots})

    def command(*args, **kwargs):
        operation = args[2:]
        operations.append(operation)
        if operation[:2] == ("shell", "sh"):
            assert "head -n 17" in operation[-1] and "-maxdepth 1" in operation[-1]
            return "\n".join(candidates)
        if operation[:2] == ("shell", "test"):
            is_file = shlex.split(operation[-1])[0].endswith(subject.FIXTURE_NAME)
            if fault == ("file-symlink" if is_file else "directory-symlink"):
                raise RuntimeError("private OS message must not be retained")
        if operation[:3] == ("shell", "readlink", "-f"):
            return "/foreign/redirected" if fault == "redirect" else canonical
        if operation[:3] == ("shell", "ls", "-A"):
            return subject.FIXTURE_NAME + ("\noperator-file" if fault == "unknown-file" else "")
        if operation[:2] == ("shell", "sha256sum"):
            return ("0" * 64 if fault == "changed-occupant" else subject.OCCUPANT_SHA256) + " synthetic"
        if operation[:2] == ("shell", "rm"):
            assert operation[2] == "--" and "-r" not in operation and "-rf" not in operation
            removed.append(shlex.split(operation[-1])[0])
        if operation[:2] == ("shell", "rmdir"):
            assert removed == [canonical + "/" + subject.FIXTURE_NAME]
            removed.append(operation[-1])
        return ""

    monkeypatch.setattr(subject, "request_json", request)
    arguments = dict(prefix=("-s", "private-serial"), retained_report=retained,
        report_sha256="0" * 64 if fault == "report-hash" else report_sha,
        fixture_sha256="0" * 64 if fault == "fixture-hash" else payload_sha, output_root=tmp_path,
        device_hash=DEVICE, expected_cert_sha256=SIGNER, base_url="http://127.0.0.1:12345",
        api_key="operator-secret", report_path=tmp_path / "cleanup.json")
    if fault:
        with pytest.raises(RuntimeError, match="Owned fixture cleanup failed"):
            subject.cleanup_report_fixture(command, **arguments)
        assert not removed
        if fault in {"report-hash", "device", "fixture-hash"}:
            assert not operations and not requests
    else:
        result = subject.cleanup_report_fixture(command, **arguments)
        assert result["status"] == "passed" and result["filesRemoved"] == result["directoriesRemoved"] == 1
        assert result["settingsChanged"] is False and removed == [canonical + "/" + subject.FIXTURE_NAME, canonical]
    evidence = (tmp_path / "cleanup.json").read_text()
    assert "operator-secret" not in evidence and "private-serial" not in evidence and "/operator/" not in evidence
    assert "operator-file" not in evidence and "private OS message" not in evidence
