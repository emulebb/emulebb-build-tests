"""Verify image smokes execute the archive's bytes and always remove owned containers."""
import hashlib
import io
import json
import subprocess
import tarfile

import pytest

from emule_test_harness.script_modules import load_script_module

smoke = load_script_module("smoke_rust_container", "smoke-rust-container.py")


def write_oci(path, *, changed_config=False, duplicate=False):
    config = json.dumps({"os": "linux", "architecture": "amd64"}).encode()
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config_digest}}).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    descriptor = {"digest": manifest_digest, "platform": {"os": "linux", "architecture": "amd64"}}
    index = json.dumps({"schemaVersion": 2, "manifests": [descriptor] * (2 if duplicate else 1)}).encode()
    index_digest = "sha256:" + hashlib.sha256(index).hexdigest()
    root = json.dumps({"schemaVersion": 2, "manifests": [{"digest": index_digest}]}).encode()
    with tarfile.open(path, "w") as archive:
        for name, data in (("index.json", root), ("blobs/sha256/" + index_digest[7:], index),
                           ("blobs/sha256/" + manifest_digest[7:], manifest),
                           ("blobs/sha256/" + config_digest[7:], config + b" " if changed_config else config)):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return config_digest


def test_reads_exact_config_from_nested_buildkit_index(tmp_path):
    archive = tmp_path / "image.oci.tar"
    expected = write_oci(archive)
    assert smoke.oci_platform_configs(archive) == {"linux/amd64": expected}


@pytest.mark.parametrize("fault", ["changed", "duplicate"])
def test_rejects_changed_config_bytes_and_ambiguous_platforms(tmp_path, fault):
    archive = tmp_path / "image.oci.tar"
    write_oci(archive, changed_config=fault == "changed", duplicate=fault == "duplicate")
    with pytest.raises(RuntimeError, match="digest mismatch|repeats a runnable platform"):
        smoke.oci_platform_configs(archive)


def test_wrong_local_tag_cannot_pass_and_its_container_is_removed(monkeypatch):
    calls = []
    def docker(*arguments, **kwargs):
        calls.append(arguments)
        if arguments[:2] == ("container", "inspect"):
            return subprocess.CompletedProcess(arguments, 1, "", "")
        return subprocess.CompletedProcess(arguments, 0, "sha256:" + "b" * 64, "")
    monkeypatch.setattr(smoke, "docker", docker)
    with pytest.raises(RuntimeError, match="does not match the OCI archive"):
        smoke.smoke_platform("local/test:beta", "linux/amd64", "sha256:" + "a" * 64)
    launch = next(call for call in calls if call[0] == "run")
    assert launch[launch.index("--pull") + 1] == "never"
    assert launch[launch.index("--label") + 1].startswith("io.emulebb.ci.image-smoke-owner=")
    name = launch[launch.index("--name") + 1]
    assert calls[-1] == ("rm", "--force", name)


def test_cleanup_failure_does_not_hide_original_image_mismatch(monkeypatch):
    def docker(*arguments, **kwargs):
        if arguments[0] == "rm":
            raise subprocess.TimeoutExpired(arguments, 1)
        return subprocess.CompletedProcess(arguments, 1 if arguments[0] == "container" else 0,
                                           "sha256:" + "b" * 64, "")
    monkeypatch.setattr(smoke, "docker", docker)
    with pytest.raises(RuntimeError, match="does not match the OCI archive") as caught:
        smoke.smoke_platform("local/test:beta", "linux/amd64", "sha256:" + "a" * 64)
    assert "cleanup failed" in caught.value.__notes__[0]
