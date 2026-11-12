"""Verify image smokes execute the archive's bytes and always remove owned containers."""
import hashlib
import io
import json
import subprocess
import tarfile
from types import SimpleNamespace

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
    return {"manifestDigest": manifest_digest, "configDigest": config_digest}


def test_reads_exact_config_from_nested_buildkit_index(tmp_path):
    archive = tmp_path / "image.oci.tar"
    expected = write_oci(archive)
    assert smoke.oci_platform_identities(archive) == {"linux/amd64": expected}


@pytest.mark.parametrize("fault", ["changed", "duplicate"])
def test_rejects_changed_config_bytes_and_ambiguous_platforms(tmp_path, fault):
    archive = tmp_path / "image.oci.tar"
    write_oci(archive, changed_config=fault == "changed", duplicate=fault == "duplicate")
    with pytest.raises(RuntimeError, match="digest mismatch|repeats a runnable platform"):
        smoke.oci_platform_identities(archive)


def test_wrong_local_tag_cannot_pass_and_its_container_is_removed(monkeypatch):
    calls = []
    def docker(*arguments, **kwargs):
        calls.append(arguments)
        if arguments[:2] in (("container", "inspect"), ("network", "inspect")) and "--format" not in arguments:
            return subprocess.CompletedProcess(arguments, 1, "", "")
        if "{{.Internal}}" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "true", "")
        return subprocess.CompletedProcess(arguments, 0, json.dumps({"digest": "sha256:" + "b" * 64}), "")
    monkeypatch.setattr(smoke, "docker", docker)
    with pytest.raises(RuntimeError, match="does not match the OCI archive"):
        smoke.smoke_platform("local/test:beta", "linux/amd64", {"manifestDigest": "sha256:" + "a" * 64})
    launch = next(call for call in calls if call[0] == "run")
    assert launch[launch.index("--pull") + 1] == "never"
    assert launch[launch.index("--label") + 1].startswith("io.emulebb.ci.image-smoke-owner=")
    name = launch[launch.index("--name") + 1]
    assert ("rm", "--force", name) in calls
    assert calls[-1][0:2] == ("network", "rm")
    assert "--internal" in next(call for call in calls if call[:2] == ("network", "create"))
    assert launch[launch.index("--dns") + 1] == "127.0.0.1"
    assert "EMULEBB_RUST_P2P_INTERFACE=eth0" in launch


def test_cleanup_failure_does_not_hide_original_image_mismatch(monkeypatch):
    def docker(*arguments, **kwargs):
        if arguments[0] == "rm":
            raise subprocess.TimeoutExpired(arguments, 1)
        if arguments[:2] in (("container", "inspect"), ("network", "inspect")) and "--format" not in arguments:
            return subprocess.CompletedProcess(arguments, 1, "", "")
        if "{{.Internal}}" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "true", "")
        return subprocess.CompletedProcess(arguments, 0,
                                           json.dumps({"digest": "sha256:" + "b" * 64}), "")
    monkeypatch.setattr(smoke, "docker", docker)
    with pytest.raises(RuntimeError, match="does not match the OCI archive") as caught:
        smoke.smoke_platform("local/test:beta", "linux/amd64", {"manifestDigest": "sha256:" + "a" * 64})
    assert "cleanup failed" in caught.value.__notes__[0]


def test_external_network_cannot_be_used_for_first_run_smoke(monkeypatch):
    calls = []
    def docker(*arguments, **kwargs):
        calls.append(arguments)
        if arguments[:2] in (("container", "inspect"), ("network", "inspect")) and "--format" not in arguments:
            return subprocess.CompletedProcess(arguments, 1, "", "")
        return subprocess.CompletedProcess(arguments, 0, "false", "")
    monkeypatch.setattr(smoke, "docker", docker)
    with pytest.raises(RuntimeError, match="internal Docker network"):
        smoke.smoke_platform("local/test:beta", "linux/amd64", {"manifestDigest": "sha256:" + "a" * 64})
    assert not any(call[0] == "run" for call in calls)
    assert calls[-1][:2] == ("network", "rm")


@pytest.fixture
def image_runtime(monkeypatch):
    key = "synthetic-image-smoke-credential-123456"
    runtime = SimpleNamespace(
        calls=[], key=key, architecture="amd64", variant="ubuntu", os_architecture=None, owner="1234 1235", pid="42",
        settings=f'[rest]\napi_key = "{key}"\n', http_status="200", auth_exit=0,
        app={"name": "eMuleBB", "version": "0.1.0-beta.2", "apiVersion": "v1",
             "build": "release", "platform": "x64", "lifecycle": {"state": "running"}},
        body=None,
    )
    def docker(*args, **kwargs):
        runtime.calls.append((args, kwargs))
        status, stdout = 0, ""
        if args[:2] in (("container", "inspect"), ("network", "inspect")) and "--format" not in args:
            status = 1
        elif "{{.Internal}}" in args or "{{.State.Running}}" in args:
            stdout = "true"
        elif "{{json .ImageManifestDescriptor}}" in args:
            stdout = json.dumps({"digest": "sha256:" + "a" * 64})
        elif "{{.State.ExitCode}}" in args:
            stdout = "0"
        elif '{{index .Config.Labels "io.emulebb.image.variant"}}' in args:
            stdout = runtime.variant
        elif args[0] == "exec":
            if "cat" in args:
                stdout = runtime.settings
            elif "pgrep" in args:
                stdout = runtime.pid
            elif "ps" in args:
                stdout = runtime.owner
            elif "stat" in args:
                stdout = "1234:1235\n1234:1235\n"
            elif "id" in args:
                stdout = "1234" if "-u" in args else "1235"
            elif "dpkg" in args:
                stdout = runtime.os_architecture or runtime.architecture
            elif "apk" in args:
                stdout = runtime.os_architecture or {"amd64": "x86_64", "arm64": "aarch64"}[runtime.architecture]
            elif "curl" in args:
                if "--header" in args:
                    assert args[args.index("--header") + 1] == "@-" and "--interactive" in args
                    assert kwargs["input"] == f"X-API-Key: {runtime.key}\n"
                    status = runtime.auth_exit
                    body = runtime.body if runtime.body is not None else json.dumps({"data": runtime.app})
                    stdout = body + "\n" + runtime.http_status
                elif "--output" in args:
                    stdout = "401"
                else:
                    stdout = "eMuleBB WebUI"
            elif "test" not in args and "/usr/local/bin/emulebb-rust-healthcheck" not in args:
                pytest.fail(f"Unexpected exec command: {args}")
        elif args[0] not in {"network", "run", "port", "stop", "rm"}:
            pytest.fail(f"Unexpected Docker command: {args}")
        return subprocess.CompletedProcess(args, status, stdout, "")
    monkeypatch.setattr(smoke, "docker", docker)
    return runtime


def run_image_runtime(runtime):
    return smoke.smoke_platform("local/test:beta", "linux/" + runtime.architecture,
                                {"manifestDigest": "sha256:" + "a" * 64, "configDigest": "sha256:" + "b" * 64})


@pytest.mark.parametrize("architecture,app_cpu", [("amd64", "x64"), ("arm64", "arm64")])
@pytest.mark.parametrize("variant", ["ubuntu", "alpine"])
def test_image_proves_authenticated_release_and_real_daemon_identity(image_runtime, architecture, app_cpu, variant):
    image_runtime.architecture = architecture
    image_runtime.variant = variant
    image_runtime.app["platform"] = app_cpu
    result = run_image_runtime(image_runtime)
    assert (result["unauthenticatedStatus"], result["authenticatedStatus"]) == (401, 200)
    assert (result["daemonUid"], result["daemonGid"]) == (1234, 1235)
    assert (result["appBuild"], result["appPlatform"], result["appVersion"]) == ("release", app_cpu, "0.1.0-beta.2")
    assert result["imageVariant"] == variant
    assert any(("apk" if variant == "alpine" else "dpkg") in args for args, _ in image_runtime.calls)
    assert image_runtime.key not in json.dumps(result)
    assert all(image_runtime.key not in str(args) for args, _ in image_runtime.calls)
    assert image_runtime.calls[-1][0][:2] == ("network", "rm")


@pytest.mark.parametrize("variant,os_architecture", [("unknown", None), ("ubuntu", "arm64"), ("alpine", "aarch64")])
def test_image_rejects_unknown_variant_or_wrong_os_package_cpu(image_runtime, variant, os_architecture):
    image_runtime.variant, image_runtime.os_architecture = variant, os_architecture
    with pytest.raises(RuntimeError):
        run_image_runtime(image_runtime)
    assert image_runtime.calls[-1][0][:2] == ("network", "rm")


@pytest.mark.parametrize("fault", ["root-daemon", "multiple-pids", "http-201", "auth-rejected",
                                  "wrong-cpu", "debug", "stopping", "malformed-json", "missing-data"])
def test_invalid_live_identity_or_authenticated_response_cannot_pass(image_runtime, fault):
    if fault == "root-daemon":
        image_runtime.owner = "0 0"
    elif fault == "multiple-pids":
        image_runtime.pid = "42\n43"
    elif fault == "http-201":
        image_runtime.http_status = "201"
    elif fault == "auth-rejected":
        image_runtime.auth_exit = 22
    elif fault == "wrong-cpu":
        image_runtime.app["platform"] = "arm64"
    elif fault == "debug":
        image_runtime.app["build"] = "debug"
    elif fault == "stopping":
        image_runtime.app["lifecycle"]["state"] = "shuttingdown"
    else:
        image_runtime.body = "not JSON" if fault == "malformed-json" else "{}"
    with pytest.raises(RuntimeError) as caught:
        run_image_runtime(image_runtime)
    assert image_runtime.key not in str(caught.value)
    assert image_runtime.calls[-1][0][:2] == ("network", "rm")


@pytest.mark.parametrize("fault", ["missing", "short", "header-injection", "malformed"])
def test_generated_credential_errors_are_sanitized_and_cleanup_runs(image_runtime, fault):
    if fault == "missing":
        image_runtime.settings = "[rest]\n"
    elif fault == "short":
        image_runtime.settings = '[rest]\napi_key = "short"\n'
    elif fault == "header-injection":
        image_runtime.settings = '[rest]\napi_key = "' + image_runtime.key + '\\r\\nX-Other: injected"\n'
    else:
        image_runtime.settings = '[rest]\napi_key = "' + image_runtime.key
    with pytest.raises(RuntimeError, match="Cannot read a valid generated image REST credential") as caught:
        run_image_runtime(image_runtime)
    assert image_runtime.key not in str(caught.value)
    assert not any("--header" in args for args, _ in image_runtime.calls)
    assert image_runtime.calls[-1][0][:2] == ("network", "rm")


def test_docker_wrapper_delivers_credentials_only_over_stdin(monkeypatch):
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(smoke.subprocess, "run", run)
    smoke.docker("exec", "--interactive", "owned", "curl", "--header", "@-", input="X-API-Key: synthetic\n")
    command, options = calls[0]
    assert "synthetic" not in str(command) and options["input"] == "X-API-Key: synthetic\n"
