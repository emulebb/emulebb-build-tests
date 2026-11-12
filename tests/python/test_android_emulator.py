"""Guest proof rejects mismatches and always tears down its owned resources."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import signal
import subprocess
import struct
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from emule_test_harness import android_emulator as subject


PROPERTIES = {"sdk": "37", "codename": "REL", "machine": "x86_64", "pageSize": "16384",
              "abis64": "x86_64,arm64-v8a", "qemu": "1"}


@pytest.mark.parametrize("page", [4096, 16384])
def test_kernel_auxv_reads_page_size_without_exposing_process_addresses(page):
    data = struct.pack("<QQQQQQ", 33, 0xABCDEF, 6, page, 0, 0)
    assert subject.page_size_from_auxv(data) == page


@pytest.mark.parametrize("data", [b"", b"x" * 17, b"x" * 65552,
    struct.pack("<QQ", 0, 0), struct.pack("<QQ", 6, 4096),
    struct.pack("<QQQQ", 6, 8192, 0, 0), struct.pack("<QQQQQQ", 6, 4096, 6, 4096, 0, 0),
    struct.pack("<QQQQQQ", 0, 0, 6, 4096, 0, 0), struct.pack("<IIII", 6, 4096, 0, 0),
], ids=["empty", "truncated", "oversized", "missing-page", "unterminated", "unsupported-page",
        "duplicate-page", "early-terminator", "elf32"])
def test_invalid_kernel_auxv_cannot_create_page_size_evidence(data):
    with pytest.raises(RuntimeError, match="auxiliary vector"):
        subject.page_size_from_auxv(data)


@pytest.mark.parametrize(("key", "bad"), [
    ("sdk", "36"), ("codename", "PREVIEW"), ("machine", "aarch64"),
    ("pageSize", "4096"), ("abis64", "arm64-v8a"), ("qemu", "0"),
])
def test_guest_mismatch_is_not_qualified(key, bad):
    with pytest.raises(RuntimeError, match="does not match"):
        subject.validate_guest({**PROPERTIES, key: bad}, api=37, page_size=16384)


def test_guest_facts_do_not_claim_arm_runtime():
    result = subject.validate_guest(PROPERTIES, api=37, page_size=16384)
    assert result["machine"] == "x86_64"
    assert result["supported64BitAbis"] == ["x86_64", "arm64-v8a"]
    assert "applicationQualification" not in result


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(subject.platform, "system", lambda: "Linux")
    monkeypatch.setattr(subject.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(subject.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(subject.socket, "if_nameindex", lambda: [(1, "lo")])
    original_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: True if p.as_posix() == "/.dockerenv" else original_is_file(p))
    listener = Mock()
    listener.__enter__ = Mock(return_value=listener)
    listener.__exit__ = Mock(return_value=False)
    listener.connect_ex.return_value = 111
    monkeypatch.setattr(subject.socket, "socket", lambda: listener)
    monkeypatch.setattr(subject.shutil, "disk_usage", lambda p: SimpleNamespace(free=20 * 1024**3))
    sdk = tmp_path / "sdk"
    image = sdk / "system-images/android-37.2/google_apis_ps16k/x86_64"
    image.mkdir(parents=True)
    (image / "system.img").touch()
    output = tmp_path / "output"
    output.mkdir()
    arguments = dict(sdk_root=sdk, image_dir=image, output_root=output,
                     report_dir=output / "guest", api=37, page_size=16384)
    return arguments, listener


@pytest.mark.parametrize("unsafe", ["root", "network", "adb", "existing", "outside", "image"])
def test_preflight_does_not_spawn_or_adopt_processes(isolated, monkeypatch, unsafe):
    arguments, listener = isolated
    spawn = Mock(side_effect=AssertionError("must not spawn"))
    monkeypatch.setattr(subject.subprocess, "run", spawn)
    if unsafe == "root":
        monkeypatch.setattr(subject.os, "getuid", lambda: 0)
    elif unsafe == "network":
        monkeypatch.setattr(subject.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    elif unsafe == "adb":
        listener.connect_ex.return_value = 0
    elif unsafe == "existing":
        arguments["report_dir"].mkdir()
    elif unsafe == "outside":
        arguments["report_dir"] = arguments["output_root"].parent / "outside"
    elif unsafe == "image":
        arguments["image_dir"] = arguments["output_root"]
    with pytest.raises(RuntimeError):
        subject.probe_guest(**arguments)
    spawn.assert_not_called()


def test_missing_kvm_never_falls_back(isolated, monkeypatch):
    arguments, _ = isolated
    calls = Mock(return_value=SimpleNamespace(returncode=1))
    monkeypatch.setattr(subject.subprocess, "run", calls)
    with pytest.raises(RuntimeError, match="usable KVM"):
        subject.probe_guest(**arguments)
    assert not arguments["report_dir"].exists()
    assert calls.call_args.args[0][-1] == "-accel-check"


@pytest.mark.parametrize("outcome", ["success", "guest-mismatch", "exit", "timeout", "capture", "adb-start",
                                    "cleanup", "late-capture", "transient-adb", "tls-success", "tls-failure"])
def test_lifecycle_retains_truthful_report_and_cleans_up(isolated, monkeypatch, outcome):
    arguments, _ = isolated
    if outcome.startswith("tls-"):
        arguments.update(tls_source_sha="1" * 40, tls_manifest_sha256="2" * 64)
        monkeypatch.setattr(subject, "_tls_payload", lambda *args, **kwargs: {"synthetic": True})
        proof = Mock(return_value={"status": "passed"})
        if outcome == "tls-failure": proof.side_effect = RuntimeError("TLS case failed")
        monkeypatch.setattr(subject, "_run_tls_payload", proof)
    commands = []
    process = Mock(pid=42, stdout=Mock())
    process.poll.return_value = 1 if outcome == "exit" else None
    capture = Mock()
    if outcome == "capture":
        capture.raise_if_failed.side_effect = RuntimeError("capture failed")
    if outcome == "late-capture":
        capture.raise_if_failed.side_effect = [None, RuntimeError("capture failed")]
    monkeypatch.setattr(subject, "AsyncBinaryCapture", Mock(return_value=capture))
    monkeypatch.setattr(subject.subprocess, "Popen", Mock(return_value=process))
    stopped = Mock()
    if outcome == "cleanup":
        stopped.side_effect = RuntimeError("cleanup failed")
    monkeypatch.setattr(subject, "_stop_group", stopped)
    monkeypatch.setattr(subject.time, "sleep", lambda seconds: None)
    clock = iter([0, 1 if outcome == "transient-adb" else 301])
    monkeypatch.setattr(subject.time, "monotonic", lambda: next(clock))
    by_property = {"ro.build.version.sdk": "37", "ro.build.version.codename": "REL",
                   "ro.product.cpu.abilist64": "x86_64", "ro.kernel.qemu": "1",
                   "-m": "x86_64"}

    def run(command, **kwargs):
        commands.append(command)
        last = command[-1]
        if last == "start-server" and outcome == "adb-start":
            raise subprocess.TimeoutExpired(command, 10)
        if last == "sys.boot_completed":
            if outcome == "transient-adb" and sum(c[-1] == last for c in commands) == 1:
                raise subprocess.TimeoutExpired(command, 10)
            text = "" if outcome == "timeout" else "1"
        else:
            text = by_property.get(last, "")
        if last == "/proc/self/auxv":
            assert kwargs["text"] is False
            text = struct.pack("<QQQQ", 6, 4096 if outcome == "guest-mismatch" else 16384, 0, 0)
        return SimpleNamespace(returncode=0, stdout=text, stderr="")

    monkeypatch.setattr(subject.subprocess, "run", run)
    passed = outcome in {"success", "transient-adb", "tls-success"}
    if passed:
        report = subject.probe_guest(**arguments)
        assert report == arguments["report_dir"] / "report.json"
    else:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            subject.probe_guest(**arguments)
    result = json.loads((arguments["report_dir"] / "report.json").read_text())
    assert result["status"] == ("passed" if passed else "failed")
    assert result["scope"] == "guest-boot"
    assert result["applicationQualification"] == "not-run"
    expected_phase = {"adb-start": "adb-start", "exit": "guest-boot", "timeout": "guest-boot",
                      "capture": "guest-boot", "guest-mismatch": "guest-validation",
                      "tls-failure": "tls-execution"}.get(outcome, "complete")
    assert result["phase"] == expected_phase
    if outcome == "guest-mismatch":
        assert result["observedGuest"]["pageSize"] == "4096"
    if outcome == "exit":
        assert result["emulatorExitCode"] == 1
    assert commands[-1][-1] == "kill-server"
    if outcome.startswith("tls-"):
        proof.assert_called_once()
        assert result.get("tls") == ({"status": "passed"} if passed else None)
    stopped.assert_called_once_with(None if outcome == "adb-start" else process)
    if outcome != "adb-start":
        capture.close.assert_called_once()
        for command in commands:
            if "shell" in command or "exec-out" in command:
                assert command[3:5] == ["-s", "emulator-5554"]


def test_stop_never_signals_an_unowned_process_group(monkeypatch):
    process = Mock(pid=42)
    process.poll.return_value = None
    monkeypatch.setattr(subject.os, "getpgid", lambda pid: 99, raising=False)
    kill = Mock()
    monkeypatch.setattr(subject.os, "killpg", kill, raising=False)
    with pytest.raises(RuntimeError, match="outside its owned"):
        subject._stop_group(process)
    kill.assert_not_called()


def test_stop_escalates_only_owned_group(monkeypatch):
    monkeypatch.setattr(subject.signal, "SIGKILL", 9, raising=False)
    process = Mock(pid=42)
    process.poll.return_value = None
    process.wait.side_effect = [subprocess.TimeoutExpired("emulator", 10), 0]
    monkeypatch.setattr(subject.os, "getpgid", lambda pid: pid, raising=False)
    kill = Mock()
    monkeypatch.setattr(subject.os, "killpg", kill, raising=False)
    subject._stop_group(process)
    assert kill.call_args_list[0].args == (42, signal.SIGTERM)
    assert kill.call_args_list[1].args == (42, signal.SIGKILL)


def tls_manifest(root):
    root.mkdir()
    files = {}
    for name in ("core-tests", "daemon-tests", "emulebb-rust"):
        data = ("synthetic " + name).encode()
        (root / name).write_bytes(data)
        files[name] = {"sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    value = {"schema": "emulebb.android.tls-payload/2", "status": "passed", "abi": "x86_64",
             "sourceDirty": False, "source": {"emulebbRust": {"commit": "1" * 40}}, "files": files,
             "buildIdentity": {"version": "0.1.0-beta.2", "channel": "development", "sourceRevision": "1" * 40, "platform": "x64", "build": "release"}}
    (root / "manifest.json").write_text(json.dumps(value))
    return value


@pytest.mark.parametrize("bad", [None, "manifest-hash", "file-hash", "source", "dirty", "abi", "extra", "size", "missing", "old-schema"])
def test_tls_payload_binds_regular_fixed_files_and_source(tmp_path, bad):
    root = tmp_path / "payload"
    value = tls_manifest(root)
    if bad == "source": value["source"]["emulebbRust"]["commit"] = "2" * 40
    if bad == "dirty": value["sourceDirty"] = True
    if bad == "abi": value["abi"] = "arm64-v8a"
    if bad == "extra": value["files"]["other-program"] = value["files"]["core-tests"]
    if bad == "size": value["files"]["core-tests"]["sizeBytes"] = 2**30 + 1
    if bad == "old-schema": value["schema"] = "emulebb.android.tls-payload/1"
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps(value))
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if bad == "manifest-hash": digest = "0" * 64
    if bad == "file-hash": (root / "core-tests").write_bytes(b"changed")
    if bad == "missing": (root / "daemon-tests").unlink()
    if bad is None:
        assert subject._tls_payload(root, source_sha="1" * 40, manifest_sha256=digest) == value
    else:
        with pytest.raises(RuntimeError):
            subject._tls_payload(root, source_sha="1" * 40, manifest_sha256=digest)


def libtest_output(case):
    return (f"running 1 test\ntest {case} ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 0.01s\n")


@pytest.mark.parametrize("bad", [None, "zero", "ignored", "failed", "extra", "wrong-name", "summary", "panic"])
def test_tls_result_requires_one_actual_named_test(bad):
    case = subject.TLS_CASES["core"][0]
    text = libtest_output(case)
    if bad == "zero": text = text.replace("running 1 test", "running 0 tests").replace("1 passed", "0 passed")
    if bad == "ignored": text = text.replace(" ... ok", " ... ignored").replace("0 ignored", "1 ignored")
    if bad == "failed": text = text.replace("0 failed", "1 failed")
    if bad == "extra": text += "test another_case ... ok\n"
    if bad == "wrong-name": text = text.replace(case, "other_case")
    if bad == "summary": text += text
    if bad == "panic": text += "panicked at synthetic failure\n"
    if bad is None:
        assert subject._tls_case_result(text, case) == {"name": case, "passed": 1, "failed": 0, "ignored": 0}
    else:
        with pytest.raises(RuntimeError, match="exactly one"):
            subject._tls_case_result(text, case)


@pytest.mark.parametrize("outcome", ["success", "guest-hash", "test-failure", "timeout"])
def test_tls_adb_uses_only_fixed_cases_and_always_removes_owned_guest_directory(tmp_path, monkeypatch, outcome):
    payload = tls_manifest(tmp_path / "payload")
    calls = []
    directory = None
    progress = {}
    startup = Mock(return_value={"status": "passed"})
    monkeypatch.setattr(subject, "_fresh_profile_startup", startup)

    def command(*arguments, **kwargs):
        nonlocal directory
        calls.append(arguments)
        if "mkdir" in arguments:
            directory = arguments[-1]
        if "sha256sum" in arguments:
            name = arguments[-1].split("/")[-1]
            digest = "0" * 64 if outcome == "guest-hash" else payload["files"][name]["sha256"]
            return digest + "  " + arguments[-1]
        if "--exact" in arguments:
            assert kwargs["timeout"] == 30
            if outcome == "timeout": raise subprocess.TimeoutExpired("owned-adb", 30)
            if outcome == "test-failure": return "running 0 tests\n"
            return libtest_output(arguments[arguments.index("--exact") + 1])
        return ""

    if outcome == "success":
        value = subject._run_tls_payload(command, payload, adb="owned-adb", child={}, report_dir=tmp_path, progress=progress)
        assert len(value["cases"]) == 6 and value["status"] == "passed"
        assert {item["name"] for item in value["cases"]} == {case for cases in subject.TLS_CASES.values() for case in cases}
        assert value["freshProfileRestReadiness"] == "passed" and value["startup"] == {"status": "passed"}
        startup.assert_called_once()
        assert set(progress["completedCases"]) == {case for cases in subject.TLS_CASES.values() for case in cases}
    else:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            subject._run_tls_payload(command, payload, adb="owned-adb", child={}, report_dir=tmp_path, progress=progress)
        startup.assert_not_called()
        assert progress["failureStage"] == ("payload-upload" if outcome == "guest-hash" else "tls-test")
    assert calls[-1] == ("-s", "emulator-5554", "shell", "rm", "-rf", directory)
    assert directory.startswith("/data/local/tmp/emulebb-tls-")
    assert all(call[:2] == ("-s", "emulator-5554") for call in calls)


BOOTSTRAP = '[rest]\nbind_addr = "127.0.0.1:20017"\napi_key = "SyntheticAndroidKeyMaterial1234567890"\n'


@pytest.mark.parametrize("bad", [None, "camel", "short", "space", "listener", "malformed", "extra", "oversize"])
def test_actual_bootstrap_contract_never_accepts_aliases_or_bad_keys(bad):
    text = BOOTSTRAP
    if bad == "camel": text = text.replace("bind_addr", "bindAddr")
    if bad == "short": text = text.replace("SyntheticAndroidKeyMaterial1234567890", "short")
    if bad == "space": text = text.replace("SyntheticAndroidKeyMaterial1234567890", " SyntheticAndroidKeyMaterial1234567890")
    if bad == "listener": text = text.replace("127.0.0.1", "0.0.0.0")
    if bad == "malformed": text += "invalid[[["
    if bad == "extra": text += 'legacy_key = "unsupported"\n'
    if bad == "oversize": text += "#" * 65537
    if bad is None:
        assert subject._bootstrap_api_key(text) == "SyntheticAndroidKeyMaterial1234567890"
    else:
        with pytest.raises(RuntimeError) as error:
            subject._bootstrap_api_key(text)
        assert "SyntheticAndroidKeyMaterial" not in str(error.value)


@pytest.mark.parametrize("bad", [None, "exe", "hash", "cwd", "argv", "stat", "pid"])
def test_process_identity_binds_pid_birth_executable_bytes_and_default_invocation(bad):
    path, cwd, sha = "/owned/exe/emulebb-rust", "/owned/caller", "1" * 64
    def command(*arguments, **kwargs):
        target = arguments[-1]
        if "readlink" in arguments:
            value = cwd if target.endswith("/cwd") else path
            return "/foreign" if bad == ("cwd" if target.endswith("/cwd") else "exe") else value
        if "sha256sum" in arguments:
            return ("2" * 64 if bad == "hash" else sha) + "  " + target
        if target.endswith("/cmdline"):
            assert kwargs["binary"] is True
            return path.encode() + (b"\0--profile\0other\0" if bad == "argv" else b"\0")
        return "bad stat" if bad == "stat" else "42 (emulebb-rust) S " + " ".join(["0"] * 18 + ["12345"])
    if bad is None:
        assert subject._daemon_identity(command, "42", path, sha, cwd) == ("42", "12345")
    else:
        with pytest.raises(RuntimeError):
            subject._daemon_identity(command, "not-a-pid" if bad == "pid" else "42", path, sha, cwd)


@pytest.mark.parametrize("outcome", ["success", "unauthorized-open", "auth-failure", "source", "version", "cwd-profile",
                                    "permissions", "short-key", "pid-reused", "timeout", "exit", "forward-cleanup"])
def test_production_first_launch_proof_requires_auth_identity_and_graceful_owned_shutdown(tmp_path, monkeypatch, outcome):
    payload = tls_manifest(tmp_path / "payload")
    calls = []
    progress = {}
    process, capture = Mock(), Mock()
    process.poll.return_value = None
    def wait(timeout):
        assert timeout == 30
        if outcome == "timeout": raise subprocess.TimeoutExpired("owned-adb", 30)
        process.poll.return_value = 1 if outcome == "exit" else 0
        return process.poll.return_value
    process.wait.side_effect = wait
    launcher = Mock(return_value=(process, capture))
    monkeypatch.setattr(subject, "_start_production_daemon", launcher)
    stopped = Mock()
    monkeypatch.setattr(subject, "_stop_group", stopped)
    identities = Mock(return_value=("42", "100"))
    if outcome == "pid-reused": identities.side_effect = [("42", "100"), ("42", "200"), ("42", "200")]
    monkeypatch.setattr(subject, "_daemon_identity", identities)
    expected = payload["buildIdentity"]
    app = {**expected, "name": "eMuleBB", "apiVersion": "v1", "lifecycle": {"state": "running"}}
    if outcome == "source": app["sourceRevision"] = "9" * 40
    if outcome == "version": app["version"] = "wrong-version"
    def request(port, api_key=None):
        assert port == 32123
        if api_key is None: return (200 if outcome == "unauthorized-open" else 401), {}
        assert identities.call_count == 1, "the owned PID birth must be bound before authenticated REST"
        assert api_key == "SyntheticAndroidKeyMaterial1234567890"
        return (401 if outcome == "auth-failure" else 200), {"data": app, "meta": {"apiVersion": "v1"}}
    monkeypatch.setattr(subject, "_rest_app", request)
    def command(*arguments, **kwargs):
        calls.append(arguments)
        if "--no-rebind" in arguments: return "32123"
        if "--remove" in arguments and outcome == "forward-cleanup": raise RuntimeError("forward cleanup failed")
        if "test" in arguments and arguments[-1].startswith("/owned/caller-cwd/") and outcome == "cwd-profile":
            raise RuntimeError("caller CWD contains a profile")
        if "stat" in arguments: return "644" if outcome == "permissions" else "600"
        if "head" in arguments:
            assert identities.call_count == 1, "the owned PID birth must precede bootstrap inspection"
            return BOOTSTRAP.replace("SyntheticAndroidKeyMaterial1234567890", "short") if outcome == "short-key" else BOOTSTRAP
        if "cat" in arguments: return "42"
        return ""
    if outcome == "success":
        result = subject._fresh_profile_startup(command, payload, "/owned", adb="private-adb", child={}, report_dir=tmp_path, progress=progress)
        assert result["status"] == "passed" and result["profilePlacement"] == "executable-directory"
        assert result["unauthenticatedStatus"] == 401 and result["authenticatedStatus"] == 200
        assert result["shutdown"] == {"signal": "SIGTERM", "identityVerified": True, "exitCode": 0, "graceful": True, "forwardRemoved": True}
        assert result["app"]["sourceRevision"] == expected["sourceRevision"]
        assert "SyntheticAndroidKeyMaterial" not in json.dumps(result)
        assert not stopped.called
    else:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            subject._fresh_profile_startup(command, payload, "/owned", adb="private-adb", child={}, report_dir=tmp_path, progress=progress)
        if outcome in {"source", "version", "pid-reused", "timeout"}:
            assert progress["failureStage"] == {"source": "app-identity", "version": "app-identity",
                                                "pid-reused": "shutdown-identity", "timeout": "shutdown-wait"}[outcome]
    assert calls[-1] == ("-s", "emulator-5554", "forward", "--remove", "tcp:32123")
    capture.close.assert_called_once()
    assert launcher.call_args.args[2:5] == ("/owned/startup-exe/emulebb-rust", "/owned/caller-cwd", "/owned")
    signals = [call for call in calls if "kill" in call]
    if outcome == "pid-reused":
        assert not signals and stopped.called
    if outcome in {"success", "exit", "forward-cleanup"}:
        assert signals == [("-s", "emulator-5554", "shell", "kill", "-TERM", "42")]


def test_fixed_daemon_launcher_has_no_profile_or_key_arguments_and_owns_bounded_private_log(tmp_path, monkeypatch):
    process, capture = Mock(pid=42, stdout=Mock()), Mock()
    spawn = Mock(return_value=process)
    sink = Mock(return_value=capture)
    monkeypatch.setattr(subject.subprocess, "Popen", spawn)
    monkeypatch.setattr(subject, "AsyncBinaryCapture", sink)
    subject._start_production_daemon("private-adb", {"PRESERVED": "value"}, "/owned/exe/emulebb-rust", "/owned/cwd", "/owned", tmp_path)
    arguments = spawn.call_args.args[0]
    assert arguments[:7] == ["private-adb", "-P", "5037", "-s", "emulator-5554", "shell", "sh"]
    assert "--profile" not in str(arguments) and "api_key" not in str(arguments)
    assert "exec env LD_LIBRARY_PATH=/owned /owned/exe/emulebb-rust" in arguments[-1]
    assert spawn.call_args.kwargs["start_new_session"] is True
    sink.assert_called_once_with(tmp_path / "daemon-startup.log", max_segment_bytes=65536, retained_segments=2)
