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
    for name in ("core-tests", "daemon-tests"):
        data = ("synthetic " + name).encode()
        (root / name).write_bytes(data)
        files[name] = {"sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    value = {"schema": "emulebb.android.tls-payload/1", "status": "passed", "abi": "x86_64",
             "sourceDirty": False, "source": {"emulebbRust": {"commit": "1" * 40}}, "files": files}
    (root / "manifest.json").write_text(json.dumps(value))
    return value


@pytest.mark.parametrize("bad", [None, "manifest-hash", "file-hash", "source", "dirty", "abi", "extra", "size", "missing"])
def test_tls_payload_binds_regular_fixed_files_and_source(tmp_path, bad):
    root = tmp_path / "payload"
    value = tls_manifest(root)
    if bad == "source": value["source"]["emulebbRust"]["commit"] = "2" * 40
    if bad == "dirty": value["sourceDirty"] = True
    if bad == "abi": value["abi"] = "arm64-v8a"
    if bad == "extra": value["files"]["other-program"] = value["files"]["core-tests"]
    if bad == "size": value["files"]["core-tests"]["sizeBytes"] = 2**30 + 1
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
def test_tls_adb_uses_only_fixed_cases_and_always_removes_owned_guest_directory(tmp_path, outcome):
    payload = tls_manifest(tmp_path / "payload")
    calls = []
    directory = None

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
        value = subject._run_tls_payload(command, payload)
        assert len(value["cases"]) == 6 and value["status"] == "passed"
        assert {item["name"] for item in value["cases"]} == {case for cases in subject.TLS_CASES.values() for case in cases}
        assert value["freshProfileRestReadiness"] == "not-run"
    else:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            subject._run_tls_payload(command, payload)
    assert calls[-1] == ("-s", "emulator-5554", "shell", "rm", "-rf", directory)
    assert directory.startswith("/data/local/tmp/emulebb-tls-")
    assert all(call[:2] == ("-s", "emulator-5554") for call in calls)
