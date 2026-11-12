"""Owned, isolated Android emulator boot proof; no APK qualification claims."""
from __future__ import annotations

import json
import hashlib
import http.client
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import signal
import socket
import subprocess
import struct
import re
import shlex
import time
import tomllib
from uuid import uuid4

from .bounded_process_output import AsyncBinaryCapture


TLS_CASES = {
    "core": (
        "http_client::tests::packaged_android_roots_are_nonempty_and_build_without_platform_initialization",
        "http_client::tests::missing_or_malformed_roots_fail_without_platform_fallback",
        "http_client::tests::controlled_ca_accepts_valid_tls_but_rejects_wrong_hostname_and_expiry",
        "http_client::tests::packaged_android_roots_do_not_trust_private_fixture_ca",
        "ed2k_net_drivers::http_client_tests::url_import_builder_rejects_private_fixture_ca",
    ),
    "daemon": ("discovery_bootstrap::tests::discovery_https_uses_verified_client_and_rejects_private_ca",),
}


def _tls_payload(root: Path, *, source_sha: str, manifest_sha256: str) -> dict:
    """Admit only the fixed source-bound Android TLS library test payloads."""
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None or re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None:
        raise ValueError("Android TLS proof requires immutable source and manifest identities")
    manifest = root / "manifest.json"
    if (root.is_symlink() or not root.is_dir() or manifest.is_symlink() or not manifest.is_file()
            or manifest.stat().st_size > 65536):
        raise RuntimeError("Android TLS proof requires its regular bounded payload manifest")
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise RuntimeError("Android TLS payload manifest identity differs")
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get("schema") != "emulebb.android.tls-payload/2"
            or value.get("status") != "passed" or value.get("abi") != "x86_64"
            or value.get("sourceDirty") is not False
            or value.get("source", {}).get("emulebbRust", {}).get("commit") != source_sha
            or not isinstance(value.get("files"), dict)
            or not {"core-tests", "daemon-tests", "emulebb-rust"} <= set(value["files"])
            or set(value["files"]) - {"core-tests", "daemon-tests", "emulebb-rust", "libc++_shared.so"}
            or not isinstance(value.get("buildIdentity"), dict)
            or value["buildIdentity"].get("sourceRevision") != source_sha
            or value["buildIdentity"].get("platform") != "x64"
            or value["buildIdentity"].get("build") != "release"
            or not isinstance(value["buildIdentity"].get("version"), str)
            or not value["buildIdentity"]["version"]
            or value["buildIdentity"].get("channel") not in {"development", "nightly"}):
        raise RuntimeError("Android TLS payload has inconsistent source, ABI or fixed files")
    for name, identity in value["files"].items():
        path = root / name
        if (not isinstance(identity, dict) or type(identity.get("sizeBytes")) is not int
                or not 0 < identity["sizeBytes"] <= 1024**3
                or re.fullmatch(r"[0-9a-f]{64}", identity.get("sha256", "")) is None
                or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve())
                or path.stat().st_size != identity["sizeBytes"]):
            raise RuntimeError("Android TLS payload file is missing, redirected or unbounded")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != identity["sha256"]:
            raise RuntimeError("Android TLS payload file hash differs")
    return value


def _tls_case_result(text: str, case: str) -> dict:
    """Reject ignored, empty, extra or failed libtest runs, even with exit status zero."""
    summaries = re.findall(r"^test result: (.*)$", text, re.MULTILINE)
    results = re.findall(r"^test (\S+) \.\.\. (\S+)\s*$", text, re.MULTILINE)
    if (results != [(case, "ok")] or len(summaries) != 1
            or re.fullmatch(r"ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", summaries[0]) is None
            or "running 1 test\n" not in text or "panicked at" in text):
        raise RuntimeError("Android TLS proof did not execute exactly one successful required test")
    return {"name": case, "passed": 1, "failed": 0, "ignored": 0}


def _run_tls_payload(command, payload: dict, *, adb: str, child: dict, report_dir: Path, progress: dict) -> dict:
    """Run only the six owned TLS cases on the already-owned Android guest."""
    directory = "/data/local/tmp/emulebb-tls-" + uuid4().hex
    prefix = ("-s", "emulator-5554")
    results = []
    progress.update(stage="payload-upload", completedCases=[])
    try:
        command(*prefix, "shell", "mkdir", "-m", "700", directory)
        for name, identity in payload["files"].items():
            target = directory + "/" + name
            command(*prefix, "push", str(Path("/tls-payload") / name), target, timeout=120)
            digest = command(*prefix, "shell", "sha256sum", target).split()
            if digest != [identity["sha256"], target]:
                raise RuntimeError("Android guest TLS payload hash differs from its source-bound bytes")
            command(*prefix, "shell", "chmod", "500", target)
        for role, cases in TLS_CASES.items():
            for case in cases:
                progress.update(stage="tls-test", activeCase=case)
                text = command(*prefix, "shell", "env", "LD_LIBRARY_PATH=" + directory,
                               directory + "/" + role + "-tests", "--exact", case,
                               "--test-threads=1", "--color", "never", timeout=30)
                # Only synthetic test names/results enter the public receipt.
                results.append(_tls_case_result(text + "\n", case))
                progress["completedCases"].append(case)
        progress.pop("activeCase", None)
        startup = _fresh_profile_startup(command, payload, directory, adb=adb, child=child, report_dir=report_dir, progress=progress)
        return {"schema": "emulebb.android.tls-execution/2", "status": "passed",
                "source": payload["source"], "files": payload["files"], "cases": results,
                "freshProfileRestReadiness": "passed", "startup": startup, "apkQualification": "not-run"}
    except BaseException as error:
        progress.setdefault("failureStage", progress["stage"])
        progress.setdefault("failureMessage", str(error))
        progress.setdefault("errorType", type(error).__name__)
        raise
    finally:
        # Fixed generated guest directory only; the fresh emulator is also
        # terminated by the existing outer owner after any failure or timeout.
        command(*prefix, "shell", "rm", "-rf", directory)


def _bootstrap_api_key(text: str) -> str:
    """Validate the actual generated bootstrap without logging or returning it in proof."""
    if len(text.encode("utf-8")) > 65536:
        raise RuntimeError("Android generated bootstrap exceeds its bound")
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise RuntimeError("Android generated bootstrap is not valid TOML") from None
    rest = value.get("rest")
    if (set(value) != {"rest"} or not isinstance(rest, dict)
            or not {"bind_addr", "api_key"} <= set(rest)
            or set(rest) - {"bind_addr", "api_key", "web_root_dir"}
            or rest["bind_addr"] != "127.0.0.1:20017"):
        raise RuntimeError("Android generated bootstrap must use the current loopback snake_case contract")
    key = rest["api_key"]
    if not isinstance(key, str) or len(key) < 32 or not all(33 <= ord(char) <= 126 for char in key):
        raise RuntimeError("Android generated bootstrap must provide a valid private API key")
    return key


def _rest_app(port: int, api_key: str | None = None) -> tuple[int, dict]:
    """Use only the owned loopback ADB forward, without inheriting HTTP proxies."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/api/v1/app", headers={} if api_key is None else {"X-API-Key": api_key})
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            raise RuntimeError("Android REST app response exceeds its bound")
        return response.status, json.loads(body) if response.status == 200 else {}
    finally:
        connection.close()


def _app_identity(document: dict, expected: dict) -> dict:
    """Require the current REST envelope and the actual running production build."""
    if not isinstance(document, dict):
        raise RuntimeError("Android REST app must return the current object envelope")
    app = document.get("data")
    if (not isinstance(document.get("meta"), dict) or document["meta"].get("apiVersion") != "v1"
            or not isinstance(app, dict) or app.get("name") != "eMuleBB" or app.get("apiVersion") != "v1"
            or not isinstance(app.get("lifecycle"), dict) or app["lifecycle"].get("state") != "running"
            or any(app.get(key) != value for key, value in expected.items())):
        raise RuntimeError("Android authenticated REST does not identify the requested running production daemon")
    return {**expected, "name": "eMuleBB", "apiVersion": "v1", "lifecycleState": "running"}


def _daemon_identity(command, pid: str, executable: str, sha256: str, cwd: str) -> tuple[str, str]:
    """Bind a guest PID to its executable bytes, invocation and kernel start time."""
    if re.fullmatch(r"[1-9][0-9]*", pid) is None:
        raise RuntimeError("Android daemon PID is invalid")
    prefix = ("-s", "emulator-5554")
    proc = "/proc/" + pid
    if command(*prefix, "shell", "readlink", proc + "/exe") != executable:
        raise RuntimeError("Android daemon executable path differs; refusing to signal it")
    if command(*prefix, "shell", "readlink", proc + "/cwd") != cwd:
        raise RuntimeError("Android daemon working directory differs; refusing to signal it")
    if command(*prefix, "shell", "sha256sum", proc + "/exe").split() != [sha256, proc + "/exe"]:
        raise RuntimeError("Android daemon executable hash differs; refusing to signal it")
    if command(*prefix, "exec-out", "cat", proc + "/cmdline", binary=True) != executable.encode() + b"\0":
        raise RuntimeError("Android daemon invocation differs; refusing to signal it")
    stat = command(*prefix, "shell", "cat", proc + "/stat")
    leader, separator, fields = stat.rpartition(") ")
    values = fields.split()
    if (not separator or not leader.startswith(pid + " (") or len(values) < 20
            or re.fullmatch(r"[0-9]+", values[19]) is None):
        raise RuntimeError("Android daemon has no verifiable kernel process identity")
    return pid, values[19]


def _start_production_daemon(adb: str, child: dict, executable: str, cwd: str,
                             library_dir: str, report_dir: Path):
    """Own one foreground ADB exec; neither its key nor its private log is published."""
    pid_file = str(PurePosixPath(executable).parent / "owned-daemon.pid")
    script = ("cd " + shlex.quote(cwd) + " && printf '%s\\n' \"$$\" > " + shlex.quote(pid_file)
              + " && exec env LD_LIBRARY_PATH=" + shlex.quote(library_dir) + " " + shlex.quote(executable))
    process = subprocess.Popen([adb, "-P", "5037", "-s", "emulator-5554", "shell", "sh", "-c", shlex.quote(script)],
                               env=child, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    capture = AsyncBinaryCapture(report_dir / "daemon-startup.log", max_segment_bytes=65536, retained_segments=2)
    try:
        capture.start(process.stdout, stop_process=lambda: _stop_group(process))
    except BaseException:
        _stop_group(process)
        capture.close()
        raise
    return process, capture


def _fresh_profile_startup(command, payload: dict, directory: str, *, adb: str, child: dict, report_dir: Path, progress: dict) -> dict:
    """Prove an EXE-relative fresh profile, authenticated REST and owned graceful shutdown."""
    prefix = ("-s", "emulator-5554")
    executable_dir, cwd = directory + "/startup-exe", directory + "/caller-cwd"
    executable = executable_dir + "/emulebb-rust"
    settings = executable_dir + "/emulebb-rust-settings.toml"
    sha256 = payload["files"]["emulebb-rust"]["sha256"]
    process = capture = None
    port = pid = identity = None
    result = None
    try:
        progress["stage"] = "daemon-prepare"
        command(*prefix, "shell", "mkdir", "-m", "700", executable_dir, cwd)
        command(*prefix, "shell", "mv", directory + "/emulebb-rust", executable)
        progress["stage"] = "daemon-launch"
        process, capture = _start_production_daemon(adb, child, executable, cwd, directory, report_dir)
        progress["stage"] = "rest-forward"
        forward = command(*prefix, "forward", "--no-rebind", "tcp:0", "tcp:20017")
        if re.fullmatch(r"[1-9][0-9]*", forward) is None or int(forward) > 65535:
            raise RuntimeError("Android REST forward did not allocate a private loopback port")
        port = int(forward)
        progress["stage"] = "rest-wait-unauthenticated"
        deadline = time.monotonic() + 90
        while True:
            capture.raise_if_failed()
            exit_code = process.poll()
            if exit_code is not None:
                progress["daemonExitCode"] = exit_code
                raise RuntimeError("Android production daemon exited before fresh-profile REST readiness")
            try:
                status, _document = _rest_app(port)
            except (OSError, TimeoutError, http.client.HTTPException):
                status = None
            if status == 401:
                break
            if status is not None:
                raise RuntimeError("Android unauthenticated REST must reject access with HTTP 401")
            if time.monotonic() >= deadline:
                raise RuntimeError("Android fresh-profile REST did not become ready within its bound")
            time.sleep(0.25)
        # Bind the process before reading its bootstrap or authenticating, then
        # compare again before signalling: two adjacent post-proof reads would
        # not establish that the same owned process served the whole proof.
        progress["stage"] = "daemon-admission"
        pid = command(*prefix, "shell", "cat", executable_dir + "/owned-daemon.pid")
        identity = _daemon_identity(command, pid, executable, sha256, cwd)
        progress["stage"] = "bootstrap-check"
        command(*prefix, "shell", "test", "!", "-e", cwd + "/emulebb-rust-settings.toml")
        command(*prefix, "shell", "test", "!", "-L", settings)
        if command(*prefix, "shell", "stat", "-c", "%a", settings) != "600":
            raise RuntimeError("Android generated bootstrap is not owner-only")
        key = _bootstrap_api_key(command(*prefix, "shell", "head", "-c", "65537", settings))
        progress["stage"] = "rest-authenticated"
        status, document = _rest_app(port, key)
        if status != 200:
            raise RuntimeError("Android authenticated REST must accept the generated API key")
        progress["stage"] = "app-identity"
        app = _app_identity(document, payload["buildIdentity"])
        progress["stage"] = "shutdown-identity"
        if _daemon_identity(command, pid, executable, sha256, cwd) != identity:
            raise RuntimeError("Android daemon PID was reused before graceful shutdown")
        progress["stage"] = "shutdown-term"
        command(*prefix, "shell", "kill", "-TERM", pid)
        progress["stage"] = "shutdown-wait"
        if process.wait(timeout=30) != 0:
            raise RuntimeError("Android production daemon did not exit gracefully after SIGTERM")
        result = {"schema": "emulebb.android.first-launch/1", "status": "passed", "app": app,
                  "profilePlacement": "executable-directory", "callerCwdDifferent": True,
                  "bootstrapSnakeCase": True, "bootstrapOwnerOnly": True,
                  "unauthenticatedStatus": 401, "authenticatedStatus": 200,
                  "shutdown": {"signal": "SIGTERM", "identityVerified": True, "exitCode": 0, "graceful": True},
                  "webuiReadiness": "not-run", "apkQualification": "not-run", "physicalDeviceQualification": "not-run"}
    except BaseException as error:
        progress.setdefault("failureStage", progress["stage"])
        progress.setdefault("failureMessage", str(error))
        progress.setdefault("errorType", type(error).__name__)
        raise
    finally:
        try:
            if process is not None and process.poll() is None:
                # On a failed proof, signal only an identity already admitted by
                # this owner. Otherwise the outer owned emulator teardown is the
                # fail-safe; never guess or kill a possibly reused guest PID.
                try:
                    if identity is not None and _daemon_identity(command, pid, executable, sha256, cwd) == identity:
                        command(*prefix, "shell", "kill", "-KILL", pid)
                finally:
                    _stop_group(process)
        finally:
            try:
                if capture is not None:
                    capture.close()
                    capture.raise_if_failed()
            finally:
                if port is not None:
                    progress["stage"] = "cleanup-forward"
                    command(*prefix, "forward", "--remove", "tcp:" + str(port))
    result["shutdown"]["forwardRemoved"] = True
    return result


def page_size_from_auxv(data: bytes) -> int:
    """Read AT_PAGESZ from the selected guest's little-endian ELF64 auxiliary vector."""
    if not isinstance(data, bytes) or not 16 <= len(data) <= 65536 or len(data) % 16:
        raise RuntimeError("Android guest auxiliary vector must be bounded ELF64 data")
    entries = list(struct.iter_unpack("<QQ", data))
    pages = [value for kind, value in entries if kind == 6]  # ELF AT_PAGESZ
    if (entries[-1] != (0, 0) or any(kind == 0 for kind, _ in entries[:-1])
            or len(pages) != 1 or pages[0] not in {4096, 16384}):
        raise RuntimeError("Android guest auxiliary vector has no unambiguous supported page size")
    return pages[0]


def validate_guest(properties: dict[str, str], *, api: int, page_size: int) -> dict:
    """Require a stable x86_64 emulator and the requested actual guest page size."""
    if (properties.get("sdk") != str(api) or properties.get("codename") != "REL"
            or properties.get("machine") != "x86_64" or properties.get("pageSize") != str(page_size)
            or "x86_64" not in properties.get("abis64", "").split(",")
            or properties.get("qemu") != "1"):
        raise RuntimeError("Booted Android guest SDK/ABI/page size/stability does not match the selected image")
    return {"sdk": api, "codename": "REL", "machine": "x86_64", "pageSize": page_size,
            "supported64BitAbis": properties["abis64"].split(","), "emulator": True}


def _stop_group(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        group = os.getpgid(process.pid)
    except ProcessLookupError:
        process.wait(timeout=5)
        return
    if group != process.pid:
        raise RuntimeError("Refusing to stop an emulator process outside its owned process group")
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=5)
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def _ini(path: Path, values: dict[str, str]) -> None:
    # AVD files have no sections. Fixed keys and validated owned paths avoid
    # invoking a launcher that could select or download a different image.
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("Android AVD values cannot contain line separators")
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")


def probe_guest(*, sdk_root: Path, image_dir: Path, api: int, page_size: int,
                output_root: Path, report_dir: Path, boot_timeout: float = 300,
                tls_source_sha: str | None = None, tls_manifest_sha256: str | None = None) -> Path:
    """Boot one fresh guest in an isolated container and stop only owned resources."""
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() == 0
            or not Path("/.dockerenv").is_file() or {name for _, name in socket.if_nameindex()} != {"lo"}):
        raise RuntimeError("Android boot probes require non-root native x86_64 Docker with network isolation")
    if api < 28 or page_size not in {4096, 16384} or not 0 < boot_timeout <= 600:
        raise ValueError("Select a supported Android API/page size and bounded boot timeout")
    if (tls_source_sha is None) != (tls_manifest_sha256 is None):
        raise ValueError("Android TLS proof requires both source and payload manifest identities")
    payload = None if tls_source_sha is None else _tls_payload(
        Path("/tls-payload"), source_sha=tls_source_sha, manifest_sha256=tls_manifest_sha256)
    output_root, sdk_root, image_dir = output_root.resolve(), sdk_root.resolve(), image_dir.resolve()
    if (report_dir.is_symlink() or report_dir.exists() or not report_dir.resolve().is_relative_to(output_root)
            or report_dir.resolve() == output_root or not image_dir.is_relative_to(sdk_root / "system-images")
            or not (image_dir / "system.img").is_file() or not output_root.is_dir()):
        raise RuntimeError("Android boot requires a fresh output directory and installed SDK system image")
    # WHY: the supported container has only loopback and no published ports.
    # Refuse an existing ADB listener rather than adopting or stopping it.
    with socket.socket() as listener:
        if listener.connect_ex(("127.0.0.1", 5037)) == 0:
            raise RuntimeError("Android boot probe requires an unused private ADB server port")
    emulator, adb = str(sdk_root / "emulator/emulator"), str(sdk_root / "platform-tools/adb")
    acceleration = subprocess.run([emulator, "-no-window", "-accel-check"], stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=30, check=False)
    if acceleration.returncode != 0:
        raise RuntimeError("Android guest boot requires usable KVM; software emulation is not a qualification fallback")
    report_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    home, avds, temporary = (report_dir / name for name in ("home", "avd", "tmp"))
    for directory in (home, avds, temporary):
        directory.mkdir(mode=0o700)
    name = "emulebb-" + uuid4().hex
    avd = avds / (name + ".avd")
    avd.mkdir(mode=0o700)
    _ini(avds / (name + ".ini"), {"avd.ini.encoding": "UTF-8", "path": str(avd), "target": "android-" + str(api)})
    _ini(avd / "config.ini", {
        "AvdId": name, "avd.ini.encoding": "UTF-8", "abi.type": "x86_64", "hw.cpu.arch": "x86_64",
        "hw.cpu.ncore": "2", "hw.ramSize": "2048", "hw.lcd.width": "1080", "hw.lcd.height": "1920",
        "hw.lcd.density": "420", "hw.keyboard": "yes", "hw.gpu.enabled": "yes", "hw.gpu.mode": "swiftshader",
        "image.sysdir.1": str(image_dir) + "/", "disk.dataPartition.size": "12G", "fastboot.forceColdBoot": "yes",
    })
    if shutil.disk_usage(report_dir).free < 5 * 1024**3:
        raise RuntimeError("Android emulator requires at least 5 GiB free before boot")
    child = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "TMPDIR": str(temporary),
             "ANDROID_AVD_HOME": str(avds), "ANDROID_EMULATOR_HOME": str(home / ".android"),
             "ANDROID_SDK_ROOT": str(sdk_root), "ANDROID_HOME": str(sdk_root), "LC_ALL": "C.UTF-8"}
    process = None
    capture = None
    adb_started = False
    value = {"schema": "emulebb.android.emulator-boot/1", "status": "failed", "scope": "guest-boot",
             "applicationQualification": "not-run", "kvm": True, "guest": None, "phase": "adb-start"}
    report = report_dir / "report.json"

    def close_capture() -> None:
        if capture is not None:
            capture.close()
            capture.raise_if_failed()

    def command(*arguments: str, check: bool = True, binary: bool = False, timeout: int = 10) -> str | bytes:
        result = subprocess.run([adb, "-P", "5037", *arguments], env=child, stdin=subprocess.DEVNULL,
                                capture_output=True, text=not binary, timeout=timeout, check=False)
        if len(result.stdout) > 65536 or len(result.stderr) > 65536 or check and result.returncode:
            raise RuntimeError("Owned Android ADB command failed")
        if result.returncode:
            return b"" if binary else ""
        return result.stdout if binary else result.stdout.strip()

    try:
        adb_started = True
        command("start-server")
        value["phase"] = "emulator-start"
        process = subprocess.Popen([emulator, "-avd", name, "-port", "5554", "-no-window", "-no-audio",
                                    "-no-snapshot", "-no-boot-anim", "-gpu", "swiftshader", "-accel", "on"],
                                   env=child, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        capture = AsyncBinaryCapture(report_dir / "emulator.log", max_segment_bytes=1024**2, retained_segments=4)
        capture.start(process.stdout, stop_process=lambda: _stop_group(process))
        value["phase"] = "guest-boot"
        deadline = time.monotonic() + boot_timeout
        while True:
            capture.raise_if_failed()
            returncode = process.poll()
            if returncode is not None:
                value["emulatorExitCode"] = returncode
                raise RuntimeError("Owned Android emulator exited before boot; inspect the private emulator log")
            try:
                booted = command("-s", "emulator-5554", "shell", "getprop", "sys.boot_completed", check=False)
            except subprocess.TimeoutExpired:
                # WHY: ADB can briefly block while Android starts its transport.
                # Retry within the overall boot bound; later property reads fail normally.
                booted = ""
            if booted == "1":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned Android emulator did not complete boot within its bound")
            time.sleep(1)
        properties = {}
        value.update(phase="guest-properties", observedGuest=properties)
        for key, arguments in {
            "sdk": ("getprop", "ro.build.version.sdk"), "codename": ("getprop", "ro.build.version.codename"),
            "abis64": ("getprop", "ro.product.cpu.abilist64"), "qemu": ("getprop", "ro.kernel.qemu"),
            "machine": ("uname", "-m"),
        }.items():
            value["property"] = key
            properties[key] = command("-s", "emulator-5554", "shell", *arguments)
        value["property"] = "pageSize"
        # WHY: Android 9 lacks a usable getconf PAGE_SIZE command. The kernel
        # supplies AT_PAGESZ on both selected guests; exec-out preserves its
        # binary bytes. Never publish the auxiliary vector's process addresses.
        properties["pageSize"] = str(page_size_from_auxv(command(
            "-s", "emulator-5554", "exec-out", "cat", "/proc/self/auxv", binary=True)))
        value["phase"] = "guest-validation"
        value["guest"] = validate_guest(properties, api=api, page_size=page_size)
        if payload is not None:
            value["phase"] = "tls-execution"
            value["tlsProgress"] = {}
            value["tls"] = _run_tls_payload(command, payload, adb=adb, child=child, report_dir=report_dir, progress=value["tlsProgress"])
        value["status"] = "passed"
        value["phase"] = "complete"
    except BaseException as error:
        value["error"] = str(error)
        raise
    finally:
        cleanup_errors = []
        for action in (lambda: _stop_group(process), lambda: command("kill-server") if adb_started else None,
                       close_capture):
            try:
                action()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if cleanup_errors:
            value.update(status="failed", cleanupErrors=cleanup_errors)
        report.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if cleanup_errors:
            raise RuntimeError("Owned Android emulator cleanup failed")
    return report
