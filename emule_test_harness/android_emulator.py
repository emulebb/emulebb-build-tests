"""Owned, isolated Android emulator boot proof; no APK qualification claims."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import time
from uuid import uuid4

from .bounded_process_output import AsyncBinaryCapture


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
                output_root: Path, report_dir: Path, boot_timeout: float = 300) -> Path:
    """Boot one fresh guest in an isolated container and stop only owned resources."""
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.getuid() == 0
            or not Path("/.dockerenv").is_file() or {name for _, name in socket.if_nameindex()} != {"lo"}):
        raise RuntimeError("Android boot probes require non-root native x86_64 Docker with network isolation")
    if api < 28 or page_size not in {4096, 16384} or not 0 < boot_timeout <= 600:
        raise ValueError("Select a supported Android API/page size and bounded boot timeout")
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

    def command(*arguments: str, check: bool = True) -> str:
        result = subprocess.run([adb, "-P", "5037", *arguments], env=child, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10, check=False)
        if len(result.stdout) > 65536 or len(result.stderr) > 65536 or check and result.returncode:
            raise RuntimeError("Owned Android ADB command failed")
        return result.stdout.strip() if result.returncode == 0 else ""

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
            "machine": ("uname", "-m"), "pageSize": ("getconf", "PAGE_SIZE"),
        }.items():
            value["property"] = key
            properties[key] = command("-s", "emulator-5554", "shell", *arguments)
        value["phase"] = "guest-validation"
        value["guest"] = validate_guest(properties, api=api, page_size=page_size)
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
