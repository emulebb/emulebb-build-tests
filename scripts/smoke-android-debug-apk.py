#!/usr/bin/env python3
"""Verify one debug APK starts and initializes its native profile on an emulator."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emule_test_harness.android_apk_device import existing_adb_server_version
from emule_test_harness.android_apk_lifecycle import APPLICATION_ID, admit_debug_payload
from emule_test_harness.paths import get_workspace_output_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--server-port", type=int, default=5037)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--abi", choices=("arm64-v8a", "x86_64"), required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    output = get_workspace_output_root().resolve()
    if not (args.manifest.resolve().is_relative_to(output) and args.report.resolve().is_relative_to(output)):
        parser.error("Package and report must be within the inherited output root")
    if (not args.adb.is_absolute() or not args.adb.is_file() or not re.fullmatch(r"emulator-[0-9]+", args.serial)
            or not 1 <= args.server_port <= 65535 or args.report.exists()):
        parser.error("Select a local emulator, an explicit ADB tool and a new report path")
    package = admit_debug_payload(args.manifest.parent, args.manifest.name, source_sha=args.source_sha,
                                  manifest_sha256=args.manifest_sha256, expected_cert_sha256=args.certificate_sha256,
                                  abi=args.abi)
    server_version = existing_adb_server_version(args.server_port)
    version = subprocess.run([str(args.adb), "version"], check=True, capture_output=True, text=True, timeout=10)
    match = re.search(r"Android Debug Bridge version 1\.0\.(\d+)\b", version.stdout)
    if not match or int(match[1]) != server_version:
        raise RuntimeError("ADB tool differs from the existing emulator server")

    def adb(*command: str, check=True, timeout=15):
        if existing_adb_server_version(args.server_port) != server_version:
            raise RuntimeError("ADB server changed during debug smoke")
        return subprocess.run([str(args.adb), "-P", str(args.server_port), "-s", args.serial, *command],
                              check=check, timeout=timeout, capture_output=True, text=True)

    if (adb("shell", "getprop", "ro.kernel.qemu").stdout.strip() != "1"
            or adb("shell", "getprop", "sys.boot_completed").stdout.strip() != "1"
            or adb("shell", "getprop", "ro.product.cpu.abi").stdout.strip() != args.abi):
        raise RuntimeError("Select a booted emulator with the package ABI")
    installed = adb("shell", "pm", "list", "packages", APPLICATION_ID).stdout.splitlines()
    if f"package:{APPLICATION_ID}" in installed:
        raise RuntimeError("Debug smoke requires an emulator without an existing eMuleBB installation")
    adb("install", package["payloadPath"], timeout=120)
    try:
        adb("shell", "am", "start", "-W", "-n", f"{APPLICATION_ID}/.MainActivity")
        deadline = time.monotonic() + 45
        while True:
            settings = adb("shell", "run-as", APPLICATION_ID, "test", "-s",
                           "files/profile/emulebb-rust-settings.toml", check=False)
            if settings.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("The debug APK did not initialize its native settings profile")
            time.sleep(1)
    finally:
        adb("uninstall", APPLICATION_ID, timeout=60)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as report:
        json.dump({"status": "passed", "abi": args.abi, "sourceSha": args.source_sha,
                   "apkSha256": package["apk"]["sha256"], "manifestSha256": args.manifest_sha256,
                   "nativeProfileInitialized": True, "publishable": False}, report, indent=2)
        report.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
