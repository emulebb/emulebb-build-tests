#!/usr/bin/env python3
"""Smoke an OCI release image's first-run s6, PUID/PGID, /config, /data, and WebUI."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments], text=True, capture_output=True, check=check, timeout=60
    )


def smoke_platform(image: str, platform: str) -> dict[str, object]:
    architecture = platform.removeprefix("linux/")
    container = f"emulebb-rust-image-smoke-{architecture}-{os.getpid()}"
    if docker("container", "inspect", container, check=False).returncode == 0:
        raise RuntimeError(f"refusing to replace existing container {container}")
    docker(
        "run", "--detach", "--name", container, "--platform", platform,
        "--network", "bridge",
        "--tmpfs", "/config", "--tmpfs", "/data",
        "--env", "PUID=1234", "--env", "PGID=1235", "--env", "TZ=UTC",
        image,
    )
    try:
        deadline = time.monotonic() + 90
        while True:
            running = docker("inspect", "--format", "{{.State.Running}}", container,
                             check=False).stdout.strip() == "true"
            if not running:
                logs = docker("logs", "--tail", "30", container, check=False)
                raise RuntimeError("image exited before serving REST/WebUI: "
                                   + logs.stdout[-3000:] + logs.stderr[-3000:])
            response = docker(
                "exec", container, "curl", "--fail", "--silent", "--max-time", "2",
                "http://127.0.0.1:4711/", check=False,
            )
            if response.returncode == 0 and "eMuleBB WebUI" in response.stdout:
                break
            if time.monotonic() >= deadline:
                logs = docker("logs", "--tail", "30", container, check=False)
                raise RuntimeError(
                    "image first-run daemon/WebUI did not start: " + logs.stdout[-3000:] + logs.stderr[-3000:]
                )
            time.sleep(1)
        uid = docker("exec", container, "id", "-u", "abc").stdout.strip()
        gid = docker("exec", container, "id", "-g", "abc").stdout.strip()
        owners = docker("exec", container, "stat", "-c", "%u:%g", "/config", "/data/ed2k").stdout.splitlines()
        docker("exec", container, "test", "-f", "/config/emulebb-rust/emulebb-rust-settings.toml")
        daemon = docker("exec", container, "pgrep", "-f", "/usr/lib/emulebb-rust/emulebb-rust")
        ports = docker("port", container).stdout.strip()
        actual_architecture = docker("exec", container, "dpkg", "--print-architecture").stdout.strip()
        if ((uid, gid) != ("1234", "1235") or owners != ["1234:1235", "1234:1235"]
                or not daemon.stdout.strip() or ports or actual_architecture != architecture):
            raise RuntimeError(f"image PUID/PGID or volume contract failed: uid={uid}, gid={gid}, owners={owners}")
        return {
            "platform": platform,
            "firstRunProfile": True, "webui": True, "uid": int(uid), "gid": int(gid),
            "configOwner": owners[0], "dataOwner": owners[1], "publishedPorts": 0,
        }
    finally:
        docker("stop", container, check=False)
        docker("rm", container, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if not args.archive.is_file():
        raise RuntimeError(f"OCI archive is missing: {args.archive}")

    loaded = docker("load", "--input", str(args.archive), check=False)
    if loaded.returncode:
        raise RuntimeError("Docker could not load the OCI candidate: "
                           + loaded.stderr[-2000:] + loaded.stdout[-2000:])
    platforms = [smoke_platform(args.image, platform) for platform in
                 ("linux/amd64", "linux/arm64")]
    print(json.dumps({
        "schema": "emulebb.rust.image-smoke/2", "status": "passed", "image": args.image,
        "platforms": platforms,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
