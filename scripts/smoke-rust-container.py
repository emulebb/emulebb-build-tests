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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if not args.archive.is_file():
        raise RuntimeError(f"OCI archive is missing: {args.archive}")

    docker("load", "--input", str(args.archive))
    container = f"emulebb-rust-image-smoke-{os.getpid()}"
    docker(
        "run", "--detach", "--rm", "--name", container, "--network", "bridge",
        "--tmpfs", "/config", "--tmpfs", "/data",
        "--env", "PUID=1234", "--env", "PGID=1235", "--env", "TZ=UTC",
        args.image,
    )
    try:
        deadline = time.monotonic() + 90
        while True:
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
        if (uid, gid) != ("1234", "1235") or owners != ["1234:1235", "1234:1235"] or not daemon.stdout.strip() or ports:
            raise RuntimeError(f"image PUID/PGID or volume contract failed: uid={uid}, gid={gid}, owners={owners}")
        print(json.dumps({
            "schema": "emulebb.rust.image-smoke/1", "status": "passed", "image": args.image,
            "firstRunProfile": True, "webui": True, "uid": int(uid), "gid": int(gid),
            "configOwner": owners[0], "dataOwner": owners[1], "publishedPorts": 0,
        }, sort_keys=True))
        return 0
    finally:
        docker("stop", container, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
