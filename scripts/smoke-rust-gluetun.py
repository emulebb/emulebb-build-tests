#!/usr/bin/env python3
"""Prove an isolated Rust image uses Gluetun and emits no off-tunnel packets.

Run from Linux/WSL with Docker. The compose project is unique and ephemeral; the
existing P2P project, its containers, networks, and volumes are never addressed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path


def command(*argv: str, timeout: int = 60, check: bool = True,
            env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, timeout=timeout,
                          check=check, env=env)


def docker(*argv: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return command("docker", *argv, **kwargs)


def request_json(url: str, key: str) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"X-API-Key": key})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def project_names() -> set[str]:
    result = docker("compose", "ls", "--all", "--format", "json")
    return {row["Name"] for row in json.loads(result.stdout)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image", default="ghcr.io/emulebb/emulebb-rust:0.1.0-beta.1")
    parser.add_argument("--capture-image", default="nicolaka/netshoot:v0.13")
    args = parser.parse_args()
    if not args.archive.is_file() or not args.compose.is_file():
        raise RuntimeError("the OCI archive and Compose file must exist")
    for name in ("custom.conf", "ca.pem", "StaticKey.pem", "openvpn_user", "openvpn_password"):
        if not (args.private_root / name).is_file():
            raise RuntimeError(f"VPN private root lacks {name}")
    if args.report.exists():
        raise RuntimeError("refusing to overwrite an existing proof report")

    project = f"emulebb-rust-beta-proof-{os.getpid()}"
    if not project.startswith("emulebb-rust-beta-proof-") or project in project_names():
        raise RuntimeError("unsafe or existing test Compose project")
    before = project_names()
    env = {**os.environ, "EMULEBB_TEST_VPN_PRIVATE_ROOT": str(args.private_root.resolve())}
    compose = ("docker", "compose", "--project-name", project, "--file", str(args.compose))
    report: dict[str, object] = {
        "schema": "emulebb.rust.gluetun-proof/1", "status": "failed",
        "project": project, "image": args.image, "captureImage": args.capture_image,
    }
    started = False
    try:
        command(*compose, "config", "--quiet", env=env)
        docker("load", "--input", str(args.archive), timeout=300)
        docker("image", "inspect", args.image)
        if docker("image", "inspect", args.capture_image, check=False).returncode:
            docker("pull", args.capture_image, timeout=300)
        report["captureImageId"] = docker("image", "inspect", args.capture_image,
                                           "--format", "{{.Id}}").stdout.strip()
        started = True
        command(*compose, "up", "--detach", "--no-build", "--pull", "never",
                env=env, timeout=300)
        gluetun = command(*compose, "ps", "--quiet", "gluetun", env=env).stdout.strip()
        rust = command(*compose, "ps", "--quiet", "emulebb-rust", env=env).stdout.strip()
        if not gluetun or not rust:
            raise RuntimeError("isolated Gluetun/Rust containers were not created")

        deadline = time.monotonic() + 120
        while True:
            page = docker("exec", rust, "curl", "--fail", "--silent", "--max-time", "3",
                          "http://127.0.0.1:4711/", check=False)
            if page.returncode == 0 and "eMuleBB WebUI" in page.stdout:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Rust WebUI did not start behind Gluetun")
            time.sleep(2)
        health = docker("inspect", "--format", "{{.State.Health.Status}}", gluetun).stdout.strip()
        tun = docker("exec", gluetun, "ip", "-4", "-o", "addr", "show", "dev", "tun0")
        processes = docker("top", rust).stdout
        if health != "healthy" or not tun.stdout.strip():
            raise RuntimeError("Gluetun is not healthy with an IPv4 tun0")
        if "--p2p-bind-interface tun0" not in processes:
            raise RuntimeError("Rust daemon was not pinned to tun0")
        settings = docker("exec", rust, "cat",
                          "/config/emulebb-rust/emulebb-rust-settings.toml").stdout
        api_key = tomllib.loads(settings)["rest"]["apiKey"]
        status = request_json("http://127.0.0.1:14711/api/v1/status", api_key)
        report["tunnelHealthy"] = True
        report["p2pInterfacePinned"] = True
        report["webuiAndRest"] = True
        report["preFailureStatus"] = status.get("data", status)

        # The capture joins Rust's network namespace, so it observes the exact
        # eth0 that could leak if Gluetun's kill switch or Rust's bind fails.
        # Gluetun is manually stopped, never the operator's existing P2P stack.
        command(*compose, "stop", "--timeout", "10", "gluetun", env=env, timeout=45)
        still_running = docker("inspect", "--format", "{{.State.Running}}", rust,
                               check=False).stdout.strip() == "true"
        report["rustRunningAfterTunnelDown"] = still_running
        if still_running:
            capture = docker(
                "run", "--rm", "--network", f"container:{rust}",
                "--cap-add", "NET_RAW", args.capture_image,
                "timeout", "45", "tcpdump", "-n", "-q", "-i", "eth0",
                "-c", "1", "ip and (tcp or udp)",
                timeout=65, check=False,
            )
            if capture.returncode not in (0, 124):
                raise RuntimeError(f"packet capture failed: {capture.stderr[-500:]}")
            report["offTunnelPacketCount"] = 1 if capture.returncode == 0 else 0
        else:
            report["offTunnelPacketCount"] = 0
        if report["offTunnelPacketCount"] != 0:
            raise RuntimeError("off-tunnel IPv4 packet observed after tunnel shutdown")
        report["status"] = "passed"
        return 0
    except Exception as error:
        report["error"] = str(error)
        if started:
            logs = command(*compose, "logs", "--tail", "40", env=env, check=False)
            report["containerLogTail"] = (logs.stdout + logs.stderr)[-4000:]
        return 1
    finally:
        if started:
            # Only the just-created, uniquely named test project and volumes.
            command(*compose, "down", "--volumes", env=env, timeout=90, check=False)
        report["preExistingProjectsPreserved"] = before <= project_names()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print(json.dumps({key: value for key, value in report.items()
                          if key not in ("preFailureStatus", "containerLogTail")}, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
