#!/usr/bin/env python3
"""Prove an isolated Rust image uses Gluetun and emits no off-tunnel packets.

Run from Linux/WSL with Docker. The compose project is unique and ephemeral; the
existing P2P project, its containers, networks, and volumes are never addressed.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
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


def request_json(url: str, key: str, *, method: str = "GET") -> dict[str, object]:
    headers = {"X-API-Key": key}
    body = None
    if method == "POST":
        headers["Content-Type"] = "application/json"
        body = b"{}"
    request = urllib.request.Request(url, headers=headers, data=body, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def project_states() -> dict[str, str]:
    result = docker("compose", "ls", "--all", "--format", "json")
    return {row["Name"]: row["Status"] for row in json.loads(result.stdout)}


def captured_packet_count(result: subprocess.CompletedProcess[str]) -> int:
    if result.returncode not in (0, 124):
        raise RuntimeError("host packet capture failed: " + result.stderr[-500:])
    packet_lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not packet_lines and "0 packets captured" not in result.stderr:
        raise RuntimeError("host packet sensor produced no capture summary: "
                           + result.stderr[-500:])
    return len(packet_lines)


def public_network_ready(payload: dict[str, object]) -> bool:
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        return False
    stats = data.get("stats", {})
    kad = data.get("kad", {})
    if not isinstance(stats, dict) or not isinstance(kad, dict):
        return False
    return bool(stats.get("ed2kConnected")) and int(kad.get("contactCount") or 0) > 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def url_is_reachable(url: str, key: str) -> bool:
    request = urllib.request.Request(url, headers={"X-API-Key": key})
    try:
        with urllib.request.urlopen(request, timeout=3):
            return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, TimeoutError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--compose-override", type=Path)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image", default="ghcr.io/emulebb/emulebb-rust:0.1.0-beta.1")
    parser.add_argument("--capture-image", default="nicolaka/netshoot:v0.13")
    parser.add_argument("--expected-executable-sha256")
    parser.add_argument("--expected-gluetun-image")
    args = parser.parse_args()
    if not args.archive.is_file() or not args.compose.is_file():
        raise RuntimeError("the OCI archive and Compose file must exist")
    if args.compose_override and not args.compose_override.is_file():
        raise RuntimeError("the Compose override file must exist")
    for name in ("custom.conf", "ca.pem", "StaticKey.pem", "openvpn_user", "openvpn_password"):
        if not (args.private_root / name).is_file():
            raise RuntimeError(f"VPN private root lacks {name}")
    pcap = args.report.with_suffix(".off-tunnel.pcap")
    if args.report.exists() or pcap.exists():
        raise RuntimeError("refusing to overwrite an existing proof report or packet capture")
    expected_executable_sha256 = (args.expected_executable_sha256 or "").lower()
    if expected_executable_sha256 and not re.fullmatch(r"[0-9a-f]{64}", expected_executable_sha256):
        raise RuntimeError("--expected-executable-sha256 must be a lowercase SHA-256 digest")
    args.report.parent.mkdir(parents=True, exist_ok=True)

    project = f"emulebb-rust-beta-proof-{os.getpid()}"
    if not project.startswith("emulebb-rust-beta-proof-") or project in project_states():
        raise RuntimeError("unsafe or existing test Compose project")
    before = project_states()
    env = {**os.environ, "EMULEBB_TEST_VPN_PRIVATE_ROOT": str(args.private_root.resolve())}
    compose_args = ["docker", "compose", "--project-name", project, "--file", str(args.compose)]
    if args.compose_override:
        compose_args.extend(("--file", str(args.compose_override)))
    compose = tuple(compose_args)
    report: dict[str, object] = {
        "schema": "emulebb.rust.gluetun-proof/2", "status": "failed",
        "project": project, "image": args.image, "captureImage": args.capture_image,
        "archive": str(args.archive.resolve()),
        "archiveSha256": sha256_file(args.archive),
        "compose": str(args.compose.resolve()),
        "composeSha256": sha256_file(args.compose),
    }
    if args.compose_override:
        report["composeOverride"] = str(args.compose_override.resolve())
        report["composeOverrideSha256"] = sha256_file(args.compose_override)
    started = False
    evidence_checks_passed = False
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
        gluetun_image = docker("inspect", "--format", "{{.Config.Image}}", gluetun).stdout.strip()
        report["gluetunImage"] = gluetun_image
        report["gluetunImageId"] = docker(
            "inspect", "--format", "{{.Image}}", gluetun
        ).stdout.strip()
        if args.expected_gluetun_image and gluetun_image != args.expected_gluetun_image:
            raise RuntimeError(
                f"Gluetun image does not match expectation: {gluetun_image} "
                f"!= {args.expected_gluetun_image}"
            )
        executable_sha256 = docker(
            "exec", rust, "sha256sum", "/usr/lib/emulebb-rust/emulebb-rust"
        ).stdout.split()[0].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", executable_sha256):
            raise RuntimeError("could not read the Rust executable SHA-256 from the image")
        report["rustExecutableSha256"] = executable_sha256
        if expected_executable_sha256 and executable_sha256 != expected_executable_sha256:
            raise RuntimeError(
                "Rust executable SHA-256 does not match the certified staged binary: "
                f"{executable_sha256} != {expected_executable_sha256}"
            )
        report["rustExecutableMatchesExpected"] = bool(expected_executable_sha256)
        bridge_ip = docker("inspect", "--format",
                           "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                           gluetun).stdout.strip()
        ipaddress.IPv4Address(bridge_ip)
        report["testBridgeIp"] = bridge_ip

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
        api = "http://127.0.0.1:14711/api/v1"
        report["networkStartupMode"] = "consumer-default-auto-connect"
        deadline = time.monotonic() + 180
        while True:
            status = request_json(api + "/status", api_key)
            data = status.get("data", status)
            if public_network_ready(status):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("P2P did not connect through the healthy tunnel")
            time.sleep(3)
        report["preFailureStatus"] = data
        report["p2pConnectedThroughTunnel"] = True

        packet_filter = f"src host {bridge_ip} and ip and (tcp or udp)"
        positive = docker(
            "run", "--rm", "--network", "host", "--cap-add", "NET_RAW",
            args.capture_image, "timeout", "30", "tcpdump", "-n", "-q",
            "-e", "-i", "any", "-c", "1", packet_filter, timeout=50, check=False,
        )
        if captured_packet_count(positive) < 1:
            raise RuntimeError("host packet sensor did not see test-tunnel egress: "
                               + positive.stderr[-500:])
        report["captureSensorPositive"] = True
        report["positivePacketSample"] = positive.stdout.strip()[-500:]

        # Gluetun is manually stopped, never the operator's existing P2P stack.
        # Capture on the host so a removed eth0 cannot hide a packet in transit.
        command(*compose, "stop", "--timeout", "10", "gluetun", env=env, timeout=45)
        still_running = docker("inspect", "--format", "{{.State.Running}}", rust,
                               check=False).stdout.strip() == "true"
        report["rustRunningAfterTunnelDown"] = still_running
        if not still_running:
            raise RuntimeError("Rust daemon stopped instead of remaining alive and isolated")
        interfaces = docker("run", "--rm", "--network", f"container:{rust}",
                            args.capture_image, "ip", "-o", "link", "show")
        remaining_interfaces = re.findall(r"\d+: ([^:]+):", interfaces.stdout)
        report["remainingInterfaces"] = remaining_interfaces
        if set(remaining_interfaces) - {"lo"}:
            raise RuntimeError(f"non-loopback interface remained after tunnel shutdown: {remaining_interfaces}")
        namespace_rest = docker(
            "exec", rust, "curl", "--fail", "--silent", "--max-time", "3",
            "--header", f"X-API-Key: {api_key}", "http://127.0.0.1:4711/api/v1/status",
            check=False,
        )
        if namespace_rest.returncode:
            raise RuntimeError("Rust loopback REST stopped responding after tunnel shutdown")
        report["restReachableAfterTunnelDownInNamespace"] = True
        if url_is_reachable("http://127.0.0.1:14711/api/v1/status", api_key):
            raise RuntimeError("host-published REST remained reachable after Gluetun shutdown")
        report["hostRestIsolatedAfterTunnelDown"] = True
        capture_mount = f"{args.report.parent.resolve()}:/proof"
        capture = docker(
            "run", "--rm", "--network", "host", "--cap-add", "NET_RAW",
            "--volume", capture_mount, args.capture_image,
            "timeout", "45", "tcpdump", "-U", "-n", "-i", "any",
            "-c", "1", "-w", f"/proof/{pcap.name}", packet_filter,
            timeout=65, check=False,
        )
        if capture.returncode not in (0, 124):
            raise RuntimeError("host packet capture failed: " + capture.stderr[-500:])
        if not pcap.is_file() or pcap.stat().st_size < 24:
            raise RuntimeError("host packet capture did not save a readable PCAP")
        decoded = docker(
            "run", "--rm", "--volume", capture_mount, args.capture_image,
            "tcpdump", "-nn", "-r", f"/proof/{pcap.name}", check=False,
        )
        if decoded.returncode:
            raise RuntimeError("saved packet capture could not be decoded: "
                               + decoded.stderr[-500:])
        report["offTunnelPacketCount"] = len(
            [line for line in decoded.stdout.splitlines() if line.strip()]
        )
        report["offTunnelPacketSample"] = decoded.stdout.strip()[-500:]
        report["offTunnelCaptureSummary"] = capture.stderr.strip()[-500:]
        report["offTunnelPcapBytes"] = pcap.stat().st_size
        report["offTunnelPcap"] = str(pcap)
        if report["offTunnelPacketCount"] != 0:
            raise RuntimeError("off-tunnel IPv4 packet observed after tunnel shutdown")
        evidence_checks_passed = True
    except Exception as error:
        report["error"] = str(error)
        if started:
            logs = command(*compose, "logs", "--tail", "40", env=env, check=False)
            report["containerLogTail"] = (logs.stdout + logs.stderr)[-4000:]
    finally:
        teardown_error = ""
        down_returncode = None
        if started:
            # Only the just-created, uniquely named test project and volumes.
            down = command(*compose, "down", "--volumes", env=env, timeout=90, check=False)
            down_returncode = down.returncode
            if down.returncode:
                teardown_error = (down.stdout + down.stderr)[-1000:]
        try:
            after = project_states()
            pre_existing_preserved = all(after.get(name) == status for name, status in before.items())
            project_removed = project not in after
            remaining_containers = docker(
                "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={project}"
            ).stdout.split()
            remaining_networks = docker(
                "network", "ls", "--quiet", "--filter", f"label=com.docker.compose.project={project}"
            ).stdout.split()
            remaining_volumes = docker(
                "volume", "ls", "--quiet", "--filter", f"label=com.docker.compose.project={project}"
            ).stdout.split()
        except Exception as error:
            pre_existing_preserved = False
            project_removed = False
            remaining_containers = ["inspection-failed"]
            remaining_networks = ["inspection-failed"]
            remaining_volumes = ["inspection-failed"]
            teardown_error = str(error)
        report["preExistingProjectsPreserved"] = pre_existing_preserved
        report["testProjectRemoved"] = project_removed
        report["remainingTestContainers"] = remaining_containers
        report["remainingTestNetworks"] = remaining_networks
        report["remainingTestVolumes"] = remaining_volumes
        clean_teardown = (
            (not started or down_returncode == 0)
            and pre_existing_preserved
            and project_removed
            and not remaining_containers
            and not remaining_networks
            and not remaining_volumes
        )
        report["cleanTeardown"] = clean_teardown
        if teardown_error:
            report["teardownError"] = teardown_error
        if evidence_checks_passed and clean_teardown:
            report["status"] = "passed"
        elif evidence_checks_passed and "error" not in report:
            report["error"] = "isolated Compose teardown was not clean"
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print(json.dumps({key: value for key, value in report.items()
                          if key not in ("preFailureStatus", "containerLogTail")}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
