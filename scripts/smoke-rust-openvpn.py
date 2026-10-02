#!/usr/bin/env python3
"""Exercise Rust eD2K/Kad searches in a plain OpenVPN Docker namespace.

Run from Linux/WSL with Docker. The Compose project is unique and ephemeral;
the operator's existing projects, containers, networks, and volumes are never
addressed. VPN credentials are consumed as Docker secrets and are not reported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.request
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import nat_live_matrix


REQUIRED_PRIVATE_FILES = (
    "custom.conf",
    "ca.pem",
    "StaticKey.pem",
    "openvpn_user",
    "openvpn_password",
)


def command(
    *argv: str,
    timeout: int = 60,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
        env=env,
    )


def docker(*argv: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return command("docker", *argv, **kwargs)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_states() -> dict[str, str]:
    result = docker("compose", "ls", "--all", "--format", "json")
    return {row["Name"]: row["Status"] for row in json.loads(result.stdout)}


def request_json(
    url: str,
    key: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    body = None
    headers = {"X-API-Key": key}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, headers=headers, data=body, method=method)
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError(f"REST response from {url} was not an object")
    return value


def response_data(payload: dict[str, object]) -> dict[str, object]:
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise RuntimeError("REST response data was not an object")
    return data


def public_network_state(payload: dict[str, object]) -> tuple[bool, int]:
    data = response_data(payload)
    stats = data.get("stats", {})
    kad = data.get("kad", {})
    if not isinstance(stats, dict) or not isinstance(kad, dict):
        return False, 0
    return bool(stats.get("ed2kConnected")), int(kad.get("contactCount") or 0)


def redact_logs(text: str) -> str:
    text = re.sub(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])", "[IP_REDACTED]", text)
    return re.sub(
        r"(?i)(username|password)(\s*[=:]\s*)\S+",
        r"\1\2[REDACTED]",
        text,
    )[-4000:]


def search_log_signals(text: str) -> list[str]:
    patterns = (
        "sent ED2K background keyword search",
        "completed ED2K background keyword search",
        "ED2K background keyword search returned no results",
        "ED2K background keyword search failed",
        "ED2K UDP keyword search attempt",
        "failed to send ED2K UDP keyword search",
        "discarding malformed ED2K UDP keyword-search response",
        "traversal phase1 done",
        "traversal phase2:",
        "traversal phase2 done",
        "kad keyword search stream summary",
        "kad recv decode-failed",
        "kad recv opcode=KADEMLIA2_SEARCH_RES",
        "kad recv dropping-unrequested-response",
        "tracker-dropping",
    )
    return [
        redact_logs(line)
        for line in text.splitlines()
        if any(pattern in line for pattern in patterns)
    ][-200:]


def start_packet_capture(
    *,
    namespace_container: str,
    capture_name: str,
    capture_image: str,
    capture_mount: str,
    pcap_name: str,
) -> None:
    docker(
        "run",
        "--detach",
        "--name",
        capture_name,
        "--network",
        f"container:{namespace_container}",
        "--cap-add",
        "NET_RAW",
        "--volume",
        capture_mount,
        capture_image,
        "tcpdump",
        "-U",
        "-n",
        "-i",
        "tun0",
        "-w",
        f"/proof/{pcap_name}",
        "ip and (tcp or udp)",
    )
    time.sleep(1)


def stop_packet_capture(capture_name: str) -> None:
    docker("kill", "--signal", "SIGINT", capture_name, check=False)
    docker("wait", capture_name, check=False)
    docker("rm", capture_name, check=False)


def decoded_packet_count(
    *,
    capture_image: str,
    capture_mount: str,
    pcap_name: str,
    packet_filter: str,
) -> int:
    decoded = docker(
        "run",
        "--rm",
        "--volume",
        capture_mount,
        capture_image,
        "tcpdump",
        "-nn",
        "-r",
        f"/proof/{pcap_name}",
        packet_filter,
        check=False,
    )
    if decoded.returncode:
        raise RuntimeError("could not decode search packet capture")
    return len([line for line in decoded.stdout.splitlines() if line.strip()])


def packet_capture_summary(
    *,
    capture_image: str,
    capture_mount: str,
    pcap: Path,
    tun_ip: str,
) -> dict[str, object]:
    if not pcap.is_file() or pcap.stat().st_size < 24:
        raise RuntimeError("search packet capture was not saved as a readable PCAP")
    common = {
        "capture_image": capture_image,
        "capture_mount": capture_mount,
        "pcap_name": pcap.name,
    }
    return {
        "pcap": str(pcap),
        "pcapBytes": pcap.stat().st_size,
        "packetCount": decoded_packet_count(packet_filter="ip and (tcp or udp)", **common),
        "outboundPacketCount": decoded_packet_count(
            packet_filter=f"src host {tun_ip}", **common
        ),
        "inboundPacketCount": decoded_packet_count(
            packet_filter=f"dst host {tun_ip}", **common
        ),
        "outboundUdpPacketCount": decoded_packet_count(
            packet_filter=f"udp and src host {tun_ip}", **common
        ),
        "inboundUdpPacketCount": decoded_packet_count(
            packet_filter=f"udp and dst host {tun_ip}", **common
        ),
        "outboundTcpPacketCount": decoded_packet_count(
            packet_filter=f"tcp and src host {tun_ip}", **common
        ),
        "inboundTcpPacketCount": decoded_packet_count(
            packet_filter=f"tcp and dst host {tun_ip}", **common
        ),
    }


def run_search(
    api: str,
    api_key: str,
    *,
    method: str,
    query: str,
    timeout_seconds: int,
) -> dict[str, object]:
    started = response_data(
        request_json(
            api + "/searches",
            api_key,
            method="POST",
            payload={"query": query, "method": method, "type": ""},
        )
    )
    search_id = str(started.get("id") or "").strip()
    if not search_id:
        raise RuntimeError(f"{method} search did not return an id")
    deadline = time.monotonic() + timeout_seconds
    maximum_count = 0
    final_status = "unknown"
    samples: list[dict[str, object]] = []
    try:
        while True:
            current = response_data(
                request_json(api + f"/searches/{search_id}", api_key)
            )
            results = current.get("items", current.get("results", []))
            if not isinstance(results, list):
                raise RuntimeError(f"{method} search results were not a list")
            total = current.get("total", len(results))
            result_count = int(total) if isinstance(total, int) else len(results)
            maximum_count = max(maximum_count, result_count)
            final_status = str(current.get("status") or "unknown")
            samples.append(
                {
                    "elapsedSeconds": timeout_seconds - max(0, int(deadline - time.monotonic())),
                    "resultCount": result_count,
                    "pageItemCount": len(results),
                    "status": final_status,
                }
            )
            if final_status == "complete" or time.monotonic() >= deadline:
                break
            time.sleep(5)
    finally:
        try:
            request_json(api + f"/searches/{search_id}", api_key, method="DELETE")
        except Exception:
            pass
    return {
        "method": method,
        "query": query,
        "maximumResultCount": maximum_count,
        "finalStatus": final_status,
        "timedOut": time.monotonic() >= deadline and final_status != "complete",
        "samples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image", default="ghcr.io/emulebb/emulebb-rust:0.1.0-beta.1")
    parser.add_argument(
        "--openvpn-image",
        default="local/emulebb-test-openvpn-client:alpine-3.22",
    )
    parser.add_argument("--capture-image", default="nicolaka/netshoot:v0.13")
    parser.add_argument("--expected-executable-sha256")
    parser.add_argument("--query", default="ubuntu")
    parser.add_argument(
        "--binding-mode",
        choices=("none", "interface", "interface-ip"),
        default="interface",
        help="Reproduce no P2P binding, tun0 interface binding, or tun0 interface+IP binding",
    )
    parser.add_argument(
        "--methods",
        choices=("server", "global", "kad"),
        nargs="+",
        default=("server", "global", "kad"),
    )
    parser.add_argument("--repeat-searches", type=int, default=1)
    parser.add_argument("--rust-log", default="info")
    parser.add_argument(
        "--tunnel-egress-delay-ms",
        type=int,
        metavar="MILLISECONDS",
        help="Add controlled tun0 egress latency after network readiness",
    )
    parser.add_argument(
        "--drop-inbound-packets-over",
        type=int,
        metavar="BYTES",
        help="Drop inbound tun0 IP packets at or above this size after readiness",
    )
    parser.add_argument("--disable-protocol-obfuscation", action="store_true")
    parser.add_argument(
        "--nat-matrix",
        action="store_true",
        help="Run the capability-aware PCP/NAT-PMP and MiniUPnPc matrix.",
    )
    args = parser.parse_args()

    if not args.archive.is_file() or not args.compose.is_file():
        raise RuntimeError("the OCI archive and Compose file must exist")
    for name in REQUIRED_PRIVATE_FILES:
        if not (args.private_root / name).is_file():
            raise RuntimeError(f"VPN private root lacks {name}")
    if args.report.exists():
        raise RuntimeError("refusing to overwrite an existing report")
    expected_sha256 = (args.expected_executable_sha256 or "").lower()
    if expected_sha256 and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise RuntimeError("--expected-executable-sha256 must be a lowercase SHA-256 digest")
    if args.drop_inbound_packets_over is not None and not 68 <= args.drop_inbound_packets_over <= 65_535:
        raise RuntimeError("--drop-inbound-packets-over must be between 68 and 65535")
    if args.tunnel_egress_delay_ms is not None and not 1 <= args.tunnel_egress_delay_ms <= 5_000:
        raise RuntimeError("--tunnel-egress-delay-ms must be between 1 and 5000")
    if not 1 <= args.repeat_searches <= 5:
        raise RuntimeError("--repeat-searches must be between 1 and 5")
    args.report.parent.mkdir(parents=True, exist_ok=True)

    project = f"emulebb-rust-openvpn-proof-{os.getpid()}"
    before = project_states()
    if project in before:
        raise RuntimeError("refusing to reuse an existing Compose project")
    env = {
        **os.environ,
        "EMULEBB_TEST_VPN_PRIVATE_ROOT": str(args.private_root.resolve()),
        "EMULEBB_TEST_P2P_INTERFACE": "" if args.binding_mode == "none" else "tun0",
        "EMULEBB_TEST_RUST_LOG": args.rust_log,
        "EMULEBB_TEST_RUST_IMAGE": args.image,
    }
    compose = (
        "docker",
        "compose",
        "--project-name",
        project,
        "--file",
        str(args.compose.resolve()),
    )
    report: dict[str, object] = {
        "schema": "emulebb.rust.openvpn-search-proof/1",
        "status": "failed",
        "project": project,
        "archive": str(args.archive.resolve()),
        "archiveSha256": sha256_file(args.archive),
        "compose": str(args.compose.resolve()),
        "composeSha256": sha256_file(args.compose),
        "image": args.image,
        "openvpnImage": args.openvpn_image,
        "captureImage": args.capture_image,
        "query": args.query,
        "bindingMode": args.binding_mode,
        "searchMethods": args.methods,
        "searchRepeatCount": args.repeat_searches,
        "protocolObfuscationRequested": not (
            args.disable_protocol_obfuscation or args.nat_matrix
        ),
    }
    if args.drop_inbound_packets_over is not None:
        report["inboundPacketDropThresholdBytes"] = args.drop_inbound_packets_over
    if args.tunnel_egress_delay_ms is not None:
        report["tunnelEgressDelayMs"] = args.tunnel_egress_delay_ms
    started = False
    completed = False
    capture_names: list[str] = []
    try:
        command(*compose, "config", "--quiet", env=env)
        docker("load", "--input", str(args.archive.resolve()), timeout=300)
        docker("image", "inspect", args.image)
        docker(
            "build",
            "--tag",
            args.openvpn_image,
            str(args.compose.resolve().parent),
            timeout=300,
        )
        report["openvpnImageId"] = docker(
            "image", "inspect", args.openvpn_image, "--format", "{{.Id}}"
        ).stdout.strip()
        if docker("image", "inspect", args.capture_image, check=False).returncode:
            docker("pull", args.capture_image, timeout=300)
        report["captureImageId"] = docker(
            "image", "inspect", args.capture_image, "--format", "{{.Id}}"
        ).stdout.strip()
        started = True
        command(
            *compose,
            "up",
            "--detach",
            "--no-build",
            "--pull",
            "never",
            env=env,
            timeout=180,
        )
        openvpn = command(*compose, "ps", "--quiet", "openvpn", env=env).stdout.strip()
        rust = command(*compose, "ps", "--quiet", "emulebb-rust", env=env).stdout.strip()
        if not openvpn or not rust:
            raise RuntimeError("isolated OpenVPN/Rust containers were not created")
        vpn_executable = docker("exec", openvpn, "readlink", "/proc/1/exe").stdout.strip()
        if vpn_executable != "/usr/sbin/openvpn":
            raise RuntimeError("VPN namespace is not owned by a plain OpenVPN process")
        report["plainOpenvpnProcess"] = True
        report["vpnPidOneExecutable"] = vpn_executable

        executable_sha256 = docker(
            "exec", rust, "sha256sum", "/usr/lib/emulebb-rust/emulebb-rust"
        ).stdout.split()[0].lower()
        report["rustExecutableSha256"] = executable_sha256
        if expected_sha256 and executable_sha256 != expected_sha256:
            raise RuntimeError("Rust executable SHA-256 does not match the certified binary")
        report["rustExecutableMatchesExpected"] = bool(expected_sha256)

        tun = docker("exec", openvpn, "ip", "-4", "-o", "addr", "show", "dev", "tun0")
        if not tun.stdout.strip():
            raise RuntimeError("plain OpenVPN did not create an IPv4 tun0")
        tun_match = re.search(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/", tun.stdout)
        if not tun_match:
            raise RuntimeError("plain OpenVPN tun0 did not expose a parseable IPv4 address")
        tun_ip = tun_match.group(1)
        route = docker("exec", openvpn, "ip", "-4", "route", "get", "1.1.1.1")
        if not re.search(r"\bdev tun0\b", route.stdout):
            raise RuntimeError("public IPv4 routing is not directed through tun0")
        route_table = docker("exec", openvpn, "ip", "-4", "route", "show").stdout
        report["literalDefaultRouteUsesTun0"] = bool(
            re.search(r"^default(?:\s+.*)?\s+dev tun0(?:\s|$)", route_table, re.MULTILINE)
        )
        report["tun0HasSplitDefaultRoutes"] = all(
            re.search(rf"^{re.escape(prefix)}(?:\s+.*)?\s+dev tun0(?:\s|$)", route_table, re.MULTILINE)
            for prefix in ("0.0.0.0/1", "128.0.0.0/1")
        )
        processes = docker("top", rust).stdout
        interface_pinned = "--p2p-bind-interface tun0" in processes
        if interface_pinned != (args.binding_mode != "none"):
            raise RuntimeError("Rust daemon P2P interface arguments did not match the requested mode")
        report["tun0Present"] = True
        report["publicRouteUsesTun0"] = True
        report["p2pInterfacePinned"] = interface_pinned

        deadline = time.monotonic() + 120
        while True:
            page = docker(
                "exec",
                rust,
                "curl",
                "--fail",
                "--silent",
                "--max-time",
                "3",
                "http://127.0.0.1:4711/",
                check=False,
            )
            if page.returncode == 0 and "eMuleBB WebUI" in page.stdout:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Rust WebUI did not start in the OpenVPN namespace")
            time.sleep(2)
        settings = docker(
            "exec",
            rust,
            "cat",
            "/config/emulebb-rust/emulebb-rust-settings.toml",
        ).stdout
        api_key = tomllib.loads(settings)["rest"]["apiKey"]
        api = "http://127.0.0.1:14712/api/v1"
        settings_patch: dict[str, object] = {}
        if args.disable_protocol_obfuscation or args.nat_matrix:
            settings_patch["ed2k"] = {"obfuscationEnabled": False}
        if args.binding_mode == "interface-ip":
            settings_patch["daemon"] = {
                "p2pBindInterface": "tun0",
                "p2pBindIp": tun_ip,
            }
        if settings_patch:
            updated = response_data(
                request_json(
                    api + "/app/settings",
                    api_key,
                    method="PATCH",
                    payload=settings_patch,
                )
            )
            if args.disable_protocol_obfuscation or args.nat_matrix:
                updated_ed2k = updated.get("ed2k", {})
                if not isinstance(updated_ed2k, dict) or updated_ed2k.get("obfuscationEnabled") is not False:
                    raise RuntimeError("REST settings PATCH did not disable protocol obfuscation")
            if args.binding_mode == "interface-ip":
                updated_daemon = updated.get("daemon", {})
                if not isinstance(updated_daemon, dict) or updated_daemon.get("p2pBindIp") != tun_ip:
                    raise RuntimeError("REST settings PATCH did not set the tun0 P2P bind IP")
            command(*compose, "restart", "emulebb-rust", env=env, timeout=90)
            deadline = time.monotonic() + 120
            while True:
                page = docker(
                    "exec",
                    rust,
                    "curl",
                    "--fail",
                    "--silent",
                    "--max-time",
                    "3",
                    "http://127.0.0.1:4711/",
                    check=False,
                )
                if page.returncode == 0 and "eMuleBB WebUI" in page.stdout:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Rust WebUI did not restart after settings update")
                time.sleep(2)
            persisted = response_data(request_json(api + "/app/settings", api_key))
            if args.disable_protocol_obfuscation or args.nat_matrix:
                persisted_ed2k = persisted.get("ed2k", {})
                if not isinstance(persisted_ed2k, dict) or persisted_ed2k.get("obfuscationEnabled") is not False:
                    raise RuntimeError("protocol-obfuscation setting did not persist across restart")
            if args.binding_mode == "interface-ip":
                persisted_daemon = persisted.get("daemon", {})
                if not isinstance(persisted_daemon, dict) or persisted_daemon.get("p2pBindIp") != tun_ip:
                    raise RuntimeError("P2P bind IP did not persist across restart")
                report["p2pBindIpMatchesTun0"] = True
        report["protocolObfuscationEnabled"] = not (
            args.disable_protocol_obfuscation or args.nat_matrix
        )

        if args.nat_matrix:
            def apply_nat_settings(payload: dict[str, object]) -> dict[str, object]:
                return request_json(
                    api + "/app/settings",
                    api_key,
                    method="PATCH",
                    payload=payload,
                )

            def restart_for_nat() -> None:
                command(*compose, "restart", "emulebb-rust", env=env, timeout=90)
                restart_deadline = time.monotonic() + 120
                while True:
                    page = docker(
                        "exec",
                        rust,
                        "curl",
                        "--fail",
                        "--silent",
                        "--max-time",
                        "3",
                        "http://127.0.0.1:4711/",
                        check=False,
                    )
                    if page.returncode == 0 and "eMuleBB WebUI" in page.stdout:
                        return
                    if time.monotonic() >= restart_deadline:
                        raise RuntimeError("Rust WebUI did not restart for NAT matrix case")
                    time.sleep(2)

            report["natMatrix"] = nat_live_matrix.run_matrix(
                apply_settings=apply_nat_settings,
                restart_daemon=restart_for_nat,
                read_nat_status=lambda: request_json(api + "/nat", api_key),
                daemon_alive=lambda: docker(
                    "inspect", "--format", "{{.State.Running}}", rust, check=False
                ).stdout.strip()
                == "true",
            )
            if not report["natMatrix"]["passed"]:
                raise RuntimeError("one or more capability-aware NAT matrix cases failed")

        network = response_data(request_json(api + "/network", api_key))
        binding = network.get("binding", {})
        if not isinstance(binding, dict):
            raise RuntimeError("network binding response was not an object")
        configured_address = binding.get("configuredAddress")
        report["resolvedP2pBindMatchesTun0"] = configured_address == tun_ip
        eth0 = docker("exec", openvpn, "ip", "-4", "-o", "addr", "show", "dev", "eth0")
        eth0_match = re.search(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/", eth0.stdout)
        report["resolvedP2pBindMatchesEth0"] = bool(
            eth0_match and configured_address == eth0_match.group(1)
        )

        deadline = time.monotonic() + 240
        connected = False
        kad_contacts = 0
        while time.monotonic() < deadline:
            status = request_json(api + "/status", api_key)
            connected, kad_contacts = public_network_state(status)
            if connected and kad_contacts > 0:
                break
            time.sleep(3)
        report["ed2kConnected"] = connected
        report["kadContactCount"] = kad_contacts
        if args.binding_mode == "none":
            ready = kad_contacts > 0
        else:
            ready = connected and kad_contacts > 0
        if not ready:
            raise RuntimeError("eD2K and Kad did not become ready through plain OpenVPN")

        if args.tunnel_egress_delay_ms is not None:
            docker(
                "exec",
                openvpn,
                "tc",
                "qdisc",
                "replace",
                "dev",
                "tun0",
                "root",
                "netem",
                "delay",
                f"{args.tunnel_egress_delay_ms}ms",
            )
            report["tunnelEgressDelayInstalled"] = True

        if args.drop_inbound_packets_over is not None:
            docker(
                "exec",
                openvpn,
                "iptables",
                "--insert",
                "INPUT",
                "1",
                "--in-interface",
                "tun0",
                "--match",
                "length",
                "--length",
                f"{args.drop_inbound_packets_over}:65535",
                "--jump",
                "DROP",
            )
            report["inboundPacketDropInstalled"] = True

        observations = []
        capture_mount = f"{args.report.parent.resolve()}:/proof"
        search_timeouts = {"server": 60, "global": 90, "kad": 120}
        for iteration in range(1, args.repeat_searches + 1):
            for method in args.methods:
                if method in {"server", "global"} and not connected:
                    observations.append(
                        {
                            "iteration": iteration,
                            "method": method,
                            "query": args.query,
                            "skipped": True,
                            "reason": "ed2k-not-connected",
                            "maximumResultCount": 0,
                        }
                    )
                    continue
                timeout_seconds = search_timeouts[method]
                label = method if args.repeat_searches == 1 else f"{iteration:02d}.{method}"
                capture_name = f"{project}-{iteration}-{method}-capture"
                pcap = args.report.with_name(f"{args.report.stem}.{label}.pcap")
                if pcap.exists():
                    raise RuntimeError(f"refusing to overwrite search capture {pcap.name}")
                capture_names.append(capture_name)
                start_packet_capture(
                    namespace_container=openvpn,
                    capture_name=capture_name,
                    capture_image=args.capture_image,
                    capture_mount=capture_mount,
                    pcap_name=pcap.name,
                )
                try:
                    observation = run_search(
                        api,
                        api_key,
                        method=method,
                        query=args.query,
                        timeout_seconds=timeout_seconds,
                    )
                finally:
                    stop_packet_capture(capture_name)
                    capture_names.remove(capture_name)
                observation["iteration"] = iteration
                observation["capture"] = packet_capture_summary(
                    capture_image=args.capture_image,
                    capture_mount=capture_mount,
                    pcap=pcap,
                    tun_ip=tun_ip,
                )
                observations.append(observation)
        report["searches"] = observations
        report["ed2kSearchHasResults"] = any(
            item["method"] in {"server", "global"} and item["maximumResultCount"] > 0
            for item in observations
        )
        report["kadSearchHasResults"] = any(
            item["method"] == "kad" and item["maximumResultCount"] > 0
            for item in observations
        )
        rust_logs = docker("logs", rust, check=False)
        report["searchLogSignals"] = search_log_signals(rust_logs.stdout + rust_logs.stderr)
        completed = True
    except Exception as error:
        report["error"] = str(error)
        if started:
            logs = command(*compose, "logs", "--tail", "80", env=env, check=False)
            report["containerLogTailRedacted"] = redact_logs(logs.stdout + logs.stderr)
    finally:
        for capture_name in capture_names:
            docker("rm", "--force", capture_name, check=False)
        down_returncode = None
        if started:
            down = command(
                *compose,
                "down",
                "--volumes",
                "--remove-orphans",
                env=env,
                timeout=90,
                check=False,
            )
            down_returncode = down.returncode
            if down.returncode:
                report["teardownError"] = redact_logs(down.stdout + down.stderr)
        try:
            after = project_states()
            preserved = all(after.get(name) == status for name, status in before.items())
            removed = project not in after
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
            preserved = False
            removed = False
            remaining_containers = ["inspection-failed"]
            remaining_networks = ["inspection-failed"]
            remaining_volumes = ["inspection-failed"]
            report["teardownInspectionError"] = str(error)
        clean_teardown = (
            (not started or down_returncode == 0)
            and preserved
            and removed
            and not remaining_containers
            and not remaining_networks
            and not remaining_volumes
        )
        report["preExistingProjectsPreserved"] = preserved
        report["testProjectRemoved"] = removed
        report["remainingTestContainers"] = remaining_containers
        report["remainingTestNetworks"] = remaining_networks
        report["remainingTestVolumes"] = remaining_volumes
        report["cleanTeardown"] = clean_teardown
        if completed and clean_teardown:
            report["status"] = "passed"
        elif completed and "error" not in report:
            report["error"] = "isolated Compose teardown was not clean"
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        printable = {
            key: value
            for key, value in report.items()
            if key != "containerLogTailRedacted"
        }
        print(json.dumps(printable, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
