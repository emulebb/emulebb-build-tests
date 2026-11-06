"""Bounded local Kad firewall witness with no routing or file-sharing state.

A client learns this contact through the stock nodes.dat import facility. A positive UDP
probe is allowed only if this witness has received no prior UDP from that IP;
otherwise it reports the stock biased-test error. It never publishes or finds
file sources, so the real clients must prove those paths themselves.
The owning local scenario explicitly disables transport obfuscation; this
fixture is product workflow evidence and makes no cross-client parity claim.
"""

from __future__ import annotations

import ipaddress
import argparse
import json
import select
import socket
import struct
import threading
import uuid
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from . import docker_ed2k_source_publisher as docker_fixture
from .docker_ed2k_source_publisher import encode_hello_answer
from .kad_nodes import BootstrapContact, encode_nodes_dat

KAD_HEADER = 0xE4
FIREWALL_UDP = 0x62
USER_HASH = bytes.fromhex("b6120eb263ab40d09def36531b168590")


def receive_frame(stream: socket.socket) -> tuple[int, int, bytes]:
    """Read one bounded plaintext eD2K/eMule client frame."""

    def exact(count: int) -> bytes:
        data = bytearray()
        while len(data) < count:
            chunk = stream.recv(count - len(data))
            if not chunk:
                raise EOFError("client closed its helper session")
            data.extend(chunk)
        return bytes(data)

    header = exact(6)
    length = struct.unpack_from("<I", header, 1)[0]
    if header[0] not in (0xE3, 0xC5) or not 1 <= length <= 65536:
        raise ValueError("invalid firewall-helper client frame")
    return header[0], header[5], exact(length - 1)


class KadFirewallHelper:
    """Own one local TCP listener and UDP socket until explicit cleanup."""

    def __init__(self, bind_ip: str, allowed_peers: set[str]) -> None:
        self.bind_ip = str(ipaddress.IPv4Address(bind_ip))
        self.allowed_peers = {str(ipaddress.IPv4Address(ip)) for ip in allowed_peers}
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._udp.bind((self.bind_ip, 0))
            self._tcp.bind((self.bind_ip, 0))
            self._tcp.listen(4)
        except Exception:
            self._udp.close()
            self._tcp.close()
            raise
        self.udp_port = self._udp.getsockname()[1]
        self.tcp_port = self._tcp.getsockname()[1]
        self._known_udp_ips: set[str] = set()
        self._counts: Counter[str] = Counter()
        fixture = self

        class NodesHandler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                self.request.settimeout(5)
                super().setup()

            def do_GET(self) -> None:
                # HTTP is the control-plane import. Linux may source it from
                # docker0, while P2P sockets bind the explicit seeder address.
                if self.path != "/nodes.dat":
                    self.send_error(404)
                    return
                body = encode_nodes_dat(
                    [
                        BootstrapContact(
                            fixture.bind_ip,
                            fixture.udp_port,
                            fixture.tcp_port,
                        )
                    ]
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                fixture._counts["contactImports"] += 1

            def log_message(self, _format: str, *args: object) -> None:
                pass

        try:
            self._http = HTTPServer((self.bind_ip, 0), NodesHandler)
        except Exception:
            self._udp.close()
            self._tcp.close()
            raise
        self.nodes_url = f"http://{self.bind_ip}:{self._http.server_port}/nodes.dat"
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="kad-firewall-witness"
        )

    def start(self) -> None:
        """Start the bounded local witness thread."""

        self._thread.start()

    def evidence(self) -> dict[str, object]:
        """Return counters without peer addresses or UDP verification keys."""

        return {
            "role": "unbiased-firewall-witness",
            "transport": "plaintext-local-fixture",
            **dict(self._counts),
        }

    def close(self) -> None:
        """Stop the thread before releasing its owned sockets."""

        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=6)
        self._tcp.close()
        self._udp.close()
        self._http.server_close()
        if self._thread.is_alive():
            raise RuntimeError("Kad firewall witness did not stop")

    def _serve(self) -> None:
        while not self._stop.is_set():
            readable, _, _ = select.select(
                [self._udp, self._tcp, self._http.socket], [], [], 0.2
            )
            # Drain pre-existing UDP before accepting TCP: prior outbound UDP
            # could have opened a NAT path and must disqualify a positive probe.
            if self._udp in readable:
                self._handle_udp()
            if self._http.socket in readable:
                self._http.handle_request()
            if self._tcp in readable:
                stream, peer = self._tcp.accept()
                with stream:
                    if peer[0] not in self.allowed_peers:
                        continue
                    stream.settimeout(5)
                    try:
                        self._handle_tcp(stream, peer[0])
                    except (OSError, EOFError, ValueError):
                        self._counts["sessionErrors"] += 1

    def _handle_udp(self) -> None:
        _packet, peer = self._udp.recvfrom(65536)
        if peer[0] not in self.allowed_peers:
            return
        self._known_udp_ips.add(peer[0])
        self._counts["priorUdpPackets"] += 1

    def _handle_tcp(self, stream: socket.socket, peer_ip: str) -> None:
        marker, opcode, payload = receive_frame(stream)
        if marker != 0xE3 or opcode != 0x01 or len(payload) < 23 or payload[0] != 16:
            raise ValueError("firewall helper requires a complete HELLO")
        stream.sendall(
            encode_hello_answer(
                user_hash=USER_HASH,
                client_id=int.from_bytes(
                    ipaddress.IPv4Address(self.bind_ip).packed, "little"
                ),
                tcp_port=self.tcp_port,
            )
        )
        for _ in range(16):
            marker, opcode, payload = receive_frame(stream)
            if (marker, opcode) != (0xC5, 0xA7):
                continue
            if len(payload) < 8:
                raise ValueError("truncated OP_FWCHECKUDPREQ")
            internal_port, external_port, _sender_key = struct.unpack_from(
                "<HHI", payload
            )
            self._counts["firewallRequests"] += 1
            if internal_port == 0:
                self._counts["invalidRequests"] += 1
                return
            while select.select([self._udp], [], [], 0)[0]:
                self._handle_udp()
            error = int(peer_ip in self._known_udp_ips)
            self._counts["biasedRequests" if error else "unbiasedRequests"] += 1
            for port in {internal_port, external_port} - {0}:
                self._udp.sendto(
                    bytes([KAD_HEADER, FIREWALL_UDP, error]) + struct.pack("<H", port),
                    (peer_ip, port),
                )
                self._counts["udpProbeReplies"] += 1
            return
        raise ValueError("helper session exceeded its packet budget")


class DockerKadFirewallWitness:
    """Own an isolated helper container on the existing WSL Docker bridge."""

    def __init__(self, name: str, receipt: Path, distribution: str | None) -> None:
        self.name = name
        self.receipt = receipt
        self.distribution = distribution
        ready = docker_fixture._wait_for_receipt(receipt, 20)
        if (
            ready.get("schema") != "emulebb.kad-firewall-witness.v1"
            or ready.get("runId") != name
        ):
            raise RuntimeError("invalid Kad witness readiness receipt")
        self.nodes_url = str(ready["nodesUrl"])

    def evidence(self) -> dict[str, object]:
        """Read the child's atomic receipt and omit its private endpoint."""

        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        return {
            **receipt["evidence"],
            "runtime": "docker-bridge",
            "image": docker_fixture.DOCKER_IMAGE,
        }

    def close(self) -> None:
        """Ask the child to flush its counters, then remove only this container."""

        try:
            stopped = docker_fixture._docker_result(
                self.distribution,
                ["stop", "--time", "6", self.name],
            )
            if stopped.returncode != 0:
                raise RuntimeError("Kad witness container did not stop cleanly")
        finally:
            removed = docker_fixture._docker_result(
                self.distribution,
                ["rm", "--force", self.name],
            )
            if removed.returncode != 0:
                raise RuntimeError("Kad witness container was not removed")


def start_docker_witness(
    run_dir: Path,
    allowed_peers: set[str],
    *,
    distribution: str | None = None,
) -> DockerKadFirewallWitness:
    """Launch the persisted witness in the pinned local Python image.

    Reuse the existing Docker fixture's image preflight and argument-vector WSL
    helpers. No host route, adapter, published port, or public service is needed.
    """

    docker_fixture._preflight_image(distribution)
    run_dir.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    linux_root = docker_fixture._wsl_path(root, distribution)
    linux_output = docker_fixture._wsl_path(run_dir, distribution)
    name = f"emulebb-kad-witness-{uuid.uuid4().hex}"
    receipt = run_dir / "witness.json"
    if receipt.exists():
        raise ValueError("Kad witness receipt already exists")
    command = [
        "run",
        "--detach",
        "--pull=never",
        "--init",
        "--network=bridge",
        f"--platform={docker_fixture.DOCKER_PLATFORM}",
        "--name",
        name,
        "--label",
        "org.emulebb.harness.fixture=kad-firewall-witness",
        "--mount",
        f"type=bind,src={linux_root},dst=/workspace,readonly",
        "--mount",
        f"type=bind,src={linux_output},dst=/run",
        "--workdir",
        "/workspace",
        docker_fixture.DOCKER_IMAGE,
        "python",
        "-m",
        "emule_test_harness.kad_firewall_helper",
        "--receipt",
        "/run/witness.json",
        "--run-id",
        name,
    ]
    for peer in sorted(allowed_peers):
        command.extend(["--allowed-peer", str(ipaddress.IPv4Address(peer))])
    try:
        launched = docker_fixture._docker_result(distribution, command)
        if launched.returncode != 0:
            raise RuntimeError("Kad witness container failed to launch")
        return DockerKadFirewallWitness(name, receipt, distribution)
    except Exception:
        docker_fixture._docker_result(distribution, ["rm", "--force", name])
        raise


def main() -> None:
    """Run the container child until its owner requests shutdown."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowed-peer", action="append", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    address = socket.gethostbyname(socket.gethostname())
    helper = KadFirewallHelper(address, set(args.allowed_peer))
    stop = threading.Event()
    handlers = docker_fixture._install_stop_handlers(stop)
    helper.start()
    previous = None
    try:
        while not stop.is_set():
            evidence = helper.evidence()
            if evidence != previous:
                docker_fixture.write_json_atomic(
                    args.receipt,
                    {
                        "schema": "emulebb.kad-firewall-witness.v1",
                        "runId": args.run_id,
                        "nodesUrl": helper.nodes_url,
                        "evidence": evidence,
                    },
                )
                previous = evidence
            stop.wait(0.2)
    finally:
        helper.close()
        docker_fixture._restore_stop_handlers(handlers)
        docker_fixture.write_json_atomic(
            args.receipt,
            {
                "schema": "emulebb.kad-firewall-witness.v1",
                "runId": args.run_id,
                "nodesUrl": helper.nodes_url,
                "evidence": helper.evidence(),
                "stopped": True,
            },
        )


if __name__ == "__main__":
    main()
