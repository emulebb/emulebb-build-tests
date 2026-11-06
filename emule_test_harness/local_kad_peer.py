"""Bounded local Kad index peer and initially unbiased firewall witness.

A client learns this contact through the stock nodes.dat import facility. A positive UDP
probe is allowed only if this witness has received no prior UDP from that IP;
otherwise it reports the stock biased-test error. Its small in-memory source
index is a rendezvous for the real clients' publish and search packets. It has
no payload bytes and never initiates a download or peer transfer.
The owning local scenario explicitly disables transport obfuscation; this
fixture is product workflow evidence and makes no cross-client parity claim.
"""

from __future__ import annotations

import ipaddress
import hashlib
import select
import socket
import struct
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

from .docker_ed2k_source_publisher import encode_hello_answer
from .kad_nodes import BootstrapContact, encode_nodes_dat
from . import ed2k_wire

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


class LocalKadPeer:
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
        self.node_id = hashlib.sha256(
            f"{self.bind_ip}:{self.udp_port}".encode("ascii")
        ).digest()[:16]
        self._sources: dict[bytes, dict[bytes, tuple[int, bytes]]] = {}
        self._last_source_reply: bytes | None = None
        self._known_udp_ips: set[str] = set()
        self._counts: Counter[str] = Counter()
        fixture = self

        class NodesHandler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                self.request.settimeout(5)
                super().setup()

            def do_GET(self) -> None:
                # The HTTP control-plane import is independent of the P2P
                # peer address selected by the seeder's bound TCP socket.
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

        shapes = []
        for sources in self._sources.values():
            for size, record in sources.values():
                tags = {
                    name: value
                    for name, value, _raw in ed2k_wire.decode_tag_sequence(
                        record[17:], record[16]
                    )
                }
                shapes.append(
                    {
                        "sizeBytes": size,
                        "sourceType": tags.get(0xFF),
                        "tcpPortPresent": bool(tags.get(0xFD)),
                        "udpPortPresent": bool(tags.get(0xFC)),
                        "connectOptions": tags.get(0xF3),
                    }
                )
        return {
            "role": "local-kad-index-and-firewall-witness",
            "transport": "plaintext-local-fixture",
            "sourceShapes": shapes,
            "lastSourceReplyHex": self._last_source_reply.hex()
            if self._last_source_reply
            else None,
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
                    self._counts["tcpConnections"] += 1
                    if peer[0] not in self.allowed_peers:
                        self._counts["disallowedTcpConnections"] += 1
                        continue
                    stream.settimeout(5)
                    try:
                        self._handle_tcp(stream, peer[0])
                    except (OSError, EOFError, ValueError):
                        self._counts["sessionErrors"] += 1

    def _handle_udp(self) -> None:
        packet, peer = self._udp.recvfrom(65536)
        if peer[0] not in self.allowed_peers:
            return
        self._known_udp_ips.add(peer[0])
        self._counts["priorUdpPackets"] += 1
        try:
            reply = self._kad_reply(packet, peer)
            if reply is not None:
                self._udp.sendto(reply, peer)
        except (ValueError, ed2k_wire.Ed2kWireError, struct.error):
            self._counts["malformedKadPackets"] += 1

    def _kad_reply(self, packet: bytes, peer: tuple[str, int]) -> bytes | None:
        """Handle the bounded stock Kad2 variants used by the local proof.

        Layout authority: KademliaUDPListener.cpp bootstrap/REQ/source publish/
        source search handlers, mirrored by emulebb-kad-proto packet types.
        Source result IP is always the observed publisher IP, never a supplied tag.
        """

        if len(packet) < 2 or packet[0] != KAD_HEADER:
            return None
        opcode, body = packet[1], packet[2:]
        if opcode == 0x01 and not body:
            return b"\xe4\x09" + self.node_id + struct.pack("<HBH", self.tcp_port, 9, 0)
        if opcode == 0x11 and len(body) >= 20:
            return b"\xe4\x19" + self.node_id + struct.pack("<HBB", self.tcp_port, 9, 0)
        if opcode == 0x60 and not body:
            return b"\xe4\x61" + struct.pack("<H", peer[1])
        if opcode == 0x21 and len(body) == 33 and body[17:] == self.node_id:
            self._counts["routingReplies"] += 1
            return b"\xe4\x29" + body[1:17] + b"\x00"
        if opcode == 0x44:
            return self._store_source(body, peer[0])
        if opcode == 0x34:
            return self._search_sources(body)
        return None

    def _store_source(self, body: bytes, publisher_ip: str) -> bytes | None:
        if len(body) < 33 or len(body) > 4096 or body[32] > 63:
            raise ValueError("source publish exceeds fixture bounds")
        tags = ed2k_wire.decode_tag_sequence(body[33:], body[32])
        if any(raw[0] & 0x80 for _name, _value, raw in tags):
            raise ValueError("Kad tags require the length-prefixed name form")
        values = {name: value for name, value, _raw in tags}
        port = values.get(0xFD)
        if (
            not isinstance(values.get(0xFF), int)
            or not isinstance(port, int)
            or not 0 < port <= 65535
        ):
            raise ValueError("source publish has no type or TCP port")
        size = values.get(0x02, 0)
        if not isinstance(size, int) or not 0 <= size < 2**64:
            raise ValueError("invalid source size")
        raw_tags = [raw for name, _value, raw in tags if name != 0xFE]
        raw_tags.insert(
            0,
            b"\x03\x01\x00\xfe"
            + struct.pack("<I", int(ipaddress.IPv4Address(publisher_ip))),
        )
        target, publisher = body[:16], body[16:32]
        record = publisher + bytes([len(raw_tags)]) + b"".join(raw_tags)
        total_bytes = sum(
            len(record)
            for sources in self._sources.values()
            for _size, record in sources.values()
        )
        sources = self._sources.get(target, {})
        old_bytes = len(sources[publisher][1]) if publisher in sources else 0
        if (
            target not in self._sources
            and len(self._sources) >= 64
            or publisher not in sources
            and len(sources) >= 32
            or total_bytes - old_bytes + len(record) > 65536
        ):
            self._counts["capacityRejects"] += 1
            return None
        self._sources.setdefault(target, {})[publisher] = (size, record)
        self._counts["sourcePublishes"] += 1
        return b"\xe4\x4b" + target + b"\x01"

    def _search_sources(self, body: bytes) -> bytes:
        if len(body) == 26:
            start, size = struct.unpack_from("<HQ", body, 16)
            start &= 0x7FFF
        elif len(body) in (20, 24):
            start = 0
            size = int.from_bytes(body[16:], "little")
        else:
            raise ValueError("invalid source search")
        records = [
            record
            for stored_size, record in self._sources.get(body[:16], {}).values()
            if size == 0 or stored_size == 0 or size == stored_size
        ][start:]
        selected = []
        payload_bytes = 36
        for record in records:
            if payload_bytes + len(record) > 60000:
                break
            selected.append(record)
            payload_bytes += len(record)
        self._counts["sourceSearches"] += 1
        self._counts["sourceResults"] += len(selected)
        self._last_source_reply = (
            b"\xe4\x3b"
            + self.node_id
            + body[:16]
            + struct.pack("<H", len(selected))
            + b"".join(selected)
        )
        return self._last_source_reply

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
