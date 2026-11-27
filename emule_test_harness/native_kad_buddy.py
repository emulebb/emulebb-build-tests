"""Hold selected outgoing Kad buddy offers until the native controller releases them."""

from __future__ import annotations

import ipaddress
import select
import socket
import struct
import threading

from . import buddy_callback_probe, ed2k_wire
from .docker_ed2k_source_publisher import encode_hello_answer
from .local_kad_peer import LocalKadPeer, receive_frame


class OutboundBuddyOffers:
    """Coordinate a failed initial HELLO and a second offer on another local peer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.first = None
        self.reserve = None
        self.first_hello = threading.Event()
        self.reserve_offer = threading.Event()
        self.fail_first = threading.Event()
        self.ready_socket = threading.Event()
        self.close_reserve = threading.Event()
        self._reserved_socket = None
        self.buddy_id = None

    def claim(self, peer: BuddyCandidate, target: bytes) -> bool:
        """Only the first two peers can answer the current buddy discovery."""
        with self._lock:
            if self.first is None:
                self.first = peer
                self.buddy_id = target
                return True
            if target != self.buddy_id or self.first is peer or self.reserve is not None:
                return False
            self.reserve = peer
        return self.first_hello.wait(3)

    def relay(self, file_hash: bytes, requester: tuple[str, int]) -> None:
        """Send the selected file's callback over the established reserve link."""
        with self._lock:
            stream = self._reserved_socket
            buddy_id = self.buddy_id
        if stream is None or buddy_id is None:
            raise RuntimeError("The reserve buddy is not attached")
        target = struct.pack("<IH", int(ipaddress.IPv4Address(requester[0])), requester[1])
        wire_hash = buddy_callback_probe._kad_uint128_wire_bytes(file_hash, "file_hash")
        payload = buddy_id + wire_hash + target
        stream.sendall(struct.pack("<BIB", ed2k_wire.PROTO_EMULE, len(payload) + 1, 0x99) + payload)

    def stop(self) -> None:
        self.fail_first.set()
        self.close_reserve.set()


class BuddyCandidate(LocalKadPeer):
    """Local Kad route peer with a held TCP buddy handshake for this scenario."""

    def __init__(self, *args, offers: OutboundBuddyOffers, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.offers = offers
        self.user_hash = b"buddy-fixture" + socket.inet_aton(self.bind_ip)[1:]

    def _kad_reply(self, packet: bytes, peer: tuple[str, int]) -> bytes | None:
        if packet[:2] != b"\xe4\x51":
            return super()._kad_reply(packet, peer)
        if len(packet) != 36 or not self.offers.claim(self, packet[2:18]):
            return None
        user_hash = buddy_callback_probe._kad_uint128_wire_bytes(self.user_hash, "buddy_user_hash")
        if self.offers.reserve is self:
            self.offers.reserve_offer.set()
        return b"\xe4\x5a" + packet[2:18] + user_hash + struct.pack("<H", self.tcp_port)

    def _handle_tcp(self, stream: socket.socket, peer_ip: str) -> None:
        marker, opcode, payload = receive_frame(stream)
        if (marker, opcode) != (ed2k_wire.PROTO_EDONKEY, 0x01) or payload[:1] != b"\x10":
            raise ed2k_wire.Ed2kWireError("Buddy candidate did not receive a complete HELLO")
        if self.offers.first is self:
            self.offers.first_hello.set()
            self.offers.fail_first.wait(7)
            return
        if self.offers.reserve is not self:
            raise ValueError("An unselected peer received the buddy TCP connection")

        stream.sendall(encode_hello_answer(
            user_hash=self.user_hash,
            client_id=int.from_bytes(socket.inet_aton(self.bind_ip), "little"),
            tcp_port=self.tcp_port,
            kad_udp_port=self.udp_port,
        ))
        with self.offers._lock:
            self.offers._reserved_socket = stream
        self.offers.ready_socket.set()
        try:
            while not self._stop.is_set() and not self.offers.close_reserve.is_set():
                if not select.select([stream], [], [], 0.1)[0]:
                    continue
                marker, opcode, payload = receive_frame(stream)
                if (marker, opcode, payload) == (ed2k_wire.PROTO_EMULE, 0x9F, b""):
                    stream.sendall(struct.pack("<BIB", ed2k_wire.PROTO_EMULE, 1, 0xA0))
        finally:
            with self.offers._lock:
                self.offers._reserved_socket = None


def sample_buddy_tags(bind: str, tcp_port: int) -> tuple[int, int] | None:
    """Read only the buddy tags from a new, isolated HELLO exchange."""
    with socket.create_connection((bind, tcp_port), timeout=2) as stream:
        own_port = stream.getsockname()[1]
        stream.sendall(buddy_callback_probe.encode_hello_request(
            user_hash=b"fixture-inspect!", client_id=11, tcp_port=own_port,
        ))
        marker, opcode, payload = receive_frame(stream)
        if (marker, opcode) == (ed2k_wire.PROTO_EMULE, 0x01):
            marker, opcode, payload = receive_frame(stream)
    if (marker, opcode) != (ed2k_wire.PROTO_EDONKEY, 0x4C) or len(payload) < 32:
        raise ed2k_wire.Ed2kWireError("Buddy advertisement probe did not receive a HELLOANSWER")
    count = struct.unpack_from("<I", payload, 22)[0]
    tags = {name: value for name, value, _raw in ed2k_wire.decode_tag_sequence(payload[26:-6], count)}
    ip, port = tags.get(0xFC), tags.get(0xFD)
    if (ip is None) != (port is None):
        raise RuntimeError("Rust advertised only one of the two buddy HELLO tags")
    return (int(ip), int(port) & 0xFFFF) if ip is not None else None
