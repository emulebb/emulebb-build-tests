"""Reverse two valid store replies at one local peer and witness the keyed ACK."""

from __future__ import annotations

import secrets
import socket
import time

from .buddy_callback_probe import _kad_uint128_wire_bytes
from .kad_fixture_envelope import decode_fixture_packet, encode_receiver_key_packet
from .local_kad_peer import LocalKadPeer
from .scripted_actions import _md4_digest

FILE_NAME = "paritycorrelation"
ACK_REQUESTER_KEY = 0x42DA1056


def fixture_targets() -> tuple[bytes, bytes, bytes]:
    """Choose a file and keyword with a common prefix for the same traversal order."""
    keyword = _md4_digest(FILE_NAME.encode("ascii"))
    for index in range(4096):
        content = b"Kad reply correlation fixture\x00" + index.to_bytes(4, "little")
        file_hash = _md4_digest(content)
        if file_hash[:1] == keyword[:1] and file_hash != keyword:
            return (
                content,
                _kad_uint128_wire_bytes(file_hash, "file hash"),
                _kad_uint128_wire_bytes(keyword, "keyword hash"),
            )
    raise RuntimeError("Unable to choose a bounded pair of synthetic Kad targets")


class CorrelationPeer(LocalKadPeer):
    """Track two concurrent targets and request a keyed ACK from an alternate port."""

    def __init__(self, *args, targets: tuple[bytes, bytes], **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._targets = targets
        self._envelope_key = 0x431BA552
        self._reply_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._reply_socket.bind((self.bind_ip, 0))
        except BaseException:
            self._reply_socket.close()
            super().close()
            raise
        self._reply_socket.setblocking(False)
        self._pending: dict[str, dict[bytes, tuple[tuple[str, int], int]]] = {
            "lookup": {},
            "publish": {},
        }
        self._reversed: dict[str, list[str]] = {}
        self._primary_acks = 0
        self._ack_endpoint: tuple[str, int] | None = None
        self._ack_requested_at: float | None = None

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._reply_socket.close()

    def _handle_udp(self) -> None:
        wire, peer = self._udp.recvfrom(65536)
        if peer[0] not in self.allowed_peers:
            return
        try:
            packet, sender_key = decode_fixture_packet(wire, self.node_id, self._envelope_key)
            self._handle_decoded(packet, peer, sender_key)
        except ValueError:
            self._counts["malformedKadPackets"] += 1

    def _reply(self, stream: socket.socket, packet: bytes, endpoint: tuple[str, int], receiver_key: int) -> None:
        if receiver_key:
            packet = encode_receiver_key_packet(
                packet,
                receiver_key,
                secrets.randbits(16),
                sender_key=ACK_REQUESTER_KEY if stream is self._reply_socket else self._envelope_key,
            )
        stream.sendto(packet, endpoint)

    def _handle_decoded(self, packet: bytes, endpoint: tuple[str, int], sender_key: int) -> None:
        if len(packet) < 2:
            raise ValueError("Truncated Kad fixture payload")
        if packet == b"\xe4\x4c":
            self._primary_acks += 1
            return
        opcode = packet[1]
        body = packet[2:]
        family = None
        target = None
        if opcode == 0x21 and len(body) == 33 and body[0] == 4 and body[17:] == self.node_id:
            family, target = "lookup", body[1:17]
        elif opcode in {0x43, 0x44} and len(body) >= 16:
            family, target = "publish", body[:16]

        if family is None or target not in self._targets:
            reply = self._kad_reply(packet, endpoint)
            if reply is not None:
                self._reply(self._udp, reply, endpoint, sender_key)
            return
        if family in self._reversed:
            return
        if (family == "publish" and
                opcode != (0x44 if target == self._targets[0] else 0x43)):
            raise ValueError("Kad publish kind disagrees with the fixture target")
        pending = self._pending[family]
        pending.setdefault(target, (endpoint, sender_key))
        if len(pending) != 2:
            return

        arrival_order = list(pending)
        for reply_target in reversed(arrival_order):
            reply_endpoint, reply_key = pending[reply_target]
            if family == "lookup":
                self._reply(self._udp, b"\xe4\x29" + reply_target + b"\x00", reply_endpoint, reply_key)
            else:
                load = 17 if reply_target == self._targets[0] else 63
                ask_ack = reply_target == self._targets[0]
                if ask_ack and not reply_key:
                    raise ValueError("The staged runtime sent the source publish without a sender verify key")
                socket_used = self._reply_socket if ask_ack else self._udp
                self._reply(
                    socket_used,
                    b"\xe4\x4b" + reply_target + bytes((load, int(ask_ack))),
                    reply_endpoint,
                    reply_key,
                )
                if ask_ack:
                    self._ack_endpoint = reply_endpoint
                    self._ack_requested_at = time.monotonic()
        self._reversed[family] = [target.hex() for target in arrival_order]

    def witness(self) -> dict[str, object] | None:
        """Return evidence only after both reordered exchanges and a keyed alternate-port ACK."""
        if len(self._reversed) != 2 or self._ack_requested_at is None:
            return None
        # Let the primary endpoint's receive loop settle after the reply.
        if time.monotonic() - self._ack_requested_at < 0.5:
            return None
        if self._primary_acks:
            raise RuntimeError("Rust sent the ACK to the initial request port")
        try:
            wire, endpoint = self._reply_socket.recvfrom(128)
        except BlockingIOError:
            return None
        packet, _ = decode_fixture_packet(wire, self.node_id, ACK_REQUESTER_KEY)
        if wire[:1] == b"\xe4" or packet != b"\xe4\x4c" or endpoint != self._ack_endpoint:
            raise RuntimeError("The alternate port did not receive the matching keyed Kad publish ACK")
        return {
            "requestTargets": dict(self._reversed),
            "replyTargets": {family: list(reversed(order)) for family, order in self._reversed.items()},
            "loadsByTarget": {self._targets[0].hex(): 17, self._targets[1].hex(): 63},
            "requestPort": self.udp_port,
            "replyPort": self._reply_socket.getsockname()[1],
            "keyedAckAtReplyPort": True,
        }
