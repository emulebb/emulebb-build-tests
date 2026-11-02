"""Deterministic buddy/source probe for LowID relayed UDP reasks."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from dataclasses import dataclass


OP_EMULEPROT = 0xC5
OP_REASKACK = 0x91
OP_REASKCALLBACKUDP = 0x94
HASH_BYTES = 16
FIXED_CALLBACK_BYTES = 2 + HASH_BYTES + HASH_BYTES


def _hash16(value: bytes, field_name: str) -> bytes:
    result = bytes(value)
    if len(result) != HASH_BYTES:
        raise ValueError(f"{field_name} must contain exactly 16 bytes")
    return result


def _port(value: int, field_name: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= 0xFFFF
    ):
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return value


def _udp_version(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4:
        raise ValueError("udp_version must be between 1 and 4")
    return value


def _decode_part_status(data: bytes) -> tuple[int, bytes, bytes]:
    if len(data) < 2:
        raise ValueError("short relayed-reask part-count field")
    part_count = int.from_bytes(data[:2], "little")
    bitmap_bytes = (part_count + 7) // 8
    if len(data) < 2 + bitmap_bytes:
        raise ValueError("short relayed-reask part-status bitmap")
    return part_count, data[2 : 2 + bitmap_bytes], data[2 + bitmap_bytes :]


def decode_reask_callback_udp(
    raw: bytes,
    *,
    source_udp_version: int,
) -> dict[str, object]:
    """Decodes one exact plaintext ``OP_REASKCALLBACKUDP`` datagram."""

    source_udp_version = _udp_version(source_udp_version)
    raw = bytes(raw)
    if len(raw) < FIXED_CALLBACK_BYTES:
        raise ValueError("short OP_REASKCALLBACKUDP datagram")
    if raw[:2] != bytes((OP_EMULEPROT, OP_REASKCALLBACKUDP)):
        raise ValueError("unexpected relayed-reask protocol marker or opcode")
    buddy_id = raw[2:18]
    file_hash = raw[18:34]
    tail = raw[34:]
    part_count: int | None = None
    part_status_hex: str | None = None
    complete_source_count: int | None = None
    if source_udp_version > 3:
        part_count, part_status, tail = _decode_part_status(tail)
        part_status_hex = part_status.hex().upper()
    if source_udp_version > 2:
        if len(tail) < 2:
            raise ValueError("short relayed-reask complete-source count")
        complete_source_count = int.from_bytes(tail[:2], "little")
        tail = tail[2:]
    if tail:
        raise ValueError("trailing bytes in OP_REASKCALLBACKUDP datagram")
    return {
        "protocol": OP_EMULEPROT,
        "opcode": OP_REASKCALLBACKUDP,
        "rawHex": raw.hex().upper(),
        "payloadHex": raw[2:].hex().upper(),
        "buddyId": buddy_id.hex().upper(),
        "fileHash": file_hash.hex().upper(),
        "sourceUdpVersion": source_udp_version,
        "partCount": part_count,
        "partStatusHex": part_status_hex,
        "completeSourceCount": complete_source_count,
    }


def encode_reask_ack(
    *,
    queue_rank: int,
    requester_udp_version: int,
    part_status: tuple[bool, ...] | None = None,
) -> bytes:
    """Encodes the exact plaintext ACK a source sends after a relayed reask."""

    requester_udp_version = _udp_version(requester_udp_version)
    if (
        not isinstance(queue_rank, int)
        or isinstance(queue_rank, bool)
        or not 0 <= queue_rank <= 0xFFFF
    ):
        raise ValueError("queue_rank must fit in an unsigned 16-bit integer")
    body = bytearray()
    if requester_udp_version > 3:
        statuses = tuple(part_status or ())
        if len(statuses) > 0xFFFF:
            raise ValueError("part_status contains too many parts")
        body.extend(struct.pack("<H", len(statuses)))
        bitmap = bytearray((len(statuses) + 7) // 8)
        for index, available in enumerate(statuses):
            if available:
                bitmap[index // 8] |= 1 << (index % 8)
        body.extend(bitmap)
    body.extend(struct.pack("<H", queue_rank))
    return bytes((OP_EMULEPROT, OP_REASKACK)) + bytes(body)


@dataclass
class RelayedReaskProbe:
    """Receives a buddy callback and ACKs it from the configured source socket."""

    buddy_host: str
    buddy_udp_port: int
    source_host: str
    source_udp_port: int
    buddy_id: bytes
    file_hash: bytes
    source_udp_version: int = 4
    requester_udp_version: int = 4
    queue_rank: int = 37

    def __post_init__(self) -> None:
        ipaddress.IPv4Address(self.buddy_host)
        ipaddress.IPv4Address(self.source_host)
        self.buddy_udp_port = _port(self.buddy_udp_port, "buddy_udp_port")
        self.source_udp_port = _port(self.source_udp_port, "source_udp_port")
        self.buddy_id = _hash16(self.buddy_id, "buddy_id")
        self.file_hash = _hash16(self.file_hash, "file_hash")
        self.source_udp_version = _udp_version(self.source_udp_version)
        self.requester_udp_version = _udp_version(self.requester_udp_version)
        self._ack = encode_reask_ack(
            queue_rank=self.queue_rank,
            requester_udp_version=self.requester_udp_version,
        )
        self._buddy_socket: socket.socket | None = None
        self._source_socket: socket.socket | None = None

    @property
    def buddy_endpoint(self) -> str:
        return f"{self.buddy_host}:{self.buddy_udp_port}"

    @property
    def source_endpoint(self) -> str:
        return f"{self.source_host}:{self.source_udp_port}"

    def start(self) -> None:
        if self._buddy_socket is not None or self._source_socket is not None:
            raise RuntimeError("relayed-reask probe is already started")
        buddy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        source = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buddy.bind((self.buddy_host, self.buddy_udp_port))
            source.bind((self.source_host, self.source_udp_port))
        except BaseException:
            buddy.close()
            source.close()
            raise
        self._buddy_socket = buddy
        self._source_socket = source

    def receive_and_ack(
        self,
        *,
        target_label: str,
        expected_requester_host: str,
        expected_requester_udp_port: int,
        timeout_seconds: float,
    ) -> dict[str, object]:
        """Receives one exact request and returns its immutable probe transcript."""

        if self._buddy_socket is None or self._source_socket is None:
            raise RuntimeError("relayed-reask probe is not started")
        if not target_label:
            raise ValueError("target_label must be non-empty")
        ipaddress.IPv4Address(expected_requester_host)
        expected_requester_udp_port = _port(
            expected_requester_udp_port, "expected_requester_udp_port"
        )
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._buddy_socket.settimeout(timeout_seconds)
        raw, requester = self._buddy_socket.recvfrom(65_535)
        received_at = time.time()
        expected_requester = (expected_requester_host, expected_requester_udp_port)
        if requester != expected_requester:
            raise RuntimeError(
                "relayed-reask request used an unexpected source endpoint: "
                f"expected={expected_requester!r} actual={requester!r}"
            )
        request = decode_reask_callback_udp(
            raw,
            source_udp_version=self.source_udp_version,
        )
        if request["buddyId"] != self.buddy_id.hex().upper():
            raise RuntimeError("relayed-reask request carried an unexpected buddy ID")
        if request["fileHash"] != self.file_hash.hex().upper():
            raise RuntimeError("relayed-reask request carried an unexpected file hash")
        sent_bytes = self._source_socket.sendto(self._ack, requester)
        sent_at = time.time()
        if sent_bytes != len(self._ack):
            raise RuntimeError(
                f"relayed-reask ACK wrote {sent_bytes} of {len(self._ack)} bytes"
            )
        return {
            "schema": "emulebb.relayed-reask-probe/1",
            "status": "completed",
            "targetLabel": target_label,
            "buddyEndpoint": self.buddy_endpoint,
            "sourceEndpoint": self.source_endpoint,
            "requesterEndpoint": f"{requester[0]}:{requester[1]}",
            "request": {**request, "receivedAt": received_at},
            "response": {
                "protocol": OP_EMULEPROT,
                "opcode": OP_REASKACK,
                "rawHex": self._ack.hex().upper(),
                "payloadHex": self._ack[2:].hex().upper(),
                "queueRank": self.queue_rank,
                "sentBytes": sent_bytes,
                "sentAt": sent_at,
            },
        }

    def close(self) -> None:
        buddy, source = self._buddy_socket, self._source_socket
        self._buddy_socket = None
        self._source_socket = None
        if buddy is not None:
            buddy.close()
        if source is not None:
            source.close()

    def __enter__(self) -> "RelayedReaskProbe":
        self.start()
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()
