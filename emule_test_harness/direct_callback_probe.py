"""Exact local ``OP_DIRECTCALLBACKREQ`` stimulus and TCP identity observation."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from dataclasses import dataclass

from emule_test_harness.docker_ed2k_source_publisher import (
    PlainEd2kIdentityProbeListener,
)


OP_EMULEPROT = 0xC5
OP_DIRECTCALLBACKREQ = 0x95
DIRECT_CALLBACK_REQUEST_BYTES = 21


def _validate_hash(user_hash: bytes) -> bytes:
    value = bytes(user_hash)
    if len(value) != 16:
        raise ValueError("user_hash must contain exactly 16 bytes")
    return value


def _validate_port(port: int, field_name: str) -> int:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 0xFFFF:
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return port


def high_id_for_ipv4(address: str) -> int:
    """Returns the stock little-endian HighID representation for one IPv4."""

    return int.from_bytes(ipaddress.IPv4Address(address).packed, "little")


def encode_direct_callback_request(
    *,
    tcp_port: int,
    user_hash: bytes,
    connect_options: int,
) -> bytes:
    """Encodes the stock 21-byte client-UDP direct-callback datagram."""

    _validate_port(tcp_port, "tcp_port")
    user_hash = _validate_hash(user_hash)
    if (
        not isinstance(connect_options, int)
        or isinstance(connect_options, bool)
        or not 0 <= connect_options <= 0xFF
    ):
        raise ValueError("connect_options must fit in one byte")
    return (
        bytes((OP_EMULEPROT, OP_DIRECTCALLBACKREQ))
        + struct.pack("<H", tcp_port)
        + user_hash
        + bytes((connect_options,))
    )


@dataclass
class DirectCallbackProbe:
    """Owns one local requester identity and emits callback requests from its IP."""

    bind_host: str
    tcp_port: int
    user_hash: bytes
    connect_options: int = 0x01

    def __post_init__(self) -> None:
        ipaddress.IPv4Address(self.bind_host)
        _validate_port(self.tcp_port, "tcp_port")
        self.user_hash = _validate_hash(self.user_hash)
        self.listener = PlainEd2kIdentityProbeListener(
            self.tcp_port,
            self.user_hash,
            bind_host=self.bind_host,
            client_id=high_id_for_ipv4(self.bind_host),
        )

    def start(self) -> None:
        self.listener.start()

    def request(
        self,
        *,
        target_host: str,
        target_udp_port: int,
        target_label: str,
        timeout_seconds: float,
    ) -> dict[str, object]:
        """Sends one exact request and waits for the resulting peer HELLO."""

        ipaddress.IPv4Address(target_host)
        _validate_port(target_udp_port, "target_udp_port")
        if not target_label:
            raise ValueError("target_label must be non-empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        raw = encode_direct_callback_request(
            tcp_port=self.tcp_port,
            user_hash=self.user_hash,
            connect_options=self.connect_options,
        )
        observation_index = self.listener.observation_count()
        attempt_index = self.listener.connection_attempt_count()
        sent_at = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind((self.bind_host, 0))
            source_host, source_port = sender.getsockname()
            sent_bytes = sender.sendto(raw, (target_host, target_udp_port))
        if sent_bytes != len(raw):
            raise RuntimeError(
                f"direct-callback UDP send wrote {sent_bytes} of {len(raw)} bytes"
            )
        try:
            callback_connection = self.listener.wait_for_observation_after(
                observation_index,
                timeout_seconds,
            )
        except TimeoutError as exc:
            attempts = self.listener.connection_attempts_after(attempt_index)
            raise TimeoutError(
                f"Timed out waiting for {target_label} direct-callback HELLO; "
                f"connectionAttempts={attempts!r}"
            ) from exc
        return {
            "schema": "emulebb.direct-callback-probe/1",
            "status": "completed",
            "targetLabel": target_label,
            "source": {"host": source_host, "udpPort": source_port},
            "target": {"host": target_host, "udpPort": target_udp_port},
            "requester": {
                "tcpPort": self.tcp_port,
                "userHash": self.user_hash.hex().upper(),
                "clientId": high_id_for_ipv4(self.bind_host),
                "connectOptions": self.connect_options,
            },
            "request": {
                "protocol": OP_EMULEPROT,
                "opcode": OP_DIRECTCALLBACKREQ,
                "rawHex": raw.hex().upper(),
                "payloadHex": raw[2:].hex().upper(),
                "sentBytes": sent_bytes,
                "sentAt": sent_at,
            },
            "callbackConnection": callback_connection,
        }

    def close(self) -> None:
        self.listener.close()

    def __enter__(self) -> "DirectCallbackProbe":
        self.start()
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()
