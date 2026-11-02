"""Deterministic Kad buddy-callback relay probe for local parity campaigns."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
import zlib
from dataclasses import dataclass

from emule_test_harness import ed2k_wire
from emule_test_harness.docker_ed2k_source_publisher import (
    OP_HELLO,
    OP_HELLOANSWER,
    PlainEd2kIdentityProbeListener,
)


OP_KADEMLIAHEADER = 0xE4
KADEMLIA_FINDBUDDY_REQ = 0x51
KADEMLIA_CALLBACK_REQ = 0x52
KADEMLIA_FINDBUDDY_RES = 0x5A

OP_EMULEPROT = 0xC5
OP_CALLBACK = 0x99
HASH_BYTES = 16
KAD_BUDDY_PAYLOAD_BYTES = 34
KAD_BUDDY_DATAGRAM_BYTES = 2 + KAD_BUDDY_PAYLOAD_BYTES
CALLBACK_RELAY_PAYLOAD_BYTES = 38


def _hash16(value: bytes, field_name: str) -> bytes:
    result = bytes(value)
    if len(result) != HASH_BYTES:
        raise ValueError(f"{field_name} must contain exactly 16 bytes")
    return result


def _kad_uint128_wire_bytes(value: bytes, field_name: str) -> bytes:
    """Converts a canonical hash to/from stock eMule `CUInt128` wire order."""

    canonical = _hash16(value, field_name)
    return b"".join(
        canonical[offset : offset + 4][::-1] for offset in range(0, HASH_BYTES, 4)
    )


def _port(value: int, field_name: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= 0xFFFF
    ):
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return value


def _u32(value: int, field_name: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFF_FFFF
    ):
        raise ValueError(f"{field_name} must fit in an unsigned 32-bit integer")
    return value


def _timeout(value: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        raise ValueError("timeout_seconds must be positive")
    return float(value)


def _endpoint(host: str, port: int) -> str:
    return f"{host}:{port}"


def encode_find_buddy_request(
    *,
    buddy_id: bytes,
    client_hash: bytes,
    tcp_port: int,
) -> bytes:
    """Encodes one plaintext stock ``KADEMLIA_FINDBUDDY_REQ`` datagram."""

    buddy_id = _hash16(buddy_id, "buddy_id")
    client_hash = _hash16(client_hash, "client_hash")
    tcp_port = _port(tcp_port, "tcp_port")
    return (
        bytes((OP_KADEMLIAHEADER, KADEMLIA_FINDBUDDY_REQ))
        + buddy_id
        + _kad_uint128_wire_bytes(client_hash, "client_hash")
        + struct.pack("<H", tcp_port)
    )


def decode_find_buddy_response(raw: bytes) -> dict[str, object]:
    """Decodes the stock 34-byte response plus its optional options byte."""

    raw = bytes(raw)
    if len(raw) not in {KAD_BUDDY_DATAGRAM_BYTES, KAD_BUDDY_DATAGRAM_BYTES + 1}:
        raise ValueError(
            "KADEMLIA_FINDBUDDY_RES must contain exactly 34 payload bytes "
            "and at most one connect-options byte"
        )
    if raw[:2] != bytes((OP_KADEMLIAHEADER, KADEMLIA_FINDBUDDY_RES)):
        raise ValueError("unexpected FINDBUDDY response protocol marker or opcode")
    return {
        "protocol": OP_KADEMLIAHEADER,
        "opcode": KADEMLIA_FINDBUDDY_RES,
        "rawHex": raw.hex().upper(),
        "payloadHex": raw[2:].hex().upper(),
        "buddyId": raw[2:18].hex().upper(),
        "clientHash": _kad_uint128_wire_bytes(raw[18:34], "client_hash_wire")
        .hex()
        .upper(),
        "clientHashWireHex": raw[18:34].hex().upper(),
        "tcpPort": int.from_bytes(raw[34:36], "little"),
        "connectOptions": raw[36] if len(raw) == 37 else None,
    }


def encode_callback_request(
    *,
    buddy_id: bytes,
    file_hash: bytes,
    requester_tcp_port: int,
) -> bytes:
    """Encodes one plaintext stock ``KADEMLIA_CALLBACK_REQ`` datagram."""

    buddy_id = _hash16(buddy_id, "buddy_id")
    file_hash = _hash16(file_hash, "file_hash")
    requester_tcp_port = _port(requester_tcp_port, "requester_tcp_port")
    return (
        bytes((OP_KADEMLIAHEADER, KADEMLIA_CALLBACK_REQ))
        + buddy_id
        + _kad_uint128_wire_bytes(file_hash, "file_hash")
        + struct.pack("<H", requester_tcp_port)
    )


def encode_hello_request(
    *,
    user_hash: bytes,
    client_id: int,
    tcp_port: int,
) -> bytes:
    """Encodes a minimal complete stock-shaped peer ``OP_HELLO`` frame."""

    user_hash = _hash16(user_hash, "user_hash")
    client_id = _u32(client_id, "client_id")
    tcp_port = _port(tcp_port, "tcp_port")
    payload = (
        bytes((HASH_BYTES,))
        + user_hash
        + struct.pack("<IH", client_id, tcp_port)
        + struct.pack("<I", 0)  # tag count
        + struct.pack("<IH", 0, 0)  # server IPv4 and port
    )
    return ed2k_wire.encode_frame(OP_HELLO, payload)


@dataclass(frozen=True)
class _Frame:
    marker: int
    opcode: int
    payload: bytes
    raw: bytes

    def evidence(self) -> dict[str, object]:
        return {
            "protocol": self.marker,
            "opcode": self.opcode,
            "rawHex": self.raw.hex().upper(),
            "payloadHex": self.payload.hex().upper(),
            "payloadLength": len(self.payload),
        }


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise ed2k_wire.Ed2kWireError(
                f"buddy-callback connection closed with {size - len(data)} bytes outstanding"
            )
        data.extend(chunk)
    return bytes(data)


def _decode_frame(raw: bytes) -> _Frame:
    raw = bytes(raw)
    if len(raw) < 6:
        raise ed2k_wire.Ed2kWireError(
            "buddy-callback frame is shorter than its six-byte header"
        )
    header = raw[:6]
    marker = header[0]
    if marker not in {
        ed2k_wire.PROTO_EDONKEY,
        ed2k_wire.PROTO_PACKED,
        OP_EMULEPROT,
    }:
        raise ed2k_wire.Ed2kWireError(
            f"unsupported buddy-callback protocol marker 0x{marker:02X}"
        )
    declared = int.from_bytes(header[1:5], "little")
    if declared < 1 or declared > ed2k_wire.MAX_FRAME_BYTES:
        raise ed2k_wire.Ed2kWireError(f"invalid buddy-callback frame length {declared}")
    if len(raw) != declared + 5:
        raise ed2k_wire.Ed2kWireError(
            "buddy-callback frame length mismatch: "
            f"declared {declared + 5}, received {len(raw)}"
        )
    payload = raw[6:]
    if marker == ed2k_wire.PROTO_PACKED:
        try:
            payload = zlib.decompress(payload)
        except zlib.error as exc:
            raise ed2k_wire.Ed2kWireError(
                f"packed buddy-callback frame decompression failed: {exc}"
            ) from exc
        if len(payload) > ed2k_wire.MAX_FRAME_BYTES:
            raise ed2k_wire.Ed2kWireError(
                "packed buddy-callback frame expands beyond the harness limit"
            )
    return _Frame(marker=marker, opcode=raw[5], payload=payload, raw=raw)


def _recv_frame(stream: socket.socket) -> _Frame:
    header = _recv_exact(stream, 6)
    declared = int.from_bytes(header[1:5], "little")
    if declared < 1 or declared > ed2k_wire.MAX_FRAME_BYTES:
        raise ed2k_wire.Ed2kWireError(f"invalid buddy-callback frame length {declared}")
    return _decode_frame(header + _recv_exact(stream, declared - 1))


def decode_hello_answer(frame: _Frame) -> dict[str, object]:
    """Returns the identity prefix from one complete ``OP_HELLOANSWER``."""

    if frame.marker != ed2k_wire.PROTO_EDONKEY or frame.opcode != OP_HELLOANSWER:
        raise ValueError("expected a clear OP_HELLOANSWER frame")
    if len(frame.payload) < 22:
        raise ValueError("OP_HELLOANSWER identity prefix is truncated")
    return {
        **frame.evidence(),
        "userHash": frame.payload[:16].hex().upper(),
        "clientId": int.from_bytes(frame.payload[16:20], "little"),
        "tcpPort": int.from_bytes(frame.payload[20:22], "little"),
    }


def decode_callback_relay(raw: bytes) -> dict[str, object]:
    """Decodes the exact stock ``OP_CALLBACK`` relayed on the buddy socket."""

    frame = _decode_frame(raw)
    if frame.marker != OP_EMULEPROT or frame.opcode != OP_CALLBACK:
        raise ValueError("expected an OP_EMULEPROT OP_CALLBACK frame")
    if len(frame.payload) != CALLBACK_RELAY_PAYLOAD_BYTES:
        raise ValueError("OP_CALLBACK relay payload must contain exactly 38 bytes")
    requester_host = str(
        ipaddress.IPv4Address(int.from_bytes(frame.payload[32:36], "little"))
    )
    return {
        **frame.evidence(),
        "buddyId": frame.payload[:16].hex().upper(),
        "fileHash": _kad_uint128_wire_bytes(frame.payload[16:32], "file_hash_wire")
        .hex()
        .upper(),
        "fileHashWireHex": frame.payload[16:32].hex().upper(),
        "requesterHost": requester_host,
        "requesterTcpPort": int.from_bytes(frame.payload[36:38], "little"),
    }


def _wait_for_frame(
    stream: socket.socket,
    *,
    marker: int,
    opcode: int,
) -> tuple[_Frame, list[dict[str, object]]]:
    preceding: list[dict[str, object]] = []
    while True:
        frame = _recv_frame(stream)
        if frame.marker == marker and frame.opcode == opcode:
            return frame, preceding
        preceding.append(frame.evidence())


@dataclass
class BuddyCallbackProbe:
    """Acts as a LowID buddy peer and an independent callback requester."""

    bind_host: str
    buddy_tcp_port: int
    buddy_udp_port: int
    buddy_user_hash: bytes
    buddy_id: bytes
    file_hash: bytes
    requester_tcp_port: int
    requester_user_hash: bytes
    buddy_client_id: int = 7

    def __post_init__(self) -> None:
        ipaddress.IPv4Address(self.bind_host)
        self.buddy_tcp_port = _port(self.buddy_tcp_port, "buddy_tcp_port")
        self.buddy_udp_port = _port(self.buddy_udp_port, "buddy_udp_port")
        self.buddy_user_hash = _hash16(self.buddy_user_hash, "buddy_user_hash")
        self.buddy_id = _hash16(self.buddy_id, "buddy_id")
        self.file_hash = _hash16(self.file_hash, "file_hash")
        self.requester_tcp_port = _port(self.requester_tcp_port, "requester_tcp_port")
        self.requester_user_hash = _hash16(
            self.requester_user_hash, "requester_user_hash"
        )
        self.buddy_client_id = _u32(self.buddy_client_id, "buddy_client_id")
        self._buddy_udp_socket: socket.socket | None = None
        self._requester_listener = PlainEd2kIdentityProbeListener(
            self.requester_tcp_port,
            self.requester_user_hash,
            bind_host=self.bind_host,
            client_id=int.from_bytes(
                ipaddress.IPv4Address(self.bind_host).packed, "little"
            ),
        )

    def start(self) -> None:
        if self._buddy_udp_socket is not None:
            raise RuntimeError("buddy-callback probe is already started")
        buddy_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buddy_udp.bind((self.bind_host, self.buddy_udp_port))
            self._requester_listener.start()
        except BaseException:
            buddy_udp.close()
            self._requester_listener.close()
            raise
        self._buddy_udp_socket = buddy_udp

    def request(
        self,
        *,
        target_label: str,
        target_host: str,
        target_tcp_port: int,
        target_udp_port: int,
        target_user_hash: bytes,
        target_server_client_id: int,
        target_peer_hello_client_id: int,
        timeout_seconds: float,
    ) -> dict[str, object]:
        """Exercises discovery, held relay, callback, and resulting peer HELLO."""

        buddy_udp = self._buddy_udp_socket
        if buddy_udp is None:
            raise RuntimeError("buddy-callback probe is not started")
        if not target_label:
            raise ValueError("target_label must be non-empty")
        ipaddress.IPv4Address(target_host)
        target_tcp_port = _port(target_tcp_port, "target_tcp_port")
        target_udp_port = _port(target_udp_port, "target_udp_port")
        target_user_hash = _hash16(target_user_hash, "target_user_hash")
        target_server_client_id = _u32(
            target_server_client_id, "target_server_client_id"
        )
        target_peer_hello_client_id = _u32(
            target_peer_hello_client_id, "target_peer_hello_client_id"
        )
        timeout_seconds = _timeout(timeout_seconds)
        target_udp_endpoint = (target_host, target_udp_port)
        target_tcp_endpoint = (target_host, target_tcp_port)
        buddy_udp.settimeout(timeout_seconds)

        find_request = encode_find_buddy_request(
            buddy_id=self.buddy_id,
            client_hash=self.buddy_user_hash,
            tcp_port=self.buddy_tcp_port,
        )
        find_sent_at = time.time()
        find_sent_bytes = buddy_udp.sendto(find_request, target_udp_endpoint)
        if find_sent_bytes != len(find_request):
            raise RuntimeError(
                f"FINDBUDDY_REQ wrote {find_sent_bytes} of {len(find_request)} bytes"
            )
        find_response_raw, find_response_source = buddy_udp.recvfrom(65_535)
        find_received_at = time.time()
        if find_response_source != target_udp_endpoint:
            raise RuntimeError(
                "FINDBUDDY_RES used an unexpected source endpoint: "
                f"expected={target_udp_endpoint!r} actual={find_response_source!r}"
            )
        find_response = decode_find_buddy_response(find_response_raw)
        if find_response["buddyId"] != self.buddy_id.hex().upper():
            raise RuntimeError("FINDBUDDY_RES carried an unexpected buddy ID")
        if find_response["clientHash"] != target_user_hash.hex().upper():
            raise RuntimeError("FINDBUDDY_RES carried an unexpected target client hash")
        if find_response["tcpPort"] != target_tcp_port:
            raise RuntimeError("FINDBUDDY_RES carried an unexpected target TCP port")
        if find_response["connectOptions"] is not None:
            raise RuntimeError(
                "plain FINDBUDDY_REQ unexpectedly received keyed connect options"
            )

        hello_request = encode_hello_request(
            user_hash=self.buddy_user_hash,
            client_id=self.buddy_client_id,
            tcp_port=self.buddy_tcp_port,
        )
        held_socket = socket.create_connection(
            target_tcp_endpoint,
            timeout=timeout_seconds,
            source_address=(self.bind_host, 0),
        )
        try:
            held_socket.settimeout(timeout_seconds)
            held_source = held_socket.getsockname()
            hello_sent_at = time.time()
            held_socket.sendall(hello_request)
            hello_answer_frame, hello_preceding = _wait_for_frame(
                held_socket,
                marker=ed2k_wire.PROTO_EDONKEY,
                opcode=OP_HELLOANSWER,
            )
            hello_answer_received_at = time.time()
            hello_answer = decode_hello_answer(hello_answer_frame)
            if hello_answer["userHash"] != target_user_hash.hex().upper():
                raise RuntimeError("OP_HELLOANSWER carried an unexpected target hash")
            if hello_answer["clientId"] != target_peer_hello_client_id:
                raise RuntimeError(
                    "OP_HELLOANSWER carried an unexpected target client ID"
                )
            if hello_answer["tcpPort"] != target_tcp_port:
                raise RuntimeError(
                    "OP_HELLOANSWER carried an unexpected target TCP port"
                )

            callback_request = encode_callback_request(
                buddy_id=self.buddy_id,
                file_hash=self.file_hash,
                requester_tcp_port=self.requester_tcp_port,
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as requester_udp:
                requester_udp.bind((self.bind_host, 0))
                requester_udp.settimeout(timeout_seconds)
                requester_udp_endpoint = requester_udp.getsockname()
                callback_sent_at = time.time()
                callback_sent_bytes = requester_udp.sendto(
                    callback_request, target_udp_endpoint
                )
            if callback_sent_bytes != len(callback_request):
                raise RuntimeError(
                    "CALLBACK_REQ wrote "
                    f"{callback_sent_bytes} of {len(callback_request)} bytes"
                )

            relay_frame, relay_preceding = _wait_for_frame(
                held_socket,
                marker=OP_EMULEPROT,
                opcode=OP_CALLBACK,
            )
            relay_received_at = time.time()
            relay = decode_callback_relay(relay_frame.raw)
            if relay["buddyId"] != self.buddy_id.hex().upper():
                raise RuntimeError("OP_CALLBACK carried an unexpected buddy ID")
            if relay["fileHash"] != self.file_hash.hex().upper():
                raise RuntimeError("OP_CALLBACK carried an unexpected file hash")
            if relay["requesterHost"] != requester_udp_endpoint[0]:
                raise RuntimeError("OP_CALLBACK carried an unexpected requester host")
            if relay["requesterTcpPort"] != self.requester_tcp_port:
                raise RuntimeError(
                    "OP_CALLBACK carried an unexpected requester TCP port"
                )

            observation_index = self._requester_listener.observation_count()
            attempt_index = self._requester_listener.connection_attempt_count()
            callback_hello = encode_hello_request(
                user_hash=self.buddy_user_hash,
                client_id=self.buddy_client_id,
                tcp_port=self.buddy_tcp_port,
            )
            callback_socket = socket.create_connection(
                (relay["requesterHost"], relay["requesterTcpPort"]),
                timeout=timeout_seconds,
                source_address=(self.bind_host, 0),
            )
            try:
                callback_socket.settimeout(timeout_seconds)
                callback_source = callback_socket.getsockname()
                callback_hello_sent_at = time.time()
                callback_socket.sendall(callback_hello)
                callback_answer_frame, callback_preceding = _wait_for_frame(
                    callback_socket,
                    marker=ed2k_wire.PROTO_EDONKEY,
                    opcode=OP_HELLOANSWER,
                )
                callback_answer_received_at = time.time()
                callback_answer = decode_hello_answer(callback_answer_frame)
            finally:
                callback_socket.close()
            try:
                callback_connection = (
                    self._requester_listener.wait_for_observation_after(
                        observation_index,
                        timeout_seconds,
                    )
                )
            except TimeoutError as exc:
                attempts = self._requester_listener.connection_attempts_after(
                    attempt_index
                )
                raise TimeoutError(
                    f"Timed out waiting for {target_label} resulting buddy HELLO; "
                    f"connectionAttempts={attempts!r}"
                ) from exc
        finally:
            held_socket.close()

        return {
            "schema": "emulebb.buddy-callback-probe/1",
            "status": "completed",
            "targetLabel": target_label,
            "target": {
                "host": target_host,
                "tcpPort": target_tcp_port,
                "udpPort": target_udp_port,
                "userHash": target_user_hash.hex().upper(),
                "serverClientId": target_server_client_id,
                "peerHelloClientId": target_peer_hello_client_id,
            },
            "buddy": {
                "host": self.bind_host,
                "tcpPort": self.buddy_tcp_port,
                "udpPort": self.buddy_udp_port,
                "userHash": self.buddy_user_hash.hex().upper(),
                "clientId": self.buddy_client_id,
                "buddyId": self.buddy_id.hex().upper(),
            },
            "requester": {
                "host": self.bind_host,
                "tcpPort": self.requester_tcp_port,
                "udpPort": requester_udp_endpoint[1],
                "userHash": self.requester_user_hash.hex().upper(),
            },
            "fileHash": self.file_hash.hex().upper(),
            "findBuddyRequest": {
                "sourceEndpoint": _endpoint(self.bind_host, self.buddy_udp_port),
                "targetEndpoint": _endpoint(target_host, target_udp_port),
                "protocol": OP_KADEMLIAHEADER,
                "opcode": KADEMLIA_FINDBUDDY_REQ,
                "rawHex": find_request.hex().upper(),
                "payloadHex": find_request[2:].hex().upper(),
                "sentBytes": find_sent_bytes,
                "sentAt": find_sent_at,
            },
            "findBuddyResponse": {
                **find_response,
                "sourceEndpoint": _endpoint(*find_response_source),
                "targetEndpoint": _endpoint(self.bind_host, self.buddy_udp_port),
                "receivedAt": find_received_at,
            },
            "heldBuddyConnection": {
                "sourceEndpoint": _endpoint(*held_source),
                "targetEndpoint": _endpoint(*target_tcp_endpoint),
                "hello": {
                    "protocol": ed2k_wire.PROTO_EDONKEY,
                    "opcode": OP_HELLO,
                    "rawHex": hello_request.hex().upper(),
                    "payloadHex": hello_request[6:].hex().upper(),
                    "sentAt": hello_sent_at,
                },
                "precedingFrames": hello_preceding,
                "helloAnswer": {
                    **hello_answer,
                    "receivedAt": hello_answer_received_at,
                },
            },
            "callbackRequest": {
                "sourceEndpoint": _endpoint(*requester_udp_endpoint),
                "targetEndpoint": _endpoint(*target_udp_endpoint),
                "protocol": OP_KADEMLIAHEADER,
                "opcode": KADEMLIA_CALLBACK_REQ,
                "rawHex": callback_request.hex().upper(),
                "payloadHex": callback_request[2:].hex().upper(),
                "sentBytes": callback_sent_bytes,
                "sentAt": callback_sent_at,
            },
            "callbackRelay": {
                **relay,
                "precedingFrames": relay_preceding,
                "receivedAt": relay_received_at,
            },
            "resultingPeerSession": {
                "sourceEndpoint": _endpoint(*callback_source),
                "targetEndpoint": _endpoint(
                    relay["requesterHost"], relay["requesterTcpPort"]
                ),
                "hello": {
                    "protocol": ed2k_wire.PROTO_EDONKEY,
                    "opcode": OP_HELLO,
                    "rawHex": callback_hello.hex().upper(),
                    "payloadHex": callback_hello[6:].hex().upper(),
                    "sentAt": callback_hello_sent_at,
                },
                "precedingFrames": callback_preceding,
                "helloAnswer": {
                    **callback_answer,
                    "receivedAt": callback_answer_received_at,
                },
                "listenerObservation": callback_connection,
            },
        }

    def close(self) -> None:
        buddy_udp = self._buddy_udp_socket
        self._buddy_udp_socket = None
        if buddy_udp is not None:
            buddy_udp.close()
        self._requester_listener.close()

    def __enter__(self) -> "BuddyCallbackProbe":
        self.start()
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()
