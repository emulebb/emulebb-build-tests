"""Exercise a downloader's upload-slot recycle over a single native socket."""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from collections.abc import Callable

from . import ed2k_wire as wire
from .docker_ed2k_source_publisher import encode_hello_answer
from .native_partial_publisher import (
    OP_ACCEPTUPLOADREQ,
    OP_FILESTATUS,
    OP_HASHSETANSWER,
    OP_HASHSETREQUEST,
    OP_HELLO,
    OP_PUBLICIP_ANSWER,
    OP_PUBLICIP_REQ,
    OP_REQFILENAMEANSWER,
    OP_REQUESTFILENAME,
    OP_SETREQFILEID,
    OP_STARTUPLOADREQ,
)
from .scripted_actions import _md4_digest

FILE_NAME = "native-slot-recycle.bin"
PAYLOAD = bytes(range(256)) * 128
PREFIX_LENGTH = 10_240
OP_OUTOFPARTREQS = 0x57
OP_QUEUERANK = 0x5C


def observe(bind_address: str, variant: int, submit_link: Callable[[str, str], None]) -> dict[str, object]:
    """Grant, recycle, and regrant a partial transfer after an ordered socket barrier."""
    payload = bytes([variant]) + PAYLOAD[1:]
    file_hash = _md4_digest(payload)
    with socket.create_server((bind_address, 0)) as listener:
        listener.settimeout(55)
        port = listener.getsockname()[1]
        link = f"ed2k://|file|{FILE_NAME}|{len(payload)}|{file_hash.hex()}|/|sources,{bind_address}:{port}|/"
        submit_link(link, file_hash.hex())
        stream, _ = listener.accept()
        with stream:
            witness = _exchange(stream, bind_address, port, payload, file_hash)
    return {**witness, "sha256": hashlib.sha256(payload).hexdigest()}


def fixture_identity(variant: int) -> tuple[str, str]:
    """Return the eD2K and SHA-256 digests independently from the wire witness."""
    payload = bytes([variant]) + PAYLOAD[1:]
    return _md4_digest(payload).hex(), hashlib.sha256(payload).hexdigest()


def _exchange(
    stream: socket.socket, bind_address: str, port: int, payload: bytes, file_hash: bytes,
) -> dict[str, object]:
    deadline = time.monotonic() + 30
    trace: list[dict[str, object]] = []

    def send(opcode: int, payload: bytes = b"") -> None:
        stream.sendall(wire.encode_frame(opcode, payload))

    def receive() -> wire.Ed2kFrame:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Slot recycle conversation exceeded its deadline")
        stream.settimeout(remaining)
        header = wire._recv_exact(stream, 6)
        size = int.from_bytes(header[1:5], "little")
        if not 1 <= size <= 65_536:
            raise wire.Ed2kWireError(f"Invalid slot recycle frame length {size}")
        frame = wire.decode_frame_bytes(header + wire._recv_exact(stream, size - 1), peer_protocol=True)
        trace.append({"direction": "from-downloader", "marker": frame.marker, "opcode": frame.opcode})
        return frame

    hello = receive()
    if (hello.marker, hello.opcode) != (wire.PROTO_EDONKEY, OP_HELLO) or hello.payload[:1] != b"\x10":
        raise wire.Ed2kWireError("Slot recycle peer expected a native HELLO")
    address = socket.inet_aton(bind_address)
    stream.sendall(encode_hello_answer(
        user_hash=b"recycle-peer" + address,
        client_id=int.from_bytes(address, "little"),
        tcp_port=port,
    ))

    granted = False
    name = FILE_NAME.encode("ascii")
    while True:
        frame = receive()
        if (frame.marker, frame.opcode) == (wire.PROTO_EMULE, OP_PUBLICIP_REQ) and not frame.payload:
            stream.sendall(struct.pack("<BIB", wire.PROTO_EMULE, 5, OP_PUBLICIP_ANSWER)
                           + socket.inet_aton(stream.getpeername()[0]))
            continue
        if frame.marker != wire.PROTO_EDONKEY or frame.payload[:16] != file_hash:
            raise wire.Ed2kWireError(f"Unexpected slot recycle startup frame 0x{frame.opcode:02x}")
        if frame.opcode == OP_REQUESTFILENAME:
            send(OP_REQFILENAMEANSWER, file_hash + struct.pack("<H", len(name)) + name)
        elif frame.opcode == OP_SETREQFILEID:
            send(OP_FILESTATUS, file_hash + struct.pack("<H", 0))
        elif frame.opcode == OP_HASHSETREQUEST:
            send(OP_HASHSETANSWER, file_hash + struct.pack("<H", 0))
        elif frame.opcode == OP_STARTUPLOADREQ and not granted:
            send(OP_ACCEPTUPLOADREQ)
            trace.append({"direction": "to-downloader", "opcode": OP_ACCEPTUPLOADREQ})
            granted = True
        elif frame.opcode == wire.OP_REQUESTPARTS and granted:
            break
        else:
            raise wire.Ed2kWireError(f"Unexpected slot recycle startup opcode 0x{frame.opcode:02x}")

    first = wire.decode_requested_parts(frame, file_hash=file_hash, file_size=len(payload))
    if len(first) != 1 or (first[0].start, first[0].end) != (0, len(payload)):
        raise wire.Ed2kWireError("Initial grant did not reserve the complete fixture range")
    stream.sendall(first[0].sending_part(0, payload[:PREFIX_LENGTH]))
    trace.append({"direction": "to-downloader", "sentRange": [0, PREFIX_LENGTH]})
    send(OP_OUTOFPARTREQS)
    trace.append({"direction": "to-downloader", "opcode": OP_OUTOFPARTREQS})
    send(OP_QUEUERANK, struct.pack("<I", 7))
    trace.append({"direction": "to-downloader", "opcode": OP_QUEUERANK, "rank": 7})
    stream.sendall(struct.pack("<BIB", wire.PROTO_EMULE, 1, OP_PUBLICIP_REQ))
    trace.append({"direction": "to-downloader", "marker": wire.PROTO_EMULE, "opcode": OP_PUBLICIP_REQ})
    barrier = receive()
    if (barrier.marker, barrier.opcode, len(barrier.payload)) != (wire.PROTO_EMULE, OP_PUBLICIP_ANSWER, 4):
        raise wire.Ed2kWireError(f"Recycle barrier expected public IP reply, got 0x{barrier.opcode:02x}")

    send(OP_ACCEPTUPLOADREQ)
    trace.append({"direction": "to-downloader", "opcode": OP_ACCEPTUPLOADREQ})
    fresh = wire.decode_requested_parts(receive(), file_hash=file_hash, file_size=len(payload))
    if len(fresh) != 1 or (fresh[0].start, fresh[0].end) != (PREFIX_LENGTH, len(payload)):
        raise wire.Ed2kWireError("Regrant did not reserve the remaining bytes")
    stream.sendall(fresh[0].sending_part(PREFIX_LENGTH, payload[PREFIX_LENGTH:]))
    trace.append({"direction": "to-downloader", "sentRange": [PREFIX_LENGTH, len(payload)]})
    stream.shutdown(socket.SHUT_WR)
    return {
        "fileHash": file_hash.hex(),
        "firstRange": [first[0].start, first[0].end],
        "regrantedRange": [fresh[0].start, fresh[0].end],
        "trace": trace,
    }
