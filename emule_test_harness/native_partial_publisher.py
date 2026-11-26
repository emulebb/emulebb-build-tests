"""Two complementary legacy eD2K sources for the scattered-byte metadata witness."""

from __future__ import annotations

import ipaddress
import math
import select
import socket
import struct
import threading
from functools import cache

from . import ed2k_wire as wire
from .docker_ed2k_source_publisher import encode_hello_answer
from .scripted_actions import ED2K_PART_SIZE as PART_SIZE, _md4_digest


TAIL_SIZE = 184_320
OP_HELLO, OP_HELLOANSWER = 0x01, 0x4C
OP_SETREQFILEID, OP_FILESTATUS = 0x4F, 0x50
OP_HASHSETREQUEST, OP_HASHSETANSWER = 0x51, 0x52
OP_STARTUPLOADREQ, OP_ACCEPTUPLOADREQ, OP_CANCELTRANSFER = 0x54, 0x55, 0x56
OP_REQUESTFILENAME, OP_REQFILENAMEANSWER = 0x58, 0x59
OP_PUBLICIP_REQ, OP_PUBLICIP_ANSWER = 0x97, 0x98


@cache
def _fixture_hashes() -> tuple[bytes, bytes]:
    hashset = _md4_digest(b"A" * PART_SIZE) + _md4_digest(b"B" * TAIL_SIZE)
    return _md4_digest(hashset), hashset


class PartialPublisher:
    """Own one part on an explicitly supplied alias. Each instance is single-use."""

    file_name = "partial-metadata-boundary.bin"
    file_size = PART_SIZE + TAIL_SIZE

    def __init__(self, bind_host: str, tcp_port: int, part_index: int):
        if part_index not in (0, 1):
            raise ValueError("part_index must be 0 (head) or 1 (tail)")
        self._address = ipaddress.IPv4Address(bind_host)
        self._port = tcp_port
        self._part = part_index
        self.file_hash, self._hashset = _fixture_hashes()
        self._covered = bytearray(PART_SIZE - 2 if part_index == 0 else 2)
        self._sent = 0
        self._connections = 0
        self._opcodes: dict[str, int] = {}
        self._last_error: str | None = None
        self._changed = threading.Condition()
        self._release = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active: socket.socket | None = None

    @property
    def tcp_port(self) -> int:
        return self._port

    @property
    def sent_bytes(self) -> int:
        """Count distinct fixture bytes successfully written across sessions."""
        with self._changed:
            return self._sent

    def wait_for_sent(self, count: int, timeout_seconds: float) -> None:
        if not 0 <= count <= len(self._covered):
            raise ValueError("requested count exceeds this publisher's budget")
        if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
            raise ValueError("a finite nonnegative timeout is required")
        with self._changed:
            self._changed.wait_for(lambda: self._sent >= count or self._stop.is_set(), timeout_seconds)
            if self._sent < count:
                raise TimeoutError(
                    f"partial publisher sent {self._sent} of {count} distinct bytes "
                    f"(connections={self._connections}, frames={self._opcodes}, last_error={self._last_error})"
                )

    def release_threshold_byte(self, timeout_seconds: float) -> None:
        """Authorize the tail's second byte on a matching live reservation and await its send."""
        if self._part != 1 or self.sent_bytes < 1:
            raise RuntimeError("release requires a tail publisher that already sent its first byte")
        if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
            raise ValueError("a finite nonnegative timeout is required")
        self._release.set()
        self.wait_for_sent(2, timeout_seconds)

    def start(self) -> None:
        if self._thread is not None or self._stop.is_set():
            raise RuntimeError("partial publisher may only be started once")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind((str(self._address), self._port))
            listener.listen(4)
            listener.settimeout(0.1)
            self._port = listener.getsockname()[1]
            self._thread = threading.Thread(target=self._listen, args=(listener,), daemon=True)
            self._thread.start()
        except BaseException:
            listener.close()
            raise

    def stop(self) -> None:
        with self._changed:
            self._stop.set()
            if self._active is not None:
                try:
                    self._active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self._changed.notify_all()
        if self._thread is not None:
            self._thread.join(3)
            if self._thread.is_alive():
                raise RuntimeError("partial publisher did not stop")

    def _listen(self, listener: socket.socket) -> None:
        with listener:
            while not self._stop.is_set():
                try:
                    stream, _ = listener.accept()
                except socket.timeout:
                    continue
                with stream:
                    with self._changed:
                        if self._stop.is_set():
                            return
                        self._active = stream
                        self._connections += 1
                    try:
                        stream.settimeout(2)
                        self._session(stream)
                    except (OSError, wire.Ed2kWireError) as error:
                        with self._changed:
                            if not self._stop.is_set():
                                self._last_error = str(error)
                    finally:
                        with self._changed:
                            self._active = None

    def _send(self, stream: socket.socket, slot: wire.RequestedPart, start: int, end: int) -> None:
        unit = b"A" if self._part == 0 else b"B"
        stream.sendall(slot.sending_part(start, unit * (end - start)))
        offset = PART_SIZE * self._part
        with self._changed:
            self._sent += self._covered.count(0, start - offset, end - offset)
            self._covered[start - offset:end - offset] = b"\x01" * (end - start)
            self._changed.notify_all()

    def _session(self, stream: socket.socket) -> None:
        greeted = granted = False
        pending: wire.RequestedPart | None = None
        while not self._stop.is_set():
            if pending is not None and self._release.is_set():
                self._send(stream, pending, PART_SIZE + 1, PART_SIZE + 2)
                pending = None
            if not select.select([stream], [], [], 0.1)[0]:
                continue
            header = wire._recv_exact(stream, 6)
            size = int.from_bytes(header[1:5], "little")
            opcode = header[5]
            trace_key = f"{header[0]:02x}/{opcode:02x}"
            with self._changed:
                self._opcodes[trace_key] = self._opcodes.get(trace_key, 0) + 1
            if header[0] not in (wire.PROTO_EDONKEY, wire.PROTO_EMULE) or not 1 <= size <= 65_536:
                raise wire.Ed2kWireError(f"Unexpected peer frame {trace_key} length {size}")
            payload = wire._recv_exact(stream, size - 1)
            if header[0] == wire.PROTO_EMULE:
                if not greeted or opcode != OP_PUBLICIP_REQ or payload:
                    raise wire.Ed2kWireError(f"Unexpected peer extension {trace_key}")
                observed = socket.inet_aton(stream.getpeername()[0])
                stream.sendall(struct.pack("<BIB", wire.PROTO_EMULE, 5, OP_PUBLICIP_ANSWER) + observed)
                continue
            if not greeted:
                if opcode != OP_HELLO or len(payload) < 33 or payload[0] != 16:
                    raise wire.Ed2kWireError("Partial publisher expected a stock-shaped peer HELLO")
                stream.sendall(encode_hello_answer(
                    user_hash=b"partial-test" + self._address.packed,
                    client_id=int.from_bytes(self._address.packed, "little"), tcp_port=self.tcp_port,
                ))
                greeted = True
            elif opcode == OP_REQUESTFILENAME and payload[:16] == self.file_hash:
                name = self.file_name.encode("ascii")
                stream.sendall(wire.encode_frame(OP_REQFILENAMEANSWER, self.file_hash + struct.pack("<H", len(name)) + name))
            elif opcode == OP_SETREQFILEID and payload == self.file_hash:
                stream.sendall(wire.encode_frame(OP_FILESTATUS, payload + struct.pack("<HB", 2, 1 << self._part)))
            elif opcode == OP_HASHSETREQUEST and payload == self.file_hash:
                stream.sendall(wire.encode_frame(OP_HASHSETANSWER, payload + struct.pack("<H", 2) + self._hashset))
            elif opcode == OP_STARTUPLOADREQ and payload == self.file_hash:
                granted = True
                stream.sendall(wire.encode_frame(OP_ACCEPTUPLOADREQ))
            elif opcode == OP_CANCELTRANSFER:
                return
            elif opcode == wire.OP_REQUESTPARTS and granted:
                frame = wire.Ed2kFrame(wire.PROTO_EDONKEY, opcode, payload)
                for slot in wire.decode_requested_parts(frame, file_hash=self.file_hash, file_size=self.file_size):
                    base = PART_SIZE * self._part
                    limit = len(self._covered)
                    if self._part == 1 and not self._release.is_set():
                        limit = 1
                        if slot.start <= base + 1 < slot.end:
                            pending = slot
                    start, end = max(base, slot.start), min(base + limit, slot.end)
                    if start < end:
                        self._send(stream, slot, start, end)
